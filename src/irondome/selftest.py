"""The checks ``irondome verify`` runs on this machine.

Every claim in ``claims.json`` names a *selfcheck*: a short experiment that
shows, on this machine, with its device backend, its Python and its build of
``cryptography``, that the claim holds. :data:`CHECKS` maps those names to
the functions below and :func:`run` runs them. Each returns a
:class:`CheckResult`: ``pass``, ``FAIL`` or ``skipped``, and one line saying
what was shown.

Where the checks work
---------------------
In one private temporary directory (mode 0700) and nowhere else. Every check
gets fresh directories inside it; for the duration of the check
``IRONDOME_HOME``, ``IRONDOME_DEVICE_DIR``, ``IRONDOME_LEGACY_DIR``, ``HOME``
and ``XDG_STATE_HOME`` point into them, the bunker, session, grant and
password-file variables are removed, and everything is put back afterwards.
Before anything destructive (``nuke``, destroying a device key) a check
asserts that every IronDome location is inside that directory. The user's own
vault, device keys, sessions, grants, settings and audit log are never
opened, changed or deleted. The directory is removed at the end.

Nothing asks for a password or a finger: Touch ID is switched off
(``IRONDOME_NO_TOUCH=1``) in every check, except for the one step that
``irondome verify --touch`` asks for.

The device backend is the strongest this machine offers (or the one
``IRONDOME_DEVICE_BACKEND`` names), so the results say what *this* machine
provides; a claim that needs a security chip it does not have is reported as
skipped, never as passed. The Argon2id cost is set to its minimum inside the
checks, except where the defaults themselves are checked: none of the other
properties depends on it.

The memory checks run in fresh interpreters (:func:`memory_probe`): a probe
process records an XOR-masked copy of every key the kernel produces, does the
work, locks the vault and then searches its own address space with
:mod:`irondome.memscan`.
"""

from __future__ import annotations

import ast
import base64
import contextlib
import gc
import hmac
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from irondome import __version__, audit, caps, crypto, keys, memscan, nuke, otp, paths, unlock
from irondome import device as devices
from irondome.device.base import POLICY_BIOMETRY, POLICY_DEVICE
from irondome.errors import AuthError, HardwareError, IronDomeError, PolicyError, UsageError, VaultError
from irondome.secmem import SecureBuffer, _wipe_str, as_view, read_secret_from_fd, wipe_bytes
from irondome.vault import Secret, Vault, VaultFile

__all__ = [
    "PASS",
    "FAIL",
    "SKIPPED",
    "CheckResult",
    "Outcome",
    "Report",
    "Sandbox",
    "SandboxError",
    "CHECKS",
    "NO_HARDWARE",
    "STDLIB_ALLOWED",
    "FORBIDDEN_IMPORTS",
    "SELECTORS_ALLOWED_IN",
    "registry",
    "run",
    "import_findings",
    "memory_probe",
    "memory_probes",
    "probe_main",
]

PASS = "pass"  # noqa: S105 - the name of a result, not a credential
FAIL = "FAIL"
SKIPPED = "skipped"

NO_HARDWARE = "no Secure Enclave or TPM here; this machine uses the file-based device key"

_SAFE_PATH = "/usr/bin:/bin"
_PROBE_TIMEOUT = 900.0
_MIN_KDF_MIB = "19"


@dataclass(frozen=True)
class CheckResult:
    """What one check found. ``status`` is :data:`PASS`, :data:`FAIL` or :data:`SKIPPED`."""

    status: str
    detail: str


@dataclass(frozen=True)
class Outcome:
    """One claim of the registry and what its check found here."""

    claim: str
    title: str
    check: Optional[str]
    result: CheckResult
    seconds: float


class SandboxError(Exception):
    """A check was about to work outside its temporary directory. It is stopped, and fails."""


def _passed(detail: str) -> CheckResult:
    return CheckResult(PASS, detail)


def _failed(detail: str) -> CheckResult:
    return CheckResult(FAIL, detail)


def _skipped(detail: str) -> CheckResult:
    return CheckResult(SKIPPED, detail)


def registry() -> Dict[str, Any]:
    """The claims registry shipped with this package."""
    with open(Path(__file__).resolve().with_name("claims.json"), "rb") as handle:
        document = json.loads(handle.read().decode("utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("claims"), list):
        raise VaultError("the claims registry shipped with IronDome is damaged")
    return document


# ---------------------------------------------------------------------------
# The sandbox
# ---------------------------------------------------------------------------

#: Variables a check sets for its own directories.
_PATH_VARIABLES = (
    "IRONDOME_HOME", "IRONDOME_DEVICE_DIR", "IRONDOME_LEGACY_DIR", "HOME", "XDG_STATE_HOME", "USERPROFILE",
)
#: Variables that could lead a check to the user's own vault or credentials: removed while it runs.
_REMOVED_VARIABLES = (
    paths.ENV_BUNKER,
    "IRONDOME_SESSION",
    "IRONDOME_GRANT",
    "IRONDOME_PASSWORD_FILE",
    "IRONDOME_TOUCH",
)
_CONTROL_VARIABLES = ("IRONDOME_NO_TOUCH", "IRONDOME_NO_PROMPT", "IRONDOME_KDF_MEMORY_MIB", "IRONDOME_DEVICE_BACKEND",
                      "IRONDOME_SE_HELPER")


def _cached_helper() -> Optional[str]:
    """The Secure Enclave helper this installation already compiled, if any.

    Looked up with the caller's own environment, before any variable is
    changed, so that the checks run the helper the user's vault uses instead
    of compiling a new one inside the sandbox. Only the program is used;
    nothing else in the user's device directory is read.
    """
    if sys.platform != "darwin":
        return None
    named = os.environ.get("IRONDOME_SE_HELPER")
    if named:
        return named if os.path.isfile(named) else None
    from irondome.device import macos_se

    try:
        candidate = macos_se._helper_path()
    except (OSError, IronDomeError):
        return None
    return str(candidate) if candidate.is_file() else None


class Sandbox:
    """One private temporary directory; every check gets fresh directories inside it."""

    def __init__(self, *, touch: bool = False, root: Optional[Path] = None) -> None:
        self.touch = touch
        self._base = root
        self.root = Path()
        self.backend: Optional[devices.DeviceBackend] = None
        self.backend_note = ""
        #: What could not be cleaned up (a device secret a chip kept); reported, never hidden.
        self.notes: List[str] = []
        self._helper: Optional[str] = None
        self._preferred: Optional[str] = None
        self._hardware = False
        self._probed: Optional[devices.DeviceBackend] = None
        self._areas = 0
        self._open = False

    # -- lifetime -----------------------------------------------------------------

    def __enter__(self) -> "Sandbox":
        self._helper = _cached_helper()
        self._preferred = os.environ.get("IRONDOME_DEVICE_BACKEND") or None
        made = tempfile.mkdtemp(prefix="irondome-verify-", dir=None if self._base is None else str(self._base))
        self.root = Path(os.path.realpath(made))
        os.chmod(str(self.root), 0o700)
        self._open = True
        try:
            if self._helper is None and sys.platform == "darwin" and self._preferred in (None, "auto", "macos-se"):
                self._helper = self._compile_helper()
            with self.area("backend"):
                self.backend, self.backend_note, self._hardware = self._strongest_backend()
                self._probed = self.backend
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        if self._open:
            self._open = False
            shutil.rmtree(str(self.root), ignore_errors=True)

    def _compile_helper(self) -> Optional[str]:
        """Compile the Secure Enclave helper once, inside the sandbox, when this installation has none yet."""
        from irondome.device import macos_se

        saved = os.environ.get("IRONDOME_DEVICE_DIR")
        os.environ["IRONDOME_DEVICE_DIR"] = str(self.root / "se-helper")
        try:
            return str(macos_se.build_helper())
        except HardwareError:
            return None  # no developer tools: no Secure Enclave backend here, as for IronDome itself
        finally:
            if saved is None:
                os.environ.pop("IRONDOME_DEVICE_DIR", None)
            else:
                os.environ["IRONDOME_DEVICE_DIR"] = saved

    def _strongest_backend(self) -> Tuple[devices.DeviceBackend, str, bool]:
        """The backend IronDome would choose here, what it says about itself, and whether it is a working chip."""
        try:
            backend = devices.choose_backend(POLICY_DEVICE, self._preferred)
            probe = backend.probe()
            return backend, probe.detail, bool(backend.hardware and probe.hardware)
        except IronDomeError as exc:
            return devices.get_backend("software"), f"no device backend worked here: {exc}", False

    @property
    def backend_name(self) -> str:
        return self.backend.name if self.backend is not None else "software"

    @property
    def hardware(self) -> bool:
        """Whether the backend is a security chip that works here.

        Asked once per backend, and only inside the sandbox: a probe can
        compile or run the Secure Enclave helper under the device directory,
        which outside an area is the user's own.
        """
        backend = self.backend
        if backend is None or not backend.hardware:
            return False
        if backend is not self._probed:
            if not self._open:
                return False
            with self.area("backend"):
                try:
                    self._hardware = bool(backend.probe().hardware)
                except IronDomeError:
                    self._hardware = False
            self._probed = backend
        return self._hardware

    # -- one check's directories ----------------------------------------------------

    @contextlib.contextmanager
    def area(self, name: str, *, touch: bool = False, other_machine: bool = False) -> Iterator[Path]:
        """Fresh directories for one check, with every IronDome location pointing into them.

        On the way out every device secret made in them is destroyed: a TPM
        keeps an NV index after its files are gone. *other_machine* also hides
        this machine's TPM, so that a vault copied there finds no device secret.
        """
        if not self._open:
            raise SandboxError("the sandbox is closed")
        self._areas += 1
        base = self.root / f"{self._areas:02d}-{name}"
        os.mkdir(str(base), 0o700)
        home = base / "home"
        os.mkdir(str(home), 0o700)
        values = {
            "IRONDOME_HOME": str(base / "irondome"),
            "IRONDOME_DEVICE_DIR": str(base / "device"),
            "IRONDOME_LEGACY_DIR": str(base / "legacy"),
            "HOME": str(home),
            "XDG_STATE_HOME": str(home / ".local" / "state"),
            "USERPROFILE": str(home),
            "IRONDOME_NO_PROMPT": "1",
            "IRONDOME_KDF_MEMORY_MIB": _MIN_KDF_MIB,
        }
        if not touch:
            values["IRONDOME_NO_TOUCH"] = "1"
        if self.backend is not None:
            values["IRONDOME_DEVICE_BACKEND"] = self.backend.name
        if self._helper is not None:
            values["IRONDOME_SE_HELPER"] = self._helper
        if other_machine and self.backend_name == "linux-tpm2":
            values["TPM2TOOLS_TCTI"] = "device:/nonexistent/irondome-verify-another-machine"
        names = set(_PATH_VARIABLES) | set(_REMOVED_VARIABLES) | set(_CONTROL_VARIABLES) | {"TPM2TOOLS_TCTI"}
        saved = {variable: os.environ.get(variable) for variable in names}
        try:
            for variable in names:
                if variable != "TPM2TOOLS_TCTI":
                    os.environ.pop(variable, None)
            os.environ.update(values)
            self.guard()
            try:
                yield base
            finally:
                if other_machine:
                    _restore(saved, ("TPM2TOOLS_TCTI",))
                self._erase(name)
        finally:
            _restore(saved, tuple(saved))

    def _erase(self, name: str) -> None:
        """Destroy every device secret and file IronDome made in the current area."""
        os.environ.pop(paths.ENV_BUNKER, None)
        self.guard()
        if not paths.root().exists() and not paths.device_root().exists():
            return
        try:
            report = nuke.execute()
        except IronDomeError as exc:
            self.notes.append(f"{name}: cleaning up failed: {exc}")
            return
        if report.errors:
            self.notes.append(f"{name}: cleaning up left: {'; '.join(report.errors[:3])}")

    def inside(self, path: Path) -> bool:
        real = Path(os.path.realpath(str(path)))
        return real == self.root or self.root in real.parents

    def guard(self) -> None:
        """Raise :class:`SandboxError` unless every IronDome location is inside the sandbox."""
        locations = (
            ("the vault root", paths.root()),
            ("the device root", paths.device_root()),
            ("the bunker directory", paths.home()),
            ("the bunker's device directory", paths.device_dir()),
            ("the 3.x directory", paths.legacy_v3_dir()),
        )
        for what, location in locations:
            if not self.inside(location):
                raise SandboxError(f"refusing to go on: {what} is {location}, outside {self.root}")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _restore(saved: Mapping[str, Optional[str]], names: Sequence[str]) -> None:
    for variable in names:
        value = saved.get(variable)
        if value is None:
            os.environ.pop(variable, None)
        else:
            os.environ[variable] = value


def _password() -> str:
    """A throwaway master password for a throwaway vault."""
    return "verify-" + secrets.token_urlsafe(18)


@contextlib.contextmanager
def _locked(text: str) -> Iterator[SecureBuffer]:
    raw = text.encode("utf-8")
    try:
        buffer = SecureBuffer.from_buffer(raw)
    finally:
        wipe_bytes(raw)
    with buffer:
        yield buffer


def _create(password: str, *, recovery: bool = True) -> Tuple[Vault, Optional[str]]:
    with _locked(password) as secret:
        return unlock.create_vault(password=secret, with_recovery=recovery)


def _open(password: str, path: Optional[Path] = None) -> Vault:
    with _locked(password) as secret:
        return unlock.open_vault(path=path, password=secret, interactive=False, allow_touch=False)


def _refusal(password: str, path: Optional[Path] = None) -> Optional[IronDomeError]:
    """The error that keeps *password* out of the vault, or None if the vault opened."""
    try:
        _open(password, path).close()
    except (AuthError, HardwareError, VaultError) as exc:
        return exc
    return None


def _files(*roots: Path) -> List[Path]:
    found: List[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for current, _dirs, names in os.walk(str(root)):
            found.extend(Path(current) / name for name in names)
    return sorted(found)


def _contains(data: bytes, needles: Sequence[bytes]) -> bool:
    return any(needle and needle in data for needle in needles)


def _forms(text: str) -> List[bytes]:
    """How a text could appear in a file: UTF-8, JSON-escaped, base64 and hex of the UTF-8."""
    raw = text.encode("utf-8")
    return [raw, json.dumps(text)[1:-1].encode("ascii"), base64.b64encode(raw), raw.hex().encode("ascii")]


def _copy_tree(source: Path, target: Path) -> None:
    if source.exists():
        shutil.copytree(str(source), str(target), symlinks=True)


def _restore_tree(copy: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(str(target))
    if copy.exists():
        shutil.copytree(str(copy), str(target), symlinks=True)


def _describe_error(exc: BaseException) -> str:
    text = str(exc).splitlines()[0] if str(exc) else ""
    return f"{exc.__class__.__name__}: {text}" if text else exc.__class__.__name__


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------


def check_device_bound(box: Sandbox) -> CheckResult:
    """A complete copy of the vault directory and the right password do not open without this device."""
    password = _password()
    with box.area("device-bound") as base:
        vault, _recovery = _create(password)
        with vault:
            vault.add("probe", Secret(password=secrets.token_urlsafe(16)))
            vault.commit()
        copy = base / "copy"
        _copy_tree(paths.root(), copy)
        if _refusal(password) is not None:
            return _failed("the vault did not open on this machine with its own password")
        # "Another machine": the copied vault directory, and none of this machine's device material.
        with box.area("another-machine", other_machine=True):
            _restore_tree(copy, paths.root())
            right = _refusal(password)
            wrong = _refusal(password + "-wrong")
    hidden_tpm = box.backend_name == "linux-tpm2"
    if right is None:
        return _failed("a copy of the vault directory opened elsewhere with the right password")
    if wrong is None or (type(right), str(right)) != (type(wrong), str(wrong)):
        return _failed("on the copy a wrong password is refused differently from the right one: guesses can be tested")
    how = "a machine without this TPM" if hidden_tpm else "a machine without this device directory"
    return _passed(
        f"a full copy of the vault directory with the right password did not open on {how} "
        f"({right.__class__.__name__}), and a wrong password failed identically ({box.backend_name} backend)"
    )


def check_key_in_hardware(box: Sandbox) -> CheckResult:
    """The device secret comes from the Secure Enclave or the TPM and is on no disk."""
    if box.backend is None or not box.backend.hardware:
        return _skipped(NO_HARDWARE)
    if not box.hardware:
        return _skipped(f"the {box.backend_name} backend here is not a security chip ({box.backend_note})")
    backend = box.backend
    with box.area("key-in-hardware"):
        auth = SecureBuffer.random(32) if backend.name == "linux-tpm2" else None
        try:
            descriptor, secret = backend.enroll(policy=POLICY_DEVICE, auth=auth, reason="irondome verify")
            with secret:
                original = bytes(secret.view())
            try:
                stored = [path.read_bytes() for path in _files(paths.root(), paths.device_root())]
                if any(original in data or original.hex().encode() in data for data in stored):
                    return _failed("the device secret was found in a file on disk")
                with backend.unseal(descriptor, auth=auth, interactive=False, reason="irondome verify") as again:
                    if not hmac.compare_digest(bytes(again.view()), original):
                        return _failed("the security chip gave a different secret the second time")
                if backend.name == "macos-se":
                    refused = _foreign_blob_refused(backend, descriptor)
                    if refused is not None:
                        return refused
            finally:
                wipe_bytes(original)
                box.guard()
                backend.destroy(descriptor)
        finally:
            if auth is not None:
                auth.wipe()
    where = "a key agreement inside the Secure Enclave" if backend.name == "macos-se" else "a TPM 2.0 NV index"
    extra = "; a key blob the chip did not make is refused" if backend.name == "macos-se" else ""
    return _passed(f"the device secret came from {where} and is in no file on disk{extra} ({box.backend_note})")


def _foreign_blob_refused(backend: devices.DeviceBackend, descriptor: Dict[str, Any]) -> Optional[CheckResult]:
    """Replace the Secure Enclave key blob with one this chip did not make; it must be refused."""
    state_path = paths.device_dir() / f"{descriptor['ref']}.json"
    original = state_path.read_bytes()
    state = json.loads(original.decode("utf-8"))
    blob = bytearray(base64.b64decode(state["key"]))
    blob[len(blob) // 2] ^= 0x01
    state["key"] = base64.b64encode(bytes(blob)).decode("ascii")
    paths.write_atomic(state_path, json.dumps(state, sort_keys=True).encode("utf-8"))
    try:
        backend.unseal(descriptor, auth=None, interactive=False, reason="irondome verify").wipe()
    except HardwareError:
        return None
    finally:
        paths.write_atomic(state_path, original)
    return _failed("the Secure Enclave accepted a key blob it did not make")


def check_biometric_enforced(box: Sandbox) -> CheckResult:
    """A Touch ID key refuses to work without the finger; with --touch, one touch makes it work."""
    backend = box.backend
    if backend is None or backend.name != "macos-se" or not box.hardware:
        return _skipped("no Secure Enclave here: Touch ID keyslots exist only on a Mac")
    from irondome.device import macos_se

    source = macos_se.helper_source().read_text(encoding="utf-8")
    if 'case "biometry": flags = [.privateKeyUsage, .biometryCurrentSet]' not in source:
        return _failed("the Secure Enclave helper does not create biometric keys with biometryCurrentSet")
    with box.area("biometric"):
        info = backend.info()  # type: ignore[attr-defined]
        if not info.get("biometry_usable"):
            detail = info.get("biometry_detail") or "no enrolled finger, or the lid is closed"
            return _skipped(f"Touch ID is not usable right now ({detail})")
        try:
            descriptor, secret = backend.enroll(
                policy=POLICY_BIOMETRY, auth=None, reason="irondome verify: this request must be refused unseen"
            )
        except AuthError:
            refused = True
        else:
            secret.wipe()
            box.guard()
            backend.destroy(descriptor)
            refused = False
        if not refused:
            return _failed("a Touch ID key produced a secret without a touch")
        descriptor, secret = backend.enroll(policy=POLICY_DEVICE, auth=None, reason="irondome verify")
        secret.wipe()
        box.guard()
        backend.destroy(descriptor)
    negative = "a biometryCurrentSet key asked to work without a touch was refused by the Secure Enclave"
    if not box.touch:
        return _passed(f"{negative}; run with --touch to prove that one touch makes it work")
    with box.area("biometric-touch", touch=True):
        try:
            descriptor, secret = backend.enroll(
                policy=POLICY_BIOMETRY, auth=None, reason="prove that IronDome's Touch ID keys need your finger"
            )
        except AuthError as exc:
            return _failed(f"{negative}, but the touch did not unlock it ({_describe_error(exc)})")
        with secret:
            agreed = len(secret) == 32 and any(secret.view())
        box.guard()
        backend.destroy(descriptor)
    if not agreed:
        return _failed("the Secure Enclave returned no secret after the touch")
    return _passed(f"{negative}, and after one touch the same kind of key completed its key agreement")


def check_crypto_erase(box: Sandbox) -> CheckResult:
    """After nuke, a restored copy of the vault directory opens with nothing but the recovery key."""
    password = _password()
    with box.area("crypto-erase") as base:
        vault, recovery = _create(password)
        with vault:
            entry = vault.add("probe", Secret(password=secrets.token_urlsafe(16)))
            for index in range(3):
                vault.update(entry, secret=Secret(password=secrets.token_urlsafe(16 + index)))
                vault.commit()
            session = caps.create_session(vault, ttl=600)
            grant, _info = caps.create_grant(vault, ["probe"], ttl=600, uses=5)
        snapshots = sorted(paths.backups_dir().glob("vault-*.irondome"))
        copy = base / "ssd-copy"
        _copy_tree(paths.root(), copy)
        box.guard()
        report = nuke.execute()
        if not report.success:
            problems = report.errors + report.leftovers
            return _failed(f"nuke did not finish cleanly: {'; '.join(problems[:3])}")
        _restore_tree(copy, paths.root())
        opened = [path.name for path in [paths.vault_file()] + snapshots if _refusal(password, path) is None]
        if opened:
            return _failed(f"after nuke the master password still opens {', '.join(opened)}")
        try:
            caps.open_session(session, VaultFile.load()).wipe()
            return _failed("after nuke a restored session file still opens the vault")
        except AuthError:
            pass
        try:
            caps.open_grant(grant).close()
            return _failed("after nuke a restored grant file still opens")
        except AuthError:
            pass
        if recovery is None or not report.recovery_bunkers:
            return _failed("nuke did not report that the vault had a recovery key")
        try:
            file = VaultFile.load()
            with Vault(file, unlock.unlock(file, recovery_key=recovery)) as restored:
                readable = restored.value(restored.find("probe")) != ""
        except IronDomeError as exc:
            return _failed(f"the recovery key did not open the restored copy ({_describe_error(exc)})")
    if not readable:
        return _failed("the recovery key opened the restored copy but its entry was empty")
    return _passed(
        f"after nuke a restored copy of the vault directory (live file and {len(snapshots)} snapshots) refused the "
        "master password, the session token and the grant token; the recovery key still opened it, as documented"
    )


def check_everything_encrypted(box: Sandbox) -> CheckResult:
    """No name, username, URL, tag, alias, note or password is readable in any file IronDome writes."""
    marker = secrets.token_hex(6)
    plain = {
        "name": f"bank-{marker}",
        "username": f"user-{marker}",
        "url": f"https://site-{marker}.example",
        "tag": f"tag-{marker}",
        "alias": f"ALIAS_{marker}",
        "note": f"note {marker}",
        "password": f"pw-{marker}-{secrets.token_urlsafe(8)}",
        "field": f"field-{marker}",
    }
    with box.area("everything-encrypted"):
        vault, _recovery = _create(_password())
        with vault:
            entry = vault.add(
                plain["name"],
                Secret(password=plain["password"], notes=plain["note"], fields={"extra": plain["field"]}),
                username=plain["username"],
                url=plain["url"],
                tags=[plain["tag"]],
            )
            vault.set_alias(plain["alias"], entry, "password")
            vault.commit()
            sizes = []
            for length in (1, 8, 20, 64, 120):
                added = vault.add(f"size-{length}-{marker}", Secret(password="x" * length))
                sizes.append(len(crypto.b64d(vault.file.records[added.id])))
            vault.commit()
            vault.update(entry, secret=Secret(password=plain["password"] + "-2", notes=plain["note"]))
            vault.commit()
            with audit.owner_key(vault) as key:
                audit.record(
                    key, vault_id=vault.vault_id, kid=audit.KID_VAULT, action="get", actor="owner",
                    target=f"{plain['name']}/password", detail=plain["alias"],
                )
            caps.create_grant(vault, [plain["alias"]], ttl=600)
            caps.create_session(vault, ttl=600)
            entries = len(vault.entries)
        files = _files(paths.root())
        leaks = []
        for path in files:
            data = path.read_bytes()
            for what, text in plain.items():
                if _contains(data, _forms(text)):
                    leaks.append(f"{what} in {path.name}")
        records = len(VaultFile.load().records)
    if leaks:
        return _failed("readable in the files: " + ", ".join(sorted(set(leaks))[:6]))
    if len(set(sizes)) != 1:
        return _failed(f"records for passwords of 1 to 120 characters have different sizes: {sizes}")
    if records != entries:
        return _failed("the vault file has a different number of records than entries")
    return _passed(
        f"no name, username, URL, tag, alias, note, field or password readable in any of {len(files)} files "
        f"(vault, snapshots, audit log, sessions, grants); passwords of 1 to 120 characters make "
        f"{sizes[0]}-byte records"
    )


def _rewrite(change: Callable[[VaultFile], None]) -> None:
    file = VaultFile.load()
    change(file)
    paths.write_atomic(paths.vault_file(), file.to_bytes())


def _flip(text: str, at: int) -> str:
    raw = bytearray(crypto.b64d(text))
    raw[at] ^= 0x01
    return crypto.b64e(bytes(raw))


def _read_refused(password: str, name: str) -> bool:
    try:
        with _open(password) as vault:
            vault.value(vault.find(name))
    except VaultError:
        return True
    return False


_FIRST_VALUE, _SECOND_VALUE, _NEWER_VALUE = "the first value", "the second value", "a newer value"


def check_tamper_evident(box: Sandbox) -> CheckResult:
    """A changed byte, a record moved to another entry or one rolled back is refused."""
    password = _password()
    with box.area("tamper-evident"):
        vault, _recovery = _create(password, recovery=False)
        with vault:
            first = vault.add("first", Secret(password=_FIRST_VALUE))
            second = vault.add("second", Secret(password=_SECOND_VALUE))
            vault.commit()
            ids = (first.id, second.id)
        good = paths.read_file(paths.vault_file())

        _rewrite(lambda file: file.records.__setitem__(ids[0], _flip(file.records[ids[0]], 20)))
        flipped = _read_refused(password, "first") and not _read_refused(password, "second")
        paths.write_atomic(paths.vault_file(), good)

        _rewrite(lambda file: file.records.__setitem__(ids[1], file.records[ids[0]]))
        moved = _read_refused(password, "second")
        paths.write_atomic(paths.vault_file(), good)

        old_record = VaultFile.load().records[ids[0]]
        with _open(password) as vault:
            vault.update(vault.find("first"), secret=Secret(password=_NEWER_VALUE))
            vault.commit()
        newer = paths.read_file(paths.vault_file())
        _rewrite(lambda file: file.records.__setitem__(ids[0], old_record))
        rolled_back = _read_refused(password, "first")
        paths.write_atomic(paths.vault_file(), newer)

        _rewrite(lambda file: setattr(file, "index", _flip(file.index, 40)))
        index_refused = _refusal(password) is not None
        paths.write_atomic(paths.vault_file(), good)
        with _open(password) as vault:
            whole_file_rollback_opens = vault.value(vault.find("first")) == _FIRST_VALUE
    problems = [
        what
        for what, ok in (
            ("a changed byte in a record", flipped),
            ("a record moved to another entry", moved),
            ("an older copy of one record", rolled_back),
            ("a changed byte in the index", index_refused),
        )
        if not ok
    ]
    if problems:
        return _failed("not refused: " + ", ".join(problems))
    if not whole_file_rollback_opens:
        return _failed("restoring an older whole vault file did not give the older vault")
    return _passed(
        "a changed byte, a record moved to another entry, an older copy of one record and a changed index were all "
        "refused; an older copy of the whole file opens as the older vault, as documented"
    )


# Published test vectors.
_ARGON2ID_RFC9106 = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
_HKDF_RFC5869_CASE1 = (
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
)
_GCM_KEY = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
_GCM_IV = "cafebabefacedbaddecaf888"
_GCM_PLAINTEXT = (
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)
_GCM_AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
_GCM_CIPHERTEXT_TAG = (
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
    "76fc6ece0f4e1768cddf8853bb2d551b"
)


def check_modern_crypto(box: Sandbox) -> CheckResult:
    """Argon2id, HKDF-SHA256 and AES-256-GCM, from cryptography, match their published test vectors."""
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    problems = []
    argon = Argon2id(salt=b"\x02" * 16, length=32, iterations=3, lanes=4, memory_cost=32, ad=b"\x04" * 12,
                     secret=b"\x03" * 8)
    if argon.derive(b"\x01" * 32).hex() != _ARGON2ID_RFC9106:
        problems.append("Argon2id differs from RFC 9106")
    salt = os.urandom(crypto.SALT_LEN)
    cost = crypto.Argon2Params(memory_kib=19 * 1024, iterations=2, lanes=1)
    with _locked("a test password") as secret, crypto.argon2id(secret, salt, cost) as ours:
        direct = Argon2id(salt=salt, length=32, iterations=2, lanes=1, memory_cost=19 * 1024).derive(b"a test password")
        if not hmac.compare_digest(bytes(ours.view()), direct):
            problems.append("irondome.crypto.argon2id is not Argon2id")
    with crypto.hkdf(bytes.fromhex("0b" * 22), info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
                     salt=bytes.fromhex("000102030405060708090a0b0c"), length=42) as okm:
        if bytes(okm.view()).hex() != _HKDF_RFC5869_CASE1:
            problems.append("HKDF-SHA256 differs from RFC 5869")
    sealed = bytes.fromhex(_GCM_IV + _GCM_CIPHERTEXT_TAG)
    if crypto.open_sealed(bytes.fromhex(_GCM_KEY), sealed, bytes.fromhex(_GCM_AAD)).hex() != _GCM_PLAINTEXT:
        problems.append("AES-256-GCM differs from the GCM specification's test case 16")
    key = os.urandom(32)
    first, second = crypto.seal(key, b"same", b"ctx"), crypto.seal(key, b"same", b"ctx")
    if len(first) != crypto.NONCE_LEN + 4 + crypto.TAG_LEN or first[: crypto.NONCE_LEN] == second[: crypto.NONCE_LEN]:
        problems.append("AES-256-GCM records do not carry a fresh 96-bit nonce and a 128-bit tag")
    try:
        crypto.Argon2Params(memory_kib=19 * 1024 - 1).validate()
        problems.append("an Argon2id cost below the OWASP minimum is accepted")
    except VaultError:
        pass
    saved = os.environ.pop("IRONDOME_KDF_MEMORY_MIB", None)
    try:
        default = crypto.default_argon2()
        with box.area("modern-crypto"):
            os.environ.pop("IRONDOME_KDF_MEMORY_MIB", None)
            vault, _recovery = _create(_password(), recovery=False)
            with vault:
                stored = vault.file.slots[0].kdf or {}
    finally:
        if saved is not None:
            os.environ["IRONDOME_KDF_MEMORY_MIB"] = saved
    if (stored.get("m"), stored.get("t"), stored.get("p")) != (default.memory_kib, default.iterations, default.lanes):
        problems.append("a new vault does not store the default Argon2id cost")
    if default.memory_kib < 19 * 1024 or default.iterations != 3 or default.lanes != 4:
        problems.append(f"the default Argon2id cost here is {default.to_dict()}")
    if problems:
        return _failed("; ".join(problems))
    import cryptography

    return _passed(
        f"RFC 9106 Argon2id, RFC 5869 HKDF and GCM test vectors match (cryptography {cryptography.__version__}); "
        f"new vaults use Argon2id m={default.memory_kib // 1024} MiB t={default.iterations} p={default.lanes}"
    )


# -- imports ------------------------------------------------------------------

#: Standard-library modules IronDome may import. Anything else (other than cryptography and irondome) is refused.
STDLIB_ALLOWED = frozenset(
    """
    __future__ abc argparse ast atexit base64 binascii codecs collections contextlib copy csv ctypes dataclasses
    datetime difflib errno fcntl fnmatch functools gc getpass grp hashlib heapq hmac importlib io itertools json math
    mmap msvcrt os pathlib platform plistlib pwd queue re resource secrets selectors shlex shutil signal stat string
    struct subprocess sys tempfile termios textwrap threading time traceback typing unicodedata urllib.parse winreg
    """.split()
)
#: Named explicitly: a module that talks to a network, or that only exists to.
FORBIDDEN_IMPORTS = frozenset(
    """
    socket ssl http urllib.request urllib.response ftplib smtplib poplib imaplib telnetlib nntplib xmlrpc asyncio
    socketserver requests httpx aiohttp urllib3 websocket websockets multiprocessing webbrowser wsgiref
    """.split()
)
#: ``selectors`` waits on pipes in exactly these modules; with ``socket`` refused, nothing can hand it a connection.
SELECTORS_ALLOWED_IN = frozenset({"irondome/agent/runner.py"})


def _allowed(module: str, where: str) -> bool:
    root = module.split(".")[0]
    if root in ("irondome", "cryptography"):
        return True
    if root == "selectors":
        return where in SELECTORS_ALLOWED_IN
    if root == "urllib":
        return module == "urllib.parse" or module.startswith("urllib.parse.")
    return module in STDLIB_ALLOWED or root in STDLIB_ALLOWED and root != "urllib"


def _forbidden(module: str) -> bool:
    parts = module.split(".")
    return any(".".join(parts[: count + 1]) in FORBIDDEN_IMPORTS for count in range(len(parts)))


def import_findings(package: Optional[Path] = None) -> Tuple[Dict[str, List[str]], List[str]]:
    """Every import of every module of the package, and what is wrong with them.

    Returns ``({module: [files]}, [problems])``. A problem is an import of a
    forbidden or unlisted module, ``selectors`` outside the module allowed to
    wait on pipes with it, a dynamic import whose argument is not a literal,
    or a dynamic import of a module that is not allowed. The registry of
    device backends, the one dynamic import that takes a name from a table,
    is checked entry by entry.
    """
    base = package or Path(__file__).resolve().parent
    found: Dict[str, List[str]] = {}
    problems: List[str] = []
    for path in sorted(base.rglob("*.py")):
        where = f"irondome/{path.relative_to(base).as_posix()}"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=where)
        for node in ast.walk(tree):
            names: List[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            elif isinstance(node, ast.Call):
                problems.extend(_dynamic_import_problems(node, where, tree))
            for name in names:
                found.setdefault(name, []).append(where)
                if _forbidden(name):
                    problems.append(f"{where} imports {name}, a networking module")
                elif not _allowed(name, where):
                    problems.append(f"{where} imports {name}, which is not on the list of allowed modules")
    return found, problems


def _called_name(node: ast.Call) -> Optional[str]:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return None


def _dynamic_import_problems(node: ast.Call, where: str, tree: ast.AST) -> List[str]:
    if _called_name(node) not in ("__import__", "import_module"):
        return []
    if not node.args:
        return [f"{where} calls {_called_name(node)} without a module name"]
    argument = node.args[0]
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        names = [argument.value]
    elif where == "irondome/device/__init__.py":
        names = _backend_registry_modules(tree)
        if not names:
            return [f"{where} imports a module by a computed name and its backend registry could not be read"]
    else:
        return [f"{where} imports a module whose name is computed at run time"]
    return [
        f"{where} imports {name} dynamically, which is not on the list of allowed modules"
        for name in names
        if _forbidden(name) or not _allowed(name, where)
    ]


def _backend_registry_modules(tree: ast.AST) -> List[str]:
    """The module names in irondome.device's ``_REGISTRY``: a literal tuple of (name, module, class)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_REGISTRY" for t in node.targets):
            try:
                table = ast.literal_eval(node.value)
            except ValueError:
                return []
            return [entry[1] for entry in table if isinstance(entry, tuple) and len(entry) == 3]
    return []


_NETWORK_MODULES = ("socket", "_socket", "ssl", "_ssl", "http", "urllib.request", "asyncio", "socketserver")


class _NoSockets:
    """Make every way of creating a socket raise, for as long as the block runs.

    Without importing ``socket``: if some module already loaded it, its
    constructors are replaced; and while the block runs, importing it (or any
    other networking module) fails. Either attempt is counted.
    """

    def __init__(self) -> None:
        self.attempts = 0
        self._saved: Dict[str, Any] = {}

    def _refuse(self, *args: object, **kwargs: object) -> None:
        self.attempts += 1
        raise OSError("irondome verify: socket creation is switched off")

    def find_spec(self, name: str, path: Any = None, target: Any = None) -> None:
        if any(name == module or name.startswith(module + ".") for module in _NETWORK_MODULES):
            self.attempts += 1
            raise ImportError(f"irondome verify: importing {name} is switched off")
        return None

    def __enter__(self) -> "_NoSockets":
        module = sys.modules.get("socket")
        if module is not None:
            for name in ("socket", "create_connection", "socketpair", "fromfd", "create_server"):
                if hasattr(module, name):
                    self._saved[name] = getattr(module, name)
                    setattr(module, name, self._refuse)
        sys.meta_path.insert(0, self)
        return self

    def __exit__(self, *exc: object) -> None:
        if self in sys.meta_path:
            sys.meta_path.remove(self)
        module = sys.modules.get("socket")
        for name, value in self._saved.items():
            setattr(module, name, value)


def check_no_network(box: Sandbox) -> CheckResult:
    """No networking module anywhere, and the everyday work goes on with sockets switched off."""
    _found, problems = import_findings()
    if problems:
        return _failed("; ".join(problems[:4]))
    password = _password()
    with box.area("no-network"), _NoSockets() as guard:
        vault, _recovery = _create(password)
        with vault:
            totp = otp.make_totp("JBSWY3DPEHPK3PXP")
            entry = vault.add("probe", Secret(password=secrets.token_urlsafe(16), totp=totp))
            vault.set_alias("PROBE", entry, "password")
            vault.commit()
            token, _info = caps.create_grant(vault, ["PROBE", "probe/totp"], ttl=600, uses=2)
            with audit.owner_key(vault) as key:
                audit.record(key, vault_id=vault.vault_id, kid=audit.KID_VAULT, action="verify", actor="owner")
        with _open(password) as vault:
            vault.value(vault.find("probe"))
            report = audit.verify(vault)
        with caps.open_grant(token) as grant:
            grant.value("PROBE")
            grant.value("probe/totp")
        from irondome.agent import runner

        result = runner.run_captured([sys.executable, "-c", "print('ok')"], {}, base_env={"PATH": _SAFE_PATH},
                                     timeout=60)
        box.guard()
        erased = nuke.execute()
    if guard.attempts:
        times = "once" if guard.attempts == 1 else f"{guard.attempts} times"
        return _failed(f"something tried to create a socket {times}")
    if not report.ok or result.code != 0 or not erased.success:
        return _failed("the work done with sockets switched off did not complete")
    return _passed(
        "no module imports a networking library; creating a vault, adding, reading, a grant, a one-time code, "
        "the audit log, running a command and nuke all worked with socket creation switched off"
    )


_EXTRA = re.compile(r";.*\bextra\s*==")
_REQUIREMENT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _metadata_requirements() -> Optional[List[str]]:
    """The requirements in the installed metadata of this very version of IronDome, or None.

    Matched on the version as well as the name: an old build directory on
    the path (an ``IronDome.egg-info`` of 3.x) must not answer for this one.
    """
    from importlib import metadata

    for distribution in metadata.distributions():
        name = (distribution.metadata.get("Name") or "").lower()
        if name == "irondome" and distribution.version == __version__:
            return list(distribution.requires or [])
    return None


def check_one_dependency(box: Sandbox) -> CheckResult:
    """The installed metadata names cryptography and nothing else; the code imports nothing else."""
    requirements = _metadata_requirements()
    if requirements is None:
        return _skipped(f"IronDome {__version__} is not installed as a package here, so its metadata cannot be read")
    runtime = [requirement for requirement in requirements if not _EXTRA.search(requirement)]
    names = sorted({found.group(0).lower() for found in map(_REQUIREMENT_NAME.match, runtime) if found})
    if names != ["cryptography"]:
        return _failed(f"the installed package requires {', '.join(runtime) or 'nothing'}")
    found, problems = import_findings()
    third_party = sorted({name.split(".")[0] for name in found} - {"irondome", "cryptography"}
                         - {name.split(".")[0] for name in STDLIB_ALLOWED})
    if third_party or problems:
        return _failed("; ".join([f"imports {', '.join(third_party)}"] if third_party else problems[:3]))
    package = Path(__file__).resolve().parent
    native = [path.name for path in package.rglob("*") if path.suffix in (".so", ".pyd", ".dylib", ".dll")]
    if native:
        return _failed(f"the package ships compiled code: {', '.join(native)}")
    if not (package / "device" / "irondome_se.swift").is_file():
        return _failed("the Secure Enclave helper's source is missing from the package")
    return _passed(f"requires {runtime[0]} and nothing else; no other third-party import; no compiled code shipped")


def check_owner_only_files(box: Sandbox) -> CheckResult:
    """Files 0600 and directories 0700 whatever the umask; atomic replacement; a concurrent writer is refused."""
    password = _password()
    previous = os.umask(0)
    try:
        with box.area("owner-only"):
            vault, _recovery = _create(password)
            with vault:
                entry = vault.add("probe", Secret(password=secrets.token_urlsafe(16)))
                vault.commit()
                vault.update(entry, secret=Secret(password=secrets.token_urlsafe(17)))
                vault.commit()
                caps.create_session(vault, ttl=600)
                caps.create_grant(vault, ["probe"], ttl=600)
                with audit.owner_key(vault) as key:
                    audit.record(key, vault_id=vault.vault_id, kid=audit.KID_VAULT, action="verify", actor="owner")
            loose = []
            helper = paths.helper_dir()
            for root in (paths.root(), paths.device_root()):
                for current, dirs, names in os.walk(str(root)):
                    if Path(current) == helper or helper in Path(current).parents:
                        continue  # the compiled Secure Enclave helper is a program: 0700 on purpose
                    for name in dirs:
                        mode = stat.S_IMODE(os.lstat(os.path.join(current, name)).st_mode)
                        if mode != 0o700:
                            loose.append(f"{name}/ {mode:o}")
                    for name in names:
                        mode = stat.S_IMODE(os.lstat(os.path.join(current, name)).st_mode)
                        if mode != 0o600:
                            loose.append(f"{name} {mode:o}")
            interrupted = _interrupted_write_is_harmless(password)
            refused = _concurrent_writer_is_refused(password)
    finally:
        os.umask(previous)
    if loose:
        return _failed(f"with umask 000 these were created too open: {', '.join(loose[:5])}")
    if not interrupted:
        return _failed("an interrupted write did not leave the previous vault intact")
    if not refused:
        return _failed("a second writer overwrote a change instead of being refused")
    return _passed(
        "with umask 000 every file was 0600 and every directory 0700; an interrupted write left the previous vault "
        "intact; a second, concurrent writer was refused"
    )


def _interrupted_write_is_harmless(password: str) -> bool:
    before = paths.read_file(paths.vault_file())
    real_replace = os.replace
    live = os.path.realpath(str(paths.vault_file()))

    def interrupted(source: Any, target: Any, **kwargs: Any) -> None:
        if os.path.realpath(os.fspath(target)) == live:
            raise OSError("irondome verify: the write was interrupted here")
        real_replace(source, target, **kwargs)

    with _open(password) as vault:
        vault.add("never-written", Secret(password="x" * 12))
        os.replace = interrupted  # type: ignore[assignment]
        try:
            vault.commit()
            return False
        except OSError:
            pass
        finally:
            os.replace = real_replace
    leftovers = [path.name for path in _files(paths.home()) if path.name.startswith(".tmp-")]
    with _open(password) as vault:
        intact = not vault.has_name("never-written")
    return intact and not leftovers and paths.read_file(paths.vault_file()) == before


def _concurrent_writer_is_refused(password: str) -> bool:
    with _open(password) as first, _open(password) as second:
        first.add("from-the-first", Secret(password="x" * 12))
        first.commit()
        second.add("from-the-second", Secret(password="y" * 12))
        try:
            second.commit()
            return False
        except VaultError:
            pass
    with _open(password) as vault:
        return vault.has_name("from-the-first") and not vault.has_name("from-the-second")


@contextlib.contextmanager
def _clock(offset: int) -> Iterator[None]:
    """Move this process's clock *offset* seconds forward for the duration of the block."""
    real = time.time
    time.time = lambda: real() + offset
    try:
        yield
    finally:
        time.time = real


def check_grants_are_scoped(box: Sandbox) -> CheckResult:
    """A grant reads what it names and nothing else, for its uses and its lifetime; then it is gone."""
    with box.area("grants-scoped"):
        vault, _recovery = _create(_password())
        with vault:
            granted = secrets.token_urlsafe(16)
            vault.add("granted", Secret(password=granted))
            vault.add("other", Secret(password=secrets.token_urlsafe(16)))
            vault.commit()
            token, info = caps.create_grant(vault, ["granted"], ttl=600, uses=2)
            expiring, expiring_info = caps.create_grant(vault, ["granted"], ttl=60, uses=None)
        problems = []
        with caps.open_grant(token) as grant:
            if grant.value("granted") != granted:
                problems.append("the granted value was wrong")
            if grant.has("other"):
                problems.append("the grant covers an entry it does not name")
            try:
                grant.value("other")
                problems.append("the grant read an entry it does not name")
            except PolicyError:
                pass
        with caps.open_grant(token) as grant:
            grant.value("granted")
        path = paths.caps_dir() / f"{info.id}.json"
        try:
            caps.open_grant(token).close()
            problems.append("a used-up grant opened a third time")
        except AuthError:
            pass
        if path.exists():
            problems.append("a used-up grant's file was not destroyed")
        with _clock(61):
            try:
                caps.open_grant(expiring).close()
                problems.append("an expired grant opened")
            except AuthError:
                pass
        if (paths.caps_dir() / f"{expiring_info.id}.json").exists():
            problems.append("an expired grant's file was not destroyed")
    if problems:
        return _failed("; ".join(problems))
    return _passed(
        "a grant read only the value it names, worked for its 2 uses and was destroyed; an expired grant was "
        "refused and destroyed"
    )


def check_grants_hold_no_keys(box: Sandbox) -> CheckResult:
    """A grant opens no session, and a process holding only the grant has no key, password or seed in memory."""
    usable, reason = memscan.supported()
    password = _password()
    seed = base64.b32encode(os.urandom(20)).decode("ascii")
    with box.area("grants-no-keys") as base:
        vault, _recovery = _create(password)
        with vault:
            granted = secrets.token_urlsafe(20)
            entry = vault.add("granted", Secret(password=granted, totp=otp.make_totp(seed)))
            vault.set_alias("GRANTED", entry, "password")
            vault.commit()
            token, _info = caps.create_grant(vault, ["GRANTED", "granted/totp"], ttl=600, uses=3)
            raw_key = bytes(vault.vault_key.view())
        try:
            try:
                caps.open_session(token, VaultFile.load()).wipe()
                return _failed("a grant token opened the vault as a session")
            except AuthError:
                pass
            if not usable:
                return _skipped(f"a grant token cannot open a session; the memory part needs the scanner ({reason})")
            needles = {
                "the vault key": raw_key,
                "the vault key in base64": base64.b64encode(raw_key),
                "the vault key in hex": raw_key.hex().encode("ascii"),
                "the master password": password.encode("utf-8"),
                "the one-time-password seed": seed.encode("ascii"),
                "the one-time-password seed as bytes": base64.b32decode(seed),
            }
            here = dict(_backend_environment(), IRONDOME_HOME=os.environ["IRONDOME_HOME"],
                        IRONDOME_DEVICE_DIR=os.environ["IRONDOME_DEVICE_DIR"])
            document = memory_probe(
                base / "probe", "grant", secret=token, needles=needles, controls={"the granted value": granted},
                environment=here,
            )
        finally:
            wipe_bytes(raw_key)
    found = [needle["label"] for needle in document["needles"] if needle["kind"] == "key" and needle["hits"]]
    seen = [needle["label"] for needle in document["needles"] if needle["kind"] == "value" and needle["hits"]]
    freed = [needle for needle in document["needles"] if needle["kind"] == "control-dropped" and needle["hits"]]
    if found:
        return _failed(f"a process that opened only the grant held {', '.join(found)}")
    if not seen:
        return _failed("the scanner did not see the granted value either, so the memory check proves nothing")
    if not freed:
        return _failed("the scanner missed a copy freed just before it ran, so the memory check proves nothing")
    if not document.get("session_refused"):
        return _failed("inside the probe the grant token opened a session")
    return _passed(
        "a grant token cannot open a session; a process that opened the grant and read its values held no copy of "
        "the vault key (raw, base64, hex), the master password or the one-time-password seed, while the granted "
        "value itself and a copy freed just before the search were found "
        f"({document['stats']['bytes_scanned'] >> 20} MiB of writable memory searched)"
    )


def check_masking(box: Sandbox) -> CheckResult:
    """A secret injected into a command is masked in everything it prints; tokens never reach it."""
    from urllib.parse import quote

    from irondome.agent import runner

    secret = f"mask/{secrets.token_urlsafe(18)}+x=y"
    code = (
        "import base64, os, sys, urllib.parse\n"
        "v = os.environ['PROBE_SECRET']\n"
        "print(v); print(base64.b64encode(v.encode()).decode()); print(v.encode().hex())\n"
        "print(urllib.parse.quote(v, safe='')); print(v[::-1])\n"
        "print(v, file=sys.stderr)\n"
        "names = ('IRONDOME_SESSION', 'IRONDOME_GRANT', 'IRONDOME_PASSWORD_FILE')\n"
        "print('tokens:', [n for n in names if n in os.environ])\n"
    )
    base_env = {
        "PATH": _SAFE_PATH,
        "IRONDOME_SESSION": "irondome_s_" + "0" * 32 + "_" + "A" * 52,
        "IRONDOME_GRANT": "irondome_g_" + "0" * 32 + "_" + "A" * 52,
        "IRONDOME_PASSWORD_FILE": "/nonexistent",
    }
    with box.area("masking") as base:
        result = runner.run_captured([sys.executable, "-I", "-c", code], {"PROBE_SECRET": secret}, base_env=base_env,
                                     cwd=str(base), timeout=60)
    output = result.stdout + result.stderr
    raw = secret.encode()
    forms = {
        "plain": secret,
        "base64": base64.b64encode(raw).decode(),
        "hex": raw.hex(),
        "percent": quote(secret, safe=""),
    }
    leaked = [name for name, form in forms.items() if form in output]
    if result.code != 0:
        return _failed(f"the test command failed with status {result.code}")
    if leaked:
        return _failed(f"the secret was printed unmasked in {', '.join(leaked)} form")
    if "tokens: []" not in result.stdout:
        return _failed("a session or grant token reached the command's environment")
    if secret[::-1] not in result.stdout:
        return _failed("the deliberately reversed secret was not printed, so the boundary was not shown")
    return _passed(
        "the secret was masked in plain, base64, hex and percent-encoded form on stdout and stderr; no session or "
        "grant token reached the command; a deliberately reversed copy got through, as documented"
    )


def check_audit_log(box: Sandbox) -> CheckResult:
    """Every use is logged, and edited, reordered, forged or removed lines are detected."""
    password = _password()
    with box.area("audit-log"):
        vault, _recovery = _create(password)
        with vault:
            vault.add("probe", Secret(password=secrets.token_urlsafe(16)))
            vault.commit()
            with audit.owner_key(vault) as key:
                for action in ("add", "edit", "get"):
                    audit.record(key, vault_id=vault.vault_id, kid=audit.KID_VAULT, action=action, actor="owner",
                                 target="probe")
            token, _info = caps.create_grant(vault, ["probe"], ttl=600, uses=2)
            caps.create_session(vault, ttl=600)
        with caps.open_grant(token) as grant:
            grant.value("probe")
        log = paths.audit_file()
        good = log.read_bytes()
        lines = good.splitlines(keepends=True)
        with _open(password) as vault:
            clean = audit.verify(vault)
            events = audit.read(vault)
            actions = {event.action for event in events}
            kids = {event.kid for event in events}

            def detected(changed: bytes) -> bool:
                log.write_bytes(changed)
                try:
                    return not audit.verify(vault).ok
                finally:
                    log.write_bytes(good)

            middle = len(lines) // 2
            edited = bytearray(lines[middle])
            edited[edited.index(b'"data":"') + 12] ^= 0x01
            forged_line = json.dumps(
                {"data": crypto.b64e(os.urandom(300)), "kid": "vault", "prev": "", "seq": len(lines) + 1, "ts": 1},
                sort_keys=True, separators=(",", ":"),
            ).encode() + b"\n"
            checks = {
                "an edited line": detected(b"".join(lines[:middle] + [bytes(edited)] + lines[middle + 1 :])),
                "two lines swapped": detected(b"".join(lines[:middle] + [lines[middle + 1], lines[middle]]
                                                       + lines[middle + 2 :])),
                "a line removed from the middle": detected(b"".join(lines[:middle] + lines[middle + 1 :])),
                "a forged line": detected(good + forged_line),
            }
            newest_removed_undetected = not detected(b"".join(lines[:-1]))
    missing = [what for what, ok in checks.items() if not ok]
    if not clean.ok:
        return _failed(f"the untouched log did not verify: {'; '.join(clean.problems[:2])}")
    if missing:
        return _failed("not detected: " + ", ".join(missing))
    if not {"grant.create", "grant.use", "session.start"} <= actions or len(kids) < 2:
        return _failed("the grant's creation and use and the session were not all in the log")
    if not newest_removed_undetected:
        return _failed("removing the newest line was reported; the documented boundary no longer matches")
    return _passed(
        f"{clean.count} records verified (owner, grant creation and use under the grant's own key, session); an edited "
        "line, two swapped lines, a removed line and a forged line were each detected; removing the newest line is "
        "not, as documented"
    )


def check_bunkers_isolated(box: Sandbox) -> CheckResult:
    """Two bunkers: separate keys, nothing of one opens the other, removing one leaves the other."""
    passwords = {"alpha": _password(), "bravo": _password()}
    tokens: Dict[str, Dict[str, str]] = {}
    problems = []
    with box.area("bunkers"):
        for name in ("alpha", "bravo"):
            os.environ[paths.ENV_BUNKER] = name
            vault, _recovery = _create(passwords[name])
            with vault:
                vault.add(f"{name}-entry", Secret(password=secrets.token_urlsafe(16)))
                vault.commit()
                session = caps.create_session(vault, ttl=600)
                grant_token, info = caps.create_grant(vault, [f"{name}-entry"], ttl=600, uses=5)
            tokens[name] = {"session": session, "grant": grant_token, "grant_id": info.id}
        device_material = {}
        for name in ("alpha", "bravo"):
            os.environ[paths.ENV_BUNKER] = name
            # Empty files are not material: a TPM bunker keeps an empty lock file beside its registry.
            device_material[name] = {path.read_bytes() for path in _files(paths.device_dir())} - {b""}
        if device_material["alpha"] & device_material["bravo"]:
            problems.append("the two bunkers share device material")
        os.environ[paths.ENV_BUNKER] = "bravo"
        # A wrong password costs one of a TPM's guesses: never spend the user's on a check.
        if box.backend_name != "linux-tpm2" and _refusal(passwords["alpha"]) is None:
            problems.append("alpha's password opened bravo")
        bravo_file = VaultFile.load()
        try:
            caps.open_session(tokens["alpha"]["session"], bravo_file).wipe()
            problems.append("alpha's session opened bravo")
        except AuthError:
            pass
        os.environ[paths.ENV_BUNKER] = "alpha"
        copied_caps = [path for path in paths.caps_dir().glob("*.json")]
        os.environ[paths.ENV_BUNKER] = "bravo"
        for path in copied_caps:
            shutil.copy2(str(path), str(paths.caps_dir() / path.name))
        try:
            caps.open_session(tokens["alpha"]["session"], VaultFile.load()).wipe()
            problems.append("alpha's session file copied into bravo opened bravo")
        except (AuthError, HardwareError):
            pass
        try:
            with caps.open_grant(tokens["alpha"]["grant"]) as grant:
                if grant.has("bravo-entry"):
                    problems.append("alpha's grant copied into bravo covers bravo's entry")
        except (AuthError, HardwareError):
            pass  # a TPM refuses sooner: bravo's registry does not list the index alpha's grant is bound to
        box.guard()
        report = nuke.execute(bunker="bravo")
        if not report.success:
            problems.append("removing bravo did not finish cleanly")
        if "bravo" in paths.bunkers():
            problems.append("bravo is still there after it was removed")
        os.environ[paths.ENV_BUNKER] = "alpha"
        if _refusal(passwords["alpha"]) is not None:
            problems.append("alpha no longer opens after bravo was removed")
        try:
            with caps.open_grant(tokens["alpha"]["grant"]) as grant:
                grant.value("alpha-entry")
        except IronDomeError:
            problems.append("alpha's grant stopped working after bravo was removed")
    if problems:
        return _failed("; ".join(problems))
    return _passed(
        "two bunkers had distinct device secrets; neither alpha's password, nor its session, nor its session and "
        "grant files copied into bravo opened bravo; removing bravo left alpha and its grant working"
    )


def check_recovery(box: Sandbox) -> CheckResult:
    """The recovery key opens a copy of the vault on a machine without this device; it is stored nowhere."""
    password = _password()
    with box.area("recovery") as base:
        vault, recovery = _create(password)
        with vault:
            value = secrets.token_urlsafe(16)
            vault.add("probe", Secret(password=value))
            vault.commit()
        if recovery is None:
            return _failed("a new vault came without a recovery key")
        raw = keys.parse_recovery_key(recovery)
        try:
            bits = len(raw) * 8
            stored = [path.read_bytes() for path in _files(paths.root(), paths.device_root())]
            kept = any(_contains(data, [raw, recovery.encode(), recovery.replace("-", "").encode()]) for data in stored)
        finally:
            wipe_bytes(raw)
        copy = base / "copy"
        _copy_tree(paths.root(), copy)
    with box.area("recovery-elsewhere", other_machine=True):
        _restore_tree(copy, paths.root())
        password_refused = _refusal(password) is not None
        try:
            file = VaultFile.load()
            with Vault(file, unlock.unlock(file, recovery_key=recovery)) as restored:
                readable = restored.value(restored.find("probe")) == value
        except IronDomeError as exc:
            return _failed(f"the recovery key did not open the copy ({_describe_error(exc)})")
        wrong = "".join("A" if char == "B" else ("B" if char.isalpha() else char) for char in recovery)
        try:
            file = VaultFile.load()
            unlock.unlock(file, recovery_key=wrong).wipe()
            wrong_refused = False
        except AuthError:
            wrong_refused = True
    problems = [
        what
        for what, ok in (
            (f"the recovery key has {bits} bits, not 160", bits == 160),
            ("the recovery key is stored in a file", not kept),
            ("the entry read back wrong", readable),
            ("another recovery key was accepted", wrong_refused),
            ("the master password opened the copy without the device", password_refused),
        )
        if not ok
    ]
    if problems:
        return _failed("; ".join(problems))
    return _passed(
        "a 160-bit recovery key, stored in no file, opened a copy of the vault on a machine without this device "
        "and read its entry; another recovery key was refused"
    )


#: macOS zeroes small blocks as they are freed, which would hide a copy some library frees without
#: wiping (glibc never does): one probe runs with that turned off, so the result does not rest on it.
_UNZEROED = {"MallocZeroOnFree": "0"}


def check_keys_wiped(box: Sandbox) -> CheckResult:
    """After the vault is locked, a scan of the whole address space finds no copy of any key."""
    usable, reason = memscan.supported()
    if not usable:
        return _skipped(reason)
    with box.area("keys-wiped") as base:
        password = _password()
        runs: List[Any] = [("keys", password), ("keys-control", password), ("kdf", password, _UNZEROED)]
        if sys.platform == "darwin":
            runs.append(("keys", password, _UNZEROED))
        documents = memory_probes(base, runs, environment=_backend_environment())
        long_derivation = long_password_probe(base / "long", environment=_backend_environment())
    clean, control, derivation = documents[:3]
    return evaluate_keys_probe(
        clean, control, documents[3] if len(documents) > 3 else None, derivation, long_derivation
    )


#: A master password longer than this is one whose copy inside Argon2id was found left behind, in part, when
#: Argon2id was still given the password itself. The check derives from one well beyond it.
_LONG_PASSWORD = 2000
_PART = 16
_FINE = 512
_LABEL_PART = "master password, bytes"


def password_parts(text: str) -> Dict[str, bytes]:
    """An ASCII password cut into the pieces a scan looks for, so that a copy of only some of it is found too.

    The last 512 bytes into pieces of 16: the copy that used to be left was of the end. What comes before
    into pieces of 32, or of 64 in a password longer than 2,048 bytes, to stay within the number of needles a
    probe takes. A scan finds whole pieces: a copy of fewer bytes than two pieces less one (31 at the end,
    up to 127 before it) can lie across a cut and be missed.
    """
    raw = text.encode("ascii")
    coarse = 2 * _PART if len(raw) <= 2048 else 4 * _PART
    cuts = [len(raw)]
    while cuts[-1] > 0:
        step = _PART if len(raw) - cuts[-1] < _FINE else coarse
        cuts.append(max(0, cuts[-1] - step))
    cuts.reverse()
    if len(cuts) > 2 and cuts[1] < memscan.MIN_NEEDLE:  # a first piece too short to search for joins the next
        del cuts[1]
    return {
        f"{_LABEL_PART} {start} to {end}": raw[start:end]
        for start, end in zip(cuts, cuts[1:])
        if end - start >= memscan.MIN_NEEDLE
    }


def long_password_probe(
    directory: Path,
    *,
    length: int = _LONG_PASSWORD,
    environment: Optional[Mapping[str, str]] = None,
    control: bool = False,
) -> Dict[str, Any]:
    """The ``kdf-first`` probe with a master password of *length* random characters, searched for piece by piece.

    One derivation, the first the process makes, as in a command that unlocks
    a vault: that is the one after which a part of a long password was found
    left when Argon2id was given the password itself. Freed memory is left
    unzeroed on macOS, as glibc leaves it.

    With *control* the probe does what IronDome must not (``kdf-control``):
    it gives Argon2id the password. Where the library and the allocator
    leave a part of that copy, this is the run that shows the search would
    find it.
    """
    text = secrets.token_urlsafe(length)[:length]
    own = dict(environment or {})
    own.update(_UNZEROED)
    mode = "kdf-control" if control else "kdf-first"
    return memory_probe(directory, mode, secret=text, needles=password_parts(text), environment=own)


#: The copy the claim's boundary names, by probe label: Argon2id in pyca/cryptography (OpenSSL) copies what
#: it is given into system-malloc memory it frees without overwriting, and IronDome cannot wipe it. What it
#: is given is the 32-byte prehash keys.stretch_password makes of the master password, never the password.
#: A scan that leaves freed memory unzeroed, or one made right after a derivation, may find that copy.
#: Anything else is a failure, a copy of the master password in any form above all: HKDF's copy of the key
#: it derives is overwritten by irondome.crypto.hkdf, which derives again from zeros. (The label is
#: _LABEL_PREHASH, defined with the probe below.)
_ARGON2_INPUT = ("prehash of the master password",)


def _leftovers(document: Dict[str, Any], allowed: Sequence[str] = (), *, only: bool = False) -> List[str]:
    """The key needles with hits, as text: those not in *allowed*, or with *only*, those in it.

    A hit on an *allowed* Argon2id input outside system-malloc memory is not the copy the boundary names,
    and counts as a leftover.
    """
    found = []
    for needle in document["needles"]:
        if needle["kind"] != "key" or not needle["hits"]:
            continue
        expected = needle["label"] in allowed and (
            needle["label"] not in _ARGON2_INPUT or all("MALLOC_" in hit["where"] for hit in needle["hits"])
        )
        if expected == only:
            found.append(
                f"{len(needle['hits'])} cop{'y' if len(needle['hits']) == 1 else 'ies'} of the {needle['label']} "
                f"({', '.join(hit['where'] for hit in needle['hits'][:2])})"
            )
    return found


def evaluate_keys_probe(
    clean: Dict[str, Any],
    control: Dict[str, Any],
    unzeroed: Optional[Dict[str, Any]] = None,
    derivation: Optional[Dict[str, Any]] = None,
    long_derivation: Optional[Dict[str, Any]] = None,
) -> CheckResult:
    """Judge the probe documents of the keys-wiped check.

    *clean* and *control* are the ``keys`` and ``keys-control`` runs;
    *unzeroed* the macOS ``keys`` run without zero-on-free; *derivation* the
    ``kdf`` run, searched right after Argon2id and HKDF; *long_derivation*
    the same with a long master password, searched for piece by piece (see
    :func:`long_password_probe`). Every leftover found in any of them is
    named.
    """
    stats = clean["stats"]
    if not stats["whole_address_space"] or stats["truncated"] or not stats["bytes_scanned"]:
        return _failed("the scan did not cover the whole address space")
    for document in (unzeroed, derivation, long_derivation):
        if document is not None and (document["stats"]["truncated"] or not document["stats"]["bytes_scanned"]):
            return _failed("a scan was cut short, so it proves nothing")
    if long_derivation is not None and not _pieces(long_derivation):
        return _failed("the long master password was not searched for piece by piece, so that scan proves nothing")
    problems = []
    leftovers = _leftovers(clean)
    if leftovers:
        problems.append("after the vault was locked memory still held " + "; ".join(leftovers))
    hidden = _leftovers(unzeroed, _ARGON2_INPUT) if unzeroed is not None else []
    if hidden:
        problems.append(
            "with the system's zeroing of freed memory turned off (MallocZeroOnFree=0), memory still held "
            + "; ".join(hidden)
            + " after the vault was locked: freed without being overwritten"
        )
    made = _leftovers(derivation, _ARGON2_INPUT) if derivation is not None else []
    if made:
        problems.append(
            "right after Argon2id and HKDF, outside the locked buffers that hold them, memory held "
            + "; ".join(made)
        )
    longer = _leftovers(long_derivation, _ARGON2_INPUT) if long_derivation is not None else []
    if longer:
        more = f" and {len(longer) - 3} more" if len(longer) > 3 else ""
        problems.append(
            f"right after Argon2id and HKDF over a master password of {_password_length(long_derivation)} bytes, "
            "outside the locked buffers that hold them, memory held " + "; ".join(longer[:3]) + more
        )
    if problems:
        return _failed(". ".join(problems))
    probes = [clean, control] + [
        document for document in (unzeroed, derivation, long_derivation) if document is not None
    ]
    controls = [needle for document in probes for needle in document["needles"] if needle["kind"].startswith("control")]
    blind = [
        needle["label"]
        for needle in controls
        if not needle["hits"]
        or (needle["expected"] is not None and needle["expected"] not in [hit["address"] for hit in needle["hits"]])
    ]
    kept_vault_key = [needle for needle in control["needles"] if needle["label"] == _LABEL_KEPT_VAULT_KEY]
    keys_checked = sorted({needle["label"] for needle in clean["needles"] if needle["kind"] == "key"})
    if blind or not kept_vault_key:
        missed = ", ".join(blind) or "the vault key"
        return _failed(f"the scanner missed a deliberate copy ({missed}), so it proves nothing")
    also = (
        ", and with the system's zeroing of freed memory turned off none but what Argon2id copies"
        if unzeroed is not None
        else ""
    )
    source = "; right after Argon2id and HKDF, none but what Argon2id copies" if derivation is not None else ""
    if long_derivation is not None:
        source += (
            f", and no part of a master password of {_password_length(long_derivation)} bytes "
            f"({_pieces(long_derivation)} pieces looked for)"
        )
    inside = [
        entry
        for document in (unzeroed, derivation, long_derivation)
        if document is not None
        for entry in _leftovers(document, _ARGON2_INPUT, only=True)
    ]
    named = (
        " (the boundary: copies made inside pyca/cryptography, which IronDome cannot wipe, found this time: "
        + "; ".join(inside)
        + ")"
        if inside
        else ""
    )
    return _passed(
        f"{stats['bytes_scanned'] / 2**30:.1f} GiB in {stats['regions']} regions searched after the vault was locked: "
        f"no copy of any of {len(keys_checked)} keys ({', '.join(keys_checked[:4])}, ...){also}{source}{named}; the "
        "deliberate copies kept or dropped as bytes were all found"
    )


def _pieces(document: Dict[str, Any]) -> int:
    """How many pieces of a long master password a ``kdf-first`` probe recorded and searched for."""
    return sum(
        1
        for needle in document["needles"]
        if needle["kind"] == "key" and needle["label"].startswith(_LABEL_PART) and needle.get("recorded", 1)
    )


def _password_length(document: Optional[Dict[str, Any]]) -> int:
    """The length of the master password a ``kdf`` probe derived from."""
    needles = document["needles"] if document is not None else []
    return max((needle["length"] for needle in needles if needle["label"] == _LABEL_PASSWORD), default=0)


def _backend_environment() -> Dict[str, str]:
    """The variables a probe needs to use the same device backend as the check that starts it."""
    names = ("IRONDOME_DEVICE_BACKEND", "IRONDOME_SE_HELPER", "TPM2TOOLS_TCTI")
    return {name: os.environ[name] for name in names if os.environ.get(name)}


CHECKS: Dict[str, Callable[[Sandbox], CheckResult]] = {
    "device_bound": check_device_bound,
    "key_in_hardware": check_key_in_hardware,
    "biometric_enforced": check_biometric_enforced,
    "crypto_erase": check_crypto_erase,
    "keys_wiped": check_keys_wiped,
    "everything_encrypted": check_everything_encrypted,
    "tamper_evident": check_tamper_evident,
    "modern_crypto": check_modern_crypto,
    "no_network": check_no_network,
    "one_dependency": check_one_dependency,
    "owner_only_files": check_owner_only_files,
    "grants_are_scoped": check_grants_are_scoped,
    "grants_hold_no_keys": check_grants_hold_no_keys,
    "masking": check_masking,
    "audit_log": check_audit_log,
    "bunkers_isolated": check_bunkers_isolated,
    "recovery": check_recovery,
}


# ---------------------------------------------------------------------------
# Running them
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Report:
    """What :func:`run` found: one :class:`Outcome` per claim, and which device backend the checks used."""

    outcomes: List[Outcome]
    backend: str
    hardware: bool
    backend_detail: str
    notes: List[str]

    def count(self, status: str) -> int:
        return sum(1 for outcome in self.outcomes if outcome.result.status == status)


def run(
    claims: Optional[Sequence[str]] = None,
    *,
    touch: bool = False,
    progress: Optional[Callable[[str], None]] = None,
    root: Optional[Path] = None,
) -> Report:
    """Run the check of every claim (or of the claims named), in one sandbox. Never raises for a failed check.

    *touch* allows the one Touch ID prompt of the biometric check. *progress*
    is called with a line before each check. *root* is where the private
    temporary directory is made (default: the system's temporary directory).
    Raises :class:`UsageError` for a claim id the registry does not have.
    """
    document = registry()
    known = [claim["id"] for claim in document["claims"]]
    wanted = list(claims) if claims else known
    unknown = [claim for claim in wanted if claim not in known]
    if unknown:
        raise UsageError(f"no claim is called {', '.join(unknown)}; the claims are: {', '.join(known)}")
    outcomes: List[Outcome] = []
    with Sandbox(touch=touch, root=root) as box:
        for claim in document["claims"]:
            if claim["id"] not in wanted:
                continue
            name = claim.get("selfcheck")
            started = time.monotonic()
            if name is None:
                result = _skipped("no check of its own runs on a user's machine; the test suite covers it")
            elif name not in CHECKS:
                result = _failed(f"the registry names a check {name!r} that this version does not have")
            else:
                if progress is not None:
                    progress(f"checking {claim['id']}")
                result = _guarded(CHECKS[name], box)
            outcomes.append(
                Outcome(claim=claim["id"], title=claim["title"], check=name, result=result,
                        seconds=round(time.monotonic() - started, 2))
            )
        return Report(
            outcomes=outcomes,
            backend=box.backend_name,
            hardware=box.hardware,
            backend_detail=box.backend_note,
            notes=list(box.notes),
        )


def _guarded(check: Callable[[Sandbox], CheckResult], box: Sandbox) -> CheckResult:
    try:
        return check(box)
    except SandboxError as exc:
        return _failed(f"stopped before it could leave its temporary directory: {exc}")
    except IronDomeError as exc:
        return _failed(_describe_error(exc))
    except Exception as exc:  # a check that breaks is a failed check, reported, never a crashed command
        return _failed(f"the check itself failed: {_describe_error(exc)}")


# ---------------------------------------------------------------------------
# Memory probes: fresh interpreters that search their own memory
# ---------------------------------------------------------------------------

_LABEL_PASSWORD = "master password"  # noqa: S105 - a label, not a credential
_LABEL_NORMALISED = "master password as normalised"
_LABEL_PREHASH = "prehash of the master password"
_LABEL_ARGON2 = "Argon2id output"
_LABEL_HKDF = "HKDF output"
_LABEL_HKDF_EXTRACTED = "key HKDF extracts"
_KDF_INFO = b"irondome/v4/probe/kdf\x00"
_LABEL_DEVICE = "device secret"
_LABEL_VAULT_KEY = "vault key"
_LABEL_KEPT = "random key kept as bytes"
_LABEL_DROPPED = "random key dropped as bytes"
_LABEL_KEPT_VAULT_KEY = "vault key kept as bytes"
_LABEL_BASE64 = "base64 of"
_LABEL_RECOVERY = "recovery key"
_LABEL_RECOVERY_TEXT = "recovery key as written down"
_LABEL_RECOVERY_UNDASHED = "recovery key without its dashes"
_RECOVERY_INFO = b"irondome/v4/recovery"  # the HKDF label that turns the recovery key into its keyslot's subkey
_GRANT_AUDIT = b"irondome/v4/audit/grant\x00"
_ENTRY_VALUE = "an ordinary entry value"
_PROBE_CAPACITY = 96

_INFO_LABELS = (
    (b"irondome/v4/password", _LABEL_PREHASH),
    (b"irondome/v4/kek/password/", "key-encryption key of the password keyslot"),
    (b"irondome/v4/kek/device/", "key-encryption key of the Touch ID keyslot"),
    (b"irondome/v4/kek/recovery/", "key-encryption key of the recovery keyslot"),
    (b"irondome/v4/device-auth", "device authorisation value"),
    (b"irondome/v4/device/", "device key"),
    (b"irondome/v4/recovery", "recovery-slot subkey"),
    (b"irondome/v4/index", "index key"),
    (b"irondome/v4/entry\x00", "entry key"),
    (b"irondome/v4/audit/grant\x00", "audit key of a grant"),
    (b"irondome/v4/audit/record", "audit sealing key"),
    (b"irondome/v4/audit", "audit owner key"),
    (b"irondome/v4/cap/device", "capability device key"),
    (b"irondome/v4/cap/session/", "session wrapping key"),
    (b"irondome/v4/cap/grant/", "grant wrapping key"),
)


def _info_label(info: bytes) -> str:
    for prefix, label in _INFO_LABELS:
        if info.startswith(prefix):
            return label
    return "subkey " + info.decode("ascii", "replace")


def _masked_needle(label: str, data: bytes, kind: str) -> Dict[str, str]:
    pad = bytes(byte or 0xA5 for byte in os.urandom(len(data)))
    return {"label": label, "kind": kind, "masked": bytes(a ^ b for a, b in zip(data, pad)).hex(), "pad": pad.hex()}


def _text_forms(label: str, text: str) -> Dict[str, bytes]:
    """The forms a text takes in memory: UTF-8, and CPython's own storage of the str."""
    forms = {label: text.encode("utf-8")}
    widest = max(map(ord, text)) if text else 0
    if widest >= 0x80:
        codec = "latin-1" if widest < 0x100 else ("utf-16-le" if widest < 0x10000 else "utf-32-le")
        forms[f"{label} as stored in a str"] = text.encode(codec)
    return forms


def _add_recovery_text(table: memscan.NeedleTable, text: str) -> None:
    """Record a recovery key as written down and without its dashes, and leave no copy of either behind.

    Its characters are ASCII, so these are also the bytes of the ``str`` that
    holds it. They are copied one at a time into buffers that are zeroed
    once the table has its masked copies.
    """
    written = bytearray(len(text))
    undashed = bytearray(len(text) - text.count("-"))
    try:
        count = 0
        for position, char in enumerate(text):  # one-character strings: shared by the interpreter, no copy
            written[position] = ord(char)
            if char != "-":
                undashed[count] = ord(char)
                count += 1
        table.add(written, _LABEL_RECOVERY_TEXT)
        if len(undashed) != len(written):
            table.add(undashed, _LABEL_RECOVERY_UNDASHED)
    finally:
        wipe_bytes(written)
        wipe_bytes(undashed)


def _probe_command(mode: str) -> List[str]:
    package_parent = str(Path(__file__).resolve().parent.parent)
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from irondome.selftest import probe_main; probe_main(sys.argv[2])"
    )
    return [sys.executable, "-I", "-c", code, package_parent, mode]


def _probe_environment(directory: Path, environment: Mapping[str, str]) -> Dict[str, str]:
    """A minimal environment: the probe's own directories unless *environment* names a vault to use."""
    allowed = ("IRONDOME_DEVICE_BACKEND", "IRONDOME_SE_HELPER", "TPM2TOOLS_TCTI", "IRONDOME_HOME",
               "IRONDOME_DEVICE_DIR", "MallocZeroOnFree", "LANG", "LC_ALL")
    env = {
        "IRONDOME_HOME": str(directory / "irondome"),
        "IRONDOME_DEVICE_DIR": str(directory / "device"),
    }
    env.update({name: value for name, value in environment.items() if name in allowed})
    env.update(
        {
            "PATH": _SAFE_PATH,
            "HOME": str(directory / "home"),
            "TMPDIR": str(directory / "tmp"),
            "IRONDOME_LEGACY_DIR": str(directory / "legacy"),
            "IRONDOME_NO_TOUCH": "1",
            "IRONDOME_NO_PROMPT": "1",
            "IRONDOME_DEBUG": "1",  # Linux: a non-dumpable process could not open its own /proc/self/mem
            "IRONDOME_KDF_MEMORY_MIB": _MIN_KDF_MIB,
        }
    )
    return env


def _start_probe(
    directory: Path,
    mode: str,
    *,
    secret: str,
    needles: Mapping[str, bytes],
    controls: Mapping[str, str],
    environment: Mapping[str, str],
) -> Tuple["subprocess.Popen[bytes]", bytes]:
    for sub in ("home", "tmp"):
        (directory / sub).mkdir(parents=True, exist_ok=True, mode=0o700)
    extra = [_masked_needle(label, data, "key") for label, data in needles.items() if len(data) >= memscan.MIN_NEEDLE]
    for label, text in controls.items():
        extra.extend(_masked_needle(name, data, "value") for name, data in _text_forms(label, text).items())
    if mode.startswith("keys") or mode.startswith("kdf"):
        extra.extend(_masked_needle(name, data, "key") for name, data in _text_forms(_LABEL_PASSWORD, secret).items())
        normalised = unicodedata.normalize("NFKC", secret)
        if normalised != secret:
            for name, data in _text_forms(_LABEL_NORMALISED, normalised).items():
                extra.append(_masked_needle(name, data, "key"))
    request = (json.dumps({"needles": extra}) + "\n" + secret + "\n").encode("utf-8")
    process = subprocess.Popen(
        _probe_command(mode),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_probe_environment(directory, environment),
        cwd=str(directory),
    )
    return process, request


def _finish_probe(process: "subprocess.Popen[bytes]", request: bytes, timeout: float) -> Dict[str, Any]:
    try:
        out, err = process.communicate(request, timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise HardwareError(f"the memory probe did not finish within {int(timeout)} seconds") from None
    if process.returncode != 0:
        tail = err.decode("utf-8", "replace").strip().splitlines()[-3:]
        raise VaultError(f"the memory probe failed (status {process.returncode}): {' | '.join(tail)}")
    try:
        document = json.loads(out.decode("utf-8"))
    except ValueError:
        raise VaultError("the memory probe printed something that is not its report") from None
    if not isinstance(document, dict) or not isinstance(document.get("needles"), list):
        raise VaultError("the memory probe's report is incomplete")
    return document


def memory_probe(
    directory: Path,
    mode: str,
    *,
    secret: str,
    needles: Optional[Mapping[str, bytes]] = None,
    controls: Optional[Mapping[str, str]] = None,
    environment: Optional[Mapping[str, str]] = None,
    timeout: float = _PROBE_TIMEOUT,
) -> Dict[str, Any]:
    """Run one probe process and return its report.

    *mode* ``keys``: a vault is created with the master password *secret*,
    used, closed, reopened with the password and once with its recovery key,
    with a session and a grant, then locked; the probe records every key the
    kernel makes (the recovery key also as written down and without its
    dashes) and searches its whole address space. The recovery key's text is
    zeroed once it has been used, as the caller it was shown to is to do with
    it. ``keys-control`` does the same but deliberately keeps a ``bytes``
    copy of the vault key. ``grant``: *secret* is a grant token; the probe
    opens it, reads every value and searches its writable memory. ``kdf``:
    the master password *secret* is normalised, its prehash made with HKDF,
    that stretched with Argon2id and expanded with HKDF, twice, and the
    writable memory is searched right after the second time, the five live
    buffers left out: what the derivation itself leaves behind.
    ``kdf-first``: the same done once, the first derivation the process
    makes, and searched at once. ``kdf-control``: as ``kdf-first``, but
    Argon2id is given the password itself, which IronDome never does: the
    control that shows what that search finds.

    *needles* are further secrets to search for (sent masked), *controls*
    values that must be found (in grant mode, what the grant hands out).
    The probe's directories are under *directory*; *environment* may name
    the device backend (``IRONDOME_DEVICE_BACKEND``, ``IRONDOME_SE_HELPER``,
    ``TPM2TOOLS_TCTI``). The report is a dict: ``mode``, ``backend``,
    ``python``, ``stats`` (see :meth:`irondome.memscan.ScanResult.stats`) and
    ``needles``: label, kind (``key``, ``value``, ``control-kept``,
    ``control-dropped``), length, how often it was recorded, ``hits``
    (address and where) and the ``expected`` address of a kept control.
    """
    return memory_probes(directory, [(mode, secret)], needles=needles, controls=controls, environment=environment,
                         timeout=timeout)[0]


def memory_probes(
    directory: Path,
    runs: Sequence[Union[Tuple[str, str], Tuple[str, str, Mapping[str, str]]]],
    *,
    needles: Optional[Mapping[str, bytes]] = None,
    controls: Optional[Mapping[str, str]] = None,
    environment: Optional[Mapping[str, str]] = None,
    timeout: float = _PROBE_TIMEOUT,
) -> List[Dict[str, Any]]:
    """Run several probes at the same time; their reports in the same order.

    Each run is ``(mode, secret)``, or ``(mode, secret, variables)`` with
    variables of its own on top of *environment* (the same few names
    :func:`memory_probe` passes on).
    """
    started = []
    try:
        for index, run in enumerate(runs):
            mode, secret, *variables = run
            own: Dict[str, str] = dict(environment or {})
            for extra in variables:
                own.update(extra)
            place = directory / f"{index}-{mode}"
            place.mkdir(parents=True, exist_ok=True, mode=0o700)
            started.append(
                _start_probe(place, mode, secret=secret, needles=needles or {}, controls=controls or {},
                             environment=own)
            )
        results: List[Optional[Dict[str, Any]]] = [None] * len(started)
        errors: List[BaseException] = []

        def finish(index: int) -> None:
            try:
                results[index] = _finish_probe(started[index][0], started[index][1], timeout)
            except BaseException as exc:  # handed to the caller below
                errors.append(exc)

        threads = [threading.Thread(target=finish, args=(index,), daemon=True) for index in range(len(started))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        if errors:
            raise errors[0]
        return [result for result in results if result is not None]
    finally:
        for process, _request in started:
            if process.poll() is None:
                process.kill()
                process.wait()


def _read_line(fd: int) -> bytes:
    """One line of text from *fd*, read a byte at a time so nothing after it is consumed."""
    raw = io.FileIO(fd, "rb", closefd=False)
    line = bytearray()
    while len(line) < 16 << 20:
        byte = raw.read(1)
        if not byte or byte == b"\n":
            return bytes(line)
        line += byte
    raise UsageError("the probe's request line is too long")


def probe_main(mode: str) -> None:
    """The probe process (see :func:`memory_probe`). Prints its report as JSON."""
    if mode not in ("keys", "keys-control", "grant", "kdf", "kdf-first", "kdf-control"):
        raise SystemExit(f"unknown probe mode {mode!r}")
    request = json.loads(_read_line(0).decode("utf-8"))
    # Everything the end of the probe needs is made now: from the end of the work to the last page
    # read, an allocation could land on a freed block that holds a copy of a key.
    scanner = memscan.open_scanner(capacity=_PROBE_CAPACITY)
    scan = scanner.scan
    collect = gc.collect
    derives = mode.startswith("kdf")
    writable_only = mode == "grant" or derives
    skip: List[List[int]] = [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0]]  # live buffers the kdf scan leaves out
    live: List[Any] = [None, None, None, None, None]
    table = memscan.NeedleTable(capacity=_PROBE_CAPACITY, size=128 * 1024)
    # The control run does all the same work, but searches only for its deliberate copies.
    scanned = memscan.NeedleTable(capacity=8, size=4096) if mode == "keys-control" else table
    kinds: Dict[int, str] = {}
    expected: Dict[int, int] = {}
    for needle in request["needles"]:
        index = table.add_masked(bytes.fromhex(needle["masked"]), bytes.fromhex(needle["pad"]), needle["label"])
        if scanned is table:
            kinds.setdefault(index, needle["kind"])
    dropped = bytearray(os.urandom(32))
    kinds[scanned.add(dropped, _LABEL_DROPPED)] = "control-dropped"
    # The control: a copy freed, without being overwritten, just before the scan. It is made now:
    # made after the work, it would take the block of the last key copy freed in its size class.
    plain = bytes(dropped)
    keep: List[Any] = []
    session_refused = None
    if mode == "grant":
        backend_name, session_refused = _probe_grant(keep)
    elif derives:
        backend_name = "none"
        _probe_kdf(table, live, skip, twice=mode == "kdf", direct=mode == "kdf-control")
    else:
        backend_name = _probe_keys(table, scanned, kinds, expected, keep, keep_vault_key=mode == "keys-control")
    position = 0
    while position < 32:
        dropped[position] = 0
        position += 1
    del plain
    if not derives:  # a collection runs finalizers, and those allocate: the kdf scan must follow at once
        collect()
    result = scan(scanned, exclude=skip if derives else (), writable_only=writable_only)
    for buffer in live:
        if buffer is not None:
            buffer.wipe()
    report = []
    for index in range(scanned.count):
        label = scanned.labels[index]
        if isinstance(label, tuple):
            label = f"{label[0]} the {_info_label(label[1])}"
        elif isinstance(label, bytes):
            label = _info_label(label)
        report.append(
            {
                "label": label,
                "kind": kinds.get(index, "key"),
                "length": scanned.length(index),
                "recorded": scanned.seen[index],
                "expected": expected.get(index),
                "hits": [{"address": address, "where": memscan.describe_address(address)}
                         for address in result.hits[index]],
            }
        )
    scanner.close()
    document = {
        "mode": mode,
        "backend": backend_name,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "stats": result.stats(),
        "session_refused": session_refused,
        "needles": report,
    }
    del keep
    if mode.startswith("keys"):  # the probe's own vault: a TPM keeps NV indices after their files are gone
        nuke.execute()
    sys.stdout.write(json.dumps(document) + "\n")
    sys.stdout.flush()


def _probe_keys(
    table: memscan.NeedleTable,
    controls: memscan.NeedleTable,
    kinds: Dict[int, str],
    expected: Dict[int, int],
    keep: List[Any],
    *,
    keep_vault_key: bool,
) -> str:
    """Wrap the kernel's key producers, then create, use, lock and reopen a vault. Returns the backend name.

    Every key goes into *table*; the deliberate copies into *controls*, with
    their kind and the address they must be found at in *kinds* and
    *expected*. The recovery key is recorded as the 160-bit secret it is
    (whatever HKDF is given to make the recovery-slot subkey: when the key
    is made, and when it is decoded again to open the vault) and as the text
    a person writes down and types back; the vault is opened with it once,
    last of all, and its text is then zeroed, as the caller it was shown to
    is to do.
    """
    original_argon2id, original_hkdf = crypto.argon2id, crypto.hkdf
    original_new_vault_key, original_normalise = keys.new_vault_key, keys.normalise_password

    def argon2id(password: Any, salt: bytes, params: crypto.Argon2Params) -> SecureBuffer:
        out = original_argon2id(password, salt, params)
        table.add(out, _LABEL_ARGON2)
        return out

    def hkdf(ikm: Any, info: bytes, salt: Optional[bytes] = None, length: int = crypto.KEY_LEN) -> SecureBuffer:
        if info == _RECOVERY_INFO:  # the recovery key itself, as made and as decoded from what was typed
            table.add(ikm, _LABEL_RECOVERY)
        out = original_hkdf(ikm, info, salt, length)
        table.add(out, info)
        if info.startswith(_GRANT_AUDIT):  # a grant carries this key in base64 text: look for that too
            text = base64.b64encode(out.view())
            table.add(text, (_LABEL_BASE64, info))
            wipe_bytes(text)
        return out

    def new_vault_key() -> SecureBuffer:
        out = original_new_vault_key()
        table.add(out, _LABEL_VAULT_KEY)
        return out

    def normalise_password(password: Any) -> SecureBuffer:
        out = original_normalise(password)
        table.add(out, _LABEL_NORMALISED)
        return out

    replacements = (
        ("argon2id", original_argon2id, argon2id),
        ("hkdf", original_hkdf, hkdf),
        ("new_vault_key", original_new_vault_key, new_vault_key),
        ("normalise_password", original_normalise, normalise_password),
    )
    for name in sorted(sys.modules):
        module = sys.modules[name]
        if module is None or not (name == "irondome" or name.startswith("irondome.")):
            continue
        for attribute, original, replacement in replacements:
            if getattr(module, attribute, None) is original:
                setattr(module, attribute, replacement)
    backend = devices.choose_backend(POLICY_DEVICE)
    backend_class = type(backend)
    original_enroll, original_unseal = backend_class.enroll, backend_class.unseal

    def enroll(self: Any, *, policy: str, auth: Optional[SecureBuffer], reason: str) -> Any:
        descriptor, secret = original_enroll(self, policy=policy, auth=auth, reason=reason)
        table.add(secret, _LABEL_DEVICE)
        return descriptor, secret

    def unseal(self: Any, descriptor: Dict[str, Any], *, auth: Optional[SecureBuffer], interactive: bool,
               reason: str) -> SecureBuffer:
        secret = original_unseal(self, descriptor, auth=auth, interactive=interactive, reason=reason)
        table.add(secret, _LABEL_DEVICE)
        return secret

    backend_class.enroll = enroll  # type: ignore[method-assign]
    backend_class.unseal = unseal  # type: ignore[method-assign]

    control = SecureBuffer.random(32)
    index = controls.add(control, _LABEL_KEPT)
    kinds[index] = "control-kept"
    kept = bytes(control.view())
    control.wipe()
    keep.append(kept)
    expected[index] = id(kept) + bytes.__basicsize__ - 1

    password = read_secret_from_fd(0)
    if password is None:
        raise SystemExit("no master password on the probe's input")
    recovery: Optional[str] = None
    try:
        table.add(password, _LABEL_PASSWORD)
        vault, recovery = unlock.create_vault(password=password)
        if recovery is not None:
            _add_recovery_text(table, recovery)
        if keep_vault_key:
            copy = bytes(vault.vault_key.view())
            keep.append(copy)
            index = controls.add(copy, _LABEL_KEPT_VAULT_KEY)
            controls.labels[index] = _LABEL_KEPT_VAULT_KEY
            kinds[index] = "control-kept"
            expected[index] = id(copy) + bytes.__basicsize__ - 1
        with vault:
            vault.add("probe", Secret(password=_ENTRY_VALUE), username="someone")
            vault.commit()
        with unlock.open_vault(password=password, interactive=False, allow_touch=False) as again:
            if again.value(again.find("probe")) != _ENTRY_VALUE:
                raise SystemExit("the probe read back the wrong value")
            session = caps.create_session(again, ttl=600)
            grant, _info = caps.create_grant(again, ["probe"], ttl=600, uses=2)
    finally:
        password.wipe()
    try:
        file = VaultFile.load()
        with Vault(file, caps.open_session(session, file)) as through_session:
            through_session.value(through_session.find("probe"))
        with caps.open_grant(grant) as opened:
            opened.value("probe")
        caps.end_sessions(session)
        if recovery is None:
            raise SystemExit("the probe's vault came without a recovery key")
        file = VaultFile.load()
        with Vault(file, unlock.unlock(file, recovery_key=recovery)) as rescued:
            if rescued.value(rescued.find("probe")) != _ENTRY_VALUE:
                raise SystemExit("the recovery key read back the wrong value")
    finally:
        if recovery is not None:
            _wipe_str(recovery)  # the caller's part: the text has been shown, and used
    return backend.name


def _probe_grant(keep: List[Any]) -> Tuple[str, bool]:
    """Open the grant whose token is the second input line and read every value. Returns (backend, session refused).

    The values go into *keep*, held until the scan as an agent holds what it
    uses: the scan must find them (they are its positive control), and a
    value dropped at once would be found or not depending on whether some
    later allocation happened to reuse its block.
    """
    token = _read_line(0).decode("ascii")
    backend = devices.choose_backend(POLICY_DEVICE)
    try:
        caps.open_session(token, VaultFile.load()).wipe()
        refused = False
    except AuthError:
        refused = True
    with caps.open_grant(token) as grant:
        for reference in grant.names():
            keep.append(grant.value(reference))
    del token
    return backend.name, refused


def _probe_kdf(
    table: memscan.NeedleTable, live: List[Any], skip: List[List[int]], *, twice: bool = True, direct: bool = False
) -> None:
    """Derive keys the way an unlock does, from the master password on the second input line.

    HKDF makes the prehash of the normalised password, Argon2id stretches
    the prehash, HKDF expands the result: the steps of
    :func:`irondome.keys.stretch_password` and of what follows it, taken
    one at a time so that each value can be looked for.

    Twice. The first time records what to look for; the scan follows the
    second time at once, so whatever those calls leave behind is still where
    they left it. The five buffers that legitimately hold the secrets (the
    password, as read and as normalised, its prehash and the two keys) stay
    alive in *live* and are left out of the scan through *skip*, both made
    by the caller before the work, so that filling them makes nothing.

    Without *twice* (the ``kdf-first`` probe) the derivation is made once,
    the first of the process, as a command that unlocks a vault makes it,
    and what it made is recorded from the live buffers afterwards. What the
    library leaves behind can differ between its first run in a process and
    a later one: the first is when it sets itself up, and it is the run
    after which the tail of a long password was found left, when Argon2id
    was still given the password. The caller has the password's pieces in
    the table already.

    *direct* (the ``kdf-control`` probe) is the control of that search: it
    gives Argon2id the normalised password instead of the prehash, which is
    what :func:`irondome.keys.stretch_password` exists to avoid.
    """
    password = read_secret_from_fd(0)
    if password is None:
        raise SystemExit("no master password on the probe's input")
    salt = os.urandom(crypto.SALT_LEN)
    params = crypto.default_argon2()
    table.add(password, _LABEL_PASSWORD)
    if twice:
        with keys.normalise_password(password) as fed:
            table.add(fed, _LABEL_NORMALISED)
            with crypto.hkdf(fed, keys._LABEL_PASSWORD, salt) as prehash:
                table.add(prehash, _LABEL_PREHASH)
                with crypto.argon2id(prehash, salt, params) as stretched:
                    table.add(stretched, _LABEL_ARGON2)
                    with crypto.hkdf(stretched, _KDF_INFO, salt) as derived:
                        table.add(derived, _LABEL_HKDF)
                    # What HKDF extracts from its input before it expands it (RFC 5869: HMAC of the input under
                    # the salt). Made here only to be looked for; made a second time from zeros, as crypto.hkdf
                    # does, so that what computing it left behind is not what the scan finds.
                    extracted = hmac.digest(salt, stretched.view(), "sha256")
                    table.add(extracted, _LABEL_HKDF_EXTRACTED)
                    wipe_bytes(extracted)
                    wipe_bytes(hmac.digest(salt, bytes(len(stretched)), "sha256"))
    live[0] = password
    live[1] = keys.normalise_password(password)
    live[2] = crypto.hkdf(live[1], keys._LABEL_PASSWORD, salt)
    if direct:
        # The control has to leave the library's copy where the search can see it: in this process, which is
        # where Argon2id ran before the work was given to a child.
        live[3] = SecureBuffer(crypto.KEY_LEN)
        crypto._stretch_here(as_view(live[1]), salt, params, live[3])
    else:
        live[3] = crypto.argon2id(live[2], salt, params)
    live[4] = crypto.hkdf(live[3], _KDF_INFO, salt)
    if not twice:
        table.add(live[1], _LABEL_NORMALISED)
        table.add(live[2], _LABEL_PREHASH)
        table.add(live[3], _LABEL_ARGON2)
        table.add(live[4], _LABEL_HKDF)
    index = 0
    while index < 5:
        skip[index][0] = live[index]._address
        skip[index][1] = live[index]._length
        index += 1
