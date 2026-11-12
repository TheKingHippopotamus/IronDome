"""``irondome doctor``: what this machine offers IronDome, and what is wrong with this installation.

:func:`collect` returns one report as a plain dict (it is what ``irondome
doctor --json`` prints). Building it changes nothing: no vault is unlocked,
no password is asked for, no Touch ID prompt can appear, nothing is compiled
and no file is written. Reading the vault file's public header (generation,
keyslots) needs no key.

Every check ends in *findings*, each with a severity and, unless it is fine,
a one-line remedy:

``ok``       checked and fine
``note``     worth knowing; nothing is wrong
``warning``  weaker than it should be, or something to fix soon
``problem``  broken, or exposed: fix it before relying on the vault

What it reports: the IronDome, Python, cryptography and OpenSSL versions;
the platform; each device backend's probe and the one a new vault would use;
the current bunker's vault, its generation and keyslots and whether their
device keys are on this machine; file and directory modes under the vault
and device directories; whether memory locking works and core dumps are off;
the clipboard tool; the TPM's dictionary-attack counters when the TPM is in
use; the Secure Enclave helper's build state and the SHA-256 of its source;
sessions and grants on disk; an IronDome 3.x vault waiting to be migrated.

Limits: the Secure Enclave is only probed when its helper is already
compiled, because compiling it is a side effect (it happens the first time a
vault uses the chip). Until then the report says so and does not guess which
backend a new vault would get, unless the helper cannot be built here at all
(no Xcode Command Line Tools, or ``IRONDOME_SE_HELPER`` naming nothing): then
it is the strongest other backend, and the report says why no chip holds the
key. Modes are checked on POSIX systems only.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from irondome import __version__, caps, paths
from irondome import device as devices
from irondome.device.base import POLICY_DEVICE
from irondome.errors import IronDomeError, UsageError
from irondome.keys import KIND_RECOVERY
from irondome.secmem import SecureBuffer
from irondome.vault import VaultFile, vault_exists

__all__ = ["SEVERITIES", "versions", "collect", "has_problem"]

SEVERITIES = ("ok", "note", "warning", "problem")

_SE = "macos-se"
_TPM = "linux-tpm2"
_SOFTWARE = "software"
#: A tree with more entries than this is not walked any further.
_MAX_WALK = 10000
_PR_GET_DUMPABLE = 3


class _Findings:
    def __init__(self) -> None:
        self.items: List[Dict[str, str]] = []

    def add(self, severity: str, check: str, message: str, remedy: str = "") -> None:
        self.items.append({"severity": severity, "check": check, "message": message, "remedy": remedy})


def versions() -> Dict[str, str]:
    """``{"irondome", "python", "cryptography", "openssl"}``: what this IronDome runs on."""
    import cryptography

    try:
        from cryptography.hazmat.backends.openssl import backend

        openssl = str(backend.openssl_version_text())
    except Exception:  # an unusual build of cryptography; the version is a detail, not a requirement
        openssl = "unknown"
    return {
        "irondome": __version__,
        "python": platform.python_version(),
        "cryptography": str(cryptography.__version__),
        "openssl": openssl,
    }


def has_problem(report: Dict[str, Any]) -> bool:
    return any(item.get("severity") == "problem" for item in report.get("findings", []))


# ---------------------------------------------------------------------------
# Platform and device backends
# ---------------------------------------------------------------------------


def _platform() -> Dict[str, str]:
    name = platform.system()
    if sys.platform == "darwin":
        name = f"macOS {platform.mac_ver()[0]}".strip()
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "name": name,
        "implementation": platform.python_implementation(),
    }


def _helper(findings: _Findings) -> Optional[Dict[str, Any]]:
    """The Secure Enclave helper: where it is, whether it is compiled, what its source hashes to. None off macOS."""
    if sys.platform != "darwin":
        return None
    from irondome.device import macos_se

    status = macos_se.helper_status()  # compiles nothing, runs no helper, shows no prompt
    state: Dict[str, Any] = {
        key: status[key] for key in ("source", "source_sha256", "path", "built", "from_environment", "compiler")
    }
    if status["error"] is not None:
        state.update(source_sha256=None, path=None, built=False, compiler=None)
        findings.add(
            "problem", "secure-enclave-helper",
            f"the Secure Enclave helper source {status['source']} cannot be read ({status['error']})",
            "reinstall IronDome",
        )
        return state
    helper = state["path"]
    if state["built"]:
        findings.add("ok", "secure-enclave-helper", f"the Secure Enclave helper is compiled ({helper})")
        return state
    if state["from_environment"]:
        findings.add(
            "problem", "secure-enclave-helper", f"IRONDOME_SE_HELPER names {helper}, which does not exist",
            "point IRONDOME_SE_HELPER at the compiled helper, or unset it",
        )
        return state
    if state["compiler"]:
        findings.add(
            "note", "secure-enclave-helper",
            "the Secure Enclave helper is not compiled yet; it is built from its source the first time a vault uses "
            "the chip, so the Secure Enclave was not probed",
        )
    else:
        findings.add(
            "warning", "secure-enclave-helper",
            "the Secure Enclave cannot be used: its helper is not compiled and the Xcode Command Line Tools, which "
            "compile it, are not installed",
            "run: xcode-select --install",
        )
    return state


def _passive_detail(backend: devices.DeviceBackend) -> str:
    """Why *backend* was not probed, in its own words, found without compiling or running anything."""
    quiet = getattr(backend, "passive_probe", None)
    if callable(quiet):
        return str(quiet().detail)
    return f"{devices.NOT_PROBED}: the Secure Enclave helper is not compiled yet"


def _helper_cannot_be_built(helper: Optional[Dict[str, Any]]) -> bool:
    """True when the Secure Enclave helper is not there and nothing here could build it on first use: no
    compiler (the Xcode Command Line Tools), or IRONDOME_SE_HELPER naming a file that does not exist."""
    return helper is not None and not helper["built"] and (helper["compiler"] is False or helper["from_environment"])


def _probe(name: str, helper: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if name == _SE and helper is not None and not helper["built"]:
        # Not compiled yet, the Xcode Command Line Tools missing, or IRONDOME_SE_HELPER naming nothing: the
        # backend's own reason, so that the remedy is in the row itself.
        try:
            detail = _passive_detail(devices.get_backend(name))
        except Exception as exc:  # a broken backend must not hide the others
            detail = str(exc)
        return {
            "name": name, "available": False, "hardware": True, "biometry": False, "probed": False,
            "detail": detail,
        }
    try:
        probe = devices.get_backend(name).probe()
    except Exception as exc:  # a broken backend must not hide the others
        return {"name": name, "available": False, "hardware": False, "biometry": False, "probed": True,
                "detail": str(exc)}
    return {
        "name": probe.name, "available": bool(probe.available), "hardware": bool(probe.hardware),
        "biometry": bool(probe.biometry), "probed": True, "detail": str(probe.detail),
    }


def _new_vault_backend(
    backends: List[Dict[str, Any]], findings: _Findings, helper: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """What ``devices.choose_backend(POLICY_DEVICE)`` would pick, worked out without its side effects."""
    by_name = {item["name"]: item for item in backends}
    forced = os.environ.get("IRONDOME_DEVICE_BACKEND") or "auto"
    if forced != "auto":
        chosen = by_name.get(forced)
        if chosen is not None and not chosen["probed"]:
            findings.add(
                "note", "device-backend",
                f"IRONDOME_DEVICE_BACKEND forces the {forced} backend for new vaults; it was not probed "
                "because its helper is not compiled yet",
            )
            return forced
        if chosen is None or not chosen["available"]:
            detail = chosen["detail"] if chosen is not None else "there is no backend of that name"
            findings.add(
                "problem", "device-backend",
                f"IRONDOME_DEVICE_BACKEND names {forced}, which is not available ({detail})",
                "unset IRONDOME_DEVICE_BACKEND, or name a backend this machine has",
            )
            return None
        findings.add("note", "device-backend", f"IRONDOME_DEVICE_BACKEND forces the {forced} backend for new vaults")
        return forced
    if _helper_cannot_be_built(helper):
        # The Secure Enclave cannot be used until its helper is there, so the choice is known without a guess.
        try:
            choice = devices.choose(POLICY_DEVICE, "auto", passive=True)  # compiles nothing, shows no prompt
        except IronDomeError as exc:
            findings.add("problem", "device-backend", f"no vault can be created here: {exc}",
                         "check the backend details above")
            return None
        if not choice.hardware:
            findings.add(
                "warning", "device-backend",
                f"no security chip would hold a new vault's device key: {choice.why_no_chip}",
                f"a chip needs {devices.chip_requirements()}",
            )
        return choice.backend.name
    for item in backends:
        if not item["probed"]:
            return None  # a stronger backend is unknown; guessing past it would be wrong
        if item["available"] and devices.get_backend(item["name"]).supports(POLICY_DEVICE):
            return str(item["name"])
    findings.add(
        "problem", "device-backend", "no device backend is available, so no vault can be created here",
        "check the backend details above",
    )
    return None


# ---------------------------------------------------------------------------
# The vault, its keyslots and what is on disk
# ---------------------------------------------------------------------------


def _device_present(slot_device: Dict[str, Any]) -> Optional[bool]:
    try:
        return bool(devices.get_backend(str(slot_device.get("backend"))).exists(slot_device))
    except Exception:  # unknown or unloadable backend, damaged descriptor: not known
        return None


def _vault(bunker: str, hardware: List[str], findings: _Findings) -> Dict[str, Any]:
    path = paths.vault_file()
    state: Dict[str, Any] = {
        "present": vault_exists(path), "path": str(path), "readable": False, "generation": None, "created": None,
        "keyslots": [], "error": None,
    }
    if not state["present"]:
        findings.add(
            "note", "vault", f"there is no vault in bunker {bunker}",
            f"create one with: irondome init{'' if bunker == paths.FIRST_BUNKER else ' --bunker ' + bunker}",
        )
        return state
    try:
        file = VaultFile.load(path)
    except IronDomeError as exc:
        state["error"] = str(exc)
        findings.add(
            "problem", "vault", f"the vault of bunker {bunker} cannot be read: {exc}",
            "restore a snapshot (irondome backup ls) or a portable backup (irondome import)",
        )
        return state
    state.update(readable=True, generation=file.generation, created=file.created)
    missing = 0
    bound = 0
    backends = set()
    for slot in file.slots:
        present = _device_present(slot.device) if slot.device is not None else None
        if slot.device is not None:
            bound += 1
            backends.add(str(slot.device.get("backend")))
            if present is False:
                missing += 1
        state["keyslots"].append(
            {
                "id": slot.id[:12], "kind": slot.kind, "label": slot.label, "description": slot.describe(),
                "backend": slot.backend_name, "policy": slot.policy, "device_key_present": present,
            }
        )
    has_recovery = any(slot.kind == KIND_RECOVERY for slot in file.slots)
    findings.add("ok", "vault", f"bunker {bunker} has a readable vault, generation {file.generation}")
    if bound and missing == bound:
        findings.add(
            "problem", "device-keys", "none of this vault's device keys is on this machine: no keyslot but the "
            "recovery key can open it", "open it with the recovery key, or restore a portable backup",
        )
    elif missing:
        findings.add(
            "warning", "device-keys", f"{missing} of this vault's device keys are missing from this machine",
            "remove the keyslots that no longer open, or re-key: irondome rekey",
        )
    elif bound:
        findings.add("ok", "device-keys", "every device key this vault needs is on this machine")
    if not has_recovery:
        findings.add(
            "note", "recovery", "this vault has no recovery key: if this machine's chip fails, nothing else opens it",
            "add one with: irondome recovery",
        )
    if _SOFTWARE in backends and hardware:
        findings.add(
            "warning", "device-keys",
            f"this vault's device key is a file (software backend), but this machine has {', '.join(hardware)}",
            "move it into the chip with: irondome rekey",
        )
    return state


def _mode_text(mode: int) -> str:
    return format(stat.S_IMODE(mode), "04o")


def _walk(top: Path, found: List[Path]) -> None:
    """*top* and everything below it, never following a link and never more than _MAX_WALK entries."""
    pending = [top]
    while pending and len(found) < _MAX_WALK:
        current = pending.pop()
        found.append(current)
        try:
            with os.scandir(str(current)) as listing:
                for item in listing:
                    if item.is_dir(follow_symlinks=False):
                        pending.append(Path(item.path))
                    else:
                        found.append(Path(item.path))
        except OSError:
            continue  # not a directory, or unreadable: its own mode is still checked


def _permissions(findings: _Findings) -> Dict[str, Any]:
    if os.name != "posix":
        findings.add("note", "permissions", "file modes are not checked on this operating system")
        return {"checked": 0, "loose": []}
    device_side = [paths.device_root()]
    vault_side = [paths.root()]
    candidates: List[Path] = []
    for top in vault_side + device_side:
        if os.path.lexists(str(top)):
            _walk(top, candidates)
    me = os.getuid()
    loose: List[Dict[str, Any]] = []
    checked = 0
    for path in sorted(set(candidates)):
        try:
            info = os.lstat(str(path))
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            continue
        checked += 1
        directory = stat.S_ISDIR(info.st_mode)
        expected = 0o700 if directory else 0o600
        exposed = info.st_mode & 0o077
        on_device_side = any(path == top or top in path.parents for top in device_side)
        if info.st_uid != me:
            findings.add(
                "warning", "permissions", f"{path} belongs to another user (uid {info.st_uid})",
                f"chown {os.getuid()} {path}",
            )
        if not exposed:
            continue
        severity = "problem" if on_device_side or info.st_mode & 0o022 else "warning"
        loose.append(
            {"path": str(path), "kind": "directory" if directory else "file", "mode": _mode_text(info.st_mode),
             "expected": format(expected, "04o"), "severity": severity}
        )
        who = "writable" if info.st_mode & 0o022 else "readable"
        findings.add(
            severity, "permissions",
            f"{path} is {who} by other users (mode {_mode_text(info.st_mode)}, expected {format(expected, '04o')})",
            f"chmod {'700' if directory else '600'} {path}",
        )
    if checked and not loose:
        findings.add("ok", "permissions", f"{checked} files and directories are owner-only")
    return {"checked": checked, "loose": loose}


# ---------------------------------------------------------------------------
# Memory, clipboard, TPM, sessions, the old vault
# ---------------------------------------------------------------------------


def _memory(findings: _Findings) -> Dict[str, Any]:
    with SecureBuffer(32) as probe:
        locked = bool(probe.locked)
    if locked:
        findings.add("ok", "memory", "key material can be locked into RAM")
    else:
        findings.add(
            "warning", "memory", "memory locking is refused here, so key material could be written to swap",
            "raise the locked-memory limit (ulimit -l) or run without a restrictive sandbox",
        )
    core: Optional[bool] = None
    try:
        import resource

        soft, _hard = resource.getrlimit(resource.RLIMIT_CORE)
        core = soft == 0
    except (ImportError, OSError, ValueError):
        core = None
    if core is True:
        findings.add("ok", "core-dumps", "core dumps are off for IronDome")
    elif core is False:
        debugging = os.environ.get("IRONDOME_DEBUG") == "1"
        findings.add(
            "warning", "core-dumps",
            "core dumps are allowed" + (" because IRONDOME_DEBUG=1 is set" if debugging else ""),
            "unset IRONDOME_DEBUG" if debugging else "run IronDome through its own command, which switches them off",
        )
    dumpable: Optional[bool] = None
    if sys.platform.startswith("linux"):
        try:
            libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
            dumpable = bool(libc.prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0))
        except (OSError, AttributeError):
            dumpable = None
        if dumpable:
            findings.add(
                "warning", "ptrace", "this process can be attached to by other processes of the same user",
                "run IronDome through its own command, which marks it non-dumpable",
            )
    return {"locking": locked, "core_dumps_disabled": core, "dumpable": dumpable}


def _clipboard(findings: _Findings) -> Dict[str, Any]:
    """The tools ``--copy`` would use, found exactly as :mod:`irondome.clipboard` finds them (it runs none)."""
    from irondome import clipboard

    try:
        _tool, writer, reader = clipboard.tools()  # runs nothing and copies nothing
    except UsageError as exc:
        findings.add(
            "note", "clipboard", f"--copy cannot work here: {exc}",
            "install a clipboard tool, or print values instead of copying them",
        )
        return {"tool": None, "reader": None}
    findings.add("ok", "clipboard", f"copying to the clipboard uses {writer}, and {reader} to clear it")
    return {"tool": writer, "reader": reader}


def _tpm(findings: _Findings) -> Optional[Dict[str, Any]]:
    try:
        status = devices.get_backend(_TPM).lockout_status()  # type: ignore[attr-defined]
    except Exception as exc:
        findings.add("warning", "tpm", f"the TPM's dictionary-attack counters cannot be read: {exc}")
        return {"error": str(exc)}
    if status.get("in_lockout"):
        wait = status.get("seconds_until_retry")
        when = f"try again in at most {wait} seconds" if wait else "it will not come out of lockout by itself"
        findings.add(
            "problem", "tpm", f"the TPM is in dictionary-attack lockout and refuses every password ({when})",
            "wait, or reset it with: tpm2_dictionarylockout --clear-lockout",
        )
    elif not status.get("recovery_seconds"):
        findings.add(
            "warning", "tpm", "the TPM's dictionary-attack protection is switched off: it does not limit guesses",
            "tpm2_dictionarylockout --setup-parameters --recovery-time=<seconds>",
        )
    elif int(status.get("remaining_tries") or 0) <= 3:
        findings.add(
            "warning", "tpm",
            f"the TPM accepts only {status.get('remaining_tries')} more wrong passwords before lockout",
            "type the master password carefully; failures are forgiven over time",
        )
    else:
        findings.add("ok", "tpm", f"the TPM allows {status.get('remaining_tries')} more wrong passwords")
    if status.get("lockout_auth_set") is False:
        findings.add(
            "note", "tpm", "the TPM's lockout authorisation is empty: anyone who can use the TPM can reset its counter",
            "set one with: tpm2_changeauth -c lockout",
        )
    return {"lockout": status}


def _sessions(findings: _Findings) -> Dict[str, Any]:
    try:
        found = caps.list_caps()
    except IronDomeError as exc:
        findings.add("warning", "sessions", str(exc))
        return {"sessions": None, "grants": None, "expired": None}
    expired = sum(1 for info in found if info.expired)
    if expired:
        findings.add(
            "note", "sessions", f"{expired} expired sessions or grants are still on disk",
            "they are destroyed the next time the vault is opened",
        )
    return {
        "sessions": sum(1 for info in found if info.kind == caps.KIND_SESSION and not info.expired),
        "grants": sum(1 for info in found if info.kind == caps.KIND_GRANT and not info.expired),
        "expired": expired,
    }


def _legacy(findings: _Findings) -> Dict[str, Any]:
    from irondome import migrate_v3

    location = paths.legacy_v3_dir()
    try:
        legacy = migrate_v3.detect()
    except IronDomeError as exc:
        findings.add("warning", "legacy-vault", f"an IronDome 3.x vault in {location} cannot be read: {exc}")
        return {"present": True, "path": str(location), "mode": None, "error": str(exc)}
    if legacy is None:
        return {"present": False, "path": str(location), "mode": None, "error": None}
    findings.add(
        "note", "legacy-vault", f"an IronDome 3.x vault is in {legacy.path}", "bring it over with: irondome migrate",
    )
    return {"present": True, "path": str(legacy.path), "mode": legacy.mode, "error": None}


def _guarded(name: str, findings: _Findings, check: Callable[[], Any]) -> Any:
    """Run one check; a check that fails is a finding, never the end of the report."""
    try:
        return check()
    except Exception as exc:
        findings.add("warning", name, f"this check could not run: {exc}")
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def collect() -> Dict[str, Any]:
    """The whole report. Changes nothing; see the module docstring for what is in it."""
    findings = _Findings()
    report: Dict[str, Any] = dict(versions())
    report["platform"] = _platform()
    helper = _guarded("secure-enclave-helper", findings, lambda: _helper(findings))
    backends = [_probe(name, helper) for name in devices.backend_names()]
    report["backends"] = backends
    report["new_vault_backend"] = _new_vault_backend(backends, findings, helper)
    hardware = [item["name"] for item in backends if item["available"] and item["hardware"]]
    if not hardware and all(item["probed"] for item in backends):
        findings.add(
            "warning", "device-backend",
            "no security chip is usable here: device keys are files, which protect a copied vault but not a "
            "stolen computer",
            "on a Mac, install the Xcode Command Line Tools; on Linux, install tpm2-tools and enable the TPM",
        )
    report["secure_enclave_helper"] = helper
    try:
        bunker = paths.bunker_name()
    except IronDomeError as exc:
        findings.add("problem", "bunker", str(exc), "choose a bunker with: irondome bunker use NAME")
        bunker = None
    report["bunker"] = bunker
    report["bunkers"] = paths.bunkers() if bunker is not None else []
    report["paths"] = {
        "vault_root": str(paths.root()),
        "device_root": str(paths.device_root()),
        "home": str(paths.home()) if bunker is not None else None,
        "device_dir": str(paths.device_dir()) if bunker is not None else None,
    }
    if bunker is not None:
        report["vault"] = _guarded("vault", findings, lambda: _vault(bunker, hardware, findings))
        report["sessions"] = _guarded("sessions", findings, lambda: _sessions(findings))
    else:
        report["vault"] = None
        report["sessions"] = None
    report["permissions"] = _guarded("permissions", findings, lambda: _permissions(findings))
    report["memory"] = _guarded("memory", findings, lambda: _memory(findings))
    report["clipboard"] = _guarded("clipboard", findings, lambda: _clipboard(findings))
    tpm_in_use = report["new_vault_backend"] == _TPM or any(
        slot.get("backend") == _TPM for slot in (report.get("vault") or {}).get("keyslots", [])
    )
    report["tpm"] = _guarded("tpm", findings, lambda: _tpm(findings)) if tpm_in_use else None
    report["legacy_vault"] = _guarded("legacy-vault", findings, lambda: _legacy(findings))
    report["findings"] = findings.items
    report["problems"] = sum(1 for item in findings.items if item["severity"] == "problem")
    return report
