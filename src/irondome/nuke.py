"""Self-destruct.

In 3.x ``nuke`` overwrote each file once and unlinked it. An SSD does not
honour that: wear-levelling, copy-on-write and journalling keep old blocks,
so the ciphertext could outlive the command that claimed to destroy it.

Here the guarantee does not rest on overwriting. Every keyslot opened by a
master password or a fingerprint needs a *device secret* held by a device
backend, and so does every session and grant. ``execute`` destroys those
secrets first. After that nothing from the vault side -- the live file, its
snapshots, the session and grant files, blocks the SSD never erased -- opens
with the master password, a session token or a grant token again. Only then
are the files themselves overwritten and removed, as hygiene.

How final the destruction of a device secret is depends on where it lived:

``linux-tpm2``  The secret existed only in the TPM's own storage, and the TPM
                deletes it. Old blocks of the device directory hold nothing
                but the numbers of indices that no longer exist.
``macos-se``    The private key never left the Secure Enclave. What is deleted
                is the sealed blob that names it. A copy of that blob recovered
                from the disk would still work only inside this Mac's Secure
                Enclave and, under the Touch ID policy, only after a
                fingerprint match.
``software``    The device key is a file. It is overwritten and unlinked,
                which on an SSD is best effort: whoever recovers its old blocks
                as well as the vault's can open the vault with the master
                password again. ``NukeReport.hardware_backed`` is then false,
                so the caller can say so.

Two things ``nuke`` cannot reach. A recovery key was designed to open the
vault without the device, so a recovery key on paper still opens a copy of
the vault file that survives somewhere else; the report names the bunkers that
had one. A portable backup (``irondome export``) needs no device at all and
opens with its own password.

Scope: with no bunker named, everything IronDome keeps on this machine --
every bunker, the shared helper cache, the default-bunker setting. With a
bunker named (``irondome bunker rm``), that bunker only, and never a device
secret that another bunker uses. A TPM index is one secret for the whole
machine whichever bunker's file names it, so a vault file copied from one
bunker into another names the first one's index; such a secret is left in
place and reported, and the removal does not count as a success, because a
copy of the removed bunker's vault file still opens while it exists.

``nuke`` removes only what IronDome created. A file it does not recognise is
left where it is and listed, never deleted: a mistyped ``IRONDOME_HOME`` must
not be able to empty someone's Documents folder. Recognising goes by the exact
names IronDome gives its files, in the exact places it puts them. Below the
two roots nothing is ever followed: a symbolic link standing where IronDome
keeps something is removed and what it points to is not touched (when that
could be a device key or a directory of the vault, the report says so). A
file that also has another name is unlinked, not overwritten, so the other
name keeps its contents; a device key is the exception, because every name
of it is the key. A root that is a filesystem root, the user's home directory
or one of its parents is refused before anything is read.
"""

from __future__ import annotations

import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from irondome import device as devices
from irondome import paths
from irondome.device.base import POLICIES, POLICY_DEVICE
from irondome.errors import HardwareError, IronDomeError, UsageError
from irondome.keys import KIND_RECOVERY, Keyslot
from irondome.vault import VaultFile

__all__ = ["DeviceKey", "NukePlan", "NukeReport", "plan", "execute"]

# ---------------------------------------------------------------------------
# What IronDome creates, by place. Anything else found there is not ours.
# ---------------------------------------------------------------------------

#: The file paths.write_atomic writes before renaming it (tempfile.mkstemp with the prefix ".tmp-").
_TEMPORARY = r"\.tmp-[a-z0-9_]{8}"
_ROOT_FILES = re.compile(rf"default-bunker|{_TEMPORARY}")
_HOME_FILES = re.compile(
    r"vault\.irondome|config\.json|\.lock|audit\.log|audit\.log\.lock|audit-[0-9]{8}T[0-9]{6}Z(?:-[0-9]+)?\.log"
    rf"|\.tmp-rekey-[0-9a-f]{{16}}\.irondome|{_TEMPORARY}"
)
_BACKUP_FILES = re.compile(rf"vault-[0-9]{{10,}}\.irondome|{_TEMPORARY}")
#: Exactly what caps.destroy_all removes: capability files in any case, its lock, its temporary files.
_CAP_FILES = re.compile(r"(?i:[0-9a-f]{32}\.json)|\.lock|\.tmp-.*", re.DOTALL)
_CAPABILITY = re.compile(r"[0-9a-f]{32}\.json", re.IGNORECASE)
_DEVICE_FILES = re.compile(rf"[0-9a-f]{{32}}\.(?:key|json)|tpm2-nv-indices\.(?:json|lock)|{_TEMPORARY}")
_HELPER_FILES = re.compile(r"irondome-se-[0-9a-f]{16}|\.build-[0-9]+-irondome-se-[0-9a-f]{16}")
#: A device secret of the file-based backend (``.key``) or of the Secure Enclave backend (``.json``).
_SECRET_FILE = re.compile(r"([0-9a-f]{32})\.(key|json)")
_VAULT_FILE = re.compile(r"vault\.irondome|\.tmp-rekey-[0-9a-f]{16}\.irondome")
_SNAPSHOT_FILE = re.compile(r"vault-[0-9]{10,}\.irondome")
_BUNKERS = "bunkers"
_HELPER = "helper"
_TPM_REGISTRY = "tpm2-nv-indices.json"
#: A Secure Enclave key file is under 2 KiB; macos_se reads no more than this.
_ENCLAVE_STATE_MAX = 64 * 1024


@dataclass(frozen=True)
class _Place:
    """One kind of directory IronDome keeps: the names of its files, and of its subdirectories.

    A subdirectory maps to the place it is, or to ``None`` when it is looked
    at on its own (``bunkers``). *leads* names the files that, replaced by a
    link, may lead to something that matters: a copy of the vault or of a
    device key, which the report then names. In a *secret* place every name of
    a file is the secret itself, so a file there is overwritten even when it
    has other names.
    """

    files: Tuple["re.Pattern[str]", ...]
    dirs: Tuple[Tuple[str, Optional["_Place"]], ...] = ()
    leads: Tuple[Tuple["re.Pattern[str]", str], ...] = ()
    secret: bool = False

    def merged(self, other: "_Place") -> "_Place":
        """The place one directory is when the two roots are the same directory."""
        return _Place(
            self.files + other.files, self.dirs + other.dirs, self.leads + other.leads, self.secret or other.secret
        )

    def lead(self, name: str) -> Optional[str]:
        return next((what for pattern, what in self.leads if pattern.fullmatch(name)), None)


_HOME = _Place(
    (_HOME_FILES,),
    (("backups", _Place((_BACKUP_FILES,), leads=((_SNAPSHOT_FILE, "vault"),))), ("caps", _Place((_CAP_FILES,)))),
    leads=((_VAULT_FILE, "vault"),),
)
_DEVICE = _Place((_DEVICE_FILES,), leads=((_SECRET_FILE, "key"),), secret=True)
_VAULT_ROOT = _Place((_ROOT_FILES,), ((_BUNKERS, None),))
_DEVICE_ROOT = _Place((), ((_HELPER, _Place((_HELPER_FILES,))), (_BUNKERS, None)))


# ---------------------------------------------------------------------------
# What callers see
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceKey:
    """One device secret of a bunker: a keyslot's, or the one its sessions and grants are bound to."""

    bunker: str
    backend: str
    policy: str
    hardware: bool
    present: bool


@dataclass
class NukePlan:
    """What :func:`execute` will destroy. Built without changing anything."""

    root: Path
    device_root: Path
    bunkers: List[str] = field(default_factory=list)
    unreadable_vaults: List[str] = field(default_factory=list)
    device_keys: List[DeviceKey] = field(default_factory=list)
    recovery_bunkers: List[str] = field(default_factory=list)
    capabilities: int = 0
    files: List[str] = field(default_factory=list)
    foreign: List[str] = field(default_factory=list)
    legacy_vault: Optional[str] = None

    @property
    def nothing_to_do(self) -> bool:
        return not self.files and not self.device_keys


@dataclass
class NukeReport:
    """What :func:`execute` did. ``success`` is true only if nothing of the vaults is left."""

    success: bool = False
    bunkers: List[str] = field(default_factory=list)
    device_keys_destroyed: int = 0
    hardware_backed: bool = False
    files_deleted: List[str] = field(default_factory=list)
    leftovers: List[str] = field(default_factory=list)
    foreign: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    recovery_bunkers: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Which directories, and a refusal to touch the wrong ones
# ---------------------------------------------------------------------------


def _account_home() -> Optional[str]:
    """The home directory the account database gives this user, whatever ``$HOME`` says."""
    try:
        import pwd
    except ImportError:
        return None
    try:
        return pwd.getpwuid(os.getuid()).pw_dir or None
    except KeyError:
        return None


def _checked_root(value: Path, what: str, variable: str) -> Path:
    """An absolute directory path that is safe to clean, or UsageError. Nothing is read before this."""
    path = Path(os.path.abspath(os.path.expanduser(str(value))))
    resolved = Path(os.path.realpath(str(path)))
    homes = [Path(os.path.realpath(home)) for home in (os.path.expanduser("~"), _account_home()) if home]
    for candidate in (path, resolved):
        if len(candidate.parts) < 3 or any(candidate == home or candidate in home.parents for home in homes):
            raise UsageError(
                f"refusing to run nuke on {candidate}: the {what} must be a directory of its own, "
                f"not a filesystem root, a home directory or one of its parents. Check {variable}. "
                "Nothing was touched."
            )
    return path


def _roots() -> Tuple[Path, Path]:
    return (
        _checked_root(paths.root(), "vault directory", "IRONDOME_HOME"),
        _checked_root(paths.device_root(), "device directory", "IRONDOME_DEVICE_DIR"),
    )


@contextmanager
def _bunker(name: str) -> Iterator[None]:
    """Point every IronDome module at bunker *name* for the duration."""
    saved = os.environ.get(paths.ENV_BUNKER)
    os.environ[paths.ENV_BUNKER] = name
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop(paths.ENV_BUNKER, None)
        else:
            os.environ[paths.ENV_BUNKER] = saved


def _is_bunker_name(name: str) -> bool:
    try:
        paths.validate_bunker_name(name)
    except UsageError:
        return False
    return True


def _listed(root: Path, device_root: Path) -> List[str]:
    """Every bunker name under a real ``bunkers`` directory on either side, as a directory or as a link."""
    found: Set[str] = set()
    for base in (root, device_root):
        if _kind_of(base / _BUNKERS) == "dir":
            found.update(
                entry.name
                for entry in _entries(base / _BUNKERS)
                if _is_bunker_name(entry.name) and _kind(entry) in ("dir", "link")
            )
    return sorted(found)


def _targets(bunker: Optional[str], root: Path, device_root: Path) -> List[str]:
    if bunker is None:
        return _listed(root, device_root)
    return [paths.validate_bunker_name(bunker)]


# ---------------------------------------------------------------------------
# Looking, never following a link
# ---------------------------------------------------------------------------


def _entries(directory: Path) -> List["os.DirEntry[str]"]:
    try:
        with os.scandir(str(directory)) as listing:
            return sorted(listing, key=lambda entry: entry.name)
    except OSError:
        return []


def _kind(entry: "os.DirEntry[str]") -> str:
    """``dir``, ``link``, ``file`` (a regular one) or ``other`` (a pipe, a socket, a device, unreadable)."""
    try:
        if entry.is_symlink():
            return "link"
        if entry.is_dir(follow_symlinks=False):
            return "dir"
        if entry.is_file(follow_symlinks=False):
            return "file"
    except OSError:
        pass  # what cannot even be looked at is "other": never followed, never read
    return "other"


def _kind_of(path: Path) -> Optional[str]:
    """What :func:`_kind` says about *path* itself, or ``None`` when there is nothing there."""
    try:
        mode = os.lstat(str(path)).st_mode
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        return "other"
    if stat.S_ISLNK(mode):
        return "link"
    if stat.S_ISDIR(mode):
        return "dir"
    return "file" if stat.S_ISREG(mode) else "other"


def _read_regular(path: Path, limit: int = paths.MAX_FILE_BYTES) -> Optional[bytes]:
    """The bytes of a regular file of at most *limit* bytes, or ``None`` for anything else.

    Reading changes nothing, so a link is followed here, but a pipe or a
    device standing under a vault's name is never opened for long: the file
    is opened without blocking and checked to be a regular file first.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)
    try:
        if not stat.S_ISREG(os.stat(str(path)).st_mode):
            return None
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks: List[bytes] = []
        wanted = limit + 1
        while wanted > 0:
            chunk = os.read(fd, min(wanted, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            wanted -= len(chunk)
        return None if wanted <= 0 else b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


@dataclass
class _Survey:
    """One look at a part of the tree, sorted into what is ours and what is not."""

    files: List[Path] = field(default_factory=list)  # ours, links included: execute removes them
    foreign: List[Path] = field(default_factory=list)  # not ours: never touched
    links: Dict[Path, str] = field(default_factory=dict)  # links that may lead to a "key", "vault" or "directory"
    secrets: Set[Path] = field(default_factory=set)  # files of a secret place: every name of them is destroyed

    def link(self, path: Path, stands_for: Optional[str]) -> None:
        self.files.append(path)
        if stands_for is not None:
            self.links[path] = stands_for


def _survey(directory: Path, place: _Place, survey: _Survey) -> None:
    """Sort what is in *directory*, a real directory, into ours and not ours."""
    subdirectories = dict(place.dirs)
    for entry in _entries(directory):
        path, kind = Path(entry.path), _kind(entry)
        if entry.name in subdirectories and kind in ("dir", "link"):
            inner = subdirectories[entry.name]
            if kind == "link":
                survey.link(path, None if entry.name == _HELPER else "directory")
            elif inner is not None:
                _survey(path, inner, survey)
            continue
        if kind != "dir" and any(pattern.fullmatch(entry.name) for pattern in place.files):
            if kind == "link":
                survey.link(path, place.lead(entry.name))
            else:
                survey.files.append(path)
                if place.secret:
                    survey.secrets.add(path)
        else:
            survey.foreign.append(path)


def _sides(root: Path, device_root: Path, vault: _Place, device: _Place) -> List[Tuple[Path, _Place]]:
    return [(root, vault.merged(device))] if root == device_root else [(root, vault), (device_root, device)]


def _survey_bunker(name: str, root: Path, device_root: Path) -> _Survey:
    """Both directories of one bunker. A side reached only through a link is not looked into."""
    survey = _Survey()
    for base, place in _sides(root, device_root, _HOME, _DEVICE):
        if _kind_of(base / _BUNKERS) != "dir":
            continue
        top = base / _BUNKERS / name
        kind = _kind_of(top)
        if kind == "dir":
            _survey(top, place, survey)
        elif kind == "link":
            survey.link(top, "directory")
        elif kind is not None:
            survey.foreign.append(top)  # a file where a bunker directory should be
    return survey


def _survey_shared(root: Path, device_root: Path) -> _Survey:
    """What a full nuke owns outside the bunkers: the default setting and the helper cache."""
    survey = _Survey()
    for base, place in _sides(root, device_root, _VAULT_ROOT, _DEVICE_ROOT):
        if not os.path.isdir(str(base)):
            continue  # the root itself may be a link: that is the configured directory, followed once
        _survey(base, place, survey)
        if _kind_of(base / _BUNKERS) == "dir":
            for entry in _entries(base / _BUNKERS):
                if not (_is_bunker_name(entry.name) and _kind(entry) in ("dir", "link")):
                    survey.foreign.append(Path(entry.path))
    return survey


# ---------------------------------------------------------------------------
# Device secrets: which there are, and whose
# ---------------------------------------------------------------------------


def _vault_files(home: Path) -> List[Path]:
    """The live vault, every snapshot and every interrupted write of either: each may name device secrets."""
    found = [home / "vault.irondome"]
    found += [Path(entry.path) for entry in _entries(home) if entry.name.startswith(".tmp-")]
    for entry in _entries(home / "backups"):
        if _BACKUP_FILES.fullmatch(entry.name):
            found.append(Path(entry.path))
    return found


def _slots(home: Path) -> Tuple[List[Keyslot], bool, bool]:
    """Device-bound keyslots of every vault file of a bunker: (slots, live file unreadable, has recovery)."""
    slots: List[Keyslot] = []
    unreadable = recovery = False
    for index, path in enumerate(_vault_files(home)):
        if not os.path.lexists(str(path)):
            continue
        raw = _read_regular(path)
        try:
            file: Optional[VaultFile] = VaultFile.from_bytes(raw) if raw is not None else None
        except Exception:  # a damaged file names nothing: its device secrets are found in the device directory
            file = None
        if file is None:
            unreadable = unreadable or index == 0
            continue
        recovery = recovery or any(slot.kind == KIND_RECOVERY for slot in file.slots)
        slots.extend(slot for slot in file.slots if slot.device is not None)
    return slots, unreadable, recovery


def _enclave_policy(path: Path) -> Optional[str]:
    """The policy of a Secure Enclave key file; ``None`` for a readable file of another backend.

    A damaged one may still hold an intact key blob, so it counts as a key,
    exactly as the Secure Enclave backend's own ``destroy_all`` counts it.
    """
    raw = _read_regular(path, _ENCLAVE_STATE_MAX)
    try:
        state = json.loads(raw.decode("utf-8")) if raw is not None else None
    except (ValueError, UnicodeDecodeError, RecursionError):
        state = None
    if not isinstance(state, dict):
        return POLICY_DEVICE
    if state.get("backend") != "macos-se":
        return None
    policy = state.get("policy")
    return policy if policy in POLICIES else POLICY_DEVICE


def _held() -> Tuple[List[Dict[str, Any]], List[str]]:
    """Descriptors of every device secret the current bunker's device directory holds, and what could not be read.

    The vault file names the secrets of its keyslots. This finds the rest by
    the names each backend gives them: the secret its sessions and grants are
    bound to (whose descriptor is in the encrypted index), and every secret a
    damaged or missing vault file no longer names.
    """
    directory = paths.device_dir()
    found: List[Dict[str, Any]] = []
    problems: List[str] = []
    for entry in _entries(directory):
        match = _SECRET_FILE.fullmatch(entry.name)
        if match is None or _kind(entry) != "file":
            continue
        ref, extension = match.groups()
        if extension == "key":
            found.append({"backend": "software", "policy": POLICY_DEVICE, "ref": ref})
            continue
        policy = _enclave_policy(Path(entry.path))
        if policy is not None:
            found.append({"backend": "macos-se", "policy": policy, "ref": ref})
    registry = directory / _TPM_REGISTRY
    try:
        recorded = stat.S_ISREG(os.stat(str(registry)).st_mode)
    except OSError:
        recorded = False
    if recorded:
        try:
            devices.get_backend("linux-tpm2")
            from irondome.device import linux_tpm

            indices = linux_tpm._load_registry()
        except IronDomeError as exc:
            problems.append(f"the TPM device keys cannot be listed: {exc}")
        else:
            found.extend(
                {"backend": "linux-tpm2", "policy": POLICY_DEVICE, "ref": format(int(index, 16), "032x"),
                 "nv_index": index}
                for index in indices
            )
    return found, problems


def _identity(bunker: str, descriptor: Dict[str, Any]) -> Tuple[str, str, str]:
    """Which secret a descriptor names. A TPM index is one secret for the machine, whichever bunker names it."""
    backend = str(descriptor.get("backend"))
    index = descriptor.get("nv_index")
    if isinstance(index, str):
        return backend, "", index.lower()
    return backend, bunker, str(descriptor.get("ref"))


def _candidates(bunker: str, slots: List[Keyslot], held: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every device secret of a bunker, once each: the keyslots' as their vault files name them, then the rest."""
    seen: Set[Tuple[str, str, str]] = set()
    found: List[Dict[str, Any]] = []
    for descriptor in [slot.device for slot in slots if slot.device is not None] + held:
        identity = _identity(bunker, descriptor)
        if identity not in seen:
            seen.add(identity)
            found.append(descriptor)
    return found


def _claims(targets: List[str], root: Path, device_root: Path) -> Dict[Tuple[str, str, str], str]:
    """The device secrets that bunkers other than *targets* use, and which bunker each belongs to.

    Only read, so links are followed here: a bunker reached through one
    still protects what it uses.
    """
    owners: Dict[Tuple[str, str, str], str] = {}
    for other in sorted((set(paths.bunkers()) | set(_listed(root, device_root))) - set(targets)):
        with _bunker(other):
            slots, _unreadable, _recovery = _slots(paths.home())
            held, _problems = _held()
        for descriptor in _candidates(other, slots, held):
            owners.setdefault(_identity(other, descriptor), other)
    return owners


def _label(descriptor: Dict[str, Any]) -> str:
    index = descriptor.get("nv_index")
    return str(descriptor.get("backend")) + (f", NV index {index}" if isinstance(index, str) else "")


def _shared_note(bunker: str, descriptor: Dict[str, Any], owner: str) -> str:
    return (
        f"{bunker}: a device key ({_label(descriptor)}) is also used by bunker {owner}, so it was left in place; "
        f"while it exists, a copy of the vault file of {bunker} that needs it still opens"
    )


def _describe(bunker: str, descriptor: Dict[str, Any]) -> DeviceKey:
    name = str(descriptor.get("backend"))
    policy = str(descriptor.get("policy"))
    try:
        backend = devices.get_backend(name)
    except Exception:  # an unknown backend, or one this platform cannot load, holds nothing here
        return DeviceKey(bunker=bunker, backend=name, policy=policy, hardware=False, present=False)
    try:
        present = backend.exists(descriptor)
    except Exception:  # a backend that cannot be asked is reported as absent; execute reports why
        present = False
    return DeviceKey(
        bunker=bunker, backend=name, policy=policy, hardware=devices.hardware_here(backend), present=present
    )


# ---------------------------------------------------------------------------
# One bunker, as found before anything is destroyed
# ---------------------------------------------------------------------------


@dataclass
class _Look:
    name: str
    survey: _Survey
    slots: List[Keyslot]
    unreadable: bool
    recovery: bool
    present: bool


def _look(name: str, root: Path, device_root: Path) -> _Look:
    with _bunker(name):
        slots, unreadable, recovery = _slots(paths.home())
    survey = _survey_bunker(name, root, device_root)
    present = bool(survey.files or survey.foreign or slots) or any(
        os.path.lexists(str(base / _BUNKERS / name)) for base in (root, device_root)
    )
    return _Look(name, survey, slots, unreadable, recovery, present)


def _reachable(base: Path) -> bool:
    """Whether a bunker's side under *base* is reached without a link: its ``bunkers`` is a directory or absent."""
    return _kind_of(base / _BUNKERS) in (None, "dir")


def _blocked_notes(name: str, root: Path, device_root: Path) -> List[str]:
    """For a bunker removed on its own: the sides that are reached only through a link, which stays."""
    notes = []
    for base, what, left in (
        (root, "vault directory", "nothing there was deleted"),
        (device_root, "device directory", "its device keys there were not destroyed"),
    ):
        parent = base / _BUNKERS
        if _kind_of(parent) == "link" and os.path.lexists(str(parent / name)):
            notes.append(
                f"{name}: its {what} is reached through the symbolic link {parent}, which other bunkers share; "
                f"nuke does not follow links, so {left}"
            )
    return notes


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def plan(bunker: Optional[str] = None) -> NukePlan:
    """Describe what :func:`execute` would destroy, without changing anything.

    *bunker* names one bunker; ``None`` means everything IronDome keeps on
    this machine. Works when vault files are missing or damaged.
    ``device_keys`` lists every device secret ``execute`` destroys, those of
    the keyslots and the one sessions and grants are bound to; ``files``
    lists, in order, every file it deletes.
    """
    root, device_root = _roots()
    result = NukePlan(root=root, device_root=device_root)
    names = _targets(bunker, root, device_root)
    owners = _claims(names, root, device_root) if bunker is not None else {}
    for look in (_look(name, root, device_root) for name in names):
        if not look.present:
            continue
        name = look.name
        result.bunkers.append(name)
        if look.unreadable:
            result.unreadable_vaults.append(name)
        if look.recovery:
            result.recovery_bunkers.append(name)
        with _bunker(name):
            held = _held()[0] if _reachable(device_root) else []
            result.device_keys.extend(
                _describe(name, descriptor)
                for descriptor in _candidates(name, look.slots, held)
                if _identity(name, descriptor) not in owners
            )
        result.files.extend(str(path) for path in look.survey.files)
        result.foreign.extend(str(path) for path in look.survey.foreign)
        result.capabilities += sum(
            1 for path in look.survey.files if path.parent.name == "caps" and _CAPABILITY.fullmatch(path.name)
        )
    if bunker is None:
        shared = _survey_shared(root, device_root)
        result.files.extend(str(path) for path in shared.files)
        result.foreign.extend(str(path) for path in shared.foreign)
    from irondome import migrate_v3

    try:
        legacy = migrate_v3.detect()
    except IronDomeError:
        legacy = None
    result.legacy_vault = str(legacy.path) if legacy is not None else None
    return result


def _shared_file(path: Path, survey: _Survey) -> bool:
    """A regular file with another name, outside a secret place: unlinked, and never overwritten."""
    try:
        info = os.lstat(str(path))
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink > 1 and path not in survey.secrets


def _delete(path: Path, survey: _Survey) -> Optional[str]:
    """Remove one of IronDome's files. Returns why it could not be removed, or ``None``.

    A link, a pipe or anything else that is not a regular file is unlinked
    and never opened. A regular file with a second name is unlinked and not
    overwritten, so that the other name keeps its contents -- unless it is in
    a device directory, where the other name is a copy of a device secret.
    Any other is overwritten first (:func:`irondome.paths.secure_delete`).
    """
    try:
        info = os.lstat(str(path))
    except FileNotFoundError:
        return None
    except OSError as exc:
        return exc.strerror or str(exc)
    try:
        if stat.S_ISREG(info.st_mode) and not _shared_file(path, survey):
            paths.secure_delete(path)
        else:
            os.unlink(str(path))
    except FileNotFoundError:
        return None
    except OSError as exc:
        return exc.strerror or str(exc)
    return None


def _link_target(path: Path) -> Optional[str]:
    """Where a link leads, when anything is there."""
    try:
        target = os.readlink(str(path))
    except OSError:
        return None
    return target if os.path.exists(str(path)) else None


#: What the report says about a link that was removed, by what it may have led to.
_LEFT_BEHIND = {
    "key": "what it points to was not destroyed. If that is a copy of a device key, destroy it yourself",
    "vault": "what it points to was not touched. If that is a copy of the vault, destroy it yourself: a recovery "
    "key still opens it",
    "directory": "nothing it points to was touched",
}


def _remove_strays(survey: _Survey, report: NukeReport) -> None:
    """Step zero: unlink what stands under one of IronDome's names and must be neither followed nor overwritten.

    That is anything but a regular file (a link, a pipe), and a regular file
    that has another name outside a device directory. Done before anything
    else, so that no later step -- a backend, the capability store -- can
    follow a link out of the tree, wait on a pipe or overwrite what another
    name still needs.
    """
    for path in survey.files:
        kind = _kind_of(path)
        if kind in (None, "dir") or (kind == "file" and not _shared_file(path, survey)):
            continue
        target = _link_target(path) if kind == "link" else None
        problem = _delete(path, survey)
        if problem is not None:
            report.errors.append(f"could not delete {path}: {problem}")
        elif target is not None and path in survey.links:
            report.errors.append(
                f"{path} was a symbolic link to {target}: the link was removed and {_LEFT_BEHIND[survey.links[path]]}"
            )


def _destroy(bunker: str, descriptor: Dict[str, Any], report: NukeReport, hardware: List[bool]) -> None:
    """Destroy one device secret and confirm with its backend that it is gone."""
    name = str(descriptor.get("backend"))
    try:
        backend = devices.get_backend(name)
        if not backend.exists(descriptor):
            return
        backend.destroy(descriptor)
        if backend.exists(descriptor):
            raise HardwareError("it is still there after it was destroyed")
    except Exception as exc:  # reported; the rest of the erasure still runs
        report.errors.append(f"{bunker}: a device key ({_label(descriptor)}) could not be destroyed: {exc}")
        return
    report.device_keys_destroyed += 1
    hardware.append(devices.hardware_here(backend))


def _stray_key_files(directory: Path) -> bool:
    """Whether the file-based backend's ``destroy_all``, which takes every ``*.key``, would take a file not ours."""
    return any(
        entry.name.endswith(".key") and not (_SECRET_FILE.fullmatch(entry.name) and _kind(entry) == "file")
        for entry in _entries(directory)
    )


def _destroy_device_secrets(
    bunker: str, slots: List[Keyslot], owners: Dict[Tuple[str, str, str], str], report: NukeReport,
    hardware: List[bool],
) -> None:
    """Step one, and the one that matters: destroy every device secret of the current bunker.

    Each secret its vault files name or its device directory holds is
    destroyed through its backend, except one that another bunker uses. Then
    each backend's ``destroy_all`` sweeps up whatever is left, so that the
    erasure does not depend on any file having been readable -- unless that
    sweep would take something that is not this bunker's.
    """
    held, problems = _held()
    report.errors.extend(f"{bunker}: {problem}" for problem in problems)
    own = {_identity(bunker, descriptor) for descriptor in held}
    skip: Set[str] = {"linux-tpm2"} if problems else set()
    for descriptor in _candidates(bunker, slots, held):
        identity = _identity(bunker, descriptor)
        owner = owners.get(identity)
        if owner is not None:
            report.errors.append(_shared_note(bunker, descriptor, owner))
            if identity in own:
                skip.add(identity[0])  # its registry lists it too: its destroy_all would take it with the rest
            continue
        _destroy(bunker, descriptor, report, hardware)
    if _stray_key_files(paths.device_dir()):
        skip.add("software")
    for name in devices.backend_names():
        if name in skip:
            continue
        try:
            backend = devices.get_backend(name)
        except Exception:  # noqa: S112 - a backend that cannot load on this platform holds nothing here
            continue
        try:
            count = backend.destroy_all()
        except Exception as exc:
            report.errors.append(f"{bunker}: {name}: {exc}")
            continue
        report.device_keys_destroyed += count
        if count:  # asking a backend what it is can mean running its tools: only when it held something
            hardware.extend([devices.hardware_here(backend)] * count)


def _rmdir(directory: Path) -> None:
    if _kind_of(directory) == "dir":
        try:
            directory.rmdir()
        except OSError:
            pass  # not empty: something that is not ours is still inside


def _destroy_bunker(
    look: _Look, root: Path, device_root: Path, owners: Dict[Tuple[str, str, str], str], report: NukeReport,
    hardware: List[bool],
) -> None:
    """Steps one to four for one bunker; links are already gone (step zero)."""
    name = look.name
    report.bunkers.append(name)
    if look.recovery:
        report.recovery_bunkers.append(name)
    vault_side, device_side = _reachable(root), _reachable(device_root)
    with _bunker(name):
        if device_side:
            _destroy_device_secrets(name, look.slots, owners, report, hardware)
        if vault_side:
            try:
                from irondome import caps

                caps.destroy_all()
            except IronDomeError as exc:
                report.errors.append(f"{name}: sessions and grants: {exc}")
    remaining = _survey_bunker(name, root, device_root)
    for path in remaining.files:
        problem = _delete(path, remaining)
        if problem is not None:
            report.errors.append(f"could not delete {path}: {problem}")
    home, device_dir = root / _BUNKERS / name, device_root / _BUNKERS / name
    for directory, reachable in ((home / "backups", vault_side), (home / "caps", vault_side), (home, vault_side),
                                 (device_dir, device_side)):
        if reachable:
            _rmdir(directory)


def execute(*, bunker: Optional[str] = None) -> NukeReport:
    """Destroy one bunker, or (``bunker=None``) everything IronDome keeps here.

    The caller must already have the user's confirmation. Order: what stands
    under IronDome's names and must be neither followed nor overwritten (a
    link, a pipe, a file with another name) is unlinked; then, per bunker,
    device secrets first (cryptographic erasure), then sessions and grants,
    then every file IronDome created, then the empty directories. Runs to
    the end whatever fails, and reports each failure. Safe to run twice.

    ``files_deleted`` lists, in the order :func:`plan` gives, every file that
    was there and is gone. ``leftovers`` lists what is IronDome's and still
    there, ``foreign`` what was left because it is not.
    """
    root, device_root = _roots()
    names = _targets(bunker, root, device_root)
    owners = _claims(names, root, device_root) if bunker is not None else {}
    report = NukeReport()
    hardware: List[bool] = []
    looks = [look for look in (_look(name, root, device_root) for name in names) if look.present]
    shared = _survey_shared(root, device_root) if bunker is None else _Survey()
    for survey in [look.survey for look in looks] + [shared]:
        _remove_strays(survey, report)
    for look in looks:
        if bunker is not None:
            report.errors.extend(_blocked_notes(look.name, root, device_root))
        _destroy_bunker(look, root, device_root, owners, report, hardware)
    if bunker is None:
        remaining = _survey_shared(root, device_root)
        for path in remaining.files:
            problem = _delete(path, remaining)
            if problem is not None:
                report.errors.append(f"could not delete {path}: {problem}")
        _rmdir(device_root / _HELPER)
        for directory in (root / _BUNKERS, device_root / _BUNKERS):
            _rmdir(directory)
        for directory in (root, device_root):
            if not os.path.islink(str(directory)):
                _rmdir(directory)
    else:
        for directory in (root / _BUNKERS, device_root / _BUNKERS):
            _rmdir(directory)  # only if this was the last bunker
    before = [path for look in looks for path in look.survey.files] + shared.files
    report.files_deleted = [str(path) for path in before if not os.path.lexists(str(path))]
    after = [_survey_bunker(look.name, root, device_root) for look in looks]
    if bunker is None:
        after.append(_survey_shared(root, device_root))
    for survey in after:
        report.leftovers.extend(str(path) for path in survey.files)
        report.foreign.extend(str(path) for path in survey.foreign)
    report.hardware_backed = bool(hardware) and all(hardware)
    report.success = not report.errors and not report.leftovers
    return report
