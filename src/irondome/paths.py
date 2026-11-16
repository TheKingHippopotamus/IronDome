"""Where IronDome keeps things, and the only code allowed to create them.

Bunkers
-------
A *bunker* is one vault with everything that belongs to it: its own master
password, device key, recovery key, sessions, grants, audit log and settings.
A machine can hold several -- one per person, or one per role -- and opening
one gives nothing about the others. The first is called ``alpha``.

Which bunker a command works on: ``IRONDOME_BUNKER`` if set (the command
line's ``--bunker`` sets it), else the default recorded by ``irondome bunker
use``, else ``alpha``.

Two roots, on purpose::

    root()          ~/.irondome                          the vaults
      default-bunker                                      name set by `bunker use`
      bunkers/<name>/vault.irondome, backups/, caps/, audit.log, config.json

    device_root()   ~/Library/Application Support/IronDome/device   (macOS)
                    $XDG_STATE_HOME/irondome/device                  (Linux)
      helper/                                             compiled Secure Enclave helper
      bunkers/<name>/                                     what binds that vault to this machine

``home()`` and ``device_dir()`` are the current bunker's directories under
each root. The vault side is safe to copy as a backup: on its own it cannot
be opened, not even with the master password, because the device key is not
in it. The device side must never be backed up or synced; ``nuke`` destroys
it.

Both roots honour an environment override (``IRONDOME_HOME``,
``IRONDOME_DEVICE_DIR``) so tests and containers never touch the real ones.
Every file is created ``0600`` and every directory ``0700`` regardless of the
process umask.
"""

from __future__ import annotations

import errno
import os
import re
import stat
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple, Union

from irondome.errors import UsageError, VaultError

__all__ = [
    "FILE_MODE",
    "DIR_MODE",
    "FIRST_BUNKER",
    "ENV_BUNKER",
    "root",
    "device_root",
    "validate_bunker_name",
    "bunker_name",
    "bunkers",
    "default_bunker",
    "set_default_bunker",
    "clear_default_bunker",
    "bunker_holding_capability",
    "home",
    "device_dir",
    "vault_file",
    "backups_dir",
    "caps_dir",
    "audit_file",
    "config_file",
    "lock_file",
    "helper_dir",
    "legacy_v3_dir",
    "ensure_dir",
    "write_atomic",
    "read_file",
    "file_lock",
    "secure_delete",
]

FILE_MODE = 0o600
DIR_MODE = 0o700

#: Refuse to load absurdly large files instead of exhausting memory on them.
MAX_FILE_BYTES = 256 * 1024 * 1024

#: How :func:`read_file` and :func:`secure_delete` open what stands under a name: never waiting on a pipe or a
#: device in a file's place, never making a terminal the controlling one, never translating bytes on Windows.
_NO_WAIT = getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0)
#: ``default-bunker`` holds one bunker name and a newline.
_DEFAULT_FILE_MAX = 256


def _expand(value: str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(value)))


#: The bunker that exists when nobody has named one.
FIRST_BUNKER = "alpha"
#: Environment variable naming the bunker a command works on.
ENV_BUNKER = "IRONDOME_BUNKER"

_BUNKER_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
_BUNKERS = "bunkers"
_DEFAULT_FILE = "default-bunker"
_CAPABILITY_ID = re.compile(r"[0-9a-f]{32}")


def root() -> Path:
    """The directory that holds every bunker's vault on this machine."""
    override = os.environ.get("IRONDOME_HOME")
    if override:
        return _expand(override)
    return _expand("~/.irondome")


def device_root() -> Path:
    """The directory that holds every bunker's device material and the helper cache."""
    override = os.environ.get("IRONDOME_DEVICE_DIR")
    if override:
        return _expand(override)
    if sys.platform == "darwin":
        return _expand("~/Library/Application Support/IronDome/device")
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
        return Path(base) / "IronDome" / "device"
    state = os.environ.get("XDG_STATE_HOME") or "~/.local/state"
    return _expand(state) / "irondome" / "device"


def validate_bunker_name(name: object) -> str:
    """A bunker name: a lower-case letter, then up to 31 letters, digits or hyphens."""
    if not isinstance(name, str) or _BUNKER_NAME.fullmatch(name) is None:
        raise UsageError(
            f"{name!r} is not a bunker name: use a lower-case letter followed by up to 31 "
            "lower-case letters, digits or hyphens (for example alpha, bravo, ops-2)"
        )
    return name


def default_bunker() -> str:
    """The bunker ``irondome bunker use`` recorded, or ``alpha`` when none was.

    Read with :func:`read_file`, so a pipe or a device put in the setting's place is refused at once
    (:class:`UsageError`) instead of holding up every command that needs to know its bunker.
    """
    path = root() / _DEFAULT_FILE
    invalid = UsageError(f"{path} does not hold a valid bunker name. Choose one with: irondome bunker use NAME")
    try:
        raw = read_file(path, limit=_DEFAULT_FILE_MAX)
    except (FileNotFoundError, NotADirectoryError):
        return FIRST_BUNKER  # nothing recorded; if the root itself is unusable, the caller's own I/O says so
    except VaultError:
        raise invalid from None  # longer than any name `irondome bunker use` writes
    except OSError as exc:
        raise UsageError(f"cannot read the default bunker from {path}: {exc.strerror or exc}") from None
    try:
        return validate_bunker_name(raw.decode("ascii").strip())
    except (UnicodeDecodeError, UsageError):
        raise invalid from None


def set_default_bunker(name: str) -> None:
    """Record *name* as the bunker commands use when nothing else names one."""
    validate_bunker_name(name)
    ensure_dir(root())
    write_atomic(root() / _DEFAULT_FILE, (name + "\n").encode("ascii"))


def clear_default_bunker() -> None:
    """Forget the recorded default, so that :func:`default_bunker` is ``alpha`` again, as on a new machine.

    Nothing to forget is not an error. A link standing in the setting's place is removed, never followed.
    """
    path = root() / _DEFAULT_FILE
    try:
        os.unlink(str(path))
    except (FileNotFoundError, NotADirectoryError):
        return


def bunker_name() -> str:
    """The bunker this process works on. See the module docstring for the order."""
    chosen = os.environ.get(ENV_BUNKER)
    if chosen:
        return validate_bunker_name(chosen)
    return default_bunker()


def bunkers() -> List[str]:
    """Every bunker that has a directory on this machine, on either side, sorted."""
    found = set()
    for base in (root() / _BUNKERS, device_root() / _BUNKERS):
        try:
            with os.scandir(str(base)) as listing:
                for entry in listing:
                    if _BUNKER_NAME.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False):
                        found.add(entry.name)
        except OSError:
            continue
    return sorted(found)


def bunker_holding_capability(cap_id: str) -> Optional[str]:
    """The bunker whose ``caps/`` holds the session or grant *cap_id*, if any.

    Lets a grant token work without naming its bunker: capability ids are 128
    random bits, so at most one bunker can hold a given one.
    """
    if not isinstance(cap_id, str) or _CAPABILITY_ID.fullmatch(cap_id.lower()) is None:
        return None
    for name in bunkers():
        directory = root() / _BUNKERS / name / "caps"
        try:
            with os.scandir(str(directory)) as listing:
                if any(entry.name.lower() == cap_id.lower() + ".json" for entry in listing):
                    return name
        except OSError:
            continue
    return None


def home() -> Path:
    """The current bunker's vault directory."""
    return root() / _BUNKERS / bunker_name()


def device_dir() -> Path:
    """The current bunker's device directory."""
    return device_root() / _BUNKERS / bunker_name()


def vault_file() -> Path:
    return home() / "vault.irondome"


def backups_dir() -> Path:
    return home() / "backups"


def caps_dir() -> Path:
    """Sessions and grants: short-lived wrapped capabilities."""
    return home() / "caps"


def audit_file() -> Path:
    return home() / "audit.log"


def config_file() -> Path:
    return home() / "config.json"


def lock_file() -> Path:
    return home() / ".lock"


def helper_dir() -> Path:
    """Where the locally compiled Secure Enclave helper is cached (shared by every bunker)."""
    return device_root() / "helper"


def legacy_v3_dir() -> Path:
    """The data directory of IronDome 1.x-3.x, read only by ``migrate``."""
    override = os.environ.get("IRONDOME_LEGACY_DIR")
    if override:
        return _expand(override)
    return _expand("~/.password_manager")


def _is_own(path: Path) -> bool:
    """True for IronDome's own directories: the two roots and anything inside them."""
    for base in (root(), device_root()):
        if path == base or base in path.parents:
            return True
    return False


def _tighten(path: Path) -> None:
    try:
        os.chmod(path, DIR_MODE)
    except OSError:
        pass  # filesystems without POSIX modes; nothing more can be done


def ensure_dir(path: Union[str, Path]) -> Path:
    """Create *path* and every missing parent, each of them owner-only.

    A directory that already exists is tightened to owner-only when it is one
    of IronDome's own: ``home()``, ``device_dir()`` or anything inside them.
    Any other existing directory (the folder a backup is written to, ``/tmp``)
    belongs to someone else and is left exactly as it is.
    """
    path = Path(path)
    target = Path(os.path.abspath(path))
    missing: List[Path] = []
    probe = target
    while not os.path.lexists(probe):
        missing.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent
    created = False
    for directory in reversed(missing):
        try:
            os.mkdir(directory, DIR_MODE)
        except FileExistsError:
            created = False  # another process made it first
            continue
        created = True
        _tighten(directory)  # mkdir applies the umask; this does not
    if not target.is_dir():
        raise FileExistsError(errno.EEXIST, "exists and is not a directory", str(target))
    if not created and _is_own(target):
        _tighten(target)
    return path


def _fsync(fd: int) -> None:
    """Flush *fd* all the way to the storage device.

    On macOS ``fsync`` only hands the data to the drive, which may keep it in
    a volatile cache; ``F_FULLFSYNC`` makes the drive write it out. A
    filesystem that does not support that gets a plain ``fsync``.
    """
    if sys.platform == "darwin":
        import fcntl

        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except OSError:
            pass  # not supported here; fall back to fsync
    os.fsync(fd)


def _fsync_dir(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        # A pipe swapped in for the directory must not hold the write up: it is refused, or opened without waiting.
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NO_WAIT)
    except OSError:
        return
    try:
        _fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_atomic(path: Union[str, Path], data: Union[bytes, bytearray, memoryview]) -> None:
    """Replace *path* with *data* so a crash leaves the old file or the new one.

    The temporary file is created ``0600`` in the same directory, written,
    fsynced and renamed over the target; then the directory is flushed to the
    storage device so the rename itself is durable. If *path* is a symbolic
    link the link is replaced, not the file it points to.
    """
    path = Path(path)
    ensure_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, FILE_MODE)
            view = memoryview(data)
            written = 0
            while written < len(view):
                written += os.write(fd, view[written:])
            _fsync(fd)  # the data is on the device before the rename can be
        finally:
            os.close(fd)
        if not hasattr(os, "fchmod"):
            try:
                os.chmod(tmp_name, FILE_MODE)
            except OSError:
                pass
        os.replace(tmp_name, str(path))
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    _fsync_dir(path.parent)


_TEMPORARY_NAME = re.compile(r"\.tmp-[a-z0-9_]{8}")


def sweep_temporary(directory: Union[str, Path], *, older_than: float = 60.0) -> int:
    """Delete what :func:`write_atomic` left in *directory* when it was killed before its rename.

    Such a file is a whole copy of what was being written: of a vault, it opens with the keyslots that
    vault had, which a later re-key or password change was meant to retire. Only regular files named as
    ``write_atomic`` names them (``.tmp-`` and eight characters) and last changed more than *older_than*
    seconds ago are taken: a write in progress keeps its file for milliseconds, so an old one belongs to
    nobody. A caller that holds the lock every writer into *directory* takes (the bunker's lock, for the
    bunker's directory and its snapshots) passes ``older_than=0``: no write can be in progress then.
    Returns how many were deleted; a file that cannot be deleted is left, and not counted.
    """
    try:
        names = os.listdir(str(directory))
    except OSError:
        return 0
    deadline = time.time() - older_than
    removed = 0
    for name in names:
        if not _TEMPORARY_NAME.fullmatch(name):
            continue
        path = Path(directory) / name
        try:
            status = os.lstat(str(path))
            if not stat.S_ISREG(status.st_mode) or status.st_mtime > deadline:
                continue
            secure_delete(path)
            removed += 1
        except OSError:
            continue
    return removed


def read_file(path: Union[str, Path], *, limit: Optional[int] = None) -> bytes:
    """Read a whole regular file, refusing anything implausibly large.

    Only a regular file is read (a symbolic link is followed to one, as
    ``open`` follows it). A pipe, a socket or a device standing in a file's
    place is refused at once and never waited on: opening a pipe for reading
    would otherwise block until something writes to it, and every command
    that reads the file with it.

    Raises ``FileNotFoundError`` (and other ``OSError``) as ``open`` would:
    ``IsADirectoryError`` for a directory, and an ``OSError`` whose
    ``strerror`` says so for anything else that is not a regular file.
    :class:`VaultError` for a file larger than *limit* bytes (by default
    ``MAX_FILE_BYTES``), decided from its size before anything is read and
    again from what was read, in case it grew.
    """
    path = Path(path)
    cap = MAX_FILE_BYTES if limit is None else limit
    fd = os.open(str(path), os.O_RDONLY | _NO_WAIT)
    try:
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            raise IsADirectoryError(errno.EISDIR, os.strerror(errno.EISDIR), str(path))
        if not stat.S_ISREG(info.st_mode):
            raise OSError(errno.EINVAL, "not a regular file (a pipe, a socket or a device is never read)", str(path))
        if info.st_size > cap:
            raise VaultError(f"{path} is too large to be an IronDome file ({info.st_size} bytes)")
        data = _read_at_most(fd, cap + 1)
    finally:
        os.close(fd)
    if len(data) > cap:  # it grew after its size was read
        raise VaultError(f"{path} is too large to be an IronDome file")
    return data


def _read_at_most(fd: int, count: int) -> bytes:
    """Up to *count* bytes from *fd*, fewer only at the end of the file."""
    parts: List[bytes] = []
    wanted = count
    while wanted > 0:
        part = os.read(fd, min(wanted, 1 << 20))
        if not part:
            break
        parts.append(part)
        wanted -= len(part)
    return b"".join(parts)


def _lock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                return
            except OSError as exc:
                # LK_LOCK gives up after ten one-second attempts while another
                # process holds the lock. Keep waiting for that, and for
                # nothing else: any other error would repeat forever.
                if exc.errno not in (errno.EACCES, errno.EDEADLK):
                    raise
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX)


def _unlock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass  # closing the descriptor releases the lock as well
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


#: Lock files held by this process, and the thread that holds each one.
_held: Dict[str, int] = {}


@contextmanager
def file_lock(path: Union[str, Path, None] = None) -> Iterator[None]:
    """Hold an exclusive advisory lock for a read-modify-write of the vault.

    Blocks until the lock is free. Processes that crash release it
    automatically because the lock lives on an open file descriptor.

    The thread that holds a lock may take it again: ``Vault.commit`` takes it
    itself, so a caller can hold it across open, change and commit. Only the
    outermost block releases it. Other threads and other processes wait.
    """
    target = Path(path) if path is not None else lock_file()
    ensure_dir(target.parent)
    key = os.path.realpath(str(target))
    me = threading.get_ident()
    if _held.get(key) == me:
        yield  # already held by this thread; the outermost block releases it
        return
    fd = os.open(str(target), os.O_RDWR | os.O_CREAT, FILE_MODE)
    try:
        _lock(fd)
        _held[key] = me
        try:
            yield
        finally:
            _held.pop(key, None)
            _unlock(fd)
    finally:
        os.close(fd)


def secure_delete(path: Union[str, Path]) -> None:
    """Unlink *path*, first overwriting the file once with random bytes flushed to the device, if it is ours alone.

    This is hygiene, not the guarantee. On SSDs, copy-on-write and journalled
    filesystems the old blocks can outlive an overwrite; what makes destroyed
    data unreadable is destroying the device key (see ``irondome.nuke``).

    An overwrite changes the file, not the name, so it reaches every other
    name the file has. It is therefore done only to a regular file that this
    user owns and that has no other name; anything else is only unlinked:

    * a symbolic link, without touching what it points to; a pipe, a socket
      or a device, without opening it;
    * a file with a second name (a hard link), which keeps every byte under
      that name: what a backup tool kept, or a file of someone else's that
      was linked in under one of IronDome's names to have IronDome destroy it;
    * a file owned by another user.

    The one exception is device material: a file directly in a bunker's
    device directory (``device_dir()``, or the same directory of another
    bunker) is overwritten under every name it has, because each of them is
    the device secret and erasing it is the point -- the rule
    :mod:`irondome.nuke` applies to that directory.

    What is overwritten is decided on the open descriptor, not on the name:
    a link, a pipe or another file swapped in after the check is never what
    gets overwritten. A read-only file of ours is made writable through a
    descriptor on it, never through its name.

    A name that is already gone is not an error. Raises ``OSError`` if the
    name is still there afterwards.
    """
    path = Path(path)
    try:
        seen = os.lstat(str(path))
    except OSError as exc:
        if exc.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
            return  # nothing under that name to remove
        raise
    if stat.S_ISREG(seen.st_mode) and seen.st_size > 0:
        try:
            _overwrite(path, seen, every_name=_device_material(path))
        except OSError:
            pass  # a file that cannot be overwritten must still be removed below
    try:
        os.unlink(str(path))
    except FileNotFoundError:
        pass  # removed by another process in the meantime: gone, as asked


def _device_material(path: Path) -> bool:
    """Whether *path* is directly in a bunker's device directory, where every name of a file is device material.

    Decided from the path as given, never by following links: a path that
    does not spell out that directory is treated as anything else.
    """
    parent = Path(os.path.abspath(str(path))).parent
    return parent.parent == device_root() / _BUNKERS and _BUNKER_NAME.fullmatch(parent.name) is not None


def _may_overwrite(opened: os.stat_result, seen: os.stat_result, every_name: bool) -> bool:
    """Whether the file behind a descriptor (its fstat, *opened*) is the one lstat saw, and may be overwritten."""
    return (
        stat.S_ISREG(opened.st_mode)
        and (opened.st_dev, opened.st_ino) == (seen.st_dev, seen.st_ino)
        and (every_name or opened.st_nlink == 1)
        and (not hasattr(os, "geteuid") or opened.st_uid == os.geteuid())
    )


def _open_to_overwrite(path: Path, seen: os.stat_result, every_name: bool) -> Optional[Tuple[int, int]]:
    """``(descriptor, size)`` of *path* open for writing, or ``None`` when it must not be overwritten.

    A link swapped in is not followed (``O_NOFOLLOW``), a pipe or device is
    not waited on, and the descriptor must be the file *seen* describes. A
    read-only file passes the same test on a read-only descriptor before
    that descriptor makes it writable.
    """
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    flags = os.O_WRONLY | nofollow | _NO_WAIT
    try:
        fd = os.open(str(path), flags)
    except PermissionError:
        probe = os.open(str(path), os.O_RDONLY | nofollow | _NO_WAIT)
        try:
            if not _may_overwrite(os.fstat(probe), seen, every_name):
                return None
            if hasattr(os, "fchmod"):
                os.fchmod(probe, FILE_MODE)
            else:
                os.chmod(str(path), FILE_MODE)  # Windows before Python 3.13: this only clears the read-only flag
        finally:
            os.close(probe)
        fd = os.open(str(path), flags)
    try:
        opened = os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise
    if not _may_overwrite(opened, seen, every_name):
        os.close(fd)
        return None
    return fd, opened.st_size


def _overwrite(path: Path, seen: os.stat_result, *, every_name: bool) -> None:
    """Overwrite the file *seen* describes once with random bytes and flush it, if it may be (see secure_delete)."""
    opened = _open_to_overwrite(path, seen, every_name)
    if opened is None:
        return
    fd, size = opened
    try:
        remaining = size
        while remaining > 0:
            remaining -= os.write(fd, os.urandom(min(remaining, 1 << 20)))
        _fsync(fd)
    finally:
        os.close(fd)
