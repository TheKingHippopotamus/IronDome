"""Where files go, how they are written, locked and destroyed."""

from __future__ import annotations

import errno
import os
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Dict, Iterator, List

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from irondome import paths
from irondome.errors import UsageError, VaultError

POSIX = os.name == "posix"
posix_only = pytest.mark.skipif(not POSIX, reason="POSIX permissions and locks")


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def within(seconds: float, call: Callable[[], object]) -> object:
    """Run *call* on a thread and fail, rather than hang the suite, if it blocks."""
    box: Dict[str, object] = {}

    def run() -> None:
        try:
            box["value"] = call()
        except BaseException as exc:  # handed back to the test thread below
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        pytest.fail(f"still blocked after {seconds} seconds")
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return box.get("value")


def wait_for(path: Path, seconds: float = 90.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if path.exists():
            return True
        time.sleep(0.01)
    return False


@pytest.fixture
def umask() -> Iterator[Callable[[int], None]]:
    """Set the process umask for one test and put the old one back afterwards."""
    original = os.umask(0o022)
    os.umask(original)

    def set_umask(value: int) -> None:
        os.umask(value)

    yield set_umask
    os.umask(original)


def leftovers(directory: Path) -> List[str]:
    return sorted(item.name for item in directory.iterdir() if item.name.startswith(".tmp-"))


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------


def test_modes_are_owner_only():
    assert paths.FILE_MODE == 0o600 and paths.DIR_MODE == 0o700
    assert 1024 * 1024 <= paths.MAX_FILE_BYTES <= 1024**3


def test_overrides_from_the_environment(isolated, monkeypatch):
    monkeypatch.setenv("IRONDOME_HOME", str(isolated / "elsewhere" / "vault"))
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", str(isolated / "elsewhere" / "device"))
    monkeypatch.setenv("IRONDOME_LEGACY_DIR", str(isolated / "elsewhere" / "old"))
    assert paths.root() == isolated / "elsewhere" / "vault"
    assert paths.device_root() == isolated / "elsewhere" / "device"
    assert paths.home() == isolated / "elsewhere" / "vault" / "bunkers" / "alpha"
    assert paths.device_dir() == isolated / "elsewhere" / "device" / "bunkers" / "alpha"
    assert paths.legacy_v3_dir() == isolated / "elsewhere" / "old"


def test_everything_else_hangs_off_the_two_roots(isolated):
    home, device = paths.home(), paths.device_dir()
    assert home == isolated / "irondome" / "bunkers" / "alpha"
    assert device == isolated / "device" / "bunkers" / "alpha"
    assert paths.vault_file() == home / "vault.irondome"
    assert paths.backups_dir() == home / "backups"
    assert paths.caps_dir() == home / "caps"
    assert paths.audit_file() == home / "audit.log"
    assert paths.config_file() == home / "config.json"
    assert paths.lock_file() == home / ".lock"
    assert paths.helper_dir() == isolated / "device" / "helper"  # one helper cache for every bunker
    assert home not in device.parents and device not in home.parents and home != device


def test_the_device_directory_is_never_inside_the_vault_directory_by_default(isolated, monkeypatch):
    monkeypatch.delenv("IRONDOME_HOME")
    monkeypatch.delenv("IRONDOME_DEVICE_DIR")
    home, device = paths.home(), paths.device_dir()
    assert paths.root() == isolated / "userhome" / ".irondome"
    assert home == isolated / "userhome" / ".irondome" / "bunkers" / "alpha"
    assert str(device).startswith(str(isolated / "userhome"))
    assert home != device and home not in device.parents and device not in home.parents


@pytest.mark.skipif(sys.platform != "darwin", reason="the macOS default")
def test_default_device_directory_on_macos(isolated, monkeypatch):
    monkeypatch.delenv("IRONDOME_DEVICE_DIR")
    assert paths.device_root() == isolated / "userhome" / "Library" / "Application Support" / "IronDome" / "device"
    assert paths.device_dir() == paths.device_root() / "bunkers" / "alpha"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the Linux default")
def test_default_device_directory_on_linux(isolated, monkeypatch):
    monkeypatch.delenv("IRONDOME_DEVICE_DIR")
    assert paths.device_root() == isolated / "userhome" / ".local" / "state" / "irondome" / "device"
    monkeypatch.setenv("XDG_STATE_HOME", str(isolated / "state"))
    assert paths.device_root() == isolated / "state" / "irondome" / "device"
    monkeypatch.delenv("XDG_STATE_HOME")
    assert paths.device_root() == isolated / "userhome" / ".local" / "state" / "irondome" / "device"
    assert paths.device_dir() == paths.device_root() / "bunkers" / "alpha"


def test_default_legacy_directory_follows_home(isolated, monkeypatch):
    monkeypatch.delenv("IRONDOME_LEGACY_DIR")
    assert paths.legacy_v3_dir() == isolated / "userhome" / ".password_manager"


@pytest.mark.parametrize("name", ["IRONDOME_HOME", "IRONDOME_DEVICE_DIR", "IRONDOME_LEGACY_DIR"])
def test_an_empty_override_means_the_default(isolated, monkeypatch, name):
    lookup = {"IRONDOME_HOME": paths.home, "IRONDOME_DEVICE_DIR": paths.device_dir,
              "IRONDOME_LEGACY_DIR": paths.legacy_v3_dir}[name]
    monkeypatch.delenv(name)
    default = lookup()
    monkeypatch.setenv(name, "")
    assert lookup() == default
    assert str(default).startswith(str(isolated / "userhome"))


def test_overrides_are_made_absolute_and_expand_the_home_directory(isolated, monkeypatch):
    monkeypatch.chdir(isolated)
    monkeypatch.setenv("IRONDOME_HOME", "relative/vault")
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", "~/keys/../device-keys")
    assert paths.root() == Path(os.path.abspath("relative/vault"))
    assert paths.home().is_absolute()
    assert paths.device_root() == isolated / "userhome" / "device-keys"


# ---------------------------------------------------------------------------
# ensure_dir
# ---------------------------------------------------------------------------


@posix_only
@pytest.mark.parametrize("mask", [0o000, 0o022, 0o077, 0o002, 0o777])
def test_ensure_dir_makes_every_missing_level_owner_only(isolated, umask, mask):
    """The whole chain is 0700, not only the last directory, whatever the umask."""
    umask(mask)
    deep = isolated / "a" / "b" / "c" / "d"
    assert paths.ensure_dir(deep) == deep
    for level in (isolated / "a", isolated / "a" / "b", isolated / "a" / "b" / "c", deep):
        assert level.is_dir() and mode(level) == 0o700, level


@posix_only
def test_the_roots_and_their_parents_are_created_owner_only(isolated, umask, monkeypatch):
    umask(0)
    monkeypatch.setenv("IRONDOME_HOME", str(isolated / "x" / "y" / "home"))
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", str(isolated / "p" / "q" / "device"))
    paths.ensure_dir(paths.backups_dir())
    paths.ensure_dir(paths.helper_dir())
    paths.ensure_dir(paths.device_dir())
    made = [isolated / "x", isolated / "x" / "y", paths.root(), paths.root() / "bunkers", paths.home(),
            paths.backups_dir(), isolated / "p", isolated / "p" / "q", paths.device_root(), paths.helper_dir(),
            paths.device_root() / "bunkers", paths.device_dir()]
    assert [mode(directory) for directory in made] == [0o700] * len(made)


@posix_only
def test_ensure_dir_tightens_irondomes_own_directories(isolated):
    for own in (paths.home(), paths.device_dir(), paths.caps_dir(), paths.helper_dir()):
        own.mkdir(parents=True, exist_ok=True)
        os.chmod(own, 0o777)  # noqa: S103 - deliberately wide open, to see it tightened
        paths.ensure_dir(own)
        assert mode(own) == 0o700


@posix_only
def test_ensure_dir_leaves_other_peoples_directories_alone(isolated):
    """A folder a backup is written into is not IronDome's to re-permission."""
    foreign = isolated / "shared"
    foreign.mkdir()
    os.chmod(foreign, 0o1777)  # noqa: S103 - like /tmp, to see it left alone
    assert paths.ensure_dir(foreign) == foreign
    assert mode(foreign) == 0o1777
    paths.ensure_dir(foreign / "new" / "deeper")
    assert mode(foreign) == 0o1777
    assert mode(foreign / "new") == 0o700 and mode(foreign / "new" / "deeper") == 0o700
    paths.write_atomic(foreign / "export.bin", b"data")
    assert mode(foreign) == 0o1777 and mode(foreign / "export.bin") == 0o600


def test_ensure_dir_is_idempotent_and_returns_what_it_was_given(isolated):
    target = paths.home() / "caps"
    assert paths.ensure_dir(target) == target
    (target / "keep").write_text("x")
    assert paths.ensure_dir(str(target)) == target
    assert (target / "keep").read_text() == "x"


def test_ensure_dir_accepts_a_relative_path(isolated, monkeypatch):
    monkeypatch.chdir(isolated)
    assert paths.ensure_dir("made/here") == Path("made/here")
    assert (isolated / "made" / "here").is_dir()
    if POSIX:
        assert mode(isolated / "made") == 0o700 and mode(isolated / "made" / "here") == 0o700


def test_ensure_dir_refuses_a_path_that_is_a_file(isolated):
    blocker = isolated / "blocker"
    blocker.write_text("x")
    with pytest.raises(FileExistsError):
        paths.ensure_dir(blocker)
    with pytest.raises(OSError):
        paths.ensure_dir(blocker / "below")
    assert blocker.read_text() == "x"


@posix_only
def test_ensure_dir_through_a_symlink_to_a_directory(isolated):
    real = isolated / "real"
    real.mkdir()
    (isolated / "link").symlink_to(real)
    paths.ensure_dir(isolated / "link" / "inside")
    assert (real / "inside").is_dir()
    with pytest.raises(OSError):
        (isolated / "dangling").symlink_to(isolated / "nowhere")
        paths.ensure_dir(isolated / "dangling")


def test_ensure_dir_survives_a_race_with_another_creator(isolated, monkeypatch):
    target = isolated / "raced" / "dir"
    real_mkdir = os.mkdir

    def racing_mkdir(path, mode=0o777):
        real_mkdir(path, mode)  # someone else gets there first...
        raise FileExistsError(errno.EEXIST, "File exists", str(path))

    monkeypatch.setattr(os, "mkdir", racing_mkdir)
    assert paths.ensure_dir(target) == target
    assert target.is_dir()


# ---------------------------------------------------------------------------
# write_atomic
# ---------------------------------------------------------------------------


@posix_only
@pytest.mark.parametrize("mask", [0o000, 0o022, 0o077, 0o777])
def test_write_atomic_creates_owner_only_files_under_any_umask(isolated, umask, mask):
    umask(mask)
    target = paths.home() / "sub" / "file.bin"
    paths.write_atomic(target, b"payload")
    assert target.read_bytes() == b"payload"
    assert mode(target) == 0o600
    assert mode(target.parent) == 0o700 and mode(paths.home()) == 0o700


@pytest.mark.parametrize("data", [b"", b"x", b"payload", bytearray(b"from a bytearray"), memoryview(b"from a view")])
def test_write_atomic_writes_what_it_is_given(isolated, data):
    target = paths.home() / "file.bin"
    paths.write_atomic(target, data)
    assert target.read_bytes() == bytes(data)
    assert leftovers(target.parent) == []


def test_write_atomic_writes_large_data_completely(isolated):
    data = os.urandom(5 * 1024 * 1024 + 17)
    target = paths.home() / "large.bin"
    paths.write_atomic(str(target), data)
    assert target.read_bytes() == data


@posix_only
def test_write_atomic_replaces_content_and_mode(isolated):
    target = paths.home() / "file.bin"
    paths.ensure_dir(target.parent)
    target.write_bytes(b"old content, readable by everyone")
    os.chmod(target, 0o644)
    paths.write_atomic(target, b"new")
    assert target.read_bytes() == b"new" and mode(target) == 0o600
    assert leftovers(target.parent) == []


def test_write_atomic_gives_the_file_a_new_inode(isolated):
    """Replace by rename: readers holding the old file keep a complete old file."""
    target = paths.home() / "file.bin"
    paths.write_atomic(target, b"first version")
    with open(target, "rb") as old:
        paths.write_atomic(target, b"second version")
        assert old.read() == b"first version"
    assert target.read_bytes() == b"second version"


@pytest.mark.parametrize("failing", ["replace", "fsync", "write"])
def test_a_failed_write_leaves_the_old_file_and_no_temporary_file(isolated, monkeypatch, failing):
    target = paths.home() / "vault.irondome"
    paths.write_atomic(target, b"the old vault")

    def crash(*args, **kwargs):
        raise OSError(errno.EIO, "the disk went away")

    with monkeypatch.context() as scoped:
        # The flush goes through paths._fsync (F_FULLFSYNC on macOS), so that is where it fails.
        scoped.setattr(*((paths, "_fsync") if failing == "fsync" else (os, failing)), crash)
        with pytest.raises(OSError, match="the disk went away"):
            paths.write_atomic(target, b"the new vault that never arrives")
    assert target.read_bytes() == b"the old vault"
    assert leftovers(target.parent) == []
    assert sorted(item.name for item in target.parent.iterdir()) == ["vault.irondome"]


def test_an_interrupted_write_cleans_up_too(isolated, monkeypatch):
    target = paths.home() / "vault.irondome"
    paths.write_atomic(target, b"the old vault")

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "replace", interrupt)
        with pytest.raises(KeyboardInterrupt):
            paths.write_atomic(target, b"new")
    assert target.read_bytes() == b"the old vault" and leftovers(target.parent) == []


def test_a_partial_write_is_continued(isolated, monkeypatch):
    real_write = os.write
    sizes: List[int] = []

    def trickle(fd, data):
        chunk = bytes(data[:7])
        sizes.append(len(chunk))
        return real_write(fd, chunk)

    target = paths.home() / "file.bin"
    with monkeypatch.context() as scoped:
        scoped.setattr(os, "write", trickle)
        paths.write_atomic(target, b"0123456789" * 5)
    assert target.read_bytes() == b"0123456789" * 5
    assert len(sizes) == 8


@posix_only
def test_write_atomic_replaces_a_symlink_instead_of_writing_through_it(isolated):
    elsewhere = isolated / "elsewhere.txt"
    elsewhere.write_bytes(b"not ours")
    target = paths.home() / "file.bin"
    paths.ensure_dir(target.parent)
    target.symlink_to(elsewhere)
    paths.write_atomic(target, b"ours")
    assert not target.is_symlink() and target.read_bytes() == b"ours"
    assert elsewhere.read_bytes() == b"not ours"


def test_readers_never_see_a_half_written_file(isolated):
    """Many replacements while a reader loops: every read is one complete version."""
    target = paths.home() / "file.bin"
    versions = [bytes([65 + index]) * 200_000 for index in range(4)]
    paths.write_atomic(target, versions[0])
    stop = threading.Event()
    seen: List[bytes] = []
    problems: List[str] = []

    def reader() -> None:
        while not stop.is_set():
            try:
                data = target.read_bytes()
            except OSError as exc:
                problems.append(repr(exc))
                return
            if data not in versions:
                problems.append(f"read {len(data)} bytes that match no version")
                return
            seen.append(data[:1])

    thread = threading.Thread(target=reader)
    thread.start()
    try:
        for round_number in range(40):
            paths.write_atomic(target, versions[round_number % 4])
    finally:
        stop.set()
        thread.join(30)
    assert problems == []
    assert seen


@pytest.mark.skipif(sys.platform != "darwin", reason="F_FULLFSYNC is a macOS control")
def test_on_macos_the_rename_is_flushed_to_the_drive(isolated, monkeypatch):
    import fcntl

    issued: List[int] = []
    real_fcntl = fcntl.fcntl

    def recording(fd, command, *args):
        issued.append(command)
        return real_fcntl(fd, command, *args)

    monkeypatch.setattr(fcntl, "fcntl", recording)
    paths.write_atomic(paths.home() / "file.bin", b"payload")
    assert fcntl.F_FULLFSYNC in issued


@pytest.mark.skipif(sys.platform != "darwin", reason="F_FULLFSYNC is a macOS control")
def test_a_filesystem_without_full_sync_falls_back_to_fsync(isolated, monkeypatch):
    import fcntl

    synced: List[int] = []
    real_fsync = os.fsync

    def refusing(fd, command, *args):
        raise OSError(errno.ENOTTY, "Inappropriate ioctl for device")

    def recording_fsync(fd):
        synced.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(fcntl, "fcntl", refusing)
    monkeypatch.setattr(os, "fsync", recording_fsync)
    target = paths.home() / "file.bin"
    paths.write_atomic(target, b"payload")
    assert target.read_bytes() == b"payload"
    assert len(synced) == 2  # the file, then its directory


@given(st.binary(max_size=4096))
@settings(max_examples=40, deadline=None)
def test_write_then_read_round_trips(data):
    target = paths.home() / "property.bin"
    paths.write_atomic(target, data)
    assert paths.read_file(target) == data
    assert leftovers(target.parent) == []


# ---------------------------------------------------------------------------
# read_file
# ---------------------------------------------------------------------------


def test_read_file_returns_the_bytes(isolated):
    target = isolated / "file.bin"
    target.write_bytes(b"\x00\x01binary\xff")
    assert paths.read_file(target) == b"\x00\x01binary\xff"
    assert paths.read_file(str(target)) == b"\x00\x01binary\xff"


def test_read_file_of_a_missing_file_raises_file_not_found(isolated):
    with pytest.raises(FileNotFoundError):
        paths.read_file(isolated / "nothing-here")


def test_read_file_of_a_directory_is_an_os_error(isolated):
    with pytest.raises(OSError):
        paths.read_file(isolated)


def test_read_file_refuses_a_file_over_the_cap(isolated, monkeypatch):
    monkeypatch.setattr(paths, "MAX_FILE_BYTES", 1000)
    exact, over = isolated / "exact.bin", isolated / "over.bin"
    exact.write_bytes(b"x" * 1000)
    over.write_bytes(b"x" * 1001)
    assert len(paths.read_file(exact)) == 1000
    with pytest.raises(VaultError, match="too large"):
        paths.read_file(over)


def test_read_file_checks_the_cap_before_reading(isolated, monkeypatch):
    """A sparse file far over the cap is refused from its size alone: not one byte of it is read."""
    huge = isolated / "huge.bin"
    with open(huge, "wb") as handle:
        handle.truncate(paths.MAX_FILE_BYTES + 1)
    reads: List[int] = []
    real_read = os.read

    def recording_read(fd: int, count: int) -> bytes:
        reads.append(count)
        return real_read(fd, count)

    monkeypatch.setattr(os, "read", recording_read)
    with pytest.raises(VaultError, match="too large"):
        paths.read_file(huge)
    assert reads == []


def test_read_file_caps_a_file_that_grows_while_it_is_read(isolated, monkeypatch):
    """The size checked first can be out of date by the time the file is read: what is read is capped as well."""
    monkeypatch.setattr(paths, "MAX_FILE_BYTES", 1000)
    target = isolated / "growing.bin"
    target.write_bytes(b"y" * 5000)
    real_fstat = os.fstat

    def size_a_moment_ago(fd: int) -> os.stat_result:
        info = real_fstat(fd)
        return os.stat_result(tuple(info[:6]) + (900,) + tuple(info[7:10]))

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "fstat", size_a_moment_ago)
        with pytest.raises(VaultError, match="too large"):
            paths.read_file(target)


def test_read_file_honours_a_smaller_limit(isolated):
    target = isolated / "small.json"
    target.write_bytes(b"x" * 100)
    assert paths.read_file(target, limit=100) == b"x" * 100
    with pytest.raises(VaultError, match="too large"):
        paths.read_file(target, limit=99)
    assert len(paths.read_file(target)) == 100, "the default stays MAX_FILE_BYTES"


@posix_only
def test_read_file_follows_a_symbolic_link_to_a_regular_file(isolated):
    real = isolated / "real.json"
    real.write_bytes(b"{}")
    (isolated / "link.json").symlink_to(real)
    assert paths.read_file(isolated / "link.json") == b"{}"


# ---------------------------------------------------------------------------
# Pipes and devices in a file's place are never waited on (red team round 1, hostile-input:2)
# ---------------------------------------------------------------------------


@pytest.fixture
def fifos() -> Iterator[Callable[[Path], Path]]:
    """Make named pipes. Afterwards each is opened once for reading and writing without waiting, which lets
    any thread still blocked on it go on: a test run against code that waits fails, and leaves nothing behind."""
    made: List[Path] = []

    def make(path: Path) -> Path:
        paths.ensure_dir(path.parent)
        os.mkfifo(str(path))
        made.append(path)
        return path

    yield make
    for path in made:
        try:
            fd = os.open(str(path), os.O_RDWR | os.O_NONBLOCK)
        except OSError:
            continue
        time.sleep(0.2)
        os.close(fd)


def feed_pipe(pipe: Path, payload: bytes) -> threading.Thread:
    """A writer that waits for a reader of *pipe*, writes *payload* and goes away."""

    def writer() -> None:
        try:
            with open(pipe, "wb") as handle:
                handle.write(payload)
        except OSError:
            pass  # the reader went away first

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    return thread


@posix_only
@pytest.mark.parametrize("writer", [False, True], ids=["nothing writes to it", "something writes to it"])
def test_read_file_refuses_a_pipe_at_once(isolated, fifos, writer):
    """Opening a pipe for reading waits for a writer: every command that reads the file would hang with it."""
    pipe = fifos(isolated / "config.json")
    if writer:
        feed_pipe(pipe, b'{"grant_ttl": 120}')
    started = time.monotonic()
    with pytest.raises(OSError, match="not a regular file") as caught:
        within(10, lambda: paths.read_file(pipe))
    assert time.monotonic() - started < 5
    assert caught.value.errno == errno.EINVAL and caught.value.filename == str(pipe)


@posix_only
@pytest.mark.skipif(not os.path.exists("/dev/null"), reason="needs /dev/null")
def test_read_file_refuses_a_device(isolated):
    with pytest.raises(OSError, match="not a regular file"):
        within(10, lambda: paths.read_file("/dev/null"))


@posix_only
def test_a_pipe_in_place_of_the_default_bunker_setting_is_refused_at_once(isolated, fifos):
    """Every command asks which bunker it works on: a pipe there would hold up every one of them."""
    fifos(paths.root() / "default-bunker")
    with pytest.raises(UsageError, match="cannot read the default bunker") as caught:
        within(10, paths.bunker_name)
    assert "not a regular file" in str(caught.value)


def test_a_default_bunker_setting_longer_than_any_name_is_refused(isolated):
    paths.ensure_dir(paths.root())
    (paths.root() / "default-bunker").write_bytes(b"bravo" + b" " * 300 + b"\n")
    with pytest.raises(UsageError, match="does not hold a valid bunker name"):
        paths.default_bunker()
    paths.set_default_bunker("bravo")
    assert paths.default_bunker() == "bravo"


@posix_only
def test_flushing_a_directory_never_waits_on_a_pipe_swapped_in_for_it(isolated, fifos):
    pipe = fifos(isolated / "caps")
    assert within(10, lambda: paths._fsync_dir(pipe)) is None


# ---------------------------------------------------------------------------
# file_lock
# ---------------------------------------------------------------------------

LOCK_CHILD = r"""
import sys
from pathlib import Path
from irondome import paths
lock, started, acquired, release = (Path(item) for item in sys.argv[1:5])
started.write_text("x")
with paths.file_lock(lock):
    acquired.write_text("x")
    while not release.exists():
        import time
        time.sleep(0.01)
"""

TRY_LOCK_CHILD = r"""
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    print("free")
except BlockingIOError:
    print("held")
"""


def spawn_locker(isolated: Path, lock: Path, tag: str) -> Dict[str, object]:
    marks = {name: isolated / f"{tag}.{name}" for name in ("started", "acquired", "release")}
    process = subprocess.Popen(
        [sys.executable, "-c", LOCK_CHILD, str(lock), str(marks["started"]), str(marks["acquired"]),
         str(marks["release"])],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return {"process": process, **marks}


def finish(child: Dict[str, object]) -> None:
    child["release"].write_text("x")  # type: ignore[union-attr]
    process = child["process"]
    try:
        _, stderr = process.communicate(timeout=30)  # type: ignore[union-attr]
    except subprocess.TimeoutExpired:
        process.kill()  # type: ignore[union-attr]
        process.communicate()  # type: ignore[union-attr]
        pytest.fail("the lock-holding child did not finish")
    assert process.returncode == 0, stderr.decode()  # type: ignore[union-attr]


def lock_state(lock: Path) -> str:
    result = subprocess.run([sys.executable, "-c", TRY_LOCK_CHILD, str(lock)], capture_output=True, text=True,
                            timeout=60)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@posix_only
def test_file_lock_keeps_a_second_process_out(isolated):
    lock = paths.lock_file()
    with paths.file_lock():
        child = spawn_locker(isolated, lock, "second")
        try:
            assert wait_for(child["started"])
            time.sleep(0.5)
            assert not child["acquired"].exists(), "a second process got the lock while this one held it"
        finally:
            pass
    try:
        assert wait_for(child["acquired"]), "the second process never got the lock after it was released"
    finally:
        finish(child)


@posix_only
def test_this_process_waits_while_another_holds_the_lock(isolated):
    lock = paths.lock_file()
    child = spawn_locker(isolated, lock, "holder")
    order: List[str] = []
    try:
        assert wait_for(child["acquired"])

        def take() -> None:
            with paths.file_lock():
                order.append("taken")

        thread = threading.Thread(target=take, daemon=True)
        thread.start()
        time.sleep(0.5)
        assert order == [], "the lock was taken while another process held it"
        order.append("released by the other process")
    finally:
        finish(child)
    thread.join(30)
    assert order == ["released by the other process", "taken"]


@posix_only
def test_a_killed_holder_releases_the_lock(isolated):
    lock = paths.lock_file()
    child = spawn_locker(isolated, lock, "doomed")
    assert wait_for(child["acquired"])
    assert lock_state(lock) == "held"
    child["process"].kill()  # type: ignore[union-attr]
    child["process"].communicate()  # type: ignore[union-attr]

    def take() -> str:
        with paths.file_lock():
            return "taken"

    assert within(20, take) == "taken"


@posix_only
def test_file_lock_is_released_when_the_block_ends_or_raises(isolated):
    lock = paths.lock_file()
    with paths.file_lock():
        assert lock_state(lock) == "held"
    assert lock_state(lock) == "free"
    with pytest.raises(RuntimeError):
        with paths.file_lock():
            raise RuntimeError("boom")
    assert lock_state(lock) == "free"
    assert paths._held == {}


@posix_only
def test_file_lock_creates_an_owner_only_lock_file(isolated, umask):
    umask(0)
    with paths.file_lock():
        pass
    assert mode(paths.lock_file()) == 0o600 and mode(paths.home()) == 0o700
    custom = isolated / "other" / "dir" / "my.lock"
    with paths.file_lock(custom):
        assert lock_state(custom) == "held"
    assert mode(custom) == 0o600 and mode(custom.parent) == 0o700


@posix_only
def test_file_lock_may_be_taken_again_by_the_thread_that_holds_it(isolated):
    """Vault.commit takes the lock itself; a caller already holding it must not deadlock."""
    lock = paths.lock_file()
    steps: List[str] = []

    def nested() -> str:
        with paths.file_lock():
            with paths.file_lock():
                with paths.file_lock(lock):  # the same file, named explicitly
                    steps.append(lock_state(lock))
                steps.append(lock_state(lock))
            steps.append(lock_state(lock))
        steps.append(lock_state(lock))
        return "done"

    assert within(60, nested) == "done"
    assert steps == ["held", "held", "held", "free"]  # only the outermost block releases it
    assert paths._held == {}


@posix_only
def test_file_lock_still_excludes_other_threads(isolated):
    inside = threading.Event()
    leave = threading.Event()
    order: List[str] = []

    def first() -> None:
        with paths.file_lock():
            inside.set()
            leave.wait(30)
            order.append("first leaves")

    def second() -> None:
        with paths.file_lock():
            order.append("second enters")

    one = threading.Thread(target=first, daemon=True)
    one.start()
    assert inside.wait(30)
    two = threading.Thread(target=second, daemon=True)
    two.start()
    time.sleep(0.4)
    assert order == []
    leave.set()
    one.join(30)
    two.join(30)
    assert order == ["first leaves", "second enters"]


@posix_only
def test_separate_lock_files_are_independent(isolated):
    def both() -> str:
        with paths.file_lock(isolated / "one.lock"):
            with paths.file_lock(isolated / "two.lock"):
                return lock_state(isolated / "one.lock") + "/" + lock_state(isolated / "two.lock")

    assert within(60, both) == "held/held"


@posix_only
def test_a_lock_reached_through_a_symlink_is_the_same_lock(isolated):
    real = paths.ensure_dir(isolated / "real")
    (isolated / "alias").symlink_to(real)

    def nested() -> str:
        with paths.file_lock(real / ".lock"):
            with paths.file_lock(isolated / "alias" / ".lock"):
                return "done"

    assert within(30, nested) == "done"


# ---------------------------------------------------------------------------
# secure_delete
# ---------------------------------------------------------------------------


def test_secure_delete_removes_the_file(isolated):
    target = isolated / "secret.bin"
    target.write_bytes(b"device key material")
    assert paths.secure_delete(target) is None
    assert not target.exists()
    paths.secure_delete(str(target))  # already gone: not an error


@posix_only
@pytest.mark.parametrize("size", [1, 32, 4096, 3 * 1024 * 1024 + 5])
def test_secure_delete_overwrites_before_it_unlinks(isolated, size):
    """Seen through a descriptor opened before: the blocks the name pointed to no longer hold the content."""
    target = isolated / "secret.bin"
    original = (b"SECRET-KEY-" * (size // 11 + 1))[:size]
    target.write_bytes(original)
    witness = os.open(str(target), os.O_RDONLY)
    try:
        paths.secure_delete(target)
        assert not target.exists()
        after = os.pread(witness, size + 1, 0)
    finally:
        os.close(witness)
    assert len(after) == size
    if size >= 32:  # a single random byte may equal the one it replaces
        assert after != original
        assert b"SECRET-KEY-" not in after
        assert len(set(after)) > 8  # random bytes, not a constant fill


def test_secure_delete_of_a_missing_path_is_silent(isolated):
    paths.secure_delete(isolated / "never-existed")
    paths.secure_delete(isolated / "no-such-dir" / "file")


def test_secure_delete_of_an_empty_file(isolated):
    target = isolated / "empty"
    target.write_bytes(b"")
    paths.secure_delete(target)
    assert not target.exists()


@posix_only
def test_secure_delete_removes_a_symlink_and_spares_its_target(isolated):
    victim = isolated / "victim.txt"
    victim.write_bytes(b"must survive untouched")
    link = isolated / "link"
    link.symlink_to(victim)
    paths.secure_delete(link)
    assert not link.is_symlink() and not link.exists()
    assert victim.read_bytes() == b"must survive untouched"


@posix_only
def test_secure_delete_removes_a_dangling_symlink(isolated):
    link = isolated / "dangling"
    link.symlink_to(isolated / "nowhere")
    paths.secure_delete(link)
    assert not link.is_symlink()


@contextmanager
def swapped_just_before_it_is_opened(monkeypatch, target: Path, swap: Callable[[], None]) -> Iterator[None]:
    """Run *swap* the first time *target* is opened: what a process racing the check between lstat and open does."""
    real_open = os.open
    pending = [True]

    def racing_open(path, flags, *args, **kwargs):
        if pending and os.fspath(path) == str(target):
            pending.clear()
            swap()
        return real_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "open", racing_open)
        yield


@posix_only
@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="needs O_NOFOLLOW")
def test_secure_delete_never_overwrites_through_a_link_swapped_in_late(isolated, monkeypatch):
    """The file is replaced by a link between the check and the overwrite: the link's target must survive."""
    victim = isolated / "victim.txt"
    victim.write_bytes(b"must survive untouched")
    target = isolated / "secret.bin"
    target.write_bytes(b"SECRET-KEY-" * 10)

    def swap() -> None:
        os.unlink(str(target))
        os.symlink(str(victim), str(target))

    with swapped_just_before_it_is_opened(monkeypatch, target, swap):
        paths.secure_delete(target)
    assert victim.read_bytes() == b"must survive untouched"
    assert not target.is_symlink() and not target.exists()


@posix_only
def test_secure_delete_never_overwrites_a_hard_link_swapped_in_late(isolated, monkeypatch):
    """Between the check and the open the name comes to stand for another file: that file is not overwritten."""
    victim = isolated / "victim.txt"
    victim.write_bytes(b"must survive untouched\n" * 10)
    target = isolated / "secret.bin"
    target.write_bytes(b"SECRET-KEY-" * 40)

    def swap() -> None:
        os.unlink(str(target))
        os.link(str(victim), str(target))

    with swapped_just_before_it_is_opened(monkeypatch, target, swap):
        paths.secure_delete(target)
    assert victim.read_bytes() == b"must survive untouched\n" * 10
    assert not os.path.lexists(str(target))


@posix_only
def test_secure_delete_never_waits_on_a_pipe_swapped_in_late(isolated, monkeypatch, fifos):
    target = isolated / "secret.bin"
    target.write_bytes(b"SECRET-KEY-" * 40)

    def swap() -> None:
        os.unlink(str(target))
        fifos(target)

    with swapped_just_before_it_is_opened(monkeypatch, target, swap):
        within(10, lambda: paths.secure_delete(target))
    assert not os.path.lexists(str(target))


@posix_only
def test_secure_delete_overwrites_a_read_only_file(isolated):
    target = isolated / "readonly.bin"
    target.write_bytes(b"SECRET-KEY-" * 10)
    os.chmod(target, 0o400)
    witness = os.open(str(target), os.O_RDONLY)
    try:
        paths.secure_delete(target)
        assert not target.exists()
        assert b"SECRET-KEY-" not in os.pread(witness, 200, 0)
    finally:
        os.close(witness)


# -- a file with a second name (red team round 1, filesystem:3) ---------------------------------------------


def plant(name: Path, victim: Path, content: bytes) -> None:
    """A file that is not IronDome's, linked in under one of IronDome's names."""
    paths.ensure_dir(victim.parent)
    victim.write_bytes(content)
    paths.ensure_dir(name.parent)
    os.link(str(victim), str(name))


@posix_only
@pytest.mark.parametrize("where", ["backups", "caps", "home", "elsewhere"])
def test_secure_delete_leaves_a_second_name_every_byte(isolated, where):
    """An overwrite changes the file, not the name, so it would reach the other name: only the name goes."""
    name = {
        "backups": paths.backups_dir() / "vault-0000000099.irondome",
        "caps": paths.caps_dir() / ("0123456789abcdef" * 2 + ".json"),
        "home": paths.vault_file(),
        "elsewhere": isolated / "exports" / "backup.irondome",
    }[where]
    victim = isolated / "victim" / "thesis.txt"
    plant(name, victim, b"years of work\n" * 100)

    paths.secure_delete(name)

    assert not os.path.lexists(str(name))
    assert victim.read_bytes() == b"years of work\n" * 100
    assert os.stat(str(victim)).st_nlink == 1


@posix_only
def test_secure_delete_does_not_even_make_a_read_only_file_with_a_second_name_writable(isolated):
    victim = isolated / "victim" / "taxes.txt"
    name = paths.caps_dir() / ("fedcba9876543210" * 2 + ".json")
    plant(name, victim, b"2025 return\n")
    os.chmod(str(victim), 0o444)

    paths.secure_delete(name)

    assert not os.path.lexists(str(name))
    assert victim.read_bytes() == b"2025 return\n" and mode(victim) == 0o444


@posix_only
def test_secure_delete_never_overwrites_a_file_of_another_user(isolated, monkeypatch):
    target = isolated / "theirs.bin"
    target.write_bytes(b"THEIRS-" * 40)
    witness = os.open(str(target), os.O_RDONLY)
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(os, "geteuid", lambda: os.getuid() + 1)  # as if the file were someone else's
            paths.secure_delete(target)
        assert not target.exists()
        assert os.pread(witness, 400, 0) == b"THEIRS-" * 40
    finally:
        os.close(witness)


@posix_only
def test_secure_delete_overwrites_device_material_under_every_name(isolated):
    """A device key's every name is the key, and erasing it is the point: the rule nuke applies to that directory."""
    key = paths.ensure_dir(paths.device_dir()) / ("ab" * 16 + ".key")
    key.write_bytes(b"0123456789abcdef0123456789abcdef")
    copy = isolated / "kept-by-a-backup-tool" / "device.key"
    copy.parent.mkdir()
    os.link(str(key), str(copy))

    paths.secure_delete(key)

    assert not key.exists()
    left = copy.read_bytes()
    assert len(left) == 32 and left != b"0123456789abcdef0123456789abcdef" and len(set(left)) > 8


def test_only_a_file_directly_in_a_bunkers_device_directory_is_device_material(isolated):
    bunkers = paths.device_root() / "bunkers"
    assert paths._device_material(paths.device_dir() / "x.key")
    assert paths._device_material(bunkers / "bravo" / "x.json")
    assert paths._device_material(Path(os.path.relpath(str(paths.device_dir() / "x.key"))))
    for other in (
        paths.device_dir() / "sub" / "x.key",
        bunkers / "Not-A-Name" / "x.key",
        bunkers / "x.key",
        paths.device_root() / "helper" / "irondome-se-0123456789abcdef",
        paths.caps_dir() / "x.json",
        paths.backups_dir() / "vault-0000000001.irondome",
        paths.vault_file(),
        isolated / "elsewhere" / "alpha" / "x.key",
    ):
        assert not paths._device_material(other), other


@posix_only
def test_no_caller_destroys_what_a_second_name_planted_under_an_irondome_name_holds(isolated, vault):
    """The red team's scenarios: snapshot rotation and purging (passwd, rekey), and sweeping (every unlock),
    revoking and destroying capabilities. Each victim is a file of the owner's linked in under an IronDome name."""
    from irondome import caps
    from irondome.vault import Secret

    outside = isolated / "owner-files"
    victims = {
        "rotated": (paths.backups_dir() / "vault-9999999999.irondome", outside / "photo.jpg"),
        "swept": (paths.caps_dir() / ".tmp-planted1", outside / "diary.txt"),
        "revoked": (paths.caps_dir() / ("0123456789abcdef" * 2 + ".json"), outside / "taxes.txt"),
        "destroyed": (paths.caps_dir() / ("fedcba9876543210" * 2 + ".json"), outside / "notes.txt"),
        "purged": (paths.backups_dir() / "vault-9999999998.irondome", outside / "thesis.txt"),
    }

    def content(what: str) -> bytes:
        return f"the owner's {what} file\n".encode() * 50

    for what, (name, victim) in victims.items():
        if what != "purged":
            plant(name, victim, content(what))
    vault.add("one-more", Secret(password="written while one snapshot is kept"))
    vault.commit(snapshots=1)  # a snapshot numbered above the vault's generation is rotated out first
    caps.sweep()
    caps.revoke("0123456789")
    caps.destroy_all()
    plant(*victims["purged"], content("purged"))
    vault.purge_snapshots()

    for what, (name, victim) in victims.items():
        assert not os.path.lexists(str(name)), what
        assert victim.read_bytes() == content(what), what


@posix_only
def test_secure_delete_of_a_directory_raises(isolated):
    directory = isolated / "a-directory"
    directory.mkdir()
    with pytest.raises(OSError):
        paths.secure_delete(directory)
    assert directory.is_dir()


@posix_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores directory permissions")
def test_secure_delete_reports_a_file_it_cannot_remove(isolated):
    directory = isolated / "locked-dir"
    directory.mkdir()
    target = directory / "secret.bin"
    target.write_bytes(b"SECRET-KEY-" * 10)
    os.chmod(directory, 0o500)
    try:
        with pytest.raises(OSError):
            paths.secure_delete(target)
        assert target.exists()
        assert b"SECRET-KEY-" not in target.read_bytes()  # removal failed, the overwrite did not
    finally:
        os.chmod(directory, 0o700)


def test_secure_delete_still_unlinks_when_the_overwrite_fails(isolated, monkeypatch):
    target = isolated / "secret.bin"
    target.write_bytes(b"content")

    def broken_write(fd, data):
        raise OSError(errno.EIO, "I/O error")

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "write", broken_write)
        paths.secure_delete(target)
    assert not target.exists()


def test_secure_delete_syncs_the_overwrite_before_unlinking(isolated, monkeypatch):
    order: List[str] = []
    real_fsync, real_unlink = paths._fsync, os.unlink

    def recording_fsync(fd):
        order.append("fsync")
        return real_fsync(fd)

    def recording_unlink(path, *args, **kwargs):
        order.append("unlink")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(paths, "_fsync", recording_fsync)
    monkeypatch.setattr(os, "unlink", recording_unlink)
    target = isolated / "secret.bin"
    target.write_bytes(b"content")
    paths.secure_delete(target)
    assert order == ["fsync", "unlink"]


# -- what a write killed before its rename leaves -------------------------------------------------


def test_sweep_temporary_takes_only_old_files_named_as_write_atomic_names_them(isolated):
    directory = paths.ensure_dir(paths.home())
    old = time.time() - 300

    def made(name: str, *, age_old: bool = True) -> Path:
        path = directory / name
        path.write_bytes(b"a whole vault, as it was being written")
        if age_old:
            os.utime(path, (old, old))
        return path

    abandoned = [made(".tmp-abcdefgh"), made(".tmp-_9x0k2aa")]
    young = made(".tmp-12345678", age_old=False)  # a write in progress keeps its file for milliseconds
    others = [made(".tmp-rekey-0123456789abcdef.irondome"), made(".tmp-short"), made("vault.irondome"),
              made(".tmp-QRSTUVWX"), made(".tmp-abcdefghi")]  # mkstemp writes lower case, digits and "_"
    target = made("pointed-at")
    link = directory / ".tmp-linkname"
    os.symlink(str(target), str(link))
    os.utime(str(link), (old, old), follow_symlinks=False)
    folder = directory / ".tmp-dir00000"
    folder.mkdir()
    os.utime(folder, (old, old))

    assert paths.sweep_temporary(directory) == 2
    assert not any(path.exists() for path in abandoned)
    assert young.exists() and all(path.exists() for path in others)
    assert link.is_symlink() and target.exists() and folder.is_dir()
    assert paths.sweep_temporary(directory, older_than=0) == 1 and not young.exists()
    assert paths.sweep_temporary(directory / "not-there") == 0


def test_a_killed_write_leaves_a_file_that_the_sweep_then_removes(isolated):
    """SIGKILL between the write and the rename: the old file is intact and the temporary one is a whole copy."""
    directory = paths.ensure_dir(paths.home())
    target = directory / "vault.irondome"
    paths.write_atomic(target, b"the old vault")
    script = (
        "import os, signal, sys\n"
        "from irondome import paths\n"
        "def kill(*args): os.kill(os.getpid(), signal.SIGKILL)\n"
        "os.replace = kill\n"
        "paths.write_atomic(sys.argv[1], b'the new vault, never renamed into place')\n"
    )
    ran = subprocess.run([sys.executable, "-c", script, str(target)], capture_output=True, timeout=60)
    assert ran.returncode == -9
    left = [path for path in directory.iterdir() if path.name.startswith(".tmp-")]
    assert target.read_bytes() == b"the old vault" and len(left) == 1
    assert left[0].read_bytes() == b"the new vault, never renamed into place"
    assert paths.sweep_temporary(directory, older_than=0) == 1
    assert [path.name for path in directory.iterdir()] == ["vault.irondome"]


# -- the device directory is kept out of Time Machine (found by hand on a Mac) -------------------------------


@pytest.mark.skipif(sys.platform != "darwin", reason="Time Machine is macOS")
def test_the_device_directory_is_marked_as_left_out_of_backups_when_it_is_made() -> None:
    """A whole-home backup held the sealed device keys, so copying both folders back undid `nuke`."""
    import plistlib

    assert not paths.device_root().exists()
    paths.ensure_dir(paths.device_dir())
    assert paths.excluded_from_backup(paths.device_root()) is True
    assert paths.excluded_from_backup(paths.root().parent) is False  # the mark is on that directory alone
    # The mark is the one `tmutil addexclusion` writes, byte for byte (read back with macOS's own tool).
    shown = subprocess.run(
        ["/usr/bin/xattr", "-px", "com.apple.metadata:com_apple_backup_excludeItem", str(paths.device_root())],
        capture_output=True, text=True, timeout=30, env={"PATH": "/usr/bin:/bin"},
    )
    assert shown.returncode == 0
    assert plistlib.loads(bytes.fromhex("".join(shown.stdout.split()))) == "com.apple.backupd"


@pytest.mark.skipif(sys.platform != "darwin", reason="Time Machine is macOS")
def test_a_directory_made_without_ensure_dir_is_reported_as_not_marked(tmp_path: Path) -> None:
    bare = tmp_path / "bare"
    bare.mkdir()
    assert paths.excluded_from_backup(bare) is False
    assert paths.exclude_from_backup(bare) is True and paths.excluded_from_backup(bare) is True
    assert paths.exclude_from_backup(tmp_path / "missing") is False


@pytest.mark.skipif(sys.platform == "darwin", reason="everywhere but macOS")
def test_off_macos_there_is_no_backup_mark(tmp_path: Path) -> None:
    assert paths.exclude_from_backup(tmp_path) is None and paths.excluded_from_backup(tmp_path) is None
