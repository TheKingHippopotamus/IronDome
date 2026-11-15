"""Locked, wipeable memory and the two ways a secret is read into it."""

from __future__ import annotations

import copy
import ctypes
import errno
import gc
import io
import json
import os
import pickle
import signal
import subprocess
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from irondome import secmem
from irondome.errors import UsageError
from irondome.secmem import SecureBuffer, as_view, read_secret, read_secret_from_fd, wipe_bytes

CPYTHON = sys.implementation.name == "cpython"
POSIX = os.name == "posix"


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


def fresh_bytes(text: str) -> bytes:
    """A bytes object nothing else refers to (constants in this file are shared)."""
    return bytes(bytearray(text.encode("utf-8")))


def fresh_str(code_points: List[int]) -> str:
    """A str object nothing else refers to."""
    return "".join([chr(code) for code in code_points])


@pytest.fixture(autouse=True)
def no_real_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test in this file may open the terminal the suite was started from."""
    real_open = os.open

    def guarded(path, flags, *args, **kwargs):
        if path == "/dev/tty":
            raise OSError(errno.ENXIO, "Device not configured")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded)


# ---------------------------------------------------------------------------
# SecureBuffer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", [0, -1, -4096, True, False, 1.5, "8", None, b"8"])
def test_size_must_be_a_positive_integer(size):
    with pytest.raises(ValueError):
        SecureBuffer(size)


@pytest.mark.parametrize("size", [1, 31, 32, 4095, 4096, 4097, 70_000])
def test_a_new_buffer_is_zeroed_writable_and_exactly_as_long_as_asked(size):
    with SecureBuffer(size) as buffer:
        view = buffer.view()
        assert len(buffer) == size == len(view)
        assert bytes(view) == bytes(size)
        assert view.readonly is False and view.format == "B"
        view[size - 1] = 0x55
        view[0] = 0xAA
        assert view[0] == 0xAA and (size == 1 or view[size - 1] == 0x55)


def test_wipe_zeroes_the_memory_itself():
    buffer = SecureBuffer(64)
    buffer.view()[:] = b"\xa5" * 64
    kept = buffer.view()[:]  # a second view of the same pages, outliving the wipe
    assert bytes(kept) == b"\xa5" * 64
    buffer.wipe()
    assert bytes(kept) == bytes(64)
    kept.release()


def test_wipe_zeroes_a_buffer_larger_than_a_page():
    size = 3 * secmem._PAGE + 17
    buffer = SecureBuffer.random(size)
    kept = buffer.view()[:]
    assert bytes(kept) != bytes(size)
    buffer.wipe()
    assert bytes(kept) == bytes(size)
    kept.release()


def test_wipe_is_idempotent():
    buffer = SecureBuffer.random(32)
    assert buffer.wiped is False
    buffer.wipe()
    assert buffer.wiped is True
    buffer.wipe()
    buffer.wipe()
    assert buffer.wiped is True and len(buffer) == 32


def test_view_after_wipe_raises():
    buffer = SecureBuffer.random(32)
    view = buffer.view()
    buffer.wipe()
    with pytest.raises(ValueError, match="wiped"):
        buffer.view()
    with pytest.raises(ValueError):
        bytes(view)  # the view handed out earlier was released, not left pointing at zeros
    with pytest.raises(ValueError):
        as_view(buffer)
    with pytest.raises(ValueError):
        buffer.copy()


def test_context_manager_wipes_on_exit():
    with SecureBuffer.random(32) as buffer:
        kept = buffer.view()[:]
        assert buffer.wiped is False
    assert buffer.wiped is True
    assert bytes(kept) == bytes(32)
    kept.release()


def test_context_manager_wipes_when_the_block_raises():
    kept = None
    with pytest.raises(RuntimeError):
        with SecureBuffer.random(32) as buffer:
            kept = buffer.view()[:]
            raise RuntimeError("boom")
    assert buffer.wiped is True
    assert bytes(kept) == bytes(32)
    kept.release()


def test_dropping_the_last_reference_wipes():
    buffer = SecureBuffer.random(48)
    kept = buffer.view()[:]
    del buffer
    gc.collect()
    assert bytes(kept) == bytes(48)
    kept.release()


def test_locked_is_a_bool_and_cleared_by_wipe():
    buffer = SecureBuffer(32)
    assert isinstance(buffer.locked, bool)
    buffer.wipe()
    assert buffer.locked is False


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="mlock is expected to work on macOS and Linux")
def test_one_page_can_be_locked_into_ram():
    with SecureBuffer(32) as buffer:
        assert buffer.locked is True, "mlock was refused: check RLIMIT_MEMLOCK"
        assert "locked" in repr(buffer)


def test_a_buffer_the_os_will_not_lock_still_works(monkeypatch):
    monkeypatch.setattr(secmem, "_lock_pages", lambda address, length: False)
    unlocked: List[int] = []
    monkeypatch.setattr(secmem, "_unlock_pages", lambda address, length: unlocked.append(length))
    buffer = SecureBuffer.random(32)
    assert buffer.locked is False
    assert "unlocked" in repr(buffer)
    kept = buffer.view()[:]
    buffer.wipe()
    assert bytes(kept) == bytes(32)
    assert unlocked == []  # nothing was locked, so nothing is unlocked
    kept.release()


def test_lock_pages_reports_refusal_instead_of_raising(monkeypatch):
    monkeypatch.setattr(secmem, "_get_libc", lambda: None)
    assert secmem._lock_pages(0, 4096) is False
    secmem._unlock_pages(0, 4096)  # and unlocking without a C library is a no-op


def test_random_is_filled_and_differs_between_calls():
    with SecureBuffer.random(32) as first, SecureBuffer.random(32) as second:
        a, b = bytes(first.view()), bytes(second.view())
    assert len(a) == len(b) == 32
    assert a != bytes(32) and b != bytes(32)
    assert a != b


@pytest.mark.parametrize("size", [1, 255, 256, 257, 1000, 5000])
def test_random_fills_every_part_of_a_large_buffer(size):
    with SecureBuffer.random(size) as buffer:
        data = bytes(buffer.view())
    assert len(data) == size
    for start in range(0, size - 63, 64):  # every 64-byte window holds something
        assert any(data[start : start + 64]), f"zeros at offset {start}"
    if size >= 64:
        assert len(set(data)) > 16


def test_random_without_getentropy_uses_the_os_generator(monkeypatch):
    monkeypatch.setattr(secmem, "_get_libc", lambda: None)
    with SecureBuffer.random(300) as first, SecureBuffer.random(300) as second:
        a, b = bytes(first.view()), bytes(second.view())
    assert a != b and a != bytes(300)
    assert any(a[256:]), "the part beyond the first 256 bytes was not filled"


def test_random_falls_back_when_getentropy_fails(monkeypatch):
    calls: List[int] = []

    class FailingGetentropy:
        argtypes = None
        restype = None

        def __call__(self, pointer, length):
            calls.append(length)
            return -1

    libc = types.SimpleNamespace(getentropy=FailingGetentropy(), mlock=None, munlock=None)
    monkeypatch.setattr(secmem, "_get_libc", lambda: libc)
    with SecureBuffer.random(300) as buffer:
        data = bytes(buffer.view())
    assert calls == [256]
    assert data != bytes(300) and any(data[:256]) and any(data[256:])


@pytest.mark.parametrize("kind", ["bytes", "bytearray", "memoryview", "securebuffer"])
def test_from_buffer_copies(kind):
    original = bytearray(b"correct horse battery staple")
    if kind == "bytes":
        source: object = bytes(original)
    elif kind == "bytearray":
        source = original
    elif kind == "memoryview":
        source = memoryview(original)
    else:
        source = SecureBuffer.from_buffer(original)
    with SecureBuffer.from_buffer(source) as buffer:  # type: ignore[arg-type]
        assert bytes(buffer.view()) == b"correct horse battery staple"
        original[:] = b"X" * len(original)
        if isinstance(source, SecureBuffer):
            source.wipe()
        assert bytes(buffer.view()) == b"correct horse battery staple"
        buffer.view()[0] = ord("C")
        assert original == b"X" * len(original)


def test_from_buffer_refuses_nothing_at_all():
    for empty in (b"", bytearray(), memoryview(b"")):
        with pytest.raises(ValueError):
            SecureBuffer.from_buffer(empty)


def test_copy_is_independent():
    with SecureBuffer.from_buffer(b"0123456789abcdef") as original:
        duplicate = original.copy()
        assert duplicate is not original
        assert bytes(duplicate.view()) == bytes(original.view())
        original.view()[0] = 0xFF
        assert duplicate.view()[0] == ord("0")
    assert duplicate.wiped is False
    assert bytes(duplicate.view()) == b"0123456789abcdef"
    duplicate.wipe()


def test_cannot_be_pickled_or_copied_by_the_copy_module():
    with SecureBuffer.from_buffer(b"key material") as buffer:
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with pytest.raises(TypeError, match="pickled"):
                pickle.dumps(buffer, protocol=protocol)
        with pytest.raises(TypeError):
            copy.copy(buffer)
        with pytest.raises(TypeError):
            copy.deepcopy(buffer)


def test_repr_and_str_never_show_the_contents():
    with SecureBuffer.from_buffer(b"hunter2hunter2hunter2") as buffer:
        for text in (repr(buffer), str(buffer), f"{buffer}", "%s" % buffer, "%r" % (buffer,)):
            assert "hunter2" not in text
            assert b"hunter2".hex() not in text
            assert "21 bytes" in text
        assert repr(buffer).startswith("<SecureBuffer")
    assert "wiped" in repr(buffer)


def test_contents_are_reachable_only_through_view():
    with SecureBuffer.from_buffer(b"key material") as buffer:
        with pytest.raises(TypeError):
            bytes(buffer)  # type: ignore[call-overload]
        with pytest.raises(TypeError):
            memoryview(buffer)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            list(buffer)  # type: ignore[call-overload]
        with pytest.raises(TypeError):
            buffer[0]  # type: ignore[index]
        with pytest.raises(AttributeError):
            buffer.note = "x"  # type: ignore[attr-defined]
        assert not hasattr(buffer, "__dict__")


def test_wipe_releases_the_mapping():
    buffer = SecureBuffer.random(32)
    mapping = buffer._map
    buffer.wipe()
    assert mapping.closed


def test_wipe_with_an_outstanding_view_zeroes_now_and_releases_later():
    buffer = SecureBuffer.random(32)
    mapping = buffer._map
    kept = buffer.view()[:]
    buffer.wipe()
    assert bytes(kept) == bytes(32)
    assert not mapping.closed  # still referenced by the view; freed when it goes
    kept.release()
    mapping.close()
    assert mapping.closed


def _ctypes_array(buffer: SecureBuffer) -> Tuple[memoryview, Sequence[Any]]:
    array = (ctypes.c_char * 16).from_buffer(buffer.view())
    return memoryview(array), (array,)


def _export_of_the_view(buffer: SecureBuffer) -> Tuple[memoryview, Sequence[Any]]:
    full = buffer.view()
    return full, (pickle.PickleBuffer(full),)  # an export: view() itself cannot be released either


#: What a caller can keep that outlives wipe(): (the writable view to test, what keeps it alive).
OUTLIVING_VIEWS: Dict[str, Callable[[SecureBuffer], Tuple[memoryview, Sequence[Any]]]] = {
    "a slice": lambda buffer: (buffer.view()[:16], ()),
    "a cast": lambda buffer: (buffer.view().cast("B"), ()),
    "a memoryview of the view": lambda buffer: (memoryview(buffer.view()), ()),
    "a ctypes array over the view": _ctypes_array,
    "an export of the view itself": _export_of_the_view,
}


@pytest.mark.skipif(not POSIX, reason="a read(2) into a page that cannot be written fails with EFAULT on POSIX")
@pytest.mark.parametrize("form", sorted(OUTLIVING_VIEWS))
def test_a_view_that_outlives_wipe_reads_zeros_and_can_be_given_nothing_new(form):
    """The late fill the pages must refuse: a pipe read straight into them, as a device backend reads its secret."""
    buffer = SecureBuffer.random(32)
    mapping = buffer._map
    target, keep = OUTLIVING_VIEWS[form](buffer)
    buffer.wipe()
    assert buffer.wiped and not buffer.locked and not mapping.closed  # the view keeps the pages mapped
    assert bytes(target) == bytes(len(target))
    reader, writer = os.pipe()
    try:
        os.write(writer, b"K" * len(target))
        with pytest.raises(OSError) as refused:
            io.FileIO(reader, "rb", closefd=False).readinto(target)
        assert refused.value.errno == errno.EFAULT
    finally:
        os.close(reader)
        os.close(writer)
    assert bytes(target) == bytes(len(target))
    buffer.wipe()  # and a second wipe, which has nothing left to do, changes none of it
    assert bytes(target) == bytes(len(target))
    for holder in keep:
        if isinstance(holder, pickle.PickleBuffer):
            holder.release()
    target.release()


FAULT_SCRIPT = r"""
import ctypes, os, signal, sys
sys.path.insert(0, sys.argv[1])
from irondome.secmem import SecureBuffer
libc = ctypes.CDLL(None)
libc.signal.argtypes = [ctypes.c_int, ctypes.c_void_p]
libc.signal.restype = ctypes.c_void_p
end = ctypes.cast(libc._exit, ctypes.c_void_p).value
for number in (signal.SIGSEGV, signal.SIGBUS):
    libc.signal(number, end)  # a memory fault ends the process at once, its number as the status: no crash report
buffer = SecureBuffer(32)
kept = buffer.view()[:16]
buffer.wipe()
os.write(1, b"wiped\n")
kept[:] = b"K" * 16
os.write(1, b"written\n")
"""


@pytest.mark.skipif(not POSIX, reason="the fault is caught with a POSIX signal handler")
def test_a_write_through_a_view_that_outlived_wipe_stops_the_process_at_that_write():
    """Late key material through a stale slice (a derive_into, a decrypt_into) never lands: the write faults."""
    package_parent = str(Path(secmem.__file__).resolve().parent.parent)
    result = subprocess.run([sys.executable, "-I", "-B", "-c", FAULT_SCRIPT, package_parent], capture_output=True,
                            timeout=60)
    assert result.stdout == b"wiped\n", (result.stdout, result.stderr)
    assert result.returncode in (signal.SIGSEGV, signal.SIGBUS), (result.returncode, result.stderr)


def test_make_read_only_reports_refusal_instead_of_raising(monkeypatch):
    monkeypatch.setattr(secmem, "_get_libc", lambda: None)
    assert secmem._make_read_only(0, 4096) is False

    def refuse(*args: object) -> int:
        raise OSError("refused")

    monkeypatch.setattr(secmem, "_get_libc", lambda: types.SimpleNamespace(mprotect=refuse))
    assert secmem._make_read_only(0, 4096) is False


def test_pages_that_cannot_be_made_read_only_are_kept_locked_and_zeroed_again(monkeypatch):
    """Where the system refuses: every later wipe, and the exit, zero the pages again; then they are unmapped."""
    monkeypatch.setattr(secmem, "_make_read_only", lambda address, length: False)
    monkeypatch.setattr(secmem, "_held", [])
    monkeypatch.setattr(secmem, "_held_at_exit", [])
    at_exit: List[Callable[[], None]] = []
    monkeypatch.setattr(secmem.atexit, "register", at_exit.append)
    buffer = SecureBuffer.random(32)
    address, mapping = buffer._address, buffer._map
    relocked: List[int] = []
    real_lock = secmem._lock_pages

    def counting_lock(where: int, length: int) -> bool:
        relocked.append(where)
        return real_lock(where, length)

    monkeypatch.setattr(secmem, "_lock_pages", counting_lock)
    kept = buffer.view()[:16]
    buffer.wipe()
    assert relocked == [address]
    assert secmem._held == [(mapping, address, secmem._PAGE)] and at_exit == [secmem._zero_held]
    assert bytes(kept) == bytes(16)
    kept[:] = b"K" * 16  # the late write that read-only pages would have refused
    SecureBuffer(8).wipe()  # any later wipe zeroes the held pages again
    assert bytes(kept) == bytes(16) and not mapping.closed
    kept[:] = b"L" * 16
    at_exit[0]()  # and so does the exit
    assert bytes(kept) == bytes(16) and not mapping.closed
    kept.release()
    SecureBuffer(8).wipe()  # the view has gone: the next wipe unmaps them
    assert mapping.closed and secmem._held == []


def test_concurrent_wipes_release_the_buffer_exactly_once(monkeypatch):
    released: List[int] = []
    real_unlock = secmem._unlock_pages

    def counting_unlock(address, length):
        released.append(address)
        real_unlock(address, length)

    monkeypatch.setattr(secmem, "_unlock_pages", counting_unlock)
    monkeypatch.setattr(secmem, "_lock_pages", lambda address, length: True)  # so every wipe would unlock
    buffers = [SecureBuffer(32) for _ in range(40)]
    start = threading.Barrier(8)

    def worker() -> None:
        start.wait()
        for buffer in buffers:
            buffer.wipe()

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert all(buffer.wiped for buffer in buffers)
    assert len(released) == len(buffers) == len(set(released))


def test_a_failed_constructor_leaves_nothing_to_wipe():
    buffer = SecureBuffer.__new__(SecureBuffer)
    with pytest.raises(ValueError):
        buffer.__init__(0)  # type: ignore[misc]
    del buffer  # the destructor of a half-built object must stay silent
    gc.collect()


@given(st.binary(min_size=1, max_size=2048))
@settings(max_examples=60, deadline=None)
def test_from_buffer_round_trips_any_bytes(data):
    buffer = SecureBuffer.from_buffer(data)
    kept = buffer.view()[:]
    assert bytes(buffer.view()) == data and len(buffer) == len(data)
    buffer.wipe()
    assert bytes(kept) == bytes(len(data))
    kept.release()


def test_as_view():
    with SecureBuffer.from_buffer(b"abc") as buffer:
        assert as_view(buffer) is buffer.view()
    data = bytearray(b"abc")
    view = as_view(data)
    assert isinstance(view, memoryview) and bytes(view) == b"abc"
    view[0] = ord("z")
    assert data == b"zbc"
    assert bytes(as_view(b"abc")) == b"abc" and as_view(b"abc").readonly


# -- fork --------------------------------------------------------------------

FORK_SCRIPT = r"""
import os, sys
from irondome.secmem import SecureBuffer
buffer = SecureBuffer.from_buffer(b"S" * 32)
sys.stdout.flush()
pid = os.fork()
if pid == 0:
    seen = bytes(buffer.view())
    os.write(1, b"child-sees:" + seen + b"\n")
    sys.exit(0)  # a normal exit: destructors run, among them the buffer's
_, status = os.waitpid(pid, 0)
killed_by = os.WTERMSIG(status) if os.WIFSIGNALED(status) else 0
exit_status = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
os.write(1, b"signal:%d exit:%d\n" % (killed_by, exit_status))
os.write(1, b"parent-sees:" + bytes(buffer.view()) + b"\n")
buffer.wipe()
"""


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
def test_a_forked_child_exits_cleanly_and_the_parent_keeps_its_key():
    """A child's destructors run wipe() too; that must not crash it (it did under MADV_DONTFORK)."""
    result = subprocess.run([sys.executable, "-c", FORK_SCRIPT], capture_output=True, timeout=60)
    lines = result.stdout.splitlines()
    assert result.returncode == 0, result.stderr.decode()
    assert b"signal:0 exit:0" in lines, result.stdout
    assert b"parent-sees:" + b"S" * 32 in lines
    if sys.platform.startswith("linux"):
        assert b"child-sees:" + bytes(32) in lines, "the child must be handed zeros, not the key"


# ---------------------------------------------------------------------------
# wipe_bytes
# ---------------------------------------------------------------------------


def test_wipe_bytes_on_a_bytearray():
    data = bytearray(b"secret material")
    assert wipe_bytes(data) is True
    assert data == bytes(15) and len(data) == 15
    assert wipe_bytes(bytearray()) is True


def test_wipe_bytes_on_a_bytearray_that_has_a_view():
    data = bytearray(b"secret material")
    view = memoryview(data)
    assert wipe_bytes(data) is True
    assert bytes(view) == bytes(15)


def test_wipe_bytes_on_a_writable_memoryview():
    data = bytearray(b"secret material")
    assert wipe_bytes(memoryview(data)[3:9]) is True
    assert data == b"sec" + bytes(6) + b"terial"


def test_wipe_bytes_refuses_a_read_only_memoryview():
    data = fresh_bytes("secret material")
    assert wipe_bytes(memoryview(data)) is False
    assert data == b"secret material"


@pytest.mark.skipif(not CPYTHON, reason="in-place zeroing of bytes is CPython-specific")
def test_wipe_bytes_on_bytes():
    data = fresh_bytes("secret material")
    assert wipe_bytes(data) is True
    assert data == bytes(15) and len(data) == 15
    big = bytes(bytearray(os.urandom(100_000)))
    assert wipe_bytes(big) is True and big == bytes(100_000)


def test_wipe_bytes_leaves_the_shared_short_bytes_alone():
    empty, single = bytes(bytearray()), bytes(bytearray(b"a"))
    assert wipe_bytes(empty) is False and wipe_bytes(single) is False
    assert empty == b"" and single == b"a"
    assert bytes([97]) == b"a" and bytes([0x61])[0] == 0x61  # the cached one-byte objects are intact


def test_wipe_bytes_refuses_everything_else():
    class Derived(bytes):
        pass

    derived = Derived(b"secret material")
    for thing in (None, 5, 5.0, ["a"], ("a",), {"a": 1}, object(), derived):
        assert wipe_bytes(thing) is False
    assert derived == b"secret material"


def test_wipe_bytes_never_touches_a_str():
    """Strings are shared too freely (interned names, constants) to be zeroed through a public function."""
    text = fresh_str([ord(char) for char in "a secret that happens to be text"])
    assert wipe_bytes(text) is False
    assert text == "a secret that happens to be text"
    shared = json.dumps({})  # on some interpreters this is one interned object, used everywhere
    assert wipe_bytes(shared) is False
    assert shared == "{}" and json.dumps({}) == "{}" and "{}".format("intact") == "intact"


@pytest.mark.skipif(not CPYTHON, reason="in-place zeroing of str is CPython-specific")
@pytest.mark.parametrize(
    "code_points",
    [
        [ord(c) for c in "plain ascii password"],
        [0xE9, 0x74, 0xE9, 0x20, 0xFF],  # Latin-1: one byte per character
        [0x5E1, 0x5D9, 0x5E1, 0x5DE, 0x5D4, 0x20, 0x31],  # Hebrew: two bytes per character
        [0x1F511, 0x61, 0x1F512, 0x5D0],  # outside the basic plane: four bytes per character
    ],
    ids=["ascii", "latin-1", "two-byte", "four-byte"],
)
def test_wipe_str(code_points):
    text = fresh_str(code_points)
    length = len(text)
    assert secmem._wipe_str(text) is True
    assert len(text) == length
    assert all(ord(char) == 0 for char in text)
    assert secmem._wipe_str(text) in (True, False)  # a second call must be harmless whatever it decides
    assert all(ord(char) == 0 for char in text)


def test_wipe_str_leaves_short_and_empty_strings_alone():
    for text in (fresh_str([]), fresh_str([0x61]), fresh_str([0xE9]), fresh_str([0x5D0])):
        before = [ord(char) for char in text]
        assert secmem._wipe_str(text) is False
        assert [ord(char) for char in text] == before
    assert chr(0x61) == "a" and chr(0xE9) == "\xe9"


@pytest.mark.skipif(not CPYTHON, reason="the cached UTF-8 form is a CPython detail")
def test_wipe_str_leaves_a_string_with_an_unexpected_layout_alone():
    """A str carrying a cached UTF-8 copy does not match the measured layout: it is not touched."""
    text = fresh_str([0x5E1, 0x5D9, 0x5E1, 0x5DE, 0x5D4])
    as_utf8 = ctypes.pythonapi.PyUnicode_AsUTF8AndSize
    as_utf8.argtypes = [ctypes.py_object, ctypes.c_void_p]
    as_utf8.restype = ctypes.c_void_p
    assert as_utf8(text, None)  # makes CPython cache the UTF-8 encoding inside the object
    assert secmem._wipe_str(text) is False
    assert text == fresh_str([0x5E1, 0x5D9, 0x5E1, 0x5DE, 0x5D4])


@pytest.mark.skipif(not CPYTHON, reason="in-place zeroing of str is CPython-specific")
@given(st.text(min_size=2, max_size=200))
@settings(max_examples=150, deadline=None)
def test_wipe_str_zeroes_exactly_the_string_it_is_given(sample):
    before = fresh_str([0x41, 0x5D0, 0x1F511])  # allocated around it: must be untouched
    text = fresh_str([ord(char) for char in sample])
    after = fresh_str([0x42, 0x5D1, 0x1F512])
    assert secmem._wipe_str(text) is True
    assert len(text) == len(sample) and all(ord(char) == 0 for char in text)
    assert [ord(char) for char in before] == [0x41, 0x5D0, 0x1F511]
    assert [ord(char) for char in after] == [0x42, 0x5D1, 0x1F512]


# ---------------------------------------------------------------------------
# harden_process
# ---------------------------------------------------------------------------

HARDEN_SCRIPT = r"""
import sys
from irondome import secmem
secmem.harden_process()
import resource
print("core", resource.getrlimit(resource.RLIMIT_CORE)[0])
if sys.platform.startswith("linux"):
    import ctypes
    print("dumpable", ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))
"""


@pytest.mark.skipif(not POSIX, reason="resource limits are POSIX")
def test_harden_process_disables_core_dumps():
    env = dict(os.environ)
    env.pop("IRONDOME_DEBUG", None)
    result = subprocess.run([sys.executable, "-c", HARDEN_SCRIPT], capture_output=True, text=True, timeout=60, env=env)
    assert result.returncode == 0, result.stderr
    assert "core 0" in result.stdout.splitlines()
    if sys.platform.startswith("linux"):
        assert "dumpable 0" in result.stdout.splitlines()


@pytest.mark.skipif(not POSIX, reason="resource limits are POSIX")
def test_harden_process_can_be_switched_off_for_debugging():
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    if hard == 0:
        pytest.skip("core dumps are already disabled for this session")
    script = (
        "import resource\n"
        "resource.setrlimit(resource.RLIMIT_CORE, (1024, resource.getrlimit(resource.RLIMIT_CORE)[1]))\n"
        "from irondome import secmem\n"
        "secmem.harden_process()\n"
        "print('core', resource.getrlimit(resource.RLIMIT_CORE)[0])\n"
    )
    env = dict(os.environ, IRONDOME_DEBUG="1")
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60, env=env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "core 1024"


def test_harden_process_never_raises(monkeypatch):
    monkeypatch.delenv("IRONDOME_DEBUG", raising=False)
    import resource

    def refuse(*args):
        raise ValueError("not allowed to raise the limit")

    monkeypatch.setattr(resource, "setrlimit", refuse)
    secmem.harden_process()


# ---------------------------------------------------------------------------
# read_secret_from_fd
# ---------------------------------------------------------------------------


def piped(data: bytes, *, close_writer: bool = True):
    reader, writer = os.pipe()
    os.write(writer, data)
    if close_writer:
        os.close(writer)
        return reader, None
    return reader, writer


def read_all(reader: int, writer: Optional[int], **kwargs) -> Optional[bytes]:
    try:
        result = within(10, lambda: read_secret_from_fd(reader, **kwargs))
    finally:
        os.close(reader)
        if writer is not None:
            os.close(writer)
    if result is None:
        return None
    assert isinstance(result, SecureBuffer)
    with result:
        return bytes(result.view())


@pytest.mark.parametrize(
    "sent, expected",
    [
        (b"hunter2\n", b"hunter2"),
        (b"hunter2\r\n", b"hunter2"),
        (b"hunter2", b"hunter2"),
        (b"hunter2\r", b"hunter2"),
        (b"hunter2\r\r\n", b"hunter2"),
        (b"  spaces kept  \n", b"  spaces kept  "),
        (b"tab\tinside\n", b"tab\tinside"),
        (b"cr\rinside\n", b"cr\rinside"),
        ("סיסמה-\U0001f511\n".encode("utf-8"), "סיסמה-\U0001f511".encode("utf-8")),
        (b"nul\x00inside\n", b"nul\x00inside"),
        (b"\xff\xfe not utf-8\n", b"\xff\xfe not utf-8"),
    ],
    ids=["lf", "crlf", "no-newline", "bare-cr", "cr-cr-lf", "spaces", "tab", "cr-inside", "utf-8", "nul", "binary"],
)
def test_read_secret_from_fd_reads_one_line(sent, expected):
    assert read_all(*piped(sent)) == expected


@pytest.mark.parametrize("sent", [b"", b"\n", b"\r\n", b"\r\r\n"])
def test_read_secret_from_fd_refuses_an_empty_secret(sent):
    with pytest.raises(UsageError, match="nothing was entered"):
        read_all(*piped(sent))


@pytest.mark.parametrize("sent", [b"", b"\n", b"\r\n"])
def test_read_secret_from_fd_returns_none_for_empty_when_allowed(sent):
    assert read_all(*piped(sent), allow_empty=True) is None


def test_read_secret_from_fd_leaves_everything_after_the_newline_unread():
    reader, writer = piped(b"first-line\nsecond-line\nthird", close_writer=False)
    try:
        with within(10, lambda: read_secret_from_fd(reader)) as first:  # type: ignore[union-attr]
            assert bytes(first.view()) == b"first-line"
        with within(10, lambda: read_secret_from_fd(reader)) as second:  # type: ignore[union-attr]
            assert bytes(second.view()) == b"second-line"
        assert os.read(reader, 100) == b"third"
    finally:
        os.close(reader)
        os.close(writer)


def test_read_secret_from_fd_takes_the_longest_secret_that_fits():
    longest = b"x" * (secmem._MAX_SECRET - 1)
    assert read_all(*piped(longest + b"\n")) == longest
    assert read_all(*piped(longest)) == longest


@pytest.mark.parametrize("extra", [0, 1, 5000])
def test_read_secret_from_fd_refuses_a_secret_that_is_too_long(extra):
    with pytest.raises(UsageError, match="too long"):
        read_all(*piped(b"x" * (secmem._MAX_SECRET + extra) + b"\n"))


def test_read_secret_from_fd_returns_exactly_sized_locked_memory():
    reader, _ = piped(b"hunter2\n")
    try:
        result = read_secret_from_fd(reader)
    finally:
        os.close(reader)
    assert isinstance(result, SecureBuffer) and len(result) == 7 and isinstance(result.locked, bool)
    result.wipe()


@pytest.mark.skipif(not hasattr(os, "set_blocking"), reason="needs non-blocking descriptors")
def test_read_secret_from_fd_waits_on_a_non_blocking_descriptor():
    """A slow writer on a non-blocking pipe must not turn into a shorter password."""
    reader, writer = os.pipe()
    os.set_blocking(reader, False)

    def slow_writer() -> None:
        os.write(writer, b"first-half")
        time.sleep(0.3)
        os.write(writer, b"-second-half\n")

    thread = threading.Thread(target=slow_writer)
    thread.start()
    try:
        time.sleep(0.1)  # the first half is there, the rest is not yet
        assert read_all(reader, None) == b"first-half-second-half"
    finally:
        thread.join(10)
        os.close(writer)


@pytest.mark.skipif(not hasattr(os, "set_blocking"), reason="needs non-blocking descriptors")
def test_read_secret_from_fd_sees_the_end_of_a_non_blocking_descriptor():
    reader, writer = os.pipe()
    os.set_blocking(reader, False)
    os.write(writer, b"no newline")
    os.close(writer)
    assert read_all(reader, None) == b"no newline"


def test_read_secret_from_fd_on_a_descriptor_that_is_not_open():
    reader, writer = os.pipe()
    os.close(reader)
    os.close(writer)
    with pytest.raises(UsageError, match="could not read the secret"):
        read_secret_from_fd(reader)


@pytest.mark.skipif(not POSIX, reason="directories can be opened read-only on POSIX")
def test_read_secret_from_fd_on_a_directory(tmp_path):
    descriptor = os.open(str(tmp_path), os.O_RDONLY)
    try:
        with pytest.raises(UsageError, match="could not read the secret"):
            read_secret_from_fd(descriptor)
    finally:
        os.close(descriptor)


def test_read_secret_from_fd_does_not_close_the_descriptor():
    reader, writer = piped(b"one\ntwo\n", close_writer=False)
    try:
        read_secret_from_fd(reader).wipe()  # type: ignore[union-attr]
        gc.collect()
        os.fstat(reader)  # still open
        read_secret_from_fd(reader).wipe()  # type: ignore[union-attr]
    finally:
        os.close(reader)
        os.close(writer)


def test_read_secret_from_fd_reads_a_regular_file(tmp_path):
    path = tmp_path / "password-file"
    path.write_bytes(b"from a file\nand more\n")
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        with read_secret_from_fd(descriptor) as secret:  # type: ignore[union-attr]
            assert bytes(secret.view()) == b"from a file"
        assert os.read(descriptor, 100) == b"and more\n"
    finally:
        os.close(descriptor)


@given(st.binary(min_size=1, max_size=300).filter(lambda data: b"\n" not in data and not data.endswith(b"\r")))
@settings(max_examples=60, deadline=None)
def test_read_secret_from_fd_returns_the_line_as_sent(line):
    assert read_all(*piped(line + b"\ntrailing")) == line


# ---------------------------------------------------------------------------
# read_secret on a pseudo-terminal
# ---------------------------------------------------------------------------

pty_only = pytest.mark.skipif(not POSIX, reason="pseudo-terminals are POSIX")

# read_secret runs in a child process whose "/dev/tty" is the pseudo-terminal,
# with this process at the keyboard. A thread would not do: on the older
# interpreters termios holds the interpreter lock while it waits for the
# terminal to take the prompt, and the thread that plays the terminal could
# then never read it.
TERMINAL_CHILD = r"""
import json, os, sys
slave, allow_empty, mode, prompt = int(sys.argv[1]), sys.argv[2] == "1", sys.argv[3], sys.argv[4]
repeat = int(sys.argv[5])
real_open = os.open

def open_terminal(path, flags, *args, **kwargs):
    if path == "/dev/tty":
        return os.dup(slave)
    return real_open(path, flags, *args, **kwargs)

os.open = open_terminal
from irondome import secmem

def open_descriptors():
    count = 0
    for number in range(256):
        try:
            os.fstat(number)
            count += 1
        except OSError:
            pass
    return count

if mode == "interrupt":
    class Interrupted:
        def __init__(self, *args, **kwargs):
            pass

        def readinto(self, buffer):
            raise KeyboardInterrupt

    secmem.io.FileIO = Interrupted

results = []
before = open_descriptors()
for _ in range(repeat):
    try:
        secret = secmem.read_secret(prompt, allow_empty=allow_empty)
        results.append({"value": None if secret is None else bytes(secret.view()).hex()})
        if secret is not None:
            secret.wipe()
    except BaseException as exc:
        results.append({"error": type(exc).__name__, "message": str(exc)})
sys.stdout.write(json.dumps({"results": results, "descriptors": [before, open_descriptors()]}))
"""


class Terminal:
    """A pseudo-terminal standing in for /dev/tty, with the test at the keyboard."""

    PROMPT = "Master password: "

    def __init__(self) -> None:
        import pty

        self.master, self.slave = pty.openpty()
        self.output = b""

    def flags(self) -> List[int]:
        import termios

        return termios.tcgetattr(self.slave)

    def echo(self) -> bool:
        import termios

        return bool(self.flags()[3] & termios.ECHO)

    def drain(self, until: Optional[bytes] = None, seconds: float = 10.0) -> bytes:
        """Collect what the program wrote to the screen (until *until* shows up, or it goes quiet)."""
        import select

        deadline = time.time() + seconds
        while time.time() < deadline:
            if until is not None and until in self.output:
                break
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if ready:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    break
            elif until is None:
                break
        return self.output

    def ask(
        self, lines: List[List[bytes]], *, allow_empty: bool = False, mode: str = "normal", delay: float = 0.0
    ) -> Dict[str, object]:
        """Run read_secret once per entry of *lines*, typing that entry when it listens with echo off."""
        before = self.flags()
        self.output = b""
        child = subprocess.Popen(
            [
                sys.executable, "-c", TERMINAL_CHILD, str(self.slave), "1" if allow_empty else "0", mode,
                self.PROMPT, str(len(lines)),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=[self.slave],
        )
        observed: Dict[str, object] = {"echo_while_reading": [], "flags_while_reading": []}
        try:
            shown = 0
            for typed in lines:
                shown += 1
                deadline = time.time() + 20
                while self.output.count(self.PROMPT.encode()) < shown and time.time() < deadline:
                    self.drain(until=None, seconds=0.2)
                    if child.poll() is not None:
                        break
                while self.echo() and time.time() < deadline and child.poll() is None:
                    time.sleep(0.005)
                observed["echo_while_reading"].append(self.echo())  # type: ignore[union-attr]
                observed["flags_while_reading"].append(self.flags())  # type: ignore[union-attr]
                for chunk in typed:
                    os.write(self.master, chunk)
                    if delay:
                        time.sleep(delay)
            stdout, stderr = child.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate()
            pytest.fail("read_secret is still waiting on the terminal")
        finally:
            if child.poll() is None:
                child.kill()
        assert child.returncode == 0, stderr.decode()
        self.drain()
        report = json.loads(stdout.decode())
        observed["results"] = report["results"]
        observed["descriptors"] = report["descriptors"]
        observed["restored"] = self.flags() == before
        return observed

    def ask_once(self, typed: List[bytes], **kwargs) -> Dict[str, object]:
        observed = self.ask([typed], **kwargs)
        outcome = dict(observed["results"][0])  # type: ignore[index]
        if outcome.get("value") is not None:
            outcome["value"] = bytes.fromhex(outcome["value"])
        outcome["echo_while_reading"] = observed["echo_while_reading"][0]  # type: ignore[index]
        outcome["flags_while_reading"] = observed["flags_while_reading"][0]  # type: ignore[index]
        outcome["restored"] = observed["restored"]
        return outcome

    def close(self) -> None:
        os.close(self.master)
        os.close(self.slave)


@pytest.fixture
def terminal():
    tty = Terminal()
    yield tty
    tty.close()


@pty_only
def test_read_secret_reads_a_line_with_echo_off(terminal):
    assert terminal.echo() is True
    outcome = terminal.ask_once([b"hunter2\n"])
    assert outcome["value"] == b"hunter2"
    assert outcome["echo_while_reading"] is False
    assert outcome["restored"] is True and terminal.echo() is True
    assert terminal.output.startswith(b"Master password: ")
    assert b"hunter2" not in terminal.output  # nothing typed was shown
    assert terminal.output.endswith(b"\n")  # the line is finished for the user


@pty_only
def test_read_secret_accepts_return_as_the_end_of_the_line(terminal):
    assert terminal.ask_once([b"hunter2\r"])["value"] == b"hunter2"


@pty_only
def test_read_secret_lets_the_terminal_edit_the_line(terminal):
    assert terminal.ask_once([b"hunterX\x7f2\n"])["value"] == b"hunter2"
    assert b"hunter" not in terminal.output


@pty_only
def test_read_secret_keeps_non_ascii_input_as_typed(terminal):
    typed = "סיסמה-\U0001f511 \xe9".encode("utf-8")
    assert terminal.ask_once([typed + b"\n"])["value"] == typed


@pty_only
def test_read_secret_refuses_an_empty_line(terminal):
    outcome = terminal.ask_once([b"\n"])
    assert outcome["error"] == "UsageError" and "nothing was entered" in outcome["message"]
    assert outcome["restored"] is True


@pty_only
def test_read_secret_returns_none_for_an_empty_line_when_allowed(terminal):
    outcome = terminal.ask_once([b"\n"], allow_empty=True)
    assert outcome["value"] is None and "error" not in outcome


@pty_only
def test_read_secret_on_closed_input_raises_usage_error(terminal):
    outcome = terminal.ask_once([b"\x04"])  # end of input at the start of the line
    assert outcome["error"] == "UsageError"
    assert "closed" in outcome["message"]
    assert outcome["restored"] is True and terminal.echo() is True


@pty_only
def test_read_secret_closed_input_is_an_error_even_when_empty_is_allowed(terminal):
    assert terminal.ask_once([b"\x04"], allow_empty=True)["error"] == "UsageError"


@pty_only
def test_read_secret_on_a_terminal_left_in_raw_mode_still_reads_a_whole_line(terminal):
    """Raw mode delivers one keystroke per read; the password must not be cut to the first one."""
    import termios
    import tty

    tty.setraw(terminal.slave)
    outcome = terminal.ask_once([b"h", b"u", b"n", b"t", b"e", b"r", b"2", b"\r"], delay=0.03)
    assert outcome["value"] == b"hunter2"
    assert outcome["flags_while_reading"][3] & termios.ICANON
    assert outcome["restored"] is True
    assert not terminal.flags()[3] & termios.ICANON  # and the caller gets its raw terminal back


@pty_only
def test_read_secret_restores_the_terminal_when_interrupted(terminal):
    outcome = terminal.ask_once([], mode="interrupt")
    assert outcome["error"] == "KeyboardInterrupt"
    assert outcome["restored"] is True and terminal.echo() is True


@pty_only
def test_read_secret_can_be_asked_again_and_leaks_no_descriptors(terminal):
    observed = terminal.ask([[b"first\n"], [b"second\n"], [b"third\n"]])
    assert [bytes.fromhex(result["value"]) for result in observed["results"]] == [b"first", b"second", b"third"]
    assert observed["echo_while_reading"] == [False, False, False]
    before, after = observed["descriptors"]
    assert before == after
    assert observed["restored"] is True


def test_read_secret_without_a_terminal_is_a_usage_error():
    with pytest.raises(UsageError, match="no terminal to ask on"):
        read_secret("Master password: ")


@pty_only
def test_read_secret_on_something_that_is_not_a_terminal(monkeypatch, tmp_path):
    """/dev/tty that does not behave like a terminal: an error message, not a traceback."""
    path = tmp_path / "not-a-tty"
    path.write_bytes(b"hunter2\n")
    guarded = os.open

    def open_file(name, flags, *args, **kwargs):
        if name == "/dev/tty":
            return guarded(str(path), os.O_RDWR)
        return guarded(name, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", open_file)
    with pytest.raises(UsageError, match="no terminal to ask on"):
        read_secret("Master password: ")
    assert path.read_bytes() == b"hunter2\n"  # and no prompt was written into it


# ---------------------------------------------------------------------------
# read_secret on a Windows console (the console API replaced by a script)
# ---------------------------------------------------------------------------


class Console:
    """Stands in for ``msvcrt``: a queue of keystrokes in, the echoed characters out."""

    def __init__(self, keys: List[str]) -> None:
        self.keys = list(keys)
        self.shown: List[str] = []

    def getwch(self) -> str:
        if not self.keys:
            return "￿"  # what the real one returns when there is no console
        return self.keys.pop(0)

    def putwch(self, char: str) -> None:
        self.shown.append(char)


def type_on_console(monkeypatch: pytest.MonkeyPatch, keys: List[str], **kwargs) -> Optional[bytes]:
    console = Console(keys)
    monkeypatch.setitem(sys.modules, "msvcrt", console)
    secret = secmem._read_secret_windows("Password: ", allow_empty=kwargs.get("allow_empty", False))
    type_on_console.console = console  # type: ignore[attr-defined]
    if secret is None:
        return None
    with secret:
        return bytes(secret.view())


def test_windows_console_plain_input(monkeypatch):
    assert type_on_console(monkeypatch, list("hunter2") + ["\r"]) == b"hunter2"
    console = type_on_console.console  # type: ignore[attr-defined]
    assert "".join(console.shown) == "Password: \r\n"  # the prompt and a line end; nothing typed


def test_windows_console_newline_also_ends_the_line(monkeypatch):
    assert type_on_console(monkeypatch, list("pw") + ["\n"]) == b"pw"


def test_windows_console_backspace_removes_whole_characters(monkeypatch):
    keys = ["a", "\xe9", "\x08", "b", "א", "\x08", "\x08", "\x08", "\x08", "c", "\r"]
    assert type_on_console(monkeypatch, keys) == b"c"
    keys = ["a", "\ud83d", "\udd11", "\x08", "z", "\r"]  # backspace over a four-byte character
    assert type_on_console(monkeypatch, keys) == b"az"


def test_windows_console_function_keys_are_ignored(monkeypatch):
    assert type_on_console(monkeypatch, ["a", "\x00", ";", "b", "\x00", "H", "\r"]) == b"ab"


def test_windows_console_keeps_a_typed_a_grave(monkeypatch):
    """0xE0 is a letter on many keyboards; swallowing it would silently change a password."""
    typed = ["v", "o", "i", "l", "\xe0", "!", "\r"]
    assert type_on_console(monkeypatch, typed) == "voil\xe0!".encode("utf-8")


def test_windows_console_joins_surrogate_pairs(monkeypatch):
    """The console speaks UTF-16; the bytes must be the UTF-8 every other platform produces."""
    typed = ["k", "\ud83d", "\udd11", "!", "\r"]
    assert type_on_console(monkeypatch, typed) == "k\U0001f511!".encode("utf-8")


def test_windows_console_drops_unpaired_surrogates(monkeypatch):
    assert type_on_console(monkeypatch, ["a", "\ud83d", "b", "\r"]) == b"ab"
    assert type_on_console(monkeypatch, ["a", "\udd11", "b", "\r"]) == b"ab"
    assert type_on_console(monkeypatch, ["a", "\ud83d", "\r"], allow_empty=True) == b"a"


def test_windows_console_non_ascii(monkeypatch):
    typed = list("סיסמה \xe9 ß") + ["\r"]
    assert type_on_console(monkeypatch, typed) == "סיסמה \xe9 ß".encode("utf-8")


def test_windows_console_control_c_interrupts(monkeypatch):
    with pytest.raises(KeyboardInterrupt):
        type_on_console(monkeypatch, ["a", "\x03"])


def test_windows_console_empty_input(monkeypatch):
    with pytest.raises(UsageError, match="nothing was entered"):
        type_on_console(monkeypatch, ["\r"])
    assert type_on_console(monkeypatch, ["\r"], allow_empty=True) is None
    with pytest.raises(UsageError, match="nothing was entered"):
        type_on_console(monkeypatch, ["a", "\x08", "\r"])


def test_windows_console_too_long(monkeypatch):
    with pytest.raises(UsageError, match="too long"):
        type_on_console(monkeypatch, ["x"] * (secmem._MAX_SECRET + 1) + ["\r"])
    assert type_on_console(monkeypatch, ["x"] * secmem._MAX_SECRET + ["\r"]) == b"x" * secmem._MAX_SECRET


def test_windows_without_a_console_is_a_usage_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "msvcrt", Console([]))
    monkeypatch.setattr(secmem, "_IS_WINDOWS", True)
    with pytest.raises(UsageError, match="no terminal to ask on"):
        within(10, lambda: read_secret("Password: "))
