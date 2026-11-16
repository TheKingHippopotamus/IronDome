"""Memory that is allowed to hold keys.

CPython gives a program no control over ``bytes`` and ``str``: they are
immutable, they are copied freely, and when they are freed their contents stay
in the heap until something else happens to reuse the space. A key held that
way cannot be erased.

So key material never becomes one. Every key in IronDome -- the master
password as typed, the Argon2id output, the device key, the key-encryption
key, the vault key and every subkey -- lives in a :class:`SecureBuffer`:

* allocated outside the Python object heap, in its own anonymous pages;
* locked into RAM (``mlock`` / ``VirtualLock``) so it is not written to swap;
* on Linux, left out of core dumps and handed to ``fork`` children as zeros
  (on macOS a forked child gets its own copy of the pages);
* filled in place: the KDFs derive *into* it, the AEAD decrypts *into* it,
  the Secure Enclave helper's pipe is read *into* it;
* overwritten with zeros by :meth:`SecureBuffer.wipe`, which every code path
  reaches through a ``with`` block or a ``finally``. A view of the buffer
  still alive at that moment (a slice of :meth:`SecureBuffer.view`, say)
  keeps its pages mapped until it goes: they are zeroed all the same and made
  read-only, or, where the system refuses that, kept locked and zeroed again
  until the view has gone.

``tests/claims/test_keys_wiped.py`` checks the result from the outside: after
a vault is locked it scans the whole address space of the process for each
key and requires zero hits.

What this module cannot do is listed in ``docs/THREAT_MODEL.md``: decrypted
*entries* are ordinary Python strings for as long as a command runs, and a
process with debugger rights over a running IronDome can read anything.
"""

from __future__ import annotations

import atexit
import ctypes
import ctypes.util
import io
import mmap
import os
import sys
import time
from typing import Any, List, Optional, Tuple, Union

from irondome.errors import UsageError

__all__ = [
    "SecureBuffer",
    "BufferLike",
    "as_view",
    "wipe_bytes",
    "harden_process",
    "read_secret",
    "read_secret_from_fd",
]

BufferLike = Union["SecureBuffer", bytes, bytearray, memoryview]

_PAGE = mmap.PAGESIZE
_IS_WINDOWS = os.name == "nt"
#: Linux 4.14+: a forked child sees zeros in the range. Not named by ``mmap``.
_MADV_WIPEONFORK = 18
#: winnt.h: the protection VirtualProtect gives pages that may be read but not written.
_PAGE_READONLY = 0x02
_libc: Any = None
_libc_loaded = False
#: Pages wipe() zeroed but could neither unmap (a view of them was still alive) nor make
#: read-only, as ``(mapping, address, length)``. See :func:`_hold`.
_held: List[Tuple[mmap.mmap, int, int]] = []
_held_at_exit: List[bool] = []


def _get_libc() -> Any:
    global _libc, _libc_loaded
    if not _libc_loaded:
        if not _IS_WINDOWS:
            try:
                _libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
            except OSError:
                _libc = None
        _libc_loaded = True  # set last: another thread must never see "loaded" without the library
    return _libc


def _lock_pages(address: int, length: int) -> bool:
    """Pin the pages in RAM. Returns False if the OS refused (e.g. RLIMIT_MEMLOCK)."""
    try:
        if _IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            kernel32.VirtualLock.restype = ctypes.c_int
            return bool(kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(length)))
        libc = _get_libc()
        if libc is None:
            return False
        libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.mlock.restype = ctypes.c_int
        return libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(length)) == 0
    except Exception:
        return False


def _unlock_pages(address: int, length: int) -> None:
    try:
        if _IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(length))
            return
        libc = _get_libc()
        if libc is not None:
            libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(length))
    except (AttributeError, OSError, ctypes.ArgumentError):
        return  # nothing to undo: the pages are zero and about to be unmapped


def _make_read_only(address: int, length: int) -> bool:
    """Let the pages be read but never written again. Returns False if the OS refused."""
    try:
        if _IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.VirtualProtect.argtypes = [
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
            ]
            kernel32.VirtualProtect.restype = ctypes.c_int
            previous = ctypes.c_ulong(0)
            return bool(
                kernel32.VirtualProtect(
                    ctypes.c_void_p(address), ctypes.c_size_t(length), _PAGE_READONLY, ctypes.byref(previous)
                )
            )
        libc = _get_libc()
        if libc is None:
            return False
        libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        libc.mprotect.restype = ctypes.c_int
        return libc.mprotect(ctypes.c_void_p(address), ctypes.c_size_t(length), mmap.PROT_READ) == 0
    except Exception:
        return False


def _hold(mapping: mmap.mmap, address: int, length: int) -> None:
    """Keep zeroed pages that could neither be unmapped nor made read-only.

    A view that is still alive can write to them, so they are locked into RAM
    again (as far as the system allows), zeroed again by every later
    :meth:`SecureBuffer.wipe` and at exit, and unmapped by the first of those
    after their last view has gone. The reference kept here is what stops
    them from being unmapped before that, unzeroed, when the view goes.
    """
    _lock_pages(address, length)
    _held.append((mapping, address, length))
    if not _held_at_exit:
        _held_at_exit.append(True)
        atexit.register(_zero_held)


def _zero_held() -> None:
    """Zero the pages :func:`_hold` keeps, and unmap those no view uses any more."""
    for _ in range(len(_held)):
        try:
            entry = _held.pop(0)  # atomic: each held mapping is handled by one caller at a time
        except IndexError:
            return
        mapping, address, length = entry
        if mapping.closed:
            continue
        ctypes.memset(address, 0, length)
        try:
            mapping.close()
        except (BufferError, ValueError):
            _held.append(entry)  # still in use: zeroed again next time


class SecureBuffer:
    """A fixed-size buffer for key material. See the module docstring.

    Use it as a context manager, or call :meth:`wipe` in a ``finally``.
    :meth:`view` returns a writable ``memoryview`` that the ``cryptography``
    primitives accept directly as a key or as an output buffer.
    """

    __slots__ = ("_map", "_anchor", "_address", "_length", "_size", "_view", "_wiped", "_live", "locked")

    def __init__(self, size: int) -> None:
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError("SecureBuffer size must be a positive integer")
        self._wiped = True  # until construction completes, there is nothing to wipe
        self._live: List[bool] = []
        self._size = size
        self._length = -(-size // _PAGE) * _PAGE
        if _IS_WINDOWS:
            self._map = mmap.mmap(-1, self._length)
        else:
            self._map = mmap.mmap(
                -1,
                self._length,
                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
        self._anchor = (ctypes.c_char * self._length).from_buffer(self._map)
        self._address = ctypes.addressof(self._anchor)
        self.locked = _lock_pages(self._address, self._length)
        if sys.platform.startswith("linux"):
            # MADV_WIPEONFORK rather than MADV_DONTFORK: a child that touches
            # a range removed by DONTFORK (its own destructor does) is killed.
            for advice in (getattr(mmap, "MADV_DONTDUMP", None), _MADV_WIPEONFORK):
                if advice is not None:
                    try:
                        self._map.madvise(advice)
                    except (OSError, ValueError):
                        pass  # an older kernel; the buffer works without it
        self._view = memoryview(self._map)[:size]
        self._live.append(True)
        self._wiped = False

    # -- construction helpers -------------------------------------------------

    @classmethod
    def random(cls, size: int) -> "SecureBuffer":
        """A buffer filled by the OS CSPRNG, without an intermediate ``bytes``."""
        buffer = cls(size)
        libc = _get_libc()
        filled = False
        if libc is not None and hasattr(libc, "getentropy"):
            try:
                libc.getentropy.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                libc.getentropy.restype = ctypes.c_int
                offset = 0
                filled = True
                while offset < size:
                    chunk = min(256, size - offset)  # getentropy's documented maximum
                    if libc.getentropy(ctypes.c_void_p(buffer._address + offset), chunk) != 0:
                        filled = False
                        break
                    offset += chunk
            except Exception:
                filled = False
        if not filled:
            fresh = os.urandom(size)
            buffer._view[:] = fresh
            wipe_bytes(fresh)
        return buffer

    @classmethod
    def from_buffer(cls, data: BufferLike) -> "SecureBuffer":
        """Copy *data* in. The caller still owns, and should wipe, the source."""
        source = as_view(data)
        buffer = cls(len(source))
        buffer._view[:] = source
        return buffer

    # -- access ---------------------------------------------------------------

    def view(self) -> memoryview:
        if self._wiped:
            raise ValueError("this SecureBuffer has been wiped")
        return self._view

    def __len__(self) -> int:
        return self._size

    @property
    def wiped(self) -> bool:
        return self._wiped

    def copy(self) -> "SecureBuffer":
        return SecureBuffer.from_buffer(self)

    # -- destruction ----------------------------------------------------------

    def wipe(self) -> None:
        """Overwrite with zeros and release. Safe to call more than once, from any thread.

        A view made from :meth:`view` that is still alive (a slice, a cast, a
        ``ctypes`` array over it) keeps the pages mapped until it goes. They
        are zeroed all the same, and then made read-only: such a view reads
        zeros, and a write through it stops the process with a memory fault
        (a ``read`` into it fails with ``EFAULT``) instead of leaving key
        material on pages that no later wipe would reach. Where the operating
        system will not make them read-only, they are kept in RAM as far as it
        allows, zeroed again by every later wipe and at exit, and unmapped by
        the first of those after the view has gone.
        """
        if _held:
            _zero_held()
        try:
            self._live.pop()  # atomic: of any number of concurrent callers, one gets past this line
        except IndexError:
            return
        self._wiped = True
        try:
            ctypes.memset(self._address, 0, self._length)
        finally:
            if self.locked:
                _unlock_pages(self._address, self._length)
                self.locked = False
            try:
                self._view.release()
            except BufferError:
                pass  # an export of the view itself is alive: the mapping stays, as below
            self._anchor = None  # type: ignore[assignment]
            try:
                self._map.close()
            except (BufferError, ValueError):
                # Another view of these pages is alive, so they stay mapped until it goes.
                if not self._map.closed:
                    ctypes.memset(self._address, 0, self._length)  # whatever reached them since the first pass
                    if not _make_read_only(self._address, self._length):
                        _hold(self._map, self._address, self._length)

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.wipe()

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:  # noqa: S110 - a destructor must not raise, least of all during interpreter shutdown
            pass

    def __repr__(self) -> str:
        state = "wiped" if self._wiped else ("locked" if self.locked else "unlocked")
        return f"<SecureBuffer {self._size} bytes, {state}>"

    def __reduce__(self) -> Any:
        raise TypeError("SecureBuffer cannot be pickled")


def as_view(data: BufferLike) -> memoryview:
    """A ``memoryview`` over a SecureBuffer or any bytes-like object."""
    if isinstance(data, SecureBuffer):
        return data.view()
    return memoryview(data)


def _wipe_str(text: str) -> bool:
    """Zero the characters of a CPython ``str`` in place.

    Private on purpose, and not reachable through :func:`wipe_bytes`: strings
    are shared far more freely than bytes (interned names, constants, the
    results of ``json.dumps`` for an empty container), and zeroing a shared
    one corrupts the whole program. Its callers pass only strings nothing
    else refers to: the transient copies ``keys.normalise_password`` made two
    lines earlier, and the memory probe's recovery key, once it is done with
    it. Returns True if the characters were overwritten.
    """
    length = len(text)
    if length < 2 or sys.implementation.name != "cpython":
        return False  # one-character strings are interpreter-wide singletons
    widest = max(map(ord, text))
    if widest < 0x80:
        width, sample = 1, "aa"
    elif widest < 0x100:
        width, sample = 1, "\xe9\xe9"
    elif widest < 0x10000:
        width, sample = 2, "\u0101\u0101"
    else:
        width, sample = 4, "\U00010000\U00010000"
    # A compact str is a header followed by its characters and a terminator.
    # The header size is measured on a string of the same class rather than
    # assumed, and anything that does not fit that layout exactly (a cached
    # UTF-8 copy, an unexpected representation) is left alone.
    header = sys.getsizeof(sample) - 3 * width
    if sys.getsizeof(text) != header + (length + 1) * width:
        return False
    ctypes.memset(id(text) + header, 0, length * width)
    return True


def wipe_bytes(obj: Any) -> bool:
    """Best-effort in-place zeroing of a ``bytearray`` or (on CPython) ``bytes``.

    For the rare value an API insists on returning as immutable ``bytes``.
    Only ever call it on an object this code created and still exclusively
    owns: zeroing a shared or interned object would corrupt the program.
    Returns True if the payload was overwritten. A ``str`` is never touched:
    it is returned as it was, with False.
    """
    if isinstance(obj, bytearray):
        length = len(obj)
        if length:
            anchor = (ctypes.c_char * length).from_buffer(obj)
            ctypes.memset(ctypes.addressof(anchor), 0, length)
            del anchor
        return True
    if isinstance(obj, memoryview):
        if obj.readonly:
            return False
        obj.cast("B")[:] = bytes(obj.nbytes)
        return True
    if type(obj) is bytes:
        # Empty and single-byte objects are interpreter-wide singletons.
        if len(obj) < 2 or sys.implementation.name != "cpython":
            return False
        offset = bytes.__basicsize__ - 1  # ob_sval starts where the header ends
        ctypes.memset(id(obj) + offset, 0, len(obj))
        return True
    return False


def harden_process() -> None:
    """Keep key material out of core files and away from same-user debuggers.

    * no core dumps (``RLIMIT_CORE = 0``) on every POSIX system;
    * Linux: ``PR_SET_DUMPABLE = 0``, which also stops other processes of the
      same user from attaching with ptrace or reading ``/proc/<pid>/mem``.

    Set ``IRONDOME_DEBUG=1`` to skip this when you need a debugger or a core.
    """
    if os.environ.get("IRONDOME_DEBUG") == "1":
        return
    if not _IS_WINDOWS:
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ImportError, OSError, ValueError):
            pass  # a platform or sandbox that does not allow it; best effort
    if sys.platform.startswith("linux"):
        libc = _get_libc()
        if libc is not None:
            try:
                pr_set_dumpable = 4
                libc.prctl(pr_set_dumpable, 0, 0, 0, 0)
            except (AttributeError, OSError, ctypes.ArgumentError):
                pass  # a C library without prctl; best effort


# ---------------------------------------------------------------------------
# Reading a secret without ever holding it as a str
# ---------------------------------------------------------------------------

_MAX_SECRET = 4096


def _finish(scratch: SecureBuffer, length: int, *, allow_empty: bool) -> Optional[SecureBuffer]:
    view = scratch.view()
    while length and view[length - 1] in (0x0A, 0x0D):
        length -= 1
    if length == 0:
        if allow_empty:
            return None
        raise UsageError("nothing was entered")
    result = SecureBuffer(length)
    result.view()[:] = view[:length]
    return result


def read_secret_from_fd(fd: int, *, allow_empty: bool = False) -> Optional[SecureBuffer]:
    """Read one line from a file descriptor straight into locked memory.

    Reads a byte at a time so nothing after the newline is consumed: a caller
    may pipe a password on the first line and other input after it. A
    descriptor in non-blocking mode is waited on, never read short. Raises
    :class:`UsageError` when the descriptor cannot be read.
    """
    with SecureBuffer(_MAX_SECRET) as scratch:
        view = scratch.view()
        length = 0
        try:
            raw = io.FileIO(fd, "rb", closefd=False)
            while length < _MAX_SECRET:
                got = raw.readinto(view[length : length + 1])
                if got is None:
                    time.sleep(0.02)  # non-blocking and nothing there yet: that is not the end
                    continue
                if not got:
                    break
                length += 1
                if view[length - 1] == 0x0A:
                    break
            else:
                raise UsageError(f"that secret is too long: IronDome reads at most {_MAX_SECRET - 1} bytes on a line")
        except OSError as exc:
            raise UsageError(f"could not read the secret from the input: {exc.strerror or exc}") from None
        return _finish(scratch, length, allow_empty=allow_empty)


def _read_secret_posix(prompt: str, *, allow_empty: bool) -> Optional[SecureBuffer]:
    import termios

    fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    try:
        try:
            saved = termios.tcgetattr(fd)
            silent = termios.tcgetattr(fd)
        except termios.error as exc:
            raise OSError(str(exc)) from None
        # Echo off. Canonical mode on, with CR read as newline, even if the
        # caller left the terminal raw: the tty then edits the line and hands
        # it over whole instead of one keystroke at a time.
        silent[3] = (silent[3] | termios.ICANON) & ~termios.ECHO
        silent[0] |= termios.ICRNL
        try:
            # Echo goes off before the prompt appears, as in getpass: nothing typed
            # or pasted in answer to the prompt can be echoed. Whatever was typed
            # earlier is discarded (TCSAFLUSH), not taken as the secret.
            try:
                termios.tcsetattr(fd, termios.TCSAFLUSH, silent)
            except termios.error as exc:
                raise OSError(str(exc)) from None
            os.write(fd, prompt.encode("utf-8", "replace"))
            with SecureBuffer(_MAX_SECRET) as scratch:
                raw = io.FileIO(fd, "rb", closefd=False)
                length = raw.readinto(scratch.view()) or 0
                if length == 0:
                    raise UsageError("input was closed before anything was entered")
                return _finish(scratch, length, allow_empty=allow_empty)
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSAFLUSH, saved)
                os.write(fd, b"\n")
            except (termios.error, OSError):
                pass  # the terminal went away; there is nothing left to restore
    finally:
        os.close(fd)


def _read_secret_windows(prompt: str, *, allow_empty: bool) -> Optional[SecureBuffer]:
    import msvcrt

    for char in prompt:
        msvcrt.putwch(char)  # type: ignore[attr-defined]
    with SecureBuffer(_MAX_SECRET) as scratch:
        view = scratch.view()
        length = 0
        pending = ""
        while True:
            char = pending or msvcrt.getwch()  # type: ignore[attr-defined]
            pending = ""
            if char in ("\r", "\n"):
                break
            if char == "\x03":
                raise KeyboardInterrupt
            if char == "\uffff":
                raise OSError("there is no console to read from")
            if char == "\x08":
                # Step back one whole UTF-8 character.
                while length and (view[length - 1] & 0xC0) == 0x80:
                    length -= 1
                    view[length] = 0
                if length:
                    length -= 1
                    view[length] = 0
                continue
            if char == "\x00":
                msvcrt.getwch()  # type: ignore[attr-defined]  # function-key prefix
                continue
            # 0xE0 also prefixes arrow keys, but it is the letter "a grave" as
            # well and the console cannot tell the two apart. It is kept, as
            # getpass keeps it: dropping a typed letter would change a password
            # without any sign of it.
            if "\ud800" <= char <= "\udbff":
                # The console speaks UTF-16: a character outside the basic
                # plane arrives as two halves, which are joined before encoding.
                low = msvcrt.getwch()  # type: ignore[attr-defined]
                if not "\udc00" <= low <= "\udfff":
                    pending = low
                    continue  # half a pair is not a character
                char = (char + low).encode("utf-16-le", "surrogatepass").decode("utf-16-le")
            elif "\udc00" <= char <= "\udfff":
                continue
            encoded = char.encode("utf-8")
            if length + len(encoded) > _MAX_SECRET:
                raise UsageError(f"that secret is too long: IronDome reads at most {_MAX_SECRET - 1} bytes on a line")
            view[length : length + len(encoded)] = encoded
            length += len(encoded)
        msvcrt.putwch("\r")  # type: ignore[attr-defined]
        msvcrt.putwch("\n")  # type: ignore[attr-defined]
        return _finish(scratch, length, allow_empty=allow_empty)


def read_secret(prompt: str, *, allow_empty: bool = False) -> Optional[SecureBuffer]:
    """Prompt on the controlling terminal with echo off; return locked bytes.

    Unlike ``getpass`` the secret is never assembled into a Python ``str``. On
    POSIX the terminal is read straight into locked memory. On Windows the
    console hands over one character at a time, each as a one-character
    ``str``; they are copied into locked memory as they arrive.
    Raises :class:`UsageError` when there is no terminal to ask on.
    """
    try:
        if _IS_WINDOWS:
            return _read_secret_windows(prompt, allow_empty=allow_empty)
        return _read_secret_posix(prompt, allow_empty=allow_empty)
    except OSError as exc:
        raise UsageError(
            "no terminal to ask on; pass --password-stdin or use a session or grant token"
        ) from exc
