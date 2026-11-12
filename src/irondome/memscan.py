"""Search the whole address space of this process for copies of a secret.

This is the instrument behind the claim that key material is wiped from
memory (``keys-wiped`` in ``claims.json``). It answers one question: after a
vault has been locked, does any readable byte of this process still hold a
copy of a key? It is verification tooling. Nothing in IronDome's normal
operation calls it; ``irondome verify`` and the claim tests do.

How it reads memory
-------------------
Every page is copied by the kernel into one scratch buffer and searched
there, so an unreadable page is an error code and never a fault:

* macOS: ``mach_vm_region_recurse`` walks every VM entry of this task
  (descending into the dyld shared cache) and ``mach_vm_read_overwrite``
  copies it;
* Linux: ``/proc/self/maps`` lists the mappings and ``/proc/self/mem`` is read
  with ``pread``; where that file cannot be opened (a process that made itself
  non-dumpable) ``process_vm_readv`` on the own pid does the same.

Every readable mapping is searched: heap, stacks, anonymous memory, mapped
files and the shared libraries. Nothing is skipped except the scratch buffer
itself and the one locked page that holds the search prefixes.

How it avoids finding itself
----------------------------
A :class:`NeedleTable` stores each secret XOR-masked with random pad bytes,
none of them zero, so the stored form differs from the secret at every byte.
During a pass the first bytes of each secret (at most 16, and never all of
it) are unmasked into a locked page that the pass does not read, and zeroed
when the pass ends; candidates found with that prefix are confirmed byte by
byte by unmasking the table on the fly. The complete plaintext of a needle
never exists anywhere. (A longer prefix searches faster; 16 bytes keep a
whole-address-space pass on a Mac to about half a minute.)

How it avoids disturbing what it looks for
------------------------------------------
CPython's allocator hands the most recently freed block of a size class to
the next request of that class, so a scanner that creates objects while it
runs overwrites exactly the freshly freed blocks it was meant to inspect.
From the start of a pass to its last read nothing is allocated except
integers small enough for the 32-byte size class, which cannot hold a bytes
or str object: index loops only, foreign functions called with argument
objects built in advance, hits stored in ``ctypes`` arrays, every buffer
allocated when the :class:`Scanner` is built. Build the table and the
scanner *before* running the code under test, record keys as they are made,
and scan afterwards.

CPython 3.9 and 3.10 also allocate behind the program's back: a code object
gets its first cache on its 1024th run, zero-filled, from those same size
classes. A function that runs once per region would reach that run a few
passes in, in the middle of one, and wipe a freed block before the pass read
it. :func:`open_scanner` therefore first runs every function of a pass more
often than that, on passes with nothing to read (once per process: code
objects are shared). CPython 3.11 and later keep these caches inside the
bytecode.

Limits of the instrument: each page is read once, at some moment during the
pass, so it is not a snapshot; it sees this process only (not the kernel's
pipe buffers or page cache, not other processes, not swap or registers); it
finds a secret only in the exact byte form it was given.

Not thread-safe; use it from one thread.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from irondome.secmem import BufferLike, SecureBuffer, as_view

__all__ = [
    "MIN_NEEDLE",
    "MAX_NEEDLE",
    "NeedleTable",
    "ScanResult",
    "Scanner",
    "supported",
    "open_scanner",
    "describe_address",
]

_IS_DARWIN = sys.platform == "darwin"
_IS_LINUX = sys.platform.startswith("linux")
_IS_CPYTHON = sys.implementation.name == "cpython"
_PAGE = mmap.PAGESIZE

#: Shortest secret worth looking for: the shortest master password IronDome accepts.
MIN_NEEDLE = 8
#: Longest: the longest secret ``irondome.secmem`` reads.
MAX_NEEDLE = 4096
#: Bytes of a needle that are unmasked to drive the search; never the whole needle.
_PREFIX = 16
_DEFAULT_CHUNK = 16 << 20
_DEFAULT_CAPACITY = 64
_DEFAULT_TABLE_BYTES = 64 * 1024
_MAX_HITS = 4096
_MAX_EXCLUDES = 32
_M30 = (1 << 30) - 1
_NO_WINDOW = (0, 1 << 62)
#: Runs of each function of a pass before the first pass that counts: more than the 1024 after
#: which CPython 3.9 and 3.10 give a code object its cache (see _warm_up).
_WARM_RUNS = 1100
_warmed = False


def supported() -> Tuple[bool, str]:
    """Whether this process can scan itself, and if not, why."""
    if not _IS_CPYTHON:
        return False, "the memory scanner needs CPython"
    if _IS_DARWIN or _IS_LINUX:
        return True, ""
    return False, "the memory scanner works on macOS and Linux only"


def _add(a: int, b: int) -> int:
    """``a + b`` for non-negative integers, without a three-digit temporary.

    CPython's adder allocates one digit more than the larger operand, so the
    sum of two 2-digit addresses would come from the 48-byte size class: the
    class of short bytes objects. Adding the 30-bit halves separately keeps
    every temporary in the 32-byte class.
    """
    low = (a & _M30) + (b & _M30)
    return (((a >> 30) + (b >> 30) + (low >> 30)) << 30) | (low & _M30)


# ---------------------------------------------------------------------------
# Foreign calls that allocate nothing
# ---------------------------------------------------------------------------
#
# A ctypes call allocates an argument object for every value it converts.
# Functions are therefore bound without argtypes and called only with
# argument objects that already exist: byref() results for pointers, and for
# integers a CArgObject made once whose value field is rewritten in place.


def _probe_carg_offset() -> Optional[int]:
    """Offset of the value field inside a ctypes CArgObject, checked on a throwaway one."""
    if not _IS_CPYTHON:
        return None
    magic = 0x1122334455667788
    try:
        probe = ctypes.c_uint64.from_param(magic)
    except (TypeError, ValueError):
        return None
    if type(probe).__name__ != "CArgObject":
        return None
    for offset in (32, 40, 24, 48):
        if ctypes.c_uint64.from_address(id(probe) + offset).value == magic:
            return offset
    return None


_CARG_OFFSET = _probe_carg_offset()


def _int_arg(ctype: Any, value: int = 0) -> Tuple[Any, Any]:
    """``(argument, cell)``: pass *argument*, assign ``cell.value`` to change what it passes.

    Falls back to a plain ctypes object, correct but allocating on every
    call, when the layout probe failed; :attr:`Scanner.allocation_free` says
    which one is in use.
    """
    if _CARG_OFFSET is None:
        obj = ctype(value)
        return obj, obj
    arg = ctype.from_param(value)
    return arg, ctype.from_address(id(arg) + _CARG_OFFSET)


def _raw(library: Any, name: str, restype: Any) -> Any:
    """A private function object for *name* with no argtypes, or None if there is no such symbol."""
    if library is None:
        return None
    try:
        function = library[name]
    except (AttributeError, KeyError):
        return None
    function.restype = restype
    return function


def _load_libc() -> Any:
    if not (_IS_DARWIN or _IS_LINUX):
        return None
    try:
        return ctypes.CDLL(None, use_errno=True)
    except (OSError, TypeError):
        return None


_LIBC = _load_libc()
_MEMMOVE = _raw(_LIBC, "memmove", None)
_READ = _raw(_LIBC, "read", ctypes.c_ssize_t)
_PREAD = _raw(_LIBC, "pread64", ctypes.c_ssize_t) or _raw(_LIBC, "pread", ctypes.c_ssize_t)
_PROCESS_VM_READV = _raw(_LIBC, "process_vm_readv", ctypes.c_ssize_t) if _IS_LINUX else None
_REGION = _raw(_LIBC, "mach_vm_region_recurse", ctypes.c_int) if _IS_DARWIN else None
_VM_READ = _raw(_LIBC, "mach_vm_read_overwrite", ctypes.c_int) if _IS_DARWIN else None


def _address_of(buffer: Any) -> Tuple[Any, int]:
    """Pin a writable buffer and return ``(anchor, address)``. Keep the anchor alive."""
    view = memoryview(buffer)
    anchor = (ctypes.c_char * view.nbytes).from_buffer(view)
    return anchor, ctypes.addressof(anchor)


# ---------------------------------------------------------------------------
# Needles
# ---------------------------------------------------------------------------


class NeedleTable:
    """The secrets to look for, XOR-masked, in storage allocated up front.

    :meth:`add` records a masked copy of a buffer without creating any
    object that could hold, or land on, a copy of a key: it writes byte by
    byte into the two arenas below. ``labels`` holds whatever object the
    caller passed with each needle; give it an object that already exists.
    Adding a secret that is already in the table returns the existing index.
    """

    def __init__(self, capacity: int = _DEFAULT_CAPACITY, size: int = _DEFAULT_TABLE_BYTES) -> None:
        if not 1 <= capacity <= 1024 or not MIN_NEEDLE <= size <= 16 << 20:
            raise ValueError("a needle table holds 1 to 1024 needles in at most 16 MiB")
        pad = bytearray(os.urandom(size))
        self._pad = pad.replace(b"\x00", b"\xa5")  # a zero pad byte would leave that byte in the clear
        self._masked = bytearray(size)
        self._offset = [0] * capacity
        self._length = [0] * capacity
        self.seen = [0] * capacity
        self.labels: List[Any] = [None] * capacity
        self.capacity = capacity
        self.count = 0
        self._used = 0

    def __len__(self) -> int:
        return self.count

    def length(self, index: int) -> int:
        return self._length[index]

    def _equal(self, index: int, view: Any, n: int) -> bool:
        if self._length[index] != n:
            return False
        base = self._offset[index]
        masked = self._masked
        pad = self._pad
        i = 0
        while i < n:
            if (masked[base + i] ^ pad[base + i]) != view[i]:
                return False
            i += 1
        return True

    def add(self, data: BufferLike, label: Any = None) -> int:
        """Record *data* and return its index. Raises ValueError for a needle that does not fit."""
        view = as_view(data)
        if view.format != "B" or view.ndim != 1:
            view = view.cast("B")
        n = len(view)
        if not MIN_NEEDLE <= n <= MAX_NEEDLE:
            raise ValueError(f"a needle is {MIN_NEEDLE} to {MAX_NEEDLE} bytes long")
        index = 0
        while index < self.count:
            if self._equal(index, view, n):
                self.seen[index] += 1
                return index
            index += 1
        if self.count >= self.capacity or self._used + n > len(self._masked):
            raise ValueError("the needle table is full")
        base = self._used
        masked = self._masked
        pad = self._pad
        i = 0
        while i < n:
            masked[base + i] = view[i] ^ pad[base + i]
            i += 1
        self._offset[index] = base
        self._length[index] = n
        self.seen[index] = 1
        self.labels[index] = label
        self._used = base + n
        self.count = index + 1
        return index

    def add_masked(self, masked: bytes, pad: bytes, label: Any = None) -> int:
        """Record a needle that arrives already masked (``masked`` is the secret XOR ``pad``).

        How a process that knows a secret hands it to the process that scans
        without ever sending the secret itself. Returns the index.
        """
        n = len(masked)
        if len(pad) != n or not MIN_NEEDLE <= n <= MAX_NEEDLE:
            raise ValueError(f"a needle is {MIN_NEEDLE} to {MAX_NEEDLE} bytes long, with a pad of the same length")
        own_masked = self._masked
        own_pad = self._pad
        index = 0
        while index < self.count:
            if self._length[index] == n:
                base = self._offset[index]
                i = 0
                while i < n and (own_masked[base + i] ^ own_pad[base + i]) == (masked[i] ^ pad[i]):
                    i += 1
                if i == n:
                    self.seen[index] += 1
                    return index
            index += 1
        if self.count >= self.capacity or self._used + n > len(own_masked):
            raise ValueError("the needle table is full")
        base = self._used
        i = 0
        while i < n:
            own_masked[base + i] = masked[i] ^ pad[i] ^ own_pad[base + i]
            i += 1
        self._offset[index] = base
        self._length[index] = n
        self.seen[index] = 1
        self.labels[index] = label
        self._used = base + n
        self.count = index + 1
        return index

    def matches(self, index: int, data: BufferLike) -> bool:
        """True if needle *index* is exactly *data* (compared without unmasking it into a buffer)."""
        view = as_view(data)
        if view.format != "B" or view.ndim != 1:
            view = view.cast("B")
        return 0 <= index < self.count and self._equal(index, view, len(view))


@dataclass(frozen=True)
class ScanResult:
    """One pass: ``hits[i]`` lists the addresses at which needle *i* was found."""

    hits: List[List[int]]
    regions: int
    bytes_scanned: int
    bytes_unreadable: int
    seconds: float
    truncated: bool
    allocation_free: bool
    window: Tuple[int, int]
    writable_only: bool

    def stats(self) -> Dict[str, Any]:
        return {
            "regions": self.regions,
            "bytes_scanned": self.bytes_scanned,
            "bytes_unreadable": self.bytes_unreadable,
            "seconds": self.seconds,
            "truncated": self.truncated,
            "allocation_free": self.allocation_free,
            "whole_address_space": self.window == _NO_WINDOW and not self.writable_only,
            "writable_only": self.writable_only,
        }


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------


class Scanner:
    """Reusable state for memory passes. Use :func:`open_scanner`; close it when done.

    Platform engines supply the region walk (``_walk_begin``, ``_walk_next``,
    ``_walk_end``) and the read primitive (``_read``); this class runs the
    pass. Everything a pass needs is allocated here.
    """

    def __init__(self, chunk_size: int = _DEFAULT_CHUNK, capacity: int = _DEFAULT_CAPACITY) -> None:
        if chunk_size < _PAGE or chunk_size % _PAGE:
            raise ValueError("the chunk size is a whole number of pages")
        if not 1 <= capacity <= 1024:
            raise ValueError("a scanner handles 1 to 1024 needles")
        self.chunk = chunk_size
        self.capacity = capacity
        self.closed = False
        self._scratch = bytearray(chunk_size + MAX_NEEDLE)
        self._scratch_anchor, self._scratch_addr = _address_of(self._scratch)
        prefix_bytes = -(-(capacity * _PREFIX) // _PAGE) * _PAGE
        self._prefix = SecureBuffer(prefix_bytes)
        self._prefix_view = self._prefix.view()
        self._prefix_anchor, self._prefix_addr = _address_of(self._prefix_view)
        stride = _PREFIX + 1
        self._windows: List[Optional[memoryview]] = [None] * (capacity * stride)
        for slot in range(capacity):
            for length in range(4, _PREFIX + 1):
                start = slot * _PREFIX
                self._windows[slot * stride + length] = self._prefix_view[start : start + length]
        self._active: List[Optional[memoryview]] = [None] * capacity
        self._n_len = [0] * capacity
        self._n_pre = [0] * capacity
        self._n_off = [0] * capacity
        self._hit_addr = (ctypes.c_uint64 * _MAX_HITS)()
        self._hit_idx = (ctypes.c_uint16 * _MAX_HITS)()
        self._ex_lo = (ctypes.c_uint64 * _MAX_EXCLUDES)()
        self._ex_hi = (ctypes.c_uint64 * _MAX_EXCLUDES)()
        self._seg = [0] * 8
        own = sorted(
            [
                (self._scratch_addr, _add(self._scratch_addr, len(self._scratch))),
                (self._prefix_addr, _add(self._prefix_addr, prefix_bytes)),
            ]
        )
        self._holes = [own[0][0], own[0][1], own[1][0], own[1][1]]
        self.own_memory = True
        self._g_mdst, self._c_mdst = _int_arg(ctypes.c_uint64, self._scratch_addr)
        self._g_msrc, self._c_msrc = _int_arg(ctypes.c_uint64)
        self._g_mlen, self._c_mlen = _int_arg(ctypes.c_uint64)
        self.allocation_free = _CARG_OFFSET is not None
        # Walk state, written by the engines.
        self.r_lo = 0
        self.r_hi = 0
        self.r_ok = False
        self.r_writable = False
        self._writable_only = False
        self._win_lo, self._win_hi = _NO_WINDOW
        self._nhits = 0
        self._truncated = False
        self._regions = 0
        self._scanned = 0
        self._unreadable = 0
        self._dirty = 0  # bytes of the scratch buffer the last pass may have written
        self._nactive = 0  # needles the last pass unmasked a prefix for
        # Bound once: each "obj.method" evaluation makes a method object, in the 80-byte class of 32-byte keys.
        self._read_bound = self._read
        self._find = self._scratch.find
        self._reserve: List[Any] = []
        self._stock()
        self._walk_bound = self._walk_next

    # -- platform hooks -------------------------------------------------------

    def _walk_begin(self) -> None:
        raise NotImplementedError

    def _walk_next(self) -> bool:
        raise NotImplementedError

    def _walk_end(self) -> None:
        return None

    def _read(self, pos: int, want: int, dst_off: int) -> int:
        raise NotImplementedError

    # -- a pass ---------------------------------------------------------------

    def scan(
        self,
        table: NeedleTable,
        *,
        exclude: Sequence[Sequence[int]] = (),
        window: Optional[Tuple[int, int]] = None,
        writable_only: bool = False,
    ) -> ScanResult:
        """Search every readable page for every needle of *table*, in one pass.

        *exclude* lists ``(address, length)`` ranges whose hits are not
        reported. *window* limits the pass to ``[low, high)``; leave it out to
        search the whole address space. *writable_only* skips mappings this
        process can never write (code and read-only data of executables and
        libraries; on macOS most of the dyld shared cache): everything a
        program can have put there itself is still searched, in a fraction
        of the time.
        """
        if self.closed:
            raise ValueError("this scanner has been closed")
        count = table.count
        if count == 0:
            raise ValueError("there is nothing to look for")
        if count > self.capacity:
            raise ValueError(f"this scanner handles at most {self.capacity} needles in one pass")
        if len(exclude) > _MAX_EXCLUDES:
            raise ValueError(f"at most {_MAX_EXCLUDES} ranges can be excluded")
        lo, hi = window if window is not None else _NO_WINDOW
        if not 0 <= lo < hi:
            raise ValueError("a window is a non-empty range of addresses")
        # From here on, index loops only: an iterator object could land on a freed block under test.
        nexcl = len(exclude)
        e = 0
        while e < nexcl:
            self._ex_lo[e] = exclude[e][0]
            self._ex_hi[e] = _add(exclude[e][0], exclude[e][1])
            e += 1
        self._win_lo, self._win_hi = lo, hi
        self._writable_only = writable_only
        longest = 0
        started = time.perf_counter()
        self._nactive = count
        try:
            stride = _PREFIX + 1
            prefix_view = self._prefix_view
            masked = table._masked
            pad = table._pad
            i = 0
            while i < count:
                n = table._length[i]
                base = table._offset[i]
                pre = n - 1 if n - 1 < _PREFIX else _PREFIX
                j = 0
                while j < pre:
                    prefix_view[i * _PREFIX + j] = masked[base + j] ^ pad[base + j]
                    j += 1
                self._active[i] = self._windows[i * stride + pre]
                self._n_len[i] = n
                self._n_pre[i] = pre
                self._n_off[i] = base
                if n > longest:
                    longest = n
                i += 1
            self._reserve.clear()  # hand the spare tuples to CPython's tuple free lists, see _stock
            self._run(table, count, longest, nexcl)
        finally:
            self._finish()
        elapsed = time.perf_counter() - started
        hits: List[List[int]] = [[] for _ in range(count)]
        for k in range(self._nhits):
            hits[self._hit_idx[k]].append(int(self._hit_addr[k]))
        return ScanResult(
            hits=[sorted(found) for found in hits],
            regions=self._regions,
            bytes_scanned=self._scanned,
            bytes_unreadable=self._unreadable,
            seconds=round(elapsed, 3),
            truncated=self._truncated,
            allocation_free=self.allocation_free,
            window=(lo, hi),
            writable_only=writable_only,
        )

    def _stock(self) -> None:
        """Keep spare tuples of the sizes a foreign call needs for its arguments.

        A ctypes function is called through ``tp_call``, which packs the
        arguments into a tuple. CPython takes tuples from per-size free lists
        before it asks its allocator, and a tuple of three to six items comes
        from the allocator's 64- to 96-byte classes: the classes of short
        bytes objects, where a freed key would be. Releasing these spares
        just before a pass fills those free lists, so the pass never takes a
        tuple from the allocator.
        """
        for size in (3, 4, 5, 6):
            for _ in range(4):
                self._reserve.append(tuple(range(size)))

    def _finish(self) -> None:
        """Zero what the pass copied into the scratch buffer, and the unmasked prefixes."""
        ctypes.memset(self._scratch_addr, 0, self._dirty)
        self._dirty = 0
        ctypes.memset(self._prefix_addr, 0, len(self._prefix_view))
        i = 0
        while i < self._nactive:
            self._active[i] = None
            i += 1
        self._nactive = 0
        self._win_lo, self._win_hi = _NO_WINDOW
        if not self._reserve and not self.closed:
            self._stock()

    def _run(self, table: NeedleTable, count: int, longest: int, nexcl: int) -> None:
        """Walk the address space and record hits. Allocation-free: see the module docstring."""
        chunk = self.chunk
        scratch = self._scratch
        scratch_addr = self._scratch_addr
        find = self._find
        masked = table._masked
        pad = table._pad
        read = self._read_bound
        walk_next = self._walk_bound
        memmove = _MEMMOVE
        g_mdst, g_msrc, g_mlen = self._g_mdst, self._g_msrc, self._g_mlen
        c_msrc, c_mlen = self._c_msrc, self._c_mlen
        # Never more than three names per assignment: four or more build a tuple, which is an allocation.
        active, n_len = self._active, self._n_len
        n_pre, n_off = self._n_pre, self._n_off
        hit_addr, hit_idx = self._hit_addr, self._hit_idx
        ex_lo, ex_hi = self._ex_lo, self._ex_hi
        seg, holes = self._seg, self._holes
        nholes = 4 if self.own_memory else 0
        win_lo, win_hi = self._win_lo, self._win_hi
        writable_only = self._writable_only
        page_mask = _PAGE - 1
        keep = longest - 1
        nhits = 0
        truncated = False
        regions = scanned = unreadable = 0
        dirty = 0
        prev_end = -1
        carry = 0
        self._walk_begin()
        try:
            while walk_next():
                if not self.r_ok or (writable_only and not self.r_writable):
                    continue
                lo = self.r_lo
                hi = self.r_hi
                if lo < win_lo:
                    lo = win_lo
                if hi > win_hi:
                    hi = win_hi
                if lo >= hi:
                    continue
                regions += 1
                nseg = 0  # [lo, hi) minus this scanner's own buffers
                j = 0
                while j < nholes:
                    h_lo = holes[j]
                    h_hi = holes[j + 1]
                    j += 2
                    if h_hi <= lo or h_lo >= hi:
                        continue
                    if h_lo > lo:
                        seg[nseg] = lo
                        seg[nseg + 1] = h_lo
                        nseg += 2
                    if h_hi > lo:
                        lo = h_hi
                if lo < hi:
                    seg[nseg] = lo
                    seg[nseg + 1] = hi
                    nseg += 2
                s = 0
                while s < nseg:
                    lo = seg[s]
                    hi = seg[s + 1]
                    s += 2
                    if lo != prev_end:
                        carry = 0  # not contiguous with the bytes before
                    pos = lo
                    page_until = 0
                    while pos < hi:
                        want = hi - pos
                        if want > chunk:
                            want = chunk
                        if pos < page_until:
                            rest = _PAGE - (pos & page_mask)
                            if want > rest:
                                want = rest
                        if carry + want > dirty:  # the most a read here can write; zeroed after the pass
                            dirty = carry + want
                        got = read(pos, want, carry)
                        if got <= 0 and want > _PAGE:  # an unreadable page inside: go page by page
                            page_until = _add(pos, want)
                            want = _PAGE - (pos & page_mask)
                            got = read(pos, want, carry)
                        if got <= 0:
                            unreadable = _add(unreadable, want)
                            pos = _add(pos, want)
                            carry = 0
                            continue
                        filled = carry + got
                        base = pos - carry
                        i = 0
                        while i < count:
                            window = active[i]
                            n = n_len[i]
                            pre = n_pre[i]
                            offset = n_off[i]
                            at = find(window, 0, filled)  # type: ignore[arg-type]  # set for every i < count: MIN_NEEDLE 8 gives pre >= 7
                            while at != -1:
                                end = at + n
                                if carry < end <= filled:  # new, and wholly inside these bytes
                                    k = pre
                                    while k < n:
                                        if (scratch[at + k] ^ pad[offset + k]) != masked[offset + k]:
                                            break
                                        k += 1
                                    if k == n:
                                        addr = _add(base, at)
                                        last = _add(addr, n)
                                        skip = False
                                        e = 0
                                        while e < nexcl:
                                            if ex_lo[e] <= addr and last <= ex_hi[e]:
                                                skip = True
                                                break
                                            e += 1
                                        if not skip:
                                            if nhits < _MAX_HITS:
                                                hit_addr[nhits] = addr
                                                hit_idx[nhits] = i
                                                nhits += 1
                                            else:
                                                truncated = True
                                at = find(window, at + 1, filled)  # type: ignore[arg-type]  # as above
                            i += 1
                        pos = _add(pos, got)
                        scanned = _add(scanned, got)
                        carry = keep if filled > keep else filled
                        if carry:  # keep the tail: a needle may continue in the next read
                            c_msrc.value = _add(scratch_addr, filled - carry)
                            c_mlen.value = carry
                            memmove(g_mdst, g_msrc, g_mlen)
                    prev_end = hi
        finally:
            self._walk_end()
            self._dirty = dirty
            self._nhits = nhits
            self._truncated = truncated
            self._regions = regions
            self._scanned = scanned
            self._unreadable = unreadable

    # -- lifetime ---------------------------------------------------------------

    def close(self) -> None:
        """Release every buffer. Idempotent."""
        if self.closed:
            return
        self.closed = True
        self._dirty = len(self._scratch)  # all of it, whatever the passes recorded
        self._finish()
        for window in self._windows:
            if window is not None:
                window.release()
        self._windows = []
        self._active = []
        self._prefix_anchor = None
        self._scratch_anchor = None
        self._prefix.wipe()

    def __enter__(self) -> "Scanner":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class _SubmapInfo(ctypes.Structure):
    """``struct vm_region_submap_info_64`` from <mach/vm_region.h>, V2 layout, #pragma pack(4)."""

    _layout_ = "ms"  # explicit since Python 3.14; same layout _pack_ always gave
    _pack_ = 4
    _fields_ = [
        ("protection", ctypes.c_int32),
        ("max_protection", ctypes.c_int32),
        ("inheritance", ctypes.c_uint32),
        ("offset", ctypes.c_uint64),
        ("user_tag", ctypes.c_uint32),
        ("pages_resident", ctypes.c_uint32),
        ("pages_shared_now_private", ctypes.c_uint32),
        ("pages_swapped_out", ctypes.c_uint32),
        ("pages_dirtied", ctypes.c_uint32),
        ("ref_count", ctypes.c_uint32),
        ("shadow_depth", ctypes.c_uint16),
        ("external_pager", ctypes.c_uint8),
        ("share_mode", ctypes.c_uint8),
        ("is_submap", ctypes.c_int32),
        ("behavior", ctypes.c_int32),
        ("object_id", ctypes.c_uint32),
        ("user_wired_count", ctypes.c_uint16),
        ("pages_reusable", ctypes.c_uint32),
        ("object_id_full", ctypes.c_uint64),
    ]


#: VM_REGION_SUBMAP_INFO_COUNT_64: the size of the structure above in 32-bit words.
_SUBMAP_INFO_COUNT = ctypes.sizeof(_SubmapInfo) // 4
_VM_PROT_READ = 1
_VM_PROT_WRITE = 2

#: Names of the VM user tags that say where a block of memory came from (<mach/vm_statistics.h>).
_VM_TAGS = {
    1: "MALLOC",
    2: "MALLOC_SMALL",
    3: "MALLOC_LARGE",
    4: "MALLOC_HUGE",
    6: "REALLOC",
    7: "MALLOC_TINY",
    8: "MALLOC_LARGE_REUSABLE",
    9: "MALLOC_LARGE_REUSED",
    11: "MALLOC_NANO",
    12: "MALLOC_MEDIUM",
    22: "VM_RECLAIM",
    30: "STACK",
    31: "GUARD",
    32: "SHARED_PMAP",
    33: "DYLIB",
    60: "DYLD",
    61: "DYLD_MALLOC",
    73: "OS_ALLOC_ONCE",
    74: "LIBDISPATCH",
}


class _DarwinScanner(Scanner):
    """``mach_vm_region_recurse`` and ``mach_vm_read_overwrite`` on this task's own port."""

    def __init__(self, chunk_size: int = _DEFAULT_CHUNK, capacity: int = _DEFAULT_CAPACITY) -> None:
        if _REGION is None or _VM_READ is None or _MEMMOVE is None:
            raise OSError("the Mach VM calls are not available")
        self._task_cell = ctypes.c_uint32.in_dll(_LIBC, "mach_task_self_")
        self._g_task, self._c_task = _int_arg(ctypes.c_uint32, self._task_cell.value)
        self._addr = ctypes.c_uint64()
        self._size = ctypes.c_uint64()
        self._depth = ctypes.c_uint32()
        self._count = ctypes.c_uint32()
        self._info = _SubmapInfo()
        self._r_addr = ctypes.byref(self._addr)
        self._r_size = ctypes.byref(self._size)
        self._r_depth = ctypes.byref(self._depth)
        self._r_count = ctypes.byref(self._count)
        self._r_info = ctypes.byref(self._info)
        self._g_src, self._c_src = _int_arg(ctypes.c_uint64)
        self._g_len, self._c_len = _int_arg(ctypes.c_uint64)
        self._g_dst, self._c_dst = _int_arg(ctypes.c_uint64)
        self._got = ctypes.c_uint64()
        self._r_got = ctypes.byref(self._got)
        self._cursor = 0
        Scanner.__init__(self, chunk_size, capacity)

    def _walk_begin(self) -> None:
        self._c_task.value = self._task_cell.value  # the port name changes across fork
        self._cursor = self._win_lo  # no entry below the window is read: the walk starts at it
        self._depth.value = 0

    def _walk_next(self) -> bool:
        info = self._info
        while True:
            cursor = self._cursor
            if cursor >= self._win_hi:
                return False  # past the window
            self._addr.value = cursor
            self._count.value = _SUBMAP_INFO_COUNT
            if _REGION(self._g_task, self._r_addr, self._r_size, self._r_depth, self._r_info, self._r_count) != 0:  # type: ignore[misc]  # __init__ refuses None
                return False  # past the last entry
            if info.is_submap:  # the dyld shared cache: look inside it
                self._depth.value += 1
                continue
            start = self._addr.value
            end = _add(start, self._size.value)
            # The kernel answers with the entry that contains the cursor, and
            # entries split and merge while the walk goes on: never go back.
            self._cursor = end if end > cursor else _add(cursor, _PAGE)
            if start < cursor:
                start = cursor
            if end <= start:
                continue
            self.r_lo = start
            self.r_hi = end
            self.r_ok = (info.protection & _VM_PROT_READ) != 0
            self.r_writable = (info.max_protection & _VM_PROT_WRITE) != 0
            return True

    def _read(self, pos: int, want: int, dst_off: int) -> int:
        # Copied by the kernel: an unreadable page is an error code, never a fault.
        self._c_src.value = pos
        self._c_len.value = want
        self._c_dst.value = _add(self._scratch_addr, dst_off)
        if _VM_READ(self._g_task, self._g_src, self._g_len, self._g_dst, self._r_got) != 0:  # type: ignore[misc]  # __init__ refuses None
            return 0
        return self._got.value


class _IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class _LinuxScanner(Scanner):
    """``/proc/<pid>/maps`` and ``/proc/<pid>/mem`` (``pread``), ``process_vm_readv`` as the fallback.

    *maps_path* and *mem_path* let a test drive the parser and the walk with
    ordinary files; the scanner then reads those, not this process.
    """

    _MAX_REGIONS = 65536
    _MAPS_CAP = 8 << 20

    def __init__(
        self,
        chunk_size: int = _DEFAULT_CHUNK,
        capacity: int = _DEFAULT_CAPACITY,
        *,
        maps_path: Optional[str] = None,
        mem_path: Optional[str] = None,
    ) -> None:
        if _READ is None or _MEMMOVE is None or (_PREAD is None and _PROCESS_VM_READV is None):
            raise OSError("the C library lacks read, pread or process_vm_readv")
        # Paths as bytes: opening a str path during a pass would allocate its encoded form.
        self._maps_path = os.fsencode(maps_path or "/proc/self/maps")
        self._mem_fd = -1
        self._maps = bytearray(self._MAPS_CAP)
        self._maps_anchor, self._maps_addr = _address_of(self._maps)
        self._reg_lo = (ctypes.c_uint64 * self._MAX_REGIONS)()
        self._reg_hi = (ctypes.c_uint64 * self._MAX_REGIONS)()
        self._reg_ok = (ctypes.c_uint8 * self._MAX_REGIONS)()
        self._nreg = 0
        self._ri = 0
        self._g_fd, self._c_fd = _int_arg(ctypes.c_int, -1)
        self._g_mfd, self._c_mfd = _int_arg(ctypes.c_int, -1)
        self._g_pdst, self._c_pdst = _int_arg(ctypes.c_uint64)
        self._g_plen, self._c_plen = _int_arg(ctypes.c_uint64)
        self._g_poff, self._c_poff = _int_arg(ctypes.c_int64)
        self._iov_local = _IOVec()
        self._iov_remote = _IOVec()
        self._r_local = ctypes.byref(self._iov_local)
        self._r_remote = ctypes.byref(self._iov_remote)
        self._g_pid, _ = _int_arg(ctypes.c_int, os.getpid())
        self._g_one, _ = _int_arg(ctypes.c_uint64, 1)
        self._g_noflags, _ = _int_arg(ctypes.c_uint64, 0)
        try:
            self._mem_fd = os.open(os.fsencode(mem_path or "/proc/self/mem"), os.O_RDONLY)
        except OSError:  # a non-dumpable process cannot open its own mem file
            self._mem_fd = -1
        self._c_mfd.value = self._mem_fd
        self.used_mem_file = self._mem_fd >= 0
        try:
            Scanner.__init__(self, chunk_size, capacity)
        except BaseException:
            self._close_mem()
            raise
        self.own_memory = maps_path is None

    def _load_maps(self) -> int:
        fd = os.open(self._maps_path, os.O_RDONLY)
        total = 0
        try:
            self._c_fd.value = fd
            while total < self._MAPS_CAP:
                self._c_pdst.value = _add(self._maps_addr, total)
                self._c_plen.value = self._MAPS_CAP - total
                got = _READ(self._g_fd, self._g_pdst, self._g_plen)
                if got <= 0:
                    break
                total += got
        finally:
            os.close(fd)
        if total >= self._MAPS_CAP:
            raise OSError("the memory map is larger than the scanner can hold")
        return total

    def _hex(self, begin: int, end: int) -> int:
        """``int(maps[begin:end], 16)`` for at most 14 hex digits, without a big temporary."""
        buf = self._maps
        split = end - 7 if end - begin > 7 else begin
        high = 0
        i = begin
        while i < split:
            ch = buf[i]
            high = high * 16 + (ch - 48 if ch < 58 else (ch | 0x20) - 87)
            i += 1
        low = 0
        while i < end:
            ch = buf[i]
            low = low * 16 + (ch - 48 if ch < 58 else (ch | 0x20) - 87)
            i += 1
        return (high << 28) | low if high else low

    def _parse_maps(self, nbytes: int) -> int:
        """Parse ``<lo>-<hi> <perms> <offset> <dev> <inode> [<path>]`` lines without creating text."""
        buf = self._maps
        reg_lo, reg_hi, reg_ok = self._reg_lo, self._reg_hi, self._reg_ok
        i = 0
        k = 0
        while i < nbytes and k < self._MAX_REGIONS:
            eol = buf.find(b"\n", i, nbytes)
            if eol < 0:
                eol = nbytes
            dash = buf.find(b"-", i, eol)
            space = buf.find(b" ", i, eol)
            if dash < 0 or space < dash or space + 2 >= eol:
                i = eol + 1
                continue
            readable = buf[space + 1] == 0x72  # 'r'
            writable = buf[space + 2] == 0x77  # 'w'
            # More than 14 hex digits (x86-64 [vsyscall]) is no offset pread can take.
            if dash - i > 14 or space - dash - 1 > 14:
                readable = False
                lo = hi = 0
            else:
                lo = self._hex(i, dash)
                hi = self._hex(dash + 1, space)
            bracket = buf.find(b"[", space, eol)
            slash = buf.find(b"/", space, eol)
            if bracket >= 0 and (buf.startswith(b"[vvar", bracket) or buf.startswith(b"[vsyscall", bracket)):
                readable = False  # kernel pages that refuse to be read
            # Written by this process at some time: writable now, or not backed by a file.
            ours = writable or slash < 0 or 0 <= bracket < slash
            reg_lo[k] = lo
            reg_hi[k] = hi
            reg_ok[k] = (1 if readable else 0) | (2 if ours else 0)
            k += 1
            i = eol + 1
        return k

    def _walk_begin(self) -> None:
        self._nreg = self._parse_maps(self._load_maps())
        self._ri = 0

    def _walk_next(self) -> bool:
        i = self._ri
        if i >= self._nreg:
            return False
        self._ri = i + 1
        self.r_lo = self._reg_lo[i]
        self.r_hi = self._reg_hi[i]
        flags = self._reg_ok[i]
        self.r_ok = (flags & 1) != 0
        self.r_writable = (flags & 2) != 0
        return True

    def _read(self, pos: int, want: int, dst_off: int) -> int:
        dst = _add(self._scratch_addr, dst_off)
        if self._mem_fd >= 0 and _PREAD is not None:
            self._c_pdst.value = dst
            self._c_plen.value = want
            self._c_poff.value = pos
            got = _PREAD(self._g_mfd, self._g_pdst, self._g_plen, self._g_poff)
            return got if got > 0 else 0
        if _PROCESS_VM_READV is None or not self.own_memory:
            return 0
        self._iov_local.base = dst
        self._iov_local.len = want
        self._iov_remote.base = pos
        self._iov_remote.len = want
        got = _PROCESS_VM_READV(self._g_pid, self._r_local, self._g_one, self._r_remote, self._g_one, self._g_noflags)
        return got if got > 0 else 0

    def _close_mem(self) -> None:
        if self._mem_fd >= 0:
            os.close(self._mem_fd)
            self._mem_fd = -1

    def close(self) -> None:
        if not self.closed:
            self._maps_anchor = None
            self._close_mem()
        Scanner.close(self)


def open_scanner(chunk_size: int = _DEFAULT_CHUNK, capacity: int = _DEFAULT_CAPACITY) -> Scanner:
    """A scanner for this process, checked on a planted pattern before it is returned.

    Raises OSError where the process cannot scan itself (see :func:`supported`),
    and RuntimeError if the check fails: the scanner would prove nothing.
    """
    usable, reason = supported()
    if not usable:
        raise OSError(reason)
    scanner: Scanner = (
        _DarwinScanner(chunk_size, capacity) if _IS_DARWIN else _LinuxScanner(chunk_size, capacity)
    )
    try:
        _warm_up(scanner)
        _self_check(scanner)
    except BaseException:
        scanner.close()
        raise
    return scanner


def _warm_up(scanner: Scanner) -> None:
    """Run every function of a pass :data:`_WARM_RUNS` times, on passes that read nothing. Once a process.

    CPython 3.9 and 3.10 allocate a code object's first cache on its 1024th
    run, zero-filled (``PyMem_Calloc``), from the small-object classes or the C
    heap: the blocks a pass must leave as they are. Without this, a function
    that runs once per region reaches that run a few passes in, inside a pass,
    and wipes a freed block before the pass reads it. Each function runs here
    instead, on passes with nothing to walk: on macOS a window above every
    mapping, on Linux the empty memory map of ``/dev/null``. Code objects are
    shared by every scanner, so one warm-up serves the process.
    """
    global _warmed
    if _warmed:
        return
    table = NeedleTable(capacity=1, size=MIN_NEEDLE)
    table.add(bytes(range(1, MIN_NEEDLE + 1)))  # never met: these passes read no memory
    idle = (_NO_WINDOW[1] - _PAGE, _NO_WINDOW[1])
    scan = scanner.scan
    read = scanner._read
    linux = scanner if isinstance(scanner, _LinuxScanner) else None
    maps = linux._maps_path if linux is not None else b""
    if linux is not None:
        linux._maps_path = os.fsencode(os.devnull)
    try:
        run = 0
        while run < _WARM_RUNS:
            scan(table, window=idle)
            read(0, 0, 0)  # zero bytes: the call, not the copy, is what counts
            _add(run, run)
            if linux is not None:
                linux._hex(0, 0)
            run += 1
    finally:
        if linux is not None:
            linux._maps_path = maps
    _warmed = True


def _self_check(scanner: Scanner) -> None:
    """Plant one pattern, find it exactly where it is, and find nothing for a pattern that is absent.

    Also the warm-up: the first pass through each code path allocates
    (frames, caches), and it must not be the pass that matters.
    """
    plant = bytearray(4 * _PAGE)
    table = NeedleTable(capacity=2, size=128)
    with SecureBuffer.random(32) as present, SecureBuffer.random(32) as absent:
        plant[_PAGE - 10 : _PAGE + 22] = present.view()  # straddles a page boundary
        table.add(present, "present")
        table.add(absent, "absent")
    anchor, base = _address_of(plant)
    try:
        page = base - base % _PAGE
        result = scanner.scan(table, window=(page, page + 6 * _PAGE))
    finally:
        del anchor
        plant[:] = bytes(len(plant))
    if result.hits != [[base + _PAGE - 10], []]:
        raise RuntimeError(f"the memory scanner failed its own check: {result.hits!r}")


def describe_address(address: int) -> str:
    """Where *address* lives, for a report: ``0x... MALLOC_TINY rw-`` or ``0x... [heap] rw-p``."""
    if _IS_DARWIN and _REGION is not None:
        region = _LIBC["mach_vm_region_recurse"]
        region.restype = ctypes.c_int
        task = ctypes.c_uint32.in_dll(_LIBC, "mach_task_self_").value
        start, size, depth = ctypes.c_uint64(address), ctypes.c_uint64(0), ctypes.c_uint32(0)
        info = _SubmapInfo()
        while True:
            count = ctypes.c_uint32(_SUBMAP_INFO_COUNT)
            status = region(
                ctypes.c_uint32(task),
                ctypes.byref(start),
                ctypes.byref(size),
                ctypes.byref(depth),
                ctypes.byref(info),
                ctypes.byref(count),
            )
            if status != 0 or start.value > address:
                return f"{address:#x} unmapped"
            if info.is_submap:
                depth.value += 1
                start.value = address
                continue
            break
        tag = info.user_tag
        label = _VM_TAGS.get(tag) or (f"tag {tag}" if tag else ("file" if info.external_pager else "anonymous"))
        mode = "".join(flag if info.protection & bit else "-" for flag, bit in (("r", 1), ("w", 2), ("x", 4)))
        return f"{address:#x} {label} {mode}"
    if _IS_LINUX:
        try:
            with open("/proc/self/maps", "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    parts = line.split(None, 5)
                    low, high = (int(value, 16) for value in parts[0].split("-"))
                    if low <= address < high:
                        name = parts[5].strip() if len(parts) > 5 else "anonymous"
                        return f"{address:#x} {name} {parts[1]}"
        except (OSError, ValueError, IndexError):
            pass
    return f"{address:#x} unmapped"
