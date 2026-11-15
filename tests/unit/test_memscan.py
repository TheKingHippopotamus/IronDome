"""irondome.memscan: the instrument behind the keys-wiped claim.

Most passes here are limited to a window of a few pages around what they
plant, so they take milliseconds; the claim test does the whole address space.
"""

from __future__ import annotations

import ctypes
import gc
import mmap
import os
import subprocess
import sys
from typing import Dict, Set

import pytest

from irondome import memscan
from irondome.secmem import SecureBuffer, wipe_bytes

PAGE = mmap.PAGESIZE

pytestmark = pytest.mark.skipif(not memscan.supported()[0], reason=memscan.supported()[1] or "scanner unavailable")


@pytest.fixture(scope="module")
def scanner():
    opened = memscan.open_scanner()
    yield opened
    opened.close()


def address_of(buffer) -> int:
    anchor = (ctypes.c_char * len(buffer)).from_buffer(buffer)
    try:
        return ctypes.addressof(anchor)
    finally:
        del anchor


def window(base: int, pages: int):
    start = base - base % PAGE
    return start, start + pages * PAGE


def random_key(length: int = 32) -> SecureBuffer:
    return SecureBuffer.random(length)


# -- the needle table --------------------------------------------------------------


def test_a_needle_is_stored_masked_at_every_byte():
    table = memscan.NeedleTable(capacity=4, size=256)
    with random_key() as key:
        index = table.add(key, "key")
        stored = bytes(table._masked[:32])
        assert all(a != b for a, b in zip(stored, key.view()))
        assert stored not in bytes(key.view())
        assert table.matches(index, key)
    assert table.labels[index] == "key" and table.length(index) == 32 and len(table) == 1


def test_the_same_secret_twice_is_one_needle_seen_twice():
    table = memscan.NeedleTable(capacity=4, size=256)
    with random_key() as key:
        first = table.add(key, "first")
        second = table.add(bytes(key.view()), "second")
    assert first == second == 0 and table.seen[0] == 2 and table.labels[0] == "first"


def test_a_needle_can_arrive_already_masked():
    table = memscan.NeedleTable(capacity=4, size=256)
    secret = os.urandom(24)
    pad = bytes(b or 1 for b in os.urandom(24))
    index = table.add_masked(bytes(a ^ b for a, b in zip(secret, pad)), pad, "imported")
    assert table.matches(index, secret)
    assert table.add(secret, "again") == index and table.seen[index] == 2


@pytest.mark.parametrize("length", [0, 7, memscan.MAX_NEEDLE + 1])
def test_needles_outside_the_accepted_lengths_are_refused(length):
    with pytest.raises(ValueError):
        memscan.NeedleTable(capacity=2, size=8192).add(b"x" * length)


def test_a_full_table_refuses_more():
    table = memscan.NeedleTable(capacity=1, size=64)
    table.add(os.urandom(16))
    with pytest.raises(ValueError, match="full"):
        table.add(os.urandom(16))
    with pytest.raises(ValueError, match="full"):
        memscan.NeedleTable(capacity=2, size=20).add(os.urandom(21))


def test_table_and_scanner_sizes_are_checked():
    with pytest.raises(ValueError):
        memscan.NeedleTable(capacity=0)
    with pytest.raises(ValueError):
        memscan.open_scanner(chunk_size=PAGE + 1)
    with pytest.raises(ValueError):
        memscan.open_scanner(capacity=0)


# -- what a pass finds -------------------------------------------------------------


def test_a_planted_secret_is_found_exactly_where_it_is(scanner):
    with random_key() as key:
        plant = bytearray(3 * PAGE)
        plant[100:132] = key.view()
        plant[PAGE + 7 : PAGE + 39] = key.view()
        table = memscan.NeedleTable(capacity=2, size=128)
        index = table.add(key, "key")
    base = address_of(plant)
    result = scanner.scan(table, window=window(base, 5))
    assert result.hits[index] == [base + 100, base + PAGE + 7]
    assert result.bytes_scanned >= 3 * PAGE and not result.truncated


def test_a_secret_that_is_absent_is_not_found(scanner):
    plant = bytearray(os.urandom(4 * PAGE))
    table = memscan.NeedleTable(capacity=1, size=64)
    with random_key() as key:
        table.add(key)
    result = scanner.scan(table, window=window(address_of(plant), 6))
    assert result.hits == [[]]


def test_the_table_never_matches_itself(scanner):
    """The masked needles and their pads are in this process too; they must not count."""
    table = memscan.NeedleTable(capacity=2, size=PAGE)
    with random_key() as key:
        table.add(key)
    for arena in (table._masked, table._pad):
        result = scanner.scan(table, window=window(address_of(arena), 3))
        assert result.hits == [[]]


def test_a_partial_copy_is_not_a_hit(scanner):
    with random_key() as key:
        plant = bytearray(2 * PAGE)
        plant[64:95] = key.view()[:31]  # all but the last byte
        plant[200:232] = bytes(key.view()[:31]) + bytes([key.view()[31] ^ 1])
        table = memscan.NeedleTable(capacity=1, size=64)
        table.add(key)
    assert scanner.scan(table, window=window(address_of(plant), 4)).hits == [[]]


def test_several_needles_in_one_pass(scanner):
    keys = [random_key(length) for length in (8, 20, 32, 64, 300)]
    plant = bytearray(4 * PAGE)
    table = memscan.NeedleTable(capacity=8, size=2048)
    offsets = [50, 900, 2000, 3000, 5000]
    for key, offset in zip(keys, offsets):
        plant[offset : offset + len(key)] = key.view()
        table.add(key)
        key.wipe()
    base = address_of(plant)
    result = scanner.scan(table, window=window(base, 6))
    assert result.hits == [[base + offset] for offset in offsets]


def test_excluded_ranges_are_not_reported(scanner):
    with random_key() as key:
        plant = bytearray(2 * PAGE)
        plant[10:42] = key.view()
        plant[PAGE : PAGE + 32] = key.view()
        table = memscan.NeedleTable(capacity=1, size=64)
        table.add(key)
    base = address_of(plant)
    result = scanner.scan(table, window=window(base, 4), exclude=[(base, PAGE)])
    assert result.hits == [[base + PAGE]]


def test_a_secret_across_chunk_and_region_boundaries_is_found_once():
    """One page per read: matches across reads, and across two VM entries made by mprotect."""
    small = memscan.open_scanner(chunk_size=PAGE)
    region = mmap.mmap(-1, 6 * PAGE, flags=mmap.MAP_PRIVATE | getattr(mmap, "MAP_ANONYMOUS", 0x20),
                       prot=mmap.PROT_READ | mmap.PROT_WRITE)
    anchor = (ctypes.c_char * (6 * PAGE)).from_buffer(region)
    base = ctypes.addressof(anchor)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    try:
        with random_key() as key:
            spots = [PAGE - 16, 2 * PAGE - 1, 3 * PAGE - 31, 4 * PAGE, 6 * PAGE - 32]
            for spot in spots:
                region[spot : spot + 32] = key.view()
            table = memscan.NeedleTable(capacity=1, size=64)
            table.add(key)
        assert libc.mprotect(base + PAGE, PAGE, mmap.PROT_READ) == 0  # two VM entries now
        result = small.scan(table, window=(base, base + 6 * PAGE))
        assert result.hits == [[base + spot for spot in spots]]
    finally:
        libc.mprotect(base + PAGE, PAGE, mmap.PROT_READ | mmap.PROT_WRITE)
        del anchor
        region.close()
        small.close()


def test_an_unreadable_page_is_skipped_without_a_fault(scanner):
    region = mmap.mmap(-1, 3 * PAGE, flags=mmap.MAP_PRIVATE | getattr(mmap, "MAP_ANONYMOUS", 0x20),
                       prot=mmap.PROT_READ | mmap.PROT_WRITE)
    anchor = (ctypes.c_char * (3 * PAGE)).from_buffer(region)
    base = ctypes.addressof(anchor)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    try:
        with random_key() as key:
            region[10:42] = key.view()
            region[2 * PAGE + 10 : 2 * PAGE + 42] = key.view()
            region[PAGE - 8 : PAGE + 24] = key.view()  # runs into the page that becomes unreadable
            table = memscan.NeedleTable(capacity=1, size=64)
            table.add(key)
        assert libc.mprotect(base + PAGE, PAGE, 0) == 0  # PROT_NONE
        result = scanner.scan(table, window=(base, base + 3 * PAGE))
        assert result.hits == [[base + 10, base + 2 * PAGE + 10]]
    finally:
        libc.mprotect(base + PAGE, PAGE, mmap.PROT_READ | mmap.PROT_WRITE)
        del anchor
        region.close()


def test_a_freed_bytes_copy_is_found_and_a_wiped_one_is_not(scanner):
    """What keys-wiped is about: a key in a freed object is still there unless it was overwritten.

    Garbage is collected before the copy is made, not after it is dropped: a
    collection runs the finalizers of whatever earlier tests left behind, those
    allocate, and the allocator hands them the block that was just freed. The
    copy needs no collection to be freed; dropping the last reference does it.
    """
    for wipe_first, expected in ((False, True), (True, False)):
        gc.collect()
        table = memscan.NeedleTable(capacity=1, size=64)
        with random_key() as key:
            table.add(key)
            copy = bytes(key.view())
        if wipe_first:
            wipe_bytes(copy)
        del copy
        assert bool(scanner.scan(table, writable_only=True).hits[0]) is expected


def test_freshly_freed_small_objects_are_not_overwritten_by_the_scan(scanner):
    """Calibration: the pass allocates nothing that could land on a block freed just before it."""
    sizes = [size - bytes.__basicsize__ for size in range(48, 513, 16)]
    table = memscan.NeedleTable(capacity=len(sizes), size=64 * len(sizes))
    scan = scanner.scan  # bound first: on 3.9 "scanner.scan(..., keyword=...)" makes a 64-byte method object
    decoys = [os.urandom(size) for size in sizes]
    for decoy in decoys:
        table.add(memoryview(decoy)[:32])
    decoys.clear()
    result = scan(table, writable_only=True)
    assert [index for index, hits in enumerate(result.hits) if not hits] == []


def test_every_function_a_pass_runs_was_run_past_cpythons_cache_threshold_first(scanner, monkeypatch):
    """CPython 3.9 and 3.10 give a code object a zero-filled cache on its 1024th run: never inside a pass.

    The calibration above is how this was found (on Linux, Python 3.9, a
    96-byte decoy was wiped by the cache of ``_add``). Here, without relying on
    where a cache lands: every Python function that runs from the start of a
    pass to its last read has already run more than 1024 times in the warm-up.
    """
    warmed: Dict[object, int] = {}

    def count(frame, event, _arg):
        if event == "call":
            warmed[frame.f_code] = warmed.get(frame.f_code, 0) + 1

    monkeypatch.setattr(memscan, "_warmed", False)
    sys.setprofile(count)
    try:
        memscan._warm_up(scanner)
    finally:
        sys.setprofile(None)
    assert memscan._warmed
    in_pass: Set[object] = set()
    active = []
    begin, end = memscan.Scanner.scan.__code__, memscan.Scanner._run.__code__

    def record(frame, event, _arg):
        if event == "call" and frame.f_code is begin:
            active.append(True)
        if event == "call" and active:
            in_pass.add(frame.f_code)
        if event == "return" and frame.f_code is end:
            active.clear()

    plant = bytearray(os.urandom(4 * PAGE))
    table = memscan.NeedleTable(capacity=1, size=64)
    table.add(plant[PAGE : PAGE + 32])
    sys.setprofile(record)
    try:
        result = scanner.scan(table, window=window(address_of(plant), 6), exclude=[(1, 1)])
    finally:
        sys.setprofile(None)
    assert result.hits[0] and result.bytes_scanned
    names = {code.co_name for code in in_pass}
    assert {"scan", "_run", "_walk_begin", "_walk_next", "_read", "_add"} <= names
    assert sorted(code.co_name for code in in_pass if warmed.get(code, 0) <= 1024) == []


def test_a_window_above_every_mapping_reads_nothing(scanner):
    """What the warm-up's passes rely on: such a pass finds no region and copies no byte."""
    table = memscan.NeedleTable(capacity=1, size=64)
    table.add(os.urandom(32))
    top = memscan._NO_WINDOW[1]
    beyond = scanner.scan(table, window=(top - PAGE, top))
    assert (beyond.regions, beyond.bytes_scanned, beyond.bytes_unreadable, beyond.hits) == (0, 0, 0, [[]])


@pytest.mark.skipif(sys.platform != "darwin", reason="the Mach walk; Linux reads the whole map in one call")
def test_on_macos_a_window_bounds_the_walk_not_only_the_reads(scanner):
    """Short passes (the warm-up's, the self-check's) ask the kernel about the entries in their window only."""
    plant = bytearray(os.urandom(PAGE))
    table = memscan.NeedleTable(capacity=1, size=64)
    table.add(plant[:32])
    asked = []

    def count(frame, event, _arg):
        if event == "call" and frame.f_code is memscan._DarwinScanner._walk_next.__code__:
            asked.append(1)

    sys.setprofile(count)
    try:
        near = scanner.scan(table, window=window(address_of(plant), 2))
    finally:
        sys.setprofile(None)
    assert near.hits[0] and 1 <= near.regions <= 2
    assert len(asked) <= 4  # the entries the two pages touch, and the answer that the window is done


def test_writable_only_skips_a_read_only_file_mapping(scanner, tmp_path):
    secret = os.urandom(32)
    path = tmp_path / "mapped"
    path.write_bytes(b"\x00" * 100 + secret + b"\x00" * (PAGE - 132))
    table = memscan.NeedleTable(capacity=1, size=64)
    table.add(secret)
    wipe_bytes(secret)
    fd = os.open(str(path), os.O_RDONLY)
    try:
        mapped = mmap.mmap(fd, PAGE, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
    finally:
        os.close(fd)
    try:
        base = _mapping_address(mapped)
        everything = scanner.scan(table, window=(base, base + PAGE))
        writable = scanner.scan(table, window=(base, base + PAGE), writable_only=True)
    finally:
        mapped.close()
    assert everything.hits == [[base + 100]]
    assert writable.hits == [[]]


def _mapping_address(mapped: mmap.mmap) -> int:
    """The address of a read-only mapping (ctypes from_buffer needs a writable one)."""
    pythonapi = ctypes.pythonapi

    class Py_buffer(ctypes.Structure):
        _fields_ = [("buf", ctypes.c_void_p), ("obj", ctypes.c_void_p), ("len", ctypes.c_ssize_t),
                    ("itemsize", ctypes.c_ssize_t), ("readonly", ctypes.c_int), ("ndim", ctypes.c_int),
                    ("format", ctypes.c_char_p), ("shape", ctypes.c_void_p), ("strides", ctypes.c_void_p),
                    ("suboffsets", ctypes.c_void_p), ("internal", ctypes.c_void_p)]

    pythonapi.PyObject_GetBuffer.argtypes = [ctypes.py_object, ctypes.POINTER(Py_buffer), ctypes.c_int]
    pythonapi.PyBuffer_Release.argtypes = [ctypes.POINTER(Py_buffer)]
    view = Py_buffer()
    assert pythonapi.PyObject_GetBuffer(mapped, ctypes.byref(view), 0) == 0
    try:
        return int(view.buf)
    finally:
        pythonapi.PyBuffer_Release(ctypes.byref(view))


def test_after_a_pass_nothing_of_the_needles_is_left_in_the_scanner(scanner):
    with random_key() as key:
        plant = bytearray(PAGE)
        plant[0:32] = key.view()
        table = memscan.NeedleTable(capacity=1, size=64)
        table.add(key)
        first16 = bytes(key.view()[:16])
    scanner.scan(table, window=window(address_of(plant), 2))
    assert first16 not in bytes(scanner._prefix_view)
    assert not any(scanner._prefix_view) and not any(scanner._scratch)
    wipe_bytes(first16)


def test_a_result_reports_its_statistics(scanner):
    table = memscan.NeedleTable(capacity=1, size=64)
    table.add(os.urandom(32))
    plant = bytearray(PAGE)
    result = scanner.scan(table, window=window(address_of(plant), 2))
    stats = result.stats()
    assert set(stats) == {"regions", "bytes_scanned", "bytes_unreadable", "seconds", "truncated",
                          "allocation_free", "whole_address_space", "writable_only"}
    assert stats["whole_address_space"] is False and stats["allocation_free"] is True


def test_a_pass_needs_something_to_look_for_and_a_sane_window(scanner):
    with pytest.raises(ValueError):
        scanner.scan(memscan.NeedleTable(capacity=1, size=64))
    table = memscan.NeedleTable(capacity=1, size=64)
    table.add(os.urandom(16))
    with pytest.raises(ValueError):
        scanner.scan(table, window=(10, 10))
    with pytest.raises(ValueError):
        scanner.scan(table, exclude=[(0, 1)] * 33)


def test_a_closed_scanner_refuses_to_scan():
    closed = memscan.open_scanner()
    closed.close()
    closed.close()
    table = memscan.NeedleTable(capacity=1, size=64)
    table.add(os.urandom(16))
    with pytest.raises(ValueError, match="closed"):
        closed.scan(table)


def test_a_scanner_that_fails_its_own_check_is_never_handed_out(monkeypatch):
    def broken(scanner):
        raise RuntimeError("the memory scanner failed its own check: []")

    monkeypatch.setattr(memscan, "_self_check", broken)
    with pytest.raises(RuntimeError, match="own check"):
        memscan.open_scanner()


def test_describe_address_names_the_region():
    plant = bytearray(PAGE)
    text = memscan.describe_address(address_of(plant))
    assert text.startswith(hex(address_of(plant))) and "r" in text
    assert memscan.describe_address(8) in ("0x8 unmapped",)


def test_a_table_holds_exactly_its_capacity():
    table = memscan.NeedleTable(capacity=64)
    for _ in range(64):
        with random_key() as key:
            table.add(key)
    assert len(table) == 64
    with random_key() as key, pytest.raises(ValueError, match="full"):
        table.add(key)


# -- the Linux engine, driven by ordinary files --------------------------------------


def test_the_linux_engine_on_a_fake_proc(tmp_path):
    secret = os.urandom(32)
    maps = tmp_path / "maps"
    mem = tmp_path / "mem"
    maps.write_text(
        "00100000-00104000 rw-p 00000000 00:00 0 \n"
        "00104000-00108000 rw-p 00000000 00:00 0                          [heap]\n"
        "00200000-00204000 r--p 00000000 fd:01 4242 /usr/lib/libdemo.so\n"
        "00300000-00304000 ---p 00000000 00:00 0 \n"
        "00400000-00404000 r--p 00000000 00:00 0                          [vvar]\n"
        "7ffd1c2e5000-7ffd1c306000 rw-p 00000000 00:00 0                  [stack]\n"
        "ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0          [vsyscall]\n"
    )
    with open(mem, "wb") as handle:
        for address in (0x100010, 0x103FF0, 0x200020, 0x300030, 0x400040):
            handle.seek(address)
            handle.write(secret)
        handle.truncate(0x500000)
    engine = memscan._LinuxScanner(PAGE, 4, maps_path=str(maps), mem_path=str(mem))
    try:
        count = engine._parse_maps(engine._load_maps())
        table = [(engine._reg_lo[i], engine._reg_hi[i], engine._reg_ok[i]) for i in range(count)]
        assert table == [
            (0x100000, 0x104000, 3),
            (0x104000, 0x108000, 3),
            (0x200000, 0x204000, 1),
            (0x300000, 0x304000, 2),
            (0x400000, 0x404000, 2),
            (0x7FFD1C2E5000, 0x7FFD1C306000, 3),
            (0, 0, 2),
        ]
        needles = memscan.NeedleTable(capacity=1, size=64)
        needles.add(secret)
        everything = engine.scan(needles)
        writable = engine.scan(needles, writable_only=True)
    finally:
        engine.close()
    assert everything.hits == [[0x100010, 0x103FF0, 0x200020]]
    assert writable.hits == [[0x100010, 0x103FF0]]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_on_linux_the_own_mem_file_or_process_vm_readv_is_used():
    opened = memscan.open_scanner()
    try:
        assert isinstance(opened, memscan._LinuxScanner)
        assert opened.used_mem_file or memscan._PROCESS_VM_READV is not None
    finally:
        opened.close()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
def test_on_macos_the_scanner_uses_the_mach_calls(scanner):
    assert isinstance(scanner, memscan._DarwinScanner)
    assert memscan._SUBMAP_INFO_COUNT == 19  # VM_REGION_SUBMAP_INFO_COUNT_64 of <mach/vm_region.h>


def test_the_region_info_structure_has_the_packed_layout_of_the_c_header():
    """``#pragma pack(4)``, named explicitly as Python 3.14 asks: the same offsets on every version."""
    info = memscan._SubmapInfo
    assert ctypes.sizeof(info) == 76 and memscan._SUBMAP_INFO_COUNT == 19
    offsets = [getattr(info, field[0]).offset for field in info._fields_]
    assert offsets == [0, 4, 8, 12, 20, 24, 28, 32, 36, 40, 44, 46, 47, 48, 52, 56, 60, 64, 68]


def test_importing_the_scanner_raises_no_deprecation_warning():
    """Python 3.14 deprecates a ``_pack_`` without a ``_layout_``, and 3.19 makes it an error."""
    package_parent = os.path.dirname(os.path.dirname(os.path.abspath(memscan.__file__)))
    code = "import sys; sys.path.insert(0, sys.argv[1]); import irondome.memscan"
    result = subprocess.run([sys.executable, "-I", "-B", "-W", "error::DeprecationWarning", "-c", code, package_parent],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
