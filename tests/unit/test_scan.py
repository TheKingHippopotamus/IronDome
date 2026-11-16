"""irondome.scan: finding vault secrets in files, and never holding one in what it reports."""

from __future__ import annotations

import base64
import os
import re
import sys
import time
from pathlib import Path
from typing import List, Sequence, Tuple

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from irondome import scan
from irondome.agent.runner import secret_patterns
from irondome.errors import UsageError
from irondome.scan import Hit, SecretValue, scan_paths

GITHUB = SecretValue("github", "password", "ghp_Example-Token/0123+abc")
BANK = SecretValue("bank", "password", 'Bank "Pass" $42 \\ é?>~')  # every encoding differs from the others
STRIPE = SecretValue("stripe", "api_key", "sk_test_stripeSecret987")
SECRETS = [GITHUB, BANK, STRIPE]


def write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def located(hits: Sequence[Hit]) -> List[Tuple[str, int, str, str, str]]:
    return [(Path(hit.path).name, hit.line, hit.entry, hit.field, hit.encoding) for hit in hits]


def forms_of(value: str) -> List[bytes]:
    return [pattern for _, pattern in secret_patterns(value)]


# ---------------------------------------------------------------------------
# What is found
# ---------------------------------------------------------------------------


def test_a_planted_secret_is_found_in_plain_base64_and_hex_with_its_line(tmp_path: Path) -> None:
    value = GITHUB.value.encode()
    write(tmp_path / "tree" / "transcript.jsonl", b'{"a": 1}\n{"tool": "env", "out": "TOKEN=' + value + b'"}\n')
    write(tmp_path / "tree" / "deep" / "er" / "log.txt", b"one\ntwo\nAuthorization: " + base64.b64encode(value) + b"\n")
    write(tmp_path / "tree" / "dump.hex", b"\n" * 6 + value.hex().encode() + b"\n")
    write(tmp_path / "tree" / "clean.md", b"nothing to see\n" * 100)

    result = scan_paths([tmp_path / "tree"], SECRETS)

    assert sorted(located(result.hits)) == [
        ("dump.hex", 7, "github", "password", "hex"),
        ("log.txt", 3, "github", "password", "base64"),
        ("transcript.jsonl", 2, "github", "password", "plain"),
    ]
    assert result.files_scanned == 4
    assert result.files_skipped == 0
    assert result.bytes_scanned == sum(path.stat().st_size for path in (tmp_path / "tree").rglob("*") if path.is_file())


def test_every_encoding_the_masker_knows_is_found(tmp_path: Path) -> None:
    """The scanner looks for exactly what `irondome run` masks, and labels each the same way."""
    forms = secret_patterns(BANK.value)
    assert {label for label, _ in forms} == {
        "plain", "base64", "base64url", "hex", "percent", "html", "json", "shell", "repr"
    }
    write(tmp_path / "leaks.txt", b"".join(b"<" + pattern + b">\n" for _, pattern in forms))

    hits = scan_paths([tmp_path], [BANK]).hits

    for line, (label, _) in enumerate(forms, start=1):
        assert ("bank", "password", label) in {(hit.entry, hit.field, hit.encoding) for hit in hits if hit.line == line}
    assert {hit.line for hit in hits} == set(range(1, len(forms) + 1))


def test_a_secret_inside_longer_base64_is_found(tmp_path: Path) -> None:
    """HTTP Basic credentials: the password is only part of what was encoded."""
    for lead in (b"u:", b"us:", b"use:"):
        write(tmp_path / f"basic-{len(lead)}.txt", b"Basic " + base64.b64encode(lead + STRIPE.value.encode()) + b"\n")

    hits = scan_paths([tmp_path], [STRIPE]).hits

    assert sorted((Path(hit.path).name, hit.encoding) for hit in hits) == [
        ("basic-2.txt", "base64"),
        ("basic-3.txt", "base64"),
        ("basic-4.txt", "base64"),
    ]


def test_each_line_is_reported_once_for_each_secret_and_encoding(tmp_path: Path) -> None:
    value = GITHUB.value.encode()
    write(tmp_path / "f.txt", value + b" " + value + b" " + value + b"\nnothing\n" + value + b"\n")

    hits = scan_paths([tmp_path], [GITHUB]).hits

    assert located(hits) == [("f.txt", 1, "github", "password", "plain"), ("f.txt", 3, "github", "password", "plain")]


def test_a_value_shared_by_two_entries_is_reported_for_both(tmp_path: Path) -> None:
    write(tmp_path / "f.txt", b"reused: Same-Password-Everywhere\n")
    reused = "Same-Password-Everywhere"
    shared = [SecretValue("mail", "password", reused), SecretValue("shop", "pin", reused)]

    hits = scan_paths([tmp_path], shared).hits

    assert located(hits) == [("f.txt", 1, "mail", "password", "plain"), ("f.txt", 1, "shop", "pin", "plain")]


def test_a_secret_and_a_longer_one_that_starts_with_it_are_both_found(tmp_path: Path) -> None:
    write(tmp_path / "f.txt", b"x Prefix-Secret-Plus-More x\n")
    nested = [
        SecretValue("short", "password", "Prefix-Secret"),
        SecretValue("long", "password", "Prefix-Secret-Plus-More"),
    ]

    assert sorted(located(scan_paths([tmp_path], nested).hits)) == [
        ("f.txt", 1, "long", "password", "plain"),
        ("f.txt", 1, "short", "password", "plain"),
    ]


def test_values_shorter_than_eight_characters_are_not_looked_for(tmp_path: Path) -> None:
    write(tmp_path / "f.txt", b"1234567 and 12345678\n")

    hits = scan_paths([tmp_path], [SecretValue("a", "pin", "1234567"), SecretValue("b", "pin", "12345678")]).hits

    assert scan.MIN_SECRET_CHARS == 8
    assert located(hits) == [("f.txt", 1, "b", "pin", "plain")]


def test_binary_files_are_searched_too(tmp_path: Path) -> None:
    blob = os.urandom(5000) + b"\x00" + STRIPE.value.encode() + b"\x00" + os.urandom(5000)
    write(tmp_path / "cache.sqlite", blob)

    hits = scan_paths([tmp_path], [STRIPE]).hits

    assert [(hit.entry, hit.encoding) for hit in hits] == [("stripe", "plain")]
    assert hits[0].line == blob[: blob.index(STRIPE.value.encode())].count(b"\n") + 1


def test_a_value_that_is_not_valid_text_is_left_out(tmp_path: Path) -> None:
    write(tmp_path / "f.txt", GITHUB.value.encode() + b"\n")

    hits = scan_paths([tmp_path], [SecretValue("odd", "password", "lone \ud800 surrogate"), GITHUB]).hits

    assert located(hits) == [("f.txt", 1, "github", "password", "plain")]


# ---------------------------------------------------------------------------
# Never the value
# ---------------------------------------------------------------------------


def test_nothing_returned_holds_the_value_or_any_encoding_of_it(tmp_path: Path) -> None:
    lines = b"".join(b"x" + pattern + b"\n" for pattern in forms_of(GITHUB.value))
    write(tmp_path / "f.txt", lines)

    result = scan_paths([tmp_path], [GITHUB])
    shown = repr(result) + repr(result.hits) + "".join(str(vars(hit)) for hit in result.hits) + repr(GITHUB)

    assert result.hits
    for pattern in forms_of(GITHUB.value):
        assert pattern.decode("utf-8") not in shown
    assert "value" not in repr(GITHUB)


# ---------------------------------------------------------------------------
# Reading in chunks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("chunk", [1, 45, 46, 47, 50, 64, 99, 128, 4096])
def test_an_occurrence_across_a_chunk_boundary_is_found_exactly_once(tmp_path: Path, chunk: int) -> None:
    """A chunk is never shorter than the longest pattern less one (46 bytes here: the hex form)."""
    value = STRIPE.value.encode()
    assert max(len(pattern) for pattern in forms_of(STRIPE.value)) == 46
    data = bytearray()
    expected = []
    for line in range(1, 41):
        if line % 7 == 3:
            data += b"z" * (line % 5) + value + b"z" * (line % 3)
            expected.append(line)
        else:
            data += b"filler " * (line % 4)
        data += b"\n"
    write(tmp_path / "f.txt", bytes(data))

    hits = scan_paths([tmp_path], [STRIPE], chunk_bytes=chunk).hits

    assert [hit.line for hit in hits] == expected
    assert {hit.encoding for hit in hits} == {"plain"}


def test_a_huge_single_line_never_has_to_fit_in_memory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    value = GITHUB.value.encode()
    size = 3 * 1024 * 1024
    write(tmp_path / "one-line.json", b"a" * (size - 40) + value + b"a" * (40 - len(value)))
    chunk = 64 * 1024
    searched: List[int] = []
    real_find = scan._Needles.find

    def spying(self: scan._Needles, data: bytes, fresh: int) -> List[Tuple[int, bytes]]:
        searched.append(len(data))
        return real_find(self, data, fresh)

    monkeypatch.setattr(scan._Needles, "find", spying)

    hits = scan_paths([tmp_path], [GITHUB], chunk_bytes=chunk).hits

    assert located(hits) == [("one-line.json", 1, "github", "password", "plain")]
    assert len(searched) >= size // chunk
    longest = max(len(pattern) for pattern in forms_of(GITHUB.value))
    assert max(searched) <= chunk + longest - 1


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    filler=st.lists(st.binary(max_size=40).map(lambda raw: raw.replace(b"\n", b".")), min_size=1, max_size=30),
    where=st.data(),
    chunk=st.integers(min_value=1, max_value=80),
)
def test_the_line_of_a_secret_is_right_wherever_it_is_and_however_the_file_is_cut(
    tmp_path: Path, filler: List[bytes], where: st.DataObject, chunk: int
) -> None:
    line = where.draw(st.integers(min_value=0, max_value=len(filler) - 1))
    column = where.draw(st.integers(min_value=0, max_value=len(filler[line])))
    lines = list(filler)
    lines[line] = lines[line][:column] + STRIPE.value.encode() + lines[line][column:]
    write(tmp_path / "random.bin", b"\n".join(lines))

    hits = scan_paths([tmp_path / "random.bin"], [STRIPE], chunk_bytes=chunk).hits

    assert [(hit.line, hit.encoding) for hit in hits if hit.encoding == "plain"] == [(line + 1, "plain")]


# ---------------------------------------------------------------------------
# What is skipped
# ---------------------------------------------------------------------------


def test_links_inside_a_tree_are_not_followed_and_are_counted(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    write(outside / "secret.txt", STRIPE.value.encode() + b"\n")
    tree = tmp_path / "tree"
    write(tree / "plain.txt", b"clean\n")
    os.symlink(outside / "secret.txt", tree / "file-link")
    os.symlink(outside, tree / "dir-link")
    os.symlink(tmp_path / "nowhere", tree / "dangling")

    result = scan_paths([tree], [STRIPE])

    assert result.hits == []
    assert result.files_scanned == 1
    assert result.skipped == {scan.SKIP_SYMLINK: 3}
    assert result.files_skipped == 3


def test_a_link_named_directly_is_followed(tmp_path: Path) -> None:
    """As grep -r does, so that ~/.claude may itself be a link."""
    real = tmp_path / "real"
    write(real / "session.jsonl", b"x\n" + STRIPE.value.encode() + b"\n")
    os.symlink(real, tmp_path / "claude-link")
    os.symlink(real / "session.jsonl", tmp_path / "file-link")

    by_directory = scan_paths([tmp_path / "claude-link"], [STRIPE])
    by_file = scan_paths([tmp_path / "file-link"], [STRIPE])

    assert located(by_directory.hits) == [("session.jsonl", 2, "stripe", "api_key", "plain")]
    assert located(by_file.hits) == [("file-link", 2, "stripe", "api_key", "plain")]


def test_a_dangling_link_named_directly_is_counted_not_raised(tmp_path: Path) -> None:
    os.symlink(tmp_path / "gone", tmp_path / "link")

    result = scan_paths([tmp_path / "link"], [STRIPE])

    assert result.skipped == {scan.SKIP_SYMLINK: 1}
    assert result.files_scanned == 0


def test_files_over_the_size_limit_are_skipped_without_being_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = STRIPE.value.encode()
    write(tmp_path / "small" / "fits.txt", value.ljust(100, b"."))
    write(tmp_path / "small" / "over.txt", value.ljust(101, b"."))
    with open(tmp_path / "sparse.log", "wb") as handle:
        handle.truncate(scan.MAX_FILE_BYTES + 1)  # a 50 MB file that takes no space on disk
    opened: List[str] = []
    real_search = scan._Scanner._search

    def spying(self: scan._Scanner, fd: int, path: str) -> None:
        opened.append(Path(path).name)
        real_search(self, fd, path)

    monkeypatch.setattr(scan._Scanner, "_search", spying)

    small = scan_paths([tmp_path / "small"], [STRIPE], max_file_bytes=100)
    sparse = scan_paths([tmp_path / "sparse.log"], [STRIPE])

    assert located(small.hits) == [("fits.txt", 1, "stripe", "api_key", "plain")]
    assert small.skipped == {scan.SKIP_TOO_LARGE: 1}
    assert sparse.skipped == {scan.SKIP_TOO_LARGE: 1} and sparse.files_scanned == 0
    assert opened == ["fits.txt"]


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0, reason="needs POSIX permissions and not root")
def test_unreadable_files_and_directories_are_skipped_and_counted(tmp_path: Path) -> None:
    locked_file = write(tmp_path / "tree" / "locked.txt", STRIPE.value.encode())
    locked_dir = tmp_path / "tree" / "private"
    write(locked_dir / "inside.txt", STRIPE.value.encode())
    write(tmp_path / "tree" / "open.txt", STRIPE.value.encode())
    locked_file.chmod(0)
    locked_dir.chmod(0)
    try:
        result = scan_paths([tmp_path / "tree"], [STRIPE])
    finally:
        locked_dir.chmod(0o700)
        locked_file.chmod(0o600)

    assert located(result.hits) == [("open.txt", 1, "stripe", "api_key", "plain")]
    assert result.skipped == {scan.SKIP_UNREADABLE: 2}


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
def test_a_fifo_is_never_opened_so_nothing_waits_on_it(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "pipe")
    write(tmp_path / "f.txt", STRIPE.value.encode())

    started = time.monotonic()
    in_tree = scan_paths([tmp_path], [STRIPE])
    named = scan_paths([tmp_path / "pipe"], [STRIPE])

    assert time.monotonic() - started < 10
    assert in_tree.skipped == {scan.SKIP_SPECIAL: 1} and in_tree.files_scanned == 1
    assert named.skipped == {scan.SKIP_SPECIAL: 1}


@pytest.mark.skipif(not os.path.exists("/dev/null"), reason="needs /dev/null")
def test_a_device_named_directly_is_skipped() -> None:
    assert scan_paths(["/dev/null"], [STRIPE]).skipped == {scan.SKIP_SPECIAL: 1}


def test_a_file_reached_through_two_paths_is_read_once(tmp_path: Path) -> None:
    original = write(tmp_path / "tree" / "a.txt", STRIPE.value.encode() + b"\n")
    os.link(original, tmp_path / "tree" / "b-hardlink.txt")

    result = scan_paths([tmp_path / "tree", tmp_path / "tree", original], [STRIPE])

    assert located(result.hits) == [("a.txt", 1, "stripe", "api_key", "plain")]
    assert result.files_scanned == 1


def test_nothing_to_look_for_opens_no_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tmp_path / "f.txt", b"abc\n")
    monkeypatch.setattr(scan._Scanner, "_file", lambda *args, **kwargs: pytest.fail("a file was opened"))

    result = scan_paths([tmp_path], [SecretValue("tiny", "pin", "1234")])

    assert (result.hits, result.files_scanned, result.files_skipped) == ([], 0, 0)


# ---------------------------------------------------------------------------
# Arguments, order and names
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "paths, secrets, message",
    [
        ([], SECRETS, "at least one"),
        ("one/path", SECRETS, "at least one"),
        (["/no/such/path/anywhere"], SECRETS, "does not exist"),
        (["bad\x00path"], SECRETS, "NUL"),
        ([42], SECRETS, "must be text"),
        (["."], ["not a SecretValue"], "SecretValue"),
        (["."], [SecretValue("a", "b", 12345678)], "must be text"),  # type: ignore[arg-type]
    ],
)
def test_bad_arguments_are_usage_errors(paths: object, secrets: object, message: str) -> None:
    with pytest.raises(UsageError, match=message):
        scan_paths(paths, secrets)  # type: ignore[arg-type]


@pytest.mark.parametrize("option", ["max_file_bytes", "chunk_bytes"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_sizes_must_be_positive_whole_numbers(tmp_path: Path, option: str, value: object) -> None:
    with pytest.raises(UsageError, match="positive whole number"):
        scan_paths([tmp_path], SECRETS, **{option: value})  # type: ignore[arg-type]


def test_check_paths_returns_text_and_refuses_what_does_not_exist(tmp_path: Path) -> None:
    write(tmp_path / "f.txt", b"")

    assert scan.check_paths([tmp_path / "f.txt", str(tmp_path)]) == [str(tmp_path / "f.txt"), str(tmp_path)]
    with pytest.raises(UsageError, match=re.escape(str(tmp_path / "missing"))):
        scan.check_paths([tmp_path / "f.txt", tmp_path / "missing"])


def test_results_come_in_a_stable_order(tmp_path: Path) -> None:
    for name in ("b", "a", "c"):
        write(tmp_path / name / "z.txt", b"\n" + STRIPE.value.encode() + b"\n" + GITHUB.value.encode() + b"\n")
        write(tmp_path / name / "y.txt", GITHUB.value.encode() + b"\n")

    first = scan_paths([tmp_path], SECRETS).hits
    second = scan_paths([tmp_path], SECRETS).hits

    assert first == second
    assert [(Path(hit.path).parent.name, Path(hit.path).name, hit.line) for hit in first] == [
        (parent, name, line) for parent in "abc" for name, line in (("y.txt", 1), ("z.txt", 2), ("z.txt", 3))
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file names")
def test_hostile_file_names_are_reported_safely(tmp_path: Path) -> None:
    write(tmp_path / "line\nbreak\x1b[31m.txt", STRIPE.value.encode())

    hit = scan_paths([tmp_path], [STRIPE]).hits[0]

    shown = scan.display_path(hit.path)
    assert "\n" not in shown and "\x1b" not in shown
    assert "\\n" in shown and "\\x1b" in shown
    assert scan.path_text(hit.path) == hit.path


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file names")
def test_a_file_name_that_is_not_utf8_can_still_be_printed(tmp_path: Path) -> None:
    raw = os.fsencode(str(tmp_path)) + b"/caf\xe9.txt"
    try:
        with open(raw, "wb") as handle:
            handle.write(STRIPE.value.encode())
    except OSError:
        pytest.skip("this filesystem only accepts UTF-8 file names")

    hit = scan_paths([tmp_path], [STRIPE]).hits[0]

    assert scan.path_text(hit.path).endswith("caf\\xe9.txt")
    scan.path_text(hit.path).encode("utf-8")
    scan.display_path(hit.path).encode("utf-8")


# ---------------------------------------------------------------------------
# The matcher
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(
    words=st.sets(st.binary(min_size=1, max_size=10), min_size=1, max_size=40),
    probes=st.lists(st.binary(max_size=10), max_size=20),
)
def test_the_trie_expression_matches_exactly_its_words(words: set, probes: List[bytes]) -> None:
    expression = re.compile(scan._trie_expression(sorted(words)))

    for word in words:
        assert expression.fullmatch(word)
    for probe in probes:
        assert bool(expression.fullmatch(probe)) == (probe in words)


def test_hundreds_of_secrets_over_megabytes_take_seconds_not_minutes(tmp_path: Path) -> None:
    secrets = [SecretValue(f"entry-{n}", "password", f"Pw-{n:04d}-{os.urandom(8).hex()}") for n in range(300)]
    text = b'{"type":"assistant","text":"Let me run the tests now and look at the output."}\n' * 30000
    noise = os.urandom(1 << 20).hex().encode()
    write(tmp_path / "transcript.jsonl", text + secrets[123].value.encode() + b"\n" + noise)

    started = time.monotonic()
    hits = scan_paths([tmp_path], secrets).hits

    assert time.monotonic() - started < 60
    assert [(hit.entry, hit.line) for hit in hits] == [("entry-123", 30001)]
