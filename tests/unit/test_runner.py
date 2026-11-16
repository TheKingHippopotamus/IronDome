"""Masking and the process runner (irondome.agent.runner).

Timing assertions here use processor time or very wide wall-clock bounds:
the suite has to pass on a loaded machine without becoming meaningless.
"""

from __future__ import annotations

import base64
import html
import json
import os
import pickle
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import textwrap
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from irondome.agent import refs, runner
from irondome.agent.runner import (
    MIN_ENCODED_BYTES,
    MIN_MASK_BYTES,
    CommandCancelledError,
    CommandNotExecutableError,
    CommandNotFoundError,
    CommandTimeoutError,
    Masker,
    RunResult,
    run_captured,
    run_command,
    secret_patterns,
)
from irondome.errors import IronDomeError, UsageError

SECRET = "hunter2-Github!"
MARK = b"[irondome:TOKEN]"
#: Upper bound, in seconds, for anything that waits on a child process.
PATIENCE = 120.0

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX signals and process groups")


def python(code: str, *arguments: str) -> List[str]:
    """A child that runs *code* in a bare interpreter (no site packages, no user environment)."""
    return [sys.executable, "-I", "-S", "-c", textwrap.dedent(code), *arguments]


# ---------------------------------------------------------------------------
# An independent statement of what masking means
# ---------------------------------------------------------------------------


def marks_for(secrets: Dict[str, str], placeholder: str = "[irondome:{name}]") -> Dict[bytes, bytes]:
    """pattern -> placeholder, by the documented rule: exact values first, then names in sorted order."""
    marked = []
    for name in sorted(secrets):
        forms = secret_patterns(secrets[name])
        if forms:
            marked.append((placeholder.format(name=name).encode("utf-8"), [pattern for _, pattern in forms]))
    marks: Dict[bytes, bytes] = {}
    for mark, patterns in marked:
        marks.setdefault(patterns[0], mark)
    for mark, patterns in marked:
        for pattern in patterns[1:]:
            marks.setdefault(pattern, mark)
    return marks


def reference_mask(data: bytes, marks: Dict[bytes, bytes]) -> bytes:
    """Brute force, one byte at a time, no streaming: the definition the Masker must agree with."""

    def longest(position: int) -> Optional[bytes]:
        best: Optional[bytes] = None
        for pattern in marks:
            if data.startswith(pattern, position) and (best is None or len(pattern) > len(best)):
                best = pattern
        return best

    out = bytearray()
    position = 0
    while position < len(data):
        match = longest(position)
        if match is None:
            out.append(data[position])
            position += 1
            continue
        out += marks[match]
        end = position + len(match)
        inside = position + 1
        while inside < end:  # a match that starts inside the region stretches it
            other = longest(inside)
            if other is not None and inside + len(other) > end:
                end = inside + len(other)
            inside += 1
        position = end
    return bytes(out)


def uncovered(data: bytes, patterns: List[bytes]) -> bytes:
    """*data* without every byte that belongs to an occurrence of any pattern."""
    covered = bytearray(len(data))
    for pattern in patterns:
        at = data.find(pattern)
        while at != -1:
            covered[at : at + len(pattern)] = b"\x01" * len(pattern)
            at = data.find(pattern, at + 1)
    return bytes(byte for byte, hit in zip(data, covered) if not hit)


def feed_in_chunks(masker: Masker, data: bytes, sizes: List[int]) -> bytes:
    out = bytearray()
    position = 0
    index = 0
    while position < len(data):
        size = sizes[index % len(sizes)] if sizes else len(data)
        out += masker.feed(data[position : position + size])
        position += size
        index += 1
    out += masker.flush()
    return bytes(out)


def mask_whole(secrets: Dict[str, str], data: bytes, **options: str) -> bytes:
    masker = Masker(secrets, **options)
    return masker.feed(data) + masker.flush()


@st.composite
def streams(draw: st.DrawFn, secrets: Dict[str, str], noise: st.SearchStrategy[bytes]) -> bytes:
    """Output that is thick with the secrets: whole patterns, cut patterns, and noise between them."""
    pool = [pattern for value in secrets.values() for _, pattern in secret_patterns(value)]
    pool += [value.encode("utf-8") for value in secrets.values()]
    parts = []
    for _ in range(draw(st.integers(0, 12))):
        kind = draw(st.integers(0, 9))
        if kind < 5 and pool:
            piece = draw(st.sampled_from(pool))
            if kind == 3:
                piece = piece[: draw(st.integers(0, len(piece)))]
            elif kind == 4:
                piece = piece[draw(st.integers(0, len(piece))) :]
            parts.append(piece)
        else:
            parts.append(draw(noise))
    return b"".join(parts)


chunk_sizes = st.lists(st.integers(1, 40), min_size=1, max_size=8)
any_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=24)


# ---------------------------------------------------------------------------
# secret_patterns
# ---------------------------------------------------------------------------


def test_short_values_have_no_patterns_and_medium_ones_only_themselves() -> None:
    assert MIN_MASK_BYTES == 4 and MIN_ENCODED_BYTES == 8
    assert secret_patterns("") == []
    assert secret_patterns("abc") == []
    assert secret_patterns("é") == []  # two bytes
    assert secret_patterns("éé") == [("plain", "éé".encode())]  # four bytes
    assert secret_patterns("abcd") == [("plain", b"abcd")]
    assert secret_patterns("abcdefg") == [("plain", b"abcdefg")]
    assert {label for label, _ in secret_patterns("abcdefgh")} >= {"plain", "base64", "hex"}


@pytest.mark.parametrize(
    "value",
    [
        SECRET,
        "correct horse battery staple",
        "p@ss w0rd/with+every&kind=of?char!*'()~",
        'quote" back\\slash and\nnewline\ttab',
        "ünïcödé-секрет-秘密-🔑",
        "sk-live-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n",
        "12345678",
        "\x7f\x01control\x1f",
    ],
)
def test_patterns_are_what_standard_encoders_produce(value: str) -> None:
    raw = value.encode("utf-8")
    forms = secret_patterns(value)
    patterns = [pattern for _, pattern in forms]
    assert forms[0] == ("plain", raw)
    assert len(set(patterns)) == len(patterns), "duplicates must be dropped"
    assert all(len(pattern) >= MIN_MASK_BYTES for pattern in patterns)
    expected = {
        "base64": [base64.b64encode(raw), base64.b64encode(raw).rstrip(b"=")],
        "base64url": [base64.urlsafe_b64encode(raw), base64.urlsafe_b64encode(raw).rstrip(b"=")],
        "hex": [raw.hex().encode(), raw.hex().upper().encode()],
        "percent": [
            urllib.parse.quote(value, safe="").encode(),
            urllib.parse.quote_plus(value, safe="").encode(),
            urllib.parse.quote(value, safe="!*'()").encode(),  # JavaScript's encodeURIComponent
            urllib.parse.quote(value).encode(),  # Python's default leaves "/" alone
            urllib.parse.quote(value, safe="!*'();/?:@&=+$,#").encode(),  # JavaScript's encodeURI
            lower_escapes(urllib.parse.quote(value, safe="")),
            lower_escapes(urllib.parse.quote(value)),
            lower_escapes(urllib.parse.quote_plus(value, safe="")),
        ],
        "html": [
            html.escape(value).encode("utf-8"),
            html.escape(value, quote=False).encode("utf-8"),
            html.escape(value).replace("&#x27;", "&#39;").encode("utf-8"),
        ],
        "json": [
            json.dumps(value)[1:-1].encode(),
            json.dumps(value, ensure_ascii=False)[1:-1].encode("utf-8"),
            json.dumps(json.dumps(value))[1:-1].encode()[2:-2],  # inside a JSON document carried as a string
        ],
        # shlex.quote puts single quotes around anything that needs them and nothing around the rest.
        "shell": [shlex.quote(value).encode() if shlex.quote(value) == value else shlex.quote(value)[1:-1].encode()],
    }
    for label, encodings in expected.items():
        for encoded in encodings:
            assert encoded in patterns, (label, encoded)
    assert {label for label, _ in forms} <= {
        "plain", "base64", "base64url", "hex", "percent", "html", "json", "shell", "repr", "line", "doubled"
    }
    lines = [line.strip() for line in raw.splitlines()]
    for line in lines if len(lines) > 1 else []:
        assert (line in patterns) == (runner._is_secret_line(line) or line == raw), line


def lower_escapes(encoded: str) -> bytes:
    """A percent-encoded text with the hex digits of its escapes in lower case, as some encoders write them."""
    return re.sub(r"%[0-9A-F]{2}", lambda escape: escape.group(0).lower(), encoded).encode()


@pytest.mark.parametrize(
    ("printed", "how"),
    [
        (lambda value: urllib.parse.quote(value, safe="!*'();/?:@&=+$,#"), "JavaScript's encodeURI"),
        (lambda value: urllib.parse.quote(value), "Python's quote as called without arguments"),
        (lambda value: lower_escapes(urllib.parse.quote(value, safe="")).decode(), "lower-case escapes"),
        (lambda value: html.escape(value), "an HTML page"),
        (lambda value: html.escape(value).replace("&quot;", "&#34;").replace("&#x27;", "&#39;"), "Go and Jinja"),
        (lambda value: html.escape(value).replace("&#x27;", "&#039;"), "PHP's HTML"),
        (lambda value: html.escape(value, quote=False).replace('"', "&quot;"), "HTML, the double quote only"),
        (lambda value: html.escape(value).replace("&#x27;", "&apos;"), "XML"),
        (lambda value: urllib.parse.quote_plus(value, safe="*").replace("~", "%7E"), "a form as browsers send it"),
        (lambda value: lower_escapes(urllib.parse.quote(value, safe="!*'()")).decode(), "encodeURIComponent, lower"),
        (lambda value: lower_escapes(urllib.parse.quote(value, safe="!*'();/?:@&=+$,#")).decode(), "encodeURI, lower"),
        (lambda value: json.dumps({"body": json.dumps({"password": value})}), "JSON inside JSON"),
        (lambda value: "".join(f"12:00:01 app | {line}\n" for line in value.splitlines()), "a logger's prefix"),
    ],
)
def test_the_encodings_a_trial_by_hand_got_past_the_mask_are_masked(printed, how: str) -> None:
    """Each of these printed a generated password, or a private key, in full before release.

    The claim said "percent-encoded forms" and the list held three of them; a
    person using ``irondome run`` with ordinary tools found the rest. The
    values are the kinds the trial used: one with the symbols a generated
    password has, and one of several lines.
    """
    for value in (
        "%bnLe1sj#ttArjwbT%G3/x&<'\">~*",
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"
        "VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDu\n-----END PRIVATE KEY-----",
    ):
        if how == "a logger's prefix" and "\n" not in value:
            continue
        masker = Masker({"TOKEN": value})
        text = printed(value)
        shown = (masker.feed(f"before {text} after".encode()) + masker.flush()).decode()
        assert "[irondome:TOKEN]" in shown, how
        for piece in ("bnLe1sj", "ttArjwbT", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7", "VJTUt9Us8cKj"):
            assert piece not in shown, (how, piece)


@pytest.mark.parametrize(
    ("value", "quoted"),
    [
        ("pa$$w0rd-with-dollars", 'pa\\$\\$w0rd-with-dollars'),  # bash: declare -p, export -p
        ('say "hi" to `them`', 'say \\"hi\\" to \\`them\\`'),
        ("back\\slash-and-$", "back\\\\slash-and-\\$"),
        ("it's-a-secret", "it'\\''s-a-secret"),  # bash and zsh: set, set -x, typeset -p
        ("it's-a-secret", "it'\"'\"'s-a-secret"),  # dash, shlex.quote
        ("it's a \"quoted\" one", "it\\'s a \"quoted\" one"),  # repr with both kinds of quote
        ("C:\\Users\\king\\key", "C:\\\\Users\\\\king\\\\key"),  # repr
        ("line one\nline two\ttab", "line one\\nline two\\ttab"),
    ],
)
def test_quoted_and_escaped_forms(value: str, quoted: str) -> None:
    assert quoted.encode() in [pattern for _, pattern in secret_patterns(value)]
    assert mask_whole({"TOKEN": value}, b"x=" + quoted.encode() + b";") == b"x=" + MARK + b";"


@pytest.mark.parametrize(
    "value",
    ["it's", 'say "hi" to them', "C:\\path\\to", "pa$$w0rd'q\"x\\y z!&`t", "tab\tand\nnewline", "plain-token-1234"],
)
def test_python_repr_of_a_value_is_one_of_its_patterns(value: str) -> None:
    padded = value + "-padding-to-eight-bytes"
    assert repr(padded)[1:-1].encode() in [pattern for _, pattern in secret_patterns(padded)]
    assert mask_whole({"TOKEN": padded}, repr({"TOKEN": padded}).encode()) in (
        b"{'TOKEN': '" + MARK + b"'}",
        b"{'TOKEN': \"" + MARK + b"\"}",
    )


def test_a_pattern_is_labelled_by_the_first_encoding_that_produces_it() -> None:
    forms = dict((pattern, label) for label, pattern in secret_patterns("abcdefghi"))  # nine bytes, nothing to escape
    assert forms[b"abcdefghi"] == "plain"  # also its percent-encoding and its JSON form
    assert forms[b"YWJjZGVmZ2hp"] == "base64"  # also its URL-safe form, and it needs no padding
    assert forms[b"616263646566676869"] == "hex"  # no letters: upper and lower case are the same
    assert sorted(set(forms.values())) == ["base64", "hex", "plain"]
    order = ["plain", "base64", "base64url", "hex", "percent", "html", "json", "shell", "repr", "doubled", "line"]
    labels = [label for label, _ in secret_patterns("a+b/c d\"e?fé")]
    assert labels == sorted(labels, key=order.index)
    assert set(labels) == {"plain", "base64", "base64url", "hex", "percent", "html", "json", "shell", "doubled"}
    labels = [label for label, _ in secret_patterns("a+b/c d\"e?fé $1 it's \\")]
    assert labels == sorted(labels, key=order.index)
    assert set(labels) == set(order) - {"line"}
    labels = [label for label, _ in secret_patterns("first-line-of-a-longer-value\nits-second-line-as-long-as-it")]
    assert labels == sorted(labels, key=order.index) and labels.count("line") == 2
    assert "line" not in [label for label, _ in secret_patterns("a line with spaces in it\nand another like it too")]


def test_patterns_reject_what_is_not_text() -> None:
    for value in (None, b"bytes-value", 12345678, ["list"]):
        with pytest.raises(UsageError):
            secret_patterns(value)  # type: ignore[arg-type]
    with pytest.raises(UsageError) as caught:
        secret_patterns("lone-surrogate-\ud800-value")
    assert "surrogate" not in str(caught.value)


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=7), st.text(min_size=8, max_size=40), st.binary(min_size=1, max_size=7), st.booleans())
def test_a_value_inside_longer_base64_is_masked(prefix: bytes, value: str, suffix: bytes, urlsafe: bool) -> None:
    # HTTP Basic credentials, `echo "$TOKEN" | base64`, a token inside an encoded JSON document ...
    raw = value.encode("utf-8")
    encode = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    encoded = encode(prefix + raw + suffix)
    lead = len(prefix) % 3
    group = 4 * (len(prefix) // 3)
    start = group + -(-8 * lead // 6)
    end = group + 8 * (lead + len(raw)) // 6
    core = encoded[start:end]
    assert core in [pattern for _, pattern in secret_patterns(value)]
    masked = mask_whole({"TOKEN": value}, b"Authorization: Basic " + encoded + b"\n")
    assert MARK in masked
    assert core not in masked
    # At most one character on each side of the value still depends on it.
    survivors = masked.replace(MARK, b"")
    assert len(survivors) <= len(b"Authorization: Basic \n") + len(encoded) - len(core)


def test_http_basic_credentials_and_piped_base64() -> None:
    credentials = base64.b64encode(b"king:" + SECRET.encode())
    assert mask_whole({"TOKEN": SECRET}, b"> Authorization: Basic " + credentials + b"\r\n") == (
        b"> Authorization: Basic a2luZzp" + MARK + b"E=\r\n"
    )
    piped = base64.b64encode(SECRET.encode() + b"\n")  # echo "$TOKEN" | base64
    assert mask_whole({"TOKEN": SECRET}, piped) == MARK + b"Cg=="


# ---------------------------------------------------------------------------
# Masker: construction
# ---------------------------------------------------------------------------


def test_masker_replaces_the_value_with_a_placeholder_naming_the_variable() -> None:
    masker = Masker({"TOKEN": SECRET})
    assert masker.feed(b"token is hunter2-Github! ok\n") == b"token is [irondome:TOKEN] ok\n"
    assert masker.flush() == b""
    assert masker.unmasked_names == []


def test_masker_placeholder_can_be_changed() -> None:
    assert mask_whole({"TOKEN": SECRET}, b"x hunter2-Github! y", placeholder="<concealed>") == b"x <concealed> y"
    assert mask_whole({"TOKEN": SECRET}, b"x hunter2-Github! y", placeholder="") == b"x  y"
    assert mask_whole({"TOKEN": SECRET}, b"x hunter2-Github! y", placeholder="{name}={name}") == b"x TOKEN=TOKEN y"
    assert mask_whole({"ÜBER": SECRET}, b"hunter2-Github!", placeholder="«{name}»") == "«ÜBER»".encode()


@pytest.mark.parametrize(
    "placeholder", ["{0}", "{other}", "{name.missing}", "{name[x]}", "{name!z}", "{", "}", None, 7]
)
def test_masker_rejects_a_malformed_placeholder(placeholder: object) -> None:
    with pytest.raises(UsageError):
        Masker({"TOKEN": SECRET}, placeholder=placeholder)  # type: ignore[arg-type]


def test_masker_reports_values_too_short_to_mask() -> None:
    masker = Masker({"PIN": "123", "EMPTY": "", "TOKEN": SECRET, "FOUR": "abcd", "ACCENT": "é"})
    assert masker.unmasked_names == ["ACCENT", "EMPTY", "PIN"]
    assert masker.feed(b"123 abcd \xc3\xa9 hunter2-Github!\n") + masker.flush() == (
        b"123 [irondome:FOUR] \xc3\xa9 [irondome:TOKEN]\n"
    )


def test_masker_with_nothing_to_mask_passes_everything_through() -> None:
    for secrets in ({}, {"PIN": "123"}):
        masker = Masker(secrets)
        assert masker.feed(b"anything \x00\xff at all") == b"anything \x00\xff at all"
        assert masker.feed(b"") == b""
        assert masker.flush() == b""


def test_masker_rejects_values_and_names_that_are_not_text() -> None:
    for secrets in ({"TOKEN": None}, {"TOKEN": b"bytes-value"}, {"TOKEN": 12345678}, {7: SECRET}, {None: SECRET}):
        with pytest.raises(UsageError):
            Masker(secrets)  # type: ignore[arg-type]


def test_masker_errors_name_the_variable_and_never_the_value() -> None:
    with pytest.raises(UsageError) as caught:
        Masker({"TOKEN": "hunter2-\ud800-Github"})
    assert "TOKEN" in str(caught.value)
    assert "hunter2" not in str(caught.value)


def test_masker_cannot_be_pickled_and_does_not_show_secrets() -> None:
    masker = Masker({"TOKEN": SECRET})
    with pytest.raises(TypeError):
        pickle.dumps(masker)
    assert "hunter2" not in repr(masker) and "hunter2" not in str(masker)


def test_masker_accepts_any_bytes_like_chunk_and_returns_bytes() -> None:
    masker = Masker({"TOKEN": SECRET})
    for chunk in (bytearray(b"a hunter2-Github! "), memoryview(b"b hunter2-Github! ")):
        out = masker.feed(chunk)
        assert type(out) is bytes and MARK in out
    with pytest.raises(TypeError):
        masker.feed("text is not bytes")  # type: ignore[arg-type]


def test_masker_can_be_reused_after_flush() -> None:
    masker = Masker({"TOKEN": SECRET})
    assert masker.feed(b"first hunter2-Git") == b"first "
    assert masker.flush() == b"hunter2-Git"  # the stream ended: that was not the secret after all
    assert masker.feed(b"hub! second hunter2-Github!") + masker.flush() == b"hub! second " + MARK
    assert masker.flush() == b""


# ---------------------------------------------------------------------------
# Masker: every encoding, as the tools that leak them write it
# ---------------------------------------------------------------------------

AWKWARD = 'p@ss w0rd/+&=?"q\\é🔑!$\'xy'


@pytest.mark.parametrize(
    "leak",
    [
        pytest.param(AWKWARD.encode(), id="plain"),
        pytest.param(base64.b64encode(AWKWARD.encode()), id="base64"),
        pytest.param(base64.b64encode(AWKWARD.encode()).rstrip(b"="), id="base64 without padding"),
        pytest.param(base64.urlsafe_b64encode(AWKWARD.encode()), id="URL-safe base64"),
        pytest.param(base64.urlsafe_b64encode(AWKWARD.encode()).rstrip(b"="), id="URL-safe base64 without padding"),
        pytest.param(AWKWARD.encode().hex().encode(), id="hex"),
        pytest.param(AWKWARD.encode().hex().upper().encode(), id="upper-case hex"),
        pytest.param(urllib.parse.quote(AWKWARD, safe="").encode(), id="percent-encoding"),
        pytest.param(urllib.parse.quote_plus(AWKWARD).encode(), id="form encoding"),
        pytest.param(urllib.parse.urlencode({"password": AWKWARD}).encode().split(b"=", 1)[1], id="a query string"),
        pytest.param(urllib.parse.quote(AWKWARD, safe="!*'()").encode(), id="encodeURIComponent"),
        pytest.param(json.dumps(AWKWARD).encode()[1:-1], id="JSON"),
        pytest.param(json.dumps(AWKWARD, ensure_ascii=False).encode()[1:-1], id="JSON with literal non-ASCII"),
        pytest.param(json.dumps({"env": {"PASSWORD": AWKWARD}}).encode(), id="a JSON document"),
        pytest.param(base64.b64encode(b"user:" + AWKWARD.encode()), id="HTTP Basic credentials"),
        pytest.param(base64.b64encode(AWKWARD.encode() + b"\n"), id="echo | base64"),
        pytest.param(shlex.quote(AWKWARD).encode(), id="shlex.quote"),
        pytest.param(repr(AWKWARD).encode(), id="repr"),
        pytest.param(repr({"PASSWORD": AWKWARD, "other": 1}).encode(), id="repr of a dict"),
    ],
)
def test_every_encoding_is_masked(leak: bytes) -> None:
    assert len(AWKWARD.encode()) % 3 != 0, "the padded and unpadded encodings must differ for this to test anything"
    out = mask_whole({"PASSWORD": AWKWARD}, b"before " + leak + b" after\n")
    assert b"[irondome:PASSWORD]" in out
    for _, pattern in secret_patterns(AWKWARD):
        assert pattern not in out
    assert out.startswith(b"before ") and out.endswith(b" after\n")


def test_exact_encodings_are_removed_completely() -> None:
    for leak in (
        base64.b64encode(AWKWARD.encode()),
        base64.urlsafe_b64encode(AWKWARD.encode()).rstrip(b"="),
        AWKWARD.encode().hex().encode(),
        urllib.parse.quote(AWKWARD, safe="").encode(),
        json.dumps(AWKWARD).encode()[1:-1],
    ):
        assert mask_whole({"PASSWORD": AWKWARD}, b"[" + leak + b"]") == b"[[irondome:PASSWORD]]"


def test_encodings_of_values_under_eight_bytes_are_left_alone() -> None:
    masker = Masker({"PIN": "1234567"})
    encoded = base64.b64encode(b"1234567") + b" " + b"1234567".hex().encode()
    assert masker.feed(b"1234567 " + encoded) + masker.flush() == b"[irondome:PIN] " + encoded


def test_what_masking_does_not_catch() -> None:
    # The documented limit: a deliberate transformation gets through.
    masker = Masker({"TOKEN": SECRET})
    for leak in (
        SECRET[::-1].encode(),  # reversed
        "\n".join(SECRET).encode(),  # one character per line
        SECRET.upper().encode(),
        SECRET.encode("utf-16-le"),
        base64.b32encode(SECRET.encode()),
    ):
        assert masker.feed(leak + b"\n") + masker.flush() == leak + b"\n"


# ---------------------------------------------------------------------------
# Masker: chunk boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cut", range(1, len(SECRET)))
def test_a_secret_split_across_two_chunks_is_masked(cut: int) -> None:
    stream = b"<" + SECRET.encode() + b">"
    masker = Masker({"TOKEN": SECRET})
    first = masker.feed(stream[: cut + 1])
    assert first == b"<", "nothing of the secret may be written before it is known not to be one"
    assert first + masker.feed(stream[cut + 1 :]) + masker.flush() == b"<" + MARK + b">"


def test_a_secret_fed_one_byte_at_a_time_is_masked() -> None:
    masker = Masker({"TOKEN": SECRET})
    stream = b"a " + SECRET.encode() + b" b " + base64.b64encode(SECRET.encode()) + b" c"
    out = b"".join(masker.feed(stream[index : index + 1]) for index in range(len(stream))) + masker.flush()
    assert out == b"a " + MARK + b" b " + MARK + b" c"


def test_output_is_not_delayed_unless_it_could_be_the_start_of_a_secret() -> None:
    masker = Masker({"TOKEN": SECRET})
    assert masker.feed(b"Password: ") == b"Password: "  # a prompt appears at once
    assert masker.feed(b"progress 50%") == b"progress 50%"
    assert masker.feed(b"\n") == b"\n"
    # "h" could be the first byte of the secret, so it waits ...
    assert masker.feed(b"oh") == b"o"
    # ... and is released by the next byte that rules the secret out.
    assert masker.feed(b"!") == b"h!"
    assert masker.feed(b" hunter2-Gith") == b" "
    assert masker.feed(b"ub") == b""
    assert masker.feed(b"? nope.") == b"hunter2-Github? nope."
    assert masker.flush() == b""


def test_a_false_start_followed_by_the_real_thing() -> None:
    masker = Masker({"TOKEN": SECRET})
    assert masker.feed(b"hunter2-hunter2-Git") + masker.feed(b"hub!hun") + masker.flush() == b"hunter2-" + MARK + b"hun"


def test_flush_writes_out_what_was_held_and_masks_what_is_complete_inside_it() -> None:
    masker = Masker({"LONG": "abcdefgh-0123456789", "SHORT": "bcdefgh-01"})
    # Everything from "a" on could still become LONG, so it is all held ...
    assert masker.feed(b"x abcdefgh-012") == b"x "
    # ... until the stream ends: LONG did not happen, but SHORT is in there.
    assert masker.flush() == b"a[irondome:SHORT]2"


# ---------------------------------------------------------------------------
# Masker: overlapping patterns
# ---------------------------------------------------------------------------


def test_the_longest_match_at_a_position_wins() -> None:
    secrets = {"SHORT": "secret-ab", "LONG": "secret-abcdef"}
    assert mask_whole(secrets, b"1 secret-abcdef 2 secret-ab 3 secret-abc") == (
        b"1 [irondome:LONG] 2 [irondome:SHORT] 3 [irondome:SHORT]c"
    )


def test_a_secret_containing_another_is_one_placeholder() -> None:
    secrets = {"DATABASE_URL": "postgres://app:s3cr3t-pw@db.internal/prod", "DB_PASSWORD": "s3cr3t-pw"}
    assert mask_whole(secrets, b"url=postgres://app:s3cr3t-pw@db.internal/prod pw=s3cr3t-pw") == (
        b"url=[irondome:DATABASE_URL] pw=[irondome:DB_PASSWORD]"
    )


def test_overlapping_secrets_leave_no_tail_behind() -> None:
    secrets = {"FIRST": "abc123", "SECOND": "123xyz"}
    # Leftmost-longest alone would print "[irondome:FIRST]xyz" and give away half of SECOND.
    assert mask_whole(secrets, b"<abc123xyz>") == b"<[irondome:FIRST]>"
    assert mask_whole(secrets, b"<123xyz>") == b"<[irondome:SECOND]>"


def test_a_secret_overlapping_itself_is_removed_whole() -> None:
    assert mask_whole({"A": "abab"}, b"<ababab>") == b"<[irondome:A]>"
    assert mask_whole({"A": "aaaa"}, b"<" + b"a" * 1000 + b">") == b"<[irondome:A]>"
    assert mask_whole({"A": "aaaa"}, b"<aaa>") == b"<aaa>"


def test_adjacent_occurrences_get_a_placeholder_each() -> None:
    assert mask_whole({"TOKEN": SECRET}, SECRET.encode() * 3) == MARK * 3


def test_two_variables_with_the_same_value_use_the_first_name() -> None:
    assert mask_whole({"B_TOKEN": SECRET, "A_TOKEN": SECRET}, SECRET.encode()) == b"[irondome:A_TOKEN]"


def test_an_exact_value_wins_over_the_same_bytes_as_an_encoding() -> None:
    encoded = base64.b64encode(SECRET.encode()).decode()
    secrets = {"A_PLAIN": SECRET, "Z_ENCODED": encoded}
    assert mask_whole(secrets, encoded.encode()) == b"[irondome:Z_ENCODED]"
    assert mask_whole(secrets, SECRET.encode()) == b"[irondome:A_PLAIN]"


# ---------------------------------------------------------------------------
# Masker: properties
# ---------------------------------------------------------------------------


@settings(max_examples=300, deadline=None)
@given(st.data())
def test_chunking_never_changes_the_output(data: st.DataObject) -> None:
    secrets = data.draw(st.dictionaries(st.sampled_from(["A", "B", "C", "TOKEN"]), any_text, min_size=1, max_size=3))
    stream = data.draw(streams(secrets, st.binary(max_size=12)))
    sizes = data.draw(chunk_sizes)
    whole = mask_whole(secrets, stream)
    assert feed_in_chunks(Masker(secrets), stream, sizes) == whole
    assert feed_in_chunks(Masker(secrets), stream, [1]) == whole
    assert whole == reference_mask(stream, marks_for(secrets))


@settings(max_examples=300, deadline=None)
@given(st.data())
def test_overlapping_and_prefix_sharing_secrets_match_the_definition(data: st.DataObject) -> None:
    # Two-letter alphabets make secrets overlap themselves, each other and each other's prefixes constantly.
    alphabet = data.draw(st.sampled_from(["ab", "a", "abc", "ab01"]))
    secrets = data.draw(
        st.dictionaries(st.sampled_from(["A", "B", "C", "D"]), st.text(alphabet, min_size=1, max_size=12), min_size=1)
    )
    stream = data.draw(streams(secrets, st.text(alphabet, max_size=6).map(str.encode)))
    sizes = data.draw(chunk_sizes)
    expected = reference_mask(stream, marks_for(secrets))
    assert mask_whole(secrets, stream) == expected
    assert feed_in_chunks(Masker(secrets), stream, sizes) == expected


@settings(max_examples=300, deadline=None)
@given(st.data())
def test_no_byte_of_any_masked_form_survives(data: st.DataObject) -> None:
    # ASCII secrets and noise; a placeholder made of bytes no pattern contains. Then the output
    # can be checked directly: no pattern anywhere, and exactly the uncovered bytes left.
    ascii_text = st.text(st.characters(min_codepoint=32, max_codepoint=126), min_size=1, max_size=20)
    secrets = data.draw(st.dictionaries(st.sampled_from(["S0", "S1", "S2"]), ascii_text, min_size=1))
    stream = data.draw(streams(secrets, ascii_text.map(str.encode)))
    sizes = data.draw(chunk_sizes)
    out = feed_in_chunks(Masker(secrets, placeholder="§{name}§"), stream, sizes)
    patterns = [pattern for value in secrets.values() for _, pattern in secret_patterns(value)]
    for pattern in patterns:
        assert pattern not in out
    survivors = out
    for name in secrets:
        survivors = survivors.replace(f"§{name}§".encode(), b"")
    assert survivors == uncovered(stream, patterns)


@settings(max_examples=200, deadline=None)
@given(st.dictionaries(st.sampled_from(["A", "B", "TOKEN"]), any_text, min_size=1), st.binary(max_size=400),
       st.lists(st.integers(0, 400), max_size=6), chunk_sizes)
def test_binary_garbage_around_secrets(secrets: Dict[str, str], garbage: bytes, places: List[int],
                                       sizes: List[int]) -> None:
    stream = bytearray(garbage)
    values = sorted(secrets.values())
    for index, place in enumerate(sorted(places, reverse=True)):
        stream[place:place] = values[index % len(values)].encode("utf-8")
    whole = mask_whole(secrets, bytes(stream))
    assert whole == reference_mask(bytes(stream), marks_for(secrets))
    assert feed_in_chunks(Masker(secrets), bytes(stream), sizes) == whole
    assert type(whole) is bytes


@settings(max_examples=200, deadline=None)
@given(st.data())
def test_only_a_possible_start_of_a_secret_is_ever_held_back(data: st.DataObject) -> None:
    secrets = data.draw(st.dictionaries(st.sampled_from(["A", "B", "C"]), any_text, min_size=1, max_size=3))
    stream = data.draw(streams(secrets, st.binary(max_size=12)))
    patterns = [pattern for value in secrets.values() for _, pattern in secret_patterns(value)]
    longest = max((len(pattern) for pattern in patterns), default=1)
    masker = Masker(secrets)
    position = 0
    for size in data.draw(chunk_sizes) * 40:
        if position >= len(stream):
            break
        masker.feed(stream[position : position + size])
        position += size
        # The internal buffer is inspected on purpose: this is the promise "at most the longest pattern
        # minus one byte, and only while it could still become a secret".
        held = masker._pending
        assert len(held) <= longest - 1
        assert not held or any(len(pattern) > len(held) and pattern.startswith(held) for pattern in patterns)


def test_megabytes_do_not_make_it_slow() -> None:
    secrets = {
        "TOKEN": SECRET,
        "API_KEY": "sk-live-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
        "PASSWORD": "correct horse battery staple",
    }
    line = b"2026-11-11T21:00:00Z INFO request served path=/api/v1/items status=200 bytes=5120 ms=12 id=7f3a9c\n"
    block = line * 600 + b"token=" + SECRET.encode() + b" " + base64.b64encode(SECRET.encode()) + b"\n"
    stream = block * (20 * 1024 * 1024 // len(block) + 1)
    assert len(stream) >= 20 * 1024 * 1024
    masker = Masker(secrets)
    started = time.process_time()
    produced = 0
    hits = 0
    for position in range(0, len(stream), 65536):
        out = masker.feed(stream[position : position + 65536])
        produced += len(out)
        hits += out.count(MARK)
    out = masker.flush()
    produced += len(out)
    hits += out.count(MARK)
    elapsed = time.process_time() - started
    assert hits >= 2 * (len(stream) // len(block)) - 2
    assert produced < len(stream)
    assert elapsed < 20.0, f"20 MB took {elapsed:.1f} s of processor time"


@pytest.mark.parametrize(
    ("secrets", "stream"),
    [
        pytest.param({"A": "aaaa"}, b"a" * 4_000_000, id="a secret that overlaps itself everywhere"),
        pytest.param({"A": "abababab"}, b"ab" * 2_000_000, id="a periodic secret"),
        pytest.param({"A": "a" * 63 + "b"}, b"a" * 4_000_000, id="near misses at every position"),
        pytest.param({"A": "ab" * 40 + "c"}, b"ab" * 2_000_000, id="periodic near misses"),
        pytest.param({"A": "x" * 5000 + "y"}, b"x" * 4_000_000, id="a long secret that never completes"),
        pytest.param(
            {f"S{index}": f"secret-{index:04d}-" + "z" * 20 for index in range(40)},
            b"secret-00" * 400_000,
            id="forty secrets sharing a prefix",
        ),
        pytest.param({"A": "ab" * 2000}, b"ab" * 2_000_000, id="a long periodic secret"),
    ],
)
def test_adversarial_streams_stay_linear(secrets: Dict[str, str], stream: bytes) -> None:
    masker = Masker(secrets)
    started = time.process_time()
    for position in range(0, len(stream), 65536):
        masker.feed(stream[position : position + 65536])
    masker.flush()
    elapsed = time.process_time() - started
    assert elapsed < 30.0, f"4 MB took {elapsed:.1f} s of processor time"


# ---------------------------------------------------------------------------
# The child's environment
# ---------------------------------------------------------------------------

DUMP_ENVIRONMENT = """
    import json, os, sys
    json.dump(dict(os.environ), sys.stdout)
"""


def environment_seen_by_child(injected: Dict[str, str], **options: object) -> Dict[str, str]:
    result = run_captured(python(DUMP_ENVIRONMENT), injected, timeout=PATIENCE, **options)  # type: ignore[arg-type]
    assert result.code == 0, result.stderr
    return json.loads(result.stdout)


def test_child_gets_the_secret_and_never_a_bearer_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IRONDOME_SESSION", "ird_s1_session-token-value")
    monkeypatch.setenv("IRONDOME_GRANT", "ird_g1_grant-token-value")
    monkeypatch.setenv("IRONDOME_PASSWORD_FILE", "/run/secrets/master")
    monkeypatch.setenv("STILL_A_REFERENCE", "irondome://github")
    monkeypatch.setenv("ALSO_A_REFERENCE", "IRONDOME://aws/prod/region")
    monkeypatch.setenv("ORDINARY", "kept")
    seen = environment_seen_by_child({"TOKEN": "x"}, literals={"NODE_ENV": "production"})
    assert seen["TOKEN"] == "x"
    assert seen["NODE_ENV"] == "production"
    assert seen["ORDINARY"] == "kept"
    for name in ("IRONDOME_SESSION", "IRONDOME_GRANT", "IRONDOME_PASSWORD_FILE", "STILL_A_REFERENCE",
                 "ALSO_A_REFERENCE"):
        assert name not in seen
    assert not any("token-value" in value or refs.is_reference(value) for value in seen.values())
    # Where the vault lives is not a credential, and a nested irondome needs it.
    assert seen["IRONDOME_HOME"] == os.environ["IRONDOME_HOME"]


def test_child_environment_precedence_and_explicit_base() -> None:
    base = {"PATH": os.environ["PATH"], "A": "base", "B": "base", "C": "base", "IRONDOME_GRANT": "ird_g1_tok",
            "REF": "irondome://x"}
    seen = environment_seen_by_child({"C": "injected-c"}, literals={"B": "literal", "C": "literal"}, base_env=base)
    assert (seen["A"], seen["B"]) == ("base", "literal")
    assert seen["C"] == "[irondome:C]", "an injected value is a secret, and the dump of it is masked"
    assert "IRONDOME_GRANT" not in seen and "REF" not in seen and "HOME" not in seen


def test_a_secret_that_looks_like_a_reference_is_still_passed_on() -> None:
    result = run_captured(python("import os; print(len(os.environ['ODD']))"), {"ODD": "irondome://odd-value"},
                          timeout=PATIENCE)
    assert result.stdout.strip() == str(len("irondome://odd-value"))


@pytest.mark.parametrize("name", ["IRONDOME_SESSION", "IRONDOME_GRANT", "IRONDOME_PASSWORD_FILE"])
def test_control_variables_cannot_be_injected(name: str) -> None:
    for injected, literals in (({name: "value-123"}, None), ({}, {name: "value-123"})):
        with pytest.raises(UsageError) as caught:
            run_captured(python("pass"), injected, literals=literals, timeout=PATIENCE)
        assert name in str(caught.value) and "value-123" not in str(caught.value)


@pytest.mark.parametrize(
    ("injected", "literals"),
    [
        ({"": "value"}, None),
        ({"A=B": "value"}, None),
        ({"A\x00B": "value"}, None),
        ({7: "value"}, None),
        ({"A": None}, None),
        ({"A": b"bytes"}, None),
        ({"A": "nul\x00inside"}, None),
        ({"A": "lone\ud800surrogate"}, None),
        ({}, {"A=B": "value"}),
        ({}, {"A": 7}),
        ({}, {"A": "nul\x00inside"}),
        ({}, {"A": "irondome://unresolved"}),
    ],
)
def test_unusable_variables_are_refused_before_anything_runs(injected, literals, tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    command = python("import sys; open(sys.argv[1], 'w').close()", str(marker))
    for call in (
        lambda: run_captured(command, injected, literals=literals, timeout=PATIENCE),
        lambda: run_command(command, injected, literals=literals, timeout=PATIENCE),
        lambda: run_command(command, injected, literals=literals, mask=False, timeout=PATIENCE),
    ):
        with pytest.raises(UsageError) as caught:
            call()
        assert "inside" not in str(caught.value) and "surrogate" not in str(caught.value)
    assert not marker.exists()


def test_inherited_variables_no_process_could_hold_are_dropped_quietly() -> None:
    base = {"PATH": os.environ["PATH"], "GOOD": "yes", "BAD=NAME": "x", "": "x", "NUL": "a\x00b", 7: "x", "NONE": None}
    seen = environment_seen_by_child({}, base_env=base)  # type: ignore[arg-type]
    assert seen["GOOD"] == "yes"
    assert not {"BAD=NAME", "", "NUL", "7", "NONE"} & set(seen)


# ---------------------------------------------------------------------------
# run_command
# ---------------------------------------------------------------------------

PRINT_SECRET = """
    import os, sys
    print("out:", os.environ["TOKEN"])
    print("err:", os.environ["TOKEN"], file=sys.stderr)
    sys.exit(int(sys.argv[1]))
"""


def test_run_command_masks_stdout_and_stderr_and_returns_the_status(capfd: pytest.CaptureFixture) -> None:
    assert run_command(python(PRINT_SECRET, "7"), {"TOKEN": SECRET}, timeout=PATIENCE) == 7
    captured = capfd.readouterr()
    assert captured.out == "out: [irondome:TOKEN]\n"
    assert captured.err == "err: [irondome:TOKEN]\n"


def test_run_command_without_masking_lets_the_child_write_directly(capfd: pytest.CaptureFixture) -> None:
    assert run_command(python(PRINT_SECRET, "0"), {"TOKEN": SECRET}, mask=False, timeout=PATIENCE) == 0
    captured = capfd.readouterr()
    assert captured.out == f"out: {SECRET}\n"
    assert captured.err == f"err: {SECRET}\n"


def test_run_command_masks_every_encoding_a_real_child_prints(capfd: pytest.CaptureFixture) -> None:
    code = """
        import base64, json, os, sys
        secret = os.environ["TOKEN"].encode()
        print(base64.b64encode(secret).decode(), secret.hex(), json.dumps(os.environ["TOKEN"]))
        print(base64.b64encode(b"user:" + secret).decode(), file=sys.stderr)
        sys.stdout.buffer.write(b"\\x00\\xff binary " + secret + b" \\xfe\\n")
    """
    awkward = 'p@ss "w0rd"\\ +/='
    assert run_command(python(code), {"TOKEN": awkward}, timeout=PATIENCE) == 0
    out, err = capfd.readouterr()
    assert out.count("[irondome:TOKEN]") == 4 and "[irondome:TOKEN]" in err
    for _, pattern in secret_patterns(awkward):
        assert pattern.decode() not in out and pattern.decode() not in err


DUMPS = [
    ("env", ["env"]),
    ("printenv", ["printenv", "TOKEN"]),
    ("bash declare -p", ["bash", "-c", "declare -p TOKEN"]),
    ("bash export -p", ["bash", "-c", "export -p"]),
    ("bash set", ["bash", "-c", "set"]),
    ("bash xtrace", ["bash", "-xc", ': "$TOKEN"']),
    ("sh export -p", ["sh", "-c", "export -p"]),
    ("sh set", ["sh", "-c", "set"]),
    ("sh xtrace", ["sh", "-xc", ': "$TOKEN"']),
    ("zsh typeset -p", ["zsh", "-fc", "typeset -p TOKEN"]),
    ("zsh xtrace", ["zsh", "-fxc", ': "$TOKEN"']),
    ("python repr", python("import os; print(os.environ); print(repr(os.environ['TOKEN']))")),
    ("python shlex", python("import os, shlex; print(shlex.quote(os.environ['TOKEN']))")),
    ("python json", python("import os, json; print(json.dumps(dict(os.environ)))")),
    ("node", ["node", "-e", "console.log(process.env); console.log(JSON.stringify(process.env))"]),
    ("ruby", ["ruby", "-e", "p ENV.to_h; puts ENV['TOKEN'].inspect"]),
    ("perl", ["perl", "-MData::Dumper", "-e", "print Dumper(\\%ENV)"]),
]


@posix_only
@pytest.mark.parametrize(("argv"), [pytest.param(argv, id=label) for label, argv in DUMPS])
@pytest.mark.parametrize(
    "value",
    [
        pytest.param("pa$$w0rd'q\"x\\y z!&`t", id="every awkward character"),
        pytest.param("Tr0ub4dor&3-pa$$w0rd!", id="a generated password"),
    ],
)
def test_dumps_of_the_environment_by_real_tools_are_masked(argv: List[str], value: str) -> None:
    # What an agent types when something does not work: every one of these prints the whole environment.
    if shutil.which(argv[0]) is None:
        pytest.skip(f"{argv[0]} is not installed")
    # A bare environment: the test must not print, even on failure, whatever this machine's own holds.
    result = run_captured(
        argv, {"TOKEN": value}, base_env={"PATH": os.environ["PATH"]}, timeout=PATIENCE, max_bytes=2_000_000
    )
    printed = result.stdout + result.stderr
    assert result.code == 0
    assert "[irondome:TOKEN]" in printed
    assert "w0rd" not in printed


def test_a_secret_written_in_two_pieces_is_still_masked(capfd: pytest.CaptureFixture) -> None:
    code = """
        import os, sys, time
        secret = os.environ["TOKEN"]
        sys.stdout.write("start " + secret[:7]); sys.stdout.flush()
        time.sleep(0.3)
        sys.stdout.write(secret[7:] + " end\\n"); sys.stdout.flush()
    """
    assert run_command(python(code), {"TOKEN": SECRET}, timeout=PATIENCE) == 0
    assert capfd.readouterr().out == "start [irondome:TOKEN] end\n"


def test_output_arrives_while_the_child_is_still_running(tmp_path: Path) -> None:
    # The wrapper's output is a pipe we read: the first line must be readable before the child ends.
    release = tmp_path / "release"
    child = python(
        """
        import os, sys, time
        print("first line", flush=True)
        while not os.path.exists(sys.argv[1]):
            time.sleep(0.02)
        print("second line", flush=True)
        """,
        str(release),
    )
    with subprocess.Popen(wrapper(child), stdout=subprocess.PIPE) as process:
        assert process.stdout is not None
        assert process.stdout.readline() == b"first line\n"
        release.write_text("go")
        assert process.stdout.read() == b"second line\n"
        assert process.wait(PATIENCE) == 0


def test_large_interleaved_output_does_not_deadlock(capfd: pytest.CaptureFixture) -> None:
    code = """
        import os, sys
        block = (b"x" * 99 + b"\\n") * 100
        secret = os.environ["TOKEN"].encode()
        for _ in range(300):
            sys.stdout.buffer.write(block + secret + b"\\n")
            sys.stderr.buffer.write(block + secret + b"\\n")
        sys.stdout.buffer.flush(); sys.stderr.buffer.flush()
    """
    assert run_command(python(code), {"TOKEN": SECRET}, timeout=PATIENCE) == 0
    out, err = capfd.readouterr()
    expected = (("x" * 99 + "\n") * 100 + "[irondome:TOKEN]\n") * 300
    assert out == expected
    assert err == expected


DIE_OF_A_SIGNAL = """
    import os, signal, sys
    number = int(sys.argv[1])
    if number != signal.SIGKILL:
        signal.signal(number, signal.SIG_DFL)  # whatever this test run inherited, die of it
    os.kill(os.getpid(), number)
"""


@posix_only
@pytest.mark.parametrize("name", ["SIGKILL", "SIGTERM", "SIGINT", "SIGHUP"])
def test_a_child_killed_by_a_signal_is_reported_as_128_plus_the_signal(name: str) -> None:
    number = int(getattr(signal, name))
    command = python(DIE_OF_A_SIGNAL, str(number))
    assert run_command(command, {"TOKEN": SECRET}, timeout=PATIENCE) == 128 + number
    assert run_command(command, {}, mask=False, timeout=PATIENCE) == 128 + number
    assert run_captured(command, {}, timeout=PATIENCE).code == 128 + number


@pytest.mark.parametrize("status", [0, 3, 255])
def test_exit_statuses_pass_through(status: int) -> None:
    code = "import sys; sys.exit(int(sys.argv[1]))"
    assert run_command(python(code, str(status)), {}, timeout=PATIENCE) == status
    assert run_command(python(code, str(status)), {}, mask=False, timeout=PATIENCE) == status
    assert run_captured(python(code, str(status)), {}, timeout=PATIENCE).code == status


def test_command_not_found_is_a_usage_error_with_status_127() -> None:
    for call in (
        lambda: run_command(["irondome-no-such-command-xyz", "arg"], {"TOKEN": SECRET}),
        lambda: run_command(["./no/such/file"], {}, mask=False),
        lambda: run_captured(["/no/such/dir/tool"], {}),
    ):
        with pytest.raises(CommandNotFoundError) as caught:
            call()
        assert isinstance(caught.value, UsageError)
        assert caught.value.exit_code == 127
        assert "command not found" in str(caught.value)


@posix_only
def test_a_file_that_cannot_be_executed_is_status_126(tmp_path: Path) -> None:
    plain = tmp_path / "not-executable.sh"
    plain.write_text("#!/bin/sh\necho hi\n")
    plain.chmod(0o600)
    garbage = tmp_path / "garbage"
    garbage.write_bytes(b"\x00\x01\x02 this is not a program")
    garbage.chmod(0o700)
    for target in (str(plain), str(tmp_path), str(garbage)):
        with pytest.raises(CommandNotExecutableError) as caught:
            run_captured([target], {})
        assert isinstance(caught.value, UsageError) and caught.value.exit_code == 126


@posix_only
def test_the_program_is_found_on_the_childs_path_relative_to_its_directory(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    tool = tools / "show-args"
    tool.write_text("#!/bin/sh\nprintf '%s|' \"$@\"\n")
    tool.chmod(0o700)
    # Not on this process's PATH ...
    with pytest.raises(CommandNotFoundError):
        run_captured(["show-args"], {})
    # ... but on the child's, absolute or relative to the child's working directory.
    for path, cwd in ((str(tools), None), ("tools", str(tmp_path)), ("", str(tools)), ("/nowhere::", str(tools))):
        result = run_captured(["show-args", "a b", "$HOME", "x;y"], {}, literals={"PATH": path}, cwd=cwd,
                              timeout=PATIENCE)
        assert result.stdout == "a b|$HOME|x;y|", "arguments are passed as they are: there is no shell"
    assert run_captured(["./show-args", "1"], {}, cwd=str(tools), timeout=PATIENCE).stdout == "1|"
    assert run_captured(["tools/show-args", "2"], {}, cwd=str(tmp_path), timeout=PATIENCE).stdout == "2|"
    assert run_captured([str(tool), "3"], {}, timeout=PATIENCE).stdout == "3|"
    with pytest.raises(CommandNotFoundError):
        run_captured(["./show-args"], {}, cwd=str(tmp_path))
    # The child still sees the name it was called by, not the path it was found at.
    assert run_captured(["sh", "-c", "echo $0"], {}, timeout=PATIENCE).stdout == "sh\n"
    # With no PATH at all the system's default search path is used, as the exec functions do.
    assert run_captured(["sh", "-c", "echo found"], {}, base_env={}, timeout=PATIENCE).stdout == "found\n"


@pytest.mark.skipif(os.name == "nt", reason="a POSIX shell script")
def test_a_program_the_caller_located_is_started_as_it_is_under_the_name_it_was_called_by(tmp_path: Path) -> None:
    """``executable=``: what the caller found (and showed) is what starts; nothing is looked up again."""
    shown = tmp_path / "shown" / "tool"
    shown.parent.mkdir()
    shown.write_text('#!/bin/sh\necho "shown $0 $1"\n')
    shown.chmod(0o755)
    planted = tmp_path / "planted" / "tool"
    planted.parent.mkdir()
    planted.write_text("#!/bin/sh\necho planted\n")
    planted.chmod(0o755)
    path = {"PATH": f"{planted.parent}{os.pathsep}{os.environ.get('PATH', os.defpath)}"}
    assert run_captured(["tool", "x"], {}, literals=path, timeout=PATIENCE).stdout == "planted\n"
    found = run_captured(["tool", "x"], {}, literals=path, timeout=PATIENCE, executable=str(shown))
    assert found.stdout == f"shown {shown} x\n"  # a script's $0 is the file the kernel started
    named = run_captured(["sh", "-c", "echo $0"], {}, timeout=PATIENCE, executable=shutil.which("sh"))
    assert named.stdout == "sh\n", "the child sees the name it was called by, not the path it was started from"
    with pytest.raises(UsageError, match="absolute path"):
        run_captured(["tool"], {}, executable="tool")
    with pytest.raises(CommandNotFoundError):
        run_captured(["tool"], {}, executable=str(tmp_path / "gone"))
    shown.chmod(0o644)
    with pytest.raises(CommandNotExecutableError):
        run_captured(["tool"], {}, executable=str(shown))
    with pytest.raises(CommandNotExecutableError):
        run_captured(["tool"], {}, executable=str(tmp_path))


def test_no_shell_ever_interprets_the_command(tmp_path: Path) -> None:
    marker = tmp_path / "owned"
    hostile = [f"; touch {marker}", f"$(touch {marker})", f"`touch {marker}`", "|", ">x", "&&", "$HOME", "*"]
    result = run_captured(python("import sys; print(sys.argv[1:])", *hostile), {}, timeout=PATIENCE)
    assert result.stdout.strip() == repr(hostile)
    assert not marker.exists()
    with pytest.raises(CommandNotFoundError):
        run_captured([f"echo hi; touch {marker}"], {})
    assert not marker.exists()


@pytest.mark.parametrize(
    "argv",
    [[], [""], "echo hi", ["echo", 7], ["echo", "nul\x00"], [None], None, b"echo", ["echo", "lone\ud800surrogate"], ()],
)
def test_unusable_commands_are_usage_errors(argv: object) -> None:
    for call in (lambda: run_command(argv, {}), lambda: run_captured(argv, {})):  # type: ignore[arg-type]
        with pytest.raises(UsageError):
            call()


@pytest.mark.parametrize("timeout", [0, -1, -0.5, float("nan"), float("inf"), "10", True, [1]])
def test_unusable_time_limits_are_usage_errors(timeout: object) -> None:
    for call in (
        lambda: run_command(python("pass"), {}, timeout=timeout),  # type: ignore[arg-type]
        lambda: run_captured(python("pass"), {}, timeout=timeout),  # type: ignore[arg-type]
    ):
        with pytest.raises(UsageError):
            call()


def test_working_directory(tmp_path: Path) -> None:
    result = run_captured(python("import os; print(os.getcwd())"), {}, cwd=str(tmp_path), timeout=PATIENCE)
    assert os.path.realpath(result.stdout.strip()) == os.path.realpath(str(tmp_path))
    assert run_captured(python("pass"), {}, cwd=tmp_path, timeout=PATIENCE).code == 0  # type: ignore[arg-type]
    for missing in (str(tmp_path / "missing"), str(tmp_path / "file\x00"), 7):
        with pytest.raises(UsageError):
            run_captured(python("pass"), {}, cwd=missing)  # type: ignore[arg-type]
        with pytest.raises(UsageError):
            run_command(python("pass"), {}, cwd=missing)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Time limits
# ---------------------------------------------------------------------------


@pytest.fixture
def spawned(monkeypatch: pytest.MonkeyPatch) -> List[subprocess.Popen]:
    """Every command the runner starts during the test, so its fate can be checked afterwards.

    Not the ``ps`` it runs to read the process table before it stops a command (macOS has no /proc).
    """
    started: List[subprocess.Popen] = []

    class Recording(subprocess.Popen):  # type: ignore[type-arg]
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)  # type: ignore[call-overload]
            if not (args and isinstance(args[0], list) and args[0][:1] == ["/bin/ps"]):
                started.append(self)

    monkeypatch.setattr(runner.subprocess, "Popen", Recording)
    return started


@posix_only
@pytest.mark.parametrize("mask", [True, False])
def test_timeout_stops_the_child_and_raises(mask: bool, spawned: List[subprocess.Popen]) -> None:
    began = time.monotonic()
    with pytest.raises(CommandTimeoutError) as caught:
        run_command(["/bin/sleep", "600"], {"TOKEN": SECRET}, mask=mask, timeout=0.5)
    assert time.monotonic() - began < PATIENCE
    assert isinstance(caught.value, IronDomeError) and not isinstance(caught.value, UsageError)
    assert caught.value.exit_code == 124
    assert caught.value.result is None
    assert "0.5 seconds" in str(caught.value) and SECRET not in str(caught.value)
    (process,) = spawned
    assert process.returncode == -signal.SIGTERM, "the child was asked to stop, complied, and was reaped"


@posix_only
@pytest.mark.parametrize("mask", [True, False])
@pytest.mark.skipif(
    not os.path.isdir("/proc/self") and not os.path.exists("/bin/ps"), reason="no process table to read here"
)
def test_timeout_stops_what_the_command_started_too(mask: bool, tmp_path: Path) -> None:
    """A time limit must not leave programs running that hold the injected value.

    The command starts one program in the background, one in a session of its
    own and one in the foreground, each holding the secret in its environment.
    All of them descend from the command when the limit passes, and all of
    them are stopped. (Found by a trial by hand before release: only the
    command itself was stopped, and three processes kept the value.)
    """
    family = python(
        """
        import os, subprocess, sys, time
        where = sys.argv[1]
        sleeper = "import os,sys,time; open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(600)"
        own = "import os,sys,time; os.setsid(); open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(600)"
        subprocess.Popen([sys.executable, "-c", sleeper, where + "/background"])
        subprocess.Popen([sys.executable, "-c", own, where + "/own-session"])
        subprocess.Popen([sys.executable, "-c", sleeper, where + "/foreground"]).wait()
        """,
        str(tmp_path),
    )
    names = ("background", "own-session", "foreground")
    try:
        with pytest.raises(CommandTimeoutError):
            run_command(family, {"TOKEN": SECRET}, mask=mask, timeout=3.0)
        pids = [int((tmp_path / name).read_text()) for name in names]
        deadline = time.monotonic() + PATIENCE
        while time.monotonic() < deadline and any(_running(pid) for pid in pids):
            time.sleep(0.05)
        assert [name for name, pid in zip(names, pids) if _running(pid)] == []
    finally:
        for name in names:
            try:
                os.kill(int((tmp_path / name).read_text()), signal.SIGKILL)
            except (OSError, ValueError):
                pass


def _running(pid: int) -> bool:
    """True while *pid* is a live process (a zombie waiting to be reaped is not)."""
    shown = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False)
    return bool(shown.stdout.strip()) and not shown.stdout.strip().startswith("Z")


def test_only_a_line_that_is_one_unbroken_token_is_masked_by_itself() -> None:
    """Each line of a key is a pattern; the lines every key and every config file share are not.

    A review found that the first version masked ``-----BEGIN PRIVATE KEY-----`` in the output of commands
    that had nothing to do with the value, and ``"type": "service_account",`` wherever it appeared.
    """
    pem = (
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"
        "VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDu\n-----END PRIVATE KEY-----\n"
    )
    account = (
        '{\n  "type": "service_account",\n  "token_uri": "https://oauth2.googleapis.com/token",\n'
        '  "private_key_id": "0123456789abcdef0123456789abcdef01234567"\n}\n'
    )
    lines = [pattern for label, pattern in secret_patterns(pem) if label == "line"]
    assert lines == [
        b"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7",
        b"VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDu",
    ]
    assert [pattern for label, pattern in secret_patterns(account) if label == "line"] == []
    masker = Masker({"TLS_KEY": pem, "ACCOUNT": account})
    other = (
        "-----BEGIN PRIVATE KEY-----\nAAAAsomeoneElsesKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        '-----END PRIVATE KEY-----\n"type": "service_account",\n'
    )
    assert (masker.feed(other.encode()) + masker.flush()).decode() == other


CHILD_THAT_TIDIES_UP = """
import os, signal, sys, time
def stop(*_):
    time.sleep(0.4)
    open(sys.argv[1] + "/tidied", "w").write("yes")
    os._exit(0)
signal.signal(signal.SIGTERM, stop)
open(sys.argv[1] + "/ready", "w").write(str(os.getpid()))
time.sleep(600)
"""


@posix_only
def test_a_time_limit_gives_what_the_command_started_the_same_time_to_stop(tmp_path: Path) -> None:
    """The command stops at once; its child needs a moment to finish what it is writing, and gets it."""
    (tmp_path / "child.py").write_text(CHILD_THAT_TIDIES_UP)
    family = python(
        """
        import os, subprocess, sys, time
        subprocess.Popen([sys.executable, sys.argv[1] + "/child.py", sys.argv[1]])
        while not os.path.exists(sys.argv[1] + "/ready"):
            time.sleep(0.02)
        time.sleep(600)
        """,
        str(tmp_path),
    )
    try:
        with pytest.raises(CommandTimeoutError):
            run_command(family, {"TOKEN": SECRET}, timeout=3.0)
        assert (tmp_path / "tidied").exists(), "the child was killed before it had its grace"
    finally:
        try:
            os.kill(int((tmp_path / "ready").read_text()), signal.SIGKILL)
        except (OSError, ValueError):
            pass


@posix_only
def test_the_descendants_of_a_process_are_found_however_they_are_named(tmp_path: Path) -> None:
    child = subprocess.Popen(
        [sys.executable, "-c",
         # On Linux the name is what /proc/<pid>/stat puts between brackets: one made to look like the
         # fields that follow it must not confuse the reading of the parent's pid.
         "import subprocess,sys,time\n"
         "try:\n    open('/proc/self/comm', 'w').write('x) S 1 1 (y')\nexcept OSError:\n    pass\n"
         "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
         "print('up', flush=True); time.sleep(60)"],
        stdout=subprocess.PIPE,
    )
    try:
        assert child.stdout is not None and child.stdout.readline().strip() == b"up"
        found = runner._descendants(child.pid)
        assert len(found) == 1 and child.pid not in found and os.getpid() not in found
        assert child.pid in runner._descendants(os.getpid())
        assert runner._descendants(2**22 + 12345) == []
    finally:
        for pid in runner._descendants(child.pid):
            os.kill(pid, signal.SIGKILL)
        child.kill()
        child.wait()


@posix_only
def test_timeout_kills_a_child_that_ignores_being_asked(
    spawned: List[subprocess.Popen], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "_TERMINATE_GRACE", 0.5)
    previous = signal.signal(signal.SIGTERM, signal.SIG_IGN)  # ignored dispositions are inherited by the child
    try:
        with pytest.raises(CommandTimeoutError):
            run_command(["/bin/sleep", "600"], {"TOKEN": SECRET}, timeout=0.5)
    finally:
        signal.signal(signal.SIGTERM, previous)
    (process,) = spawned
    assert process.returncode == -signal.SIGKILL


@posix_only
def test_captured_timeout_stops_the_whole_tree_and_keeps_the_output(
    tmp_path: Path, spawned: List[subprocess.Popen]
) -> None:
    pids = tmp_path / "pids"
    code = """
        import os, subprocess, sys, time
        grandchild = subprocess.Popen(["/bin/sleep", "600"])
        with open(sys.argv[1], "w") as handle:
            handle.write(f"{os.getpid()} {grandchild.pid}")
        print("partial", os.environ["TOKEN"], flush=True)
        time.sleep(600)
    """
    deadline = time.monotonic() + PATIENCE
    # The limit must outlast the child's start-up. On a busy machine that can take a while, so try longer ones.
    for limit in (3.0, 10.0, 40.0):
        if pids.exists():
            pids.unlink()
        with pytest.raises(CommandTimeoutError) as caught:
            run_captured(python(code, str(pids)), {"TOKEN": SECRET}, timeout=limit)
        result = caught.value.result
        assert isinstance(result, RunResult) and result.code == 124
        if result.stdout:
            break
    assert result.stdout == "partial [irondome:TOKEN]\n" and not result.truncated
    child, grandchild = (int(pid) for pid in pids.read_text().split())
    process = spawned[-1]
    assert process.pid == child and process.returncode is not None
    assert _gone(grandchild, deadline), "what the command started must not outlive its time limit"


def test_a_cancelled_capture_stops_the_whole_tree(tmp_path: Path, spawned: List[subprocess.Popen]) -> None:
    """An MCP client that cancels a call must not leave the command, or what it started, running."""
    pids = tmp_path / "pids"
    code = """
        import os, subprocess, sys, time
        grandchild = subprocess.Popen(["/bin/sleep", "600"])
        with open(sys.argv[1] + ".part", "w") as handle:
            handle.write(f"{os.getpid()} {grandchild.pid}")
        os.rename(sys.argv[1] + ".part", sys.argv[1])
        time.sleep(600)
    """
    deadline = time.monotonic() + PATIENCE
    with pytest.raises(CommandCancelledError):
        run_captured(python(code, str(pids)), {"TOKEN": SECRET}, timeout=None, cancelled=pids.exists)
    child, grandchild = (int(pid) for pid in pids.read_text().split())
    process = spawned[-1]
    assert process.pid == child and process.returncode is not None
    assert _gone(grandchild, deadline), "what a cancelled command started must not outlive it"


def test_a_capture_that_is_never_cancelled_runs_to_its_end() -> None:
    result = run_captured(python("print('done')"), {}, cancelled=lambda: False)
    assert result.code == 0 and result.stdout == "done\n"


def _gone(pid: int, deadline: float) -> bool:
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return True  # the number was reused by someone else's process
        time.sleep(0.05)
    return False


def test_a_limit_longer_than_the_system_can_wait_is_waited_in_slices(monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_command(python("pass"), {}, timeout=1e15) == 0  # 31 million years: must not overflow anything
    monkeypatch.setattr(runner, "_WAIT_SLICE", 0.05)
    nap = python("import time; time.sleep(0.4); print('slept')")
    assert run_captured(nap, {}, timeout=PATIENCE).stdout == "slept\n"
    with pytest.raises(CommandTimeoutError):
        run_captured(python("import time; time.sleep(600)"), {}, timeout=0.3)


# ---------------------------------------------------------------------------
# Processes the command leaves behind
# ---------------------------------------------------------------------------

LEAVE_A_SLEEPER = """
    import subprocess, sys
    sleeper = subprocess.Popen(["/bin/sleep", "600"])  # inherits our stdout and stderr and keeps them open
    print("sleeper", sleeper.pid, flush=True)
    sys.exit(5)
"""


@posix_only
@pytest.mark.parametrize("selectable", [True, False])
def test_a_background_process_holding_the_pipe_does_not_hang_the_run(
    selectable: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "_DRAIN_GRACE", 0.3)
    monkeypatch.setattr(runner, "_SELECTABLE_PIPES", selectable)
    began = time.monotonic()
    result = run_captured(python(LEAVE_A_SLEEPER), {"TOKEN": SECRET}, timeout=PATIENCE)
    elapsed = time.monotonic() - began
    sleeper = int(result.stdout.split()[1])
    try:
        assert result.code == 5
        assert elapsed < PATIENCE / 2, "the run must end with the command, not with what it left behind"
        os.kill(sleeper, 0)  # still there: only its output is given up on
    finally:
        os.kill(sleeper, signal.SIGKILL)


@posix_only
def test_a_background_process_flooding_the_pipe_does_not_hang_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner, "_DRAIN_GRACE", 0.3)
    monkeypatch.setattr(runner, "_DRAIN_BYTES", 256 * 1024)
    code = """
        import subprocess, sys
        flood = subprocess.Popen(["/usr/bin/yes", "flooding"], stderr=subprocess.DEVNULL)
        print(flood.pid, file=sys.stderr, flush=True)
    """
    began = time.monotonic()
    result = run_captured(python(code), {"TOKEN": SECRET}, timeout=PATIENCE, max_bytes=4096)
    elapsed = time.monotonic() - began
    flood = int(result.stderr)
    try:
        assert result.code == 0 and result.truncated
        assert elapsed < PATIENCE / 2
    finally:
        try:
            os.kill(flood, signal.SIGKILL)
        except ProcessLookupError:
            pass  # it already died of the closed pipe


@posix_only
def test_the_fallback_for_pipes_that_cannot_be_selected(monkeypatch: pytest.MonkeyPatch,
                                                         capfd: pytest.CaptureFixture) -> None:
    # Windows cannot wait on a pipe; the blocking code path is exercised here so that it is not untested.
    monkeypatch.setattr(runner, "_SELECTABLE_PIPES", False)
    assert run_command(python(PRINT_SECRET, "3"), {"TOKEN": SECRET}, timeout=PATIENCE) == 3
    captured = capfd.readouterr()
    assert (captured.out, captured.err) == ("out: [irondome:TOKEN]\n", "err: [irondome:TOKEN]\n")
    shout = python("import sys; print(sys.stdin.read().upper())")
    assert run_captured(shout, {}, stdin=b"piped in", timeout=PATIENCE).stdout == "PIPED IN\n"


def test_the_wait_for_the_command_is_never_one_unbounded_wait():
    """A signal that arrives just as a blocking wait starts is noted but interrupts nothing. With no limit on
    its wait the runner would then sit on SIGTERM until the command ended by itself; it waits in bounded
    slices, and Python acts on the signal between them."""

    class Slow:
        def __init__(self) -> None:
            self.limits: List[Optional[float]] = []

        def wait(self, timeout: Optional[float] = None) -> int:
            self.limits.append(timeout)
            if len(self.limits) < 3:
                raise subprocess.TimeoutExpired("command", timeout or 0)
            return 7

    process = Slow()
    assert runner._wait(process, None) == 7  # type: ignore[arg-type]
    assert len(process.limits) == 3 and all(limit is not None and 0 < limit <= 1.0 for limit in process.limits)


@posix_only
def test_the_threads_that_carry_the_streams_cannot_be_handed_a_signal_that_ends_the_program():
    """They start with SIGINT, SIGTERM, SIGHUP and SIGQUIT blocked, so the system hands those to the main
    thread, whose wait they interrupt; the main thread's own mask is put back."""
    seen = []
    before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    blocked = runner._block_ending_signals()
    try:
        thread = threading.Thread(target=lambda: seen.append(signal.pthread_sigmask(signal.SIG_BLOCK, [])))
        thread.start()
        thread.join()
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
    assert blocked == before and signal.pthread_sigmask(signal.SIG_BLOCK, []) == before
    assert {signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT} <= seen[0]


# ---------------------------------------------------------------------------
# Signals, through a real wrapper process
# ---------------------------------------------------------------------------

WRAPPER = """
import signal, sys
from irondome.agent import runner
# Start from the usual dispositions, however this test run itself was started.
signal.signal(signal.SIGINT, signal.default_int_handler)
signal.signal(signal.SIGTERM, signal.SIG_DFL)
signal.signal(signal.SIGHUP, signal.SIG_DFL)
sys.exit(runner.run_command(sys.argv[3:], {"TOKEN": sys.argv[1]}, mask=sys.argv[2] == "mask"))
"""

COUNT_SIGNALS = """
    import os, signal, sys, time
    seen = []
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, lambda signum, frame: seen.append(signum))
    print("child-ready", os.environ["TOKEN"], flush=True)
    deadline = time.time() + 100
    while not seen and time.time() < deadline:
        time.sleep(0.02)
    time.sleep(1.5)  # a second copy of the signal would arrive in this window
    print("signals", ",".join(str(number) for number in seen), flush=True)
    sys.exit(40 + len(seen))
"""


def wrapper(command: List[str], secret: str = SECRET, mask: bool = True) -> List[str]:
    """`irondome run` in miniature: a separate process that calls run_command on *command*."""
    return [sys.executable, "-c", WRAPPER, secret, "mask" if mask else "plain", *command]


def lines_until(stream, marker: bytes) -> Iterator[bytes]:
    deadline = time.monotonic() + PATIENCE
    while time.monotonic() < deadline:
        line = stream.readline()
        if not line:
            raise AssertionError(f"the stream ended before {marker!r}")
        yield line
        if marker in line:
            return
    raise AssertionError(f"timed out waiting for {marker!r}")


@posix_only
@pytest.mark.parametrize("name", ["SIGTERM", "SIGINT", "SIGHUP"])
def test_signals_sent_to_the_runner_reach_the_child_once(name: str) -> None:
    number = int(getattr(signal, name))
    # A session of its own: no terminal could have delivered the signal to the child, so the runner must.
    process = subprocess.Popen(
        wrapper(python(COUNT_SIGNALS)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    )
    try:
        ready = list(lines_until(process.stdout, b"child-ready"))
        assert ready[-1] == b"child-ready [irondome:TOKEN]\n"
        os.kill(process.pid, number)
        out, err = process.communicate(timeout=PATIENCE)
    finally:
        process.kill()
        process.wait()
    assert out == f"signals {number}\n".encode(), err
    assert process.returncode == 41, "the child handled the signal and chose its own exit status"


@posix_only
@pytest.mark.parametrize(("name", "status"), [("SIGTERM", 143), ("SIGINT", 130), ("SIGHUP", 129)])
def test_a_child_that_dies_of_the_relayed_signal_gives_128_plus_the_signal(name: str, status: int) -> None:
    number = int(getattr(signal, name))
    child = ["/bin/sh", "-c", "echo child-ready; exec sleep 600"]
    process = subprocess.Popen(wrapper(child), stdout=subprocess.PIPE, start_new_session=True)
    try:
        list(lines_until(process.stdout, b"child-ready"))
        os.kill(process.pid, number)
        assert process.wait(PATIENCE) == status
    finally:
        process.kill()
        process.wait()


def in_a_terminal(argv: List[str], on_ready) -> Tuple[bytes, int]:
    """Run *argv* as the foreground job of a new pseudo-terminal; call on_ready(master, pid) at "child-ready"."""
    import pty  # POSIX only, like every test that gets here

    pid, master = pty.fork()
    if pid == 0:
        try:
            os.execv(argv[0], argv)  # noqa: S606 - the test interpreter itself, no shell involved
        finally:
            os._exit(127)
    output = b""
    told = False
    deadline = time.monotonic() + PATIENCE
    try:
        while time.monotonic() < deadline:
            if not select.select([master], [], [], 0.2)[0]:
                continue
            try:
                data = os.read(master, 4096)
            except OSError:
                break  # Linux reports the closed terminal as an error, macOS as end of file
            if not data:
                break
            output += data
            if not told and b"child-ready" in output:
                told = True
                on_ready(master, pid)
        else:
            os.kill(pid, signal.SIGKILL)
    finally:
        os.close(master)
    return output, os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])


@posix_only
@pytest.mark.parametrize("mask", [True, False])
def test_ctrl_c_in_a_terminal_reaches_the_child_exactly_once(mask: bool) -> None:
    # The terminal sends SIGINT to the whole foreground group: the runner and the child both get it.
    # Relaying it as well would deliver it twice, which many programs take as "abort immediately".
    output, status = in_a_terminal(
        wrapper(python(COUNT_SIGNALS), mask=mask), lambda master, pid: os.write(master, b"\x03")
    )
    assert (b"child-ready [irondome:TOKEN]" if mask else b"child-ready " + SECRET.encode()) in output
    assert b"signals 2\r\n" in output, output
    assert status == 41


@posix_only
@pytest.mark.parametrize("mask", [True, False])
def test_the_child_reads_the_terminal_it_inherited(mask: bool) -> None:
    child = python(
        """
        import os
        print("child-ready", flush=True)
        print("typed:", input(), os.environ["TOKEN"], flush=True)
        """
    )
    output, status = in_a_terminal(wrapper(child, mask=mask), lambda master, pid: os.write(master, b"a line\n"))
    assert (b"typed: a line [irondome:TOKEN]" if mask else b"typed: a line " + SECRET.encode()) in output
    assert status == 0


@posix_only
def test_sigterm_in_a_terminal_is_still_relayed() -> None:
    output, status = in_a_terminal(
        wrapper(python(COUNT_SIGNALS)), lambda master, pid: os.kill(pid, signal.SIGTERM)
    )
    assert b"signals 15\r\n" in output, output
    assert status == 41


@posix_only
def test_a_signal_that_arrives_before_the_child_exists_is_delivered_to_it() -> None:
    if signal.getsignal(signal.SIGTERM) != signal.SIG_DFL:
        pytest.skip("this test run does not have the default SIGTERM disposition")
    with runner._Relay(cancel=False) as relay:
        os.kill(os.getpid(), signal.SIGTERM)  # caught by the relay: there is no child to pass it to yet
        child = subprocess.Popen(["/bin/sleep", "600"])
        try:
            assert child.poll() is None
            relay.attach(child)
            assert child.wait(PATIENCE) == -signal.SIGTERM
        finally:
            child.kill()
            child.wait()
    assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL


@posix_only
def test_an_early_signal_cancels_a_captured_command_and_then_takes_its_usual_course() -> None:
    if signal.getsignal(signal.SIGINT) is not signal.default_int_handler:
        pytest.skip("this test run does not have Python's usual SIGINT handler")
    child = None
    try:
        with pytest.raises(KeyboardInterrupt):
            with runner._Relay(cancel=True) as relay:
                os.kill(os.getpid(), signal.SIGINT)
                child = subprocess.Popen(["/bin/sleep", "600"], start_new_session=True)
                relay.attach(child)
        assert child is not None and child.wait(PATIENCE) == -signal.SIGKILL
    finally:
        if child is not None:
            child.kill()
            child.wait()
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


def test_a_failure_while_masking_is_raised_and_does_not_leave_the_child_blocked(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture
) -> None:
    def broken(self: Masker, chunk: bytes) -> bytes:
        raise RuntimeError("masking failed")

    monkeypatch.setattr(Masker, "feed", broken)
    flood = python("import sys\nfor _ in range(2000): sys.stdout.write('x' * 1000)")
    began = time.monotonic()
    with pytest.raises(RuntimeError, match="masking failed"):
        run_command(flood, {"TOKEN": SECRET}, timeout=PATIENCE)
    assert time.monotonic() - began < PATIENCE / 2
    assert "x" not in capfd.readouterr().out, "nothing unmasked may be written when the filter breaks"


@posix_only
def test_a_closed_destination_ends_the_run_instead_of_hanging_it() -> None:
    # `irondome run -- yes | head -1`: when nobody reads any more, the child must be told (SIGPIPE).
    process = subprocess.Popen(wrapper(["/usr/bin/yes", SECRET]), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        assert process.stdout is not None
        assert process.stdout.readline() == b"[irondome:TOKEN]\n"
        process.stdout.close()
        assert process.wait(PATIENCE) == 128 + signal.SIGPIPE
    finally:
        process.kill()
        process.wait()


@posix_only
@pytest.mark.parametrize("name", ["SIGTERM", "SIGHUP", "SIGINT", "SIGQUIT"])
def test_killing_a_host_that_captures_takes_the_command_with_it(name: str, tmp_path: Path) -> None:
    # An MCP server shut down in the middle of a tool call must not leave the agent's command running.
    number = int(getattr(signal, name))
    pids = tmp_path / "pids"
    host = """
import resource, signal, sys
from irondome.agent import runner
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
    signal.signal(number, signal.SIG_DFL)
signal.signal(signal.SIGINT, signal.default_int_handler)
runner.run_captured(sys.argv[1:], {"TOKEN": "hunter2-Github!"}, timeout=600)
"""
    child = python(
        """
        import os, subprocess, sys, time
        grandchild = subprocess.Popen(["/bin/sleep", "600"])
        with open(sys.argv[1] + ".tmp", "w") as handle:
            handle.write(f"{os.getpid()} {grandchild.pid}")
        os.rename(sys.argv[1] + ".tmp", sys.argv[1])
        time.sleep(600)
        """,
        str(pids),
    )
    process = subprocess.Popen(
        [sys.executable, "-c", host, *child], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + PATIENCE
    try:
        while not pids.exists():
            assert time.monotonic() < deadline and process.poll() is None
            time.sleep(0.05)
        os.kill(process.pid, number)
        assert process.wait(PATIENCE) == -number, "the host still ends the way that signal ends it"
        for pid in (int(pid) for pid in pids.read_text().split()):
            assert _gone(pid, deadline)
    finally:
        process.kill()
        process.wait()


# ---------------------------------------------------------------------------
# run_captured
# ---------------------------------------------------------------------------


def test_run_captured_returns_masked_text() -> None:
    result = run_captured(python(PRINT_SECRET, "9"), {"TOKEN": SECRET}, timeout=PATIENCE)
    assert result == RunResult(code=9, stdout="out: [irondome:TOKEN]\n", stderr="err: [irondome:TOKEN]\n",
                               truncated=False)


def test_run_captured_never_reads_this_process_input_and_feeds_what_it_is_given() -> None:
    echo = python("import sys; data = sys.stdin.buffer.read(); print(len(data), data[:20])")
    assert run_captured(echo, {}, timeout=PATIENCE).stdout == "0 b''\n"
    assert run_captured(echo, {}, stdin=b"", timeout=PATIENCE).stdout == "0 b''\n"
    assert run_captured(echo, {}, stdin=b"hello\n", timeout=PATIENCE).stdout == "6 b'hello\\n'\n"
    assert run_captured(echo, {}, stdin=bytearray(b"abc"), timeout=PATIENCE).stdout == "3 b'abc'\n"
    big = bytes(range(256)) * 4096  # 1 MiB: far more than a pipe holds
    assert run_captured(echo, {}, stdin=big, timeout=PATIENCE).stdout.startswith(f"{len(big)} ")
    with pytest.raises(UsageError):
        run_captured(echo, {}, stdin="text")  # type: ignore[arg-type]


def test_run_captured_survives_a_child_that_never_reads_its_input() -> None:
    big = b"x" * (4 * 1024 * 1024)
    assert run_captured(python("print('done')"), {}, stdin=big, timeout=PATIENCE).stdout == "done\n"
    closes = python("import os, time; os.close(0); time.sleep(0.2); print('closed it')")
    assert run_captured(closes, {}, stdin=big, timeout=PATIENCE).stdout == "closed it\n"


def test_run_captured_truncates_each_stream_and_says_so() -> None:
    code = """
        import os, sys
        sys.stdout.write("o" * int(sys.argv[1])); sys.stderr.write("e" * int(sys.argv[2]))
    """
    result = run_captured(python(code, "5000", "10"), {}, max_bytes=1000, timeout=PATIENCE)
    assert (result.stdout, result.stderr, result.truncated) == ("o" * 1000, "e" * 10, True)
    result = run_captured(python(code, "10", "5000"), {}, max_bytes=1000, timeout=PATIENCE)
    assert (result.stdout, result.stderr, result.truncated) == ("o" * 10, "e" * 1000, True)
    result = run_captured(python(code, "1000", "1000"), {}, max_bytes=1000, timeout=PATIENCE)
    assert (len(result.stdout), len(result.stderr), result.truncated) == (1000, 1000, False)
    result = run_captured(python(code, "1", "0"), {}, max_bytes=0, timeout=PATIENCE)
    assert (result.stdout, result.stderr, result.truncated) == ("", "", True)
    result = run_captured(python(code, "0", "0"), {}, max_bytes=0, timeout=PATIENCE)
    assert (result.stdout, result.stderr, result.truncated) == ("", "", False)
    # Past the limit the child is still read to the end, so it never blocks on a full pipe.
    result = run_captured(python(code, str(3 * 1024 * 1024), "0"), {}, max_bytes=10, timeout=PATIENCE)
    assert (result.code, result.stdout, result.truncated) == (0, "o" * 10, True)


def test_run_captured_default_limit_is_200_000_bytes() -> None:
    result = run_captured(python("import sys; sys.stdout.write('x' * 200_001)"), {}, timeout=PATIENCE)
    assert len(result.stdout) == 200_000 and result.truncated


def test_truncation_applies_to_the_masked_output_and_never_exposes_a_secret() -> None:
    stream = b"ab" + SECRET.encode() * 5 + b"cd"
    masked = b"ab" + MARK * 5 + b"cd"
    for limit in range(len(masked) + 3):
        for size in (1, 7, len(stream)):
            capture = runner._Capture(Masker({"TOKEN": SECRET}), limit)
            for position in range(0, len(stream), size):
                assert capture.consume(stream[position : position + size]) is True
            capture.finish()
            assert capture.text() == masked[:limit].decode()
            assert capture.truncated == (limit < len(masked))
    code = "import os, sys; sys.stdout.write('ab' + os.environ['TOKEN'] * 50)"
    for limit in (9, 17, 18, 19):
        result = run_captured(python(code), {"TOKEN": SECRET}, max_bytes=limit, timeout=PATIENCE)
        assert result.stdout == ("ab" + "[irondome:TOKEN]" * 50)[:limit] and result.truncated


def test_run_captured_decodes_with_replacement_and_does_not_garble_a_cut_character() -> None:
    code = "import sys; sys.stdout.buffer.write(b'ok \\xff\\xfe ' + '€'.encode() * 4)"
    assert run_captured(python(code), {}, timeout=PATIENCE).stdout == "ok \ufffd\ufffd €€€€"
    # 3 bytes of "ok ", 2 invalid, 1 space, then three-byte characters: a limit of 8 cuts one in half.
    cut = run_captured(python(code), {}, max_bytes=8, timeout=PATIENCE)
    assert cut.stdout == "ok \ufffd\ufffd " and cut.truncated


@pytest.mark.parametrize("max_bytes", [-1, 1.5, "100", None, True])
def test_run_captured_rejects_an_unusable_limit(max_bytes: object) -> None:
    with pytest.raises(UsageError):
        run_captured(python("pass"), {}, max_bytes=max_bytes)  # type: ignore[arg-type]


@posix_only
def test_run_captured_child_has_no_terminal_and_its_own_session() -> None:
    code = """
        import os
        try:
            os.close(os.open("/dev/tty", os.O_RDWR))
            terminal = True
        except OSError:
            terminal = False
        print(terminal, os.getsid(0) == os.getpid(), os.getpgrp() == os.getpid())
    """
    assert run_captured(python(code), {}, timeout=PATIENCE).stdout == "False True True\n"


def test_run_captured_from_a_thread_without_signal_handlers() -> None:
    results: List[RunResult] = []
    worker = threading.Thread(
        target=lambda: results.append(run_captured(python(PRINT_SECRET, "0"), {"TOKEN": SECRET}, timeout=PATIENCE))
    )
    worker.start()
    worker.join(PATIENCE)
    assert results and results[0].stdout == "out: [irondome:TOKEN]\n"


def test_run_captured_from_several_threads_at_once() -> None:
    results: Dict[int, List[RunResult]] = {}

    def work(number: int) -> None:
        secret = f"secret-number-{number}-{number * 7919}"
        code = "import os, sys; print(sys.argv[1], os.environ['TOKEN']); print(os.environ['TOKEN'])"
        command = python(code, str(number))
        results[number] = [run_captured(command, {"TOKEN": secret}, timeout=PATIENCE) for _ in range(2)]

    workers = [threading.Thread(target=work, args=(number,)) for number in range(6)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(PATIENCE)
    assert sorted(results) == list(range(6))
    for number, pair in results.items():
        for result in pair:
            assert result == RunResult(0, f"{number} [irondome:TOKEN]\n[irondome:TOKEN]\n", "", False)


def test_signal_handlers_are_put_back(capfd: pytest.CaptureFixture) -> None:
    before = (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM))
    run_command(python("pass"), {"TOKEN": SECRET}, timeout=PATIENCE)
    run_captured(python("pass"), {"TOKEN": SECRET}, timeout=PATIENCE)
    with pytest.raises(CommandNotFoundError):
        run_command(["irondome-no-such-command-xyz"], {})
    assert (signal.getsignal(signal.SIGINT), signal.getsignal(signal.SIGTERM)) == before


def test_nothing_is_left_open_after_a_run() -> None:
    def open_descriptors() -> int:
        count = 0
        for descriptor in range(256):
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            count += 1
        return count

    run_captured(python("pass"), {"TOKEN": SECRET}, timeout=PATIENCE)  # warm up whatever opens lazily
    before = open_descriptors()
    for _ in range(3):
        run_captured(python("print('x')"), {"TOKEN": SECRET}, stdin=b"abc", timeout=PATIENCE)
        run_command(python("pass"), {"TOKEN": SECRET}, timeout=PATIENCE)
        with pytest.raises(CommandNotFoundError):
            run_captured(["irondome-no-such-command-xyz"], {})
    assert open_descriptors() == before


# ---------------------------------------------------------------------------
# The whole path: plan, resolve from a vault, run
# ---------------------------------------------------------------------------


def test_plan_resolve_run_with_a_real_vault(vault, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH", "irondome://GITHUB_TOKEN")
    monkeypatch.setenv("IRONDOME_SESSION", "ird_s1_session-token-value")
    env_file = refs.parse_env_file(
        "NODE_ENV=production\nAWS_KEY=irondome://aws%2Fprod\nREGION=irondome://aws%2Fprod/region\n"
    )
    plan = refs.plan_injection(os.environ, env_file, ["GITHUB_TOKEN"])

    def lookup(reference: str) -> str:
        entry, field = vault.resolve(reference)
        return vault.value(entry, field)

    secrets = refs.resolve_plan(plan, lookup)
    assert Masker(secrets).unmasked_names == []
    code = """
        import json, os
        print(json.dumps({name: os.environ.get(name) for name in
                          ("GH", "GITHUB_TOKEN", "AWS_KEY", "REGION", "NODE_ENV", "IRONDOME_SESSION")}))
    """
    result = run_captured(python(code), secrets, literals=plan.literals, timeout=PATIENCE)
    assert json.loads(result.stdout) == {
        "GH": "[irondome:GH]",
        "GITHUB_TOKEN": "[irondome:GH]",  # the same value: the first name in sorted order labels it
        "AWS_KEY": "[irondome:AWS_KEY]",
        "REGION": "[irondome:REGION]",
        "NODE_ENV": "production",
        "IRONDOME_SESSION": None,
    }
    for value in ("hunter2-Github!", "AKIA-not-a-real-key", "eu-west-1", "session-token-value"):
        assert value not in result.stdout and value not in result.stderr


def test_public_names() -> None:
    assert set(runner.__all__) == {
        "MIN_MASK_BYTES", "MIN_LINE_BYTES", "MIN_ENCODED_BYTES", "CommandNotFoundError", "CommandNotExecutableError",
        "CommandTimeoutError", "CommandCancelledError", "RunResult", "Masker", "secret_patterns", "run_command",
        "run_captured", "locate_command",
    }
    assert (CommandNotFoundError.exit_code, CommandNotExecutableError.exit_code, CommandTimeoutError.exit_code) == (
        127, 126, 124,
    )
    assert CommandCancelledError.exit_code == 130


# -- encodings a second person got past the mask with, by hand, on the final build ----------------------


def test_patterns_cover_the_other_json_csv_percent_and_hex_writers() -> None:
    value = 'p@ss/w0rd+x&y=1<z>"q" ~end'
    raw = value.encode()
    patterns = {pattern for _, pattern in runner.secret_patterns(value)}
    # Go's encoding/json writes &, < and > as \u escapes (its documentation: "so that the JSON will be safe to
    # embed inside HTML"); PHP's json_encode writes "/" as "\/" unless JSON_UNESCAPED_SLASHES is given.
    assert b'p@ss/w0rd+x\\u0026y=1\\u003cz\\u003e\\"q\\" ~end' in patterns
    assert b'p@ss\\/w0rd+x&y=1<z>\\"q\\" ~end' in patterns
    assert value.replace('"', '""').encode() in patterns  # a CSV field
    once = urllib.parse.quote(value, safe="")
    assert urllib.parse.quote(once, safe="").encode() in patterns  # a URL inside a URL
    assert lower_escapes(once).replace(b"%", b"%25") in patterns
    for separator in (":", " ", "-"):
        assert raw.hex(separator).encode() in patterns and raw.hex(separator).upper().encode() in patterns
    masker = runner.Masker({"S": value})
    shown = masker.feed(b'{"k":"p@ss/w0rd+x\\u0026y=1\\u003cz\\u003e\\"q\\" ~end"}\n') + masker.flush()
    assert shown == b'{"k":"[irondome:S]"}\n'


def test_a_quote_written_twice_is_a_pattern() -> None:
    patterns = {pattern for _, pattern in runner.secret_patterns("it's \"the\" secret")}
    assert b"it''s \"the\" secret" in patterns and b"it's \"\"the\"\" secret" in patterns


@pytest.mark.skipif(not os.path.exists("/bin/bash"), reason="needs bash")
@pytest.mark.parametrize(
    "value",
    [
        "47rCE6q-Tx012DR*FijL",
        "#lead ~tilde:~x=~y$z",
        "a b'c\"d\\e!f&g(h)i;j<k>l?m[n]o^p`q{r|s}t,u",
        "~start#mid%done@x+y-z.w/v:u=t",
        "plainlettersanddigits0123",
    ],
)
def test_what_bash_printf_q_writes_is_a_pattern(value: str) -> None:
    """Asked of the bash on this machine: 3.2 on a Mac, 5.x on Linux; they differ about ``~``."""
    ran = subprocess.run(
        ["/bin/bash", "-c", 'printf "%q\\n%q\\n" "$1" "X=$1"', "bash", value], capture_output=True, timeout=30
    )
    whole, inside = ran.stdout.splitlines()
    patterns = {pattern for label, pattern in runner.secret_patterns(value) if label in ("shell", "plain")}
    assert whole in patterns, whole
    assert inside[:2] == b"X=" and inside[2:] in patterns, inside
    masker = runner.Masker({"S": value})
    assert masker.feed(ran.stdout) + masker.flush() == b"[irondome:S]\nX=[irondome:S]\n"


def test_a_value_with_a_control_character_gets_no_bash_form() -> None:
    """bash writes such a value as ``$'...'``, another style: said in the claim, not pretended here."""
    assert runner._bash_quoted("tab\there") == []
