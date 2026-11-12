"""cli.output: durations are ASCII and bounded, NO_COLOR follows no-color.org, and a failure under --json is
a document."""

from __future__ import annotations

import io
import json
from typing import List

import pytest

from irondome.cli.output import Output, parse_duration
from irondome.errors import UsageError


class Terminal(io.StringIO):
    """A stream that says it is a terminal, so that Output would colour it."""

    def isatty(self) -> bool:
        return True


class Gone(io.StringIO):
    """A stream whose reader has gone away."""

    def write(self, text: str) -> int:
        raise BrokenPipeError(32, "Broken pipe")


@pytest.mark.parametrize(
    "text, seconds",
    [("90", 90), ("90s", 90), ("15m", 900), ("2h", 7200), ("7d", 604800), (" 15M ", 900), ("0", 0),
     ("999999999999s", 999999999999)],
)
def test_a_duration_is_ascii_digits_and_an_optional_unit(text: str, seconds: int) -> None:
    assert parse_duration(text) == seconds


@pytest.mark.parametrize(
    "text",
    [
        "²",  # superscript two: str.isdigit() says yes, int() raises ValueError
        "³m",
        "¹⁰",
        "①",  # circled one
        "²\x1e",
        "٣",  # Arabic-Indic three: int() reads it as 3
        "١٥m",
        "１５m",  # fullwidth 15
        "1" * 13,
        "1" * 400,  # a float overflows past 308 digits (the time limit of `irondome run`)
        "1" * 5000,  # int() refuses more than 4300 digits on Python 3.11+ (and 3.9.14+, 3.10.7+)
        "",
        "m",
        "-5m",
        "1.5h",
        "5 m",
        "abc",
    ],
)
def test_anything_else_is_a_usage_error_never_a_crash_or_a_number(text: str) -> None:
    with pytest.raises(UsageError, match="is not a duration; use forms like 90s, 15m, 2h or 7d"):
        parse_duration(text)


def test_a_long_non_duration_is_not_echoed_whole() -> None:
    with pytest.raises(UsageError) as caught:
        parse_duration("1" * 5000)
    message = str(caught.value)
    assert "(5000 characters)" in message and len(message) < 120


def test_an_empty_no_color_asks_for_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """https://no-color.org: NO_COLOR disables colour when it is present and not an empty string."""
    monkeypatch.delenv("TERM", raising=False)
    monkeypatch.setenv("NO_COLOR", "")
    assert Output(stderr=Terminal()).style("error", "red", err=True) == "\x1b[31merror\x1b[0m"
    for value in ("1", "0", "false"):
        monkeypatch.setenv("NO_COLOR", value)
        assert Output(stderr=Terminal()).style("error", "red", err=True) == "error"
    monkeypatch.delenv("NO_COLOR")
    assert Output(stderr=Terminal(), color=False).style("error", "red", err=True) == "error"


def streams() -> List[io.StringIO]:
    return [io.StringIO(), io.StringIO()]


def test_a_failure_under_json_is_the_one_document_on_stdout() -> None:
    stdout, stderr = streams()
    Output(json_mode=True, stdout=stdout, stderr=stderr).failure("no entry or alias named 'x'", 3)
    assert json.loads(stdout.getvalue()) == {"ok": False, "error": "no entry or alias named 'x'", "exit_code": 3}
    assert stderr.getvalue() == "error  no entry or alias named 'x'\n"


def test_a_failure_after_the_result_adds_no_second_document() -> None:
    stdout, stderr = streams()
    out = Output(json_mode=True, stdout=stdout, stderr=stderr)
    out.json({"exit_code": 124, "stdout": "", "stderr": "", "truncated": False})
    out.failure("the command was still running after 5 seconds and was stopped", 124)
    assert json.loads(stdout.getvalue())["exit_code"] == 124  # still exactly one document
    assert "still running" in stderr.getvalue()


def test_a_failure_without_json_is_text_on_stderr_only() -> None:
    stdout, stderr = streams()
    Output(stdout=stdout, stderr=stderr).failure("wrong master password", 4)
    assert stdout.getvalue() == "" and stderr.getvalue() == "error  wrong master password\n"


def test_a_failure_with_nobody_listening_does_not_raise() -> None:
    Output(json_mode=True, stdout=Gone(), stderr=Gone()).failure("interrupted", 130)
