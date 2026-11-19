"""cli.output: durations are ASCII and bounded, NO_COLOR follows no-color.org, and a failure under --json is
a document."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
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


# ---------------------------------------------------------------------------
# Two forms: plain for a pipe, a file, a script; laid out for a person at a terminal
# ---------------------------------------------------------------------------

ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
LONG = (
    "the recovery key opens a copy of this vault on any machine, without this device and without "
    "the master password. Keep it offline (on paper, not in a file or a photo)."
)


class Screen(Terminal):
    """A terminal that can show the marks and rules: its encoding has them."""

    encoding = "utf-8"  # type: ignore[assignment]


def _bare(text: str) -> str:
    return ESCAPE.sub("", text)


def _everything(out: Output) -> None:
    out.info("Checking for Touch ID...")
    out.ok("created the vault of bunker alpha")
    out.warn(LONG)
    out.error("wrong master password")
    out.table(("kind", "device key"), [("password", "present"), ("recovery", "-")])
    out.pairs([("bunker", "alpha"), ("sessions", "0 active")])
    out.finding("ok", "vault", "bunker alpha has a readable vault", None)
    out.finding("problem", "device-keys", "one is damaged", "irondome recovery use")
    out.framed("AAAA-BBBB")


PLAIN_ERR = (
    "Checking for Touch ID...\n"
    "ok  created the vault of bunker alpha\n"
    f"warning  {LONG}\n"
    "error  wrong master password\n"
)
PLAIN_OUT = (
    "KIND      DEVICE KEY\n"
    "password  present\n"
    "recovery  -\n"
    "bunker    alpha\n"
    "sessions  0 active\n"
    "ok       vault: bunker alpha has a readable vault\n"
    "problem  device-keys: one is damaged\n"
    "         fix: irondome recovery use\n"
    "AAAA-BBBB"
)


def test_the_plain_form_is_one_line_per_message_and_a_word_in_front() -> None:
    stdout, stderr = io.StringIO(), io.StringIO()
    _everything(Output(stdout=stdout, stderr=stderr))
    assert stderr.getvalue() == PLAIN_ERR
    assert stdout.getvalue() == PLAIN_OUT


@pytest.mark.parametrize("how", ["flag", "NO_COLOR", "TERM"])
def test_a_terminal_that_may_not_be_coloured_gets_the_plain_form_layout_included(
    how: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLUMNS", "60")
    if how == "NO_COLOR":
        monkeypatch.setenv("NO_COLOR", "1")
    if how == "TERM":
        monkeypatch.setenv("TERM", "dumb")
    stdout, stderr = Screen(), Screen()
    _everything(Output(stdout=stdout, stderr=stderr, color=False if how == "flag" else None))
    assert stderr.getvalue() == PLAIN_ERR
    assert stdout.getvalue() == PLAIN_OUT + "\n"  # a terminal gets the line break after a value


@pytest.fixture()
def screen(monkeypatch: pytest.MonkeyPatch) -> Output:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLUMNS", "60")
    return Output(stdout=Screen(), stderr=Screen())


def _said(out: Output) -> str:
    return out.stderr.getvalue()  # type: ignore[attr-defined, no-any-return]


def _printed(out: Output) -> str:
    return out.stdout.getvalue()  # type: ignore[attr-defined, no-any-return]


def test_laid_out_a_warning_is_wrapped_under_its_mark_and_stands_apart(screen: Output) -> None:
    screen.ok("created the vault of bunker alpha")
    screen.warn(LONG)
    screen.info("Next comes this.")
    lines = _bare(_said(screen)).split("\n")
    assert lines[0] == "✓ created the vault of bunker alpha"
    assert lines[1] == ""  # an empty line before the warning ...
    assert lines[2].startswith("! the recovery key opens a copy of this vault")
    warning = lines[2 : lines.index("", 2)]
    assert len(warning) > 1 and all(line.startswith("  ") for line in warning[1:])
    assert all(len(line) <= 60 for line in warning)
    assert " ".join(line.strip() for line in warning) == "! " + LONG  # nothing lost, nothing added
    assert lines[lines.index("", 2) + 1] == "Next comes this."  # ... and one after it
    assert "\x1b[33;1m!\x1b[0m" in _said(screen)


def test_laid_out_two_warnings_have_one_empty_line_between_them_and_none_first(screen: Output) -> None:
    screen.warn("first")
    screen.warn("second")
    assert _bare(_said(screen)) == "! first\n\n! second\n"


def test_laid_out_an_error_is_bold_after_a_red_mark_and_progress_is_faint(screen: Output) -> None:
    screen.info("Checking for Touch ID...")
    screen.error("wrong master password")
    progress, error = _said(screen).rstrip("\n").split("\n")
    assert progress == "\x1b[2mChecking for Touch ID...\x1b[22m"
    assert error == "\x1b[31;1m✗\x1b[0m \x1b[1mwrong master password\x1b[22m"


def test_laid_out_each_line_of_a_message_keeps_its_own_indentation(screen: Output) -> None:
    screen.error(
        "the vault is locked and nothing here can unlock it.\n"
        "  Set IRONDOME_GRANT to a grant token (the owner creates one with: irondome grant create),\n"
        "  or pipe the master password with --password-stdin."
    )
    lines = _bare(_said(screen)).rstrip("\n").split("\n")
    assert lines[0] == "✗ the vault is locked and nothing here can unlock it."
    assert all(line.startswith("    ") for line in lines[1:])  # under the mark, then the two spaces of their own
    assert all(len(line) <= 60 for line in lines)
    assert " ".join(line.strip() for line in lines[1:]) == (
        "Set IRONDOME_GRANT to a grant token (the owner creates one with: irondome grant create), "
        "or pipe the master password with --password-stdin."
    )


def test_laid_out_a_row_of_columns_goes_on_under_its_last_column(screen: Output) -> None:
    screen.info("  1  password  master password + this machine's security chip (the default choice here)")
    first, second = _bare(_said(screen)).rstrip("\n").split("\n")
    assert first.startswith("  1  password  master password")
    assert second.startswith(" " * len("  1  password  ")) and not second.startswith(" " * (len("  1  password  ") + 1))


def test_where_the_terminal_cannot_show_the_marks_the_words_stand_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    out = Output(stdout=Terminal(), stderr=Terminal())  # no encoding: ASCII is all it is known to show
    out.ok("done")
    out.error("no")
    out.framed("AAAA-BBBB")
    out.table(("a",), [("b",)])
    assert _bare(_said(out)) == "ok done\nerror no\n"
    assert _bare(_printed(out)) == "  +-----------+\n  | AAAA-BBBB |\n  +-----------+\nA\n-\nb\n"


COMMANDS = [
    ("Next: irondome add NAME --generate stores a new login.", ["irondome add NAME --generate"]),
    ("irondome rekey moves the vault onto it", ["irondome rekey"]),
    ("the recovery key opens it: irondome recovery use (the chip said no)", ["irondome recovery use"]),
    ("then run: irondome auth touchid.", ["irondome auth touchid"]),
    ("revoke it with: irondome grant revoke 8573dd4e4097", ["irondome grant revoke 8573dd4e4097"]),
    ("allow an entry with: irondome edit NAME --agent use", ["irondome edit NAME --agent use"]),
    ("irondome edit github --agent use lets agents use it", ["irondome edit github --agent use"]),
    ("Make another with: irondome bunker create work", ["irondome bunker create work"]),
    ("it is injected by irondome run, and irondome get refuses", ["irondome run", "irondome get"]),
    ("irondome unlock and use it", ["irondome unlock"]),
    ("run: irondome edit 'my bank' --agent use", ["irondome edit"]),  # a quoted name with a space is not guessed at
    ("run: irondome edit 'bank' --agent use", ["irondome edit 'bank' --agent use"]),
    ("a reference: irondome://NAME is what --env NAME writes", []),
    # found by a reviewer: prose taken for a command, and commands coloured in part
    ("irondome export without --plaintext writes an encrypted file", ["irondome export"]),
    ("prefix every command: irondome --bunker bravo COMMAND", ["irondome --bunker bravo COMMAND"]),
    ("as in: irondome run --env GITHUB_TOKEN -- gh repo list", ["irondome run --env GITHUB_TOKEN -- gh repo list"]),
    ("irondome run -- node server.js, and then nothing", ["irondome run -- node server.js"]),
    ("the alias gh is taken (irondome alias rm gh) by another entry", ["irondome alias rm gh"]),
    (
        "run: IRONDOME_DEVICE_BACKEND=software irondome recovery use",
        ["IRONDOME_DEVICE_BACKEND=software irondome recovery use"],
    ),
    ('allow it with: irondome edit "bank" --agent use', ['irondome edit "bank" --agent use']),
    ("irondome import - reads nothing from a lone dash", ["irondome import"]),
    (
        "irondome grant create DB_URL --uses 3 --label nightly makes one",
        ["irondome grant create DB_URL --uses 3 --label nightly"],
    ),
    ("irondome add NAME --generate stores a new login", ["irondome add NAME --generate"]),
    ("IronDome keeps nothing else; irondome", ["irondome"]),
    ("no command here", []),
]


@pytest.mark.parametrize("text, commands", COMMANDS)
def test_laid_out_the_commands_in_a_message_are_picked_out_and_nothing_else(
    text: str, commands: List[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("COLUMNS", "200")
    out = Output(stdout=Screen(), stderr=Screen())
    out.info(text)
    assert re.findall(r"\x1b\[36m(.*?)\x1b\[39m", _said(out)) == commands
    assert _bare(_said(out)) == text + "\n"


def test_laid_out_a_command_broken_over_two_lines_is_coloured_on_both(screen: Output) -> None:
    command = "irondome run --env GITHUB_TOKEN --env STRIPE_KEY --env DB_URL=prod-db/url --timeout 10m -- ./deploy.sh"
    screen.info(f"Run: {command}")
    lines = _said(screen).rstrip("\n").split("\n")
    assert len(lines) == 2 and lines[0].endswith("\x1b[39m") and lines[1].lstrip(" ").startswith("\x1b[36m")
    assert " ".join(re.findall(r"\x1b\[36m(.*?)\x1b\[39m", _said(screen))) == command


def test_the_two_characters_that_mark_a_command_are_dropped_from_what_is_said(screen: Output) -> None:
    screen.info("the entry \x00x\x01 is read by irondome get")
    assert _said(screen) == "the entry x is read by \x1b[36mirondome get\x1b[39m\n"


def test_every_command_of_the_parser_is_a_word_the_highlighter_knows() -> None:
    from irondome.cli.main import build_parser
    from irondome.cli.output import _COMMAND_WORDS

    found = set()

    def walk(parser: argparse.ArgumentParser) -> None:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, sub in action.choices.items():
                    found.add(name)
                    walk(sub)

    walk(build_parser())
    assert found == set(_COMMAND_WORDS)


def test_every_option_of_the_parser_that_takes_a_value_is_one_the_highlighter_knows() -> None:
    from irondome.cli.main import build_parser
    from irondome.cli.output import _VALUE_OPTIONS

    found = set()

    def walk(parser: argparse.ArgumentParser) -> None:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for sub_parser in action.choices.values():
                    walk(sub_parser)
            elif action.option_strings and action.nargs != 0:
                found.update(action.option_strings)

    walk(build_parser())
    assert found == set(_VALUE_OPTIONS)


@pytest.mark.parametrize(
    "value",
    [
        "tab\tin the middle",
        "ends with spaces   ",
        "   ",
        "two  spaces",
        "correct horse battery staple " * 6,  # a long passphrase: longer than the terminal is wide
        "x" * 300,
    ],
)
def test_laid_out_a_value_in_a_pair_is_shown_exactly_as_it_is(screen: Output, value: str) -> None:
    """``show --reveal`` prints a password in a pair: a wrapped, trimmed or re-spaced one would be another password."""
    screen.pairs([("password", value)])
    assert _bare(_printed(screen)) == f"password  {value}\n"


@pytest.mark.parametrize(
    "value", ["tab\tin a sentence that is long enough to be wrapped by a terminal of sixty columns", "a  b " * 20]
)
def test_laid_out_even_a_pair_that_may_wrap_keeps_a_value_with_odd_spacing_whole(screen: Output, value: str) -> None:
    screen.pairs([("detail", value)], wrap=True)
    assert _bare(_printed(screen)) == f"detail  {value}\n"


def test_laid_out_a_table_shows_a_cell_with_a_line_break_or_a_tab_as_it_is_and_an_empty_row(screen: Output) -> None:
    odd = "a tab\tand words enough to be longer than the room that a terminal of sixty columns leaves here"
    screen.table(("name", "notes"), [("x", odd), ()])
    lines = _bare(_printed(screen)).split("\n")
    assert lines[2] == f"x     {odd}" and lines[3] == ""


def test_the_width_is_columns_then_the_terminal_then_80_and_never_under_40(monkeypatch: pytest.MonkeyPatch) -> None:
    import pty

    parent, child = pty.openpty()  # a terminal that reports no width at all
    try:
        with os.fdopen(os.dup(child), "w") as stream:
            monkeypatch.delenv("COLUMNS", raising=False)
            assert os.get_terminal_size(stream.fileno()).columns == 0
            assert Output._columns(stream) == 80
            monkeypatch.setenv("COLUMNS", "120")
            assert Output._columns(stream) == 120
            monkeypatch.setenv("COLUMNS", "7")
            assert Output._columns(stream) == 40
            monkeypatch.setenv("COLUMNS", "wide")
            assert Output._columns(stream) == 80
    finally:
        os.close(parent)
        os.close(child)

    class Odd(io.StringIO):
        def fileno(self) -> int:
            return "three"  # type: ignore[return-value]

    monkeypatch.delenv("COLUMNS", raising=False)
    assert Output._columns(Odd()) == 80


def test_laid_out_a_terminal_too_narrow_for_the_frame_gets_the_bare_value(
    screen: Output, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COLUMNS", "40")
    screen.framed("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH")
    assert _printed(screen) == "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH\n"


def test_an_escape_sequence_already_in_a_message_does_not_confuse_the_colouring(screen: Output) -> None:
    screen.error("left open \x1b[36m here\n\nand then: irondome status")
    assert _said(screen).count("\x1b[36mirondome status\x1b[39m") == 1
    assert "\x1b[\x1b" not in _said(screen)


def test_laid_out_a_table_is_ruled_its_states_coloured_its_last_column_wrapped(screen: Output) -> None:
    screen.table(
        ("keyslot", "device key", "description"),
        [
            ("6f03", "present", "master password and the device key of this machine, made today"),
            ("5c5e", "DAMAGED", "x"),
        ],
    )
    shown = _printed(screen)
    lines = _bare(shown).rstrip("\n").split("\n")
    assert lines[0].split() == ["KEYSLOT", "DEVICE", "KEY", "DESCRIPTION"]
    assert set(lines[1]) == {"─", " "}
    assert lines[2].startswith("6f03     present     master password and")
    assert lines[3].startswith(" " * len("6f03     present     ")) and lines[3].strip()  # under its own column
    assert all(len(line) <= 60 for line in lines)
    assert "\x1b[32mpresent\x1b[0m" in shown and "\x1b[31;1mDAMAGED\x1b[0m" in shown
    assert " ".join(_bare(shown).split()).count("master password and the device key of this machine, made today") == 1


def test_laid_out_a_pair_with_a_long_value_goes_on_under_the_value(screen: Output) -> None:
    long = "2 (alpha: macos-se (security chip); alpha: macos-se (security chip); bravo: none)"
    screen.pairs([("device keys", long)], wrap=True)
    first, second = _bare(_printed(screen)).rstrip("\n").split("\n")
    assert first.startswith("device keys  2 (alpha:")
    assert second.startswith(" " * len("device keys  ")) and second[len("device keys  ")] != " "
    assert len(first) <= 60 and len(second) <= 60


def test_laid_out_a_value_to_keep_is_framed_and_alone_on_its_line(screen: Output) -> None:
    screen.framed("AAAA-BBBB-CCCC")
    lines = _bare(_printed(screen)).rstrip("\n").split("\n")
    assert lines == ["  ┌────────────────┐", "  │ AAAA-BBBB-CCCC │", "  └────────────────┘"]
    assert "\x1b[1mAAAA-BBBB-CCCC\x1b[22m" in _printed(screen)  # the key itself is one unbroken run of characters


def test_laid_out_a_finding_carries_its_mark_and_names_the_fix(screen: Output) -> None:
    screen.finding("ok", "vault", "bunker alpha has a readable vault", None)
    screen.finding("note", "device-backend", "forced", None)
    screen.finding("problem", "device-keys", "one is damaged", "irondome recovery use")
    lines = _bare(_printed(screen)).rstrip("\n").split("\n")
    assert lines == [
        "✓ vault: bunker alpha has a readable vault",
        "· device-backend: forced",
        "✗ device-keys: one is damaged",
        "  fix: irondome recovery use",
    ]
    assert "\x1b[1mvault\x1b[22m:" in _printed(screen) and "\x1b[36mirondome recovery use\x1b[39m" in _printed(screen)


def test_a_prompt_is_bold_where_colour_is_allowed_and_its_text_stays_in_one_piece(screen: Output) -> None:
    assert screen.prompt("Master password: ") == "\x1b[1mMaster password: \x1b[22m"
    asked = screen.prompt("To read github from bunker alpha:\nMaster password: ")
    assert asked == "To read github from bunker alpha:\n\x1b[1mMaster password: \x1b[22m"
    plain = Output(stdout=io.StringIO(), stderr=io.StringIO(), color=False)
    assert plain.prompt("Master password: ") == "Master password: "


def test_laid_out_prose_never_runs_wider_than_92_columns_however_wide_the_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.setenv("COLUMNS", "250")
    out = Output(stdout=Screen(), stderr=Screen())
    out.warn(LONG * 3)
    assert max(len(line) for line in _bare(_said(out)).split("\n")) <= 92


def test_laid_out_the_device_folder_is_not_broken_at_the_space_in_its_path(screen: Output) -> None:
    folder = "/Users/someone/Library/Application Support/IronDome/device"
    for lead in range(0, 40):  # wherever on the line the path starts
        screen.info("x" * lead + " " + f"the device keys were files in {folder} until now")
    assert _bare(_said(screen)).count(folder) == 40

