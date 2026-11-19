"""cli.main: errors are one line and say what to type instead, they honour --json and --no-color from the very
first argument on, and the bunker's reason is recorded once."""

from __future__ import annotations

import argparse
import errno
import io
import json
import sys
from typing import List, Tuple

import pytest

import irondome
from irondome import caps, paths
from irondome import device as devices
from irondome.cli import cmd_vault, main
from irondome.cli.context import ENV_GRANT, ENV_SESSION
from irondome.errors import UsageError

pytestmark = pytest.mark.usefixtures("isolated")


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> Tuple[int, str, str]:
    code = main.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def failing_status(error: OSError):
    def status(ctx, args):
        raise error

    return status


@pytest.mark.parametrize(
    "error, expected",
    [
        (OSError(errno.ENOSPC, "No space left on device", "/data/irondome/bunkers/alpha/vault.irondome"),
         "/data/irondome/bunkers/alpha/vault.irondome: No space left on device (free some space and run the command "
         "again)"),
        (PermissionError(errno.EACCES, "Permission denied", "/home/k/.irondome"),
         "/home/k/.irondome: Permission denied (check that the directory is yours and writable)"),
        (OSError(errno.EROFS, "Read-only file system", "/ro/.irondome"),
         "/ro/.irondome: Read-only file system (check that the directory is yours and writable)"),
        (OSError(errno.EXDEV, "Invalid cross-device link", "/a/.tmp-1", None, "/b/vault.irondome"),  # as os.replace
         "/a/.tmp-1 -> /b/vault.irondome: Invalid cross-device link"),
        (OSError(errno.EIO, "Input/output error"),
         "IronDome could not write or read one of its files: Input/output error"),
        (OSError(errno.EFBIG, "File too large", "/data/vault.irondome"),
         "/data/vault.irondome: File too large (a limit on file size stopped the write: see ulimit -f, then run the "
         "command again)"),
        (OSError("something odd"), "IronDome could not write or read one of its files: OSError"),
        (OSError(errno.ENOENT, "No such file", "/x/line\nbreak\x1b[2J"), "/x/line\\nbreak\\x1b[2J: No such file"),
    ],
)
def test_an_operating_system_error_is_one_line_with_the_path_and_the_reason(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], error: OSError, expected: str
) -> None:
    monkeypatch.setattr(cmd_vault, "_status", failing_status(error))
    assert main.main(["status"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "Traceback" not in captured.err
    assert captured.err.splitlines() == [f"error  {expected}"]


def test_a_reader_that_went_away_is_still_no_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cmd_vault, "_status", failing_status(BrokenPipeError(errno.EPIPE, "Broken pipe")))
    monkeypatch.setattr(main.sys, "stdout", open(__file__))  # closed by main, as it closes a broken stdout
    assert main.main(["status"]) == 0


def chosen(*argv: str) -> argparse.Namespace:
    args = main.build_parser().parse_args(list(argv))
    main.select_bunker(args)
    return args


def test_select_bunker_records_why(monkeypatch: pytest.MonkeyPatch, make_vault) -> None:
    monkeypatch.delenv(paths.ENV_BUNKER, raising=False)  # select_bunker exports what it chose; undone after the test
    vault, _ = make_vault()
    session = caps.create_session(vault, ttl=300)
    assert chosen("status").bunker_source == "default"
    assert chosen("--bunker", "bravo", "status").bunker_source == "flag"
    monkeypatch.delenv(paths.ENV_BUNKER)
    monkeypatch.setenv(ENV_SESSION, f" {session}\n")
    args = chosen("status")
    assert (args.bunker_source, args.bunker_token) == ("token", ENV_SESSION)
    assert paths.bunker_name() == "alpha"
    # The environment names the very bunker the token belongs to: the reason is the environment, which wins.
    args = chosen("status")
    assert (args.bunker_source, args.bunker_token) == ("environment", None)
    monkeypatch.delenv(paths.ENV_BUNKER)
    monkeypatch.delenv(ENV_SESSION)
    monkeypatch.setenv(ENV_GRANT, "irondome_g_" + "0" * 32 + "_" + "A" * 52)  # a grant no bunker here holds
    assert chosen("status").bunker_source == "default"


# ---------------------------------------------------------------------------
# --json: a failing command prints one document too; --version --json is `version --json`
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv, status, fragment",
    [
        (["get", "nosuchentry", "--json"], 6, "there is no vault in bunker alpha"),  # raised by the command
        (["get", "x", "--json", "--no-such-flag"], 2, "unrecognized arguments: --no-such-flag"),  # after parsing
        (["get", "--json"], 2, "the following arguments are required: REF"),  # in the middle of parsing
        (["--json", "lst"], 2, "invalid choice: 'lst'"),  # before the parser got as far as --json
        (["--json", "--bunker", "NOT A NAME", "status"], 2, "is not a bunker name"),  # by select_bunker
        (["--json", "run", "--timeout", "²", "--", "/usr/bin/true"], 2, "is not a duration"),
    ],
)
def test_under_json_a_failure_is_one_document_on_stdout_and_a_line_on_stderr(
    capsys: pytest.CaptureFixture[str], argv: List[str], status: int, fragment: str
) -> None:
    code, out, err = run(capsys, *argv)
    document = json.loads(out)
    assert code == status and document["ok"] is False and document["exit_code"] == status
    assert fragment in document["error"] and err.startswith(f"error  {document['error'].splitlines()[0]}")


def test_json_after_double_dash_belongs_to_the_command_that_irondome_run_starts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, err = run(capsys, "run", "--bogus", "--", "some-tool", "--json")
    assert code == 2 and out == "" and "unrecognized arguments: --bogus" in err


@pytest.mark.parametrize("argv", [["--version", "--json"], ["--json", "--version"]])
def test_version_with_json_is_the_document_of_irondome_version(
    capsys: pytest.CaptureFixture[str], argv: List[str]
) -> None:
    code, out, _ = run(capsys, *argv)
    assert code == 0 and json.loads(out) == json.loads(run(capsys, "version", "--json")[1])
    assert json.loads(out)["version"] == irondome.__version__


def test_version_alone_is_still_one_line_of_text(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "--version") == (0, f"irondome {irondome.__version__}\n", "")


# ---------------------------------------------------------------------------
# A duration that is not one is a usage error, never a traceback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("timeout", ["²", "٣", "1" * 400, "1" * 5000])
def test_run_timeout_that_is_not_a_duration_is_a_usage_error(capsys: pytest.CaptureFixture[str], timeout: str) -> None:
    code, out, err = run(capsys, "run", "--timeout", timeout, "--", "/usr/bin/true")
    assert code == 2 and out == "" and "Traceback" not in err
    assert err.splitlines()[0].startswith("error  ") and "is not a duration" in err


# ---------------------------------------------------------------------------
# Mistakes on the command line: did you mean, the help that has the answer, options in full
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv, suggestion, hint",
    [
        (["lst"], "did you mean: irondome ls", "(try: irondome --help)"),
        (["statsu"], "did you mean: irondome status", "(try: irondome --help)"),
        (["Status"], "did you mean: irondome status", "(try: irondome --help)"),
        (["grant", "creat", "GITHUB_TOKEN"], "did you mean: irondome grant create", "(try: irondome grant --help)"),
        (["bunker", "crate", "bravo"], "did you mean: irondome bunker create", "(try: irondome bunker --help)"),
        (["add", "x", "--genrate"], "unrecognized arguments: --genrate; did you mean --generate?",
         "(try: irondome add --help)"),
        (["--jsn", "status"], "did you mean --json?", "(try: irondome status --help)"),
        (["init", "--mode", "touch"], "did you mean touchid?", "(try: irondome init --help)"),
    ],
)
def test_a_typo_gets_a_suggestion_and_the_help_of_its_own_command(
    capsys: pytest.CaptureFixture[str], argv: List[str], suggestion: str, hint: str
) -> None:
    code, out, err = run(capsys, *argv)
    assert code == 2 and out == ""
    assert suggestion in err and err.rstrip().endswith(hint), err


def test_several_unknown_options_each_get_their_suggestion(capsys: pytest.CaptureFixture[str]) -> None:
    _, _, err = run(capsys, "add", "x", "--genrate", "--lenght", "20")
    assert "did you mean --generate (for --genrate), --length (for --lenght)?" in err


def test_nothing_close_means_no_suggestion_and_the_full_list(capsys: pytest.CaptureFixture[str]) -> None:
    code, _, err = run(capsys, "bunker", "nope")
    assert code == 2 and "invalid choice: 'nope' (choose from " in err and "did you mean" not in err


def test_an_unknown_argument_is_shown_escaped(capsys: pytest.CaptureFixture[str]) -> None:
    _, _, err = run(capsys, "status", "--x\x1b[2J")
    assert "\x1b" not in err and "--x\\x1b[2J" in err


@pytest.mark.parametrize(
    "argv, meant",
    [
        (["show", "github", "--rev"], "--reveal"),
        (["add", "github", "--password"], "--password-stdin"),  # was taken for a master password on stdin
        (["rm", "github", "--y"], "--yes"),
        (["grant", "create", "GITHUB_TOKEN", "--un"], "--unlimited"),
        (["run", "--no-m", "--", "true"], "--no-mask"),
    ],
)
def test_options_are_never_abbreviated(argv: List[str], meant: str) -> None:
    with pytest.raises(UsageError, match=f"did you mean {meant}"):
        main.build_parser().parse_args(argv)


def test_every_parser_refuses_abbreviations() -> None:
    pending = [main.build_parser()]
    while pending:
        parser = pending.pop()
        assert parser.allow_abbrev is False, parser.prog
        pending.extend(parser._subparsers_of())


# ---------------------------------------------------------------------------
# --no-color, and NO_COLOR, from the first argument on
# ---------------------------------------------------------------------------


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def on_a_terminal(monkeypatch: pytest.MonkeyPatch) -> Terminal:
    """stderr becomes a terminal and nothing in the environment says no colour: only --no-color can.

    Called in the test itself: pytest puts its own stderr back between a fixture and the test.
    """
    stream = Terminal()
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    monkeypatch.setattr(sys, "stderr", stream)
    return stream


@pytest.mark.parametrize(
    "argv",
    [
        ["--no-color", "lst"],  # a mistyped command: argparse stops before it reaches the flag
        ["status", "--bogus", "--no-color"],  # an unknown option
        ["--no-color", "--bunker", "NOT A NAME", "status"],  # select_bunker
        ["--no-color"],  # the overview, with a damaged default-bunker file (below)
    ],
)
def test_no_color_holds_for_errors_from_before_the_command_runs(
    monkeypatch: pytest.MonkeyPatch, argv: List[str]
) -> None:
    paths.ensure_dir(paths.root())
    (paths.root() / "default-bunker").write_text("NOT A NAME\n")
    terminal = on_a_terminal(monkeypatch)
    assert main.main(argv) == 2
    assert terminal.getvalue().startswith("error  ") and "\x1b[" not in terminal.getvalue()


def test_without_no_color_a_terminal_gets_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = on_a_terminal(monkeypatch)
    assert main.main(["lst"]) == 2
    # Laid out: the mark in red (the word, where the stream is not known to show more than ASCII), the text bold.
    assert terminal.getvalue().startswith("\x1b[31;1merror\x1b[0m \x1b[1m")


def test_help_and_usage_errors_carry_no_colour_codes_even_where_python_would_colour(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Python 3.14 colours help on a terminal (FORCE_COLOR stands in for one) and wrote those codes into the
    name of every subcommand, which every usage error then repeated: "(try: ^[[1;35mirondome^[[0m add --help)"."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    pending = [main.build_parser()]
    while pending:
        parser = pending.pop()
        assert "\x1b" not in parser.prog, repr(parser.prog)
        pending.extend(parser._subparsers_of())
    for argv in (["--help"], ["add", "--help"], ["grant", "create", "--help"]):
        with pytest.raises(SystemExit):
            main.main(argv)
        assert "\x1b" not in capsys.readouterr().out, argv
    code, _, err = run(capsys, "add", "x", "--genrate")
    assert code == 2 and err.rstrip().endswith("(try: irondome add --help)") and "\x1b" not in err


# ---------------------------------------------------------------------------
# Something slow (compiling the Secure Enclave helper) is announced, unless --quiet
# ---------------------------------------------------------------------------


def slow_status(ctx: object, args: object) -> int:
    devices.report_progress("Compiling the Secure Enclave helper...")
    return 0


@pytest.mark.parametrize("argv, said", [(["status"], True), (["-q", "status"], False)])
def test_backends_can_say_that_something_slow_has_started(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: List[str], said: bool
) -> None:
    monkeypatch.setattr(cmd_vault, "_status", slow_status)
    before = devices.set_progress(None)
    try:
        assert run(capsys, *argv) == (0, "", "Compiling the Secure Enclave helper...\n" if said else "")
        assert devices.set_progress(None) is None  # main() puts back the callback it found
    finally:
        devices.set_progress(before)
