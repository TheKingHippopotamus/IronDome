"""The parts of the agent commands (irondome.cli.cmd_agent) that the end-to-end tests cannot pin down one by one.

* Touch ID prompts: what ``approve`` and ``run`` put in front of the owner. The text names the bunker, and
  names the program by the whole path it is started by, or the request is refused: a path is never cut.
* Help pages: every page of an agent command ends with real examples of that command, which parse as such
  and are never wrapped across lines.

tests/e2e/test_cli_agent.py runs the same rules through the real command line on a stand-in chip.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import sys
import types
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

import pytest

from irondome import paths
from irondome.cli import cmd_agent
from irondome.cli.context import Context
from irondome.cli.main import build_parser
from irondome.cli.output import Output
from irondome.device.base import POLICY_BIOMETRY, POLICY_DEVICE
from irondome.keys import KIND_DEVICE, KIND_PASSWORD, KIND_RECOVERY

LIMIT = 200  # the most a Touch ID prompt shows (device/irondome_se.swift)


# ---------------------------------------------------------------------------
# Touch ID prompts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bunker", ["work", "personal", "a" + "-" * 31])
def test_every_prompt_ends_with_the_bunker_it_opens(monkeypatch: pytest.MonkeyPatch, bunker: str) -> None:
    monkeypatch.setenv(paths.ENV_BUNKER, bunker)

    reason = cmd_agent._run_reason("/opt/homebrew/bin/gh", ["GITHUB_TOKEN"])

    assert cmd_agent._touch_reason("let an agent use GITHUB_TOKEN for 10 minutes") == (
        f"let an agent use GITHUB_TOKEN for 10 minutes (bunker {bunker})"
    )
    assert reason == f"let '/opt/homebrew/bin/gh' use GITHUB_TOKEN (bunker {bunker})"


def test_the_same_request_reads_differently_in_two_bunkers(monkeypatch: pytest.MonkeyPatch) -> None:
    reasons = []
    for bunker in ("work", "personal"):
        monkeypatch.setenv(paths.ENV_BUNKER, bunker)
        reasons.append(cmd_agent._run_reason("/opt/homebrew/bin/gh", ["GITHUB_TOKEN"]))

    assert reasons[0] != reasons[1]


@pytest.mark.parametrize("length", [21, 80, 81, 120, 158])
def test_a_program_path_that_fits_is_shown_whole(length: int) -> None:
    program = "/" + "x" * (length - 4) + "/gh"
    assert len(program) == length

    reason = cmd_agent._run_reason(program, ["GITHUB_TOKEN"])

    assert reason is not None and len(reason) <= LIMIT
    assert f"'{program}'" in reason and "\u2026" not in reason


def test_a_program_path_that_cannot_be_shown_whole_is_not_shown_at_all() -> None:
    longest = LIMIT - len("let '' use 1 secret (bunker alpha)")
    fits = "/" + "x" * (longest - 4) + "/gh"
    too_long = "/" + "x" * (longest - 3) + "/gh"

    assert cmd_agent._run_reason(fits, ["GITHUB_TOKEN"]) == f"let '{fits}' use 1 secret (bunker alpha)"
    assert cmd_agent._run_reason(too_long, ["GITHUB_TOKEN"]) is None
    assert cmd_agent._run_reason(too_long, [f"S{index}" for index in range(30)]) is None


def test_references_that_do_not_fit_are_counted_and_the_path_stays_whole() -> None:
    program = "/" + "p" * 100 + "/tool"
    references = [f"SECRET_NUMBER_{index:02d}" for index in range(8)]

    reason = cmd_agent._run_reason(program, references)

    assert reason is not None and len(reason) <= LIMIT
    assert reason.startswith(f"let '{program}' use SECRET_NUMBER_00, ")
    assert re.search(r" and \d+ more \(bunker alpha\)$", reason), reason


@pytest.mark.parametrize(
    "program, shown",
    [
        ("/tmp/gh' use NOTHING (bunker work) and '/x", "'/tmp/gh\\' use NOTHING (bunker work) and \\'/x'"),
        ("/tmp/back\\slash", "'/tmp/back\\\\slash'"),
        ("/tmp/new\nline", "'/tmp/new\\nline'"),
        ("/tmp/\u202eevil", "'/tmp/\\u202eevil'"),
        ("/Users/k/Documents - k\u2019s Mac/tool", "'/Users/k/Documents - k\u2019s Mac/tool'"),
    ],
)
def test_where_the_program_path_ends_cannot_be_mistaken(program: str, shown: str) -> None:
    """A quote in the path cannot close it early, and nothing in it is invisible or moves the text around."""
    assert cmd_agent._quoted(program) == shown
    assert cmd_agent._run_reason(program, ["GITHUB_TOKEN"]) == f"let {shown} use GITHUB_TOKEN (bunker alpha)"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX links")
def test_the_started_path_resolves_every_directory_and_keeps_the_programs_name(tmp_path: Path) -> None:
    real = Path(os.path.realpath(tmp_path))
    tool = real / "opt" / "bin" / "tool"
    tool.parent.mkdir(parents=True)
    tool.write_text("")
    (real / "opt" / "bin" / "alias").symlink_to("tool")  # a program known by a link's name (a venv's python)
    (real / "linked").symlink_to(real / "opt" / "bin")  # a link to a directory
    depth = len((real / "L").parts) - 1
    (real / "deep").joinpath(*(["d"] * depth)).mkdir(parents=True)
    (real / "L").symlink_to((real / "deep").joinpath(*(["d"] * depth)))
    spoof = str(real / "L") + "/.." * depth + "/usr/bin/curl"  # as text: /usr/bin/curl

    assert cmd_agent._started_path(str(tool)) == str(tool)
    assert cmd_agent._started_path(str(real / "opt" / "bin" / "alias")) == str(real / "opt" / "bin" / "alias")
    assert cmd_agent._started_path(str(real / "linked" / "tool")) == str(tool)
    assert cmd_agent._started_path(str(real / "opt" / "." / "bin" / ".." / "bin" / "tool")) == str(tool)
    assert os.path.normpath(spoof) == "/usr/bin/curl"
    assert cmd_agent._started_path(spoof) == str(real / "deep" / "usr" / "bin" / "curl")


# -- when a prompt can appear at all -----------------------------------------------


def _context(*, terminal: bool = False, touch: bool = False, no_touch: bool = False, stdin: bool = False) -> Context:
    args = argparse.Namespace(touch=touch, no_touch=no_touch, password_stdin=stdin)
    ctx = Context(args, Output())
    ctx.has_terminal = terminal
    return ctx


def _slot(kind: str, policy: Optional[str] = None) -> Any:
    return types.SimpleNamespace(kind=kind, policy=policy)


TOUCH_ID = _slot(KIND_DEVICE, POLICY_BIOMETRY)
PASSWORD = _slot(KIND_PASSWORD, POLICY_DEVICE)
PASSWORD_AND_FINGER = _slot(KIND_PASSWORD, POLICY_BIOMETRY)
RECOVERY = _slot(KIND_RECOVERY)


@pytest.fixture
def vault_slots(monkeypatch: pytest.MonkeyPatch) -> Iterator[List[Any]]:
    """The keyslots the vault file is read to have, on a Mac where Touch ID can be asked for."""
    slots: List[Any] = []
    monkeypatch.setattr(cmd_agent, "vault_exists", lambda: True)
    monkeypatch.setattr(cmd_agent.VaultFile, "load", classmethod(lambda cls: types.SimpleNamespace(slots=slots)))
    monkeypatch.setattr(cmd_agent.unlock, "can_ask_for_touch", lambda: True)
    yield slots


@pytest.mark.parametrize(
    "slots, who, environment, expected",
    [
        ([TOUCH_ID, PASSWORD], {"terminal": True}, {}, True),  # the owner at a terminal
        ([TOUCH_ID, PASSWORD], {"touch": True}, {}, True),  # an agent with --touch
        ([PASSWORD_AND_FINGER], {"terminal": True, "stdin": True}, {}, True),  # the password slot needs a finger
        ([TOUCH_ID, PASSWORD], {"terminal": True, "stdin": True}, {}, False),  # a given password: Touch ID not tried
        ([PASSWORD, RECOVERY], {"terminal": True}, {}, False),  # no keyslot asks for a finger
        ([TOUCH_ID, PASSWORD], {}, {}, False),  # no terminal and no --touch
        ([TOUCH_ID, PASSWORD], {"terminal": True, "no_touch": True}, {}, False),
        ([TOUCH_ID, PASSWORD], {"touch": True}, {"IRONDOME_GRANT": "irondome_g_x"}, False),  # the grant opens
        ([TOUCH_ID, PASSWORD], {"touch": True}, {"IRONDOME_SESSION": "irondome_s_x"}, False),  # the session opens
    ],
)
def test_a_prompt_is_expected_exactly_where_unlocking_would_show_one(
    vault_slots: List[Any],
    monkeypatch: pytest.MonkeyPatch,
    slots: List[Any],
    who: Dict[str, bool],
    environment: Dict[str, str],
    expected: bool,
) -> None:
    vault_slots.extend(slots)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    ctx = _context(**who)

    assert cmd_agent._touch_may_show(ctx, ctx.args) is expected


def test_no_prompt_is_expected_where_touch_id_cannot_be_asked_for_or_there_is_no_vault(
    vault_slots: List[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    vault_slots.append(TOUCH_ID)
    ctx = _context(terminal=True)
    assert cmd_agent._touch_may_show(ctx, ctx.args) is True

    monkeypatch.setattr(cmd_agent.unlock, "can_ask_for_touch", lambda: False)
    assert cmd_agent._touch_may_show(ctx, ctx.args) is False
    monkeypatch.setattr(cmd_agent.unlock, "can_ask_for_touch", lambda: True)
    monkeypatch.setattr(cmd_agent, "vault_exists", lambda: False)
    assert cmd_agent._touch_may_show(ctx, ctx.args) is False


# ---------------------------------------------------------------------------
# Help pages
# ---------------------------------------------------------------------------

#: One ``irondome ...`` invocation in an example's command line: words separated by single spaces, up to
#: the end of a ``$(...)`` or a closing quote.
_INVOCATION = re.compile(r"\birondome((?: [^\s\"')$]+)*)")


def _command_of(example: str) -> str:
    """The command line of an example, without what it does: the two columns are three spaces or more apart."""
    return re.split(r" {3,}", example, maxsplit=1)[0]


def _agent_commands() -> List[str]:
    """The top-level commands cmd_agent.py registers."""
    scratch = argparse.ArgumentParser()
    subparsers = scratch.add_subparsers()
    cmd_agent.register(subparsers, argparse.ArgumentParser(add_help=False))
    return sorted(subparsers.choices)


def _pages() -> Iterator[Tuple[str, argparse.ArgumentParser]]:
    """Every help page of an agent command, in the real command line: ("grant create", its parser)."""

    def walk(parser: argparse.ArgumentParser, path: Sequence[str]) -> Iterator[Tuple[str, argparse.ArgumentParser]]:
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for name, child in action.choices.items():
                    yield " ".join([*path, name]), child
                    yield from walk(child, [*path, name])

    commands = set(_agent_commands())
    for path, parser in walk(build_parser(), []):
        if path.split()[0] in commands:
            yield path, parser


PAGES = sorted(path for path, _ in _pages())


def _page(path: str) -> argparse.ArgumentParser:
    return dict(_pages())[path]


def _examples(parser: argparse.ArgumentParser) -> List[str]:
    """The example lines at the end of a help page, without their indent."""
    lines = (parser.epilog or "").splitlines()
    heading = next((index for index, line in enumerate(lines) if line in ("example:", "examples:")), None)
    examples: List[str] = []
    for line in lines[heading + 1 :] if heading is not None else []:
        if not line.startswith("  "):
            break
        examples.append(line[2:])
    return examples


def _handlers(parser: argparse.ArgumentParser) -> List[Any]:
    """The handler of *parser* and of every command below it."""
    found = [parser.get_default("handler")]
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                found += _handlers(child)
    return [handler for handler in found if handler is not None]


def test_the_agent_commands_are_the_ones_these_tests_walk() -> None:
    assert _agent_commands() == ["alias", "approve", "audit", "grant", "lock", "mcp", "run", "scan", "unlock"]
    assert len(PAGES) == 16


@pytest.mark.parametrize("path", PAGES)
def test_every_agent_help_page_ends_with_examples_of_its_own_command(path: str) -> None:
    parser = _page(path)
    examples = _examples(parser)

    assert examples, f"irondome {path} --help shows no example"
    assert any(f"irondome {path}" in _command_of(example) for example in examples)


@pytest.mark.parametrize("path", PAGES)
def test_every_example_parses_as_the_command_whose_page_shows_it(path: str) -> None:
    """An example is a command line that works as written: it parses, and it runs this command or one below it."""
    parser = _page(path)
    own, below = parser.get_default("handler"), _handlers(parser)
    handlers = []
    for example in _examples(parser):
        found = _INVOCATION.findall(_command_of(example))
        assert len(found) == 1, example
        args = build_parser().parse_args(shlex.split(found[0]))
        assert args.handler in below, example
        handlers.append(args.handler)
    assert own is None or own in handlers, f"no example of irondome {path} itself"


@pytest.mark.parametrize("path", PAGES)
def test_help_keeps_examples_whole_however_narrow_the_terminal(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    monkeypatch.setenv("COLUMNS", "40")
    parser = _page(path)
    text = parser.format_help()

    for example in _examples(parser):
        assert f"\n  {example}\n" in text, example
    for line in (parser.description or "").splitlines() + (parser.epilog or "").splitlines():
        assert len(line) <= 79, line
    assert "!" not in text
