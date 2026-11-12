"""The help pages of the maintenance commands (cli/cmd_admin.py): each ends with real examples (red-team dx:4).

An example is only worth having if it can be copied: each one is checked to parse as the command it shows,
and to come out of ``--help`` on one line even where the terminal is narrow.
"""

from __future__ import annotations

import argparse
import re
import shlex
from typing import List

import pytest

from irondome.cli.main import build_parser

ADMIN_PAGES = ["backup", "backup ls", "backup restore", "export", "import", "migrate", "rekey", "nuke", "doctor",
               "completion", "version",
               "verify"]  # cli/cmd_verify.py: the one page re-verification of dx:4 still found without an example
#: ``irondome`` and the words after it, up to a shell character or the two spaces before an explanation.
_COMMAND = re.compile(r"\birondome((?: [^ ()<>|]+)+)")


def _parser_for(path: str) -> argparse.ArgumentParser:
    parser = build_parser()
    for word in path.split():
        group = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
        parser = group.choices[word]
    return parser


def _examples(parser: argparse.ArgumentParser) -> List[str]:
    return [line for line in (parser.epilog or "").splitlines() if "irondome " in line]


@pytest.mark.parametrize("path", ADMIN_PAGES)
def test_every_admin_page_ends_with_an_example_of_itself(path: str) -> None:
    examples = _examples(_parser_for(path))
    assert examples, f"irondome {path} --help shows no example"
    assert any(f"irondome {path}" in line for line in examples), examples


@pytest.mark.parametrize("path", ADMIN_PAGES)
def test_every_example_is_a_command_that_parses(path: str) -> None:
    for line in _examples(_parser_for(path)):
        match = _COMMAND.search(line)
        assert match, line
        arguments = shlex.split(match.group(1))
        parsed = build_parser().parse_args(arguments)  # a usage error raises here
        assert getattr(parsed, "handler", None) is not None, line


@pytest.mark.parametrize("path", ADMIN_PAGES)
def test_examples_stay_whole_on_a_narrow_terminal_and_the_description_is_wrapped(
    path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COLUMNS", "50")
    parser = _parser_for(path)
    shown = parser.format_help()
    for line in _examples(parser):
        assert line in shown.splitlines(), f"{line!r} was refilled:\n{shown}"
    assert parser.description and all(len(line) <= 78 for line in parser.description.splitlines())
    assert "!" not in shown
