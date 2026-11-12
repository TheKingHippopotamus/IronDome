"""Counts read as English (red-team dx:8): no "(s)" plurals, and a list of bunkers joined with "and"."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from irondome import caps
from irondome.cli import cmd_admin

SOURCE = Path(__file__).resolve().parents[2] / "src" / "irondome"


def test_no_message_says_s_in_parentheses() -> None:
    found = [
        f"{path.relative_to(SOURCE)}:{number}: {line.strip()}"
        for path in sorted(SOURCE.rglob("*.py"))
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"[a-z]\(s\)", line)
    ]
    assert found == []


@pytest.mark.parametrize(
    ("bunkers", "named"),
    [
        (["bravo"], "the vault file of bunker bravo that survives"),
        (["bravo", "charlie"], "the vault files of bunkers bravo and charlie that survives"),
        (["alpha", "bravo", "charlie"], "the vault files of bunkers alpha, bravo and charlie that survives"),
    ],
)
def test_the_nuke_caveat_names_one_two_or_more_bunkers_as_a_sentence(bunkers: list, named: str) -> None:
    caveat = cmd_admin._recovery_caveat(bunkers)
    assert f"a recovery key still opens any copy of {named} elsewhere" in caveat
    assert ("recovery key on paper: destroy it," if len(bunkers) == 1 else "recovery keys on paper: destroy them,") \
        in caveat


@pytest.mark.parametrize(("count", "text"), [(0, "0 sessions ended"), (1, "1 session ended"), (2, "2 sessions ended")])
def test_caps_counts_are_singular_or_plural(count: int, text: str) -> None:
    assert caps._plural(count, "session ended", "sessions ended") == text
