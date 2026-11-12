"""Claim ``clipboard-cleared``: a copied secret is taken off the clipboard.

Statement: --copy hands the value to the system's clipboard tool on its
standard input, never as an argument, and clears the clipboard after the
bunker's clipboard_clear_seconds (30 by default), but only if the clipboard
still holds that value.

No test here touches the clipboard of the person running the suite: the tools
are stand-ins named ``pbcopy`` and ``pbpaste`` in a temporary directory that
replaces the module's search path, and the "clipboard" is a file. The rest of
the statement (stdin only, a changed clipboard left alone, the process list)
is proved in tests/unit/test_clipboard.py and tests/e2e/test_cli_vault.py.
"""

from __future__ import annotations

import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Tuple

import pytest

from conftest import PASSWORD
from irondome import clipboard
from irondome.cli import main
from support.claimkit import add, init, ok, session

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the stand-in tools are shell scripts")

STAND_IN = r'''
import sys
board, name = sys.argv[1], sys.argv[2]
if name == "pbcopy":
    data = sys.stdin.buffer.read()
    with open(board, "wb") as handle:
        handle.write(data)
else:
    with open(board, "rb") as handle:
        sys.stdout.buffer.write(handle.read())
'''


def stand_in_tools(root: Path) -> Path:
    """``pbcopy`` and ``pbpaste`` that keep the clipboard in ``root/board``; returns their directory."""
    tools = root / "bin"
    tools.mkdir(parents=True)
    script = root / "tool.py"
    script.write_text(STAND_IN, encoding="utf-8")
    (root / "board").write_bytes(b"")
    for name in ("pbcopy", "pbpaste"):
        path = tools / name
        path.write_text(
            f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(script))} "
            f"{shlex.quote(str(root / 'board'))} {name}\n",
            encoding="utf-8",
        )
        path.chmod(stat.S_IRWXU)
    return tools


def test_copy_asks_for_the_clipboard_to_be_cleared_after_the_bunkers_setting_30_seconds_by_default(
    cli, monkeypatch, capsys
):
    init(cli)
    add(cli, "github", "the-github-token-1234")
    monkeypatch.setenv("IRONDOME_SESSION", session(cli))
    monkeypatch.setattr(main, "harden_process", lambda: None)  # leave this test process's own limits alone
    copied: List[Tuple[str, int]] = []
    monkeypatch.setattr(clipboard, "copy", lambda value, seconds: copied.append((value, seconds)) or "pbcopy")
    assert main.main(["get", "github", "--copy"]) == 0
    shown = capsys.readouterr()
    assert copied == [("the-github-token-1234", 30)]
    assert "the-github-token-1234" not in shown.out + shown.err and "cleared in 30s" in shown.err
    ok(cli("config", "set", "clipboard_clear_seconds", "7", "--password-stdin", stdin=PASSWORD + "\n"))
    assert main.main(["get", "github", "--copy"]) == 0
    assert copied[-1] == ("the-github-token-1234", 7) and "cleared in 7s" in capsys.readouterr().err


# -- the boundary ------------------------------------------------------------------


def test_boundary_until_it_is_cleared_every_program_of_yours_can_read_it(tmp_path, monkeypatch):
    """Clearing happens after the delay: until then any program can paste the value."""
    tools = stand_in_tools(tmp_path / "clipboard")
    monkeypatch.setattr(clipboard, "_search_path", lambda: str(tools))
    monkeypatch.setattr(clipboard, "_system", lambda: "darwin")
    assert clipboard.copy("the-github-token-1234", 2) == "pbcopy"
    another_program = [str(tools / "pbpaste")]
    assert ok(subprocess.run(another_program, capture_output=True, text=True, timeout=30)).stdout == (
        "the-github-token-1234"
    )
    deadline = time.monotonic() + 30
    while (tmp_path / "clipboard" / "board").read_bytes() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert subprocess.run(another_program, capture_output=True, text=True, timeout=30).stdout == ""
