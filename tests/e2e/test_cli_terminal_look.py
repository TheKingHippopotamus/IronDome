"""What a person sees at a terminal, and what a script reads: the real command line on a real pseudo-terminal.

A by-hand run on a Mac ended with: one font, one colour, hard to follow. On a terminal IronDome now lays its
output out (``irondome.cli.output``); everywhere else, and whenever colour is switched off, the lines are the
plain ones every other test in this suite reads. The unit tests are in ``tests/unit/test_cli_output.py``; these
run the installed command the way a person does.
"""

from __future__ import annotations

import os
import re
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from conftest import PASSWORD
from support.claimkit import init

pty = pytest.importorskip("pty")  # no pseudo-terminals on Windows

ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
SUPPORT = Path(__file__).resolve().parent.parent / "support"


def _environment(extra: Dict[str, str]) -> Dict[str, str]:
    """The isolated environment of the running test, with colour allowed and sockets refused as the cli fixture does."""
    merged = dict(os.environ)
    merged.pop("NO_COLOR", None)
    merged.pop("COLUMNS", None)
    merged["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SUPPORT), merged.get("PYTHONPATH", "")]))
    merged.update({"IRONDOME_TEST_BLOCK_SOCKETS": "1", "TERM": "xterm-256color", "PYTHONUTF8": "1"})
    merged.update(extra)
    return merged


def at_a_terminal(*args: str, env: Dict[str, str], columns: int = 72, stdin: str = "") -> Tuple[int, str]:
    """Run ``irondome ARGS`` with a pseudo-terminal as stdout and stderr: the exit status, and what it showed."""
    import fcntl
    import struct
    import termios

    parent, child = pty.openpty()
    fcntl.ioctl(child, termios.TIOCSWINSZ, struct.pack("HHHH", 40, columns, 0, 0))
    merged = _environment({"IRONDOME_NO_PROMPT": "1", **env})
    process = subprocess.Popen(
        [sys.executable, "-m", "irondome", *args], stdin=subprocess.PIPE, stdout=child, stderr=child, env=merged
    )
    os.close(child)
    assert process.stdin is not None
    process.stdin.write(stdin.encode())
    process.stdin.close()
    shown = b""
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        ready, _, _ = select.select([parent], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(parent, 65536)
            except OSError:  # Linux: the terminal is gone once the command has ended
                break
            if not chunk:
                break
            shown += chunk
        elif process.poll() is not None:
            break
    os.close(parent)
    return process.wait(timeout=30), shown.decode("utf-8").replace("\r\n", "\n")


def conversation(*args: str, answers: List[Tuple[str, str]], columns: int = 100) -> Tuple[int, str]:
    """Run ``irondome ARGS`` as a person does, on a terminal of its own, typing each answer when its prompt shows."""
    import fcntl
    import struct
    import termios

    env = _environment({})
    env.pop("IRONDOME_NO_PROMPT", None)  # the suite's default says nobody is there to answer; here somebody is
    pid, fd = pty.fork()
    if pid == 0:  # the child: the pseudo-terminal is its controlling terminal, as a shell's is
        os.execve(sys.executable, [sys.executable, "-m", "irondome", *args], env)  # noqa: S606 - the command under test
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, columns, 0, 0))
    shown, pending = b"", list(answers)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            shown += chunk
        if pending and pending[0][0].encode() in shown:
            os.write(fd, pending.pop(0)[1].encode() + b"\n")
            shown += b"<answered>"
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.WEXITSTATUS(status), shown.decode("utf-8").replace("\r\n", "\n")


def test_at_a_terminal_the_question_of_every_prompt_is_bold_and_its_text_unbroken(isolated) -> None:  # type: ignore[no-untyped-def]
    """Both ways a prompt is written: the hidden one (a password) and the echoed one (Press Enter)."""
    status, shown = conversation(
        "init",
        answers=[("New master password: ", PASSWORD), ("Repeat it: ", PASSWORD), ("written it down. ", "")],
    )
    assert status == 0, shown
    for question in ("New master password: ", "Repeat it: ", "Press Enter once you have written it down. "):
        assert f"\x1b[1m{question}\x1b[22m" in shown
    bare = ESCAPE.sub("", shown)
    assert "✓ created the vault of bunker alpha" in bare
    assert re.search(r"┌─+┐\n  │ (?:[A-Z2-7]{4}-){7}[A-Z2-7]{4} │\n  └─+┘", bare)  # the recovery key, framed
    assert "\n\n! the recovery key opens a copy of this vault" in bare  # a warning, set apart


def test_at_a_terminal_a_result_is_marked_wrapped_and_coloured(cli) -> None:  # type: ignore[no-untyped-def]
    init(cli, "--no-recovery")
    added, said = at_a_terminal(
        "add", "github", "--kind", "secret", "--value-stdin", "--password-stdin", env={}, stdin=PASSWORD + "\na-value\n"
    )
    assert added == 0 and "\x1b[32;1m✓\x1b[0m added github to bunker alpha" in said
    status, shown = at_a_terminal("ls", "--password-stdin", env={}, stdin=PASSWORD + "\n")
    assert status == 0
    lines = ESCAPE.sub("", shown).rstrip("\n").split("\n")
    assert lines[0].split()[:2] == ["NAME", "USERNAME"]
    assert set(lines[1]) == {"─", " "}  # the rule under the headings
    assert lines[2].startswith("github")
    assert "\x1b[1mNAME" in shown


def test_at_a_terminal_an_error_carries_its_mark_and_fits_the_width(cli) -> None:  # type: ignore[no-untyped-def]
    init(cli, "--no-recovery")
    status, shown = at_a_terminal("get", "github", env={}, columns=60)
    bare = ESCAPE.sub("", shown).rstrip("\n").split("\n")
    assert status == 4
    assert bare[0].startswith("✗ the vault is locked")
    assert len(bare) > 2 and all(len(line) <= 60 for line in bare)
    assert "\x1b[31;1m✗\x1b[0m" in shown and "\x1b[36mirondome grant create\x1b[39m" in shown


@pytest.mark.parametrize("off", [{"NO_COLOR": "1"}, {"TERM": "dumb"}, {"flag": "--no-color"}])
def test_at_a_terminal_with_colour_off_the_lines_are_the_ones_a_pipe_gets(cli, off: Dict[str, str]) -> None:  # type: ignore[no-untyped-def]
    init(cli, "--no-recovery")
    flag = [off["flag"]] if "flag" in off else []
    env = {name: value for name, value in off.items() if name != "flag"}
    status, shown = at_a_terminal(*flag, "get", "github", env=env, columns=60)
    piped = cli(*flag, "get", "github", env={"IRONDOME_NO_PROMPT": "1"})
    assert status == piped.returncode == 4
    assert "\x1b" not in shown
    assert shown == piped.stderr and shown.startswith("error  the vault is locked")
