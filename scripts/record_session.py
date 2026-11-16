"""Record a real IronDome session for the website's terminal player.

Every command below is run for real, through a pseudo-terminal, against a
throwaway home directory; prompts are answered the way a person would answer
them. The output is written as a transcript (``$ command`` lines followed by
what the terminal showed), with the temporary paths rewritten to ``~`` and the
throwaway secrets left exactly as they were generated. Nothing is edited by
hand, so the page can say "this is a recording" and mean it.

    python scripts/record_session.py OUTPUT.txt [--backend software|macos-se]

``macos-se`` records against the real Secure Enclave of this Mac (device
policy only: no Touch ID prompt appears). Standard library only.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import re
import select
import shutil
import signal
import struct
import sys
import tempfile
import termios
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# Throwaway values for a throwaway home directory: they are shown on the website.
PASSWORD = "correct horse battery staple"  # noqa: S105
BRAVO_PASSWORD = "a different password for bravo"  # noqa: S105
TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # noqa: S105 - the example seed from RFC 6238 tutorials

# (command, answers): each answer is (prompt regex, reply). A reply of None
# means "press Enter". Answers are given in order; one whose regex starts with
# OPTIONAL is skipped when the prompt after it shows up first (a Mac with
# Touch ID asks how the vault should open; other machines do not ask).
Step = Tuple[str, List[Tuple[str, Optional[str]]]]
OPTIONAL = "(?#optional)"
# Enter takes the default: the master password plus this machine's security chip.
HOW_TO_OPEN = (OPTIONAL + r"Choose 1, 2 or 3 \[1\]: ", None)

SCENES: List[Tuple[str, List[Step]]] = [
    ("setup", [
        ("irondome init", [
            HOW_TO_OPEN,
            (r"New master password: ", PASSWORD),
            (r"Repeat it: ", PASSWORD),
            (r"(?i)press enter|saved it", None),
        ]),
        ("irondome status", []),
    ]),
    ("everyday", [
        ("irondome add github --username king --url https://github.com --generate --alias GITHUB_TOKEN",
         [(r"Master password: ", PASSWORD)]),
        ("irondome add stripe --kind secret --value-stdin < stripe.key", [(r"Master password: ", PASSWORD)]),
        ("irondome ls", [(r"Master password: ", PASSWORD)]),
        ("irondome gen --words 6", []),
    ]),
    ("bunkers", [
        ("irondome bunker create bravo", [
            HOW_TO_OPEN,
            (r"New master password: ", BRAVO_PASSWORD),
            (r"Repeat it: ", BRAVO_PASSWORD),
            (r"(?i)press enter|saved it", None),
        ]),
        ("irondome bunker ls", []),
    ]),
    ("agent", [
        ("export IRONDOME_GRANT=\"$(irondome grant create GITHUB_TOKEN --ttl 15m)\"",
         [(r"Master password: ", PASSWORD)]),
        ("irondome run --env GITHUB_TOKEN -- sh -c 'echo \"the token is $GITHUB_TOKEN\"'", []),
        ("irondome run --env GITHUB_TOKEN -- sh -c 'echo \"the token is $GITHUB_TOKEN\"'", []),
        ("unset IRONDOME_GRANT", []),
    ]),
    ("one-time codes", [
        ("irondome edit github --totp-stdin < totp.txt", [(r"Master password: ", PASSWORD)]),
        ("irondome otp github", [(r"Master password: ", PASSWORD)]),
    ]),
    ("audit", [
        ("irondome audit", [(r"Master password: ", PASSWORD)]),
        ("irondome audit --verify", [(r"Master password: ", PASSWORD)]),
    ]),
    ("self-destruct", [
        ("irondome nuke", [(r"Type DESTROY", "DESTROY")]),
        ("irondome status", []),
    ]),
]


def _shell_environment(home: Path, backend: str, bindir: Path) -> Dict[str, str]:
    env = {
        "HOME": str(home),
        "PATH": f"{bindir}:/usr/bin:/bin",
        "TERM": "dumb",
        "NO_COLOR": "1",
        "LANG": "en_US.UTF-8",
        "IRONDOME_DEVICE_BACKEND": backend,
        "IRONDOME_NO_TOUCH": "1",
        "PS1": "",
    }
    if backend == "macos-se" and os.environ.get("IRONDOME_SE_HELPER"):
        env["IRONDOME_SE_HELPER"] = os.environ["IRONDOME_SE_HELPER"]
    return env


class Shell:
    """One bash process on a pseudo-terminal, driven command by command."""

    def __init__(self, env: Dict[str, str], cwd: Path) -> None:
        pid, fd = os.forkpty()
        if pid != 0:  # wide enough that no typed command is wrapped or scrolled when the shell echoes it
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 250, 0, 0))
        if pid == 0:  # child
            os.chdir(str(cwd))
            os.execve("/bin/bash", ["bash", "--noprofile", "--norc"], env)  # noqa: S606 - the shell being recorded
        self.pid, self.fd = pid, fd
        self._drain(1.0)

    def _read(self, timeout: float) -> bytes:
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return b""
        try:
            return os.read(self.fd, 65536)
        except OSError:
            return b""

    def _drain(self, quiet: float) -> bytes:
        out = b""
        while True:
            chunk = self._read(quiet)
            if not chunk:
                return out
            out += chunk

    def run(self, command: str, answers: Sequence[Tuple[str, Optional[str]]], timeout: float = 120.0) -> str:
        marker = f"__done_{time.monotonic_ns()}__"
        os.write(self.fd, (f"{command}; printf '\\n{marker}\\n'\n").encode())
        pending = list(answers)
        answered = 0  # how much of what this command showed has been matched to an answer
        seen = b""
        deadline = time.monotonic() + timeout
        # Done when printf's own line arrives: the marker between two real line
        # breaks. The echo of the typed command holds the marker too, but
        # between a backslash-n and a quote, never on a line of its own.
        done = re.compile(rb"\n" + marker.encode() + rb"\r?\n")
        while not done.search(seen):
            if time.monotonic() > deadline:
                shown = seen.decode("utf-8", "replace")[-400:]
                raise SystemExit(f"timed out waiting for: {command}\nthe terminal showed:\n{shown}")
            chunk = self._read(0.2)
            seen += chunk
            shown = seen.decode("utf-8", "replace").split(command, 1)[-1]
            while len(pending) > 1 and pending[0][0].startswith(OPTIONAL) and not re.search(pending[0][0], shown):
                if not re.search(pending[1][0], shown[answered:]):
                    break
                pending.pop(0)  # the optional prompt never came; the one after it did
            if pending:
                match = re.search(pending[0][0], shown[answered:])
                if match:
                    answered += match.end()
                    reply = pending.pop(0)[1]
                    time.sleep(0.15)
                    os.write(self.fd, ((reply or "") + "\n").encode())
        text = seen.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "")
        # Drop the echoed command line. A command typed before the shell is reading
        # again is echoed twice (by the terminal, then by the shell as it redraws its
        # line), so what the command showed starts after the last echo: the marker
        # followed by the backslash-n and the quote that only the typed line holds.
        body = text.rsplit(marker + "\\n'", 1)[-1]
        body = body.split("\n", 1)[1] if "\n" in body else ""
        body = body.split(marker)[0]
        return body.rstrip("\n")

    def close(self) -> None:
        """End the shell. Its output is read until it is gone: a shell with unread output never finishes exiting."""
        try:
            os.write(self.fd, b"exit\n")
        except OSError:
            pass
        deadline = time.monotonic() + 5.0
        while True:
            self._read(0.1)
            try:
                if os.waitpid(self.pid, os.WNOHANG)[0] == self.pid:
                    break
            except ChildProcessError:
                break
            if time.monotonic() > deadline:
                try:
                    os.killpg(os.getpgid(self.pid), signal.SIGKILL)  # the shell and whatever it was still running
                except OSError:
                    pass
                deadline = float("inf")
        try:
            os.close(self.fd)
        except OSError:
            pass


def record(output: Path, backend: str) -> None:
    irondome = shutil.which("irondome")
    if irondome is None:
        raise SystemExit("irondome is not on PATH: install the package into the environment first")
    with tempfile.TemporaryDirectory(prefix="irondome-recording-") as scratch:
        home = Path(scratch) / "home"
        home.mkdir()
        (home / "stripe.key").write_text("demo-api-key-" + os.urandom(12).hex() + "\n")  # visibly not a real key
        (home / "totp.txt").write_text(TOTP_SECRET + "\n")  # the RFC 6238 example seed, from a file: never in history
        shell = Shell(_shell_environment(home, backend, Path(irondome).parent), home)
        lines: List[str] = []
        try:
            for scene, steps in SCENES:
                lines.append(f"# scene: {scene}")
                for command, answers in steps:
                    out = shell.run(command, answers)
                    lines.append(f"$ {command}")
                    lines.extend(out.splitlines())
                    lines.append("")
        finally:
            shell.close()
        text = "\n".join(lines).replace(str(home), "~").replace(os.path.realpath(str(home)), "~")
        text = re.sub(r"/(private/)?var/folders/[^\s]+", "~/tmp", text)
    output.write_text(text.rstrip("\n") + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path)
    parser.add_argument("--backend", default="software", choices=["software", "macos-se"])
    args = parser.parse_args()
    record(args.output, args.backend)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
