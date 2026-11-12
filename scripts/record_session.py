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
import os
import re
import select
import shutil
import signal
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

# Throwaway values for a throwaway home directory: they are shown on the website.
PASSWORD = "correct horse battery staple"  # noqa: S105
BRAVO_PASSWORD = "a different password for bravo"  # noqa: S105
TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # noqa: S105 - the example seed from RFC 6238 tutorials

# (command, answers): each answer is (prompt regex, reply). A reply of None
# means "press Enter".
Step = Tuple[str, List[Tuple[str, Optional[str]]]]

SCENES: List[Tuple[str, List[Step]]] = [
    ("setup", [
        ("irondome init", [
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
        seen = b""
        deadline = time.monotonic() + timeout
        while marker.encode() not in seen.split(b"printf", 1)[-1] or not seen.rstrip().endswith(marker.encode()):
            if time.monotonic() > deadline:
                raise SystemExit(f"timed out waiting for: {command}")
            chunk = self._read(0.2)
            seen += chunk
            text = seen.decode("utf-8", "replace")
            if pending and re.search(pending[0][0], text.split(command, 1)[-1]):
                reply = pending.pop(0)[1]
                time.sleep(0.15)
                os.write(self.fd, ((reply or "") + "\n").encode())
        text = seen.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "")
        body = text.split("\n", 1)[1] if "\n" in text else ""  # drop the echoed command line
        body = body.split(marker)[0]
        return body.rstrip("\n")

    def close(self) -> None:
        try:
            os.write(self.fd, b"exit\n")
            time.sleep(0.2)
            os.kill(self.pid, signal.SIGTERM)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
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
