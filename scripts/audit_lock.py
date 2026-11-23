#!/usr/bin/env python3
"""Run pip-audit over every version uv.lock pins, whatever Python or platform a pin is for.

    uv export --locked --all-extras --all-groups --no-emit-project --format requirements-txt -o FILE
    uv run --locked --only-group ci python scripts/audit_lock.py FILE

`uv export` writes one entry for each pinned version, with the marker that says
where it is installed (`pytest==8.4.2 ; python_full_version < '3.10'`).
pip-audit leaves out every entry whose marker does not hold for the interpreter
that runs it, so one run on Python 3.14 on macOS never looks at what is pinned
for Python 3.9, for Linux or for Windows. This script takes the markers away
and gives pip-audit every entry. A package pinned at several versions cannot
appear twice in one requirements file, so there are as many runs as the most
versions any package has.

ACCEPTED names the advisories that are known and stay: each for one pinned
version, with the reason. Nothing else is let through. An accepted advisory
is let through only for the run that holds its pin, a new advisory against
the same pin fails like any other, and an entry whose pin has left the lock
fails too, so the list cannot outlive its reasons.

Exits 0 when no run found anything, 1 otherwise. Standard library only; it
starts pip-audit with the interpreter that runs it.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Sequence, Tuple

#: (package, version) -> the advisories accepted for that pin.
ACCEPTED: Dict[Tuple[str, str], Tuple[str, ...]] = {
    # pytest 9 needs Python 3.10, so the tests on Python 3.9 run on the last pytest 8. The advisory
    # (CVE-2025-71176, fixed in 9.0.3) is about the directory /tmp/pytest-of-USER, which another
    # user of the same machine can create first. The tests run where there is no other user: in
    # the temporary directory macOS gives each user, in a container, on a CI runner. It goes when
    # Python 3.9 does.
    ("pytest", "8.4.2"): ("GHSA-6w46-j5rx-g56g",),
}

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")

Entry = Tuple[str, str, str]  # package (normalised), version, the entry without its marker


def _normalised(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def entries(text: str) -> List[Entry]:
    """Every pinned entry of an exported requirements file, its marker removed and its hashes kept."""
    found: List[Entry] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        index += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        block = [line]
        while block[-1].rstrip().endswith("\\") and index < len(lines):
            block.append(lines[index])
            index += 1
        match = _PIN.match(line)
        if match is None:
            raise ValueError(f"not a pinned requirement: {line.strip()}")
        hashes = [part.strip().rstrip("\\").strip() for part in block[1:]]
        if not hashes or not all(part.startswith("--hash=") for part in hashes):
            raise ValueError(f"{match.group(0)} has no hash, or something that is not one")
        pin = f"{match.group(1)}=={match.group(2)}"
        found.append((_normalised(match.group(1)), match.group(2), " \\\n    ".join([pin] + hashes) + "\n"))
    return found


def passes(found: Sequence[Entry]) -> List[List[Entry]]:
    """The entries in as few groups as hold each package once: one requirements file a group."""
    groups: List[List[Entry]] = []
    seen: Dict[str, int] = {}
    for entry in found:
        position = seen.get(entry[0], 0)
        seen[entry[0]] = position + 1
        if position == len(groups):
            groups.append([])
        groups[position].append(entry)
    return groups


def main(arguments: Sequence[str], run: Callable[..., "subprocess.CompletedProcess[bytes]"] = subprocess.run) -> int:
    if len(arguments) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        found = entries(Path(arguments[0]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"audit_lock: {exc}", file=sys.stderr)
        return 1
    if not found:
        print("audit_lock: the file pins nothing", file=sys.stderr)
        return 1
    pinned = {(name, version) for name, version, _ in found}
    gone = sorted(pin for pin in ACCEPTED if pin not in pinned)
    if gone:
        for name, version in gone:
            print(f"audit_lock: {name}=={version} is no longer pinned: take it out of ACCEPTED", file=sys.stderr)
        return 1
    failed = False
    groups = passes(found)
    with tempfile.TemporaryDirectory() as work:
        for number, group in enumerate(groups, 1):
            requirements = Path(work) / f"requirements-{number}.txt"
            requirements.write_text("".join(text for _, _, text in group), encoding="utf-8")
            command = [
                sys.executable, "-m", "pip_audit", "--progress-spinner", "off",
                "--disable-pip", "--require-hashes", "-r", str(requirements),
            ]  # fmt: skip
            for name, version, _ in group:
                for advisory in ACCEPTED.get((name, version), ()):
                    print(f"audit_lock: accepted for {name}=={version}: {advisory} (the reason is in this script)")
                    command += ["--ignore-vuln", advisory]
            print(f"audit_lock: run {number} of {len(groups)}: {len(group)} pinned versions", flush=True)
            if run(command, check=False).returncode != 0:
                failed = True
    if failed:
        print("audit_lock: a pinned version has a known vulnerability, or a run could not finish", file=sys.stderr)
        return 1
    print(f"audit_lock: {len(found)} pinned versions, no known vulnerability that is not accepted above")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
