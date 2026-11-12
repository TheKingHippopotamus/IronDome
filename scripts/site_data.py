#!/usr/bin/env python3
"""Write the numbers and the claims the website prints, or check that they are current.

    python scripts/site_data.py SITE_DIR            write SITE_DIR/src/data/counts.json and claims.json
    python scripts/site_data.py SITE_DIR --check    exit 1 if either is stale, or the transcript is provisional

counts.json is ``{"version", "tests", "claims", "files", "python"}``: the
IronDome version, the number of tests pytest collects in this repository, the
number of claims, the tests per top-level test directory (or file directly
under tests/), and the supported Python versions as the package metadata
lists them. claims.json is a byte-for-byte copy of src/irondome/claims.json.
The check also refuses a SITE_DIR/src/data/transcript.txt that still starts
with "# PROVISIONAL" (a stand-in written by hand before a real recording).

Standard library only; the test count comes from running pytest's own
collection with the interpreter that runs this script.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPOSITORY = Path(__file__).resolve().parent.parent
REGISTRY = REPOSITORY / "src" / "irondome" / "claims.json"
VERSION_FILE = REPOSITORY / "src" / "irondome" / "__init__.py"
PYPROJECT = REPOSITORY / "pyproject.toml"
PROVISIONAL = "# PROVISIONAL"
_COLLECT_TIMEOUT = 600


def version() -> str:
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', VERSION_FILE.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        raise SystemExit(f"no __version__ in {VERSION_FILE}")
    return match.group(1)


def python_range() -> str:
    """'3.9–3.14': the oldest and newest Python the package classifiers list."""
    found = re.findall(r'"Programming Language :: Python :: (3\.\d+)"', PYPROJECT.read_text(encoding="utf-8"))
    if not found:
        raise SystemExit(f"no Python version classifiers in {PYPROJECT}")
    ordered = sorted(found, key=lambda text: tuple(int(part) for part in text.split(".")))
    return f"{ordered[0]}–{ordered[-1]}"


def collected() -> List[str]:
    """The node id of every test pytest collects in this repository."""
    command = [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"]
    result = subprocess.run(command, cwd=str(REPOSITORY), capture_output=True, text=True, timeout=_COLLECT_TIMEOUT)
    ids = [line.strip() for line in result.stdout.splitlines() if "::" in line and not line.startswith(" ")]
    summary = re.search(r"(\d+) tests? collected", result.stdout)
    if result.returncode != 0 or summary is None or int(summary.group(1)) != len(ids):
        tail = (result.stdout + result.stderr).strip().splitlines()[-5:]
        raise SystemExit("pytest could not collect the tests:\n" + "\n".join(tail))
    return ids


def per_place(ids: List[str]) -> Dict[str, int]:
    """Tests per top-level test directory, or per test file that sits directly in tests/."""
    counts: Dict[str, int] = {}
    for node_id in ids:
        parts = node_id.split("::", 1)[0].split("/")
        place = "/".join(parts[:2]) if len(parts) >= 2 else parts[0]
        counts[place] = counts.get(place, 0) + 1
    return dict(sorted(counts.items()))


def counts() -> Dict[str, Any]:
    ids = collected()
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return {
        "version": version(),
        "tests": len(ids),
        "claims": len(registry["claims"]),
        "files": per_place(ids),
        "python": python_range(),
    }


def _encoded(document: Dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def targets(site: Path) -> Tuple[Path, Path, Path]:
    data = site / "src" / "data"
    return data / "counts.json", data / "claims.json", data / "transcript.txt"


def check(site: Path) -> List[str]:
    counts_path, claims_path, transcript = targets(site)
    problems = []
    if not counts_path.exists() or counts_path.read_bytes() != _encoded(counts()):
        problems.append(f"{counts_path} is out of date: run python scripts/site_data.py {site}")
    if not claims_path.exists() or claims_path.read_bytes() != REGISTRY.read_bytes():
        problems.append(f"{claims_path} is not a copy of {REGISTRY.relative_to(REPOSITORY)}")
    if not transcript.exists():
        problems.append(f"{transcript} is missing")
    elif transcript.read_text(encoding="utf-8").startswith(PROVISIONAL):
        problems.append(f"{transcript} is still the provisional stand-in: record a real session")
    return problems


def write(site: Path) -> None:
    counts_path, claims_path, _transcript = targets(site)
    counts_path.parent.mkdir(parents=True, exist_ok=True)
    counts_path.write_bytes(_encoded(counts()))
    claims_path.write_bytes(REGISTRY.read_bytes())
    print(f"wrote {counts_path} and {claims_path}", file=sys.stderr)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="scripts/site_data.py", description="Write the website's data files.")
    parser.add_argument("site", metavar="SITE_DIR", type=Path, help="the website's repository")
    parser.add_argument("--check", action="store_true", help="exit 1 if the data is stale; write nothing")
    args = parser.parse_args(argv)
    if not args.site.is_dir():
        print(f"{args.site} is not a directory", file=sys.stderr)
        return 2
    if args.check:
        problems = check(args.site)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    write(args.site)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
