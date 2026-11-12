"""The on-disk form of a legacy-vault fixture, and how to turn it back into a directory.

A fixture is one JSON file. It holds an IronDome 1.x-3.x data directory (every
file base64-encoded, with its mode) next to what a test needs to know about
it: the credentials that open it and the entries it contains, as an
independent reader decrypted them when the fixture was generated.

Why not the directory itself? The repository's ``.gitignore`` excludes
``secrets/``, ``backups/``, ``*.enc``, ``salt.bin`` and ``password_manager.log``
(they used to be how a real vault ended up in a commit), git does not record
file modes or empty directories, and line-ending conversion would damage a
16-byte salt on some checkouts. One JSON file has none of those problems, and
a test can never modify or destroy the original: it only ever works on a copy
that ``unpack`` wrote somewhere else.

Used by ``build_fixtures.py`` (to write fixtures) and by
``tests/unit/test_migrate_v3.py`` (to read them). Standard library only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, List, Union

FORMAT = "irondome-legacy-vault-fixture"
VERSION = 1
_CHUNK = 96  # characters of base64 per line, so that a diff of a fixture stays readable


def pack(data_dir: Union[str, Path]) -> Dict[str, List[Dict[str, Any]]]:
    """``{"directories": [...], "files": [...]}`` for everything under *data_dir*, in sorted order."""
    root = Path(data_dir)
    directories: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    for current, names, filenames in os.walk(root):
        names.sort()
        here = Path(current)
        if here != root:
            directories.append({"path": here.relative_to(root).as_posix(), "mode": _mode(here)})
        for name in sorted(filenames):
            path = here / name
            data = path.read_bytes()
            text = base64.b64encode(data).decode("ascii")
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "mode": _mode(path),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "base64": [text[start : start + _CHUNK] for start in range(0, len(text), _CHUNK)],
                }
            )
    return {"directories": directories, "files": files}


def _mode(path: Path) -> str:
    return format(stat.S_IMODE(path.lstat().st_mode), "04o")


def load(path: Union[str, Path]) -> Dict[str, Any]:
    """Read a fixture file and check that it is one."""
    fixture = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(fixture, dict) or fixture.get("format") != FORMAT or fixture.get("version") != VERSION:
        raise ValueError(f"{path} is not a version {VERSION} legacy-vault fixture")
    return fixture


def unpack(fixture: Dict[str, Any], destination: Union[str, Path]) -> Path:
    """Write the fixture's data directory to *destination*, which must not exist yet.

    Every file is checked against the digest recorded when the fixture was
    built, so a fixture damaged in transit fails here and not in a decryption
    three calls later.
    """
    target = Path(destination)
    target.mkdir(mode=0o700)
    for directory in fixture["directories"]:
        (target / directory["path"]).mkdir(mode=0o700)
    for item in fixture["files"]:
        data = base64.b64decode("".join(item["base64"]), validate=True)
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError(f"fixture file {item['path']} does not match its recorded digest")
        path = target / item["path"]
        path.write_bytes(data)
        os.chmod(path, int(item["mode"], 8))
    for directory in reversed(fixture["directories"]):
        os.chmod(target / directory["path"], int(directory["mode"], 8))
    return target
