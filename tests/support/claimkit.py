"""Helpers shared by the claim tests in ``tests/claims``.

They drive the real command line through the ``cli`` fixture (a subprocess in
the isolated environment of ``tests/conftest.py``) and look at what it left on
disk. Nothing here knows the vault format: the tests stay black-box.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from conftest import PASSWORD

Cli = Callable[..., subprocess.CompletedProcess]

#: A TOTP seed made up for the tests (RFC 6238's own example key, in base32).
TOTP_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def ok(result: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    """The result, after checking that the command succeeded (its stderr is the message if not)."""
    assert result.returncode == 0, f"exit {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    return result


def fails(result: subprocess.CompletedProcess, status: int) -> subprocess.CompletedProcess:
    """The result, after checking that the command failed with exactly *status*."""
    assert result.returncode == status, (
        f"expected exit {status}, got {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    return result


def document(result: subprocess.CompletedProcess) -> Any:
    """The one JSON document a --json command printed on stdout."""
    return json.loads(ok(result).stdout)


def init(cli: Cli, *args: str, password: str = PASSWORD, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """``irondome init`` with the master password on stdin; its JSON report (holds the recovery key)."""
    return document(cli("init", "--password-stdin", "--json", *args, stdin=password + "\n", env=env))


def add(
    cli: Cli,
    name: str,
    value: str,
    *args: str,
    password: str = PASSWORD,
    totp: Optional[str] = None,
    fields: Optional[Dict[str, str]] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """``irondome add NAME --value-stdin`` (``--totp-stdin`` when *totp* is given, ``--field NAME`` per field).

    Everything secret is on stdin, in the order ``add`` reads it: the master
    password, the value, the TOTP secret, then one line per custom field.
    """
    fields = fields or {}
    lines = [password, value] + ([totp] if totp is not None else []) + list(fields.values())
    extra = ["--totp-stdin"] if totp is not None else []
    for field in fields:
        extra += ["--field", field]
    return document(
        cli("add", name, "--password-stdin", "--value-stdin", "--json", *extra, *args,
            stdin="\n".join(lines) + "\n", env=env)
    )


def grant(
    cli: Cli, *refs: str, args: Sequence[str] = (), password: str = PASSWORD, env: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """``irondome grant create REF...``: its JSON report, whose ``token`` is the grant token."""
    return document(cli("grant", "create", *refs, "--password-stdin", "--json", *args, stdin=password + "\n", env=env))


def session(cli: Cli, *, password: str = PASSWORD, env: Optional[Dict[str, str]] = None) -> str:
    """``irondome unlock --print-token``: a session token."""
    return ok(cli("unlock", "--print-token", "--password-stdin", stdin=password + "\n", env=env)).stdout.strip()


def mac_screen_locked() -> bool:
    """True while this Mac's console is locked (``IOConsoleLocked`` in the I/O Registry).

    Then the Secure Enclave helper answers every refusal with "this Mac is
    locked": a refusal while locked says nothing about the key itself.
    """
    if sys.platform != "darwin":
        return False
    shown = subprocess.run(["/usr/sbin/ioreg", "-n", "Root", "-d1"], capture_output=True, text=True, timeout=30,
                           env={"PATH": "/usr/bin:/bin"})
    return '"IOConsoleLocked" = Yes' in shown.stdout


def irondome_dirs() -> Dict[str, Path]:
    """The isolated vault root and device root of the running test."""
    return {"home": Path(os.environ["IRONDOME_HOME"]), "device": Path(os.environ["IRONDOME_DEVICE_DIR"])}


def files(*roots: Path) -> List[Path]:
    """Every regular file below *roots*."""
    found: List[Path] = []
    for root in roots:
        if root.exists():
            found.extend(path for path in sorted(root.rglob("*")) if path.is_file() and not path.is_symlink())
    return found


def contents(*roots: Path) -> Dict[str, bytes]:
    """``{path: bytes}`` for every file below *roots*."""
    return {str(path): path.read_bytes() for path in files(*roots)}


def copy_tree(source: Path, target: Path) -> None:
    """A bit-perfect copy, the way a backup or an SSD that kept every block would hold it."""
    shutil.copytree(str(source), str(target), symlinks=True)


def restore_tree(copy: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(str(target))
    shutil.copytree(str(copy), str(target), symlinks=True)


def found_in(data: bytes, secrets: Iterable[str]) -> List[str]:
    """Which of *secrets* appear in *data*, raw (UTF-8) or JSON-escaped."""
    hits = []
    for secret in secrets:
        forms = {secret.encode("utf-8"), json.dumps(secret)[1:-1].encode("utf-8")}
        if any(form and form in data for form in forms):
            hits.append(secret)
    return hits
