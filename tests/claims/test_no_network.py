"""Claim ``no-network``: IronDome cannot make a network connection.

Statement: no module imports a networking library, and every command works
with socket creation disabled. There is no account, no sync, no telemetry and
no update check.

Two proofs. Static: every module of the package is parsed, and every import,
including dynamic ones, must be on an explicit list of what IronDome may use.
Runtime: every command-line process the suite starts runs with
``tests/support/sitecustomize.py``, which makes creating a socket raise and
logs the attempt; a representative sequence of commands must succeed with no
attempt logged.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

import irondome
from conftest import PASSWORD
from irondome import selftest
from support.claimkit import TOTP_SEED, add, document, grant, init, ok

PACKAGE = Path(irondome.__file__).resolve().parent
SUPPORT = Path(__file__).resolve().parents[1] / "support"

#: The standard-library modules IronDome uses. Anything else, except cryptography and irondome itself, fails.
ALLOWED_STDLIB = frozenset(
    """
    __future__ abc argparse ast atexit base64 binascii codecs collections contextlib copy csv ctypes dataclasses
    datetime difflib errno fcntl fnmatch functools gc getpass grp hashlib heapq hmac importlib io itertools json math
    mmap msvcrt os pathlib platform plistlib pwd queue re resource secrets selectors shlex shutil signal stat string
    struct subprocess sys tempfile termios textwrap threading time traceback typing unicodedata urllib winreg
    """.split()
)
#: Named on purpose, so that adding one of them to the list above is a visible decision.
FORBIDDEN = frozenset(
    """
    socket ssl http urllib.request ftplib smtplib poplib imaplib telnetlib xmlrpc asyncio requests httpx aiohttp
    """.split()
)
#: Where ``selectors`` may be imported: it waits on pipes there, and with socket refused it can wait on nothing else.
SELECTORS_ONLY_IN = {"agent/runner.py"}
#: The only part of urllib that is allowed: text parsing, no I/O.
URLLIB_ONLY = {"urllib.parse"}


def modules() -> Dict[str, ast.AST]:
    return {path.relative_to(PACKAGE).as_posix(): ast.parse(path.read_text(encoding="utf-8"), str(path))
            for path in sorted(PACKAGE.rglob("*.py"))}


def static_imports() -> List[tuple]:
    found = []
    for where, tree in modules().items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.extend((where, alias.name) for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.append((where, node.module))
    return found


def dynamic_imports() -> List[tuple]:
    found = []
    for where, tree in modules().items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                function = node.func
                name = function.attr if isinstance(function, ast.Attribute) else getattr(function, "id", None)
                if name in ("__import__", "import_module"):
                    found.append((where, node))
    return found


def problem(module: str, where: str) -> str:
    root = module.split(".")[0]
    parts = module.split(".")
    if any(".".join(parts[: count + 1]) in FORBIDDEN for count in range(len(parts))):
        return f"{where}: imports {module}, a networking module"
    if root in ("irondome", "cryptography"):
        return ""
    if root == "urllib" and module not in URLLIB_ONLY and not any(module.startswith(u + ".") for u in URLLIB_ONLY):
        return f"{where}: imports {module}; only urllib.parse is allowed"
    if root == "selectors" and where not in SELECTORS_ONLY_IN:
        return f"{where}: imports selectors outside the pipe pump"
    if root not in ALLOWED_STDLIB:
        return f"{where}: imports {module}, which is not on the list of modules IronDome may use"
    return ""


def test_no_module_imports_a_networking_library():
    problems = [problem(module, where) for where, module in static_imports()]
    assert [text for text in problems if text] == []


def test_the_forbidden_modules_are_named_and_none_of_them_is_allowed():
    for name in FORBIDDEN:
        assert problem(name, "anywhere.py"), name
    assert problem("selectors", "anywhere.py")
    assert problem("urllib.request.urlopen", "anywhere.py")
    assert not problem("urllib.parse", "otp.py")


def test_every_dynamic_import_names_an_allowed_module_literally():
    problems = []
    for where, node in dynamic_imports():
        argument = node.args[0] if node.args else None
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
            text = problem(argument.value, where)
            if text:
                problems.append(text + " (dynamically)")
        elif where != "device/__init__.py":
            problems.append(f"{where}: imports a module whose name is computed at run time")
    assert problems == []


def test_the_device_backend_registry_names_only_irondome_modules():
    """irondome.device imports its backends by name; the names come from one literal table."""
    tree = modules()["device/__init__.py"]
    tables = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "_REGISTRY" for target in node.targets)]
    assert len(tables) == 1
    registry = ast.literal_eval(tables[0].value)
    assert [module for _name, module, _cls in registry] == [
        "irondome.device.macos_se", "irondome.device.linux_tpm", "irondome.device.software"
    ]
    from irondome import device

    assert [module for _name, module, _cls in device._REGISTRY] == [module for _n, module, _c in registry]


def test_the_check_irondome_verify_ships_agrees_with_this_one():
    assert FORBIDDEN <= selftest.FORBIDDEN_IMPORTS
    assert not {name.split(".")[0] for name in selftest.STDLIB_ALLOWED} & FORBIDDEN
    assert {name.split(".")[0] for name in selftest.STDLIB_ALLOWED} <= ALLOWED_STDLIB


def test_the_socket_guard_is_in_force_in_the_processes_the_suite_starts(tmp_path):
    """The control: without it, a command that 'works with sockets disabled' would prove nothing."""
    log = tmp_path / "sockets.log"
    env = dict(os.environ, PYTHONPATH=str(SUPPORT), IRONDOME_TEST_BLOCK_SOCKETS="1", IRONDOME_TEST_SOCKET_LOG=str(log))
    code = "import socket\ntry:\n    socket.socket()\nexcept PermissionError:\n    print('refused')\n"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60)
    assert result.stdout.strip() == "refused"
    assert "socket.socket() refused" in log.read_text()


def test_every_command_of_a_working_day_runs_with_socket_creation_refused(cli, tmp_path):
    log = tmp_path / "sockets.log"
    guarded = {"IRONDOME_TEST_SOCKET_LOG": str(log)}
    stdin = PASSWORD + "\n"
    init(cli, env=guarded)
    add(cli, "github", "a-token-value-1234", "--alias", "GITHUB_TOKEN", totp=TOTP_SEED, env=guarded)
    assert ok(cli("get", "github", "--password-stdin", stdin=stdin, env=guarded)).stdout == "a-token-value-1234"
    probe = "import os; print(len(os.environ['GITHUB_TOKEN']))"
    ran = ok(cli("run", "--env", "GITHUB_TOKEN", "--password-stdin", "--", sys.executable, "-c", probe,
                 stdin=stdin, env=guarded))
    assert ran.stdout.strip() == "18"
    token = grant(cli, "GITHUB_TOKEN", args=("--uses", "2"), env=guarded)["token"]
    as_agent = dict(guarded, IRONDOME_GRANT=token)
    through_grant = ok(cli("run", "--env", "GITHUB_TOKEN", "--", sys.executable, "-c", probe, env=as_agent))
    assert through_grant.stdout.strip() == "18"
    assert ok(cli("otp", "github", "--password-stdin", stdin=stdin, env=guarded)).stdout.strip().isdigit()
    assert ok(cli("audit", "--verify", "--password-stdin", stdin=stdin, env=guarded)).returncode == 0
    assert document(cli("status", "--json", env=guarded))["exists"] is True
    report = document(cli("nuke", "--yes-destroy-everything", "--password-stdin", "--json", stdin=stdin, env=guarded))
    assert report["success"]
    assert not log.exists() or log.read_text() == ""


def test_in_process_sockets_are_refused_too_and_the_library_does_not_mind(make_vault):
    """tests/conftest.py replaces socket.socket for every in-process test; a whole vault life runs under it."""
    import socket

    from irondome.vault import Secret

    try:
        socket.socket()
        raised = False
    except AssertionError:
        raised = True
    assert raised
    vault, _recovery = make_vault()
    with vault:
        vault.add("entry", Secret(password="a value"))
        vault.commit()
        assert vault.value(vault.find("entry")) == "a value"


# -- the boundary ------------------------------------------------------------------


def test_boundary_a_program_started_with_irondome_run_is_free_to_use_sockets(cli):
    init(cli)
    add(cli, "github", "a-token-value-1234", "--alias", "GITHUB_TOKEN")
    code = "import socket; a, b = socket.socketpair(); a.sendall(b'x'); print(b.recv(1).decode())"
    unguarded = {"IRONDOME_TEST_BLOCK_SOCKETS": "0"}
    ran = ok(cli("run", "--env", "GITHUB_TOKEN", "--password-stdin", "--", sys.executable, "-c", code,
                 stdin=PASSWORD + "\n", env=unguarded))
    assert ran.stdout.strip() == "x"
