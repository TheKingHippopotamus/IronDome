"""Test-only: refuse network sockets in every Python process the test suite starts.

``tests/conftest.py`` puts this directory first on ``PYTHONPATH`` for the
command-line subprocesses its ``cli`` fixture starts, and sets
``IRONDOME_TEST_BLOCK_SOCKETS=1``. Python imports ``sitecustomize`` at start-up,
before any IronDome code runs, so from then on creating a socket in that
process raises ``PermissionError``: ``socket.socket``, ``socket.create_connection``,
``socket.create_server``, ``socket.socketpair`` and ``socket.fromfd``, and the
C-level ``_socket.socket``.

With ``IRONDOME_TEST_SOCKET_LOG`` naming a file, every refused attempt is also
appended to it with the stack that made it, so a test can tell "nothing tried"
from "something tried and swallowed the error".

This file shadows any other ``sitecustomize`` on the path; the next one found
is run afterwards, so the environment behaves as it would without it.
"""

import errno
import os
import sys


def _note(what: str) -> None:
    log = os.environ.get("IRONDOME_TEST_SOCKET_LOG")
    if not log:
        return
    import traceback

    stack = "".join(traceback.format_stack(limit=16)[:-2])
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(f"{what} refused in process {os.getpid()}\n{stack}\n")


def _refusal(what: str) -> PermissionError:
    _note(what)
    return PermissionError(errno.EPERM, f"{what}: network sockets are blocked by the IronDome test suite")


def _block_sockets() -> None:
    import _socket
    import socket

    class BlockedSocket(socket.socket):
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise _refusal("socket.socket()")

    def blocked(name: str):
        def refuse(*args: object, **kwargs: object) -> None:
            raise _refusal(f"socket.{name}()")

        return refuse

    socket.socket = BlockedSocket  # type: ignore[misc]
    _socket.socket = BlockedSocket  # type: ignore[misc]
    for name in ("create_connection", "create_server", "socketpair", "fromfd"):
        if hasattr(socket, name):
            setattr(socket, name, blocked(name))


def _run_next_sitecustomize() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    for entry in sys.path:
        if not entry or os.path.abspath(entry) == here:
            continue
        candidate = os.path.join(entry, "sitecustomize.py")
        if os.path.isfile(candidate):
            import importlib.util

            spec = importlib.util.spec_from_file_location("_next_sitecustomize", candidate)
            if spec is not None and spec.loader is not None:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            return


if os.environ.get("IRONDOME_TEST_BLOCK_SOCKETS") == "1":
    _block_sockets()
_run_next_sitecustomize()
