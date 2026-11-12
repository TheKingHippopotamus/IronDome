"""Claim ``process-hardened``: no core dumps, and on Linux no debugger from your other programs.

Statement: IronDome turns off core dumps for itself, and on Linux also marks
itself non-dumpable, which stops other processes of the same user from
attaching a debugger or reading its memory.

The proofs run the real command line. A process's limits pass to the
programs it starts, so the program ``irondome run`` starts reports the core
limit IronDome gave itself; each test first raises the limit IronDome is
started with as far as the session allows, so that a zero cannot come from
the session. On Linux the test reads ``/proc/<pid>/mem`` of a running
``irondome mcp`` as its parent, which the kernel otherwise allows.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Dict, Optional, Tuple

import pytest

from conftest import PASSWORD
from support.claimkit import add, init

pytestmark = pytest.mark.skipif(os.name != "posix", reason="core limits and /proc are POSIX")

CORE = "import resource; print(resource.getrlimit(resource.RLIMIT_CORE))"


def _allowed_core() -> Tuple[int, int]:
    """The core limit a program started from this session may raise itself to: (soft, hard)."""
    import resource

    _soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    if hard == 0:
        pytest.skip("core dumps are already off for this whole session, so nothing would tell IronDome's doing apart")
    return hard, hard


def core_limit_of_a_program_irondome_runs(cli, extra: Optional[Dict[str, str]] = None) -> str:
    """``irondome run -- python -c CORE`` started with core dumps allowed; what the program printed."""
    import resource

    init(cli)
    add(cli, "bank", "the-bank-password-5678")
    allowed = _allowed_core()
    done = subprocess.run(
        [sys.executable, "-m", "irondome", "run", "--env", "VALUE=bank", "--password-stdin", "--",
         sys.executable, "-c", CORE],
        input=PASSWORD + "\n", capture_output=True, text=True, timeout=120, env=dict(os.environ, **(extra or {})),
        preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, allowed),
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def test_irondome_turns_off_core_dumps_for_itself(cli):
    assert core_limit_of_a_program_irondome_runs(cli) == "(0, 0)"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the non-dumpable flag is Linux's")
def test_on_linux_another_process_of_yours_cannot_read_irondomes_memory(cli):
    """Its parent, which may read any ordinary child's memory, is refused IronDome's."""
    control = subprocess.Popen([sys.executable, "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE)
    server = subprocess.Popen([sys.executable, "-m", "irondome", "mcp"], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        hello = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}
        assert server.stdin is not None and server.stdout is not None
        server.stdin.write((json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": hello}) +
                            "\n").encode())
        server.stdin.flush()
        assert json.loads(server.stdout.readline())["id"] == 1  # it is serving, so it has hardened itself
        try:
            open(f"/proc/{control.pid}/mem", "rb").close()  # an ordinary child of ours: allowed
        except PermissionError:
            pytest.skip("this kernel refuses a parent even an ordinary child's memory (Yama ptrace_scope 2 or 3)")
        with pytest.raises(PermissionError):
            open(f"/proc/{server.pid}/mem", "rb").close()
    finally:
        for process in (server, control):
            assert process.stdin is not None
            process.stdin.close()
            process.wait(timeout=60)


# -- the boundary ------------------------------------------------------------------


def test_boundary_irondome_debug_switches_it_off_and_doctor_says_so(cli):
    """IRONDOME_DEBUG=1 is the documented way to get a debugger or a core file; doctor then warns."""
    import resource

    soft, _hard = _allowed_core()
    shown = core_limit_of_a_program_irondome_runs(cli, {"IRONDOME_DEBUG": "1"})
    assert shown == str((soft, soft))
    done = subprocess.run(
        [sys.executable, "-m", "irondome", "doctor", "--json"], capture_output=True, text=True, timeout=120,
        env=dict(os.environ, IRONDOME_DEBUG="1"),
        preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (soft, soft)),
    )
    assert "core dumps are allowed because IRONDOME_DEBUG=1 is set" in done.stdout + done.stderr
