"""End to end: the MCP server over real pipes, against a real vault, real grants and the audit log.

The server runs in a child process inside the isolated environment of
``tests/conftest.py``, started the way a client starts it: ``irondome mcp``
(``python -m irondome mcp``). A test that needs something in place first (the
stand-in sensor below) runs that, then the command line's ``main``. Should the
command line be unable to start, ``mcp.serve()`` is called directly instead
and ``test_the_command_line_serves_mcp`` reports a skip.

Touch ID mode runs against a stand-in sensor: a device backend that keeps its
key in a file and answers the way the test tells it to. IRONDOME_NO_TOUCH=1
stays set throughout, so the real Secure Enclave helper never shows a prompt.
"""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pytest

from irondome import audit, caps, device, keys, otp, paths
from irondome.device.base import DEVICE_SECRET_LEN, POLICY_BIOMETRY, POLICY_DEVICE, new_ref
from irondome.device.software import SoftwareBackend
from irondome.errors import AuthError
from irondome.secmem import SecureBuffer
from irondome.vault import Secret

GITHUB = "ghp_e2eSecretValue0123456789"
BANK = "bank-Reveal-Me-0042"
PRIVATE = "never-for-agents-77"
TINY = "ab3"
TOTP_SEED = "JBSWY3DPEHPK3PXP"
#: Values that must never reach the server's output unless a test reveals them on purpose.
VALUES = (GITHUB, BANK, PRIVATE, TOTP_SEED)
#: Upper bound, in seconds, for anything that waits on the server.
PATIENCE = 120.0

MODERN_META: Dict[str, Any] = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientInfo": {"name": "e2e", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}
TOOL_NAMES = ["list_secrets", "run_with_secrets", "get_totp", "reveal_secret"]
_SUPPORT = Path(__file__).resolve().parents[1] / "support"


# ---------------------------------------------------------------------------
# A stand-in Touch ID sensor
# ---------------------------------------------------------------------------


class FakeSensor(SoftwareBackend):
    """A Touch ID keyslot for tests: a key file, and a sensor that answers as FAKE_TOUCH_ANSWER says.

    Every prompt is logged, one JSON object per line, to FAKE_TOUCH_LOG.
    """

    name = "fake-touch"
    policies = (POLICY_DEVICE, POLICY_BIOMETRY)

    def enroll(self, *, policy: str, auth: Optional[SecureBuffer], reason: str) -> Tuple[Dict[str, Any], SecureBuffer]:
        descriptor = {"backend": self.name, "policy": policy, "ref": new_ref()}
        secret = SecureBuffer.random(DEVICE_SECRET_LEN)
        paths.write_atomic(self._path(descriptor), secret.view())
        return descriptor, secret

    def unseal(
        self, descriptor: Dict[str, Any], *, auth: Optional[SecureBuffer], interactive: bool, reason: str
    ) -> SecureBuffer:
        if descriptor.get("policy") != POLICY_DEVICE:
            prompt = {"reason": reason, "interactive": interactive, "timeout": os.environ.get("IRONDOME_TOUCH_TIMEOUT")}
            with open(os.environ["FAKE_TOUCH_LOG"], "a", encoding="utf-8") as log:
                log.write(json.dumps(prompt) + "\n")
            if not interactive:
                raise AuthError("Touch ID is required, and no prompt may be shown here")
            if os.environ.get("FAKE_TOUCH_ANSWER") == "deny":
                raise AuthError("Touch ID did not authorise this: the owner cancelled")
        return super().unseal(descriptor, auth=auth, interactive=interactive, reason=reason)


def install_fake_sensor() -> None:
    """What the server process runs before serving: the fake sensor stands in for the Mac's."""
    from irondome import device, unlock
    from irondome.cli import context

    device._instances[FakeSensor.name] = FakeSensor()
    unlock.can_ask_for_touch = lambda: True
    context.can_ask_for_touch = lambda: True


_SENSOR_PRELUDE = """\
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional, Tuple

from irondome import paths
from irondome.device.base import DEVICE_SECRET_LEN, POLICY_BIOMETRY, POLICY_DEVICE, new_ref
from irondome.device.software import SoftwareBackend
from irondome.errors import AuthError
from irondome.secmem import SecureBuffer
"""


#: Run before the server, so that its Touch ID prompts go to the fake sensor.
SENSOR = "\n".join(
    (
        _SENSOR_PRELUDE,
        inspect.getsource(FakeSensor),
        inspect.getsource(install_fake_sensor),
        "install_fake_sensor()",
        "",
    )
)


# ---------------------------------------------------------------------------
# Speaking to the server
# ---------------------------------------------------------------------------


def server_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """The isolated environment, as the ``cli`` fixture hands it to a child."""
    env = dict(os.environ)
    if _SUPPORT.is_dir():
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(_SUPPORT), env.get("PYTHONPATH", "")]))
        env["IRONDOME_TEST_BLOCK_SOCKETS"] = "1"
    env.update(extra or {})
    return env


@functools.lru_cache(maxsize=None)
def command_line_ready() -> bool:
    """True once ``python -m irondome`` can start: every command module is in place."""
    try:
        probe = subprocess.run(
            [sys.executable, "-m", "irondome", "mcp", "--help"], capture_output=True, env=server_env(), timeout=PATIENCE
        )
    except subprocess.TimeoutExpired:
        return False
    return probe.returncode == 0


def server_command(prelude: str = "", touch_timeout: Optional[int] = None) -> List[str]:
    """How a client starts the server, after running *prelude* in the same process."""
    options = [] if touch_timeout is None else ["--touch-timeout", str(touch_timeout)]
    if command_line_ready():
        if not prelude:
            return [sys.executable, "-m", "irondome", "mcp", *options]
        entry = f"import sys\nfrom irondome.cli.main import main\nsys.exit(main({['mcp', *options]!r}))\n"
    else:
        argument = "" if touch_timeout is None else f"touch_timeout={touch_timeout}"
        entry = f"import sys\nfrom irondome import mcp\nsys.exit(mcp.serve({argument}))\n"
    return [sys.executable, "-c", prelude + entry]


def rpc(method: str, params: Optional[Dict[str, Any]] = None, request_id: Any = 1, *, modern: bool = True) -> Dict:
    body = dict(params or {})
    if modern:
        body["_meta"] = MODERN_META
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": body}


def tool(name: str, arguments: Dict[str, Any], request_id: Any = 1, *, modern: bool = True) -> Dict:
    return rpc("tools/call", {"name": name, "arguments": arguments}, request_id, modern=modern)


def cancel(request_id: Any) -> Dict:
    params = {"requestId": request_id, "reason": "test"}
    return {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": params}


def protocol_line(line: bytes) -> Dict[str, Any]:
    """One line of the server's stdout: a complete JSON-RPC 2.0 message and nothing else."""
    assert line.endswith(b"\n") and line.count(b"\n") == 1 and line.isascii(), line[:200]
    body = json.loads(line)
    assert isinstance(body, dict) and body.get("jsonrpc") == "2.0", body
    if "id" in body:
        assert ("result" in body) != ("error" in body), body
    else:
        assert body["method"].startswith("notifications/"), body
    return body


def python(code: str) -> List[str]:
    return [sys.executable, "-I", "-S", "-c", code]


def ok(result: Dict[str, Any]) -> Dict[str, Any]:
    """The structured content of a successful tool result, checked against its text mirror."""
    assert result["isError"] is False, result["content"][0]["text"]
    assert result["resultType"] == "complete"
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    return result["structuredContent"]


def refused(result: Dict[str, Any]) -> str:
    """The message of a tool result that reports a failure."""
    assert result["isError"] is True, result
    assert "structuredContent" not in result
    return result["content"][0]["text"]


def started_path(command: str) -> str:
    """The path the server starts *command* by, as its Touch ID prompt names it: its directory resolved."""
    found = shutil.which(command)
    assert found is not None, f"{command} is not installed"
    return os.path.join(os.path.realpath(os.path.dirname(found)), os.path.basename(found))


def wait_for(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + PATIENCE
    while not condition():
        assert time.monotonic() < deadline, "timed out waiting"
        time.sleep(0.02)


class McpServer:
    """The server in a child process, spoken to over its pipes, one request at a time or ahead of time."""

    def __init__(self, command: List[str], env: Optional[Dict[str, str]], *, cwd: Path) -> None:
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=server_env(env),
            cwd=str(cwd),
        )
        self.stdout_lines: List[bytes] = []
        self._lines: "queue.Queue[Optional[bytes]]" = queue.Queue()
        self._stderr = bytearray()
        self._threads = [
            threading.Thread(target=self._pump_stdout, daemon=True),
            threading.Thread(target=self._pump_stderr, daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        self._next_id = 0

    def _pump_stdout(self) -> None:
        assert self.process.stdout is not None
        for line in iter(self.process.stdout.readline, b""):
            self.stdout_lines.append(line)
            self._lines.put(line)
        self._lines.put(None)

    def _pump_stderr(self) -> None:
        assert self.process.stderr is not None
        for chunk in iter(lambda: self.process.stderr.read1(65536), b""):  # type: ignore[union-attr]
            self._stderr += chunk

    @property
    def stderr(self) -> str:
        return self._stderr.decode("utf-8", "replace")

    def send(self, body: Any) -> None:
        self.send_raw(json.dumps(body).encode("utf-8") + b"\n")

    def send_raw(self, data: bytes) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def receive(self) -> Dict[str, Any]:
        line = self._lines.get(timeout=PATIENCE)
        assert line is not None, f"the server closed its stdout; stderr: {self.stderr}"
        return protocol_line(line)

    def request(self, method: str, params: Optional[Dict[str, Any]] = None, *, modern: bool = True) -> Dict:
        self._next_id += 1
        self.send(rpc(method, params, self._next_id, modern=modern))
        reply = self.receive()
        assert reply["id"] == self._next_id, reply
        return reply

    def call(self, name: str, arguments: Optional[Dict[str, Any]] = None, *, modern: bool = True) -> Dict:
        return self.request("tools/call", {"name": name, "arguments": arguments or {}}, modern=modern)["result"]

    def close(self) -> int:
        """End the input, as a client does to shut a server down. Returns its exit status."""
        assert self.process.stdin is not None
        self.process.stdin.close()
        status = self.process.wait(PATIENCE)
        for thread in self._threads:
            thread.join(PATIENCE)
        for line in self.stdout_lines:
            protocol_line(line)
        return status

    def everything(self) -> str:
        return b"".join(self.stdout_lines).decode("ascii") + self.stderr

    def kill(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(PATIENCE)


class Servers:
    def __init__(self, cwd: Path) -> None:
        self.cwd = cwd
        self.started: List[McpServer] = []

    def start(
        self,
        env: Optional[Dict[str, str]] = None,
        *,
        prelude: str = "",
        touch_timeout: Optional[int] = None,
        argv: Optional[List[str]] = None,
    ) -> McpServer:
        command = [sys.executable, *argv] if argv is not None else server_command(prelude, touch_timeout)
        server = McpServer(command, env, cwd=self.cwd)
        self.started.append(server)
        return server


@pytest.fixture
def servers(tmp_path: Path) -> Iterator[Servers]:
    pool = Servers(tmp_path)
    yield pool
    for server in pool.started:
        server.kill()


def converse(
    bodies: List[Any], cwd: Path, *, env: Optional[Dict[str, str]] = None, raw: bytes = b"", prelude: str = ""
) -> Tuple[int, List[Dict[str, Any]], str]:
    """Send everything at once, close the input, and collect every line the server wrote."""
    data = b"".join(json.dumps(body).encode("utf-8") + b"\n" for body in bodies) + raw
    finished = subprocess.run(
        server_command(prelude),
        input=data,
        capture_output=True,
        env=server_env(env),
        cwd=str(cwd),
        timeout=PATIENCE,
    )
    replies = [protocol_line(line) for line in finished.stdout.splitlines(keepends=True)]
    return finished.returncode, replies, finished.stderr.decode("utf-8", "replace")


def assert_nothing_leaked(text: str, *also: str) -> None:
    for value in VALUES + also:
        assert value not in text, f"{value[:6]}... leaked"


def snapshot(root: Path) -> Dict[str, Tuple[Any, ...]]:
    """Every file and directory under *root*: kind, size, modification time and content hash."""
    state: Dict[str, Tuple[Any, ...]] = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        name = str(path.relative_to(root))
        if path.is_symlink():
            state[name] = ("link", os.readlink(path))
        elif path.is_dir():
            state[name] = ("dir", info.st_mtime_ns)
        else:
            state[name] = ("file", info.st_size, info.st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
    return state


# ---------------------------------------------------------------------------
# A vault with something in it
# ---------------------------------------------------------------------------


class World:
    """The vault of the isolated bunker alpha, and the grants a test hands to the server."""

    def __init__(self, vault: Any) -> None:
        self.vault = vault

    def grant(self, references: List[str], *, mode: str = "use", uses: Optional[int] = 1) -> str:
        token, _ = caps.create_grant(self.vault, references, mode=mode, ttl=900, uses=uses)
        return token

    def _info(self, token: str) -> Optional[caps.CapInfo]:
        cap_id = caps.parse_token(token)[1]
        return next((info for info in caps.list_caps() if info.id == cap_id), None)

    def exists(self, token: str) -> bool:
        return self._info(token) is not None

    def uses_left(self, token: str) -> Optional[int]:
        info = self._info(token)
        assert info is not None, "the grant is gone"
        return info.uses_left

    def events(self, kid: str = audit.KID_VAULT) -> List[audit.AuditEvent]:
        return [event for event in audit.read(self.vault) if event.kid == kid]


@pytest.fixture
def world(make_vault: Callable[..., Any]) -> World:
    vault, _ = make_vault(with_recovery=False)
    github = vault.add("github", Secret(password=GITHUB), agent="use")
    bank = vault.add("bank", Secret(password=BANK), agent="reveal")
    vault.add("private", Secret(password=PRIVATE), agent="deny")
    mfa = vault.add("mfa", Secret(totp=otp.make_totp(TOTP_SEED)), agent="use")
    vault.add("tiny", Secret(password=TINY), agent="use")
    vault.set_alias("GITHUB_TOKEN", github)
    vault.set_alias("BANK_PIN", bank)
    vault.set_alias("MFA", mfa, "totp")
    vault.commit()
    return World(vault)


class Touch:
    """The fake sensor's side of a test: where its prompts are logged and how it answers."""

    def __init__(self, log: Path) -> None:
        self.log = log

    def env(self, **extra: str) -> Dict[str, str]:
        return dict(extra, FAKE_TOUCH_LOG=str(self.log))

    def prompts(self) -> List[Dict[str, Any]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def reasons(self) -> List[str]:
        return [prompt["reason"] for prompt in self.prompts()]


@pytest.fixture
def touch(world: World, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Touch:
    """Give the vault a Touch ID keyslot held by the fake sensor."""
    sensor = FakeSensor()
    monkeypatch.setitem(device._instances, FakeSensor.name, sensor)
    vault = world.vault
    vault.add_slot(keys.create_device_slot(vault.vault_key, vault.vault_id, backend=sensor, policy=POLICY_BIOMETRY))
    vault.commit()
    return Touch(tmp_path / "touch.log")


# ---------------------------------------------------------------------------
# Both eras over the wire
# ---------------------------------------------------------------------------


def test_a_modern_client_lists_and_uses_secrets_through_a_grant(world: World, servers: Servers) -> None:
    token = world.grant(["GITHUB_TOKEN", "MFA"], uses=5)
    server = servers.start({"IRONDOME_GRANT": token})
    discovered = server.request("server/discover")["result"]
    assert discovered["supportedVersions"] == ["2026-07-28"]
    assert discovered["capabilities"] == {"tools": {"listChanged": False}}
    assert [entry["name"] for entry in server.request("tools/list")["result"]["tools"]] == TOOL_NAMES
    assert ok(server.call("list_secrets")) == {
        "secrets": [{"name": "GITHUB_TOKEN", "kind": "value"}, {"name": "MFA", "kind": "totp"}],
        "mode": "grant",
        "can_reveal": False,
    }
    command = python("import os; print(os.environ['TOKEN'])")
    ran = server.call("run_with_secrets", {"command": command, "env": {"TOKEN": "GITHUB_TOKEN"}})
    assert ok(ran) == {"exit_code": 0, "stdout": "[irondome:TOKEN]\n", "stderr": "", "truncated": False}
    assert server.close() == 0
    assert_nothing_leaked(server.everything(), token)
    assert world.uses_left(token) == 4


def test_an_older_client_shakes_hands_first(world: World, servers: Servers) -> None:
    token = world.grant(["GITHUB_TOKEN"], uses=2)
    server = servers.start({"IRONDOME_GRANT": token})
    hello = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "old", "version": "1"}}
    answer = server.request("initialize", hello, modern=False)["result"]
    assert answer["protocolVersion"] == "2025-06-18"
    assert answer["serverInfo"] == {"name": "irondome", "version": "4.0.0"}
    server.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert [entry["name"] for entry in server.request("tools/list", modern=False)["result"]["tools"]] == TOOL_NAMES
    assert server.request("ping", modern=False)["result"] == {}
    command = python("import os; print(len(os.environ['TOKEN']))")
    ran = ok(server.call("run_with_secrets", {"command": command, "env": {"TOKEN": "GITHUB_TOKEN"}}, modern=False))
    assert ran["stdout"] == f"{len(GITHUB)}\n"
    assert server.close() == 0
    assert [protocol_line(line)["id"] for line in server.stdout_lines] == [1, 2, 3, 4]
    assert world.uses_left(token) == 1


def test_discovery_and_tools_list_touch_no_file_and_spend_no_use(world: World, tmp_path: Path) -> None:
    token = world.grant(["GITHUB_TOKEN"], uses=1)
    for lock in tmp_path.rglob("*.lock"):
        lock.unlink()  # nothing holds them now; a lock taken by the server would bring one back
    before = snapshot(tmp_path)
    bodies = [
        rpc("server/discover", request_id="server-discover-probe-1"),
        rpc("tools/list", request_id=0),
        rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}}, 1, modern=False),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        rpc("tools/list", request_id=2, modern=False),
        rpc("ping", request_id=3, modern=False),
        rpc("subscriptions/listen", {"notifications": {"toolsListChanged": True}}, "listen-1"),
        rpc("resources/list", request_id=4),
    ]
    status, replies, stderr = converse(bodies, tmp_path, env={"IRONDOME_GRANT": token}, raw=b"junk\n")
    assert status == 0, stderr
    expected = ["server-discover-probe-1", 0, 1, 2, 3, "notice", 4, None]
    assert [reply.get("id", "notice") for reply in replies] == expected
    assert snapshot(tmp_path) == before
    assert world.uses_left(token) == 1
    assert stderr == ""


def test_protocol_errors_on_the_wire(world: World, tmp_path: Path) -> None:
    unsupported = rpc("tools/list", request_id=2)
    unsupported["params"]["_meta"] = dict(MODERN_META, **{"io.modelcontextprotocol/protocolVersion": "2030-01-01"})
    anonymous = rpc("tools/list", request_id=3)
    anonymous["params"]["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    bodies = [
        tool("no_such_tool", {}, 1),
        unsupported,
        anonymous,
        rpc("ping", request_id=4),
        rpc("tools/list", request_id=5, modern=False),
        {"jsonrpc": "2.0", "id": True, "method": "ping"},
    ]
    status, replies, _ = converse(bodies, tmp_path)
    assert status == 0
    assert [(reply["id"], reply["error"]["code"]) for reply in replies] == [
        (1, -32602), (2, -32022), (3, -32602), (4, -32601), (5, -32602), (None, -32600)
    ]
    assert replies[1]["error"]["data"] == {
        "supported": ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"],
        "requested": "2030-01-01",
    }


#: Run before the server: list_secrets then writes to stdout behind the protocol's back.
STRAY_PRELUDE = """\
import os
import sys
from irondome import mcp

listed = mcp.Server._list_secrets


def noisy(self, request_id, arguments):
    print("stray print from inside a tool")
    sys.stdout.flush()
    os.write(1, b"stray bytes on descriptor 1\\n")
    return listed(self, request_id, arguments)


mcp.Server._list_secrets = noisy
"""


def test_nothing_but_protocol_messages_reach_stdout(world: World, tmp_path: Path) -> None:
    token = world.grant(["GITHUB_TOKEN"], uses=1)
    hostile = b"".join(
        (
            b"\xff\xfe\xfd\n",
            b"[" * 200_000 + b"\n",
            b'{"jsonrpc": "2.0", "id": 9, "method": "ping", "params": {"x": NaN}}\n',
            b"x" * (2 * 1024 * 1024) + b"\n",
            b"\x00\n",
            b'[{"jsonrpc": "2.0", "id": 8, "method": "ping"}]\n',
            b'{"jsonrpc": "2.0", "id": 7, "id": 6, "method": "ping"}\n',
        )
    )
    bodies = [tool("list_secrets", {}, "first")]
    status, replies, stderr = converse(
        bodies, tmp_path, env={"IRONDOME_GRANT": token}, raw=hostile, prelude=STRAY_PRELUDE
    )
    assert status == 0, stderr
    assert replies[0]["id"] == "first" and ok(replies[0]["result"])["mode"] == "grant"
    assert [(reply["id"], reply["error"]["code"]) for reply in replies[1:]] == [
        (None, -32700), (None, -32700), (None, -32700), (None, -32600), (None, -32700), (None, -32600),
        (None, -32700),
    ]
    assert "stray print from inside a tool" in stderr and "stray bytes on descriptor 1" in stderr


def test_a_client_that_reads_stderr_through_stdout_still_gets_only_protocol_messages(
    world: World, tmp_path: Path
) -> None:
    token = world.grant(["GITHUB_TOKEN"], uses=1)
    session = "irondome_s_" + "0" * 32 + "_" + "A" * 52  # set, so the server has a warning to give
    data = json.dumps(tool("list_secrets", {}, 1)).encode("utf-8") + b"\nnot json\n"
    finished = subprocess.run(
        server_command(STRAY_PRELUDE),
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=server_env({"IRONDOME_GRANT": token, "IRONDOME_SESSION": session}),
        cwd=str(tmp_path),
        timeout=PATIENCE,
    )
    assert finished.returncode == 0
    replies = [protocol_line(line) for line in finished.stdout.splitlines(keepends=True)]
    assert [(reply["id"], "error" in reply) for reply in replies] == [(1, False), (None, True)]
    assert ok(replies[0]["result"])["mode"] == "grant"


def test_the_server_exits_when_its_input_ends(servers: Servers) -> None:
    server = servers.start()
    assert server.request("tools/list")["result"]["tools"]
    time.sleep(0.3)
    assert server.process.poll() is None  # idle, still serving
    began = time.monotonic()
    assert server.close() == 0
    assert time.monotonic() - began < 20


# ---------------------------------------------------------------------------
# With a grant
# ---------------------------------------------------------------------------


def test_list_secrets_with_a_grant_spends_no_use(world: World, servers: Servers) -> None:
    token = world.grant(["MFA", "GITHUB_TOKEN"], uses=1)
    server = servers.start({"IRONDOME_GRANT": token})
    first = ok(server.call("list_secrets"))
    assert ok(server.call("list_secrets")) == first
    assert [secret["name"] for secret in first["secrets"]] == ["GITHUB_TOKEN", "MFA"]
    assert world.uses_left(token) == 1
    ok(server.call("get_totp", {"reference": "MFA"}))
    assert not world.exists(token)
    assert server.close() == 0


def test_run_with_secrets_injects_the_value_and_masks_it(world: World, servers: Servers) -> None:
    token = world.grant(["GITHUB_TOKEN"], uses=1)
    server = servers.start({"IRONDOME_GRANT": token})
    code = (
        "import base64, os; value = os.environ['TOKEN']; print(value); "
        "print(base64.b64encode(value.encode()).decode()); print(len(value)); "
        "print(sorted(name for name in os.environ if name in ('IRONDOME_GRANT', 'IRONDOME_SESSION')))"
    )
    ran = ok(server.call("run_with_secrets", {"command": python(code), "env": {"TOKEN": "irondome://GITHUB_TOKEN"}}))
    assert ran["stdout"] == f"[irondome:TOKEN]\n[irondome:TOKEN]\n{len(GITHUB)}\n[]\n"
    assert server.close() == 0
    assert_nothing_leaked(server.everything(), token)
    grant_id = caps.parse_token(token)[1]
    records = [(event.action, event.actor, event.target) for event in world.events(grant_id)]
    assert records == [("grant.use", "grant", grant_id), ("use", "grant", "GITHUB_TOKEN")]
    detail = world.events(grant_id)[1].detail
    assert detail.startswith("mcp run_with_secrets TOKEN: ") and "python" in detail


def test_run_with_secrets_honours_its_options(world: World, servers: Servers, tmp_path: Path) -> None:
    token = world.grant(["GITHUB_TOKEN"], uses=10)
    server = servers.start({"IRONDOME_GRANT": token})
    secrets = {"TOKEN": "GITHUB_TOKEN"}
    work = tmp_path / "work"
    work.mkdir()

    def run(code: str, **options: Any) -> Dict[str, Any]:
        return server.call("run_with_secrets", dict(options, command=python(code), env=secrets))

    here = ok(run("import os; print(os.getcwd())", cwd=str(work)))
    assert os.path.samefile(here["stdout"].strip(), work)
    assert ok(run("import sys; print(sys.stdin.read().upper())", stdin="hello"))["stdout"] == "HELLO\n"
    assert ok(run("import sys; print(repr(sys.stdin.read()))"))["stdout"] == "''\n"
    failed = ok(run("import sys; sys.stderr.write('bad'); sys.exit(3)"))
    assert failed == {"exit_code": 3, "stdout": "", "stderr": "bad", "truncated": False}
    big = ok(run("import os; print(os.environ['TOKEN'] + 'x' * 300000)"))
    assert big["truncated"] is True and len(big["stdout"]) == 100_000
    assert big["stdout"].startswith("[irondome:TOKEN]xxx")
    sleeper = "import os, time; print(os.environ['TOKEN'], flush=True); time.sleep(60)"
    stopped = refused(run(sleeper, timeout_seconds=1.5))
    assert "was still running after 1.5 seconds and was stopped" in stopped
    assert "[irondome:TOKEN]" in stopped
    assert server.close() == 0
    assert_nothing_leaked(server.everything(), token)
    assert world.uses_left(token) == 4


@pytest.mark.parametrize(
    ("name", "arguments", "says"),
    [
        ("run_with_secrets", {"command": "printenv TOKEN", "env": {"TOKEN": "GITHUB_TOKEN"}}, "through a shell"),
        ("run_with_secrets", {"command": ["no-such-program-xyz"], "env": {"TOKEN": "GITHUB_TOKEN"}}, "not found"),
        ("run_with_secrets", {"command": ["printenv"], "env": {"T": "GITHUB_TOKEN"}, "cwd": "/no/such"}, "directory"),
        ("run_with_secrets", {"command": ["printenv"], "env": {"TOKEN": "bank"}}, "does not cover 'bank'"),
        ("run_with_secrets", {"command": ["printenv"], "env": {"IRONDOME_GRANT": "GITHUB_TOKEN"}}, "reserved"),
        ("run_with_secrets", {"command": ["printenv"], "env": {"T": "GITHUB_TOKEN"}, "timeout_seconds": 900}, "600"),
        ("get_totp", {"reference": "GITHUB_TOKEN"}, "not a one-time password"),
        ("get_totp", {"reference": "private"}, "does not cover 'private'"),
        ("reveal_secret", {"reference": "GITHUB_TOKEN"}, "Use run_with_secrets"),
        ("reveal_secret", {"reference": "GITHUB_TOKEN", "please": True}, "unknown argument please"),
    ],
)
def test_a_call_the_grant_cannot_serve_spends_no_use(
    world: World, servers: Servers, name: str, arguments: Dict[str, Any], says: str
) -> None:
    token = world.grant(["GITHUB_TOKEN", "MFA"], uses=1)
    server = servers.start({"IRONDOME_GRANT": token})
    assert says in refused(server.call(name, arguments))
    assert world.uses_left(token) == 1
    ok(server.call("get_totp", {"reference": "MFA"}))  # the one use was still there
    assert not world.exists(token)
    assert server.close() == 0


@pytest.mark.parametrize(("granted", "asked"), [("MFA", "MFA"), ("mfa/totp", "mfa/totp"), ("MFA", "irondome://MFA")])
def test_get_totp_returns_the_code_of_the_moment(world: World, servers: Servers, granted: str, asked: str) -> None:
    token = world.grant([granted], uses=1)
    server = servers.start({"IRONDOME_GRANT": token})
    settings = otp.make_totp(TOTP_SEED)
    before = time.time()
    result = ok(server.call("get_totp", {"reference": asked}))
    after = time.time()
    assert result["code"] in {otp.code_at(settings, before), otp.code_at(settings, after)}
    assert 1 <= result["seconds_remaining"] <= 30
    assert server.close() == 0
    assert_nothing_leaked(server.everything(), token)


def test_reveal_secret_needs_a_reveal_grant(world: World, servers: Servers) -> None:
    use_only = world.grant(["GITHUB_TOKEN"], uses=1)
    server = servers.start({"IRONDOME_GRANT": use_only})
    message = refused(server.call("reveal_secret", {"reference": "GITHUB_TOKEN"}))
    assert "lets secrets be used, not shown" in message and "run_with_secrets" in message
    assert server.close() == 0
    assert_nothing_leaked(server.everything(), use_only)
    assert world.uses_left(use_only) == 1

    showing = world.grant(["GITHUB_TOKEN"], mode="reveal", uses=1)
    server = servers.start({"IRONDOME_GRANT": showing})
    assert ok(server.call("list_secrets"))["can_reveal"] is True
    assert ok(server.call("reveal_secret", {"reference": "GITHUB_TOKEN"})) == {"value": GITHUB}
    assert server.close() == 0
    assert not world.exists(showing)
    grant_id = caps.parse_token(showing)[1]
    assert [(event.action, event.target) for event in world.events(grant_id)][-1] == ("reveal", "GITHUB_TOKEN")


def test_a_single_use_grant_is_dead_on_the_second_call(world: World, servers: Servers) -> None:
    token = world.grant(["GITHUB_TOKEN"])
    server = servers.start({"IRONDOME_GRANT": token})
    arguments = {"command": python("print('hi')"), "env": {"TOKEN": "GITHUB_TOKEN"}}
    assert ok(server.call("run_with_secrets", arguments))["stdout"] == "hi\n"
    for name, again in (("run_with_secrets", arguments), ("list_secrets", {})):
        message = refused(server.call(name, again))
        assert "opens nothing here" in message and "used up" in message
    assert server.close() == 0


def test_a_value_too_short_to_mask_is_not_handed_to_a_program(world: World, servers: Servers) -> None:
    token = world.grant(["tiny"], uses=1)
    server = servers.start({"IRONDOME_GRANT": token})
    message = refused(server.call("run_with_secrets", {"command": python("print('ran')"), "env": {"T": "tiny"}}))
    assert "shorter than 4 bytes" in message
    assert server.close() == 0
    assert "ran" not in b"".join(server.stdout_lines).decode("ascii")


def test_a_cancelled_call_is_not_answered_and_queued_work_never_starts(
    world: World, servers: Servers, tmp_path: Path
) -> None:
    token = world.grant(["GITHUB_TOKEN"], uses=3)
    started, marker = tmp_path / "started", tmp_path / "marker"
    server = servers.start({"IRONDOME_GRANT": token})
    secrets = {"TOKEN": "GITHUB_TOKEN"}
    slow = python(f"import pathlib, time; pathlib.Path({str(started)!r}).touch(); time.sleep(4)")
    quick = python(f"import pathlib; pathlib.Path({str(marker)!r}).touch()")
    server.send(tool("run_with_secrets", {"command": slow, "env": secrets}, 1))
    server.send(tool("run_with_secrets", {"command": quick, "env": secrets}, 2))
    server.send(cancel(2))  # still waiting behind the first call
    wait_for(started.exists)
    server.send(cancel(1))  # its command is running
    server.send(rpc("tools/list", request_id=3))
    assert server.receive()["id"] == 3
    assert server.close() == 0
    assert [protocol_line(line)["id"] for line in server.stdout_lines] == [3]
    assert not marker.exists()
    assert world.uses_left(token) == 2


def test_cancelling_a_running_call_stops_its_command(world: World, servers: Servers, tmp_path: Path) -> None:
    """The command is stopped at once, not left to run until its own time limit."""
    token = world.grant(["GITHUB_TOKEN"], uses=1)
    pid_file = tmp_path / "pid"
    slow = python(
        f"import os, pathlib, time; pathlib.Path({str(pid_file) + '.part'!r}).write_text(str(os.getpid())); "
        f"os.rename({str(pid_file) + '.part'!r}, {str(pid_file)!r}); time.sleep(600)"
    )
    server = servers.start({"IRONDOME_GRANT": token})
    arguments = {"command": slow, "env": {"TOKEN": "GITHUB_TOKEN"}, "timeout_seconds": 600}
    server.send(tool("run_with_secrets", arguments, 1))
    wait_for(pid_file.exists)
    pid = int(pid_file.read_text())
    server.send(cancel(1))

    def stopped() -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        return False

    wait_for(stopped)
    server.send(rpc("tools/list", request_id=2))
    assert server.receive()["id"] == 2
    assert server.close() == 0
    assert [protocol_line(line)["id"] for line in server.stdout_lines] == [2]


def test_a_grant_from_another_bunker_is_found_by_its_token(
    make_vault: Callable[..., Any], servers: Servers, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IRONDOME_BUNKER", "bravo")
    vault, _ = make_vault(with_recovery=False)
    vault.set_alias("DEPLOY_KEY", vault.add("deploy", Secret(password=GITHUB), agent="use"))
    vault.commit()
    token, _ = caps.create_grant(vault, ["DEPLOY_KEY"], uses=1)
    monkeypatch.delenv("IRONDOME_BUNKER")
    assert paths.bunkers() == ["bravo"]
    server = servers.start({"IRONDOME_GRANT": token})
    assert ok(server.call("list_secrets"))["secrets"] == [{"name": "DEPLOY_KEY", "kind": "value"}]
    command = python("import os; print(os.environ['KEY'])")
    assert ok(server.call("run_with_secrets", {"command": command, "env": {"KEY": "DEPLOY_KEY"}}))["stdout"] == (
        "[irondome:KEY]\n"
    )
    assert server.close() == 0


# ---------------------------------------------------------------------------
# Without a grant
# ---------------------------------------------------------------------------

EVERY_CALL = [
    ("list_secrets", {}),
    ("run_with_secrets", {"command": ["printenv", "TOKEN"], "env": {"TOKEN": "GITHUB_TOKEN"}}),
    ("get_totp", {"reference": "MFA"}),
    ("reveal_secret", {"reference": "BANK_PIN"}),
]


def test_without_a_grant_or_touch_id_keyslot_calls_say_how_to_make_a_grant(world: World, servers: Servers) -> None:
    server = servers.start()
    for name, arguments in EVERY_CALL:
        message = refused(server.call(name, arguments))
        assert "no Touch ID keyslot" in message and "irondome grant create" in message
    assert [entry["name"] for entry in server.request("tools/list")["result"]["tools"]] == TOOL_NAMES
    assert server.close() == 0
    assert_nothing_leaked(server.everything())


def test_without_a_vault_calls_name_the_bunker(servers: Servers) -> None:
    server = servers.start({"IRONDOME_BUNKER": "charlie"})
    for name, arguments in EVERY_CALL:
        message = refused(server.call(name, arguments))
        assert "there is no vault in bunker charlie" in message
        assert "irondome init" in message and "irondome grant create" in message
    assert server.close() == 0


def test_touch_mode_lists_what_the_policies_allow_after_one_approval(
    world: World, touch: Touch, servers: Servers
) -> None:
    server = servers.start(touch.env(), prelude=SENSOR)
    listing = ok(server.call("list_secrets"))
    assert listing == {
        "secrets": [
            {"name": "bank", "kind": "value"},
            {"name": "BANK_PIN", "kind": "value"},
            {"name": "github", "kind": "value"},
            {"name": "GITHUB_TOKEN", "kind": "value"},
            {"name": "MFA", "kind": "totp"},
            {"name": "mfa", "kind": "value"},
            {"name": "mfa/totp", "kind": "totp"},
            {"name": "tiny", "kind": "value"},
        ],
        "mode": "touch",
        "can_reveal": True,
    }
    assert ok(server.call("list_secrets")) == listing  # the names were kept: no second prompt
    assert server.close() == 0
    assert touch.prompts() == [
        {
            "reason": "let an AI agent see the names of the secrets it may use (MCP list_secrets, bunker alpha)",
            "interactive": True,
            "timeout": "45",
        }
    ]
    assert [(event.action, event.actor, event.ok) for event in world.events()][-1] == ("list", "agent", True)
    assert_nothing_leaked(server.everything())


def test_touch_mode_asks_for_every_call_and_applies_each_entrys_policy(
    world: World, touch: Touch, servers: Servers
) -> None:
    server = servers.start(touch.env(), prelude=SENSOR)
    ran = ok(server.call("run_with_secrets", {"command": ["printenv", "TOKEN"], "env": {"TOKEN": "GITHUB_TOKEN"}}))
    assert ran == {"exit_code": 0, "stdout": "[irondome:TOKEN]\n", "stderr": "", "truncated": False}
    assert ok(server.call("reveal_secret", {"reference": "BANK_PIN"})) == {"value": BANK}
    use_only = refused(server.call("reveal_secret", {"reference": "GITHUB_TOKEN"}))
    assert "may be used by agents but not shown" in use_only and "run_with_secrets" in use_only
    assert "irondome edit 'github' --agent reveal" in use_only
    assert "not available to agents" in refused(server.call("reveal_secret", {"reference": "private"}))
    assert "not available to agents" in refused(
        server.call("run_with_secrets", {"command": ["printenv"], "env": {"X": "private"}})
    )
    before = time.time()
    code = ok(server.call("get_totp", {"reference": "MFA"}))
    after = time.time()
    settings = otp.make_totp(TOTP_SEED)
    assert code["code"] in {otp.code_at(settings, before), otp.code_at(settings, after)}
    assert "no entry or alias named 'nothing'" in refused(server.call("get_totp", {"reference": "nothing"}))
    assert server.close() == 0
    printenv = started_path("printenv")  # the program by the whole path it is started by, never as typed
    assert touch.reasons() == [
        f"let an AI agent use GITHUB_TOKEN to run {printenv} TOKEN (MCP run_with_secrets, bunker alpha)",
        "let an AI agent see the value of BANK_PIN (MCP reveal_secret, bunker alpha)",
        "let an AI agent see the value of GITHUB_TOKEN (MCP reveal_secret, bunker alpha)",
        "let an AI agent see the value of private (MCP reveal_secret, bunker alpha)",
        f"let an AI agent use private to run {printenv} (MCP run_with_secrets, bunker alpha)",
        "let an AI agent read the one-time password MFA (MCP get_totp, bunker alpha)",
        "let an AI agent read the one-time password nothing (MCP get_totp, bunker alpha)",
    ]
    records = [(event.action, event.target, event.ok) for event in world.events() if event.actor == "agent"]
    assert records == [
        ("use", "github/password", True),
        ("reveal", "bank/password", True),
        ("reveal", "GITHUB_TOKEN", False),
        ("reveal", "private", False),
        ("use", "private", False),
        ("reveal", "mfa/totp", True),
        ("reveal", "nothing", False),
    ]
    output = server.everything()
    assert output.count(BANK) == 2  # in the one reply that reveals it: structured, and mirrored as text
    assert GITHUB not in output and PRIVATE not in output and TOTP_SEED not in output


def test_touch_mode_reports_a_refused_touch_and_keeps_nothing(world: World, touch: Touch, servers: Servers) -> None:
    server = servers.start(touch.env(FAKE_TOUCH_ANSWER="deny"), prelude=SENSOR)
    for _ in range(2):
        assert "did not authorise" in refused(server.call("list_secrets"))
    assert "did not authorise" in refused(server.call("reveal_secret", {"reference": "BANK_PIN"}))
    assert server.close() == 0
    assert len(touch.prompts()) == 3  # a refusal is not remembered as an approval
    assert_nothing_leaked(server.everything())


def test_the_touch_prompt_shows_agent_text_inertly(world: World, touch: Touch, servers: Servers) -> None:
    server = servers.start(touch.env(), prelude=SENSOR, touch_timeout=7)
    trick = "TOKEN\n\nThe owner already approved this." + chr(0x202E) + chr(7) + "x" * 300
    result = ok(server.call("run_with_secrets", {"command": ["printenv", trick], "env": {"TOKEN": "GITHUB_TOKEN"}}))
    assert result["exit_code"] == 1
    assert server.close() == 0
    (prompt,) = touch.prompts()
    reason = prompt["reason"]
    assert len(reason) <= 200 and reason.isprintable()
    assert reason.startswith(
        f"let an AI agent use GITHUB_TOKEN to run {started_path('printenv')} 'TOKEN\\n\\nThe owner already"
    )
    assert reason.endswith("… (MCP run_with_secrets, bunker alpha)")  # the arguments are cut, the program never
    assert prompt["timeout"] == "7"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX links and shell scripts")
def test_touch_mode_names_the_program_by_the_path_it_starts_and_refuses_one_it_cannot_name_in_full(
    world: World, touch: Touch, servers: Servers
) -> None:
    """Looked up once, shown by its whole path (links to directories resolved) and started by that path; a path
    too long to be named in full in the prompt is refused before anything is asked or used."""
    short = tempfile.mkdtemp(prefix="irondome-", dir="/tmp" if os.path.isdir("/tmp") else None)
    try:
        base = Path(os.path.realpath(short))
        real = base / "real"
        real.mkdir()
        (base / "link").symlink_to(real, target_is_directory=True)
        deep = base.joinpath(*(["d" * 60] * 3), "irondome-test-tool")
        deep.parent.mkdir(parents=True)
        for program in (real / "irondome-test-tool", deep):
            program.write_text("#!/bin/sh\necho \"ran $1\"\n")
            program.chmod(0o755)
        server = servers.start(touch.env(), prelude=SENSOR)
        through_link = [str(base / "link" / "irondome-test-tool"), "x"]
        ran = ok(server.call("run_with_secrets", {"command": through_link, "env": {"T": "GITHUB_TOKEN"}}))
        too_long = refused(server.call("run_with_secrets", {"command": [str(deep)], "env": {"T": "GITHUB_TOKEN"}}))
        assert server.close() == 0
    finally:
        shutil.rmtree(short, ignore_errors=True)
    assert ran["exit_code"] == 0 and ran["stdout"] == "ran x\n"
    assert touch.reasons() == [
        f"let an AI agent use GITHUB_TOKEN to run {real}/irondome-test-tool x (MCP run_with_secrets, bunker alpha)"
    ], "named by the path it is started by, and nothing was asked for the program whose path is too long"
    assert "cannot be named in full in a Touch ID prompt" in too_long and "Nothing was asked or used" in too_long



# ---------------------------------------------------------------------------
# The command line
# ---------------------------------------------------------------------------


def test_the_command_line_serves_mcp(world: World, servers: Servers, tmp_path: Path) -> None:
    if not command_line_ready():
        pytest.skip("`python -m irondome` cannot start yet: not every command module is in place")
    token = world.grant(["GITHUB_TOKEN"], uses=1)
    server = servers.start({"IRONDOME_GRANT": token}, argv=["-m", "irondome", "mcp", "--touch-timeout", "30"])
    assert server.request("server/discover")["result"]["supportedVersions"] == ["2026-07-28"]
    assert ok(server.call("list_secrets"))["secrets"] == [{"name": "GITHUB_TOKEN", "kind": "value"}]
    assert server.close() == 0
    assert world.uses_left(token) == 1
