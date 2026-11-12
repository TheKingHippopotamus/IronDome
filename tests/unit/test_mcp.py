"""The MCP server's protocol layer (irondome.mcp): both eras, discovery, errors, framing.

Everything here is answered in-process by :class:`irondome.mcp.Server`. No
vault exists in the isolated environment, so a tool call that gets as far as
asking for access is refused by the vault check, and nothing is ever run.
The tools themselves are exercised end to end in ``tests/e2e/test_mcp_e2e.py``.
"""

from __future__ import annotations

import io
import json
import os
import re
from typing import Any, Callable, Dict, List, Optional

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from irondome import mcp
from irondome.errors import UsageError
from irondome.mcp import LEGACY_VERSIONS, MAX_LINE_BYTES, MODERN_VERSIONS, PROTOCOL_VERSIONS, TOOLS, Server

MODERN = "2026-07-28"
VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_KEY = "io.modelcontextprotocol/clientInfo"
CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities"
SERVER_KEY = "io.modelcontextprotocol/serverInfo"
META: Dict[str, Any] = {
    VERSION_KEY: MODERN,
    CLIENT_KEY: {"name": "unit-test", "version": "1"},
    CAPABILITIES_KEY: {},
}
TOOL_NAMES = ["list_secrets", "run_with_secrets", "get_totp", "reveal_secret"]
SECRET_TOOLS = {"run_with_secrets", "get_totp", "reveal_secret"}


def message(method: str, params: Optional[Dict[str, Any]] = None, *, request_id: Any = 1, modern: bool = True) -> Dict:
    params = dict(params or {})
    if modern:
        params["_meta"] = META
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def ask(server: Server, method: str, params: Optional[Dict[str, Any]] = None, **options: Any) -> Dict[str, Any]:
    reply = server.handle_message(message(method, params, **options))
    assert reply is not None
    return reply


def result_of(reply: Dict[str, Any]) -> Dict[str, Any]:
    assert set(reply) == {"jsonrpc", "id", "result"}, reply
    return reply["result"]


def error_of(reply: Dict[str, Any]) -> Dict[str, Any]:
    assert set(reply) == {"jsonrpc", "id", "error"}, reply
    assert isinstance(reply["error"]["code"], int) and isinstance(reply["error"]["message"], str)
    return reply["error"]


def initialized(version: str = "2025-11-25") -> Server:
    server = Server()
    result_of(ask(server, "initialize", {"protocolVersion": version, "capabilities": {}}, modern=False))
    assert server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    return server


def tool_failure(reply: Dict[str, Any]) -> str:
    result = result_of(reply)
    assert result["isError"] is True and result["resultType"] == "complete"
    assert "structuredContent" not in result
    return result["content"][0]["text"]


# ---------------------------------------------------------------------------
# Versions and the two eras
# ---------------------------------------------------------------------------


def test_versions_are_newest_first_and_split_by_era() -> None:
    assert PROTOCOL_VERSIONS == ("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
    assert MODERN_VERSIONS + LEGACY_VERSIONS == PROTOCOL_VERSIONS
    assert list(PROTOCOL_VERSIONS) == sorted(PROTOCOL_VERSIONS, reverse=True)


@pytest.mark.parametrize("version", LEGACY_VERSIONS)
def test_initialize_echoes_every_supported_older_version(version: str) -> None:
    server = Server()
    result = result_of(ask(server, "initialize", {"protocolVersion": version}, modern=False))
    assert result["protocolVersion"] == version
    assert server.legacy_version == version


@pytest.mark.parametrize("requested", ["2099-01-01", MODERN, "", None, 20251125, ["2025-11-25"]])
def test_initialize_answers_its_newest_older_version_otherwise(requested: Any) -> None:
    result = result_of(ask(Server(), "initialize", {"protocolVersion": requested}, modern=False))
    assert result["protocolVersion"] == LEGACY_VERSIONS[0] == "2025-11-25"


def test_initialize_result_shape() -> None:
    result = result_of(ask(Server(), "initialize", {"protocolVersion": "2025-06-18"}, modern=False))
    assert result == {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": "irondome", "version": mcp.SERVER_INFO["version"]},
        "instructions": mcp.INSTRUCTIONS,
    }


def test_initialize_works_without_params_and_with_modern_meta() -> None:
    bare = Server().handle_message({"jsonrpc": "2.0", "id": 0, "method": "initialize"})
    assert result_of(bare)["protocolVersion"] == "2025-11-25"
    with_meta = result_of(ask(Server(), "initialize", {"protocolVersion": "2024-11-05"}))
    assert with_meta["protocolVersion"] == "2024-11-05"


def test_an_older_client_works_after_the_handshake() -> None:
    server = initialized("2025-03-26")
    listing = result_of(ask(server, "tools/list", modern=False, request_id=2))
    assert [tool["name"] for tool in listing["tools"]] == TOOL_NAMES
    assert result_of(ask(server, "ping", modern=False, request_id=3)) == {}
    failure = tool_failure(ask(server, "tools/call", {"name": "list_secrets", "arguments": {"x": 1}}, modern=False))
    assert "unknown argument x" in failure


def test_an_older_request_before_the_handshake_is_refused() -> None:
    for method in ("tools/list", "tools/call"):
        error = error_of(ask(Server(), method, {"name": "list_secrets"}, modern=False))
        assert error["code"] == -32602
        assert VERSION_KEY in error["message"] and "initialize" in error["message"]


def test_ping_is_answered_before_the_handshake_and_absent_from_the_modern_era() -> None:
    assert result_of(Server().handle_message({"jsonrpc": "2.0", "id": 9, "method": "ping"})) == {}
    assert error_of(ask(Server(), "ping"))["code"] == -32601


def test_server_discover() -> None:
    reply = ask(Server(), "server/discover", request_id="server-discover-probe-1")
    assert reply["id"] == "server-discover-probe-1"
    assert result_of(reply) == {
        "resultType": "complete",
        "supportedVersions": [MODERN],
        "capabilities": {"tools": {"listChanged": False}},
        "instructions": mcp.INSTRUCTIONS,
        "ttlMs": 300_000,
        "cacheScope": "public",
        "_meta": {SERVER_KEY: {"name": "irondome", "version": mcp.SERVER_INFO["version"]}},
    }


def test_server_discover_needs_the_modern_meta() -> None:
    for server in (Server(), initialized()):
        error = error_of(ask(server, "server/discover", modern=False))
        assert error["code"] == -32602 and VERSION_KEY in error["message"]


@pytest.mark.parametrize("version", ["2027-01-01", "2025-11-25", "2024-11-05", "", "latest"])
def test_an_unsupported_version_is_refused_with_the_supported_list(version: str) -> None:
    params = {"_meta": dict(META, **{VERSION_KEY: version})}
    for method in ("server/discover", "tools/list", "tools/call", "no/such/method"):
        reply = Server().handle_message({"jsonrpc": "2.0", "id": 5, "method": method, "params": params})
        assert reply is not None
        error = error_of(reply)
        assert error["code"] == -32022
        assert error["data"] == {"supported": list(PROTOCOL_VERSIONS), "requested": version}


@pytest.mark.parametrize(
    ("meta", "missing"),
    [
        ({VERSION_KEY: MODERN, CAPABILITIES_KEY: {}}, CLIENT_KEY),
        ({VERSION_KEY: MODERN, CLIENT_KEY: {"name": "x", "version": "1"}}, CAPABILITIES_KEY),
        ({VERSION_KEY: MODERN, CLIENT_KEY: "x", CAPABILITIES_KEY: {}}, CLIENT_KEY),
        ({VERSION_KEY: MODERN, CLIENT_KEY: {}, CAPABILITIES_KEY: []}, CAPABILITIES_KEY),
        ({VERSION_KEY: 20260728, CLIENT_KEY: {}, CAPABILITIES_KEY: {}}, VERSION_KEY),
        ({VERSION_KEY: None, CLIENT_KEY: {}, CAPABILITIES_KEY: {}}, VERSION_KEY),
    ],
)
def test_a_modern_request_without_its_required_meta_is_invalid(meta: Dict[str, Any], missing: str) -> None:
    reply = Server().handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}})
    assert reply is not None
    error = error_of(reply)
    assert error["code"] == -32602 and missing in error["message"]


def test_meta_without_a_protocol_version_is_an_older_request() -> None:
    """Older clients put other things in _meta (a progress token); that does not make them modern."""
    server = initialized()
    params = {"_meta": {"progressToken": 7}}
    reply = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": params})
    assert reply is not None and len(result_of(reply)["tools"]) == 4


def test_each_modern_request_stands_alone() -> None:
    """No handshake, no memory: a fresh server answers the same as one that has seen everything."""
    used = initialized()
    for method in ("server/discover", "tools/list"):
        assert ask(Server(), method) == ask(used, method)


@pytest.mark.parametrize("modern", [True, False])
def test_unknown_methods(modern: bool) -> None:
    server = Server() if modern else initialized()
    for method in ("resources/list", "prompts/list", "logging/setLevel", "completion/complete", "tools", "", "x" * 500):
        error = error_of(ask(server, method, modern=modern))
        assert error["code"] == -32601
        assert len(error["message"]) < 200


def test_subscriptions_are_acknowledged_and_never_answered() -> None:
    notice = ask(Server(), "subscriptions/listen", {"notifications": {"toolsListChanged": True}}, request_id="listen-1")
    assert notice == {
        "jsonrpc": "2.0",
        "method": "notifications/subscriptions/acknowledged",
        "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": "listen-1"}, "notifications": {}},
    }
    assert error_of(ask(initialized(), "subscriptions/listen", modern=False))["code"] == -32601


# ---------------------------------------------------------------------------
# tools/list
# ---------------------------------------------------------------------------


def test_tools_list_shape_is_the_same_in_both_eras() -> None:
    modern = result_of(ask(Server(), "tools/list"))
    older = result_of(ask(initialized(), "tools/list", modern=False))
    assert modern == older
    assert modern["resultType"] == "complete"
    assert modern["ttlMs"] == 300_000 and modern["cacheScope"] == "public"
    assert modern["_meta"] == {SERVER_KEY: mcp.SERVER_INFO}
    assert [tool["name"] for tool in modern["tools"]] == TOOL_NAMES
    assert "nextCursor" not in modern


def test_tools_list_is_static_and_cannot_be_changed_through_a_result() -> None:
    server = Server()
    first = result_of(ask(server, "tools/list"))
    first["tools"][0]["name"] = "changed"
    first["tools"][1]["inputSchema"]["properties"].clear()
    second = result_of(ask(server, "tools/list", {"cursor": "anything"}))
    assert [tool["name"] for tool in second["tools"]] == TOOL_NAMES
    assert second["tools"] == list(TOOLS)
    assert json.dumps(second, sort_keys=True) == json.dumps(result_of(ask(Server(), "tools/list")), sort_keys=True)


@pytest.mark.parametrize("tool", TOOLS, ids=TOOL_NAMES)
def test_each_tool_definition(tool: Dict[str, Any]) -> None:
    assert re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", tool["name"])
    assert tool["title"] and tool["annotations"]["title"] == tool["title"]
    for schema in (tool["inputSchema"], tool["outputSchema"]):
        assert schema["type"] == "object" and schema["additionalProperties"] is False
        assert set(schema.get("required", [])) <= set(schema["properties"])
    hints = tool["annotations"]
    assert set(hints) == {"title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}
    assert all(isinstance(hints[name], bool) for name in hints if name != "title")
    if tool["name"] in SECRET_TOOLS:
        assert tool["_meta"] == {"anthropic/requiresUserInteraction": True}
        assert hints["readOnlyHint"] is False
    else:
        assert "_meta" not in tool and hints["readOnlyHint"] is True
    description = tool["description"]
    assert description.isprintable() and 40 < len(description) < 700
    lowered = description.lower()
    for phrase in ("ignore", "always ", "never call", "you must", "important", "<", "system prompt"):
        assert phrase not in lowered


def test_the_input_schemas_say_what_the_tools_take() -> None:
    schemas = {tool["name"]: tool["inputSchema"] for tool in TOOLS}
    assert schemas["list_secrets"] == {"type": "object", "properties": {}, "additionalProperties": False}
    run = schemas["run_with_secrets"]
    assert run["required"] == ["command", "env"]
    assert set(run["properties"]) == {"command", "env", "cwd", "timeout_seconds", "stdin"}
    assert run["properties"]["timeout_seconds"]["maximum"] == 600
    assert run["properties"]["env"]["minProperties"] == 1
    for name in ("get_totp", "reveal_secret"):
        assert schemas[name]["required"] == ["reference"] and list(schemas[name]["properties"]) == ["reference"]


# ---------------------------------------------------------------------------
# tools/call: what is refused before any access is asked for
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["no_such_tool", "", "LIST_SECRETS", None, 7, ["list_secrets"]])
def test_an_unknown_tool_is_a_protocol_error(name: Any) -> None:
    params = {} if name is None else {"name": name}
    error = error_of(ask(Server(), "tools/call", params))
    assert error["code"] == -32602 and error["message"].startswith("Unknown tool")


@pytest.mark.parametrize(
    ("tool", "arguments", "says"),
    [
        ("list_secrets", [], "arguments of a tool call are a JSON object"),
        ("list_secrets", "x", "arguments of a tool call are a JSON object"),
        ("list_secrets", {"all": True}, "unknown argument all"),
        ("run_with_secrets", {}, "command must be a list"),
        ("run_with_secrets", {"command": "gh repo list", "env": {"T": "t"}}, "not run through a shell"),
        ("run_with_secrets", {"command": [], "env": {"T": "t"}}, "command must be a list"),
        ("run_with_secrets", {"command": ["gh", 7], "env": {"T": "t"}}, "command must be a list"),
        ("run_with_secrets", {"command": [""], "env": {"T": "t"}}, "cannot be empty"),
        ("run_with_secrets", {"command": ["a\x00b"], "env": {"T": "t"}}, "NUL"),
        ("run_with_secrets", {"command": ["env"]}, "env must name at least one secret"),
        ("run_with_secrets", {"command": ["env"], "env": {}}, "env must name at least one secret"),
        ("run_with_secrets", {"command": ["env"], "env": {"1X": "t"}}, "not an environment variable name"),
        ("run_with_secrets", {"command": ["env"], "env": {"A=B": "t"}}, "not an environment variable name"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": ""}}, "non-empty string"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": 5}}, "non-empty string"),
        ("run_with_secrets", {"command": ["env"], "env": {"IRONDOME_GRANT": "t"}}, "reserved by IronDome"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": " padded "}}, "whitespace"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": "irondome://%zz"}}, "malformed reference"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": "t"}, "cwd": "/no/such/directory"}, "no directory"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": "t"}, "cwd": 3}, "cwd must be a string"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": "t"}, "timeout_seconds": 0}, "timeout_seconds"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": "t"}, "timeout_seconds": 601}, "timeout_seconds"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": "t"}, "timeout_seconds": True}, "timeout_seconds"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": "t"}, "timeout_seconds": "9"}, "timeout_seconds"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": "t"}, "stdin": 4}, "stdin must be a string"),
        ("run_with_secrets", {"command": ["env"], "env": {"T": "t"}, "shell": True}, "unknown argument shell"),
        ("run_with_secrets", {"command": ["no-such-program-xyz"], "env": {"T": "t"}}, "command not found"),
        ("get_totp", {}, "reference is required"),
        ("get_totp", {"reference": 12}, "reference must be a string"),
        ("get_totp", {"reference": ""}, "empty reference"),
        ("get_totp", {"reference": "a\nb"}, "control characters"),
        ("reveal_secret", {"reference": "x", "why": "please"}, "unknown argument why"),
        ("reveal_secret", {"reference": None}, "reference is required"),
    ],
)
def test_invalid_arguments_are_tool_errors_not_protocol_errors(tool: str, arguments: Any, says: str) -> None:
    reply = ask(Server(), "tools/call", {"name": tool, "arguments": arguments})
    assert says in tool_failure(reply)


def test_too_many_variables_are_refused() -> None:
    env = {f"V{index}": "t" for index in range(65)}
    reply = ask(Server(), "tools/call", {"name": "run_with_secrets", "arguments": {"command": ["env"], "env": env}})
    assert "at most 64 variables" in tool_failure(reply)


def test_absent_or_null_arguments_mean_none() -> None:
    for params in ({"name": "list_secrets"}, {"name": "list_secrets", "arguments": None}):
        text = tool_failure(ask(Server(), "tools/call", params))
        assert "there is no vault in bunker alpha" in text  # got as far as asking for access


def test_without_a_vault_or_grant_a_call_says_how_to_set_one_up() -> None:
    for name, arguments in (
        ("list_secrets", {}),
        ("run_with_secrets", {"command": ["env"], "env": {"T": "GITHUB_TOKEN"}}),
        ("get_totp", {"reference": "MFA"}),
        ("reveal_secret", {"reference": "irondome://GITHUB_TOKEN"}),
    ):
        text = tool_failure(ask(Server(), "tools/call", {"name": name, "arguments": arguments}))
        assert "there is no vault in bunker alpha" in text
        assert "irondome init" in text and "irondome grant create" in text


def test_a_tool_result_is_mirrored_as_text() -> None:
    structured = {"secrets": [{"name": "A", "kind": "value"}], "mode": "grant", "can_reveal": False}
    result = mcp._tool_success(structured)
    assert result["structuredContent"] is structured
    assert result["isError"] is False and result["resultType"] == "complete"
    assert [block["type"] for block in result["content"]] == ["text"]
    assert json.loads(result["content"][0]["text"]) == structured


# ---------------------------------------------------------------------------
# JSON-RPC: what is not a well-formed request
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [[], [{"jsonrpc": "2.0", "id": 1, "method": "ping"}], "ping", 1, 1.5, None, True])
def test_a_message_that_is_not_an_object_is_an_invalid_request(value: Any) -> None:
    error = error_of(Server().handle_message(value) or {})
    assert error["code"] == -32600
    assert (Server().handle_message(value) or {})["id"] is None


@pytest.mark.parametrize("request_id", [True, False, 1.5, 1.0, None, {}, [], 2**63, -(2**63) - 1])
def test_an_id_that_is_neither_string_nor_integer_is_invalid(request_id: Any) -> None:
    reply = Server().handle_message({"jsonrpc": "2.0", "id": request_id, "method": "ping"})
    assert reply is not None and error_of(reply)["code"] == -32600 and reply["id"] is None


@pytest.mark.parametrize("request_id", [0, -1, 2**63 - 1, -(2**63), "", "abc", "1", "\u00e9\u2028"])
def test_ids_may_be_strings_or_integers_and_are_echoed_exactly(request_id: Any) -> None:
    reply = Server().handle_message({"jsonrpc": "2.0", "id": request_id, "method": "ping"})
    assert reply is not None and reply["id"] == request_id and type(reply["id"]) is type(request_id)


@pytest.mark.parametrize("version", [None, "1.0", "2", 2.0, 2])
def test_the_jsonrpc_member_must_say_2_0(version: Any) -> None:
    body: Dict[str, Any] = {"id": 4, "method": "ping"}
    if version is not None:
        body["jsonrpc"] = version
    reply = Server().handle_message(body)
    assert reply is not None and error_of(reply)["code"] == -32600 and reply["id"] == 4


@pytest.mark.parametrize("method", [None, 5, ["ping"], {"name": "ping"}])
def test_the_method_must_be_a_string(method: Any) -> None:
    reply = Server().handle_message({"jsonrpc": "2.0", "id": 4, "method": method})
    assert reply is not None and error_of(reply)["code"] == -32600 and reply["id"] == 4


def test_a_message_without_method_or_answer_is_invalid() -> None:
    for body in ({"jsonrpc": "2.0", "id": 3}, {"jsonrpc": "2.0"}, {}):
        reply = Server().handle_message(body)
        assert reply is not None and error_of(reply)["code"] == -32600
        assert reply["id"] == body.get("id")


@pytest.mark.parametrize("params", [[], [1, 2], "x", 3, True])
def test_params_must_be_an_object(params: Any) -> None:
    reply = Server().handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params})
    assert reply is not None and error_of(reply)["code"] == -32602


def test_params_may_be_absent_or_null() -> None:
    bare = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    for body in (bare, dict(bare, params=None)):
        assert result_of(Server().handle_message(body) or {}) == {}


@pytest.mark.parametrize(
    "body",
    [
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 5, "reason": "timeout"}},
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": True}},
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": []},
        {"jsonrpc": "2.0", "method": "notifications/cancelled"},
        {"jsonrpc": "2.0", "method": "notifications/roots/list_changed", "params": {"_meta": META}},
        {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "run_with_secrets"}},
        {"jsonrpc": "2.0", "method": "no/such/notification"},
        {"jsonrpc": "1.0", "method": "notifications/initialized"},
        {"method": 5},
        {"method": None, "params": "x"},
    ],
)
def test_notifications_are_never_answered(body: Dict[str, Any]) -> None:
    assert Server().handle_message(body) is None


def test_answers_from_the_client_are_ignored() -> None:
    for body in (
        {"jsonrpc": "2.0", "id": "srv-1", "result": {"action": "accept"}},
        {"jsonrpc": "2.0", "id": 7, "error": {"code": -1, "message": "no"}},
        {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
    ):
        assert Server().handle_message(body) is None


def test_cancelling_an_unknown_or_finished_request_changes_nothing() -> None:
    server = Server()
    cancel = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}
    assert server.handle_message(cancel) is None
    assert not server.cancelled(1)
    assert result_of(ask(server, "tools/list", request_id=1))["tools"]


def test_cancellation_marks_only_open_requests_until_they_finish() -> None:
    server = Server()
    server.begin(5)
    server.begin("5")
    server.cancel(5)
    server.cancel(6)
    assert server.cancelled(5) and not server.cancelled("5") and not server.cancelled(6)
    server.finish(5)
    assert not server.cancelled(5)
    server.cancel(5)  # finished: nothing to cancel any more
    assert not server.cancelled(5)
    server.begin(7)
    server.begin(7)
    server.cancel(7)
    server.finish(7)
    assert server.cancelled(7)  # the same id is still open once more
    server.finish(7)
    assert not server.cancelled(7)


def test_module_level_handle_message_starts_from_nothing() -> None:
    reply = mcp.handle_message(message("tools/list", modern=False))
    assert reply is not None and error_of(reply)["code"] == -32602
    server = initialized()
    reply = mcp.handle_message(message("tools/list", modern=False), server)
    assert reply is not None and result_of(reply)["tools"]


# ---------------------------------------------------------------------------
# Framing: lines, parsing, encoding
# ---------------------------------------------------------------------------


def reader(data: bytes, size: int) -> Callable[[int], bytes]:
    stream = io.BytesIO(data)
    return lambda wanted: stream.read(min(wanted, size))


@pytest.mark.parametrize("size", [1, 3, 64, 65536])
def test_lines_are_split_on_newlines_however_the_bytes_arrive(size: int) -> None:
    data = b'{"a":1}\n\n{"b":2}\r\n  \nlast without newline'
    assert list(mcp._lines(reader(data, size))) == [b'{"a":1}', b"", b'{"b":2}\r', b"  ", b"last without newline"]


def test_a_line_is_at_most_one_mebibyte() -> None:
    exact = b"a" * MAX_LINE_BYTES
    over = b"b" * (MAX_LINE_BYTES + 1)
    data = exact + b"\n" + over + b"\n" + b"next\n" + over
    assert list(mcp._lines(reader(data, 65536))) == [exact, None, b"next", None]


def test_a_huge_line_is_dropped_as_it_arrives() -> None:
    chunks = [b"x" * 65536] * 200 + [b"\nafter\n"]  # 12.5 MiB without a newline
    sizes: List[int] = []

    def read(wanted: int) -> bytes:
        sizes.append(wanted)
        return chunks.pop(0) if chunks else b""

    assert list(mcp._lines(read)) == [None, b"after"]
    assert max(sizes) <= 65536


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"{",
        b'{"a": NaN}',
        b'{"a": Infinity}',
        b'{"a": -Infinity}',
        b'{"a": 1e400}',
        b'{"a": 123456789012345678901}',
        b'{"id": 1, "id": 2}',
        b"[" * 100_000,
        b'{"a": "\xff"}',
        b'\xef\xbb\xbf{"a": 1}',
        b'{"a": "line\nbreak"}',
        b'{"a": 1} {"b": 2}',
        b"",
    ],
)
def test_parse_refuses_anything_doubtful(raw: bytes) -> None:
    with pytest.raises(ValueError):
        mcp._parse(raw)


def test_parse_accepts_plain_json() -> None:
    assert mcp._parse(b' {"id": -12345678901234567890, "x": [1.5, "\\u00e9", null, true]}\r') == {
        "id": -12345678901234567890,
        "x": [1.5, "\u00e9", None, True],
    }


def test_encode_writes_one_ascii_line() -> None:
    line = mcp._encode({"jsonrpc": "2.0", "id": 1, "result": {"text": "a\nb\u2028c\u00e9\ud800", "n": [1]}})
    assert line.endswith(b"\n") and line.count(b"\n") == 1 and line.isascii()
    assert json.loads(line)["result"]["text"] == "a\nb\u2028c\u00e9\ud800"


def test_encode_turns_what_json_cannot_hold_into_an_internal_error(capsys: pytest.CaptureFixture[str]) -> None:
    line = mcp._encode({"jsonrpc": "2.0", "id": 3, "result": {"bad": float("nan")}})
    assert json.loads(line) == {"jsonrpc": "2.0", "id": 3, "error": {"code": -32603, "message": "Internal error"}}
    assert "internal error (ValueError" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# serve(), in-process
# ---------------------------------------------------------------------------


def serve_lines(lines: List[bytes], **options: Any) -> List[Dict[str, Any]]:
    out = io.BytesIO()
    assert mcp.serve(io.BytesIO(b"".join(lines)), out, **options) == 0
    replies = []
    for line in out.getvalue().splitlines():
        reply = json.loads(line)
        assert reply["jsonrpc"] == "2.0"
        replies.append(reply)
    return replies


def encoded(body: Any) -> bytes:
    return json.dumps(body).encode("utf-8") + b"\n"


def test_serve_answers_in_order_and_ends_with_its_input() -> None:
    replies = serve_lines(
        [
            encoded(message("server/discover", request_id="d")),
            b"garbage\n",
            b"z" * (MAX_LINE_BYTES + 10) + b"\n",
            b'{"jsonrpc":"2.0","id":"\xff","method":"ping"}\n',
            encoded({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            b"\n   \n",
            encoded({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}}),
            encoded([]),
            encoded(message("tools/list", request_id=2)),
            encoded(message("initialize", {"protocolVersion": "2025-06-18"}, request_id=3, modern=False)),
            encoded(message("ping", request_id=4, modern=False))[:-1],  # the last line may lack its newline
        ]
    )
    assert [reply["id"] for reply in replies] == ["d", None, None, None, None, 2, 3, 4]
    assert [reply.get("error", {}).get("code") for reply in replies] == [
        None, -32700, -32600, -32700, -32600, None, None, None
    ]
    assert "a message is at most 1048576 bytes long" in replies[2]["error"]["message"]
    assert replies[6]["result"]["protocolVersion"] == "2025-06-18"
    assert replies[7]["result"] == {}


def test_serve_takes_long_lines_in_turn() -> None:
    """Lines too long to parse ahead are parsed when their turn comes, in order, cancellations included."""
    pad = "x" * 100_000
    replies = serve_lines(
        [
            encoded({"jsonrpc": "2.0", "id": "big", "method": "ping", "params": {"pad": pad}}),
            b'{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"pad": "' + pad.encode() + b'"\n',
            encoded({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1, "reason": pad}}),
            encoded(message("ping", request_id="small", modern=False)),
        ]
    )
    assert [(reply["id"], reply.get("error", {}).get("code")) for reply in replies] == [
        ("big", None), (None, -32700), ("small", None)
    ]


def test_serve_accepts_text_streams() -> None:
    out = io.StringIO()
    status = mcp.serve(io.StringIO(json.dumps(message("ping", modern=False)) + "\n"), out)
    assert status == 0
    assert json.loads(out.getvalue()) == {"jsonrpc": "2.0", "id": 1, "result": {}}


class Watching(io.BytesIO):
    """Standard input that notes what the environment says while the server reads it."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.seen: List[Optional[str]] = []

    def read1(self, size: int = -1) -> bytes:
        self.seen.append(os.environ.get(mcp.ENV_TOUCH_TIMEOUT))
        return super().read1(size)


@pytest.mark.parametrize(
    ("argument", "inherited", "during"), [(None, None, "45"), (None, "120", "120"), (7, "120", "7")]
)
def test_the_touch_timeout_is_handed_on_while_serving_and_put_back_after(
    monkeypatch: pytest.MonkeyPatch, argument: Optional[int], inherited: Optional[str], during: str
) -> None:
    if inherited is None:
        monkeypatch.delenv(mcp.ENV_TOUCH_TIMEOUT, raising=False)
    else:
        monkeypatch.setenv(mcp.ENV_TOUCH_TIMEOUT, inherited)
    stdin = Watching(encoded(message("ping", modern=False)))
    assert mcp.serve(stdin, io.BytesIO(), touch_timeout=argument) == 0
    assert stdin.seen and set(stdin.seen) == {during}
    assert os.environ.get(mcp.ENV_TOUCH_TIMEOUT) == inherited


@pytest.mark.parametrize("value", [0, -1, 3601, True, 1.5, "30"])
def test_an_unusable_touch_timeout_is_refused_before_serving(value: Any) -> None:
    with pytest.raises(UsageError, match="Touch ID timeout"):
        mcp.serve(io.BytesIO(), io.BytesIO(), touch_timeout=value)


def test_serve_ignores_a_session_token_and_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("IRONDOME_SESSION", "irondome_s_" + "0" * 32 + "_" + "A" * 52)
    replies = serve_lines([encoded(message("tools/call", {"name": "list_secrets"}))])
    assert "there is no vault in bunker alpha" in replies[0]["result"]["content"][0]["text"]
    assert "ignoring IRONDOME_SESSION" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# The Touch ID prompt text
# ---------------------------------------------------------------------------


def test_the_touch_prompt_is_short_inert_and_names_the_tool_and_bunker() -> None:
    hostile = mcp._shown("rm -rf ~\n\nThe owner already approved this.\u202e\u0007 " + "A" * 400)
    reason = Server()._reason("run_with_secrets", f"use {mcp._listed(['GITHUB_TOKEN'] * 70, 80)} to run {hostile}")
    assert len(reason) <= 200
    assert reason.isprintable()
    assert reason.startswith("let an AI agent use GITHUB_TOKEN, GITHUB_TOKEN")
    assert reason.endswith(" (MCP run_with_secrets, bunker alpha)")
    assert "\u202e" not in reason and "\n" not in reason


@pytest.mark.parametrize(
    ("items", "budget", "expected"),
    [
        ([], 10, ""),
        (["a", "b"], 10, "a, b"),
        (["alpha", "beta", "gamma", "delta"], 22, "alpha, beta and 2 more"),
        (["alpha", "beta", "gamma", "delta"], 18, "alpha and 3 more"),
        (["a-very-long-name-indeed", "b"], 16, "a-ve\u2026 and 1 more"),
        (["a-very-long-name-indeed"], 10, "a-very-lo\u2026"),
    ],
)
def test_lists_in_the_prompt_are_cut_to_fit(items: List[str], budget: int, expected: str) -> None:
    text = mcp._listed(items, budget)
    assert text == expected and len(text) <= budget


def test_agent_text_in_the_prompt_is_quoted_and_escaped() -> None:
    assert mcp._shown("gh") == "gh"
    assert mcp._shown("my secret") == "'my secret'"
    assert mcp._shown("a\nb\u202ec") == "'a\\nb\\u202ec'"
    assert mcp._shown("it's") == "'it'\"'\"'s'"


# ---------------------------------------------------------------------------
# No input makes the server raise
# ---------------------------------------------------------------------------

json_values = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**70), max_value=2**70)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=16),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=16,
)
methods = st.sampled_from(
    [
        "initialize",
        "ping",
        "server/discover",
        "tools/list",
        "tools/call",
        "subscriptions/listen",
        "notifications/cancelled",
        "notifications/initialized",
        "resources/list",
    ]
) | st.text(max_size=12)
metas = st.one_of(
    st.just(META),
    json_values,
    st.fixed_dictionaries(
        {VERSION_KEY: st.sampled_from(PROTOCOL_VERSIONS) | json_values},
        optional={CLIENT_KEY: st.just({"name": "f", "version": "1"}) | json_values, CAPABILITIES_KEY: json_values},
    ),
)
tool_arguments = st.dictionaries(
    st.sampled_from(["command", "env", "cwd", "timeout_seconds", "stdin", "reference", "other"]),
    json_values
    | st.lists(st.sampled_from(["env", "true", "", "\x00", "no-such-program-xyz"]), max_size=3)
    | st.dictionaries(st.from_regex(r"[A-Z_][A-Z0-9_]{0,4}", fullmatch=True), st.text(max_size=8), max_size=2),
    max_size=5,
)
params = st.one_of(
    st.none(),
    json_values,
    st.fixed_dictionaries(
        {},
        optional={
            "_meta": metas,
            "name": st.sampled_from(TOOL_NAMES) | json_values,
            "arguments": tool_arguments | json_values,
            "protocolVersion": st.sampled_from(PROTOCOL_VERSIONS) | json_values,
            "requestId": json_values,
        },
    ),
)
messages = st.one_of(
    json_values,
    st.fixed_dictionaries(
        {},
        optional={
            "jsonrpc": st.just("2.0") | json_values,
            "id": st.integers() | st.text(max_size=8) | json_values,
            "method": methods | json_values,
            "params": params,
            "result": json_values,
            "error": json_values,
        },
    ),
)


def assert_well_formed(reply: Optional[Dict[str, Any]]) -> None:
    if reply is None:
        return
    assert reply["jsonrpc"] == "2.0"
    if "method" in reply:
        assert reply["method"] == "notifications/subscriptions/acknowledged" and "id" not in reply
    else:
        assert set(reply) in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})
        assert reply["id"] is None or mcp._is_id(reply["id"])
        if "error" in reply:
            assert isinstance(reply["error"]["code"], int) and isinstance(reply["error"]["message"], str)
        else:
            assert isinstance(reply["result"], dict)
    line = mcp._encode(reply)
    assert line.count(b"\n") == 1 and json.loads(line) == json.loads(json.dumps(reply))


@settings(max_examples=400, deadline=None)
@given(body=messages)
def test_handle_message_never_raises(body: Any) -> None:
    assert_well_formed(Server().handle_message(body))


@settings(max_examples=150, deadline=None)
@given(bodies=st.lists(messages, max_size=6))
def test_a_sequence_of_messages_never_breaks_a_server(bodies: List[Any]) -> None:
    server = Server()
    for body in bodies:
        assert_well_formed(server.handle_message(body))
    assert result_of(ask(server, "tools/list", request_id="after"))["tools"]


@settings(max_examples=300, deadline=None)
@given(data=st.binary(max_size=300), size=st.integers(min_value=1, max_value=64))
def test_reading_arbitrary_bytes_never_raises(data: bytes, size: int) -> None:
    for line in mcp._lines(reader(data, size)):
        if line is None:
            continue
        try:
            body = mcp._parse(line)
        except ValueError:
            continue
        assert_well_formed(Server().handle_message(body))
