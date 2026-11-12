"""The MCP server: an AI agent uses secrets without being handed them.

``irondome mcp`` speaks the Model Context Protocol over standard input and
output, one JSON-RPC 2.0 message per line, so an agent's host (Claude Code,
Codex, Cursor and the rest) can start it as a stdio server. It offers four
tools, always the same four:

``list_secrets``      the names of the secrets this server may use, never values
``run_with_secrets``  run a program with secrets in its environment; they are
                      masked in the output that comes back
``get_totp``          the current one-time password of a ``totp`` secret
``reveal_secret``     a value itself, where the owner allowed showing it

Who decides what the agent gets
-------------------------------
The rules are those of :mod:`irondome.cli.context`; this module asks it.

* ``IRONDOME_GRANT`` set in the server's environment: each tool call that
  reads a secret opens the grant once, which is one use, and reaches only the
  references, mode, lifetime and use count the owner gave it. Listing spends
  no use, and neither does a call the grant could not serve (a name it does
  not cover, showing a value under a ``use`` grant): those are refused first.
* No grant, and a vault with a Touch ID keyslot on a Mac: each call puts a
  Touch ID prompt on the owner's screen that names the tool, the secrets and,
  for ``run_with_secrets``, the command. After the touch, each entry's agent
  policy (``irondome edit NAME --agent deny|use|reveal``) limits what is read.
  The names one approved ``list_secrets`` returned are kept for the life of
  the process; values never are.
* Neither: tool calls fail with a message that tells the owner how to set up
  a grant. A session token (``IRONDOME_SESSION``) is never used here.

Every value read is written to the vault's audit log before it is used.

The protocol
------------
Both eras of MCP are answered, because a client of the older one cannot fall
forward. Revision 2026-07-28 is stateless: every request names its protocol
version and client in ``params._meta`` and ``server/discover`` replaces the
handshake. The revisions before it begin with ``initialize``. One result
shape serves both. ``server/discover`` and ``tools/list`` are static: they
work while the vault is locked and touch no file, because some clients start
a server only to probe it and kill it without warning. The vault is opened in
``tools/call``, for that one call.

stdout carries protocol messages and nothing else: while :func:`serve` runs,
anything else written to file descriptor 1 lands on stderr. Messages are read
by a thread of their own, so a ``notifications/cancelled`` reaches a call
that is waiting for a touch or for its command; work that had not started is
then skipped and no answer is sent. A line longer than 1 MiB is refused
without being held in memory, and no input makes the server raise.

What this cannot do
-------------------
* A program run with a secret has the secret. It can print it in a form the
  masking does not recognise, or send it anywhere (``docs/THREAT_MODEL.md``,
  section 4). ``run_with_secrets`` keeps secrets out of the transcript by
  default; it is not a sandbox.
* The grant token in this server's environment is a bearer credential: any
  process of the same user that can read the host's configuration can read
  it, and that may include the agent's own shell tool. Keep grants narrow and
  short-lived. Touch ID mode has no such token.
* A command that has started runs until it exits or reaches its own time
  limit, even if the client cancels the call meanwhile.
* ``reveal_secret`` puts a value into the agent's context: that is what it
  is for. The owner decides per grant or per entry whether it works at all.
"""

from __future__ import annotations

import argparse
import copy
import io
import json
import math
import os
import queue
import re
import shlex
import stat
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from typing import IO, Any, Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple, Union

from irondome import __version__, caps, otp, paths
from irondome.agent import refs, runner
from irondome.cli import main as cli_main
from irondome.cli.context import ENV_GRANT, ENV_SESSION, PURPOSE_REVEAL, PURPOSE_USE, Access, Context
from irondome.cli.output import Output
from irondome.errors import EXIT_INTERRUPTED, EXIT_OK, IronDomeError, NotFoundError, PolicyError, UsageError, VaultError
from irondome.secmem import harden_process
from irondome.vault import Entry, Vault, vault_exists

__all__ = [
    "PROTOCOL_VERSIONS",
    "MODERN_VERSIONS",
    "LEGACY_VERSIONS",
    "MAX_LINE_BYTES",
    "ENV_TOUCH_TIMEOUT",
    "DEFAULT_TOUCH_TIMEOUT",
    "SERVER_INFO",
    "INSTRUCTIONS",
    "TOOLS",
    "Server",
    "handle_message",
    "serve",
]

#: Every revision answered, newest first.
PROTOCOL_VERSIONS: Tuple[str, ...] = ("2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
#: Revisions in which each request carries its own version and client in ``params._meta``.
MODERN_VERSIONS: Tuple[str, ...] = PROTOCOL_VERSIONS[:1]
#: Revisions that begin with ``initialize``.
LEGACY_VERSIONS: Tuple[str, ...] = PROTOCOL_VERSIONS[1:]

#: The longest line read as a message. Anything longer is refused unread.
MAX_LINE_BYTES = 1024 * 1024

#: Seconds a Touch ID prompt waits for the owner, passed to the Secure Enclave backend.
ENV_TOUCH_TIMEOUT = "IRONDOME_TOUCH_TIMEOUT"
#: Short enough that the prompt is gone before a client that gives up after 60 seconds does.
DEFAULT_TOUCH_TIMEOUT = 45
#: The bound ``irondome mcp --touch-timeout`` accepts, an hour.
_MAX_TOUCH_TIMEOUT = 3600

SERVER_INFO: Dict[str, str] = {"name": "irondome", "version": __version__}

INSTRUCTIONS = (
    "IronDome keeps secrets for you without showing them. list_secrets returns the names of the secrets you "
    "may use. run_with_secrets runs a program with secrets in its environment and masks them in its output. "
    "get_totp returns a current one-time password. reveal_secret returns a value only where the vault's "
    "owner allowed that."
)

_DEFAULT_COMMAND_TIMEOUT = 60
_MAX_COMMAND_TIMEOUT = 600
#: Bytes of each output stream handed back; the rest is read and dropped.
_OUTPUT_LIMIT = 100_000
#: The Secure Enclave helper shows at most this much of a prompt's text.
_MAX_REASON = 200
_MAX_REFERENCES_SHOWN = 80
#: Audit details are cut here; the log itself would cut them at 4096.
_MAX_DETAIL = 1000
_LIST_TTL_MS = 300_000
#: Messages read ahead while a call is being answered; more wait in the pipe.
_QUEUE_LIMIT = 16
#: Lines up to this size are parsed as soon as they are read (a cancellation is far smaller).
_PARSE_AHEAD = 64 * 1024
_READ_SIZE = 65536
_MAX_ID = 2**63

# JSON-RPC 2.0 and MCP error codes.
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603
_UNSUPPORTED_VERSION = -32022

_META_VERSION = "io.modelcontextprotocol/protocolVersion"
_META_CLIENT = "io.modelcontextprotocol/clientInfo"
_META_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
_META_SERVER = "io.modelcontextprotocol/serverInfo"
_META_SUBSCRIPTION = "io.modelcontextprotocol/subscriptionId"

_CAPABILITIES: Dict[str, Any] = {"tools": {"listChanged": False}}
#: Makes Claude Code ask its user before every call, whatever permission mode it runs in.
_ASK_FIRST: Dict[str, Any] = {"anthropic/requiresUserInteraction": True}
_VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_TOTP_FIELD = "totp"


# ---------------------------------------------------------------------------
# The tools
# ---------------------------------------------------------------------------


def _object(properties: Dict[str, Any], required: Sequence[str] = ()) -> Dict[str, Any]:
    schema: Dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        schema["required"] = list(required)
    return schema


_REFERENCE_INPUT = _object(
    {"reference": {"type": "string", "minLength": 1, "description": "The name of a secret, as list_secrets gives it."}},
    ("reference",),
)

#: The tool definitions ``tools/list`` returns: fixed, in this order, for every client.
TOOLS: Tuple[Dict[str, Any], ...] = (
    {
        "name": "list_secrets",
        "title": "List secrets",
        "description": (
            "Lists the names of the secrets you may use, never their values. Pass a name to run_with_secrets, "
            'get_totp or reveal_secret. kind is "totp" for a one-time-password generator and "value" for anything '
            'else. mode is "grant" when the vault\'s owner gave this server a grant and "touch" when the owner '
            "approves each call with Touch ID. can_reveal says whether reveal_secret can return a value."
        ),
        "inputSchema": _object({}),
        "outputSchema": _object(
            {
                "secrets": {
                    "type": "array",
                    "items": _object(
                        {"name": {"type": "string"}, "kind": {"type": "string", "enum": ["value", "totp"]}},
                        ("name", "kind"),
                    ),
                },
                "mode": {"type": "string", "enum": ["grant", "touch"]},
                "can_reveal": {"type": "boolean"},
            },
            ("secrets", "mode", "can_reveal"),
        ),
        "annotations": {
            "title": "List secrets",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "name": "run_with_secrets",
        "title": "Run a program with secrets",
        "description": (
            "Runs a program with secrets in its environment and returns its exit code and output. command is the "
            "program and its arguments; it is started directly, not through a shell. env maps each environment "
            "variable to set to the name of a secret from list_secrets. Wherever a secret appears in the output it "
            f"is replaced by [irondome:VARIABLE]. Each output stream is cut at {_OUTPUT_LIMIT} bytes; truncated "
            "says whether that happened. The program reads no input unless stdin is given."
        ),
        "inputSchema": _object(
            {
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": 'The program and its arguments, for example ["gh", "repo", "list"].',
                },
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string", "minLength": 1},
                    "minProperties": 1,
                    "maxProperties": caps.MAX_REFERENCES,
                    "description": (
                        "Environment variables to set. Each key is a variable name (letters, digits and underscores, "
                        "not starting with a digit), each value the name of a secret from list_secrets."
                    ),
                },
                "cwd": {
                    "type": "string",
                    "minLength": 1,
                    "description": "The directory to run the program in. Default: the server's working directory.",
                },
                "timeout_seconds": {
                    "type": "number",
                    "exclusiveMinimum": 0,
                    "maximum": _MAX_COMMAND_TIMEOUT,
                    "description": (
                        f"Stop the program after this many seconds. Default {_DEFAULT_COMMAND_TIMEOUT}, "
                        f"at most {_MAX_COMMAND_TIMEOUT}."
                    ),
                },
                "stdin": {"type": "string", "description": "Text to give the program on its standard input."},
            },
            ("command", "env"),
        ),
        "outputSchema": _object(
            {
                "exit_code": {"type": "integer"},
                "stdout": {"type": "string"},
                "stderr": {"type": "string"},
                "truncated": {"type": "boolean"},
            },
            ("exit_code", "stdout", "stderr", "truncated"),
        ),
        "annotations": {
            "title": "Run a program with secrets",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        "_meta": _ASK_FIRST,
    },
    {
        "name": "get_totp",
        "title": "Get a one-time password",
        "description": (
            'Returns the current one-time password of a secret whose kind is "totp" in list_secrets, and the '
            "number of seconds it stays valid."
        ),
        "inputSchema": _REFERENCE_INPUT,
        "outputSchema": _object(
            {"code": {"type": "string"}, "seconds_remaining": {"type": "integer", "minimum": 1}},
            ("code", "seconds_remaining"),
        ),
        "annotations": {
            "title": "Get a one-time password",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "_meta": _ASK_FIRST,
    },
    {
        "name": "reveal_secret",
        "title": "Reveal a secret",
        "description": (
            "Returns the value of a secret. This works only where the vault's owner allowed values to be shown "
            "(can_reveal in list_secrets); any other secret can still be used with run_with_secrets."
        ),
        "inputSchema": _REFERENCE_INPUT,
        "outputSchema": _object({"value": {"type": "string"}}, ("value",)),
        "annotations": {
            "title": "Reveal a secret",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "_meta": _ASK_FIRST,
    },
)


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


class _RpcError(Exception):
    """A request that gets a JSON-RPC error instead of a result."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class _Notice:
    """A notification sent in place of an answer (``subscriptions/listen`` is never answered)."""

    def __init__(self, message: Dict[str, Any]) -> None:
        self.message = message


class _Cancelled(Exception):
    """The client cancelled the call before its work was done."""


def _is_id(value: Any) -> bool:
    """MCP request ids are strings or integers; booleans and fractions are not."""
    if isinstance(value, str):
        return True
    return isinstance(value, int) and not isinstance(value, bool) and -_MAX_ID <= value < _MAX_ID


def _answerable_id(message: Any) -> Optional[Union[str, int]]:
    """The id an answer to *message* carries: its own if it is valid, else null."""
    if isinstance(message, dict) and _is_id(message.get("id")):
        return message["id"]
    return None


def _request_id(message: Any) -> Optional[Union[str, int]]:
    """The id of a request (a message with a method and a valid id), else None."""
    if isinstance(message, dict) and isinstance(message.get("method"), str):
        return _answerable_id(message)
    return None


def _cancellation(message: Any) -> Optional[Union[str, int]]:
    """The request a ``notifications/cancelled`` names, or None for any other message."""
    if not isinstance(message, dict) or "id" in message or message.get("method") != "notifications/cancelled":
        return None
    params = message.get("params")
    if isinstance(params, dict) and _is_id(params.get("requestId")):
        return params["requestId"]
    return None


def _error(request_id: Optional[Union[str, int]], code: int, message: str, data: Any = None) -> Dict[str, Any]:
    error: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _complete(result: Dict[str, Any], *, listing: bool = False) -> Dict[str, Any]:
    """*result* in the shape both eras accept: marked complete, naming this server, cacheable if a list."""
    shaped: Dict[str, Any] = {"resultType": "complete"}
    shaped.update(result)
    if listing:
        shaped["ttlMs"] = _LIST_TTL_MS
        shaped["cacheScope"] = "public"
    shaped["_meta"] = {_META_SERVER: dict(SERVER_INFO)}
    return shaped


def _tool_success(structured: Dict[str, Any]) -> Dict[str, Any]:
    text = json.dumps(structured, ensure_ascii=False, sort_keys=True)
    return _complete({"content": [{"type": "text", "text": text}], "structuredContent": structured, "isError": False})


def _tool_failure(text: str) -> Dict[str, Any]:
    return _complete({"content": [{"type": "text", "text": text}], "isError": True})


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "\u2026"


def _printable(text: str) -> str:
    """*text* with every character a dialog or terminal would not show as itself escaped."""
    if text.isprintable():
        return text
    return "".join(char if char.isprintable() else char.encode("unicode_escape").decode("ascii") for char in text)


def _shown(text: str) -> str:
    """One word of agent-supplied text as the owner should read it: quoted, escaped, inert."""
    return shlex.quote(_printable(text))


def _started_path(found: str) -> str:
    """The path that starts the program *found*, as ``irondome run`` shows it: every directory resolved as the
    kernel resolves it (no ``..`` or link to a directory can stand for one file in the prompt and reach
    another), the program's own name kept, since a multi-call program or a virtual environment depends on it."""
    directory, name = os.path.split(found)
    return os.path.join(os.path.realpath(directory), name)


def _listed(items: Sequence[str], budget: int) -> str:
    """``a, b and 3 more``: as many of *items* as fit in *budget* characters."""
    whole = ", ".join(items)
    if len(whole) <= budget:
        return whole
    kept: List[str] = []
    for item in items:
        rest = len(items) - len(kept) - 1
        if len(", ".join(kept + [item]) + f" and {rest} more") > budget:
            break
        kept.append(item)
    rest = len(items) - len(kept)
    tail = f" and {rest - 1} more" if not kept and rest > 1 else ""
    if not kept:
        return _clip(items[0], budget - len(tail)) + tail
    return ", ".join(kept) + f" and {rest} more"


def _say(text: str) -> None:
    """A line for whoever reads the server's stderr. Never fails a call."""
    try:
        sys.stderr.write(text + "\n")
        sys.stderr.flush()
    except (AttributeError, OSError, ValueError):
        pass  # no stderr to write to; the protocol stream carries on regardless


def _report_bug(exc: BaseException) -> None:
    """Where an unexpected exception happened, without its message: that could hold a value."""
    frames = traceback.extract_tb(exc.__traceback__)
    where = f" at {os.path.basename(frames[-1].filename)}:{frames[-1].lineno}" if frames else ""
    _say(f"irondome mcp: internal error ({type(exc).__name__}{where}); the request was answered with an error")


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------


def _only(arguments: Dict[Any, Any], allowed: Sequence[str]) -> None:
    unknown = sorted(_clip(str(name), 40) for name in arguments if name not in allowed)
    if unknown:
        takes = ", ".join(allowed) if allowed else "no arguments"
        raise UsageError(f"unknown argument {', '.join(unknown[:5])}: this tool takes {takes}")


def _text(arguments: Dict[Any, Any], name: str, *, required: bool) -> Optional[str]:
    value = arguments.get(name)
    if value is None:
        if required:
            raise UsageError(f"{name} is required")
        return None
    if not isinstance(value, str):
        raise UsageError(f"{name} must be a string")
    return value


def _reference(arguments: Dict[Any, Any]) -> str:
    text = _text(arguments, "reference", required=True)
    return refs.parse_reference(text or "")


def _command(arguments: Dict[Any, Any]) -> List[str]:
    value = arguments.get("command")
    if not isinstance(value, list) or not value or not all(isinstance(part, str) for part in value):
        raise UsageError(
            'command must be a list of strings: the program, then its arguments, for example ["gh", "repo", "list"]. '
            "It is not run through a shell"
        )
    if not value[0]:
        raise UsageError("the program (the first item of command) cannot be empty")
    if any("\x00" in part for part in value):
        raise UsageError("command cannot contain NUL characters")
    return list(value)


def _variables(arguments: Dict[Any, Any]) -> Dict[str, str]:
    value = arguments.get("env")
    if not isinstance(value, dict) or not value:
        raise UsageError(
            'env must name at least one secret: an object mapping each variable to a secret, for example '
            '{"GITHUB_TOKEN": "GITHUB_TOKEN"}'
        )
    if len(value) > caps.MAX_REFERENCES:
        raise UsageError(f"env can name at most {caps.MAX_REFERENCES} variables")
    for name, reference in value.items():
        if not isinstance(name, str) or not _VARIABLE.fullmatch(name):
            raise UsageError(
                f"{_clip(repr(name), 60)} is not an environment variable name: use letters, digits and underscores, "
                "not starting with a digit"
            )
        if not isinstance(reference, str) or not reference:
            raise UsageError(f"the secret for {name} must be given by its name, a non-empty string")
    return dict(value)


def _directory(arguments: Dict[Any, Any]) -> Optional[str]:
    path = _text(arguments, "cwd", required=False)
    if path is None:
        return None
    if not path or "\x00" in path or not os.path.isdir(path):
        raise UsageError(f"cwd: there is no directory {_clip(path, 200)!r}")
    return path


def _time_limit(arguments: Dict[Any, Any]) -> float:
    value = arguments.get("timeout_seconds")
    if value is None:
        return float(_DEFAULT_COMMAND_TIMEOUT)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= _MAX_COMMAND_TIMEOUT:
        raise UsageError(f"timeout_seconds must be a number of seconds above 0 and at most {_MAX_COMMAND_TIMEOUT}")
    return float(value)


def _standard_input(arguments: Dict[Any, Any]) -> Optional[bytes]:
    text = _text(arguments, "stdin", required=False)
    if text is None:
        return None
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise UsageError("stdin must be valid Unicode text") from None


# ---------------------------------------------------------------------------
# What a tool call may read
# ---------------------------------------------------------------------------


def _grant_mode() -> bool:
    """True when the owner gave this server a grant: then that grant is all it uses."""
    return bool(os.environ.get(ENV_GRANT))


def _agent_context() -> Context:
    """The Context of one tool call: an agent asks, and nobody at a terminal is part of it.

    The server may well have inherited a terminal from its host, but no
    request ever comes from it, so no prompt goes to it either. Everything the
    context has to say goes to stderr: stdout is the protocol stream.
    """
    return Context(
        argparse.Namespace(touch=True),
        Output(stdout=sys.stderr, stderr=sys.stderr, color=False),
        agent=True,
        inject_with="the run_with_secrets tool",
    )


def _vault_of(access: Access) -> Vault:
    if access.vault is None:
        raise IronDomeError("this access is closed")
    return access.vault


def _grant_of(access: Access) -> caps.Grant:
    if access.grant is None:
        raise IronDomeError("this access holds no grant")
    return access.grant


def _current_code(read: Callable[[], str], period_of: Callable[[], int]) -> Tuple[str, int]:
    """A one-time password and the whole seconds it stays valid, both for the same time step.

    The code is read again if the step changed while it was being read, so a
    code is never paired with the lifetime of the next one.
    """
    before = time.time()
    code = read()
    after = time.time()
    period = period_of()
    for _ in range(2):
        if int(before // period) == int(after // period):
            break
        before = time.time()
        code = read()
        after = time.time()
    return code, period - int(after % period)


def _timed_out(exc: runner.CommandTimeoutError) -> str:
    text = str(exc)
    result = exc.result
    if result is not None and (result.stdout or result.stderr):
        text += (
            ". What it printed before it was stopped, with secrets masked:\n--- stdout ---\n"
            f"{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    return text


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------


class Server:
    """The state of one connection, and the answer to each message.

    :meth:`handle_message` takes one parsed JSON-RPC message and returns the
    message to send back, or None; it never raises. The only state kept is
    what the protocol needs (the revision ``initialize`` agreed on, which
    requests are still open and which of them the client cancelled) and the
    names a Touch ID approval listed. Cancellation bookkeeping is the one part
    that is safe to call from another thread.
    """

    def __init__(self) -> None:
        #: The revision agreed by ``initialize``; None until a client of the older era sends it.
        self.legacy_version: Optional[str] = None
        self._listing: Optional[Dict[str, Any]] = None
        self._lock = threading.Lock()
        self._open: Dict[Union[str, int], int] = {}
        self._cancelled: Set[Union[str, int]] = set()
        self._tools: Dict[str, Callable[[Optional[Union[str, int]], Dict[Any, Any]], Dict[str, Any]]] = {
            "list_secrets": self._list_secrets,
            "run_with_secrets": self._run_with_secrets,
            "get_totp": self._get_totp,
            "reveal_secret": self._reveal_secret,
        }

    # -- cancellation (shared with the reading thread) ------------------------

    def begin(self, request_id: Union[str, int]) -> None:
        """A request has been read and is waiting to be answered."""
        with self._lock:
            self._open[request_id] = self._open.get(request_id, 0) + 1

    def cancel(self, request_id: Union[str, int]) -> None:
        """The client cancelled *request_id*. Ignored unless that request is still open."""
        with self._lock:
            if request_id in self._open:
                self._cancelled.add(request_id)

    def cancelled(self, request_id: Union[str, int]) -> bool:
        with self._lock:
            return request_id in self._cancelled

    def finish(self, request_id: Union[str, int]) -> None:
        """A request has been answered, or dropped because it was cancelled."""
        with self._lock:
            remaining = self._open.get(request_id, 0) - 1
            if remaining > 0:
                self._open[request_id] = remaining
            else:
                self._open.pop(request_id, None)
                self._cancelled.discard(request_id)

    def _abort_if_cancelled(self, request_id: Optional[Union[str, int]]) -> None:
        if request_id is not None and self.cancelled(request_id):
            raise _Cancelled()

    # -- messages -------------------------------------------------------------

    def handle_message(self, message: Any) -> Optional[Dict[str, Any]]:
        """The message to send in answer to *message*, or None when nothing is sent."""
        try:
            return self._handle(message)
        except Exception as exc:  # a bug costs one answer, never the connection
            _report_bug(exc)
            return _error(_answerable_id(message), _INTERNAL_ERROR, "Internal error")

    def _handle(self, message: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(message, dict):
            return _error(None, _INVALID_REQUEST, "Invalid Request: a message is a JSON object")
        if "method" not in message:
            if "id" in message and ("result" in message or "error" in message):
                return None  # an answer to a request: this server never sends any
            return _error(_answerable_id(message), _INVALID_REQUEST, "Invalid Request: the message has no method")
        method, params = message["method"], message.get("params")
        if "id" not in message:
            self._notification(method, params)
            return None  # notifications are never answered, not even with an error
        request_id = message["id"]
        if not _is_id(request_id):
            return _error(None, _INVALID_REQUEST, "Invalid Request: the id must be a string or an integer")
        if message.get("jsonrpc") != "2.0":
            return _error(request_id, _INVALID_REQUEST, 'Invalid Request: "jsonrpc" must be "2.0"')
        if not isinstance(method, str):
            return _error(request_id, _INVALID_REQUEST, "Invalid Request: the method must be a string")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return _error(request_id, _INVALID_PARAMS, "Invalid params: params must be an object")
        try:
            outcome = self._dispatch(request_id, method, params)
        except _RpcError as exc:
            return _error(request_id, exc.code, exc.message, exc.data)
        if isinstance(outcome, _Notice):
            return outcome.message
        return {"jsonrpc": "2.0", "id": request_id, "result": outcome}

    def _notification(self, method: Any, params: Any) -> None:
        if method == "notifications/cancelled" and isinstance(params, dict) and _is_id(params.get("requestId")):
            self.cancel(params["requestId"])

    def _dispatch(
        self, request_id: Union[str, int], method: str, params: Dict[Any, Any]
    ) -> Union[Dict[str, Any], _Notice]:
        if method == "initialize":
            return self._initialize(params)
        if _modern_version(params) is None:
            return self._legacy(request_id, method, params)
        if method == "server/discover":
            return _complete(
                {
                    "supportedVersions": list(MODERN_VERSIONS),
                    "capabilities": copy.deepcopy(_CAPABILITIES),
                    "instructions": INSTRUCTIONS,
                },
                listing=True,
            )
        if method == "tools/list":
            return _complete({"tools": copy.deepcopy(list(TOOLS))}, listing=True)
        if method == "tools/call":
            return self._call(request_id, params)
        if method == "subscriptions/listen":
            # Nothing here ever changes, so no notification is honoured and the request stays open until the
            # client cancels it: it is acknowledged and never answered.
            return _Notice(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/subscriptions/acknowledged",
                    "params": {"_meta": {_META_SUBSCRIPTION: request_id}, "notifications": {}},
                }
            )
        raise _RpcError(_METHOD_NOT_FOUND, f"Method not found: {_clip(method, 100)}")

    def _initialize(self, params: Dict[Any, Any]) -> Dict[str, Any]:
        requested = params.get("protocolVersion")
        version = requested if isinstance(requested, str) and requested in LEGACY_VERSIONS else LEGACY_VERSIONS[0]
        self.legacy_version = version
        return {
            "protocolVersion": version,
            "capabilities": copy.deepcopy(_CAPABILITIES),
            "serverInfo": dict(SERVER_INFO),
            "instructions": INSTRUCTIONS,
        }

    def _legacy(self, request_id: Union[str, int], method: str, params: Dict[Any, Any]) -> Dict[str, Any]:
        """A request without a protocol version in ``_meta``: the older era, after ``initialize``."""
        if method == "ping":
            return {}
        if method not in ("server/discover", "tools/list", "tools/call"):
            raise _RpcError(_METHOD_NOT_FOUND, f"Method not found: {_clip(method, 100)}")
        if method == "server/discover" or self.legacy_version is None:
            hint = "" if method == "server/discover" else " (or send initialize first)"
            raise _RpcError(_INVALID_PARAMS, f"Invalid params: missing required _meta field {_META_VERSION}{hint}")
        if method == "tools/list":
            return _complete({"tools": copy.deepcopy(list(TOOLS))}, listing=True)
        return self._call(request_id, params)

    def _call(self, request_id: Union[str, int], params: Dict[Any, Any]) -> Dict[str, Any]:
        name = params.get("name")
        tool = self._tools.get(name) if isinstance(name, str) else None
        if tool is None:
            shown = _clip(name, 100) if isinstance(name, str) else "no name given"
            raise _RpcError(_INVALID_PARAMS, f"Unknown tool: {shown}")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        try:
            if not isinstance(arguments, dict):
                raise UsageError("the arguments of a tool call are a JSON object")
            return _tool_success(tool(request_id, arguments))
        except _Cancelled:
            return _tool_failure("the client cancelled this call")
        except IronDomeError as exc:
            return _tool_failure(str(exc) or type(exc).__name__)

    # -- access ---------------------------------------------------------------

    def _reason(self, tool: str, action: str) -> str:
        """What the Touch ID prompt says. It completes "<helper> is trying to ...", in 200 characters at most."""
        suffix = f" (MCP {tool}, bunker {paths.bunker_name()})"
        return _clip("let an AI agent " + action, _MAX_REASON - len(suffix)) + suffix

    @staticmethod
    def _run_reason(references: Sequence[str], program: str, arguments: Sequence[str]) -> Optional[str]:
        """The prompt for run_with_secrets: the secrets, the program by the whole path it starts, its arguments.

        The path is never shortened, because the part left out could make another program look like the one
        the owner trusts; the secrets are counted rather than named, and the arguments cut, before that.
        None when even that does not fit in 200 characters.
        """
        suffix = f" (MCP run_with_secrets, bunker {paths.bunker_name()})"
        names = [_shown(reference) for reference in references]
        counted = f"{len(names)} secret" + ("" if len(names) == 1 else "s")
        for listed in (_listed(names, _MAX_REFERENCES_SHOWN), counted):
            head = f"let an AI agent use {listed} to run {_shown(program)}"
            room = _MAX_REASON - len(suffix) - len(head)
            if not arguments and room >= 0:
                return head + suffix
            if arguments and room >= 2:  # a space and at least the mark of a cut
                return head + " " + _clip(" ".join(_shown(part) for part in arguments), room - 1) + suffix
        return None

    @contextmanager
    def _touch(self, ctx: Context, reason: str, request_id: Optional[Union[str, int]]) -> Iterator[Access]:
        """The vault, opened by the owner's touch for this one call and limited by each entry's agent policy."""
        if not vault_exists():
            raise VaultError(
                f"there is no vault in bunker {paths.bunker_name()}, and this server was given no grant "
                f"({ENV_GRANT}). The vault's owner sets one up with: irondome init, then irondome grant create"
            )
        access = Access(ctx, vault=ctx.open_vault_by_touch(reason=reason), restricted=True)
        try:
            self._abort_if_cancelled(request_id)
            yield access
        finally:
            access.close()

    @staticmethod
    def _refused(ctx: Context, access: Access, reference: str, purpose: str, detail: str, exc: Exception) -> None:
        """Write a refused read to the audit log: the owner touched the sensor for it."""
        ctx.audit(
            _vault_of(access), purpose, target=_clip(reference, 200), detail=f"refused ({detail}): {exc}", ok=False
        )

    def _touch_value(self, ctx: Context, access: Access, reference: str, purpose: str, detail: str) -> str:
        """Read through the touch-opened vault, where each entry's agent policy decides."""
        try:
            return access.value(reference, purpose, detail=detail)
        except (NotFoundError, PolicyError) as exc:
            self._refused(ctx, access, reference, purpose, detail, exc)
            raise

    def _touch_resolve(
        self, ctx: Context, access: Access, reference: str, purpose: str, detail: str
    ) -> Tuple[Entry, str]:
        """The entry and field *reference* stands for, before anything is read from it."""
        try:
            return _vault_of(access).resolve(reference)
        except (NotFoundError, UsageError) as exc:
            self._refused(ctx, access, reference, purpose, detail, exc)
            raise

    @staticmethod
    def _look(ctx: Context, references: Sequence[str], *, totp: bool = False, reveal: bool = False) -> None:
        """Check a call against the grant without spending a use, so that a call it cannot serve costs nothing."""
        with ctx.access(consume=False) as access:
            grant = _grant_of(access)
            missing = [reference for reference in references if not grant.has(reference)]
            if missing:
                raise PolicyError(
                    f"this grant does not cover {', '.join(repr(name) for name in missing)}; "
                    f"it covers: {', '.join(grant.names())}"
                )
            for reference in references:
                if totp and not grant.is_totp(reference):
                    raise UsageError(f"{reference!r} is not a one-time password; get_totp reads secrets of kind totp")
                if reveal and grant.mode != caps.MODE_REVEAL and not grant.is_totp(reference):
                    raise PolicyError(
                        "this grant lets secrets be used, not shown. Use run_with_secrets to put "
                        f"{reference!r} into a program's environment, masked in its output"
                    )

    # -- tools ----------------------------------------------------------------

    def _list_secrets(self, request_id: Optional[Union[str, int]], arguments: Dict[Any, Any]) -> Dict[str, Any]:
        _only(arguments, ())
        ctx = _agent_context()
        if _grant_mode():
            with ctx.access(consume=False) as access:
                grant = _grant_of(access)
                secrets = [
                    {"name": name, "kind": _TOTP_FIELD if grant.is_totp(name) else "value"} for name in access.names()
                ]
                return {"secrets": secrets, "mode": "grant", "can_reveal": grant.mode == caps.MODE_REVEAL}
        if self._listing is None:
            reason = self._reason("list_secrets", "see the names of the secrets it may use")
            with self._touch(ctx, reason, request_id) as access:
                listing = _touch_listing(access)
                ctx.audit(_vault_of(access), "list", detail=f"mcp list_secrets: {len(listing['secrets'])} names")
            self._listing = listing
        return copy.deepcopy(self._listing)

    def _run_with_secrets(self, request_id: Optional[Union[str, int]], arguments: Dict[Any, Any]) -> Dict[str, Any]:
        _only(arguments, ("command", "env", "cwd", "timeout_seconds", "stdin"))
        command = _command(arguments)
        variables = _variables(arguments)
        cwd = _directory(arguments)
        limit = _time_limit(arguments)
        feed = _standard_input(arguments)
        plan = refs.plan_injection({}, None, [f"{name}={reference}" for name, reference in variables.items()])
        # A program that cannot be started is refused before a use is spent or the owner is asked. It is
        # looked up once, here, on the command's own PATH, and started by exactly that path (executable=):
        # a file put earlier on PATH, or a link turned, while the owner reads the prompt changes nothing.
        program = _started_path(runner._prepare(command, {}, plan.literals, None, cwd, limit)[1])
        users: Dict[str, List[str]] = {}
        for variable, reference in plan.references.items():
            users.setdefault(reference, []).append(variable)
        shown = " ".join(_shown(part) for part in command)

        def detail(reference: str) -> str:
            return _clip(f"mcp run_with_secrets {','.join(users[reference])}: {shown}", _MAX_DETAIL)

        ctx = _agent_context()
        if _grant_mode():
            self._look(ctx, list(users))
            self._abort_if_cancelled(request_id)
            with ctx.access(consume=True) as access:
                injected = refs.resolve_plan(
                    plan, lambda reference: access.value(reference, PURPOSE_USE, detail=detail(reference))
                )
        else:
            reason = self._run_reason(list(users), program, command[1:])
            if reason is None:
                raise UsageError(
                    f"the program {_shown(program)} cannot be named in full in a Touch ID prompt (at most "
                    f"{_MAX_REASON} characters with the bunker's name), and IronDome does not shorten it: a "
                    "shortened path could pass for another program. Nothing was asked or used. Give the program "
                    "a shorter path, or ask the vault's owner for a grant (irondome grant create)"
                )
            with self._touch(ctx, reason, request_id) as access:
                injected = refs.resolve_plan(
                    plan,
                    lambda reference: self._touch_value(ctx, access, reference, PURPOSE_USE, detail(reference)),
                )
        try:
            short = sorted(name for name in runner.Masker(injected).unmasked_names if injected[name])
            if short:
                raise PolicyError(
                    f"the value of {', '.join(short)} is shorter than {runner.MIN_MASK_BYTES} bytes, too short to be "
                    "masked in the output, so it is not handed to a program through MCP"
                )
            self._abort_if_cancelled(request_id)
            try:
                result = runner.run_captured(
                    command,
                    injected,
                    literals=plan.literals,
                    cwd=cwd,
                    timeout=limit,
                    max_bytes=_OUTPUT_LIMIT,
                    stdin=feed,
                    cancelled=(lambda: self.cancelled(request_id)) if request_id is not None else None,
                    executable=program,
                )
            except runner.CommandTimeoutError as exc:
                raise IronDomeError(_timed_out(exc)) from None
            except runner.CommandCancelledError:
                raise _Cancelled() from None
        finally:
            injected.clear()
        return {
            "exit_code": result.code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "truncated": result.truncated,
        }

    def _get_totp(self, request_id: Optional[Union[str, int]], arguments: Dict[Any, Any]) -> Dict[str, Any]:
        _only(arguments, ("reference",))
        reference = _reference(arguments)
        ctx = _agent_context()
        if _grant_mode():
            self._look(ctx, [reference], totp=True)
            self._abort_if_cancelled(request_id)
            with ctx.access(consume=True) as access:
                grant = _grant_of(access)
                if not grant.is_totp(reference):
                    raise UsageError(f"{reference!r} is not a one-time password")
                code, remaining = _current_code(
                    lambda: access.value(reference, PURPOSE_REVEAL, detail="mcp get_totp"),
                    lambda: grant.period(reference),
                )
        else:
            reason = self._reason("get_totp", f"read the one-time password {_clip(_shown(reference), 100)}")
            with self._touch(ctx, reason, request_id) as access:
                vault = _vault_of(access)
                entry, field = self._touch_resolve(ctx, access, reference, PURPOSE_REVEAL, "mcp get_totp")
                if field != _TOTP_FIELD:
                    raise UsageError(f"{reference!r} is not a one-time password; get_totp reads secrets of kind totp")
                code, remaining = _current_code(
                    lambda: self._touch_value(ctx, access, reference, PURPOSE_REVEAL, "mcp get_totp"),
                    lambda: otp.validate(vault.read_secret(entry).totp)["period"],
                )
        return {"code": code, "seconds_remaining": remaining}

    def _reveal_secret(self, request_id: Optional[Union[str, int]], arguments: Dict[Any, Any]) -> Dict[str, Any]:
        _only(arguments, ("reference",))
        reference = _reference(arguments)
        ctx = _agent_context()
        if _grant_mode():
            self._look(ctx, [reference], reveal=True)
            self._abort_if_cancelled(request_id)
            with ctx.access(consume=True) as access:
                value = access.value(reference, PURPOSE_REVEAL, detail="mcp reveal_secret")
        else:
            reason = self._reason("reveal_secret", f"see the value of {_clip(_shown(reference), 100)}")
            with self._touch(ctx, reason, request_id) as access:
                try:
                    value = self._touch_value(ctx, access, reference, PURPOSE_REVEAL, "mcp reveal_secret")
                except PolicyError:
                    entry, _field = _vault_of(access).resolve(reference)
                    if entry.agent != "use":
                        raise
                    raise PolicyError(
                        f"{entry.name!r} may be used by agents but not shown to them. Use run_with_secrets to put it "
                        f"into a program's environment, masked in its output. Its owner can allow showing it with: "
                        f"irondome edit {entry.name!r} --agent reveal"
                    ) from None
        return {"value": value}


def _touch_listing(access: Access) -> Dict[str, Any]:
    """What ``list_secrets`` shows after a touch: every reference the entries' agent policies leave open."""
    vault = _vault_of(access)
    kinds: Dict[str, str] = {}
    entries: Dict[str, Entry] = {}
    revealable = False
    for name in access.names():
        if name in kinds:
            continue  # an alias that shadows an entry of the same name: the alias is what the name resolves to
        try:
            entry, field = vault.resolve(name)
        except IronDomeError:
            continue
        kinds[name] = _TOTP_FIELD if field == _TOTP_FIELD else "value"
        entries[entry.id] = entry
        revealable = revealable or (field != _TOTP_FIELD and entry.agent == "reveal")
    for entry in entries.values():
        reference = f"{entry.name}/{_TOTP_FIELD}"
        if not entry.has_totp or reference in kinds:
            continue
        try:
            target, field = vault.resolve(reference)
        except IronDomeError:
            continue
        if target.id == entry.id and field == _TOTP_FIELD:
            kinds[reference] = _TOTP_FIELD
    secrets = [{"name": name, "kind": kinds[name]} for name in sorted(kinds, key=lambda item: (item.casefold(), item))]
    return {"secrets": secrets, "mode": "touch", "can_reveal": revealable}


def _modern_version(params: Dict[Any, Any]) -> Optional[str]:
    """The revision a stateless request names in ``_meta``, or None for a request of the older era."""
    meta = params.get("_meta")
    if not isinstance(meta, dict) or _META_VERSION not in meta:
        return None
    version = meta[_META_VERSION]
    if not isinstance(version, str):
        raise _RpcError(_INVALID_PARAMS, f"Invalid params: _meta field {_META_VERSION} must be a string")
    if version not in MODERN_VERSIONS:
        raise _RpcError(
            _UNSUPPORTED_VERSION,
            "Unsupported protocol version",
            {"supported": list(PROTOCOL_VERSIONS), "requested": version},
        )
    for field in (_META_CLIENT, _META_CAPABILITIES):
        if not isinstance(meta.get(field), dict):
            raise _RpcError(_INVALID_PARAMS, f"Invalid params: missing required _meta field {field}")
    return version


def handle_message(message: Any, server: Optional[Server] = None) -> Optional[Dict[str, Any]]:
    """Answer one parsed message: the message to send back, or None. Never raises.

    Without *server* a fresh one answers, so nothing carries over between
    calls; pass the same :class:`Server` to keep a connection's state.
    """
    return (server if server is not None else Server()).handle_message(message)


# ---------------------------------------------------------------------------
# The wire
# ---------------------------------------------------------------------------


def _strict_int(token: str) -> int:
    """Refuse a long literal before converting it: that is quadratic in its length on Python 3.9."""
    if len(token.lstrip("-")) > 20:
        raise ValueError("integer literal is too long")
    return int(token)


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("number out of range")
    return value


def _no_constant(token: str) -> Any:
    raise ValueError(f"{token} is not JSON")


def _unique_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("an object repeats a key")
    return result


_DECODER = json.JSONDecoder(
    parse_int=_strict_int, parse_float=_finite_float, parse_constant=_no_constant, object_pairs_hook=_unique_keys
)


def _parse(line: bytes) -> Any:
    """One message, read as hostile input. Raises ``ValueError`` for anything that is not plain JSON."""
    try:
        return _DECODER.decode(line.decode("utf-8"))
    except RecursionError:
        raise ValueError("nested too deeply") from None


def _encode(message: Dict[str, Any]) -> bytes:
    """One line of ASCII JSON: no raw newline can appear in it, whatever the values hold."""
    try:
        text = json.dumps(message, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError) as exc:
        _report_bug(exc)
        text = json.dumps(_error(_answerable_id(message), _INTERNAL_ERROR, "Internal error"), separators=(",", ":"))
    return text.encode("ascii") + b"\n"


def _lines(read: Callable[[int], bytes]) -> Iterator[Optional[bytes]]:
    """Each line of the stream, without its newline; None for a line longer than MAX_LINE_BYTES.

    At most one line's worth of bytes is held: the rest of an over-long line
    is read and dropped as it arrives. A last line without a newline counts.
    """
    buffer = bytearray()
    scanned = 0
    skipping = False
    while True:
        chunk = read(_READ_SIZE)
        if not chunk:
            break
        buffer += chunk
        start = 0
        while True:
            newline = buffer.find(b"\n", scanned)
            if newline == -1:
                break
            if skipping or newline - start > MAX_LINE_BYTES:
                yield None
                skipping = False
            else:
                yield bytes(buffer[start:newline])
            start = scanned = newline + 1
        del buffer[:start]
        scanned = len(buffer)
        if len(buffer) > MAX_LINE_BYTES:
            skipping = True
            buffer.clear()
            scanned = 0
    if skipping:
        yield None
    elif buffer:
        yield bytes(buffer)


def _byte_source(stdin: Optional[IO[Any]]) -> Callable[[int], bytes]:
    """How the reading thread gets bytes.

    The process's own standard input is read with ``os.read``, which holds no
    lock of Python's: a thread blocked in it cannot stall the interpreter's
    exit the way one blocked in ``sys.stdin.buffer`` can.
    """
    if stdin is None:
        return lambda size: os.read(0, size)
    source = getattr(stdin, "buffer", stdin)
    reader = getattr(source, "read1", None) or source.read

    def read(size: int) -> bytes:
        chunk = reader(size)
        if isinstance(chunk, str):
            return chunk.encode("utf-8", "surrogateescape")
        return bytes(chunk or b"")

    return read


def _write_descriptor(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(descriptor, view) :]


def _one_pipe(first: int, second: int) -> bool:
    """True when two descriptors write into the same pipe or socket: a client merged stderr into stdout."""
    try:
        one, two = os.fstat(first), os.fstat(second)
    except OSError:
        return False
    shared = (one.st_dev, one.st_ino) == (two.st_dev, two.st_ino)
    return shared and (stat.S_ISFIFO(one.st_mode) or stat.S_ISSOCK(one.st_mode))


@contextmanager
def _protocol_output(stdout: Optional[IO[Any]]) -> Iterator[Callable[[bytes], None]]:
    """Where protocol messages are written, and nothing else.

    With the process's own stdout, descriptor 1 is moved aside for the
    protocol and stderr takes its place, so that no stray write, by this
    program or by anything it starts, can corrupt the stream. A client that
    reads stderr through the same pipe as stdout gets no diagnostics at all:
    they go to the null device instead of into its protocol stream. Every
    descriptor is put back on the way out.
    """
    if stdout is not None:
        target = getattr(stdout, "buffer", stdout)
        if isinstance(target, io.TextIOBase):

            def write_text(data: bytes) -> None:
                target.write(data.decode("ascii"))
                target.flush()

            yield write_text
        else:

            def write_bytes(data: bytes) -> None:
                target.write(data)
                target.flush()

            yield write_bytes
        return
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (AttributeError, OSError, ValueError):
            pass  # closed or absent: nothing is buffered for it
    protocol = os.dup(1)
    merged = _one_pipe(1, 2)
    diagnostics = os.dup(2) if merged else -1
    try:
        with open(os.devnull, "wb") as sink:
            if merged:
                os.dup2(sink.fileno(), 2)
            try:
                os.dup2(2, 1)
            except OSError:
                os.dup2(sink.fileno(), 1)  # no stderr at all: stray output is dropped
        try:
            yield lambda data: _write_descriptor(protocol, data)
        finally:
            for stream in (sys.stdout, sys.stderr):
                try:
                    stream.flush()
                except (AttributeError, OSError, ValueError):
                    pass  # what was written meanwhile went to stderr or nowhere; there is nothing to keep
            os.dup2(protocol, 1)
            if merged:
                os.dup2(diagnostics, 2)
    finally:
        os.close(protocol)
        if merged:
            os.close(diagnostics)


class _Message:
    """A parsed message waiting its turn, and the id of the request it is, if it is one."""

    def __init__(self, message: Any, request_id: Optional[Union[str, int]]) -> None:
        self.message = message
        self.request_id = request_id


class _Line:
    """A line too long to parse ahead: queued as bytes, parsed when its turn comes."""

    def __init__(self, line: bytes) -> None:
        self.line = line


class _Unreadable:
    """A line that could not be taken as a message; it is answered with this error, id null."""

    def __init__(self, code: int, text: str) -> None:
        self.code = code
        self.text = text


_END = object()


def _admit(server: Server, line: bytes) -> Union[_Message, _Unreadable, None]:
    """Parse one line. A cancellation is acted on at once (None); a request is marked open."""
    try:
        message = _parse(line)
    except ValueError:
        return _Unreadable(_PARSE_ERROR, "Parse error")
    target = _cancellation(message)
    if target is not None:
        server.cancel(target)
        return None
    request_id = _request_id(message)
    if request_id is not None:
        server.begin(request_id)
    return _Message(message, request_id)


def _read_messages(server: Server, read: Callable[[int], bytes], messages: "queue.Queue[Any]") -> None:
    """The reading thread: act on cancellations as they arrive and queue everything else in order.

    Lines up to ``_PARSE_AHEAD`` bytes are parsed here, so a request can be
    cancelled while it waits its turn. Longer ones wait as bytes: a parsed
    line can take many times its size in memory, and the queue is to hold
    at most ``_QUEUE_LIMIT`` lines' worth.
    """
    too_long = f"Invalid Request: a message is at most {MAX_LINE_BYTES} bytes long"
    try:
        for line in _lines(read):
            if line is None:
                messages.put(_Unreadable(_INVALID_REQUEST, too_long))
            elif len(line) > _PARSE_AHEAD:
                messages.put(_Line(line))
            elif line.strip():
                item = _admit(server, line)
                if item is not None:
                    messages.put(item)
    except OSError as exc:
        _say(f"irondome mcp: standard input could not be read ({exc.strerror or type(exc).__name__}); stopping")
    except Exception as exc:  # the server must still stop cleanly, below
        _report_bug(exc)
    finally:
        messages.put(_END)


def _serve_lines(server: Server, read: Callable[[int], bytes], write: Callable[[bytes], None]) -> int:
    """Answer messages in the order they arrive until the input ends. Returns the exit status."""
    messages: "queue.Queue[Any]" = queue.Queue(maxsize=_QUEUE_LIMIT)
    reader = threading.Thread(target=_read_messages, args=(server, read, messages), name="irondome-mcp", daemon=True)
    reader.start()
    try:
        while True:
            item = messages.get()
            if item is _END:
                return EXIT_OK
            if isinstance(item, _Line):
                item = _admit(server, item.line)
                if item is None:
                    continue
            if isinstance(item, _Unreadable):
                write(_encode(_error(None, item.code, item.text)))
                continue
            request_id = item.request_id
            if request_id is not None and server.cancelled(request_id):
                server.finish(request_id)  # cancelled before it started: it never starts
                continue
            reply = server.handle_message(item.message)
            if reply is not None and not (request_id is not None and server.cancelled(request_id)):
                write(_encode(reply))
            if request_id is not None:
                server.finish(request_id)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        return EXIT_OK  # the client closed its end: there is nobody left to answer


def _touch_timeout(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_TOUCH_TIMEOUT:
        raise UsageError(f"the Touch ID timeout is a whole number of seconds from 1 to {_MAX_TOUCH_TIMEOUT}")
    return value


@contextmanager
def _environment_kept(*names: str) -> Iterator[None]:
    """Put the named environment variables back as they were when :func:`serve` returns."""
    saved = {name: os.environ.get(name) for name in names}
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def serve(
    stdin: Optional[IO[Any]] = None, stdout: Optional[IO[Any]] = None, *, touch_timeout: Optional[int] = None
) -> int:
    """Serve MCP on *stdin* and *stdout* (the process's own by default) until the input ends.

    *touch_timeout* is how many seconds a Touch ID prompt waits, handed to the
    Secure Enclave backend as ``IRONDOME_TOUCH_TIMEOUT``. Without it a value
    already in the environment stays, else :data:`DEFAULT_TOUCH_TIMEOUT`.
    Streams passed in are binary, or text streams with a binary ``buffer``.

    Returns 0 when the input ends or the client closes its end, 130 when
    interrupted, 1 when the protocol stream itself fails. Raises
    :class:`UsageError` for an unusable *touch_timeout*.
    """
    seconds = _touch_timeout(touch_timeout)
    harden_process()
    with _environment_kept(ENV_TOUCH_TIMEOUT, paths.ENV_BUNKER):
        if seconds is not None:
            os.environ[ENV_TOUCH_TIMEOUT] = str(seconds)
        elif not os.environ.get(ENV_TOUCH_TIMEOUT):
            os.environ[ENV_TOUCH_TIMEOUT] = str(DEFAULT_TOUCH_TIMEOUT)
        try:
            with _protocol_output(stdout) as write:
                _start()
                return _serve_lines(Server(), _byte_source(stdin), write)
        except OSError as exc:
            _say(f"irondome mcp: the protocol stream failed ({exc.strerror or type(exc).__name__})")
            return 1


def _start() -> None:
    """Choose the bunker the way ``irondome`` does before every command, and warn about a session token."""
    try:
        cli_main.select_bunker(argparse.Namespace())  # the bunker that holds the grant, when no bunker is named
    except IronDomeError as exc:
        _say(f"irondome mcp: {exc}")
    if os.environ.get(ENV_SESSION):
        _say(
            f"irondome mcp: ignoring {ENV_SESSION}. A session is the owner's own key to the vault and is never "
            "used here; give an agent a grant instead (irondome grant create)"
        )
