"""Run a command with secrets in its environment, and keep them out of what it prints.

``irondome run`` and the MCP tool ``run_with_secrets`` end here, after a vault
or a grant has handed over the values:

1. The child's environment is the caller's, plus the plain values of an env
   file, plus the secrets -- minus IronDome's own bearer credentials
   (``IRONDOME_SESSION``, ``IRONDOME_GRANT``, ``IRONDOME_PASSWORD_FILE``) and
   minus every variable that still holds an unresolved ``irondome://``
   reference. A child therefore never inherits a way into the vault.
2. The command is started directly from its argument list. No shell is ever
   involved, and no secret is placed in an argument.
3. Its standard output and standard error pass through a :class:`Masker`,
   which replaces each secret, and the usual encodings of it, with a
   placeholder that names the variable.

What that is worth, stated plainly
----------------------------------
Injection gives the child the secret. The child can send it anywhere, write it
to a file or hand it to programs of its own. Choose what you run.

Masking stops secrets from landing in logs and in model transcripts by
accident: a tool that echoes its configuration, a failed request printed with
its headers, ``env`` typed to debug something. It is a filter over two byte
streams, not a boundary. A program that deliberately transforms a secret
before printing it -- reverses it, splits it across lines, compresses or
encrypts it -- still leaks it, and so does anything the child writes somewhere
other than its standard output and error: a file, the terminal device, a
socket. Values shorter than four bytes are not masked at all.

The values are ordinary Python strings in this process for as long as the
command runs (the limit is documented in ``docs/THREAT_MODEL.md``). They are
never written to a file, a log line, an exception message or an argument list.
"""

from __future__ import annotations

import base64
import codecs
import heapq
import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import (
    IO,
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
)

from irondome.agent.refs import CONTROL_VARIABLES, is_reference
from irondome.errors import IronDomeError, UsageError

__all__ = [
    "MIN_MASK_BYTES",
    "MIN_LINE_BYTES",
    "MIN_ENCODED_BYTES",
    "CommandNotFoundError",
    "CommandNotExecutableError",
    "CommandTimeoutError",
    "CommandCancelledError",
    "RunResult",
    "Masker",
    "secret_patterns",
    "run_command",
    "run_captured",
    "locate_command",
]

#: Shorter values are not masked: replacing them would shred ordinary output.
MIN_MASK_BYTES = 4
#: From this length on, the encodings of a value are masked as well.
MIN_ENCODED_BYTES = 8

_PLACEHOLDER = "[irondome:{name}]"
_READ_SIZE = 65536
#: Seconds a command gets between being asked to stop and being killed.
_TERMINATE_GRACE = 3.0
#: Once the command has exited, how long its output pipes may stay silent, and
#: how much they may still deliver, before a process it left behind is taken
#: to be holding them.
_DRAIN_GRACE = 1.0
_DRAIN_BYTES = 8 * 1024 * 1024
#: The longest single wait for the command. It is never one unbounded wait: a signal that arrives in the
#: instant between Python's last check for signals and the start of a blocking wait is noted but interrupts
#: nothing, and would sit unhandled until the command ended by itself. A wait with a time limit comes back
#: to Python at least every 50 ms (subprocess polls), where the signal is then acted on.
_WAIT_SLICE = 1.0
_STDOUT = 1
_STDERR = 2
#: Windows cannot wait on a pipe; there the reader threads block instead.
_SELECTABLE_PIPES = os.name != "nt"


class CommandNotFoundError(UsageError):
    """The command to run does not exist. Exit status 127, as a shell reports it."""

    exit_code = 127


class CommandNotExecutableError(UsageError):
    """The command exists but could not be started. Exit status 126, as a shell reports it."""

    exit_code = 126


class CommandTimeoutError(IronDomeError):
    """The command outlived its time limit and was stopped. Exit status 124, as ``timeout(1)`` reports it.

    When :func:`run_captured` raises it, ``result`` holds the masked output
    the command produced before it was stopped.
    """

    exit_code = 124

    def __init__(self, message: str, result: Optional["RunResult"] = None) -> None:
        super().__init__(message)
        self.result = result


class CommandCancelledError(IronDomeError):
    """The caller cancelled the command while it ran; it was stopped with everything it started."""

    exit_code = 130


#: How often a cancellable wait looks at its caller's cancel flag, in seconds.
_CANCEL_POLL = 0.1


@dataclass(frozen=True)
class RunResult:
    """What :func:`run_captured` hands back. The text is masked."""

    code: int
    stdout: str
    stderr: str
    truncated: bool


# ---------------------------------------------------------------------------
# What a secret looks like in a stream
# ---------------------------------------------------------------------------

#: From this length on, each line of a value of several lines is masked by itself as well.
MIN_LINE_BYTES = 20

_UNRESERVED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_COMPONENT = _UNRESERVED | frozenset(b"!*'()")
#: What the common percent-encoders leave alone: RFC 3986's unreserved set (Python's ``quote(value, safe="")``),
#: JavaScript's ``encodeURIComponent``, Python's ``quote`` as called without arguments, JavaScript's ``encodeURI``.
_PERCENT_KEEPS = (
    _UNRESERVED,
    _COMPONENT,
    _UNRESERVED | frozenset(b"/"),
    _COMPONENT | frozenset(b";,/?:@&=+$#"),
)
#: What HTML form encoding leaves alone where it differs from the above: ``*`` is kept and ``~`` is escaped
#: (``URLSearchParams``, Java's ``URLEncoder``, PHP's ``urlencode``), with a space written as ``+``.
_FORM_KEEP = (_UNRESERVED - frozenset(b"~")) | frozenset(b"*")


def _percent(raw: bytes, keep: FrozenSet[int], space: bytes, *, lower: bool = False) -> bytes:
    escape = b"%%%02x" if lower else b"%%%02X"
    return b"".join(space if byte == 0x20 else bytes((byte,)) if byte in keep else escape % byte for byte in raw)


def _percent_forms(raw: bytes) -> List[bytes]:
    """*raw* as the common percent-encoders write it, with upper- and lower-case escapes."""
    forms = []
    for lower in (False, True):
        for keep in _PERCENT_KEEPS:
            forms.append(_percent(raw, keep, b"%20", lower=lower))
        forms.append(_percent(raw, _UNRESERVED, b"+", lower=lower))
        forms.append(_percent(raw, _FORM_KEEP, b"+", lower=lower))
    return forms


def _html_forms(value: str) -> List[bytes]:
    """*value* as HTML and XML escape text: ``&``, ``<`` and ``>`` always, and the quotes left alone or
    written as the libraries in common use write them (``&quot;`` or ``&#34;``; ``&#x27;``, ``&#39;``,
    ``&#039;`` or ``&apos;``)."""
    body = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    forms = [body]
    for double in ("&quot;", "&#34;"):
        quoted = body.replace('"', double)
        forms.append(quoted)
        forms += [quoted.replace("'", single) for single in ("&#x27;", "&#39;", "&#039;", "&apos;")]
    return [text.encode("utf-8") for text in forms]


def _is_secret_line(line: bytes) -> bool:
    """Whether one line of a value of several lines is masked by itself.

    Long enough to be told apart, and one unbroken token: the lines of a private key or a certificate are,
    and a line with spaces in it (``"type": "service_account",``, ``- name: admin``) is ordinary text that
    other output holds too. The lines that open and close a PEM block say what the block is and are the same
    in every key: masking them would blank them in output that has nothing to do with this value.
    """
    if len(line) < MIN_LINE_BYTES or line.startswith(b"-----") or line.endswith(b"-----"):
        return False
    return not any(byte in b" \t" for byte in line)


def _embedded_base64(raw: bytes, altchars: Optional[bytes]) -> List[bytes]:
    """What *raw* looks like inside the base64 encoding of a longer value.

    Base64 turns three bytes into four characters, so the same bytes encode
    differently depending on whether zero, one or two bytes precede them in
    their group of three. For each of the three cases this returns the
    characters that are determined by *raw* alone. The one character at each
    edge that also depends on a neighbouring byte is left out; it carries at
    most four bits of *raw*.
    """
    cores = []
    for lead in range(3):
        padded = bytes(lead) + raw
        padded += bytes(-len(padded) % 3)
        encoded = base64.b64encode(padded, altchars)
        cores.append(encoded[-(-8 * lead // 6) : 8 * (lead + len(raw)) // 6])
    return cores


def secret_patterns(value: str) -> List[Tuple[str, bytes]]:
    """Every byte string that gives *value* away in a stream, as ``(encoding, bytes)``.

    This is the list :class:`Masker` works from; a leak scanner can use the
    same one. The first item is always ``("plain", value as UTF-8)``. For a
    value of :data:`MIN_ENCODED_BYTES` or more it is followed by:

    ``base64`` / ``base64url``
        the standard and the URL-safe alphabet, with and without ``=``
        padding; and, for each of the three byte alignments, the characters
        the value contributes when it is only part of what was encoded (the
        password inside HTTP Basic credentials, ``echo "$TOKEN" | base64``
        with its trailing newline);
    ``hex``
        lower and upper case;
    ``percent``
        RFC 3986 escaping of everything but letters, digits and ``-._~``; the
        same with a space written as ``+`` (HTML forms); and the variants
        that also leave alone ``!*'()`` (JavaScript's ``encodeURIComponent``),
        ``/`` (Python's ``urllib.parse.quote`` as called without arguments)
        or the characters that structure a URL (JavaScript's ``encodeURI``);
        each with upper- and with lower-case hex digits;
    ``html``
        ``&``, ``<`` and ``>`` written as entities, with the quotes left
        alone or written ``&quot;`` and ``&#x27;``, ``&#39;`` or ``&apos;``;
    ``json``
        the body of the JSON string, as ``json.dumps`` and ``JSON.stringify``
        write it, with non-ASCII characters both literal and as ``\\uXXXX``;
        and the same escaped once more, as it is inside a JSON document that
        is itself carried as a string;
    ``shell``
        the value as a shell quotes it: between double quotes with a
        backslash before each backslash, double quote, ``$`` and backtick
        (``export -p``, ``declare -p``), and between single quotes with each
        ``'`` written ``'\\''`` or ``'"'"'`` (``set``, ``set -x``,
        ``shlex.quote``);
    ``repr``
        the value as a debugger prints a string: backslashes doubled and
        control characters escaped, with and without a backslash before
        ``'`` (Python's ``repr``, Node's ``console.log`` of an object, Perl's
        ``Data::Dumper``);
    ``line``
        for a value of several lines, each line of :data:`MIN_LINE_BYTES` or
        more by itself, without the white space around it: what is left of
        the value when a logger puts a time or a name in front of every line.
        Only a line that is one unbroken token counts (the body of a key or a
        certificate); a line with spaces in it, and the lines that open and
        close a PEM block, are ordinary text and are left alone.

    Duplicates are dropped: a value made only of letters and digits is its
    own percent, JSON, shell and repr form. A value shorter than
    :data:`MIN_MASK_BYTES` gives an empty list. Raises :class:`UsageError` if
    *value* is not text that can be encoded as UTF-8.
    """
    if not isinstance(value, str):
        raise UsageError("a secret value must be text")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError:
        raise UsageError("a secret value must be valid Unicode text") from None
    if len(raw) < MIN_MASK_BYTES:
        return []
    forms: List[Tuple[str, bytes]] = [("plain", raw)]
    if len(raw) >= MIN_ENCODED_BYTES:
        for label, altchars in (("base64", None), ("base64url", b"-_")):
            whole = base64.b64encode(raw, altchars)
            forms += [(label, whole), (label, whole.rstrip(b"="))]
            forms += [(label, core) for core in _embedded_base64(raw, altchars)]
        digits = raw.hex().encode("ascii")
        forms += [("hex", digits), ("hex", digits.upper())]
        forms += [("percent", form) for form in _percent_forms(raw)]
        forms += [("html", form) for form in _html_forms(value)]
        escaped = json.dumps(value, ensure_ascii=False)[1:-1]
        forms += [("json", escaped.encode("utf-8")), ("json", json.dumps(value)[1:-1].encode("ascii"))]
        # A JSON document carried as a string inside another one: every backslash and quote escaped once more.
        forms += [
            ("json", json.dumps(escaped, ensure_ascii=False)[1:-1].encode("utf-8")),
            ("json", json.dumps(json.dumps(value)[1:-1])[1:-1].encode("ascii")),
            ("json", json.dumps(escaped)[1:-1].encode("ascii")),  # literal inside, \\u escapes outside
        ]
        forms += [
            ("shell", "".join("\\" + char if char in '\\"$`' else char for char in value).encode("utf-8")),
            ("shell", value.replace("'", "'\\''").encode("utf-8")),
            ("shell", value.replace("'", "'\"'\"'").encode("utf-8")),
        ]
        # In a JSON string a double quote is always written as backslash-quote; a debugger leaves it alone.
        plain_quotes = escaped.replace('\\"', '"')
        forms += [("repr", plain_quotes.encode("utf-8")), ("repr", plain_quotes.replace("'", "\\'").encode("utf-8"))]
        # A value of several lines (a private key, a certificate) that a logger prints with something in
        # front of every line never appears whole: each line long enough to be told apart is a pattern too.
        lines = [line.strip() for line in raw.splitlines()]
        if len(lines) > 1:
            forms += [("line", line) for line in lines if _is_secret_line(line)]
    seen: Set[bytes] = set()
    unique: List[Tuple[str, bytes]] = []
    for label, pattern in forms:
        if pattern not in seen:
            seen.add(pattern)
            unique.append((label, pattern))
    return unique


class Masker:
    """A streaming filter that replaces secrets with placeholders.

    *secrets* maps a variable name to its value. :meth:`feed` takes the next
    chunk of a stream and returns everything that can already be written;
    :meth:`flush` ends the stream and returns the rest. Chunk boundaries do
    not matter: the concatenated output is the same however the stream was
    cut, and no part of a secret is written before it is known not to be one.

    What is replaced is every pattern :func:`secret_patterns` lists for every
    value, by ``placeholder`` with ``{name}`` filled in. When matches overlap,
    the longest one at the earliest position supplies the placeholder and
    every match overlapping it is removed with it, so no byte of any
    occurrence of any pattern reaches the output. If two variables produce
    the same pattern, a variable holding it as its exact value wins over one
    for which it is an encoding, then the first name in sorted order.

    Held back, and only while the end of the stream seen so far could still
    be the beginning of a pattern: at most the length of the longest pattern
    minus one byte. Everything else is returned at once.

    ``unmasked_names`` lists the variables whose values are too short to mask
    (fewer than :data:`MIN_MASK_BYTES` bytes); a caller should warn about them.

    Limits. This removes exact byte sequences. It prevents accidents, not
    intent: a program that reverses a secret, splits it across lines, wraps
    its base64 at 76 columns or uses an encoding or quoting style not listed
    by :func:`secret_patterns` prints something this filter does not
    recognise. Where a value is part of a longer base64 text, the one
    character at each edge of it that is shared with a neighbouring byte
    stays; it holds at most four bits of the value.

    One instance filters one stream and is not safe to share between threads.
    Cost per chunk is linear in its size times the number of patterns.
    """

    def __init__(self, secrets: Mapping[str, str], *, placeholder: str = _PLACEHOLDER) -> None:
        if not isinstance(placeholder, str):
            raise UsageError("the placeholder must be text; {name} in it stands for the variable's name")
        names = list(secrets)
        if not all(isinstance(name, str) for name in names):
            raise UsageError("the names of secrets must be text")
        self.unmasked_names: List[str] = []
        marked: List[Tuple[bytes, List[bytes]]] = []
        for name in sorted(names):
            try:
                forms = secret_patterns(secrets[name])
            except UsageError as exc:
                raise UsageError(f"{name}: {exc}") from None
            if not forms:
                self.unmasked_names.append(name)
                continue
            try:
                mark = placeholder.format(name=name).encode("utf-8")
            except (AttributeError, IndexError, KeyError, TypeError, ValueError):
                raise UsageError(
                    "the placeholder is malformed; write {name} where the variable's name goes"
                ) from None
            marked.append((mark, [pattern for _, pattern in forms]))
        marks: Dict[bytes, bytes] = {}
        for mark, patterns in marked:
            marks.setdefault(patterns[0], mark)
        for mark, patterns in marked:
            for pattern in patterns[1:]:
                marks.setdefault(pattern, mark)
        self._patterns: Tuple[bytes, ...] = tuple(marks)
        self._marks: Tuple[bytes, ...] = tuple(marks.values())
        self._heads: Tuple[bytes, ...] = tuple(pattern[:2] for pattern in self._patterns)
        self._first: FrozenSet[int] = frozenset(pattern[0] for pattern in self._patterns)
        #: Bytes not yet decided, and how many of them an emitted placeholder already covers.
        self._pending = b""
        self._covered = 0

    def feed(self, chunk: bytes) -> bytes:
        """Take the next *chunk* of the stream; return what can be written now."""
        data = self._pending + bytes(chunk)
        if not self._patterns or not data:
            return data
        return self._scan(data, self._hold(data))

    def flush(self) -> bytes:
        """End the stream: return what was held back. The filter is then ready for a new stream."""
        return self._scan(self._pending, len(self._pending))

    def __reduce__(self) -> Any:
        raise TypeError("a Masker holds secrets and cannot be pickled")

    def _hold(self, data: bytes) -> int:
        """Where the undecided tail of *data* starts.

        That is the earliest position from which the rest of *data* is the
        beginning of some pattern, but not all of it: whether a secret starts
        there depends on bytes that have not arrived.
        """
        size = len(data)
        hold = size
        for pattern, head in zip(self._patterns, self._heads):
            start = max(0, size - len(pattern) + 1)
            at = data.find(head, start, hold + 1)
            while at != -1:
                if pattern.startswith(data[at:]):
                    hold = at
                    break
                at = data.find(head, at + 1, hold + 1)
        if hold == size and data[-1] in self._first:
            hold = size - 1
        return hold

    def _scan(self, data: bytes, hold: int) -> bytes:
        """Mask *data* up to *hold*; keep the rest for the next call.

        ``done`` is the end of the last masked region: every byte before it
        has been written or removed. A match that starts at or after ``done``
        opens a new region and writes its placeholder; one that starts inside
        the region can only stretch it.
        """
        patterns = self._patterns
        done = self._covered
        pieces: List[bytes] = []
        matches: List[Tuple[int, int, int]] = []
        for index, pattern in enumerate(patterns):
            length = len(pattern)
            at = data.find(pattern, max(0, done - length + 1), hold + length - 1)
            if at != -1:
                matches.append((at, -length, index))
        heapq.heapify(matches)
        while matches:
            at, negative, index = matches[0]
            length = -negative
            pattern = patterns[index]
            if at >= done:
                pieces.append(data[done:at])
                pieces.append(self._marks[index])
                done = at + length
            elif at + length > done:
                done = at + length
            while True:
                # The same pattern again, starting inside the region and running past its end.
                again = data.rfind(pattern, max(0, done - length + 1), min(done, hold) + length - 1)
                if again == -1:
                    break
                done = again + length
            following = data.find(pattern, done, hold + length - 1)
            if following == -1:
                heapq.heappop(matches)
            else:
                heapq.heapreplace(matches, (following, negative, index))
        if done < hold:
            pieces.append(data[done:hold])
        self._pending = data[hold:]
        self._covered = max(0, done - hold)
        return b"".join(pieces)


# ---------------------------------------------------------------------------
# The child's environment and executable
# ---------------------------------------------------------------------------


def _key(name: str) -> str:
    """Environment variable names are case-insensitive on Windows."""
    return name.upper() if os.name == "nt" else name


def _unusable(name: object, value: object, *, secret: bool = False) -> Optional[str]:
    """Why a variable cannot be given to a process, or None if it can."""
    # Windows keeps per-drive working directories in variables whose names start with "=".
    if not isinstance(name, str) or not name or "\x00" in name or "=" in name[1 if os.name == "nt" else 0 :]:
        return "an environment variable needs a name, without '=' or NUL characters"
    if not isinstance(value, str):
        return f"the value of {name} is not text"
    if "\x00" in value:
        return f"the value of {name} contains a NUL character, which no environment variable can hold"
    try:
        os.fsencode(name)
        if secret:
            value.encode("utf-8")
        else:
            os.fsencode(value)
    except UnicodeEncodeError:
        return f"the name or value of {name} is not valid Unicode text"
    return None


def _settable(name: str, value: str, *, secret: bool = False) -> str:
    """Check a variable the caller asked for; return the key it is stored under."""
    problem = _unusable(name, value, secret=secret)
    if problem is not None:
        raise UsageError(problem)
    if _key(name) in CONTROL_VARIABLES:
        raise UsageError(f"{name} is reserved by IronDome and is never passed to a command")
    return _key(name)


def _environment(
    injected: Mapping[str, str], literals: Optional[Mapping[str, str]], base_env: Optional[Mapping[str, str]]
) -> Dict[str, str]:
    """The environment the child gets. See the module docstring for the rules.

    Variables asked for by the caller are checked and refused with an error.
    Inherited ones that no process could be given are left out silently.
    """
    environment: Dict[str, str] = {}
    for name, value in (os.environ if base_env is None else base_env).items():
        if _unusable(name, value) is None and _key(name) not in CONTROL_VARIABLES and not is_reference(value):
            environment[_key(name)] = value
    for name, value in (literals or {}).items():
        key = _settable(name, value)
        if is_reference(value):
            raise UsageError(f"{name} still holds an irondome:// reference; resolve it before the command runs")
        environment[key] = value
    for name, value in injected.items():
        environment[_settable(name, value, secret=True)] = value
    return environment


def locate_command(command: str, environment: Mapping[str, str], cwd: Optional[str]) -> str:
    """The absolute path of the program a shell would start for *command* in *cwd*.

    Raises :class:`CommandNotFoundError` or :class:`CommandNotExecutableError`. Callers use it to
    refuse a command before they spend anything on it (a grant use, a Touch ID prompt).
    """
    try:
        base = os.path.abspath(cwd) if cwd is not None else os.getcwd()
    except OSError:
        raise UsageError("the current directory no longer exists; give a working directory") from None
    if os.sep in command or (os.altsep is not None and os.altsep in command):
        candidate = os.path.join(base, command)
        found = shutil.which(candidate)
        if found is None and os.path.exists(candidate):
            raise CommandNotExecutableError(f"{command} is not an executable file")
    else:
        search = environment.get("PATH", os.defpath)
        directories = [os.path.join(base, entry or os.curdir) for entry in search.split(os.pathsep)]
        found = shutil.which(command, path=os.pathsep.join(directories))
    if found is None:
        raise CommandNotFoundError(f"command not found: {command}")
    return found


def _arguments(argv: Sequence[str]) -> List[str]:
    if isinstance(argv, (str, bytes)) or not argv:
        raise UsageError("there is no command to run")
    arguments = list(argv)
    if not all(isinstance(argument, str) and "\x00" not in argument for argument in arguments) or not arguments[0]:
        raise UsageError("a command and its arguments must be text without NUL characters")
    try:
        for argument in arguments:
            os.fsencode(argument)
    except UnicodeEncodeError:
        raise UsageError("a command and its arguments must be valid Unicode text") from None
    return arguments


def _directory(cwd: Any) -> Optional[str]:
    if cwd is None:
        return None
    try:
        path = os.fsdecode(cwd)
    except TypeError:
        raise UsageError("the working directory must be a path") from None
    if not os.path.isdir(path):
        raise UsageError(f"the working directory {path!r} does not exist")
    return path


def _limit(timeout: Any) -> Optional[float]:
    if timeout is None:
        return None
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout < float("inf"):
        raise UsageError("the time limit must be a positive number of seconds")
    return float(timeout)


# ---------------------------------------------------------------------------
# Carrying the child's streams
# ---------------------------------------------------------------------------


class _Sink(Protocol):
    """Where one stream of the child's output goes."""

    def consume(self, chunk: bytes) -> bool:
        """Take a chunk. False means nothing more is wanted from this stream."""

    def finish(self) -> None:
        """The stream has ended."""


def _write_all(descriptor: int, data: bytes) -> bool:
    """Write all of *data* to *descriptor*. False once the destination is gone."""
    view = memoryview(data)
    while view:
        try:
            view = view[os.write(descriptor, view) :]
        except BlockingIOError:
            with selectors.SelectSelector() as selector:
                selector.register(descriptor, selectors.EVENT_WRITE)
                selector.select(1.0)
        except OSError:
            return False
    return True


class _Forward:
    """Mask a stream and write it to one of this process's own descriptors."""

    def __init__(self, masker: Masker, descriptor: int) -> None:
        self._masker = masker
        self._descriptor = descriptor

    def consume(self, chunk: bytes) -> bool:
        return _write_all(self._descriptor, self._masker.feed(chunk))

    def finish(self) -> None:
        _write_all(self._descriptor, self._masker.flush())


class _Capture:
    """Mask a stream and keep the first *limit* bytes of the result."""

    def __init__(self, masker: Masker, limit: int) -> None:
        self._masker = masker
        self._limit = limit
        self._kept = bytearray()
        self.truncated = False

    def _keep(self, data: bytes) -> None:
        room = self._limit - len(self._kept)
        self._kept += data[:room]
        self.truncated = len(data) > room

    def consume(self, chunk: bytes) -> bool:
        if not self.truncated:
            self._keep(self._masker.feed(chunk))
        return True  # past the limit the child is still read, so that it never blocks on a full pipe

    def finish(self) -> None:
        if not self.truncated:
            self._keep(self._masker.flush())

    def text(self) -> str:
        """The kept bytes as text. A character cut in half by the limit is dropped, not garbled."""
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        return decoder.decode(bytes(self._kept), final=not self.truncated)


class _Pump(threading.Thread):
    """Copy one of the child's output pipes into a sink until the pipe ends.

    The pipe ends when every process holding its other end has closed it. A
    command can leave such a process behind (a daemon it started); once
    *wake* becomes readable -- the command itself has exited -- the pump
    therefore stops as soon as the pipe has been silent for ``_DRAIN_GRACE``
    seconds in total or has delivered ``_DRAIN_BYTES`` more.
    """

    def __init__(self, source: IO[bytes], sink: _Sink, wake: int) -> None:
        super().__init__(daemon=True)
        self._source = source
        self._sink = sink
        self._wake = wake
        self.error: Optional[Exception] = None
        #: Since when a blocking read has been waiting (only where pipes cannot be selected).
        self.waiting_since: Optional[float] = None

    def run(self) -> None:
        try:
            for chunk in self._chunks():
                if not self._sink.consume(chunk):
                    break
            else:
                self._sink.finish()
        except Exception as exc:
            self.error = exc
        finally:
            try:
                self._source.close()
            except OSError:
                pass

    def _chunks(self) -> Iterator[bytes]:
        descriptor = self._source.fileno()
        if not _SELECTABLE_PIPES:
            while True:
                self.waiting_since = time.monotonic()
                data = os.read(descriptor, _READ_SIZE)
                self.waiting_since = None
                if not data:
                    return
                yield data
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            selector.register(self._wake, selectors.EVENT_READ)
            grace: Optional[float] = None  # None while the command is running
            drained = 0
            while True:
                began = time.monotonic()
                ready = selector.select(grace)
                if grace is not None:
                    grace -= time.monotonic() - began
                    if not ready:
                        return
                for key, _ in ready:
                    if key.fd == self._wake:
                        selector.unregister(self._wake)
                        grace = _DRAIN_GRACE
                        continue
                    data = os.read(descriptor, _READ_SIZE)
                    if not data:
                        return
                    yield data
                    if grace is not None:
                        drained += len(data)
                        if drained > _DRAIN_BYTES:
                            return


def _feed(sink: IO[bytes], data: bytes, wake: int) -> None:
    """Write *data* to the child's standard input, then close it.

    Stops without an error when the child closes its end or exits first.
    """
    try:
        descriptor = sink.fileno()
        view = memoryview(data)
        if not _SELECTABLE_PIPES:
            while view:
                view = view[os.write(descriptor, view) :]
            return
        os.set_blocking(descriptor, False)
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_WRITE)
            selector.register(wake, selectors.EVENT_READ)
            while view:
                if any(key.fd == wake for key, _ in selector.select()):
                    return
                try:
                    view = view[os.write(descriptor, view[:_READ_SIZE]) :]
                except BlockingIOError:
                    continue
    except OSError:
        pass
    finally:
        try:
            sink.close()
        except OSError:
            pass


def _block_ending_signals() -> Optional[Any]:
    """Block SIGINT, SIGTERM, SIGHUP and SIGQUIT in this thread; return the mask to put back, or None."""
    if not hasattr(signal, "pthread_sigmask"):
        return None  # Windows: no thread signal masks, and no signals delivered to threads this way
    ending = {getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT") if hasattr(signal, name)}
    return signal.pthread_sigmask(signal.SIG_BLOCK, ending)


def _pipe(stream: Optional[IO[bytes]]) -> IO[bytes]:
    if stream is None:
        raise IronDomeError("the command was started without the pipe IronDome asked for")
    return stream


class _Plumbing:
    """The threads that carry a child's standard streams, and how they are told it has exited."""

    def __init__(self) -> None:
        # Closing the write end makes the read end readable in every thread that watches it.
        self._wake_read, self._wake_write = os.pipe()
        self._pumps: List[_Pump] = []
        self._feeder: Optional[threading.Thread] = None

    def start(
        self, process: "subprocess.Popen[bytes]", sinks: Optional[Tuple[_Sink, _Sink]], feed: Optional[bytes]
    ) -> None:
        # A thread starts with the signal mask of the thread that starts it. These threads start with the
        # signals that end a program blocked, so the system can only hand such a signal to the main thread,
        # which is waiting for the command: the wait is interrupted and the signal is acted on at once. Handed
        # to one of these threads instead, it would be noted and then sit there until the command ended by
        # itself. A signal that arrives in between stays pending and is delivered when the mask is put back.
        blocked = _block_ending_signals()
        try:
            if sinks is not None:
                for stream, sink in zip((process.stdout, process.stderr), sinks):
                    pump = _Pump(_pipe(stream), sink, self._wake_read)
                    pump.start()
                    self._pumps.append(pump)
            if feed is not None:
                feeder = threading.Thread(
                    target=_feed, args=(_pipe(process.stdin), feed, self._wake_read), daemon=True
                )
                feeder.start()
                self._feeder = feeder
        finally:
            if blocked is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, blocked)

    def finish(self) -> None:
        """The command has exited: let every thread drain what is left and stop."""
        self._signal_exit()
        exited = time.monotonic()
        for pump in self._pumps:
            if _SELECTABLE_PIPES:
                pump.join()
                continue
            while pump.is_alive():
                pump.join(0.05)
                waiting = pump.waiting_since
                if waiting is not None and time.monotonic() - max(waiting, exited) >= _DRAIN_GRACE:
                    break  # still blocked in a read: something the command left behind holds the pipe
        if self._feeder is not None:
            self._feeder.join(None if _SELECTABLE_PIPES else _DRAIN_GRACE)

    def check(self) -> None:
        """Raise what went wrong in a pump, if anything did."""
        for pump in self._pumps:
            if pump.error is not None:
                raise pump.error

    def _signal_exit(self) -> None:
        if self._wake_write != -1:
            os.close(self._wake_write)
            self._wake_write = -1

    def close(self) -> None:
        self._signal_exit()
        if self._wake_read != -1:
            os.close(self._wake_read)
            self._wake_read = -1


# ---------------------------------------------------------------------------
# Starting, signalling and stopping the child
# ---------------------------------------------------------------------------


def _spawn(
    arguments: List[str],
    program: str,
    environment: Dict[str, str],
    cwd: Optional[str],
    *,
    feed: Optional[bytes],
    piped: bool,
    detached: bool,
) -> "subprocess.Popen[bytes]":
    options: Dict[str, Any] = {}
    if detached:
        options["stdin"] = subprocess.DEVNULL if feed is None else subprocess.PIPE
        if os.name != "nt":
            options["start_new_session"] = True
    if piped:
        options["stdout"] = options["stderr"] = subprocess.PIPE
    try:
        return subprocess.Popen(arguments, executable=program, env=environment, cwd=cwd, bufsize=0, **options)
    except OSError as exc:
        reason = exc.strerror or "the operating system refused"
        raise CommandNotExecutableError(f"could not start {arguments[0]}: {reason}") from None


def _send(process: "subprocess.Popen[bytes]", signum: int) -> None:
    try:
        process.send_signal(signum)
    except (OSError, ValueError):
        pass  # already gone, or a signal this platform cannot deliver


def _kill(process: "subprocess.Popen[bytes]", *, group: bool) -> None:
    try:
        if group and os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except OSError:
        pass  # already gone


def _descendants(pid: int) -> List[int]:
    """Every process that descends from *pid* right now, nearest first. Empty where that cannot be read.

    Read from the process table: ``/proc`` on Linux, ``/bin/ps`` elsewhere. A
    process whose parent has already exited has been handed to init and is
    no longer a descendant of anything here: one that made itself a daemon
    is not found.
    """
    parents: Dict[int, int] = {}
    try:
        if os.path.isdir("/proc/self"):
            for name in os.listdir("/proc"):
                if not name.isdigit():
                    continue
                try:
                    with open(f"/proc/{name}/stat", "rb") as status:
                        fields = status.read().rsplit(b")", 1)[-1].split()  # the name may hold spaces and brackets
                    parents[int(name)] = int(fields[1])
                except (OSError, ValueError, IndexError):
                    continue  # gone since it was listed
        elif os.name != "nt":
            listed = subprocess.run(
                ["/bin/ps", "-axo", "pid=,ppid="], stdin=subprocess.DEVNULL, capture_output=True, timeout=3,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, check=False,
            )
            for line in listed.stdout.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    parents[int(parts[0])] = int(parts[1])
    except (OSError, subprocess.SubprocessError):
        return []
    found: List[int] = []
    wave = [pid]
    while wave:
        wave = [child for child, parent in parents.items() if parent in wave and child not in found and child != pid]
        found.extend(wave)
    return found


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _signal_each(pids: Sequence[int], signum: int) -> None:
    for pid in pids:
        try:
            os.kill(pid, signum)
        except OSError:
            pass  # already gone, or no longer ours to signal


def _stop(process: "subprocess.Popen[bytes]", *, group: bool) -> None:
    """Stop the child and what it started: ask, give ``_TERMINATE_GRACE`` seconds, then kill.

    With *group* the child leads a process group of its own and the whole
    group is signalled. Either way the processes that descend from the child
    are found first, while it is still their ancestor, and are signalled
    too: a program the command left in the background, or put in a session
    of its own, holds the same injected values and must not be left running
    by a time limit. A process that detached itself completely (its parent
    exited: a daemon) is not found, and is not stopped.
    """
    others = _descendants(process.pid) if os.name != "nt" else []
    try:
        if group and os.name != "nt":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except OSError:
        pass  # already gone
    _signal_each(others, signal.SIGTERM)
    deadline = time.monotonic() + _TERMINATE_GRACE
    try:
        process.wait(_TERMINATE_GRACE)
    except subprocess.TimeoutExpired:
        pass
    # The grace is for all of them: a command that stops at once must not cost its children theirs.
    while others and time.monotonic() < deadline and any(_alive(pid) for pid in others):
        time.sleep(0.05)
    _kill(process, group=group)
    if others:
        _signal_each(others, signal.SIGKILL)
    process.wait()


def _wait(
    process: "subprocess.Popen[bytes]", limit: Optional[float], cancelled: Optional[Callable[[], bool]] = None
) -> int:
    """Wait for the child to exit.

    Raises ``subprocess.TimeoutExpired`` after *limit* seconds, and
    :class:`CommandCancelledError` as soon as *cancelled* returns true.
    """
    deadline = None if limit is None else time.monotonic() + limit
    slice_ = _WAIT_SLICE if cancelled is None else _CANCEL_POLL
    while True:
        if cancelled is not None and cancelled():
            raise CommandCancelledError("the command was cancelled and has been stopped")
        remaining = None if deadline is None else deadline - time.monotonic()
        try:
            return process.wait(slice_ if remaining is None else max(0.0, min(remaining, slice_)))
        except subprocess.TimeoutExpired:
            if remaining is not None and remaining <= slice_:
                raise


def _keyboard_reaches_child() -> bool:
    """True when the terminal delivers a keyboard interrupt to the child itself.

    Ctrl-C is sent to every process in the terminal's foreground group. The
    child stays in this process's group, so when that group is in the
    foreground the child has already received the signal and must not be sent
    it a second time (many programs treat a second interrupt as "abort now").
    """
    if os.name == "nt":
        return True
    try:
        terminal = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY)
    except OSError:
        return False
    try:
        return os.tcgetpgrp(terminal) == os.getpgrp()
    except OSError:
        return False
    finally:
        os.close(terminal)


class _Relay:
    """What the signals that end a program do to this process while a command runs.

    ``cancel=False`` (:func:`run_command`): SIGINT, SIGTERM and SIGHUP are
    passed on to the command and this process keeps waiting, so the command
    decides how to end and its exit status is still reported.

    ``cancel=True`` (:func:`run_captured`): on SIGINT, SIGTERM, SIGHUP or
    SIGQUIT the command's process group is killed, then the handler that was
    in place before is restored and takes its course, so a host that is being
    shut down does not leave the command behind.

    Handlers can only be installed from the main thread; elsewhere this does
    nothing. A signal that was being ignored stays ignored.
    """

    def __init__(self, *, cancel: bool) -> None:
        self._cancel = cancel
        self._process: Optional["subprocess.Popen[bytes]"] = None
        self._early: List[int] = []
        self._previous: Dict[int, Any] = {}

    def __enter__(self) -> "_Relay":
        if threading.current_thread() is threading.main_thread():
            names = ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT") if self._cancel else ("SIGINT", "SIGTERM", "SIGHUP")
            for name in names:
                signum = getattr(signal, name, None)  # Windows has neither SIGHUP nor SIGQUIT
                previous = None if signum is None else signal.getsignal(signum)
                if signum is not None and previous is not None and previous != signal.SIG_IGN:
                    signal.signal(signum, self._handle)
                    self._previous[signum] = previous
        return self

    def __exit__(self, *exc: object) -> None:
        self._restore()

    def _restore(self) -> None:
        while self._previous:
            signum, previous = self._previous.popitem()
            signal.signal(signum, previous)

    def attach(self, process: "subprocess.Popen[bytes]") -> None:
        """Name the child. Signals that arrived before it existed are acted on now."""
        self._process = process
        while self._early:
            self._handle(self._early.pop(0), None, early=True)

    def _handle(self, signum: int, frame: Any, early: bool = False) -> None:
        process = self._process
        if process is None:
            self._early.append(signum)
        elif self._cancel:
            previous = self._previous.get(signum)
            _kill(process, group=True)
            self._restore()
            if callable(previous):
                previous(signum, frame)
            else:
                os.kill(os.getpid(), signum)
        elif early or signum != signal.SIGINT or not _keyboard_reaches_child():
            _send(process, signum)


def _execute(
    arguments: List[str],
    program: str,
    environment: Dict[str, str],
    cwd: Optional[str],
    limit: Optional[float],
    *,
    sinks: Optional[Tuple[_Sink, _Sink]],
    feed: Optional[bytes],
    detached: bool,
    cancelled: Optional[Callable[[], bool]] = None,
) -> int:
    """Start the child, carry its streams, wait for it; return its exit status."""
    plumbing = _Plumbing()
    try:
        with _Relay(cancel=detached) as relay:
            process = _spawn(
                arguments, program, environment, cwd, feed=feed, piped=sinks is not None, detached=detached
            )
            try:
                relay.attach(process)
                plumbing.start(process, sinks, feed)
                try:
                    status = _wait(process, limit, cancelled)
                except subprocess.TimeoutExpired:
                    raise CommandTimeoutError(
                        f"{arguments[0]} was still running after {limit:g} seconds and was stopped"
                    ) from None
            except BaseException:
                _stop(process, group=detached)
                plumbing.finish()
                raise
            plumbing.finish()
    finally:
        plumbing.close()
    plumbing.check()
    return 128 - status if status < 0 else status


def _given_program(executable: Any) -> str:
    """*executable*, a program the caller already located (and may have shown someone): it is started as it is.

    It must be an absolute path to an executable regular file (links are followed, as exec follows them);
    nothing is searched for, so what starts is exactly what the caller named.
    """
    if not isinstance(executable, str) or not executable or "\x00" in executable or not os.path.isabs(executable):
        raise UsageError("the program to start must be named by an absolute path")
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        if not os.path.exists(executable):
            raise CommandNotFoundError(f"command not found: {executable}")
        raise CommandNotExecutableError(f"{executable} is not an executable file")
    return executable


def _prepare(
    argv: Sequence[str],
    injected: Mapping[str, str],
    literals: Optional[Mapping[str, str]],
    base_env: Optional[Mapping[str, str]],
    cwd: Any,
    timeout: Any,
    executable: Optional[str] = None,
) -> Tuple[List[str], str, Dict[str, str], Optional[str], Optional[float]]:
    arguments = _arguments(argv)
    limit = _limit(timeout)
    directory = _directory(cwd)
    environment = _environment(injected, literals, base_env)
    if executable is not None:
        return arguments, _given_program(executable), environment, directory, limit
    return arguments, locate_command(arguments[0], environment, directory), environment, directory, limit


# ---------------------------------------------------------------------------
# The two ways to run a command
# ---------------------------------------------------------------------------


def run_command(
    argv: List[str],
    injected: Mapping[str, str],
    *,
    literals: Optional[Mapping[str, str]] = None,
    mask: bool = True,
    cwd: Optional[str] = None,
    base_env: Optional[Mapping[str, str]] = None,
    timeout: Optional[float] = None,
    executable: Optional[str] = None,
) -> int:
    """Run *argv* with the secrets *injected* in its environment; return its exit status.

    *injected* maps variable names to secret values (what
    ``agent.refs.resolve_plan`` returns); *literals* are plain variables to
    set as well, which are not masked. Both are laid over *base_env* (this
    process's environment by default) under the rules in the module
    docstring. The program is looked up on the child's ``PATH``, relative to
    *cwd*, and started without a shell. With *executable* (an absolute path
    to an executable file, typically what :func:`locate_command` found
    earlier) nothing is looked up: that file is started, and ``argv[0]`` is
    still what the child sees as its name.

    ``mask=True``: the child's standard output and error are pipes, copied as
    they arrive through a :class:`Masker` each to this process's descriptors 1
    and 2. Standard input is inherited. Because its output is a pipe the
    child sees no terminal there, and a process it leaves running in the
    background loses its output a second after the command exits.

    ``mask=False``: the child inherits all three streams untouched. Use it for
    interactive programs; nothing is masked.

    The result is the child's exit status, or 128 plus the signal number if a
    signal ended it. SIGINT, SIGTERM and SIGHUP sent to this process are
    passed on to the child (when called from the main thread; a signal that
    was being ignored stays ignored). The child stays in this process's
    process group, so a keyboard interrupt in a terminal has already reached
    it and is not sent a second time.

    Raises :class:`CommandNotFoundError` (exit status 127) or
    :class:`CommandNotExecutableError` (126) if the command cannot be started,
    :class:`UsageError` for an unusable argument, variable or directory, and
    :class:`CommandTimeoutError` (124) after stopping the child -- SIGTERM,
    then SIGKILL -- when *timeout* seconds have passed. The processes that
    descend from the command are stopped with it; one that made itself a
    daemon is not found and may outlive it.
    """
    arguments, program, environment, directory, limit = _prepare(
        argv, injected, literals, base_env, cwd, timeout, executable
    )
    sinks: Optional[Tuple[_Sink, _Sink]] = None
    if mask:
        sinks = (_Forward(Masker(injected), _STDOUT), _Forward(Masker(injected), _STDERR))
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (AttributeError, OSError, ValueError):
            pass  # closed or absent; there is nothing buffered to keep in order
    return _execute(arguments, program, environment, directory, limit, sinks=sinks, feed=None, detached=False)


def run_captured(
    argv: List[str],
    injected: Mapping[str, str],
    *,
    literals: Optional[Mapping[str, str]] = None,
    cwd: Optional[str] = None,
    base_env: Optional[Mapping[str, str]] = None,
    timeout: Optional[float] = 60.0,
    max_bytes: int = 200_000,
    stdin: Optional[bytes] = None,
    cancelled: Optional[Callable[[], bool]] = None,
    executable: Optional[str] = None,
) -> RunResult:
    """Run *argv* like :func:`run_command` and return its masked output instead of printing it.

    The environment rules are the same, and so is *executable*. Output is always masked, then cut to
    the first *max_bytes* bytes of each stream (``truncated`` says whether
    either was cut; the child is read to the end regardless) and decoded as
    UTF-8, with undecodable bytes replaced.

    The child never reads this process's standard input: it gets *stdin* if
    given and an empty input otherwise. It runs in a session of its own, with
    no controlling terminal, so on *timeout* the command and everything it
    started are stopped together.

    Raises what :func:`run_command` raises. A :class:`CommandTimeoutError`
    carries the output produced so far in its ``result``. If this process
    receives SIGINT, SIGTERM, SIGHUP or SIGQUIT meanwhile (when called from
    the main thread), the command is killed before the signal takes its usual
    effect, so a host that is shut down in the middle of a call leaves
    nothing running. SIGKILL cannot be caught: then the command runs on.

    *cancelled*, when given, is asked about ten times a second while the
    command runs; once it returns true the command and everything it started
    are stopped and :class:`CommandCancelledError` is raised.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise UsageError("the output limit must be a whole number of bytes, zero or more")
    if stdin is not None and not isinstance(stdin, (bytes, bytearray, memoryview)):
        raise UsageError("standard input for the command must be bytes")
    arguments, program, environment, directory, limit = _prepare(
        argv, injected, literals, base_env, cwd, timeout, executable
    )
    out = _Capture(Masker(injected), max_bytes)
    err = _Capture(Masker(injected), max_bytes)
    feed = None if stdin is None else bytes(stdin)
    try:
        status = _execute(
            arguments, program, environment, directory, limit, sinks=(out, err), feed=feed, detached=True,
            cancelled=cancelled,
        )
    except CommandTimeoutError as exc:
        exc.result = RunResult(exc.exit_code, out.text(), err.text(), out.truncated or err.truncated)
        raise
    return RunResult(status, out.text(), err.text(), out.truncated or err.truncated)
