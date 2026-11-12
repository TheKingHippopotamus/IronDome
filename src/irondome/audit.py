"""The audit log: a record of every use of a session or grant and every change.

``audit.log`` sits beside the vault, one JSON object per line (written with
its keys in alphabetical order and no spaces)::

    {"seq": 7, "ts": 1794430000, "prev": "<sha256 of line 6>", "kid": "vault", "data": "<sealed>"}

``data`` holds the record -- action, actor, target, detail, ok -- padded to a
multiple of 256 bytes and sealed with AES-256-GCM. The file therefore shows
how many records exist, when each was written, which key wrote it and its
size in steps of 256 bytes. It shows no entry name, alias or command.

Keys::

    owner key      = HKDF(vault key, "irondome/v4/audit", salt = vault id)
    grant key (id) = HKDF(owner key, "irondome/v4/audit/grant\\0" + grant id)
    sealing key    = HKDF(owner key or grant key, "irondome/v4/audit/record")

``kid`` names the key a line was sealed under: ``"vault"`` for the owner key,
otherwise a grant id. A grant carries its own grant key, from which neither
the owner key nor another grant's key can be derived, so a grant holder can
append records about itself and cannot write a line that passes as the owner's
or as another grant's. ``kid`` is the only authenticated statement of who
wrote a line; ``actor`` is whatever the writer put there.

The associated data of every line binds the vault id, ``seq``, ``ts``, ``kid``
and ``prev``, and :func:`verify` requires each line to be byte for byte what
those values serialise to, so nothing in a line can change without its key.

What :func:`verify` detects: an edited line; a line that was not sealed with a
key of this vault; lines removed from the beginning or the middle; reordered,
repeated or inserted lines; a final line that was cut short.

What it cannot detect: removal of the newest lines, up to and including the
whole file. Nothing outside the log records how long it should be. A grant
holder can write as many records under its own ``kid`` as it likes, true or
not, for as long as it can write to the file, and so can replace the newest
lines with lines of its own. And the log records what went through IronDome:
a process that decrypts a grant file itself, with a token it holds, leaves no
line here.

The owner key comes from the vault key, so a vault that is given a new vault
key can no longer check the lines written before: :func:`archive` the log
first.

:func:`record` either appends one complete line or raises :class:`AuditError`
and leaves the file as it was. Callers decide what a failure means for them:
:mod:`irondome.caps` refuses to create or use a capability it cannot record,
and the command line reports a warning after a vault change that has already
been committed.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import sys
import time
from collections import deque
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Deque, Dict, Iterator, List, Optional, Tuple, Union

from irondome import paths
from irondome.crypto import KEY_LEN, NONCE_LEN, TAG_LEN, DecryptError, b64d, b64e, hkdf, open_sealed, pad, seal, unpad
from irondome.errors import IronDomeError, UsageError, VaultError
from irondome.keys import VAULT_ID_LEN
from irondome.secmem import BufferLike, SecureBuffer, as_view, wipe_bytes

if TYPE_CHECKING:
    from irondome.vault import Vault

__all__ = [
    "KID_VAULT",
    "AuditError",
    "AuditEvent",
    "AuditReport",
    "owner_key",
    "grant_key",
    "record",
    "read",
    "verify",
    "archive",
    "strict_loads",
]

#: The ``kid`` of lines sealed under the owner key.
KID_VAULT = "vault"

_LABEL_OWNER = b"irondome/v4/audit"
_LABEL_GRANT = b"irondome/v4/audit/grant\x00"
_LABEL_RECORD = b"irondome/v4/audit/record"
_LABEL_AAD = b"irondome/v4/audit\x00"

_GRANT_ID = re.compile(r"[0-9a-f]{32}")
_PREV = re.compile(r"(?:[0-9a-f]{64})?")
_LINE_KEYS = frozenset(("seq", "ts", "prev", "kid", "data"))
_RECORD_KEYS = ("action", "actor", "target", "detail", "ok")

_PAD_BLOCK = 256
_MAX_ACTION = 64
_MAX_ACTOR = 128
_MAX_TARGET = 1024
_MAX_DETAIL = 4096
#: No line :func:`record` writes is longer than this, whatever its fields hold.
_MAX_LINE = 65536
_MAX_SEQ = 2**62
_MAX_TS = 2**40
_MAX_INT_DIGITS = 20
_CHUNK = 65536
_MAX_PROBLEMS = 50
_MAX_CACHED_KEYS = 16


class AuditError(IronDomeError):
    """The audit log could not be written or read. The message says why."""


@dataclass(frozen=True)
class AuditEvent:
    """One authenticated record. Text fields are escaped so they are safe to print."""

    seq: int
    ts: int
    kid: str
    action: str
    actor: str
    target: str
    detail: str
    ok: bool


@dataclass(frozen=True)
class AuditReport:
    """The result of :func:`verify`. ``count`` is the number of authenticated records."""

    ok: bool
    count: int
    problems: List[str]


class _BadLine(Exception):
    """A line that is not a record of this log. The message completes "line N ..."."""


# ---------------------------------------------------------------------------
# Hostile JSON
# ---------------------------------------------------------------------------


def _strict_int(token: str) -> int:
    if len(token) > _MAX_INT_DIGITS:
        raise ValueError("integer literal is too long")
    return int(token)


def _no_constant(token: str) -> Any:
    raise ValueError(f"{token} is not allowed")


def _unique_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("an object repeats a key")
    return result


def strict_loads(raw: Union[bytes, bytearray, str]) -> Any:
    """Parse JSON read from disk. Raises ``ValueError`` on anything doubtful.

    Stricter than ``json.loads`` in three ways that matter for hostile input:
    integer literals longer than 20 digits are refused before they are
    converted (converting a multi-megabyte literal takes minutes on Python
    3.9), ``NaN`` and ``Infinity`` are refused, and so is an object that names
    a key twice. Bytes must be UTF-8. Shared with :mod:`irondome.caps`.
    """
    text = raw if isinstance(raw, str) else raw.decode("utf-8")
    try:
        return json.loads(text, parse_int=_strict_int, parse_constant=_no_constant, object_pairs_hook=_unique_keys)
    except RecursionError:
        raise ValueError("nested too deeply") from None


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def owner_key(vault: "Vault") -> SecureBuffer:
    """The key the vault owner's records are written and read with. Wipe it after use."""
    return hkdf(vault.vault_key, info=_LABEL_OWNER, salt=vault.vault_id)


def grant_key(owner: BufferLike, grant_id: str) -> SecureBuffer:
    """The key one grant writes its records with, derived from the owner key.

    It is embedded in the grant when the grant is created. Knowing it reveals
    nothing about the owner key or about any other grant's key.
    """
    if not isinstance(grant_id, str) or not _GRANT_ID.fullmatch(grant_id):
        raise UsageError("a grant id is 32 hexadecimal characters")
    return hkdf(owner, info=_LABEL_GRANT + grant_id.encode("ascii"))


def _sealing_key(key: BufferLike) -> SecureBuffer:
    return hkdf(key, info=_LABEL_RECORD)


class _KeyRing:
    """Sealing keys for the lines of one log, derived on demand and wiped on exit."""

    def __init__(self, owner: SecureBuffer) -> None:
        self._owner = owner
        self._keys: Dict[str, SecureBuffer] = {}

    def get(self, kid: str) -> SecureBuffer:
        key = self._keys.get(kid)
        if key is None:
            if len(self._keys) >= _MAX_CACHED_KEYS:
                self.close()
            if kid == KID_VAULT:
                key = _sealing_key(self._owner)
            else:
                with grant_key(self._owner, kid) as derived:
                    key = _sealing_key(derived)
            self._keys[kid] = key
        return key

    def close(self) -> None:
        for key in self._keys.values():
            key.wipe()
        self._keys.clear()

    def __enter__(self) -> "_KeyRing":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Lines
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Line:
    seq: int
    ts: int
    prev: str
    kid: str
    blob: bytes


def _valid_kid(kid: Any) -> bool:
    return isinstance(kid, str) and (kid == KID_VAULT or _GRANT_ID.fullmatch(kid) is not None)


def _aad(vault_id: bytes, seq: int, ts: int, kid: str, prev: str) -> bytes:
    """Everything a line states in the clear, in a form no two lines share."""
    name = kid.encode("ascii")
    return b"".join(
        (
            _LABEL_AAD,
            bytes(vault_id),
            seq.to_bytes(8, "big"),
            ts.to_bytes(8, "big"),
            len(name).to_bytes(1, "big"),
            name,
            bytes.fromhex(prev),
        )
    )


def _encode_line(seq: int, ts: int, prev: str, kid: str, blob: bytes) -> bytes:
    document = {"seq": seq, "ts": ts, "prev": prev, "kid": kid, "data": b64e(blob)}
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


def _parse_line(raw: bytes) -> _Line:
    try:
        document = strict_loads(raw)
    except ValueError:
        raise _BadLine("is not an audit record (unreadable)") from None
    if not isinstance(document, dict) or set(document) != _LINE_KEYS:
        raise _BadLine("is not an audit record")
    seq, ts, prev, kid = document["seq"], document["ts"], document["prev"], document["kid"]
    if not _is_int(seq) or not 1 <= seq <= _MAX_SEQ:
        raise _BadLine("has no valid sequence number")
    if not _is_int(ts) or not 0 <= ts <= _MAX_TS:
        raise _BadLine("has no valid time")
    if not isinstance(prev, str) or not _PREV.fullmatch(prev):
        raise _BadLine("has no valid link to the line before it")
    if not _valid_kid(kid):
        raise _BadLine("names no key of this vault")
    try:
        blob = b64d(document["data"], what="audit record")
    except VaultError:
        raise _BadLine("holds no sealed record") from None
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise _BadLine("holds no sealed record")
    if _encode_line(seq, ts, prev, kid, blob) != raw:
        raise _BadLine("is not in the form IronDome writes: it was edited")
    return _Line(seq=seq, ts=ts, prev=prev, kid=kid, blob=blob)


def _display(text: str) -> str:
    """Escape control, format and unassigned characters so a terminal prints them inertly."""
    if text.isprintable():
        return text
    return "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)


def _open_record(line: _Line, key: SecureBuffer, vault_id: bytes) -> AuditEvent:
    try:
        padded = open_sealed(key, line.blob, _aad(vault_id, line.seq, line.ts, line.kid, line.prev))
    except DecryptError:
        raise _BadLine("failed authentication: it was edited, or was not written with a key of this vault") from None
    malformed = "is authentic but is not a record IronDome writes"
    try:
        try:
            plain = unpad(padded)
        except VaultError:
            raise _BadLine(malformed) from None
        text = ""
        try:
            text = plain.decode("utf-8")
            document = strict_loads(text)
        except ValueError:
            raise _BadLine(malformed) from None
        finally:
            wipe_bytes(plain)
            wipe_bytes(text)
    finally:
        wipe_bytes(padded)
    if not isinstance(document, dict) or any(name not in document for name in _RECORD_KEYS):
        raise _BadLine(malformed)
    action, actor, target, detail, ok = (document[name] for name in _RECORD_KEYS)
    limits = ((action, _MAX_ACTION), (actor, _MAX_ACTOR), (target, _MAX_TARGET), (detail, _MAX_DETAIL))
    if any(not isinstance(value, str) or len(value) > limit for value, limit in limits):
        raise _BadLine(malformed)
    if not action or not isinstance(ok, bool):
        raise _BadLine(malformed)
    return AuditEvent(
        seq=line.seq,
        ts=line.ts,
        kid=line.kid,
        action=_display(action),
        actor=_display(actor),
        target=_display(target),
        detail=_display(detail),
        ok=ok,
    )


# ---------------------------------------------------------------------------
# The file
# ---------------------------------------------------------------------------


def _lock_path(path: Path) -> Path:
    return path.with_name(path.name + ".lock")


def _reason(exc: OSError) -> str:
    return exc.strerror or exc.__class__.__name__


def _open_log(path: Path, *, create: bool) -> int:
    """Open the log itself: never a symbolic link, a pipe or a device in its place."""
    flags = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    flags |= os.O_RDWR | os.O_APPEND | os.O_CREAT if create else os.O_RDONLY
    try:
        fd = os.open(str(path), flags, paths.FILE_MODE)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise OSError(None, "it is a symbolic link") from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(None, "it is not a regular file")
        if create and hasattr(os, "fchmod"):
            os.fchmod(fd, paths.FILE_MODE)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_at(fd: int, offset: int, length: int) -> bytes:
    os.lseek(fd, offset, os.SEEK_SET)
    parts = []
    remaining = length
    while remaining > 0:
        part = os.read(fd, remaining)
        if not part:
            break
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def _last_newline(fd: int, before: int) -> int:
    """Offset of the last newline in the first *before* bytes, or -1."""
    position = before
    while position > 0:
        step = min(_CHUNK, position)
        position -= step
        index = _read_at(fd, position, step).rfind(b"\n")
        if index >= 0:
            return position + index
    return -1


def _digest_range(fd: int, start: int, stop: int) -> Tuple[str, Optional[bytes]]:
    """SHA-256 of ``[start, stop)``, and the bytes themselves if they could be a record."""
    digest = hashlib.sha256()
    keep = stop - start <= _MAX_LINE
    parts = []
    position = start
    while position < stop:
        part = _read_at(fd, position, min(_CHUNK, stop - position))
        if not part:
            break
        digest.update(part)
        if keep:
            parts.append(part)
        position += len(part)
    return digest.hexdigest(), b"".join(parts) if keep else None


def _count_lines(fd: int, end: int) -> int:
    count = 0
    position = 0
    while position < end:
        part = _read_at(fd, position, min(_CHUNK, end - position))
        if not part:
            break
        count += part.count(b"\n")
        position += len(part)
    return count


def _next_position(fd: int) -> Tuple[int, str, int]:
    """Where the next line goes: its sequence number, its ``prev``, and the file offset.

    A trailing fragment with no newline is the remains of a write that was
    interrupted before it completed. It was never a record, and it is removed
    here so the next line starts on a line of its own.
    """
    size = os.fstat(fd).st_size
    if size and _read_at(fd, size - 1, 1) != b"\n":
        size = _last_newline(fd, size) + 1
        os.ftruncate(fd, size)
    if size == 0:
        return 1, "", 0
    start = _last_newline(fd, size - 1) + 1
    digest, raw = _digest_range(fd, start, size - 1)
    seq = 0
    if raw is not None:
        try:
            seq = _parse_line(raw).seq + 1
        except _BadLine:
            seq = 0
    if not 1 <= seq <= _MAX_SEQ:
        # The last line is not a record, so it cannot say what comes next: number by position.
        seq = _count_lines(fd, size) + 1
    return seq, digest, size


def _flush(fd: int) -> None:
    """Flush to the storage device, as :func:`irondome.paths.write_atomic` does for the vault.

    On macOS ``fsync`` leaves data in the drive's volatile cache;
    ``F_FULLFSYNC`` has the drive write it out. Where that is not supported a
    plain ``fsync`` is what there is.
    """
    if sys.platform == "darwin":
        import fcntl

        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except OSError:
            pass  # not supported on this filesystem
    os.fsync(fd)


def _append(fd: int, end: int, line: bytes) -> None:
    """Write one line at the end, or leave the file exactly ``end`` bytes long."""
    try:
        view = memoryview(line)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        _flush(fd)
    except BaseException:
        try:
            os.ftruncate(fd, end)
        except OSError:
            pass  # the fragment has no newline; the next record() removes it
        raise


def _lines(handle: BinaryIO) -> Iterator[Tuple[Optional[bytes], str, bool]]:
    """Yield ``(line, sha256 of the line, terminated)`` without ever holding a huge line.

    ``line`` excludes its newline and is ``None`` when it is longer than any
    record; the hash is still that of the whole line, so the chain can be
    followed across it.
    """
    while True:
        chunk = handle.readline(_MAX_LINE + 1)
        if not chunk:
            return
        if chunk.endswith(b"\n"):
            body = chunk[:-1]
            yield body, hashlib.sha256(body).hexdigest(), True
            continue
        if len(chunk) <= _MAX_LINE:
            yield chunk, hashlib.sha256(chunk).hexdigest(), False
            return
        digest = hashlib.sha256(chunk)
        terminated = False
        while not terminated:
            more = handle.readline(_CHUNK)
            if not more:
                break
            terminated = more.endswith(b"\n")
            digest.update(more[:-1] if terminated else more)
        yield None, digest.hexdigest(), terminated
        if not terminated:
            return


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _storable(value: Any, limit: int, what: str) -> str:
    """Text as it will be stored: lone surrogates escaped, over-long text cut with a mark."""
    if not isinstance(value, str):
        raise UsageError(f"an audit record's {what} must be text")
    text = value.encode("utf-8", "backslashreplace").decode("utf-8")
    if len(text) > limit:
        text = text[: limit - 1] + "\u2026"
    return text


def record(
    key: BufferLike,
    *,
    vault_id: bytes,
    kid: str,
    action: str,
    actor: str = "",
    target: str = "",
    detail: str = "",
    ok: bool = True,
) -> None:
    """Append one record, sealed under *key*, and flush it to the device.

    *key* is the owner key (``kid="vault"``) or a grant's own key (``kid`` is
    the grant id). *actor*, *target* and *detail* longer than 128, 1024 and
    4096 characters are cut and marked with an ellipsis rather than refused.

    Raises :class:`AuditError` if the line could not be written (no space, no
    permission, the log is not a regular file). In that case the file is left
    as it was: no partial line. Raises :class:`~irondome.errors.UsageError`
    for arguments that cannot form a record. Both are
    :class:`~irondome.errors.IronDomeError`, so a caller that has already
    completed its own work can report the failure and carry on.
    """
    if not isinstance(vault_id, (bytes, bytearray)) or len(vault_id) != VAULT_ID_LEN:
        raise UsageError("an audit record needs the 16-byte vault id")
    if not _valid_kid(kid):
        raise UsageError('an audit record\'s key id is "vault" or a grant id')
    if not isinstance(action, str) or not action or len(action) > _MAX_ACTION:
        raise UsageError(f"an audit record's action must be 1 to {_MAX_ACTION} characters of text")
    if not isinstance(ok, bool):
        raise UsageError("an audit record's ok flag must be true or false")
    try:
        key_length = len(as_view(key))
    except (TypeError, ValueError):
        raise UsageError("the audit key is not usable (wiped, or not bytes)") from None
    if key_length != KEY_LEN:
        raise UsageError("the audit key must be 32 bytes")
    payload = {
        "action": _storable(action, _MAX_ACTION, "action"),
        "actor": _storable(actor, _MAX_ACTOR, "actor"),
        "target": _storable(target, _MAX_TARGET, "target"),
        "detail": _storable(detail, _MAX_DETAIL, "detail"),
        "ok": ok,
    }
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    encoded = text.encode("utf-8")
    padded = pad(encoded, _PAD_BLOCK)
    path = paths.audit_file()
    try:
        with paths.file_lock(_lock_path(path)):
            fd = _open_log(path, create=True)
            try:
                seq, prev, end = _next_position(fd)
                ts = min(max(int(time.time()), 0), _MAX_TS)
                with _sealing_key(key) as sealing:
                    blob = seal(sealing, padded, _aad(bytes(vault_id), seq, ts, kid, prev))
                _append(fd, end, _encode_line(seq, ts, prev, kid, blob) + b"\n")
            finally:
                os.close(fd)
    except OSError as exc:
        raise AuditError(
            f"the audit log {path} could not be written ({_reason(exc)}). "
            "Free some space or fix the file's permissions, then run the command again."
        ) from None
    finally:
        wipe_bytes(padded)
        wipe_bytes(encoded)
        wipe_bytes(text)


def archive() -> Optional[Path]:
    """Set the current log aside as ``audit-<UTC time>.log`` and return its new path.

    The next :func:`record` starts a new chain at record 1. Nothing is
    deleted: the archived file can still be checked with ``verify(vault,
    path=...)``. Returns ``None`` when there is no log. This is the way out
    after :func:`verify` has reported damage that has been looked into.
    """
    path = paths.audit_file()
    try:
        with paths.file_lock(_lock_path(path)):
            if not os.path.lexists(str(path)):
                return None
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(time.time()))
            target = path.with_name(f"audit-{stamp}.log")
            serial = 1
            while os.path.lexists(str(target)):
                serial += 1
                target = path.with_name(f"audit-{stamp}-{serial}.log")
            os.rename(str(path), str(target))
            return target
    except OSError as exc:
        raise AuditError(f"the audit log {path} could not be archived ({_reason(exc)})") from None


# ---------------------------------------------------------------------------
# Reading and verifying
# ---------------------------------------------------------------------------


class _Problems:
    """Findings, capped so a log full of damage cannot produce an unbounded report."""

    def __init__(self) -> None:
        self.items: List[str] = []
        self.dropped = 0

    def add(self, text: str) -> None:
        if len(self.items) < _MAX_PROBLEMS:
            self.items.append(text)
        else:
            self.dropped += 1

    def result(self) -> List[str]:
        if self.dropped:
            return self.items + [f"and {self.dropped} more problems, not listed"]
        return list(self.items)


def _scan(
    vault: "Vault", path: Union[str, Path, None], limit: Optional[int]
) -> Tuple[List[AuditEvent], int, List[str]]:
    """Walk the log once. Returns the newest *limit* events, the event count, the problems."""
    target = Path(path) if path is not None else paths.audit_file()
    vault_id = vault.vault_id
    events: Deque[AuditEvent] = deque(maxlen=limit)
    problems = _Problems()
    count = 0
    try:
        with ExitStack() as stack:
            stack.enter_context(paths.file_lock(_lock_path(paths.audit_file())))
            try:
                fd = _open_log(target, create=False)
            except FileNotFoundError:
                return [], 0, []
            stack.callback(os.close, fd)
            if os.fstat(fd).st_size > paths.MAX_FILE_BYTES:
                return [], 0, [f"the log is larger than {paths.MAX_FILE_BYTES} bytes and was not read"]
            handle = stack.enter_context(open(fd, "rb", closefd=False))
            keys = stack.enter_context(_KeyRing(stack.enter_context(owner_key(vault))))
            expected: Optional[int] = 1
            previous = ""
            for number, (raw, digest, terminated) in enumerate(_lines(handle), start=1):
                if not terminated:  # always the last line there is
                    problems.add(
                        f"line {number} is incomplete: a write was interrupted, or the end of the log was cut off"
                    )
                    continue
                if raw is None:
                    problems.add(f"line {number} is longer than any record IronDome writes")
                    expected, previous = None, digest
                    continue
                try:
                    line = _parse_line(raw)
                except _BadLine as exc:
                    problems.add(f"line {number} {exc}")
                    expected, previous = None, digest
                    continue
                if expected is not None and line.seq != expected:
                    cause = (
                        "the beginning of the log was removed"
                        if number == 1
                        else "records were removed, repeated or reordered"
                    )
                    problems.add(f"line {number} is record {line.seq} where record {expected} belongs: {cause}")
                if line.prev != previous:
                    cause = (
                        "the beginning of the log was removed"
                        if number == 1
                        else "a line was edited, removed, inserted or moved"
                    )
                    problems.add(f"line {number} does not follow what is before it: {cause}")
                try:
                    events.append(_open_record(line, keys.get(line.kid), vault_id))
                    count += 1
                except _BadLine as exc:
                    problems.add(f"line {number} {exc}")
                expected, previous = line.seq + 1, digest
    except OSError as exc:
        raise AuditError(f"the audit log {target} could not be read ({_reason(exc)})") from None
    return list(events), count, problems.result()


def read(
    vault: "Vault", *, limit: Optional[int] = None, path: Union[str, Path, None] = None
) -> List[AuditEvent]:
    """Every record that authenticates under a key of this vault, oldest first.

    *limit* keeps only the newest that many. Lines that are damaged or forged
    are left out, so a gap in ``seq`` is the only trace of them here: call
    :func:`verify` to learn whether the log is complete and in order. The text
    fields come from whoever wrote the record, which for a grant's records is
    the grant holder; they are returned with control and formatting characters
    escaped, and ``kid`` (not ``actor``) says which key wrote them.
    """
    if limit is not None and (not _is_int(limit) or limit < 1):
        raise UsageError("the number of audit records to read must be a positive whole number")
    events, _, _ = _scan(vault, path, limit)
    return events


def verify(vault: "Vault", *, path: Union[str, Path, None] = None) -> AuditReport:
    """Check every line of the log and say what is wrong with it, if anything.

    Detects: a line that was edited in any way; a line not sealed with the
    owner key or with the key of the grant it names; lines removed from the
    beginning or the middle; lines reordered, repeated or inserted; a last
    line that was cut short.

    Does not detect: removal of the newest lines, including removal of the
    whole file (an absent or empty log verifies as ``ok`` with ``count`` 0).
    A grant holder can also append any number of records under its own key.

    ``count`` equals ``len(read(vault))``. Once a problem is in the log it
    stays there; :func:`archive` sets the file aside and starts a new one.
    """
    _, count, problems = _scan(vault, path, 1)
    return AuditReport(ok=not problems, count=count, problems=problems)
