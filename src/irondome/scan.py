"""Finding secrets from the vault in files where they do not belong.

Secrets end up in files when something prints them: an agent's transcript
that captured a command's output, a shell history, a CI log, a debug dump, a
commit. From there they travel into backups, sync folders and the context
windows of models. :func:`scan_paths` searches files and directory trees for
the values it is given, in plain text and in every encoding
:func:`irondome.agent.runner.secret_patterns` lists -- base64 (whole and
inside longer base64), hex, percent-encoding, JSON, shell and debugger
quoting: the list ``irondome run`` masks -- and reports where each one is:
the path, the line, the entry and field it belongs to, and the encoding.

A :class:`Hit` names a secret. It never holds one, and nothing in this module
writes a value anywhere; :class:`SecretValue` keeps its value out of ``repr``.

How files are read
------------------
* A path named directly is followed when it is a symbolic link, as ``grep -r``
  does, so ``~/.claude`` may be a link. Inside a directory tree symbolic links
  are never followed.
* Only regular files are opened. FIFOs, sockets and devices inside a tree are
  skipped without being opened, and anything opened is checked again with
  ``fstat`` before it is read, so nothing is ever waited on. Files larger than
  :data:`MAX_FILE_BYTES` and files or directories that cannot be read are
  skipped as well. Every skip is counted under its reason in
  :attr:`ScanResult.skipped`.
* A file is read in chunks. Each chunk is searched together with the last
  bytes of the one before (the length of the longest pattern, less one), so
  an occurrence that crosses a boundary is found, exactly once, and a file
  that is one enormous line never has to fit in memory.
* A file reached through two paths (two arguments, a hard link) is read once.

Matching
--------
A vault holds hundreds of values and each has a dozen or more encodings, so a
scan looks for thousands of byte strings at once. They are grouped by their
first byte; for each group one regular expression, built as a trie of the
patterns' first eight bytes, finds candidate positions at C speed, and each
candidate is compared with the full patterns that start that way. Every
pattern looked for is at least eight bytes long: every pattern of a value of
eight or more characters is, and of a value kept with white space around it,
what is left without that white space is looked for only when it is that long
too. Shorter values are not looked for at all: they turn up by chance in
ordinary text.

What it cannot find
-------------------
A secret that was changed on its way into the file in a way the pattern list
does not cover: reversed, split across lines, base64 wrapped at 76 columns,
compressed (git objects, zip and gzip archives) or encrypted. A secret written
in an encoding other than UTF-8. A value shorter than eight characters.
"""

from __future__ import annotations

import errno
import os
import re
import stat
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from irondome.agent.runner import secret_patterns
from irondome.errors import UsageError

__all__ = [
    "MIN_SECRET_CHARS",
    "MAX_FILE_BYTES",
    "SKIP_SYMLINK",
    "SKIP_UNREADABLE",
    "SKIP_TOO_LARGE",
    "SKIP_SPECIAL",
    "SecretValue",
    "Hit",
    "ScanResult",
    "check_paths",
    "scan_paths",
    "path_text",
    "display_path",
]

#: Values shorter than this are not looked for.
MIN_SECRET_CHARS = 8
#: Larger files are skipped and counted.
MAX_FILE_BYTES = 50 * 1024 * 1024

#: Reasons a file is skipped: the keys of :attr:`ScanResult.skipped`.
SKIP_SYMLINK = "symlink"
SKIP_UNREADABLE = "unreadable"
SKIP_TOO_LARGE = "too large"
SKIP_SPECIAL = "not a regular file"

_CHUNK_BYTES = 4 * 1024 * 1024
_READ_BYTES = 1024 * 1024
_ANCHOR_BYTES = 8
#: Marks the end of a word in the trie. No byte has this value.
_END = -1

_OPEN_FLAGS = (
    os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
)
_NO_FOLLOW = getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True)
class SecretValue:
    """One value to look for, and the entry and field it belongs to. ``repr`` never shows the value."""

    entry: str
    field: str
    value: str = dataclass_field(repr=False)


@dataclass(frozen=True)
class Hit:
    """A secret, in one encoding, on one line of one file. Holds no part of the value."""

    path: str
    line: int
    entry: str
    field: str
    encoding: str


@dataclass
class ScanResult:
    """What :func:`scan_paths` found and how much it read.

    ``hits`` are in the order the files were read, then by line. ``skipped``
    counts what was not read, by reason (``SKIP_*``).
    """

    hits: List[Hit] = dataclass_field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    skipped: Dict[str, int] = dataclass_field(default_factory=dict)

    @property
    def files_skipped(self) -> int:
        return sum(self.skipped.values())


# ---------------------------------------------------------------------------
# Paths as text
# ---------------------------------------------------------------------------


def path_text(path: str) -> str:
    """*path* as text that can be encoded: bytes that were not UTF-8 become ``\\xNN``.

    File names on POSIX are bytes. Python decodes the ones that are not UTF-8
    into lone surrogates, which no output stream can encode; this puts them
    back as visible escapes and leaves every valid name exactly as it is.
    """
    try:
        return path.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    except UnicodeEncodeError:
        return path.encode("utf-8", "backslashreplace").decode("utf-8")


def display_path(path: str) -> str:
    """*path* as text that is safe to print on a terminal: control and format characters escaped."""
    text = path_text(path)
    if text.isprintable():
        return text
    return "".join(char if char.isprintable() else char.encode("unicode_escape").decode("ascii") for char in text)


def check_paths(paths: Sequence[Any]) -> List[str]:
    """Return *paths* as text after checking that each one exists.

    Raises :class:`UsageError` for an empty list, for something that is not a
    path, and for the first path that does not exist. A symbolic link that
    leads nowhere exists; it is skipped and counted when scanned.
    """
    if isinstance(paths, (str, bytes)) or not isinstance(paths, (list, tuple)) or not paths:
        raise UsageError("give at least one file or directory to scan")
    checked: List[str] = []
    for path in paths:
        try:
            name = os.fspath(path)
        except TypeError:
            raise UsageError("a path to scan must be text") from None
        if not isinstance(name, str) or not name or "\x00" in name:
            raise UsageError("a path to scan must be text, not empty, and without NUL characters")
        if not os.path.lexists(name):
            raise UsageError(f"{display_path(name)} does not exist")
        checked.append(name)
    return checked


# ---------------------------------------------------------------------------
# Matching many patterns at once
# ---------------------------------------------------------------------------


def _trie_expression(words: Sequence[bytes]) -> bytes:
    """A regular expression that matches exactly *words*, with shared prefixes factored out.

    ``re`` tries the alternatives of a group one after another, so a flat
    alternation of thousands of literals is slow. As a trie, each step only
    offers the bytes that can actually come next.
    """
    root: Dict[int, Any] = {}
    for word in words:
        node = root
        for byte in word:
            node = node.setdefault(byte, {})
        node[_END] = {}
    return _node_expression(root)


def _node_expression(node: Dict[int, Any]) -> bytes:
    branches = []
    for first in sorted(key for key in node if key != _END):
        literal = bytearray((first,))
        child = node[first]
        while len(child) == 1 and _END not in child:
            ((following, child),) = child.items()
            literal.append(following)
        branches.append(re.escape(bytes(literal)) + _node_expression(child))
    if not branches:
        return b""
    body = branches[0] if len(branches) == 1 else b"(?:" + b"|".join(branches) + b")"
    return b"(?:" + body + b")?" if _END in node else body


class _Needles:
    """Every pattern of every value, who owns it, and the searches that find them."""

    def __init__(self, secrets: Iterable[SecretValue]) -> None:
        owners: Dict[bytes, List[Tuple[str, str, str]]] = {}
        for item in secrets:
            if not isinstance(item, SecretValue):
                raise UsageError("the secrets to look for must be given as SecretValue items")
            if not all(isinstance(text, str) for text in (item.entry, item.field, item.value)):
                raise UsageError("a secret to look for, its entry and its field must be text")
            if len(item.value) < MIN_SECRET_CHARS:
                continue
            try:
                forms = secret_patterns(item.value)
            except UsageError:
                continue  # not valid Unicode text: no UTF-8 file can contain it
            for encoding, pattern in forms:
                if len(pattern) < MIN_SECRET_CHARS:
                    continue  # the value without the white space around it, when that is too short to look for
                labels = owners.setdefault(pattern, [])
                label = (item.entry, item.field, encoding)
                if label not in labels:
                    labels.append(label)
        self.owners = owners
        self.longest = max((len(pattern) for pattern in owners), default=0)
        width = min([_ANCHOR_BYTES] + [len(pattern) for pattern in owners])
        by_anchor: Dict[bytes, List[bytes]] = {}
        for pattern in sorted(owners):
            by_anchor.setdefault(pattern[:width], []).append(pattern)
        groups: Dict[int, List[bytes]] = {}
        for anchor in sorted(by_anchor):
            groups.setdefault(anchor[0], []).append(anchor)
        self._by_anchor = by_anchor
        self._searches: List[Callable[..., Optional["re.Match[bytes]"]]] = [
            re.compile(_trie_expression(anchors)).search for anchors in groups.values()
        ]

    def __bool__(self) -> bool:
        return bool(self.owners)

    def find(self, data: bytes, fresh: int) -> List[Tuple[int, bytes]]:
        """``(position, pattern)`` of every occurrence in *data* that ends after offset *fresh*, sorted.

        Occurrences that end at or before *fresh* lie wholly in the part of
        *data* that was already searched with the chunk before.
        """
        found: List[Tuple[int, bytes]] = []
        by_anchor = self._by_anchor
        for search in self._searches:
            match = search(data)
            while match is not None:
                at = match.start()
                for pattern in by_anchor[match.group()]:
                    if at + len(pattern) > fresh and data.startswith(pattern, at):
                        found.append((at, pattern))
                match = search(data, at + 1)
        found.sort()
        return found


# ---------------------------------------------------------------------------
# Walking and reading
# ---------------------------------------------------------------------------


def _read_up_to(fd: int, size: int) -> bytes:
    parts = []
    remaining = size
    while remaining > 0:
        part = os.read(fd, min(remaining, _READ_BYTES))
        if not part:
            break
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


class _Scanner:
    def __init__(self, needles: _Needles, max_file_bytes: int, chunk_bytes: int) -> None:
        self._needles = needles
        self._limit = max_file_bytes
        self._chunk = max(chunk_bytes, needles.longest - 1, 1)
        self._read_files: Set[Tuple[int, int]] = set()
        self.result = ScanResult()

    def _skip(self, reason: str) -> None:
        self.result.skipped[reason] = self.result.skipped.get(reason, 0) + 1

    def named(self, path: str) -> None:
        """A path from the caller: followed if it is a link, walked if it is a directory."""
        try:
            info = os.stat(path)
        except FileNotFoundError:
            if os.path.islink(path):
                self._skip(SKIP_SYMLINK)  # a link that leads nowhere
                return
            raise UsageError(f"{display_path(path)} does not exist") from None
        except OSError:
            self._skip(SKIP_UNREADABLE)
            return
        if stat.S_ISDIR(info.st_mode):
            self._tree(path)
        elif stat.S_ISREG(info.st_mode):
            self._file(path, follow=True)
        else:
            self._skip(SKIP_SPECIAL)

    def _tree(self, top: str) -> None:
        pending = [top]
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as listing:
                    entries = sorted(listing, key=lambda entry: entry.name)
            except OSError:
                self._skip(SKIP_UNREADABLE)
                continue
            below = []
            for entry in entries:
                try:
                    if entry.is_symlink():
                        self._skip(SKIP_SYMLINK)
                    elif entry.is_dir(follow_symlinks=False):
                        below.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        self._file(entry.path, follow=False)
                    else:
                        self._skip(SKIP_SPECIAL)
                except OSError:
                    self._skip(SKIP_UNREADABLE)
            pending.extend(reversed(below))  # depth first, in name order

    def _file(self, path: str, *, follow: bool) -> None:
        try:
            fd = os.open(path, _OPEN_FLAGS | (0 if follow else _NO_FOLLOW))
        except OSError as exc:
            swapped = not follow and exc.errno in (errno.ELOOP, errno.EMLINK)  # became a link after listing
            self._skip(SKIP_SYMLINK if swapped else SKIP_UNREADABLE)
            return
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                self._skip(SKIP_SPECIAL)
                return
            if info.st_size > self._limit:
                self._skip(SKIP_TOO_LARGE)
                return
            identity = (info.st_dev, info.st_ino)
            if identity in self._read_files:
                return  # the same file, reached through another path: read once
            self._read_files.add(identity)
            try:
                self._search(fd, path)
            except OSError:
                self._skip(SKIP_UNREADABLE)
                return
            self.result.files_scanned += 1
        finally:
            os.close(fd)

    def _search(self, fd: int, path: str) -> None:
        """Search one open file chunk by chunk, recording one hit per line, secret and encoding."""
        needles = self._needles
        keep = needles.longest - 1
        remaining = self._limit
        carried = b""
        lines_before = 0  # newlines in the file before the first byte of `carried`
        seen: Set[Tuple[int, str, str, str]] = set()
        hits: List[Hit] = []
        try:
            while remaining > 0:
                fresh = _read_up_to(fd, min(self._chunk, remaining))
                if not fresh:
                    break
                remaining -= len(fresh)
                self.result.bytes_scanned += len(fresh)
                data = carried + fresh
                position, lines = 0, lines_before
                for at, pattern in needles.find(data, len(carried)):
                    lines += data.count(b"\n", position, at)
                    position = at
                    for entry, field, encoding in needles.owners[pattern]:
                        key = (lines + 1, entry, field, encoding)
                        if key not in seen:
                            seen.add(key)
                            hits.append(Hit(path=path, line=lines + 1, entry=entry, field=field, encoding=encoding))
                cut = max(len(data) - keep, 0)
                lines_before += data.count(b"\n", 0, cut)
                carried = data[cut:]
        finally:
            hits.sort(key=lambda hit: (hit.line, hit.entry, hit.field, hit.encoding))
            self.result.hits.extend(hits)


def _whole(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise UsageError(f"{what} must be a positive whole number of bytes")
    return value


def scan_paths(
    paths: Sequence[Any],
    secrets: Iterable[SecretValue],
    *,
    max_file_bytes: int = MAX_FILE_BYTES,
    chunk_bytes: int = _CHUNK_BYTES,
) -> ScanResult:
    """Search files and directory trees for *secrets*; see the module docstring.

    *paths* are files or directories, searched in the order given. *secrets*
    are the values to look for; those shorter than :data:`MIN_SECRET_CHARS`
    characters, and any that are not valid Unicode text, are left out. With
    nothing left to look for no file is opened.

    Raises :class:`UsageError` for a path that does not exist or for
    arguments of the wrong kind. A file or directory that cannot be read is
    counted in ``skipped``, never raised.
    """
    names = check_paths(paths)
    limit = _whole(max_file_bytes, "the file size limit")
    chunk = _whole(chunk_bytes, "the chunk size")
    needles = _Needles(secrets)
    scanner = _Scanner(needles, limit, chunk)
    if needles:
        for name in names:
            scanner.named(name)
    return scanner.result
