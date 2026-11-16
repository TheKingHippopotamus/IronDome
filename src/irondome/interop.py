"""Other password managers' export files, and IronDome's own plaintext exports.

Pure parsing: nothing in this module opens a vault, derives a key, runs a
program or touches the network. :func:`parse` turns an export into a list of
:class:`ImportedEntry`, :func:`dump` writes the two plaintext formats that
``irondome export --plaintext`` offers, and :func:`detect_format` tells the
formats apart for ``irondome import --format auto``.

=============  ==========================================================
``json``       IronDome's own plaintext JSON (``export --plaintext json``)
``csv``        any CSV whose header names its columns, IronDome's own
               (``export --plaintext csv``) included
``bitwarden``  Bitwarden's unencrypted export, JSON or CSV
``1password``  1Password's CSV export
``chrome``     Chrome, Edge and Brave: ``name,url,username,password[,note]``
``firefox``    Firefox: ``url,username,password,httpRealm,...``
``irondome``   a portable encrypted backup (``irondome export``). It is
               opened with its password by the command line, never parsed
               here; :func:`detect_format` only recognises it.
=============  ==========================================================

Everything read is treated as hostile. A file larger than 50 MB, a path that
is not a regular file, text that is neither UTF-8 nor UTF-16 with a byte
order mark, a CSV row that cannot be read and a JSON item of the wrong shape
raise :class:`~irondome.errors.UsageError` naming the file and the row or
item. Nothing else is raised, whatever the input. Cells that look like
spreadsheet formulas (``=HYPERLINK(...)``, ``+1``, ``@SUM``) are data and are
kept exactly as they are: nothing here evaluates anything.

What the entries look like
--------------------------
Names are made valid entry names: control characters become spaces, space at
either end is dropped, at most 200 characters are kept, and an entry without
a name is named after the host of its web address, then its address, then
its user name, then ``untitled``. Names that repeat within one file (compared
without regard to case, as the vault compares them) are told apart with the
user name, then ``(2)``, ``(3)`` ... Tags and custom field names are made
valid in the same way. User names and web addresses lose their control
characters, which the vault refuses there (on a terminal they are escape
sequences); an entry whose user name, address or tags had any lists those
parts in ``ImportedEntry.cleaned``, so that the caller can say so. Nothing
else about a user name or a web address changes, spaces included, except
that Bitwarden's list of addresses (one CSV cell, or the ``uris`` of a JSON
item) is split into its addresses and each one trimmed. Values -- passwords,
notes, one-time-password secrets, custom field values -- are never changed.
An alias in IronDome's JSON must be a valid alias name, or the file is
refused: IronDome never writes another, and its text is not passed on.

What it does not do
-------------------
* The values are ordinary Python strings for as long as the caller keeps the
  entries; they cannot be wiped from memory.
* The one-time-password text is passed on as it was found (an
  ``otpauth://totp/`` link or a bare base32 secret); checking it is the
  caller's part (:mod:`irondome.otp`).
* Attachments and passkeys are not carried over; a Bitwarden folder becomes a
  tag, and a password history keeps its newest five passwords.
* IronDome's CSV does not hold a password history, aliases, the times an
  entry was created and last changed, a NUL character, a tag that contains
  a comma or a semicolon, or a custom field with no value: one ``field.NAME``
  column serves every entry, and its empty cell cannot tell a field with no
  value from a field the entry does not have, so neither comes back. The
  JSON format holds all of them: it is the one that round-trips exactly.
"""

from __future__ import annotations

import codecs
import csv
import io
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import urlsplit

from irondome.errors import UsageError
from irondome.vault import FIELDS, fold_name, validate_alias, validate_name, without_control

__all__ = [
    "MAX_FILE_BYTES",
    "FORMATS",
    "PLAINTEXT_FORMATS",
    "FORMAT_IRONDOME",
    "EXPORT_FORMAT",
    "EXPORT_VERSION",
    "KINDS",
    "ImportedEntry",
    "detect_format",
    "parse",
    "dump",
]

#: Files larger than this are refused before they are read.
MAX_FILE_BYTES = 50 * 1024 * 1024
#: A portable encrypted backup: recognised here, opened by the caller.
FORMAT_IRONDOME = "irondome"
FORMATS = (FORMAT_IRONDOME, "json", "csv", "bitwarden", "1password", "chrome", "firefox")
#: What :func:`dump` writes.
PLAINTEXT_FORMATS = ("json", "csv")
#: The ``format`` of IronDome's plaintext JSON, and its current version.
EXPORT_FORMAT = "irondome-export"
EXPORT_VERSION = 1
#: Entry kinds, as the vault names them.
KINDS = ("login", "secret")

Source = Union[str, bytes, bytearray, Path]

_NAME_LIMIT = 200
_USER_IN_NAME_LIMIT = 80
_TAG_LIMIT = 64
_FIELD_LIMIT = 64
_HISTORY_KEEP = 5
_HEAD_BYTES = 64 * 1024
_MAX_INT_DIGITS = 19
_MAX_TIME = 2**40
_UNTITLED = "untitled"
_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_NOT_FIELD_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")
_TAG_SEPARATORS = re.compile(r"[,;\n]")
_VAULT_MARKER = re.compile(r'"format"\s*:\s*"irondome-vault"')
_VAULT_MARKER_BYTES = re.compile(rb'"format"\s*:\s*"irondome-vault"')
_CSV_FIELD_PREFIX = "field."
_CSV_COLUMNS = ("name", "kind", "username", "password", "url", "notes", "totp", "tags")


# ---------------------------------------------------------------------------
# What callers see
# ---------------------------------------------------------------------------


@dataclass
class ImportedEntry:
    """One entry read from an export, or about to be written to one.

    ``totp`` is an ``otpauth://totp/`` link or a bare base32 secret, as found.
    ``history`` holds ``{"password": str, "retired": unix time}`` items,
    newest first; ``aliases`` holds ``(alias, field)`` pairs. ``origin`` says
    where in the file the entry came from (``row 4``, ``item 2``) for
    messages. ``cleaned`` names what :func:`parse` took control characters
    out of (``username``, ``url``, ``tags``). The secret parts are left out
    of ``repr``.
    """

    name: str
    username: str = ""
    password: str = field(default="", repr=False)
    url: str = ""
    notes: str = field(default="", repr=False)
    totp: str = field(default="", repr=False)
    tags: List[str] = field(default_factory=list)
    fields: Dict[str, str] = field(default_factory=dict, repr=False)
    kind: str = "login"
    created: Optional[int] = None
    modified: Optional[int] = None
    history: List[Dict[str, Any]] = field(default_factory=list, repr=False)
    aliases: List[Tuple[str, str]] = field(default_factory=list)
    origin: str = ""
    cleaned: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Reading the input
# ---------------------------------------------------------------------------


def _what(source: Any) -> str:
    if isinstance(source, os.PathLike):
        return str(Path(source))
    return "the input"


def _too_large(what: str, size: Optional[int] = None) -> UsageError:
    detail = f" ({size} bytes)" if size is not None else ""
    return UsageError(f"{what} is larger than 50 MB{detail}; IronDome does not read exports that large")


def _open_regular(path: Path) -> Tuple[int, int]:
    """``(descriptor, size)`` of a regular file. A pipe or device put in its place cannot make this block."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        raise UsageError(f"there is no file at {path}") from None
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from None
    try:
        info = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from None
    if not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise UsageError(f"{path} is not a regular file")
    return fd, info.st_size


def _read_from(fd: int, path: Path, limit: int) -> bytes:
    chunks: List[bytes] = []
    total = 0
    try:
        while total <= limit:
            chunk = os.read(fd, min(1 << 20, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError as exc:
        raise UsageError(f"cannot read {path}: {exc.strerror or exc}") from None
    return b"".join(chunks)


def _read_file(path: Path) -> bytes:
    fd, size = _open_regular(path)
    try:
        if size > MAX_FILE_BYTES:
            raise _too_large(str(path), size)
        data = _read_from(fd, path, MAX_FILE_BYTES)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:  # it grew while it was read
        raise _too_large(str(path))
    return data


def _read_head(path: Path) -> bytes:
    fd, _size = _open_regular(path)
    try:
        return _read_from(fd, path, _HEAD_BYTES)[:_HEAD_BYTES]
    finally:
        os.close(fd)


def _decode(data: bytes, what: str) -> str:
    """UTF-8 (with or without a byte order mark), or UTF-16 with one."""
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding, label = "utf-16", "UTF-16"
    else:
        encoding, label = "utf-8-sig", "UTF-8"
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError as exc:
        raise UsageError(
            f"{what} is not {label} text (byte {exc.start} cannot be read); export it again as UTF-8"
        ) from None
    return text[1:] if text.startswith("﻿") else text


def _text_of(source: Source, what: str) -> str:
    if isinstance(source, str):
        if len(source) > MAX_FILE_BYTES:
            raise _too_large(what)
        return source[1:] if source.startswith("﻿") else source
    if isinstance(source, (bytes, bytearray)):
        if len(source) > MAX_FILE_BYTES:
            raise _too_large(what, len(source))
        return _decode(bytes(source), what)
    if isinstance(source, os.PathLike):
        return _decode(_read_file(Path(source)), what)
    raise UsageError("an export is read from a path, or given as text or bytes")


def _bounded_int(text: str) -> int:
    """``json`` hook: refuse absurd integers before converting them (quadratic on old interpreters)."""
    if len(text.lstrip("-")) > _MAX_INT_DIGITS:
        raise ValueError("integer out of range")
    return int(text)


def _load_json(text: str, what: str) -> Any:
    try:
        return json.loads(text, parse_int=_bounded_int)
    except RecursionError:
        raise UsageError(f"{what} is nested too deeply to be an export") from None
    except json.JSONDecodeError as exc:
        raise UsageError(f"{what} is not valid JSON ({exc.msg} at line {exc.lineno}, column {exc.colno})") from None
    except ValueError:
        raise UsageError(f"{what} holds a number too large to be part of an export") from None


# ---------------------------------------------------------------------------
# Making names, tags and field names valid
# ---------------------------------------------------------------------------


def _is_control(char: str) -> bool:
    code = ord(char)
    return code < 32 or 0x7F <= code <= 0x9F or code in (0x2028, 0x2029)


def _label(text: str, limit: int) -> str:
    """*text* as a name may hold it: no control characters, no lone surrogates, no space at either end."""
    cleaned = []
    for char in text:
        if 0xD800 <= ord(char) <= 0xDFFF:
            cleaned.append("\N{REPLACEMENT CHARACTER}")
        elif _is_control(char):
            cleaned.append(" ")
        else:
            cleaned.append(char)
    result = "".join(cleaned).strip()
    return result[:limit].rstrip() if len(result) > limit else result


def _host(url: str) -> str:
    text = url.strip()
    if not text:
        return ""
    try:
        return urlsplit(text if "://" in text else "//" + text).hostname or ""
    except ValueError:
        return ""


def _entry_name(name: str, url: str, username: str) -> str:
    for candidate in (name, _host(url), url, username):
        cleaned = _label(candidate, _NAME_LIMIT)
        if cleaned:
            return validate_name(cleaned)
    return _UNTITLED


def _fit(base: str, suffix: str) -> str:
    return validate_name(base[: _NAME_LIMIT - len(suffix)].rstrip() + suffix)


def _tags(values: Iterable[str]) -> List[str]:
    result: List[str] = []
    seen: Set[str] = set()
    for value in values:
        tag = _label(value, _TAG_LIMIT)
        if tag and tag.casefold() not in seen:
            seen.add(tag.casefold())
            result.append(tag)
    return result


def _split_tags(text: str) -> List[str]:
    """The tags of one cell, as found; :func:`_storable` makes them valid."""
    return _TAG_SEPARATORS.split(text) if text else []


def _storable(entry: ImportedEntry) -> None:
    """Make what the vault would refuse storable, without losing the entry, and note in ``cleaned`` what changed.

    A user name or a web address loses its control characters; tags are made valid as names are
    (control characters become spaces, space at either end goes, repeats go).
    """
    for part in ("username", "url"):
        value = getattr(entry, part)
        kept = without_control(value)
        if kept != value:
            setattr(entry, part, kept)
            entry.cleaned.append(part)
    if any(_is_control(char) for tag in entry.tags for char in tag):
        entry.cleaned.append("tags")
    entry.tags = _tags(entry.tags)


class _Fields:
    """Custom fields of one entry under valid, distinct names."""

    def __init__(self) -> None:
        self.values: Dict[str, str] = {}
        self._taken: Set[str] = set(FIELDS)

    def add(self, label: str, value: str, *, keep_empty: bool = False) -> None:
        if not value and not keep_empty:
            return
        if _FIELD_NAME.fullmatch(label) and label not in self._taken:
            name = label
        else:
            name = self._free(self._clean(label))
        self._taken.add(name)
        self.values[name] = value

    @staticmethod
    def _clean(label: str) -> str:
        text = _NOT_FIELD_CHARS.sub("_", label.strip()).strip("_")
        if not text:
            return "field"
        if not (text[0].isascii() and (text[0].isalpha() or text[0] == "_")):
            text = "_" + text
        return text[:_FIELD_LIMIT]

    def _free(self, name: str) -> str:
        if name not in self._taken:
            return name
        number = 2
        while True:
            suffix = f"_{number}"
            candidate = name[: _FIELD_LIMIT - len(suffix)] + suffix
            if candidate not in self._taken:
                return candidate
            number += 1


def _disambiguate(entries: List[ImportedEntry]) -> None:
    """Give every entry of one file a name no other entry of that file has (ignoring case)."""
    shared = Counter(fold_name(entry.name) for entry in entries)
    taken: Set[str] = set()
    for entry in entries:
        name = entry.name
        if shared[fold_name(name)] > 1:
            user = _label(entry.username, _USER_IN_NAME_LIMIT)
            if user:
                name = _fit(name, f" ({user})")
        candidate = name
        number = 1
        while fold_name(candidate) in taken:
            number += 1
            candidate = _fit(name, f" ({number})")
        taken.add(fold_name(candidate))
        entry.name = candidate


# ---------------------------------------------------------------------------
# Times
# ---------------------------------------------------------------------------


def _iso_time(value: Any) -> Optional[int]:
    """An ISO 8601 time (``2024-05-01T12:00:00.000Z``) as a Unix time; None when it is not one."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text[-1] in "Zz":
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        stamp = int(moment.timestamp())
    except (ValueError, OverflowError, OSError):
        return None
    return stamp if 0 <= stamp <= _MAX_TIME else None


def _time_cell(value: str) -> Optional[int]:
    """A CSV time: milliseconds since 1970 as Firefox writes them, seconds, or ISO 8601; else None."""
    text = value.strip()
    if text.isascii() and text.isdigit():
        if len(text) > 16:
            return None
        stamp = int(text) // 1000 if len(text) >= 12 else int(text)
        return stamp if stamp <= _MAX_TIME else None
    return _iso_time(text)


# ---------------------------------------------------------------------------
# JSON items of the right shape
# ---------------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _text(mapping: Dict[str, Any], key: str, where: str) -> str:
    value = mapping.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise UsageError(f"{where}: {key} is not text")
    return value


def _object(value: Any, where: str, what: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise UsageError(f"{where}: {what} is not an object")
    return value


def _array(value: Any, where: str, what: str) -> List[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise UsageError(f"{where}: {what} is not a list")
    return value


def _time_field(mapping: Dict[str, Any], key: str, where: str) -> Optional[int]:
    value = mapping.get(key)
    if value is None:
        return None
    if not _is_int(value) or not 0 <= value <= _MAX_TIME:
        raise UsageError(f"{where}: {key} is not a time in seconds since 1970")
    return int(value)


# ---------------------------------------------------------------------------
# IronDome's own plaintext JSON
# ---------------------------------------------------------------------------


def _irondome_history(raw: Any, where: str) -> List[Dict[str, Any]]:
    history: List[Dict[str, Any]] = []
    for number, item in enumerate(_array(raw, where, "history"), start=1):
        place = f"{where}, history item {number}"
        item = _object(item, place, "it")
        password = _text(item, "password", place)
        retired = _time_field(item, "retired", place)
        history.append({"password": password, "retired": retired or 0})
    return history[:_HISTORY_KEEP]


def _parse_irondome_json(document: Any, what: str) -> List[ImportedEntry]:
    if not isinstance(document, dict) or document.get("format") != EXPORT_FORMAT:
        raise UsageError(f"{what} is not an IronDome plaintext export (its format is not {EXPORT_FORMAT!r})")
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise UsageError(f"{what} has no usable version number")
    if version > EXPORT_VERSION:
        raise UsageError(f"{what} was written by a newer IronDome (export format {version}); upgrade to import it")
    entries: List[ImportedEntry] = []
    for number, item in enumerate(_array(document.get("entries"), what, "entries"), start=1):
        where = f"{what}: entry {number}"
        if not isinstance(item, dict):
            raise UsageError(f"{where} is not an object")
        kind = item.get("kind", "login")
        if kind not in KINDS:
            raise UsageError(f"{where}: kind must be login or secret")
        tags = _array(item.get("tags"), where, "tags")
        if not all(isinstance(tag, str) for tag in tags):
            raise UsageError(f"{where}: tags must be text")
        fields = _Fields()
        for label, value in _object(item.get("fields"), where, "fields").items():
            if not isinstance(value, str):
                raise UsageError(f"{where}: custom field {_label(label, _FIELD_LIMIT)!r} is not text")
            fields.add(label, value, keep_empty=True)
        aliases: List[Tuple[str, str]] = []
        for alias, target in _object(item.get("aliases"), where, "aliases").items():
            try:
                validate_alias(alias)
            except UsageError:
                # IronDome writes only valid aliases. Anything else (an escape sequence, a line break) is a
                # damaged or crafted file, and its text is never handed on to be printed: repr() escapes it.
                raise UsageError(
                    f"{where}: {_label(alias, 128)!r} is not an alias (a letter or _, then letters, digits, "
                    "_ . or -, at most 128 characters)"
                ) from None
            if not isinstance(target, str):
                raise UsageError(f"{where}: alias {alias} does not name a field")
            aliases.append((alias, target))
        url = _text(item, "url", where)
        username = _text(item, "username", where)
        entries.append(
            ImportedEntry(
                name=_entry_name(_text(item, "name", where), url, username),
                username=username,
                password=_text(item, "password", where),
                url=url,
                notes=_text(item, "notes", where),
                totp=_text(item, "totp", where).strip(),
                tags=list(tags),
                fields=fields.values,
                kind=kind,
                created=_time_field(item, "created", where),
                modified=_time_field(item, "modified", where),
                history=_irondome_history(item.get("history"), where),
                aliases=aliases,
                origin=f"entry {number}",
            )
        )
    return entries


# ---------------------------------------------------------------------------
# Bitwarden's unencrypted JSON
# ---------------------------------------------------------------------------

_BITWARDEN_LOGIN = 1
_BITWARDEN_CARD = 3
_BITWARDEN_IDENTITY = 4
_BITWARDEN_SSH_KEY = 5
_BITWARDEN_LINKED_FIELD = 3
_BITWARDEN_CARD_FIELDS = (
    ("cardholderName", "cardholder"),
    ("brand", "brand"),
    ("number", "number"),
    ("expMonth", "expiry_month"),
    ("expYear", "expiry_year"),
    ("code", "code"),
)
_BITWARDEN_IDENTITY_FIELDS = (
    ("title", "title"),
    ("firstName", "first_name"),
    ("middleName", "middle_name"),
    ("lastName", "last_name"),
    ("company", "company"),
    ("email", "email"),
    ("phone", "phone"),
    ("address1", "address_1"),
    ("address2", "address_2"),
    ("address3", "address_3"),
    ("city", "city"),
    ("state", "state"),
    ("postalCode", "postal_code"),
    ("country", "country"),
    ("ssn", "ssn"),
    ("passportNumber", "passport_number"),
    ("licenseNumber", "license_number"),
)
_BITWARDEN_SSH_FIELDS = (("privateKey", "private_key"), ("publicKey", "public_key"), ("keyFingerprint", "fingerprint"))


def _bitwarden_folders(document: Dict[str, Any], what: str) -> Dict[str, str]:
    folders: Dict[str, str] = {}
    for number, folder in enumerate(_array(document.get("folders"), what, "folders"), start=1):
        where = f"{what}: folder {number}"
        folder = _object(folder, where, "it")
        folder_id = folder.get("id")
        if isinstance(folder_id, str):
            folders[folder_id] = _text(folder, "name", where)
    return folders


def _bitwarden_history(raw: Any, where: str) -> List[Dict[str, Any]]:
    history: List[Dict[str, Any]] = []
    for number, item in enumerate(_array(raw, where, "passwordHistory"), start=1):
        place = f"{where}, password history item {number}"
        item = _object(item, place, "it")
        password = _text(item, "password", place)
        if password:
            history.append({"password": password, "retired": _iso_time(item.get("lastUsedDate")) or 0})
    return history[:_HISTORY_KEEP]


def _bitwarden_fields(raw: Any, where: str, fields: _Fields) -> None:
    for number, item in enumerate(_array(raw, where, "fields"), start=1):
        place = f"{where}, custom field {number}"
        item = _object(item, place, "it")
        if item.get("type") == _BITWARDEN_LINKED_FIELD:
            continue  # points at another field of the item; it holds no value of its own
        fields.add(_text(item, "name", place) or "field", _text(item, "value", place))


def _bitwarden_item(item: Any, number: int, what: str, folders: Dict[str, str]) -> ImportedEntry:
    where = f"{what}: item {number}"
    if not isinstance(item, dict):
        raise UsageError(f"{where} is not an object")
    item_type = item.get("type", _BITWARDEN_LOGIN)
    if not _is_int(item_type):
        raise UsageError(f"{where}: type is not a number")
    fields = _Fields()
    username = password = url = totp = ""
    login = _object(item.get("login"), where, "login")
    if login:
        username = _text(login, "username", where)
        password = _text(login, "password", where)
        totp = _text(login, "totp", where).strip()
        addresses = []
        for index, uri in enumerate(_array(login.get("uris"), where, "uris"), start=1):
            value = _text(_object(uri, f"{where}, address {index}", "it"), "uri", where).strip()
            if value:
                addresses.append(value)
        if addresses:
            url = addresses[0]
            for index, extra in enumerate(addresses[1:], start=2):
                fields.add(f"url_{index}", extra)
    sections = (
        ("card", _BITWARDEN_CARD_FIELDS),
        ("identity", _BITWARDEN_IDENTITY_FIELDS),
        ("sshKey", _BITWARDEN_SSH_FIELDS),
    )
    for key, names in sections:
        section = _object(item.get(key), where, key)
        for source, target in names:
            fields.add(target, _text(section, source, where))
        if key == "identity" and not username:
            username = _text(section, "username", where)
    _bitwarden_fields(item.get("fields"), where, fields)
    folder_id = item.get("folderId")
    tags = [folders[folder_id]] if isinstance(folder_id, str) and folder_id in folders else []
    created = _iso_time(item.get("creationDate"))
    modified = _iso_time(item.get("revisionDate"))
    return ImportedEntry(
        name=_entry_name(_text(item, "name", where), url, username),
        username=username,
        password=password,
        url=url,
        notes=_text(item, "notes", where),
        totp=totp,
        tags=tags,
        fields=fields.values,
        kind="login" if item_type == _BITWARDEN_LOGIN else "secret",
        created=created if created is not None else modified,
        modified=modified if modified is not None else created,
        history=_bitwarden_history(item.get("passwordHistory"), where),
        origin=f"item {number}",
    )


def _parse_bitwarden_json(document: Any, what: str) -> List[ImportedEntry]:
    if not isinstance(document, dict):
        raise UsageError(f"{what} is not a Bitwarden export (it is not a JSON object)")
    if document.get("encrypted") is True:
        raise UsageError(
            f"{what} is an encrypted Bitwarden export. Export again and choose the unencrypted .json or .csv format"
        )
    items = document.get("items")
    if not isinstance(items, list):
        raise UsageError(f"{what} is not a Bitwarden export (it has no list of items)")
    folders = _bitwarden_folders(document, what)
    return [_bitwarden_item(item, number, what, folders) for number, item in enumerate(items, start=1)]


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CsvSpec:
    """How one exporter's CSV is laid out: the columns that mean something, by what they hold."""

    label: str
    columns: Dict[str, Tuple[str, ...]]
    required: Tuple[str, ...] = ()
    ignored: FrozenSet[str] = frozenset()
    extras_as_fields: bool = True
    detect_delimiter: bool = False


#: Columns exporters add that say nothing about the secret: neither imported nor kept as custom fields.
_NOISE = frozenset(
    {
        "favorite", "favorite status", "archived status", "reprompt", "icon", "guid", "httprealm",
        "formactionorigin", "timecreated", "timelastused", "timepasswordchanged", "last modified",
        "created", "modified", "type", "collections",
    }
)

_GENERIC = _CsvSpec(
    label="CSV",
    columns={
        "name": ("name", "title"),
        "username": ("username", "login", "user", "user name", "login_username", "email", "e-mail"),
        "password": ("password", "pass", "passwd", "login_password"),
        "url": ("url", "website", "uri", "urls", "site", "web site", "login_uri"),
        "notes": ("notes", "note", "comments", "comment", "extra"),
        "totp": ("totp", "otp", "otpauth", "one-time password", "login_totp", "2fa", "mfa"),
        "tags": ("tags", "tag", "labels", "label", "folder", "group", "category"),
        "kind": ("kind",),
        "created": ("created", "creationdate", "timecreated"),
        "modified": ("last modified", "modified", "revisiondate", "timepasswordchanged"),
    },
    ignored=_NOISE,
    detect_delimiter=True,
)

_CHROME = _CsvSpec(
    label="Chrome CSV",
    columns={"name": ("name",), "url": ("url",), "username": ("username",), "password": ("password",),
             "notes": ("note", "notes")},
    required=("url", "username", "password"),
)

_FIREFOX = _CsvSpec(
    label="Firefox CSV",
    columns={
        "url": ("url",),
        "username": ("username",),
        "password": ("password",),
        "created": ("timecreated",),
        "modified": ("timepasswordchanged",),
    },
    required=("url", "username", "password"),
    ignored=_NOISE,
)

_ONEPASSWORD = _CsvSpec(
    label="1Password CSV",
    columns={
        "name": ("title", "name"),
        "url": ("website", "url", "urls", "login_uri"),
        "username": ("username", "login_username"),
        "password": ("password", "login_password"),
        "totp": ("one-time password", "otpauth", "otp", "totp"),
        "tags": ("tags",),
        "notes": ("notes", "notesplain", "note"),
    },
    required=("name",),
    ignored=_NOISE,
)

_BITWARDEN_CSV = _CsvSpec(
    label="Bitwarden CSV",
    columns={
        "name": ("name",),
        "url": ("login_uri",),
        "username": ("login_username",),
        "password": ("login_password",),
        "totp": ("login_totp",),
        "notes": ("notes",),
        "tags": ("folder", "collections"),
        "bitwarden_fields": ("fields",),
        "bitwarden_type": ("type",),
    },
    required=("name",),
    ignored=_NOISE,
)


def _csv_reader(text: str, delimiter: str) -> Any:
    return csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)


def _csv_text(text: str, what: str) -> str:
    if "\x00" in text:
        raise UsageError(
            f"{what} contains NUL characters, so it is not a CSV text file "
            "(a UTF-16 file without a byte order mark looks like this); export it again as UTF-8"
        )
    return text


def _delimiter(text: str) -> str:
    """The separator a generic CSV uses, read from its first line: a comma, a semicolon or a tab."""
    first = text.split("\n", 1)[0]
    counts = {separator: first.count(separator) for separator in (",", ";", "\t")}
    best = max(counts, key=lambda separator: counts[separator])
    return best if counts[best] else ","


def _csv_rows(text: str, what: str, delimiter: str) -> List[Tuple[int, List[str]]]:
    """``(row number, cells)`` of every record; the header is row 1, as a spreadsheet counts."""
    previous = csv.field_size_limit()
    csv.field_size_limit(MAX_FILE_BYTES)
    rows: List[Tuple[int, List[str]]] = []
    try:
        reader = _csv_reader(text, delimiter)
        number = 0
        while True:
            try:
                row = next(reader)
            except StopIteration:
                break
            except csv.Error as exc:
                raise UsageError(
                    f"{what}: row {number + 1} (line {reader.line_num}) cannot be read as CSV: {exc}"
                ) from None
            number += 1
            rows.append((number, row))
    finally:
        csv.field_size_limit(previous)
    return rows


def _first_row(text: str, delimiter: str) -> Optional[List[str]]:
    """The first record that is not blank, for telling formats apart; None if there is none or it is unreadable."""
    previous = csv.field_size_limit()
    csv.field_size_limit(MAX_FILE_BYTES)
    try:
        for row in _csv_reader(text, delimiter):
            if any(cell.strip() for cell in row):
                return row
    except csv.Error:
        return None
    finally:
        csv.field_size_limit(previous)
    return None


def _column_names(header: Sequence[str]) -> List[str]:
    return [cell.strip().lstrip("﻿").strip().lower() for cell in header]


class _Layout:
    """Which column holds what, for one header under one spec."""

    def __init__(self, header: List[str], spec: _CsvSpec, what: str) -> None:
        names = _column_names(header)
        self.width = len(header)
        self.columns: Dict[str, int] = {}
        self.tag_columns: List[int] = []
        used: Set[int] = set()
        for key, synonyms in spec.columns.items():
            for synonym in synonyms:
                if synonym in names and names.index(synonym) not in used:
                    index = names.index(synonym)
                    if key == "tags":
                        self.tag_columns.append(index)
                        used.add(index)
                        continue
                    self.columns[key] = index
                    used.add(index)
                    break
        missing = [key for key in spec.required if key not in self.columns]
        if missing:
            raise UsageError(
                f"{what} is not a {spec.label} export: its header has no column for {', '.join(missing)}"
            )
        if not ({"name", "username", "password", "url"} & set(self.columns)):
            raise UsageError(
                f"{what}: the CSV header names no column IronDome knows "
                "(name or title, username or login, password, url or website, notes, totp, tags)"
            )
        self.extras: List[Tuple[int, str]] = []
        for index, (name, original) in enumerate(zip(names, header)):
            if index in used or not name or name in spec.ignored or not spec.extras_as_fields:
                continue
            label = original.strip().lstrip("﻿").strip()
            if name.startswith(_CSV_FIELD_PREFIX) and len(label) > len(_CSV_FIELD_PREFIX):
                label = label[len(_CSV_FIELD_PREFIX):]
            self.extras.append((index, label))

    def cell(self, row: List[str], key: str) -> str:
        index = self.columns.get(key)
        return row[index] if index is not None and index < len(row) else ""


def _bitwarden_csv_fields(text: str, fields: _Fields) -> None:
    """Bitwarden writes custom fields into one cell, one ``name: value`` per line."""
    for line in text.splitlines():
        if not line.strip():
            continue
        name, separator, value = line.partition(":")
        if separator:
            fields.add(name.strip() or "field", value[1:] if value.startswith(" ") else value)
        else:
            fields.add("field", line)


def _csv_entry(row: List[str], number: int, layout: _Layout, spec: _CsvSpec) -> Optional[ImportedEntry]:
    fields = _Fields()
    address = layout.cell(row, "url")
    if spec is _BITWARDEN_CSV:
        # Bitwarden puts every address of an item into one cell, separated by commas: each is trimmed.
        urls = [part.strip() for part in re.split(r"[,\n]", address)]
        urls = [url for url in urls if url]
    else:
        urls = [address] if address else []  # kept exactly as it is, as the vault keeps it
    url = urls[0] if urls else ""
    for index, extra in enumerate(urls[1:], start=2):
        fields.add(f"url_{index}", extra)
    for index, label in layout.extras:
        if index < len(row):
            fields.add(label, row[index])
    if spec is _BITWARDEN_CSV:
        _bitwarden_csv_fields(layout.cell(row, "bitwarden_fields"), fields)
    username = layout.cell(row, "username")
    password = layout.cell(row, "password")
    notes = layout.cell(row, "notes")
    totp = layout.cell(row, "totp").strip()
    name = layout.cell(row, "name")
    if not any((name.strip(), username, password, url, notes, totp, fields.values)):
        return None
    tags: List[str] = []
    for index in layout.tag_columns:
        if index < len(row):
            tags.extend(_split_tags(row[index]))
    kind = "login"
    if spec is _BITWARDEN_CSV and layout.cell(row, "bitwarden_type").strip().lower() == "note":
        kind = "secret"
    elif layout.cell(row, "kind").strip().lower() == "secret":
        kind = "secret"
    created = _time_cell(layout.cell(row, "created"))
    modified = _time_cell(layout.cell(row, "modified"))
    return ImportedEntry(
        name=_entry_name(name, url, username),
        username=username,
        password=password,
        url=url,
        notes=notes,
        totp=totp,
        tags=tags,
        fields=fields.values,
        kind=kind,
        created=created if created is not None else modified,
        modified=modified if modified is not None else created,
        origin=f"row {number}",
    )


def _parse_csv(text: str, spec: _CsvSpec, what: str) -> List[ImportedEntry]:
    text = _csv_text(text, what)
    delimiter = _delimiter(text) if spec.detect_delimiter else ","
    rows = [(number, row) for number, row in _csv_rows(text, what, delimiter) if any(cell.strip() for cell in row)]
    if not rows:
        raise UsageError(f"{what} is empty: there is not even a header row")
    header_number, header = rows[0]
    layout = _Layout(header, spec, what)
    entries: List[ImportedEntry] = []
    for number, row in rows[1:]:
        if len(row) > layout.width and any(cell.strip() for cell in row[layout.width:]):
            raise UsageError(
                f"{what}: row {number} has {len(row)} cells, but the header (row {header_number}) "
                f"names {layout.width} columns"
            )
        entry = _csv_entry(row, number, layout, spec)
        if entry is not None:
            entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Telling formats apart
# ---------------------------------------------------------------------------

_GENERIC_NAMES = frozenset(name for synonyms in _GENERIC.columns.values() for name in synonyms)


def _sniff(text: str, what: str) -> str:
    if _VAULT_MARKER.search(text[:_HEAD_BYTES]):
        return FORMAT_IRONDOME
    if text.lstrip().startswith(("{", "[")):
        document = _load_json(text, what)
        if isinstance(document, dict):
            if document.get("format") == "irondome-vault":
                return FORMAT_IRONDOME
            if document.get("format") == EXPORT_FORMAT:
                return "json"
            if isinstance(document.get("items"), list):
                return "bitwarden"
        raise UsageError(
            f"{what} is JSON, but neither an IronDome export nor Bitwarden's unencrypted JSON; "
            "choose the format with --format"
        )
    header = _first_row(_csv_text(text, what), _delimiter(text))
    if header is None:
        raise UsageError(f"{what} is empty, or not a CSV file IronDome can read; choose the format with --format")
    names = _column_names(header)
    present = set(names)
    if {"login_uri", "login_username", "login_password"} <= present:
        return "bitwarden"
    if names[:3] == ["url", "username", "password"] and present & {"httprealm", "formactionorigin", "guid"}:
        return "firefox"
    if {"name", "url", "username", "password"} <= present <= {"name", "url", "username", "password", "note"}:
        return "chrome"
    if "title" in present and present & {"one-time password", "favorite status", "archived status"}:
        return "1password"
    if present & _GENERIC_NAMES:
        return "csv"
    raise UsageError(f"{what} is not an export format IronDome recognises; choose the format with --format")


def detect_format(source: Source) -> str:
    """Which of :data:`FORMATS` *source* is in.

    *source* is a path (``pathlib.Path`` or any ``os.PathLike``), which is
    read from disk, or the content itself as ``str`` or ``bytes``. A portable
    backup is recognised from its first 64 KiB, whatever its size; anything
    else must be at most 50 MB. Raises :class:`UsageError` when the format
    cannot be told.
    """
    what = _what(source)
    if isinstance(source, os.PathLike):
        if _VAULT_MARKER_BYTES.search(_read_head(Path(source))):
            return FORMAT_IRONDOME
    elif isinstance(source, (bytes, bytearray)) and _VAULT_MARKER_BYTES.search(bytes(source[:_HEAD_BYTES])):
        return FORMAT_IRONDOME
    return _sniff(_text_of(source, what), what)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse(source: Source, fmt: str = "auto") -> List[ImportedEntry]:
    """Read every entry of an export.

    *source* is a path or the content itself (see :func:`detect_format`);
    *fmt* is one of :data:`FORMATS` other than ``irondome``, or ``auto``.
    Returns the entries in the order the file holds them, each with a name
    no other entry of the file has. Raises :class:`UsageError`, and nothing
    else, for anything that cannot be read.
    """
    if fmt != "auto" and fmt not in FORMATS:
        raise UsageError(f"unknown export format {fmt!r}; choose one of: auto, {', '.join(FORMATS)}")
    what = _what(source)
    if fmt == "auto":
        fmt = detect_format(source)
    if fmt == FORMAT_IRONDOME:
        raise UsageError(f"{what} is an IronDome portable backup: it is opened with its password, not parsed")
    text = _text_of(source, what)
    if fmt == "json":
        entries = _parse_irondome_json(_load_json(text, what), what)
    elif fmt == "bitwarden" and text.lstrip().startswith(("{", "[")):
        entries = _parse_bitwarden_json(_load_json(text, what), what)
    else:
        spec = {
            "csv": _GENERIC,
            "bitwarden": _BITWARDEN_CSV,
            "1password": _ONEPASSWORD,
            "chrome": _CHROME,
            "firefox": _FIREFOX,
        }[fmt]
        entries = _parse_csv(text, spec, what)
    for entry in entries:
        _storable(entry)
    _disambiguate(entries)
    return entries


def _json_entry(entry: ImportedEntry) -> Dict[str, Any]:
    return {
        "name": entry.name,
        "kind": entry.kind,
        "username": entry.username,
        "password": entry.password,
        "url": entry.url,
        "notes": entry.notes,
        "totp": entry.totp,
        "tags": list(entry.tags),
        "fields": dict(entry.fields),
        "aliases": {alias: target for alias, target in entry.aliases},
        "history": [
            {"password": item.get("password", ""), "retired": item.get("retired", 0)} for item in entry.history
        ],
        "created": entry.created,
        "modified": entry.modified,
    }


def _dump_json(entries: Sequence[ImportedEntry]) -> bytes:
    document = {"format": EXPORT_FORMAT, "version": EXPORT_VERSION, "entries": [_json_entry(e) for e in entries]}
    try:
        return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    except UnicodeEncodeError:  # text that is not valid Unicode: written as escapes, which read back exactly
        return (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def _dump_csv(entries: Sequence[ImportedEntry]) -> bytes:
    custom = sorted({name for entry in entries for name in entry.fields})
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(list(_CSV_COLUMNS) + [_CSV_FIELD_PREFIX + name for name in custom])
    for entry in entries:
        row = [
            entry.name, entry.kind, entry.username, entry.password, entry.url, entry.notes, entry.totp,
            ", ".join(entry.tags),
        ] + [entry.fields.get(name, "") for name in custom]
        for cell in row:
            if "\x00" in cell:
                raise UsageError(f"{entry.name!r} holds a NUL character, which a CSV file cannot carry; export as JSON")
            try:
                cell.encode("utf-8")
            except UnicodeEncodeError:
                raise UsageError(f"{entry.name!r} holds text that is not valid Unicode; export as JSON") from None
        writer.writerow(row)
    return buffer.getvalue().encode("utf-8")


def dump(entries: Sequence[ImportedEntry], fmt: str) -> bytes:
    """Write *entries* in one of :data:`PLAINTEXT_FORMATS`, every value unencrypted.

    ``json`` holds everything an :class:`ImportedEntry` holds and reads back
    exactly with ``parse(..., "json")``. ``csv`` has the columns ``name,
    kind, username, password, url, notes, totp, tags`` and one ``field.NAME``
    column per custom field name; it reads back with ``parse(..., "csv")``
    without the history, the aliases, the created and modified times, and
    the custom fields that have no value (an empty cell is a field the entry
    does not have). The result is UTF-8; the caller writes it to a file only
    it can read.
    """
    if fmt == "json":
        return _dump_json(entries)
    if fmt == "csv":
        return _dump_csv(entries)
    raise UsageError(f"IronDome writes plaintext exports as {' or '.join(PLAINTEXT_FORMATS)}, not {fmt!r}")
