"""The vault file and the unlocked vault.

On disk a vault is one JSON document (``vault.irondome``)::

    {
      "format": "irondome-vault", "version": 4,
      "vault_id": <16 random bytes>,          public, binds every ciphertext
      "created": <unix time>,
      "generation": <counter>,                bumped on every write
      "keyslots": [ ... ],                    see irondome.keys
      "index": <sealed>,                      names, usernames, URLs, tags, aliases
      "records": { <entry id>: <sealed> }     one secret record per entry
    }

Everything about an entry is encrypted, including its name. The index is one
AES-256-GCM record; each entry's secret (password, TOTP seed, notes, custom
fields, password history) is its own record under its own key, so reading one
password decrypts one record and nothing else.

Keys, all derived from the vault key with HKDF-SHA256::

    index key        = HKDF(vault key, "irondome/v4/index",          salt = vault id)
    entry key (id)   = HKDF(vault key, "irondome/v4/entry\\0" + id,   salt = vault id)

Associated data ties each ciphertext to its place, so records cannot be
swapped, replayed or rolled back individually:

    index   "irondome/v4/index\\0"  || vault id || generation
    record  "irondome/v4/entry\\0"  || vault id || entry id || 0 || revision

The index stores every entry's current revision; a record restored from an
older copy of the file fails authentication. Plaintexts are length-prefixed
and zero-padded to fixed blocks, so ciphertext sizes do not reveal password
lengths. Writes are atomic (temp file, fsync, rename, fsync directory) and
serialised by a lock file; the previous file is kept as a snapshot first.

What the format does not do: detect a rollback of the *whole* file to an
earlier state (that needs a monotonic counter outside the file), or hide the
number of entries.
"""

from __future__ import annotations

import json
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from irondome import __version__, paths
from irondome.crypto import DecryptError, b64d, b64e, hkdf, open_sealed, pad, seal, unpad
from irondome.errors import NotFoundError, UsageError, VaultError
from irondome.keys import VAULT_ID_LEN, Keyslot
from irondome.secmem import SecureBuffer, wipe_bytes

__all__ = [
    "FORMAT",
    "VERSION",
    "FIELDS",
    "AGENT_POLICIES",
    "Entry",
    "Secret",
    "Alias",
    "VaultFile",
    "Vault",
    "validate_name",
    "fold_name",
    "validate_alias",
    "validate_field_name",
    "without_control",
    "vault_exists",
]

FORMAT = "irondome-vault"
VERSION = 4

_LABEL_INDEX = b"irondome/v4/index"
_LABEL_ENTRY = b"irondome/v4/entry\x00"
_RECORD_BLOCK = 256
_INDEX_BLOCK = 1024
_HISTORY_LIMIT = 5
_DEFAULT_SNAPSHOTS = 10
_MAX_SLOTS = 32
_MAX_INT = 2**63 - 1  # every counter and timestamp fits a signed 64-bit field

#: Built-in fields a reference can name. Anything else is a custom field.
FIELDS = ("password", "username", "url", "notes", "totp", "name")
#: What an AI agent approved by Touch ID may do with an entry.
AGENT_POLICIES = ("deny", "use", "reveal")
_KINDS = ("login", "secret")

# Always used with fullmatch: "$" would also accept a trailing newline.
_ALIAS = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}")
_ENTRY_ID = re.compile(r"[0-9a-f]{32}")
_FIELD_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_SNAPSHOT = re.compile(r"vault-(\d{10,})\.irondome")
_ONE_MEANING = (
    "A reference must mean one thing: choose another name, or first rename or remove what it clashes with "
    "(irondome edit NAME --name NEW, irondome alias rm ALIAS)"
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _is_control(char: str) -> bool:
    code = ord(char)
    return code < 32 or 0x7F <= code <= 0x9F or code in (0x2028, 0x2029)


def _has_control(text: str) -> bool:
    """True for C0 and C1 control characters, DEL, and the Unicode line and paragraph separators."""
    return any(_is_control(char) for char in text)


def without_control(text: str) -> str:
    """*text* without the characters an entry name, username, URL or tag may not hold.

    Those are the C0 and C1 control characters, DEL and the Unicode line and
    paragraph separators: on a terminal they are escape sequences and line
    breaks, not text. Importers use this to keep an entry the vault would
    otherwise refuse.
    """
    return "".join(char for char in text if not _is_control(char))


def fold_name(name: str) -> str:
    """*name* as names are compared: one Unicode form, without regard to letter case.

    "café" typed with one code point for the accented letter and typed with two (what macOS file names
    and many pastes carry) is one name, as "GitHub" and "github" are.
    """
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", name).casefold())


def validate_name(name: Any) -> str:
    """Entry names are free text, but never empty, padded or holding control characters.

    Returns the name in the one Unicode form (NFC) in which names are stored.
    """
    if not isinstance(name, str) or not name:
        raise UsageError("an entry needs a name")
    name = unicodedata.normalize("NFC", name)
    if name != name.strip():
        raise UsageError("an entry name cannot start or end with whitespace")
    if len(name) > 200:
        raise UsageError("an entry name cannot be longer than 200 characters")
    if _has_control(name):
        raise UsageError("an entry name cannot contain control characters")
    return name


def validate_alias(alias: Any) -> str:
    """Aliases are identifiers: usable as an environment variable or in a URL."""
    if not isinstance(alias, str) or not _ALIAS.fullmatch(alias):
        raise UsageError(
            "an alias must start with a letter or underscore and contain only letters, "
            "digits, '_', '.' and '-' (at most 128 characters)"
        )
    return alias


def _text(value: Any, what: str, limit: int = 100_000) -> str:
    if not isinstance(value, str):
        raise VaultError(f"{what} is not text")
    if len(value) > limit:
        raise VaultError(f"{what} is too long")
    return value


def _integer(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _MAX_INT:
        raise VaultError(f"{what} is not a non-negative integer")
    return value


def _json_int(text: str) -> int:
    """``json`` hook for the vault file: refuse absurd integers before converting them.

    Converting a decimal string is quadratic in its length on the older
    interpreters IronDome supports, so a file holding a million-digit number
    would stall the program instead of being rejected.
    """
    if len(text) > 19:
        raise ValueError("integer out of range")
    return int(text)


def _argument_text(value: Any, what: str, limit: int = 100_000) -> str:
    if not isinstance(value, str):
        raise UsageError(f"{what} must be text")
    if len(value) > limit:
        raise UsageError(f"{what} is too long")
    return value


def _shown_text(value: Any, what: str) -> str:
    """A username or URL: text that listings print, so without control characters (escape sequences)."""
    text = _argument_text(value, what)
    if _has_control(text):
        raise UsageError(f"{what} cannot contain control characters (such as escape sequences or line breaks)")
    return text


def _folded_field(tail: str, fields: Iterable[Any]) -> bool:
    """Whether *tail*, in any case, is a built-in field or one of *fields*: a ``name/tail`` reference can reach it."""
    folded = tail.casefold()
    return folded in FIELDS or any(isinstance(name, str) and name.casefold() == folded for name in fields)


def _argument_time(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _MAX_INT:
        raise UsageError(f"{what} must be a whole number of seconds since 1970")
    return value


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass
class Entry:
    """Everything about an entry except its secrets. Lives in the encrypted index."""

    id: str
    name: str
    username: str = ""
    url: str = ""
    tags: List[str] = field(default_factory=list)
    kind: str = "login"
    created: int = 0
    modified: int = 0
    rev: int = 0
    has_totp: bool = False
    agent: str = "deny"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "username": self.username,
            "url": self.url,
            "tags": list(self.tags),
            "kind": self.kind,
            "created": self.created,
            "modified": self.modified,
            "rev": self.rev,
            "has_totp": self.has_totp,
            "agent": self.agent,
        }

    @classmethod
    def from_dict(cls, entry_id: str, data: Any) -> "Entry":
        if not isinstance(entry_id, str) or not _ENTRY_ID.fullmatch(entry_id) or not isinstance(data, dict):
            raise VaultError("index entry is malformed")
        tags = data.get("tags", [])
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise VaultError("entry tags are malformed")
        kind = data.get("kind", "login")
        agent = data.get("agent", "deny")
        if kind not in _KINDS or agent not in AGENT_POLICIES:
            raise VaultError("entry kind or agent policy is unknown")
        has_totp = data.get("has_totp", False)
        if not isinstance(has_totp, bool):
            raise VaultError("entry TOTP flag is malformed")
        return cls(
            id=entry_id,
            name=_text(data.get("name"), "entry name", 200),
            username=_text(data.get("username", ""), "entry username"),
            url=_text(data.get("url", ""), "entry URL"),
            tags=list(tags),
            kind=kind,
            created=_integer(data.get("created", 0), "entry creation time"),
            modified=_integer(data.get("modified", 0), "entry modification time"),
            rev=_integer(data.get("rev", 0), "entry revision"),
            has_totp=has_totp,
            agent=agent,
        )


@dataclass
class Secret:
    """The secret half of an entry. Lives in its own encrypted record."""

    password: str = ""
    totp: Optional[Dict[str, Any]] = None
    notes: str = ""
    fields: Dict[str, str] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "password": self.password,
            "totp": self.totp,
            "notes": self.notes,
            "fields": dict(self.fields),
            "history": list(self.history),
        }

    @classmethod
    def from_dict(cls, data: Any) -> "Secret":
        if not isinstance(data, dict):
            raise VaultError("secret record is malformed")
        totp = data.get("totp")
        if totp is not None and not isinstance(totp, dict):
            raise VaultError("TOTP settings are malformed")
        fields = data.get("fields", {})
        if not isinstance(fields, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in fields.items()
        ):
            raise VaultError("custom fields are malformed")
        history = data.get("history", [])
        if not isinstance(history, list) or not all(isinstance(item, dict) for item in history):
            raise VaultError("password history is malformed")
        return cls(
            password=_text(data.get("password", ""), "password"),
            totp=totp,
            notes=_text(data.get("notes", ""), "notes", 1_000_000),
            fields=dict(fields),
            history=list(history),
        )


@dataclass
class Alias:
    """A name an agent or a script uses instead of the secret: entry + field."""

    entry: str
    field: str = "password"


# ---------------------------------------------------------------------------
# The file
# ---------------------------------------------------------------------------


@dataclass
class VaultFile:
    """A parsed vault file. Holds only ciphertext and public parameters."""

    vault_id: bytes
    created: int
    generation: int
    slots: List[Keyslot]
    index: str
    records: Dict[str, str]

    def to_bytes(self) -> bytes:
        document = {
            "format": FORMAT,
            "version": VERSION,
            "vault_id": b64e(self.vault_id),
            "created": self.created,
            "generation": self.generation,
            "keyslots": [slot.to_dict() for slot in self.slots],
            "index": self.index,
            "records": self.records,
        }
        return (json.dumps(document, indent=1, sort_keys=True) + "\n").encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "VaultFile":
        try:
            document = json.loads(data.decode("utf-8"), parse_int=_json_int)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise VaultError("this is not an IronDome vault file (unreadable JSON)") from None
        if not isinstance(document, dict) or document.get("format") != FORMAT:
            raise VaultError("this is not an IronDome vault file")
        version = document.get("version")
        if not isinstance(version, int) or isinstance(version, bool):
            raise VaultError("the vault file has no version")
        if version > VERSION:
            raise VaultError(
                f"this vault was written by a newer IronDome (format {version}); upgrade to open it"
            )
        if version != VERSION:
            raise VaultError(f"unsupported vault format {version}; run: irondome migrate")
        vault_id = b64d(document.get("vault_id"), what="vault id")
        if len(vault_id) != VAULT_ID_LEN:
            raise VaultError("vault id has the wrong length")
        raw_slots = document.get("keyslots")
        if not isinstance(raw_slots, list) or not raw_slots or len(raw_slots) > _MAX_SLOTS:
            raise VaultError("the vault file has no usable keyslots")
        slots = [Keyslot.from_dict(item) for item in raw_slots]
        if len({slot.id for slot in slots}) != len(slots):
            raise VaultError("the vault file has duplicate keyslots")
        records = document.get("records")
        if not isinstance(records, dict):
            raise VaultError("the vault file has no record table")
        for entry_id, sealed in records.items():
            if not isinstance(entry_id, str) or not _ENTRY_ID.fullmatch(entry_id):
                raise VaultError("the vault file has a malformed record id")
            b64d(sealed, what="record")
        index = document.get("index")
        if not isinstance(index, str):
            raise VaultError("the vault file has no index")
        b64d(index, what="index")
        return cls(
            vault_id=vault_id,
            created=_integer(document.get("created", 0), "vault creation time"),
            generation=_integer(document.get("generation", 0), "vault generation"),
            slots=slots,
            index=index,
            records=dict(records),
        )

    @classmethod
    def load(cls, path: Union[str, Path, None] = None) -> "VaultFile":
        target = Path(path) if path is not None else paths.vault_file()
        try:
            return cls.from_bytes(paths.read_file(target))
        except FileNotFoundError:
            raise VaultError(f"there is no vault at {target}. Create one with: irondome init") from None
        except OSError as exc:
            raise VaultError(f"cannot read the vault at {target}: {exc.strerror or exc}") from None


def vault_exists(path: Union[str, Path, None] = None) -> bool:
    return (Path(path) if path is not None else paths.vault_file()).is_file()


def _checked_bytes(file: VaultFile) -> bytes:
    """Serialise *file*, refusing to produce anything :meth:`VaultFile.from_bytes` would reject."""
    try:
        payload = file.to_bytes()
        VaultFile.from_bytes(payload)
    except (TypeError, ValueError) as exc:
        raise VaultError(f"refusing to write a vault that could not be opened again: {exc}") from None
    except VaultError as exc:
        raise VaultError(f"refusing to write a vault that could not be opened again: {exc}") from None
    return payload


def _parse_index(document: Any, records: Dict[str, str]) -> Tuple[Dict[str, Entry], Dict[str, Alias], Dict[str, Any]]:
    """Validate a decrypted index against the record table it describes."""
    if not isinstance(document, dict):
        raise VaultError("the vault index is malformed")
    raw_entries = document.get("entries", {})
    raw_aliases = document.get("aliases", {})
    meta = document.get("meta", {})
    if not isinstance(raw_entries, dict) or not isinstance(raw_aliases, dict) or not isinstance(meta, dict):
        raise VaultError("the vault index is malformed")
    entries = {entry_id: Entry.from_dict(entry_id, data) for entry_id, data in raw_entries.items()}
    aliases: Dict[str, Alias] = {}
    for name, data in raw_aliases.items():
        if (
            not isinstance(name, str)
            or not _ALIAS.fullmatch(name)
            or not isinstance(data, dict)
            or not isinstance(data.get("entry"), str)
            or data["entry"] not in entries
            or not isinstance(data.get("field"), str)
        ):
            raise VaultError("the vault index has a malformed alias")
        aliases[name] = Alias(entry=data["entry"], field=data["field"])
    missing = [entry.name for entry_id, entry in entries.items() if entry_id not in records]
    if missing:
        raise VaultError(f"the vault file is missing the secret record for: {', '.join(sorted(missing))}")
    return entries, aliases, meta


def _encode_secret(secret: Any) -> bytes:
    """Serialise a secret record, refusing anything that could not be read back."""
    if not isinstance(secret, Secret):
        raise UsageError("a secret record is required")
    _check_custom_fields(secret)
    try:
        encoded = json.dumps(secret.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise UsageError(f"this secret cannot be stored: {exc}") from None
    try:
        Secret.from_dict(json.loads(encoded.decode("utf-8")))
    except VaultError as exc:
        wipe_bytes(encoded)
        raise UsageError(f"this secret cannot be stored: {exc}") from None
    return encoded


# ---------------------------------------------------------------------------
# The unlocked vault
# ---------------------------------------------------------------------------


class Vault:
    """An unlocked vault. Close it (or use ``with``) so the keys are wiped."""

    def __init__(self, file: VaultFile, vault_key: SecureBuffer, path: Union[str, Path, None] = None) -> None:
        self.file = file
        self.path = Path(path) if path is not None else paths.vault_file()
        self._key: Optional[SecureBuffer] = vault_key
        self._index_key: Optional[SecureBuffer] = hkdf(vault_key, info=_LABEL_INDEX, salt=file.vault_id)
        self._loaded_generation = file.generation
        self.entries: Dict[str, Entry] = {}
        self.aliases: Dict[str, Alias] = {}
        self.meta: Dict[str, Any] = {}
        try:
            self._load_index()
        except BaseException:
            self.close()
            raise

    # -- lifecycle ------------------------------------------------------------

    @classmethod
    def create(
        cls,
        vault_key: SecureBuffer,
        slots: List[Keyslot],
        vault_id: bytes,
        path: Union[str, Path, None] = None,
        *,
        overwrite: bool = False,
    ) -> "Vault":
        """Write a new, empty vault. Takes ownership of *vault_key*."""
        target = Path(path) if path is not None else paths.vault_file()
        if not slots:
            raise VaultError("a vault needs at least one keyslot")
        paths.ensure_dir(target.parent)
        now = int(time.time())
        file = VaultFile(vault_id=vault_id, created=now, generation=0, slots=list(slots), index="", records={})
        vault = cls.__new__(cls)
        vault.file = file
        vault.path = target
        vault._key = vault_key
        vault._index_key = hkdf(vault_key, info=_LABEL_INDEX, salt=vault_id)
        vault._loaded_generation = 0
        vault.entries = {}
        vault.aliases = {}
        vault.meta = {"created_by": __version__}
        try:
            with paths.file_lock(target.parent / ".lock"):
                if target.exists() and not overwrite:
                    raise VaultError(f"a vault already exists at {target}")
                file.generation = 1
                file.index = vault._seal_index(1)
                paths.write_atomic(target, _checked_bytes(file))
                vault._loaded_generation = 1
        except BaseException:
            vault.close()
            raise
        return vault

    def close(self) -> None:
        """Wipe every key this object holds. Idempotent."""
        for name in ("_index_key", "_key"):
            buffer = getattr(self, name, None)
            if buffer is not None:
                buffer.wipe()
                setattr(self, name, None)

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: S110 - a destructor must not raise, least of all during interpreter shutdown
            pass

    @property
    def vault_id(self) -> bytes:
        return self.file.vault_id

    @property
    def vault_key(self) -> SecureBuffer:
        """The vault key itself, for the few callers that wrap it (slots, sessions)."""
        if self._key is None:
            raise VaultError("the vault is locked")
        return self._key

    # -- index ----------------------------------------------------------------

    def _index_aad(self, generation: int) -> bytes:
        return _LABEL_INDEX + b"\x00" + self.file.vault_id + generation.to_bytes(8, "big")

    def _seal_index(self, generation: int) -> str:
        if self._index_key is None:
            raise VaultError("the vault is locked")
        document = {
            "entries": {entry_id: entry.to_dict() for entry_id, entry in self.entries.items()},
            "aliases": {name: {"entry": alias.entry, "field": alias.field} for name, alias in self.aliases.items()},
            "meta": self.meta,
        }
        try:
            encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
            _parse_index(json.loads(encoded.decode("utf-8")), self.file.records)
        except (TypeError, ValueError) as exc:
            raise VaultError(f"refusing to write a vault that could not be opened again: {exc}") from None
        except VaultError as exc:
            raise VaultError(f"refusing to write a vault that could not be opened again: {exc}") from None
        padded = pad(encoded, _INDEX_BLOCK)
        try:
            return b64e(seal(self._index_key, padded, self._index_aad(generation)))
        finally:
            wipe_bytes(padded)
            wipe_bytes(encoded)

    def _load_index(self) -> None:
        if self._index_key is None:
            raise VaultError("the vault is locked")
        try:
            padded = open_sealed(
                self._index_key, b64d(self.file.index, what="index"), self._index_aad(self.file.generation)
            )
        except DecryptError:
            raise VaultError("the vault index failed authentication: the file is damaged or was altered") from None
        try:
            plain = unpad(padded)
            try:
                document = json.loads(plain.decode("utf-8"))
            except (ValueError, UnicodeDecodeError, RecursionError):
                raise VaultError("the vault index is unreadable") from None
            finally:
                wipe_bytes(plain)
        finally:
            wipe_bytes(padded)
        self.entries, self.aliases, self.meta = _parse_index(document, self.file.records)

    # -- lookup ---------------------------------------------------------------

    def find(self, name: str) -> Entry:
        """Find an entry by exact name, then without regard to case or Unicode form if that is unambiguous.

        Exactly as typed first: a vault written before names were stored in one form may hold a name in
        another, and typing it that way must still reach it.
        """
        for spelling in (name, unicodedata.normalize("NFC", name)):
            for entry in self.entries.values():
                if entry.name == spelling:
                    return entry
        folded = fold_name(name)
        matches = [entry for entry in self.entries.values() if fold_name(entry.name) == folded]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise UsageError(
                f"{name!r} matches several entries that differ only in case or Unicode form; use the exact name"
            )
        raise NotFoundError(f"no entry named {name!r}")

    def has_name(self, name: str) -> bool:
        folded = fold_name(name)
        return any(fold_name(entry.name) == folded for entry in self.entries.values())

    def _named(self, name: str) -> Optional[Entry]:
        """:meth:`find`, but ``None`` instead of :class:`NotFoundError`."""
        try:
            return self.find(name)
        except NotFoundError:
            return None

    def _head(self, head: str) -> Optional[Entry]:
        """The entry the part of a reference before its last ``/`` names, by alias or by name; ``None`` if neither."""
        alias = self.aliases.get(head)
        named = self._named(head)
        if alias is None:
            return named
        target = self.entries[alias.entry]
        if named is not None and named.id != target.id:
            raise UsageError(
                f"{head!r} could mean the alias {head} (which points at {target.name!r}) or the entry "
                f"{named.name!r}. IronDome does not guess which: remove the alias (irondome alias rm {head}) "
                "or rename the entry (irondome edit NAME --name NEW)"
            )
        return target

    def _holds(self, entry: Entry, field_name: str) -> bool:
        """Whether ``entry/field_name`` stands for a value: a built-in field, or a custom field *entry* has.

        Reads the entry's record only for a custom field. A record that cannot be read counts as holding
        it: this decides whether a reference has two meanings, and assuming one too many is the safe side.
        """
        if field_name in FIELDS:
            return True
        if not _FIELD_NAME.fullmatch(field_name):
            return False
        try:
            return field_name in self.read_secret(entry).fields
        except VaultError:
            return True

    def resolve(self, reference: str, default_field: str = "password") -> Tuple[Entry, str]:
        """Turn ``alias``, ``name`` or ``name/field`` into an entry and a field.

        ``irondome://`` in front is accepted and ignored, so the same string
        works in an env file. An alias may name the entry it points at (the
        alias ``MFA`` for ``mfa/totp``): then the alias says which field. A
        reference that names two different entries -- an alias and an entry
        of the same name, or an entry called ``github/password`` beside the
        field ``password`` of ``github`` -- is refused with
        :class:`UsageError`, never settled by a rule of precedence: whatever
        can add an entry or an alias (an imported file) could otherwise make
        a reference that works today hand out a value of its choosing.
        ``name/field`` with a custom field the entry does not have competes
        with nothing, so ``aws`` and ``aws/prod`` can both be entry names.
        """
        if not isinstance(reference, str) or not reference:
            raise UsageError("empty reference")
        if reference.startswith("irondome://"):
            reference = reference[len("irondome://") :]
        meanings: List[Tuple[Entry, str, str]] = []
        alias = self.aliases.get(reference)
        if alias is not None:
            target = self.entries[alias.entry]
            meanings.append((target, alias.field, f"the alias {reference} (which points at {target.name!r})"))
        named = self._named(reference)
        if named is not None:
            meanings.append((named, default_field, f"the entry {named.name!r}"))
        head, slash, tail = reference.rpartition("/")
        # A tail that cannot be a field name (it has a space, say) only matters when nothing else matches.
        if slash and head and tail and (not meanings or tail in FIELDS or _FIELD_NAME.fullmatch(tail)):
            owner = self._head(head)
            if owner is not None:
                if not meanings:
                    return owner, tail  # nothing competes: value() says so if the entry has no such field
                if self._holds(owner, tail):
                    meanings.append((owner, tail, f"the field {tail!r} of the entry {owner.name!r}"))
        if not meanings:
            raise NotFoundError(f"no entry or alias named {reference!r}")
        entry, field_name, first = meanings[0]
        for other, _, second in meanings[1:]:
            if other.id != entry.id:
                remedy = "rename one of the entries (irondome edit NAME --name NEW)"
                if alias is not None:
                    remedy = f"remove the alias (irondome alias rm {reference}) or {remedy}"
                raise UsageError(
                    f"{reference!r} could mean {first} or {second}. IronDome does not guess which: {remedy}"
                )
        return entry, field_name

    def conflict(self, name: str, fields: Iterable[str] = (), *, entry: Optional[Entry] = None) -> Optional[str]:
        """Why an entry called *name*, holding the custom *fields*, would give a reference two meanings.

        ``None`` when it would not. That happens when an alias has the name
        (compared without regard to case, as entry names are), when the name
        is ``head/field`` for an entry or alias *head* that has that field
        (``github/password`` beside ``github``), or when another entry is
        called ``name/field`` after one of the fields this one would have.
        *entry* is the entry being renamed or changed, which never conflicts
        with itself. :meth:`add` and :meth:`update` refuse what this reports;
        an importer asks first, to choose another name instead.
        """
        own = entry.id if entry is not None else None
        folded = fold_name(name)
        # The alias spelled exactly so first: it is the one the person means when two differ only in case.
        for alias_name, alias in sorted(self.aliases.items(), key=lambda item: (item[0] != name, item[0])):
            if alias.entry != own and fold_name(alias_name) == folded:
                target = self.entries.get(alias.entry)
                where = f" (it points at {target.name!r})" if target is not None else ""
                return f"the alias {alias_name}{where} has that name"
        head, slash, tail = name.rpartition("/")
        if slash and head and tail:
            # Without regard to case, as find() matches names: "GitHub/PASSWORD" is found as "github/password".
            folded_head = fold_name(head)
            heads = [item for item in self.entries.values() if fold_name(item.name) == folded_head]
            heads += [self.entries[item.entry] for alias_name, item in sorted(self.aliases.items())
                      if fold_name(alias_name) == folded_head and item.entry in self.entries]
            for owner in heads:
                if owner.id != own and (tail.casefold() in FIELDS or _folded_field(tail, self._fields_of(owner))):
                    return f"the reference {name!r} already means the field {tail!r} of {owner.name!r}"
        return self._shadowed({folded}, fields, own)

    def _fields_of(self, entry: Entry) -> List[str]:
        """The custom field names of *entry*; none for a record that cannot be read (resolve() is the backstop)."""
        try:
            return list(self.read_secret(entry).fields)
        except VaultError:
            return []

    def _shadowed(self, heads: Iterable[str], fields: Iterable[Any], own: Optional[str]) -> Optional[str]:
        """Why an entry ``head/field`` clashes: *head* one of *heads*, *field* a built-in or one of *fields*."""
        wanted = {fold_name(head) for head in heads}
        held = list(fields)
        for other in self.entries.values():
            if other.id == own:
                continue
            head, slash, tail = other.name.rpartition("/")
            if slash and head and tail and fold_name(head) in wanted and _folded_field(tail, held):
                return (
                    f"the reference {other.name!r} would then mean the field {tail!r} of {head!r} as well as "
                    f"the entry {other.name!r}"
                )
        return None

    def list(self, *, tag: Optional[str] = None, query: Optional[str] = None) -> List[Entry]:
        """Entries sorted by name, optionally filtered by tag and by a search string."""
        result: Iterable[Entry] = self.entries.values()
        if tag is not None:
            wanted = tag.casefold()
            result = [entry for entry in result if any(item.casefold() == wanted for item in entry.tags)]
        if query:
            needle = fold_name(query)
            alias_names: Dict[str, List[str]] = {}
            for name, alias in self.aliases.items():
                alias_names.setdefault(alias.entry, []).append(name)
            result = [
                entry
                for entry in result
                if needle in fold_name(entry.name)
                or needle in fold_name(entry.username)
                or needle in fold_name(entry.url)
                or any(needle in fold_name(item) for item in entry.tags)
                or any(needle in fold_name(item) for item in alias_names.get(entry.id, []))
            ]
        return sorted(result, key=lambda entry: (fold_name(entry.name), entry.name))

    def aliases_of(self, entry: Entry) -> List[str]:
        return sorted(name for name, alias in self.aliases.items() if alias.entry == entry.id)

    # -- secret records -------------------------------------------------------

    def _entry_key(self, entry_id: str) -> SecureBuffer:
        if self._key is None:
            raise VaultError("the vault is locked")
        return hkdf(self._key, info=_LABEL_ENTRY + entry_id.encode("ascii"), salt=self.file.vault_id)

    def _record_aad(self, entry_id: str, rev: int) -> bytes:
        return _LABEL_ENTRY + self.file.vault_id + entry_id.encode("ascii") + b"\x00" + rev.to_bytes(8, "big")

    def read_secret(self, entry: Entry) -> Secret:
        """Decrypt one entry's secret record.

        The revision checked is the one in this vault's own index, so a copy
        of an entry taken earlier (or from another ``Vault`` object) reads the
        same record as the entry itself.
        """
        entry = self.entries.get(entry.id, entry)
        sealed = self.file.records.get(entry.id)
        if sealed is None:
            raise VaultError(f"the secret record for {entry.name!r} is missing")
        with self._entry_key(entry.id) as key:
            try:
                padded = open_sealed(key, b64d(sealed, what="record"), self._record_aad(entry.id, entry.rev))
            except DecryptError:
                raise VaultError(
                    f"the secret record for {entry.name!r} failed authentication: "
                    "the file is damaged, was altered, or holds a stale copy of this record"
                ) from None
        try:
            plain = unpad(padded)
            try:
                return Secret.from_dict(json.loads(plain.decode("utf-8")))
            except (ValueError, UnicodeDecodeError, RecursionError):
                raise VaultError(f"the secret record for {entry.name!r} is unreadable") from None
            finally:
                wipe_bytes(plain)
        finally:
            wipe_bytes(padded)

    def _write_secret(self, entry: Entry, secret: Secret) -> None:
        """Seal *secret* as the next revision of *entry*. Changes nothing if it fails."""
        encoded = _encode_secret(secret)
        padded = pad(encoded, _RECORD_BLOCK)
        rev = entry.rev + 1
        try:
            with self._entry_key(entry.id) as key:
                sealed = b64e(seal(key, padded, self._record_aad(entry.id, rev)))
        finally:
            wipe_bytes(padded)
            wipe_bytes(encoded)
        self.file.records[entry.id] = sealed
        entry.rev = rev
        entry.has_totp = bool(secret.totp)

    def value(self, entry: Entry, field_name: str = "password") -> str:
        """The value a reference to *field_name* stands for."""
        if field_name == "name":
            return entry.name
        if field_name == "username":
            return entry.username
        if field_name == "url":
            return entry.url
        secret = self.read_secret(entry)
        if field_name == "password":
            return secret.password
        if field_name == "notes":
            return secret.notes
        if field_name == "totp":
            if not secret.totp:
                raise NotFoundError(f"{entry.name!r} has no one-time-password secret")
            from irondome import otp

            return otp.code_for(secret.totp)
        if field_name in secret.fields:
            return secret.fields[field_name]
        raise NotFoundError(f"{entry.name!r} has no field named {field_name!r}")

    # -- changes (in memory until commit) -------------------------------------

    def add(
        self,
        name: str,
        secret: Secret,
        *,
        username: str = "",
        url: str = "",
        tags: Optional[List[str]] = None,
        kind: str = "login",
        agent: str = "deny",
        entry_id: Optional[str] = None,
        created: Optional[int] = None,
        modified: Optional[int] = None,
    ) -> Entry:
        """Add an entry (in memory until :meth:`commit`).

        Its name, username, URL and tags may not hold control characters: they are listed and
        printed, and on a terminal those characters are escape sequences. Notes and values may.
        A name that would give a reference two meanings is refused (see :meth:`conflict`).
        """
        name = validate_name(name)
        if not self.has_name(name) and isinstance(secret, Secret) and isinstance(secret.fields, dict):
            reason = self.conflict(name, secret.fields)
            if reason is not None:
                raise UsageError(f"an entry cannot be named {name!r}: {reason}. {_ONE_MEANING}")
        return self._add(
            name, secret, username=_shown_text(username, "the username"), url=_shown_text(url, "the URL"),
            tags=tags, kind=kind, agent=agent, entry_id=entry_id, created=created, modified=modified,
        )

    def _add(
        self,
        name: str,
        secret: Secret,
        *,
        username: str,
        url: str,
        tags: Optional[List[str]],
        kind: str,
        agent: str,
        entry_id: Optional[str],
        created: Optional[int],
        modified: Optional[int],
    ) -> Entry:
        name = validate_name(name)
        if self.has_name(name):
            raise UsageError(f"an entry named {name!r} already exists")
        if kind not in _KINDS:
            raise UsageError(f"unknown entry kind {kind!r}")
        if agent not in AGENT_POLICIES:
            raise UsageError(f"unknown agent policy {agent!r}")
        new_id = entry_id or os.urandom(16).hex()
        if not isinstance(new_id, str) or not _ENTRY_ID.fullmatch(new_id) or new_id in self.entries:
            raise UsageError("entry id is malformed or already in use")
        now = int(time.time())
        entry = Entry(
            id=new_id,
            name=name,
            username=_argument_text(username, "the username"),
            url=_argument_text(url, "the URL"),
            tags=_clean_tags(tags),
            kind=kind,
            created=_argument_time(created, "the creation time") if created is not None else now,
            modified=_argument_time(modified, "the modification time") if modified is not None else now,
            agent=agent,
        )
        self.entries[new_id] = entry
        try:
            self._write_secret(entry, secret)
        except BaseException:
            self.entries.pop(new_id, None)
            self.file.records.pop(new_id, None)
            raise
        return entry

    def update(
        self,
        entry: Entry,
        *,
        secret: Optional[Secret] = None,
        name: Optional[str] = None,
        username: Optional[str] = None,
        url: Optional[str] = None,
        tags: Optional[List[str]] = None,
        kind: Optional[str] = None,
        agent: Optional[str] = None,
    ) -> Entry:
        """Change metadata and/or replace the secret. A changed password is kept in history.

        Works on this vault's own record of the entry and returns it. Every
        argument is checked before anything is changed: a call that raises
        leaves the entry exactly as it was. A new name, or a new custom field,
        that would give a reference two meanings is refused (see :meth:`conflict`).
        """
        current = self.entries.get(entry.id)
        if current is None:
            raise NotFoundError(f"no entry named {entry.name!r}")
        new_name = current.name
        renamed = False
        if name is not None:
            name = validate_name(name)
        if name is not None and name != current.name:
            renamed = fold_name(name) != fold_name(current.name)
            if renamed and self.has_name(name):
                raise UsageError(f"an entry named {name!r} already exists")
            new_name = name
        new_username = current.username if username is None else _shown_text(username, "the username")
        new_url = current.url if url is None else _shown_text(url, "the URL")
        new_tags = current.tags if tags is None else _clean_tags(tags)
        if kind is not None and kind not in _KINDS:
            raise UsageError(f"unknown entry kind {kind!r}")
        if agent is not None and agent not in AGENT_POLICIES:
            raise UsageError(f"unknown agent policy {agent!r}")
        previous: Optional[Secret] = None
        if secret is not None:
            if not isinstance(secret, Secret):
                raise UsageError("a secret record is required")
            previous = self.read_secret(current)
        self._check_update(current, new_name if renamed else None, previous, secret)
        if secret is not None and previous is not None:
            history = secret.history
            if previous.password and previous.password != secret.password:
                retired = {"password": previous.password, "retired": int(time.time())}
                history = ([retired] + list(previous.history))[:_HISTORY_LIMIT]
            elif not secret.history:
                history = list(previous.history)
            stored = Secret(
                password=secret.password, totp=secret.totp, notes=secret.notes, fields=secret.fields, history=history
            )
            self._write_secret(current, stored)
            secret.history = history
        current.name = new_name
        current.username = new_username
        current.url = new_url
        current.tags = new_tags
        if kind is not None:
            current.kind = kind
        if agent is not None:
            current.agent = agent
        current.modified = int(time.time())
        return current

    def _check_update(
        self, current: Entry, new_name: Optional[str], previous: Optional[Secret], secret: Optional[Secret]
    ) -> None:
        """Refuse a rename to *new_name*, or the custom fields of *secret*, that would give a reference two meanings."""
        given = secret.fields if secret is not None and isinstance(secret.fields, dict) else None
        if new_name is None and given is None:
            return
        if previous is not None:
            before: Dict[str, str] = previous.fields
        else:
            try:
                before = self.read_secret(current).fields
            except VaultError:
                before = {}  # a rename must not fail on a damaged record; resolve() still refuses a clash
        after = given if given is not None else before
        if new_name is not None:
            reason = self.conflict(new_name, after, entry=current)
            if reason is not None:
                raise UsageError(f"{current.name!r} cannot be renamed to {new_name!r}: {reason}. {_ONE_MEANING}")
        added = [field_name for field_name in after if field_name not in before]
        if added:
            heads = [new_name or current.name] + self.aliases_of(current)
            reason = self._shadowed(heads, added, current.id)
            if reason is not None:
                raise UsageError(
                    f"{current.name!r} cannot get a new custom field here: {reason}. A reference must mean one "
                    "thing: rename that entry first (irondome edit NAME --name NEW), or name the field otherwise"
                )

    def remove(self, entry: Entry) -> None:
        if entry.id not in self.entries:
            raise NotFoundError(f"no entry named {entry.name!r}")
        del self.entries[entry.id]
        self.file.records.pop(entry.id, None)
        for alias in [name for name, target in self.aliases.items() if target.entry == entry.id]:
            del self.aliases[alias]

    def set_alias(self, alias: str, entry: Entry, field_name: str = "password") -> None:
        """Point *alias* at *field_name* of *entry*, replacing an alias of that name.

        Refused when the alias would give a reference two meanings: when another entry has its name
        (compared without regard to case), or when an entry called ``alias/field`` is in the vault
        for a field the target has. An alias may have the name of the entry it points at.
        """
        validate_alias(alias)
        if entry.id not in self.entries:
            raise NotFoundError(f"no entry named {entry.name!r}")
        if not isinstance(field_name, str) or (field_name not in FIELDS and not _FIELD_NAME.fullmatch(field_name)):
            raise UsageError(f"{field_name!r} is not a valid field name")
        if field_name == "name":
            raise UsageError("an alias must point at a value, not at the entry name")
        target = self.entries[entry.id]
        folded = fold_name(alias)
        named = [item.name for item in self.entries.values() if item.id != target.id and fold_name(item.name) == folded]
        if named:
            raise UsageError(
                f"the alias {alias} cannot be set: the entry {min(named)!r} has that name, and a reference "
                "must mean one thing; choose another alias"
            )
        if any(fold_name(other.name).startswith(folded + "/") for other in self.entries.values()):
            reason = self._shadowed([alias], self._fields_of(target), target.id)
            if reason is not None:
                raise UsageError(
                    f"the alias {alias} cannot be set: {reason}. A reference must mean one thing: choose another "
                    "alias, or rename that entry first (irondome edit NAME --name NEW)"
                )
        self.aliases[alias] = Alias(entry=target.id, field=field_name)

    def remove_alias(self, alias: str) -> None:
        if alias not in self.aliases:
            raise NotFoundError(f"no alias named {alias!r}")
        del self.aliases[alias]

    # -- keyslots -------------------------------------------------------------

    def add_slot(self, slot: Keyslot) -> None:
        if any(existing.id == slot.id for existing in self.file.slots):
            raise VaultError("that keyslot already exists")
        if len(self.file.slots) >= _MAX_SLOTS:
            raise VaultError(f"a vault holds at most {_MAX_SLOTS} keyslots; remove one first")
        self.file.slots.append(slot)

    def remove_slot(self, slot_id: str) -> Keyslot:
        for index, slot in enumerate(self.file.slots):
            if slot.id == slot_id:
                if len(self.file.slots) == 1:
                    raise VaultError("refusing to remove the last keyslot: the vault could never be opened again")
                return self.file.slots.pop(index)
        raise NotFoundError("no such keyslot")

    def slots(self, kind: Optional[str] = None) -> List[Keyslot]:
        return [slot for slot in self.file.slots if kind is None or slot.kind == kind]

    # -- persistence ----------------------------------------------------------

    def commit(self, *, snapshots: Optional[int] = None) -> None:
        """Write every pending change to disk, atomically.

        Fails rather than overwrite if another process changed the vault since
        this one read it.
        """
        keep = _DEFAULT_SNAPSHOTS if snapshots is None else snapshots
        with paths.file_lock(self.path.parent / ".lock"):
            try:
                current = paths.read_file(self.path)
            except FileNotFoundError:
                raise VaultError(f"the vault at {self.path} disappeared; nothing was written") from None
            except OSError as exc:
                raise VaultError(
                    f"cannot read the vault at {self.path}: {exc.strerror or exc}; nothing was written"
                ) from None
            on_disk = VaultFile.from_bytes(current)
            if on_disk.vault_id != self.file.vault_id:
                raise VaultError("the vault on disk was replaced by a different one; nothing was written")
            if on_disk.generation != self._loaded_generation:
                raise VaultError("the vault changed on disk while this command was running; run it again")
            generation = self._loaded_generation + 1
            index = self._seal_index(generation)
            payload = _checked_bytes(
                VaultFile(
                    vault_id=self.file.vault_id,
                    created=self.file.created,
                    generation=generation,
                    slots=self.file.slots,
                    index=index,
                    records=self.file.records,
                )
            )
            if keep > 0:
                self._snapshot(current, on_disk.generation, keep)
            paths.write_atomic(self.path, payload)
            # What a write killed before its rename left behind is a whole older vault, or a snapshot of one.
            # Every write into these two directories is made with this lock held, so none is in progress.
            paths.sweep_temporary(self.path.parent, older_than=0)
            paths.sweep_temporary(self._snapshot_dir(), older_than=0)
            self.file.index = index
            self.file.generation = generation
            self._loaded_generation = generation

    def _snapshot_dir(self) -> Path:
        return self.path.parent / "backups"

    def _snapshot_files(self) -> List[Tuple[int, Path]]:
        """``(generation, path)`` of every automatic snapshot, lowest generation first.

        Only files named exactly as :meth:`_snapshot` names them count, so a
        backup someone else put in the same folder is never rotated or purged.
        """
        directory = self._snapshot_dir()
        found: List[Tuple[int, Path]] = []
        if directory.is_dir():
            for path in directory.iterdir():
                match = _SNAPSHOT.fullmatch(path.name)
                if match and path.is_file() and not path.is_symlink():
                    found.append((int(match.group(1)), path))
        return sorted(found)

    def _snapshot(self, current: bytes, generation: int, keep: int) -> None:
        directory = paths.ensure_dir(self._snapshot_dir())
        paths.write_atomic(directory / f"vault-{generation:010d}.irondome", current)
        existing = self._snapshot_files()
        # A snapshot numbered above the one just written is left over from an
        # earlier vault at this path (it was re-created or restored). Those
        # are the stale ones, so they are rotated out first.
        ordered = [item for item in existing if item[0] > generation]
        ordered += [item for item in existing if item[0] <= generation]
        for _, stale in ordered[:-keep] if len(ordered) > keep else []:
            try:
                paths.secure_delete(stale)
            except OSError:
                pass

    def snapshots(self) -> List[Path]:
        return [path for _, path in self._snapshot_files()]

    def purge_snapshots(self) -> int:
        """Delete every automatic snapshot (they still open with *old* keyslots). Call with the bunker's lock held."""
        count = 0
        for snapshot in self.snapshots():
            paths.secure_delete(snapshot)
            count += 1
        paths.sweep_temporary(self._snapshot_dir(), older_than=0)  # a snapshot that never got its name
        return count

    # -- cloning (backup, restore, re-key) ------------------------------------

    def copy_into(self, other: "Vault") -> int:
        """Re-encrypt every entry and alias into *other* (which must be empty).

        Entries are copied as they are: a username or URL written before control characters were
        refused there is carried over, not refused, so that a re-key or a backup never loses one.
        """
        if other.entries:
            raise VaultError("the destination vault is not empty")
        for entry in self.list():
            secret = self.read_secret(entry)
            copied = other._add(
                entry.name,
                secret,
                username=entry.username,
                url=entry.url,
                tags=list(entry.tags),
                kind=entry.kind,
                agent=entry.agent,
                entry_id=entry.id,
                created=entry.created,
                modified=entry.modified,
            )
            copied.modified = entry.modified
        for name, alias in self.aliases.items():
            other.aliases[name] = Alias(entry=alias.entry, field=alias.field)
        return len(self.entries)


def _clean_tags(tags: Optional[List[str]]) -> List[str]:
    if isinstance(tags, (str, bytes)):
        raise UsageError("tags must be a list of text, not one string")
    cleaned: List[str] = []
    for tag in tags or []:
        if not isinstance(tag, str):
            raise UsageError("tags must be text")
        tag = tag.strip()
        if not tag:
            continue
        if len(tag) > 64 or _has_control(tag):
            raise UsageError(f"{tag!r} is not a valid tag")
        if tag.casefold() not in [existing.casefold() for existing in cleaned]:
            cleaned.append(tag)
    return cleaned


def validate_field_name(name: Any) -> str:
    """A custom field name: a letter or ``_``, then letters, digits, ``_ . -``; never a built-in field."""
    if not isinstance(name, str) or name in FIELDS or not _FIELD_NAME.fullmatch(name):
        raise UsageError(
            f"{name!r} cannot be used as a custom field name "
            "(letters, digits, '_', '.', '-'; not one of the built-in fields)"
        )
    return name


def _check_custom_fields(secret: Secret) -> None:
    if not isinstance(secret.fields, dict):
        raise UsageError("custom fields must be a mapping of names to text")
    for key in secret.fields:
        validate_field_name(key)
