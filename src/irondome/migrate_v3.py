"""Reading an IronDome 1.x-3.x vault, copying it into a version 4 vault, destroying it.

The old format
--------------
Everything lived in one directory, ``~/.password_manager``::

    secrets/salt.bin            16 random bytes; the only salt
    secrets/.passwords.enc      one Fernet token holding a JSON list of entries
    secrets/.master_user.enc    Fernet token: the master username
    secrets/.master_hash.enc    Fernet token: hex of a password verifier
    secrets/.login_attempts.dat, secrets/.airspace.session, settings.json,
    password_manager.log, backups/, .device_id      not needed to read a vault

The 2025 script this project grew out of kept the four files directly in the
data directory. Later code copied them into ``secrets/`` and from then on read
only that copy, so ``secrets/`` is looked at first and the old place second.

Every key is PBKDF2-HMAC-SHA256 over the one salt, used as a Fernet key
(AES-128-CBC with HMAC-SHA256). The derivation of the vault key changed twice,
and a vault written under an old derivation was never converted, so all three
are tried, newest first:

==============  ==========  ==============================================
2.0.0 - 3.2.2   600,000     ``len(username)`` as 8 bytes, username, password
1.0.1 - 1.1.0   600,000     username, ``":"``, password
before 1.0.1    100,000     username, ``":"``, password
==============  ==========  ==============================================

A vault set up as "biometric only" (2.0.0 and later) has no master password.
Its Fernet key is random and was stored in the operating system's keychain
under service ``IronDome``, account ``master_key``, base64-encoded a second
time on top of the 44-character Fernet form.

The master username and the verifier are wrapped under a "system key": the
same PBKDF2 (100,000 iterations before 1.0.1) over a machine identifier:
``/etc/machine-id``, else ``user@hostname``, else a ``.device_id`` file in the
data directory. That key guards nothing a vault needs. It is used here only to
prefill the username, to recognise a biometric-only vault and to tell a
damaged store from a wrong password; when it cannot be rebuilt (a renamed
computer, a vault copied from another one) those three are simply unknown.

What this module guarantees
---------------------------
* Nothing is written to, renamed in or removed from the old directory until
  :func:`destroy_legacy` is called. Reading opens files read-only.
* Everything read from the old directory is treated as hostile: only regular
  files, with size limits, structure checked before any key is derived, and
  every field of every entry type-checked. A damaged vault raises
  :class:`~irondome.errors.VaultError`; credentials that do not open it raise
  :class:`~irondome.errors.AuthError`.
* Keys derived here are held in :class:`~irondome.secmem.SecureBuffer` and
  wiped before the function that derived them returns. The decrypted JSON is
  zeroed once it has been parsed.
* :func:`import_into` changes the open vault in memory only and undoes its own
  additions if it fails part-way; nothing reaches the disk until the caller
  commits. It never overwrites or removes an entry that is already there.
* :func:`destroy_legacy` deletes a directory only if it still holds the vault
  that was detected and nothing but files the old versions created.

What it does not do
-------------------
* The entries themselves are ordinary ``str`` objects, as they are everywhere
  else in IronDome while a command runs; they cannot be wiped.
* The 3.x key fetched from the keychain reaches Python as an immutable object
  and :func:`keychain_master_key` returns ``bytes``, because that is what
  ``subprocess`` hands over from the keychain command's output. The copies
  handed over and made here are zeroed; a copy ``subprocess`` made while
  reading the pipe is out of reach. ``secmem.wipe_bytes`` can zero the result.
* No keychain is read but through the system's own command:
  ``/usr/bin/security`` on macOS, ``secret-tool`` on Linux; no third-party
  package, even where 3.x left ``keyring`` installed. Where there is no such
  command (Windows, where 3.x kept the key in the Credential Manager; a Linux
  without ``secret-tool``) the keychain is neither read nor cleared, and the
  key has to be supplied: :func:`keychain_unreachable` says why, in words a
  person can act on.
* Backups made by 3.x (``backups/``) are not imported. They are older copies
  of the same vault and :func:`destroy_legacy` removes them with the rest.
* The 3.x recovery key opens nothing here. It never derived a key: 3.x used it
  only to decide whether to read the same keychain entry.
* Overwriting files is hygiene, not erasure: see ``paths.secure_delete``.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import errno
import getpass
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from secrets import compare_digest
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from irondome import paths
from irondome.errors import AuthError, IronDomeError, UsageError, VaultError
from irondome.secmem import BufferLike, SecureBuffer, _wipe_str, as_view, wipe_bytes
from irondome.vault import Entry, Secret, Vault, fold_name, validate_name, without_control

__all__ = [
    "LAYOUT_SECRETS",
    "LAYOUT_FLAT",
    "MODE_BIOMETRIC_ONLY",
    "LegacyVault",
    "LegacyEntry",
    "MigrationReport",
    "LegacyDestroyReport",
    "detect",
    "stored_username",
    "read_entries",
    "keychain_master_key",
    "keychain_unreachable",
    "import_into",
    "verify",
    "destroy_legacy",
]

LAYOUT_SECRETS = "secrets"
LAYOUT_FLAT = "flat"
MODE_BIOMETRIC_ONLY = "biometric_only"

_SALT_FILE = "salt.bin"
_STORE_FILE = ".passwords.enc"
_USER_FILE = ".master_user.enc"
_HASH_FILE = ".master_hash.enc"
_DEVICE_ID_FILE = ".device_id"
_CORE_FILES = (_SALT_FILE, _USER_FILE, _HASH_FILE, _STORE_FILE)

_SALT_LEN = 16
_KEY_LEN = 32
_HALF_KEY = 16
_BLOCK = 16
_MAC_LEN = 32
_TOKEN_HEADER = 1 + 8 + _BLOCK  # version, timestamp, IV
_TOKEN_MIN = _TOKEN_HEADER + _BLOCK + _MAC_LEN
_TOKEN_VERSION = 0x80

#: Size limits on what is read from the old directory.
_MAX_STORE_BYTES = 64 * 1024 * 1024
_MAX_SMALL_BYTES = 64 * 1024

#: (PBKDF2 iterations, username length-prefixed?) for the vault key, newest first.
_VAULT_KEY_GENERATIONS = ((600_000, True), (600_000, False), (100_000, False))
#: PBKDF2 iterations for the system key and the verifier: 1.0.1 and later, then earlier.
_SYSTEM_KEY_ITERATIONS = (600_000, 100_000)
_VERIFIER_ITERATIONS = 600_000

_MACHINE_ID_FILES = ("/etc/machine-id", "/var/lib/dbus/machine-id")
#: What the code before 1.0.1 used when it could not name the machine.
_ORIGINAL_FALLBACK_ID = "secure_password_manager_default_key"
#: What 2.0.0+ hashed into the verifier of a vault that has no master password.
_BIOMETRIC_PLACEHOLDER = b"biometric_only_placeholder"
_BIOMETRIC_USER_PREFIX = "bio_"

_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
_NAME_LIMIT = 200  # vault.validate_name
_USER_IN_NAME_LIMIT = 80
_UNTITLED = "untitled"

_KEYCHAIN_SERVICE = "IronDome"
#: The vault key first: once it is gone a biometric-only vault cannot be decrypted.
_KEYCHAIN_ACCOUNTS = ("master_key", "recovery_hash", "auth_mode")
#: macOS's own keychain command, run from this one path and never looked up in ``$PATH``.
_MACOS_TOOL = "/usr/bin/security"
#: libsecret's command for the Secret Service on Linux, looked for in ``_TOOL_PATH`` only.
_LINUX_TOOL = "secret-tool"
_TOOL_PATH = "/usr/bin:/bin"
#: The operating system may be showing an unlock or permission dialog.
_TOOL_TIMEOUT = 180.0
_TOOL_ENVIRONMENT = (
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "__CF_USER_TEXT_ENCODING",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "DISPLAY",
    "WAYLAND_DISPLAY",
)
_SECURITY_NOT_FOUND = 44  # errSecItemNotFound, as /usr/bin/security reports it
_PLATFORM = sys.platform
_TO_STANDARD_BASE64 = bytes.maketrans(b"-_", b"+/")
_TO_URLSAFE_BASE64 = bytes.maketrans(b"+/", b"-_")

#: Every name 1.x-3.x created, by where it sits in the data directory.
_KNOWN_TOP_FILES = (
    _SALT_FILE,
    _USER_FILE,
    _HASH_FILE,
    _STORE_FILE,
    ".login_attempts.dat",
    "password_manager.log",
    "settings.json",
    _DEVICE_ID_FILE,
    "passwords_backup_*.enc",
    ".passwords_backup_*.enc",
)
_KNOWN_SECRETS_FILES = (_SALT_FILE, _USER_FILE, _HASH_FILE, _STORE_FILE, ".login_attempts.dat", ".airspace.session")
_KNOWN_BACKUP_FILES = ("*.enc",)
_KNOWN_DIRECTORIES = ("secrets", "backups")
#: Files a file manager leaves behind; removed along with the vault.
_DESKTOP_LITTER = (".DS_Store", "._*", "Thumbs.db", "desktop.ini")


# ---------------------------------------------------------------------------
# What callers see
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LegacyVault:
    """A 1.x-3.x vault found on disk. Holds nothing secret.

    ``layout`` is ``"secrets"`` or ``"flat"`` (the four files directly in the
    data directory). ``mode`` is ``"biometric_only"`` when the vault is known
    to have no master password, and None otherwise: either it is opened with
    a username and password, or its mode could not be determined here.
    """

    path: Path
    layout: str
    salt: bytes
    has_entries: bool
    mode: Optional[str]


@dataclass(frozen=True)
class LegacyEntry:
    """One entry of an old vault. ``created`` and ``modified`` are Unix times, or None when unknown.

    The password and the notes are left out of ``repr`` so that an entry can
    appear in a log line or a traceback without revealing them.
    """

    username: str
    website: str
    password: str = field(repr=False)
    notes: str = field(repr=False)
    created: Optional[int] = None
    modified: Optional[int] = None


@dataclass
class MigrationReport:
    """What :func:`import_into` did.

    ``renamed`` lists ``(website, name given)`` for every imported entry whose
    name is not exactly its old website. ``skipped`` says, one line per entry,
    what was not imported and why. ``cleaned`` names, one line per entry, an
    imported entry whose username lost control characters the vault refuses
    there. None of them holds a password.
    """

    imported: int
    renamed: List[Tuple[str, str]]
    skipped: List[str]
    cleaned: List[str] = field(default_factory=list)


@dataclass
class LegacyDestroyReport:
    """What :func:`destroy_legacy` did.

    ``keychain_cleared`` is True when the three keychain entries are confirmed
    absent, False when one remains or the keychain could not be examined, and
    None when the keychain was left alone (not asked for, or not this vault's).
    ``success`` is True only when nothing is left on disk, nothing went wrong
    and ``keychain_cleared`` is not False.
    """

    success: bool
    files_deleted: List[str]
    leftovers: List[str]
    keychain_cleared: Optional[bool]
    errors: List[str]


@dataclass(frozen=True)
class _Token:
    """A structurally valid Fernet token, split into what the MAC covers and the MAC."""

    signed: bytes
    mac: bytes


@dataclass(frozen=True)
class _Master:
    """What the system key protects. Either part is None when it is missing or unreadable."""

    username: Optional[str]
    verifier: Optional[bytes]


# ---------------------------------------------------------------------------
# Reading files that may be anything
# ---------------------------------------------------------------------------


def _reason(error: OSError) -> str:
    return error.strerror or type(error).__name__


def _read_regular(path: Path, limit: int) -> Optional[bytes]:
    """The contents of a regular file of at most *limit* bytes, or None if there is no such file.

    Symbolic links are followed, as the old versions followed them; a link
    whose target is missing is reported as damage rather than as absence.
    Anything that is not a regular file, is larger than *limit* or cannot be
    read raises :class:`VaultError`. A pipe or device put in a file's place
    cannot make this block: the descriptor is opened non-blocking and checked
    before it is read.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(path), flags)
    except (FileNotFoundError, NotADirectoryError):
        if os.path.islink(path):
            raise VaultError(f"{path} is a symbolic link to something that is not there") from None
        return None
    except OSError as exc:
        raise VaultError(f"cannot read {path}: {_reason(exc)}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise VaultError(f"{path} is not a regular file")
        if info.st_size > limit:
            raise VaultError(f"{path} is too large to belong to an IronDome 3.x vault ({info.st_size} bytes)")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(1 << 20, limit + 1 - len(data)))
            if not chunk:
                break
            data += chunk
    except OSError as exc:
        raise VaultError(f"cannot read {path}: {_reason(exc)}") from None
    finally:
        os.close(fd)
    if len(data) > limit:
        raise VaultError(f"{path} is too large to belong to an IronDome 3.x vault")
    return bytes(data)


def _read_text(path: Path) -> Optional[str]:
    """A small text file, stripped; None when it is missing, unreadable or not text."""
    try:
        data = _read_regular(path, _MAX_SMALL_BYTES)
    except VaultError:
        return None
    if data is None:
        return None
    try:
        return data.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None


def _base_dir(root: Path, layout: str) -> Path:
    return root / "secrets" if layout == LAYOUT_SECRETS else root


def _locate(root: Path) -> Optional[Tuple[str, bytes, bool]]:
    """``(layout, salt, has entries)`` for the vault in *root*, or None when there is none.

    Derives no key and decrypts nothing.
    """
    try:
        if not root.is_dir():
            return None
    except OSError as exc:
        raise VaultError(f"cannot examine {root}: {_reason(exc)}") from None
    layout = None
    for candidate in (LAYOUT_SECRETS, LAYOUT_FLAT):
        base = _base_dir(root, candidate)
        if any(os.path.lexists(base / name) for name in _CORE_FILES):
            layout = candidate
            break
    if layout is None:
        return None
    base = _base_dir(root, layout)
    salt = _read_regular(base / _SALT_FILE, _MAX_SMALL_BYTES)
    if salt is None:
        raise VaultError(
            f"the IronDome 3.x vault in {root} has no {_SALT_FILE}; without the salt it cannot be decrypted"
        )
    if len(salt) != _SALT_LEN:
        raise VaultError(
            f"{base / _SALT_FILE} is {len(salt)} bytes long instead of {_SALT_LEN}: "
            "the salt is damaged and the vault cannot be decrypted"
        )
    return layout, salt, os.path.lexists(base / _STORE_FILE)


# ---------------------------------------------------------------------------
# Fernet, read-only, with keys that never leave locked memory
# ---------------------------------------------------------------------------


def _decode_base64(text: bytes) -> bytes:
    """Strict URL-safe base64; raises ``binascii.Error`` or ``ValueError``.

    The alphabet is translated here rather than inside ``base64`` so that the
    translated copy, which may be a key, can be zeroed.
    """
    standard = text.translate(_TO_STANDARD_BASE64)  # the same object when there was nothing to translate
    try:
        return base64.b64decode(standard, validate=True)
    finally:
        if standard is not text:
            wipe_bytes(standard)


def _parse_token(data: bytes, what: str) -> _Token:
    """Check that *data* has the shape of a Fernet token, before any key is involved."""
    text = b"".join(data.split())
    raw = b""
    if text:
        with contextlib.suppress(binascii.Error, ValueError):
            raw = _decode_base64(text)
    if len(raw) < _TOKEN_MIN or raw[0] != _TOKEN_VERSION or (len(raw) - _TOKEN_HEADER - _MAC_LEN) % _BLOCK:
        raise VaultError(f"{what} is not a Fernet token: the file is damaged or was replaced")
    return _Token(signed=raw[:-_MAC_LEN], mac=raw[-_MAC_LEN:])


def _open_token(token: _Token, key: SecureBuffer) -> Optional[bytearray]:
    """Authenticate *token* under *key* and decrypt it.

    Returns None when the MAC does not verify, which is what a wrong key looks
    like. The result is a ``bytearray`` the caller must wipe. Unlike
    ``cryptography.fernet.Fernet`` this keeps the key in the caller's
    ``SecureBuffer`` and applies no time-to-live, which 3.x never used.
    """
    view = key.view()
    signing = view[:_HALF_KEY]
    encryption = view[_HALF_KEY:]
    mac = hmac.HMAC(signing, hashes.SHA256())
    try:
        mac.update(token.signed)
        mac.verify(token.mac)
    except InvalidSignature:
        return None
    finally:
        del mac
    ciphertext = token.signed[_TOKEN_HEADER:]
    scratch = bytearray(len(ciphertext) + _BLOCK - 1)
    decryptor = Cipher(algorithms.AES(encryption), modes.CBC(token.signed[9:_TOKEN_HEADER])).decryptor()
    try:
        length = decryptor.update_into(ciphertext, scratch) + len(decryptor.finalize())
    finally:
        del decryptor
    padding = scratch[length - 1] if length else 0
    if not 1 <= padding <= _BLOCK or scratch[length - padding : length] != bytes([padding]) * padding:
        wipe_bytes(scratch)
        raise VaultError("a Fernet token authenticated but is not padded as Fernet pads; IronDome did not write it")
    plain = bytearray(memoryview(scratch)[: length - padding])
    wipe_bytes(scratch)
    return plain


def _pbkdf2(material: BufferLike, salt: bytes, iterations: int) -> SecureBuffer:
    """PBKDF2-HMAC-SHA256 to 32 bytes, derived straight into locked memory."""
    out = SecureBuffer(_KEY_LEN)
    try:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=_KEY_LEN, salt=salt, iterations=iterations)
        kdf.derive_into(as_view(material), out.view())
    except BaseException:
        out.wipe()
        raise
    return out


def _user_key(username: bytes, password: memoryview, salt: bytes, iterations: int, prefixed: bool) -> SecureBuffer:
    """The vault key of one generation, from the master username and password."""
    head = len(username).to_bytes(8, "big") + username if prefixed else username + b":"
    with SecureBuffer(len(head) + len(password)) as material:
        view = material.view()
        view[: len(head)] = head
        view[len(head) :] = password
        return _pbkdf2(material, salt, iterations)


def _master_key_buffer(key: BufferLike) -> Optional[SecureBuffer]:
    """The 32 raw bytes of a 3.x vault key given in either text form, or None if it is neither.

    Accepts the 44-character Fernet key and the 60-character value the
    keychain holds (the same key base64-encoded once more), with or without
    surrounding whitespace.
    """
    scratch: List[bytes] = [bytes(as_view(key))]  # every intermediate copy, so that all of them are wiped
    try:
        for _ in range(2):
            scratch.append(scratch[-1].strip())
            if not scratch[-1]:
                return None
            try:
                scratch.append(_decode_base64(scratch[-1]))
            except (binascii.Error, ValueError):
                return None
            if len(scratch[-1]) == _KEY_LEN:
                return SecureBuffer.from_buffer(scratch[-1])
        return None
    finally:
        for copy in scratch:
            wipe_bytes(copy)


# ---------------------------------------------------------------------------
# The system key: master username and password verifier
# ---------------------------------------------------------------------------


def _login_names() -> List[str]:
    """The login name as ``getpass.getuser`` (1.0.1 and later) and ``os.getlogin`` (earlier) report it."""
    names = []
    probes: List[Optional[Callable[[], str]]] = [getpass.getuser, getattr(os, "getlogin", None)]
    for probe in probes:
        if probe is None:
            continue
        with contextlib.suppress(OSError, KeyError, ImportError):  # no terminal, no account entry
            names.append(probe())
    return _distinct(name for name in names if name)


def _node_names() -> List[str]:
    """This machine's node name, and the forms macOS switches between as networks change."""
    uname = getattr(os, "uname", None)
    if uname is None:
        return []  # 3.x on Windows had no node name and fell through to the device-id file
    node = str(uname().nodename)
    if not node:
        return []
    short = node.split(".", 1)[0]
    return _distinct([node, short + ".local", short])


def _distinct(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _machine_ids(root: Path) -> List[bytes]:
    """Every machine identifier 1.x-3.x could have used for the vault in *root*, likeliest first."""
    candidates: List[str] = []
    for name in _MACHINE_ID_FILES:
        text = _read_text(Path(name))
        if text is not None:
            candidates.append(text)
    for user in _login_names():
        for node in _node_names():
            candidates.append(f"{user}@{node}")
    device_id = _read_text(root / _DEVICE_ID_FILE)
    if device_id is not None:
        candidates.append(device_id)
    candidates.append("fallback-" + os.path.expanduser("~"))
    candidates.append(_ORIGINAL_FALLBACK_ID)
    encoded = []
    for candidate in _distinct(candidates):
        with contextlib.suppress(UnicodeEncodeError):
            encoded.append(candidate.encode("utf-8"))
    return encoded


def _optional_token(path: Path) -> Optional[_Token]:
    try:
        data = _read_regular(path, _MAX_SMALL_BYTES)
        return None if data is None else _parse_token(data, path.name)
    except VaultError:
        return None


def _decode_username(plain: Optional[bytearray]) -> Optional[str]:
    if plain is None:
        return None
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _decode_verifier(plain: Optional[bytearray]) -> Optional[bytes]:
    if plain is None:
        return None
    try:
        digest = bytes.fromhex(plain.decode("ascii"))
    except ValueError:
        return None
    return digest if len(digest) == _KEY_LEN else None


def _read_master(root: Path, layout: str, salt: bytes) -> Optional[_Master]:
    """The stored master username and verifier, or None when the system key cannot be rebuilt here."""
    base = _base_dir(root, layout)
    user_token = _optional_token(base / _USER_FILE)
    hash_token = _optional_token(base / _HASH_FILE)
    if user_token is None and hash_token is None:
        return None
    machine_ids = _machine_ids(root)
    for iterations in _SYSTEM_KEY_ITERATIONS:
        for machine_id in machine_ids:
            try:
                with _pbkdf2(machine_id, salt, iterations) as key:
                    user = None if user_token is None else _open_token(user_token, key)
                    digest = None if hash_token is None else _open_token(hash_token, key)
            except VaultError:
                return None
            if user is not None or digest is not None:
                return _Master(username=_decode_username(user), verifier=_decode_verifier(digest))
    return None


def _is_biometric_only(master: _Master, salt: bytes) -> bool:
    """True when the verifier is the one 2.0.0+ stored for a vault with no master password."""
    if master.verifier is None:
        return False
    if master.username is not None and not master.username.startswith(_BIOMETRIC_USER_PREFIX):
        return False
    with _pbkdf2(_BIOMETRIC_PLACEHOLDER, salt, _VERIFIER_ITERATIONS) as expected:
        return compare_digest(expected.view(), master.verifier)


def _credentials_match(master: Optional[_Master], username: str, password: memoryview, salt: bytes) -> Optional[bool]:
    """Whether the stored verifier accepts these credentials; None when there is nothing to check against."""
    if master is None or master.verifier is None:
        return None
    if master.username is not None and master.username != username:
        return False
    with _pbkdf2(password, salt, _VERIFIER_ITERATIONS) as stretched:
        if compare_digest(stretched.view(), master.verifier):
            return True
    original = hashlib.sha256(salt)  # before 1.0.1 the verifier was SHA-256(salt || password)
    original.update(password)
    return compare_digest(original.digest(), master.verifier)


# ---------------------------------------------------------------------------
# detect, stored_username, read_entries
# ---------------------------------------------------------------------------


def detect(path: Union[str, Path, None] = None) -> Optional[LegacyVault]:
    """Find a 1.x-3.x vault in *path* (default: ``paths.legacy_v3_dir()``).

    Returns None when there is none. Raises :class:`VaultError` when there is
    one whose salt is missing or damaged, because such a vault cannot be
    decrypted and "no vault here" would be the wrong thing to report.

    Working out ``mode`` rebuilds the system key, which costs one PBKDF2 run
    (about a tenth of a second) per machine identifier tried: one when the
    machine is the one that wrote the vault, around ten when none fits. It
    never touches the keychain and never asks for anything.
    """
    root = Path(os.path.abspath(os.fspath(path))) if path is not None else paths.legacy_v3_dir()
    located = _locate(root)
    if located is None:
        return None
    layout, salt, has_entries = located
    master = _read_master(root, layout, salt)
    mode = MODE_BIOMETRIC_ONLY if master is not None and _is_biometric_only(master, salt) else None
    return LegacyVault(path=root, layout=layout, salt=salt, has_entries=has_entries, mode=mode)


def stored_username(legacy: LegacyVault) -> Optional[str]:
    """The master username the old vault stored, or None when it cannot be recovered here.

    Best effort: it depends on rebuilding the system key from this machine's
    identifiers. A biometric-only vault stores a placeholder such as
    ``bio_touch_id``.
    """
    _require_vault(legacy)
    master = _read_master(legacy.path, legacy.layout, legacy.salt)
    return None if master is None else master.username


def _require_vault(legacy: Any) -> None:
    if not isinstance(legacy, LegacyVault):
        raise UsageError("this needs the vault object returned by migrate_v3.detect()")


def _parse_time(value: Any) -> Optional[int]:
    """A 3.x timestamp (naive local time) as a Unix time; None when absent, malformed or before 1970."""
    if not isinstance(value, str):
        return None
    try:
        stamp = int(time.mktime(time.strptime(value, _TIME_FORMAT)))
    except (ValueError, OverflowError):
        return None
    return stamp if stamp >= 0 else None


def _entries_from(plain: bytearray) -> List[LegacyEntry]:
    """Parse the decrypted list and zero the plaintext, whatever happens."""
    text: Optional[str] = None
    document: Any = None
    readable = True
    try:
        text = plain.decode("utf-8")
        document = json.loads(text)
    except (ValueError, RecursionError):
        readable = False
    finally:
        wipe_bytes(plain)
        if text is not None:
            _wipe_str(text)  # the decoded copy: made here, and json.loads keeps no part of it
    # Raised here, outside the handler, so that no exception carrying the
    # plaintext (JSONDecodeError.doc, UnicodeDecodeError.object) is chained.
    if not readable or not isinstance(document, list):
        raise VaultError("the IronDome 3.x vault decrypted, but it does not hold a list of entries")
    entries = []
    for number, item in enumerate(document, start=1):
        if not isinstance(item, dict):
            raise VaultError(f"entry {number} of the IronDome 3.x vault is not a record")
        for key in ("username", "website", "password"):
            if not isinstance(item.get(key), str):
                raise VaultError(f"entry {number} of the IronDome 3.x vault has no usable {key}")
        notes = item.get("notes")
        if notes is None:
            notes = ""
        if not isinstance(notes, str):
            raise VaultError(f"entry {number} of the IronDome 3.x vault has notes that are not text")
        created = _parse_time(item.get("created_at"))
        modified = _parse_time(item.get("updated_at"))
        entries.append(
            LegacyEntry(
                username=item["username"],
                website=item["website"],
                password=item["password"],
                notes=notes,
                created=created if created is not None else modified,
                modified=modified if modified is not None else created,
            )
        )
    return entries


def read_entries(
    legacy: LegacyVault,
    *,
    username: Optional[str] = None,
    password: Optional[BufferLike] = None,
    master_key: Optional[BufferLike] = None,
) -> List[LegacyEntry]:
    """Decrypt the old vault and return its entries in stored order.

    Give *password* (and *username*, unless :func:`stored_username` can recover
    it) for a vault with a master password, or *master_key* for a
    biometric-only vault: the 44-character Fernet key or the 60-character
    value from the keychain. The caller keeps ownership of both and wipes them.

    Raises :class:`AuthError` when the credentials do not open the vault,
    :class:`VaultError` when the vault is damaged, :class:`UsageError` when
    something needed was not given. A vault with no password store yields an
    empty list; a password is still checked against the stored verifier when
    that can be read.

    The lockout counter 3.x kept is not consulted: it was a file next to the
    vault and never protected it.
    """
    _require_vault(legacy)
    if password is not None and master_key is not None:
        raise UsageError("give the 3.x master password or the 3.x vault key, not both")
    for value, what in ((password, "master password"), (master_key, "vault key")):
        if value is not None and not isinstance(value, (SecureBuffer, bytes, bytearray, memoryview)):
            raise UsageError(f"the 3.x {what} must be bytes or a SecureBuffer")
    store = _base_dir(legacy.path, legacy.layout) / _STORE_FILE
    data = _read_regular(store, _MAX_STORE_BYTES)
    token = None if data is None else _parse_token(data, str(store))

    if master_key is not None:
        key = _master_key_buffer(master_key)
        if key is None:
            raise AuthError(
                "that is not an IronDome 3.x vault key: expected the 44-character key "
                "or the 60-character value stored in the OS keychain"
            )
        with key:
            plain = None if token is None else _open_token(token, key)
        if token is None:
            return []
        if plain is None:
            raise AuthError("that key does not open this IronDome 3.x vault")
        return _entries_from(plain)

    if password is None:
        if legacy.mode == MODE_BIOMETRIC_ONLY:
            raise UsageError(
                "this IronDome 3.x vault has no master password: it opens with the key 3.x kept "
                "in the OS keychain. Pass master_key (see keychain_master_key)"
            )
        raise UsageError("this IronDome 3.x vault needs its master password")

    master: Optional[_Master] = None
    master_read = False
    if username is None:
        master = _read_master(legacy.path, legacy.layout, legacy.salt)
        master_read = True
        username = None if master is None else master.username
        if username is None:
            raise UsageError(
                "the 3.x master username could not be recovered on this machine "
                "(the key that wraps it depends on the computer's name); pass username"
            )
    if not isinstance(username, str) or not username:
        raise UsageError("the 3.x master username must be non-empty text")
    try:
        name = username.encode("utf-8")
    except UnicodeEncodeError:
        raise UsageError("the 3.x master username is not valid text") from None
    secret = as_view(password)
    if token is not None:
        for iterations, prefixed in _VAULT_KEY_GENERATIONS:
            with _user_key(name, secret, legacy.salt, iterations, prefixed) as key:
                plain = _open_token(token, key)
            if plain is not None:
                return _entries_from(plain)
    if not master_read:
        master = _read_master(legacy.path, legacy.layout, legacy.salt)
    accepted = _credentials_match(master, username, secret, legacy.salt)
    if token is None:
        if accepted is False:
            raise AuthError("wrong IronDome 3.x master username or password")
        return []
    if legacy.mode == MODE_BIOMETRIC_ONLY:  # checked first: its verifier is that of a fixed, public string
        raise AuthError(
            "this IronDome 3.x vault has no master password: it opens with the key 3.x kept "
            "in the OS keychain. Pass master_key (see keychain_master_key)"
        )
    if accepted:
        raise VaultError(
            f"the 3.x master username and password are right, but {store} does not decrypt with them: "
            "the file is damaged or was replaced"
        )
    raise AuthError("wrong IronDome 3.x master username or password")


# ---------------------------------------------------------------------------
# The operating system's keychain, through the system's own command
# ---------------------------------------------------------------------------


def _account_home() -> Optional[str]:
    """The home directory the account database gives this user, or None where there is no such database."""
    try:
        import pwd
    except ImportError:
        return None
    try:
        return pwd.getpwuid(os.getuid()).pw_dir or None
    except KeyError:
        return None


def _keychain_is_ours() -> bool:
    """Whether the keychain this process can reach is the one 3.x paired with ``~/.password_manager``.

    3.x found its vault through ``$HOME`` and its keys through the account's
    keychain. When ``$HOME`` points somewhere other than the account's own
    home (a test, a container, ``sudo -E``) the two no longer belong together,
    and the keychain is left alone rather than read or cleared for a vault it
    does not belong to.
    """
    if os.name == "nt":
        return True
    home = _account_home()
    if home is None:
        return False
    return os.path.realpath(home) == os.path.realpath(os.path.expanduser("~"))


def _owns_keychain(root: Path) -> bool:
    """True when *root* is the one directory whose vault the keychain entries can belong to."""
    standard = os.path.realpath(os.path.expanduser(os.path.join("~", ".password_manager")))
    return _keychain_is_ours() and os.path.realpath(root) == standard


def _keychain_tool() -> Optional[str]:
    """Absolute path of the system's own keychain command, or None where there is none to run.

    ``/usr/bin/security`` on macOS, at that fixed path; ``secret-tool`` on
    Linux, from ``/usr/bin`` or ``/bin``. ``$PATH`` is never searched, so a
    program of the same name planted earlier in it is never run, and a command
    that somebody other than root or this user could have replaced is not run
    either (:func:`irondome.paths.program_fault`): it would be handed the key
    of the 3.x vault.
    """
    found = _keychain_tool_installed()
    if found is None or paths.program_fault(found) is not None:
        return None
    return found


def _keychain_tool_installed() -> Optional[str]:
    """Where the keychain command is, whether or not it is one to run."""
    if _PLATFORM == "darwin":
        return shutil.which(_MACOS_TOOL)  # a path with a directory: checked as it is, never searched for
    if _PLATFORM.startswith("linux"):
        return shutil.which(_LINUX_TOOL, path=_TOOL_PATH)
    return None


def _no_tool() -> str:
    """Why there is no keychain command to run here, in words a person can act on."""
    found = _keychain_tool_installed()
    fault = paths.program_fault(found) if found is not None else None
    if fault:
        return f"{fault}, and IronDome runs the keychain command only where nobody but root or you can change it"
    if _PLATFORM == "darwin":
        return f"{_MACOS_TOOL}, the macOS keychain command, cannot be run here"
    if _PLATFORM.startswith("linux"):
        return (
            f"{_LINUX_TOOL} is not installed in /usr/bin or /bin "
            "(it comes with libsecret; on Debian and Ubuntu the package is libsecret-tools)"
        )
    if _PLATFORM == "win32":
        return "IronDome has no way to read the Windows Credential Manager, where 3.x kept it"
    return f"IronDome reads the OS keychain only on macOS, with {_MACOS_TOOL}, and on Linux, with {_LINUX_TOOL}"


def keychain_unreachable() -> Optional[str]:
    """Why :func:`keychain_master_key` cannot ask the OS keychain here, in plain words; None when it can.

    Runs nothing: it only looks at ``$HOME`` and for the command. When
    :func:`keychain_master_key` returns None, this tells "the keychain did
    not hand over a key" (None here) from "the keychain was not asked" (the
    reason here), so that the caller can say which, and ask for the key
    instead (``read_entries(master_key=...)``; ``irondome migrate
    --legacy-key`` reads it from the terminal, or from stdin with
    ``--password-stdin``).
    """
    if not _keychain_is_ours():
        return (
            "$HOME is not this account's home directory, so the keychain within reach "
            "is not the one IronDome 3.x used"
        )
    if _keychain_tool() is None:
        return _no_tool()
    return None


def _keychain_commands(tool: str, account: str) -> Dict[str, List[str]]:
    if _PLATFORM == "darwin":
        item = ["-s", _KEYCHAIN_SERVICE, "-a", account]
        return {
            "read": [tool, "find-generic-password", *item, "-w"],
            "probe": [tool, "find-generic-password", *item],
            "delete": [tool, "delete-generic-password", *item],
        }
    item = ["service", _KEYCHAIN_SERVICE, "username", account]
    return {"read": [tool, "lookup", *item], "probe": [tool, "lookup", *item], "delete": [tool, "clear", *item]}


def _run_tool(command: List[str]) -> Tuple[int, bytes]:
    """Run one keychain command. Returns ``(exit status, stdout)``; status -1 if it did not run or finish.

    No secret is passed to the command: not in its arguments, not in its
    environment. What it prints may be one; callers wipe it.
    """
    environment = {name: os.environ[name] for name in _TOOL_ENVIRONMENT if name in os.environ}
    environment["PATH"] = _TOOL_PATH
    try:
        done = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=_TOOL_TIMEOUT,
            env=environment,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        wipe_bytes(exc.output)  # whatever it had printed before it was stopped
        return -1, b""
    except (OSError, subprocess.SubprocessError):
        return -1, b""
    return done.returncode, done.stdout


def _keychain_read(account: str) -> Optional[bytes]:
    """The value stored for *account*; None when there is none, or no command here to ask with.

    What the command prints is read from a pipe and zeroed once copied; it
    is never logged, and a failure is reported by exit status alone.
    """
    tool = _keychain_tool()
    if tool is None:
        return None
    status, output = _run_tool(_keychain_commands(tool, account)["read"])
    try:
        if status == 0:
            stripped = output.strip()  # the same object when there was nothing to strip
            kept = memoryview(stripped).tobytes()  # a copy: everything else is wiped
            if stripped is not output:
                wipe_bytes(stripped)
            return kept or None
        if _PLATFORM != "darwin" or status == _SECURITY_NOT_FOUND:
            return None  # secret-tool exits 1 both for "no such item" and for "no Secret Service running"
    finally:
        wipe_bytes(output)
    outcome = "did not finish" if status < 0 else f"exited with status {status}"
    raise AuthError(
        f"the operating system did not release the IronDome 3.x key from the keychain (security {outcome}). "
        "Unlock the login keychain and allow the request, or supply the key yourself"
    )


def keychain_master_key() -> Optional[bytes]:
    """The key of a biometric-only 3.x vault, fetched from the OS keychain.

    Returns the 44-character Fernet key, or None when the keychain holds no
    such entry or was not asked; :func:`keychain_unreachable` says whether,
    and why not. It is read with the system's own command and nothing else:
    ``/usr/bin/security`` on macOS, ``secret-tool`` (libsecret) on Linux. No
    third-party package is used. There is no command for the Windows
    Credential Manager, where 3.x kept the key on Windows, nor on a Linux
    without ``secret-tool``: there the key has to be supplied directly.

    macOS shows a dialog asking for permission, since ``security`` is not the
    program that stored the key, unless it was allowed before; the call waits
    up to three minutes for the answer. A refusal raises :class:`AuthError`.
    ``secret-tool`` cannot tell a missing entry from a Secret Service that is
    not running, and both come back as None. An entry that is not a vault key
    raises :class:`VaultError`.

    The keychain is consulted only when ``$HOME`` is the account's real home
    directory, since that is the only arrangement in which 3.x could have put
    this vault's key there.
    """
    if not _keychain_is_ours():
        return None
    stored = _keychain_read(_KEYCHAIN_ACCOUNTS[0])
    if stored is None:
        return None
    try:
        key = _master_key_buffer(stored)
    finally:
        wipe_bytes(stored)
    if key is None:
        raise VaultError(
            f"the {_KEYCHAIN_SERVICE}/{_KEYCHAIN_ACCOUNTS[0]} entry in the OS keychain is not an IronDome 3.x vault key"
        )
    with key:
        standard = base64.b64encode(key.view())
        fernet_form = standard.translate(_TO_URLSAFE_BASE64)  # the same object when there was nothing to translate
        if fernet_form is not standard:
            wipe_bytes(standard)
        return fernet_form


def _keychain_forget(account: str) -> Optional[str]:
    """Delete one keychain entry. Returns None once it is confirmed absent, else what went wrong."""
    tool = _keychain_tool()
    if tool is None:
        return f"could not be examined: {_no_tool()}"
    commands = _keychain_commands(tool, account)
    name = os.path.basename(tool)
    status, output = _run_tool(commands["delete"])
    wipe_bytes(output)
    absent = _SECURITY_NOT_FOUND if _PLATFORM == "darwin" else 1
    if status != 0 and not (_PLATFORM == "darwin" and status == absent):
        return f"could not be deleted ({name} exited with status {status})"
    status, output = _run_tool(commands["probe"])
    wipe_bytes(output)
    if status == 0:
        return "is still there after deletion"
    if status != absent:
        return f"could not be confirmed deleted ({name} exited with status {status})"
    return None


def _clear_keychain(errors: List[str]) -> bool:
    cleared = True
    for account in _KEYCHAIN_ACCOUNTS:
        problem = _keychain_forget(account)
        if problem is not None:
            cleared = False
            errors.append(f"OS keychain entry {_KEYCHAIN_SERVICE}/{account} {problem}")
    return cleared


# ---------------------------------------------------------------------------
# Into the new vault
# ---------------------------------------------------------------------------

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://\S+$")


def _name_allows(char: str) -> bool:
    """Whether an entry name may contain *char*, asked of the vault's own rule so the two cannot drift apart."""
    try:
        validate_name(f"a{char}a")
    except UsageError:
        return False
    return True


def _clean(text: str) -> str:
    """*text* with what an entry name may not hold taken out.

    Every character ``validate_name`` refuses (control characters) becomes a
    space, a lone surrogate (which cannot be printed or typed) becomes
    U+FFFD, and space at either end is dropped. Nothing else is changed.
    """
    verdicts: Dict[str, bool] = {}
    cleaned = []
    for char in text:
        if 0xD800 <= ord(char) <= 0xDFFF:
            cleaned.append("\N{REPLACEMENT CHARACTER}")
            continue
        if char not in verdicts:
            verdicts[char] = _name_allows(char)
        cleaned.append(char if verdicts[char] else " ")
    return "".join(cleaned).strip()


def _fit(base: str, suffix: str = "") -> str:
    """*base* plus *suffix*, shortening *base* so the whole stays a valid entry name."""
    return base[: _NAME_LIMIT - len(suffix)].rstrip() + suffix


def _plan_names(entries: Sequence[LegacyEntry]) -> List[str]:
    """The entry name each legacy entry gets, as a function of the legacy entries alone.

    The website; ``website (username)`` when several entries share a website
    (compared without regard to case, as entry names are); ``(2)``, ``(3)``
    ... after that for whatever still collides.
    """
    bases = [_fit(_clean(entry.website) or _UNTITLED) for entry in entries]
    shared = Counter(fold_name(base) for base in bases)
    taken: Set[str] = set()
    names = []
    for entry, base in zip(entries, bases):
        name = base
        user = _clean(entry.username)[:_USER_IN_NAME_LIMIT].rstrip()
        if shared[fold_name(base)] > 1 and user:
            name = _fit(base, f" ({user})")
        candidate = name
        number = 1
        while fold_name(candidate) in taken:
            number += 1
            candidate = _fit(name, f" ({number})")
        taken.add(fold_name(candidate))
        names.append(validate_name(candidate))
    return names


def _looks_like_address(text: str) -> bool:
    """True for ``scheme://something`` and for ``host.tld`` with an optional port and path."""
    if not text or any(char.isspace() or ord(char) < 32 or 0x7F <= ord(char) <= 0x9F for char in text):
        return False
    if _SCHEME.match(text):
        return True
    host, _, port = text.split("/", 1)[0].partition(":")
    if port and not (port.isdigit() and len(port) <= 5):
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or label[0] == "-" or label[-1] == "-":
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False
    if not labels[-1].isdigit():
        return True
    return len(labels) == 4 and all(label.isdigit() and int(label) <= 255 for label in labels)


def _label(entry: LegacyEntry) -> str:
    """How an entry is named in a report: its website and username, cleaned and shortened."""
    website = _clean(entry.website)[:60] or _UNTITLED
    username = _clean(entry.username)[:40]
    return f"{website} ({username})" if username else website


def _names_in(vault: Vault) -> Dict[str, Entry]:
    """The vault's entries by case-folded name, which is how the vault itself tells names apart."""
    return {fold_name(existing.name): existing for existing in vault.entries.values()}


def _username(entry: LegacyEntry) -> str:
    """The username as the vault keeps it: without the control characters it refuses there."""
    return without_control(entry.username)


def _difference(vault: Vault, existing: Entry, entry: LegacyEntry) -> Optional[str]:
    """None when *existing* holds the same username, password and notes as *entry*; else what differs."""
    if existing.username != _username(entry):
        return "the username differs"
    try:
        secret = vault.read_secret(existing)
    except IronDomeError as exc:
        return f"its record cannot be read ({exc})"
    if secret.password != entry.password:
        return "the password differs"
    if secret.notes != entry.notes:
        return "the notes differ"
    return None


def _url(entry: LegacyEntry) -> str:
    """The website, without stray space around it, when it reads as an address; otherwise nothing."""
    website = entry.website.strip()
    return website if _looks_like_address(website) else ""


def _require_import_arguments(vault: Any, entries: Any) -> None:
    if not isinstance(vault, Vault):
        raise UsageError("this needs an open IronDome vault")
    if isinstance(entries, (str, bytes)) or not all(isinstance(entry, LegacyEntry) for entry in entries):
        raise UsageError("this needs the list of entries returned by migrate_v3.read_entries()")


def import_into(vault: Vault, entries: Sequence[LegacyEntry]) -> MigrationReport:
    """Add *entries* to the open *vault*. Does not commit; the caller commits.

    Each entry becomes a login whose name is its website, whose URL is the
    website when that looks like a URL or a host name, and whose username,
    password, notes and times are carried over unchanged -- except that a
    username loses any control character, which the vault refuses there
    (``MigrationReport.cleaned`` names those entries). Several entries for
    one website (compared without regard to case, as entry names are) are
    named ``website (username)``; whatever still collides gets ``(2)``,
    ``(3)`` and so on. A website that is not a valid entry name (control
    characters, space at either end, more than 200 characters, nothing at
    all) is cleaned up first. Agents get no access to an imported entry
    (``agent="deny"``), the default for every new entry.

    An entry already in the vault under the name it would get, with the same
    username, password and notes, is skipped, so running a migration twice
    adds nothing. A name taken by a *different* entry is never reused: the
    newcomer gets the next free ``(2)``, ``(3)`` ... name. An entry the vault
    refuses to store (a field beyond its length limits) is skipped and
    reported with the vault's reason; :func:`verify` then reports it as
    missing.

    If anything fails, the entries added by this call are removed again
    before the exception leaves, so the vault is as it was.
    """
    _require_import_arguments(vault, entries)
    report = MigrationReport(imported=0, renamed=[], skipped=[])
    added: List[Entry] = []
    present = _names_in(vault)
    try:
        for entry, planned in zip(entries, _plan_names(entries)):
            name: Optional[str] = planned
            number = 1
            while name is not None:
                existing = present.get(fold_name(name))
                if existing is None:
                    break
                if _difference(vault, existing, entry) is None:
                    name = None
                else:
                    number += 1
                    name = _fit(planned, f" ({number})")
            if name is None:
                report.skipped.append(f"{_label(entry)}: already in the vault")
                continue
            try:
                created = vault.add(
                    name,
                    Secret(password=entry.password, notes=entry.notes),
                    username=_username(entry),
                    url=_url(entry),
                    created=entry.created,
                    modified=entry.modified,
                )
            except UsageError as exc:  # the vault will not hold it; its messages name the field, never the value
                report.skipped.append(f"{_label(entry)}: {exc}")
                continue
            added.append(created)
            present[fold_name(name)] = created
            if name != entry.website:
                report.renamed.append((entry.website, name))
            if created.username != entry.username:
                report.cleaned.append(f"{_label(entry)}: control characters were taken out of its username")
    except BaseException:
        for undone in reversed(added):
            with contextlib.suppress(IronDomeError):
                vault.remove(undone)
        raise
    report.imported = len(added)
    return report


def verify(vault: Vault, entries: Sequence[LegacyEntry]) -> List[str]:
    """Compare every legacy entry with *vault*. Returns the problems found; an empty list means none.

    An entry passes when the vault holds an entry under the name
    :func:`import_into` gives it (or under one of the ``(2)``, ``(3)`` ...
    names it falls back to) with exactly the same password and notes, and
    the same username as :func:`import_into` stores it (without control
    characters). Everything else is reported, one line per entry, without the
    values. Run it on the vault as reopened from disk before destroying
    anything.
    """
    _require_import_arguments(vault, entries)
    problems = []
    present = _names_in(vault)
    for entry, planned in zip(entries, _plan_names(entries)):
        name = planned
        number = 1
        first_difference: Optional[str] = None
        while True:
            existing = present.get(fold_name(name))
            if existing is None:
                problems.append(f"{_label(entry)}: {first_difference or 'is not in the vault'}")
                break
            difference = _difference(vault, existing, entry)
            if difference is None:
                break
            if first_difference is None:
                first_difference = difference
            number += 1
            name = _fit(planned, f" ({number})")
    return problems


# ---------------------------------------------------------------------------
# Destroying the old vault
# ---------------------------------------------------------------------------


def _matches(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatchcase(name, pattern) for pattern in patterns)


def _scan(top: Path) -> Tuple[List[Path], List[Path], List[str]]:
    """Every non-directory and every directory under *top* (parents before children), and what could not be listed.

    Symbolic links are listed as files and never followed.
    """
    files: List[Path] = []
    directories: List[Path] = []
    unreadable: List[str] = []
    pending = [top]
    while pending:
        directory = pending.pop()
        directories.append(directory)
        try:
            with os.scandir(directory) as listing:
                for item in listing:
                    if item.is_dir(follow_symlinks=False):
                        pending.append(Path(item.path))
                    else:
                        files.append(Path(item.path))
        except OSError as exc:
            unreadable.append(f"could not list {directory}: {_reason(exc)}")
    return files, directories, unreadable


def _unexpected(top: Path, files: List[Path], directories: List[Path]) -> List[str]:
    """Paths under *top* that no 1.x-3.x release put there."""
    strangers = []
    for directory in directories:
        relative = directory.relative_to(top).parts
        if relative and not (len(relative) == 1 and relative[0] in _KNOWN_DIRECTORIES):
            strangers.append(str(directory))
    for path in files:
        relative = path.relative_to(top).parts
        name = relative[-1]
        if _matches(name, _DESKTOP_LITTER):
            continue
        if len(relative) == 1:
            known = _matches(name, _KNOWN_TOP_FILES) or name in _KNOWN_DIRECTORIES  # a link in a directory's place
        elif len(relative) == 2 and relative[0] == "secrets":
            known = _matches(name, _KNOWN_SECRETS_FILES)
        elif len(relative) == 2 and relative[0] == "backups":
            known = _matches(name, _KNOWN_BACKUP_FILES)
        else:
            known = False
        if not known:
            strangers.append(str(path))
    return sorted(strangers)


def _inside(path: Path, top: Path) -> bool:
    return path == top or top in path.parents


def _checked_target(legacy: LegacyVault) -> Tuple[Path, Path, List[Path], List[Path]]:
    """``(root, resolved root, files, directories)`` once destroying them is established as safe; raises otherwise."""
    root = Path(os.path.abspath(os.fspath(legacy.path)))
    located = _locate(root)
    if located is None or located[1] != legacy.salt:
        raise VaultError(
            f"{root} does not hold the IronDome 3.x vault that was detected "
            "(it changed, or is already gone). Nothing was deleted"
        )
    top = Path(os.path.realpath(root))
    keep = [(paths.home(), "the IronDome vault"), (paths.device_dir(), "the IronDome device keys")]
    with contextlib.suppress(RuntimeError):
        keep.append((Path.home(), "your home directory"))
    for kept, what in keep:
        resolved = Path(os.path.realpath(kept))
        if _inside(resolved, top):
            raise UsageError(f"refusing to destroy {top}: {what} ({resolved}) is inside it. Nothing was deleted")
    files, directories, unreadable = _scan(top)
    if unreadable:
        raise UsageError(f"refusing to destroy {top}: {'; '.join(unreadable)}. Nothing was deleted")
    strangers = _unexpected(top, files, directories)
    if strangers:
        shown = ", ".join(strangers[:5]) + (f" and {len(strangers) - 5} more" if len(strangers) > 5 else "")
        raise UsageError(
            f"refusing to destroy {top}: it holds things IronDome 3.x did not put there ({shown}). "
            "Move them away or delete the directory yourself. Nothing was deleted"
        )
    return root, top, files, directories


def _destroy_order(path: Path) -> Tuple[int, str]:
    """Salt first: once it is gone, a password store that survives can no longer be decrypted."""
    if path.name == _SALT_FILE:
        return 0, str(path)
    return (1 if path.name.endswith(".enc") else 2), str(path)


def _link_target_outside(path: Path, top: Path) -> Optional[Path]:
    """Where a symbolic link leads, when that exists and lies outside the tree being destroyed."""
    if not path.is_symlink():
        return None
    target = Path(os.path.realpath(path))
    return target if os.path.lexists(target) and not _inside(target, top) else None


def _has_other_names(path: Path) -> bool:
    """True for a regular file that is also linked under another name, inside the tree or outside it."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_nlink > 1


def destroy_legacy(legacy: LegacyVault, *, keychain: bool = True) -> LegacyDestroyReport:
    """Destroy the old vault: its directory tree and, when they are this vault's, its keychain entries.

    Before anything is touched the directory must still hold the vault that
    was detected (same salt), must not contain the IronDome 4 vault, its
    device keys or the home directory, and must hold nothing but files the
    old versions created; otherwise this raises and deletes nothing.

    Then, in this order: the keychain entries ``master_key``,
    ``recovery_hash`` and ``auth_mode`` (only when *keychain* is true and the
    vault is the one at ``~/.password_manager`` of this account, the only
    vault they can belong to); every ``salt.bin``; the password stores and
    backups; everything else; the directories. Files are overwritten once and
    unlinked (``paths.secure_delete``). Symbolic links are removed, never
    followed, and a link target outside the tree is reported as a leftover. A
    file that has a second name (a hard link) is unlinked without being
    overwritten, and reported: overwriting it would destroy what the other
    name holds, which may lie outside the tree.

    Failures do not stop the run: everything that can be destroyed is, and the
    report names what could not. ``leftovers`` is taken from the disk after
    the run, not from what the run believes it did.
    """
    _require_vault(legacy)
    root, top, files, directories = _checked_target(legacy)
    errors: List[str] = []
    deleted: List[str] = []
    beyond: List[str] = []
    cleared = _clear_keychain(errors) if keychain and _owns_keychain(root) else None

    for directory in directories:
        with contextlib.suppress(OSError):  # a read-only directory would keep its contents from being unlinked
            os.chmod(directory, paths.DIR_MODE)
    for path in sorted(files, key=_destroy_order):
        target = _link_target_outside(path, top)
        shared = _has_other_names(path)
        try:
            if shared:
                os.unlink(path)
            else:
                paths.secure_delete(path)
        except OSError as exc:
            errors.append(f"could not delete {path}: {_reason(exc)}")
            continue
        deleted.append(str(path))
        if target is not None:
            beyond.append(str(target))
            errors.append(f"{path} was a symbolic link; what it pointed to, {target}, was not deleted")
        if shared:
            errors.append(f"{path} has another name (a hard link); its contents remain under that name")
    for directory in reversed(directories):
        try:
            os.rmdir(directory)
        except OSError as exc:
            if exc.errno not in (errno.ENOTEMPTY, errno.EEXIST):  # not empty: the file left in it is already named
                errors.append(f"could not remove the directory {directory}: {_reason(exc)}")
    if root != top and not os.path.lexists(top):
        try:
            os.unlink(root)
        except OSError as exc:
            errors.append(f"could not remove the link {root}: {_reason(exc)}")

    leftovers: List[str] = []
    if os.path.lexists(top):
        remaining_files, remaining_directories, _ = _scan(top)
        leftovers.extend(str(path) for path in remaining_files + remaining_directories)
    if root != top and os.path.lexists(root):
        leftovers.append(str(root))
    leftovers = sorted(leftovers) + beyond
    return LegacyDestroyReport(
        success=not leftovers and not errors and cleared is not False,
        files_deleted=deleted,
        leftovers=leftovers,
        keychain_cleared=cleared,
        errors=errors,
    )
