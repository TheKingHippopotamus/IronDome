"""The primitives IronDome is built from, and nothing else.

==============  =============================================================
Password KDF    Argon2id (RFC 9106), parameters stored per keyslot
Key derivation  HKDF-SHA256 (RFC 5869), one label per purpose
Encryption      AES-256-GCM (NIST SP 800-38D): 96-bit random nonce, 128-bit tag
Randomness      the operating system CSPRNG
==============  =============================================================

All of it comes from the ``cryptography`` package (pyca), IronDome's single
runtime dependency. Nothing here is invented: this module only fixes
parameters, binds every ciphertext to its context through the associated data,
and makes sure keys go in and come out through :class:`~irondome.secmem.SecureBuffer`
rather than through immutable ``bytes``.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from irondome.errors import IronDomeError, VaultError
from irondome.secmem import BufferLike, SecureBuffer, as_view, wipe_bytes

__all__ = [
    "KEY_LEN",
    "NONCE_LEN",
    "TAG_LEN",
    "SALT_LEN",
    "DecryptError",
    "Argon2Params",
    "DEFAULT_ARGON2",
    "default_argon2",
    "argon2id",
    "hkdf",
    "seal",
    "open_sealed",
    "open_sealed_into",
    "pad",
    "unpad",
    "b64e",
    "b64d",
    "random_bytes",
]

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
SALT_LEN = 16


class DecryptError(IronDomeError):
    """Authenticated decryption failed: wrong key, or the data was altered."""


def random_bytes(length: int) -> bytes:
    """Public random values: salts, nonces, identifiers. Never use it for keys."""
    return os.urandom(length)


# ---------------------------------------------------------------------------
# Argon2id
# ---------------------------------------------------------------------------

# Bounds enforced whenever parameters are used. The upper bounds stop a tampered
# header from making an unlock attempt allocate all the RAM in the machine or
# run for a week. The lower bounds are the OWASP Password Storage Cheat Sheet's
# Argon2id minimum: 19 MiB with two passes, or 46 MiB with a single pass.
# Parameters cannot be weakened by editing the file either way: they are part
# of the derivation, so a slot whose parameters were changed no longer opens.
_MIN_MEMORY_KIB = 19 * 1024
_MIN_SINGLE_PASS_MEMORY_KIB = 46 * 1024
_MAX_MEMORY_KIB = 4 * 1024 * 1024
_MAX_ITERATIONS = 64
_MAX_LANES = 16


@dataclass(frozen=True)
class Argon2Params:
    """Argon2id cost parameters. ``memory_kib`` is in kibibytes."""

    memory_kib: int = 262_144  # 256 MiB
    iterations: int = 3
    lanes: int = 4

    def validate(self) -> "Argon2Params":
        for name in ("memory_kib", "iterations", "lanes"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise VaultError(f"Argon2id parameter {name} is not an integer")
        if not _MIN_MEMORY_KIB <= self.memory_kib <= _MAX_MEMORY_KIB:
            raise VaultError(f"Argon2id memory cost {self.memory_kib} KiB is outside the accepted range")
        if not 1 <= self.iterations <= _MAX_ITERATIONS:
            raise VaultError(f"Argon2id iteration count {self.iterations} is outside the accepted range")
        if not 1 <= self.lanes <= _MAX_LANES:
            raise VaultError(f"Argon2id lane count {self.lanes} is outside the accepted range")
        if self.memory_kib < 8 * self.lanes:
            raise VaultError("Argon2id memory cost is too small for its lane count")
        if self.iterations == 1 and self.memory_kib < _MIN_SINGLE_PASS_MEMORY_KIB:
            raise VaultError(
                f"Argon2id with a single pass needs at least {_MIN_SINGLE_PASS_MEMORY_KIB // 1024} MiB "
                "(the OWASP minimum); use two passes or more memory"
            )
        return self

    def to_dict(self) -> Dict[str, int]:
        return {"m": self.memory_kib, "t": self.iterations, "p": self.lanes}

    @classmethod
    def from_dict(cls, data: Any) -> "Argon2Params":
        if not isinstance(data, dict):
            raise VaultError("Argon2id parameters are malformed")
        try:
            return cls(memory_kib=data["m"], iterations=data["t"], lanes=data["p"]).validate()
        except KeyError as exc:
            raise VaultError(f"Argon2id parameter {exc} is missing") from None


#: RFC 9106 recommends t=3, p=4 with as much memory as can be spared; 256 MiB
#: costs about a quarter of a second on a 2020 laptop.
DEFAULT_ARGON2 = Argon2Params()


def _physical_memory_bytes() -> Optional[int]:
    try:
        return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, ValueError, OSError):
        return None


def default_argon2() -> Argon2Params:
    """The default cost, scaled down on machines too small to afford it.

    ``IRONDOME_KDF_MEMORY_MIB`` overrides the memory cost (used by the test
    suite to stay fast, and by people who want it higher).
    """
    override = os.environ.get("IRONDOME_KDF_MEMORY_MIB")
    if override:
        try:
            return Argon2Params(memory_kib=int(override) * 1024).validate()
        except ValueError:
            raise VaultError("IRONDOME_KDF_MEMORY_MIB must be a whole number of mebibytes") from None
    total = _physical_memory_bytes()
    if total is not None and total < 3 * 1024**3:
        return Argon2Params(memory_kib=64 * 1024)  # RFC 9106's low-memory profile
    return DEFAULT_ARGON2


def argon2id(password: BufferLike, salt: bytes, params: Argon2Params) -> SecureBuffer:
    """Stretch *password* into a 32-byte key, written straight into locked memory.

    pyca/cryptography copies the password it is given into memory it frees
    without overwriting. IronDome cannot reach that copy safely, so it has the
    library overwrite it: Argon2id is run once more from this same frame, at
    the lowest cost there is, with an all-zero password and salt of the same
    lengths. The second run asks the allocator for blocks of the same sizes
    in the same order and is handed the ones just freed. That is the
    allocator's choice, not a guarantee: see the boundary of the keys-wiped
    claim for where it is checked.
    """
    params.validate()
    if len(salt) < SALT_LEN:
        raise VaultError("Argon2id salt is too short")
    view = as_view(password)
    out = SecureBuffer(KEY_LEN)
    try:
        kdf = Argon2id(
            salt=salt,
            length=KEY_LEN,
            iterations=params.iterations,
            lanes=params.lanes,
            memory_cost=params.memory_kib,
        )
        try:
            kdf.derive_into(view, out.view())  # type: ignore[arg-type, unused-ignore]  # any buffer is accepted
        except MemoryError:
            raise VaultError(
                f"not enough memory to stretch the password: Argon2id is set to use {params.memory_kib // 1024} MiB "
                "and this machine would not give it that much. Free some memory and try again; for a new vault or "
                "backup, IRONDOME_KDF_MEMORY_MIB sets a lower cost"
            ) from None
        finally:
            # Also when the derivation failed (too little memory for its cost): the copy was made before that.
            try:
                again = Argon2id(salt=bytes(len(salt)), length=KEY_LEN, iterations=1, lanes=params.lanes,
                                 memory_cost=8 * params.lanes)
                again.derive_into(bytes(len(view)), bytearray(KEY_LEN))
            except Exception:  # noqa: S110 - a refused second run must not change what the first one did
                pass
    except BaseException:
        out.wipe()
        raise
    return out


# ---------------------------------------------------------------------------
# HKDF
# ---------------------------------------------------------------------------


def hkdf(ikm: BufferLike, info: bytes, salt: Optional[bytes] = None, length: int = KEY_LEN) -> SecureBuffer:
    """Derive a purpose-bound key. *info* is the purpose label and is mandatory.

    pyca/cryptography leaves its working keys behind, the intermediate key
    it extracts and the key it derives: in its own frames on the C stack and
    in memory it frees without overwriting. So the
    derivation is run a second time from this same frame, with an all-zero
    key of the same length and the same label, salt and output length. The
    second run takes the same path through the same code, puts its working
    values where the first run put them, and what is left afterwards is a
    key derived from zeros.
    """
    if not info:
        raise ValueError("HKDF needs a purpose label")
    view = as_view(ikm)
    out = SecureBuffer(length)
    try:
        HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive_into(view, out.view())
        zeros, scratch = bytes(len(view)), bytearray(length)
        HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive_into(zeros, scratch)
    except BaseException:
        out.wipe()
        raise
    return out


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------


def _cipher(key: BufferLike) -> AESGCM:
    view = as_view(key)
    if len(view) != KEY_LEN:
        raise ValueError("AES-256-GCM needs a 32-byte key")
    return AESGCM(view)


def seal(key: BufferLike, plaintext: BufferLike, aad: bytes) -> bytes:
    """Encrypt and authenticate. Returns ``nonce || ciphertext || tag``.

    *aad* names what this ciphertext is and where it belongs; decryption under
    any other context fails. The cipher object, which holds an expanded copy
    of the key inside OpenSSL, is dropped before returning so that copy is
    cleansed immediately instead of whenever the garbage collector gets to it.
    """
    nonce = os.urandom(NONCE_LEN)
    cipher = _cipher(key)
    try:
        body = cipher.encrypt(nonce, as_view(plaintext), aad)
    finally:
        del cipher
    return nonce + body


def _split(blob: bytes) -> "tuple[bytes, bytes]":
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise DecryptError("ciphertext is truncated")
    return blob[:NONCE_LEN], blob[NONCE_LEN:]


def open_sealed(key: BufferLike, blob: bytes, aad: bytes) -> bytearray:
    """Decrypt :func:`seal` output into a ``bytearray`` the caller must wipe."""
    nonce, body = _split(blob)
    out = bytearray(len(body) - TAG_LEN)
    cipher = _cipher(key)
    try:
        cipher.decrypt_into(nonce, body, aad, out)
    except InvalidTag:
        wipe_bytes(out)
        raise DecryptError("decryption failed: wrong key, or the data was altered") from None
    except BaseException:
        wipe_bytes(out)
        raise
    finally:
        del cipher
    return out


def open_sealed_into(key: BufferLike, blob: bytes, aad: bytes, out: SecureBuffer) -> None:
    """Decrypt key material directly into a :class:`SecureBuffer`.

    The cipher writes into *out* before it has checked the tag, so on any
    failure *out* is zeroed: nothing unauthenticated is left for a caller to
    use by mistake.
    """
    nonce, body = _split(blob)
    if len(body) - TAG_LEN != len(out):
        raise DecryptError("ciphertext has the wrong length for this key")
    cipher = _cipher(key)
    view = out.view()
    try:
        cipher.decrypt_into(nonce, body, aad, view)
    except InvalidTag:
        view[:] = bytes(len(view))
        raise DecryptError("decryption failed: wrong key, or the data was altered") from None
    except BaseException:
        view[:] = bytes(len(view))
        raise
    finally:
        del cipher


# ---------------------------------------------------------------------------
# Length hiding and text encoding
# ---------------------------------------------------------------------------


def pad(data: BufferLike, block: int) -> bytearray:
    """Prefix the length and pad with zeros to a multiple of *block* bytes.

    A ciphertext is as long as its plaintext, so without this the size of a
    record would reveal the length of the password inside it.
    """
    view = as_view(data)
    total = -(-(4 + len(view)) // block) * block
    out = bytearray(total)
    out[:4] = len(view).to_bytes(4, "big")
    out[4 : 4 + len(view)] = view
    return out


def unpad(data: BufferLike) -> bytearray:
    """Inverse of :func:`pad`. The result is a copy the caller must wipe."""
    view = as_view(data)
    if len(view) < 4:
        raise VaultError("record is too short to hold its length")
    length = int.from_bytes(view[:4], "big")
    if length > len(view) - 4:
        raise VaultError("record length field is inconsistent")
    return bytearray(view[4 : 4 + length])


def b64e(data: BufferLike) -> str:
    return base64.b64encode(as_view(data)).decode("ascii")


def b64d(text: Any, *, what: str = "value") -> bytes:
    """Decode standard base64, accepting only the canonical encoding of the result.

    What ``base64`` tolerates beyond that (stray padding, unused bits that
    are not zero) differs between Python versions; a file must not be valid
    on one interpreter and damaged on another.
    """
    if not isinstance(text, str):
        raise VaultError(f"{what} is not a base64 string")
    try:
        decoded = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise VaultError(f"{what} is not valid base64") from None
    if base64.b64encode(decoded).decode("ascii") != text:
        raise VaultError(f"{what} is not valid base64")
    return decoded
