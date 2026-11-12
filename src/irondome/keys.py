"""Keyslots: the ways into a vault.

One random 256-bit **vault key** encrypts everything. It is never stored. A
vault file carries one or more *keyslots*, each holding the vault key wrapped
(AES-256-GCM) under a key-encryption key derived from that slot's factors::

    password slot   Argon2id(master password)  +  device secret
    device slot     device secret under a biometric policy      (Touch ID)
    recovery slot   a 160-bit recovery key shown once at setup

    factor keys ──HKDF──▶ key-encryption key ──AES-256-GCM──▶ vault key

A **password slot** needs both factors. The device secret comes from a
:mod:`irondome.device` backend (Secure Enclave, TPM 2.0, or a file where there
is no chip), so a copy of the vault file cannot be attacked offline: without
the device there is nothing to test a guessed password against. Where the
backend supports it (TPM) the chip itself verifies a password-derived value
and rate-limits wrong guesses.

A **device slot** has no password at all: the Secure Enclave releases the
device secret only after a fingerprint match, so the fingerprint is enforced
by hardware on the key operation itself.

A **recovery slot** is deliberately independent of the device, because its job
is to survive losing it. The price is stated wherever it matters: whoever
holds the recovery key and a copy of the vault file can open that copy.
Destroying the device key (``nuke``) cannot reach a recovery key on paper.

Changing a password or enrolling a finger rewrites one slot. The vault key,
and so every record, stays put: what retires the old slot is destroying its
device secret, after which no copy of the old slot opens anything. A
recovery slot has no device secret, so taking it out of the file retires
nothing: whoever kept the old slot (any earlier copy of the file) and the old
key still has the vault key. Replacing or removing the recovery key therefore
re-keys the vault (``irondome recovery new`` and ``recovery remove`` run the
re-key of ``irondome rekey``).

Retiring device secrets survives interruptions. Before a vault file that adds
or drops keyslots is written, :func:`record_retirement` notes every device
secret the change involves; :func:`finish_retirement` then destroys exactly
those the vault file on disk does not use. Run again by the next command after
a crash or a power cut, it finishes the change whichever side of the write the
interruption fell on, and it never touches a secret the live vault needs.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from irondome import device as devices
from irondome import paths
from irondome.crypto import (
    KEY_LEN,
    NONCE_LEN,
    SALT_LEN,
    TAG_LEN,
    Argon2Params,
    DecryptError,
    argon2id,
    b64d,
    b64e,
    hkdf,
    open_sealed_into,
    seal,
)
from irondome.device.base import POLICY_DEVICE, DeviceBackend
from irondome.errors import AuthError, HardwareError, IronDomeError, UsageError, VaultError
from irondome.secmem import BufferLike, SecureBuffer, _wipe_str, as_view, wipe_bytes

__all__ = [
    "KIND_PASSWORD",
    "KIND_DEVICE",
    "KIND_RECOVERY",
    "VAULT_ID_LEN",
    "RETIREMENT_FILE",
    "Keyslot",
    "new_vault_key",
    "create_password_slot",
    "create_device_slot",
    "create_recovery_slot",
    "open_slot",
    "destroy_slot_device",
    "destroy_device",
    "record_retirement",
    "finish_retirement",
    "normalise_password",
    "format_recovery_key",
    "parse_recovery_key",
]

KIND_PASSWORD = "password"  # noqa: S105 - the name of a keyslot kind, not a credential
KIND_DEVICE = "device"
KIND_RECOVERY = "recovery"
_KINDS = (KIND_PASSWORD, KIND_DEVICE, KIND_RECOVERY)

VAULT_ID_LEN = 16
_SLOT_ID_LEN = 16
_SLOT_ID = re.compile(r"[0-9a-f]{%d}" % (_SLOT_ID_LEN * 2))
_WRAP_LEN = NONCE_LEN + KEY_LEN + TAG_LEN  # a sealed 32-byte vault key
_MAX_TIME = 2**63 - 1
_RECOVERY_BYTES = 20  # 160 bits: far beyond guessing, so no slow KDF is needed
_RECOVERY_DIGITS = _RECOVERY_BYTES * 8 // 5  # 32 base32 digits, written in groups of four
_BASE32 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
#: The value of each base32 digit once upper-cased, and of 0, 1 and 8, typed for the letters they look like.
_BASE32_VALUE = {chr(code): value for value, code in enumerate(_BASE32)}
_BASE32_VALUE.update({"0": _BASE32_VALUE["O"], "1": _BASE32_VALUE["I"], "8": _BASE32_VALUE["B"]})

_LABEL_SLOT = b"irondome/v4/slot\x00"
_LABEL_KEK = b"irondome/v4/kek/"
_LABEL_DEVICE = b"irondome/v4/device/"
_LABEL_DEVICE_AUTH = b"irondome/v4/device-auth"
_LABEL_RECOVERY = b"irondome/v4/recovery"

#: The record of device secrets a keyslot change is retiring, in the bunker's vault directory.
RETIREMENT_FILE = "retire-keyslots.json"
_RETIREMENT_FORMAT = "irondome-keyslot-retirement"
_RETIREMENT_VERSION = 1
_MAX_RETIRING = 256  # a vault holds at most 32 keyslots, so one change names at most 64


@dataclass
class Keyslot:
    """One wrapped copy of the vault key, plus the public data needed to unwrap it."""

    id: str
    kind: str
    wrap: str
    created: int = 0
    label: str = ""
    kdf: Optional[Dict[str, Any]] = None
    device: Optional[Dict[str, Any]] = None
    salt: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "created": self.created,
            "label": self.label,
            "wrap": self.wrap,
        }
        if self.kdf is not None:
            data["kdf"] = self.kdf
        if self.device is not None:
            data["device"] = self.device
        if self.salt is not None:
            data["salt"] = self.salt
        return data

    @classmethod
    def from_dict(cls, data: Any) -> "Keyslot":
        if not isinstance(data, dict):
            raise VaultError("keyslot is malformed")
        slot_id = data.get("id")
        if not isinstance(slot_id, str) or not _SLOT_ID.fullmatch(slot_id):
            raise VaultError("keyslot id is malformed")
        kind = data.get("kind")
        if not isinstance(kind, str) or kind not in _KINDS:
            raise VaultError("keyslot has an unknown kind")
        wrap = data.get("wrap")
        if not isinstance(wrap, str) or len(b64d(wrap, what="keyslot wrap")) != _WRAP_LEN:
            raise VaultError("keyslot wrap is malformed")
        created = data.get("created", 0)
        label = data.get("label", "")
        if (
            not isinstance(created, int)
            or isinstance(created, bool)
            or not 0 <= created <= _MAX_TIME
            or not isinstance(label, str)
        ):
            raise VaultError("keyslot metadata is malformed")
        kdf = data.get("kdf")
        device = data.get("device")
        salt = data.get("salt")
        if kind == KIND_PASSWORD:
            if not isinstance(kdf, dict) or kdf.get("alg") != "argon2id":
                raise VaultError("password keyslot has no Argon2id parameters")
            Argon2Params.from_dict(kdf)
            if len(b64d(kdf.get("salt"), what="Argon2id salt")) < SALT_LEN:
                raise VaultError("Argon2id salt is too short")
        elif kdf is not None:
            raise VaultError(f"{kind} keyslot must not carry password parameters")
        if kind == KIND_DEVICE and not isinstance(device, dict):
            raise VaultError("device keyslot has no device descriptor")
        if kind == KIND_RECOVERY:
            if device is not None:
                raise VaultError("recovery keyslot must not be bound to a device")
            if len(b64d(salt, what="recovery salt")) < SALT_LEN:
                raise VaultError("recovery salt is too short")
        elif salt is not None:
            raise VaultError(f"{kind} keyslot must not carry a recovery salt")
        if device is not None:
            if not isinstance(device, dict) or not isinstance(device.get("backend"), str):
                raise VaultError("keyslot device descriptor is malformed")
        return cls(id=slot_id, kind=kind, wrap=wrap, created=created, label=label, kdf=kdf, device=device, salt=salt)

    # -- convenience ----------------------------------------------------------

    @property
    def backend_name(self) -> Optional[str]:
        return self.device.get("backend") if self.device else None

    @property
    def policy(self) -> Optional[str]:
        return self.device.get("policy") if self.device else None

    @property
    def needs_password(self) -> bool:
        return self.kind == KIND_PASSWORD

    def describe(self) -> str:
        if self.kind == KIND_RECOVERY:
            return "recovery key"
        parts = []
        if self.kind == KIND_PASSWORD:
            parts.append("master password")
        if self.device:
            policy = self.device.get("policy")
            backend = self.device.get("backend")
            if policy == POLICY_DEVICE:
                parts.append(f"device key ({backend})")
            else:
                parts.append(f"{'Touch ID' if policy == 'biometry' else 'Touch ID or login password'} ({backend})")
        return " + ".join(parts)


# ---------------------------------------------------------------------------
# Passwords and recovery keys as bytes
# ---------------------------------------------------------------------------


def normalise_password(password: BufferLike) -> SecureBuffer:
    """Return the bytes that are fed to Argon2id.

    ASCII passwords are used exactly as typed. Anything else is normalised to
    Unicode NFKC first, so the same passphrase typed on a different keyboard
    or operating system still produces the same key. (Normalising needs a
    ``str``, so only non-ASCII passwords pass through one. IronDome decodes
    and encodes it by hand, so that the two ``str`` objects it makes, the text
    as typed and as normalised, are the only copies it makes, and on CPython
    it zeroes both in place before this function returns. Python's
    ``unicodedata.normalize`` keeps working copies of its own, as 4-byte code
    points, and frees them without overwriting them: IronDome cannot reach
    those. See the boundary of the ``keys-wiped`` claim.)
    """
    view = memoryview(password.view() if isinstance(password, SecureBuffer) else password)
    if len(view) == 0:
        raise UsageError("the master password cannot be empty")
    if all(byte < 0x80 for byte in view):
        return SecureBuffer.from_buffer(view)
    import unicodedata

    text = _decode_utf8(view)
    if text is None:
        return SecureBuffer.from_buffer(view)  # not text: use the bytes as they are
    normalised = text
    try:
        normalised = unicodedata.normalize("NFKC", text)
        return _encode_utf8(normalised)
    finally:
        _wipe_str(normalised)
        _wipe_str(text)


def _decode_utf8(view: memoryview) -> Optional[str]:
    """*view* decoded as strict UTF-8 (exactly what Python's own codec accepts), or None if it is not UTF-8.

    Decoded one code point at a time and joined once, so the ``str`` returned
    is the only copy of the text. ``bytes.decode`` builds its result in a
    buffer sized for the worst case and shrinks it at the end; when the
    allocator moves the block (CPython 3.9 does, for this size), a whole copy
    of the text stays behind in freed memory.
    """
    chars: List[str] = []
    size = len(view)
    index = 0
    while index < size:
        lead = view[index]
        if lead < 0x80:
            point, extra, smallest = lead, 0, 0
        elif 0xC2 <= lead <= 0xDF:
            point, extra, smallest = lead & 0x1F, 1, 0x80
        elif 0xE0 <= lead <= 0xEF:
            point, extra, smallest = lead & 0x0F, 2, 0x800
        elif 0xF0 <= lead <= 0xF4:
            point, extra, smallest = lead & 0x07, 3, 0x10000
        else:
            return None
        if index + extra >= size:
            return None
        for offset in range(1, extra + 1):
            follow = view[index + offset]
            if follow & 0xC0 != 0x80:
                return None
            point = point << 6 | follow & 0x3F
        if point < smallest or 0xD800 <= point <= 0xDFFF or point > 0x10FFFF:
            return None
        chars.append(chr(point))  # one character: never a copy of the text
        index += extra + 1
    return "".join(chars)  # sized from its parts: one allocation, never resized


def _encode_utf8(text: str) -> SecureBuffer:
    """*text* as UTF-8, written straight into locked memory.

    ``str.encode`` builds a short result in a buffer on the C stack and copies
    it into a ``bytes`` object; both would be copies of the password.
    """
    length = 0
    for char in text:
        point = ord(char)
        length += 1 if point < 0x80 else 2 if point < 0x800 else 3 if point < 0x10000 else 4
    out = SecureBuffer(length)
    try:
        view = out.view()
        position = 0
        for char in text:
            point = ord(char)
            if point < 0x80:
                count, lead = 1, 0
            elif point < 0x800:
                count, lead = 2, 0xC0
            elif point < 0x10000:
                count, lead = 3, 0xE0
            else:
                count, lead = 4, 0xF0
            for offset in range(count - 1, 0, -1):
                view[position + offset] = 0x80 | point & 0x3F
                point >>= 6
            view[position] = lead | point
            position += count
    except BaseException:
        out.wipe()
        raise
    return out


def format_recovery_key(raw: BufferLike) -> str:
    """The recovery key as a person writes it down: 32 base32 digits in groups of four.

    Encoded by hand into a buffer that is zeroed before this returns, so the
    ``str`` it returns is the only copy of the text it makes (``base64``
    leaves three more behind, unwiped). That ``str`` is the caller's to show
    and then to zero.
    """
    view = as_view(raw)
    if len(view) != _RECOVERY_BYTES:
        raise ValueError(f"a recovery key is {_RECOVERY_BYTES} bytes")
    text = bytearray(_RECOVERY_DIGITS + _RECOVERY_DIGITS // 4 - 1)
    try:
        pending = bits = digits = position = 0
        for index in range(_RECOVERY_BYTES):
            pending = (pending << 8 | view[index]) & 0xFFF
            bits += 8
            while bits >= 5:
                bits -= 5
                if digits and not digits % 4:
                    text[position] = 0x2D  # "-"
                    position += 1
                text[position] = _BASE32[pending >> bits & 0x1F]
                position += 1
                digits += 1
        return text.decode("ascii")
    finally:
        wipe_bytes(text)


def _decode_recovery_key(text: str, out: Any) -> None:
    """Decode *text*, typed in any case with any separators, into the 20 writable bytes of *out*.

    Read a character at a time, each upper-cased on its own as ``str.upper``
    would (a ``ß`` stands for ``SS``): no upper-cased, joined or encoded copy
    of the text is made. Raises :class:`AuthError`; *out* may then hold part
    of a key, and is the caller's to wipe.
    """
    digits = 0
    for char in text:
        for upper in char.upper():
            if upper.isalnum():
                digits += 1
    if digits != _RECOVERY_DIGITS:
        raise AuthError("that is not a valid recovery key (wrong length)")
    pending = bits = index = 0
    for char in text:
        for upper in char.upper():
            if not upper.isalnum():
                continue
            value = _BASE32_VALUE.get(upper)
            if value is None:
                raise AuthError("that is not a valid recovery key")
            pending = (pending << 5 | value) & 0xFFF
            bits += 5
            if bits >= 8:
                bits -= 8
                out[index] = pending >> bits & 0xFF
                index += 1


def parse_recovery_key(text: str) -> bytes:
    """Decode a recovery key as a human typed it: any case, any separators.

    The result is key material in an immutable object: the caller passes it
    to :func:`irondome.secmem.wipe_bytes` when done. (:func:`open_slot` does
    not use this: it decodes straight into locked memory.)
    """
    scratch = bytearray(_RECOVERY_BYTES)
    try:
        _decode_recovery_key(text, scratch)
        return bytes(scratch)
    finally:
        wipe_bytes(scratch)


# ---------------------------------------------------------------------------
# Deriving the key-encryption key
# ---------------------------------------------------------------------------


def _binding(vault_id: bytes, slot_id: str) -> bytes:
    if len(vault_id) != VAULT_ID_LEN:
        raise VaultError("vault id has the wrong length")
    return vault_id + bytes.fromhex(slot_id)


def _kek(kind: str, factor_names: List[str], factors: List[SecureBuffer], binding: bytes) -> SecureBuffer:
    """Combine the factor keys into the key-encryption key for one slot."""
    with SecureBuffer(KEY_LEN * len(factors)) as material:
        view = material.view()
        for index, factor in enumerate(factors):
            view[index * KEY_LEN : (index + 1) * KEY_LEN] = factor.view()
        info = _LABEL_KEK + kind.encode("ascii") + b"/" + "+".join(factor_names).encode("ascii")
        return hkdf(material, info=info, salt=binding)


def _slot_aad(binding: bytes, kind: str) -> bytes:
    return _LABEL_SLOT + binding + kind.encode("ascii")


def _device_key(backend: DeviceBackend, raw: SecureBuffer, binding: bytes) -> SecureBuffer:
    return hkdf(raw, info=_LABEL_DEVICE + backend.name.encode("ascii"), salt=binding)


def _wrap(vault_key: SecureBuffer, kek: SecureBuffer, binding: bytes, kind: str) -> str:
    if len(vault_key) != KEY_LEN:
        raise ValueError("the vault key must be 32 bytes")
    return b64e(seal(kek, vault_key, _slot_aad(binding, kind)))


def new_vault_key() -> SecureBuffer:
    return SecureBuffer.random(KEY_LEN)


# ---------------------------------------------------------------------------
# Creating slots
# ---------------------------------------------------------------------------


def create_password_slot(
    vault_key: SecureBuffer,
    password: BufferLike,
    vault_id: bytes,
    *,
    params: Argon2Params,
    backend: Optional[DeviceBackend],
    policy: str = POLICY_DEVICE,
    label: str = "",
    reason: str = "protect your IronDome vault",
) -> Keyslot:
    """A slot opened by the master password plus, normally, this device.

    ``backend=None`` makes a portable slot with no device factor. That is what
    ``irondome backup`` writes, and nothing else should.
    """
    slot_id = os.urandom(_SLOT_ID_LEN).hex()
    binding = _binding(vault_id, slot_id)
    salt = os.urandom(SALT_LEN)
    descriptor: Optional[Dict[str, Any]] = None
    names = ["password"]
    with normalise_password(password) as secret, argon2id(secret, salt, params) as password_key:
        factors = [password_key]
        device_key: Optional[SecureBuffer] = None
        try:
            if backend is not None:
                with hkdf(password_key, info=_LABEL_DEVICE_AUTH, salt=binding) as auth:
                    descriptor, raw = backend.enroll(policy=policy, auth=auth, reason=reason)
                try:
                    with raw:
                        device_key = _device_key(backend, raw, binding)
                except BaseException:
                    _discard(backend, descriptor)
                    raise
                factors.append(device_key)
                names.append("device")
            try:
                with _kek(KIND_PASSWORD, names, factors, binding) as kek:
                    wrap = _wrap(vault_key, kek, binding, KIND_PASSWORD)
            except BaseException:
                if backend is not None and descriptor is not None:
                    _discard(backend, descriptor)
                raise
        finally:
            if device_key is not None:
                device_key.wipe()
    kdf: Dict[str, Any] = {"alg": "argon2id", "salt": b64e(salt)}
    kdf.update(params.to_dict())
    return Keyslot(
        id=slot_id, kind=KIND_PASSWORD, wrap=wrap, created=int(time.time()), label=label, kdf=kdf, device=descriptor
    )


def create_device_slot(
    vault_key: SecureBuffer,
    vault_id: bytes,
    *,
    backend: DeviceBackend,
    policy: str,
    label: str = "",
    reason: str = "enrol Touch ID for your IronDome vault",
) -> Keyslot:
    """A slot opened by the device alone, under a biometric or presence policy."""
    if policy == POLICY_DEVICE:
        raise UsageError("a slot with no password must require a biometric or presence check")
    slot_id = os.urandom(_SLOT_ID_LEN).hex()
    binding = _binding(vault_id, slot_id)
    descriptor, raw = backend.enroll(policy=policy, auth=None, reason=reason)
    try:
        with raw, _device_key(backend, raw, binding) as device_key:
            with _kek(KIND_DEVICE, ["device"], [device_key], binding) as kek:
                wrap = _wrap(vault_key, kek, binding, KIND_DEVICE)
    except BaseException:
        _discard(backend, descriptor)
        raise
    return Keyslot(id=slot_id, kind=KIND_DEVICE, wrap=wrap, created=int(time.time()), label=label, device=descriptor)


def create_recovery_slot(vault_key: SecureBuffer, vault_id: bytes, *, label: str = "") -> Tuple[Keyslot, str]:
    """A slot opened by a fresh recovery key. Returns ``(slot, key to show once)``."""
    slot_id = os.urandom(_SLOT_ID_LEN).hex()
    binding = _binding(vault_id, slot_id)
    salt = os.urandom(SALT_LEN)
    with SecureBuffer.random(_RECOVERY_BYTES) as raw:
        with hkdf(raw, info=_LABEL_RECOVERY, salt=salt) as recovery_key:
            with _kek(KIND_RECOVERY, ["recovery"], [recovery_key], binding) as kek:
                wrap = _wrap(vault_key, kek, binding, KIND_RECOVERY)
        text = format_recovery_key(raw)  # the text a person is shown: the one copy left, the caller's to zero
    slot = Keyslot(id=slot_id, kind=KIND_RECOVERY, wrap=wrap, created=int(time.time()), label=label, salt=b64e(salt))
    return slot, text


def _discard(backend: DeviceBackend, descriptor: Dict[str, Any]) -> bool:
    """Destroy a device secret while unwinding from a failed enrolment.

    Never raises: the error that caused the unwinding is the one to report.
    Returns whether the backend confirmed the destruction.
    """
    try:
        backend.destroy(descriptor)
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# Opening a slot
# ---------------------------------------------------------------------------


def open_slot(
    slot: Keyslot,
    vault_id: bytes,
    *,
    password: Optional[BufferLike] = None,
    recovery_key: Optional[str] = None,
    interactive: bool = True,
    reason: str = "unlock your IronDome vault",
) -> SecureBuffer:
    """Unwrap the vault key with this slot's factors.

    Raises :class:`AuthError` when a factor is wrong or refused and
    :class:`HardwareError` when the device factor is not available here.
    """
    binding = _binding(vault_id, slot.id)
    factors: List[SecureBuffer] = []
    names: List[str] = []
    try:
        if slot.kind == KIND_RECOVERY:
            if recovery_key is None:
                raise UsageError("this keyslot needs the recovery key")
            with SecureBuffer(_RECOVERY_BYTES) as raw:
                _decode_recovery_key(recovery_key, raw.view())
                factors.append(hkdf(raw, info=_LABEL_RECOVERY, salt=b64d(slot.salt, what="recovery salt")))
            names.append("recovery")
        else:
            auth: Optional[SecureBuffer] = None
            try:
                if slot.kind == KIND_PASSWORD:
                    if password is None:
                        raise UsageError("this keyslot needs the master password")
                    if slot.kdf is None:
                        raise VaultError("password keyslot has no Argon2id parameters")
                    params = Argon2Params.from_dict(slot.kdf)
                    with normalise_password(password) as secret:
                        password_key = argon2id(secret, b64d(slot.kdf.get("salt"), what="Argon2id salt"), params)
                    factors.append(password_key)
                    names.append("password")
                    auth = hkdf(password_key, info=_LABEL_DEVICE_AUTH, salt=binding)
                if slot.device is not None:
                    backend = devices.get_backend(str(slot.device.get("backend")))
                    with backend.unseal(slot.device, auth=auth, interactive=interactive, reason=reason) as raw_device:
                        factors.append(_device_key(backend, raw_device, binding))
                    names.append("device")
            finally:
                if auth is not None:
                    auth.wipe()
        vault_key = SecureBuffer(KEY_LEN)
        try:
            with _kek(slot.kind, names, factors, binding) as kek:
                open_sealed_into(kek, b64d(slot.wrap, what="keyslot wrap"), _slot_aad(binding, slot.kind), vault_key)
        except DecryptError:
            vault_key.wipe()
            if slot.kind == KIND_RECOVERY:
                raise AuthError("that recovery key does not open this vault") from None
            if slot.kind == KIND_PASSWORD:
                raise AuthError("wrong master password") from None
            raise AuthError("this device key does not open the vault") from None
        except BaseException:
            vault_key.wipe()
            raise
        return vault_key
    finally:
        for factor in factors:
            factor.wipe()


def destroy_slot_device(slot: Keyslot) -> bool:
    """Destroy the device secret behind a slot. Returns False if it has none."""
    if slot.device is None:
        return False
    destroy_device(slot.device)
    return True


def destroy_device(descriptor: Dict[str, Any]) -> None:
    """Destroy one device secret and check with its backend that it is gone. One already gone is fine."""
    backend = devices.get_backend(str(descriptor.get("backend")))
    backend.destroy(descriptor)
    if backend.exists(descriptor):
        raise HardwareError(f"the {backend.name} device key survived destruction")


# ---------------------------------------------------------------------------
# Retiring device secrets across an interruption
# ---------------------------------------------------------------------------


def _identity(descriptor: Dict[str, Any]) -> str:
    """One device secret, whatever the order of its descriptor's keys."""
    return json.dumps(descriptor, sort_keys=True, separators=(",", ":"))


def _retirement_path() -> Path:
    return paths.home() / RETIREMENT_FILE


def _read_retirement(path: Path) -> List[Dict[str, Any]]:
    """The device descriptors recorded in *path*. Raises :class:`VaultError` if it is not such a record."""
    try:
        document = json.loads(paths.read_file(path).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise VaultError("it is not valid JSON") from None
    if (
        not isinstance(document, dict)
        or document.get("format") != _RETIREMENT_FORMAT
        or document.get("version") != _RETIREMENT_VERSION
        or not isinstance(document.get("devices"), list)
        or len(document["devices"]) > _MAX_RETIRING
    ):
        raise VaultError("it is not a record of device keys to retire")
    devices_named: List[Dict[str, Any]] = []
    for descriptor in document["devices"]:
        if not isinstance(descriptor, dict) or not isinstance(descriptor.get("backend"), str):
            raise VaultError("it names a device key it does not describe")
        devices_named.append(descriptor)
    return devices_named


def _write_retirement(path: Path, descriptors: Sequence[Dict[str, Any]]) -> None:
    document = {"format": _RETIREMENT_FORMAT, "version": _RETIREMENT_VERSION, "devices": list(descriptors)}
    paths.write_atomic(path, (json.dumps(document, indent=1, sort_keys=True) + "\n").encode("utf-8"))


def record_retirement(slots: Sequence[Keyslot]) -> bool:
    """Note the device secrets of *slots* before a vault file that adds or drops those slots is written.

    Pass every slot the change removes and every slot it adds, with the vault lock held
    (``paths.file_lock()``); then write the vault file, then call :func:`finish_retirement`. Returns
    whether anything was recorded: slots without a device secret need nothing. What an earlier change
    left recorded is kept. A record that cannot be read stops the change before anything is written.
    """
    descriptors = [slot.device for slot in slots if slot.device is not None]
    if not descriptors:
        return False
    path = _retirement_path()
    recorded: List[Dict[str, Any]] = []
    if os.path.lexists(path):
        try:
            recorded = _read_retirement(path)
        except (VaultError, OSError) as exc:
            raise VaultError(
                f"the record of device keys to retire ({path}) cannot be read ({exc}); nothing was changed"
            ) from None
    known = {_identity(item) for item in recorded}
    recorded += [descriptor for descriptor in descriptors if _identity(descriptor) not in known]
    if len(recorded) > _MAX_RETIRING:
        raise VaultError(f"{path} already names {_MAX_RETIRING} device keys to retire; nothing was changed")
    _write_retirement(path, recorded)
    return True


def finish_retirement() -> List[str]:
    """Destroy the recorded device secrets that the vault file on disk does not use. Returns what went wrong.

    Run it after the write that :func:`record_retirement` prepared, and at the start of any later command:
    after an interruption it destroys the old slots' secrets if the new file was written, and the new
    slots' secrets if it was not. It holds the vault lock, so it never acts between another command's
    record and that command's write. While the vault file cannot be read nothing is destroyed and the
    record stays: a secret goes only once it is certain that the live vault does not use it. A secret
    that cannot be destroyed stays recorded for the next call; the record is deleted once it is empty.
    """
    path = _retirement_path()
    if not os.path.lexists(path):
        return []
    from irondome.vault import VaultFile  # here, not at the top: irondome.vault imports this module

    with paths.file_lock(paths.lock_file()):
        if not os.path.lexists(path):
            return []  # another command finished it while this one waited for the lock
        try:
            recorded = _read_retirement(path)
        except OSError as exc:
            return [f"the record of device keys to retire ({path}) cannot be read: {exc.strerror or exc}"]
        except VaultError as exc:
            try:
                os.unlink(str(path))
            except OSError as gone:
                return [f"the record of device keys to retire ({path}) is damaged ({exc}) and cannot be removed: "
                        f"{gone.strerror or gone}"]
            return [f"the record of device keys to retire ({path}) was damaged ({exc}) and was removed; "
                    "old device keys it named may still be on this machine"]
        try:
            live = VaultFile.load()
        except VaultError:
            return []  # nothing can be decided without the vault file, and the command says what is wrong with it
        in_use = {_identity(slot.device) for slot in live.slots if slot.device is not None}
        problems: List[str] = []
        left: List[Dict[str, Any]] = []
        for descriptor in recorded:
            if _identity(descriptor) in in_use:
                continue  # the vault on disk uses it: its change did not happen, or this is the slot it added
            try:
                destroy_device(descriptor)
            except (IronDomeError, OSError) as exc:
                left.append(descriptor)
                problems.append(
                    f"an old {descriptor.get('backend')} device key could not be destroyed yet ({exc}). The vault "
                    "here no longer uses it, but a copy of the vault file made before the change still opens with "
                    "it; the next command that opens the vault tries again"
                )
        try:
            if left:
                _write_retirement(path, left)
            else:
                os.unlink(str(path))
        except OSError as exc:
            problems.append(f"the record of device keys to retire ({path}) could not be updated: {exc.strerror or exc}")
        return problems
