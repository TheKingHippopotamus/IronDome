"""Capabilities: sessions for the vault's owner, grants for agents and scripts.

A *session* spares a person from retyping the master password for a while.
A *grant* is what a person hands to an AI agent or a script in place of a
secret. Both come in two halves that are useless apart, and both work only on
the machine they were made on:

* a **token**, shown once and stored nowhere by IronDome. It lives in the
  holder's environment (``IRONDOME_SESSION`` / ``IRONDOME_GRANT``)::

      irondome_s_<32 hex: id>_<52 base32: 256 random bits>      session
      irondome_g_<32 hex: id>_<52 base32: 256 random bits>      grant

  The fixed prefix is there so secret scanners can find a leaked token;
  :data:`TOKEN_PATTERN` is the expression to give them.

* a **file**, ``caps/<id>.json`` (format 2), holding the payload sealed with
  AES-256-GCM under a key that needs both the token and this machine::

      device key   = HKDF(device secret, "irondome/v4/cap/device", salt = vault id)
      wrapping key = HKDF(token secret || device key,
                          "irondome/v4/cap/" + kind + "/token+device", salt)

  The header beside it (kind, id, vault id, creation and expiry times, uses
  left, label, and the descriptor of the device secret) is readable, and all
  of it is bound into the ciphertext as associated data: change any of it and
  the file no longer opens. Files of format 1, which needed the token alone,
  are not capabilities any more.

A session's payload is the vault key: full access, meant for the owner's own
shell and for nothing else. A grant's payload is a snapshot of exactly the
values that were named when it was made, its mode, and a key that lets its
holder write audit records about itself. A grant never holds the vault key,
the master password or anything that was not named, and for a one-time
password it holds the codes for its own lifetime, never the seed.

Starting a session, making a grant and each use of a grant are written to the
audit log by this module, and they do not happen without it: a session or
grant that cannot be recorded is not created, and a grant whose use cannot be
recorded is not opened. Ending, revoking and sweeping are never held up by
the log; they are recorded when the caller passes the open vault.

Binding to the machine
----------------------
Every vault has one *capability device secret*, held by a device backend
(:mod:`irondome.device`) under the ``device`` policy: this machine releases it
to a program of the logged-in user with no password and no touch. With the
Secure Enclave it is a key that any process of the owner can use once the Mac
has been unlocked after it started; with a TPM it is an NV index whose authorisation value is empty,
which any process of any account allowed to use the TPM can read; with the
file-based backend it is a file in the device directory only the owner can
read. Its descriptor lives in the vault's encrypted index
(``meta["cap_device"]``) and a copy of it in the header of every capability.

It is made the first time a session or grant is created for the vault, and
made again whenever the one recorded cannot be used on this machine: the
vault was restored elsewhere with its recovery key, the secret was
destroyed, or the backend has it but cannot unseal it (a damaged key file, a
Secure Enclave key file copied from another Mac). The one replaced is not
forgotten: capabilities made under it still name it, so the index keeps
every descriptor it replaced (``meta["cap_device_retired"]``) and
:func:`destroy_device` destroys those too. When the backend works here but
cannot even tell whether the recorded secret is still here (a TPM that does
not answer), or the secret is here and its backend does not work now,
nothing is replaced (and so nothing weaker is bound): the session or grant
is refused with :class:`HardwareError` and can be tried again. Opening a capability asks the
backend for the secret named in its header. When that secret is not on this
machine, the capability is dead.

What this buys: a capability file and its token are useless anywhere but on
this machine, and useless here as well once the device secret is destroyed.
``nuke`` destroys it together with every other device secret of the bunker,
so a copy of the capability directory restored afterwards opens nothing,
whichever token is presented; ``rekey`` does the same for one vault through
:func:`destroy_device`, which takes every device secret the vault has
recorded. How final that destruction is depends on the backend, exactly as
for keyslots (see :mod:`irondome.nuke`).

What this module cannot do
--------------------------
* On this machine a token together with its file is as good as what is
  inside. Any process that holds both and may use the device secret (every
  process of the owner, and with a TPM every account that may use the TPM)
  can read the payload without IronDome (the format is public), and then
  nothing is counted or recorded.
* Expiry and use counts are enforced by this code and by destroying the
  file, not by hardware; the binding to the machine does not change that. A
  process that holds a grant token and can read the file can copy the file
  before a use and put it back afterwards, and a restored backup of the
  directory brings a used grant back until it expires. Time is whatever this
  machine's clock says.
* Destroying a file means overwriting and unlinking it; a file that has
  another name (a hard link a backup tool made, say) is only unlinked, and
  the other name keeps it (see :func:`irondome.paths.secure_delete`). On an
  SSD the old blocks can survive an overwrite. Either way what is left stays
  unreadable without the token, and without the device secret once that is
  destroyed.
* The Secure Enclave key behind sessions and grants is usable once the Mac
  has been unlocked after it started, and stays usable while the screen is
  locked (``AfterFirstUnlockThisDeviceOnly``). Until that first unlock, a
  session or grant does not open. Keys that need Touch ID or a password are
  usable only while the screen is unlocked.
* The first session or grant of a vault on a machine records the device
  secret by committing the vault, so whatever else is pending in the
  :class:`~irondome.vault.Vault` passed in is written with it. The audit log
  records the session or grant, not the device secret.
* Mode ``use`` keeps values out of an agent's transcript by default, because
  IronDome's own commands then only inject them into a child process. It
  cannot stop that process from printing its environment, and it cannot stop
  a token holder from decrypting the file itself.
* A token is a Python string in a process environment. It cannot be wiped
  from memory the way keys are.
* :func:`list_caps` shows headers nobody has authenticated. Anything that can
  write the directory can make it show anything; only opening a capability
  with its token proves what it is.
"""

from __future__ import annotations

import base64
import errno
import json
import os
import re
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, Iterator, List, Optional, Tuple, Type

from irondome import audit, config, otp, paths
from irondome import device as devices
from irondome.crypto import (
    KEY_LEN,
    NONCE_LEN,
    SALT_LEN,
    TAG_LEN,
    DecryptError,
    b64d,
    b64e,
    hkdf,
    open_sealed,
    open_sealed_into,
    pad,
    seal,
    unpad,
)
from irondome.device.base import POLICY_DEVICE, DeviceBackend, check_descriptor
from irondome.errors import AuthError, HardwareError, IronDomeError, NotFoundError, PolicyError, UsageError, VaultError
from irondome.keys import VAULT_ID_LEN
from irondome.secmem import BufferLike, SecureBuffer, as_view, wipe_bytes

if TYPE_CHECKING:
    from irondome.vault import Vault, VaultFile

__all__ = [
    "KIND_SESSION",
    "KIND_GRANT",
    "MODE_USE",
    "MODE_REVEAL",
    "MODES",
    "TOKEN_PATTERN",
    "session_expires",
    "session_mark",
    "SESSION_TTL_MIN",
    "SESSION_TTL_MAX",
    "GRANT_TTL_MIN",
    "GRANT_TTL_MAX",
    "TOTP_GRANT_TTL_MAX",
    "MAX_REFERENCES",
    "MAX_USES",
    "CapInfo",
    "GrantInfo",
    "Grant",
    "parse_token",
    "create_session",
    "open_session",
    "end_sessions",
    "create_grant",
    "open_grant",
    "list_caps",
    "revoke",
    "sweep",
    "destroy_all",
    "destroy_device",
    "bound_devices",
]

KIND_SESSION = "session"
KIND_GRANT = "grant"

#: Values may only be injected into a child process by ``irondome run``.
MODE_USE = "use"
#: Values may also be printed.
MODE_REVEAL = "reveal"
MODES = (MODE_USE, MODE_REVEAL)

#: Matches every well-formed token and nothing else. Unanchored, for scanners.
TOKEN_PATTERN = r"irondome_[sg]_[0-9a-f]{32}_[A-Z2-7]{51}[AQ]"  # noqa: S105 (an expression, not a token)

SESSION_TTL_MIN = 60
SESSION_TTL_MAX = 12 * 3600
GRANT_TTL_MIN = 60
GRANT_TTL_MAX = 30 * 86400
#: A grant that includes a one-time password carries one code per time step.
TOTP_GRANT_TTL_MAX = 86400
MAX_REFERENCES = 64
MAX_USES = 1_000_000

_TOKEN = re.compile(r"irondome_([sg])_([0-9a-f]{32})_([A-Z2-7]{51}[AQ])")
_KIND_OF = {"s": KIND_SESSION, "g": KIND_GRANT}
_LETTER_OF = {KIND_SESSION: "s", KIND_GRANT: "g"}
_FILE_NAME = re.compile(r"([0-9a-f]{32})\.json", re.IGNORECASE)
_ID_PREFIX = re.compile(r"[0-9a-f]{6,32}")
_COUNTER = re.compile(r"0|[1-9][0-9]{0,19}")
_SCHEME = "irondome://"

_FORMAT = 2
_ID_LEN = 16
_SECRET_LEN = 32
_LABEL_KEY = b"irondome/v4/cap/"
_LABEL_FACTORS = b"/token+device"
_LABEL_DEVICE = b"irondome/v4/cap/device"
_LABEL_AAD = b"irondome/v4/cap\x00"
_HEADER_KEYS = frozenset(
    ("v", "kind", "id", "vault_id", "created", "expires", "uses_left", "label", "device", "salt", "wrap")
)
#: Where the vault's index records its capability device secret.
_META_DEVICE = "cap_device"
#: Where the vault's index lists the capability device secrets it replaced, oldest first.
_META_RETIRED = "cap_device_retired"
#: Shown by no backend: the device policy never asks anyone for anything.
_DEVICE_REASON = "open an IronDome session or grant"
#: The fields of the descriptors each backend writes (see irondome.device). Nothing else is a capability's.
_DESCRIPTOR_FIELDS: Dict[str, FrozenSet[str]] = {
    "macos-se": frozenset(("backend", "policy", "ref")),
    "linux-tpm2": frozenset(("backend", "policy", "ref", "nv_index")),
    "software": frozenset(("backend", "policy", "ref")),
}
_DESCRIPTOR_VALUE = re.compile(r"[0-9a-z][0-9a-z-]{0,63}")
_PAYLOAD_KEYS = frozenset(("vault_id", "mode", "items", "audit_key"))
_VALUE_KEYS = frozenset(("entry", "field", "value"))
_TOTP_KEYS = frozenset(("entry", "field", "period", "digits", "codes"))
_TOTP_FIELD = "totp"

_PAD_BLOCK = 256
_MAX_LABEL = 200
_MAX_REFERENCE = 512
_MAX_ENTRY_NAME = 200
_MAX_FIELD_NAME = 64
_MAX_TIME = 2**40
_MAX_COUNTER = 2**64 - 1
_MAX_PAYLOAD = 8 * 1024 * 1024
_MAX_FILE = 16 * 1024 * 1024
_LOCK_NAME = ".lock"
_TEMPORARY = ".tmp-"  # how paths.write_atomic names a file it has not renamed yet
_OWNER = "owner"
_HOLDER = "grant"

_SESSION_GONE = (
    "that session token opens nothing here: the session ended or expired, or it was started on "
    "another machine. Start a new one with: irondome unlock"
)
_GRANT_GONE = (
    "that grant token opens nothing here: the grant was used up, expired or revoked, or it was made on "
    "another machine. Its owner can make a new one with: irondome grant create"
)
_SESSION_DEAD = (
    "that session token cannot be used here: the session belongs to another machine or to a vault that was "
    "destroyed (the device key it is bound to is not on this machine). Start a new one with: irondome unlock"
)
_GRANT_DEAD = (
    "that grant token cannot be used here: the grant belongs to another machine or to a vault that was destroyed "
    "(the device key it is bound to is not on this machine). Its owner can make a new one with: irondome grant create"
)


class _Malformed(Exception):
    """A capability file that IronDome did not write, or that was altered."""


# ---------------------------------------------------------------------------
# What callers see
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapInfo:
    """One session or grant as its file's header describes it. Not authenticated."""

    id: str
    kind: str
    created: int
    expires: int
    uses_left: Optional[int]
    label: str
    expired: bool


@dataclass(frozen=True)
class GrantInfo:
    """What :func:`create_grant` made. ``uses_left`` is ``None`` for unlimited."""

    id: str
    mode: str
    created: int
    expires: int
    uses_left: Optional[int]
    label: str
    references: Tuple[str, ...]


@dataclass(frozen=True, repr=False)
class _Item:
    """One granted reference. ``value`` and ``codes`` are left empty when a grant is only looked at."""

    entry: str
    field: str
    value: str = ""
    period: int = 0
    codes: Dict[int, str] = dataclass_field(default_factory=dict)


class Grant:
    """An opened grant: the references one token reaches, and their values.

    ``mode`` says what IronDome's commands may do with the values (see
    :data:`MODE_USE`, :data:`MODE_REVEAL`); enforcing it is the caller's part.
    ``uses_left`` is what remains after this opening, ``None`` for unlimited.
    ``audit_key`` and ``vault_id`` are what :func:`irondome.audit.record`
    needs to write a record under this grant's id.

    A grant opened with ``consume=False`` is for looking at: it lists its
    references and holds no values, so no value can be read without a use
    being spent and recorded. The values of a consumed grant are ordinary
    strings for as long as this object lives; :meth:`close` drops them and
    wipes the audit key.
    """

    def __init__(
        self,
        header: "_Header",
        mode: str,
        items: Dict[str, _Item],
        audit_key: SecureBuffer,
        *,
        consumed: bool,
        uses_left: Optional[int],
    ) -> None:
        self.id = header.id
        self.vault_id = header.vault_id
        self.mode = mode
        self.created = header.created
        self.expires = header.expires
        self.uses_left = uses_left
        self.label = header.label
        self.consumed = consumed
        self.audit_key = audit_key
        self._items = items
        self._closed = False

    def names(self) -> List[str]:
        """The references this grant covers, sorted."""
        return sorted(self._items)

    def has(self, reference: str) -> bool:
        """True if *reference* (with or without ``irondome://``) is covered."""
        return isinstance(reference, str) and _strip_scheme(reference) in self._items

    def is_totp(self, reference: str) -> bool:
        """True if *reference* is covered and stands for a one-time password."""
        item = self._items.get(_strip_scheme(reference)) if isinstance(reference, str) else None
        return item is not None and item.field == _TOTP_FIELD

    def source(self, reference: str) -> Tuple[str, str]:
        """The entry name and field *reference* stood for when the grant was made."""
        item = self._item(reference)
        return item.entry, item.field

    def value(self, reference: str) -> str:
        """The granted value, or the one-time password that is valid now.

        Raises :class:`PolicyError` if *reference* is not in the grant, if the
        grant was opened with ``consume=False`` or has been closed, and
        :class:`AuthError` once the grant has expired, even if it was opened
        before that.
        """
        item = self._item(reference)
        if self._closed:
            raise PolicyError("this grant has been closed; open it again to read from it")
        if not self.consumed:
            raise PolicyError(
                "this grant was opened only to look at what it covers and holds no values; "
                "open it with consume=True to spend a use and read them"
            )
        if _now() >= self.expires:
            raise AuthError("this grant has expired")
        if item.field == _TOTP_FIELD:
            return otp.code_from_window(item.codes, item.period)
        return item.value

    def period(self, reference: str) -> int:
        """The time step, in seconds, of the one-time password *reference* stands for.

        Raises :class:`PolicyError` if *reference* is not in the grant or is
        not a one-time password, and if the grant holds no values (it was only
        looked at, or it has been closed).
        """
        item = self._item(reference)
        if item.field != _TOTP_FIELD:
            raise PolicyError(f"{reference!r} is not a one-time password")
        if self._closed or not self.consumed:
            raise PolicyError("this grant holds no values; open it with consume=True to read them")
        return item.period

    def close(self) -> None:
        """Drop the values and wipe the audit key. Idempotent."""
        self._closed = True
        self._items = {name: _Item(entry=item.entry, field=item.field) for name, item in self._items.items()}
        self.audit_key.wipe()

    def _item(self, reference: str) -> _Item:
        item = self._items.get(_strip_scheme(reference)) if isinstance(reference, str) else None
        if item is None:
            raise PolicyError(f"this grant does not cover {reference!r}")
        return item

    def __enter__(self) -> "Grant":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<Grant {self.id} mode={self.mode} references={len(self._items)}>"


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


def parse_token(text: str) -> Tuple[str, str, bytes]:
    """Split a token into ``(kind, id, secret)``; :class:`AuthError` if it is not one.

    Exactly one string encodes each (kind, id, secret): lower-case hex,
    upper-case base32 without padding, unused bits zero, nothing before or
    after. The secret comes back as ``bytes`` because the token it was read
    from is already an immutable string; callers in this module wipe their
    copy once the wrapping key is derived.
    """
    match = _TOKEN.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        raise AuthError(
            "that is not an IronDome token. A session token starts with irondome_s_, a grant token with "
            "irondome_g_, and both are 96 characters long: check that all of it was copied"
        )
    return _KIND_OF[match.group(1)], match.group(2), base64.b32decode(match.group(3) + "====")


def _token(kind: str, cap_id: str, secret: SecureBuffer) -> str:
    raw = bytes(secret.view())
    try:
        encoded = base64.b32encode(raw).decode("ascii").rstrip("=")
    finally:
        wipe_bytes(raw)
    return f"irondome_{_LETTER_OF[kind]}_{cap_id}_{encoded}"


def _wrap_key(kind: str, secret: BufferLike, device_key: BufferLike, salt: bytes) -> SecureBuffer:
    """The key a capability is sealed under: HKDF over the token secret and the device key, side by side.

    Both halves are fixed-length and are joined in locked memory that is
    wiped before this returns.
    """
    token_part, device_part = as_view(secret), as_view(device_key)
    if len(token_part) != _SECRET_LEN or len(device_part) != KEY_LEN:
        raise ValueError("a capability key is made from a 32-byte token secret and a 32-byte device key")
    with SecureBuffer(_SECRET_LEN + KEY_LEN) as material:
        view = material.view()
        view[:_SECRET_LEN] = token_part
        view[_SECRET_LEN:] = device_part
        return hkdf(material, info=_LABEL_KEY + kind.encode("ascii") + _LABEL_FACTORS, salt=salt)


# ---------------------------------------------------------------------------
# The device secret
# ---------------------------------------------------------------------------

#: A descriptor as a header holds it: its fields, sorted, so that a header stays hashable.
_Descriptor = Tuple[Tuple[str, str], ...]


def _descriptor(value: Any) -> _Descriptor:
    """A device descriptor as a capability may carry it. Raises :class:`_Malformed` for anything else.

    Headers come from a directory anyone running as the owner can write, so
    only the exact shape each backend writes passes: the backend's own
    fields, each one short lower-case text, the ``device`` policy, and what
    :func:`irondome.device.base.check_descriptor` accepts. The backend
    validates it once more before it acts on it, and the whole descriptor is
    bound into the associated data, so a descriptor that passes here and was
    swapped all the same opens nothing.
    """
    if not isinstance(value, dict):
        raise _Malformed()
    backend = value.get("backend")
    fields = _DESCRIPTOR_FIELDS.get(backend) if isinstance(backend, str) else None
    if fields is None or set(value) != fields:
        raise _Malformed()
    if not all(isinstance(item, str) and _DESCRIPTOR_VALUE.fullmatch(item) for item in value.values()):
        raise _Malformed()
    if value["policy"] != POLICY_DEVICE:
        raise _Malformed()
    try:
        check_descriptor(value, str(backend))
    except VaultError:
        raise _Malformed() from None
    return tuple(sorted(value.items()))


def _descriptor_bytes(device: _Descriptor) -> bytes:
    return json.dumps(dict(device), sort_keys=True, separators=(",", ":")).encode("ascii")


def _derived_device_key(raw: SecureBuffer, vault_id: bytes) -> SecureBuffer:
    return hkdf(raw, info=_LABEL_DEVICE, salt=vault_id)


def _unseal(backend: DeviceBackend, device: _Descriptor) -> SecureBuffer:
    return backend.unseal(dict(device), auth=None, interactive=False, reason=_DEVICE_REASON)


def _usable_here(device: _Descriptor) -> Optional[SecureBuffer]:
    """The device secret behind the descriptor the vault records, or ``None`` if this machine cannot give it.

    ``None`` when the backend cannot run here, says the secret is not here
    (another machine, a destroyed secret), or works and still cannot unseal
    it (a damaged key file, a Secure Enclave key file of another Mac). A new
    secret then takes its place and this one goes on the vault's list of
    retired secrets (:func:`_record`), which :func:`destroy_device` destroys
    as well: capabilities made under it name it in their headers and keep
    working wherever it can still be unsealed.

    :class:`HardwareError` when replacing it would be a guess: the backend
    works here but cannot say whether the secret is here (a TPM that does
    not answer), or the secret is here and its backend does not work now (a
    helper that does not run). Nothing is made, nothing weaker takes its
    place, and the caller can try again.
    """
    descriptor = dict(device)
    try:
        backend = devices.get_backend(descriptor["backend"])
    except IronDomeError:
        return None  # a backend this installation cannot even load holds nothing on this machine
    try:
        here = backend.exists(descriptor)
    except IronDomeError as exc:
        if not _works_here(backend):
            return None
        raise _try_again("checked", exc) from None
    if not here:
        return None
    try:
        return _unseal(backend, device)
    except IronDomeError as exc:
        if _works_here(backend):
            return None
        raise _try_again("used", exc) from None


def _try_again(what: str, exc: IronDomeError) -> HardwareError:
    return HardwareError(
        f"the device key this vault's sessions and grants are bound to cannot be {what} now ({exc}); "
        "nothing was made. Try again"
    )


def _discard(backend: DeviceBackend, descriptor: Dict[str, Any]) -> None:
    """Destroy a device secret that was made and then not recorded. Never raises: the first error is reported."""
    try:
        backend.destroy(descriptor)
    except Exception:
        return


def _recorded(vault: "Vault") -> Optional[_Descriptor]:
    """The descriptor the vault's index records, if it is one capabilities can be bound to."""
    value = vault.meta.get(_META_DEVICE)
    if value is None:
        return None
    try:
        return _descriptor(value)
    except _Malformed:
        return None  # written by something else: a new secret replaces it


def _retired(vault: "Vault") -> List[_Descriptor]:
    """The descriptors the vault's index lists as replaced, oldest first. What is not a descriptor is skipped."""
    value = vault.meta.get(_META_RETIRED)
    found: List[_Descriptor] = []
    for item in value if isinstance(value, list) else []:
        try:
            device = _descriptor(item)
        except _Malformed:
            continue  # nothing could be destroyed through it
        if device not in found:
            found.append(device)
    return found


def _every_bound(vault: "Vault") -> List[_Descriptor]:
    """Every device secret the vault's index names: the one recorded now, then the ones it replaced."""
    recorded = _recorded(vault)
    every = [] if recorded is None else [recorded]
    return every + [device for device in _retired(vault) if device not in every]


def _record(vault: "Vault", device: _Descriptor, replaced: Optional[_Descriptor]) -> None:
    """Write *device* into the vault's index, add *replaced* to its retired secrets, and commit.

    The index is left exactly as it was if that fails.
    """
    before = {key: vault.meta[key] for key in (_META_DEVICE, _META_RETIRED) if key in vault.meta}
    retired = _retired(vault)
    if replaced is not None and replaced != device and replaced not in retired:
        retired.append(replaced)
    vault.meta[_META_DEVICE] = dict(device)
    if retired:
        vault.meta[_META_RETIRED] = [dict(item) for item in retired]
    try:
        vault.commit(snapshots=config.get("snapshots"))
    except BaseException:
        for key in (_META_DEVICE, _META_RETIRED):
            if key in before:
                vault.meta[key] = before[key]
            else:
                vault.meta.pop(key, None)
        raise


def _bound_device(vault: "Vault") -> Tuple[_Descriptor, SecureBuffer]:
    """The vault's capability device descriptor and the device key it gives. The caller wipes the key.

    The descriptor in the vault's index is used while its secret can be
    unsealed on this machine. Otherwise a new secret is enrolled with the
    strongest backend that offers the device policy here, recorded in the
    index together with the descriptor it replaces (on the list of retired
    secrets, so that :func:`destroy_device` still reaches the capabilities
    made under it) and committed; if any of that fails the new secret is
    destroyed again and the vault's index is left as it was.
    :class:`HardwareError`, and nothing made, when the backend cannot tell
    whether the recorded secret is here (see :func:`_usable_here`).
    """
    _refuse_while_rekeying()  # every session and grant that is made comes through here
    vault_id = vault.vault_id
    recorded = _recorded(vault)
    if recorded is not None:
        raw = _usable_here(recorded)
        if raw is not None:
            with raw:
                return recorded, _derived_device_key(raw, vault_id)
    backend = devices.choose_backend(POLICY_DEVICE)
    descriptor, raw = backend.enroll(policy=POLICY_DEVICE, auth=None, reason=_DEVICE_REASON)
    try:
        with raw:
            try:
                device = _descriptor(descriptor)
            except _Malformed:
                raise HardwareError(
                    f"the {backend.name} device backend made a device key that sessions and grants cannot be bound to"
                ) from None
            key = _derived_device_key(raw, vault_id)
        try:
            _record(vault, device, replaced=recorded)
        except BaseException:
            key.wipe()
            raise
    except BaseException:
        _discard(backend, descriptor)
        raise
    return device, key


def _works_here(backend: DeviceBackend) -> bool:
    """Whether *backend* is available on this machine at all."""
    try:
        return backend.probe().available
    except IronDomeError:
        return False


def _present(backend: DeviceBackend, descriptor: Dict[str, Any]) -> bool:
    """Whether a device secret is still on this machine, for deciding what a failed unseal means.

    When the backend cannot even say, the secret counts as present if the
    backend works here at all: a backend that is not available on this
    machine (a TPM key on a Mac) holds nothing here.
    """
    try:
        return backend.exists(descriptor)
    except IronDomeError:
        return _works_here(backend)


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


# ---------------------------------------------------------------------------
# A re-key that stopped after its switch
# ---------------------------------------------------------------------------

#: The re-keyed vault that ``irondome rekey`` (and ``recovery new`` / ``recovery remove``) builds beside the live
#: one, ``.tmp-rekey-<hex>.irondome`` in the bunker's directory. It is deleted once the re-key has finished.
REKEY_STAGING_PREFIX = ".tmp-rekey-"
REKEY_STAGING_SUFFIX = ".irondome"
#: In a re-keyed vault's encrypted index: what the vault it replaced leaves to destroy, until that is destroyed.
REKEY_PLAN = "rekey"


def rekey_staging_files() -> List[Path]:
    """The staging files of re-keys in the bunker's directory: one running now, or ones that did not finish."""
    try:
        found = list(paths.home().glob(f"{REKEY_STAGING_PREFIX}*{REKEY_STAGING_SUFFIX}"))
    except OSError:
        return []
    return sorted(path for path in found if path.is_file() and not path.is_symlink())


def unfinished_rekey() -> Optional[Path]:
    """The staging file of a re-key that switched to its new vault and has not finished, or ``None``. Needs no key.

    That staging file holds the live vault's own id: the new vault key took over, but what the old one opens
    (its device keys, snapshots, sessions and grants) may not all be destroyed yet. A re-key deletes the file
    last of all, so while it is there the re-key is either running now or stopped (SIGKILL, a crash, a power
    cut). A staging file with another id is from a re-key that stopped before its switch, which changed nothing
    that opens the vault; the next ``rekey`` deletes it.
    """
    staged = rekey_staging_files()
    if not staged:
        return None
    from irondome.vault import VaultFile  # only a type at the top of this module

    try:
        live = VaultFile.load().vault_id
    except (IronDomeError, OSError):
        return None
    for path in staged:
        try:
            if VaultFile.load(path).vault_id == live:
                return path
        except (IronDomeError, OSError):
            continue  # torn or unreadable: written by a re-key that stopped before its switch
    return None


def unfinished_rekey_warning(path: Path) -> str:
    """What a command that finds :func:`unfinished_rekey` tells the owner: the cause, and how to finish."""
    return (
        f"a re-key of bunker {paths.bunker_name()} stopped after the new vault key took over (its staging file "
        f"{path.name} is still there), before everything the old vault key opens was destroyed. Until it "
        "finishes, no session or grant can be used or made, and the new recovery key it made may never have "
        "been shown. Finish it with: irondome rekey (it shows a new recovery key)"
    )


def _refuse_while_rekeying() -> None:
    """Fail closed: refuse every session and grant while a re-key that switched has not finished.

    Ending the sessions and grants made before a re-key is part of what it does after its switch. Were they
    honoured meanwhile, one that stopped there would leave them working until the owner happened to re-key again.
    """
    path = unfinished_rekey()
    if path is not None:
        raise AuthError(
            f"sessions and grants of bunker {paths.bunker_name()} cannot be used now: a re-key of its vault has "
            f"not finished (its staging file {path.name} is still there). If none is running, it stopped after "
            "the new vault key took over, and the owner finishes it with: irondome rekey"
        )


def _opening_key(header: "_Header", path: Path, dead: str) -> SecureBuffer:
    """The device key the capability in *header* was sealed under. The caller wipes it.

    Every session and grant that is opened comes through here, so this is where an unfinished re-key
    refuses them all (:func:`_refuse_while_rekeying`), before anything is unsealed.

    Raises :class:`AuthError`: with *dead* when its device secret is not on
    this machine (made on another one, or destroyed since), and saying the
    file was altered when the backend refuses the descriptor itself; and
    while a re-key that switched has not finished.
    :class:`HardwareError` when the secret is here but cannot be used now,
    for instance on a locked Mac.
    """
    _refuse_while_rekeying()
    descriptor = dict(header.device)
    try:
        backend = devices.get_backend(descriptor["backend"])
    except IronDomeError:
        raise AuthError(dead) from None
    try:
        raw = _unseal(backend, header.device)
    except VaultError:
        raise _damaged(header.kind, path) from None
    except IronDomeError as exc:
        if not _present(backend, descriptor):
            raise AuthError(dead) from None
        raise HardwareError(f"the device key that {header.kind} is bound to cannot be used: {exc}") from None
    with raw:
        return _derived_device_key(raw, header.vault_id)


# ---------------------------------------------------------------------------
# The file
# ---------------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class _Header:
    """A capability file: the clear header and the sealed payload."""

    kind: str
    id: str
    vault_id: bytes
    created: int
    expires: int
    uses_left: Optional[int]
    label: str
    device: _Descriptor
    salt: bytes
    wrap: bytes

    def aad(self) -> bytes:
        """Every clear field, in a form no two different headers share."""
        uses = b"\x00" if self.uses_left is None else b"\x01" + self.uses_left.to_bytes(8, "big")
        device = _descriptor_bytes(self.device)
        return b"".join(
            (
                _LABEL_AAD,
                bytes((_FORMAT,)),
                self.kind.encode("ascii") + b"\x00",
                bytes.fromhex(self.id),
                self.vault_id,
                self.created.to_bytes(8, "big"),
                self.expires.to_bytes(8, "big"),
                uses,
                len(device).to_bytes(2, "big"),
                device,
                self.label.encode("utf-8"),
            )
        )

    def to_bytes(self) -> bytes:
        document = {
            "v": _FORMAT,
            "kind": self.kind,
            "id": self.id,
            "vault_id": b64e(self.vault_id),
            "created": self.created,
            "expires": self.expires,
            "uses_left": self.uses_left,
            "label": self.label,
            "device": dict(self.device),
            "salt": b64e(self.salt),
            "wrap": b64e(self.wrap),
        }
        return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")

    @classmethod
    def from_bytes(cls, raw: bytes, cap_id: str) -> "_Header":
        """Parse a file as hostile input. Raises :class:`_Malformed`."""
        try:
            document = audit.strict_loads(raw)
        except ValueError:
            raise _Malformed() from None
        if not isinstance(document, dict) or set(document) != _HEADER_KEYS:
            raise _Malformed()
        kind, label = document["kind"], document["label"]
        created, expires, uses_left = document["created"], document["expires"], document["uses_left"]
        if document["v"] != _FORMAT or not _is_int(document["v"]) or document["id"] != cap_id:
            raise _Malformed()
        if kind not in (KIND_SESSION, KIND_GRANT):
            raise _Malformed()
        if not _is_int(created) or not _is_int(expires) or not 0 <= created < expires <= _MAX_TIME:
            raise _Malformed()
        shortest, longest = (
            (SESSION_TTL_MIN, SESSION_TTL_MAX) if kind == KIND_SESSION else (GRANT_TTL_MIN, GRANT_TTL_MAX)
        )
        if not shortest <= expires - created <= longest:
            raise _Malformed()
        if uses_left is not None and (kind == KIND_SESSION or not _is_int(uses_left) or not 1 <= uses_left <= MAX_USES):
            raise _Malformed()
        if not isinstance(label, str) or len(label) > _MAX_LABEL or not label.isprintable():
            raise _Malformed()
        device = _descriptor(document["device"])
        try:
            vault_id = b64d(document["vault_id"])
            salt = b64d(document["salt"])
            wrap = b64d(document["wrap"])
        except VaultError:
            raise _Malformed() from None
        if len(vault_id) != VAULT_ID_LEN or len(salt) != SALT_LEN:
            raise _Malformed()
        sealed = len(wrap) - NONCE_LEN - TAG_LEN
        if kind == KIND_SESSION and sealed != KEY_LEN:
            raise _Malformed()
        if kind == KIND_GRANT and (sealed < _PAD_BLOCK or sealed % _PAD_BLOCK):
            raise _Malformed()
        header = cls(
            kind=kind,
            id=cap_id,
            vault_id=vault_id,
            created=created,
            expires=expires,
            uses_left=uses_left,
            label=label,
            device=device,
            salt=salt,
            wrap=wrap,
        )
        if header.to_bytes() != raw:
            raise _Malformed()  # not byte for byte what IronDome writes
        return header


def _now() -> int:
    """This machine's clock, in whole seconds, as every expiry check reads it."""
    return min(max(int(time.time()), 0), _MAX_TIME)


def _path(cap_id: str) -> Path:
    return paths.caps_dir() / f"{cap_id}.json"


@contextmanager
def _store(error: Type[IronDomeError]) -> Iterator[None]:
    """Hold the capability directory's lock; report a filesystem failure as *error*."""
    try:
        with paths.file_lock(paths.caps_dir() / _LOCK_NAME):
            yield
    except OSError as exc:
        reason = exc.strerror or exc.__class__.__name__
        raise error(f"the capability directory {paths.caps_dir()} could not be used ({reason})") from None


def _read(path: Path) -> Optional[bytes]:
    """The bytes of a capability file, or ``None`` if there is no such file.

    Never follows a symbolic link, never waits on a pipe or a device, and
    never reads more than a capability can be: anything else in a
    capability's place is :class:`_Malformed`.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise _Malformed() from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise _Malformed()
        parts = []
        wanted = _MAX_FILE + 1
        while wanted > 0:
            part = os.read(fd, min(wanted, 1 << 20))
            if not part:
                break
            parts.append(part)
            wanted -= len(part)
    finally:
        os.close(fd)
    if wanted == 0:
        raise _Malformed()  # more than a capability can hold
    return b"".join(parts)


def _load(path: Path, cap_id: str) -> Optional[_Header]:
    raw = _read(path)
    return None if raw is None else _Header.from_bytes(raw, cap_id)


def _load_quietly(path: Path, cap_id: str) -> Optional[_Header]:
    """The header, or ``None`` for a file that is missing, unreadable or not a capability."""
    try:
        return _load(path, cap_id)
    except (_Malformed, OSError):
        return None


def _entries() -> List[Path]:
    """Everything in the capability directory that is not itself a directory."""
    found = []
    try:
        with os.scandir(str(paths.caps_dir())) as entries:
            for entry in entries:
                try:
                    directory = entry.is_dir(follow_symlinks=False)
                except OSError:
                    directory = False
                if not directory:
                    found.append(Path(entry.path))
    except FileNotFoundError:
        return []
    return sorted(found)


def _capability_files() -> List[Tuple[str, Path]]:
    """``(id, path)`` of everything in the directory that is named like a capability.

    Names are matched without regard to case, because on the filesystems macOS
    and Windows use by default ``<ID>.JSON`` is the file a token for ``<id>``
    opens. What a name holds is not looked at here: a symbolic link, a pipe or
    a file of noise under a capability's name is listed, and
    :func:`_load_quietly` then finds it is not a capability.
    """
    found = []
    for path in _entries():
        match = _FILE_NAME.fullmatch(path.name)
        if match is not None:
            found.append((match.group(1).lower(), path))
    return found


def _destroy(path: Path) -> None:
    """Overwrite and unlink *path*. :class:`VaultError` if it is still there afterwards."""
    try:
        paths.secure_delete(path)
    except OSError:
        pass  # another process removed it first, or it cannot be unlinked: the check below decides
    if os.path.lexists(str(path)):
        raise VaultError(f"{path} could not be deleted; remove it by hand")


def _destroy_quietly(path: Path) -> bool:
    try:
        _destroy(path)
    except VaultError:
        return False
    return True


def _remove_temporaries() -> None:
    """Delete what an interrupted write left behind: each is a full copy of a capability.

    Only called with the lock held, when no write can be in progress.
    """
    for path in _entries():
        if path.name.startswith(_TEMPORARY):
            _destroy_quietly(path)


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------


def _lifetime(ttl: Any, shortest: int, longest: int, what: str) -> int:
    if not _is_int(ttl) or not shortest <= ttl <= longest:
        span = f"{longest // 86400} days" if longest >= 2 * 86400 else f"{longest // 3600} hours"
        raise UsageError(f"{what} lasts a whole number of seconds from {shortest} to {longest} ({span})")
    return int(ttl)


def _label(label: Any) -> str:
    """A label is shown by ``list_caps`` straight from a file nobody authenticated: keep it inert."""
    if not isinstance(label, str) or len(label) > _MAX_LABEL or not label.isprintable():
        raise UsageError(f"a label is at most {_MAX_LABEL} printable characters (no control or formatting characters)")
    return label


def _has_scheme(reference: str) -> bool:
    return reference[: len(_SCHEME)].lower() == _SCHEME


def _strip_scheme(reference: str) -> str:
    return reference[len(_SCHEME) :] if _has_scheme(reference) else reference


def _is_control(char: str) -> bool:
    """What an entry name may not contain (see ``irondome.vault``), so no reference can either."""
    code = ord(char)
    return code < 32 or 0x7F <= code <= 0x9F or code in (0x2028, 0x2029)


def _reference(value: Any) -> str:
    """A reference as a grant stores and compares it: without ``irondome://``."""
    if not isinstance(value, str):
        raise UsageError("a reference must be text: an alias, an entry name, or entry/field")
    name = _strip_scheme(value)
    if (
        not name
        or len(name) > _MAX_REFERENCE
        or name != name.strip()
        or _has_scheme(name)
        or any(_is_control(char) for char in name)
    ):
        raise UsageError(
            f"a reference is an alias, an entry name, or entry/field: 1 to {_MAX_REFERENCE} characters, "
            "no control characters, no space at either end"
        )
    return name


# ---------------------------------------------------------------------------
# Creating
# ---------------------------------------------------------------------------


def _publish(
    vault: "Vault", header: _Header, action: str, detail: str, nothing: str, actor: str = _OWNER
) -> None:
    """Write a new capability file and record it; if it cannot be recorded, take it back."""
    path = _path(header.id)
    with _store(VaultError):
        paths.write_atomic(path, header.to_bytes())
        try:
            with audit.owner_key(vault) as owner:
                audit.record(
                    owner,
                    vault_id=vault.vault_id,
                    kid=audit.KID_VAULT,
                    action=action,
                    actor=actor,
                    target=header.id,
                    detail=detail,
                )
        except BaseException as exc:
            _destroy_quietly(path)
            if isinstance(exc, audit.AuditError):
                raise audit.AuditError(f"{nothing}, because it could not be recorded: {exc}") from None
            raise


def create_session(vault: "Vault", *, ttl: int = 900, label: str = "") -> str:
    """Wrap the vault key under a new session token and return the token.

    The token is full access to the vault for *ttl* seconds (60 seconds to 12
    hours): it is for the owner's own shell, never for an agent. The vault
    key is sealed straight out of locked memory, under the token and the
    vault's capability device secret, so the session opens on this machine
    only. The first session or grant of a vault on a machine creates that
    secret and commits the vault to record it (with whatever else is pending
    in *vault*), and so does one that replaces a recorded secret this machine
    cannot give (see the module docstring); :class:`HardwareError`, with
    nothing made, when the backend cannot tell whether that secret is here.
    The session is recorded in the audit log;
    :class:`irondome.audit.AuditError` means it could not be, and that no
    session exists. A locked vault is refused with :class:`VaultError`
    before anything is made.
    """
    ttl = _lifetime(ttl, SESSION_TTL_MIN, SESSION_TTL_MAX, "a session")
    label = _label(label)
    vault_key = vault.vault_key
    device, device_key = _bound_device(vault)
    with device_key:
        created = _now()
        cap_id = os.urandom(_ID_LEN).hex()
        salt = os.urandom(SALT_LEN)
        header = _Header(
            kind=KIND_SESSION,
            id=cap_id,
            vault_id=vault.vault_id,
            created=created,
            expires=created + ttl,
            uses_left=None,
            label=label,
            device=device,
            salt=salt,
            wrap=b"",
        )
        with SecureBuffer.random(_SECRET_LEN) as secret:
            with _wrap_key(KIND_SESSION, secret, device_key, salt) as key:
                header = replace(header, wrap=seal(key, vault_key, header.aad()))
            token = _token(KIND_SESSION, cap_id, secret)
    detail = f"ttl={ttl}s" + (f" label={label}" if label else "")
    _publish(vault, header, "session.start", detail, "no session was started")
    return token


def _snapshot(vault: "Vault", name: str, created: int, expires: int) -> Dict[str, Any]:
    """The payload item for one reference: its value now, or its one-time passwords until expiry."""
    entry, field = vault.resolve(name)
    if field != _TOTP_FIELD:
        value = vault.value(entry, field)
        if not value:
            raise NotFoundError(f"{name!r} has nothing to grant: the {field} of {entry.name!r} is empty")
        return {"entry": entry.name, "field": field, "value": value}
    settings = vault.read_secret(entry).totp
    if not settings:
        raise NotFoundError(f"{entry.name!r} has no one-time-password secret")
    if expires - created > TOTP_GRANT_TTL_MAX:
        raise UsageError(
            f"a grant that includes a one-time password ({name!r}) lasts at most "
            f"{TOTP_GRANT_TTL_MAX} seconds ({TOTP_GRANT_TTL_MAX // 3600} hours)"
        )
    settings = otp.validate(settings)
    # The grant stops working at `expires`, so the last moment it needs a code for is the second before.
    codes = otp.codes_for_window(settings, created, expires - 1)
    return {
        "entry": entry.name,
        "field": _TOTP_FIELD,
        "period": settings["period"],
        "digits": settings["digits"],
        "codes": {str(counter): code for counter, code in codes.items()},
    }


def create_grant(
    vault: "Vault",
    references: List[str],
    *,
    mode: str = MODE_USE,
    ttl: int = 900,
    uses: Optional[int] = 1,
    label: str = "",
    actor: str = _OWNER,
) -> Tuple[str, GrantInfo]:
    """Snapshot the named values under a new grant token. Returns ``(token, info)``.

    *actor* is who the audit log says made it: the owner, or ``"session"`` when a session token and
    nothing else opened the vault for this.

    Each of the 1 to 64 *references* is resolved with ``vault.resolve`` and
    its value is copied as it is now; later changes to the vault do not reach
    the grant. A reference to a ``totp`` field stores the codes for the
    grant's lifetime, computed here, and not the seed. A reference whose
    value is empty is refused, as is one given twice. ``irondome://`` in
    front of a reference is accepted and dropped: the grant is asked for
    ``GITHUB_TOKEN`` whether it was made with that or ``irondome://GITHUB_TOKEN``.

    *mode* is :data:`MODE_USE` or :data:`MODE_REVEAL`. *ttl* is 60 seconds to
    30 days, at most 24 hours if a one-time password is included. *uses* is a
    count from 1, or ``None`` for unlimited.

    The snapshot is sealed under the token and the vault's capability device
    secret, so the grant opens on this machine only. When every reference
    has been resolved, the first session or grant of a vault on a machine
    creates that secret and commits the vault to record it (with whatever
    else is pending in *vault*), and so does one that replaces a recorded
    secret this machine cannot give; a grant refused before that commits
    nothing. :class:`HardwareError`, with nothing made, when the backend
    cannot tell whether the recorded secret is here.
    The grant is recorded in the audit log; :class:`irondome.audit.AuditError`
    means it could not be, and that no grant exists.
    """
    if mode not in MODES:
        raise UsageError(f"a grant's mode is {MODE_USE!r} or {MODE_REVEAL!r}")
    ttl = _lifetime(ttl, GRANT_TTL_MIN, GRANT_TTL_MAX, "a grant")
    if uses is not None and (not _is_int(uses) or not 1 <= uses <= MAX_USES):
        raise UsageError(f"a grant can be used from 1 to {MAX_USES} times, or without a limit")
    label = _label(label)
    if isinstance(references, str) or not isinstance(references, (list, tuple)):
        raise UsageError("give the references to grant as a list")
    if not 1 <= len(references) <= MAX_REFERENCES:
        raise UsageError(f"a grant covers from 1 to {MAX_REFERENCES} references")
    names = [_reference(reference) for reference in references]
    repeated = sorted({name for name in names if names.count(name) > 1})
    if repeated:
        raise UsageError(f"a reference was given more than once: {', '.join(repeated)}")

    created = _now()
    expires = created + ttl
    cap_id = os.urandom(_ID_LEN).hex()
    salt = os.urandom(SALT_LEN)
    items = {name: _snapshot(vault, name, created, expires) for name in names}
    text = json.dumps({"vault_id": b64e(vault.vault_id), "mode": mode, "items": items}, separators=(",", ":"))
    encoded = text.encode("ascii")
    payload = bytearray(encoded)
    wipe_bytes(encoded)
    try:
        # The grant's audit key is derived from the vault key, so its text never becomes a str and never
        # goes through the JSON encoder: it is appended here, in buffers that are wiped below.
        with audit.owner_key(vault) as owner, audit.grant_key(owner, cap_id) as holder_key:
            key_text = base64.b64encode(holder_key.view())
        try:
            payload[-1:] = b',"audit_key":"'
            payload += key_text
            payload += b'"}'
        finally:
            wipe_bytes(key_text)
        if len(payload) > _MAX_PAYLOAD:
            raise UsageError(
                f"those values come to {len(payload)} bytes and a grant holds at most {_MAX_PAYLOAD}; "
                "grant fewer of them"
            )
        padded = pad(payload, _PAD_BLOCK)
        try:
            # Bound only now, once every reference has been resolved: a grant that cannot be made commits nothing.
            device, device_key = _bound_device(vault)
            with device_key:
                header = _Header(
                    kind=KIND_GRANT,
                    id=cap_id,
                    vault_id=vault.vault_id,
                    created=created,
                    expires=expires,
                    uses_left=uses,
                    label=label,
                    device=device,
                    salt=salt,
                    wrap=b"",
                )
                with SecureBuffer.random(_SECRET_LEN) as secret:
                    with _wrap_key(KIND_GRANT, secret, device_key, salt) as key:
                        header = replace(header, wrap=seal(key, padded, header.aad()))
                    token = _token(KIND_GRANT, cap_id, secret)
        finally:
            wipe_bytes(padded)
    finally:
        wipe_bytes(payload)
        wipe_bytes(text)
    limit = "unlimited" if uses is None else str(uses)
    detail = f"mode={mode} uses={limit} ttl={ttl}s" + (f" label={label}" if label else "")
    _publish(
        vault, header, "grant.create", f"{detail} references: {', '.join(names)}", "no grant was made", actor
    )
    return token, GrantInfo(
        id=cap_id,
        mode=mode,
        created=created,
        expires=expires,
        uses_left=uses,
        label=label,
        references=tuple(names),
    )


# ---------------------------------------------------------------------------
# Opening
# ---------------------------------------------------------------------------


def _damaged(kind: str, path: Path) -> AuthError:
    return AuthError(f"that {kind} token can no longer be used: its file {path} is damaged or was altered")


def _find(path: Path, cap_id: str, kind: str, gone: str) -> _Header:
    """The header behind a token of *kind*, or :class:`AuthError` saying why there is none."""
    try:
        header = _load(path, cap_id)
    except _Malformed:
        raise _damaged(kind, path) from None
    if header is None or header.kind != kind:
        raise AuthError(gone)
    return header


def open_session(token: str, file: "VaultFile") -> SecureBuffer:
    """Return the vault key a session token wraps, in locked memory the caller wipes.

    :class:`AuthError` if the token is malformed or is a grant token, if no
    session answers to it, if the session belongs to another vault, if it
    has expired (its file is then deleted here), if the device secret it is
    bound to is not on this machine (it was made on another one, or the
    secret was destroyed, by ``nuke`` for instance), or if the token does not
    open it (wrong secret, or any change to the file). :class:`HardwareError`
    if that device secret is here but cannot be used now (a locked Mac, a
    busy TPM).
    """
    kind, cap_id, secret = parse_token(token)
    try:
        if kind != KIND_SESSION:
            raise AuthError("that is a grant token, not a session token: it cannot unlock the vault")
        with _store(AuthError):
            path = _path(cap_id)
            header = _find(path, cap_id, KIND_SESSION, _SESSION_GONE)
            if header.expires <= _now():
                _destroy_quietly(path)
                raise AuthError("that session has expired. Start a new one with: irondome unlock")
            if header.vault_id != file.vault_id:
                raise AuthError("that session token belongs to a different vault")
            with _opening_key(header, path, _SESSION_DEAD) as device_key:
                vault_key = SecureBuffer(KEY_LEN)
                try:
                    with _wrap_key(KIND_SESSION, secret, device_key, header.salt) as key:
                        open_sealed_into(key, header.wrap, header.aad(), vault_key)
                except DecryptError:
                    vault_key.wipe()
                    raise AuthError(
                        "that session token does not open its session: the token is wrong, or the session "
                        "file was altered. Start a new one with: irondome unlock"
                    ) from None
                except BaseException:
                    vault_key.wipe()
                    raise
                return vault_key
    finally:
        wipe_bytes(secret)


def session_expires(token: str) -> Optional[int]:
    """When the session *token* names ends (Unix time), or None if no such session is here.

    Read from the file's clear header. The time is part of what the token
    authenticates, so once :func:`open_session` has opened that same file
    with the token, the value is the one the session was made with.
    """
    try:
        kind, cap_id, secret = parse_token(token)
    except AuthError:
        return None
    wipe_bytes(secret)
    if kind != KIND_SESSION:
        return None
    try:
        header = _load_quietly(_path(cap_id), cap_id)
    except (OSError, IronDomeError):
        return None
    return header.expires if header is not None and header.kind == KIND_SESSION else None


def _unwrap(header: _Header, secret: bytes, device_key: SecureBuffer) -> bytearray:
    """A grant's padded payload. The caller wipes it."""
    with _wrap_key(KIND_GRANT, secret, device_key, header.salt) as key:
        try:
            return open_sealed(key, header.wrap, header.aad())
        except DecryptError:
            raise AuthError(
                "that grant token does not open its grant: the token is wrong, or the grant file was altered"
            ) from None


def _payload_item(name: Any, raw: Any, keep_values: bool) -> _Item:
    if _reference(name) != name or not isinstance(raw, dict):
        raise ValueError("item")
    entry, field = raw.get("entry"), raw.get("field")
    if not isinstance(entry, str) or not 1 <= len(entry) <= _MAX_ENTRY_NAME:
        raise ValueError("entry")
    if not isinstance(field, str) or not 1 <= len(field) <= _MAX_FIELD_NAME:
        raise ValueError("field")
    if field != _TOTP_FIELD:
        value = raw.get("value")
        if set(raw) != _VALUE_KEYS or not isinstance(value, str) or not value:
            raise ValueError("value")
        return _Item(entry=entry, field=field, value=value if keep_values else "")
    period, digits, codes = raw.get("period"), raw.get("digits"), raw.get("codes")
    if set(raw) != _TOTP_KEYS:
        raise ValueError("item")
    if not isinstance(period, int) or isinstance(period, bool) or not otp.MIN_PERIOD <= period <= otp.MAX_PERIOD:
        raise ValueError("period")
    if not _is_int(digits) or digits not in otp.DIGITS:
        raise ValueError("digits")
    if not isinstance(codes, dict) or not 1 <= len(codes) <= otp.MAX_WINDOW_CODES:
        raise ValueError("codes")
    table: Dict[int, str] = {}
    for counter, code in codes.items():
        if not _COUNTER.fullmatch(counter) or int(counter) > _MAX_COUNTER:
            raise ValueError("counter")
        if not isinstance(code, str) or len(code) != digits or not code.isascii() or not code.isdigit():
            raise ValueError("code")
        table[int(counter)] = code
    return _Item(entry=entry, field=field, period=period, codes=table if keep_values else {})


def _read_payload(
    padded: bytearray, header: _Header, *, keep_values: bool
) -> Tuple[str, Dict[str, _Item], SecureBuffer]:
    """Check a decrypted payload as hostile input: whoever holds the token can have written it.

    Returns ``(mode, items, audit key)``. :class:`AuthError` for anything
    :func:`create_grant` would not have produced.
    """
    refusal = "that grant cannot be used: what it holds is not what IronDome writes"
    try:
        plain = unpad(padded)
    except VaultError:
        raise AuthError(refusal) from None
    text = ""
    try:
        text = plain.decode("utf-8")
        document = audit.strict_loads(text)
    except ValueError:
        raise AuthError(refusal) from None
    finally:
        wipe_bytes(plain)
        wipe_bytes(text)
    key_text = document.get("audit_key") if isinstance(document, dict) else None
    key_bytes = raw_key = b""
    try:
        if not isinstance(document, dict) or set(document) != _PAYLOAD_KEYS:
            raise ValueError("payload")
        mode, raw_items = document["mode"], document["items"]
        if b64d(document["vault_id"]) != header.vault_id or mode not in MODES:
            raise ValueError("binding")
        if not isinstance(raw_items, dict) or not 1 <= len(raw_items) <= MAX_REFERENCES:
            raise ValueError("items")
        items = {name: _payload_item(name, raw, keep_values) for name, raw in raw_items.items()}
        if not isinstance(key_text, str):
            raise ValueError("key")
        key_bytes = key_text.encode("ascii")
        raw_key = base64.b64decode(key_bytes, validate=True)
        if len(raw_key) != KEY_LEN:
            raise ValueError("key")
        return mode, items, SecureBuffer.from_buffer(raw_key)
    except (ValueError, IronDomeError):
        raise AuthError(refusal) from None
    finally:
        # The audit key was in locked memory when the grant was made. Every copy made of it here is zeroed.
        wipe_bytes(raw_key)
        wipe_bytes(key_bytes)
        if isinstance(key_text, str):
            wipe_bytes(key_text)


def _note_expired(header: _Header, path: Path, secret: bytes) -> None:
    """Tell the owner that an expired grant was presented, if the token really is that grant's.

    Written as a use that was refused. Best effort: the caller is refused
    whether or not this can be recorded, and nothing is recorded when the
    device secret the grant is bound to cannot be had.
    """
    try:
        device_key = _opening_key(header, path, _GRANT_DEAD)
    except IronDomeError:
        return
    with device_key:
        try:
            padded = _unwrap(header, secret, device_key)
        except AuthError:
            return
    try:
        _, _, holder_key = _read_payload(padded, header, keep_values=False)
    except AuthError:
        return
    finally:
        wipe_bytes(padded)
    with holder_key:
        try:
            audit.record(
                holder_key,
                vault_id=header.vault_id,
                kid=header.id,
                action="grant.use",
                actor=_HOLDER,
                target=header.id,
                detail="refused: the grant had expired; it was destroyed",
                ok=False,
            )
        except IronDomeError:
            pass  # the refusal that follows does not depend on this record


def _spend(
    path: Path,
    header: _Header,
    remaining: Optional[int],
    padded: bytearray,
    secret: bytes,
    device_key: SecureBuffer,
) -> None:
    """Make one use count: delete the file after the last, else seal it again with the new count."""
    if remaining is None:
        return
    if remaining == 0:
        _destroy(path)
        return
    salt = os.urandom(SALT_LEN)
    renewed = replace(header, uses_left=remaining, salt=salt, wrap=b"")
    with _wrap_key(KIND_GRANT, secret, device_key, salt) as key:
        renewed = replace(renewed, wrap=seal(key, padded, renewed.aad()))
    paths.write_atomic(path, renewed.to_bytes())


def open_grant(token: str, *, consume: bool = True) -> Grant:
    """Open the grant a token names.

    With ``consume=True`` (the default) this is one use. In order, while
    holding the directory lock: the use is written to the audit log under the
    grant's own key; the count goes down by one, sealed again with the new
    count in its associated data; and after the last use the file is
    destroyed. Of two processes that present a single-use token at once,
    exactly one gets the grant and the other :class:`AuthError`.

    With ``consume=False`` nothing is spent or recorded and the returned
    :class:`Grant` holds no values: it only says what the grant covers.

    Raises :class:`AuthError` if the token is malformed or is a session
    token, if no grant answers to it (used up, revoked, never here), if the
    device secret it is bound to is not on this machine (it was made on
    another one, or the secret was destroyed, by ``nuke`` for instance), if
    the token does not open it (wrong secret, or any change to the file), or
    if it has expired, in which case its file is deleted here and, when the
    token is the right one, the refusal is recorded.
    Raises :class:`HardwareError` if that device secret is here but cannot be
    used now (a locked Mac, a busy TPM): nothing is spent or recorded.
    Raises :class:`irondome.audit.AuditError` if the use cannot be recorded:
    nothing is spent and nothing is returned.
    Raises :class:`VaultError` if the use was recorded and the count then
    cannot be written: nothing is returned, and a second record says that
    the first did not happen.
    """
    kind, cap_id, secret = parse_token(token)
    try:
        if kind != KIND_GRANT:
            raise AuthError("that is a session token, not a grant token")
        with _store(AuthError):
            path = _path(cap_id)
            header = _find(path, cap_id, KIND_GRANT, _GRANT_GONE)
            if header.expires <= _now():
                _note_expired(header, path, secret)
                _destroy_quietly(path)
                raise AuthError(
                    "that grant has expired. Its owner can make a new one with: irondome grant create"
                )
            with _opening_key(header, path, _GRANT_DEAD) as device_key:
                padded = _unwrap(header, secret, device_key)
                try:
                    mode, items, holder_key = _read_payload(padded, header, keep_values=consume)
                    try:
                        if not consume:
                            return Grant(header, mode, items, holder_key, consumed=False, uses_left=header.uses_left)
                        remaining = None if header.uses_left is None else header.uses_left - 1
                        _record_use(header, holder_key, remaining)
                        try:
                            _spend(path, header, remaining, padded, secret, device_key)
                        except (OSError, VaultError):
                            _record_unspent(header, holder_key)
                            raise VaultError(
                                f"that grant was not used: its use count in {path} could not be updated. "
                                "Check that the directory is writable and has free space"
                            ) from None
                        return Grant(header, mode, items, holder_key, consumed=True, uses_left=remaining)
                    except BaseException:
                        holder_key.wipe()
                        raise
                finally:
                    wipe_bytes(padded)
    finally:
        wipe_bytes(secret)


def _record_use(header: _Header, holder_key: SecureBuffer, remaining: Optional[int]) -> None:
    left = "unlimited" if remaining is None else str(remaining)
    try:
        audit.record(
            holder_key,
            vault_id=header.vault_id,
            kid=header.id,
            action="grant.use",
            actor=_HOLDER,
            target=header.id,
            detail=f"uses left: {left}",
        )
    except audit.AuditError as exc:
        raise audit.AuditError(f"that grant was not used, because the use could not be recorded: {exc}") from None


def _record_unspent(header: _Header, holder_key: SecureBuffer) -> None:
    try:
        audit.record(
            holder_key,
            vault_id=header.vault_id,
            kid=header.id,
            action="grant.use",
            actor=_HOLDER,
            target=header.id,
            detail="the use recorded just before this did not happen: its count could not be written",
            ok=False,
        )
    except IronDomeError:
        pass  # the caller is refused either way


# ---------------------------------------------------------------------------
# Listing and removing
# ---------------------------------------------------------------------------


def list_caps() -> List[CapInfo]:
    """Every session and grant in the directory, oldest first, expired ones included.

    Read from the clear headers only, so nothing here is authenticated (see
    the module docstring). Files that are not well-formed capabilities are
    left out.
    """
    now = _now()
    try:
        files = _capability_files()
    except OSError as exc:
        reason = exc.strerror or exc.__class__.__name__
        raise VaultError(f"the capability directory {paths.caps_dir()} could not be read ({reason})") from None
    found = []
    for cap_id, path in files:
        header = _load_quietly(path, cap_id)
        if header is not None:
            found.append(
                CapInfo(
                    id=header.id,
                    kind=header.kind,
                    created=header.created,
                    expires=header.expires,
                    uses_left=header.uses_left,
                    label=header.label,
                    expired=header.expires <= now,
                )
            )
    return sorted(found, key=lambda info: (info.created, info.id))


def _note_removed(vault: Optional["Vault"], removed: List[Tuple[str, str]], summary: str) -> None:
    """Record removals for the owner, after they are done, when a vault was passed.

    A removal is never undone or held up by the log. If it cannot be recorded
    the :class:`irondome.audit.AuditError` says that it happened all the same.
    """
    if vault is None or not removed:
        return
    try:
        with audit.owner_key(vault) as owner:
            for action, cap_id in removed:
                audit.record(
                    owner, vault_id=vault.vault_id, kid=audit.KID_VAULT, action=action, actor=_OWNER, target=cap_id
                )
    except audit.AuditError as exc:
        raise audit.AuditError(f"{summary}, but that could not be recorded: {exc}") from None


def session_mark(token: str) -> str:
    """What the label of a grant made under the session *token* ends with: ``[session <first 12 of its id>]``.

    :func:`end_sessions` revokes the grants that carry the mark of a session it ends, so that a grant a
    session made does not outlive it. The label is part of what a capability file authenticates.
    :class:`AuthError` if *token* is not a session token.
    """
    kind, cap_id, secret = parse_token(token)
    wipe_bytes(secret)
    if kind != KIND_SESSION:
        raise AuthError("that is a grant token, not a session token")
    return f"[session {cap_id[:12]}]"


def end_sessions(token: Optional[str] = None, *, vault: Optional["Vault"] = None) -> int:
    """Destroy the session *token* names, or every session when there is no token.

    Returns how many were destroyed (0 if the token's session is already
    gone). Needs only the token's id, not a correct secret: ending a session
    is always allowed. The grants made under a session that ends here (their
    label ends with its :func:`session_mark`) are revoked with it. Pass
    *vault* to have each one recorded in the audit log as ``session.end``
    and ``grant.revoke``.
    """
    ended: List[str] = []
    revoked: List[str] = []
    if token is not None:
        kind, cap_id, secret = parse_token(token)
        wipe_bytes(secret)
        if kind != KIND_SESSION:
            raise UsageError("that is a grant token, not a session token; revoke a grant by its id")
    with _store(VaultError):
        if token is None:
            for found_id, path in _capability_files():
                header = _load_quietly(path, found_id)
                if header is not None and header.kind == KIND_SESSION:
                    _destroy(path)
                    ended.append(found_id)
        else:
            path = _path(cap_id)
            header = _load_quietly(path, cap_id)
            if os.path.lexists(str(path)) and (header is None or header.kind == KIND_SESSION):
                _destroy(path)
                ended.append(cap_id)
        marks = tuple(f"[session {ended_id[:12]}]" for ended_id in ended)
        if marks:
            for found_id, path in _capability_files():
                header = _load_quietly(path, found_id)
                if header is not None and header.kind == KIND_GRANT and header.label.endswith(marks):
                    _destroy(path)
                    revoked.append(found_id)
    _note_removed(
        vault,
        [("session.end", ended_id) for ended_id in ended] + [("grant.revoke", grant_id) for grant_id in revoked],
        _plural(len(ended), "session ended", "sessions ended"),
    )
    return len(ended)


def revoke(id_prefix: str, *, vault: Optional["Vault"] = None) -> int:
    """Destroy the one session or grant whose id starts with *id_prefix*. Returns 1.

    The prefix is at least 6 hexadecimal characters. :class:`UsageError` if
    it is malformed or matches more than one capability,
    :class:`NotFoundError` if it matches none. A file that is named like a
    capability but is damaged can be revoked too. Pass *vault* to have the
    revocation recorded in the audit log.
    """
    prefix = id_prefix.lower() if isinstance(id_prefix, str) else ""
    if not _ID_PREFIX.fullmatch(prefix):
        raise UsageError("give at least the first 6 characters of the id (hexadecimal) of the grant or session")
    with _store(VaultError):
        matches = [(cap_id, path) for cap_id, path in _capability_files() if cap_id.startswith(prefix)]
        ids = sorted({cap_id for cap_id, _ in matches})
        if not ids:
            raise NotFoundError(f"no grant or session has an id starting with {prefix}")
        if len(ids) > 1:
            raise UsageError(f"{len(ids)} grants or sessions have an id starting with {prefix}; give more of it")
        cap_id = ids[0]
        header = None
        for _, path in matches:  # more than one only where names that differ in case are different files
            header = header or _load_quietly(path, cap_id)
            _destroy(path)
    kind = header.kind if header is not None else "capability"
    action = "session.end" if kind == KIND_SESSION else f"{kind}.revoke"
    _note_removed(vault, [(action, cap_id)], f"the {kind} {cap_id} was revoked")
    return 1


def sweep(*, vault: Optional["Vault"] = None) -> int:
    """Destroy every expired session and grant. Returns how many were destroyed.

    Also removes temporary files an interrupted write left in the directory.
    Files that are not well-formed capabilities are left alone. Pass *vault*
    to have each removal recorded in the audit log.
    """
    removed: List[Tuple[str, str]] = []
    with _store(VaultError):
        now = _now()
        for cap_id, path in _capability_files():
            header = _load_quietly(path, cap_id)
            if header is not None and header.expires <= now and _destroy_quietly(path):
                removed.append((f"{header.kind}.expire", cap_id))
        _remove_temporaries()
    _note_removed(
        vault, removed,
        _plural(len(removed), "expired grant or session was removed", "expired grants and sessions were removed"),
    )
    return len(removed)


def destroy_all() -> int:
    """Destroy every session and grant, valid or not. Used by ``nuke``.

    Removes every file named like a capability, whatever it contains and in
    whatever case its name is written, the temporary files of interrupted
    writes, the lock file, and then the directory if nothing else is in it.
    Files with other names are not IronDome's and are left where they are.
    The device secrets the capabilities are bound to are not touched here:
    ``nuke`` destroys them before, with every other device secret of the
    bunker, and that is what makes surviving copies of these files useless
    (:func:`destroy_device` does the same for one vault). A device
    descriptor read from a header nobody authenticated is never acted on to
    destroy anything.

    Returns the number of capability files destroyed; :class:`VaultError` if
    one of them is still there afterwards.
    """
    directory = paths.caps_dir()
    if not directory.is_dir():
        return 0
    survivors: List[str] = []
    destroyed = 0
    with _store(VaultError):
        for _, path in _capability_files():
            if _destroy_quietly(path):
                destroyed += 1
            else:
                survivors.append(path.name)
        _remove_temporaries()
    _destroy_quietly(directory / _LOCK_NAME)
    try:
        directory.rmdir()
    except OSError:
        pass  # something that is not IronDome's is still in it
    if survivors:
        raise VaultError(
            f"{_plural(len(survivors), 'capability file', 'capability files')} in {directory} could not be deleted: "
            f"{', '.join(sorted(survivors)[:5])}"
        )
    return destroyed


def destroy_device(vault: "Vault") -> int:
    """Destroy every capability device secret of *vault* on this machine. Returns how many were here (0 if none).

    That is the secret the vault's index records and every one it replaced
    (see :func:`_bound_device`), so that every session and grant ever made
    for the vault here stops working at once, and so does every copy of
    their files, whichever token is presented: for one vault, what ``nuke``
    does to capabilities. Meant for when the vault's old keys must stop
    opening anything (``rekey``). The descriptors are taken from the vault's
    authenticated index, never from a capability file. The files themselves
    are left to :func:`destroy_all`, and the index keeps naming the destroyed
    secrets until the next session or grant replaces them, so nothing is
    committed here.

    Every secret is tried, even after one fails. :class:`HardwareError` then
    if a secret that is here could not be destroyed, or survived; its message
    says how many others were destroyed.
    """
    destroyed = 0
    problems: List[str] = []
    for device in _every_bound(vault):
        descriptor = dict(device)
        try:
            backend = devices.get_backend(descriptor["backend"])
        except IronDomeError:
            continue  # a backend this installation cannot even load holds nothing on this machine
        try:
            here = backend.exists(descriptor)
        except IronDomeError as exc:
            here = _works_here(backend)
            if not here and devices.applies_here(backend.name):
                # This system's own chip, out of reach for now: it may still hold the secret. Not "gone".
                problems.append(f"the {backend.name} device key of this vault's sessions and grants could not be "
                                f"checked: {exc}")
                continue
        if not here:
            continue
        try:
            backend.destroy(descriptor)
            if backend.exists(descriptor):
                raise HardwareError(
                    f"the {backend.name} device key of this vault's sessions and grants survived destruction"
                )
        except IronDomeError as exc:
            problems.append(str(exc))
            continue
        destroyed += 1
    if problems:
        detail = "; ".join(problems)
        if len(problems) == 1 and not destroyed:
            raise HardwareError(detail)
        raise HardwareError(
            f"{len(problems)} of the {len(problems) + destroyed} device keys of this vault's sessions and grants "
            f"could not be destroyed ({destroyed} {'was' if destroyed == 1 else 'were'}): {detail}"
        )
    return destroyed


def bound_devices(vault: "Vault") -> List[Dict[str, Any]]:
    """The descriptor of every capability device secret *vault* has bound sessions and grants to on any machine.

    The one its index records now first, then every one it replaced, oldest
    first (see :func:`_bound_device`): together, everything that has to be
    destroyed for every session and grant of the vault to stop working, which
    is what :func:`destroy_device` does and what a re-key must do for the
    vault it replaces. Read from the vault's authenticated index only;
    anything there that is not a descriptor a capability could carry is left
    out. Fresh copies: changing them changes nothing.
    """
    return [dict(device) for device in _every_bound(vault)]
