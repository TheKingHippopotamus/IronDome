"""Creating a vault and getting back into one.

Three ways to set a vault up, chosen at ``irondome init``:

``password``           master password + device key. The default everywhere.
``touchid``            Touch ID alone opens the vault (Secure Enclave, enforced
                       by the chip). A master password is still set as the
                       fallback for when the sensor is unavailable.
``touchid+password``   both are required, every time.

Every mode can also carry a recovery key. :func:`unlock` tries what the vault
offers in the order a person would want: Touch ID if there is a slot for it
and a person present, otherwise the master password.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Callable, List, Optional, Tuple, Union

from irondome import device as devices
from irondome import keys
from irondome.crypto import Argon2Params, default_argon2
from irondome.device.base import POLICY_BIOMETRY, POLICY_DEVICE
from irondome.errors import AuthError, HardwareError, IronDomeError, UsageError, VaultError
from irondome.keys import KIND_DEVICE, KIND_PASSWORD, KIND_RECOVERY, Keyslot
from irondome.secmem import SecureBuffer
from irondome.vault import Vault, VaultFile

__all__ = [
    "MODE_PASSWORD",
    "MODE_TOUCHID",
    "MODE_TOUCHID_PASSWORD",
    "MODES",
    "MIN_PASSWORD_BYTES",
    "PasswordSource",
    "create_vault",
    "unlock",
    "open_vault",
    "can_ask_for_touch",
    "check_new_password",
]

MODE_PASSWORD = "password"  # noqa: S105 - the name of a setup mode, not a credential
MODE_TOUCHID = "touchid"
MODE_TOUCHID_PASSWORD = "touchid+password"  # noqa: S105 - the name of a setup mode, not a credential
MODES = (MODE_PASSWORD, MODE_TOUCHID, MODE_TOUCHID_PASSWORD)

MIN_PASSWORD_BYTES = 8

#: Called when a password is needed; returns it in locked memory.
PasswordSource = Callable[[], SecureBuffer]


def check_new_password(password: SecureBuffer) -> None:
    if len(password) < MIN_PASSWORD_BYTES:
        raise UsageError(f"the master password must be at least {MIN_PASSWORD_BYTES} characters")


def can_ask_for_touch() -> bool:
    """True when a Touch ID prompt has a chance of being seen and answered."""
    if sys.platform != "darwin":
        return False
    if os.environ.get("IRONDOME_NO_TOUCH") == "1":
        return False
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        return False
    return True


def create_vault(
    *,
    mode: str = MODE_PASSWORD,
    password: Optional[SecureBuffer] = None,
    with_recovery: bool = True,
    params: Optional[Argon2Params] = None,
    path: Union[str, Path, None] = None,
    backend_name: Optional[str] = None,
) -> Tuple[Vault, Optional[str]]:
    """Create a new vault. Returns the open vault and the recovery key, if any.

    The recovery key is returned exactly once and stored nowhere.
    """
    if mode not in MODES:
        raise UsageError(f"unknown mode {mode!r}; choose one of: {', '.join(MODES)}")
    if mode != MODE_TOUCHID and password is None:
        raise UsageError("this mode needs a master password")
    if password is None and not with_recovery:
        # Adding or removing a fingerprint invalidates a Touch ID key for good.
        raise UsageError(
            "a vault that opens with Touch ID alone needs a second way in: "
            "set a master password or keep the recovery key"
        )
    if password is not None:
        check_new_password(password)
    cost = (params or default_argon2()).validate()
    vault_id = os.urandom(keys.VAULT_ID_LEN)
    vault_key = keys.new_vault_key()
    slots: List[Keyslot] = []
    recovery: Optional[str] = None
    try:
        if mode == MODE_TOUCHID:
            touch = devices.choose_backend(POLICY_BIOMETRY, backend_name)
            slots.append(
                keys.create_device_slot(vault_key, vault_id, backend=touch, policy=POLICY_BIOMETRY, label="Touch ID")
            )
        if password is not None:
            # touchid+password: the password slot's own device key needs the finger.
            # The other two modes: a device key this machine releases silently.
            policy = POLICY_BIOMETRY if mode == MODE_TOUCHID_PASSWORD else POLICY_DEVICE
            label = {
                MODE_PASSWORD: "master password",
                MODE_TOUCHID: "master password (fallback)",
                MODE_TOUCHID_PASSWORD: "master password + Touch ID",
            }[mode]
            backend = devices.choose_backend(policy, backend_name)
            slots.append(
                keys.create_password_slot(
                    vault_key, password, vault_id, params=cost, backend=backend, policy=policy, label=label
                )
            )
        if with_recovery:
            slot, recovery = keys.create_recovery_slot(vault_key, vault_id, label="recovery key")
            slots.append(slot)
        vault = Vault.create(vault_key, slots, vault_id, path)
    except BaseException:
        vault_key.wipe()
        for slot in slots:
            try:
                keys.destroy_slot_device(slot)
            except IronDomeError:
                pass
        raise
    return vault, recovery


def _needs_person(slot: Keyslot) -> bool:
    """True when the slot's device key is released only after a biometric or presence check."""
    return slot.policy not in (None, POLICY_DEVICE)


def _try_touch(file: VaultFile, reason: str) -> Tuple[Optional[SecureBuffer], Optional[IronDomeError]]:
    """Try the Touch ID slots. Returns the vault key, or the reason there is none.

    A slot whose key is missing or damaged is skipped in favour of the next.
    A refusal ends the attempt: someone who cancelled one prompt is not shown
    another for the same request. Neither outcome blocks the password.
    """
    last: Optional[IronDomeError] = None
    for slot in file.slots:
        if slot.kind != KIND_DEVICE:
            continue
        try:
            return keys.open_slot(slot, file.vault_id, interactive=True, reason=reason), None
        except AuthError as exc:
            return None, exc
        except (HardwareError, VaultError) as exc:
            last = exc
    return None, last


def unlock(
    file: VaultFile,
    *,
    password: Optional[SecureBuffer] = None,
    password_source: Optional[PasswordSource] = None,
    recovery_key: Optional[str] = None,
    interactive: bool = True,
    allow_touch: bool = True,
    reason: str = "unlock your IronDome vault",
) -> SecureBuffer:
    """Return the vault key, using whichever keyslot the available factors open.

    * *recovery_key* given: only recovery slots are tried.
    * a device (Touch ID) slot exists, a person can be prompted and no password
      was supplied up front: Touch ID is tried first.
    * otherwise the master password, taken from *password* or asked for through
      *password_source*, is tried against every password slot.

    A Touch ID prompt is shown only when *interactive* and *allow_touch* are
    both true and :func:`can_ask_for_touch` agrees. That holds for a password
    slot whose device key needs a finger as much as for a Touch ID slot:
    where no prompt may appear, such a slot is refused with an ``AuthError``.
    """
    if recovery_key is not None:
        refused: IronDomeError = AuthError("this vault has no recovery key")
        for slot in file.slots:
            if slot.kind != KIND_RECOVERY:
                continue
            try:
                return keys.open_slot(slot, file.vault_id, recovery_key=recovery_key)
            except AuthError as exc:
                refused = exc
        raise refused

    may_prompt = interactive and allow_touch and can_ask_for_touch()
    touch_failure: Optional[IronDomeError] = None
    has_touch_slot = any(slot.kind == KIND_DEVICE for slot in file.slots)
    if has_touch_slot and may_prompt and password is None:
        vault_key, touch_failure = _try_touch(file, reason)
        if vault_key is not None:
            return vault_key

    password_slots = [slot for slot in file.slots if slot.kind == KIND_PASSWORD]
    if not password_slots:
        if touch_failure is not None:
            raise touch_failure
        if has_touch_slot and password is not None:
            # Touch ID is not tried when a password is given: the caller chose the password.
            raise AuthError(
                "this vault opens with Touch ID only: it has no master password, so a password cannot open it. "
                "Leave the password out (no --password-stdin) and touch the sensor."
            )
        if has_touch_slot:
            raise AuthError(
                "this vault opens with Touch ID only, and Touch ID cannot be asked for here (that needs this Mac's "
                "own desktop session, without --no-touch or IRONDOME_NO_TOUCH=1). Run the command there; a command "
                "that only reads secrets also takes a grant or session token made there."
            )
        raise VaultError("this vault has no keyslot that can be opened here")

    owned: Optional[SecureBuffer] = None
    if password is None:
        if password_source is None:
            if touch_failure is not None:
                raise touch_failure
            raise AuthError("the master password is required")
        owned = password_source()
        password = owned
    try:
        failures: List[IronDomeError] = []
        for slot in password_slots:
            try:
                return keys.open_slot(
                    slot,
                    file.vault_id,
                    password=password,
                    interactive=may_prompt if _needs_person(slot) else interactive,
                    reason=reason,
                )
            except (AuthError, HardwareError, VaultError) as exc:
                failures.append(exc)
        # Prefer reporting a wrong password over a missing device.
        refusals = [exc for exc in failures if isinstance(exc, AuthError)]
        raise (refusals[-1:] or failures[:1])[0]
    finally:
        if owned is not None:
            owned.wipe()


def open_vault(
    *,
    path: Union[str, Path, None] = None,
    password: Optional[SecureBuffer] = None,
    password_source: Optional[PasswordSource] = None,
    recovery_key: Optional[str] = None,
    interactive: bool = True,
    allow_touch: bool = True,
    reason: str = "unlock your IronDome vault",
) -> Vault:
    """Load the vault file and unlock it. The caller must close the result."""
    file = VaultFile.load(path)
    vault_key = unlock(
        file,
        password=password,
        password_source=password_source,
        recovery_key=recovery_key,
        interactive=interactive,
        allow_touch=allow_touch,
        reason=reason,
    )
    return Vault(file, vault_key, path)
