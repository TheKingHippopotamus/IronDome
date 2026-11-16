"""Everyday commands: create a vault, keep secrets in it, read them back, decide what protects it.

``init``, ``status``, ``add``, ``get``, ``show``, ``ls``, ``find``, ``edit``, ``rm``, ``gen``, ``otp``,
``passwd``, ``recovery``, ``auth``, ``config`` and ``bunker``, plus :func:`overview`, which is what
``irondome`` prints with no command.

Who may do what follows :mod:`irondome.cli.context`. Reading a value (``get``, ``otp``, ``ls``,
``find``) goes through ``ctx.access()``, so a grant or a Touch ID approval limits it, and a request a
grant would refuse spends none of its uses. Everything that changes the vault, its keyslots, aliases
or settings, and ``show``, is for the owner: in agent mode (no terminal and no ``--password-stdin``)
it is refused with a :class:`PolicyError`. Commands that change how the vault is protected
(``passwd``, ``recovery``, ``auth``) unlock afresh: a session token is not enough for them. The
``bunker`` commands that unlock nothing (``use``, ``rm``, and ``create`` next to an existing vault)
call :meth:`Context.prove_owner`: ``--password-stdin`` counts only with a password that opens the
bunker's vault, and ``bunker rm --yes`` only with that. At a terminal they put a question to the
person, which an agent that inherited the terminal cannot answer.

A keyslot change retires what it replaces, whatever interrupts it (:func:`_replace_slots`): the old
device keys are destroyed, or are destroyed by the next command if a crash came first. The recovery
key has no device key to destroy, so ``recovery new`` and ``recovery remove`` re-key the vault with
the re-key of ``irondome rekey`` (:func:`_rekey_vault`).

Secrets never come from command-line arguments, where shell history and the process list would keep
them. They come from a hidden prompt on the terminal or from stdin. With ``--password-stdin`` the
master password is the first line; then, for ``add`` and ``edit``, the value (``--value-stdin``),
the TOTP secret (``--totp-stdin``) and one line per ``--field NAME``, in command-line order; the
notes (``--note-stdin``) take whatever is left. A value that is the last of these on stdin is read to
the end of input (:func:`_stdin_value`): a key of several lines is never cut at its first line.
Field values come from stdin whenever stdin carries any of that input, and from a hidden prompt
otherwise.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from irondome import caps, clipboard, config, generator, keys, otp, paths
from irondome import device as devices
from irondome.agent import refs
from irondome.cli.context import ENV_GRANT, PURPOSE_REVEAL, Access, Context
from irondome.cli.output import format_duration, format_time
from irondome.crypto import DEFAULT_ARGON2, Argon2Params, default_argon2
from irondome.device.base import POLICY_BIOMETRY, POLICY_DEVICE, DeviceBackend
from irondome.errors import (
    AuthError,
    HardwareError,
    IronDomeError,
    LockedOutError,
    NotFoundError,
    PolicyError,
    UsageError,
    VaultError,
)
from irondome.keys import KIND_DEVICE, KIND_PASSWORD, KIND_RECOVERY, Keyslot
from irondome.secmem import SecureBuffer, _wipe_str, read_secret, read_secret_from_fd, wipe_bytes
from irondome.unlock import MODE_PASSWORD, MODE_TOUCHID, MODE_TOUCHID_PASSWORD, MODES, create_vault, unlock
from irondome.vault import (
    AGENT_POLICIES,
    FIELDS,
    FORMAT,
    VERSION,
    Entry,
    Secret,
    Vault,
    VaultFile,
    validate_alias,
    validate_field_name,
    validate_name,
    vault_exists,
)

__all__ = ["register", "overview"]

Handler = Callable[[Context, argparse.Namespace], int]

_KINDS = ("login", "secret")
#: The most --note-stdin reads: the vault itself holds notes of up to a million characters.
_NOTE_LIMIT_BYTES = 4 * 1024 * 1024
_VALUE_LIMIT_BYTES = 64 * 1024  # a value read to the end of stdin: room for any key or certificate chain
#: How Vault.commit names its automatic snapshots (``backups/vault-<generation>.irondome``).
_SNAPSHOT_NAME = re.compile(r"vault-\d{10,}\.irondome")
_MODE_PHRASES = {
    MODE_PASSWORD: "master password + device key",
    MODE_TOUCHID: "Touch ID, or the master password",
    MODE_TOUCHID_PASSWORD: "master password + Touch ID, every time",
    "touchid-only": "Touch ID only (there is no master password)",
    "recovery-only": "the recovery key only",
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _bunker() -> str:
    return paths.bunker_name()


def _safe(text: str) -> str:
    """Text for a terminal: anything not printable (escape sequences, bidi overrides) is shown escaped."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in str(text))


def _count(number: int, singular: str, plural: str = "") -> str:
    """``1 snapshot``, ``2 snapshots``; *plural* where adding an s is wrong (``entry``, ``entries``)."""
    return f"{number} {singular if number == 1 else (plural or singular + 's')}"


def _joined(items: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    words = list(items)
    if len(words) < 2:
        return "".join(words)
    return f"{', '.join(words[:-1])} and {words[-1]}"


class _CarriedThrough:
    """Hold back SIGINT, SIGTERM and SIGHUP while a change that is being written is carried through.

    Between writing a vault file that drops keyslots and retiring them (destroying their device
    keys; for a re-key also the snapshots, sessions and grants), an interruption would leave a way
    in open that the change exists to close. Inside the block a signal is only noted. At its end a
    Ctrl-C is reported and the command goes on to report what it did, since that is done; SIGTERM
    and SIGHUP then take their usual course. Only the main thread can hold signals; elsewhere the
    block changes nothing. A crash or a power cut cannot be held back: for the device keys,
    :func:`irondome.keys.finish_retirement` completes the change at the next command.
    """

    _SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP")

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx
        self._previous: Dict[int, Any] = {}
        self._pending: List[int] = []

    def __enter__(self) -> "_CarriedThrough":
        if threading.current_thread() is not threading.main_thread():
            return self
        for name in self._SIGNALS:
            signum = getattr(signal, name, None)  # Windows has no SIGHUP
            if signum is None:
                continue
            previous = signal.getsignal(signum)
            if previous is None or previous == signal.SIG_IGN:
                continue  # set outside Python, or ignored: left exactly as it is
            signal.signal(signum, self._note)
            self._previous[signum] = previous
        return self

    def _note(self, signum: int, frame: Any) -> None:
        if signum not in self._pending:
            self._pending.append(signum)

    def __exit__(self, kind: Any, error: Any, trace: Any) -> None:
        while self._previous:
            signum, previous = self._previous.popitem()
            signal.signal(signum, previous)
        ending = [signum for signum in self._pending if signum != signal.SIGINT]
        if ending:
            os.kill(os.getpid(), ending[0])  # the handler put back above takes its usual course now
        elif self._pending and kind is None:
            self._ctx.out.warn("interrupted while the change was being written; it was completed first")


def _finish_retirement(ctx: Context) -> None:
    """Destroy the old device keys an interrupted keyslot change left behind (:func:`keys.finish_retirement`)."""
    for problem in keys.finish_retirement():
        ctx.out.warn(problem)


def _require_owner(ctx: Context, action: str) -> None:
    if ctx.agent_mode:
        raise PolicyError(
            f"{action} is for the vault's owner: run it at a terminal, or pipe the master password with "
            "--password-stdin. An agent reaches secrets through a grant its owner makes (irondome grant create)."
        )


def _create_hint(name: str) -> str:
    return "irondome init" if name == paths.FIRST_BUNKER else f"irondome bunker create {name}"


def _require_vault() -> None:
    if not vault_exists():
        name = _bunker()
        raise VaultError(f"there is no vault in bunker {name}. Create one with: {_create_hint(name)}")


def _grant_in_use(args: argparse.Namespace) -> bool:
    """True when ``ctx.access`` will open the grant in the environment rather than the vault."""
    return bool(os.environ.get(ENV_GRANT, "").strip()) and not getattr(args, "no_grant", False)


@contextlib.contextmanager
def _in_bunker(name: str) -> Iterator[None]:
    """Point every path at bunker *name* for the duration, as ``--bunker`` would."""
    saved = os.environ.get(paths.ENV_BUNKER)
    os.environ[paths.ENV_BUNKER] = name
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop(paths.ENV_BUNKER, None)
        else:
            os.environ[paths.ENV_BUNKER] = saved


def _commit(vault: Vault, settings: Dict[str, int]) -> None:
    vault.commit(snapshots=settings["snapshots"])


def _text_of(buffer: Optional[SecureBuffer], what: str) -> str:
    """The text in *buffer*, which is wiped. Entries are ``str`` once they are decrypted anyway."""
    if buffer is None:
        raise UsageError(f"{what} cannot be empty")
    raw = bytes(buffer.view())
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise UsageError(f"{what} is not valid UTF-8 text") from None
    finally:
        wipe_bytes(raw)
        buffer.wipe()


def _stdin_text(what: str) -> str:
    buffer = read_secret_from_fd(0, allow_empty=True)
    if buffer is None:
        raise UsageError(f"expected {what} on the next line of stdin, and found nothing")
    return _text_of(buffer, what)


def _prompt_text(ctx: Context, prompt: str, what: str, alternative: str) -> str:
    if not ctx.has_terminal:
        raise UsageError(f"there is no terminal to type {what} at; pass it with {alternative}")
    return _text_of(read_secret(prompt, allow_empty=True), what)


def _skip_password_line(ctx: Context) -> None:
    """With --password-stdin the first line is the master password, even when a session opened the vault."""
    if ctx.password_stdin and ctx.unlocked_by == "session":
        # From stdin, or at a hidden prompt when stdin is this terminal: either way the line is not the value.
        unused = ctx.read_secret("Master password (a session is open, so it is not checked): ", allow_empty=True)
        if unused is not None:
            unused.wipe()


def _copy(ctx: Context, value: str, what: str) -> str:
    seconds = config.get("clipboard_clear_seconds")
    tool = clipboard.copy(value, seconds)
    ctx.out.ok(f"copied {what} to the clipboard ({tool}); it is cleared in {seconds}s unless you copy something else")
    return tool


def _mode_of(slots: Sequence[Keyslot]) -> str:
    """The setup mode a list of keyslots amounts to (see ``irondome init --mode``)."""
    has_touch = any(slot.kind == KIND_DEVICE for slot in slots)
    passwords = [slot for slot in slots if slot.kind == KIND_PASSWORD]
    if has_touch:
        return MODE_TOUCHID if passwords else "touchid-only"
    if any(slot.policy not in (None, POLICY_DEVICE) for slot in passwords):
        return MODE_TOUCHID_PASSWORD
    return MODE_PASSWORD if passwords else "recovery-only"


def _hardware_of(name: Optional[str]) -> Optional[bool]:
    """Whether the backend *name* is a chip on this machine (a TPM simulator is not), or None if unknown."""
    try:
        return devices.hardware_here(devices.get_backend(str(name)))
    except IronDomeError:
        return None


def _slot_info(slot: Keyslot) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "id": slot.id,
        "kind": slot.kind,
        "label": slot.label,
        "describe": slot.describe(),
        "created": slot.created,
        "backend": slot.backend_name,
        "policy": slot.policy,
        "hardware": None,
        "device_present": None,
        "device_fault": None,
        "kdf": None,
    }
    if slot.kind == KIND_PASSWORD and slot.kdf is not None:
        try:
            info["kdf"] = cost_phrase(Argon2Params.from_dict(slot.kdf))
        except IronDomeError:
            pass  # a damaged keyslot is reported where it is opened
    if slot.device is not None:
        try:
            backend = devices.get_backend(str(slot.backend_name))
            info["hardware"] = devices.hardware_here(backend)
            info["device_present"] = bool(backend.exists(slot.device))
            info["device_fault"] = backend.fault(slot.device)
        except (IronDomeError, OSError):
            pass  # an unknown backend or a damaged descriptor: reported as unknown
    return info


def _devices_of(slots: Sequence[Keyslot]) -> List[Dict[str, Any]]:
    names = sorted({str(slot.backend_name) for slot in slots if slot.device is not None})
    return [{"backend": name, "hardware": _hardware_of(name)} for name in names]


def _device_phrase(device: Dict[str, Any]) -> str:
    where = f"a file in {paths.device_dir()}" if device["backend"] == "software" else "software stands in for the chip"
    kind = {True: "hardware", False: f"not hardware: {where}", None: "unknown here"}
    return f"{device['backend']} ({kind[device['hardware']]})"


def _capability_counts() -> Tuple[Optional[int], Optional[int]]:
    """Active sessions and grants of the current bunker, from the capability headers."""
    try:
        listed = caps.list_caps()
    except IronDomeError:
        return None, None
    active = [item for item in listed if not item.expired]
    sessions = sum(1 for item in active if item.kind == caps.KIND_SESSION)
    return sessions, sum(1 for item in active if item.kind == caps.KIND_GRANT)


def _snapshot_count() -> int:
    try:
        with os.scandir(str(paths.backups_dir())) as listing:
            return sum(
                1 for item in listing if _SNAPSHOT_NAME.fullmatch(item.name) and item.is_file(follow_symlinks=False)
            )
    except OSError:
        return 0


def _legacy_info() -> Optional[Dict[str, Any]]:
    """Where an IronDome 3.x vault is, if there is one."""
    from irondome import migrate_v3

    try:
        found = migrate_v3.detect()
    except IronDomeError as exc:
        return {"path": str(paths.legacy_v3_dir()), "error": str(exc)}
    return None if found is None else {"path": str(found.path), "error": None}


def _legacy_hint(ctx: Context) -> None:
    legacy = _legacy_info()
    if legacy is not None:
        ctx.out.info(f"An IronDome 3.x vault is at {legacy['path']}. Bring its entries over with: irondome migrate")


def _end_sessions(ctx: Context, vault: Vault) -> int:
    try:
        return caps.end_sessions(vault=vault)
    except IronDomeError as exc:
        ctx.out.warn(f"sessions: {exc}")
        return 0


@contextlib.contextmanager
def _naming_the_bunker() -> Iterator[None]:
    """Where several bunkers live, say which one refused: a wrong password is otherwise ambiguous."""
    try:
        yield
    except AuthError as exc:
        if len(paths.bunkers()) < 2:
            raise
        raise type(exc)(f"bunker {_bunker()}: {exc}") from None


@contextlib.contextmanager
def _unlocked(ctx: Context, reason: str, *, fresh: bool = False) -> Iterator[Vault]:
    """``ctx.open_vault`` as a block that closes the vault, with the bunker named in a refusal."""
    _finish_retirement(ctx)
    with _naming_the_bunker():
        vault = ctx.open_vault(reason=reason, fresh=fresh)
    with vault:
        yield vault


@contextlib.contextmanager
def _accessing(
    ctx: Context,
    reason: str,
    *,
    consume: bool = True,
    references: Optional[Sequence[str]] = None,
    purpose: str = PURPOSE_REVEAL,
    detail: str = "",
) -> Iterator[Access]:
    """``ctx.access`` as a block that closes it, with the bunker named in a refusal.

    *references* (with *purpose* and *detail*) are what the block will read: a grant is looked at
    first, so that a request it refuses spends none of its uses.
    """
    _finish_retirement(ctx)
    with _naming_the_bunker():
        access = ctx.access(reason=reason, consume=consume, references=references, purpose=purpose, detail=detail)
    with access:
        yield access


# ---------------------------------------------------------------------------
# Keyslots
# ---------------------------------------------------------------------------


def _choose_backend(policy: str) -> DeviceBackend:
    return _choose(policy).backend


def _choose(policy: str) -> devices.Choice:
    """The device backend for a new keyslot, and why it is that one (see devices.Choice)."""
    try:
        return devices.choose(policy)
    except HardwareError as exc:
        if policy == POLICY_DEVICE:
            raise
        raise HardwareError(
            "Touch ID needs a Mac with a Secure Enclave and a usable fingerprint sensor, and no device "
            f"backend here can enforce it ({exc})"
        ) from None


def _backend_phrase(backend: DeviceBackend) -> str:
    """The backend's name, whether it is hardware here, and its own description of itself.

    Whether it is hardware comes from the probe of this machine: a TPM 2.0 simulator is the TPM
    backend, and it is software.
    """
    try:
        probe = backend.probe()
    except IronDomeError:
        return f"{backend.name}, {'hardware' if backend.hardware else 'not hardware'}"
    kind = "hardware" if probe.hardware else "not hardware"
    return f"{backend.name}, {kind}" + (f" -- {probe.detail}" if probe.detail else "")


def _chip_status() -> Dict[str, Optional[str]]:
    """For status, when a device key is a file: why no chip holds it, and the way to one. Compiles nothing.

    It asks what this machine has (``auto``), whatever IRONDOME_DEVICE_BACKEND says: that variable is
    part of the answer, not the question.
    """
    try:
        choice = devices.choose(POLICY_DEVICE, "auto", passive=True)
    except IronDomeError as exc:
        return {"why": str(exc), "fix": None}
    rekey = "irondome rekey moves the vault onto it (and shows a new recovery key)"
    if choice.hardware:
        why, fix = None, f"this machine's {choice.backend.name} can hold it: {rekey}"
    elif choice.chip_unknown:
        why = choice.why_no_chip
        fix = "irondome rekey tries the chip and moves the vault onto it if it works (and shows a new recovery key)"
    else:
        why, fix = choice.why_no_chip, f"a chip needs {devices.chip_requirements()}; then {rekey}"
    forced = os.environ.get(devices.ENV_BACKEND, "auto")
    if forced not in ("", "auto"):
        why = f"{devices.ENV_BACKEND} is set to {forced}" + (f"; {why}" if why else "")
        fix = f"unset {devices.ENV_BACKEND} first; {fix}"
    return {"why": why, "fix": fix}


def cost_phrase(params: Argon2Params) -> str:
    """The Argon2id cost in words, and whether it is below what IronDome uses by default."""
    lanes = "lane" if params.lanes == 1 else "lanes"
    passes = "pass" if params.iterations == 1 else "passes"
    text = f"Argon2id, {params.memory_kib // 1024} MiB, {params.iterations} {passes}, {params.lanes} {lanes}"
    if params.memory_kib < DEFAULT_ARGON2.memory_kib:
        text += f" (below the usual {DEFAULT_ARGON2.memory_kib // 1024} MiB)"
    return text


def warn_if_cheap(ctx: Context, params: Argon2Params, what: str) -> None:
    """Say so when *what* was made with less Argon2id memory than the default, and why that is.

    The cost is lowered by an environment variable, by an option or by a small machine, and none of
    them is visible afterwards: a person must not find out from a stopwatch.
    """
    if params.memory_kib >= DEFAULT_ARGON2.memory_kib:
        return
    if os.environ.get("IRONDOME_KDF_MEMORY_MIB"):
        why = "IRONDOME_KDF_MEMORY_MIB is set in the environment"
    elif params == default_argon2():
        why = "this machine has less than 3 GiB of RAM"
    else:
        why = "that is the cost it was asked for, or the cost of the keyslot it replaces"
    ctx.out.warn(
        f"{what} stretches its password with {params.memory_kib // 1024} MiB of memory, not the usual "
        f"{DEFAULT_ARGON2.memory_kib // 1024} MiB ({why}): each guess at the password costs an attacker that much less"
    )




def _params_of(slots: Sequence[Keyslot]) -> Argon2Params:
    """The Argon2id cost of the first password slot, or today's default when there is none."""
    for slot in slots:
        if slot.kind == KIND_PASSWORD and slot.kdf is not None:
            return Argon2Params.from_dict(slot.kdf)
    return default_argon2()


def _destroy_devices(slots: Sequence[Keyslot]) -> List[str]:
    """Destroy the device secrets of *slots*; return what could not be destroyed."""
    problems = []
    for slot in slots:
        try:
            keys.destroy_slot_device(slot)
        except IronDomeError as exc:
            problems.append(f"the device key of the old keyslot {slot.id[:8]} ({slot.describe()}): {exc}")
    return problems


def _replace_slots(
    ctx: Context,
    vault: Vault,
    *,
    remove: Sequence[Keyslot],
    add: Sequence[Keyslot],
    purge: bool = False,
    end_sessions: bool = False,
    forget: Sequence[Keyslot] = (),
) -> Tuple[int, int]:
    """Swap keyslots and write the vault; then destroy the device secrets of the slots that went.

    In this order, holding the vault lock, so that no interruption leaves an old way in open:

    1. whatever an earlier, interrupted change left recorded is finished;
    2. with *purge* every snapshot is deleted, and with *end_sessions* every session ends: they were
       made under the old keyslots, and losing them costs nothing if the write then fails;
    3. every device secret involved, old and new, is recorded (:func:`keys.record_retirement`);
    4. the vault is written, with no snapshot: a copy holding the old keyslots is what must not stay;
    5. of the recorded secrets, those the file on disk does not use are destroyed.

    4 and 5 run with signals held back (:class:`_CarriedThrough`); after a crash or a power cut, the
    next command that opens the vault does 5. The file on disk decides, so a failed write destroys the
    new slots' secrets instead, which nothing refers to, and never the old ones. Old device secrets
    go only once the new file is on disk: whatever happens, the vault still opens. Returns
    ``(snapshots deleted, sessions ended)``.

    *forget* are keyslots taken out of the file whose device secrets are left alone: they are not on
    this machine, or cannot be reached from it, so there is nothing here to destroy and nothing to
    keep trying to (``recovery use`` on a machine that never held them, or whose chip has died).
    """
    purged = ended = 0
    with paths.file_lock(paths.lock_file()):
        _finish_retirement(ctx)
        recorded = False
        try:
            if purge:
                purged = vault.purge_snapshots()
            if end_sessions:
                ended = _end_sessions(ctx, vault)
            for slot in add:
                vault.add_slot(slot)
            for slot in [*remove, *forget]:
                vault.remove_slot(slot.id)
            recorded = keys.record_retirement([*remove, *add])
            with _CarriedThrough(ctx):
                vault.commit(snapshots=0)
                _finish_retirement(ctx)
            # A keyslot change killed before its rename left a whole vault with the old keyslots in a temporary
            # file. The lock is held, so nothing is writing one now.
            paths.sweep_temporary(paths.home(), older_than=0)
        except BaseException:
            if recorded:
                _finish_retirement(ctx)
            else:
                _destroy_devices(add)
            raise
    return purged, ended


def _new_password_slot(
    vault: Vault, password: SecureBuffer, *, backend: Optional[DeviceBackend], policy: str, label: str,
    params: Argon2Params,
) -> Keyslot:
    return keys.create_password_slot(
        vault.vault_key, password, vault.vault_id, params=params, backend=backend, policy=policy, label=label
    )


@contextlib.contextmanager
def _open_with_password(ctx: Context, reason: str) -> Iterator[Tuple[Vault, Optional[SecureBuffer]]]:
    """A fresh unlock that keeps the master password, where the vault has one, for new keyslots.

    A vault with a password keyslot is opened with the master password itself, which is kept. A
    vault without one (Touch ID and the recovery key only) is opened as usual, and the password is
    None. The caller must not keep either beyond the block.
    """
    _finish_retirement(ctx)
    file = VaultFile.load()
    password: Optional[SecureBuffer] = None
    if any(slot.kind == KIND_PASSWORD for slot in file.slots):
        password = ctx.master_password(reason)
        may_touch = not ctx.no_touch and (ctx.has_terminal or ctx.touch)
        try:
            with _naming_the_bunker():
                key = unlock(
                    file,
                    password=password,
                    interactive=may_touch or ctx.has_terminal,
                    allow_touch=may_touch,
                    reason=reason,
                )
            vault = Vault(file, key)
        except BaseException:
            password.wipe()
            raise
    else:
        with _naming_the_bunker():
            vault = ctx.open_vault(reason=reason, fresh=True)
    try:
        yield vault, password
    finally:
        if password is not None:
            password.wipe()
        vault.close()


@contextlib.contextmanager
def _open_keeping_password(ctx: Context, reason: str) -> Iterator[Tuple[Vault, SecureBuffer]]:
    """:func:`_open_with_password`, except that a vault without a master password is given a new one.

    The new master password is asked for once the vault is open. The caller gets both and must not
    keep either beyond the block.
    """
    with _open_with_password(ctx, reason) as (vault, current):
        password = current if current is not None else ctx.new_master_password()
        try:
            yield vault, password
        finally:
            password.wipe()


def _print_recovery_key(ctx: Context, key: str, bunker: str) -> None:
    """Print the recovery key once, framed."""
    ctx.out.info("")
    ctx.out.info(f"Recovery key for bunker {bunker}. It is shown this once and stored nowhere:")
    ctx.out.info("")
    ctx.out.secret(key)
    ctx.out.info("")
    ctx.out.warn(
        "the recovery key opens a copy of this vault on any machine, without this device and without "
        "the master password. Keep it offline (on paper, not in a file or a photo)."
    )


def _wait_until_kept(ctx: Context) -> None:
    if ctx.has_terminal:
        ctx.ask("Press Enter once you have written it down. ")


def _show_recovery_key(ctx: Context, key: str, bunker: str) -> None:
    """Print the recovery key once, framed, and on a terminal wait until the person has kept it."""
    _print_recovery_key(ctx, key, bunker)
    _wait_until_kept(ctx)


def _rekey_vault(
    ctx: Context, vault: Vault, password: Optional[SecureBuffer], *, action: str, detail: str,
    on_switch: Optional[Callable[[List[str]], None]] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    """Re-key *vault*, with the keyslots it holds now, as ``irondome rekey`` does. Returns (report, recovery keys).

    It is the one re-key there is, :mod:`irondome.cli.cmd_admin`'s: a new vault key and vault id;
    every entry and alias re-encrypted; every keyslot of *vault* made anew (a recovery keyslot with
    a new recovery key, returned to be shown once); then the old device keys destroyed, the
    snapshots deleted, every session and grant ended and the audit log archived. *action* and
    *detail* are recorded in the new vault's audit log afterwards. The report holds what
    ``irondome rekey --json`` reports, under the same names. *password* stays the caller's.
    *on_switch* is called with the new recovery keys as soon as the new vault is live, before
    anything that a crash could stop: from then on they are the only ones that open it.
    """
    from irondome.cli import cmd_admin  # the re-key lives there; nothing else here needs that module

    used = cmd_admin._rekey_password(ctx, vault, password)
    try:
        fresh, recovery, staging = cmd_admin._rekey(vault, used)
    finally:
        if used is not None and used is not password:
            used.wipe()
    try:
        if on_switch is not None:
            on_switch(recovery)
        outcome = cmd_admin._retire(ctx, vault, fresh, staging)
        ctx.audit(fresh, action, detail=detail)
        report: Dict[str, Any] = {
            "vault_id": fresh.vault_id.hex(),
            "entries": len(fresh.entries),
            "keyslots": [
                {"kind": slot.kind, "label": slot.label, "backend": slot.backend_name, "policy": slot.policy}
                for slot in fresh.file.slots
            ],
        }
        report.update(outcome)
    finally:
        fresh.close()
    return report, recovery


def _say_rekeyed(ctx: Context, report: Dict[str, Any]) -> None:
    """What re-keying did, in words, and anything it could not do."""
    ctx.out.info(
        f"Re-keyed: a new vault key and vault id, {_count(report['entries'], 'entry', 'entries')} re-encrypted "
        f"and {_count(len(report['keyslots']), 'keyslot')} made anew; "
        f"{_count(report['sessions_and_grants_ended'], 'session or grant', 'sessions and grants')} ended, "
        f"{_count(report['snapshots_deleted'], 'snapshot')} deleted and "
        f"{_count(report['device_keys_destroyed'], 'old device key')} destroyed."
    )
    if report["audit_archive"]:
        ctx.out.info(
            f"The audit log was archived as {report['audit_archive']}. Read or check it with: "
            f"irondome audit --archive {Path(report['audit_archive']).name}"
        )
    ctx.out.warn(
        "copies of the vault file made before now (backups, synced folders) still open with the old recovery "
        "key, on any machine, and show what they held then. Delete them, or treat what they hold as known to "
        "whoever has that key."
    )
    for leftover in report["leftovers"]:
        ctx.out.warn(leftover)


# ---------------------------------------------------------------------------
# init and bunker create
# ---------------------------------------------------------------------------


def _kdf_params(mib: Optional[int]) -> Optional[Argon2Params]:
    if mib is None:
        return None
    try:
        return Argon2Params(memory_kib=mib * 1024).validate()
    except VaultError as exc:
        raise UsageError(f"--kdf-memory-mib {mib} cannot be used: {exc}") from None


def _offer_modes(ctx: Context) -> str:
    """On a terminal where Touch ID works, let the person choose; otherwise the password mode."""
    if not ctx.has_terminal or ctx.out.json_mode:
        return MODE_PASSWORD
    ctx.out.info("Checking for Touch ID...")
    try:
        offered = _choose_backend(POLICY_BIOMETRY).probe().biometry
    except IronDomeError:
        offered = False
    if not offered:
        return MODE_PASSWORD
    ctx.out.info("This machine can use Touch ID. How should the vault open?")
    ctx.out.info("  1  password          master password + this machine's security chip (default)")
    ctx.out.info("  2  touchid           Touch ID, with the master password as the fallback")
    ctx.out.info("  3  touchid+password  both, every time")
    answer = ctx.ask("Choose 1, 2 or 3 [1]: ").strip().lower()
    choices = {"": MODE_PASSWORD, "1": MODE_PASSWORD, "2": MODE_TOUCHID, "3": MODE_TOUCHID_PASSWORD}
    choices.update({mode: mode for mode in MODES})
    if answer not in choices:
        raise UsageError(f"{answer!r} is not one of the choices; nothing was created. Run it again, or pass --mode")
    return choices[answer]


def _has_vault(name: str) -> bool:
    with _in_bunker(name):
        return vault_exists()


def _prove_for_another_bunker(ctx: Context, name: str) -> None:
    """Where another bunker already has a vault, only its owner may make one more.

    Otherwise an agent could make a bunker whose master password it chose itself, and then the
    default. The proof is the default bunker's: its master password on stdin, or a person at a
    terminal. (Where the default bunker has no vault, alpha's or else the first that has one.)
    The very first vault on a machine is anyone's to create, a script's included.
    """
    others = [other for other in paths.bunkers() if other != name and _has_vault(other)]
    if not others:
        return
    try:
        default: Optional[str] = paths.default_bunker()
    except UsageError:
        default = None
    if default not in others:
        default = paths.FIRST_BUNKER if paths.FIRST_BUNKER in others else others[0]
    ctx.prove_owner(f"adding bunker {name} next to bunker {default}", bunker=default)


def _create(ctx: Context, args: argparse.Namespace) -> int:
    """``init`` for the current bunker; ``bunker create`` runs it inside the named one."""
    name = _bunker()
    _require_owner(ctx, "creating a vault")
    if vault_exists():
        raise VaultError(
            f"bunker {name} already has a vault ({paths.vault_file()}); nothing was changed. "
            "Make another with: irondome bunker create NAME"
        )
    if args.no_password and args.mode != MODE_TOUCHID:
        raise UsageError("--no-password goes with --mode touchid: Touch ID alone, the recovery key as the fallback")
    if args.no_password and args.no_recovery:
        raise UsageError(
            "a vault that opens with Touch ID alone needs a second way in: keep the recovery key, "
            "or set a master password"
        )
    params = _kdf_params(args.kdf_memory_mib)
    _prove_for_another_bunker(ctx, name)
    mode = args.mode if args.mode is not None else _offer_modes(ctx)
    choice = _choose(POLICY_DEVICE if mode == MODE_PASSWORD else POLICY_BIOMETRY)
    backend = choice.backend
    ctx.out.info(f"Creating the vault of bunker {name}. Device key: {_backend_phrase(backend)}.")
    if choice.picked == "auto" and choice.why_no_chip is not None:
        ctx.out.warn(f"no security chip holds this vault's device key: {choice.why_no_chip}")
        held = (
            f"The device key is a file in {paths.device_dir()}: anyone who can read your files can copy it."
            if backend.name == "software"
            else f"The device key is held by {backend.name}, which on this machine is software and not a chip: "
            "whoever can read what that software stores can copy it."
        )
        ctx.out.info(
            f"{held} A chip needs {devices.chip_requirements()}; once that is in place, irondome rekey moves "
            "the vault onto it (and shows a new recovery key)."
        )
    password = None if args.no_password else ctx.new_master_password()
    try:
        vault, recovery = create_vault(
            mode=mode, password=password, with_recovery=not args.no_recovery, params=params, backend_name=backend.name
        )
    finally:
        if password is not None:
            password.wipe()
    with vault:
        used = _params_of(vault.slots(KIND_PASSWORD)) if vault.slots(KIND_PASSWORD) else None
        ctx.audit(
            vault, "vault.create", target=name,
            detail=f"mode={mode} backend={backend.name} recovery={'yes' if recovery else 'no'}",
        )
        path = vault.path
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "created": True,
                "bunker": name,
                "path": str(path),
                "mode": mode,
                "device": {"backend": backend.name, "hardware": choice.hardware,
                           "why_no_chip": choice.why_no_chip},
                "recovery_key": recovery,
            }
        )
    else:
        ctx.out.ok(f"created the vault of bunker {name} at {path}")
        ctx.out.info(f"It opens with: {_MODE_PHRASES[mode]}.")
        if used is not None:
            ctx.out.info(f"Password stretching: {cost_phrase(used)}.")
        if recovery is not None:
            _show_recovery_key(ctx, recovery, name)
        else:
            ctx.out.warn(
                "there is no recovery key: if this machine or its security chip is lost, so is this vault"
                + (" (a restore of this Mac from Time Machine counts: it leaves the device key out)"
                   if sys.platform == "darwin" else "")
            )
    _legacy_hint(ctx)
    ctx.out.info("Next: irondome add NAME --generate stores a new login with a generated password.")
    return 0


def _bunker_create(ctx: Context, args: argparse.Namespace) -> int:
    name = paths.validate_bunker_name(args.name)
    _require_owner(ctx, "creating a bunker")
    with _in_bunker(name):
        status = _create(ctx, args)
    ctx.out.info(
        f"Work on it with: irondome --bunker {name} COMMAND (or IRONDOME_BUNKER={name}). "
        f"Make it the default with: irondome bunker use {name}"
    )
    return status


# ---------------------------------------------------------------------------
# status and the overview
# ---------------------------------------------------------------------------


def _status_document() -> Tuple[Dict[str, Any], int]:
    """What ``status`` reports, and the exit status that goes with it. Unlocks nothing."""
    sessions, grants = _capability_counts()
    document: Dict[str, Any] = {
        "bunker": _bunker(),
        "path": str(paths.vault_file()),
        "exists": vault_exists(),
        "error": None,
        "format": None,
        "version": None,
        "generation": None,
        "created": None,
        "mode": None,
        "device": [],
        "hardware": None,
        "chip": None,
        "keyslots": [],
        "sessions": sessions,
        "grants": grants,
        "snapshots": _snapshot_count(),
        "legacy_v3": _legacy_info(),
        "unfinished_rekey": None,
    }
    if not document["exists"]:
        return document, 0
    try:
        file = VaultFile.load()
    except VaultError as exc:
        document["error"] = str(exc)
        return document, VaultError.exit_code
    used = _devices_of(file.slots)
    staged = caps.unfinished_rekey()
    document.update(
        unfinished_rekey=str(staged) if staged is not None else None,
        format=FORMAT,
        version=VERSION,
        generation=file.generation,
        created=file.created,
        mode=_mode_of(file.slots),
        device=used,
        hardware=all(item["hardware"] is True for item in used) if used else None,
        keyslots=[_slot_info(slot) for slot in file.slots],
    )
    if any(item["hardware"] is False for item in used):
        document["chip"] = _chip_status()
    return document, 0


def _slot_line(info: Dict[str, Any]) -> str:
    if info["kind"] == KIND_RECOVERY:
        return f"{info['describe']} (not bound to this device)"
    present = {True: "device key present", False: "device key MISSING: this keyslot cannot open", None: "unknown"}
    cost = f"; {info['kdf']}" if info.get("kdf") else ""
    state = present[info["device_present"]]
    if info.get("device_fault"):
        state = "device key file DAMAGED: this keyslot cannot open"
    return f"{_safe(info['describe'])} -- {state}{cost}"


def _print_status(ctx: Context, document: Dict[str, Any]) -> None:
    pairs: List[Tuple[str, str]] = [("bunker", document["bunker"])]
    if not document["exists"]:
        pairs.append(("vault", f"none yet (it would be {document['path']})"))
    elif document["error"]:
        pairs.append(("vault", f"{document['path']} -- cannot be read: {document['error']}"))
    else:
        pairs.append(("vault", document["path"]))
        pairs.append(
            ("format", f"{document['format']} {document['version']}, generation {document['generation']}, "
             f"created {format_time(document['created'])}")
        )
        pairs.append(("opens with", _MODE_PHRASES.get(document["mode"], document["mode"])))
        pairs.extend(("device key", _device_phrase(item)) for item in document["device"])
        chip = document.get("chip")
        if chip is not None:
            pairs.extend((label, chip[key]) for label, key in (("no chip", "why"), ("fix", "fix")) if chip[key])
        pairs.extend(("keyslot", _slot_line(info)) for info in document["keyslots"])
        if document.get("unfinished_rekey"):
            pairs.append(("re-key", "UNFINISHED: sessions and grants are refused until it is. Run: irondome rekey"))
    for label in ("sessions", "grants"):
        count = document[label]
        shown = "unknown (the capability directory cannot be read)" if count is None else f"{count} active"
        pairs.append((label, shown))
    pairs.append(("snapshots", str(document["snapshots"])))
    legacy = document["legacy_v3"]
    if legacy is not None:
        detail = f"damaged: {legacy['error']}" if legacy["error"] else "bring it over with: irondome migrate"
        pairs.append(("3.x vault", f"{legacy['path']} ({detail})"))
    ctx.out.pairs(pairs)


def _status(ctx: Context, args: argparse.Namespace) -> int:
    document, status = _status_document()
    if ctx.out.json_mode:
        ctx.out.json(document)
    else:
        _print_status(ctx, document)
    if document["unfinished_rekey"]:
        ctx.out.warn(caps.unfinished_rekey_warning(Path(document["unfinished_rekey"])))  # stderr, with --json too
    return status


def overview(ctx: Context, parser: argparse.ArgumentParser) -> int:
    """What ``irondome`` prints when no command is given: how to start, or the status and a hint."""
    document, _status_code = _status_document()
    if ctx.out.json_mode:
        ctx.out.json(document)
        return 0
    prog = parser.prog
    if not document["exists"]:
        ctx.out.data(f"There is no vault in bunker {document['bunker']} yet. To start:")
        ctx.out.data(f"  {prog} init      create it: a master password, Touch ID, or both")
        ctx.out.data(f"  {prog} --help    every command, with examples")
        legacy = document["legacy_v3"]
        if legacy is not None:
            ctx.out.data(f"An IronDome 3.x vault is at {legacy['path']}. Bring it over with: {prog} migrate")
        return 0
    _print_status(ctx, document)
    ctx.out.data("")
    ctx.out.data(f"{prog} ls lists the entries, {prog} add NAME --generate stores one, {prog} --help shows the rest.")
    return 0


# ---------------------------------------------------------------------------
# add, edit: where values come from
# ---------------------------------------------------------------------------


def _value_source(args: argparse.Namespace) -> Optional[str]:
    chosen = [
        flag
        for flag, given in (
            ("--generate", args.generate),
            ("--words", args.words is not None),
            ("--value-stdin", args.value_stdin),
            ("--prompt-value", getattr(args, "prompt_value", False)),
        )
        if given
    ]
    if len(chosen) > 1:
        raise UsageError(f"the value comes from one source; choose one of {', '.join(chosen)}")
    return chosen[0] if chosen else None


def _totp_source(args: argparse.Namespace) -> Optional[str]:
    chosen = [
        flag
        for flag, given in (
            ("--totp", args.totp),
            ("--totp-stdin", args.totp_stdin),
            ("--no-totp", getattr(args, "no_totp", False)),
        )
        if given
    ]
    if len(chosen) > 1:
        raise UsageError(f"choose one of {', '.join(chosen)}")
    return chosen[0] if chosen else None


def _check_value_options(ctx: Context, args: argparse.Namespace, source: Optional[str], totp: Optional[str]) -> None:
    """Everything about the value and TOTP options that can be refused before the vault is opened."""
    password_options = [
        flag
        for flag, given in (
            ("--length", args.length is not None),
            ("--no-symbols", args.no_symbols),
            ("--no-digits", args.no_digits),
            ("--no-upper", args.no_upper),
            ("--no-ambiguous", args.no_ambiguous),
        )
        if given
    ]
    if password_options and source != "--generate":
        verb = "applies" if len(password_options) == 1 else "apply"
        raise UsageError(f"{', '.join(password_options)} {verb} only to --generate")
    if (args.show or args.copy) and source not in ("--generate", "--words"):
        raise UsageError("--show and --copy apply to a generated value (--generate or --words)")
    if source == "--generate":
        _password_bits(args, config.get("password_length"))  # checks the length and the classes
    if source == "--words":
        generator.passphrase_entropy_bits(args.words)  # checks the word count
    if source in ("--prompt-value", "prompt") and not ctx.has_terminal:
        raise UsageError("there is no terminal to type the value at: pass --generate, --words N or --value-stdin")
    if totp == "--totp" and not ctx.has_terminal:
        raise UsageError("there is no terminal to type the one-time-password secret at: pass --totp-stdin")


def _password_bits(args: argparse.Namespace, default_length: int) -> float:
    length = args.length if args.length is not None else default_length
    return generator.password_entropy_bits(
        length,
        upper=not args.no_upper,
        digits=not args.no_digits,
        symbols=not args.no_symbols,
        exclude_ambiguous=args.no_ambiguous,
    )


def _read_value(
    ctx: Context, args: argparse.Namespace, source: str, name: str, settings: Dict[str, int]
) -> Tuple[str, Optional[str]]:
    """The value, and a description of it when it was generated."""
    if source == "--generate":
        length = args.length if args.length is not None else settings["password_length"]
        value = generator.generate_password(
            length,
            upper=not args.no_upper,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
            exclude_ambiguous=args.no_ambiguous,
        )
        return value, f"a {length}-character password ({_password_bits(args, length):.0f} bits)"
    if source == "--words":
        bits = generator.passphrase_entropy_bits(args.words)
        return generator.generate_passphrase(args.words), f"a {args.words}-word passphrase ({bits:.0f} bits)"
    if source == "--value-stdin" and ctx.typed_stdin:
        # Typed, not piped: a line read from the terminal would be echoed, so it is asked for as any typed value.
        ctx.out.info(
            "stdin is this terminal, so the value is typed at a hidden prompt, one line. For a value of several "
            "lines, give this command the file on stdin instead: ... --value-stdin < FILE"
        )
        return _prompt_text(ctx, f"Value for {_safe(name)}: ", "the value", "--value-stdin"), None
    if source == "--value-stdin":
        return _stdin_value(args), None
    return _prompt_text(ctx, f"Value for {_safe(name)}: ", "the value", "--value-stdin"), None


def _stdin_value(args: argparse.Namespace) -> str:
    """The value from stdin: all that is left there, or one line when something else follows it.

    A private key or a certificate is several lines, and a command that kept the first and said ``ok``
    would lose the rest without a word. So when the value is the last thing stdin holds for this command
    (no ``--totp-stdin``, no ``--field``, no ``--note-stdin``) it is everything up to the end of input: a
    single line without the line breaks after it, several lines exactly as they came. When something
    follows, each item is one line; a value of several lines then needs its own command. (At a terminal
    the value is typed at a hidden prompt instead: see :func:`_read_value`.)
    """
    what = "the value"
    if args.totp_stdin or args.field or args.note_stdin:
        return _stdin_text(what)
    data = _stdin_bytes(what, _VALUE_LIMIT_BYTES)
    try:
        if not data:
            raise UsageError(f"expected {what} on stdin, and found nothing")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise UsageError(f"{what} is not valid UTF-8 text") from None
    finally:
        wipe_bytes(data)
    body = text.rstrip("\r\n")  # `echo token`, or a file whose last lines are blank: still one line
    if not body:
        # `echo "$TOKEN"` with TOKEN unset: saying ok would empty the value that was there.
        raise UsageError(f"{what} cannot be empty: stdin held only line breaks")
    return text if "\n" in body else body


def _read_totp(ctx: Context, source: Optional[str]) -> Optional[Dict[str, Any]]:
    what = "the one-time-password secret"
    if source == "--totp-stdin" and not ctx.typed_stdin:
        text = _stdin_text(what)
    elif source in ("--totp", "--totp-stdin"):
        text = _prompt_text(ctx, "One-time-password secret (base32, or an otpauth:// link): ", what, "--totp-stdin")
    else:
        return None
    text = text.strip()
    if text.lower().startswith("otpauth"):
        return otp.parse_otpauth(text)
    return otp.make_totp(text)


def _field_names(items: Optional[Sequence[str]]) -> List[str]:
    """The custom fields ``--field`` names, in command-line order. Their values never come from argv."""
    names: List[str] = []
    for item in items or []:
        if "=" in item:
            # The value is not repeated here: it is a secret, and it is already one place too many.
            key = _safe(item.partition("=")[0]) or "NAME"
            raise UsageError(
                "--field takes only the field's name; IronDome asks for the value (or reads it from stdin), so it "
                f"never lands in your shell history or the process list. Give --field {key} instead. If that value "
                "is a real secret, it is in your shell history now: remove it there."
            )
        if item in FIELDS:
            raise UsageError(f"{item!r} is a built-in field; use its own option instead of --field")
        validate_field_name(item)
        if item in names:
            raise UsageError(f"--field {item} was given twice")
        names.append(item)
    return names


def _stdin_carries_input(ctx: Context, args: argparse.Namespace) -> bool:
    """True when this command reads its input from stdin: then the field values come from there as well."""
    return ctx.password_stdin or any(
        getattr(args, flag, False) for flag in ("value_stdin", "totp_stdin", "note_stdin")
    )


_FIELDS_ON_STDIN = "--password-stdin (stdin then holds the master password, then one line per --field)"


def _read_fields(ctx: Context, args: argparse.Namespace, names: Sequence[str]) -> Dict[str, str]:
    """The value of each named custom field: one stdin line each, in order, or a hidden prompt each."""
    values: Dict[str, str] = {}
    from_stdin = _stdin_carries_input(ctx, args) and not ctx.typed_stdin
    for name in names:
        what = f"the value of the field {name}"
        if from_stdin:
            values[name] = _stdin_text(what)
        else:
            values[name] = _prompt_text(ctx, f"Value of the field {name}: ", what, _FIELDS_ON_STDIN)
    return values


def _stdin_bytes(what: str, limit: int) -> bytearray:
    """Everything left on stdin, up to *limit* bytes. The caller wipes what it gets."""
    raw = io.FileIO(0, "rb", closefd=False)
    data = bytearray()
    try:
        while True:
            try:
                chunk = raw.read(65536)
            except OSError as exc:
                raise UsageError(f"could not read {what} from stdin: {exc.strerror or exc}") from None
            if chunk is None:  # non-blocking and nothing there yet: that is not the end
                time.sleep(0.02)
                continue
            if not chunk:
                return data
            data += chunk
            if len(data) > limit:
                raise UsageError(f"{what} is too long: at most {limit // 1024} KiB")
    except BaseException:
        wipe_bytes(data)
        raise


def _stdin_rest(what: str) -> str:
    """Everything left on stdin, without its final line break: multi-line notes."""
    data = _stdin_bytes(what, _NOTE_LIMIT_BYTES)
    try:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise UsageError(f"{what} is not valid UTF-8 text") from None
    finally:
        wipe_bytes(data)
    for ending in ("\r\n", "\n"):
        if text.endswith(ending):
            return text[: -len(ending)]
    return text


def _check_note_source(args: argparse.Namespace) -> None:
    if args.note is not None and args.note_stdin:
        raise UsageError("the notes come from one place: choose --note or --note-stdin")


def _read_note(ctx: Context, args: argparse.Namespace) -> Optional[str]:
    """The notes from --note, or from the rest of stdin (--note-stdin): read last, after every other line."""
    if args.note_stdin:
        if ctx.typed_stdin:
            # Several lines cannot be typed unseen, and a command that waits without a word looks hung.
            ctx.out.notice(
                "Type the notes: they are shown as you type. Finish with Ctrl-D on a line of its own. "
                "(To keep them off the screen, give this command a file on stdin: ... --note-stdin < FILE)"
            )
        return _stdin_rest("the notes")
    return args.note


def _agent_note(ctx: Context, policy: Optional[str], name: str) -> None:
    if policy == "use":
        ctx.out.info(f"Agents approved by Touch ID may use {_safe(name)} with irondome run, but not see it.")
    elif policy == "reveal":
        ctx.out.info(f"Agents approved by Touch ID may use and see {_safe(name)}.")
    if policy in ("use", "reveal") and sys.platform != "darwin":
        ctx.out.info("Touch ID approval exists on a Mac only. Here an agent reaches it through a grant you create.")


# ---------------------------------------------------------------------------
# add, get, show, ls, find, edit, rm
# ---------------------------------------------------------------------------


def _add(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "adding an entry")
    _require_vault()
    name = validate_name(args.name)
    alias = validate_alias(args.alias) if args.alias is not None else None
    field_names = _field_names(args.field)
    source = _value_source(args) or "prompt"
    totp_source = _totp_source(args)
    _check_value_options(ctx, args, source, totp_source)
    _check_note_source(args)
    settings = config.load()
    bunker = _bunker()
    # An entry that agents may use or see is a standing permission, which outlasts any session: as in edit.
    with _unlocked(
        ctx, f"add {name} to bunker {bunker}", fresh=args.agent in ("use", "reveal")
    ) as vault:
        _skip_password_line(ctx)
        if vault.has_name(name):
            raise UsageError(f"bunker {bunker} already has an entry named {name!r}; change it with: irondome edit")
        if alias is not None and alias in vault.aliases:
            taken = vault.entries[vault.aliases[alias].entry].name
            raise UsageError(f"the alias {alias} is taken: it points at {taken!r}. Choose another")
        # In the order the help gives: the value, the TOTP secret, each --field, the notes (the rest of stdin).
        value, generated = _read_value(ctx, args, source, name, settings)
        totp = _read_totp(ctx, totp_source)
        fields = _read_fields(ctx, args, field_names)
        notes = _read_note(ctx, args) or ""
        entry = vault.add(
            name,
            Secret(password=value, totp=totp, notes=notes, fields=fields),
            username=args.username or "",
            url=args.url or "",
            tags=args.tag or [],
            kind=args.kind,
            agent=args.agent,
        )
        if alias is not None:
            vault.set_alias(alias, entry, "password")
        _commit(vault, settings)
        parts = ("generated" if generated else "", "totp" if totp else "", f"alias {alias}" if alias else "")
        detail = ", ".join(part for part in parts if part)
        ctx.audit(vault, "entry.add", target=entry.name, detail=detail)
        entry_id = entry.id
    tool = _copy(ctx, value, "it") if args.copy else None
    if ctx.out.json_mode:
        document: Dict[str, Any] = {"name": name, "id": entry_id, "generated": generated is not None, "alias": alias}
        if args.show:
            document["value"] = value
        if tool is not None:
            document["clipboard"] = tool
        ctx.out.json(document)
    else:
        if generated is not None:
            ctx.out.info(f"Generated {generated}.")
        if args.show:
            ctx.out.secret(value)
        ctx.out.ok(f"added {_safe(name)} to bunker {bunker}" + (f", with the alias {alias}" if alias else ""))
        _agent_note(ctx, args.agent, name)
    return 0


def _reference(text: str, field: Optional[str]) -> str:
    """A bare reference (``alias``, ``name``, ``name/field``), with *field* appended when given."""
    bare = refs.parse_reference(text)
    if field is None:
        return bare
    return refs.parse_reference(refs.format_reference(bare, field))


def _resolved_field(access: Access, reference: str) -> str:
    if access.grant is not None:
        return access.grant.source(reference)[1]
    if access.vault is None:
        raise IronDomeError("this access is closed")
    return access.vault.resolve(reference)[1]


def _access_reason(ctx: Context, what: str) -> str:
    return f"{what} from bunker {_bunker()}" + (" for an agent" if ctx.agent_mode else "")


def _get(ctx: Context, args: argparse.Namespace) -> int:
    reference = _reference(args.reference, args.field)
    if not _grant_in_use(args):
        _require_vault()
    detail = "irondome get" + (" --copy" if args.copy else "")
    with _accessing(ctx, _access_reason(ctx, f"read {reference}"), references=[reference], detail=detail) as access:
        value = access.value(reference, PURPOSE_REVEAL, detail=detail)
        field = _resolved_field(access, reference)
    tool = _copy(ctx, value, reference) if args.copy else None
    if ctx.out.json_mode:
        document: Dict[str, Any] = {"reference": reference, "field": field, "value": None if args.copy else value}
        if tool is not None:
            document["clipboard"] = tool
        ctx.out.json(document)
    elif tool is None:
        ctx.out.secret(value)
    return 0


def _totp_summary(settings: Any) -> str:
    if not isinstance(settings, dict):
        return "yes"
    label = " ".join(str(part) for part in (settings.get("issuer"), settings.get("account")) if part)
    return (
        f"yes ({_safe(label) + ', ' if label else ''}{settings.get('algorithm')}, {settings.get('digits')} digits "
        f"every {settings.get('period')}s)"
    )


def _show(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "showing an entry")
    _require_vault()
    bunker = _bunker()
    with _unlocked(ctx, f"show {args.name} from bunker {bunker}") as vault:
        entry = vault.find(args.name)
        secret = vault.read_secret(entry)
        aliases = [{"name": alias, "field": vault.aliases[alias].field} for alias in vault.aliases_of(entry)]
        otpauth: Optional[str] = None
        if args.reveal:
            ctx.audit(vault, "entry.reveal", target=entry.name, detail="irondome show --reveal")
            if secret.totp:
                settings = otp.validate(secret.totp)
                named = settings["issuer"] or settings["account"]
                otpauth = otp.to_otpauth(settings, label=None if named else entry.name)
    if ctx.out.json_mode:
        totp_settings = None
        if isinstance(secret.totp, dict):
            totp_settings = {
                key: secret.totp.get(key) for key in ("issuer", "account", "algorithm", "digits", "period")
            }
        ctx.out.json(
            {
                "name": entry.name,
                "id": entry.id,
                "bunker": bunker,
                "kind": entry.kind,
                "username": entry.username,
                "url": entry.url,
                "tags": list(entry.tags),
                "agent": entry.agent,
                "aliases": aliases,
                "has_password": bool(secret.password),
                "password": secret.password if args.reveal else None,
                "has_totp": bool(secret.totp),
                "totp": totp_settings,
                "otpauth": otpauth,
                "has_notes": bool(secret.notes),
                "notes": secret.notes if args.reveal else None,
                "fields": dict(secret.fields) if args.reveal else sorted(secret.fields),
                "history": len(secret.history),
                "created": entry.created,
                "modified": entry.modified,
            }
        )
        return 0
    masked = "******** (show it with --reveal)"
    agents = {"deny": "may not use it", "use": "may use it, not see it", "reveal": "may use and see it"}
    if args.reveal and secret.totp:
        totp_line = otpauth or "-"
    else:
        totp_line = _totp_summary(secret.totp) if secret.totp else "no"
    pairs: List[Tuple[str, str]] = [
        ("name", _safe(entry.name)),
        ("bunker", bunker),
        ("kind", entry.kind),
        ("username", _safe(entry.username) or "-"),
        ("url", _safe(entry.url) or "-"),
        ("tags", _safe(", ".join(entry.tags)) or "-"),
        ("aliases", ", ".join(f"{item['name']} ({_safe(item['field'])})" for item in aliases) or "-"),
        ("agents", agents[entry.agent]),
        ("password", (secret.password if args.reveal else masked) if secret.password else "-"),
        ("totp", totp_line),
    ]
    if args.reveal:
        pairs.extend((f"field {_safe(key)}", value) for key, value in sorted(secret.fields.items()))
    else:
        pairs.append(("fields", ", ".join(_safe(key) for key in sorted(secret.fields)) or "-"))
    pairs.append(("history", f"{_count(len(secret.history), 'earlier password')} kept" if secret.history else "-"))
    pairs.append(("created", format_time(entry.created)))
    pairs.append(("modified", format_time(entry.modified)))
    if not args.reveal:
        lines = len(secret.notes.splitlines()) or 1
        pairs.append(("notes", f"{_count(lines, 'line')}, hidden" if secret.notes else "-"))
    ctx.out.pairs(pairs)
    if args.reveal and secret.notes:
        ctx.out.data("notes:")
        ctx.out.data(secret.notes)
    return 0


def _entry_row(entry: Entry, vault: Vault) -> Dict[str, Any]:
    return {
        "name": entry.name,
        "id": entry.id,
        "kind": entry.kind,
        "username": entry.username,
        "url": entry.url,
        "tags": list(entry.tags),
        "has_totp": entry.has_totp,
        "agent": entry.agent,
        "aliases": vault.aliases_of(entry),
        "created": entry.created,
        "modified": entry.modified,
    }


def _list_grant(ctx: Context, access: Access, query: Optional[str]) -> int:
    grant = access.grant
    if grant is None:
        raise IronDomeError("this access is closed")
    rows = []
    for reference in grant.names():
        if query and query.casefold() not in reference.casefold():
            continue
        entry, field = grant.source(reference)
        rows.append({"reference": reference, "entry": entry, "field": field})
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "bunker": _bunker(),
                "grant": {
                    "id": grant.id,
                    "label": grant.label,
                    "mode": grant.mode,
                    "created": grant.created,
                    "expires": grant.expires,
                    "uses_left": grant.uses_left,
                },
                "references": rows,
            }
        )
        return 0
    uses = "unlimited uses" if grant.uses_left is None else f"{_count(grant.uses_left, 'use')} left"
    ctx.out.info(
        f"grant {grant.id[:8]}: mode {grant.mode}, {uses}, expires in {format_duration(grant.expires - time.time())}. "
        "Listing it used none."
    )
    ctx.out.table(
        ("reference", "kind", "entry", "field"),
        [
            (
                _safe(row["reference"]),
                "totp" if grant.is_totp(row["reference"]) else "value",
                _safe(row["entry"]),
                _safe(row["field"]),
            )
            for row in rows
        ],
    )
    return 0


def _list(ctx: Context, args: argparse.Namespace, query: Optional[str]) -> int:
    if not _grant_in_use(args):
        _require_vault()
    bunker = _bunker()
    with _accessing(ctx, _access_reason(ctx, "list the entries"), consume=False) as access:
        if access.via_grant:
            if args.tag is not None:
                raise UsageError("--tag does not apply to a grant: it covers references, not tagged entries")
            return _list_grant(ctx, access, query)
        vault = access.vault
        if vault is None:
            raise IronDomeError("this access is closed")
        entries = [
            entry for entry in vault.list(tag=args.tag, query=query) if not access.restricted or entry.agent != "deny"
        ]
        rows = [_entry_row(entry, vault) for entry in entries]
    if ctx.out.json_mode:
        ctx.out.json({"bunker": bunker, "entries": rows})
        return 0
    if not rows:
        what = f"matches {query!r}" if query else ("has that tag" if args.tag is not None else "is stored yet")
        ctx.out.info(f"nothing in bunker {bunker} {what}")
        return 0
    ctx.out.table(
        ("name", "username", "url", "tags", "otp", "agent", "modified"),
        [
            (
                _safe(row["name"]),
                _safe(row["username"]),
                _safe(row["url"]),
                _safe(",".join(row["tags"])),
                "yes" if row["has_totp"] else "",
                row["agent"],
                format_time(row["modified"]),
            )
            for row in rows
        ],
    )
    return 0


def _ls(ctx: Context, args: argparse.Namespace) -> int:
    return _list(ctx, args, None)


def _find(ctx: Context, args: argparse.Namespace) -> int:
    if not args.query.strip():
        raise UsageError("give something to search for")
    return _list(ctx, args, args.query)


def _new_tags(ctx: Context, current: List[str], args: argparse.Namespace) -> Optional[List[str]]:
    if args.tag is None and not args.add_tag and not args.rm_tag:
        return None
    tags = list(args.tag) if args.tag is not None else list(current)
    for tag in args.add_tag or []:
        if tag.strip().casefold() not in [existing.casefold() for existing in tags]:
            tags.append(tag)
    for tag in args.rm_tag or []:
        kept = [existing for existing in tags if existing.casefold() != tag.strip().casefold()]
        if len(kept) == len(tags):
            ctx.out.warn(f"there was no tag {_safe(tag)!r} to remove")
        tags = kept
    return tags


def _edit(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "changing an entry")
    _require_vault()
    new_name = validate_name(args.new_name) if args.new_name is not None else None
    field_names = _field_names(args.field)
    removed = list(dict.fromkeys(args.rm_field or []))
    both = sorted(set(field_names) & set(removed))
    if both:
        raise UsageError(f"--field and --rm-field both name {', '.join(both)}")
    source = _value_source(args)
    totp_source = _totp_source(args)
    _check_value_options(ctx, args, source, totp_source)
    _check_note_source(args)
    metadata = {
        "name": new_name,
        "username": args.username,
        "url": args.url,
        "kind": args.kind,
        "agent": args.agent,
    }
    touches_notes = args.note is not None or args.note_stdin
    touches_secret = bool(source or totp_source or touches_notes or field_names or removed)
    touches_tags = args.tag is not None or bool(args.add_tag) or bool(args.rm_tag)
    if not touches_secret and not touches_tags and all(value is None for value in metadata.values()):
        raise UsageError("nothing to change: give at least one option, for example --username or --generate")
    settings = config.load()
    bunker = _bunker()
    # What agents may do with an entry outlasts any session, so a session alone cannot change it.
    with _unlocked(ctx, f"change {args.name} in bunker {bunker}", fresh=args.agent is not None) as vault:
        _skip_password_line(ctx)
        entry = vault.find(args.name)
        changed = [key for key, value in metadata.items() if value is not None]
        tags = _new_tags(ctx, entry.tags, args)
        if tags is not None:
            changed.append("tags")
        secret: Optional[Secret] = None
        value: Optional[str] = None
        generated: Optional[str] = None
        if touches_secret:
            current = vault.read_secret(entry)
            value = current.password
            if source is not None:
                value, generated = _read_value(ctx, args, source, entry.name, settings)
                changed.append("password")
            totp = current.totp
            if totp_source == "--no-totp":
                totp = None
                changed.append("totp")
            elif totp_source is not None:
                totp = _read_totp(ctx, totp_source)
                changed.append("totp")
            new_fields = dict(current.fields)
            for key in removed:
                if key not in new_fields:
                    raise NotFoundError(f"{entry.name!r} has no field named {key!r}")
                del new_fields[key]
            new_fields.update(_read_fields(ctx, args, field_names))
            if field_names or removed:
                changed.append("fields")
            note = _read_note(ctx, args)
            if note is not None:
                changed.append("notes")
            notes = note if note is not None else current.notes
            secret = Secret(password=value, totp=totp, notes=notes, fields=new_fields, history=[])
        updated = vault.update(
            entry,
            secret=secret,
            name=new_name,
            username=args.username,
            url=args.url,
            tags=tags,
            kind=args.kind,
            agent=args.agent,
        )
        _commit(vault, settings)
        ctx.audit(vault, "entry.edit", target=updated.name, detail="changed: " + ", ".join(changed))
        final_name, entry_id = updated.name, updated.id
    tool = _copy(ctx, value, "the new value") if args.copy and value is not None else None
    if ctx.out.json_mode:
        document: Dict[str, Any] = {
            "name": final_name, "id": entry_id, "changed": changed, "generated": generated is not None
        }
        if args.show:
            document["value"] = value
        if tool is not None:
            document["clipboard"] = tool
        ctx.out.json(document)
    else:
        if generated is not None:
            ctx.out.info(f"Generated {generated}; the previous password is kept in the entry's history.")
        if args.show and value is not None:
            ctx.out.secret(value)
        ctx.out.ok(f"updated {_safe(final_name)} in bunker {bunker}: {', '.join(changed)}")
        if args.agent is not None:
            _agent_note(ctx, args.agent, final_name)
    return 0


def _rm(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "removing an entry")
    _require_vault()
    settings = config.load()
    bunker = _bunker()
    with _unlocked(ctx, f"remove {args.name} from bunker {bunker}") as vault:
        entry = vault.find(args.name)
        aliases = vault.aliases_of(entry)
        named = f"alias {aliases[0]}" if len(aliases) == 1 else f"aliases {_joined(aliases)}"
        with_aliases = f" and its {named}" if aliases else ""
        if not ctx.confirm(f"Remove {_safe(entry.name)!r}{with_aliases} from bunker {bunker}?"):
            raise IronDomeError(f"not confirmed; {_safe(entry.name)!r} was not removed")
        vault.remove(entry)
        _commit(vault, settings)
        ctx.audit(vault, "entry.remove", target=entry.name, detail=f"aliases: {', '.join(aliases) or 'none'}")
    _sessions, grants = _capability_counts()
    if ctx.out.json_mode:
        ctx.out.json({"removed": entry.name, "id": entry.id, "aliases": aliases})
    else:
        ctx.out.ok(f"removed {_safe(entry.name)}{with_aliases} from bunker {bunker}")
        if grants:
            ctx.out.info("Grants made earlier keep their own copy of what they named until they expire or are revoked.")
    return 0


# ---------------------------------------------------------------------------
# gen, otp
# ---------------------------------------------------------------------------


def _gen(ctx: Context, args: argparse.Namespace) -> int:
    kinds = [
        flag
        for flag, given in (
            ("--words", args.words is not None),
            ("--username", args.username),
            ("--email-alias", args.email_alias is not None),
        )
        if given
    ]
    if len(kinds) > 1:
        raise UsageError(f"choose one of {', '.join(kinds)}")
    password_only = [
        flag
        for flag, given in (
            ("--no-symbols", args.no_symbols),
            ("--no-digits", args.no_digits),
            ("--no-upper", args.no_upper),
            ("--no-ambiguous", args.no_ambiguous),
        )
        if given
    ]
    if kinds and password_only:
        verb = "applies" if len(password_only) == 1 else "apply"
        raise UsageError(f"{', '.join(password_only)} {verb} only to passwords")
    if args.length is not None and (args.words is not None or args.email_alias is not None):
        raise UsageError("--length applies to passwords and user names")
    bits: Optional[float] = None
    if args.words is not None:
        kind, value = "passphrase", generator.generate_passphrase(args.words)
        bits = generator.passphrase_entropy_bits(args.words)
    elif args.username:
        kind = "username"
        value = generator.generate_username(args.length) if args.length is not None else generator.generate_username()
    elif args.email_alias is not None:
        kind, value = "email-alias", generator.email_alias(args.email_alias)
    else:
        length = args.length if args.length is not None else config.get("password_length")
        kind = "password"
        bits = _password_bits(args, length)
        value = generator.generate_password(
            length,
            upper=not args.no_upper,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
            exclude_ambiguous=args.no_ambiguous,
        )
    if bits is not None:
        ctx.out.info(f"{bits:.0f} bits of entropy ({generator.strength_label(bits)})")
    tool = _copy(ctx, value, f"the {kind}") if args.copy else None
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "kind": kind,
                "value": None if args.copy else value,
                "entropy_bits": None if bits is None else round(bits, 1),
                "clipboard": tool,
            }
        )
    elif tool is None:
        ctx.out.secret(value)
    return 0


def _otp_reference(access: Access, bare: str) -> str:
    """*bare* when it already names a one-time password, else the entry's ``totp`` field."""
    candidate = f"{bare}/totp"
    if access.grant is not None:
        return bare if access.grant.is_totp(bare) else candidate
    if access.vault is None:
        raise IronDomeError("this access is closed")
    return bare if access.vault.resolve(bare)[1] == "totp" else candidate


def _otp_timing(access: Access, reference: str) -> Tuple[Optional[int], Optional[int]]:
    """Seconds left and the period, when the vault itself is open. A grant does not say."""
    if access.vault is None:
        return None, None
    entry, _field = access.vault.resolve(reference)
    settings = otp.validate(access.vault.read_secret(entry).totp)
    return otp.seconds_remaining(settings), settings["period"]


def _otp(ctx: Context, args: argparse.Namespace) -> int:
    bare = refs.parse_reference(args.reference)
    reason = _access_reason(ctx, f"show a one-time code for {bare}")
    detail = "irondome otp" + (" --copy" if args.copy else "")
    looked: Optional[str] = None
    if _grant_in_use(args):
        # Which reference to read depends on what the grant covers; finding out spends nothing.
        with _accessing(ctx, reason, consume=False) as look:
            looked = _otp_reference(look, bare)
    else:
        _require_vault()
    with _accessing(ctx, reason, references=None if looked is None else [looked], detail=detail) as access:
        reference = looked if looked is not None else _otp_reference(access, bare)
        code = access.value(reference, PURPOSE_REVEAL, detail=detail)
        remaining, period = _otp_timing(access, reference)
    tool = _copy(ctx, code, "the code") if args.copy else None
    if ctx.out.json_mode:
        document: Dict[str, Any] = {
            "code": None if args.copy else code,
            "seconds_remaining": remaining,
            "period": period,
        }
        if tool is not None:
            document["clipboard"] = tool
        ctx.out.json(document)
        return 0
    if tool is None:
        ctx.out.secret(code)
    if remaining is not None:
        ctx.out.info(f"valid for {_count(remaining, 'more second')}")
    return 0


# ---------------------------------------------------------------------------
# passwd, recovery, auth
# ---------------------------------------------------------------------------


def _passwd(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "changing the master password")
    _require_vault()
    bunker = _bunker()
    if not any(slot.kind == KIND_PASSWORD for slot in VaultFile.load().slots):
        raise UsageError(
            f"the vault of bunker {bunker} has no master password: it opens with Touch ID and the recovery key. "
            "Add one with: irondome auth password"
        )
    with _unlocked(ctx, f"change the master password of bunker {bunker}", fresh=True) as vault:
        old = vault.slots(KIND_PASSWORD)
        password = ctx.new_master_password()
        created: List[Keyslot] = []
        try:
            for slot in old:
                backend = devices.get_backend(str(slot.backend_name)) if slot.device is not None else None
                created.append(
                    _new_password_slot(
                        vault, password, backend=backend, policy=slot.policy or POLICY_DEVICE,
                        label=slot.label or "master password", params=_params_of([slot]),
                    )
                )
        except BaseException:
            _destroy_devices(created)
            raise
        finally:
            password.wipe()
        # The snapshots open with the old password, and the sessions were opened with it: both go before the
        # new keyslots are written, so that no interruption leaves either behind.
        purged, ended = _replace_slots(ctx, vault, remove=old, add=created, purge=True, end_sessions=True)
        ctx.audit(
            vault, "keyslot.passwd",
            detail=f"{_count(len(created), 'keyslot')} replaced, {_count(purged, 'snapshot')} purged, "
            f"{_count(ended, 'session')} ended",
        )
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "changed": True,
                "bunker": bunker,
                "keyslots": len(created),
                "snapshots_purged": purged,
                "sessions_ended": ended,
            }
        )
    else:
        ctx.out.ok(f"changed the master password of bunker {bunker}")
        if purged:
            opened = "it opened" if purged == 1 else "they opened"
            ctx.out.info(f"{_count(purged, 'snapshot')} deleted: {opened} with the old password.")
        if ended:
            ctx.out.info(f"{_count(ended, 'session')} ended. Start a new one with: irondome unlock")
    return 0


def _rekey_question(bunker: str) -> str:
    return (
        f"The vault of bunker {bunker} is re-keyed for this: every entry is re-encrypted under a new vault key, "
        "every session and grant ends, the snapshots are deleted and the audit log is archived."
    )


def _recovery_new(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "changing the recovery key")
    _require_vault()
    bunker = _bunker()
    report: Optional[Dict[str, Any]] = None
    printed: List[str] = []

    def show_at_switch(recovery: List[str]) -> None:
        # The re-key's new recovery key is the only one that opens the vault from its switch on: printed then,
        # before what a crash could stop. With --json it is in the one document below (see cmd_admin.cmd_rekey).
        if not ctx.out.json_mode:
            for each in recovery:
                _print_recovery_key(ctx, each, bunker)
                printed.append(each)

    with _open_with_password(ctx, f"make a new recovery key for bunker {bunker}") as (vault, password):
        old = vault.slots(KIND_RECOVERY)
        if old and ctx.has_terminal and not ctx.confirm(f"Make a new recovery key? {_rekey_question(bunker)}"):
            raise IronDomeError("not confirmed; nothing was changed")
        with _CarriedThrough(ctx):  # from here the new key is put in place and shown, whatever comes
            if old:
                # Taking the old keyslot out retires nothing: it has no device key, and its recovery key goes on
                # giving the vault key to whoever kept a copy of the slot. A new vault key retires it; the
                # keyslot kept below is made anew with a new recovery key.
                for extra in old[1:]:
                    vault.remove_slot(extra.id)
                report, shown = _rekey_vault(
                    ctx, vault, password, action="keyslot.recovery-new",
                    detail=f"re-keyed to replace {_count(len(old), 'recovery key')}",
                    on_switch=show_at_switch,
                )
                key = shown[0]
            else:
                slot, key = keys.create_recovery_slot(vault.vault_key, vault.vault_id, label="recovery key")
                _replace_slots(ctx, vault, remove=[], add=[slot])
                ctx.audit(vault, "keyslot.recovery-new", target=slot.id, detail="added; there was none")
            if ctx.out.json_mode:
                ctx.out.json({"bunker": bunker, "recovery_key": key, "replaced": len(old), "rekey": report})
            elif report is None:
                ctx.out.ok(f"made a recovery key for bunker {bunker}")
            else:
                ctx.out.ok(
                    f"made a new recovery key for bunker {bunker} and re-keyed its vault: the old recovery key "
                    "opens neither the vault as it is now nor anything stored in it later"
                )
            if report is not None:
                _say_rekeyed(ctx, report)  # on stderr, with --json as well
            if not ctx.out.json_mode and key not in printed:
                _print_recovery_key(ctx, key, bunker)
    if not ctx.out.json_mode:
        _wait_until_kept(ctx)
    return 1 if report is not None and report["leftovers"] else 0


def _recovery_remove(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "removing the recovery key")
    _require_vault()
    bunker = _bunker()

    def check(slots: Sequence[Keyslot]) -> None:
        if not any(slot.kind == KIND_RECOVERY for slot in slots):
            raise NotFoundError(f"the vault of bunker {bunker} has no recovery key")
        if not any(slot.kind == KIND_PASSWORD for slot in slots):
            raise UsageError(
                "this vault opens with Touch ID alone, and the recovery key is its only other way in. "
                "Set a master password first (irondome auth password), or keep the recovery key"
            )

    check(VaultFile.load().slots)  # before anything is asked for
    with _open_with_password(ctx, f"remove the recovery key of bunker {bunker}") as (vault, password):
        check(vault.file.slots)
        old = vault.slots(KIND_RECOVERY)
        if not ctx.confirm(
            f"Remove the recovery key of bunker {bunker}? Without it, losing this machine or its security chip "
            f"means losing the vault. {_rekey_question(bunker)}"
        ):
            raise IronDomeError("not confirmed; the recovery key was kept")
        with _CarriedThrough(ctx):
            # As for recovery new: only a new vault key retires the old recovery key.
            for slot in old:
                vault.remove_slot(slot.id)
            report, _none = _rekey_vault(
                ctx, vault, password, action="keyslot.recovery-remove",
                detail=f"re-keyed to remove {_count(len(old), 'recovery key')}",
            )
    if ctx.out.json_mode:
        ctx.out.json({"bunker": bunker, "removed": len(old), "rekey": report})
    else:
        ctx.out.ok(
            f"removed the recovery key of bunker {bunker} and re-keyed its vault: the old recovery key opens "
            "neither the vault as it is now nor anything stored in it later"
        )
    _say_rekeyed(ctx, report)  # on stderr, with --json as well
    if all(slot["backend"] for slot in report["keyslots"]):
        ctx.out.warn("this vault now opens only on this machine: losing it, or its security chip, loses the vault")
    return 1 if report["leftovers"] else 0


def _device_key_here(slot: Keyslot) -> bool:
    """True when *slot*'s device key is on this machine and its backend can be asked about it now."""
    if slot.device is None:
        return False
    try:
        return bool(devices.get_backend(str(slot.backend_name)).exists(slot.device))
    except Exception:  # an unknown backend, a chip that does not answer: not something to destroy here
        return False


def _recovery_use(ctx: Context, args: argparse.Namespace) -> int:
    """Open the vault with its recovery key and give it a master password that works on this machine.

    This is what the recovery key is for: the machine, its security chip or the device key file is
    gone, or the master password is forgotten. Every keyslot that needs a device key is replaced by
    one new password keyslot on this machine; the recovery keyslot stays as it is.
    """
    if ctx.agent_mode:
        raise PolicyError(
            "opening the vault with its recovery key is for the vault's owner: run it at a terminal, or pipe the "
            "recovery key and the new master password with --password-stdin"
        )
    _require_vault()
    bunker = _bunker()
    _finish_retirement(ctx)
    file = VaultFile.load()
    if not any(slot.kind == KIND_RECOVERY for slot in file.slots):
        raise NotFoundError(
            f"the vault of bunker {bunker} has no recovery key: it was made with --no-recovery, or the key was removed"
        )
    backend = _choose_backend(POLICY_DEVICE)  # before anything is asked for
    typed = ctx.read_secret("Recovery key: ")
    if typed is None:
        raise AuthError("the recovery key cannot be empty")
    text = ""
    try:
        text = bytes(typed.view()).decode("utf-8", "replace").strip()
        with _naming_the_bunker():
            key = unlock(file, recovery_key=text)
    finally:
        typed.wipe()
        _wipe_str(text)
    with Vault(file, key) as vault:
        old = vault.slots(KIND_PASSWORD) + vault.slots(KIND_DEVICE)
        touch = sum(1 for slot in old if slot.kind == KIND_DEVICE or slot.policy not in (None, POLICY_DEVICE))
        password = ctx.new_master_password()
        try:
            slot = _new_password_slot(
                vault, password, backend=backend, policy=POLICY_DEVICE, label="master password",
                params=_params_of(old),
            )
        except LockedOutError as exc:
            # Found by using it: a TPM in lockout takes no new keyslot either, so the recovery key seemed
            # useless exactly when wrong guesses had locked the owner out. A file-based device key is the
            # way in until the chip answers again; nothing was changed by this attempt.
            raise LockedOutError(
                f"{exc}\nThe security chip will not take a new keyslot until then, and nothing was changed. To get "
                f"in now, keep the new device key in a file instead: {devices.ENV_BACKEND}=software irondome "
                "recovery use (irondome rekey moves the vault back onto the chip afterwards)"
            ) from None
        finally:
            password.wipe()
        # An old keyslot's device key is destroyed where it is on this machine, as passwd does. Where it is
        # not (another machine's, a dead chip's), the keyslot just goes: there is nothing here to destroy.
        here = [each for each in old if _device_key_here(each)]
        gone = [each for each in old if each not in here]
        # As for passwd: the snapshots and the sessions belong to the keyslots that go.
        purged, ended = _replace_slots(
            ctx, vault, remove=here, add=[slot], purge=True, end_sessions=True, forget=gone
        )
        ctx.audit(
            vault, "keyslot.recovery-use", target=slot.id,
            detail=f"opened with the recovery key; {_count(len(old), 'keyslot')} replaced, "
            f"{_count(purged, 'snapshot')} purged, {_count(ended, 'session')} ended",
        )
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "bunker": bunker,
                "recovered": True,
                "backend": backend.name,
                "replaced": len(old),
                "device_keys_destroyed": len(here),
                "snapshots_purged": purged,
                "sessions_ended": ended,
            }
        )
        return 0
    ctx.out.ok(
        f"bunker {bunker} opened with its recovery key. It now opens with the new master password on this "
        f"machine ({_backend_phrase(backend)})"
    )
    if old:
        ctx.out.info(
            f"{_count(len(old), 'old keyslot')} removed: the old master password and device key open nothing in "
            "this vault file any more."
        )
    if here:
        ctx.out.info(
            f"{_count(len(here), 'old device key')} was on this machine and was destroyed: any other copy of "
            "this vault here that still used it now opens only with the recovery key."
            if len(here) == 1
            else f"{_count(len(here), 'old device key')} were on this machine and were destroyed: any other copy "
            "of this vault here that still used them now opens only with the recovery key."
        )
    if gone:
        ctx.out.info(
            f"The device key of {_count(len(gone), 'old keyslot')} is not on this machine, or cannot be reached "
            "from it, and was left alone: where it still exists, the old master password still opens old copies "
            "of the vault file."
        )
    if touch:
        ctx.out.info("Touch ID is no longer enrolled. Enrol again with: irondome auth touchid")
    if os.environ.get(devices.ENV_BACKEND) == "software":
        ctx.out.info(
            f"The new device key is a file, because {devices.ENV_BACKEND}=software was set. To move the vault onto "
            "a security chip once it is usable: irondome rekey, without that variable"
        )
    ctx.out.warn(
        "the recovery key you typed still opens this vault and every copy of it. If anyone else may have seen "
        "it, replace it with: irondome recovery new"
    )
    return 0


def _auth_show(ctx: Context, args: argparse.Namespace) -> int:
    _require_vault()
    file = VaultFile.load()
    mode = _mode_of(file.slots)
    slots = [_slot_info(slot) for slot in file.slots]
    if ctx.out.json_mode:
        ctx.out.json({"bunker": _bunker(), "mode": mode, "keyslots": slots})
        return 0
    ctx.out.info(f"bunker {_bunker()} opens with: {_MODE_PHRASES.get(mode, mode)}")
    present = {True: "present", False: "MISSING", None: "-"}
    ctx.out.table(
        ("kind", "opens with", "device key", "created", "id"),
        [
            (
                str(info["kind"]),
                _safe(info["describe"]),
                "DAMAGED" if info.get("device_fault") else present[info["device_present"]],
                format_time(info["created"]),
                str(info["id"])[:8],
            )
            for info in slots
        ],
    )
    return 0


def _auth_touchid(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "enrolling Touch ID")
    _require_vault()
    if ctx.no_touch:
        raise UsageError("--no-touch forbids the Touch ID prompt that enrolling needs")
    backend = _choose_backend(POLICY_BIOMETRY)
    bunker = _bunker()
    reason = f"enrol Touch ID for bunker {bunker}"
    if args.require_password:
        with _open_keeping_password(ctx, reason) as (vault, password):
            replaced = vault.slots(KIND_PASSWORD) + vault.slots(KIND_DEVICE)
            ctx.out.info("Touch the sensor to enrol your fingerprint.")
            slot = _new_password_slot(
                vault, password, backend=backend, policy=POLICY_BIOMETRY, label="master password + Touch ID",
                params=_params_of(replaced),
            )
            _replace_slots(ctx, vault, remove=replaced, add=[slot])
            ctx.audit(vault, "keyslot.touchid", target=slot.id, detail=f"require password; {len(replaced)} replaced")
        mode = MODE_TOUCHID_PASSWORD
    else:
        with _unlocked(ctx, reason, fresh=True) as vault:
            replaced = vault.slots(KIND_DEVICE)
            ctx.out.info("Touch the sensor to enrol your fingerprint.")
            slot = keys.create_device_slot(
                vault.vault_key, vault.vault_id, backend=backend, policy=POLICY_BIOMETRY, label="Touch ID"
            )
            _replace_slots(ctx, vault, remove=replaced, add=[slot])
            ctx.audit(vault, "keyslot.touchid", target=slot.id, detail=f"Touch ID alone; {len(replaced)} replaced")
            mode = _mode_of(vault.file.slots)
    if ctx.out.json_mode:
        ctx.out.json({"bunker": bunker, "mode": mode, "backend": backend.name, "replaced": len(replaced)})
    else:
        ctx.out.ok(f"bunker {bunker} now opens with: {_MODE_PHRASES.get(mode, mode)}")
    return 0


def _auth_password(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "changing how the vault opens")
    _require_vault()
    bunker = _bunker()
    file = VaultFile.load()
    touch_slots = [slot for slot in file.slots if slot.kind == KIND_DEVICE]
    passwords = [slot for slot in file.slots if slot.kind == KIND_PASSWORD]
    plain = [slot for slot in passwords if slot.policy in (None, POLICY_DEVICE)]
    if passwords and not touch_slots and len(plain) == len(passwords):
        if ctx.out.json_mode:
            ctx.out.json({"bunker": bunker, "mode": MODE_PASSWORD, "changed": False, "replaced": 0})
        else:
            ctx.out.info(f"bunker {bunker} already opens with the master password and the device key; nothing changed")
        return 0
    reason = f"switch bunker {bunker} back to the master password"
    if plain:
        keep = {slot.id for slot in plain}
        with _unlocked(ctx, reason, fresh=True) as vault:
            replaced = [
                slot
                for slot in vault.file.slots
                if slot.kind == KIND_DEVICE or (slot.kind == KIND_PASSWORD and slot.id not in keep)
            ]
            _replace_slots(ctx, vault, remove=replaced, add=[])
            ctx.audit(vault, "keyslot.password", detail=f"{_count(len(replaced), 'Touch ID keyslot')} removed")
    else:
        backend = _choose_backend(POLICY_DEVICE)
        with _open_keeping_password(ctx, reason) as (vault, password):
            replaced = vault.slots(KIND_PASSWORD) + vault.slots(KIND_DEVICE)
            slot = _new_password_slot(
                vault, password, backend=backend, policy=POLICY_DEVICE, label="master password",
                params=_params_of(replaced),
            )
            _replace_slots(ctx, vault, remove=replaced, add=[slot])
            ctx.audit(vault, "keyslot.password", target=slot.id, detail=f"{_count(len(replaced), 'keyslot')} replaced")
    if ctx.out.json_mode:
        ctx.out.json({"bunker": bunker, "mode": MODE_PASSWORD, "changed": True, "replaced": len(replaced)})
    else:
        ctx.out.ok(f"bunker {bunker} now opens with: {_MODE_PHRASES[MODE_PASSWORD]}; Touch ID keys were destroyed")
    return 0


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def _config_ls(ctx: Context, args: argparse.Namespace) -> int:
    values = config.load()
    rows = [
        {
            "key": key,
            "value": values[key],
            "default": setting.default,
            "minimum": setting.minimum,
            "maximum": setting.maximum,
            "help": setting.help,
        }
        for key, setting in sorted(config.SETTINGS.items())
    ]
    if ctx.out.json_mode:
        ctx.out.json({"bunker": _bunker(), "settings": rows})
        return 0
    note = "" if vault_exists() else " (it has no vault yet: these are the defaults)"
    ctx.out.info(f"settings of bunker {_bunker()}{note}")
    ctx.out.table(
        ("key", "value", "default", "range", "meaning"),
        [
            (
                str(row["key"]),
                str(row["value"]),
                str(row["default"]),
                f"{row['minimum']}-{row['maximum']}",
                str(row["help"]),
            )
            for row in rows
        ],
    )
    return 0


def _config_get(ctx: Context, args: argparse.Namespace) -> int:
    value = config.get(args.key)
    if ctx.out.json_mode:
        ctx.out.json({"key": args.key, "value": value, "default": config.SETTINGS[args.key].default})
    else:
        ctx.out.data(str(value))
    return 0


def _config_set(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "changing a setting")
    _require_vault()
    config.get(args.key)  # an unknown setting is refused before anything is asked for
    bunker = _bunker()
    # The settings file itself is not authenticated, but changing it through IronDome takes the owner:
    # grant_ttl and session_ttl decide how long the next grants and sessions live.
    with _unlocked(ctx, f"change a setting of bunker {bunker}") as vault:
        value = config.set_value(args.key, args.value)
        ctx.audit(vault, "config.set", target=args.key, detail=str(value))
    if ctx.out.json_mode:
        ctx.out.json({"key": args.key, "value": value})
    else:
        ctx.out.ok(f"{args.key} = {value} in bunker {bunker}")
    return 0


def _config_reset(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "changing a setting")
    _require_vault()
    keys_given = list(args.keys)
    for key in keys_given:
        config.get(key)
    bunker = _bunker()
    with _unlocked(ctx, f"reset settings of bunker {bunker}") as vault:
        config.reset(keys_given)
        ctx.audit(vault, "config.reset", target=", ".join(keys_given) or "all")
    values = config.load()
    if ctx.out.json_mode:
        ctx.out.json({"reset": keys_given or sorted(config.SETTINGS), "values": values})
    else:
        named = ", ".join(keys_given) if keys_given else "every setting"
        ctx.out.ok(f"{named} back to the default in bunker {bunker}")
    return 0


# ---------------------------------------------------------------------------
# bunker
# ---------------------------------------------------------------------------


def _bunker_source(args: argparse.Namespace) -> Tuple[str, str]:
    """Why this bunker was chosen, as irondome.cli.main.select_bunker recorded it: (source, explanation)."""
    source = getattr(args, "bunker_source", None)
    if source is None:  # not chosen by select_bunker: only the environment can have named it
        source = "environment" if os.environ.get(paths.ENV_BUNKER) else "default"
    if source == "flag":
        return "flag", "chosen with --bunker"
    if source == "environment":
        return "environment", f"{paths.ENV_BUNKER} is set"
    if source == "token":
        return "token", f"the token in {getattr(args, 'bunker_token', ENV_GRANT)} belongs to it"
    return "default", "the default bunker (change it with: irondome bunker use NAME)"


def _bunker_info(name: str, current: str, default: str) -> Dict[str, Any]:
    with _in_bunker(name):
        path = paths.vault_file()
        info: Dict[str, Any] = {
            "name": name,
            "vault": vault_exists(),
            "path": str(path),
            "mode": None,
            "device": [],
            "hardware": None,
            "sessions": None,
            "grants": None,
            "current": name == current,
            "default": name == default,
            "error": None,
        }
        if info["vault"]:
            try:
                file = VaultFile.load()
            except VaultError as exc:
                info["error"] = str(exc)
            else:
                info["mode"] = _mode_of(file.slots)
                info["device"] = _devices_of(file.slots)
                info["hardware"] = all(item["hardware"] is True for item in info["device"]) if info["device"] else None
        info["sessions"], info["grants"] = _capability_counts()
    return info


def _bunker_ls(ctx: Context, args: argparse.Namespace) -> int:
    current = _bunker()
    default = paths.default_bunker()
    names = sorted(set(paths.bunkers()) | {current, default})
    rows = [_bunker_info(name, current, default) for name in names]
    if ctx.out.json_mode:
        ctx.out.json({"bunkers": rows})
        return 0

    def count(value: Optional[int]) -> str:
        return "?" if value is None else str(value)

    ctx.out.table(
        ("name", "vault", "device key", "hardware", "sessions", "grants", "note"),
        [
            (
                row["name"],
                "damaged" if row["error"] else ("yes" if row["vault"] else "no"),
                ", ".join(item["backend"] for item in row["device"]) or "-",
                {True: "yes", False: "no", None: "-"}[row["hardware"]],
                count(row["sessions"]),
                count(row["grants"]),
                ", ".join(label for label, flag in (("current", row["current"]), ("default", row["default"])) if flag),
            )
            for row in rows
        ],
    )
    return 0


def _bunker_use(ctx: Context, args: argparse.Namespace) -> int:
    name = paths.validate_bunker_name(args.name)
    _require_owner(ctx, "changing the default bunker")
    with _in_bunker(name):
        if not vault_exists():
            raise NotFoundError(f"there is no vault in bunker {name}. Create it first with: {_create_hint(name)}")
    # It unlocks nothing, and every command that names no bunker goes where the default points.
    ctx.prove_owner(f"making bunker {name} the default", bunker=name)
    try:
        before: Optional[str] = paths.default_bunker()
    except UsageError:
        before = None  # an unreadable setting is replaced
    changed = before != name
    if changed and not ctx.password_stdin:
        # prove_owner lets through whatever runs at a terminal, an agent that inherited the owner's included,
        # so the person is asked. `bunker use` has no --yes: nothing skips this question.
        answer = ctx.ask(f"Make bunker {name} the default, for every command that names no bunker? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            raise IronDomeError("not confirmed; the default bunker was not changed")
    if changed:
        paths.set_default_bunker(name)
    source, _explanation = _bunker_source(args)
    overridden = os.environ.get(paths.ENV_BUNKER) if source == "environment" else None
    if ctx.out.json_mode:
        ctx.out.json({"default": name, "changed": changed, "overridden_by_environment": overridden})
    elif changed:
        ctx.out.ok(f"bunker {name} is now the default")
    else:
        ctx.out.info(f"bunker {name} is the default already; nothing changed")
    if overridden is not None and overridden != name:
        ctx.out.warn(
            f"{paths.ENV_BUNKER}={overridden} is set here and wins over the default; unset it to work on {name}"
        )
    return 0


def _bunker_current(ctx: Context, args: argparse.Namespace) -> int:
    name = _bunker()
    source, explanation = _bunker_source(args)
    if ctx.out.json_mode:
        ctx.out.json({"name": name, "source": source, "reason": explanation, "vault": vault_exists()})
        return 0
    ctx.out.data(name)
    ctx.out.info(explanation + ("" if vault_exists() else f"; it has no vault yet ({_create_hint(name)})"))
    return 0


def _print_plan(ctx: Context, plan: Any, name: str) -> None:
    ctx.out.info(f"Removing bunker {name} destroys:")
    if plan.device_keys:
        for key in plan.device_keys:
            where = "a security chip" if key.hardware else "a file, not hardware"
            ctx.out.info(f"  device key  {key.backend} ({where}), {'present' if key.present else 'already gone'}")
    else:
        ctx.out.info("  device key  none found")
    ctx.out.info(f"  files       {len(plan.files)}: everything IronDome keeps for this bunker")
    ctx.out.info(f"  sessions and grants  {plan.capabilities}")
    for path in plan.foreign:
        ctx.out.info(f"  left alone (not IronDome's)  {path}")
    if plan.unreadable_vaults:
        ctx.out.warn(
            f"the vault of bunker {name} cannot be read; its device keys are found in the device directory instead"
        )
    if name in plan.recovery_bunkers:
        ctx.out.warn(
            f"bunker {name} has a recovery key. It is out of reach from here: a copy of this vault that survives "
            "somewhere still opens with it."
        )


def _default_after_removal(removed: str) -> Optional[str]:
    """If *removed* was the default, make another bunker the default; returns the new default, if it changed.

    With no bunker left, the setting is removed: the default is then alpha, as on a new machine.
    """
    try:
        recorded = paths.default_bunker()
    except UsageError:
        recorded = removed  # an unreadable setting is replaced as well
    if recorded != removed:
        return None
    remaining = [name for name in paths.bunkers() if name != removed]
    with_vault = [name for name in remaining if _has_vault(name)]
    preferred = [name for name in (paths.FIRST_BUNKER,) if name in with_vault] + with_vault + remaining
    if preferred:
        paths.set_default_bunker(preferred[0])
        return preferred[0]
    paths.clear_default_bunker()
    return None if removed == paths.FIRST_BUNKER else paths.FIRST_BUNKER


def _bunker_rm(ctx: Context, args: argparse.Namespace) -> int:
    from irondome import nuke

    name = paths.validate_bunker_name(args.name)
    _require_owner(ctx, "removing a bunker")
    if args.yes and not ctx.password_stdin:
        raise UsageError(
            f"-y skips the question only together with --password-stdin and bunker {name}'s master password: an "
            "agent can pass -y, it cannot pass your password. At a terminal, leave out -y and answer the question. "
            "Nothing was removed."
        )
    plan = nuke.plan(bunker=name)
    if not plan.bunkers:
        raise NotFoundError(f"there is no bunker named {name} on this machine")
    _print_plan(ctx, plan, name)
    if not args.yes and not ctx.has_terminal:
        raise UsageError(
            f"removing bunker {name} cannot be undone: confirm it by typing its name at a terminal, or pass --yes "
            "with --password-stdin and its master password. Nothing was removed."
        )
    if ctx.password_stdin:
        # It unlocks nothing, so the password must prove the owner: --yes alone is a flag any agent can pass.
        ctx.prove_owner(f"removing bunker {name}", bunker=name)
    if not args.yes and not ctx.confirm_phrase(f"This destroys bunker {name} for good.", name):
        raise IronDomeError(f"the name did not match; bunker {name} was not touched")
    report = nuke.execute(bunker=name)
    new_default = _default_after_removal(name)
    survives = name in report.recovery_bunkers
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "bunker": name,
                "success": report.success,
                "device_keys_destroyed": report.device_keys_destroyed,
                "hardware_backed": report.hardware_backed,
                "files_deleted": report.files_deleted,
                "leftovers": report.leftovers,
                "foreign": report.foreign,
                "errors": report.errors,
                "recovery_key_survives": survives,
                "default": new_default,
            }
        )
    else:
        held = "held by a security chip" if report.hardware_backed else "not hardware-held"
        summary = (
            f"{_count(report.device_keys_destroyed, 'device key')} destroyed ({held}), "
            f"{_count(len(report.files_deleted), 'file')} deleted"
        )
        if report.success:
            ctx.out.ok(f"bunker {name} is gone: {summary}")
        else:
            ctx.out.warn(f"bunker {name} was only partly removed: {summary}")
        for path in report.leftovers:
            ctx.out.warn(f"still there: {path}")
        for problem in report.errors:
            ctx.out.error(problem)
        for path in report.foreign:
            ctx.out.info(f"left alone (not IronDome's): {path}")
        if survives:
            ctx.out.warn(f"the recovery key of bunker {name} still opens any copy of its vault that survives elsewhere")
        if new_default is not None:
            ctx.out.info(f"The default bunker is now {new_default}.")
    return 0 if report.success else 1


# ---------------------------------------------------------------------------
# The parsers
# ---------------------------------------------------------------------------


class _HelpFormatter(argparse.HelpFormatter):
    """argparse's own layout, except that a text with line breaks of its own keeps them.

    The description is one paragraph, wrapped to the terminal as usual. The epilog (the examples,
    and for list commands the shape of their --json document) is laid out by hand, so that an
    example is never broken across lines and can be copied as it stands.
    """

    def _fill_text(self, text: str, width: int, indent: str) -> str:
        if "\n" in text:
            return "".join(indent + line for line in text.splitlines(keepends=True))
        return super()._fill_text(text, width, indent)


#: An example: the command line, and what it does.
Example = Tuple[str, str]


def _epilog(examples: Sequence[Example], *paragraphs: str) -> str:
    """The examples, one per line and aligned, then *paragraphs* exactly as written."""
    width = max(len(command) for command, _what in examples) + 3
    lines = ["examples:"] + [f"  {command.ljust(width)}{what}".rstrip() for command, what in examples]
    return "\n\n".join(["\n".join(lines), *paragraphs])


def _command(
    subparsers: Any,
    common: argparse.ArgumentParser,
    name: str,
    handler: Handler,
    help_text: str,
    description: str,
    examples: Sequence[Example],
    *paragraphs: str,
) -> argparse.ArgumentParser:
    parser: argparse.ArgumentParser = subparsers.add_parser(
        name, parents=[common], help=help_text, description=description, epilog=_epilog(examples, *paragraphs),
        formatter_class=_HelpFormatter,
    )
    parser.set_defaults(handler=handler)
    return parser


def _group(
    subparsers: Any,
    common: argparse.ArgumentParser,
    name: str,
    dest: str,
    help_text: str,
    description: str,
    examples: Sequence[Example],
) -> Any:
    """A command made of actions (``recovery new``); argparse refuses it without one."""
    parser: argparse.ArgumentParser = subparsers.add_parser(
        name, parents=[common], help=help_text, description=description, epilog=_epilog(examples),
        formatter_class=_HelpFormatter,
    )
    return parser.add_subparsers(
        dest=dest, metavar="<subcommand>", parser_class=type(parser), required=True,
        help="what to do; each has --help"
    )


_JSON_ENTRIES = """\
json (--json):
  {"bunker": NAME, "entries": [ENTRY, ...]}
  ENTRY: name, id, kind, username, url, tags, has_totp, agent, aliases,
         created, modified
  under a grant (IRONDOME_GRANT set):
  {"bunker": NAME, "grant": GRANT, "references": [REFERENCE, ...]}
  GRANT: id, label, mode, created, expires, uses_left
  REFERENCE: reference, entry, field"""

_JSON_BUNKERS = """\
json (--json):
  {"bunkers": [BUNKER, ...]}
  BUNKER: name, vault, path, mode, device, hardware, sessions, grants,
          current, default, error"""

_JSON_SETTINGS = """\
json (--json):
  {"bunker": NAME, "settings": [SETTING, ...]}
  SETTING: key, value, default, minimum, maximum, help"""

_JSON_KEYSLOTS = """\
json (--json):
  {"bunker": NAME, "mode": MODE, "keyslots": [KEYSLOT, ...]}
  KEYSLOT: id, kind, label, describe, created, backend, policy, hardware,
           device_present, device_fault (why a device key file that is
           there cannot be the key, or null), kdf (the Argon2id cost of a
           password keyslot)"""


def _add_setup_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mode",
        choices=MODES,
        default=None,
        help="how the vault opens: password (default), touchid (Touch ID, password as fallback), "
        "touchid+password (both every time)",
    )
    parser.add_argument(
        "--no-recovery", action="store_true", help="make no recovery key (losing this machine then loses the vault)"
    )
    parser.add_argument(
        "--no-password",
        action="store_true",
        help="with --mode touchid: no master password; the recovery key is the fallback",
    )
    parser.add_argument(
        "--kdf-memory-mib", type=int, metavar="N", default=None,
        help="memory for Argon2id, in MiB (default 256, less on small machines; at least 19)",
    )


def _add_entry_options(parser: argparse.ArgumentParser, *, editing: bool) -> None:
    group = parser.add_argument_group("entry details")
    if editing:
        group.add_argument("--name", dest="new_name", metavar="NEW", help="rename the entry (its aliases follow it)")
    group.add_argument("--username", metavar="U", help="the user name or account")
    group.add_argument("--url", metavar="URL", help="where it is used")
    group.add_argument(
        "--tag", action="append", metavar="T",
        help="a tag; repeat for several" + ("; replaces the tag list (--tag '' clears it)" if editing else ""),
    )
    if editing:
        group.add_argument("--add-tag", action="append", metavar="T", help="add a tag, keeping the others")
        group.add_argument("--rm-tag", action="append", metavar="T", help="remove a tag")
    group.add_argument(
        "--note", metavar="TEXT",
        help="notes kept with the secret; typed here, they are in your shell history and, while the command runs, "
        "the process list (use --note-stdin for anything private)",
    )
    group.add_argument(
        "--note-stdin", action="store_true",
        help="read the notes from the rest of stdin, after every other line, so they can run over several lines "
        "(typed at a terminal they are shown; finish with Ctrl-D)",
    )
    group.add_argument(
        "--kind", choices=_KINDS, default=None if editing else "login", help="login (default) or secret (an API key)"
    )
    group.add_argument(
        "--agent", choices=AGENT_POLICIES, default=None if editing else "deny",
        help="what agents approved by Touch ID may do: deny (default), use (inject only) or reveal",
    )
    group.add_argument(
        "--field", action="append", metavar="NAME",
        help="a custom field, by name only; its value is asked for at a hidden prompt, or read from stdin, one line "
        "per --field, when stdin carries the other input; repeat for several",
    )
    if editing:
        group.add_argument("--rm-field", action="append", metavar="KEY", help="remove a custom field")


def _add_value_options(parser: argparse.ArgumentParser, *, editing: bool) -> None:
    kept = "; leave all out to keep the current value)" if editing else "; default: a hidden prompt)"
    group = parser.add_argument_group("the value (one source" + kept)
    group.add_argument("--generate", action="store_true", help="generate a random password")
    group.add_argument("--length", type=int, metavar="N", help="with --generate: its length (default: password_length)")
    group.add_argument("--no-symbols", action="store_true", help="with --generate: no symbols")
    group.add_argument("--no-digits", action="store_true", help="with --generate: no digits")
    group.add_argument("--no-upper", action="store_true", help="with --generate: no capital letters")
    group.add_argument(
        "--no-ambiguous", action="store_true", help="with --generate: leave out look-alikes such as 0, O, 1, l"
    )
    group.add_argument("--words", type=int, metavar="N", help="generate a passphrase of N words instead")
    group.add_argument(
        "--value-stdin", action="store_true",
        help="read the value from stdin: piped in and last there, all of it (several lines exactly, one line "
        "without the line breaks after it); one line when --totp-stdin, --field or --note-stdin follow; typed at "
        "a hidden prompt when stdin is a terminal; never empty",
    )
    if editing:
        group.add_argument("--prompt-value", action="store_true", help="type the new value at a hidden prompt")
    group.add_argument("--show", action="store_true", help="print the generated value on stdout")
    group.add_argument("-c", "--copy", action="store_true", help="copy the generated value to the clipboard")
    totp = parser.add_argument_group("one-time passwords")
    totp.add_argument(
        "--totp", action="store_true", help="type a TOTP secret (base32 or otpauth://) at a hidden prompt"
    )
    totp.add_argument(
        "--totp-stdin", action="store_true",
        help="read the TOTP secret from the next line of stdin (a hidden prompt when stdin is a terminal)",
    )
    if editing:
        totp.add_argument("--no-totp", action="store_true", help="remove the TOTP secret")


def _add_access_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-grant", action="store_true", help=f"ignore {ENV_GRANT} and open the vault itself")


def register(subparsers: Any, common: argparse.ArgumentParser) -> None:
    """Add this module's commands to the ``irondome`` parser."""
    parser = _command(
        subparsers, common, "init", _create, "create the vault of this bunker (alpha unless another is chosen)",
        "Create the vault of the current bunker and bind it to this machine's security chip, or to a device key "
        "file where there is none. Choose a master password, Touch ID or both; a recovery key is shown once. "
        "With --password-stdin the new master password is the first line of stdin, unless another bunker already "
        "has a vault: only its owner may add one, so the default bunker's master password comes first; when stdout "
        "is not a terminal, the recovery key is the one thing written to it (the rest goes to stderr), so whatever "
        "captures a script's output keeps that key.",
        [
            ("irondome init", "create the vault of bunker alpha"),
            ("irondome init --mode touchid", "Touch ID, with the password as fallback"),
            ("irondome init --no-recovery", "no recovery key: losing this machine loses it"),
        ],
    )
    _add_setup_options(parser)

    _command(
        subparsers, common, "status", _status, "what protects this bunker's vault; needs no unlock",
        "Show the vault file, its format and generation, every keyslot and whether its device key is still here, "
        "the device backend and whether it is hardware, active sessions and grants, snapshots, and any 3.x vault. "
        "Nothing is unlocked.",
        [
            ("irondome status", "the current bunker"),
            ("irondome --bunker work status", "bunker work"),
            ("irondome status --json", "as one JSON document"),
        ],
    )

    parser = _command(
        subparsers, common, "add", _add, "store a new entry",
        "Store a new login or secret. The value comes from one source (--generate, --words N, --value-stdin or a "
        "hidden prompt); a custom field's (--field NAME) from a hidden prompt or stdin, never the command line. "
        "stdin holds, in order: the master password (--password-stdin), the value (--value-stdin), the TOTP secret "
        "(--totp-stdin), one line per --field, then the notes (--note-stdin), which take the rest; a value that is the "
        "last thing on stdin is read to the end of input, so a key of several lines is stored whole.",
        [
            ("irondome add github --generate", "a login with a generated password"),
            ("irondome add aws/prod --kind secret", "an API key, typed at a prompt"),
            ("irondome add bank --generate --field pin", "the pin is typed at a prompt"),
        ],
    )
    parser.add_argument("name", metavar="NAME", help="the entry's name, for example github or aws/prod")
    parser.add_argument("--alias", metavar="ALIAS", help="also name its password with an alias, e.g. GITHUB_TOKEN")
    _add_entry_options(parser, editing=False)
    _add_value_options(parser, editing=False)

    parser = _command(
        subparsers, common, "get", _get, "print the value a reference stands for",
        "Print the value of an alias, an entry (its password) or entry/field. With IRONDOME_GRANT set, the grant "
        "decides what may be read, and it may only be printed if the grant allows revealing. With --copy nothing "
        "secret is printed.",
        [
            ("irondome get github", "the password of github"),
            ("irondome get GITHUB_TOKEN --copy", "to the clipboard; nothing is printed"),
            ("irondome get aws/prod --field region", "one field of an entry"),
        ],
    )
    parser.add_argument("reference", metavar="REF", help="an alias, an entry name, entry/field, or irondome://...")
    parser.add_argument(
        "--field", metavar="F", help="read this field instead: password, username, url, notes, totp or a custom one"
    )
    parser.add_argument("-c", "--copy", action="store_true", help="copy it to the clipboard instead of printing it")
    _add_access_options(parser)

    parser = _command(
        subparsers, common, "show", _show, "everything about one entry, values hidden",
        "Show an entry's details, aliases, TOTP settings, custom field names and password history. Values stay "
        "hidden unless --reveal is given. For the vault's owner only.",
        [
            ("irondome show github", "every detail, values hidden"),
            ("irondome show github --reveal", "the password, notes and fields as well"),
        ],
    )
    parser.add_argument("name", metavar="NAME", help="the entry")
    parser.add_argument("--reveal", action="store_true", help="also show the password, notes, fields and TOTP link")

    parser = _command(
        subparsers, common, "ls", _ls, "list the entries (never their values)",
        "List the entries of this bunker: name, user name, URL, tags, whether it has a one-time password, what "
        "agents may do and when it changed. With IRONDOME_GRANT set it lists what the grant covers, without "
        "using it up.",
        [
            ("irondome ls", "every entry of the current bunker"),
            ("irondome ls --tag work --json", "those tagged work, as JSON"),
        ],
        _JSON_ENTRIES,
    )
    parser.add_argument("--tag", metavar="T", help="only entries with this tag")
    _add_access_options(parser)

    parser = _command(
        subparsers, common, "find", _find, "search entries by name, user name, URL, tag or alias",
        "List the entries whose name, user name, URL, tags or aliases contain QUERY, ignoring case. Values are "
        "never searched or shown. With IRONDOME_GRANT set it searches what the grant covers.",
        [
            ("irondome find git", "github, gitlab, an alias GIT_TOKEN..."),
            ("irondome find aws --json", "as JSON"),
        ],
        _JSON_ENTRIES,
    )
    parser.add_argument("query", metavar="QUERY", help="text to look for")
    parser.add_argument("--tag", metavar="T", help="only entries with this tag")
    _add_access_options(parser)

    parser = _command(
        subparsers, common, "edit", _edit, "change an entry",
        "Change an entry's details, value, TOTP secret or custom fields; options left out keep what is there. A "
        "replaced password is kept in the entry's history. stdin holds, in order: the master password "
        "(--password-stdin), the value (--value-stdin), the TOTP secret (--totp-stdin), one line per --field, then "
        "the notes (--note-stdin), which take the rest; a value that is the last thing on stdin is read to the end "
        "of input, several lines included.",
        [
            ("irondome edit github --generate", "a new password; the old one is kept"),
            ("irondome edit github --agent use", "agents may use it, not see it"),
            ("irondome edit github --name GitHub", "rename it; its aliases follow"),
        ],
    )
    parser.add_argument("name", metavar="NAME", help="the entry")
    _add_entry_options(parser, editing=True)
    _add_value_options(parser, editing=True)

    parser = _command(
        subparsers, common, "rm", _rm, "remove an entry",
        "Remove an entry and its aliases from the vault, after confirmation. Grants made earlier keep their own "
        "copy until they expire or are revoked.",
        [("irondome rm github", "github and its aliases, once you say yes")],
    )
    parser.add_argument("name", metavar="NAME", help="the entry")
    parser.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")

    parser = _command(
        subparsers, common, "gen", _gen, "generate a password, passphrase, user name or mail alias",
        "Print a random password (default), a passphrase, a user name or a plus-address mail alias. Needs no vault. "
        "The entropy goes to stderr; with --copy the value goes to the clipboard and is not printed.",
        [
            ("irondome gen", "a password of the default length"),
            ("irondome gen --words 6 --copy", "six words, to the clipboard"),
            ("irondome gen --email-alias me@example.com", "me+x7k2ab9q@example.com"),
        ],
    )
    parser.add_argument("--length", type=int, metavar="N", help="length of the password or user name")
    parser.add_argument("--words", type=int, metavar="N", help="a passphrase of N words")
    parser.add_argument("--no-symbols", action="store_true", help="no symbols")
    parser.add_argument("--no-digits", action="store_true", help="no digits")
    parser.add_argument("--no-upper", action="store_true", help="no capital letters")
    parser.add_argument("--no-ambiguous", action="store_true", help="leave out look-alikes such as 0, O, 1, l")
    parser.add_argument("--username", action="store_true", help="a random user name instead")
    parser.add_argument(
        "--email-alias", metavar="ADDRESS", help="a plus-address for ADDRESS, e.g. name+x7k2@example.com"
    )
    parser.add_argument("-c", "--copy", action="store_true", help="copy it to the clipboard instead of printing it")

    parser = _command(
        subparsers, common, "otp", _otp, "the current one-time code of an entry",
        "Print the current TOTP code of an entry, alias or entry/totp reference; the seconds it stays valid go to "
        "stderr. Works through a grant that covers the code.",
        [
            ("irondome otp github", "the code; the seconds left go to stderr"),
            ("irondome otp github --copy", "to the clipboard instead"),
        ],
    )
    parser.add_argument("reference", metavar="REF", help="an entry, an alias, or entry/totp")
    parser.add_argument(
        "-c", "--copy", action="store_true", help="copy the code to the clipboard instead of printing it"
    )
    _add_access_options(parser)

    _command(
        subparsers, common, "passwd", _passwd, "change the master password",
        "Change the master password of this bunker. Every password keyslot is replaced on the same device "
        "backend, the snapshots are deleted, sessions end and the old device key is destroyed; if that is "
        "interrupted, the next command that opens the vault finishes it. stdin lines with --password-stdin: the "
        "current password, then the new one.",
        [("irondome passwd", "the current password, then the new one twice")],
    )

    actions = _group(
        subparsers, common, "recovery", "recovery_action", "use the recovery key, make a new one, or remove it",
        "The recovery key opens the vault, or a copy of it, without this device and without the master password. "
        "Use it when the machine, its security chip or the master password is lost. Replacing or removing it "
        "re-keys the vault as irondome rekey does, because only a new vault key stops the old recovery key from "
        "opening it; the master password is asked for each time.",
        [
            ("irondome recovery use", "open the vault with the recovery key"),
            ("irondome recovery new", "a new recovery key, shown once"),
            ("irondome recovery remove", "no recovery key at all"),
        ],
    )
    _command(
        actions, common, "use", _recovery_use, "open the vault with the recovery key and set a new master password",
        "Open this bunker's vault with its recovery key, on any machine, and give it a new master password "
        "bound to this machine's device key. For a lost or replaced machine, a cleared security chip, a lost "
        "device key file or a forgotten master password: put the vault file back in place first (irondome "
        "status shows where it belongs). Every keyslot that needed the old device key or the old password, "
        "Touch ID keyslots included, is replaced by the new one; the snapshots are deleted and sessions end. Grants "
        "are not revoked: one whose device key is still on this machine works until it expires (irondome grant "
        "revoke --all ends them; irondome rekey also stops any copy of them). "
        "The recovery key itself is not changed. stdin lines with --password-stdin: the recovery key, then the "
        "new master password.",
        [("irondome recovery use", "the recovery key, then the new master password twice")],
    )
    action = _command(
        actions, common, "new", _recovery_new, "replace the recovery key with a new one, shown once",
        "Make a new recovery key, shown once. If there was one, the vault is re-keyed as well: a new vault key, "
        "every entry re-encrypted, every session and grant ended, the snapshots deleted and the audit log "
        "archived, so that the old key opens nothing in it from now on. Copies of the vault file made earlier "
        "still open with the old key, and nothing here can change that: delete them.",
        [
            ("irondome recovery new", "re-key, then show the new key once"),
            ("irondome recovery new --yes", "without the question at the terminal"),
        ],
    )
    action.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation at a terminal")
    action = _command(
        actions, common, "remove", _recovery_remove, "remove the recovery key",
        "Remove the recovery key, after confirmation, and re-key the vault as recovery new does, so that the old "
        "key opens nothing in it from now on. Copies of the vault file made earlier still open with the old key. "
        "Without it, losing this machine or its security chip means losing the vault.",
        [("irondome recovery remove", "asks first, then re-keys")],
    )
    action.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")

    actions = _group(
        subparsers, common, "auth", "auth_action", "show or change how the vault opens",
        "List the keyslots, enrol Touch ID, or go back to the master password and the device key. Changes ask "
        "for the master password each time, and device keys of replaced keyslots are destroyed.",
        [
            ("irondome auth show", "what opens the vault"),
            ("irondome auth touchid", "open it with Touch ID"),
            ("irondome auth password", "back to the master password"),
        ],
    )
    _command(
        actions, common, "show", _auth_show, "list the keyslots; needs no unlock",
        "List every keyslot of this vault, what opens it and whether its device key is still on this machine. "
        "Only the vault file is read; nothing is unlocked.",
        [
            ("irondome auth show", "every keyslot, and whether its device key is here"),
            ("irondome auth show --json", "as JSON"),
        ],
        _JSON_KEYSLOTS,
    )
    action = _command(
        actions, common, "touchid", _auth_touchid, "enrol Touch ID",
        "Add a keyslot that opens with Touch ID alone, enforced by the Secure Enclave. With --require-password "
        "the master-password keyslot itself is re-made so that both are needed every time.",
        [
            ("irondome auth touchid", "Touch ID alone opens the vault"),
            ("irondome auth touchid --require-password", "password and Touch ID, every time"),
        ],
    )
    action.add_argument(
        "--require-password", action="store_true", help="need both the master password and Touch ID, every time"
    )
    _command(
        actions, common, "password", _auth_password, "back to the master password and the device key",
        "Remove the Touch ID keyslots and open with the master password and this machine's device key again. A "
        "vault without a master password gets one.",
        [("irondome auth password", "Touch ID keys destroyed, the password again")],
    )

    actions = _group(
        subparsers, common, "config", "config_action", "list, read and change settings",
        "Settings are small defaults that a flag can always override, kept per bunker. Every value is "
        "range-checked.",
        [
            ("irondome config ls", "every setting, its value and range"),
            ("irondome config set grant_ttl 600", "grants live ten minutes by default"),
        ],
    )
    _command(
        actions, common, "ls", _config_ls, "list every setting",
        "List every setting of this bunker with its value, default and range. Nothing is unlocked.",
        [
            ("irondome config ls", "the settings of the current bunker"),
            ("irondome config ls --json", "as JSON"),
        ],
        _JSON_SETTINGS,
    )
    action = _command(
        actions, common, "get", _config_get, "print one setting",
        "Print the value of one setting of this bunker. A setting never changed prints its default.",
        [("irondome config get grant_ttl", "seconds a grant lives by default")],
    )
    action.add_argument("key", metavar="KEY", help="the setting")
    action = _command(
        actions, common, "set", _config_set, "change one setting",
        "Change one setting of this bunker within its range. It takes the master password (or a session), and the "
        "change is written to the audit log.",
        [
            ("irondome config set grant_ttl 600", "grants live ten minutes by default"),
            ("irondome config set snapshots 3", "keep three snapshots"),
        ],
    )
    action.add_argument("key", metavar="KEY", help="the setting")
    action.add_argument("value", metavar="VALUE", help="the new value")
    action = _command(
        actions, common, "reset", _config_reset, "back to the defaults",
        "Return the named settings, or all of them, to their defaults. It takes the master password (or a "
        "session), and the change is written to the audit log.",
        [
            ("irondome config reset grant_ttl", "one setting"),
            ("irondome config reset", "every setting"),
        ],
    )
    action.add_argument("keys", metavar="KEY", nargs="*", help="settings to reset (default: all)")

    actions = _group(
        subparsers, common, "bunker", "bunker_action", "several separate vaults on one machine",
        "A bunker is one vault with its own master password, device key, recovery key, sessions, grants and "
        "settings. Commands work on the current bunker: --bunker, else IRONDOME_BUNKER, else the bunker that holds "
        "the token in the environment, else the default.",
        [
            ("irondome bunker create work", "a second vault, apart from alpha"),
            ("irondome --bunker work ls", "work on it"),
            ("irondome bunker use work", "make it the default"),
        ],
    )
    action = _command(
        actions, common, "create", _bunker_create, "create a new bunker and its vault",
        "Create a new bunker with its own vault; the options are those of irondome init. Where another bunker "
        "already has a vault, only its owner may add one: at a terminal, or with the default bunker's master "
        "password as the first line of stdin and the new one after it. The default bunker does not change.",
        [
            ("irondome bunker create work", "a new bunker and its vault"),
            ("irondome bunker create work --mode touchid", "opened by Touch ID"),
        ],
    )
    action.add_argument(
        "name", metavar="NAME",
        help="a lower-case letter, then lower-case letters, digits or hyphens (32 characters at most)",
    )
    _add_setup_options(action)
    _command(
        actions, common, "ls", _bunker_ls, "list the bunkers; needs no unlock",
        "List every bunker on this machine: whether it has a vault, its device backend and whether that is "
        "hardware, active sessions and grants, and which is current and which the default. Nothing is unlocked, "
        "and no entry count is shown: that is encrypted.",
        [
            ("irondome bunker ls", "every bunker on this machine"),
            ("irondome bunker ls --json", "as JSON"),
        ],
        _JSON_BUNKERS,
    )
    action = _command(
        actions, common, "use", _bunker_use, "make a bunker the default",
        f"Record NAME as the bunker commands use when nothing else chooses one. {paths.ENV_BUNKER} and --bunker "
        "still win over it. Only the owner can: at a terminal, by answering its question, or with NAME's master "
        "password on stdin (--password-stdin).",
        [("irondome bunker use work", "asks, then makes work the default")],
    )
    action.add_argument("name", metavar="NAME", help="the bunker")
    _command(
        actions, common, "current", _bunker_current, "the bunker commands work on now, and why",
        "Print the name of the current bunker; why it was chosen (--bunker, the environment, a token or the "
        "default) goes to stderr. Scripts can rely on stdout holding the name alone.",
        [("irondome bunker current", "the name on stdout, the reason on stderr")],
    )
    action = _command(
        actions, common, "rm", _bunker_rm, "destroy a bunker, device key first",
        "Destroy one bunker for good: its device key first, then its vault, snapshots, audit log, settings, "
        "sessions and grants. You must type its name at a terminal, unless --yes comes with its master password "
        "on stdin (--password-stdin). Other bunkers are untouched.",
        [("irondome bunker rm work", "type work to confirm; it cannot be undone")],
    )
    action.add_argument("name", metavar="NAME", help="the bunker")
    action.add_argument(
        "-y", "--yes", action="store_true",
        help="do not ask for the name to be typed; only with --password-stdin and the bunker's master password",
    )

