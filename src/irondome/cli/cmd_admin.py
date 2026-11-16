"""Maintenance commands: backups, import and export, migration, re-keying, self-destruct, diagnostics.

==========================  =================================================
``backup ls|restore``       the snapshots ``Vault.commit`` keeps of the vault
``export PATH``             a portable encrypted backup, or (``--plaintext``)
                            every value in the clear
``import PATH``             a portable backup or another manager's export
``migrate``                 an IronDome 3.x vault into this one
``rekey``                   a new vault key, after a suspected compromise
``nuke``                    every bunker on this machine, destroyed
``doctor``                  what this machine offers and what is wrong
``completion SHELL``        a static completion script
``version``                 the version
==========================  =================================================

Everything here that changes a vault, its keyslots or its protection, or
that exports data, is the owner's: it refuses to run for an agent (no
terminal and no ``--password-stdin``). ``rekey``, ``export`` and ``backup
restore`` unlock with the master password or Touch ID even when a session
token is set. ``nuke`` unlocks nothing, so it asks for DESTROY to be typed at
a terminal; ``--yes-destroy-everything`` skips that only when the password
given with ``--password-stdin`` opens every vault it destroys (see
:meth:`Context.prove_owner`). ``doctor``, ``completion`` and ``version`` read
nothing secret and are open to anyone.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hmac
import json
import os
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from irondome import audit, caps, config, doctor, interop, keys, migrate_v3, nuke, otp, paths
from irondome import device as devices
from irondome.cli.cmd_vault import warn_if_cheap
from irondome.cli.context import Context, readable_vault
from irondome.cli.output import format_time
from irondome.crypto import Argon2Params, default_argon2
from irondome.device.base import POLICY_BIOMETRY, POLICY_DEVICE
from irondome.errors import AuthError, HardwareError, IronDomeError, NotFoundError, PolicyError, UsageError, VaultError
from irondome.generator import estimate_strength
from irondome.keys import KIND_DEVICE, KIND_PASSWORD, KIND_RECOVERY, Keyslot
from irondome.secmem import SecureBuffer, wipe_bytes
from irondome.unlock import MIN_PASSWORD_BYTES, MODE_PASSWORD, MODE_TOUCHID, MODES, create_vault, open_vault, unlock
from irondome.vault import _SNAPSHOT, Entry, Secret, Vault, VaultFile, vault_exists, without_control

__all__ = ["register"]

_NAME_LIMIT = 200
_CONFLICT_POLICIES = ("rename", "skip", "replace")
_IMPORT_FORMATS = ("auto",) + interop.FORMATS
_SHELLS = ("bash", "zsh", "fish")
_UNPARSED_TOTP_FIELD = "totp_unparsed"
_WEAK = ("very weak", "weak", "fair")
#: The re-keyed vault, built beside the live one: ``.tmp-rekey-<hex>.irondome`` in the bunker's directory.
#: Defined in caps, which refuses every session and grant while one of the live vault is there.
_STAGING_PREFIX = caps.REKEY_STAGING_PREFIX
_STAGING_SUFFIX = caps.REKEY_STAGING_SUFFIX
#: In a re-keyed vault's encrypted index: the device secrets of the vault it replaced, until they are destroyed.
_REKEY_PLAN = caps.REKEY_PLAN

_Handler = Callable[[Context, argparse.Namespace], int]


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def _page(description: str, examples: str) -> Dict[str, Any]:
    """The help page of one command: the description wrapped as argparse wraps it, the examples kept as written.

    argparse would refill the examples into one paragraph, breaking a command across lines where the
    terminal is narrow; with its own line breaks each example stays one line that can be copied.
    """
    return {
        "description": textwrap.fill(" ".join(description.split()), width=78),
        "epilog": examples,
        "formatter_class": argparse.RawDescriptionHelpFormatter,
    }


def register(subparsers: Any, common: argparse.ArgumentParser) -> None:
    """Add the maintenance commands to the ``irondome`` parser."""

    def command(name: str, summary: str, description: str, handler: _Handler, examples: str) -> Any:
        parser = subparsers.add_parser(name, parents=[common], help=summary, **_page(description, examples))
        parser.set_defaults(handler=handler)
        return parser

    backup = subparsers.add_parser(
        "backup",
        parents=[common],
        help="list or restore the automatic snapshots of the vault",
        **_page(
            "Every change to the vault keeps the file it replaces as a snapshot (the setting `snapshots` says how "
            "many). `backup ls` lists them; `backup restore` puts one back after checking that it opens with your "
            "current master password.",
            "examples:\n"
            "  irondome backup ls                  the snapshots, oldest first\n"
            "  irondome backup restore 12          put snapshot 12 back in place of the vault\n",
        ),
    )
    backups = backup.add_subparsers(
        dest="backup_command", metavar="<subcommand>", parser_class=type(backup), required=True
    )
    ls = backups.add_parser(
        "ls",
        parents=[common],
        help="list the snapshots of the vault",
        **_page(
            "List the snapshots of this bunker's vault: the generation each was taken at, when, and its size. "
            "Nothing is unlocked.",
            "examples:\n"
            "  irondome backup ls\n"
            "  irondome --bunker bravo backup ls --json\n",
        ),
    )
    ls.set_defaults(handler=cmd_backup_ls)
    restore = backups.add_parser(
        "restore",
        parents=[common],
        help="replace the vault with one of its snapshots",
        **_page(
            "Put a snapshot back in place of the vault. The snapshot is first unlocked with your current master "
            "password (or Touch ID), so a restore can never leave you with a vault you cannot open; the file it "
            "replaces is kept as a snapshot, so a restore can be undone.",
            "examples:\n"
            "  irondome backup restore 12          snapshot 12, as irondome backup ls numbers it\n"
            "  irondome backup restore vault-0000000012.irondome --yes\n",
        ),
    )
    restore.add_argument("snapshot", metavar="SNAPSHOT", help="the generation number or file name `backup ls` shows")
    restore.add_argument("-y", "--yes", action="store_true", help="restore without asking for confirmation")
    restore.set_defaults(handler=cmd_backup_restore)

    export = command(
        "export",
        "write a portable encrypted backup, or a plaintext export",
        (
            "Write every entry and alias of the vault to PATH. By default the file is a portable encrypted backup: "
            "it opens on any machine with a password you choose now (asked twice, or the second line of stdin "
            "after the master password), and with --recovery also with a recovery key shown once. --plaintext "
            "writes every value unencrypted instead, as JSON or CSV, after a warning and a typed confirmation."
        ),
        cmd_export,
        "examples:\n"
        "  irondome export ~/alpha.irondome --recovery     encrypted, with a recovery key as well\n"
        "  irondome export ~/alpha.json --plaintext json   every value in the clear\n",
    )
    export.add_argument("path", metavar="PATH", help="the file to write")
    export.add_argument(
        "--plaintext", choices=interop.PLAINTEXT_FORMATS, help="write every value unencrypted, as json or csv"
    )
    export.add_argument("--recovery", action="store_true", help="give the backup a recovery key as well, shown once")
    export.add_argument(
        "-y", "--yes", action="store_true",
        help="overwrite PATH if it exists, and confirm a plaintext export without asking",
    )

    importer = command(
        "import",
        "add the entries of a backup or of another password manager's export",
        (
            "Add every entry of PATH to the vault: a portable IronDome backup (its password is asked for, or read "
            "from the line of stdin after the master password), IronDome's plaintext JSON or CSV, or an export of "
            "Bitwarden, 1Password, Chrome or Firefox. Entries whose name is taken are renamed, skipped or replaced "
            "as --on-conflict says; an entry already in the vault with the same values is skipped. No value is "
            "ever printed."
        ),
        cmd_import,
        "examples:\n"
        "  irondome import ~/alpha.irondome\n"
        "  irondome import ~/Downloads/bitwarden_export.json --on-conflict skip\n",
    )
    importer.add_argument("path", metavar="PATH", help="the file to read")
    importer.add_argument(
        "--format", choices=_IMPORT_FORMATS, default="auto", help="what PATH is (default: recognised from its content)"
    )
    importer.add_argument(
        "--on-conflict",
        choices=_CONFLICT_POLICIES,
        default="rename",
        help="an entry whose name is taken is renamed to 'NAME (imported)' (default), skipped, or replaces it",
    )

    migrate = command(
        "migrate",
        "bring an IronDome 3.x vault into this one",
        (
            "Read an IronDome 3.x vault, copy every entry into this bunker's vault (creating it if there is none) "
            "and compare each one with the original before reporting success. The 3.x vault is not changed unless "
            "--destroy-old is given and the comparison was clean. With --password-stdin the lines are: the 3.x "
            "master password (or, for a 3.x vault without one, its key when the OS keychain does not have it), "
            "then the master password of the existing vault, or the new one with --new-password or when the 3.x "
            "vault had no master password. A 3.x key that the OS keychain hands over proves nothing about who is "
            "asking, so such a vault is migrated at a terminal, without --password-stdin."
        ),
        cmd_migrate,
        "examples:\n"
        "  irondome migrate                    from ~/.password_manager, the 3.x vault is kept\n"
        "  irondome migrate --destroy-old      the same, then destroy the 3.x vault\n",
    )
    migrate.add_argument(
        "--from", dest="from_dir", metavar="DIR", help="the 3.x data directory (default: ~/.password_manager)"
    )
    migrate.add_argument(
        "--legacy-username", metavar="USER", help="the 3.x master username, when it cannot be read on this machine"
    )
    migrate.add_argument(
        "--legacy-key",
        action="store_true",
        help="the 3.x vault has no master password (biometric only): use the key 3.x kept in the OS keychain; "
        "where the keychain cannot give it, the key is asked for, or read as the first line of stdin with "
        "--password-stdin",
    )
    migrate.add_argument("--mode", choices=MODES, help="how a new vault is opened, as for init (default: password)")
    migrate.add_argument("--no-recovery", action="store_true", help="create the new vault without a recovery key")
    migrate.add_argument(
        "--kdf-memory-mib", type=int, metavar="N", help="memory for Argon2id in a new vault, in MiB, as for init"
    )
    passwords = migrate.add_mutually_exclusive_group()
    passwords.add_argument(
        "--keep-password", action="store_true", help="the new vault uses the 3.x master password (the default)"
    )
    passwords.add_argument("--new-password", action="store_true", help="choose a new master password for the new vault")
    passwords.add_argument(
        "--no-password", action="store_true",
        help="with --mode touchid: no master password; the recovery key is the fallback",
    )
    migrate.add_argument(
        "--destroy-old", action="store_true", help="destroy the 3.x vault once every entry has been verified"
    )
    migrate.add_argument("-y", "--yes", action="store_true", help="confirm --destroy-old without typing DESTROY")

    rekey = command(
        "rekey",
        "replace the vault key itself, after a suspected compromise",
        (
            "Re-encrypt the vault under a new vault key and vault id, with fresh keyslots of the same kinds (a "
            "new recovery key is shown once). Afterwards every session and grant is gone, the snapshots are "
            "deleted, the old device keys are destroyed and the audit log is archived, so nothing taken before "
            "opens the vault again; if a re-key is stopped part way, the next one also finishes what it left. "
            "Use it after a session, a device or a backup may have been compromised."
        ),
        cmd_rekey,
        "example:\n"
        "  irondome rekey                      asks for the master password, then for REKEY to be typed\n",
    )
    rekey.add_argument("-y", "--yes", action="store_true", help="re-key without typing REKEY")

    destroy = command(
        "nuke",
        "destroy every bunker on this machine",
        (
            "Destroy everything IronDome keeps on this machine: every bunker's device keys first, so that no copy "
            "of a vault file opens with a master password again, then its sessions, grants and files, the shared "
            "helper cache and the default-bunker setting. Files IronDome did not create are left in place and "
            "listed. To remove one bunker, use `irondome bunker rm`."
        ),
        cmd_nuke,
        "examples:\n"
        "  irondome nuke                       shows what goes, then asks for DESTROY to be typed\n"
        "  irondome nuke --include-legacy      an IronDome 3.x vault goes as well\n",
    )
    destroy.add_argument(
        "--yes-destroy-everything", action="store_true",
        help="destroy without typing DESTROY; only with --password-stdin and a master password that opens every vault",
    )
    destroy.add_argument("--include-legacy", action="store_true", help="destroy an IronDome 3.x vault as well")

    command(
        "doctor",
        "check this machine and this installation",
        (
            "Report the versions in use, the security chips and device backends this machine offers, the vault's "
            "keyslots, file permissions, memory locking and more, each with a remedy when something is wrong. "
            "Nothing is unlocked and nothing is changed. Exits with status 1 when it finds a problem."
        ),
        cmd_doctor,
        "examples:\n"
        "  irondome doctor\n"
        "  irondome --bunker bravo doctor --json\n",
    )

    completion = command(
        "completion",
        "print a shell completion script",
        (
            "Print a completion script for bash, zsh or fish, generated from this version's commands and options. "
            "It is static: completing a word never runs irondome. Load it with, for example, "
            "`source <(irondome completion bash)`."
        ),
        cmd_completion,
        "examples:\n"
        "  source <(irondome completion bash)       in ~/.bashrc\n"
        "  irondome completion fish > ~/.config/fish/completions/irondome.fish\n",
    )
    completion.add_argument("shell", choices=_SHELLS, help="the shell to write the script for")

    command(
        "version",
        "print the version",
        "Print the version of IronDome, as --version does. With --json, also the Python, cryptography and OpenSSL "
        "versions it runs on.",
        cmd_version,
        "examples:\n"
        "  irondome version\n"
        "  irondome version --json\n",
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _owner_only(ctx: Context, action: str) -> None:
    if ctx.agent_mode:
        raise PolicyError(
            f"{action} needs the vault's owner: run it at a terminal, or give the master password with "
            "--password-stdin. An agent or a script without either cannot do it."
        )


def _count(number: int, singular: str, plural: str = "") -> str:
    return f"{number} {singular if number == 1 else (plural or singular + 's')}"


def _printable(text: str) -> str:
    """*text* safe to show on a terminal: control characters (escape sequences included) written as escapes."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)


def _bunker_hint(bunker: str) -> str:
    return "" if bunker == paths.FIRST_BUNKER else f" --bunker {bunker}"


def _require_vault(bunker: str) -> None:
    if not vault_exists():
        raise VaultError(
            f"there is no vault in bunker {bunker} ({paths.vault_file()}). "
            f"Create one with: irondome{_bunker_hint(bunker)} init"
        )


@contextlib.contextmanager
def _disk(what: str) -> Iterator[None]:
    """Report a disk operation that failed (no space, no permission) as what could not be done, not a traceback."""
    try:
        yield
    except OSError as exc:
        raise VaultError(f"{what}: {exc.strerror or exc}") from None


def _commit(vault: Vault) -> None:
    with _disk("the vault could not be written, so it was left as it was"):
        vault.commit(snapshots=config.get("snapshots"))


def _absolute(text: str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(text)))


def _unlock_file(
    ctx: Context, file: VaultFile, *, reason: str, keep_password: bool = False
) -> Tuple[SecureBuffer, Optional[SecureBuffer]]:
    """Open *file* with the owner's own factors, as ``Context.open_vault`` does, but never with a session.

    ``Context.open_vault`` only opens the live vault and never hands back the
    password it read. This opens any vault file (a snapshot, the live one) and,
    with *keep_password*, returns a copy of the master password when that is
    what opened it, for a caller that must wrap a new key under it. Returns
    ``(vault key, password or None)``; the caller wipes both.
    """
    captured: List[SecureBuffer] = []

    def source() -> SecureBuffer:
        password = ctx.master_password(reason)
        if keep_password:
            captured.append(password.copy())
        return password

    supplied = ctx.master_password(reason) if ctx.password_stdin else None
    may_touch = not ctx.no_touch and (ctx.has_terminal or ctx.touch)
    try:
        vault_key = unlock(
            file,
            password=supplied,
            password_source=source if (supplied is None and ctx.has_terminal) else None,
            interactive=may_touch or ctx.has_terminal,
            allow_touch=may_touch,
            reason=reason,
        )
    except BaseException:
        for item in captured:
            item.wipe()
        if supplied is not None:
            supplied.wipe()
        raise
    if not keep_password:
        if supplied is not None:
            supplied.wipe()
        return vault_key, None
    kept = supplied if supplied is not None else (captured.pop() if captured else None)
    for item in captured:
        item.wipe()
    return vault_key, kept


def _new_secret(ctx: Context, prompt: str, what: str) -> SecureBuffer:
    """A new password: asked twice on a terminal, or the next line of stdin. The caller wipes it."""
    first = ctx.read_secret(f"{prompt}: ")
    if first is None:
        raise UsageError(f"the {what} cannot be empty")
    try:
        if len(first) < MIN_PASSWORD_BYTES:
            raise UsageError(f"the {what} must be at least {MIN_PASSWORD_BYTES} characters")
        if not ctx.password_stdin:
            second = ctx.read_secret("Repeat it: ")
            try:
                if second is None or not hmac.compare_digest(first.view(), second.view()):
                    raise UsageError("the two entries do not match")
            finally:
                if second is not None:
                    second.wipe()
    except BaseException:
        first.wipe()
        raise
    return first


def _show_recovery(ctx: Context, key: str, what: str) -> None:
    ctx.out.info(
        f"Recovery key for {what}. It is shown only this once: write it down and keep it offline. "
        "It opens a copy of the file without a password or this computer."
    )
    ctx.out.secret(key)


def _plain(value: Any) -> Any:
    """A dataclass or container as JSON-ready values: paths become text."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _plain(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _snapshot_files() -> List[Tuple[int, Path]]:
    """``(number, path)`` of every automatic snapshot of the current bunker, lowest first.

    ``Vault.snapshots`` lists the same files but needs an unlocked vault, and
    listing must work when the live vault is the thing that is broken.
    """
    directory = paths.backups_dir()
    try:
        with os.scandir(str(directory)) as listing:
            found = [
                (int(match.group(1)), Path(item.path))
                for item in listing
                for match in [_SNAPSHOT.fullmatch(item.name)]
                if match and item.is_file(follow_symlinks=False)
            ]
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise VaultError(f"cannot list the snapshots in {directory}: {exc.strerror or exc}") from None
    return sorted(found)


# ---------------------------------------------------------------------------
# backup ls / backup restore
# ---------------------------------------------------------------------------


def _live_header() -> Tuple[Optional[bytes], Optional[int]]:
    try:
        file = VaultFile.load()
    except VaultError:
        return None, None
    return file.vault_id, file.generation


def cmd_backup_ls(ctx: Context, args: argparse.Namespace) -> int:
    _owner_only(ctx, "listing the vault's snapshots")
    bunker = paths.bunker_name()
    live_id, live_generation = _live_header()
    snapshots: List[Dict[str, Any]] = []
    for number, path in _snapshot_files():
        written: Optional[int] = None
        size: Optional[int] = None
        with contextlib.suppress(OSError):
            info = path.stat()
            written, size = int(info.st_mtime), info.st_size
        try:
            file = VaultFile.load(path)
        except VaultError:
            belongs, generation = "unreadable", None
        else:
            belongs = "this vault" if live_id is None or file.vault_id == live_id else "another vault"
            generation = file.generation
        snapshots.append(
            {"snapshot": number, "file": path.name, "path": str(path), "generation": generation,
             "written": written, "size": size, "vault": belongs}
        )
    if ctx.out.json_mode:
        ctx.out.json({"bunker": bunker, "generation": live_generation, "snapshots": snapshots})
        return 0
    if not snapshots:
        ctx.out.info(f"Bunker {bunker} has no snapshots yet: one is kept each time the vault changes.")
        return 0
    ctx.out.table(
        ("snapshot", "written", "size", "vault"),
        (
            (str(item["snapshot"]), format_time(item["written"]), "-" if item["size"] is None else f"{item['size']} B",
             item["vault"])
            for item in snapshots
        ),
    )
    current = "missing or unreadable" if live_generation is None else f"generation {live_generation}"
    ctx.out.info(f"Bunker {bunker}: the vault itself is at {current}. Restore one with: irondome backup restore N")
    return 0


def _find_snapshot(text: str) -> Tuple[int, Path]:
    wanted = text.strip()
    for number, path in _snapshot_files():
        if path.name == wanted or (wanted.isascii() and wanted.isdigit() and int(wanted) == number):
            return number, path
    raise NotFoundError(f"there is no snapshot {wanted!r}; list them with: irondome backup ls")


def _replace_live(data: bytes) -> Optional[int]:
    """Write *data* as the live vault, keeping the file it replaces as a snapshot. Returns that snapshot's number."""
    live = paths.vault_file()
    with _disk("the snapshot could not be put in place, so the vault was left as it was"), paths.file_lock(
        paths.lock_file()
    ):
        try:
            current: Optional[bytes] = paths.read_file(live)
        except FileNotFoundError:
            current = None
        kept: Optional[int] = None
        if current is not None:
            try:
                kept = VaultFile.from_bytes(current).generation
            except VaultError:
                # A damaged file has no generation: number it after every snapshot there is.
                kept = max([number for number, _ in _snapshot_files()] + [0]) + 1
            paths.write_atomic(paths.ensure_dir(paths.backups_dir()) / f"vault-{kept:010d}.irondome", current)
        paths.write_atomic(live, data)
    return kept


def cmd_backup_restore(ctx: Context, args: argparse.Namespace) -> int:
    _owner_only(ctx, "restoring a snapshot")
    bunker = paths.bunker_name()
    number, source = _find_snapshot(args.snapshot)
    if not ctx.assume_yes and not ctx.has_terminal:
        raise UsageError("restoring a snapshot needs confirmation: run it at a terminal, or add --yes")
    try:
        data = paths.read_file(source)
    except OSError as exc:
        raise VaultError(f"cannot read the snapshot {source}: {exc.strerror or exc}") from None
    file = VaultFile.from_bytes(data)  # what is checked here is exactly what is written below
    vault_key, _ = _unlock_file(ctx, file, reason=f"restore a snapshot of IronDome bunker {bunker}")
    ctx.note_unfinished_rekey()
    restored = Vault(file, vault_key, path=source)
    try:
        for entry in restored.list():
            restored.read_secret(entry)  # every record must authenticate, not only the index
        count = len(restored.entries)
        what = f"{_count(count, 'entry', 'entries')}, generation {file.generation}"
        question = (
            f"Replace the vault of bunker {bunker} with snapshot {number} ({what})? "
            "The file it replaces is kept as a snapshot."
        )
        if not ctx.confirm(question):
            ctx.out.info("Nothing was changed.")
            return 1
        kept = _replace_live(data)
        ctx.audit(restored, "backup.restore", target=source.name, detail=f"generation {file.generation}")
    finally:
        restored.close()
    if ctx.out.json_mode:
        ctx.out.json(
            {"bunker": bunker, "restored": number, "generation": file.generation, "entries": count, "kept": kept,
             "path": str(paths.vault_file())}
        )
        return 0
    ctx.out.ok(f"Restored snapshot {number} of bunker {bunker}: {what}.")
    if kept is not None:
        ctx.out.info(f"The file it replaced is snapshot {kept}; undo with: irondome backup restore {kept}")
    return 0


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


def _export_target(text: str, *, overwrite: bool) -> Path:
    target = _absolute(text)
    resolved = Path(os.path.realpath(str(target)))
    for own in (paths.root(), paths.device_root()):
        mine = Path(os.path.realpath(str(own)))
        if resolved == mine or mine in resolved.parents:
            raise UsageError(f"{target} is inside IronDome's own directory {own}; write the export somewhere else")
    if target.is_dir():
        raise UsageError(f"{target} is a directory; give the path of the file to write")
    if os.path.lexists(str(target)) and not overwrite:
        raise UsageError(f"{target} already exists; run again with --yes to overwrite it")
    return target


def _aliases_of(vault: Vault, entry: Entry) -> List[Tuple[str, str]]:
    return [(name, alias.field) for name, alias in sorted(vault.aliases.items()) if alias.entry == entry.id]


def _plain_entries(vault: Vault) -> List[interop.ImportedEntry]:
    entries = []
    for entry in vault.list():
        secret = vault.read_secret(entry)
        entries.append(
            interop.ImportedEntry(
                name=entry.name,
                username=entry.username,
                password=secret.password,
                url=entry.url,
                notes=secret.notes,
                totp=otp.to_otpauth(secret.totp) if secret.totp else "",
                tags=list(entry.tags),
                fields=dict(secret.fields),
                kind=entry.kind,
                created=entry.created,
                modified=entry.modified,
                history=[dict(item) for item in secret.history],
                aliases=_aliases_of(vault, entry),
            )
        )
    return entries


def _build_portable(
    vault: Vault, password: SecureBuffer, directory: Path, *, with_recovery: bool
) -> Tuple[bytes, Optional[str], int]:
    """The bytes of a portable copy of *vault*: one password slot with no device factor, maybe a recovery slot.

    ``Vault.create`` always writes to disk and locks the directory it writes
    in, so the copy is built in a private directory beside the destination,
    read back, and that directory destroyed.
    """
    paths.ensure_dir(directory)
    scratch = Path(tempfile.mkdtemp(prefix=".irondome-export-", dir=str(directory)))
    vault_id = os.urandom(keys.VAULT_ID_LEN)
    recovery: Optional[str] = None
    try:
        vault_key = keys.new_vault_key()
        slots: List[Keyslot] = []
        try:
            slots.append(
                keys.create_password_slot(
                    vault_key, password, vault_id, params=default_argon2(), backend=None, label="backup password"
                )
            )
            if with_recovery:
                slot, recovery = keys.create_recovery_slot(vault_key, vault_id, label="recovery key")
                slots.append(slot)
        except BaseException:
            vault_key.wipe()
            raise
        portable = Vault.create(vault_key, slots, vault_id, scratch / "backup.irondome")  # owns the key now
        try:
            count = vault.copy_into(portable)
            portable.commit(snapshots=0)
            data = paths.read_file(portable.path)
        finally:
            portable.close()
    finally:
        for leftover in sorted(scratch.iterdir()):
            with contextlib.suppress(OSError):
                paths.secure_delete(leftover)
        with contextlib.suppress(OSError):
            scratch.rmdir()
    return data, recovery, count


def _check_portable(target: Path, password: SecureBuffer, count: int) -> None:
    """Open what was written with the backup password, before saying that it opens."""
    try:
        check = open_vault(path=target, password=password, interactive=False, allow_touch=False)
    except IronDomeError as exc:
        with contextlib.suppress(OSError):
            paths.secure_delete(target)
        raise VaultError(f"the backup written to {target} does not open again ({exc}); it was deleted") from None
    try:
        if len(check.entries) != count:
            raise VaultError(f"the backup written to {target} holds {len(check.entries)} entries instead of {count}")
    finally:
        check.close()


def _export_portable(ctx: Context, vault: Vault, target: Path, bunker: str, *, with_recovery: bool) -> int:
    password = _new_secret(ctx, "Password for the backup", "backup password")
    try:
        strength = estimate_strength(password)
        with _disk(f"the backup could not be written to {target}"):
            data, recovery, count = _build_portable(vault, password, target.parent, with_recovery=with_recovery)
            paths.write_atomic(target, data)
        _check_portable(target, password, count)
    finally:
        password.wipe()
    aliases = len(vault.aliases)
    ctx.audit(
        vault, "export", target=str(target),
        detail=f"portable backup, {_count(count, 'entry', 'entries')}" + (", with a recovery key" if recovery else ""),
    )
    if strength.label in _WEAK:
        ctx.out.warn(
            f"that password is {strength.label} for a file anyone who gets it can try to guess offline; "
            "consider exporting again with a long passphrase (irondome gen --words 6 makes one)"
        )
    warn_if_cheap(ctx, default_argon2(), "this backup")
    if ctx.out.json_mode:
        ctx.out.json(
            {"bunker": bunker, "path": str(target), "format": interop.FORMAT_IRONDOME, "encrypted": True,
             "entries": count, "aliases": aliases, "recovery_key": recovery}
        )
        return 0
    held = f"{_count(count, 'entry', 'entries')}, {_count(aliases, 'alias', 'aliases')}"
    ctx.out.ok(f"Wrote a portable backup of bunker {bunker} ({held}) to {target}.")
    ctx.out.info(
        "It opens on any machine with its password, not with your master password and without this computer. "
        f"Bring it back with: irondome import {target}"
    )
    if recovery:
        _show_recovery(ctx, recovery, "this backup")
    return 0


def _csv_losses(entries: Sequence[interop.ImportedEntry]) -> str:
    """What of *entries* a CSV export cannot hold, in words; empty when nothing is lost (see ``interop.dump``)."""
    if not entries:
        return ""
    parts = ["when each entry was created and changed"]
    histories = sum(1 for entry in entries if entry.history)
    if histories:
        parts.append(f"the password history of {_count(histories, 'entry', 'entries')}")
    aliases = sum(len(entry.aliases) for entry in entries)
    if aliases:
        parts.append(_count(aliases, "alias", "aliases"))
    empty = sum(1 for entry in entries for value in entry.fields.values() if not value)
    if empty:
        parts.append(
            f"{_count(empty, 'custom field')} with no value (an empty cell cannot tell such a field from one the "
            "entry does not have)"
        )
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]


def _export_plaintext(ctx: Context, vault: Vault, target: Path, fmt: str, bunker: str) -> int:
    entries = _plain_entries(vault)
    ctx.out.warn(
        "this writes every password, one-time-password secret, note and custom field of "
        f"{_count(len(entries), 'entry', 'entries')} in bunker {bunker} to {target} in plain text, unencrypted. "
        "Anyone who can read that file, or any copy of it (a backup, a synced folder, the trash), has all of them. "
        "Delete it as soon as you are done."
    )
    if fmt == "csv":
        ctx.out.warn("do not open it in a spreadsheet: cells that begin with = + - or @ can run as formulas there")
        lost = _csv_losses(entries)
        if lost:
            ctx.out.warn(
                f"CSV cannot carry {lost}: importing the file brings back everything else. For an exact copy, "
                "export with --plaintext json, or make a portable backup (irondome export without --plaintext)."
            )
    if not ctx.assume_yes and not ctx.confirm_phrase("Write the plaintext export?", "EXPORT"):
        ctx.out.info("Nothing was written.")
        return 1
    data = interop.dump(entries, fmt)
    try:
        with _disk(f"the export could not be written to {target}"):
            paths.write_atomic(target, data)
    finally:
        wipe_bytes(data)
    ctx.audit(vault, "export.plaintext", target=str(target), detail=f"{fmt}, {len(entries)} entries")
    if ctx.out.json_mode:
        ctx.out.json(
            {"bunker": bunker, "path": str(target), "format": fmt, "encrypted": False, "entries": len(entries),
             "aliases": len(vault.aliases), "recovery_key": None}
        )
        return 0
    ctx.out.ok(
        f"Wrote {_count(len(entries), 'entry', 'entries')} of bunker {bunker} to {target}, unencrypted "
        "(readable only by you)."
    )
    return 0


def cmd_export(ctx: Context, args: argparse.Namespace) -> int:
    _owner_only(ctx, "exporting the vault")
    if args.plaintext and args.recovery:
        raise UsageError("--recovery is for encrypted backups; a plaintext export has no keys to recover")
    bunker = paths.bunker_name()
    target = _export_target(args.path, overwrite=args.yes)
    _require_vault(bunker)
    if args.plaintext and not ctx.assume_yes and not ctx.has_terminal:
        raise UsageError(
            "a plaintext export must be confirmed by typing EXPORT at a terminal, or with --yes; nothing was written"
        )
    vault = ctx.open_vault(reason=f"export IronDome bunker {bunker}", fresh=True)
    try:
        if args.plaintext:
            return _export_plaintext(ctx, vault, target, args.plaintext, bunker)
        return _export_portable(ctx, vault, target, bunker, with_recovery=args.recovery)
    finally:
        vault.close()


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------


@dataclass
class _Incoming:
    """One entry on its way into the vault, from whichever format it came."""

    name: str
    secret: Secret = field(repr=False)
    username: str = ""
    url: str = ""
    tags: List[str] = field(default_factory=list)
    kind: str = "login"
    agent: str = "deny"
    created: Optional[int] = None
    modified: Optional[int] = None
    aliases: List[Tuple[str, str]] = field(default_factory=list)


@dataclass
class _Outcome:
    source: str
    name: str
    action: str
    reason: str = ""


def _free_field(fields: Dict[str, str], name: str) -> str:
    candidate, number = name, 1
    while candidate in fields:
        number += 1
        candidate = f"{name}_{number}"
    return candidate


def _cleaned_warning(name: str, parts: Sequence[str]) -> str:
    spoken = {"username": "user name", "url": "web address", "tags": "tags"}
    named = [spoken.get(part, part) for part in parts]
    listed = named[0] if len(named) == 1 else ", ".join(named[:-1]) + " and " + named[-1]
    return (
        f"{_printable(name)}: control characters were taken out of its {listed}, which cannot hold them; "
        "nothing else was changed"
    )


def _from_interop(entry: interop.ImportedEntry, warnings: List[str]) -> _Incoming:
    if entry.cleaned:
        warnings.append(_cleaned_warning(entry.name, entry.cleaned))
    fields = dict(entry.fields)
    totp: Optional[Dict[str, Any]] = None
    if entry.totp:
        try:
            if entry.totp.lower().startswith("otpauth"):
                totp = otp.parse_otpauth(entry.totp)
            else:
                totp = otp.make_totp(entry.totp)
        except UsageError as exc:
            kept = _free_field(fields, _UNPARSED_TOTP_FIELD)
            fields[kept] = entry.totp
            warnings.append(f"{_printable(entry.name)}: its one-time-password secret could not be read "
                            f"({_printable(str(exc))}); it is kept in the custom field {kept}")
    secret = Secret(
        password=entry.password, totp=totp, notes=entry.notes, fields=fields,
        history=[dict(item) for item in entry.history],
    )
    return _Incoming(
        name=entry.name, secret=secret, username=entry.username, url=entry.url, tags=list(entry.tags),
        kind=entry.kind, created=entry.created, modified=entry.modified, aliases=list(entry.aliases),
    )


def _from_backup(ctx: Context, path: Path, warnings: List[str]) -> List[_Incoming]:
    password = ctx.read_secret("Password of the backup: ")
    if password is None:
        raise UsageError("the backup's password cannot be empty")
    try:
        backup = open_vault(path=path, password=password, interactive=False, allow_touch=False)
    except AuthError:
        raise AuthError(f"that password does not open the backup {path}") from None
    except HardwareError:
        raise UsageError(
            f"{path} is not a portable backup: its keyslots need a device key of the machine it was made on. "
            "Make a portable one there with: irondome export"
        ) from None
    finally:
        password.wipe()
    try:
        incoming = []
        for entry in backup.list():
            secret = backup.read_secret(entry)
            # A backup made before control characters were refused in user names and addresses may hold some.
            username, url = without_control(entry.username), without_control(entry.url)
            changed = [part for part, old, new in (("username", entry.username, username), ("url", entry.url, url))
                       if old != new]
            if changed:
                warnings.append(_cleaned_warning(entry.name, changed))
            incoming.append(
                _Incoming(
                    name=entry.name,
                    secret=Secret(password=secret.password, totp=secret.totp, notes=secret.notes,
                                  fields=dict(secret.fields), history=list(secret.history)),
                    username=username, url=url, tags=list(entry.tags), kind=entry.kind,
                    agent=entry.agent, created=entry.created, modified=entry.modified,
                    aliases=_aliases_of(backup, entry),
                )
            )
    finally:
        backup.close()
    return incoming


def _named(vault: Vault, name: str) -> Optional[Entry]:
    folded = name.casefold()
    return next((entry for entry in vault.entries.values() if entry.name.casefold() == folded), None)


def _same(vault: Vault, existing: Entry, item: _Incoming) -> bool:
    """True when *existing* already holds everything *item* would bring."""
    if existing.username != item.username or existing.url != item.url:
        return False
    secret = vault.read_secret(existing)
    return (
        secret.password == item.secret.password
        and secret.notes == item.secret.notes
        and (secret.totp or None) == (item.secret.totp or None)
        and secret.fields == item.secret.fields
    )


def _fit(base: str, suffix: str) -> str:
    return base[: _NAME_LIMIT - len(suffix)].rstrip() + suffix


def _renamed(vault: Vault, item: _Incoming) -> Tuple[str, Optional[Entry]]:
    """The first of ``NAME (imported)``, ``NAME (imported 2)`` ... that is free, or the one already holding *item*.

    Free means no entry has the name and an entry of that name would give no reference a second meaning
    (``Vault.conflict``). The suffix ends the name with a space and a parenthesis, which no field name or
    alias holds, so a name like ``github/password`` stops meaning a field of ``github`` once it has one.
    """
    suffix, number = " (imported)", 1
    while True:
        candidate = _fit(item.name, suffix)
        existing = _named(vault, candidate)
        if existing is None and vault.conflict(candidate, item.secret.fields) is None:
            return candidate, None
        if existing is not None and _same(vault, existing, item):
            return candidate, existing  # imported before: importing the same file twice adds nothing
        number += 1
        suffix = f" (imported {number})"


def _copy_secret(secret: Secret) -> Secret:
    return Secret(
        password=secret.password, totp=dict(secret.totp) if secret.totp else None, notes=secret.notes,
        fields=dict(secret.fields), history=[dict(item) for item in secret.history],
    )


def _place(vault: Vault, item: _Incoming, policy: str, keep_agent: bool) -> Tuple[_Outcome, Optional[Entry]]:
    """Add *item* to *vault* as *policy* says, or say why not.

    A name is taken when an entry has it, and also when an entry of that name would give a reference that
    works now a second meaning (an alias of that name, ``github/password`` beside ``github``): a file must
    never change what an existing reference hands out. Such a name is renamed or skipped as for a taken
    one; ``replace`` replaces only an entry of the same name, and renames for anything else.
    """
    existing = _named(vault, item.name)
    if existing is not None and _same(vault, existing, item):
        return _Outcome(item.name, existing.name, "skipped", "already in the vault"), None
    clash = vault.conflict(item.name, item.secret.fields) if existing is None else None
    try:
        if existing is not None and policy == "skip":
            return _Outcome(item.name, existing.name, "skipped", "an entry of that name exists"), None
        if clash is not None and policy == "skip":
            return _Outcome(item.name, item.name, "skipped", clash), None
        if existing is not None and policy == "replace":
            entry = vault.update(
                existing, secret=_copy_secret(item.secret), username=item.username, url=item.url,
                tags=item.tags or None, kind=item.kind, agent=item.agent if keep_agent else None,
            )
            return _Outcome(item.name, entry.name, "replaced"), entry
        name = item.name
        if existing is not None or clash is not None:
            name, earlier = _renamed(vault, item)
            if earlier is not None:
                return _Outcome(item.name, earlier.name, "skipped", "already in the vault"), None
        entry = vault.add(
            name, _copy_secret(item.secret), username=item.username, url=item.url, tags=item.tags, kind=item.kind,
            agent=item.agent if keep_agent else "deny", created=item.created, modified=item.modified,
        )
    except UsageError as exc:  # the vault will not hold it; its messages name the field, never the value
        return _Outcome(item.name, item.name, "skipped", str(exc)), None
    return _Outcome(item.name, entry.name, "added" if name == item.name else "renamed", clash or ""), entry


def _merge(
    vault: Vault, incoming: Sequence[_Incoming], policy: str, *, keep_agent: bool, warnings: List[str]
) -> Tuple[List[_Outcome], int]:
    """Add *incoming* to *vault* in memory. Returns what happened to each entry, and how many aliases were set."""
    earlier = {entry.name.casefold(): entry.id for entry in vault.entries.values()}
    outcomes: List[_Outcome] = []
    placed: List[Tuple[_Incoming, Entry]] = []
    for item in incoming:
        outcome, entry = _place(vault, item, policy, keep_agent)
        outcomes.append(outcome)
        if entry is not None:
            placed.append((item, entry))
    aliases = 0
    for item, entry in placed:
        for alias, target in item.aliases:
            current = vault.aliases.get(alias)
            if current is not None:
                if (current.entry, current.field) != (entry.id, target):
                    warnings.append(f"alias {alias} was not imported: it already names another value")
                continue
            shadowed = earlier.get(alias.casefold())
            if shadowed is not None and shadowed != entry.id:
                warnings.append(f"alias {alias} was not imported: an entry of that name is already in the vault")
                continue
            try:
                vault.set_alias(alias, entry, target)
            except (UsageError, NotFoundError) as exc:
                warnings.append(f"alias {alias} was not imported: {exc}")
                continue
            aliases += 1
    return outcomes, aliases


def cmd_import(ctx: Context, args: argparse.Namespace) -> int:
    _owner_only(ctx, "importing into the vault")
    bunker = paths.bunker_name()
    source = _absolute(args.path)
    fmt = interop.detect_format(source) if args.format == "auto" else args.format
    warnings: List[str] = []
    incoming: Optional[List[_Incoming]] = None
    if fmt != interop.FORMAT_IRONDOME:
        # Read before unlocking: a file that cannot be read never costs a password.
        incoming = [_from_interop(entry, warnings) for entry in interop.parse(source, fmt)]
    _require_vault(bunker)
    vault = ctx.open_vault(reason=f"import into IronDome bunker {bunker}")
    try:
        if incoming is None:
            incoming = _from_backup(ctx, source, warnings)
        outcomes, aliases = _merge(
            vault, incoming, args.on_conflict, keep_agent=fmt == interop.FORMAT_IRONDOME, warnings=warnings
        )
        counts = {action: sum(1 for item in outcomes if item.action == action)
                  for action in ("added", "renamed", "replaced", "skipped")}
        written = counts["added"] + counts["renamed"] + counts["replaced"]
        if written or aliases:
            _commit(vault)
            ctx.audit(
                vault, "import", target=str(source),
                detail=f"{fmt}: {written} imported, {counts['renamed']} renamed, {counts['replaced']} replaced, "
                f"{counts['skipped']} skipped, {aliases} aliases",
            )
    finally:
        vault.close()
    # Everything below can carry text from the file (names, aliases, what a parser said about them): never raw to
    # a terminal, where an escape sequence would retitle the window, rewrite these lines or fill the clipboard.
    warnings = [_printable(warning) for warning in warnings]
    for warning in warnings:
        ctx.out.warn(warning)
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "bunker": bunker, "source": str(source), "format": fmt, "imported": written,
                "renamed": counts["renamed"], "replaced": counts["replaced"], "skipped": counts["skipped"],
                "aliases": aliases, "warnings": warnings,
                "entries": [{**dataclasses.asdict(item), "reason": _printable(item.reason)} for item in outcomes],
            }
        )
        return 0
    if not outcomes:
        ctx.out.info(f"{source} holds no entries; nothing was imported.")
        return 0
    ctx.out.pairs(
        (
            ("imported", str(written)), ("renamed", str(counts["renamed"])), ("replaced", str(counts["replaced"])),
            ("skipped", str(counts["skipped"])), ("aliases", str(aliases)),
        )
    )
    details = [item for item in outcomes if item.action != "added"]
    if details:
        ctx.out.data()
        ctx.out.table(
            ("entry", "action", "now", "why"),
            ((_printable(item.source), item.action, _printable(item.name) if item.action != "skipped" else "-",
              _printable(item.reason) or "-") for item in details),
        )
    if written or aliases:
        ctx.out.ok(f"Imported {_count(written, 'entry', 'entries')} from {source} into bunker {bunker}.")
    else:
        ctx.out.info(f"Nothing was imported into bunker {bunker}: see the reasons above.")
    return 0


# ---------------------------------------------------------------------------
# migrate
# ---------------------------------------------------------------------------


def _read_legacy(
    ctx: Context, legacy: migrate_v3.LegacyVault, args: argparse.Namespace, keyless: bool
) -> Tuple[List[migrate_v3.LegacyEntry], Optional[SecureBuffer], bool]:
    """Decrypt the 3.x entries.

    Returns them, the 3.x master password (None for a vault without one), and whether the key came
    from the OS keychain rather than from the person asking.
    """
    if keyless:
        # Asked first, so that a keychain that cannot be reached here is never reported as one without the key.
        unreachable = migrate_v3.keychain_unreachable()
        if unreachable is None:
            ctx.out.info(
                "This 3.x vault has no master password: its key is in the OS keychain. "
                "The operating system may ask you to allow IronDome to read it."
            )
            try:
                stored = migrate_v3.keychain_master_key()
            except AuthError as exc:  # refused (macOS "Deny", or a locked keychain over SSH): ask for the key instead
                stored, missing = None, f"The OS keychain here did not hand over the 3.x key: {exc}."
            else:
                # secret-tool says the same for "no such entry" and for "no Secret Service running"
                missing = "The OS keychain here did not hand over the 3.x key."
            if stored is not None:
                try:
                    return migrate_v3.read_entries(legacy, master_key=stored), None, True
                finally:
                    wipe_bytes(stored)
        else:
            missing = (
                "This 3.x vault has no master password, and the OS keychain cannot be asked for its key: "
                f"{unreachable}."
            )
        if not ctx.password_stdin and not ctx.has_terminal:
            raise UsageError(
                f"{missing} Give the key 3.x kept there (its 'master_key' value) on standard input, with "
                "--legacy-key --password-stdin"
            )
        ctx.out.info(
            f"{missing} The key 3.x kept there (its 'master_key' value) is asked for instead: type it at the "
            "terminal, or pipe it in with --legacy-key --password-stdin."
        )
        key = ctx.read_secret("IronDome 3.x vault key (the 'master_key' value 3.x kept in the keychain): ")
        if key is None:
            raise UsageError("the 3.x vault key cannot be empty")
        try:
            return migrate_v3.read_entries(legacy, master_key=key), None, False
        finally:
            key.wipe()
    username = args.legacy_username or migrate_v3.stored_username(legacy)
    if not username:
        if not ctx.has_terminal:
            raise UsageError(
                "the 3.x master username cannot be read on this machine (it is tied to the computer's name); "
                "give it with --legacy-username"
            )
        username = ctx.ask("IronDome 3.x master username: ")
    password = ctx.read_secret("IronDome 3.x master password: ")
    if password is None:
        raise UsageError("the 3.x master password cannot be empty")
    try:
        return migrate_v3.read_entries(legacy, username=username, password=password), password, False
    except AuthError as exc:
        password.wipe()
        raise AuthError(
            f"{exc}. If this 3.x vault was set up without a master password (biometric only), run again with "
            "--legacy-key"
        ) from None
    except BaseException:
        password.wipe()
        raise


def _kdf_params(mib: Optional[int]) -> Optional[Argon2Params]:
    if mib is None:
        return None
    try:
        return Argon2Params(memory_kib=mib * 1024).validate()
    except VaultError as exc:
        raise UsageError(f"--kdf-memory-mib {mib} cannot be used: {exc}") from None


def _migration_password(
    ctx: Context, args: argparse.Namespace, legacy_password: Optional[SecureBuffer], bunker: str
) -> SecureBuffer:
    """The master password of the vault migrate creates. The caller wipes it."""
    if legacy_password is None or args.new_password:
        return ctx.new_master_password()
    keep = True
    if not args.keep_password and ctx.has_terminal and not ctx.password_stdin and not ctx.assume_yes:
        keep = ctx.confirm(f"Use your 3.x master password for the new vault in bunker {bunker} too?", default=True)
    if not keep:
        return ctx.new_master_password()
    if len(legacy_password) < MIN_PASSWORD_BYTES:
        if ctx.has_terminal and not ctx.password_stdin and not args.keep_password:
            ctx.out.info(
                f"Your 3.x master password is shorter than the {MIN_PASSWORD_BYTES} characters IronDome 4 needs; "
                "choose a new one."
            )
            return ctx.new_master_password()
        raise UsageError(
            f"the 3.x master password is shorter than the {MIN_PASSWORD_BYTES} characters IronDome 4 needs; "
            "run again with --new-password"
            + (" and give the new master password on the second line of stdin" if ctx.password_stdin else "")
        )
    return legacy_password.copy()


def _discard_new_vault(vault: Vault) -> None:
    """Undo a vault this command created and could not finish: its device keys, its file, its snapshots."""
    slots = list(vault.file.slots)
    vault.close()
    for slot in slots:
        with contextlib.suppress(IronDomeError):
            keys.destroy_slot_device(slot)
    for _, snapshot in _snapshot_files():
        with contextlib.suppress(OSError):
            paths.secure_delete(snapshot)
    with contextlib.suppress(OSError):
        paths.secure_delete(paths.vault_file())


def _verify_migration(vault: Vault, entries: Sequence[migrate_v3.LegacyEntry]) -> List[str]:
    """Compare every 3.x entry with the vault as it is now on disk, not as it is in memory."""
    reopened = Vault(VaultFile.load(), vault.vault_key.copy())
    try:
        return migrate_v3.verify(reopened, entries)
    finally:
        reopened.close()


def _destroy_old(ctx: Context, legacy: migrate_v3.LegacyVault) -> Dict[str, Any]:
    """Destroy the 3.x vault once the person confirmed it; never raises for what the run found."""
    question = (
        f"This deletes the IronDome 3.x vault in {legacy.path} for good, and its keychain entries when they "
        "are this vault's. Every entry was verified in the new vault."
    )
    if not ctx.assume_yes and not ctx.confirm_phrase(question, "DESTROY"):
        return {"done": False, "confirmed": False, "files_deleted": 0, "leftovers": [], "errors": [],
                "keychain_cleared": None}
    try:
        report = migrate_v3.destroy_legacy(legacy)
    except IronDomeError as exc:
        return {"done": False, "confirmed": True, "files_deleted": 0, "leftovers": [], "errors": [str(exc)],
                "keychain_cleared": None}
    return {
        "done": report.success, "confirmed": True, "files_deleted": len(report.files_deleted),
        "leftovers": list(report.leftovers), "errors": list(report.errors), "keychain_cleared": report.keychain_cleared,
    }


def cmd_migrate(ctx: Context, args: argparse.Namespace) -> int:
    _owner_only(ctx, "migrating a 3.x vault")
    bunker = paths.bunker_name()
    location = _absolute(args.from_dir) if args.from_dir else paths.legacy_v3_dir()
    legacy = migrate_v3.detect(location)
    if legacy is None:
        hint = "" if args.from_dir else "; point at one with --from DIR"
        raise NotFoundError(f"there is no IronDome 3.x vault in {location}{hint}")
    exists = vault_exists()
    creating = [
        flag
        for flag, given in (
            ("--mode", args.mode is not None), ("--no-recovery", args.no_recovery),
            ("--kdf-memory-mib", args.kdf_memory_mib is not None), ("--keep-password", args.keep_password),
            ("--new-password", args.new_password), ("--no-password", args.no_password),
        )
        if given
    ]
    if exists and creating:
        raise UsageError(
            f"bunker {bunker} already has a vault, so migrate adds the 3.x entries to it; "
            f"{', '.join(creating)} {'applies' if len(creating) == 1 else 'apply'} only when migrate creates the vault"
        )
    if args.no_password and args.mode != MODE_TOUCHID:
        raise UsageError("--no-password goes with --mode touchid: Touch ID alone, the recovery key as the fallback")
    if args.no_password and args.no_recovery:
        raise UsageError("a vault that opens with Touch ID alone needs the recovery key as its second way in")
    params = _kdf_params(args.kdf_memory_mib)
    keyless = args.legacy_key or legacy.mode == migrate_v3.MODE_BIOMETRIC_ONLY
    if keyless and args.keep_password:
        raise UsageError("this 3.x vault has no master password to keep; leave out --keep-password")
    if args.destroy_old and not ctx.assume_yes and not ctx.has_terminal:
        raise UsageError("--destroy-old must be confirmed by typing DESTROY at a terminal, or with --yes")

    entries, legacy_password, from_keychain = _read_legacy(ctx, legacy, args, keyless)
    if from_keychain and ctx.password_stdin:
        # Any process running as you can read that key: having it proves nothing about who is asking. So nothing
        # on stdin may open or choose the vault the entries go into (the first vault on a machine may be a
        # script's); a person types the password at a terminal, where a session does not count either.
        raise PolicyError(
            "this 3.x vault has no master password, and its key came from the OS keychain, which any program running "
            "as you can read, so it proves nothing about who is asking. Run migrate at a terminal without "
            "--password-stdin and type the master password there. Nothing was created, copied or destroyed."
        )
    created = False
    recovery: Optional[str] = None
    try:
        if exists:
            vault = ctx.open_vault(reason=f"migrate into IronDome bunker {bunker}", fresh=from_keychain)
        else:
            mode = args.mode or MODE_PASSWORD
            password = None if args.no_password else _migration_password(ctx, args, legacy_password, bunker)
            try:
                with _disk(f"the vault of bunker {bunker} could not be created"):
                    vault, recovery = create_vault(
                        mode=mode, password=password, with_recovery=not args.no_recovery, params=params
                    )
            finally:
                if password is not None:
                    password.wipe()
            created = True
    finally:
        if legacy_password is not None:
            legacy_password.wipe()
    try:
        try:
            report = migrate_v3.import_into(vault, entries)
            _commit(vault)
            problems = _verify_migration(vault, entries)
        except BaseException:
            if created:
                _discard_new_vault(vault)  # nothing was recorded yet, so nothing in the audit log names it
                recovery = None
            raise
        verified = not problems
        if created:
            ctx.audit(
                vault, "vault.create", target=bunker,
                detail=f"mode={args.mode or MODE_PASSWORD} recovery={'yes' if recovery else 'no'}, "
                "by migrate from IronDome 3.x",
            )
        ctx.audit(
            vault, "migrate", target=str(legacy.path),
            detail=f"{report.imported} imported, {len(report.renamed)} renamed, {len(report.skipped)} skipped, "
            f"verified={'yes' if verified else 'no'}",
        )
    finally:
        vault.close()

    renamed = [{"from": old, "to": new} for old, new in report.renamed]
    if not ctx.out.json_mode:
        _show_migration(ctx, bunker, legacy, report, problems, created)
    destroyed: Optional[Dict[str, Any]] = None
    if verified and args.destroy_old:
        destroyed = _destroy_old(ctx, legacy)
        if not ctx.out.json_mode:
            _show_destroyed(ctx, legacy, destroyed)
    elif verified and not ctx.out.json_mode:
        ctx.out.info(
            f"The 3.x vault in {legacy.path} was not changed. Once you have checked the new vault, remove it with: "
            f"irondome{_bunker_hint(bunker)} migrate --destroy-old"
            + ("" if args.from_dir is None else f" --from {legacy.path}")
        )
    if recovery and not ctx.out.json_mode:
        _show_recovery(ctx, recovery, f"the new vault of bunker {bunker}")
    legacy_destroyed = bool(destroyed and destroyed["done"])
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "bunker": bunker, "created": created, "legacy_path": str(legacy.path), "imported": report.imported,
                "renamed": renamed, "skipped": list(report.skipped), "cleaned": list(report.cleaned),
                "verified": verified, "problems": problems,
                "legacy_destroyed": legacy_destroyed, "destroy": destroyed, "recovery_key": recovery,
            }
        )
    if not verified:
        return 1
    return 1 if args.destroy_old and not legacy_destroyed else 0


def _show_migration(
    ctx: Context,
    bunker: str,
    legacy: migrate_v3.LegacyVault,
    report: migrate_v3.MigrationReport,
    problems: List[str],
    created: bool,
) -> None:
    ctx.out.pairs(
        (
            ("bunker", f"{bunker} (new vault)" if created else bunker),
            ("imported", str(report.imported)),
            ("renamed", str(len(report.renamed))),
            ("skipped", str(len(report.skipped))),
            ("verified", "yes" if not problems else f"no: {len(problems)} problems"),
        )
    )
    for old, new in report.renamed:  # the 3.x website is whatever the old file held: never raw to a terminal
        ctx.out.data(f"renamed   {_printable(old)} -> {_printable(new)}")
    for reason in report.skipped:
        ctx.out.data(f"skipped   {_printable(reason)}")
    for note in report.cleaned:
        ctx.out.data(f"cleaned   {_printable(note)}")
    if problems:
        for problem in problems:
            ctx.out.warn(problem)
        ctx.out.error(
            "the migrated vault does not match the 3.x vault for the entries above; the 3.x vault was left as it was"
        )
    else:
        ctx.out.ok(
            f"Migrated the IronDome 3.x vault in {legacy.path} into bunker {bunker}; every entry was compared "
            "with the original after it was written."
        )


def _show_destroyed(ctx: Context, legacy: migrate_v3.LegacyVault, destroyed: Dict[str, Any]) -> None:
    if not destroyed["confirmed"]:
        ctx.out.info(f"Not confirmed: the 3.x vault in {legacy.path} was left as it was.")
        return
    if destroyed["done"]:
        # A destruction that succeeded either cleared the keychain or had nothing of this vault's to clear there.
        keychain = (
            "its OS keychain entries were removed"
            if destroyed["keychain_cleared"]
            else "the OS keychain was not touched (it holds nothing of this vault's, or is not reachable here)"
        )
        deleted = _count(destroyed["files_deleted"], "file")
        ctx.out.ok(f"Destroyed the 3.x vault in {legacy.path}: {deleted} deleted; {keychain}.")
        return
    for problem in destroyed["errors"] + [f"left on disk: {path}" for path in destroyed["leftovers"]]:
        ctx.out.warn(problem)
    ctx.out.error(f"the 3.x vault in {legacy.path} was not completely destroyed")


# ---------------------------------------------------------------------------
# rekey
# ---------------------------------------------------------------------------


def _rekey_password(ctx: Context, old: Vault, captured: Optional[SecureBuffer]) -> Optional[SecureBuffer]:
    """The master password every new password slot is wrapped under, checked against the old slots."""
    slots = old.slots(KIND_PASSWORD)
    if not slots:
        if captured is not None:
            captured.wipe()
        return None
    if captured is not None and len(slots) == 1:
        return captured  # it is what just opened the vault
    if captured is None:
        ctx.out.info("The vault opened without the master password; it is needed once more for its password keyslot.")
        captured = ctx.master_password("make the vault's new password keyslot")
    try:
        for slot in slots:
            keys.open_slot(
                slot, old.vault_id, password=captured, interactive=ctx.has_terminal, reason="re-key your vault"
            ).wipe()
    except AuthError:
        captured.wipe()
        raise AuthError(
            "that master password does not open every password keyslot of this vault; re-keying needs one that does"
        ) from None
    except BaseException:
        captured.wipe()
        raise
    return captured


def _mirror(
    slot: Keyslot, vault_key: SecureBuffer, vault_id: bytes, password: Optional[SecureBuffer]
) -> Tuple[Keyslot, Optional[str]]:
    """A new keyslot of the kind, policy, label and cost of *slot*, for the new vault key.

    Device secrets are enrolled anew on the strongest backend that can enforce
    the slot's policy, as ``init`` chooses one. A recovery slot gets a new key,
    returned to be shown once.
    """
    if slot.kind == KIND_RECOVERY:
        return keys.create_recovery_slot(vault_key, vault_id, label=slot.label or "recovery key")
    if slot.kind == KIND_DEVICE:
        touch = slot.policy or POLICY_BIOMETRY
        made = keys.create_device_slot(
            vault_key, vault_id, backend=devices.choose_backend(touch), policy=touch, label=slot.label
        )
        return made, None
    if password is None:
        raise UsageError("a password keyslot cannot be re-created without the master password")
    params = Argon2Params.from_dict(slot.kdf) if slot.kdf else default_argon2()
    policy = slot.policy or POLICY_DEVICE
    # A password slot without a device factor (a portable vault in use as the live one) stays without one.
    backend = devices.choose_backend(policy) if slot.device is not None else None
    made = keys.create_password_slot(
        vault_key, password, vault_id, params=params, backend=backend, policy=policy, label=slot.label
    )
    return made, None


def _live_vault_id() -> Optional[bytes]:
    try:
        return VaultFile.load().vault_id
    except VaultError:
        return None


def _new_slots(
    old: Vault, vault_key: SecureBuffer, vault_id: bytes, password: Optional[SecureBuffer], made: List[Keyslot]
) -> List[str]:
    """Mirror every keyslot of *old* into *made*. Returns the new recovery keys. Wipes *vault_key* if it fails."""
    recovery: List[str] = []
    try:
        for slot in old.file.slots:
            mirrored, shown = _mirror(slot, vault_key, vault_id, password)
            made.append(mirrored)
            if shown:
                recovery.append(shown)
    except BaseException:
        vault_key.wipe()
        raise
    return recovery


def _staging_files() -> List[Path]:
    """The re-keyed vaults ``_rekey`` builds beside the live one, still there when a re-key did not finish."""
    return caps.rekey_staging_files()


def _identity(descriptor: Dict[str, Any]) -> str:
    return json.dumps(descriptor, sort_keys=True, default=str)


def _destroy_device(descriptor: Dict[str, Any]) -> bool:
    """Destroy the device secret *descriptor* names. Returns whether it was on this machine; raises if it survives.

    A backend that cannot even say whether it holds the secret counts as holding it if it works here at all,
    as ``caps.destroy_device`` decides. One that does not work here holds nothing only if it belongs to another
    system (a TPM key named on a Mac); this system's own chip out of reach for now (tpm2-tools gone, the TPM
    closed to you) may still hold it, so that raises, and the caller keeps it to try again.
    """
    try:
        backend = devices.get_backend(str(descriptor.get("backend")))
    except IronDomeError:
        return False  # a backend this installation cannot even load holds nothing on this machine
    try:
        present = backend.exists(descriptor)
    except IronDomeError as exc:
        try:
            present = backend.probe().available
        except IronDomeError:
            present = False
        if not present and devices.applies_here(backend.name):
            raise HardwareError(f"the {backend.name} device key could not be checked: {exc}") from None
    if not present:
        return False
    backend.destroy(descriptor)
    if backend.exists(descriptor):
        raise HardwareError(f"the {backend.name} device key survived destruction")
    return True


def _held_devices(value: Any) -> List[Dict[str, Any]]:
    """``{"label": ..., "device": {...}}`` items of a retirement plan; anything malformed is left out."""
    items = []
    for item in value if isinstance(value, list) else []:
        device = item.get("device") if isinstance(item, dict) else None
        if isinstance(device, dict) and isinstance(device.get("backend"), str):
            items.append({"label": str(item.get("label") or "a keyslot"), "device": dict(device)})
    return items


def _retirement_plan(old: Vault) -> Dict[str, Any]:
    """What making *old* open nothing takes: every device secret it is bound to, and what an earlier re-key left.

    The plan travels in the encrypted index of the vault that replaces *old*, from the moment that one is live,
    until it is carried out: whatever stops a re-key after the switch, the next one finds it there.
    """
    inherited = old.meta.get(_REKEY_PLAN)
    inherited = inherited if isinstance(inherited, dict) else {}
    devices_left: List[Dict[str, Any]] = [
        {"label": f"the keyslot '{slot.label or slot.kind}'", "device": dict(slot.device)}
        for slot in old.file.slots
        if slot.device is not None
    ]
    for descriptor in caps.bound_devices(old):
        # Every device secret a session or grant of the old vault was bound to: the one its index records and
        # each one that replaced. Once they are gone, no copy of their files opens on this machine either,
        # whichever token is presented.
        devices_left.append({"label": "the old sessions and grants", "device": descriptor})
    devices_left += _held_devices(inherited.get("devices"))
    unique: Dict[str, Dict[str, Any]] = {}
    for item in devices_left:
        unique.setdefault(_identity(item["device"]), item)
    return {"from": old.vault_id.hex(), "devices": list(unique.values())}


def _sweep_staging(live: Vault, leftovers: List[str]) -> int:
    """Remove what re-keys that stopped before their switch left: staging files, and device keys only those use.

    Called with the bunker's lock held, so no re-key is building one now. A staging file of the live vault
    itself (a re-key that stopped after its switch) is only deleted: its device keys are the live ones, and what
    the old vault left to destroy is in the live vault's plan. Returns how many device keys were destroyed.
    """
    used = {_identity(slot.device) for slot in live.file.slots if slot.device is not None}
    destroyed = 0
    for path in _staging_files():
        try:
            staged: Optional[VaultFile] = VaultFile.load(path)
        except VaultError:
            staged = None  # unreadable: nothing in it can be trusted to name a device key
        if staged is not None and staged.vault_id != live.vault_id:
            for slot in staged.slots:
                if slot.device is None or _identity(slot.device) in used:
                    continue
                try:
                    if _destroy_device(slot.device):
                        destroyed += 1
                except IronDomeError as exc:
                    leftovers.append(f"a device key left by an interrupted re-key was not destroyed: {exc}")
        try:
            paths.secure_delete(path)
        except OSError as exc:
            leftovers.append(f"{path} (left by an interrupted re-key) could not be deleted: {exc.strerror or exc}")
    return destroyed


def _rekey(old: Vault, password: Optional[SecureBuffer]) -> Tuple[Vault, List[str], Path]:
    """Build the re-keyed vault beside the old one and put it in place. Returns it, its recovery keys, the staging file.

    Holds the bunker's lock throughout. Before the switch, every keyslot device secret involved, old and new, is
    recorded with :func:`irondome.keys.record_retirement`, and the new vault carries in its encrypted index what
    the old one leaves to destroy (:func:`_retirement_plan`). So whatever stops a re-key, nothing is lost: until
    the live file is replaced, a failure destroys what was made (the new device keys, the staging file) and
    leaves the old vault exactly as it was, and after a crash the next command that finishes keyslot changes
    destroys the new device keys; once the switch has happened, nothing is undone and nothing stops the re-key,
    and after a crash the next command destroys the old keyslot device keys and the next re-key everything else.
    """
    vault_id = os.urandom(keys.VAULT_ID_LEN)
    staging = paths.home() / f"{_STAGING_PREFIX}{os.urandom(8).hex()}{_STAGING_SUFFIX}"
    made: List[Keyslot] = []
    fresh: Optional[Vault] = None
    recovery: List[str] = []
    with paths.file_lock(paths.lock_file()):
        try:
            vault_key = keys.new_vault_key()
            recovery = _new_slots(old, vault_key, vault_id, password, made)
            keys.record_retirement([*old.file.slots, *made])
            fresh = Vault.create(vault_key, made, vault_id, staging)  # owns the key from here; wipes it on failure
            # Entries and aliases only. The old index's meta names the old capability device secret, which the
            # plan destroys: the new vault gets a new one with its first session or grant.
            old.copy_into(fresh)
            fresh.meta[_REKEY_PLAN] = _retirement_plan(old)
            # The audit log is sealed under a key of the old vault key. What reads it, and what reads the
            # logs of the vault keys before, travels in the new vault's encrypted index from the switch on.
            # Losing that costs the history, never the re-key.
            with contextlib.suppress(Exception):
                audit.carry_keys(old, fresh)
            fresh.commit(snapshots=0)
            data = paths.read_file(staging)
            current = VaultFile.load()
            if current.vault_id != old.vault_id or current.generation != old.file.generation:
                raise VaultError("the vault changed on disk while it was being re-keyed; nothing was replaced")
            paths.write_atomic(paths.vault_file(), data)
        except BaseException as exc:
            if fresh is None or _live_vault_id() != vault_id:
                if fresh is not None:
                    fresh.close()
                for slot in made:
                    with contextlib.suppress(Exception):
                        keys.destroy_slot_device(slot)
                with contextlib.suppress(Exception):
                    keys.finish_retirement()  # the old vault is live, so this keeps its keys and clears the record
                with contextlib.suppress(OSError):
                    paths.secure_delete(staging)
                if isinstance(exc, OSError):
                    raise VaultError(
                        f"re-keying failed ({exc.strerror or exc}); the vault was left as it was"
                    ) from None
                raise
            # The switch happened: the new device keys are what opens the vault now, so the re-key goes on.
    if fresh is None:  # not reached: without a new vault there is no switch, and the failure was raised above
        raise VaultError("re-keying failed; the vault was left as it was")
    fresh.path = paths.vault_file()
    return fresh, recovery, staging


def _retire(
    ctx: Context, old: Vault, fresh: Vault, staging: Path, *, keep_staging: bool = False
) -> Dict[str, Any]:
    """After the switch: make everything that opened the old vault open nothing. Reports what it could not do.

    Every step can be repeated: what is already gone is skipped, so the next re-key carries out whatever an
    interrupted one left in its plan. The audit log comes first, so that whatever runs after an interruption
    writes to the new vault's chain; the plan is updated last, keeping only what could not be destroyed. The
    staging file is deleted unless *keep_staging* (``rekey`` deletes it itself, last of all).
    """
    leftovers: List[str] = []
    plan = fresh.meta.get(_REKEY_PLAN)
    held = _held_devices(plan.get("devices")) if isinstance(plan, dict) else []
    ctx.audit(old, "rekey", detail=f"the vault key was replaced; the new vault id is {fresh.vault_id.hex()}")
    try:
        archived = audit.archive()
    except IronDomeError as exc:
        archived = None
        leftovers.append(f"the audit log could not be archived: {exc}")
    ctx.audit(
        fresh, "rekey",
        detail=f"new vault key; previous vault id {old.vault_id.hex()}"
        + (f"; earlier records are in {archived.name}" if archived else ""),
    )
    used = {_identity(slot.device) for slot in fresh.file.slots if slot.device is not None}
    destroyed = 0
    kept: List[Dict[str, Any]] = []
    for item in held:
        if _identity(item["device"]) in used:
            continue  # never one the new vault is opened with
        try:
            if _destroy_device(item["device"]):
                destroyed += 1
        except IronDomeError as exc:
            kept.append(item)
            leftovers.append(f"the old device key of {item['label']} was not destroyed: {exc}")
    # The record made before the switch names the old keyslots' device keys, gone by now unless one could not be
    # destroyed above, and the new ones, which the vault uses: finishing it clears it.
    leftovers.extend(keys.finish_retirement())
    try:
        purged = old.purge_snapshots()
    except OSError as exc:
        purged = 0
        leftovers.append(f"a snapshot opened by the old keys could not be deleted: {exc.strerror or exc}")
    try:
        ended = caps.destroy_all()
    except IronDomeError as exc:
        ended = 0
        leftovers.append(f"sessions and grants: {exc}")
    if kept and isinstance(plan, dict):
        fresh.meta[_REKEY_PLAN] = {**plan, "devices": kept}  # the next re-key tries these again
    else:
        fresh.meta.pop(_REKEY_PLAN, None)
    try:
        fresh.commit(snapshots=0)
    except (IronDomeError, OSError) as exc:
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else exc
        leftovers.append(f"the re-keyed vault could not be updated ({reason}); run irondome rekey again to finish")
    if not keep_staging:
        with contextlib.suppress(OSError):
            paths.secure_delete(staging)
    return {"device_keys_destroyed": destroyed, "snapshots_deleted": purged, "sessions_and_grants_ended": ended,
            "audit_archive": str(archived) if archived else None, "leftovers": leftovers}


def _show_recovery_keys(ctx: Context, bunker: str, recovery: List[str]) -> None:
    for index, key in enumerate(recovery):
        if index:
            ctx.out.data()  # one key per line, even where each is printed bare
        _show_recovery(ctx, key, f"bunker {bunker}")


def _show_unfinished(ctx: Context, bunker: str, fresh: Vault, recovery: List[str]) -> None:
    """The re-key stopped after its switch: the new recovery key is the only one that opens the vault, so show it.

    *recovery* holds the keys not shown yet (none in human mode, where they go out right after the switch).
    """
    try:
        if ctx.out.json_mode:
            ctx.out.json({"bunker": bunker, "vault_id": fresh.vault_id.hex(), "entries": len(fresh.entries),
                          "recovery_keys": recovery, "finished": False})
        ctx.out.warn(
            f"the re-key of bunker {bunker} stopped after the new vault key took over, before everything the old "
            "one opens was destroyed. Until it finishes, no session or grant can be used. Run irondome rekey "
            "again: it finishes what this one could not."
        )
        if not ctx.out.json_mode:
            _show_recovery_keys(ctx, bunker, recovery)
    except Exception:  # noqa: S110 - this runs while another exception is on its way out; that one is reported
        pass


def cmd_rekey(ctx: Context, args: argparse.Namespace) -> int:
    _owner_only(ctx, "re-keying the vault")
    bunker = paths.bunker_name()
    _require_vault(bunker)
    if not ctx.assume_yes and not ctx.has_terminal:
        raise UsageError("rekey must be confirmed by typing REKEY at a terminal, or with --yes; nothing was changed")
    file = VaultFile.load()
    vault_key, password = _unlock_file(ctx, file, reason=f"re-key IronDome bunker {bunker}", keep_password=True)
    try:
        old = Vault(file, vault_key)
    except BaseException:
        if password is not None:
            password.wipe()
        raise
    try:
        question = (
            f"Re-key bunker {bunker}: every entry is re-encrypted under a new vault key, every session and grant "
            "ends, the snapshots are deleted and the audit log is archived."
        )
        if not ctx.assume_yes and not ctx.confirm_phrase(question, "REKEY"):
            ctx.out.info("Nothing was changed.")
            return 1
        password = _rekey_password(ctx, old, password)
        leftovers: List[str] = []
        # Held from the first check to the last write: no other command changes the vault in between, and no
        # other re-key can be building a staging file that the sweep below would take for an abandoned one.
        with paths.file_lock(paths.lock_file()):
            current = VaultFile.load()
            if current.vault_id != old.vault_id or current.generation != old.file.generation:
                raise VaultError("the vault changed on disk since it was unlocked; nothing was re-keyed. Run it again")
            leftovers.extend(keys.finish_retirement())  # an interrupted keyslot change or re-key, finished first
            swept = _sweep_staging(old, leftovers)
            fresh, recovery, staging = _rekey(old, password)
            finished = False
            shown = False
            try:
                # From the switch on, the new recovery key is the only one that opens the vault: it goes out
                # before anything that a crash could stop. With --json, stdout holds one document, written at
                # the end; a re-key killed before then is reported by every later command (caps.unfinished_rekey)
                # until `irondome rekey` finishes it and shows a new recovery key.
                if not ctx.out.json_mode:
                    _show_recovery_keys(ctx, bunker, recovery)
                    shown = True
                outcome = _retire(ctx, old, fresh, staging, keep_staging=True)
                outcome["device_keys_destroyed"] += swept
                outcome["leftovers"] = leftovers + outcome["leftovers"]
                count = len(fresh.entries)
                slots = [
                    {"kind": slot.kind, "label": slot.label, "backend": slot.backend_name, "policy": slot.policy}
                    for slot in fresh.file.slots
                ]
                new_id = fresh.vault_id.hex()
                finished = True
            finally:
                if not finished:
                    _show_unfinished(ctx, bunker, fresh, [] if shown else recovery)
                fresh.close()
        had_recovery = any(slot.kind == KIND_RECOVERY for slot in old.file.slots)
    finally:
        old.close()
        if password is not None:
            password.wipe()
    if ctx.out.json_mode:
        document = {"bunker": bunker, "vault_id": new_id, "entries": count, "keyslots": slots,
                    "recovery_keys": recovery, "finished": True}
        document.update(outcome)
        ctx.out.json(document)
    else:
        _show_rekey(ctx, bunker, count, slots, outcome)
    # Warnings are conversation: they reach stderr whether or not the result is JSON.
    if had_recovery:
        ctx.out.warn(
            "copies of the vault file made before now (backups, synced folders) still open with the OLD recovery "
            "key. Delete them, or treat that key as known to whoever has them."
        )
    for leftover in outcome["leftovers"]:
        ctx.out.warn(_printable(leftover))
    # Last of all, once the recovery key is out: while this file is there, the re-key has not finished.
    with contextlib.suppress(OSError):
        paths.secure_delete(staging)
    return 1 if outcome["leftovers"] else 0


def _show_rekey(ctx: Context, bunker: str, count: int, slots: List[Dict[str, Any]], outcome: Dict[str, Any]) -> None:
    ctx.out.ok(
        f"Re-keyed bunker {bunker}: a new vault key and vault id, {_count(count, 'entry', 'entries')} re-encrypted, "
        f"{_count(len(slots), 'keyslot')} made anew."
    )
    ctx.out.info(
        f"Ended {_count(outcome['sessions_and_grants_ended'], 'session or grant', 'sessions and grants')}, deleted "
        f"{_count(outcome['snapshots_deleted'], 'snapshot')} and destroyed "
        f"{_count(outcome['device_keys_destroyed'], 'old device key')}."
    )
    if outcome["audit_archive"]:
        ctx.out.info(
            f"The audit log was archived as {outcome['audit_archive']}. Read or check it with: "
            f"irondome audit --archive {Path(outcome['audit_archive']).name}"
        )
    ctx.out.info("Portable backups made with `irondome export` are not affected: they open with their own password.")


# ---------------------------------------------------------------------------
# nuke
# ---------------------------------------------------------------------------


def _recovery_caveat(bunkers: Sequence[str]) -> str:
    names = list(bunkers)
    named = names[0] if len(names) < 2 else f"{', '.join(names[:-1])} and {names[-1]}"
    if len(names) == 1:
        where = f"any copy of the vault file of bunker {named} that survives elsewhere"
        which = "a recovery key on paper: destroy it"
    else:
        where = f"any copy of the vault files of bunkers {named} that survives elsewhere"
        which = "recovery keys on paper: destroy them"
    return (
        f"a recovery key still opens {where} (a backup, a synced folder, a copy on another disk). nuke cannot "
        f"reach {which}, and those copies, yourself."
    )


def _show_plan(ctx: Context, plan: nuke.NukePlan, include_legacy: bool) -> None:
    say = ctx.out.info
    say("This destroys everything IronDome keeps on this machine:")
    say(f"  bunkers              {', '.join(plan.bunkers) or 'none'}")
    if plan.device_keys:
        described = "; ".join(
            f"{key.bunker}: {key.backend} ({'security chip' if key.hardware else 'file'}"
            f"{'' if key.present else ', already gone'})"
            for key in plan.device_keys
        )
        say(f"  device keys          {len(plan.device_keys)} ({described})")
    say(f"  sessions and grants  {plan.capabilities}")
    say(f"  files                {len(plan.files)}, under {plan.root} and {plan.device_root}")
    say("  also                 the default-bunker setting and the compiled Secure Enclave helper, if any")
    if plan.unreadable_vaults:
        say(
            f"The vault file of {', '.join(plan.unreadable_vaults)} cannot be read; its device keys are found by "
            "asking each backend instead."
        )
    if plan.foreign:
        say("Left in place, because IronDome did not create them:")
        for path in plan.foreign:
            say(f"  {path}")
    if plan.legacy_vault:
        if include_legacy:
            say(f"The IronDome 3.x vault in {plan.legacy_vault} is destroyed as well.")
        else:
            say(f"The IronDome 3.x vault in {plan.legacy_vault} is not touched; add --include-legacy to destroy it.")
    if plan.recovery_bunkers:
        ctx.out.warn(_recovery_caveat(plan.recovery_bunkers))


def _destroy_legacy_for_nuke() -> Dict[str, Any]:
    try:
        legacy = migrate_v3.detect()
        if legacy is None:
            return {"success": True, "files_deleted": [], "leftovers": [], "errors": [], "keychain_cleared": None}
        report = migrate_v3.destroy_legacy(legacy)
    except IronDomeError as exc:
        return {"success": False, "files_deleted": [], "leftovers": [], "errors": [str(exc)], "keychain_cleared": None}
    return _plain(report)


def _prove_for_nuke(ctx: Context, plan: nuke.NukePlan) -> None:
    """With --password-stdin: one master password must open every vault nuke destroys that can be read.

    A flag proves nothing, an agent can pass it; the password does. A vault that cannot be read
    cannot check it, so at least one must be readable.
    """
    readable = []
    for bunker in plan.bunkers:
        try:
            readable_vault(bunker)
        except VaultError:
            continue  # missing or damaged: nothing here can check a password against it
        readable.append(bunker)
    if not readable:
        raise PolicyError(
            "no vault nuke would destroy can be read, so the master password given with --password-stdin cannot be "
            "checked against anything. Run nuke at a terminal and type DESTROY. Nothing was destroyed."
        )
    password = ctx.master_password()
    try:
        for bunker in readable:
            try:
                ctx.check_master_password(password, bunker=bunker, reason="destroy every IronDome bunker here")
            except (AuthError, HardwareError, VaultError) as exc:
                raise type(exc)(
                    f"nuke --password-stdin needs one master password that opens every vault it destroys, and the one "
                    f"given does not open the vault of bunker {bunker} ({exc}). Run nuke at a terminal and type "
                    "DESTROY, or remove the bunkers one at a time, each with its own master password: "
                    "irondome bunker rm NAME --yes --password-stdin. Nothing was destroyed."
                ) from None
    finally:
        password.wipe()


def cmd_nuke(ctx: Context, args: argparse.Namespace) -> int:
    _owner_only(ctx, "nuke")
    if args.yes_destroy_everything and not ctx.password_stdin:
        raise UsageError(
            "--yes-destroy-everything skips typing DESTROY only together with --password-stdin and a master password "
            "that opens every vault on this machine: an agent can pass --yes-destroy-everything, it cannot pass "
            "your password. At a terminal, leave it out and type DESTROY. Nothing was destroyed."
        )
    plan = nuke.plan()
    include_legacy = bool(args.include_legacy and plan.legacy_vault)
    if plan.nothing_to_do and not include_legacy:
        if ctx.out.json_mode:
            ctx.out.json({"plan": _plain(plan), "report": None, "legacy": None, "success": True,
                          "nothing_to_do": True})
        else:
            ctx.out.info("There is nothing of IronDome's on this machine to destroy.")
            for path in plan.foreign:
                ctx.out.info(f"  left in place (not IronDome's): {path}")
        return 0
    _show_plan(ctx, plan, bool(args.include_legacy))
    if not args.yes_destroy_everything and not ctx.has_terminal:
        raise UsageError(
            "nuke destroys every bunker on this machine and cannot be undone: confirm it by typing DESTROY at "
            "a terminal, or pass --yes-destroy-everything with --password-stdin and the master password. "
            "Nothing was destroyed."
        )
    if ctx.password_stdin:
        _prove_for_nuke(ctx, plan)
    if not args.yes_destroy_everything and not ctx.confirm_phrase("This cannot be undone.", "DESTROY"):
        ctx.out.info("Nothing was destroyed.")
        return 1
    report = nuke.execute()
    legacy = _destroy_legacy_for_nuke() if include_legacy else None
    success = report.success and (legacy is None or bool(legacy["success"]))
    caveat = sorted(set(report.recovery_bunkers) | set(plan.recovery_bunkers))
    if ctx.out.json_mode:
        ctx.out.json({"plan": _plain(plan), "report": _plain(report), "legacy": legacy, "success": success,
                      "nothing_to_do": False})
    else:
        _show_nuked(ctx, report, legacy, success)
    if caveat:
        ctx.out.warn(_recovery_caveat(caveat))
    return 0 if success else 1


def _show_nuked(ctx: Context, report: nuke.NukeReport, legacy: Optional[Dict[str, Any]], success: bool) -> None:
    how = (
        "all held by a security chip"
        if report.hardware_backed
        else "not all held by a security chip: a file is overwritten and unlinked, which on an SSD is best "
        "effort, and a software TPM forgets a key only as well as its own storage does"
    )
    rows = [
        ("bunkers destroyed", ", ".join(report.bunkers) or "none"),
        ("device keys destroyed", f"{report.device_keys_destroyed} ({how})" if report.device_keys_destroyed else "0"),
        ("files deleted", str(len(report.files_deleted))),
    ]
    if legacy is not None:
        rows.append(("3.x vault", "destroyed" if legacy["success"] else "not completely destroyed"))
    ctx.out.pairs(rows)
    for path in report.foreign:
        ctx.out.info(f"left in place (not created by IronDome): {path}")
    problems = list(report.errors) + [f"left on disk: {path}" for path in report.leftovers]
    if legacy is not None:
        problems += [f"3.x vault: {error}" for error in legacy["errors"]]
        problems += [f"3.x vault, left on disk: {path}" for path in legacy["leftovers"]]
    for problem in problems:
        ctx.out.warn(problem)
    if success:
        ctx.out.ok(
            "Destroyed every bunker on this machine. Their device keys are gone, so no copy of those vault files "
            "opens with a master password any more."
        )
    else:
        ctx.out.error(f"nuke did not finish: {len(problems)} things above are left or went wrong")


# ---------------------------------------------------------------------------
# doctor, version
# ---------------------------------------------------------------------------


def _yes(value: Any) -> str:
    return {True: "yes", False: "no"}.get(value, "unknown")


def _note_unfinished_rekey(report: Dict[str, Any]) -> None:
    """Add to doctor's *report* the finding for a re-key that stopped after its switch (caps.unfinished_rekey)."""
    staged = caps.unfinished_rekey()
    if staged is None:
        return
    report.setdefault("findings", []).insert(0, {
        "severity": "problem", "check": "rekey", "message": caps.unfinished_rekey_warning(staged),
        "remedy": "irondome rekey",
    })
    report["problems"] = int(report.get("problems") or 0) + 1


def cmd_doctor(ctx: Context, args: argparse.Namespace) -> int:
    report = doctor.collect()
    _note_unfinished_rekey(report)
    if ctx.out.json_mode:
        ctx.out.json(report)
        return 1 if doctor.has_problem(report) else 0
    vault = report.get("vault") or {}
    memory = report.get("memory") or {}
    clipboard = report.get("clipboard") or {}
    helper = report.get("secure_enclave_helper")
    where = "none" if not vault.get("present") else vault.get("path", "")
    if vault.get("readable"):
        where += f", generation {vault.get('generation')}"
    rows = [
        ("irondome", report["irondome"]),
        ("python", f"{report['python']} ({report['platform']['implementation']})"),
        ("cryptography", f"{report['cryptography']}, {report['openssl']}"),
        ("platform", f"{report['platform']['name']} ({report['platform']['machine']})"),
        ("bunker", f"{report.get('bunker')} (on this machine: {', '.join(report.get('bunkers') or []) or 'none'})"),
        ("vault", where),
        ("new vaults use", report.get("new_vault_backend") or "unknown until the Secure Enclave helper is compiled"),
        ("memory locking", _yes(memory.get("locking"))),
        ("core dumps off", _yes(memory.get("core_dumps_disabled"))),
        ("clipboard", clipboard.get("tool") or "none"),
    ]
    if helper is not None:
        rows.append(("enclave helper", ("compiled" if helper.get("built") else "not compiled")
                     + f", source sha256 {helper.get('source_sha256')}"))
    ctx.out.pairs(rows)
    ctx.out.data()
    ctx.out.table(
        ("backend", "available", "kind", "detail"),
        ((item["name"], _yes(item["available"]) if item["probed"] else "not probed",
          "chip" if item["hardware"] else "file", item["detail"]) for item in report["backends"]),
    )
    if vault.get("keyslots"):
        ctx.out.data()
        ctx.out.table(
            ("keyslot", "kind", "device key", "description"),
            ((slot["id"], slot["kind"],
              "-" if slot["device_key_present"] is None else ("present" if slot["device_key_present"] else "MISSING"),
              slot["description"]) for slot in vault["keyslots"]),
        )
    ctx.out.data()
    for finding in report["findings"]:
        ctx.out.data(f"{finding['severity']:<8} {finding['check']}: {finding['message']}")
        if finding["remedy"]:
            ctx.out.data(f"{'':<8} fix: {finding['remedy']}")
    return 1 if doctor.has_problem(report) else 0


def cmd_version(ctx: Context, args: argparse.Namespace) -> int:
    found = doctor.versions()
    if ctx.out.json_mode:
        ctx.out.json(
            {"version": found["irondome"], "python": found["python"], "cryptography": found["cryptography"],
             "openssl": found["openssl"]}
        )
    else:
        ctx.out.data(f"irondome {found['irondome']}")
    return 0


# ---------------------------------------------------------------------------
# completion
# ---------------------------------------------------------------------------


@dataclass
class _Option:
    strings: List[str]
    value: str  # "" when it takes no value; else "file", "dir", "any" or "choices a b c"
    help: str


@dataclass
class _Node:
    path: str
    help: str
    options: List[_Option] = field(default_factory=list)
    positionals: List[str] = field(default_factory=list)
    children: Dict[str, "_Node"] = field(default_factory=dict)

    def walk(self) -> List["_Node"]:
        nodes = [self]
        for child in self.children.values():
            nodes.extend(child.walk())
        return nodes


def _value_kind(action: argparse.Action) -> str:
    if action.choices:
        return "choices " + " ".join(str(choice) for choice in action.choices)
    metavar = action.metavar if isinstance(action.metavar, str) else str(action.dest or "")
    if metavar.upper() in ("PATH", "FILE"):
        return "file"
    if metavar.upper() in ("DIR", "DIRECTORY"):
        return "dir"
    return "any"


def _tree(parser: argparse.ArgumentParser, path: str = "", summary: str = "") -> _Node:
    """The commands, subcommands, options and arguments of *parser*, read from argparse's own tables."""
    node = _Node(path=path, help=summary)
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            helps = {choice.dest: choice.help or "" for choice in action._choices_actions}
            for name, sub in action.choices.items():
                node.children[name] = _tree(sub, f"{path} {name}".strip(), helps.get(name, ""))
        elif action.option_strings:
            value = "" if action.nargs == 0 else _value_kind(action)
            if action.help != argparse.SUPPRESS:
                node.options.append(_Option(list(action.option_strings), value, action.help or ""))
        else:
            node.positionals.append(_value_kind(action))
    return node


def _sq(text: str) -> str:
    """*text* as one single-quoted word for bash and zsh."""
    return "'" + text.replace("'", "'\\''") + "'"


def _fish_quote(text: str) -> str:
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _case_table(function: str, comment: str, cases: List[Tuple[str, str]]) -> List[str]:
    """A bash/zsh function that prints the value for its key with ``case``. Keys and values are pre-quoted."""
    lines = [f"# {comment}", f"{function}() {{", '    case "$1" in']
    for key, value in cases:
        lines.append(f"        {key}) printf '%s\\n' {value} ;;")
    lines += ["    esac", "}", ""]
    return lines


def _shell_tables(tree: _Node, *, describe: bool) -> List[str]:
    commands: List[Tuple[str, str]] = []
    names: List[Tuple[str, str]] = []
    options: List[Tuple[str, str]] = []
    values: List[Tuple[str, str]] = []
    positionals: List[Tuple[str, str]] = []
    for node in tree.walk():
        if node.children:
            names.append((_sq(node.path), " ".join(_sq(name) for name in node.children)))
            if describe:
                commands.append(
                    (_sq(node.path), " ".join(_sq(f"{name}:{_one_line(child.help)}")
                                              for name, child in node.children.items()))
                )
        strings = [string for option in node.options for string in option.strings]
        if strings:
            options.append((_sq(node.path), " ".join(_sq(string) for string in strings)))
        for option in node.options:
            if option.value:
                for string in option.strings:
                    values.append((_sq(f"{node.path}|{string}"), _sq(option.value)))
        for index, kind in enumerate(node.positionals):
            positionals.append((_sq(f"{node.path}|{index}"), _sq(kind)))
    lines: List[str] = []
    lines += _case_table("_irondome_command_names", "subcommands of a command path", names)
    if describe:
        lines += _case_table("_irondome_commands", "subcommands with their descriptions", commands)
    lines += _case_table("_irondome_options", "option names of a command path", options)
    lines += _case_table("_irondome_value", "how the value of an option is completed (empty: it takes none)", values)
    lines += _case_table("_irondome_positional", "how the Nth plain argument of a command is completed", positionals)
    return lines


_BASH_BODY = r"""_irondome_kind() {
    local IFS
    case "$1" in
        file) IFS=$'\n'; COMPREPLY=($(compgen -f -- "$cur")) ;;
        dir) IFS=$'\n'; COMPREPLY=($(compgen -d -- "$cur")) ;;
        choices\ *) COMPREPLY=($(compgen -W "${1#choices }" -- "$cur")) ;;
        *) COMPREPLY=() ;;
    esac
}

_irondome() {
    local cur word kind names cmdpath="" positional=0 ended=0 i=1
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    while [ "$i" -lt "$COMP_CWORD" ]; do
        word="${COMP_WORDS[i]}"
        if [ "$ended" = 1 ]; then
            positional=$((positional + 1))
        elif [ "$word" = "--" ]; then
            ended=1
        elif [ "$word" = "=" ]; then
            :
        elif [[ "$word" == -* ]]; then
            kind="$(_irondome_value "$cmdpath|${word%%=*}")"
            if [ -n "$kind" ] && [[ "$word" != *=* ]]; then
                i=$((i + 1))
                if [ "${COMP_WORDS[i]}" = "=" ]; then
                    i=$((i + 1))
                fi
            fi
        else
            names=$'\n'"$(_irondome_command_names "$cmdpath")"$'\n'
            if [[ "$names" == *$'\n'"$word"$'\n'* ]]; then
                cmdpath="${cmdpath:+$cmdpath }$word"
                positional=0
            else
                positional=$((positional + 1))
            fi
        fi
        i=$((i + 1))
    done
    if [ "$ended" = 0 ] && [ "$COMP_CWORD" -gt 1 ]; then
        word="${COMP_WORDS[COMP_CWORD-1]}"
        if [ "$word" = "=" ] && [ "$COMP_CWORD" -gt 2 ]; then
            word="${COMP_WORDS[COMP_CWORD-2]}"
        fi
        if [[ "$word" == -* ]]; then
            kind="$(_irondome_value "$cmdpath|$word")"
            if [ -n "$kind" ]; then
                _irondome_kind "$kind"
                return 0
            fi
        fi
    fi
    if [ "$ended" = 0 ] && [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$(_irondome_options "$cmdpath")" -- "$cur"))
        return 0
    fi
    names="$(_irondome_command_names "$cmdpath")"
    if [ -n "$names" ] && [ "$positional" = 0 ]; then
        COMPREPLY=($(compgen -W "$names" -- "$cur"))
        return 0
    fi
    _irondome_kind "$(_irondome_positional "$cmdpath|$positional")"
    return 0
}

complete -o filenames -F _irondome irondome
"""

_ZSH_BODY = r"""_irondome_kind() {
  case "$1" in
    file) _files ;;
    dir) _files -/ ;;
    choices\ *) compadd -- ${=${1#choices }} ;;
  esac
}

_irondome() {
  local cur word kind cmdpath=""
  local -a names described
  integer i=2 positional=0 ended=0
  cur="${words[CURRENT]}"
  while (( i < CURRENT )); do
    word="${words[i]}"
    if (( ended )); then
      (( positional += 1 ))
    elif [[ "$word" == "--" ]]; then
      ended=1
    elif [[ "$word" == -* ]]; then
      kind="$(_irondome_value "$cmdpath|${word%%=*}")"
      if [[ -n "$kind" && "$word" != *=* ]]; then
        (( i += 1 ))
      fi
    else
      names=(${(f)"$(_irondome_command_names "$cmdpath")"})
      if (( ${names[(Ie)$word]} )); then
        cmdpath="${cmdpath:+$cmdpath }$word"
        positional=0
      else
        (( positional += 1 ))
      fi
    fi
    (( i += 1 ))
  done
  if (( ! ended && CURRENT > 2 )) && [[ "${words[CURRENT-1]}" == -* ]]; then
    kind="$(_irondome_value "$cmdpath|${words[CURRENT-1]}")"
    if [[ -n "$kind" ]]; then
      _irondome_kind "$kind"
      return
    fi
  fi
  if (( ! ended )) && [[ "$cur" == -* ]]; then
    compadd -- ${(f)"$(_irondome_options "$cmdpath")"}
    return
  fi
  described=(${(f)"$(_irondome_commands "$cmdpath")"})
  if (( ${#described} && positional == 0 )); then
    _describe -t commands 'irondome command' described
    return
  fi
  _irondome_kind "$(_irondome_positional "$cmdpath|$positional")"
}

if [[ "${funcstack[1]}" == "_irondome" ]]; then
  _irondome "$@"
else
  compdef _irondome irondome
fi
"""


def _bash(tree: _Node) -> str:
    head = [
        "# bash completion for irondome, generated by `irondome completion bash`.",
        "# Static: completing a word never runs irondome. Load it with: source <(irondome completion bash)",
        "",
    ]
    return "\n".join(head + _shell_tables(tree, describe=False)) + _BASH_BODY


def _zsh(tree: _Node) -> str:
    head = [
        "#compdef irondome",
        "# zsh completion for irondome, generated by `irondome completion zsh`.",
        "# Static: completing a word never runs irondome. Install it as _irondome in a directory on $fpath,",
        "# or load it with: source <(irondome completion zsh)",
        "",
    ]
    return "\n".join(head + _shell_tables(tree, describe=True)) + _ZSH_BODY


def _fish(tree: _Node) -> str:
    lines = [
        "# fish completion for irondome, generated by `irondome completion fish`.",
        "# Static: completing a word never runs irondome.",
        "# Install it with: irondome completion fish > ~/.config/fish/completions/irondome.fish",
        "",
        "function __irondome_command_names",
        '    switch "$argv[1]"',
    ]
    for node in tree.walk():
        if node.children:
            lines.append(f"        case {_fish_quote(node.path)}")
            lines.append(f"            printf '%s\\n' {' '.join(_fish_quote(name) for name in node.children)}")
    lines += ["    end", "end", "", "function __irondome_takes_value", '    switch "$argv[1]"']
    takes = [f"{node.path}|{string}" for node in tree.walk() for option in node.options if option.value
             for string in option.strings]
    if takes:
        lines.append(f"        case {' '.join(_fish_quote(key) for key in takes)}")
        lines.append("            return 0")
    lines += [
        "    end",
        "    return 1",
        "end",
        "",
        "function __irondome_path",
        "    set -l tokens (commandline -opc)",
        "    set -e tokens[1]",
        "    set -l cmdpath ''",
        "    set -l skip 0",
        "    for word in $tokens",
        "        if test $skip = 1",
        "            set skip 0",
        "            continue",
        "        end",
        "        if test \"$word\" = '--'",
        "            break",
        "        end",
        "        if string match -q -- '-*' $word",
        "            set -l option (string split -m 1 -- '=' $word)[1]",
        "            if not string match -q -- '*=*' $word; and __irondome_takes_value \"$cmdpath|$option\"",
        "                set skip 1",
        "            end",
        "            continue",
        "        end",
        "        if contains -- $word (__irondome_command_names \"$cmdpath\")",
        "            if test -z \"$cmdpath\"",
        "                set cmdpath $word",
        "            else",
        "                set cmdpath \"$cmdpath $word\"",
        "            end",
        "        end",
        "    end",
        "    printf '%s\\n' $cmdpath",
        "end",
        "",
        "function __irondome_at",
        "    set -l here (__irondome_path)",
        "    test \"$here\" = \"$argv[1]\"",
        "end",
        "",
        "complete -c irondome -f",
    ]
    for node in tree.walk():
        condition = _fish_quote(f"__irondome_at {_fish_quote(node.path)}")
        for name, child in node.children.items():
            lines.append(
                f"complete -c irondome -n {condition} -a {_fish_quote(name)} -d {_fish_quote(_one_line(child.help))}"
            )
        for option in node.options:
            flags = []
            for string in option.strings:
                if string.startswith("--"):
                    flags.append(f"-l {_fish_quote(string[2:])}")
                elif len(string) == 2:
                    flags.append(f"-s {_fish_quote(string[1:])}")
                else:
                    flags.append(f"-o {_fish_quote(string[1:])}")
            value = ""
            if option.value == "file":
                value = " -r -F"
            elif option.value == "dir":
                value = " -x -a '(__fish_complete_directories)'"
            elif option.value.startswith("choices "):
                value = f" -x -a {_fish_quote(option.value[len('choices '):])}"
            elif option.value:
                value = " -x"
            lines.append(
                f"complete -c irondome -n {condition} {' '.join(flags)}{value} -d {_fish_quote(_one_line(option.help))}"
            )
        for kind in node.positionals[:1]:
            if kind == "file":
                lines.append(f"complete -c irondome -n {condition} -F")
            elif kind == "dir":
                lines.append(f"complete -c irondome -n {condition} -a '(__fish_complete_directories)'")
            elif kind.startswith("choices "):
                lines.append(f"complete -c irondome -n {condition} -a {_fish_quote(kind[len('choices '):])}")
    return "\n".join(lines) + "\n"


def cmd_completion(ctx: Context, args: argparse.Namespace) -> int:
    from irondome.cli.main import build_parser

    tree = _tree(build_parser())
    script = {"bash": _bash, "zsh": _zsh, "fish": _fish}[args.shell](tree)
    if ctx.out.json_mode:
        ctx.out.json({"shell": args.shell, "script": script})
    else:
        ctx.out.data(script, newline=False)
    return 0
