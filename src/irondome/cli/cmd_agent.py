"""Commands for AI agents and scripts: alias, run, grant, approve, unlock, lock, audit, scan, mcp.

Who may do what (:mod:`irondome.cli.context` defines who counts as a person):

* ``run`` and ``mcp`` are what agents use. They read secrets only through
  :meth:`Context.access`, so a grant, a Touch ID approval or the owner's own
  unlock decides what resolves, and the use is recorded in the audit log.
* ``approve`` is the one thing an agent may ask for: a short, use-only grant
  for entries marked for agents, and only a Touch ID on the owner's Mac
  creates it.
* Everything that changes the vault, its aliases, grants or sessions, that
  reads the audit log, or that reads every secret (``scan``), needs the owner:
  a terminal, or the master password on stdin. An agent is refused with exit
  status 5 before anything is opened, prompted for or spent. ``grant revoke``
  and ``lock --all`` need no key, so they call :meth:`Context.prove_owner`
  first: a password given on stdin must open the vault, or nothing is revoked.
* ``grant ls``, ``mcp config`` and ending the session named in the
  environment (``lock``) need no unlock.

Tokens: a grant token is printed on stdout and nowhere else, so it can be
captured with ``$(...)``. A session token opens the whole vault, so it is
never printed to a terminal unless ``--print-token`` asks for exactly that.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib
import json
import os
import re
import shlex
import shutil
import stat
import sys
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from irondome import audit, caps, config, paths, scan, unlock
from irondome.agent import refs, runner
from irondome.cli.context import ENV_GRANT, ENV_SESSION, PURPOSE_REVEAL, PURPOSE_USE, Context
from irondome.cli.output import format_duration, format_time, parse_duration
from irondome.device.base import POLICY_DEVICE
from irondome.errors import AuthError, IronDomeError, NotFoundError, PolicyError, UsageError, VaultError
from irondome.keys import KIND_DEVICE, KIND_PASSWORD
from irondome.vault import Entry, Vault, VaultFile, validate_alias, vault_exists

__all__ = ["register"]

#: A Touch ID prompt shows at most this many characters of its reason (see device/irondome_se.swift).
_REASON_LIMIT = 200
#: How much of a command line is kept in the audit record of a use.
_DETAIL_LIMIT = 200
_APPROVAL_TTL = 600
_APPROVAL_TTL_MAX = 3600
_APPROVAL_LABEL = "approved with Touch ID"
_AGENT_ALLOWED = ("use", "reveal")
_AUDIT_COUNT = 50
_ENV_FILE_NAME = ".env.irondome"
_ENV_FILE_LIMIT = 1024 * 1024
_ID = re.compile(r"[0-9a-f]{32}")
_ID_PREFIX = re.compile(r"[0-9a-fA-F]{6,32}")
_MCP_CLIENTS = ("claude-code", "claude-desktop", "cursor", "codex", "vscode", "zed")

_SKIP_WORDS = {
    scan.SKIP_SYMLINK: ("symbolic link", "symbolic links"),
    scan.SKIP_UNREADABLE: ("unreadable", "unreadable"),
    scan.SKIP_TOO_LARGE: ("larger than 50 MB", "larger than 50 MB"),
    scan.SKIP_SPECIAL: ("not a regular file", "not regular files"),
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _bunker() -> str:
    return paths.bunker_name()


def _bunker_option() -> str:
    """`` --bunker NAME`` when the current bunker is not the one a bare command would pick."""
    name = _bunker()
    try:
        default = paths.default_bunker()
    except UsageError:
        default = paths.FIRST_BUNKER
    return "" if name == default else f" --bunker {name}"


def _require_owner(ctx: Context, what: str) -> None:
    """Refuse an agent before anything is opened: *what* changes or reveals more than a grant could."""
    if ctx.agent_mode:
        raise PolicyError(
            f"{what} needs the vault's owner: run it at a terminal, or give the master password with "
            "--password-stdin. An agent cannot do this, with or without a grant"
        )


def _require_vault() -> None:
    if not vault_exists():
        name = _bunker()
        create = "irondome init" if name == paths.FIRST_BUNKER else f"irondome bunker create {name}"
        raise VaultError(f"there is no vault in bunker {name}. Create it with: {create}")


def _open(ctx: Context, reason: str, *, fresh: bool = False) -> Vault:
    _require_vault()
    return ctx.open_vault(reason=reason, fresh=fresh)


def _open_to_outlast(ctx: Context, reason: str, ttl: int) -> Vault:
    """Open the vault to make something that lasts *ttl* seconds. A session cannot make what outlives it.

    A session token stands for the person for a limited time, and anything that holds it can use
    it. So a grant that would still work after the session has ended needs what the session was
    started with: the master password or Touch ID, asked for afresh.
    """
    vault = _open(ctx, reason)
    if ctx.unlocked_by != "session":
        return vault
    left = (ctx.session_expires or 0) - int(time.time())
    if ttl <= left:
        return vault
    vault.close()
    ctx.out.info(
        f"This would outlast your session, which ends in {format_duration(max(left, 0))}: a session cannot "
        "make that, so the vault is unlocked again."
    )
    return _open(ctx, reason, fresh=True)


def _commit(ctx: Context, vault: Vault, action: str, *, target: str, detail: str) -> None:
    vault.commit(snapshots=config.get("snapshots"))
    ctx.audit(vault, action, target=target, detail=detail)


def _printable(text: str) -> str:
    """*text* with control and formatting characters escaped, for prompts and tables."""
    if text.isprintable():
        return text
    return "".join(char if char.isprintable() else char.encode("unicode_escape").decode("ascii") for char in text)


def _shorten(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _quoted(text: str) -> str:
    """*text* between single quotes, so that where it ends cannot be mistaken: a quote or a backslash in it is
    escaped with a backslash, and so is every character a dialog would not show as itself."""
    return "'" + _printable(text.replace("\\", "\\\\").replace("'", "\\'")) + "'"


def _touch_reason(action: str) -> str:
    """The text of a Touch ID prompt: *action*, then the bunker it opens.

    It completes the system's own sentence ("<helper> is trying to ..."), as the MCP server's prompts do,
    and it names the bunker, so that approving a secret of one bunker never looks like approving the same
    reference in another. Callers keep the whole text within :data:`_REASON_LIMIT`, so that nothing of it
    is ever cut off on the way to the prompt.
    """
    return f"{action} (bunker {_bunker()})"


def _spoken_list(items: Sequence[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _spoken_duration(seconds: int) -> str:
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds % size == 0:
            count = seconds // size
            return f"{count} {unit}{'' if count == 1 else 's'}"
    return f"{seconds} seconds"


def _seconds(text: str) -> int:
    return parse_duration(text)


def _within(seconds: int, shortest: int, longest: int, what: str) -> int:
    if not shortest <= seconds <= longest:
        raise UsageError(
            f"{what} lasts from {_spoken_duration(shortest)} to {_spoken_duration(longest)}, "
            f"not {_spoken_duration(seconds)}"
        )
    return seconds


def _references(texts: Sequence[str]) -> List[str]:
    """Bare references, as a grant stores them: ``irondome://`` and percent-escapes resolved."""
    names = [refs.parse_reference(text) for text in texts]
    repeated = sorted({name for name in names if names.count(name) > 1})
    if repeated:
        raise UsageError(f"a reference was given more than once: {', '.join(repeated)}")
    if len(names) > caps.MAX_REFERENCES:
        raise UsageError(f"a grant covers at most {caps.MAX_REFERENCES} references")
    return names


def _source(vault: Vault, reference: str) -> Tuple[Entry, str, str]:
    """The entry and field *reference* stands for, and how to show that to the owner."""
    entry, field = vault.resolve(reference)
    target = f"{entry.name}/{field}"
    return entry, field, reference if reference == target else f"{reference} ({target})"


def _is_terminal(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def _short_id(text: str) -> str:
    return text[:12] if _ID.fullmatch(text) else text


def _size(count: int) -> str:
    for unit, scale in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if count >= scale:
            return f"{count / scale:.1f} {unit}"
    return f"{count} bytes"


def _plural(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


# ---------------------------------------------------------------------------
# alias
# ---------------------------------------------------------------------------


def _alias_set(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "changing an alias")
    alias = validate_alias(args.alias)
    reference = refs.parse_reference(args.reference)
    with _open(ctx, f"set the alias {alias}") as vault:
        if vault.has_name(alias):
            raise UsageError(
                f"{alias!r} is the name of an entry, and an alias of that name would hide it; choose another"
            )
        entry, field = vault.resolve(reference)
        previous = vault.aliases.get(alias)
        before = f"{vault.entries[previous.entry].name}/{previous.field}" if previous is not None else None
        vault.set_alias(alias, entry, field)
        empty = vault.value(entry, field) == ""  # NotFoundError for a field the entry does not have
        _commit(ctx, vault, "alias.set", target=alias, detail=f"{entry.name}/{field}")
    if ctx.out.json_mode:
        ctx.out.json({"alias": alias, "entry": entry.name, "field": field, "replaced": before is not None})
    replaced = f" (it pointed at {before})" if before is not None and before != f"{entry.name}/{field}" else ""
    ctx.out.ok(f"alias {alias} now points at {entry.name}/{field} in bunker {_bunker()}{replaced}")
    if empty:
        ctx.out.warn(f"{entry.name}/{field} is empty, so {alias} stands for nothing until it is set")
    return 0


def _alias_rm(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "removing an alias")
    with _open(ctx, f"remove the alias {args.alias}") as vault:
        alias = vault.aliases.get(args.alias)
        if alias is None:
            raise NotFoundError(f"there is no alias named {args.alias!r} in bunker {_bunker()}")
        entry_name, field = vault.entries[alias.entry].name, alias.field
        target = f"{entry_name}/{field}"
        vault.remove_alias(args.alias)
        _commit(ctx, vault, "alias.rm", target=args.alias, detail=target)
    if ctx.out.json_mode:
        ctx.out.json({"alias": args.alias, "entry": entry_name, "field": field})
    ctx.out.ok(f"alias {args.alias} removed from bunker {_bunker()} (it pointed at {target})")
    ctx.out.info("Grants already made for it keep working until they expire or are revoked (irondome grant ls).")
    return 0


def _alias_ls(ctx: Context, args: argparse.Namespace) -> int:
    if ctx.agent_mode and os.environ.get(ENV_GRANT) and not os.environ.get(ENV_SESSION) and not ctx.touch:
        raise PolicyError(
            "a grant cannot open the vault's list of aliases; irondome ls lists the names this grant covers"
        )
    with _open(ctx, "list your aliases") as vault:
        restricted = ctx.agent_mode and ctx.unlocked_by == "touch"
        rows = []
        for name in sorted(vault.aliases):
            alias = vault.aliases[name]
            entry = vault.entries[alias.entry]
            if not restricted or entry.agent != "deny":
                rows.append((name, entry.name, alias.field))
    if ctx.out.json_mode:
        ctx.out.json({"aliases": [{"alias": name, "entry": entry, "field": field} for name, entry, field in rows]})
        return 0
    ctx.out.table(("alias", "entry", "field"), [(name, _printable(entry), field) for name, entry, field in rows])
    if not rows:
        ctx.out.info(f"no aliases in bunker {_bunker()}. Create one with: irondome alias set NAME ENTRY[/FIELD]")
    return 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def _group_is_the_users_alone(gid: int) -> bool:
    """Whether the user running irondome is the only account in group *gid*.

    Debian, Ubuntu, Fedora and their relatives give every user a group of their own and a umask of 002, so
    every file an editor or ``git clone`` writes there can be changed by its group: a group of one. That is
    the one case in which a group's write permission gives nobody else anything. It has to be the user's own
    primary group, with no other member listed and no other account that has it as its primary group; a
    group or an account that cannot be looked up counts as somebody else.
    """
    try:
        import grp
        import pwd

        user = pwd.getpwuid(os.geteuid())
        group = grp.getgrgid(gid)
        accounts = pwd.getpwall()
    except (ImportError, KeyError, OSError):
        return False
    if user.pw_gid != gid or any(member != user.pw_name for member in group.gr_mem):
        return False
    return all(account.pw_uid == user.pw_uid for account in accounts if account.pw_gid == gid)


def _who_else_can_change(info: os.stat_result) -> Optional[str]:
    """Who, besides the user running irondome, can change a file with this status; ``None`` for nobody."""
    if info.st_uid != os.geteuid():
        return "it belongs to another user"
    if info.st_mode & stat.S_IWOTH:
        return "every user of this machine can change it"
    if info.st_mode & stat.S_IWGRP and not _group_is_the_users_alone(info.st_gid):
        try:
            import grp

            group = f"the group {_printable(grp.getgrgid(info.st_gid).gr_name)}"
        except (ImportError, KeyError, OSError):
            group = f"group {info.st_gid}"
        return f"the members of {group} can change it"
    return None


def _read_env_file(path: str, *, found: bool) -> str:
    """The text of an env file. *found*: it was picked up from the working directory, not named."""
    shown = scan.display_path(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError:
        raise UsageError(f"the env file {shown} does not exist") from None
    except OSError as exc:
        raise UsageError(f"cannot read the env file {shown}: {exc.strerror or exc}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise UsageError(f"the env file {shown} is not a regular file")
        if found and hasattr(os, "geteuid"):
            reason = _who_else_can_change(info)
            if reason is not None:
                raise UsageError(
                    f"{shown} was not used: {reason}, so it could name any of your secrets. Make it yours "
                    "and not writable by others (chmod go-w), or name a file with --env-file"
                )
        parts = []
        size = 0
        while size <= _ENV_FILE_LIMIT:
            part = os.read(fd, 65536)
            if not part:
                break
            parts.append(part)
            size += len(part)
    except OSError as exc:
        raise UsageError(f"cannot read the env file {shown}: {exc.strerror or exc}") from None
    finally:
        os.close(fd)
    if size > _ENV_FILE_LIMIT:
        raise UsageError(f"the env file {shown} is too large (more than 1 MiB)")
    try:
        return b"".join(parts).decode("utf-8")
    except UnicodeDecodeError:
        raise UsageError(f"the env file {shown} is not UTF-8 text") from None


def _env_file(ctx: Context, named: Optional[str], cwd: Optional[str]) -> Optional[Dict[str, str]]:
    """``--env-file``, else ``.env.irondome`` in the directory the command runs in, else nothing."""
    if named is not None:
        path, text = named, _read_env_file(named, found=False)
    else:
        try:
            base = cwd if cwd is not None else os.getcwd()
        except OSError:
            raise UsageError("the current directory no longer exists; give one with --cwd") from None
        path = os.path.join(base, _ENV_FILE_NAME)
        if not os.path.lexists(path):
            return None
        text = _read_env_file(path, found=True)
    values = refs.parse_env_file(text)
    if named is not None:
        ctx.out.info(f"using {scan.display_path(path)}")
        return values
    # Nobody named this file: it was found where the command runs, and whoever wrote the directory may have
    # written it. Its author must not be able to choose a variable and what goes into it: PATH set as written
    # starts another program, and so does PATH pointed at a field whose content the author can guess (a user
    # name, a URL). No list of such variables is complete, so there is none. The one thing such a file may do
    # is what --env NAME does: ask for the secret the owner stored under that very name.
    own = sorted(name for name, value in values.items() if _asks_for_its_own_name(name, value))
    other = sorted(name for name in values if name not in own)
    if other:
        shown = scan.display_path(path)
        raise UsageError(
            f"{shown} was found in the working directory and sets {_listed(other)} to something other than the "
            "secret you keep under that name. A file nobody named may only ask for a secret under its own name, "
            "as --env does: NAME=irondome://NAME, where NAME is an alias (irondome alias set NAME ENTRY) or the "
            "name of an entry. Anything else would let whoever wrote the file choose a variable, PATH for one, "
            f"and what goes into it. Read the file; if it is yours, run with: --env-file {shown}"
        )
    # Said even with -q: this is the one notice of what a file nobody named puts into the command.
    supplied = f"from the vault, each under its own name: {_listed(own)}" if own else "empty"
    ctx.out.notice(f"using {scan.display_path(path)}, found in the working directory ({supplied})")
    return values


def _asks_for_its_own_name(name: str, value: str) -> bool:
    """True when the env-file line ``name=value`` is ``NAME=irondome://NAME``: the same as ``--env NAME``."""
    if not refs.is_reference(value):
        return False
    try:
        return refs.parse_reference(value) == name
    except UsageError:
        return False


def _listed(names: Sequence[str], limit: int = 8) -> str:
    shown = ", ".join(_printable(name) for name in names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def _started_path(found: str) -> str:
    """The path that starts the program *found* (an absolute path, as :func:`runner.locate_command` gives it).

    Every directory in it is resolved, as the kernel resolves it, so that no ``..`` and no link to a
    directory in it can stand for one file in the prompt and reach another when the program starts. The
    program's own name is kept even when it is a link (Homebrew's ``gh``, a virtual environment's
    ``python``): a program sees that name, and a multi-call program or a virtual environment depends on it.
    """
    directory, name = os.path.split(found)
    return os.path.join(os.path.realpath(directory), name)


def _run_reason(program: str, references: Sequence[str]) -> Optional[str]:
    """What the owner reads in a Touch ID prompt for ``run``: the program, the secrets, the bunker.

    *program* is the path the command is started by (:func:`_started_path`), shown whole: a ``./gh`` an
    agent wrote, or a PATH it changed, shows as where it really is. Every reference that fits is named and
    the rest are counted ("and 2 more"). The path is never shortened, because the part left out could make
    another program look like the one the owner trusts: None when it does not fit with the bunker.
    """
    name = _quoted(program)
    shown = [_printable(reference) for reference in references]
    for count in range(len(shown), 0, -1):
        listed = shown[:count] + ([f"{len(shown) - count} more"] if count < len(shown) else [])
        text = _touch_reason(f"let {name} use {_spoken_list(listed)}")
        if len(text) <= _REASON_LIMIT:
            return text
    text = _touch_reason(f"let {name} use {_plural(len(shown), 'secret', 'secrets')}")
    return text if len(text) <= _REASON_LIMIT else None


def _unnamed_program(ctx: Context, program: str, references: Sequence[str]) -> UsageError:
    """The refusal of a Touch ID prompt that could not name *program* in full."""
    shortest = len(_touch_reason(f"let {_quoted(program)} use {_plural(len(references), 'secret', 'secrets')}"))
    instead = (
        "ask the vault's owner for a grant (irondome grant create)"
        if ctx.agent_mode
        else "run it in a session (irondome unlock) or with --no-touch, which need no such prompt"
    )
    return UsageError(
        f"the program {_quoted(program)} cannot be named in full in a Touch ID prompt ({shortest} characters with "
        f"the bunker's name, at most {_REASON_LIMIT}), and IronDome does not shorten it: a shortened path could pass "
        f"for another program. Nothing was asked or used. Give the program a shorter path, or {instead}"
    )


def _touch_may_show(ctx: Context, args: argparse.Namespace) -> bool:
    """True when opening the vault for this command could put a Touch ID prompt on the owner's screen.

    It decides as :meth:`Context.access` and :func:`unlock.unlock` do: a grant in the environment opens
    instead of the vault, and so does a session (should the session fail, :func:`_run` has switched
    Touch ID off for the command); a prompt needs Touch ID allowed here (a terminal or ``--touch``, no
    ``--no-touch``, a desktop session on a Mac) and a keyslot that asks for a finger: a Touch ID keyslot,
    which is not tried when the password comes with ``--password-stdin``, or a password keyslot whose
    device key needs the finger as well.
    """
    if _grant_in_use(args) or os.environ.get(ENV_SESSION, "").strip():
        return False
    if ctx.no_touch or not (ctx.has_terminal or ctx.touch) or not unlock.can_ask_for_touch():
        return False
    if not vault_exists():
        return False  # opening it fails before anything is asked
    try:
        slots = VaultFile.load().slots
    except IronDomeError:
        return False  # the same error stops the command before anything is asked
    return any(
        (slot.kind == KIND_DEVICE and not ctx.password_stdin)
        or (slot.kind == KIND_PASSWORD and slot.policy not in (None, POLICY_DEVICE))
        for slot in slots
    )


def _grant_in_use(args: argparse.Namespace) -> bool:
    """True when :meth:`Context.access` will open the grant in the environment rather than the vault."""
    return bool(os.environ.get(ENV_GRANT, "").strip()) and not getattr(args, "no_grant", False)


def _run_document(result: "runner.RunResult") -> Dict[str, Any]:
    return {"exit_code": result.code, "stdout": result.stdout, "stderr": result.stderr, "truncated": result.truncated}


def _run(ctx: Context, args: argparse.Namespace) -> int:
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise UsageError(
            "give the command to run after --, for example: irondome run --env GITHUB_TOKEN -- gh repo list"
        )
    if args.no_mask and ctx.out.json_mode:
        raise UsageError("--no-mask cannot be combined with --json: captured output is always masked")
    if args.cwd is not None and not os.path.isdir(args.cwd):
        raise UsageError(f"the working directory {scan.display_path(args.cwd)} does not exist")
    limit = _seconds(args.timeout) if args.timeout is not None else None
    plan = refs.plan_injection(os.environ, _env_file(ctx, args.env_file, args.cwd), args.env or [])
    if not plan.references:
        raise UsageError(
            "nothing to inject: give --env VAR=REFERENCE or --env ALIAS, an env file whose values are "
            "irondome:// references, or such a reference in the environment"
        )
    # Everything that can go wrong without a secret goes wrong here, before a use is spent or a
    # Touch ID prompt is shown: the arguments, the directory, the time limit, the program itself.
    program = _started_path(runner._prepare(command, {}, plan.literals, None, args.cwd, limit)[1])
    # The program is looked up once, here, and started by exactly this path (runner's executable=): a file
    # the agent puts earlier on PATH, or a link it turns, while the owner reads the prompt changes nothing.
    # The program still sees the name it was called by (argv[0] as typed).
    purpose = PURPOSE_REVEAL if args.no_mask else PURPOSE_USE
    references = list(dict.fromkeys(plan.references.values()))
    detail = _shorten(shlex.join(command), _DETAIL_LIMIT)
    reason = _run_reason(program, references)
    if reason is None:
        if _touch_may_show(ctx, args):
            raise _unnamed_program(ctx, program, references)
        # No prompt can show this: a grant, a session or the master password opens the vault. Should
        # the session fail, Touch ID stays off rather than show a prompt that cannot name the program.
        ctx.no_touch = True
        reason = _touch_reason(f"let a program use {_plural(len(references), 'secret', 'secrets')}")
    # A grant is looked at first: a request it refuses (a name it does not cover, --no-mask under a
    # use-only grant) is turned away without spending one of its uses.
    access = ctx.access(
        reason=reason, references=references, purpose=purpose, detail=detail,
        reveal_hint="--no-mask would show them in the output: run without --no-mask",
    )
    try:
        injected = refs.resolve_plan(plan, lambda reference: access.value(reference, purpose, detail=detail))
    finally:
        access.close()  # the vault key is wiped, or the grant dropped, before the command starts
    if not args.no_mask:
        for name in runner.Masker(injected).unmasked_names:
            ctx.out.warn(
                f"the value of {name} is shorter than {runner.MIN_MASK_BYTES} bytes and is not masked in the output"
            )
    if ctx.out.json_mode:
        try:
            result = runner.run_captured(
                command, injected, literals=plan.literals, cwd=args.cwd, timeout=limit, executable=program
            )
        except runner.CommandTimeoutError as exc:
            if exc.result is None:
                raise
            ctx.out.json(_run_document(exc.result))
            ctx.out.error(str(exc))
            return exc.exit_code
        ctx.out.json(_run_document(result))
        return result.code
    return runner.run_command(
        command, injected, literals=plan.literals, mask=not args.no_mask, cwd=args.cwd, timeout=limit,
        executable=program,
    )


# ---------------------------------------------------------------------------
# grant and approve
# ---------------------------------------------------------------------------


def _report_grant(ctx: Context, token: str, info: "caps.GrantInfo", covers: Sequence[str], how: str) -> None:
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "token": token,
                "id": info.id,
                "references": list(info.references),
                "mode": info.mode,
                "expires": info.expires,
                "uses": info.uses_left,
            }
        )
    else:
        ctx.out.secret(token)
    mode = (
        "use: the values can only be injected into a command by irondome run"
        if info.mode == caps.MODE_USE
        else "reveal: the values can be injected and also printed"
    )
    ctx.out.ok(f"grant {info.id[:12]} {how} in bunker {_bunker()}")
    for label, value in (
        ("covers", ", ".join(_printable(text) for text in covers)),
        ("mode", mode),
        # Its whole life, not what is left of it a moment later: a grant made for one minute says 60s, not 59s.
        ("expires", f"{format_time(info.expires)}, in {format_duration(info.expires - info.created)}"),
        ("uses", "unlimited" if info.uses_left is None else str(info.uses_left)),
        ("id", info.id),
    ):
        ctx.out.info(f"  {label:<8} {value}")
    ctx.out.info(
        "The token is a bearer secret: whoever holds it can use the grant. Give it to one agent, keep it out "
        f"of files and chats, and revoke it with: irondome grant revoke {info.id[:12]}"
    )


def _grant_create(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "creating a grant")
    references = _references(args.references)
    ttl = _seconds(args.ttl) if args.ttl is not None else config.get("grant_ttl")
    _within(ttl, caps.GRANT_TTL_MIN, caps.GRANT_TTL_MAX, "a grant")
    uses: Optional[int] = None if args.unlimited else (1 if args.uses is None else args.uses)
    if uses is not None and not 1 <= uses <= caps.MAX_USES:
        raise UsageError(f"a grant can be used from 1 to {caps.MAX_USES} times, or without a limit (--unlimited)")
    mode = caps.MODE_REVEAL if args.reveal else caps.MODE_USE
    with _open_to_outlast(ctx, f"create a grant for {_spoken_list(references)}", ttl) as vault:
        covers = [_source(vault, reference)[2] for reference in references]
        label = args.label or ""
        if caps.SESSION_MARK.search(label):
            raise UsageError(
                "a label cannot end with [session ...]: that is how IronDome marks a grant made under a session, "
                "and ending that session would revoke this grant with it"
            )
        if ctx.unlocked_by == "session":
            # Marked as this session's: ending the session (irondome lock) revokes it too.
            mark = caps.session_mark(os.environ.get(ENV_SESSION, "").strip())
            room = caps.MAX_LABEL - len(mark) - 1
            if len(label) > room:
                raise UsageError(
                    f"under a session a label is at most {room} characters: the grant is also marked {mark}, so "
                    "that ending the session revokes it"
                )
            label = f"{label} {mark}".strip()
        token, info = caps.create_grant(
            vault, references, mode=mode, ttl=ttl, uses=uses, label=label,
            actor="session" if ctx.unlocked_by == "session" else "owner",
        )
    _report_grant(ctx, token, info, covers, "created")
    return 0


def _approve(ctx: Context, args: argparse.Namespace) -> int:
    references = _references(args.references)
    ttl = _seconds(args.ttl) if args.ttl is not None else _APPROVAL_TTL
    _within(ttl, caps.GRANT_TTL_MIN, _APPROVAL_TTL_MAX, "an approval")
    listed = _spoken_list([_printable(text) for text in references])
    reason = _touch_reason(f"let an agent use {listed} for {_spoken_duration(ttl)}")
    if len(reason) > _REASON_LIMIT:
        raise UsageError(
            f"that request is too long to be shown in full in the Touch ID prompt ({len(reason)} characters, "
            f"at most {_REASON_LIMIT}): ask for fewer references at a time"
        )
    _require_vault()
    target = ", ".join(references)
    vault = ctx.open_vault_by_touch(reason=reason)
    try:
        try:
            covers = []
            denied = []
            for reference in references:
                entry, _field, shown = _source(vault, reference)
                covers.append(shown)
                if entry.agent not in _AGENT_ALLOWED:
                    denied.append(entry.name)
            if denied:
                names = ", ".join(repr(name) for name in sorted(set(denied)))
                raise PolicyError(
                    f"{names} {'is' if len(set(denied)) == 1 else 'are'} not available to agents, so nothing was "
                    f"approved. The owner can allow an entry with: irondome edit NAME --agent use"
                )
            token, info = caps.create_grant(
                vault, references, mode=caps.MODE_USE, ttl=ttl, uses=None, label=_APPROVAL_LABEL
            )
        except IronDomeError as exc:
            ctx.audit(vault, "approve", target=target, detail=f"refused: {exc}", ok=False)
            raise
        ctx.audit(vault, "approve", target=target, detail=f"lifetime {ttl}s, grant {info.id}")
    finally:
        vault.close()
    _report_grant(ctx, token, info, covers, "approved with Touch ID")
    return 0


def _grant_ls(ctx: Context, args: argparse.Namespace) -> int:
    grants = [info for info in caps.list_caps() if info.kind == caps.KIND_GRANT]
    now = time.time()
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "grants": [
                    {
                        "id": info.id,
                        "label": info.label,
                        "created": info.created,
                        "expires": info.expires,
                        "expired": info.expired,
                        "uses_left": info.uses_left,
                    }
                    for info in grants
                ]
            }
        )
        return 0
    ctx.out.table(
        ("id", "label", "expires in", "uses left"),
        [
            (
                info.id[:12],
                _printable(info.label) or "-",
                "expired" if info.expired else format_duration(info.expires - now),
                "unlimited" if info.uses_left is None else str(info.uses_left),
            )
            for info in grants
        ],
    )
    if not grants:
        ctx.out.info(f"no grants in bunker {_bunker()}")
    return 0


def _record_with(ctx: Context, proven: Optional[Vault]) -> Optional[Vault]:
    """The vault to record a removal in the audit log with: the one the owner's password opened, if any.

    At a terminal, where a person passed :meth:`Context.prove_owner` without a password, the vault
    is opened the usual way; the removal goes ahead if it cannot be, because that person asked for it.
    """
    if proven is not None:
        return proven
    try:
        return _open(ctx, "record a revocation in your IronDome audit log")
    except IronDomeError as exc:
        ctx.out.warn(f"this is not recorded in the audit log, because the vault could not be opened: {exc}")
        return None


def _revoke_one(cap_id: str, vault: Optional[Vault], ctx: Context) -> bool:
    """Revoke one capability by its full id. False if it was gone already."""
    try:
        caps.revoke(cap_id, vault=vault)
    except NotFoundError:
        return False
    except audit.AuditError as exc:
        ctx.out.warn(str(exc))
    return True


def _revoke(ctx: Context, args: argparse.Namespace, prefix: str, proven: Optional[Vault]) -> List[Dict[str, str]]:
    """Revoke what *args* names; returns what went. *proven* is the vault the owner's password opened, if any."""
    if args.all:
        targets = [info for info in caps.list_caps() if info.kind == caps.KIND_GRANT]
        if not targets:
            return []
        candidates = [(info.id, info.kind) for info in targets]
    else:
        matches = [info for info in caps.list_caps() if info.id.startswith(prefix)]
        if len(matches) > 1:
            raise UsageError(f"{len(matches)} grants or sessions have an id starting with {prefix}; give more of it")
        if not matches:
            caps.revoke(prefix)  # a damaged file named like a capability; NotFoundError when there is nothing
            return [{"id": prefix, "kind": "capability"}]
        candidates = [(matches[0].id, matches[0].kind)]
    vault = _record_with(ctx, proven)
    try:
        revoked = [{"id": cap_id, "kind": kind} for cap_id, kind in candidates if _revoke_one(cap_id, vault, ctx)]
    finally:
        if vault is not None and vault is not proven:
            vault.close()
    if not args.all and not revoked:
        raise NotFoundError(f"no grant or session in bunker {_bunker()} has an id starting with {prefix}")
    return revoked


def _grant_revoke(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "revoking a grant")
    if args.all == (args.id_prefix is not None):
        raise UsageError("give the id of the grant to revoke, as irondome grant ls shows it, or --all")
    prefix = "" if args.all else args.id_prefix.lower()
    if not args.all and not _ID_PREFIX.fullmatch(prefix):
        raise UsageError("give at least the first 6 characters of the id (hexadecimal), as irondome grant ls shows it")
    # Revoking unlocks nothing it needs, so the owner is proven first: a person at a terminal, or a password
    # that opens the vault. Nothing is revoked when that fails; the vault it opened records the revocation.
    proven = ctx.prove_owner("revoking a grant", keep_open=True)
    try:
        revoked = _revoke(ctx, args, prefix, proven)
    finally:
        if proven is not None:
            proven.close()
    if ctx.out.json_mode:
        ctx.out.json({"revoked": revoked})
    for item in revoked:
        verb = "ended session" if item["kind"] == caps.KIND_SESSION else f"revoked {item['kind']}"
        ctx.out.ok(f"{verb} {item['id'][:12]} in bunker {_bunker()}")
    if not revoked:
        ctx.out.info(f"there are no grants to revoke in bunker {_bunker()}")
    return 0


# ---------------------------------------------------------------------------
# unlock and lock
# ---------------------------------------------------------------------------


def _unlock(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "starting a session")
    ttl = _seconds(args.ttl) if args.ttl is not None else config.get("session_ttl")
    _within(ttl, caps.SESSION_TTL_MIN, caps.SESSION_TTL_MAX, "a session")
    if not args.print_token and _is_terminal(ctx.out.stdout):
        # Checked before the password is asked for: no session is ever made for a token nobody may see.
        raise UsageError(
            "a session token is not printed to a terminal, where it would stay in the scrollback. "
            'Run it as: eval "$(irondome unlock)"   (or pass --print-token to print it anyway)'
        )
    with _open(ctx, "start an IronDome session", fresh=True) as vault:
        token = caps.create_session(vault, ttl=ttl)
    expires = int(time.time()) + ttl
    if ctx.out.json_mode:
        ctx.out.json({"token": token, "expires": expires, "bunker": _bunker()})
    elif args.print_token:
        ctx.out.secret(token)
    else:
        ctx.out.data(f"export {ENV_SESSION}='{token}'")
    ctx.out.ok(f"session started for bunker {_bunker()}; it lasts {format_duration(ttl)}, until {format_time(expires)}")
    ctx.out.info(f'Set it in this shell with: eval "$(irondome{_bunker_option()} unlock)"; end it with: irondome lock')
    ctx.out.info(
        f"The token opens the whole vault: never export {ENV_SESSION} into an agent's environment. "
        "Give agents a grant instead (irondome grant create)."
    )
    return 0


def _session_vault(token: Optional[str]) -> Optional[Vault]:
    """The vault the session in the environment opens, to record its end; None without asking anyone."""
    if not token or not vault_exists():
        return None
    try:
        file = VaultFile.load()
        key = caps.open_session(token, file)
    except IronDomeError:
        return None
    try:
        return Vault(file, key)
    except IronDomeError:
        return None


def _lock(ctx: Context, args: argparse.Namespace) -> int:
    proven: Optional[Vault] = None
    if args.all:
        _require_owner(ctx, "ending every session")
        # It unlocks nothing, and it ends the owner's sessions too: the owner is proven first.
        proven = ctx.prove_owner("ending every session", keep_open=True)
    token = os.environ.get(ENV_SESSION, "").strip() or None
    ended = 0
    vault = proven if proven is not None else _session_vault(token)
    try:
        if args.all:
            ended = caps.end_sessions(vault=vault)
        elif token is not None:
            ended = caps.end_sessions(token, vault=vault, actor="session")  # the token is all that was shown
    except audit.AuditError as exc:
        ended = max(ended, 1)
        ctx.out.warn(str(exc))
    except (UsageError, AuthError) as exc:
        ctx.out.warn(f"{ENV_SESSION} does not hold a session token, so nothing was ended: {exc}")
    finally:
        if vault is not None:
            vault.close()
    if ctx.out.json_mode:
        ctx.out.json({"ended": ended})
    else:
        ctx.out.data(f"unset {ENV_SESSION}")
    if ended:
        ctx.out.ok(
            f"ended {_plural(ended, 'session', 'sessions')} in bunker {_bunker()}, and revoked any grant made under "
            f"{'it' if ended == 1 else 'them'}"
        )
    return 0


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def _who(event: "audit.AuditEvent") -> str:
    """Who wrote a record, as its key proves it: the owner's key, or one grant's."""
    if event.kid == audit.KID_VAULT:
        return event.actor or "owner"
    return f"grant {event.kid[:12]}"


def _archived_log(name: str) -> Path:
    """The archived audit log *name* of this bunker: a file name as ``irondome audit`` lists it, or its path."""
    wanted = Path(name).name
    for path in audit.archives():
        if path.name == wanted and (os.sep not in name or Path(name).resolve() == path.resolve()):
            return path
    known = ", ".join(path.name for path in audit.archives()) or "none"
    raise NotFoundError(f"bunker {_bunker()} has no archived audit log named {wanted} (it has: {known})")


def _audit(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "reading the audit log")
    if args.count < 0:
        raise UsageError("-n takes the number of records to show: 1 or more, or 0 for all of them")
    archived = _archived_log(args.archive) if args.archive is not None else None
    with _open(ctx, "read your IronDome audit log") as vault:
        events = audit.read(vault, limit=args.count + 1 if args.count else None, path=archived)
        report = audit.verify(vault, path=archived) if args.verify else None
        if archived is not None and report is None and not events and archived.stat().st_size:
            raise VaultError(
                f"no record in {archived.name} could be read with a key this vault holds: it was altered, it "
                "belongs to another vault, or it was set aside before this vault kept what reads such logs. "
                "--verify says what is wrong with each line"
            )
    more = bool(args.count) and len(events) > args.count
    if more:
        events = events[1:]
    # A re-key that switched vaults and stopped before setting the log aside: the log on disk was written under
    # the key that re-key replaced, so a failure to verify it now says nothing about tampering.
    midway = report is not None and not report.ok and archived is None and caps.unfinished_rekey() is not None
    if ctx.out.json_mode:
        verified = None if report is None else {"ok": report.ok, "count": report.count, "problems": report.problems}
        if verified is not None and midway:
            verified["unfinished_rekey"] = True
        ctx.out.json({"events": [dataclasses.asdict(event) for event in events], "verify": verified})
    else:
        ctx.out.table(
            ("time", "who", "action", "target", "detail"),
            [
                (
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.ts)),
                    _who(event),
                    event.action if event.ok else f"{event.action} (refused)",
                    _shorten(_short_id(event.target), 40),
                    _shorten(event.detail, 72),
                )
                for event in events
            ],
        )
        if report is not None:
            if events:
                ctx.out.data("")
            if report.ok:
                ctx.out.data(f"verified: all {report.count} records are authentic and in order")
            elif midway:
                ctx.out.data("NOT VERIFIED: this log was written before a re-key that has not finished")
            else:
                found = _plural(len(report.problems), "problem", "problems")
                ctx.out.data(f"ALTERED: the log fails verification ({found})")
                for problem in report.problems:
                    ctx.out.data(f"  {problem}")
    earlier = [] if archived is not None else audit.archives()
    if earlier and not ctx.out.json_mode:
        ctx.out.info(
            f"{_plural(len(earlier), 'earlier log was', 'earlier logs were')} set aside by a re-key "
            f"({', '.join(path.name for path in earlier[-3:])}{', ...' if len(earlier) > 3 else ''}). "
            "Read one with: irondome audit --archive NAME"
        )
    if not events:
        ctx.out.info(f"the audit log of bunker {_bunker()} is empty")
    elif more:
        ctx.out.info(f"showing the newest {args.count} records; -n 0 shows all of them")
    if report is not None and report.ok:
        ctx.out.info("Removing the newest records, or the whole log, is the one change verification cannot detect.")
    if midway:
        ctx.out.warn(
            f"a re-key of bunker {_bunker()} stopped part way, and its audit log is still the one written under the "
            "old vault key: it cannot be checked until that re-key is finished. Run irondome rekey; it sets the log "
            "aside and names it, and irondome audit --archive NAME --verify then checks it."
        )
        return 1
    if report is not None and not report.ok:
        ctx.out.warn(
            f"the audit log of bunker {_bunker()} was edited, cut or added to by something other than IronDome"
        )
        return 1
    return 0


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _vault_secrets(ctx: Context, vault: Vault) -> List[scan.SecretValue]:
    """Every value worth looking for: passwords (also previous ones), custom fields, one-time-password seeds."""
    found: List[scan.SecretValue] = []
    for entry in vault.list():
        try:
            secret = vault.read_secret(entry)
        except VaultError as exc:
            ctx.out.warn(f"{exc}; its values are not looked for")
            continue
        values: List[Tuple[str, Any]] = [("password", secret.password)]
        values += sorted(secret.fields.items())
        if secret.totp:
            seed = secret.totp.get("secret")
            values += [("totp", seed), ("totp", seed.lower() if isinstance(seed, str) else None)]
        values += [("previous password", item.get("password")) for item in secret.history]
        for field, value in values:
            if isinstance(value, str) and len(value) >= scan.MIN_SECRET_CHARS:
                found.append(scan.SecretValue(entry=entry.name, field=field, value=value))
    return found


def _scan(ctx: Context, args: argparse.Namespace) -> int:
    _require_owner(ctx, "scanning for leaked secrets")
    targets = scan.check_paths(args.paths)
    with _open(ctx, "look for your secrets in files") as vault:
        secrets = _vault_secrets(ctx, vault)
    if not secrets:
        ctx.out.info(f"bunker {_bunker()} holds no secret of {scan.MIN_SECRET_CHARS} or more characters to look for")
    result = scan.scan_paths(targets, secrets)
    looked_for = len({(item.entry, item.field) for item in secrets})
    del secrets
    hits = result.hits
    if ctx.out.json_mode:
        ctx.out.json(
            {
                "hits": [
                    {
                        "path": scan.path_text(hit.path),
                        "line": hit.line,
                        "entry": hit.entry,
                        "field": hit.field,
                        "encoding": hit.encoding,
                    }
                    for hit in hits
                ],
                "files_scanned": result.files_scanned,
                "files_skipped": result.files_skipped,
            }
        )
    else:
        ctx.out.table(
            ("path:line", "entry", "field", "encoding"),
            [
                (f"{scan.display_path(hit.path)}:{hit.line}", _printable(hit.entry), hit.field, hit.encoding)
                for hit in hits
            ],
        )
    summary = (
        f"looked for {_plural(looked_for, 'secret', 'secrets')} from bunker {_bunker()} in "
        f"{_plural(result.files_scanned, 'file', 'files')} ({_size(result.bytes_scanned)})"
    )
    if result.files_skipped:
        reasons = ", ".join(
            f"{count} {_SKIP_WORDS.get(reason, (reason, reason))[count != 1]}"
            for reason, count in sorted(result.skipped.items())
        )
        summary += f"; skipped {result.files_skipped}: {reasons}"
    ctx.out.info(summary)
    if not hits:
        ctx.out.ok("no secret from the vault was found")
        return 0
    leaked = len({(hit.entry, hit.field) for hit in hits})
    files = len({hit.path for hit in hits})
    ctx.out.warn(
        f"{_plural(leaked, 'secret', 'secrets')} found in {_plural(files, 'file', 'files')}. Change each one where "
        "it is used and in IronDome (irondome edit), then delete or redact those files"
    )
    return 1


# ---------------------------------------------------------------------------
# mcp
# ---------------------------------------------------------------------------


def _mcp(ctx: Context, args: argparse.Namespace) -> int:
    if ctx.out.json_mode:
        raise UsageError("--json does not apply to irondome mcp: the server already speaks JSON-RPC on stdout")
    timeout = None if args.touch_timeout is None else _seconds(args.touch_timeout)
    try:
        mcp = importlib.import_module("irondome.mcp")
    except ModuleNotFoundError as exc:
        if exc.name != "irondome.mcp":
            raise
        raise IronDomeError("this installation of IronDome has no MCP server (irondome.mcp is missing)") from None
    return int(mcp.serve(touch_timeout=timeout))


def _json_text(document: Any) -> str:
    return json.dumps(document, indent=2)


def _snippet(client: str, kind: str, file: Optional[str], text: str) -> Dict[str, Optional[str]]:
    return {"client": client, "kind": kind, "file": file, "text": text}


def _mcp_snippets(client: str) -> List[Dict[str, Optional[str]]]:
    """The verified ways to register ``irondome mcp`` in *client*. IRONDOME_GRANT comes from the environment."""
    passed = {ENV_GRANT: "${" + ENV_GRANT + "}"}
    claude = {"mcpServers": {"irondome": {"command": "irondome", "args": ["mcp"], "env": passed}}}
    if client == "claude-code":
        return [
            _snippet(client, "command", None, "claude mcp add --transport stdio --scope user irondome -- irondome mcp"),
            _snippet(client, "file", ".mcp.json", _json_text(claude)),
        ]
    if client == "claude-desktop":
        where = "~/Library/Application Support/Claude/claude_desktop_config.json"
        return [_snippet(client, "file", where, _json_text(claude))]
    if client == "cursor":
        cursor_env = {ENV_GRANT: "${env:" + ENV_GRANT + "}"}
        server = {"type": "stdio", "command": "irondome", "args": ["mcp"], "env": cursor_env}
        return [_snippet(client, "file", "~/.cursor/mcp.json", _json_text({"mcpServers": {"irondome": server}}))]
    if client == "codex":
        toml = f'[mcp_servers.irondome]\ncommand = "irondome"\nargs = ["mcp"]\nenv_vars = ["{ENV_GRANT}"]'
        return [_snippet(client, "file", "~/.codex/config.toml", toml)]
    if client == "vscode":
        vscode = {"servers": {"irondome": {"type": "stdio", "command": "irondome", "args": ["mcp"]}}}
        return [_snippet(client, "file", ".vscode/mcp.json", _json_text(vscode))]
    zed = {"context_servers": {"irondome": {"command": "irondome", "args": ["mcp"], "env": {}}}}
    return [_snippet(client, "file", "~/.config/zed/settings.json", _json_text(zed))]


_CLIENT_NAMES = {
    "claude-code": "Claude Code",
    "claude-desktop": "Claude Desktop",
    "cursor": "Cursor",
    "codex": "Codex",
    "vscode": "VS Code",
    "zed": "Zed",
}


def _irondome_path() -> Optional[str]:
    """The ``irondome`` program running now, else the one on PATH: what a client should start."""
    running = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    if os.path.basename(running) == "irondome" and os.path.isfile(running):
        return running
    return shutil.which("irondome")


def _mcp_config(ctx: Context, args: argparse.Namespace) -> int:
    clients = [args.client] if args.client else list(_MCP_CLIENTS)
    snippets = [snippet for client in clients for snippet in _mcp_snippets(client)]
    if ctx.out.json_mode:
        ctx.out.json({"snippets": snippets})
        return 0
    for index, snippet in enumerate(snippets):
        name = _CLIENT_NAMES[str(snippet["client"])]
        if snippet["kind"] == "command":
            ctx.out.info(f"{name}: run this once")
        elif snippet["file"] == ".mcp.json":
            ctx.out.info(f"{name}, for one project: add this to .mcp.json at the project's root")
        else:
            ctx.out.info(f"{name}: add this to {snippet['file']}, merged with what is already there")
        ctx.out.data(str(snippet["text"]))
        if index < len(snippets) - 1:
            ctx.out.data("")
    ctx.out.info(
        f"The server reads {ENV_GRANT} from the environment the client was started in; the token is never "
        "written into the file. Nothing was changed: copy the snippet yourself."
    )
    located = _irondome_path()
    if located:
        ctx.out.info(f"If the client cannot find irondome, write its full path instead: {located}")
    return 0


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def _wrapped(text: str) -> str:
    """A description for a parser whose epilog keeps its own line breaks."""
    return textwrap.fill(text, width=78)


def _page(description: str, examples: Sequence[Tuple[str, str]], *notes: str) -> Dict[str, Any]:
    """The help page of a command: its description, then real examples and *notes* below the options.

    *examples* are (command line, what it does) pairs, laid out as on every other page: one per line,
    what each does aligned in a column. The page keeps its own line breaks, so no example is ever
    wrapped across two lines, however narrow the terminal: each one can be copied as it stands.
    """
    width = max(len(command) for command, _what in examples) + 3
    lines = ["examples:"] + [f"  {command.ljust(width)}{what}".rstrip() for command, what in examples]
    return {
        "description": _wrapped(description),
        "epilog": "\n\n".join(["\n".join(lines)] + [_wrapped(note) for note in notes]),
        "formatter_class": argparse.RawDescriptionHelpFormatter,
    }


def _subcommands(parser: argparse.ArgumentParser, dest: str, *, required: bool = True) -> Any:
    group = parser.add_subparsers(dest=dest, metavar="<subcommand>", parser_class=type(parser))
    group.required = required
    return group


def _register_alias(subparsers: Any, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "alias",
        parents=[common],
        help="name a secret so that agents and scripts can refer to it",
        **_page(
            "An alias is the name an agent or a script uses instead of a secret: it points at one field of one "
            "entry, for example GITHUB_TOKEN at github/password. Aliases are kept in the encrypted vault, and "
            "only the vault's owner can change them.",
            [
                ("irondome alias set GITHUB_TOKEN github", "name the password of github"),
                ("irondome alias set DB_URL prod-db/url", "name a field of an entry"),
                ("irondome alias ls", "every alias, and what it names"),
            ],
        ),
    )
    group = _subcommands(parser, "alias_command")
    setter = group.add_parser(
        "set",
        parents=[common],
        help="point an alias at a field of an entry",
        **_page(
            "Point ALIAS at one field of an entry. REF is an entry name, which means its password, or "
            "entry/field, for example github/totp. An alias of the same name is replaced.",
            [
                ("irondome alias set GITHUB_TOKEN github", "the password of github"),
                ("irondome alias set GITHUB_OTP github/totp", "its one-time password"),
            ],
        ),
    )
    setter.add_argument("alias", metavar="ALIAS", help="the alias: a letter or _, then letters, digits, _ . or -")
    setter.add_argument("reference", metavar="REF", help="entry, or entry/field (default field: password)")
    setter.set_defaults(handler=_alias_set)
    remover = group.add_parser(
        "rm",
        parents=[common],
        help="remove an alias",
        **_page(
            "Remove ALIAS. The entry it pointed at is not touched, and grants already made for the alias keep "
            "working until they expire or are revoked.",
            [("irondome alias rm GITHUB_TOKEN", "the entry it named stays as it is")],
        ),
    )
    remover.add_argument("alias", metavar="ALIAS", help="the alias to remove")
    remover.set_defaults(handler=_alias_rm)
    lister = group.add_parser(
        "ls",
        parents=[common],
        help="list aliases and what they point at",
        **_page(
            "List every alias with the entry and field it points at; values are never shown. Aliases are "
            "stored encrypted, so this unlocks the vault.",
            [("irondome alias ls", ""), ("irondome alias ls --json", "the same, as JSON")],
        ),
    )
    lister.set_defaults(handler=_alias_ls)


def _register_run(subparsers: Any, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "run",
        parents=[common],
        help="run a command with secrets in its environment, masked in its output",
        **_page(
            "Run COMMAND with secrets from the vault in its environment, and replace each of them, in plain "
            "text or encoded, with [irondome:NAME] in everything the command prints. The command never gets "
            "IRONDOME_GRANT or IRONDOME_SESSION, no shell is involved, and the exit status is the command's "
            "(127 when it does not exist, 124 when --timeout stops it).",
            [
                ("irondome run --env GITHUB_TOKEN -- gh repo list", ""),
                ("irondome run --env DB_URL=prod-db/url -- ./migrate.sh", ""),
                ("irondome run -- node server.js", ""),
                ("IRONDOME_GRANT=<token> irondome run --env GITHUB_TOKEN -- gh pr create", ""),
                ("irondome run --touch --env GITHUB_TOKEN -- gh pr list", ""),
            ],
            "Secrets are also taken from irondome:// values in the environment and, unless --env-file names "
            "another file, from .env.irondome in the directory the command runs in; --env wins over both. A "
            "file found that way may only set NAME=irondome://NAME (what --env NAME does); one that sets "
            "anything else is refused until it is named with --env-file. "
            "Masking prevents accidents, not intent: a command that transforms a secret before printing it "
            "gets it through. With --json the output is captured and the command reads no input.",
            "COMMAND is looked up once, before anything is unlocked, and started by the path found then. With "
            "--touch, an agent asks the owner for Touch ID, and the prompt names that path in full, the bunker, "
            "and every secret that fits (the rest are counted). A path too long to be shown in full is refused, "
            "never shortened.",
        ),
    )
    parser.add_argument(
        "--env",
        action="append",
        metavar="VAR=REF",
        help="give VAR the value of REF (an alias, entry or entry/field); a bare ALIAS sets the variable of "
        "that name; repeatable",
    )
    parser.add_argument(
        "--env-file",
        metavar="FILE",
        help="VAR=VALUE lines: irondome:// references are resolved, other values passed on as they are "
        f"(without this option, {_ENV_FILE_NAME} in the directory the command runs in is used if there is "
        "one, and may only set NAME=irondome://NAME)",
    )
    parser.add_argument(
        "--no-mask",
        action="store_true",
        help="let the command write to the terminal directly, unfiltered (without it the command's output is a "
        "pipe that IronDome filters, not a terminal); this shows the values, so a grant "
        "or entry policy must allow revealing them",
    )
    parser.add_argument("--cwd", metavar="DIR", help="run the command in DIR")
    parser.add_argument(
        "--timeout", metavar="DURATION",
        help="stop the command, and the processes it started, after DURATION (90s, 15m, 2h); exit status 124"
    )
    parser.add_argument(
        "command", nargs=argparse.REMAINDER, metavar="-- COMMAND [ARG...]", help="the command to run, after --"
    )
    parser.set_defaults(handler=_run)


def _register_grant(subparsers: Any, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "grant",
        parents=[common],
        help="give an agent or a script a token for the secrets you name",
        **_page(
            "A grant is a token for exactly the secrets you name, for a limited time and number of uses. Give "
            "it to an agent as IRONDOME_GRANT; the agent can then use those values with irondome run, and "
            "nothing else in the vault.",
            [
                ('export IRONDOME_GRANT="$(irondome grant create GITHUB_TOKEN --ttl 15m)"', ""),
                ("irondome grant ls", ""),
                ("irondome grant revoke 3f2a9c81d0e4", ""),
            ],
        ),
    )
    group = _subcommands(parser, "grant_command")
    create = group.add_parser(
        "create",
        parents=[common],
        help="create a grant and print its token",
        **_page(
            "Snapshot the values of REF... into a new grant and print its token on stdout and nothing else, so "
            'that export IRONDOME_GRANT="$(irondome grant create ...)" works; the details go to stderr. A '
            "grant for a one-time-password field (entry/totp) holds the codes for its lifetime, never the "
            "seed. Only the vault's owner can create grants.",
            [
                ('export IRONDOME_GRANT="$(irondome grant create GITHUB_TOKEN --ttl 15m)"', ""),
                ("irondome grant create DB_URL --uses 3 --label nightly-backup", ""),
                ("irondome grant create github/totp --ttl 8h --unlimited", ""),
            ],
        ),
    )
    create.add_argument("references", nargs="+", metavar="REF", help="an alias, an entry, or entry/field")
    create.add_argument(
        "--ttl",
        metavar="DURATION",
        help="how long it lasts: 1m to 30d, at most 24h with a one-time password (default: grant_ttl, 15m)",
    )
    uses = create.add_mutually_exclusive_group()
    uses.add_argument("--uses", type=int, metavar="N", help="how many times it can be used (default 1)")
    uses.add_argument("--unlimited", action="store_true", help="any number of uses until it expires")
    create.add_argument(
        "--reveal",
        action="store_true",
        help="also allow printing the values (irondome get); by default they can only be injected",
    )
    create.add_argument(
        "--label", metavar="TEXT",
        help="a note to recognise it by in grant ls: at most 200 characters, kept in clear; under a session the "
        "grant is also marked [session ID] there, and a label may not end like that mark",
    )
    create.set_defaults(handler=_grant_create)
    lister = group.add_parser(
        "ls",
        parents=[common],
        help="list grants (needs no unlock)",
        **_page(
            "List the grants of this bunker: id, label, time left and uses left. This reads the unencrypted "
            "headers of the grant files, so it needs no unlock; only a grant's token proves what it holds.",
            [("irondome grant ls", ""), ("irondome grant ls --json", "the same, as JSON")],
        ),
    )
    lister.set_defaults(handler=_grant_ls)
    revoke = group.add_parser(
        "revoke",
        parents=[common],
        help="destroy a grant, so its token stops working",
        **_page(
            "Destroy the grant whose id starts with ID_PREFIX (at least 6 characters, as grant ls shows them), "
            "or every grant with --all. The token stops working at once. Only the owner revokes: at a terminal, "
            "where it goes ahead even if the vault cannot be opened to record it, or with a master password on "
            "stdin (--password-stdin) that opens the vault.",
            [
                ("irondome grant revoke 3f2a9c81d0e4", "one grant, by the start of its id"),
                ("irondome grant revoke --all", "every grant of this bunker"),
            ],
        ),
    )
    revoke.add_argument("id_prefix", nargs="?", metavar="ID_PREFIX", help="the start of the grant's id")
    revoke.add_argument("--all", action="store_true", help="revoke every grant of this bunker")
    revoke.set_defaults(handler=_grant_revoke)


def _register_approve(subparsers: Any, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "approve",
        parents=[common],
        help="as an agent, ask the owner for one Touch ID that approves a short, use-only grant",
        **_page(
            "The one thing an agent can ask for. The owner sees a single Touch ID prompt, written by IronDome, "
            "naming every reference, how long it lasts and the bunker; on a touch the token of a grant for "
            "exactly those references is printed on stdout: use only, any number of uses, at most 1 hour. Only "
            "entries the owner marked with irondome edit NAME --agent use (or reveal) can be approved, and only "
            "on a Mac whose vault has a Touch ID keyslot; anywhere else, ask the owner for a grant.",
            [
                ('export IRONDOME_GRANT="$(irondome approve GITHUB_TOKEN --ttl 10m)"', ""),
                ('export IRONDOME_GRANT="$(irondome --bunker work approve DB_URL)"', ""),
            ],
        ),
    )
    parser.add_argument("references", nargs="+", metavar="REF", help="an alias, an entry, or entry/field")
    parser.add_argument("--ttl", metavar="DURATION", help="how long the grant lasts: 1m to 1h (default 10m)")
    parser.set_defaults(handler=_approve)


def _register_sessions(subparsers: Any, common: argparse.ArgumentParser) -> None:
    starter = subparsers.add_parser(
        "unlock",
        parents=[common],
        help="start a session, so this shell needs no password for a while",
        **_page(
            "Unlock the vault and start a session: prints export IRONDOME_SESSION='...' for the shell to run, "
            'so use it as eval "$(irondome unlock)". The token opens the whole vault until it expires or '
            "irondome lock ends it, so it is never printed to a terminal, and it must never be given to an "
            "agent: agents get grants.",
            [
                ('eval "$(irondome unlock)"', "a session for this shell"),
                ('eval "$(irondome unlock --ttl 1h)"', "one that lasts an hour"),
            ],
        ),
    )
    starter.add_argument(
        "--ttl", metavar="DURATION", help="how long the session lasts: 1m to 12h (default: session_ttl, 15m)"
    )
    starter.add_argument("--print-token", action="store_true", help="print only the token, even to a terminal")
    starter.set_defaults(handler=_unlock)
    ender = subparsers.add_parser(
        "lock",
        parents=[common],
        help="end the session in IRONDOME_SESSION, or every session",
        **_page(
            "End the session named by IRONDOME_SESSION, or every session of this bunker with --all, and print "
            'unset IRONDOME_SESSION for the shell: use it as eval "$(irondome lock)". The grants made under a '
            "session are revoked with it. Succeeds quietly when there is nothing to end.",
            [
                ('eval "$(irondome lock)"', "end the session of this shell"),
                ('eval "$(irondome lock --all)"', "end every session of this bunker"),
            ],
        ),
    )
    ender.add_argument("--all", action="store_true", help="end every session of this bunker (owner only)")
    ender.set_defaults(handler=_lock)


def _register_audit(subparsers: Any, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "audit",
        parents=[common],
        help="show what grants, sessions and Touch ID approvals used, and every change",
        **_page(
            "Show the newest records of the encrypted, hash-chained audit log: every use of a grant, a session "
            "or a Touch ID approval, and every change to the vault. With --verify every line is also checked, "
            "and the exit status is 1 if any was edited, removed, reordered or forged.",
            [
                ("irondome audit", f"the newest {_AUDIT_COUNT} records"),
                ("irondome audit -n 0 --verify", "every record, each one checked"),
                ("irondome audit -n 200 --json", "the newest 200, as JSON"),
                ("irondome audit --archive NAME --verify", "a log from before a re-key"),
            ],
        ),
    )
    parser.add_argument(
        "-n",
        dest="count",
        type=int,
        default=_AUDIT_COUNT,
        metavar="N",
        help=f"show the newest N records (default {_AUDIT_COUNT}; 0 shows all)",
    )
    parser.add_argument("--verify", action="store_true", help="check every line; exit status 1 if the log was altered")
    parser.add_argument(
        "--archive", metavar="NAME",
        help="read a log that a re-key set aside (audit-<time>.log in the bunker's directory), not the current one",
    )
    parser.set_defaults(handler=_audit)


def _register_scan(subparsers: Any, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "scan",
        parents=[common],
        help="find secrets from the vault that leaked into files",
        **_page(
            "Search files and directories, such as agent transcripts, logs, repositories and shell history, for "
            "every secret of 8 or more characters in this vault (passwords, custom fields, one-time-password "
            "seeds), in plain text and base64, hex, percent, JSON and shell-quoted form. Prints where each one "
            "is (path, line, entry, field, encoding), never the value, and exits with status 1 when anything "
            "is found.",
            [("irondome scan ~/.claude ~/.codex ~/.zsh_history .", ""), ("irondome scan --json ~/project", "")],
            "Links inside directories are not followed; files over 50 MB, unreadable files and anything that "
            "is not a regular file are skipped and counted. Compressed files (git objects, archives) are "
            "searched as they are, not unpacked.",
        ),
    )
    parser.add_argument("paths", nargs="+", metavar="PATH", help="a file or directory to search")
    parser.set_defaults(handler=_scan)


def _register_mcp(subparsers: Any, common: argparse.ArgumentParser) -> None:
    parser = subparsers.add_parser(
        "mcp",
        parents=[common],
        help="serve the Model Context Protocol to an AI agent, over stdio",
        **_page(
            "Serve the Model Context Protocol on stdin and stdout, so that an agent can list the names it may "
            "use, run commands with secrets injected and output masked, and read one-time codes, under the "
            "same rules as the command line. irondome mcp config prints how to register it in a client.",
            [
                ("irondome mcp", "what an MCP client starts"),
                ("irondome mcp --touch-timeout 120", "a Touch ID prompt waits 2 minutes"),
                ("irondome mcp config --client claude-code", "how to register it in Claude Code"),
            ],
        ),
    )
    parser.add_argument(
        "--touch-timeout",
        metavar="SECONDS",
        help="how long a Touch ID prompt waits for the owner before the request fails (the server sets the range)",
    )
    parser.set_defaults(handler=_mcp)
    group = _subcommands(parser, "mcp_command", required=False)
    configure = group.add_parser(
        "config",
        parents=[common],
        help="print how to register irondome mcp in an MCP client",
        **_page(
            "Print the exact command or configuration snippet that registers irondome mcp as a local stdio "
            "server in CLIENT, or in every client when none is named. IRONDOME_GRANT is passed through from the "
            "environment, never written into a file, and nothing is edited: stderr says where the snippet goes.",
            [
                ("irondome mcp config --client claude-code", "the snippet for Claude Code"),
                ("irondome mcp config --json", "every snippet, as JSON"),
            ],
        ),
    )
    configure.add_argument(
        "--client",
        choices=_MCP_CLIENTS,
        metavar="CLIENT",
        help=f"the client to print the snippet for: {', '.join(_MCP_CLIENTS[:-1])} or {_MCP_CLIENTS[-1]}",
    )
    configure.set_defaults(handler=_mcp_config)


def register(subparsers: Any, common: argparse.ArgumentParser) -> None:
    """Add alias, run, approve, grant, unlock, lock, audit, scan and mcp to the command line."""
    _register_alias(subparsers, common)
    _register_run(subparsers, common)
    _register_approve(subparsers, common)
    _register_grant(subparsers, common)
    _register_sessions(subparsers, common)
    _register_audit(subparsers, common)
    _register_scan(subparsers, common)
    _register_mcp(subparsers, common)
