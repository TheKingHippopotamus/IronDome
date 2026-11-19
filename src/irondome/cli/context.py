"""What a command needs, and the single place that decides how it gets it.

Who is asking
-------------
*A person* has a terminal. They are asked for the master password, or touch
the sensor, and may then do anything.

*An agent or a script* has no terminal. It can reach secrets in exactly three
ways, each of them something the owner set up on purpose:

``IRONDOME_GRANT``    a grant token. Access is limited to the values named in
                      the grant, to its mode, its lifetime and its use count.
``--touch``           a Touch ID prompt on the owner's screen for this one
                      command. Access is limited to entries the owner marked
                      for agents (``irondome edit NAME --agent use|reveal``).
``--password-stdin``  the master password itself. That is the owner, by
                      definition; nothing is restricted.

``IRONDOME_SESSION`` (from ``irondome unlock``) is the owner's convenience for
their own shell and grants full access. It should never be exported into an
agent's environment; that is what grants are for.

Proving the owner
-----------------
A flag proves nothing: an agent can pass ``--password-stdin`` or ``--yes`` as
easily as anyone. An agent may even run in the owner's own terminal session,
inheriting the terminal, but it cannot answer a hidden password prompt or type
a confirmation into it. So a command that acts without unlocking the vault
(``bunker use``, ``bunker rm``, ``nuke``, ``lock --all``, ``grant revoke``)
calls :meth:`Context.prove_owner` first: a person at a terminal passes, and
the questions that follow are put to them; with ``--password-stdin`` the
password must actually open the vault.
"""

from __future__ import annotations

import argparse
import contextlib
import hmac
import io
import os
import stat
import sys
from typing import Iterator, List, Optional, Sequence

from irondome import audit, caps, paths
from irondome.cli.output import Output
from irondome.errors import AuthError, HardwareError, IronDomeError, PolicyError, UsageError, VaultError
from irondome.generator import estimate_strength
from irondome.keys import KIND_DEVICE
from irondome.secmem import SecureBuffer, read_secret, read_secret_from_fd
from irondome.unlock import can_ask_for_touch, check_new_password, unlock
from irondome.vault import Entry, Vault, VaultFile, vault_exists

__all__ = [
    "ENV_SESSION",
    "ENV_GRANT",
    "ENV_TOUCH",
    "ENV_NO_PROMPT",
    "Context",
    "Access",
    "PURPOSE_USE",
    "PURPOSE_REVEAL",
    "readable_vault",
]

ENV_SESSION = "IRONDOME_SESSION"
ENV_GRANT = "IRONDOME_GRANT"
ENV_TOUCH = "IRONDOME_TOUCH"
ENV_NO_PROMPT = "IRONDOME_NO_PROMPT"

#: The value will be handed to a child process and never shown.
PURPOSE_USE = "use"
#: The value will be printed or copied.
PURPOSE_REVEAL = "reveal"


def _has_terminal() -> bool:
    """True when there is a terminal on which a person could answer a prompt."""
    if os.environ.get(ENV_NO_PROMPT) == "1":
        return False
    if os.name == "nt":
        try:
            return sys.stdin.isatty()
        except (AttributeError, ValueError):
            return False
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return False
    os.close(fd)
    return True


def _token(variable: str) -> Optional[str]:
    """A session or grant token from the environment, without the whitespace a copy or ``$(...)`` adds."""
    value = os.environ.get(variable, "").strip()
    return value or None


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


def _note_refusal(grant: "caps.Grant", purpose: str, references: Sequence[str], why: str, detail: str) -> None:
    """Tell the owner, in the grant's own audit records, that it was asked for more than it allows. Best effort."""
    try:
        audit.record(
            grant.audit_key, vault_id=grant.vault_id, kid=grant.id, action=purpose, actor="grant",
            target=", ".join(references), detail=f"refused before any use: {why}; {detail}", ok=False,
        )
    except IronDomeError:
        pass  # the refusal stands whether or not it could be written down


def readable_vault(bunker: str) -> VaultFile:
    """The vault file of *bunker*, or a :class:`VaultError` that says why no password can be checked against it."""
    with _in_bunker(bunker):
        if not vault_exists():
            raise VaultError(
                f"there is no vault in bunker {bunker}, so there is no master password to check; "
                "run the command at a terminal instead"
            )
        try:
            return VaultFile.load()
        except VaultError as exc:
            raise VaultError(
                f"the vault of bunker {bunker} cannot be read ({exc}), so its master password cannot be checked; "
                "run the command at a terminal instead"
            ) from None


_WEAK_LABELS = ("very weak", "weak")


class _TryAgain(UsageError):
    """A new master password that was too short, or typed two different ways: worth asking for again."""


class Context:
    """Per-invocation state shared by every command.

    ``agent=True`` is for code that serves an agent, such as the MCP server: the
    invocation is never the owner's, whatever terminal the process inherited.
    *inject_with* names, in refusals, the way that caller hands values to a
    program without showing them.
    """

    def __init__(
        self, args: argparse.Namespace, out: Output, *, agent: bool = False, inject_with: str = "`irondome run`"
    ) -> None:
        self.args = args
        self.out = out
        self.agent = agent
        self.inject_with = inject_with
        self.has_terminal = False if agent else _has_terminal()
        self.password_stdin = bool(getattr(args, "password_stdin", False))
        self.assume_yes = bool(getattr(args, "yes", False))
        self.no_touch = bool(getattr(args, "no_touch", False))
        self.touch = bool(getattr(args, "touch", False)) or os.environ.get(ENV_TOUCH) == "1"
        #: How the vault was opened by the last open_vault(): session, touch or password.
        self.unlocked_by: Optional[str] = None
        #: When the session that opened the vault ends (Unix time), if a session did.
        self.session_expires: Optional[int] = None
        self._asked_password = False
        #: What the vault is being opened for, in words: shown before the master password is asked for.
        self._purpose = ""
        self._rekey_noted = False
        self._exposure_noted = False

    # -- who is asking --------------------------------------------------------

    @property
    def agent_mode(self) -> bool:
        """An agent or a script: no terminal and no master password supplied, or a caller that serves an agent.

        Not being in agent mode proves nothing by itself: ``--password-stdin`` is a flag, and an agent can
        pass it. A command that acts without unlocking the vault calls :meth:`prove_owner` as well.
        """
        return self.agent or (not self.has_terminal and not self.password_stdin)

    def prove_owner(self, action: str, *, bunker: Optional[str] = None, keep_open: bool = False) -> Optional[Vault]:
        """Refuse *action* unless the vault's owner is the one asking. Call it before anything changes.

        What proves the owner:

        * a person at a terminal, without ``--password-stdin``. An agent that inherited that terminal is
          let through as well, so what follows must put a question to the person: an agent can neither
          answer a hidden password prompt nor type a confirmation;
        * with ``--password-stdin``, the master password of *bunker* (the current bunker by default) on
          the next line of stdin. The vault is unlocked with it afresh, never with a session token, and
          its key is wiped at once. With *keep_open* (current bunker only) the vault is returned open
          instead, for the caller to use and close.

        ``agent=True`` (a caller that serves an agent) is refused outright, and so is anything else: no
        terminal and no password raises a :class:`PolicyError` that says what would work. A password
        that does not open the vault raises what unlocking raises: :class:`AuthError` for a wrong one,
        :class:`VaultError` when there is no readable vault to check it against, :class:`HardwareError`
        when the vault's device key cannot be used here.
        """
        name = paths.bunker_name() if bunker is None else paths.validate_bunker_name(bunker)
        if self.agent:
            raise PolicyError(
                f"{action} is for the vault's owner, and this request comes from a program that serves an agent. "
                "The owner can run it at a terminal."
            )
        if not self.password_stdin:
            if self.has_terminal:
                return None
            raise PolicyError(
                f"{action} is for the vault's owner: run it at a terminal, or give the master password of bunker "
                f"{name} with --password-stdin. An agent or a script without either cannot do it."
            )
        if keep_open and name != paths.bunker_name():
            raise ValueError("prove_owner(keep_open=True) works on the current bunker only")
        file = readable_vault(name)  # refused before a password is read for a vault that cannot check it
        password = self.master_password()
        try:
            key = self._unlock_with(file, password, bunker=name, reason=f"confirm that you own IronDome bunker {name}")
        except AuthError as exc:
            if len(paths.bunkers()) < 2:
                raise
            raise type(exc)(f"bunker {name}: {exc}") from None  # where there are several, say which one refused
        finally:
            password.wipe()
        if not keep_open:
            key.wipe()
            if name == paths.bunker_name():
                self.note_unfinished_rekey()  # an owner command that unlocked; the index is not read here
            return None
        self.unlocked_by = "password"
        return self._opened(Vault(file, key))

    def check_master_password(self, password: SecureBuffer, *, bunker: str, reason: str) -> None:
        """Raise unless *password* alone opens the vault of *bunker*. A session never counts.

        The vault key is wiped at once. *password* is not: one password can be checked against
        several vaults (``nuke``).
        """
        self._unlock_with(readable_vault(bunker), password, bunker=bunker, reason=reason).wipe()

    def _unlock_with(self, file: VaultFile, password: SecureBuffer, *, bunker: str, reason: str) -> SecureBuffer:
        """The vault key *password* opens in *file*, the vault of *bunker*. The caller wipes it."""
        may_touch = not self.no_touch and (self.has_terminal or self.touch)
        with _in_bunker(bunker):  # the device key it needs is the bunker's own
            return unlock(
                file,
                password=password,
                interactive=may_touch or self.has_terminal,
                allow_touch=may_touch,
                reason=reason,
            )

    # -- talking to the person ------------------------------------------------

    def _read_line(self, prompt: str) -> str:
        if not self.has_terminal:
            raise UsageError("this needs an answer from a person, and there is no terminal to ask on")
        if os.name == "nt":
            self.out.stderr.write(prompt)
            self.out.stderr.flush()
            return sys.stdin.readline().rstrip("\r\n")
        # A terminal is not seekable, so open() in "r+" text mode (which wants a
        # BufferedRandom) fails on it. Wrap the raw descriptor, as getpass does.
        try:
            fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        except OSError:
            raise UsageError("this needs an answer from a person, and the terminal cannot be opened") from None
        with io.TextIOWrapper(io.FileIO(fd, "r+"), encoding="utf-8", errors="replace") as tty:
            tty.write(self.out.prompt(prompt))
            tty.flush()
            return tty.readline().rstrip("\r\n")

    def ask(self, prompt: str) -> str:
        """Ask for a line of non-secret text."""
        return self._read_line(prompt)

    def confirm(self, question: str, *, default: bool = False) -> bool:
        """Yes/no. ``--yes`` answers yes; without a terminal it refuses rather than guess."""
        if self.assume_yes:
            return True
        if not self.has_terminal:
            raise UsageError("this needs confirmation; run it again with --yes to confirm without a prompt")
        answer = self._read_line(f"{question} [{'Y/n' if default else 'y/N'}] ").strip().lower()
        if not answer:
            return default
        return answer in ("y", "yes")

    def confirm_phrase(self, question: str, phrase: str) -> bool:
        """Require the exact *phrase* to be typed. Used before irreversible actions."""
        if not self.has_terminal:
            raise UsageError(
                "this is irreversible and must be confirmed by a person at a terminal, or with its --yes flag"
            )
        return self._read_line(f"{question}\nType {phrase} to continue: ").strip() == phrase

    @property
    def typed_stdin(self) -> bool:
        """True when what a command reads from stdin would be typed by a person at this terminal.

        A line read from a terminal is echoed, and a command that waits for one without a prompt looks
        hung. So wherever a command would take a line from stdin (``--password-stdin``, ``--value-stdin``,
        ``--totp-stdin``, the value of a ``--field``) it asks at a hidden prompt instead when this is true:
        the same lines, in the same order, typed unseen.
        """
        if not self.has_terminal:
            return False
        try:
            return os.isatty(0)
        except OSError:
            return False

    def read_secret(self, prompt: str, *, allow_empty: bool = False) -> Optional[SecureBuffer]:
        """One secret, from the next line of stdin (--password-stdin) or from the terminal."""
        if self.password_stdin and not self.typed_stdin:
            return read_secret_from_fd(0, allow_empty=allow_empty)
        if not self.has_terminal:
            raise AuthError(
                "there is no terminal to ask on. Pipe the value with --password-stdin, "
                "or use a grant (IRONDOME_GRANT) or session (irondome unlock) token."
            )
        return read_secret(self.out.prompt(prompt), allow_empty=allow_empty)

    def master_password(self, purpose: Optional[str] = None) -> SecureBuffer:
        """The current master password, in locked memory. The caller wipes it.

        *purpose* says, in words, what typing it will do (``create a grant for stripe``); without one,
        what the vault is being opened for by :meth:`open_vault`. It is shown on the terminal itself,
        as part of the prompt, with anything a terminal would act on escaped.
        """
        self._asked_password = True
        if not self.password_stdin and not self.has_terminal:
            raise AuthError(
                "the vault is locked and there is no terminal to ask for the master password.\n"
                "  For an agent or script: set IRONDOME_GRANT to a grant token (irondome grant create),\n"
                "  or pass --touch on a Mac with Touch ID. For yourself: pipe it with --password-stdin."
            )
        # The prompt is what stands between a program in this terminal and the vault: it says what typing
        # the password will do, so that a person does not authorise something they did not ask for. It is
        # written by the prompt itself, on the terminal: redirecting stderr, or --quiet, does not hide it.
        said = purpose if purpose is not None else self._purpose
        shown = "".join(char if char.isprintable() else repr(char)[1:-1] for char in said)[:200]
        password = self.read_secret(f"To {shown}:\nMaster password: " if shown else "Master password: ")
        if password is None:
            raise AuthError("the master password cannot be empty")
        return password

    def new_master_password(self) -> SecureBuffer:
        """A new master password, asked twice on a terminal. The caller wipes it.

        At a terminal a password that is too short, or two entries that differ, are asked for again,
        three times in all: a command that gave up at the first slip would leave whatever the person
        typed next, often the password once more, to be read by the shell as a command.
        """
        attempts = 1 if self.password_stdin or not self.has_terminal else 3
        while True:
            attempts -= 1
            try:
                password = self._new_master_password_once()
            except _TryAgain as exc:
                if attempts <= 0:
                    raise UsageError(str(exc)) from None
                self.out.error(f"{exc}. Try again.")
                continue
            try:
                self._warn_if_weak(password)
            except BaseException:
                password.wipe()
                raise
            return password

    def _warn_if_weak(self, password: SecureBuffer) -> None:
        """A remark, never a refusal, when a new master password is one a guessing program finds early.

        Made wherever a new master password is taken (``init``, ``bunker create``, ``passwd``, ``recovery
        use``), so that none of them accepts ``password`` without a word.
        """
        strength = estimate_strength(password)
        if strength.label in _WEAK_LABELS:
            reason = f" ({strength.warnings[0]})" if strength.warnings else ""
            self.out.warn(
                f"that master password is {strength.label}{reason}. The device key keeps a copied vault file from "
                "being guessed at, but whoever has this machine or its files can still try passwords: a longer "
                "passphrase costs nothing here (irondome gen --words 6 makes one; irondome passwd changes it)"
            )

    def _new_master_password_once(self) -> SecureBuffer:
        """One try. :class:`_TryAgain` for a slip of the fingers; anything else (input closed) ends it."""
        first = self.read_secret("New master password: ")
        if first is None:
            raise _TryAgain("the master password cannot be empty")
        try:
            try:
                check_new_password(first)
            except UsageError as exc:
                raise _TryAgain(str(exc)) from None
            if not self.password_stdin:
                second = self.read_secret("Repeat it: ")
                try:
                    if second is None or not hmac.compare_digest(first.view(), second.view()):
                        raise _TryAgain("the two entries do not match")
                finally:
                    if second is not None:
                        second.wipe()
        except BaseException:
            first.wipe()
            raise
        return first

    # -- the vault ------------------------------------------------------------

    def open_vault(self, *, reason: str = "unlock your IronDome vault", fresh: bool = False) -> Vault:
        """Unlock the vault for this command. The caller must close it.

        ``fresh=True`` ignores a session token: commands that change how the
        vault is protected always ask for the real thing.
        """
        file = VaultFile.load()
        self.unlocked_by = None
        self._asked_password = False
        self._purpose = reason
        token = _token(ENV_SESSION)
        if token and not fresh:
            try:
                vault_key = caps.open_session(token, file)
            except (AuthError, HardwareError) as exc:
                # A session that cannot be used right now (a locked Mac, a busy TPM) is no reason
                # to fail: the person at the terminal can still unlock the usual way.
                self.out.warn(f"ignoring {ENV_SESSION}: {exc}")
            else:
                self.unlocked_by = "session"
                self.session_expires = caps.session_expires(token)
                return self._opened(Vault(file, vault_key))

        supplied: Optional[SecureBuffer] = self.master_password() if self.password_stdin else None
        may_touch = not self.no_touch and (self.has_terminal or self.touch)
        has_touch_slot = any(slot.kind == KIND_DEVICE for slot in file.slots)
        if self.agent_mode and not may_touch:
            hint = "  or pass --touch to ask the owner for Touch ID,\n" if has_touch_slot else ""
            raise AuthError(
                "the vault is locked and nothing here can unlock it.\n"
                "  Set IRONDOME_GRANT to a grant token (the owner creates one with: irondome grant create),\n"
                f"{hint}"
                "  or pipe the master password with --password-stdin."
            )
        if self.agent_mode:
            # --touch from an agent: the owner's finger is the only thing it can ask for.
            if not has_touch_slot:
                raise AuthError(
                    "--touch asks the vault's owner for Touch ID, and this vault has no keyslot that opens with "
                    "Touch ID alone.\n"
                    "  Ask the owner for a grant (irondome grant create) and set IRONDOME_GRANT to its token.\n"
                    "  irondome approve needs such a keyslot too; the owner adds one with: irondome auth touchid"
                )
            if not can_ask_for_touch():
                raise AuthError(
                    "--touch asks the vault's owner for Touch ID, and Touch ID cannot be asked for here (it needs a "
                    "desktop session on the owner's Mac, and IRONDOME_NO_TOUCH must not be set).\n"
                    "  Ask the owner for a grant (irondome grant create) and set IRONDOME_GRANT to its token."
                )
        try:
            vault_key = unlock(
                file,
                password=supplied,
                password_source=self.master_password if (supplied is None and self.has_terminal) else None,
                interactive=may_touch or self.has_terminal,
                allow_touch=may_touch,
                reason=reason,
            )
        finally:
            if supplied is not None:
                supplied.wipe()
        self.unlocked_by = "password" if self._asked_password else "touch"
        return self._opened(Vault(file, vault_key))

    def _opened(self, vault: Vault) -> Vault:
        """Housekeeping on every unlock: expired sessions and grants are destroyed and recorded.

        It also says, on every unlock, that a re-key has not finished (:meth:`note_unfinished_rekey`).
        """
        self.note_unfinished_rekey(vault)
        self._note_exposed_files()
        try:
            caps.sweep(vault=vault)
        except IronDomeError as exc:
            self.out.warn(f"could not clear expired sessions and grants: {exc}")
        return vault

    def _note_exposed_files(self) -> None:
        """Warn, once per command, when this bunker's vault, device key or their directories are open to others.

        IronDome makes them owner-only, and a later ``chmod``, a restore or a sync tool can undo that. The
        vault file is encrypted either way; a file-based device key that others can read is half of what
        opens it. ``irondome doctor`` lists every file with its fix; this is the nudge to run it.
        """
        if self._exposure_noted or os.name != "posix":
            return
        self._exposure_noted = True
        places = [paths.root(), paths.home(), paths.vault_file(), paths.device_dir()]
        try:
            places += sorted(path for path in paths.device_dir().iterdir())[:16]
        except OSError:
            pass
        loose = []
        for path in places:
            try:
                info = os.lstat(str(path))
            except OSError:
                continue
            if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o077:
                loose.append(f"{path} (mode {stat.S_IMODE(info.st_mode):04o})")
        if loose:
            more = f" and {len(loose) - 1} more" if len(loose) > 1 else ""
            self.out.warn(
                f"other users of this machine can reach {loose[0]}{more}; IronDome keeps these owner-only. "
                "irondome doctor lists each one with the command that fixes it"
            )

    def note_unfinished_rekey(self, vault: Optional[Vault] = None) -> None:
        """Warn, once per command, while a re-key of the current bunker has not finished, and say how to finish.

        Two marks, either of which ``irondome rekey`` clears:

        * a staging file holding the live vault's id (:func:`caps.unfinished_rekey`): the re-key stopped after
          its switch (SIGKILL, a crash, a power cut), so the old sessions, grants, snapshots and device keys may
          all still be there, and the new recovery key may never have been shown. Seen without a key, so
          ``status`` and ``doctor`` report it too; meanwhile every session and grant is refused.
        * the re-key plan still in the unlocked *vault*'s index (``caps.REKEY_PLAN``), with no such staging file:
          a re-key finished except for old device keys it could not destroy. Those keys could still open copies
          of the old vault's sessions and grants on this machine; the next re-key tries them again.
        """
        if self._rekey_noted:
            return
        staged = caps.unfinished_rekey()
        if staged is not None:
            self._rekey_noted = True
            self.out.warn(caps.unfinished_rekey_warning(staged))
            return
        plan = vault.meta.get(caps.REKEY_PLAN) if vault is not None else None
        if isinstance(plan, dict):
            held = plan.get("devices")
            count = len(held) if isinstance(held, list) else 0
            self._rekey_noted = True
            self.out.warn(
                f"the last re-key of bunker {paths.bunker_name()} did not finish: "
                + (f"{count} old device key{'' if count == 1 else 's'} of the vault it replaced could not be "
                   "destroyed. " if count else "")
                + "Finish it with: irondome rekey"
            )

    def open_vault_by_touch(self, *, reason: str) -> Vault:
        """Unlock through a Touch ID keyslot and nothing else. The caller must close it.

        This is how an agent asks its owner for something: no password, session
        or grant can stand in for the touch. *reason* is shown in the prompt.
        """
        file = VaultFile.load()
        self.unlocked_by = None
        if not any(slot.kind == KIND_DEVICE for slot in file.slots):
            raise AuthError(
                "this vault has no Touch ID keyslot, so there is nothing to approve with.\n"
                "  Ask the vault's owner for a grant (irondome grant create), "
                "or to enrol Touch ID (irondome auth touchid)."
            )
        if self.no_touch or not can_ask_for_touch():
            raise AuthError(
                "Touch ID cannot be asked for here (not a Mac desktop session, or it was switched off). "
                "Ask the vault's owner for a grant: irondome grant create"
            )
        vault_key = unlock(file, interactive=True, allow_touch=True, reason=reason)
        self.unlocked_by = "touch"
        return self._opened(Vault(file, vault_key))

    # -- access to values (get, otp, run, the MCP server) ---------------------

    def access(
        self,
        *,
        reason: str = "read from your IronDome vault",
        consume: bool = True,
        references: Optional[Sequence[str]] = None,
        purpose: str = PURPOSE_USE,
        detail: str = "",
        reveal_hint: str = "",
    ) -> "Access":
        """Open whatever this invocation is entitled to read from.

        A grant token wins when one is set (unless ``--no-grant``): the point
        of a grant is that its holder gets the grant and nothing more.

        Opening a grant for real (*consume*) costs one of its uses. Given the
        *references* the caller will read and their *purpose*, the grant is
        looked at first without spending anything, and a request it would
        refuse is refused there: a reference it does not cover, or a reveal
        under a use-only grant (a one-time code may be revealed under any
        grant, as :meth:`Access.value` allows). The refusal is recorded under
        the grant's own key with *detail*; *reveal_hint* says, in that
        refusal, what in the request would have shown the values.
        """
        token = _token(ENV_GRANT)
        if token and not getattr(self.args, "no_grant", False):
            if consume and references is not None:
                self._look_at_grant(token, references, purpose, detail, reveal_hint)
            return Access(self, grant=caps.open_grant(token, consume=consume))
        vault = self.open_vault(reason=reason)
        restricted = self.agent_mode and self.unlocked_by == "touch"
        return Access(self, vault=vault, restricted=restricted)

    def _look_at_grant(
        self, token: str, references: Sequence[str], purpose: str, detail: str, reveal_hint: str
    ) -> None:
        """Refuse, before a use is spent, what the grant in *token* would refuse once opened."""
        with caps.open_grant(token, consume=False) as grant:
            outside = [reference for reference in references if not grant.has(reference)]
            if outside:
                _note_refusal(grant, purpose, outside, "not covered by this grant", detail)
                raise PolicyError(
                    f"this grant does not cover {outside[0]!r}; it covers: {', '.join(sorted(grant.names()))}. "
                    f"Nothing was used. ({ENV_GRANT} is set, so the grant answered; the owner opens the vault "
                    "instead with --no-grant after the command's name)"
                )
            if purpose == PURPOSE_REVEAL and grant.mode != caps.MODE_REVEAL:
                hidden = [reference for reference in references if not grant.is_totp(reference)]
                if hidden:
                    _note_refusal(grant, purpose, hidden, "showing a value under a use-only grant", detail)
                    hint = f" ({reveal_hint})" if reveal_hint else ""
                    raise PolicyError(
                        f"this grant only allows injecting its values into a command with {self.inject_with}; "
                        f"it does not allow showing them{hint}. Nothing was used"
                    )

    # -- audit ----------------------------------------------------------------

    def audit(self, vault: Vault, action: str, *, target: str = "", detail: str = "", ok: bool = True) -> None:
        """Record an owner-side event. A failing audit log is a warning, not a failed command.

        Who did it is what proved them: ``session`` when a session token opened the vault for this
        command, with or without a terminal, since anything that holds the token could have run it;
        ``agent`` when the master password or Touch ID opened it for a command that had no terminal
        (a program ran it, not a person at a keyboard); ``owner`` otherwise.
        """
        actor = "session" if self.unlocked_by == "session" else ("agent" if self.agent_mode else "owner")
        try:
            with audit.owner_key(vault) as key:
                audit.record(
                    key, vault_id=vault.vault_id, kid=audit.KID_VAULT, action=action, actor=actor, target=target,
                    detail=detail, ok=ok,
                )
        except IronDomeError as exc:
            self.out.warn(f"could not write the audit log: {exc}")


class Access:
    """A read-only view of the secrets this invocation may use: a grant or the vault."""

    def __init__(
        self,
        ctx: Context,
        *,
        grant: Optional["caps.Grant"] = None,
        vault: Optional[Vault] = None,
        restricted: bool = False,
    ) -> None:
        if (grant is None) == (vault is None):
            raise ValueError("Access needs exactly one of a grant or a vault")
        self.ctx = ctx
        self.grant = grant
        self.vault = vault
        self.restricted = restricted

    @property
    def via_grant(self) -> bool:
        return self.grant is not None

    def names(self) -> List[str]:
        """The references this access can resolve (aliases and entry names).

        Listing is all a grant opened with ``consume=False`` can do: it holds
        no values, so reading one always costs a use.
        """
        if self.grant is not None:
            return sorted(self.grant.names())
        vault = self._vault()
        entries = [entry for entry in vault.list() if not self.restricted or entry.agent != "deny"]
        allowed = {entry.id for entry in entries}
        aliases = [name for name, alias in vault.aliases.items() if alias.entry in allowed]
        return sorted(aliases) + [entry.name for entry in entries]

    def _check_policy(self, entry: Entry, field: str, purpose: str) -> None:
        if not self.restricted:
            return
        if entry.agent == "deny":
            raise PolicyError(
                f"{entry.name!r} is not available to agents. Its owner can allow it with: "
                f"irondome edit {entry.name!r} --agent use"
            )
        if purpose == PURPOSE_REVEAL and field != "totp" and entry.agent != "reveal":
            raise PolicyError(
                f"{entry.name!r} may be used by agents but not shown to them. Inject it with {self.ctx.inject_with}, "
                f"or its owner can allow showing it with: irondome edit {entry.name!r} --agent reveal"
            )

    def value(self, reference: str, purpose: str, *, detail: str = "") -> str:
        """Resolve *reference* for *purpose*, enforcing scope and recording the access."""
        if self.grant is not None:
            grant = self.grant
            if not grant.has(reference):
                covered = ", ".join(sorted(grant.names()))
                raise PolicyError(f"this grant does not cover {reference!r}; it covers: {covered}")
            if purpose == PURPOSE_REVEAL and grant.mode != "reveal" and not grant.is_totp(reference):
                raise PolicyError(
                    f"this grant only allows injecting values into a command with {self.ctx.inject_with}; "
                    "it does not allow printing them"
                )
            self._record_grant(purpose, reference, detail)
            return grant.value(reference)
        vault = self._vault()
        entry, field = vault.resolve(reference)
        self._check_policy(entry, field, purpose)
        if self.ctx.agent_mode or self.ctx.unlocked_by == "session":
            # Recorded before the value is read: an access that cannot be
            # logged does not happen.
            with audit.owner_key(vault) as key:
                audit.record(
                    key, vault_id=vault.vault_id, kid=audit.KID_VAULT, action=purpose,
                    actor="session" if self.ctx.unlocked_by == "session" else "agent",
                    target=f"{entry.name}/{field}", detail=detail,
                )
        return vault.value(entry, field)

    def _vault(self) -> Vault:
        if self.vault is None:
            raise IronDomeError("this access is closed")
        return self.vault

    def _record_grant(self, action: str, reference: str, detail: str) -> None:
        """Record which value a grant was used for. Raises if the log cannot be written."""
        grant = self.grant
        if grant is None:
            return
        audit.record(
            grant.audit_key, vault_id=grant.vault_id, kid=grant.id, action=action, actor="grant",
            target=reference, detail=detail,
        )

    def close(self) -> None:
        if self.vault is not None:
            self.vault.close()
            self.vault = None
        if self.grant is not None:
            closer = getattr(self.grant, "close", None)
            if callable(closer):
                closer()
            self.grant = None

    def __enter__(self) -> "Access":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
