"""The ``irondome`` command.

One program, subcommands, no interactive menus. Conventions:

* stdout carries the result, stderr carries prompts and messages;
* ``--json`` on any command prints one JSON document on stdout instead of
  text: the result, or, when the command fails before printing it,
  ``{"ok": false, "error": "<message>", "exit_code": <n>}`` (the message is on
  stderr as text as well). ``--version --json`` prints what
  ``irondome version --json`` prints; ``--help`` is always plain text;
* exit status: 0 ok · 1 error · 2 bad usage · 3 not found · 4 authentication
  failed · 5 denied by policy · 6 vault missing or damaged · 7 device key
  unavailable · 130 interrupted (see :mod:`irondome.errors`);
* options are written out in full (``--reveal``, never ``--rev``), and a
  mistyped command, subcommand, choice or option gets a did-you-mean;
* nothing is ever read from, or written to, the network.

Each command group lives in its own module and exposes
``register(subparsers, common)``, adding parsers whose ``handler`` default is a
function ``(ctx: Context, args: Namespace) -> int``.
"""

from __future__ import annotations

import argparse
import difflib
import errno
import itertools
import os
import sys
from typing import Any, Callable, Dict, Iterable, Iterator, List, NoReturn, Optional, Sequence, Tuple

from irondome import caps, paths
from irondome import device as devices
from irondome.cli.context import ENV_GRANT, ENV_SESSION, Context
from irondome.cli.output import Output
from irondome.errors import EXIT_INTERRUPTED, EXIT_OK, IronDomeError, UsageError
from irondome.secmem import harden_process, wipe_bytes

__all__ = ["main", "build_parser"]

_EPILOG = """\
getting started:
  irondome init                         create your first bunker (vault), alpha
  irondome add github --generate        store a new login with a generated password
  irondome get github                   print it      (-c copies it instead)
  irondome run --env GITHUB_TOKEN=github -- gh repo list
                                        run a command with that secret in its environment

for AI agents and scripts:
  irondome alias set GITHUB_TOKEN github        give a secret a name an agent can use
  irondome grant create GITHUB_TOKEN --ttl 15m  a one-time token for exactly that
  IRONDOME_GRANT=<token> irondome run --env GITHUB_TOKEN -- <command>

several bunkers on one machine (one per person or role):
  irondome bunker create bravo          a second, fully separate vault
  irondome --bunker bravo ls            work on it   (or: IRONDOME_BUNKER=bravo)
  irondome bunker use bravo             make it the default

documentation: https://github.com/Nir-Ghub/IronDome
"""


def _printable(text: str) -> str:
    """*text* on one line, with anything a terminal would act on (escape sequences, line breaks) shown escaped."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in text)


def _closest(word: object, candidates: Iterable[object]) -> Optional[str]:
    """The one of *candidates* that *word* most likely meant, or None. Case does not count: ``Status`` is ``status``."""
    if not isinstance(word, str) or not word:
        return None
    names: Dict[str, str] = {}
    for candidate in candidates:
        if isinstance(candidate, str):
            names.setdefault(candidate.lower(), candidate)
    found = difflib.get_close_matches(word.lower(), list(names), n=1)
    return names[found[0]] if found else None


class _VersionWanted(Exception):
    """``--version`` was read: :func:`main` prints the version, and nothing after it on the line is looked at."""


class _Version(argparse.Action):
    """``--version``: what ``irondome version`` prints, with ``--json`` too. Stops the parse, as argparse's own does."""

    def __init__(
        self, option_strings: Sequence[str], dest: str = argparse.SUPPRESS, default: Any = argparse.SUPPRESS,
        help: Optional[str] = None,
    ) -> None:
        super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(
        self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values: Any,
        option_string: Optional[str] = None,
    ) -> NoReturn:
        raise _VersionWanted()


class _Commands(argparse._SubParsersAction):
    """A parser's subcommands. Notes on the parser which one was given, for :meth:`_Parser.reject`.

    The namespace cannot say: ``irondome run`` has a positional of its own called ``command``, which
    overwrites the name of the command that the top-level parser stored there.
    """

    def __call__(
        self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values: Any,
        option_string: Optional[str] = None,
    ) -> None:
        given = self.choices.get(values[0]) if isinstance(self.choices, dict) and values else None
        if isinstance(parser, _Parser) and isinstance(given, _Parser):
            parser._given = given
        super().__call__(parser, namespace, values, option_string)


class _Parser(argparse.ArgumentParser):
    """argparse, with IronDome's usage errors.

    * A usage error raises :class:`UsageError` (exit status 2), which names the help of the command it is about.
    * Options are written out in full: ``allow_abbrev`` is off, so ``--rev`` is never taken for ``--reveal`` nor
      ``--password`` for ``--password-stdin``, and a new option never changes what an old script meant.
    * A mistyped command, subcommand, choice or option gets a did-you-mean, the same on every Python version.
    * Help is plain text on every Python version. Python 3.14 colours it on a terminal, and in doing so writes
      its colour codes into the name of every subcommand (``prog``), from where they reach error messages, log
      files and ``--no-color`` output alike.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)
        # Python 3.14 can suggest a choice itself (3.15 does by default); one suggestion, ours, on every version.
        self.suggest_on_error = False
        self.color = False  # Python 3.14+: before any subcommand's prog is made from this parser's usage
        self.register("action", "parsers", _Commands)
        self._commands: Optional[argparse.Action] = None
        #: The parser of the subcommand given in the last parse, if any.
        self._given: Optional[_Parser] = None

    def add_subparsers(self, **kwargs: Any) -> Any:
        self._commands = super().add_subparsers(**kwargs)
        return self._commands

    def parse_known_args(self, args: Any = None, namespace: Any = None) -> Any:
        self._given = None
        return super().parse_known_args(args, namespace)

    def error(self, message: str) -> NoReturn:
        raise UsageError(f"{message}\n(try: {self.prog} --help)")

    def _check_value(self, action: argparse.Action, value: Any) -> None:
        try:
            super()._check_value(action, value)
        except argparse.ArgumentError as exc:
            guess = _closest(value, action.choices or ())
            if guess is None:
                raise
            if action is self._commands:  # the list of commands is long, and --help shows it
                message = f"invalid choice: {value!r}; did you mean: {self.prog} {guess}"
            else:
                message = f"{exc.message}; did you mean {guess}?"
            raise argparse.ArgumentError(action, message) from None

    def parse_args(self, args: Any = None, namespace: Any = None) -> Any:
        parsed, extras = self.parse_known_args(args, namespace)
        if extras:
            self.reject(extras)
        return parsed

    def reject(self, extras: Sequence[str]) -> NoReturn:
        """The usage error for *extras*, the arguments the last parse left over, from the (sub)command given.

        argparse reports them from the top-level parser, whose help lacks the options of the command
        (``irondome add x --genrate`` would point at ``irondome --help``); this names ``irondome add --help``
        and suggests ``--generate``.
        """
        owner = self
        while owner._given is not None:
            owner = owner._given
        owner.error(owner._unrecognized(extras))

    def _option_meant(self, word: str) -> Optional[str]:
        """The option *word* most likely meant: the only one it begins (``--rev``: ``--reveal``), or the closest."""
        typed = word.split("=", 1)[0]
        options = [
            string for action in self._actions if action.help != argparse.SUPPRESS for string in action.option_strings
        ]
        if typed.startswith("--"):
            options = [option for option in options if option.startswith("--")]  # --y means --yes, not -y
        begun = [option for option in options if option.startswith(typed)]
        return begun[0] if len(begun) == 1 else _closest(typed, options)

    def _unrecognized(self, extras: Sequence[str]) -> str:
        guesses: List[Tuple[str, str]] = []
        for extra in extras:
            if extra.startswith("-") and extra not in ("-", "--"):
                guess = self._option_meant(extra)
                if guess is not None:
                    guesses.append((_printable(extra), guess))
        message = "unrecognized arguments: " + " ".join(_printable(extra) for extra in extras)
        misplaced = [guess for extra, guess in guesses if extra.split("=", 1)[0] == guess]
        if misplaced and len(misplaced) == len(guesses):
            # They exist, and were written where this parser does not take them: before the command's name.
            what = f"{misplaced[0]} is an option" if len(misplaced) == 1 else f"{', '.join(misplaced)} are options"
            message += f"; {what} of the command: write {'it' if len(misplaced) == 1 else 'them'} after its name"
        elif len(guesses) == 1:
            message += f"; did you mean {guesses[0][1]}?"
        elif guesses:
            message += "; did you mean " + ", ".join(f"{guess} (for {extra})" for extra, guess in guesses) + "?"
        return message

    def _subparsers_of(self) -> Iterator["_Parser"]:
        if self._commands is not None and isinstance(self._commands.choices, dict):
            for parser in dict.fromkeys(self._commands.choices.values()):  # an alias names the same parser
                if isinstance(parser, _Parser):
                    yield parser


def _common_options() -> argparse.ArgumentParser:
    """Flags accepted by every command, before or after the command name."""
    common = argparse.ArgumentParser(add_help=False)
    group = common.add_argument_group("global options")
    group.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS,
        help="print one JSON document on stdout: the result, or the error the command ended with",
    )
    group.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS, help="no progress messages")
    group.add_argument(
        "--no-color", action="store_true", default=argparse.SUPPRESS, help="plain output: no colour, no layout"
    )
    group.add_argument(
        "--password-stdin",
        action="store_true",
        default=argparse.SUPPRESS,
        help="read the master password from the first line of stdin (typed at a terminal, it is asked for unseen)",
    )
    group.add_argument(
        "--touch",
        action="store_true",
        default=argparse.SUPPRESS,
        help="allow a Touch ID prompt even without a terminal (how an agent asks its owner)",
    )
    group.add_argument("--no-touch", action="store_true", default=argparse.SUPPRESS, help="never ask for Touch ID")
    group.add_argument(
        "--bunker",
        metavar="NAME",
        default=argparse.SUPPRESS,
        help="the bunker (vault) to work on; default: IRONDOME_BUNKER, then `irondome bunker use`, then alpha",
    )
    return common


def select_bunker(args: argparse.Namespace) -> str:
    """Decide which bunker this process works on, before any command runs, and record why.

    ``--bunker`` wins and is exported as ``IRONDOME_BUNKER`` for the rest of
    the process. Otherwise ``IRONDOME_BUNKER`` from the environment, then a
    session or grant token in the environment selects the bunker that holds
    it, so an agent never has to name one; else the default. The reason --
    ``flag``, ``environment``, ``token`` or ``default`` -- is returned and
    kept on *args* as ``bunker_source`` (with ``bunker_token``, the variable
    that held the token), so that ``bunker current`` reports exactly this.
    """
    args.bunker_source, args.bunker_token = "default", None
    chosen = getattr(args, "bunker", None)
    if chosen is not None:
        os.environ[paths.ENV_BUNKER] = paths.validate_bunker_name(chosen)
        args.bunker_source = "flag"
    elif os.environ.get(paths.ENV_BUNKER):
        paths.validate_bunker_name(os.environ[paths.ENV_BUNKER])
        args.bunker_source = "environment"
    else:
        for variable in (ENV_GRANT, ENV_SESSION):
            token = os.environ.get(variable)
            if not token:
                continue
            try:
                _kind, cap_id, secret = caps.parse_token(token.strip())
            except IronDomeError:
                continue  # the command reports a malformed token in its own words
            wipe_bytes(secret)
            holder = paths.bunker_holding_capability(cap_id)
            if holder is not None:
                os.environ[paths.ENV_BUNKER] = holder
                args.bunker_source, args.bunker_token = "token", variable
                break
    return str(args.bunker_source)


def build_parser() -> _Parser:
    """The whole command line. Reading ``--version`` raises ``_VersionWanted``: :func:`main` prints it."""
    common = _common_options()
    parser = _Parser(
        prog="irondome",
        description="A local, hardware-bound secrets vault for people and their AI agents.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
    )
    parser.add_argument(
        "--version", action=_Version, help="print the version and exit (with --json, as `irondome version` does)"
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<command>", parser_class=_Parser)

    from irondome.cli import cmd_admin, cmd_agent, cmd_vault, cmd_verify

    for module in (cmd_vault, cmd_agent, cmd_admin, cmd_verify):
        module.register(subparsers, common)
    return parser


def _output(args: argparse.Namespace) -> Output:
    """The output the parsed command line asks for: ``--json``, ``--quiet``, ``--no-color``."""
    color: Optional[bool] = False if getattr(args, "no_color", False) else None
    return Output(json_mode=bool(getattr(args, "json", False)), quiet=bool(getattr(args, "quiet", False)), color=color)


def _written_flags(arguments: Sequence[str]) -> argparse.Namespace:
    """``--json`` and ``--no-color`` as written in *arguments*, for errors from before the line is understood.

    Only whole words count (options are never abbreviated), and nothing after ``--``, which belongs to the
    command that ``irondome run`` starts.
    """
    ours = list(itertools.takewhile(lambda word: word != "--", arguments))
    return argparse.Namespace(json="--json" in ours, no_color="--no-color" in ours)


def _open_standard_streams() -> None:
    """Give a closed stdin, stdout or stderr the null device, so that writing to it is not an error.

    A shell can start a program with one of them closed (``irondome status >&-``). Python then puts
    ``None`` in its place, and the first write to it would end in a traceback.

    ``None`` is what says the stream was closed, not the state of descriptor 0, 1 or 2 now: by the
    time this runs, an import may have left a file of its own on the lowest free descriptor (some
    Python builds keep ``/dev/urandom`` or their own executable open). That descriptor is then
    valid and is not ours to write to, so the stream gets the null device on whichever descriptor
    the system hands out; when the number is still free, that is the stream's own.
    """
    for name, mode in (("stdin", "r"), ("stdout", "w"), ("stderr", "w")):
        if getattr(sys, name) is not None:
            continue
        try:
            descriptor = os.open(os.devnull, os.O_RDWR)
        except OSError:
            continue  # no null device: Python's own None is what a write meets
        try:
            setattr(sys, name, open(descriptor, mode, closefd=False))  # noqa: SIM115 - lives as long as the process
        except OSError:
            os.close(descriptor)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the command line. Returns the process exit status."""
    _open_standard_streams()
    harden_process()
    arguments: List[str] = list(sys.argv[1:] if argv is None else argv)
    written = _written_flags(arguments)
    out = _output(written)  # until the command line is understood: an error in it honours its own flags
    previous = devices.set_progress(out.info)
    try:
        parser = build_parser()
        try:
            args, extras = parser.parse_known_args(arguments)
        except _VersionWanted:
            from irondome.cli import cmd_admin

            return int(cmd_admin.cmd_version(Context(written, out), written) or EXIT_OK)
        out = _output(args)
        devices.set_progress(out.info)  # "compiling the Secure Enclave helper...", silenced by --quiet
        if extras:
            parser.reject(extras)
        select_bunker(args)
        ctx = Context(args, out)
        handler: Optional[Callable[[Context, argparse.Namespace], int]] = getattr(args, "handler", None)
        if handler is None:
            from irondome.cli import cmd_vault

            return cmd_vault.overview(ctx, parser)
        return int(handler(ctx, args) or EXIT_OK)
    except IronDomeError as exc:
        out.failure(str(exc), exc.exit_code)
        return exc.exit_code
    except KeyboardInterrupt:
        out.failure("interrupted", EXIT_INTERRUPTED)
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        # The reader went away (e.g. `irondome ls | head`). Not an error.
        try:
            sys.stdout.close()
        except OSError:
            pass
        return EXIT_OK
    except OSError as exc:
        # A full disk, a read-only or unwritable home, a file that is not where it should be: what could not be
        # done and why, in one line, never a traceback. Nothing here holds a secret: only a path and a reason.
        out.failure(_os_error(exc), IronDomeError.exit_code)
        return IronDomeError.exit_code
    finally:
        devices.set_progress(previous)


def _os_error(exc: OSError) -> str:
    """``PATH: reason`` for an OSError, on one line and with nothing a terminal would act on."""
    reason = exc.strerror or (errno.errorcode.get(exc.errno, "") if exc.errno else "") or type(exc).__name__
    places = [
        os.fsdecode(name) if isinstance(name, (str, bytes)) else str(name)
        for name in (exc.filename, exc.filename2)
        if name is not None
    ]
    text = f"{' -> '.join(places) or 'IronDome could not write or read one of its files'}: {reason}"
    if exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
        text += " (check that the directory is yours and writable)"
    elif exc.errno in (errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)):
        text += " (free some space and run the command again)"
    elif exc.errno == errno.EFBIG:
        text += " (a limit on file size stopped the write: see ulimit -f, then run the command again)"
    return _printable(text)


if __name__ == "__main__":
    raise SystemExit(main())
