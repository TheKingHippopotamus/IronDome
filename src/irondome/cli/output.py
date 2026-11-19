"""What the command line prints, and where.

Rules every command follows:

* **stdout is data.** The thing that was asked for and nothing else, so it can
  be piped. With ``--json`` it is one JSON document: the result, or, for a
  command that fails before it has printed anything there,
  ``{"ok": false, "error": "<message>", "exit_code": <n>}``.
* **stderr is conversation.** Prompts, progress, warnings and errors. An error
  is written here as text in every mode, ``--json`` included.
* **Two forms.** *Plain*: one unbroken line per message, a word in front of
  results, warnings and errors (``ok``, ``warning``, ``error``), tables of
  aligned text. It is what a pipe, a file and this project's tests get, and it
  does not depend on the terminal. *Laid out*: for a person at a terminal.
  Prose is wrapped to the terminal's width, results, warnings and errors carry
  a coloured mark, commands to type are coloured, tables are ruled. A stream
  gets the laid-out form only when it is a terminal and colour is allowed:
  ``--no-color``, a non-empty ``NO_COLOR`` (https://no-color.org) and
  ``TERM=dumb`` each mean the plain form, layout included. Neither form
  changes a value a person may copy: no wrapping, no trimming.
* No emoji, no banners.
* A secret is printed only by the commands whose purpose is to print it.
"""

from __future__ import annotations

import json
import os
import re
import sys
import textwrap
import time
from typing import Any, Iterable, List, Optional, Sequence, TextIO, Tuple

__all__ = ["Output", "format_time", "format_duration", "parse_duration"]

_CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "cyan": "36"}

#: The most digits a duration may have. The longest one IronDome accepts anywhere is 30 days (2592000
#: seconds); twelve digits leave room for every spelling of it and stop what is not a duration before
#: ``int()`` refuses it (over 4300 digits) or a time limit overflows a float (over 308).
_MAX_DURATION_DIGITS = 12


def format_time(timestamp: Optional[int]) -> str:
    if not timestamp:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))


def format_duration(seconds: float) -> str:
    """A short human duration: ``45s``, ``12m``, ``3h``, ``2d``."""
    seconds = int(max(0, seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 90 * 60:
        return f"{round(seconds / 60)}m"
    if seconds < 36 * 3600:
        return f"{round(seconds / 3600)}h"
    return f"{round(seconds / 86400)}d"


def parse_duration(text: str) -> int:
    """Parse ``90``, ``90s``, ``15m``, ``2h`` or ``7d`` into seconds.

    Only the ASCII digits 0-9 count, and at most twelve of them. ``str.isdigit`` alone is also true of
    ``'²'``, which ``int()`` refuses with a ValueError, and of ``'٣'`` or ``'１５'``, which it reads as
    numbers; anything of that kind is a :class:`UsageError`, as is every other text that is not a duration.
    """
    from irondome.errors import UsageError

    cleaned = text.strip().lower()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    factor = 1
    if cleaned and cleaned[-1] in units:
        factor = units[cleaned[-1]]
        cleaned = cleaned[:-1]
    if not (cleaned.isascii() and cleaned.isdigit()) or len(cleaned) > _MAX_DURATION_DIGITS:
        shown = repr(text) if len(text) <= 32 else f"{text[:24]!r}... ({len(text)} characters)"
        raise UsageError(f"{shown} is not a duration; use forms like 90s, 15m, 2h or 7d")
    return int(cleaned) * factor


#: Laid-out prose is never wider than this, however wide the terminal: a longer line is hard to read.
_MAX_WIDTH = 92
#: ... and never narrower, however narrow the terminal says it is.
_MIN_WIDTH = 40
#: What a table's last column is wrapped to at least; a terminal too narrow for that gets long lines.
_MIN_CELL = 16

#: Around a command to type, from the moment a message is read until its lines are written.
_START, _END = "\x00", "\x01"
_CYAN, _DEFAULT = "\x1b[36m", "\x1b[39m"

#: Every command and subcommand; tests/unit/test_cli_output.py compares it with the parser.
_COMMAND_WORDS = frozenset({
    "add", "alias", "approve", "audit", "auth", "backup", "bunker", "completion", "config", "create", "current",
    "doctor", "edit", "export", "find", "gen", "get", "grant", "import", "init", "lock", "ls", "mcp", "migrate",
    "new", "nuke", "otp", "passwd", "password", "recovery", "rekey", "remove", "reset", "restore", "revoke", "rm",
    "run", "scan", "set", "show", "status", "touchid", "unlock", "use", "verify", "version",
})  # fmt: skip
#: Every option that is followed by a value; tests/unit/test_cli_output.py compares it with the parser.
_VALUE_OPTIONS = frozenset({
    "--add-tag", "--agent", "--alias", "--archive", "--bunker", "--claim", "--client", "--cwd", "--email-alias",
    "--env", "--env-file", "--field", "--format", "--from", "--kdf-memory-mib", "--kind", "--label",
    "--legacy-username", "--length", "--mode", "--name", "--note", "--on-conflict", "--plaintext", "--rm-field",
    "--rm-tag", "--tag", "--timeout", "--touch-timeout", "--ttl", "--url", "--username", "--uses", "--words", "-n",
})  # fmt: skip
#: Words that carry a sentence on after a command and are never the name of an entry in an example.
_PROSE = frozenset({"and", "as", "but", "for", "in", "is", "not", "on", "or", "then", "to", "with", "without"})
_OPTION = re.compile(r"--?[A-Za-z][\w-]*(=\S*)?")
_SETTING = re.compile(r"[A-Z_][A-Z0-9_]*=\S+")
#: How doctor's findings are marked: the mark, then its colour.
_FINDING_MARKS = {"ok": ("✓", "green"), "warning": ("!", "yellow"), "problem": ("✗", "red")}
_BOLD, _FAINT, _NORMAL = "\x1b[1m", "\x1b[2m", "\x1b[22m"
#: Punctuation that follows a word in a sentence and is no part of a command.
_TAIL = ".,;:)\"'`"

#: A table cell that is exactly one of these words is shown in its colour.
_CELL_STYLES = {
    "pass": ("green",),
    "FAIL": ("red", "bold"),
    "skipped": ("dim",),
    "present": ("green",),
    "missing": ("red",),
    "DAMAGED": ("red", "bold"),
    "MISSING": ("red", "bold"),
    "-": ("dim",),
}

#: The one path of IronDome's own with a space in it is not broken there: a path is copied whole.
_KEPT_TOGETHER, _JOINED = "Application Support", "Application\x02Support"

_COLUMNS = re.compile(r"\S( {2,})(?=\S)")


def _split_tail(piece: str) -> Tuple[str, str]:
    """*piece* and the sentence punctuation after it: ``("touchid", ".")`` for ``touchid.``."""
    if piece == "...":
        return piece, ""
    word = piece.rstrip(_TAIL)
    if word[:1] in ("'", '"') and piece[len(word) :].startswith(word[0]):
        word += word[0]  # a name as IronDome quotes it keeps its closing quote
    return word, piece[len(word) :]


def _belongs(word: str, position: int, following: Optional[str], closing: bool) -> bool:
    """Whether *word*, the *position*-th after ``irondome``, is still part of the command line.

    *following* is the word after it, None where the line ends with *word* and the command came
    after a colon ("... run: irondome bunker use work"); *closing*: the command stands in brackets
    and *word* is the last one in them.
    """
    if not word:
        return False
    if word[0] in ("'", '"') and word[-1] == word[0] and len(word) > 2:
        return True  # a name as IronDome quotes it
    if word in ("--", "...") or _OPTION.fullmatch(word):
        return True
    if word in _COMMAND_WORDS and position <= 2:
        return True
    if word[0] in "$~./<[" or "/" in word or "=" in word or "_" in word or any(ch.isdigit() for ch in word):
        return True
    if word.isupper():
        return True  # a placeholder: NAME, REF
    # An example's own name ("github" in: irondome add github --generate) is told from the
    # sentence going on ("moves" in: irondome rekey moves the vault) by what comes after it: an
    # option, the end of a line that was leading up to the command, or the closing bracket.
    if not word.replace("-", "").isalnum() or word in _PROSE:
        return False
    return closing or following is None or bool(_OPTION.fullmatch(_split_tail(following)[0]))


def _mark_commands(line: str) -> str:
    """*line* with each ``irondome ...`` command in it between :data:`_START` and :data:`_END`.

    This reads sentences, so it is a judgement: it colours, and changes nothing else.
    """
    if "irondome" not in line:
        return line
    parts = re.split(r"( +)", line)  # words at the even places, the spaces between them at the odd ones
    out: List[str] = []
    index = 0
    while index < len(parts):
        part = parts[index]
        lead = len(part) - len(part.lstrip("(\"'`"))
        word, tail = _split_tail(part[lead:])
        if word != "irondome":
            out.append(part)
            index += 1
            continue
        last, position = index, 0
        value_due = rest = False  # the word after an option that takes one; everything after a bare "--"
        announced = index >= 2 and parts[index - 2].endswith(":")
        bracketed = "(" in part[:lead]
        while not tail and last + 2 < len(parts):
            candidate, candidate_tail = _split_tail(parts[last + 2])
            at_end = last + 4 >= len(parts)
            following: Optional[str] = "" if at_end else parts[last + 4]
            if at_end and announced and not candidate_tail:
                following = None
            position += 1
            closing = bracketed and candidate_tail.startswith(")")
            if not (candidate and (value_due or rest)) and not _belongs(candidate, position, following, closing):
                break
            rest = rest or candidate == "--"
            value_due = candidate in _VALUE_OPTIONS
            last, tail = last + 2, candidate_tail
        # Settings written in front of the command belong to it: IRONDOME_NO_TOUCH=1 irondome ...
        settings: List[str] = []
        while not lead and len(out) >= 2 and out[-1].isspace() and _SETTING.fullmatch(out[-2]):
            settings[:0] = [out[-2], out[-1]]
            del out[-2:]
        out.append(part[:lead] + _START + "".join(settings) + word)
        if last != index:
            out.extend(parts[index + 1 : last])
            out.append(_split_tail(parts[last])[0])
        out.append(_END + tail)
        index = last + 1
    return "".join(out)


def _wrap(line: str, width: int, margin: int) -> List[str]:
    """One line of a message as lines of *width* at most, each after *margin* spaces.

    The line's own indentation is kept on every line it becomes. Where the line is a row of columns
    (two spaces or more between them), what does not fit continues under its last column. A word
    longer than the room there is stays whole on a line of its own, and each command in the line
    takes two columns more than it shows.
    """
    body = line.strip(" ").replace(_KEPT_TOGETHER, _JOINED)
    if not body:
        return [""]
    indent = margin + len(line) - len(line.lstrip(" "))
    hang = 0
    columns = list(_COLUMNS.finditer(_strip_marks(body)))
    if columns and columns[-1].end(1) <= (width - indent) // 2:
        hang = columns[-1].end(1)
    wrapper = textwrap.TextWrapper(
        width=max(width, indent + hang + 20),
        initial_indent=" " * indent,
        subsequent_indent=" " * (indent + hang),
        break_long_words=False,
        break_on_hyphens=False,
        replace_whitespace=False,
        expand_tabs=False,
    )
    return [wrapped.replace(_JOINED, _KEPT_TOGETHER) for wrapped in wrapper.wrap(body)] or [""]


def _paint_commands(lines: Sequence[str]) -> List[str]:
    """Turn the marks :func:`_mark_commands` left into colour; a command broken over two lines stays one colour."""
    painted: List[str] = []
    inside = False
    for line in lines:
        ends_inside = line.rfind(_START) > line.rfind(_END) if _START in line or _END in line else inside
        if inside:
            text = line.lstrip(" ")
            line = line[: len(line) - len(text)] + _CYAN + text
        line = line.replace(_START, _CYAN).replace(_END, _DEFAULT)
        painted.append(line + _DEFAULT if ends_inside else line)
        inside = ends_inside
    return painted


def _strip_marks(text: str) -> str:
    return text.replace(_START, "").replace(_END, "")


class Output:
    """Writes for one command invocation. Created by the CLI context."""

    def __init__(
        self,
        *,
        json_mode: bool = False,
        quiet: bool = False,
        color: Optional[bool] = None,
        stdout: Optional[TextIO] = None,
        stderr: Optional[TextIO] = None,
    ) -> None:
        self.json_mode = json_mode
        self.quiet = quiet
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stderr = stderr if stderr is not None else sys.stderr
        if color is None:
            # https://no-color.org: NO_COLOR counts when it is present and not empty, whatever its value.
            color = not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
        # Colour and layout go together: a stream that gets one gets the other (see the module's rules).
        self._color = bool(color)
        self._color_out = bool(color) and self._is_tty(self.stdout)
        self._color_err = bool(color) and self._is_tty(self.stderr)
        #: Whether anything has been written to stdout yet; see :meth:`failure`.
        self._printed = False
        #: Laid out: whether the last line shown was empty (nothing shown yet counts), and whether
        #: an empty line is owed before the next thing said, because a warning came before it.
        self._blank = True
        self._owed = False

    @staticmethod
    def _is_tty(stream: TextIO) -> bool:
        try:
            return stream.isatty()
        except (AttributeError, ValueError):
            return False

    @staticmethod
    def _columns(stream: TextIO) -> int:
        """How wide the terminal behind *stream* is, as shutil.get_terminal_size decides it.

        ``COLUMNS`` where it holds a number, else what the terminal reports, else 80 (a terminal
        that reports no width, a stream that is none); never less than 40.
        """
        declared = os.environ.get("COLUMNS", "")
        columns = int(declared) if declared.isascii() and declared.isdigit() and len(declared) < 5 else 0
        if columns <= 0:
            try:
                columns = os.get_terminal_size(stream.fileno()).columns
            except (AttributeError, OSError, TypeError, ValueError):
                columns = 0
        return max(columns, _MIN_WIDTH) if columns > 0 else 80

    @staticmethod
    def _draws(stream: TextIO, text: str) -> bool:
        """Whether *stream* can show *text* (a mark, a rule): its encoding has those characters."""
        try:
            text.encode(getattr(stream, "encoding", None) or "ascii")
        except (LookupError, UnicodeError):
            return False
        return True

    # -- styling --------------------------------------------------------------

    def style(self, text: str, *names: str, err: bool = False) -> str:
        enabled = self._color_err if err else self._color_out
        if not enabled or not names:
            return text
        codes = ";".join(_CODES[name] for name in names)
        return f"\x1b[{codes}m{text}\x1b[0m"

    # -- stdout: data ---------------------------------------------------------

    def data(self, text: str = "", *, newline: bool = True) -> None:
        """Print the result of a command."""
        self._printed = True
        self._blank = text == "" and newline
        self.stdout.write(text + ("\n" if newline else ""))
        self.stdout.flush()

    def secret(self, value: str) -> None:
        """Print a secret: bare when piped, newline-terminated on a terminal."""
        self._printed = True
        self._blank = False
        self.stdout.write(value)
        if self._is_tty(self.stdout):
            self.stdout.write("\n")
        self.stdout.flush()

    def framed(self, value: str) -> None:
        """Print a value to keep, a recovery key: framed on a terminal, as :meth:`secret` prints it otherwise.

        The value is written as it is, on its own: no other text is built that holds it.
        """
        if not self._color_out or self._columns(self.stdout) < len(value) + 6:
            self.secret(value)
            return
        top, side, bottom = ("┌─┐", "│", "└─┘") if self._draws(self.stdout, "┌─┐│└┘") else ("+-+", "|", "+-+")
        rule = top[1] * (len(value) + 2)
        self._printed = True
        self._blank = False
        self.stdout.write(f"  {self.style(top[0] + rule + top[2], 'dim')}\n  {self.style(side, 'dim')} {_BOLD}")
        self.stdout.write(value)
        self.stdout.write(f"{_NORMAL} {self.style(side, 'dim')}\n  {self.style(bottom[0] + rule + bottom[2], 'dim')}\n")
        self.stdout.flush()

    def json(self, document: Any) -> None:
        self._printed = True
        self.stdout.write(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        self.stdout.flush()

    def table(self, headers: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
        """An aligned table: plain text, or ruled and coloured on a terminal. Empty when there are no rows."""
        materialised: List[Sequence[str]] = [tuple(str(cell) for cell in row) for row in rows]
        if not materialised:
            return
        widths = [len(header) for header in headers]
        for row in materialised:
            for index, cell in enumerate(row):
                widths[index] = max(widths[index], len(cell))
        if not self._color_out:
            self.data("  ".join(h.upper().ljust(widths[i]) for i, h in enumerate(headers)).rstrip())
            for row in materialised:
                self.data("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
            return
        # The last column takes what the terminal has left, and what does not fit goes on under it.
        start = sum(widths[:-1]) + 2 * (len(widths) - 1)
        room = self._columns(self.stdout) - start
        if _MIN_CELL <= room < widths[-1]:
            widths[-1] = room
        dash = "─" if self._draws(self.stdout, "─") else "-"
        self.data("  ".join(self.style(h.upper().ljust(widths[i]), "bold") for i, h in enumerate(headers)).rstrip())
        self.data(self.style("  ".join(dash * width for width in widths), "dim"))
        for row in materialised:
            if not row:
                self.data()
                continue
            last = [row[-1]]
            if row[-1].isprintable():  # anything else is shown as it is, on one line
                last = textwrap.wrap(row[-1], widths[-1], break_long_words=False, break_on_hyphens=False) or [""]
            cells = [self._cell(cell, widths[i]) for i, cell in enumerate(row[:-1])]
            cells.append(self._cell(last[0], 0) if len(last) == 1 else last[0])
            self.data("  ".join(cells).rstrip())
            for more in last[1:]:
                self.data(" " * start + more)

    def _cell(self, text: str, width: int) -> str:
        names = _CELL_STYLES.get(text, ())
        return self.style(text, *names) + " " * max(width - len(text), 0)

    def pairs(self, items: Iterable[Sequence[str]], *, wrap: bool = False) -> None:
        """Aligned ``label  value`` lines, each value exactly as it is.

        *wrap* is for values that are sentences, never for one a person may copy: on a terminal
        such a value goes on under its own start.
        """
        materialised = [(str(label), str(value)) for label, value in items]
        width = max((len(label) for label, _ in materialised), default=0)
        room = min(self._columns(self.stdout), _MAX_WIDTH) - width - 2 if wrap and self._color_out else 0
        for label, value in materialised:
            lines = [value]
            if room >= _MIN_CELL and value.isprintable() and value == " ".join(value.split()):
                lines = textwrap.wrap(value, room, break_long_words=False, break_on_hyphens=False) or [""]
            self.data(f"{self.style(label.ljust(width), 'dim')}  {lines[0]}")
            for more in lines[1:]:
                self.data(" " * (width + 2) + more)

    # -- stderr: conversation -------------------------------------------------

    def _lay(
        self, stream: TextIO, text: str, word: str = "", mark: str = "", colour: str = "", weight: str = ""
    ) -> List[str]:
        """*text* as the lines a terminal on *stream* shows.

        Wrapped to the terminal's width, after *mark* in *colour* (after *word* where the terminal
        cannot show the mark), the commands in it picked out, the text itself in *weight* (bold
        or faint) where one is given.
        """
        text = _strip_marks(text)  # the two characters this module marks commands with are nobody else's
        if word and not self._draws(stream, mark):
            mark = word
        margin = len(mark) + 1 if mark else 0
        width = min(self._columns(stream), _MAX_WIDTH)
        lines: List[str] = []
        for line in text.split("\n"):
            lines.extend(_wrap(_mark_commands(line), width, margin))
        lines = _paint_commands(lines)
        if weight:
            lines = [line[:margin] + weight + line[margin:] + _NORMAL if line else line for line in lines]
        if mark:
            lines[0] = f"\x1b[{_CODES[colour]};1m{mark}\x1b[0m" + lines[0][len(mark) :]
        return lines

    def _say(
        self, text: str, word: str = "", mark: str = "", colour: str = "", *, weight: str = "", apart: bool = False
    ) -> None:
        """Say *text* on stderr.

        Plain: one line, after *word* and two spaces when there is a word. Laid out: as
        :meth:`_lay` makes it; *apart*, as for a warning, sets it off by an empty line from what
        was said before it and from what is said after it.
        """
        if not self._color_err:
            self.stderr.write((f"{word}  {text}" if word else text) + "\n")
            self.stderr.flush()
            return
        lines = self._lay(self.stderr, text, word, mark, colour, weight)
        if (apart or self._owed) and not self._blank and lines != [""]:
            self.stderr.write("\n")
        self.stderr.write("\n".join(lines) + "\n")
        self.stderr.flush()
        self._blank = lines[-1] == ""
        self._owed = apart

    def prompt(self, text: str) -> str:
        """A prompt as the terminal shows it: where colour is allowed, its last line, the question, in bold.

        The question's own characters stay next to each other, the space after it included, so
        that whatever waits for the prompt's text on a terminal still finds it.
        """
        if not self._color or os.name == "nt":  # a Windows console may show the codes instead of obeying them
            return text
        before, line_break, question = text.rpartition("\n")
        return f"{before}{line_break}{_BOLD}{question}{_NORMAL}"

    def finding(self, severity: str, check: str, message: str, remedy: Optional[str] = None) -> None:
        """One result of a check-up (doctor), on stdout: how it went, what was checked, what was found, the fix."""
        if not self._color_out:
            self.data(f"{severity:<8} {check}: {message}")
            if remedy:
                self.data(f"{'':<8} fix: {remedy}")
            return
        mark, colour = _FINDING_MARKS.get(severity, ("·", "dim"))
        text = f"{check}: {message}" + (f"\nfix: {remedy}" if remedy else "")
        lines = self._lay(self.stdout, text, severity, mark, colour)
        lines[0] = lines[0].replace(f" {check}:", f" {_BOLD}{check}{_NORMAL}:", 1)
        for line in lines:
            self.data(line)

    def info(self, text: str) -> None:
        if not self.quiet:
            # Progress ("Checking for Touch ID...") is the least of what is said: it is shown faint.
            self._say(text, weight=_FAINT if text.endswith("...") and "\n" not in text else "")

    def notice(self, text: str) -> None:
        """A line the user must not miss and that is not a warning: printed with ``-q`` as well."""
        self._say(text)

    def ok(self, text: str) -> None:
        if not self.quiet:
            self._say(text, "ok", "✓", "green")

    def warn(self, text: str) -> None:
        self._say(text, "warning", "!", "yellow", apart=True)

    def error(self, text: str) -> None:
        self._say(text, "error", "✗", "red", weight=_BOLD)

    def failure(self, text: str, exit_code: int) -> None:
        """The error a command ends with, and the exit status it ends with.

        It is written to stderr as text, as :meth:`error` writes it. With ``--json``, and when the
        command has printed nothing on stdout, it is also the one JSON document there:
        ``{"ok": false, "error": text, "exit_code": exit_code}``. A command that has already printed
        its result keeps that as its only document; the exit status still says that it failed.
        """
        try:
            self.error(text)
        except (OSError, ValueError):
            pass  # stderr is closed: there is nobody to tell, and the exit status still says it
        if self.json_mode and not self._printed:
            try:
                self.json({"ok": False, "error": text, "exit_code": exit_code})
            except (OSError, ValueError):
                pass  # nobody reads stdout any more (a closed pipe); stderr and the exit status said it
