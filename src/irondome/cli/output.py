"""What the command line prints, and where.

Rules every command follows:

* **stdout is data.** The thing that was asked for and nothing else, so it can
  be piped. With ``--json`` it is one JSON document: the result, or, for a
  command that fails before it has printed anything there,
  ``{"ok": false, "error": "<message>", "exit_code": <n>}``.
* **stderr is conversation.** Prompts, progress, warnings and errors. An error
  is written here as text in every mode, ``--json`` included.
* No colour unless stderr/stdout is a terminal; ``--no-color`` and a non-empty
  ``NO_COLOR`` (https://no-color.org) are honoured. No emoji, no banners.
* A secret is printed only by the commands whose purpose is to print it.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Iterable, List, Optional, Sequence, TextIO

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
        self._color_out = bool(color) and self._is_tty(self.stdout)
        self._color_err = bool(color) and self._is_tty(self.stderr)
        #: Whether anything has been written to stdout yet; see :meth:`failure`.
        self._printed = False

    @staticmethod
    def _is_tty(stream: TextIO) -> bool:
        try:
            return stream.isatty()
        except (AttributeError, ValueError):
            return False

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
        self.stdout.write(text + ("\n" if newline else ""))
        self.stdout.flush()

    def secret(self, value: str) -> None:
        """Print a secret: bare when piped, newline-terminated on a terminal."""
        self._printed = True
        self.stdout.write(value)
        if self._is_tty(self.stdout):
            self.stdout.write("\n")
        self.stdout.flush()

    def json(self, document: Any) -> None:
        self._printed = True
        self.stdout.write(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
        self.stdout.flush()

    def table(self, headers: Sequence[str], rows: Iterable[Sequence[str]]) -> None:
        """A plain aligned table. Empty when there are no rows."""
        materialised: List[Sequence[str]] = [tuple(str(cell) for cell in row) for row in rows]
        if not materialised:
            return
        widths = [len(header) for header in headers]
        for row in materialised:
            for index, cell in enumerate(row):
                widths[index] = max(widths[index], len(cell))
        self.data(self.style("  ".join(h.upper().ljust(widths[i]) for i, h in enumerate(headers)).rstrip(), "dim"))
        for row in materialised:
            self.data("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())

    def pairs(self, items: Iterable[Sequence[str]]) -> None:
        """Aligned ``label  value`` lines."""
        materialised = [(str(label), str(value)) for label, value in items]
        width = max((len(label) for label, _ in materialised), default=0)
        for label, value in materialised:
            self.data(f"{self.style(label.ljust(width), 'dim')}  {value}")

    # -- stderr: conversation -------------------------------------------------

    def _say(self, text: str) -> None:
        self.stderr.write(text + "\n")
        self.stderr.flush()

    def info(self, text: str) -> None:
        if not self.quiet:
            self._say(text)

    def notice(self, text: str) -> None:
        """A line the user must not miss and that is not a warning: printed with ``-q`` as well."""
        self._say(text)

    def ok(self, text: str) -> None:
        if not self.quiet:
            self._say(f"{self.style('ok', 'green', err=True)}  {text}")

    def warn(self, text: str) -> None:
        self._say(f"{self.style('warning', 'yellow', err=True)}  {text}")

    def error(self, text: str) -> None:
        self._say(f"{self.style('error', 'red', err=True)}  {text}")

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
