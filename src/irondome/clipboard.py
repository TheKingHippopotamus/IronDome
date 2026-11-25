"""Copying a secret to the clipboard, and taking it off again.

:func:`copy` hands the value to the platform's clipboard tool on its standard
input -- never as an argument, which every user of the machine can read in
the process list -- and starts a small detached helper that clears the
clipboard a few seconds later, but only if the clipboard still holds that
value. Whatever was copied in the meantime is left alone.

==========  ======================  ===================================
Platform    Writes with             Reads back with
==========  ======================  ===================================
macOS       ``pbcopy``              ``pbpaste``
Wayland     ``wl-copy``             ``wl-paste``
X11         ``xclip``, else         the same tool
            ``xsel``
Windows     ``clip.exe``            PowerShell ``Get-Clipboard``
==========  ======================  ===================================

The tools are looked up in a fixed list of system directories and never in
the caller's ``PATH``: a program planted early in ``PATH`` would otherwise be
handed the secret. Each one runs from its absolute path, with an argument
list, a minimal environment and a time limit.

The helper is ``python -m irondome.clipboard --clear-after N --sha256 HEX``
plus the absolute paths of the two tools it may run. ``HEX`` is the SHA-256 of
a random salt followed by the value; the salt reaches the helper through its
environment, which only the same user can read. So the helper never holds the
value, and the process list shows nothing a password guess could be checked
against. It runs in a session of its own with its standard streams closed,
so it outlives the command and the terminal that started it.

What this cannot do: every program running as you can read the clipboard
while the value is on it, and clipboard managers or clipboard sync may keep
copies of their own. Clearing is best effort: if the helper is killed or the
computer sleeps through the delay, the value stays until something else is
copied.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple, Union

from irondome import paths
from irondome.errors import IronDomeError, UsageError
from irondome.secmem import wipe_bytes

__all__ = ["MIN_CLEAR_SECONDS", "MAX_CLEAR_SECONDS", "ToolRefused", "tools", "copy", "main"]

#: Bounds for the delay before the clipboard is cleared.
MIN_CLEAR_SECONDS = 1
MAX_CLEAR_SECONDS = 3600

#: Where clipboard tools are looked up on every system except Windows.
_POSIX_PATH = os.pathsep.join(("/usr/bin", "/bin", "/usr/local/bin", "/run/current-system/sw/bin"))
#: The helper finds the salt for its digest here.
_SALT_VARIABLE = "IRONDOME_CLIPBOARD_SALT"
_SALT_BYTES = 32
_TOOL_TIMEOUT = 10.0
#: What a tool is allowed to see of the caller's environment.
_PASSED_VARIABLES = (
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "PYTHONDONTWRITEBYTECODE",
)
_POWERSHELL_READ = (
    "$text = Get-Clipboard -Raw; if ($null -eq $text) { $text = '' }; "
    "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "
    "[Console]::Out.Write($text)"
)


@dataclass(frozen=True)
class _Tool:
    """One clipboard tool: how to write to the clipboard, read it back and empty it."""

    name: str
    writer: str
    write_args: Tuple[str, ...]
    reader: str
    read_args: Tuple[str, ...]
    clear_args: Tuple[str, ...]
    utf16: bool = False


_TOOLS: Dict[str, _Tool] = {
    tool.name: tool
    for tool in (
        _Tool("pbcopy", "pbcopy", (), "pbpaste", (), ()),
        _Tool("wl-copy", "wl-copy", (), "wl-paste", ("--no-newline",), ("--clear",)),
        _Tool(
            "xclip",
            "xclip",
            ("-selection", "clipboard", "-in"),
            "xclip",
            ("-selection", "clipboard", "-out"),
            ("-selection", "clipboard", "-in"),
        ),
        _Tool(
            "xsel",
            "xsel",
            ("--clipboard", "--input"),
            "xsel",
            ("--clipboard", "--output"),
            ("--clipboard", "--clear"),
        ),
        _Tool(
            "clip",
            "clip.exe",
            (),
            "powershell.exe",
            ("-NoProfile", "-NonInteractive", "-Command", _POWERSHELL_READ),
            (),
            utf16=True,
        ),
    )
}


# ---------------------------------------------------------------------------
# Finding the tool
# ---------------------------------------------------------------------------


def _system() -> str:
    """The platform whose clipboard tools are wanted."""
    return sys.platform


def _windows_system_dir() -> str:
    """``System32``, asked of Windows itself rather than read from a variable the caller sets."""
    import ctypes

    buffer = ctypes.create_unicode_buffer(260)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))  # type: ignore[attr-defined]
    return buffer.value if 0 < length < len(buffer) else r"C:\Windows\System32"


def _search_path() -> str:
    """The fixed list of directories clipboard tools are taken from."""
    if _system() == "win32":
        system = _windows_system_dir()
        return os.pathsep.join((system, os.path.join(system, "WindowsPowerShell", "v1.0")))
    return _POSIX_PATH


def _candidates() -> List[str]:
    system = _system()
    if system == "darwin":
        return ["pbcopy"]
    if system == "win32":
        return ["clip"]
    names = []
    if os.environ.get("WAYLAND_DISPLAY"):
        names.append("wl-copy")
    if os.environ.get("DISPLAY"):
        names.extend(["xclip", "xsel"])
    if not names:
        raise UsageError(
            "there is no graphical session here to copy to (neither WAYLAND_DISPLAY nor DISPLAY is set); "
            "run the command again without --copy"
        )
    return names


def _install_advice() -> str:
    system = _system()
    if system == "darwin":
        return "pbcopy and pbpaste were not found in /usr/bin, where macOS keeps them"
    if system == "win32":
        return "clip.exe and PowerShell were not found in the Windows system directory"
    return (
        "no clipboard tool was found. Install wl-clipboard (Wayland) or xclip or xsel (X11), "
        "for example: sudo apt install wl-clipboard xclip"
    )


class ToolRefused(UsageError):
    """A clipboard tool is installed, and it is one that somebody else could have replaced."""


def tools() -> Tuple[str, str, str]:
    """The tool :func:`copy` would use here: ``(name, writer, reader)``, the last two absolute paths.

    Runs nothing and copies nothing. Raises :class:`UsageError`, with advice on what to install,
    where there is no usable tool, and :class:`ToolRefused` where the tool that was found is not
    one to hand a secret to.
    """
    tool, writer, reader = _find_tool()
    return tool.name, writer, reader


def _find_tool() -> Tuple[_Tool, str, str]:
    """The first installed tool and the absolute paths of its writer and reader.

    The tool that is found is the one that is used or refused: a tool that somebody else could
    have replaced is not passed over for the next one, because whoever replaced it is then
    someone to hear about.
    """
    search = _search_path()
    for name in _candidates():
        tool = _TOOLS[name]
        writer = shutil.which(tool.writer, path=search)
        reader = shutil.which(tool.reader, path=search)
        if writer and reader:
            writer, reader = os.path.abspath(writer), os.path.abspath(reader)
            for program in (writer, reader):
                fault = paths.program_fault(program)
                if fault:
                    raise ToolRefused(
                        f"cannot copy to the clipboard: {fault}, and a secret is given only to a tool "
                        "that nobody but root or you can change"
                    )
            return tool, writer, reader
    raise UsageError(f"cannot copy to the clipboard: {_install_advice()}")


# ---------------------------------------------------------------------------
# Running a tool
# ---------------------------------------------------------------------------


def _environment() -> Dict[str, str]:
    """What a clipboard tool (or the helper) gets: the display, the locale, and the fixed PATH."""
    env = {name: os.environ[name] for name in _PASSED_VARIABLES if name in os.environ}
    env["PATH"] = _search_path()
    if _system() == "darwin":
        env["LANG"] = env["LC_ALL"] = "en_US.UTF-8"  # pbcopy reads its input in the locale's encoding
    return env


def _workdir() -> str:
    """A directory every tool can start in, and where nothing can have been planted."""
    return _windows_system_dir() if os.name == "nt" else "/"


def _encode(tool: _Tool, value: str) -> bytes:
    if tool.utf16:
        return b"\xff\xfe" + value.encode("utf-16-le")  # clip.exe reads UTF-16 when it starts with a byte-order mark
    return value.encode("utf-8")


def _run(tool: _Tool, executable: str, arguments: Tuple[str, ...], data: bytes, *, capture: bool) -> bytes:
    """Run one tool with *data* on its stdin. Returns its stdout when *capture* is set.

    Standard error goes to a temporary file, not a pipe: ``xclip``, ``xsel``
    and ``wl-copy`` leave a process behind that serves the clipboard, and a
    pipe it inherited would never reach end-of-file.
    """
    with tempfile.TemporaryFile() as errors:
        try:
            result = subprocess.run(
                [executable, *arguments],
                input=data,
                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                stderr=errors,
                timeout=_TOOL_TIMEOUT,
                env=_environment(),
                cwd=_workdir(),
                close_fds=True,
            )
        except subprocess.TimeoutExpired:
            raise IronDomeError(
                f"the clipboard tool {tool.name} did not finish within {_TOOL_TIMEOUT:.0f} seconds"
            ) from None
        except OSError as exc:
            raise IronDomeError(f"could not run the clipboard tool {executable}: {exc.strerror or exc}") from None
        if result.returncode != 0:
            errors.seek(0)
            detail = errors.read(400).decode("utf-8", "replace").strip()
            raise IronDomeError(
                f"the clipboard tool {tool.name} failed (exit status {result.returncode})"
                + (f": {detail}" if detail else "")
            )
    return result.stdout if capture and result.stdout else b""


def _clear(tool: _Tool, writer: str) -> None:
    """Empty the clipboard: the writer with nothing on its input, or the tool's own clear option."""
    _run(tool, writer, tool.clear_args, _encode(tool, ""), capture=False)


# ---------------------------------------------------------------------------
# The clearing helper
# ---------------------------------------------------------------------------


def _digest(salt: bytes, data: Union[bytes, memoryview]) -> str:
    digest = hashlib.sha256(salt)
    digest.update(data)
    return digest.hexdigest()


def _spawn(argv: List[str], env: Dict[str, str]) -> None:
    """Start the helper detached: its own session, no standard streams, no handles of ours."""
    windows = os.name == "nt"
    flags = 0
    if windows:
        flags = getattr(subprocess, "DETACHED_PROCESS", 0x8) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
    subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
        cwd=_workdir(),
        close_fds=True,
        start_new_session=not windows,
        creationflags=flags,
    )


def _start_clearer(tool: _Tool, writer: str, reader: str, value: str, clear_after: int) -> None:
    if not sys.executable:
        raise IronDomeError("cannot start the helper that clears the clipboard: the Python interpreter is unknown")
    salt = os.urandom(_SALT_BYTES)
    encoded = value.encode("utf-8")
    try:
        digest = _digest(salt, encoded)
    finally:
        wipe_bytes(encoded)
    env = _environment()
    env[_SALT_VARIABLE] = salt.hex()
    # The helper imports this same copy of IronDome, wherever it was loaded from.
    env["PYTHONPATH"] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    argv = [
        sys.executable,
        "-m",
        "irondome.clipboard",
        "--clear-after",
        str(clear_after),
        "--sha256",
        digest,
        "--tool",
        tool.name,
        "--reader",
        reader,
        "--writer",
        writer,
    ]
    try:
        _spawn(argv, env)
    except OSError as exc:
        raise IronDomeError(f"could not start the helper that clears the clipboard: {exc.strerror or exc}") from None


def copy(value: str, clear_after: int) -> str:
    """Put *value* on the clipboard and have it cleared after *clear_after* seconds.

    Returns the name of the tool that was used. Raises :class:`UsageError`
    when there is no clipboard tool (with advice on installing one) and
    :class:`IronDomeError` when the tool fails. If the clearing helper cannot
    be started, the clipboard is emptied again before the error is raised: a
    secret is never left there with nothing to take it off.
    """
    if not isinstance(value, str):
        raise UsageError("only text can be copied to the clipboard")
    if isinstance(clear_after, bool) or not isinstance(clear_after, int):
        raise UsageError("the delay before the clipboard is cleared must be a whole number of seconds")
    if not MIN_CLEAR_SECONDS <= clear_after <= MAX_CLEAR_SECONDS:
        raise UsageError(
            f"the clipboard is cleared after {MIN_CLEAR_SECONDS} to {MAX_CLEAR_SECONDS} seconds, not {clear_after}"
        )
    tool, writer, reader = _find_tool()
    data = _encode(tool, value)
    try:
        _run(tool, writer, tool.write_args, data, capture=False)
    finally:
        wipe_bytes(data)
    try:
        _start_clearer(tool, writer, reader, value, clear_after)
    except BaseException:
        try:
            _clear(tool, writer)
        except IronDomeError:
            pass  # the error being raised already says the value may still be there
        raise
    return tool.name


def _still_there(current: bytes, salt: bytes, expected: str) -> bool:
    """True if what the clipboard holds now is the value the digest was made from.

    A tool may add a byte-order mark or a final line break on the way out;
    those forms count as the value too.
    """
    whole = memoryview(current)
    starts = [0, 3] if current.startswith(b"\xef\xbb\xbf") else [0]
    spans = []
    for start in starts:
        spans.append((start, len(current)))
        for ending in (b"\r\n", b"\n"):
            if current.endswith(ending) and len(current) - len(ending) >= start:
                spans.append((start, len(current) - len(ending)))
                break
    matched = False
    for start, end in spans:  # views, not copies: no extra copy of the value is made
        matched = hmac.compare_digest(_digest(salt, whole[start:end]), expected) or matched
    whole.release()
    return matched


def _parse_helper_arguments(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m irondome.clipboard",
        description=(
            "Clear the clipboard after a delay, if it still holds the value whose salted SHA-256 is given. "
            f"The salt is read from {_SALT_VARIABLE}. Started by IronDome itself; not meant to be run by hand."
        ),
    )
    parser.add_argument("--clear-after", type=int, required=True, metavar="N", help="seconds to wait first")
    parser.add_argument("--sha256", required=True, metavar="HEX", help="SHA-256 of the salt and the copied value")
    parser.add_argument("--tool", required=True, choices=sorted(_TOOLS), help="the clipboard tool family")
    parser.add_argument("--reader", required=True, metavar="PATH", help="absolute path of the tool that reads")
    parser.add_argument("--writer", required=True, metavar="PATH", help="absolute path of the tool that writes")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """The clearing helper. Returns 0 when it did its job, whether or not that meant clearing."""
    args = _parse_helper_arguments(argv)
    expected = args.sha256.lower()
    try:
        salt = bytes.fromhex(os.environ.get(_SALT_VARIABLE, ""))
    except ValueError:
        return 2
    if (
        len(salt) != _SALT_BYTES
        or len(expected) != 64
        or any(char not in "0123456789abcdef" for char in expected)
        or not 0 <= args.clear_after <= MAX_CLEAR_SECONDS
    ):
        return 2
    for path in (args.reader, args.writer):
        if not os.path.isabs(path) or not os.path.isfile(path) or paths.program_fault(path):
            return 2
    tool = _TOOLS[args.tool]
    time.sleep(args.clear_after)
    try:
        current = _run(tool, args.reader, tool.read_args, b"", capture=True)
    except IronDomeError:
        return 1
    try:
        if not _still_there(current, salt, expected):
            return 0
    finally:
        wipe_bytes(current)
    try:
        _clear(tool, args.writer)
    except IronDomeError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
