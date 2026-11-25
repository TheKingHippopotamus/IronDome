"""The clipboard helper: values go to the tool on stdin only, and only what was copied is cleared.

Every test runs against fake clipboard tools: small scripts named like the real ones, in a
directory that replaces the module's search path. They keep the "clipboard" in a file and log
each call (arguments, environment, size of the input), so nothing here can touch the clipboard of
the person running the suite.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest

from irondome import clipboard
from irondome.errors import IronDomeError, UsageError

SECRET = "s3cret-Value-\u00e9\u2603-42"
TOOL_NAMES = ("pbcopy", "pbpaste", "wl-copy", "wl-paste", "xclip", "xsel", "clip.exe", "powershell.exe")

_FAKE_TOOL = r'''
import json
import os
import sys

STATE = sys.argv[1]
NAME = sys.argv[2]
ARGS = sys.argv[3:]
BOARD = os.path.join(STATE, "clipboard")
data = sys.stdin.buffer.read()
with open(os.path.join(STATE, "log.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": NAME, "argv": ARGS, "env": dict(os.environ), "stdin": len(data)}) + "\n")
if os.path.exists(os.path.join(STATE, "fail-" + NAME)):
    sys.stderr.write("boom: cannot open display\n")
    sys.exit(1)


def store(content):
    with open(BOARD, "wb") as board:
        board.write(content)


def show():
    with open(BOARD, "rb") as board:
        sys.stdout.buffer.write(board.read())


if NAME == "clip.exe":
    if not data.startswith(b"\xff\xfe"):
        sys.exit(3)  # the real clip.exe would read the console code page and mangle the text
    store(data[2:].decode("utf-16-le").encode("utf-8"))
elif NAME in ("pbpaste", "wl-paste", "powershell.exe"):
    show()
elif NAME == "wl-copy":
    store(b"" if "--clear" in ARGS else data)
elif NAME == "xclip":
    show() if "-out" in ARGS else store(data)
elif NAME == "xsel":
    if "--output" in ARGS:
        show()
    else:
        store(b"" if "--clear" in ARGS else data)
else:
    store(data)
'''


class FakeTools:
    """A directory of fake clipboard tools and the state they share."""

    def __init__(self, root: Path) -> None:
        self.state = root / "state"
        self.bin = root / "bin"
        self.state.mkdir(parents=True)
        self.bin.mkdir()
        script = self.state / "fake_tool.py"
        script.write_text(_FAKE_TOOL, encoding="utf-8")
        for name in TOOL_NAMES:
            self.install(name, script)
        self.set_clipboard(b"before")

    def install(self, name: str, script: Path) -> None:
        path = self.bin / name
        path.write_text(
            "#!/bin/sh\n"
            f"exec {shlex.quote(sys.executable)} {shlex.quote(str(script))} {shlex.quote(str(self.state))} "
            f"{shlex.quote(name)} \"$@\"\n",
            encoding="utf-8",
        )
        path.chmod(stat.S_IRWXU)

    def remove(self, *names: str) -> None:
        for name in names:
            (self.bin / name).unlink()

    def fail(self, name: str) -> None:
        (self.state / f"fail-{name}").write_bytes(b"")

    def clipboard(self) -> bytes:
        return (self.state / "clipboard").read_bytes()

    def set_clipboard(self, content: bytes) -> None:
        (self.state / "clipboard").write_bytes(content)

    def log(self) -> List[Dict[str, Any]]:
        path = self.state / "log.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.fixture
def tools(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeTools:
    """Fake tools on the module's search path, and a Mac as far as the module can tell."""
    fake = FakeTools(tmp_path / "clipboard-tools")
    monkeypatch.setattr(clipboard, "_search_path", lambda: str(fake.bin))
    monkeypatch.setattr(clipboard, "_system", lambda: "darwin")
    for name in ("DISPLAY", "WAYLAND_DISPLAY"):
        monkeypatch.delenv(name, raising=False)
    return fake


@pytest.fixture
def spawned(monkeypatch: pytest.MonkeyPatch) -> List[Tuple[List[str], Dict[str, str]]]:
    """Record the clearing helper instead of starting it."""
    calls: List[Tuple[List[str], Dict[str, str]]] = []
    monkeypatch.setattr(clipboard, "_spawn", lambda argv, env: calls.append((list(argv), dict(env))))
    return calls


def _option(argv: List[str], name: str) -> str:
    return argv[argv.index(name) + 1]


def _salted(env: Dict[str, str], value: str) -> str:
    return hashlib.sha256(bytes.fromhex(env["IRONDOME_CLIPBOARD_SALT"]) + value.encode("utf-8")).hexdigest()


def _platform(monkeypatch: pytest.MonkeyPatch, system: str, variables: Dict[str, str]) -> None:
    monkeypatch.setattr(clipboard, "_system", lambda: system)
    for name, value in variables.items():
        monkeypatch.setenv(name, value)


def _wait_for(condition: Callable[[], bool], seconds: float = 20.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return condition()


# ---------------------------------------------------------------------------
# copy
# ---------------------------------------------------------------------------

PLATFORMS = [
    pytest.param("darwin", {}, "pbcopy", "pbcopy", "pbpaste", id="macos"),
    pytest.param("linux", {"WAYLAND_DISPLAY": "wayland-0"}, "wl-copy", "wl-copy", "wl-paste", id="wayland"),
    pytest.param("linux", {"DISPLAY": ":0"}, "xclip", "xclip", "xclip", id="x11-xclip"),
    pytest.param("win32", {}, "clip", "clip.exe", "powershell.exe", id="windows"),
]


@pytest.mark.parametrize("system, variables, tool, writer, reader", PLATFORMS)
def test_copy_hands_the_value_over_on_stdin_and_never_as_an_argument(
    tools: FakeTools,
    spawned: List[Tuple[List[str], Dict[str, str]]],
    monkeypatch: pytest.MonkeyPatch,
    system: str,
    variables: Dict[str, str],
    tool: str,
    writer: str,
    reader: str,
) -> None:
    _platform(monkeypatch, system, variables)
    monkeypatch.setenv("IRONDOME_TEST_CANARY", "do-not-pass-me-on")

    assert clipboard.copy(SECRET, 30) == tool

    assert tools.clipboard().decode("utf-8") == SECRET
    calls = tools.log()
    assert [call["tool"] for call in calls] == [writer]
    for call in calls:
        assert not any(SECRET in argument for argument in call["argv"])
        assert SECRET not in json.dumps(call["env"])
        assert call["env"]["PATH"] == str(tools.bin)
        assert "IRONDOME_TEST_CANARY" not in call["env"]
    assert calls[0]["stdin"] > 0

    (argv, env), = spawned
    assert argv[:3] == [sys.executable, "-m", "irondome.clipboard"]
    assert not any(SECRET in argument for argument in argv)
    assert SECRET not in json.dumps(env)
    assert _option(argv, "--clear-after") == "30"
    assert _option(argv, "--tool") == tool
    assert _option(argv, "--writer") == str(tools.bin / writer)
    assert _option(argv, "--reader") == str(tools.bin / reader)
    assert _option(argv, "--sha256") == _salted(env, SECRET)
    assert _option(argv, "--sha256") != hashlib.sha256(SECRET.encode("utf-8")).hexdigest()
    assert "IRONDOME_TEST_CANARY" not in env
    assert env["PATH"] == str(tools.bin)
    assert Path(env["PYTHONPATH"], "irondome", "clipboard.py").is_file()


def test_tools_names_what_copy_would_use_and_runs_nothing(tools: FakeTools, monkeypatch: pytest.MonkeyPatch) -> None:
    assert clipboard.tools() == ("pbcopy", str(tools.bin / "pbcopy"), str(tools.bin / "pbpaste"))
    _platform(monkeypatch, "linux", {"DISPLAY": ":0"})
    assert clipboard.tools() == ("xclip", str(tools.bin / "xclip"), str(tools.bin / "xclip"))
    assert tools.log() == []
    tools.remove("xclip", "xsel")
    with pytest.raises(UsageError, match="install"):
        clipboard.tools()


posix_only = pytest.mark.skipif(not hasattr(os, "getuid"), reason="owners and modes")


@posix_only
@pytest.mark.parametrize("which", ["pbcopy", "pbpaste"])
@pytest.mark.parametrize("mode", [0o720, 0o702], ids=["group", "others"])
def test_a_tool_that_others_can_write_is_given_nothing(
    tools: FakeTools, spawned: List[Any], which: str, mode: int
) -> None:
    """The writer would be handed the secret, the reader is run by the helper that clears it: both are checked."""
    (tools.bin / which).chmod(mode)
    with pytest.raises(clipboard.ToolRefused, match="can be written by other users") as refused:
        clipboard.copy(SECRET, 30)
    assert str(tools.bin / which) in str(refused.value) and SECRET not in str(refused.value)
    assert isinstance(refused.value, UsageError)
    with pytest.raises(clipboard.ToolRefused):
        clipboard.tools()
    assert tools.log() == [] and spawned == []
    assert tools.clipboard() == b"before"
    (tools.bin / which).chmod(0o700)
    assert clipboard.copy(SECRET, 30) == "pbcopy"


@posix_only
def test_a_tool_that_is_refused_is_not_passed_over_for_the_next_one(
    tools: FakeTools, spawned: List[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _platform(monkeypatch, "linux", {"DISPLAY": ":0"})
    (tools.bin / "xclip").chmod(0o777)
    with pytest.raises(clipboard.ToolRefused, match="xclip can be written by other users"):
        clipboard.copy(SECRET, 30)
    assert tools.log() == [] and spawned == []


@posix_only
def test_a_tool_of_another_user_is_given_nothing(
    tools: FakeTools, spawned: List[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = (tools.bin / "pbcopy").stat().st_uid
    if owner == 0:
        pytest.skip("root's tools are anybody's to run")
    monkeypatch.setattr(os, "getuid", lambda: owner + 1)
    with pytest.raises(clipboard.ToolRefused, match="belongs to another user"):
        clipboard.copy(SECRET, 30)
    assert tools.log() == [] and spawned == []


@posix_only
@pytest.mark.parametrize("which", ["pbcopy", "pbpaste"])
def test_the_helper_runs_no_tool_that_others_can_write(tools: FakeTools, salt: bytes, which: str) -> None:
    """Between the copy and the clearing a tool may have been replaced; the helper looks again."""
    tools.set_clipboard(SECRET.encode("utf-8"))
    digest = hashlib.sha256(salt + SECRET.encode("utf-8")).hexdigest()
    (tools.bin / which).chmod(0o722)
    assert clipboard.main(_helper_arguments(tools, digest)) == 2
    assert tools.log() == []
    assert tools.clipboard() == SECRET.encode("utf-8")
    (tools.bin / which).chmod(0o700)
    assert clipboard.main(_helper_arguments(tools, digest)) == 0
    assert tools.clipboard() == b""


@posix_only
@pytest.mark.parametrize("which", ["pbcopy", "pbpaste"])
def test_the_helper_looks_at_its_tools_again_after_the_wait(
    tools: FakeTools, salt: bytes, which: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wait is when a tool can be replaced. A by-hand trial made one writable during it, and it was run."""
    tools.set_clipboard(SECRET.encode("utf-8"))
    digest = hashlib.sha256(salt + SECRET.encode("utf-8")).hexdigest()
    monkeypatch.setattr(clipboard.time, "sleep", lambda seconds: (tools.bin / which).chmod(0o722))
    assert clipboard.main(_helper_arguments(tools, digest)) == 2
    assert tools.log() == []
    assert tools.clipboard() == SECRET.encode("utf-8")


def test_xsel_is_used_where_there_is_no_xclip(
    tools: FakeTools, spawned: List[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _platform(monkeypatch, "linux", {"DISPLAY": ":0"})
    tools.remove("xclip")
    assert clipboard.copy(SECRET, 30) == "xsel"
    assert tools.clipboard().decode("utf-8") == SECRET
    assert tools.log()[0]["argv"] == ["--clipboard", "--input"]


def test_wayland_without_wl_clipboard_falls_back_to_x11(
    tools: FakeTools, spawned: List[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _platform(monkeypatch, "linux", {"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"})
    tools.remove("wl-copy", "wl-paste")
    assert clipboard.copy(SECRET, 30) == "xclip"


def test_without_a_tool_the_error_says_what_to_install(
    tools: FakeTools, spawned: List[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _platform(monkeypatch, "linux", {"DISPLAY": ":0"})
    tools.remove("xclip", "xsel")
    with pytest.raises(UsageError, match="xclip"):
        clipboard.copy(SECRET, 30)
    assert spawned == []
    assert tools.clipboard() == b"before"


def test_without_a_graphical_session_nothing_is_tried(
    tools: FakeTools, spawned: List[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    _platform(monkeypatch, "linux", {})
    with pytest.raises(UsageError, match="DISPLAY"):
        clipboard.copy(SECRET, 30)
    assert tools.log() == []


def test_the_callers_path_is_never_searched(
    tools: FakeTools, spawned: List[Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    empty = tmp_path / "nothing-here"
    empty.mkdir()
    monkeypatch.setattr(clipboard, "_search_path", lambda: str(empty))
    monkeypatch.setenv("PATH", str(tools.bin))
    with pytest.raises(UsageError, match="pbcopy"):
        clipboard.copy(SECRET, 30)
    assert tools.log() == []


def test_the_default_search_path_ignores_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(clipboard, "_system", lambda: "linux")
    search = clipboard._search_path().split(os.pathsep)
    assert str(tmp_path) not in search
    assert all(os.path.isabs(directory) for directory in search)
    assert "/usr/bin" in search


def test_a_failing_tool_is_reported_and_no_helper_is_started(
    tools: FakeTools, spawned: List[Any]
) -> None:
    tools.fail("pbcopy")
    with pytest.raises(IronDomeError, match="cannot open display"):
        clipboard.copy(SECRET, 30)
    assert spawned == []


def test_if_the_helper_cannot_start_the_clipboard_is_emptied_again(
    tools: FakeTools, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(argv: List[str], env: Dict[str, str]) -> None:
        raise OSError(11, "Resource temporarily unavailable")

    monkeypatch.setattr(clipboard, "_spawn", refuse)
    with pytest.raises(IronDomeError, match="helper"):
        clipboard.copy(SECRET, 30)
    assert tools.clipboard() == b""
    assert [call["tool"] for call in tools.log()] == ["pbcopy", "pbcopy"]


@pytest.mark.parametrize("delay", [0, -1, 3601, True, "5", 2.5])
def test_the_delay_must_be_a_sensible_whole_number(tools: FakeTools, spawned: List[Any], delay: Any) -> None:
    with pytest.raises(UsageError):
        clipboard.copy(SECRET, delay)
    assert tools.log() == []


def test_only_text_can_be_copied(tools: FakeTools, spawned: List[Any]) -> None:
    with pytest.raises(UsageError):
        clipboard.copy(b"bytes", 30)  # type: ignore[arg-type]


def test_the_helper_starts_detached_with_its_streams_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: Dict[str, Any] = {}

    class Recorder:
        def __init__(self, argv: List[str], **options: Any) -> None:
            seen["argv"] = argv
            seen.update(options)

    monkeypatch.setattr(clipboard.subprocess, "Popen", Recorder)
    clipboard._spawn(["python", "-m", "irondome.clipboard"], {"PATH": "/usr/bin"})
    assert seen["stdin"] == seen["stdout"] == seen["stderr"] == subprocess.DEVNULL
    assert seen["close_fds"] is True
    assert seen["env"] == {"PATH": "/usr/bin"}
    if os.name != "nt":
        assert seen["start_new_session"] is True
        assert seen["cwd"] == "/"
        assert seen["creationflags"] == 0
    assert "shell" not in seen


# ---------------------------------------------------------------------------
# The clearing helper, run in this process
# ---------------------------------------------------------------------------


def _helper_arguments(tools: FakeTools, digest: str, tool: str = "pbcopy", **paths: str) -> List[str]:
    readers = {"pbcopy": "pbpaste", "clip": "powershell.exe", "xsel": "xsel"}
    writers = {"pbcopy": "pbcopy", "clip": "clip.exe", "xsel": "xsel"}
    return [
        "--clear-after", "0",
        "--sha256", digest,
        "--tool", tool,
        "--reader", paths.get("reader", str(tools.bin / readers[tool])),
        "--writer", paths.get("writer", str(tools.bin / writers[tool])),
    ]


@pytest.fixture
def salt(monkeypatch: pytest.MonkeyPatch) -> bytes:
    value = os.urandom(32)
    monkeypatch.setenv("IRONDOME_CLIPBOARD_SALT", value.hex())
    return value


def test_the_helper_clears_the_clipboard_while_it_still_holds_the_value(tools: FakeTools, salt: bytes) -> None:
    tools.set_clipboard(SECRET.encode("utf-8"))
    digest = hashlib.sha256(salt + SECRET.encode("utf-8")).hexdigest()
    assert clipboard.main(_helper_arguments(tools, digest)) == 0
    assert tools.clipboard() == b""
    assert [call["tool"] for call in tools.log()] == ["pbpaste", "pbcopy"]
    assert all(SECRET not in " ".join(call["argv"]) for call in tools.log())


def test_the_helper_leaves_whatever_was_copied_since_alone(tools: FakeTools, salt: bytes) -> None:
    tools.set_clipboard(b"something the user copied afterwards")
    digest = hashlib.sha256(salt + SECRET.encode("utf-8")).hexdigest()
    assert clipboard.main(_helper_arguments(tools, digest)) == 0
    assert tools.clipboard() == b"something the user copied afterwards"
    assert [call["tool"] for call in tools.log()] == ["pbpaste"]


def test_the_helper_needs_the_right_salt(tools: FakeTools, salt: bytes) -> None:
    tools.set_clipboard(SECRET.encode("utf-8"))
    unsalted = hashlib.sha256(SECRET.encode("utf-8")).hexdigest()
    assert clipboard.main(_helper_arguments(tools, unsalted)) == 0
    assert tools.clipboard() == SECRET.encode("utf-8")


@pytest.mark.parametrize(
    "shown",
    [b"\xef\xbb\xbf" + SECRET.encode("utf-8"), SECRET.encode("utf-8") + b"\r\n", SECRET.encode("utf-8") + b"\n"],
    ids=["byte-order-mark", "crlf", "lf"],
)
def test_the_helper_recognises_the_value_as_a_tool_prints_it(tools: FakeTools, salt: bytes, shown: bytes) -> None:
    tools.set_clipboard(shown)
    digest = hashlib.sha256(salt + SECRET.encode("utf-8")).hexdigest()
    assert clipboard.main(_helper_arguments(tools, digest, tool="clip")) == 0
    assert tools.clipboard() == b""


def test_xsel_is_cleared_with_its_own_option(tools: FakeTools, salt: bytes) -> None:
    tools.set_clipboard(SECRET.encode("utf-8"))
    digest = hashlib.sha256(salt + SECRET.encode("utf-8")).hexdigest()
    assert clipboard.main(_helper_arguments(tools, digest, tool="xsel")) == 0
    assert tools.clipboard() == b""
    assert tools.log()[-1]["argv"] == ["--clipboard", "--clear"]


def test_a_failing_reader_changes_nothing(tools: FakeTools, salt: bytes) -> None:
    tools.set_clipboard(SECRET.encode("utf-8"))
    tools.fail("pbpaste")
    digest = hashlib.sha256(salt + SECRET.encode("utf-8")).hexdigest()
    assert clipboard.main(_helper_arguments(tools, digest)) == 1
    assert tools.clipboard() == SECRET.encode("utf-8")


@pytest.mark.parametrize(
    "change",
    [
        {"sha256": "not-hex"},
        {"sha256": "ab" * 31},
        {"reader": "pbpaste"},
        {"writer": "/nonexistent/pbcopy"},
        {"clear-after": "-1"},
        {"clear-after": "3601"},
    ],
    ids=["sha256-not-hex", "sha256-short", "relative-reader", "missing-writer", "negative-delay", "long-delay"],
)
def test_the_helper_refuses_arguments_it_did_not_expect(
    tools: FakeTools, salt: bytes, change: Dict[str, str]
) -> None:
    tools.set_clipboard(SECRET.encode("utf-8"))
    digest = hashlib.sha256(salt + SECRET.encode("utf-8")).hexdigest()
    arguments = _helper_arguments(tools, change.get("sha256", digest), **{
        key: value for key, value in change.items() if key in ("reader", "writer")
    })
    if "clear-after" in change:
        arguments[1] = change["clear-after"]
    assert clipboard.main(arguments) == 2
    assert tools.log() == []
    assert tools.clipboard() == SECRET.encode("utf-8")


def test_the_helper_refuses_to_run_without_its_salt(tools: FakeTools, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IRONDOME_CLIPBOARD_SALT", raising=False)
    digest = hashlib.sha256(SECRET.encode("utf-8")).hexdigest()
    assert clipboard.main(_helper_arguments(tools, digest)) == 2
    monkeypatch.setenv("IRONDOME_CLIPBOARD_SALT", "zz")
    assert clipboard.main(_helper_arguments(tools, digest)) == 2
    assert tools.log() == []


def test_the_helper_knows_only_its_own_tools(tools: FakeTools, salt: bytes) -> None:
    with pytest.raises(SystemExit) as stopped:
        clipboard.main(["--clear-after", "0", "--sha256", "ab" * 32, "--tool", "sh", "--reader", "/bin/sh",
                        "--writer", "/bin/sh"])
    assert stopped.value.code == 2


# ---------------------------------------------------------------------------
# The real detached helper
# ---------------------------------------------------------------------------


def _tool_calls(tools: FakeTools, name: str) -> List[int]:
    return [index for index, call in enumerate(tools.log()) if call["tool"] == name]


def test_the_detached_helper_clears_the_clipboard_after_the_delay(tools: FakeTools) -> None:
    started = time.monotonic()
    assert clipboard.copy(SECRET, 1) == "pbcopy"
    assert tools.clipboard().decode("utf-8") == SECRET
    assert _wait_for(lambda: tools.clipboard() == b"")
    assert time.monotonic() - started >= 1.0
    reader_calls = [call for call in tools.log() if call["tool"] == "pbpaste"]
    assert len(reader_calls) == 1
    assert "IRONDOME_CLIPBOARD_SALT" not in reader_calls[0]["env"]


def test_the_detached_helper_leaves_a_changed_clipboard_alone(tools: FakeTools) -> None:
    clipboard.copy(SECRET, 1)
    tools.set_clipboard(b"copied by the user in the meantime")
    assert _wait_for(lambda: bool(_tool_calls(tools, "pbpaste")))
    time.sleep(1.0)  # a clear would follow the read at once
    assert tools.clipboard() == b"copied by the user in the meantime"
    writes = _tool_calls(tools, "pbcopy")
    assert writes == [0]


def _command_line_of_helpers() -> Optional[List[str]]:
    """The command lines of running clipboard helpers, where ps can tell (for the leak check below)."""
    try:
        listing = subprocess.run(
            ["/bin/ps", "-Ao", "args"], capture_output=True, text=True, timeout=10, check=True
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return [line for line in listing.splitlines() if "irondome.clipboard" in line]


@pytest.mark.skipif(not os.path.exists("/bin/ps"), reason="needs ps to read the process list")
def test_the_process_list_never_shows_the_value(tools: FakeTools) -> None:
    if _command_line_of_helpers() is None:
        pytest.skip("ps could not be run here")
    clipboard.copy(SECRET, 3)
    seen: List[str] = []

    def helper_listed() -> bool:
        seen[:] = _command_line_of_helpers() or []
        return any("--sha256" in line for line in seen)

    assert _wait_for(helper_listed, 2.5), "the helper was not found in the process list while it waited"
    assert _wait_for(lambda: tools.clipboard() == b"")
    assert not any(SECRET in line for line in seen)
    assert not any(hashlib.sha256(SECRET.encode("utf-8")).hexdigest() in line for line in seen)
