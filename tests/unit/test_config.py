"""Settings: config.json is not authenticated, so no value inside its ranges may be unsafe."""

from __future__ import annotations

import json
import math
import os
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List

import pytest

from irondome import config, generator, paths
from irondome.errors import UsageError

pytestmark = pytest.mark.usefixtures("isolated")


def write_config(values: dict) -> None:
    path = paths.config_file()
    paths.ensure_dir(path.parent)
    path.write_text(json.dumps(values))


def test_the_floors_are_safe_whoever_wrote_the_file() -> None:
    settings = config.SETTINGS
    assert settings["password_length"].minimum >= 16
    assert settings["passphrase_words"].minimum >= 5
    assert settings["grant_ttl"].maximum <= 24 * 3600
    assert settings["session_ttl"].maximum <= 12 * 3600
    assert settings["clipboard_clear_seconds"].maximum <= 600
    # 5 words from the EFF list (7776 words) is about 64 bits.
    assert settings["passphrase_words"].minimum * math.log2(len(generator.wordlist())) >= 64


def test_a_hostile_file_cannot_weaken_the_defaults() -> None:
    write_config({"password_length": 8, "passphrase_words": 3, "grant_ttl": 30 * 86_400, "session_ttl": 10**9,
                  "clipboard_clear_seconds": 86_400, "snapshots": -1})
    values = config.load()
    for key, setting in config.SETTINGS.items():
        assert values[key] == setting.default, key


@pytest.mark.parametrize("value", [True, 20.0, "20", None, [20]])
def test_values_of_the_wrong_type_fall_back_to_the_default(value) -> None:
    write_config({"password_length": value})
    assert config.get("password_length") == config.SETTINGS["password_length"].default


def test_a_damaged_file_falls_back_to_every_default() -> None:
    path = paths.config_file()
    paths.ensure_dir(path.parent)
    path.write_bytes(b"\xff{not json")
    assert config.load() == {key: setting.default for key, setting in config.SETTINGS.items()}


@pytest.mark.parametrize("key, value", [("password_length", "15"), ("passphrase_words", "4"),
                                        ("grant_ttl", "86401"), ("password_length", "twenty")])
def test_setting_a_value_outside_its_range_is_refused(key: str, value: str) -> None:
    with pytest.raises(UsageError):
        config.set_value(key, value)
    assert config.get(key) == config.SETTINGS[key].default


def test_a_value_at_its_bounds_is_kept() -> None:
    assert config.set_value("password_length", "16") == 16
    assert config.set_value("grant_ttl", "86400") == 86_400
    assert config.get("password_length") == 16 and config.get("grant_ttl") == 86_400
    config.reset([])
    assert config.get("password_length") == config.SETTINGS["password_length"].default


DEFAULTS = {key: setting.default for key, setting in config.SETTINGS.items()}


def write_raw(data: bytes) -> None:
    path = paths.config_file()
    paths.ensure_dir(path.parent)
    path.write_bytes(data)


# ---------------------------------------------------------------------------
# A hostile file (red team round 1, hostile-input:1 and hostile-input:2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("depth", [32_000, 100_000], ids=["within the size limit", "the red team's file"])
def test_a_file_nested_without_end_falls_back_to_every_default_and_can_be_reset(depth: int) -> None:
    """json raises RecursionError for deep nesting. It is not a ValueError, so it escaped as a traceback."""
    write_raw(b"[" * depth + b"]" * depth)
    assert config.load() == DEFAULTS
    assert config.get("grant_ttl") == DEFAULTS["grant_ttl"]
    config.reset([])  # the way out: it read the file first, and crashed with everything else
    assert not paths.config_file().exists()
    write_raw(b"[" * depth + b"]" * depth)
    assert config.set_value("grant_ttl", "120") == 120
    assert config.load() == dict(DEFAULTS, grant_ttl=120)


@pytest.mark.parametrize(
    "text",
    ['{"grant_ttl": ' + "1" * 5000 + "}", '{"grant_ttl": 120, "grant_ttl": 60}', '{"grant_ttl": NaN}'],
    ids=["a number thousands of digits long", "a key given twice", "not a number"],
)
def test_what_irondome_never_writes_falls_back_to_the_default(text: str) -> None:
    write_raw(text.encode("ascii"))
    assert config.load() == DEFAULTS


def test_a_file_too_large_to_be_irondomes_falls_back_to_every_default() -> None:
    """Over read_file's cap the VaultError escaped load(). Over 64 KiB a file is not IronDome's and is not read."""
    path = paths.config_file()
    paths.ensure_dir(path.parent)
    with open(path, "wb") as handle:
        handle.truncate(paths.MAX_FILE_BYTES + 1)  # sparse: nothing is written to the disk
    assert config.load() == DEFAULTS
    write_raw(b'{"grant_ttl": 120}' + b" " * (64 * 1024))
    assert config.get("grant_ttl") == DEFAULTS["grant_ttl"]
    write_raw(b'{"grant_ttl": 120}' + b" " * (64 * 1024 - 18))
    assert config.get("grant_ttl") == 120, "64 KiB exactly is still read"


@pytest.fixture
def pipe_for_config() -> Iterator[Path]:
    """config.json as a named pipe nothing writes to. Afterwards it is opened once for reading and writing without
    waiting, which lets a thread blocked on it go on, so that a run against code that waits fails and ends."""
    path = paths.config_file()
    paths.ensure_dir(path.parent)
    os.mkfifo(str(path))
    yield path
    try:
        fd = os.open(str(path), os.O_RDWR | os.O_NONBLOCK)
    except OSError:
        return
    time.sleep(0.2)
    os.close(fd)


def finished(seconds: float, call: Callable[[], Any]) -> Any:
    """The result of *call*, run on a thread; the test fails instead of hanging if *call* is still running later."""
    box: Dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = call()
        except BaseException as exc:  # handed back below
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        pytest.fail(f"still blocked after {seconds} seconds")
    if "error" in box:
        raise box["error"]
    return box.get("value")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_pipe_in_place_of_the_file_is_never_waited_on(pipe_for_config: Path) -> None:
    """Opening a pipe for reading waits for a writer: every command that reads a setting hung on it."""
    assert finished(10, config.load) == DEFAULTS
    assert finished(10, lambda: config.set_value("snapshots", "3")) == 3
    assert stat.S_ISREG(os.lstat(str(pipe_for_config)).st_mode), "the setting replaced the pipe"
    assert config.get("snapshots") == 3


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_the_command_line_does_not_hang_on_a_pipe_or_crash_on_deep_nesting(cli, pipe_for_config: Path) -> None:
    """The red team's reproductions, end to end: `config get` was killed by a timeout, or printed a traceback."""
    on_a_pipe = cli("config", "get", "grant_ttl", timeout=60)
    assert (on_a_pipe.returncode, on_a_pipe.stdout.strip()) == (0, "900"), on_a_pipe.stderr
    os.unlink(str(pipe_for_config))
    write_raw(b"[" * 100_000 + b"]" * 100_000)
    nested = cli("config", "get", "grant_ttl", timeout=60)
    assert (nested.returncode, nested.stdout.strip()) == (0, "900"), nested.stderr
    assert "Traceback" not in nested.stderr and "RecursionError" not in nested.stderr


# ---------------------------------------------------------------------------
# Two changes at once (red team round 1, filesystem:4)
# ---------------------------------------------------------------------------


def race(monkeypatch: pytest.MonkeyPatch, first: Callable[[], Any], second: Callable[[], Any]) -> None:
    """Run *first* until it is about to write config.json, then *second*, then let *first* write.

    *second* gets as far as it can: without a lock it reads the file *first* has not written yet and writes its
    own; with one it waits on the lock. Only then is *first* let go. Deterministic: no sleeping, no timing.
    """
    paused, release, second_read, second_waits = (threading.Event() for _ in range(4))
    threads: Dict[str, threading.Thread] = {}
    real_write, real_load, real_lock = config._write, config.load, paths._lock

    def write(stored: Dict[str, int]) -> None:
        if threading.current_thread() is threads.get("first"):
            paused.set()
            assert release.wait(60), "never released"
        real_write(stored)

    def load() -> Dict[str, int]:
        values = real_load()
        if threading.current_thread() is threads.get("second"):
            second_read.set()  # set once the file has been read: what it held then is what it will write back
        return values

    def lock(fd: int) -> None:
        if threading.current_thread() is threads.get("second"):
            second_waits.set()
        real_lock(fd)

    monkeypatch.setattr(config, "_write", write)
    monkeypatch.setattr(config, "load", load)
    monkeypatch.setattr(paths, "_lock", lock)
    errors: List[BaseException] = []

    def run(call: Callable[[], Any]) -> Callable[[], None]:
        def target() -> None:
            try:
                call()
            except BaseException as exc:  # reported by the test thread
                errors.append(exc)

        return target

    threads["first"] = threading.Thread(target=run(first), daemon=True)
    threads["second"] = threading.Thread(target=run(second), daemon=True)
    threads["first"].start()
    assert paused.wait(60), "the first change never reached its write"
    threads["second"].start()
    deadline = time.monotonic() + 60
    while not (second_read.is_set() or second_waits.is_set()) and time.monotonic() < deadline:
        time.sleep(0.005)
    if second_read.is_set():
        threads["second"].join(60)  # unlocked: it finishes on its own, from what it read
    release.set()
    for thread in threads.values():
        thread.join(60)
        assert not thread.is_alive(), "a change never finished"
    assert errors == []


def test_two_settings_changed_at_once_are_both_kept(monkeypatch) -> None:
    """Both commands said ok, and the later write put back the file as the other had read it."""
    race(monkeypatch, lambda: config.set_value("snapshots", "0"), lambda: config.set_value("grant_ttl", "60"))

    assert config.load() == dict(DEFAULTS, snapshots=0, grant_ttl=60)
    assert json.loads(paths.config_file().read_text()) == {"grant_ttl": 60, "snapshots": 0}


def test_a_reset_and_a_change_made_at_once_are_both_kept(monkeypatch) -> None:
    config.set_value("grant_ttl", "60")

    race(monkeypatch, lambda: config.reset(["grant_ttl"]), lambda: config.set_value("snapshots", "0"))

    assert config.load() == dict(DEFAULTS, snapshots=0)


def test_changing_a_setting_holds_the_bunkers_lock(monkeypatch) -> None:
    held: List[bool] = []
    real_write = config._write

    def write(stored: Dict[str, int]) -> None:
        held.append(os.path.realpath(str(paths.lock_file())) in paths._held)
        real_write(stored)

    monkeypatch.setattr(config, "_write", write)
    config.set_value("grant_ttl", "60")
    config.reset([])
    assert held == [True, True]
    assert os.path.realpath(str(paths.lock_file())) not in paths._held, "and lets it go"
