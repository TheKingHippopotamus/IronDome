"""The everyday commands, end to end: the real ``irondome`` in a subprocess, in throwaway directories.

Every test drives ``python -m irondome`` through the ``cli`` fixture, with ``IRONDOME_NO_PROMPT=1``,
so nothing can wait on a terminal: the master password always arrives with ``--password-stdin``,
and a test without it is an agent. Results are checked on the exit status, stdout, stderr and the
vault left behind, and wherever a secret must not be printed, that it was not.

Touch ID and the clipboard are faked inside the child process by a ``sitecustomize`` hook that a
test writes into its own temporary directory: a fingerprint "chip" kept in files of the bunker's
device directory, and clipboard tools that keep the "clipboard" in a file. The hook is checked to
be active before anything is copied, so no test can reach the real clipboard or the real sensor.
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import os
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence

import pytest

from conftest import PASSWORD, secret
from irondome import caps, otp, paths, unlock
from irondome.errors import AuthError
from irondome.vault import VaultFile

PASSWORD2 = "a different horse, a different staple"
TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238's test key: "12345678901234567890"
RECOVERY_KEY = re.compile(r"[A-Z2-7]{4}(-[A-Z2-7]{4}){7}")
REPOSITORY = Path(__file__).resolve().parents[2]

Run = Callable[..., subprocess.CompletedProcess]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def lines(*values: str) -> str:
    return "".join(value + "\n" for value in values)


def show(result: subprocess.CompletedProcess) -> str:
    return f"exit {result.returncode}\n--- stdout\n{result.stdout}\n--- stderr\n{result.stderr}"


def ok(result: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    assert result.returncode == 0, show(result)
    return result


def fails(result: subprocess.CompletedProcess, code: int, *fragments: str) -> subprocess.CompletedProcess:
    assert result.returncode == code, show(result)
    for fragment in fragments:
        assert fragment in result.stderr, show(result)
    assert result.stdout == "", show(result)
    return result


def as_json(result: subprocess.CompletedProcess) -> Any:
    ok(result)
    return json.loads(result.stdout)


def owner(cli: Run, *args: str, more: Sequence[str] = (), password: str = PASSWORD, **options: Any):
    """Run a command as the owner: the master password on the first line of stdin, then *more*."""
    return cli("--password-stdin", *args, stdin=lines(password, *more), **options)


def leaked(result: subprocess.CompletedProcess, *values: str) -> List[str]:
    return [value for value in values if value and (value in result.stdout or value in result.stderr)]


def init(cli: Run, *args: str, password: str = PASSWORD, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return as_json(cli("--json", "init", "--password-stdin", *args, stdin=lines(password), env=env))


def status(cli: Run, *args: str, env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return as_json(cli("--json", *args, "status", env=env))


def get(cli: Run, reference: str, *args: str, password: str = PASSWORD, env: Optional[Dict[str, str]] = None) -> str:
    return ok(owner(cli, "get", reference, *args, password=password, env=env)).stdout


def device_files() -> List[Path]:
    """Every device key file of every bunker, on the device side."""
    return sorted(paths.device_root().glob("bunkers/*/*.*"))


def snapshot_files(bunker: str = paths.FIRST_BUNKER) -> List[Path]:
    return sorted((paths.root() / "bunkers" / bunker / "backups").glob("vault-*.irondome"))


@pytest.fixture
def vault(cli: Run) -> str:
    """Bunker alpha with a vault, two entries and an alias. Returns its recovery key."""
    recovery = init(cli)["recovery_key"]
    ok(owner(cli, "add", "github", "--value-stdin", "--username", "king", "--url", "https://github.com",
             "--tag", "dev", "--alias", "GITHUB_TOKEN", more=["gh-value-1"]))
    ok(owner(cli, "add", "aws/prod", "--kind", "secret", "--value-stdin", "--field", "region",
             "--note", "the production account", more=["AKIA-prod-value", "eu-west-1"]))
    return recovery


def open_vault(password: str = PASSWORD) -> Any:
    buffer = secret(password)
    try:
        return unlock.open_vault(password=buffer)
    finally:
        buffer.wipe()


def make_grant(references: List[str], *, password: str = PASSWORD, bunker: Optional[str] = None, **options: Any) -> str:
    """A grant made the way ``irondome grant create`` makes one, in *bunker* (default: alpha).

    The bunker is chosen for this call only: the child processes must find it from the token.
    """
    saved = os.environ.get(paths.ENV_BUNKER)
    if bunker is not None:
        os.environ[paths.ENV_BUNKER] = bunker
    try:
        with open_vault(password) as opened:
            token, _info = caps.create_grant(opened, references, **options)
    finally:
        if saved is None:
            os.environ.pop(paths.ENV_BUNKER, None)
        else:
            os.environ[paths.ENV_BUNKER] = saved
    return token


# ---------------------------------------------------------------------------
# The hook that fakes Touch ID and the clipboard in the child
# ---------------------------------------------------------------------------

HOOK = r'''
"""Test hooks for the CLI child processes of tests/e2e/test_cli_vault.py. Not part of IronDome."""
import importlib.util
import json
import os
import sys
import types

_HERE = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))


def _chain():
    """Run the sitecustomize this one shadows: the next one after this file's place on sys.path."""
    folders = [os.path.realpath(entry or os.curdir) for entry in sys.path]
    if _HERE not in folders:
        return
    for folder in folders[folders.index(_HERE) + 1:]:
        candidate = os.path.join(folder, "sitecustomize.py")
        if os.path.isfile(candidate):
            spec = importlib.util.spec_from_file_location("_shadowed_sitecustomize", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return


def _fake_touch():
    from irondome import device, paths
    from irondome.device.base import (
        POLICY_BIOMETRY, POLICY_DEVICE, POLICY_PRESENCE, DeviceBackend, Probe, check_descriptor, new_ref,
    )
    from irondome.errors import AuthError, HardwareError
    from irondome.secmem import SecureBuffer

    class FileTouch(DeviceBackend):
        """A chip with a fingerprint sensor, kept in files so that it outlives one process."""

        name = "fake-touch"
        hardware = True
        policies = (POLICY_DEVICE, POLICY_BIOMETRY, POLICY_PRESENCE)

        def _path(self, descriptor):
            check_descriptor(descriptor, self.name)
            return paths.device_dir() / (descriptor["ref"] + ".json")

        def probe(self):
            return Probe(self.name, True, True, True, "a stand-in chip with a fingerprint sensor")

        def _authorise(self, operation, policy, interactive, reason):
            if policy == POLICY_DEVICE:
                return
            if not interactive:
                raise AuthError("a fingerprint is required, and it cannot be asked for here")
            with open(os.environ["IRONDOME_TEST_TOUCH_LOG"], "a", encoding="utf-8") as log:
                log.write(json.dumps({"operation": operation, "reason": reason}) + "\n")
            if os.environ.get("IRONDOME_TEST_FINGER") == "refuse":
                raise AuthError("the fingerprint prompt was cancelled")

        def enroll(self, *, policy, auth, reason):
            if not self.supports(policy):
                raise HardwareError("the stand-in chip has no " + policy + " policy")
            self._authorise("enroll", policy, True, reason)
            descriptor = {"backend": self.name, "policy": policy, "ref": new_ref()}
            raw = os.urandom(32)
            state = {"backend": self.name, "secret": raw.hex()}
            paths.write_atomic(self._path(descriptor), json.dumps(state).encode("ascii"))
            return descriptor, SecureBuffer.from_buffer(raw)

        def unseal(self, descriptor, *, auth, interactive, reason):
            path = self._path(descriptor)
            if not path.is_file():
                raise HardwareError("the stand-in chip does not hold this key")
            self._authorise("unseal", descriptor["policy"], interactive, reason)
            return SecureBuffer.from_buffer(bytes.fromhex(json.loads(path.read_text())["secret"]))

        def destroy(self, descriptor):
            paths.secure_delete(self._path(descriptor))

        def exists(self, descriptor):
            return self._path(descriptor).is_file()

        def destroy_all(self):
            count = 0
            folder = paths.device_dir()
            for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
                try:
                    holder = json.loads(path.read_text()).get("backend")
                except ValueError:
                    continue
                if holder == self.name:
                    paths.secure_delete(path)
                    count += 1
            return count

    device._REGISTRY = device._REGISTRY + (("fake-touch", "irondome.no_such_module", "FileTouch"),)
    device._instances["fake-touch"] = FileTouch()
    if sys.platform != "darwin":
        import irondome.unlock

        irondome.unlock.sys = types.SimpleNamespace(platform="darwin")


def _fake_clipboard(folder):
    from irondome import clipboard

    clipboard._search_path = lambda: folder
    clipboard._system = lambda: "darwin"


def _signal_after_first_write(name):
    """Send this process signal *name* the moment its first vault write has returned: Ctrl-C, kill, a crash."""
    import signal

    from irondome import vault

    signum = getattr(signal, name)
    if signum != signal.SIGKILL:  # whatever the test runner ignores, the signal acts here as it would at a terminal
        signal.signal(signum, signal.default_int_handler if signum == signal.SIGINT else signal.SIG_DFL)
    write = vault.Vault.commit
    sent = []

    def commit(self, *args, **kwargs):
        write(self, *args, **kwargs)
        if not sent:
            sent.append(name)
            os.kill(os.getpid(), signum)

    vault.Vault.commit = commit


# Another sitecustomize that searches all of sys.path for the next one can run this file again: once is enough.
if not getattr(sys, "_irondome_cli_vault_hook", False):
    sys._irondome_cli_vault_hook = True
    _chain()
    if os.environ.get("IRONDOME_TEST_FAKE_TOUCH") == "1":
        _fake_touch()
    if os.environ.get("IRONDOME_TEST_CLIPBOARD_DIR"):
        _fake_clipboard(os.environ["IRONDOME_TEST_CLIPBOARD_DIR"])
    if os.environ.get("IRONDOME_TEST_SIGNAL_AFTER_WRITE"):
        _signal_after_first_write(os.environ["IRONDOME_TEST_SIGNAL_AFTER_WRITE"])
    if os.environ.get("IRONDOME_TEST_HOOK_MARKER"):
        open(os.environ["IRONDOME_TEST_HOOK_MARKER"], "a").close()
'''

FAKE_CLIPBOARD_TOOL = r'''
import json
import os
import sys

STATE, NAME = sys.argv[1], sys.argv[2]
data = sys.stdin.buffer.read()
with open(os.path.join(STATE, "log.jsonl"), "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": NAME, "argv": sys.argv[3:]}) + "\n")
board = os.path.join(STATE, "clipboard")
if NAME == "pbpaste":
    with open(board, "rb") as handle:
        sys.stdout.buffer.write(handle.read())
else:
    with open(board, "wb") as handle:
        handle.write(data)
'''


def _hook_env(tmp_path: Path, extra: Dict[str, str]) -> Dict[str, str]:
    folder = tmp_path / "hook"
    if not folder.is_dir():
        folder.mkdir()
        (folder / "sitecustomize.py").write_text(HOOK, encoding="utf-8")
    support = Path(__file__).resolve().parents[1] / "support"
    # The suite's own hook (no sockets) goes first, as the cli fixture puts it; it runs this one next.
    parts = ([str(support)] if support.is_dir() else []) + [str(folder)]
    if os.environ.get("PYTHONPATH"):
        parts.append(os.environ["PYTHONPATH"])
    env = {"PYTHONPATH": os.pathsep.join(parts), "IRONDOME_TEST_HOOK_MARKER": str(tmp_path / "hook-loaded")}
    env.update(extra)
    return env


class Touch:
    """The environment that gives the child a fingerprint sensor, and what the sensor was asked."""

    def __init__(self, tmp_path: Path) -> None:
        self.log = tmp_path / "touch.jsonl"
        self.env = _hook_env(
            tmp_path,
            {
                "IRONDOME_TEST_FAKE_TOUCH": "1",
                "IRONDOME_TEST_TOUCH_LOG": str(self.log),
                "IRONDOME_DEVICE_BACKEND": "fake-touch",
                "IRONDOME_NO_TOUCH": "0",
            },
        )

    def prompts(self) -> List[Dict[str, str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def refusing(self) -> Dict[str, str]:
        return dict(self.env, IRONDOME_TEST_FINGER="refuse")


@pytest.fixture
def touch(cli: Run, tmp_path: Path) -> Touch:
    sensor = Touch(tmp_path)
    ok(cli("--version", env=sensor.env))
    assert (tmp_path / "hook-loaded").exists(), "the fake sensor hook did not load in the child"
    return sensor


class Clipboard:
    """Fake pbcopy and pbpaste; the clipboard is a file."""

    def __init__(self, tmp_path: Path) -> None:
        self.state = tmp_path / "clipboard-state"
        self.bin = tmp_path / "clipboard-bin"
        self.state.mkdir()
        self.bin.mkdir()
        script = self.state / "tool.py"
        script.write_text(FAKE_CLIPBOARD_TOOL, encoding="utf-8")
        for name in ("pbcopy", "pbpaste"):
            path = self.bin / name
            path.write_text(
                f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(script))} "
                f"{shlex.quote(str(self.state))} {name} \"$@\"\n",
                encoding="utf-8",
            )
            path.chmod(stat.S_IRWXU)
        (self.state / "clipboard").write_bytes(b"")
        self.env = _hook_env(tmp_path, {"IRONDOME_TEST_CLIPBOARD_DIR": str(self.bin)})

    def text(self) -> str:
        return (self.state / "clipboard").read_bytes().decode("utf-8")

    def calls(self) -> List[Dict[str, Any]]:
        log = self.state / "log.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def clipboard(cli: Run, tmp_path: Path) -> Clipboard:
    fake = Clipboard(tmp_path)
    ok(cli("--version", env=fake.env))
    assert (tmp_path / "hook-loaded").exists(), "the fake clipboard hook did not load; refusing to copy anything"
    return fake


def legacy_fixture(name: str = "password_only") -> Dict[str, Any]:
    spec = importlib.util.spec_from_file_location(
        "legacy_archive", REPOSITORY / "tests" / "fixtures" / "v3" / "archive.py"
    )
    assert spec is not None and spec.loader is not None
    archive = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(archive)
    fixture = archive.load(REPOSITORY / "tests" / "fixtures" / "v3" / f"{name}.json")
    archive.unpack(fixture, paths.legacy_v3_dir())
    return fixture


# ---------------------------------------------------------------------------
# No command, status, init
# ---------------------------------------------------------------------------


def test_with_no_command_and_no_vault_it_says_how_to_start(cli: Run) -> None:
    result = ok(cli())
    shown = result.stdout.splitlines()
    assert len(shown) == 3
    assert "no vault in bunker alpha" in shown[0]
    assert "irondome init" in result.stdout
    assert "migrate" not in result.stdout
    assert not paths.root().exists(), "looking must not create anything"


def test_with_no_command_a_3x_vault_is_pointed_at_migrate(cli: Run) -> None:
    legacy_fixture()
    result = ok(cli())
    assert len(result.stdout.splitlines()) == 4
    assert "irondome migrate" in result.stdout
    assert str(paths.legacy_v3_dir()) in result.stdout


def test_with_no_command_and_a_vault_it_prints_the_status_and_a_hint(cli: Run, vault: str) -> None:
    result = ok(cli())
    assert "bunker" in result.stdout and "alpha" in result.stdout
    assert "keyslot" in result.stdout
    assert "irondome ls" in result.stdout.splitlines()[-1]
    assert as_json(cli("--json")) == status(cli)


def test_status_without_a_vault_says_so_and_succeeds(cli: Run) -> None:
    result = ok(cli("status"))
    assert "none yet" in result.stdout
    document = status(cli)
    assert document["exists"] is False
    assert document["bunker"] == "alpha"
    assert document["keyslots"] == [] and document["device"] == [] and document["chip"] is None
    assert document["sessions"] == 0 and document["grants"] == 0 and document["snapshots"] == 0
    assert document["legacy_v3"] is None


def test_init_creates_a_password_vault_and_reports_its_device_key(cli: Run) -> None:
    created = init(cli)
    assert set(created) == {"created", "bunker", "path", "mode", "device", "recovery_key"}
    assert created["created"] is True and created["bunker"] == "alpha" and created["mode"] == "password"
    assert created["device"] == {
        "backend": "software", "hardware": False,
        "why_no_chip": "IRONDOME_DEVICE_BACKEND is set to software, so no security chip was looked for",
    }
    assert RECOVERY_KEY.fullmatch(created["recovery_key"])
    assert Path(created["path"]) == paths.vault_file() and paths.vault_file().is_file()

    document = status(cli)
    assert document["exists"] is True and document["error"] is None
    assert document["format"] == "irondome-vault" and document["version"] == 4 and document["generation"] == 1
    assert document["mode"] == "password"
    assert document["device"] == [{"backend": "software", "hardware": False}] and document["hardware"] is False
    assert document["chip"]["why"].startswith("IRONDOME_DEVICE_BACKEND is set to software")
    assert document["chip"]["fix"].startswith("unset IRONDOME_DEVICE_BACKEND first; ")
    kinds = {slot["kind"]: slot for slot in document["keyslots"]}
    assert set(kinds) == {"password", "recovery"}
    assert kinds["password"]["device_present"] is True and kinds["password"]["describe"].startswith("master password")
    assert kinds["recovery"]["device_present"] is None
    human = ok(cli("status")).stdout
    assert "not hardware" in human and "device key present" in human
    assert f"a file in {paths.device_dir()}" in human
    assert "no chip     IRONDOME_DEVICE_BACKEND is set to software" in human


def test_with_no_chip_init_and_status_say_why_and_what_would_put_the_key_on_one(
    cli: Run, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where no chip can hold the device key, init and status say why, and what to install, never just "file"."""
    from irondome import device as devices
    from irondome.device.base import POLICY_DEVICE

    # Left to choose for itself, with a Secure Enclave helper that is not there (so nothing is compiled).
    env = {"IRONDOME_DEVICE_BACKEND": "auto", "IRONDOME_SE_HELPER": str(tmp_path / "no-such-helper")}
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    devices._instances.clear()
    choice = devices.choose(POLICY_DEVICE, passive=True)
    if choice.backend.name != "software":
        pytest.skip(f"a chip backend can hold the device key here: {choice.backend.name}")
    devices._instances.clear()
    created = ok(cli("init", "--password-stdin", stdin=lines(PASSWORD), env=env))
    assert f"no security chip holds this vault's device key: {choice.why_no_chip}" in created.stderr
    assert f"The device key is a file in {paths.device_dir()}" in created.stderr
    assert f"A chip needs {devices.chip_requirements()}" in created.stderr
    document = status(cli, env=env)
    assert document["chip"] == {"why": choice.why_no_chip, "fix": f"a chip needs {devices.chip_requirements()}; "
                                "then irondome rekey moves the vault onto it (and shows a new recovery key)"}
    human = ok(cli("status", env=env)).stdout
    assert f"no chip     {choice.why_no_chip}" in human and "fix         a chip needs" in human


def test_init_shows_the_recovery_key_once_with_its_trade_off(cli: Run) -> None:
    result = ok(cli("init", "--password-stdin", stdin=lines(PASSWORD)))
    key = result.stdout
    assert RECOVERY_KEY.fullmatch(key), show(result)
    assert key not in result.stderr
    assert "shown this once" in result.stderr
    assert "without this device" in result.stderr and "offline" in result.stderr
    assert "bunker alpha" in result.stderr
    assert "software, not hardware" in result.stderr
    assert not leaked(result, PASSWORD)
    with pytest.raises(AuthError):
        unlock.unlock(VaultFile.load(), recovery_key="AAAA-" * 7 + "AAAA")
    unlock.unlock(VaultFile.load(), recovery_key=key.lower()).wipe()


def test_init_refuses_a_second_vault_and_changes_nothing(cli: Run) -> None:
    init(cli)
    before = paths.vault_file().read_bytes()
    fails(cli("init", "--password-stdin", stdin=lines(PASSWORD2)), 6, "already has a vault", "bunker alpha")
    assert paths.vault_file().read_bytes() == before


def test_init_without_a_recovery_key_warns(cli: Run) -> None:
    result = ok(cli("init", "--no-recovery", "--password-stdin", stdin=lines(PASSWORD)))
    assert result.stdout == ""
    assert "no recovery key" in result.stderr
    assert [slot["kind"] for slot in status(cli)["keyslots"]] == ["password"]


def test_init_takes_the_argon2_memory_it_is_given(cli: Run) -> None:
    init(cli, "--kdf-memory-mib", "24")
    slot = next(slot for slot in VaultFile.load().slots if slot.kind == "password")
    assert slot.kdf is not None and slot.kdf["m"] == 24 * 1024


@pytest.mark.parametrize(
    "arguments, fragment",
    [
        (["--kdf-memory-mib", "4"], "--kdf-memory-mib"),
        (["--kdf-memory-mib", "lots"], "invalid int value"),
        (["--no-password"], "--no-password goes with --mode touchid"),
        (["--mode", "touchid", "--no-password", "--no-recovery"], "second way in"),
        (["--mode", "fingers"], "invalid choice"),
    ],
)
def test_init_refuses_bad_options_before_asking_anything(cli: Run, arguments: List[str], fragment: str) -> None:
    fails(cli("init", "--password-stdin", *arguments, stdin=lines(PASSWORD)), 2, fragment)
    assert not paths.vault_file().exists()


def test_init_refuses_a_short_or_missing_password(cli: Run) -> None:
    fails(cli("init", "--password-stdin", stdin=lines("short")), 2, "at least 8")
    fails(cli("init", "--password-stdin"), 2)
    assert not paths.vault_file().exists()


def test_touch_id_needs_a_backend_that_can_enforce_it(cli: Run) -> None:
    fails(cli("init", "--mode", "touchid", "--password-stdin", stdin=lines(PASSWORD)), 7, "Touch ID")
    assert not paths.vault_file().exists()


def test_init_is_for_the_owner_only(cli: Run) -> None:
    fails(cli("init"), 5, "for the vault's owner", "--password-stdin")
    assert not paths.vault_file().exists()


def test_init_points_at_migrate_when_a_3x_vault_is_here(cli: Run) -> None:
    legacy_fixture()
    result = ok(cli("init", "--password-stdin", stdin=lines(PASSWORD)))
    assert "irondome migrate" in result.stderr
    assert status(cli)["legacy_v3"] == {"path": str(paths.legacy_v3_dir()), "error": None}


# ---------------------------------------------------------------------------
# Touch ID modes, with the stand-in sensor
# ---------------------------------------------------------------------------


def _slots(cli: Run, env: Dict[str, str]) -> List[Any]:
    return sorted((slot["kind"], slot["backend"], slot["policy"]) for slot in status(cli, env=env)["keyslots"])


def test_init_touchid_mode_opens_with_touch_or_the_fallback_password(cli: Run, touch: Touch) -> None:
    created = init(cli, "--mode", "touchid", env=touch.env)
    assert created["mode"] == "touchid" and created["device"] == {"backend": "fake-touch", "hardware": True}
    assert _slots(cli, touch.env) == [
        ("device", "fake-touch", "biometry"),
        ("password", "fake-touch", "device"),
        ("recovery", None, None),
    ]
    assert status(cli, env=touch.env)["mode"] == "touchid"
    ok(owner(cli, "add", "github", "--value-stdin", more=["gh-value-1"], env=touch.env))
    assert get(cli, "github", env=touch.env) == "gh-value-1"  # the fallback password, no prompt
    enrolled = len(touch.prompts())
    fails(cli("--touch", "get", "github", env=touch.env), 5, "not available to agents")
    asked = {"operation": "unseal", "reason": "read github from bunker alpha for an agent"}
    assert touch.prompts()[enrolled:] == [asked]


def test_init_touchid_password_mode_needs_both(cli: Run, touch: Touch) -> None:
    init(cli, "--mode", "touchid+password", env=touch.env)
    assert _slots(cli, touch.env) == [("password", "fake-touch", "biometry"), ("recovery", None, None)]
    fails(owner(cli, "ls", env=touch.env), 4, "fingerprint")
    ok(owner(cli, "--touch", "add", "github", "--value-stdin", more=["gh-value-1"], env=touch.env))
    assert get(cli, "github", "--touch", env=touch.env) == "gh-value-1"
    fails(owner(cli, "--touch", "get", "github", env=touch.refusing()), 4, "cancelled")
    fails(owner(cli, "--touch", "get", "github", password=PASSWORD2, env=touch.env), 4, "wrong master password")


def test_init_touchid_without_a_password_keeps_the_recovery_key(cli: Run, touch: Touch) -> None:
    # No password to pipe; --password-stdin says that the owner, not an agent, is asking.
    created = as_json(cli("--json", "init", "--mode", "touchid", "--no-password", "--password-stdin", env=touch.env))
    assert created["recovery_key"] and created["mode"] == "touchid"
    assert _slots(cli, touch.env) == [("device", "fake-touch", "biometry"), ("recovery", None, None)]
    assert status(cli, env=touch.env)["mode"] == "touchid-only"
    fails(owner(cli, "passwd", env=touch.env), 2, "no master password", "irondome auth password")
    # A password was given, so Touch ID was not tried: the refusal says so, and suggests no session or token
    # (`irondome unlock`, which makes a session, refuses one itself).
    for command in (["ls"], ["unlock", "--print-token"]):
        refused = fails(owner(cli, *command, env=touch.env), 4, "opens with Touch ID only: it has no master password",
                        "Leave the password out")
        assert "session" not in refused.stderr and "token" not in refused.stderr


def test_init_touchid_without_a_password_is_for_the_owner(cli: Run, touch: Touch) -> None:
    fails(cli("init", "--mode", "touchid", "--no-password", env=touch.env), 5, "owner")


def test_auth_touchid_adds_touch_and_agents_get_only_what_entries_allow(cli: Run, touch: Touch) -> None:
    init(cli, env=touch.env)
    ok(owner(cli, "add", "github", "--value-stdin", "--totp-stdin", more=["gh-value-1", TOTP_SECRET], env=touch.env))
    # --touch from an agent, and no keyslot opens with Touch ID alone: it is told what would work instead.
    fails(cli("--touch", "get", "github", env=touch.env), 4, "no keyslot that opens with Touch ID alone",
          "irondome grant create", "irondome approve needs such a keyslot")

    enrolled = as_json(owner(cli, "--json", "auth", "touchid", env=touch.env))
    assert enrolled == {"bunker": "alpha", "mode": "touchid", "backend": "fake-touch", "replaced": 0}
    first = {path.name for path in device_files()}
    again = as_json(owner(cli, "--json", "auth", "touchid", env=touch.env))
    assert again["replaced"] == 1
    assert len([slot for slot in VaultFile.load().slots if slot.kind == "device"]) == 1
    assert len(first - {path.name for path in device_files()}) == 1, "the replaced Touch ID key was not destroyed"

    fails(cli("--touch", "get", "github", env=touch.env), 5, "not available to agents", "--agent use")
    ok(owner(cli, "edit", "github", "--agent", "use", env=touch.env))
    fails(cli("--touch", "get", "github", env=touch.env), 5, "not shown to them")
    code = ok(cli("--touch", "otp", "github", env=touch.env)).stdout
    assert re.fullmatch(r"\d{6}", code)
    listed = as_json(cli("--json", "--touch", "ls", env=touch.env))
    assert [row["name"] for row in listed] == ["github"]
    ok(owner(cli, "edit", "github", "--agent", "reveal", env=touch.env))
    assert ok(cli("--touch", "get", "github", env=touch.env)).stdout == "gh-value-1"
    fails(cli("--touch", "get", "github", env=touch.refusing()), 4, "cancelled")
    fails(cli("--touch", "show", "github", env=touch.env), 5, "owner")
    fails(cli("--touch", "add", "other", "--generate", env=touch.env), 5, "owner")


def test_auth_touchid_with_require_password_needs_both_every_time(cli: Run, touch: Touch) -> None:
    init(cli, "--mode", "touchid", env=touch.env)
    ok(owner(cli, "add", "github", "--value-stdin", more=["gh-value-1"], env=touch.env))
    before = {path.name for path in device_files()}
    result = as_json(owner(cli, "--json", "auth", "touchid", "--require-password", env=touch.env))
    assert result["mode"] == "touchid+password" and result["replaced"] == 2
    assert _slots(cli, touch.env) == [("password", "fake-touch", "biometry"), ("recovery", None, None)]
    assert not before & {path.name for path in device_files()}, "old device keys survived"
    fails(owner(cli, "get", "github", env=touch.env), 4, "fingerprint")
    assert get(cli, "github", "--touch", env=touch.env) == "gh-value-1"
    fails(cli("--touch", "get", "github", env=touch.env), 4)


def test_auth_password_goes_back_to_the_password_and_destroys_touch_keys(cli: Run, touch: Touch) -> None:
    init(cli, "--mode", "touchid+password", env=touch.env)
    ok(owner(cli, "--touch", "add", "github", "--value-stdin", more=["gh-value-1"], env=touch.env))
    before = {path.name for path in device_files()}
    result = as_json(owner(cli, "--json", "--touch", "auth", "password", env=touch.env))
    assert result == {"bunker": "alpha", "mode": "password", "changed": True, "replaced": 1}
    assert _slots(cli, touch.env) == [("password", "fake-touch", "device"), ("recovery", None, None)]
    assert not before & {path.name for path in device_files()}
    assert get(cli, "github", env=touch.env) == "gh-value-1"
    again = as_json(owner(cli, "--json", "auth", "password", env=touch.env))
    assert again["changed"] is False


def test_auth_password_from_touchid_mode_only_drops_the_touch_slot(cli: Run, touch: Touch) -> None:
    init(cli, "--mode", "touchid", env=touch.env)
    password_slot = next(slot.id for slot in VaultFile.load().slots if slot.kind == "password")
    result = as_json(owner(cli, "--json", "auth", "password", env=touch.env))
    assert result["replaced"] == 1
    assert [slot.id for slot in VaultFile.load().slots if slot.kind == "password"] == [password_slot]
    assert not [slot for slot in VaultFile.load().slots if slot.kind == "device"]


def test_auth_touchid_needs_a_sensor(cli: Run, vault: str) -> None:
    fails(owner(cli, "auth", "touchid"), 7, "Touch ID")
    fails(owner(cli, "--no-touch", "auth", "touchid"), 2, "--no-touch")
    fails(cli("auth", "touchid"), 5, "owner")


def test_auth_show_lists_the_keyslots_without_unlocking(cli: Run, vault: str) -> None:
    document = as_json(cli("--json", "auth", "show"))
    assert set(document) == {"bunker", "mode", "keyslots"}
    assert document["mode"] == "password"
    assert {slot["kind"] for slot in document["keyslots"]} == {"password", "recovery"}
    human = ok(cli("auth", "show"))
    assert "master password + device key" in human.stdout + human.stderr
    assert "present" in human.stdout


def test_passwd_keeps_the_touch_policy_of_the_password_slot(cli: Run, touch: Touch) -> None:
    init(cli, "--mode", "touchid+password", env=touch.env)
    ok(owner(cli, "--touch", "passwd", more=[PASSWORD2], env=touch.env))
    assert _slots(cli, touch.env) == [("password", "fake-touch", "biometry"), ("recovery", None, None)]
    fails(owner(cli, "--touch", "ls", env=touch.env), 4, "wrong master password")
    ok(owner(cli, "--touch", "ls", password=PASSWORD2, env=touch.env))


# ---------------------------------------------------------------------------
# add, get, show, ls, find, edit, rm
# ---------------------------------------------------------------------------


def test_add_takes_the_value_from_each_source(cli: Run) -> None:
    init(cli)
    generated = ok(owner(cli, "add", "one", "--generate"))
    assert generated.stdout == ""
    value = get(cli, "one")
    assert len(value) == 20 and not leaked(generated, value, PASSWORD)
    assert "20-character password" in generated.stderr

    ok(owner(cli, "add", "two", "--generate", "--length", "32", "--no-symbols", "--no-ambiguous"))
    value = get(cli, "two")
    assert len(value) == 32 and value.isalnum() and not set(value) & set("0Oo1lI")

    shown = ok(owner(cli, "add", "three", "--words", "5", "--show"))
    assert shown.stdout == get(cli, "three") and len(shown.stdout.split("-")) == 5

    ok(owner(cli, "add", "four", "--value-stdin", more=["typed value with spaces  "]))
    assert get(cli, "four") == "typed value with spaces  "

    fails(owner(cli, "add", "five"), 2, "no terminal", "--value-stdin")
    fails(owner(cli, "add", "five", "--value-stdin"), 2, "expected the value")
    fails(owner(cli, "add", "five", "--value-stdin", "--totp", more=["v"]), 2, "--totp-stdin")
    assert [row["name"] for row in as_json(owner(cli, "--json", "ls"))] == ["four", "one", "three", "two"]


def test_add_reports_json_and_records_everything_given(cli: Run) -> None:
    init(cli)
    added = as_json(owner(
        cli, "--json", "add", "stripe", "--kind", "secret", "--username", "ops", "--url", "https://stripe.com",
        "--tag", "pay", "--tag", "prod", "--note", "rotate yearly", "--agent", "use", "--alias", "STRIPE_KEY",
        "--field", "account", "--value-stdin", "--totp-stdin",
        more=["sk_live_value", "otpauth://totp/Stripe:ops?secret=JBSWY3DPEHPK3PXP&issuer=Stripe", "acct_1"],
    ))
    assert set(added) == {"name", "id", "generated", "alias"}
    assert added["name"] == "stripe" and added["generated"] is False and added["alias"] == "STRIPE_KEY"
    assert re.fullmatch(r"[0-9a-f]{32}", added["id"])

    entry = as_json(owner(cli, "--json", "show", "stripe"))
    assert entry["id"] == added["id"] and entry["kind"] == "secret" and entry["agent"] == "use"
    assert entry["username"] == "ops" and entry["url"] == "https://stripe.com" and entry["tags"] == ["pay", "prod"]
    assert entry["aliases"] == [{"name": "STRIPE_KEY", "field": "password"}]
    assert entry["has_totp"] is True and entry["totp"]["issuer"] == "Stripe" and entry["otpauth"] is None
    assert entry["fields"] == ["account"] and entry["has_notes"] is True and entry["notes"] is None
    assert entry["password"] is None and entry["has_password"] is True and entry["history"] == 0
    assert get(cli, "STRIPE_KEY") == "sk_live_value"

    revealed = as_json(owner(cli, "--json", "show", "stripe", "--reveal"))
    assert revealed["password"] == "sk_live_value" and revealed["notes"] == "rotate yearly"
    assert revealed["fields"] == {"account": "acct_1"}
    assert "secret=JBSWY3DPEHPK3PXP" in revealed["otpauth"]


def test_add_with_a_generated_value_can_show_or_copy_it_and_nothing_else(cli: Run, clipboard: Clipboard) -> None:
    init(cli)
    ok(owner(cli, "config", "set", "clipboard_clear_seconds", "5"))
    shown = as_json(owner(cli, "--json", "add", "one", "--generate", "--show"))
    assert set(shown) == {"name", "id", "generated", "alias", "value"} and shown["generated"] is True
    assert shown["value"] == get(cli, "one")
    copied = ok(owner(cli, "add", "two", "--generate", "--copy", env=clipboard.env))
    value = get(cli, "two")
    assert copied.stdout == "" and not leaked(copied, value)
    assert clipboard.text() == value


@pytest.mark.parametrize(
    "arguments, more, fragment",
    [
        (["github", "--generate"], [], "already has an entry named 'github'"),
        (["new", "--generate", "--alias", "GITHUB_TOKEN"], [], "the alias GITHUB_TOKEN is taken"),
        (["new", "--generate", "--alias", "9lives"], [], "an alias must start"),
        (["new ", "--generate"], [], "whitespace"),
        (["new", "--generate", "--field", "region=eu-1"], [], "--field takes only the field's name"),
        (["new", "--generate", "--field", "region"], [], "expected the value of the field region"),
        (["new", "--generate", "--field", "url"], [], "built-in field"),
        (["new", "--generate", "--field", "a", "--field", "a"], ["1", "2"], "given twice"),
        (["new", "--generate", "--field", "bad key"], ["1"], "custom field name"),
        (["new", "--generate", "--note", "n", "--note-stdin"], ["n"], "choose --note or --note-stdin"),
        (["new", "--value-stdin", "--show"], ["v"], "--show and --copy"),
        (["new", "--generate", "--words", "4"], [], "one source"),
        (["new", "--length", "30", "--value-stdin"], ["v"], "--length applies only to --generate"),
        (["new", "--no-digits", "--no-upper", "--words", "4"], [], "--no-digits, --no-upper apply only to --generate"),
        (["new", "--generate", "--length", "7"], [], "from 8 to 512"),
        (["new", "--words", "2"], [], "from 3 to 24"),
        (["new", "--value-stdin", "--totp-stdin"], ["v", "not base32!"], "base32"),
        (["new", "--value-stdin", "--totp-stdin"], ["v", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"], "hotp"),
        (["new", "--value-stdin", "--totp", "--totp-stdin"], ["v"], "choose one of"),
        (["new", "--generate", "--kind", "card"], [], "invalid choice"),
    ],
)
def test_add_refuses_bad_input(cli: Run, vault: str, arguments: List[str], more: List[str], fragment: str) -> None:
    generation = VaultFile.load().generation
    fails(owner(cli, "add", *arguments, more=more), 2, fragment)
    assert VaultFile.load().generation == generation


def test_get_prints_exactly_the_value(cli: Run, vault: str) -> None:
    assert get(cli, "github") == "gh-value-1"
    assert get(cli, "GITHUB_TOKEN") == "gh-value-1"
    assert get(cli, "irondome://GITHUB_TOKEN") == "gh-value-1"
    assert get(cli, "github", "--field", "username") == "king"
    assert get(cli, "aws/prod/region") == "eu-west-1"
    assert get(cli, "irondome://aws%2Fprod/notes") == "the production account"
    document = as_json(owner(cli, "--json", "get", "GITHUB_TOKEN"))
    assert document == {"reference": "GITHUB_TOKEN", "field": "password", "value": "gh-value-1"}
    assert as_json(owner(cli, "--json", "get", "aws/prod", "--field", "region"))["field"] == "region"


def test_get_fails_cleanly(cli: Run, vault: str) -> None:
    assert "bunker" not in fails(owner(cli, "get", "github", password=PASSWORD2), 4).stderr, "one bunker: no prefix"
    fails(owner(cli, "get", "gitlab"), 3, "no entry or alias named 'gitlab'")
    fails(owner(cli, "get", "github", "--field", "pin"), 3, "no field named 'pin'")
    fails(owner(cli, "get", "github", "--field", "bad field"), 2, "field name")
    fails(owner(cli, "get", "github/totp"), 3, "no one-time-password secret")
    wrong = fails(owner(cli, "get", "github", password=PASSWORD2), 4, "wrong master password")
    assert not leaked(wrong, PASSWORD2, "gh-value-1")
    fails(owner(cli, "get", "github", password=""), 2)


def test_without_a_vault_every_command_names_the_bunker(cli: Run) -> None:
    fails(owner(cli, "get", "github"), 6, "no vault in bunker alpha", "irondome init")
    fails(owner(cli, "--bunker", "bravo", "ls"), 6, "no vault in bunker bravo", "irondome bunker create bravo")
    fails(owner(cli, "passwd"), 6, "bunker alpha")


def test_an_agent_with_no_grant_is_told_about_grants(cli: Run, vault: str) -> None:
    for arguments in (["get", "github"], ["otp", "github"], ["ls"], ["find", "git"]):
        result = fails(cli(*arguments), 4, "IRONDOME_GRANT", "irondome grant create")
        assert not leaked(result, "gh-value-1")


@pytest.mark.parametrize(
    "arguments",
    [
        ["add", "x", "--generate"],
        ["edit", "github", "--username", "x"],
        ["rm", "github", "--yes"],
        ["show", "github"],
        ["passwd"],
        ["recovery", "new"],
        ["recovery", "remove", "--yes"],
        ["auth", "touchid"],
        ["auth", "password"],
        ["config", "set", "snapshots", "3"],
        ["config", "reset"],
        ["bunker", "create", "bravo"],
        ["bunker", "use", "alpha"],
        ["bunker", "rm", "alpha", "--yes"],
    ],
    ids=lambda arguments: "-".join(arguments[:2]),
)
def test_an_agent_cannot_change_the_vault_or_read_it_as_the_owner(cli: Run, vault: str, arguments: List[str]) -> None:
    before = paths.vault_file().read_bytes()
    fails(cli(*arguments), 5, "for the vault's owner", "--password-stdin")
    assert paths.vault_file().read_bytes() == before


def test_show_hides_values_unless_asked(cli: Run, vault: str) -> None:
    result = ok(owner(cli, "show", "aws/prod"))
    assert not leaked(result, "AKIA-prod-value", "eu-west-1", "the production account")
    assert "region" in result.stdout and "--reveal" in result.stdout and "bunker" in result.stdout
    revealed = ok(owner(cli, "show", "aws/prod", "--reveal"))
    assert "AKIA-prod-value" in revealed.stdout and "eu-west-1" in revealed.stdout
    assert "the production account" in revealed.stdout
    aliases = ok(owner(cli, "show", "github")).stdout
    assert "GITHUB_TOKEN (password)" in aliases
    fails(owner(cli, "show", "nothing"), 3, "no entry named 'nothing'")


def test_ls_and_find_list_entries_and_never_values(cli: Run, vault: str) -> None:
    table = ok(owner(cli, "ls"))
    header = table.stdout.splitlines()[0].split()
    assert header == ["NAME", "USERNAME", "URL", "TAGS", "OTP", "AGENT", "MODIFIED"]
    assert not leaked(table, "gh-value-1", "AKIA-prod-value")
    rows = as_json(owner(cli, "--json", "ls"))["entries"]
    assert [row["name"] for row in rows] == ["aws/prod", "github"]
    assert set(rows[1]) == {"name", "id", "kind", "username", "url", "tags", "has_totp", "agent", "aliases",
                            "created", "modified"}
    assert rows[1]["aliases"] == ["GITHUB_TOKEN"] and rows[1]["has_totp"] is False and rows[1]["agent"] == "deny"
    assert [row["name"] for row in as_json(owner(cli, "--json", "ls", "--tag", "DEV"))["entries"]] == ["github"]
    assert [row["name"] for row in as_json(owner(cli, "--json", "find", "token"))["entries"]] == ["github"]
    assert [row["name"] for row in as_json(owner(cli, "--json", "find", "AWS"))["entries"]] == ["aws/prod"]
    assert as_json(owner(cli, "--json", "find", "nothing-like-this")) == {"bunker": "alpha", "entries": []}
    empty = ok(owner(cli, "find", "nothing-like-this"))
    assert empty.stdout == "" and "bunker alpha" in empty.stderr
    fails(owner(cli, "find", " "), 2)


def test_edit_changes_what_it_is_told_and_keeps_the_rest(cli: Run, vault: str) -> None:
    changed = as_json(owner(
        cli, "--json", "edit", "github", "--name", "GitHub", "--username", "queen", "--add-tag", "work",
        "--rm-tag", "dev", "--kind", "secret", "--agent", "use", "--field", "org", more=["acme"],
    ))
    assert set(changed) == {"name", "id", "changed", "generated"}
    assert changed["name"] == "GitHub" and changed["generated"] is False
    assert set(changed["changed"]) == {"name", "username", "kind", "agent", "tags", "fields"}
    entry = as_json(owner(cli, "--json", "show", "GitHub", "--reveal"))
    assert entry["username"] == "queen" and entry["tags"] == ["work"] and entry["kind"] == "secret"
    assert entry["url"] == "https://github.com" and entry["password"] == "gh-value-1"
    assert entry["fields"] == {"org": "acme"} and entry["aliases"] == [{"name": "GITHUB_TOKEN", "field": "password"}]

    ok(owner(cli, "edit", "GitHub", "--value-stdin", "--totp-stdin", "--note", "", "--rm-field", "org",
             more=["gh-value-2", TOTP_SECRET]))
    entry = as_json(owner(cli, "--json", "show", "GitHub", "--reveal"))
    assert entry["password"] == "gh-value-2" and entry["history"] == 1 and entry["has_totp"] is True
    assert entry["fields"] == {} and entry["notes"] == ""
    regenerated = ok(owner(cli, "edit", "GitHub", "--generate", "--tag", "a", "--tag", "b", "--no-totp"))
    new_value = get(cli, "GITHUB_TOKEN")
    assert new_value != "gh-value-2" and not leaked(regenerated, new_value)
    entry = as_json(owner(cli, "--json", "show", "GitHub"))
    assert entry["history"] == 2 and entry["has_totp"] is False and entry["tags"] == ["a", "b"]
    ok(owner(cli, "edit", "GitHub", "--tag", ""))
    assert as_json(owner(cli, "--json", "show", "GitHub"))["tags"] == []


def test_edit_refuses_what_it_cannot_do(cli: Run, vault: str) -> None:
    fails(owner(cli, "edit", "github"), 2, "nothing to change")
    fails(owner(cli, "edit", "gitlab", "--username", "x"), 3, "no entry named 'gitlab'")
    fails(owner(cli, "edit", "github", "--rm-field", "pin"), 3, "no field named 'pin'")
    fails(owner(cli, "edit", "github", "--name", "aws/prod"), 2, "already exists")
    fails(owner(cli, "edit", "github", "--field", "a", "--rm-field", "a"), 2, "both name a")
    fails(owner(cli, "edit", "github", "--field", "a=1"), 2, "--field takes only the field's name")
    fails(owner(cli, "edit", "github", "--show"), 2, "--show and --copy")
    fails(owner(cli, "edit", "github", "--prompt-value"), 2, "no terminal")
    assert get(cli, "github") == "gh-value-1"


def test_rm_asks_first_then_removes_the_entry_and_its_aliases(cli: Run, vault: str) -> None:
    fails(owner(cli, "rm", "github"), 2, "--yes")
    assert get(cli, "github") == "gh-value-1"
    removed = as_json(owner(cli, "--json", "rm", "github", "--yes"))
    assert removed["removed"] == "github" and removed["aliases"] == ["GITHUB_TOKEN"]
    fails(owner(cli, "get", "github"), 3)
    fails(owner(cli, "get", "GITHUB_TOKEN"), 3)
    fails(owner(cli, "rm", "github", "--yes"), 3)
    human = ok(owner(cli, "rm", "aws/prod", "-y"))
    assert "removed aws/prod from bunker alpha" in human.stderr


def test_changes_are_kept_as_snapshots(cli: Run, vault: str) -> None:
    assert status(cli)["snapshots"] == len(snapshot_files()) == 2
    ok(owner(cli, "config", "set", "snapshots", "1"))
    ok(owner(cli, "add", "third", "--generate"))
    assert len(snapshot_files()) == 1


def test_a_session_opens_the_vault_and_the_password_line_is_still_skipped(cli: Run, vault: str) -> None:
    with open_vault() as opened:
        token = caps.create_session(opened, ttl=300)
    env = {"IRONDOME_SESSION": token}
    ok(cli("--password-stdin", "add", "via-session", "--value-stdin", stdin=lines("not the password", "v1"), env=env))
    assert get(cli, "via-session") == "v1"
    fails(owner(cli, "passwd", password="not the password", more=[PASSWORD2], env=env), 4, "wrong master password")


# ---------------------------------------------------------------------------
# gen, otp
# ---------------------------------------------------------------------------


def test_gen_needs_no_vault_and_prints_only_the_value(cli: Run) -> None:
    result = ok(cli("gen"))
    assert len(result.stdout) == 20 and "\n" not in result.stdout
    assert "bits of entropy" in result.stderr and result.stdout not in result.stderr
    lower = ok(cli("gen", "--length", "40", "--no-symbols", "--no-digits", "--no-upper")).stdout
    assert len(lower) == 40 and lower.isalpha() and lower.islower()
    assert len(ok(cli("gen", "--words", "4")).stdout.split("-")) == 4
    name = ok(cli("gen", "--username", "--length", "12"))
    assert re.fullmatch(r"[a-z][a-z0-9]{11}", name.stdout) and name.stderr == ""
    assert re.fullmatch(r"me\+[a-z0-9]{8}@example\.com", ok(cli("gen", "--email-alias", "me@example.com")).stdout)
    document = as_json(cli("--json", "gen", "--words", "6"))
    assert set(document) == {"kind", "value", "entropy_bits", "clipboard"}
    assert document["kind"] == "passphrase" and document["entropy_bits"] == 77.5 and document["clipboard"] is None
    assert not paths.root().exists()


@pytest.mark.parametrize(
    "arguments, fragment",
    [
        (["--words", "4", "--username"], "choose one of"),
        (["--words", "4", "--no-symbols"], "--no-symbols applies only to passwords"),
        (["--words", "4", "--length", "9"], "--length applies"),
        (["--length", "7"], "from 8 to 512"),
        (["--email-alias", "not an address"], "email address"),
        (["--no-symbols", "--no-digits", "--words", "3"], "--no-symbols, --no-digits apply only to passwords"),
    ],
)
def test_gen_refuses_options_that_do_not_fit(cli: Run, arguments: List[str], fragment: str) -> None:
    fails(cli("gen", *arguments), 2, fragment)


def test_gen_follows_the_password_length_setting(cli: Run) -> None:
    init(cli)
    ok(owner(cli, "config", "set", "password_length", "33"))
    assert len(ok(cli("gen")).stdout) == 33


def _codes_between(settings: Dict[str, Any], start: float, end: float) -> set:
    return {otp.code_at(settings, moment) for moment in range(int(start), int(end) + 2)}


def test_otp_prints_the_current_code_of_a_known_secret(cli: Run, vault: str) -> None:
    ok(owner(cli, "add", "bank", "--value-stdin", "--totp-stdin", "--alias", "BANK", more=["pin-1", TOTP_SECRET]))
    settings = otp.make_totp(TOTP_SECRET)
    started = time.time()
    result = ok(owner(cli, "otp", "bank"))
    assert result.stdout in _codes_between(settings, started, time.time())
    assert re.search(r"valid for \d+ more second", result.stderr)
    started = time.time()
    document = as_json(owner(cli, "--json", "otp", "BANK"))
    assert set(document) == {"code", "seconds_remaining", "period"}
    assert document["code"] in _codes_between(settings, started, time.time())
    assert document["period"] == 30 and 1 <= document["seconds_remaining"] <= 30
    assert ok(owner(cli, "otp", "bank/totp")).stdout in _codes_between(settings, started, time.time())
    assert get(cli, "bank/totp") in _codes_between(settings, started, time.time())
    fails(owner(cli, "otp", "github"), 3, "no one-time-password secret")
    fails(owner(cli, "otp", "nothing"), 3)


def test_otp_reads_the_settings_of_an_otpauth_link(cli: Run, vault: str) -> None:
    link = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60"
    ok(owner(cli, "add", "example", "--value-stdin", "--totp-stdin", more=["pw", link]))
    settings = otp.parse_otpauth(link)
    started = time.time()
    document = as_json(owner(cli, "--json", "otp", "example"))
    assert document["period"] == 60 and len(document["code"]) == 8
    assert document["code"] in {otp.code_at(settings, moment) for moment in range(int(started), int(time.time()) + 2)}


# ---------------------------------------------------------------------------
# Grants
# ---------------------------------------------------------------------------


def test_a_grant_reads_what_it_covers_and_nothing_else(cli: Run, vault: str) -> None:
    token = make_grant(["GITHUB_TOKEN", "aws/prod/region"], mode="reveal", uses=3)
    env = {"IRONDOME_GRANT": token}
    listed = as_json(cli("--json", "ls", env=env))
    assert set(listed) == {"bunker", "grant", "references"} and listed["bunker"] == "alpha"
    assert listed["references"] == [
        {"reference": "GITHUB_TOKEN", "entry": "github", "field": "password"},
        {"reference": "aws/prod/region", "entry": "aws/prod", "field": "region"},
    ]
    assert set(listed["grant"]) == {"id", "label", "mode", "created", "expires", "uses_left"}
    assert listed["grant"]["mode"] == "reveal" and listed["grant"]["uses_left"] == 3
    human = ok(cli("ls", env=env))
    assert "3 uses left" in human.stderr and "used none" in human.stderr
    found = as_json(cli("--json", "find", "region", env=env))["references"]
    assert [row["reference"] for row in found] == ["aws/prod/region"]
    fails(cli("ls", "--tag", "dev", env=env), 2, "--tag")
    assert ok(cli("get", "GITHUB_TOKEN", env=env)).stdout == "gh-value-1"
    document = as_json(cli("--json", "get", "irondome://aws/prod/region", env=env))
    assert document == {"reference": "aws/prod/region", "field": "region", "value": "eu-west-1"}
    fails(cli("get", "github", env=env), 5, "does not cover 'github'", "GITHUB_TOKEN", "Nothing was used")
    assert ok(cli("get", "GITHUB_TOKEN", env=env)).stdout == "gh-value-1"  # the refusal spent none of the three
    fails(cli("get", "GITHUB_TOKEN", env=env), 4, "used up")
    assert ok(owner(cli, "get", "github", "--no-grant", env=env)).stdout == "gh-value-1"


def test_listing_a_grant_spends_no_use(cli: Run, vault: str) -> None:
    token = make_grant(["GITHUB_TOKEN"], mode="reveal", uses=1)
    env = {"IRONDOME_GRANT": token}
    for _ in range(3):
        ok(cli("ls", env=env))
    assert ok(cli("get", "GITHUB_TOKEN", env=env)).stdout == "gh-value-1"
    fails(cli("ls", env=env), 4, "used up")


def test_a_use_only_grant_is_never_printed(cli: Run, vault: str) -> None:
    ok(owner(cli, "edit", "github", "--totp-stdin", more=[TOTP_SECRET]))
    token = make_grant(["GITHUB_TOKEN", "github/totp"], mode="use", uses=5, ttl=600)
    env = {"IRONDOME_GRANT": token}
    result = fails(cli("get", "GITHUB_TOKEN", env=env), 5, "irondome run")
    assert not leaked(result, "gh-value-1")
    settings = otp.make_totp(TOTP_SECRET)
    started = time.time()
    code = as_json(cli("--json", "otp", "github", env=env))
    assert code["code"] in _codes_between(settings, started, time.time())
    assert code["seconds_remaining"] is None and code["period"] is None
    fails(cli("otp", "aws/prod", env=env), 5, "does not cover")


# ---------------------------------------------------------------------------
# passwd, recovery
# ---------------------------------------------------------------------------


def test_passwd_replaces_the_password_everywhere_it_mattered(cli: Run, vault: str) -> None:
    with open_vault() as opened:
        caps.create_session(opened, ttl=300)
    assert status(cli)["sessions"] == 1
    assert snapshot_files()
    old_keys = {path.name for path in device_files()}
    old_slot = next(slot.id for slot in VaultFile.load().slots if slot.kind == "password")

    purged = len(snapshot_files())  # the change itself keeps none: a copy under the old keyslots is what must go
    result = owner(cli, "--json", "passwd", more=[PASSWORD2])
    document = as_json(result)
    assert document == {
        "changed": True, "bunker": "alpha", "keyslots": 1, "snapshots_purged": purged, "sessions_ended": 1
    }
    assert not leaked(result, PASSWORD, PASSWORD2)

    fails(owner(cli, "get", "github"), 4, "wrong master password")
    assert get(cli, "github", password=PASSWORD2) == "gh-value-1"
    assert snapshot_files() == [] and status(cli)["snapshots"] == 0
    assert status(cli)["sessions"] == 0
    slots = VaultFile.load().slots
    assert [slot.kind for slot in slots].count("password") == 1
    assert old_slot not in {slot.id for slot in slots}
    survivors = old_keys & {path.name for path in device_files()}
    assert len(survivors) == 1, "the old password slot's device key must be gone; the session key may stay"


def test_passwd_refuses_a_weak_or_missing_new_password(cli: Run, vault: str) -> None:
    fails(owner(cli, "passwd", more=["short"]), 2, "at least 8")
    fails(owner(cli, "passwd"), 2)
    fails(owner(cli, "passwd", password=PASSWORD2, more=[PASSWORD]), 4)
    assert get(cli, "github") == "gh-value-1"


def test_recovery_new_retires_the_old_key(cli: Run, vault: str) -> None:
    first = vault
    unlock.unlock(VaultFile.load(), recovery_key=first).wipe()
    result = owner(cli, "--json", "recovery", "new")
    document = as_json(result)  # stdout is exactly one JSON document; the re-key summary goes to stderr
    assert "re-keyed its vault" in result.stderr and document["recovery_key"] not in result.stderr
    assert set(document) == {"bunker", "recovery_key", "replaced", "rekey"}
    second = document["recovery_key"]
    assert RECOVERY_KEY.fullmatch(second) and second != first and document["replaced"] == 1
    assert set(document["rekey"]) == {"vault_id", "entries", "keyslots", "device_keys_destroyed", "snapshots_deleted",
                                      "sessions_and_grants_ended", "audit_archive", "leftovers"}
    assert document["rekey"]["entries"] == 2 and document["rekey"]["leftovers"] == []
    with pytest.raises(AuthError):
        unlock.unlock(VaultFile.load(), recovery_key=first)
    unlock.unlock(VaultFile.load(), recovery_key=second).wipe()
    assert snapshot_files() == []
    human = ok(owner(cli, "recovery", "new"))
    third = human.stdout
    assert RECOVERY_KEY.fullmatch(third) and third not in human.stderr
    assert "re-keyed its vault" in human.stderr and "shown this once" in human.stderr
    assert "copies of the vault file made before now" in human.stderr and "irondome rekey" not in human.stderr
    with pytest.raises(AuthError):
        unlock.unlock(VaultFile.load(), recovery_key=second)


def test_recovery_remove_asks_and_then_no_recovery_key_opens_the_vault(cli: Run, vault: str) -> None:
    fails(owner(cli, "recovery", "remove"), 2, "--yes")
    unlock.unlock(VaultFile.load(), recovery_key=vault).wipe()
    document = as_json(owner(cli, "--json", "recovery", "remove", "--yes"))
    assert document["removed"] == 1
    assert [slot.kind for slot in VaultFile.load().slots] == ["password"]
    with pytest.raises(AuthError, match="no recovery key"):
        unlock.unlock(VaultFile.load(), recovery_key=vault)
    assert snapshot_files() == []
    fails(owner(cli, "recovery", "remove", "--yes"), 3, "no recovery key")
    fails(owner(cli, "recovery"), 2, "<subcommand>")
    assert RECOVERY_KEY.fullmatch(as_json(owner(cli, "--json", "recovery", "new"))["recovery_key"])


# ---------------------------------------------------------------------------
# A recovery key that is replaced or removed opens nothing new: both re-key the vault
# ---------------------------------------------------------------------------


def _what_the_old_recovery_key_opens(earlier: bytes, old_key: str, current: Path, tmp_path: Path) -> List[str]:
    """Every value the recovery keyslot of an *earlier* copy, with its key, opens in the vault file *current*.

    The attacker of the finding: the old key (a photo of the paper) and the old keyslot (about 200 bytes of any
    earlier copy: a synced folder, Time Machine, an old backup disk). They use the vault key it gives on the
    current file offline, under the file's vault id and under the copy's, and they splice the old keyslot into
    the current file and open that with the stock recovery path.
    """
    from irondome import keys
    from irondome.crypto import b64d
    from irondome.errors import VaultError
    from irondome.keys import Keyslot
    from irondome.vault import Vault

    copy = json.loads(earlier)
    slot = Keyslot.from_dict(next(item for item in copy["keyslots"] if item["kind"] == "recovery"))
    opened: List[str] = []
    for vault_id in (VaultFile.load(current).vault_id, b64d(copy["vault_id"], what="vault id")):
        try:
            key = keys.open_slot(slot, vault_id, recovery_key=old_key)
        except AuthError:
            continue
        try:
            with Vault(VaultFile.load(current), key, current) as stolen:
                opened += [stolen.value(entry) for entry in stolen.list()]
        except VaultError:
            pass
    spliced = json.loads(current.read_bytes())
    spliced["keyslots"].append(slot.to_dict())
    target = tmp_path / "spliced.irondome"
    target.write_bytes(json.dumps(spliced).encode("utf-8"))
    try:
        with unlock.open_vault(path=target, recovery_key=old_key) as stolen:
            opened += [stolen.value(entry) for entry in stolen.list()]
    except (AuthError, VaultError):
        pass
    return opened


def test_recovery_new_re_keys_so_the_old_key_opens_nothing_stored_from_now_on(
    cli: Run, vault: str, tmp_path: Path
) -> None:
    old_key = vault
    earlier = paths.vault_file().read_bytes()
    old_id = VaultFile.load().vault_id
    with open_vault() as opened:
        caps.create_session(opened, ttl=300)
    grant = make_grant(["GITHUB_TOKEN"], mode="reveal", uses=5)
    old_keys = {path.name for path in device_files()}
    assert len(old_keys) == 2  # the master password's device key and the one sessions and grants are bound to

    document = as_json(owner(cli, "--json", "recovery", "new"))
    ok(owner(cli, "add", "after", "--value-stdin", more=["NEW-SECRET-AFTER"]))

    assert _what_the_old_recovery_key_opens(earlier, old_key, paths.vault_file(), tmp_path) == []
    report = document["rekey"]
    assert VaultFile.load().vault_id != old_id and report["vault_id"] == VaultFile.load().vault_id.hex()
    assert report["leftovers"] == [] and report["entries"] == 2
    unlock.unlock(VaultFile.load(), recovery_key=document["recovery_key"]).wipe()
    assert get(cli, "after") == "NEW-SECRET-AFTER" and get(cli, "github") == "gh-value-1"
    # Whatever the old vault key opened is gone as well: sessions, grants, snapshots and the old device keys.
    assert report["sessions_and_grants_ended"] == 2 and status(cli)["sessions"] == 0
    fails(cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": grant}), 4)
    assert report["snapshots_deleted"] >= 2
    assert old_keys.isdisjoint(path.name for path in device_files())
    # What no re-key can change, and the command says so: the earlier copy opens with the old key, as it was then.
    copy = tmp_path / "earlier.irondome"
    copy.write_bytes(earlier)
    file = VaultFile.load(copy)
    from irondome.vault import Vault

    with Vault(file, unlock.unlock(file, recovery_key=old_key), copy) as then:
        assert sorted(entry.name for entry in then.list()) == ["aws/prod", "github"]


def test_recovery_remove_re_keys_so_the_old_key_opens_nothing_stored_from_now_on(
    cli: Run, vault: str, tmp_path: Path
) -> None:
    old_key = vault
    earlier = paths.vault_file().read_bytes()
    removed = owner(cli, "--json", "recovery", "remove", "--yes")
    document = as_json(removed)  # stdout is exactly one JSON document; the re-key summary goes to stderr
    assert "re-keyed its vault" in removed.stderr
    assert set(document) == {"bunker", "removed", "rekey"} and document["removed"] == 1
    assert [slot["kind"] for slot in document["rekey"]["keyslots"]] == ["password"]
    ok(owner(cli, "add", "after", "--value-stdin", more=["NEW-SECRET-AFTER"]))
    assert _what_the_old_recovery_key_opens(earlier, old_key, paths.vault_file(), tmp_path) == []
    with pytest.raises(AuthError, match="no recovery key"):
        unlock.unlock(VaultFile.load(), recovery_key=old_key)

    second = as_json(owner(cli, "--json", "recovery", "new"))["recovery_key"]  # none to replace: nothing re-keyed
    result = ok(owner(cli, "recovery", "remove", "--yes"))
    assert "re-keyed its vault" in result.stderr and "opens only on this machine" in result.stderr
    assert "copies of the vault file made before now" in result.stderr
    with pytest.raises(AuthError, match="no recovery key"):
        unlock.unlock(VaultFile.load(), recovery_key=second)


def test_recovery_new_where_there_is_none_adds_one_and_re_keys_nothing(cli: Run) -> None:
    init(cli, "--no-recovery")
    before = VaultFile.load().vault_id
    document = as_json(owner(cli, "--json", "recovery", "new"))
    assert document["replaced"] == 0 and document["rekey"] is None
    assert VaultFile.load().vault_id == before
    unlock.unlock(VaultFile.load(), recovery_key=document["recovery_key"]).wipe()
    human = ok(owner(cli, "recovery", "new"))  # now there is one to replace
    assert "re-keyed its vault" in human.stderr and VaultFile.load().vault_id != before


def test_recovery_new_re_keys_a_touch_id_vault_with_its_touch_id_keyslot(cli: Run, touch: Touch) -> None:
    init(cli, "--mode", "touchid", env=touch.env)
    before = _slots(cli, touch.env)
    old_keys = {path.name for path in device_files()}
    document = as_json(owner(cli, "--json", "recovery", "new", env=touch.env))
    assert document["rekey"]["leftovers"] == []
    assert _slots(cli, touch.env) == before  # the same kinds of keyslot, on the same backend, under the same policy
    assert old_keys.isdisjoint(path.name for path in device_files())
    assert [prompt["operation"] for prompt in touch.prompts()].count("enroll") == 2  # init, then the re-key
    ok(owner(cli, "add", "after", "--generate", env=touch.env))  # the fallback password opens the re-keyed vault
    unlock.unlock(VaultFile.load(), recovery_key=document["recovery_key"]).wipe()


# ---------------------------------------------------------------------------
# An interrupted keyslot change still retires the old keyslots
# ---------------------------------------------------------------------------


def _password_key() -> str:
    """The device key file of the master password's keyslot."""
    slot = next(slot for slot in VaultFile.load().slots if slot.kind == "password")
    assert slot.device is not None
    return f"{slot.device['ref']}.key"


def _old_password_opens(path: Path) -> bool:
    from irondome.errors import HardwareError

    with secret(PASSWORD) as password:
        try:
            unlock.open_vault(path=path, password=password, interactive=False).close()
        except (AuthError, HardwareError):
            return False
    return True


@pytest.mark.parametrize("signame", ["SIGINT", "SIGTERM", "SIGHUP"])
def test_passwd_interrupted_right_after_the_write_still_retires_the_old_password(
    cli: Run, vault: str, tmp_path: Path, signame: str
) -> None:
    with open_vault() as opened:
        caps.create_session(opened, ttl=300)
    earlier = tmp_path / "earlier.irondome"
    earlier.write_bytes(paths.vault_file().read_bytes())
    old_password_key = _password_key()
    assert snapshot_files() and _old_password_opens(earlier)

    env = _hook_env(tmp_path, {"IRONDOME_TEST_SIGNAL_AFTER_WRITE": signame})
    result = owner(cli, "passwd", more=[PASSWORD2], env=env)
    if signame == "SIGINT":  # Ctrl-C: the change is completed first, then the command reports it
        assert result.returncode == 0, show(result)
        assert "interrupted while the change was being written; it was completed first" in result.stderr
        assert "changed the master password of bunker alpha" in result.stderr
    else:  # the process is ended as it was asked, once the change is complete
        assert result.returncode == -getattr(signal, signame), show(result)

    assert snapshot_files() == [] and status(cli)["sessions"] == 0
    assert old_password_key not in {path.name for path in device_files()}
    assert not (paths.home() / "retire-keyslots.json").exists()
    assert not _old_password_opens(earlier)
    fails(owner(cli, "get", "github"), 4, "wrong master password")
    assert get(cli, "github", password=PASSWORD2) == "gh-value-1"


def test_passwd_killed_right_after_the_write_is_finished_by_the_next_command(
    cli: Run, vault: str, tmp_path: Path
) -> None:
    with open_vault() as opened:
        caps.create_session(opened, ttl=300)
    earlier = tmp_path / "earlier.irondome"
    earlier.write_bytes(paths.vault_file().read_bytes())
    old_password_key = _password_key()

    env = _hook_env(tmp_path, {"IRONDOME_TEST_SIGNAL_AFTER_WRITE": "SIGKILL"})
    killed = owner(cli, "passwd", more=[PASSWORD2], env=env)
    assert killed.returncode == -signal.SIGKILL, show(killed)
    # What comes before the write is done: no snapshot under the old keyslots, no session opened with them ...
    assert snapshot_files() == [] and status(cli)["sessions"] == 0
    # ... and what comes after it is recorded, not lost.
    record = paths.home() / "retire-keyslots.json"
    assert record.is_file() and old_password_key in {path.name for path in device_files()}
    assert _old_password_opens(earlier)

    assert get(cli, "github", password=PASSWORD2) == "gh-value-1"  # the next command that opens the vault
    assert not record.exists()
    assert old_password_key not in {path.name for path in device_files()}
    assert not _old_password_opens(earlier)
    fails(owner(cli, "get", "github"), 4, "wrong master password")


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def test_config_lists_reads_changes_and_resets_per_bunker(cli: Run, vault: str) -> None:
    document = as_json(cli("--json", "config", "ls"))
    assert set(document) == {"bunker", "settings"} and document["bunker"] == "alpha"
    listing = document["settings"]
    assert [row["key"] for row in listing] == sorted(row["key"] for row in listing)
    assert {row["key"] for row in listing} >= {"clipboard_clear_seconds", "grant_ttl", "snapshots"}
    assert set(listing[0]) == {"key", "value", "default", "minimum", "maximum", "help"}
    assert as_json(cli("--json", "config", "get", "grant_ttl")) == {"key": "grant_ttl", "value": 900, "default": 900}

    assert as_json(owner(cli, "--json", "config", "set", "grant_ttl", "600")) == {"key": "grant_ttl", "value": 600}
    assert ok(cli("config", "get", "grant_ttl")).stdout == "600\n"
    fails(owner(cli, "config", "set", "grant_ttl", "5"), 2, "between")
    fails(owner(cli, "config", "set", "grant_ttl", "soon"), 2, "whole number")
    fails(owner(cli, "config", "set", "colour", "1"), 2, "unknown setting")
    fails(owner(cli, "config", "set", "grant_ttl", "700", password=PASSWORD2), 4)
    assert ok(cli("config", "get", "grant_ttl")).stdout == "600\n"

    ok(cli("bunker", "create", "bravo", "--password-stdin", stdin=lines(PASSWORD, PASSWORD2)))
    assert ok(cli("--bunker", "bravo", "config", "get", "grant_ttl")).stdout == "900\n"
    ok(owner(cli, "--bunker", "bravo", "config", "set", "snapshots", "2", password=PASSWORD2))
    assert ok(cli("config", "get", "snapshots")).stdout == "10\n"

    reset = as_json(owner(cli, "--json", "config", "reset", "grant_ttl"))
    assert reset["reset"] == ["grant_ttl"] and reset["values"]["grant_ttl"] == 900
    ok(owner(cli, "config", "set", "session_ttl", "120"))
    ok(owner(cli, "config", "reset"))
    assert ok(cli("config", "get", "session_ttl")).stdout == "900\n"
    fails(owner(cli, "config", "reset", "colour"), 2, "unknown setting")
    fails(cli("config", "get", "colour"), 2, "unknown setting")


def test_config_changes_need_a_vault(cli: Run) -> None:
    fails(owner(cli, "config", "set", "snapshots", "3"), 6, "no vault in bunker alpha")
    assert as_json(cli("--json", "config", "get", "snapshots"))["value"] == 10
    assert "no vault yet" in ok(cli("config", "ls")).stderr


# ---------------------------------------------------------------------------
# Bunkers
# ---------------------------------------------------------------------------


@pytest.fixture
def two_bunkers(cli: Run, vault: str) -> None:
    # alpha has a vault, so only its owner may add a bunker: alpha's password first, then bravo's new one.
    created = as_json(cli("--json", "bunker", "create", "bravo", "--password-stdin", stdin=lines(PASSWORD, PASSWORD2)))
    assert created["bunker"] == "bravo" and created["mode"] == "password"
    assert Path(created["path"]) == paths.root() / "bunkers" / "bravo" / "vault.irondome"
    ok(owner(cli, "--bunker", "bravo", "add", "SHARED", "--value-stdin", more=["bravo-value"], password=PASSWORD2))


def test_bunkers_are_independent(cli: Run, two_bunkers: None) -> None:
    assert ok(owner(cli, "--bunker", "bravo", "get", "SHARED", password=PASSWORD2)).stdout == "bravo-value"
    assert ok(owner(cli, "get", "SHARED", password=PASSWORD2, env={"IRONDOME_BUNKER": "bravo"})).stdout == "bravo-value"
    fails(owner(cli, "--bunker", "bravo", "get", "SHARED"), 4, "bunker bravo: wrong master password")
    fails(owner(cli, "get", "SHARED"), 3)
    fails(owner(cli, "get", "github", password=PASSWORD2), 4)
    fails(owner(cli, "--bunker", "bravo", "get", "github", password=PASSWORD2), 3)
    assert status(cli, "--bunker", "bravo")["bunker"] == "bravo"
    assert "bravo" in ok(cli("--bunker", "bravo", "status")).stdout
    assert status(cli)["bunker"] == "alpha"
    fails(owner(cli, "bunker", "create", "bravo", password=PASSWORD2), 6, "bunker bravo already has a vault")
    fails(cli("bunker", "create", "Bravo", "--password-stdin", stdin=lines(PASSWORD2)), 2, "not a bunker name")
    fails(owner(cli, "--bunker", "../alpha", "ls"), 2, "not a bunker name")


def _bunker_rows(cli: Run) -> List[Dict[str, Any]]:
    document = as_json(cli("--json", "bunker", "ls"))
    assert set(document) == {"bunkers"}
    return document["bunkers"]


def test_bunker_ls_current_and_use(cli: Run, two_bunkers: None) -> None:
    rows = _bunker_rows(cli)
    assert [row["name"] for row in rows] == ["alpha", "bravo"]
    assert set(rows[0]) == {"name", "vault", "path", "mode", "device", "hardware", "sessions", "grants", "current",
                            "default", "error"}
    flags = (rows[0]["current"], rows[0]["default"], rows[1]["current"], rows[1]["default"])
    assert flags == (True, True, False, False)
    assert rows[1]["vault"] is True and rows[1]["device"] == [{"backend": "software", "hardware": False}]
    assert rows[1]["sessions"] == 0 and rows[1]["grants"] == 0
    table = ok(cli("bunker", "ls")).stdout
    assert "current, default" in table and table.splitlines()[0].split()[:3] == ["NAME", "VAULT", "DEVICE"]
    assert not leaked(ok(cli("bunker", "ls")), "gh-value-1", "bravo-value")

    current = ok(cli("bunker", "current"))
    assert current.stdout == "alpha\n" and "default" in current.stderr
    assert as_json(cli("--json", "--bunker", "bravo", "bunker", "current"))["source"] == "flag"
    environment = as_json(cli("--json", "bunker", "current", env={"IRONDOME_BUNKER": "bravo"}))
    assert environment == {"name": "bravo", "source": "environment", "reason": "IRONDOME_BUNKER is set", "vault": True}

    used = ok(owner(cli, "bunker", "use", "bravo", password=PASSWORD2))  # bravo's own master password
    assert "bunker bravo is now the default" in used.stderr
    assert ok(cli("bunker", "current")).stdout == "bravo\n"
    assert ok(owner(cli, "get", "SHARED", password=PASSWORD2)).stdout == "bravo-value"
    rows = _bunker_rows(cli)
    assert [(row["name"], row["current"], row["default"]) for row in rows] == [
        ("alpha", False, False), ("bravo", True, True)
    ]
    overridden = ok(owner(cli, "bunker", "use", "alpha", env={"IRONDOME_BUNKER": "bravo"}))
    assert "IRONDOME_BUNKER=bravo" in overridden.stderr
    assert ok(cli("bunker", "current")).stdout == "alpha\n"
    fails(owner(cli, "bunker", "use", "charlie"), 3, "no vault in bunker charlie")
    fails(owner(cli, "bunker", "use", "Charlie"), 2)


def test_a_grant_finds_its_own_bunker_and_reaches_nothing_else(cli: Run, two_bunkers: None) -> None:
    token = make_grant(["SHARED"], password=PASSWORD2, bunker="bravo", mode="reveal", uses=5)
    assert paths.ENV_BUNKER not in os.environ
    env = {"IRONDOME_GRANT": token}
    assert ok(cli("get", "SHARED", env=env)).stdout == "bravo-value"
    current = as_json(cli("--json", "bunker", "current", env=env))
    assert current["name"] == "bravo" and current["source"] == "token"
    fails(cli("get", "github", env=env), 5, "does not cover 'github'")
    fails(cli("--bunker", "alpha", "get", "SHARED", env=env), 4, "bunker alpha: that grant token opens nothing here")
    fails(cli("--bunker", "alpha", "get", "github", env=env), 4)
    rows = {row["name"]: row for row in _bunker_rows(cli)}
    assert rows["bravo"]["grants"] == 1 and rows["alpha"]["grants"] == 0


def test_bunker_rm_destroys_one_bunker_and_leaves_the_other(cli: Run, two_bunkers: None) -> None:
    ok(owner(cli, "bunker", "use", "bravo", password=PASSWORD2))
    bravo_keys = sorted((paths.device_root() / "bunkers" / "bravo").glob("*.key"))
    assert bravo_keys
    fails(cli("bunker", "rm", "bravo"), 5, "owner")
    refused = fails(owner(cli, "bunker", "rm", "bravo", password=PASSWORD2), 2, "--yes")
    assert "Removing bunker bravo destroys" in refused.stderr
    assert paths.root().joinpath("bunkers", "bravo", "vault.irondome").is_file()

    report = as_json(owner(cli, "--json", "bunker", "rm", "bravo", "--yes", password=PASSWORD2))
    assert set(report) == {"bunker", "success", "device_keys_destroyed", "hardware_backed", "files_deleted",
                           "leftovers", "foreign", "errors", "recovery_key_survives", "default"}
    assert report["bunker"] == "bravo" and report["success"] is True and report["errors"] == []
    assert report["device_keys_destroyed"] >= 1 and report["hardware_backed"] is False
    assert report["recovery_key_survives"] is True and report["default"] == "alpha"
    assert not any(path.exists() for path in bravo_keys)
    assert not (paths.root() / "bunkers" / "bravo").exists()
    assert not (paths.device_root() / "bunkers" / "bravo").exists()

    assert ok(cli("bunker", "current")).stdout == "alpha\n"
    assert [row["name"] for row in _bunker_rows(cli)] == ["alpha"]
    assert get(cli, "github") == "gh-value-1"
    fails(owner(cli, "bunker", "rm", "bravo", "--yes"), 3, "no bunker named bravo")


def test_bunker_rm_in_words_names_what_survives(cli: Run, two_bunkers: None) -> None:
    result = ok(owner(cli, "bunker", "rm", "bravo", "--yes", password=PASSWORD2))
    assert "bunker bravo is gone" in result.stderr
    assert re.search(r"\b1 device key destroyed|\b\d+ device keys destroyed", result.stderr), result.stderr
    assert "not hardware-held" in result.stderr and "(s)" not in result.stderr
    assert "recovery key" in result.stderr
    assert result.stdout == ""


def test_removing_every_bunker_leaves_alpha_as_the_default(cli: Run, two_bunkers: None) -> None:
    ok(owner(cli, "bunker", "use", "bravo", password=PASSWORD2))
    assert as_json(owner(cli, "--json", "bunker", "rm", "alpha", "--yes"))["default"] is None
    assert ok(cli("bunker", "current")).stdout == "bravo\n"
    setting = paths.root() / "default-bunker"
    assert setting.read_text(encoding="ascii") == "bravo\n"
    assert as_json(owner(cli, "--json", "bunker", "rm", "bravo", "--yes", password=PASSWORD2))["default"] == "alpha"
    assert not setting.exists()  # forgotten, as on a new machine, rather than rewritten to say alpha
    current = as_json(cli("--json", "bunker", "current"))
    assert current == {"name": "alpha", "source": "default", "reason": current["reason"], "vault": False}
    assert [(row["name"], row["vault"]) for row in _bunker_rows(cli)] == [("alpha", False)]
    assert device_files() == []
    assert ok(cli()).stdout.startswith("There is no vault in bunker alpha")


def test_bunker_rm_without_recovery_key_has_no_caveat(cli: Run, vault: str) -> None:
    ok(cli("bunker", "create", "charlie", "--no-recovery", "--password-stdin", stdin=lines(PASSWORD, PASSWORD2)))
    report = as_json(owner(cli, "--json", "bunker", "rm", "charlie", "--yes", password=PASSWORD2))
    assert report["recovery_key_survives"] is False and report["default"] is None


# ---------------------------------------------------------------------------
# Proving the owner: --password-stdin counts only with a password that opens the vault
# ---------------------------------------------------------------------------


def _machine() -> Dict[str, bytes]:
    """Every file IronDome keeps, on both sides, with its content."""
    return {
        str(path): path.read_bytes()
        for root in (paths.root(), paths.device_root()) if root.exists()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


@pytest.mark.parametrize("piped", ["", "not the master password\n"], ids=["no-line", "wrong"])
def test_an_agent_that_passes_password_stdin_cannot_remove_switch_or_add_bunkers(
    cli: Run, two_bunkers: None, piped: str
) -> None:
    """Without a terminal, --password-stdin is all an agent can show: the flag alone proves nothing."""
    before = _machine()
    own = lines("an agent's own new password")
    for arguments, stdin in (
        (["bunker", "rm", "bravo", "--yes"], piped),
        (["bunker", "use", "bravo"], piped),
        (["bunker", "create", "charlie"], piped + own),
        (["--bunker", "charlie", "init"], piped + own),
        (["bunker", "create", "charlie"], own),  # its own password as the only line counts for nothing either
    ):
        # No line at all is a usage error (nothing was entered); any other line is a wrong master password.
        refused = fails(cli("--password-stdin", *arguments, stdin=stdin), 2 if stdin == "" else 4)
        assert "nothing was entered" in refused.stderr or "wrong master password" in refused.stderr
        assert not leaked(refused, "bravo-value", "gh-value-1")
    assert _machine() == before
    assert paths.bunkers() == ["alpha", "bravo"] and paths.default_bunker() == "alpha"


def test_bunker_rm_and_use_need_the_named_bunkers_own_password(cli: Run, two_bunkers: None) -> None:
    fails(owner(cli, "bunker", "rm", "bravo", "--yes"), 4, "bunker bravo: wrong master password")
    fails(owner(cli, "bunker", "use", "bravo"), 4, "bunker bravo: wrong master password")
    assert (paths.root() / "bunkers" / "bravo" / "vault.irondome").is_file() and paths.default_bunker() == "alpha"
    ok(owner(cli, "bunker", "use", "bravo", password=PASSWORD2))
    assert paths.default_bunker() == "bravo"


def test_a_second_bunker_takes_the_default_bunkers_password_and_a_first_vault_none(cli: Run) -> None:
    init(cli)  # the first vault on a machine: a script may make it with nothing but the new password
    fails(cli("bunker", "create", "bravo", "--password-stdin", stdin=lines(PASSWORD2)), 4, "wrong master password")
    assert paths.bunkers() == ["alpha"]
    created = as_json(cli("--json", "bunker", "create", "bravo", "--password-stdin", stdin=lines(PASSWORD, PASSWORD2)))
    assert created["bunker"] == "bravo"
    ok(owner(cli, "bunker", "use", "bravo", password=PASSWORD2))
    # Now bravo is the default, so its owner is the one who may add the next bunker; --bunker X init is the same.
    third = "charlie's own new password"
    fails(cli("--bunker", "charlie", "init", "--password-stdin", stdin=lines(PASSWORD, third)), 4)
    ok(cli("--bunker", "charlie", "init", "--password-stdin", stdin=lines(PASSWORD2, third)))
    assert sorted(paths.bunkers()) == ["alpha", "bravo", "charlie"]
    ok(owner(cli, "--bunker", "charlie", "add", "x", "--generate", password=third))  # charlie opens with its own


def test_bunker_current_reports_exactly_why_the_bunker_was_chosen(cli: Run, two_bunkers: None) -> None:
    """The environment wins over a token, even a token of the same bunker: the reason says so."""
    grant = make_grant(["SHARED"], password=PASSWORD2, bunker="bravo", mode="reveal", uses=5)
    with open_vault(PASSWORD) as opened:
        session = caps.create_session(opened, ttl=300)
    named = as_json(cli("--json", "bunker", "current", env={"IRONDOME_BUNKER": "bravo", "IRONDOME_GRANT": grant}))
    assert (named["name"], named["source"], named["reason"]) == ("bravo", "environment", "IRONDOME_BUNKER is set")
    by_grant = as_json(cli("--json", "bunker", "current", env={"IRONDOME_GRANT": grant}))
    assert (by_grant["name"], by_grant["source"]) == ("bravo", "token")
    assert by_grant["reason"] == "the token in IRONDOME_GRANT belongs to it"
    by_session = as_json(cli("--json", "bunker", "current", env={"IRONDOME_SESSION": session}))
    assert (by_session["name"], by_session["reason"]) == ("alpha", "the token in IRONDOME_SESSION belongs to it")
    flagged = as_json(cli("--json", "--bunker", "alpha", "bunker", "current", env={"IRONDOME_GRANT": grant}))
    assert (flagged["name"], flagged["source"]) == ("alpha", "flag")
    assert as_json(cli("--json", "bunker", "current"))["source"] == "default"


# ---------------------------------------------------------------------------
# A request a grant refuses spends none of its uses
# ---------------------------------------------------------------------------


def test_a_mistyped_reference_or_a_reveal_leaves_a_single_use_grant_whole(cli: Run, vault: str) -> None:
    ok(owner(cli, "edit", "github", "--totp-stdin", more=[TOTP_SECRET]))
    env = {"IRONDOME_GRANT": make_grant(["GITHUB_TOKEN"], mode="use", uses=1)}
    for arguments, fragment in (
        (["get", "OTHER"], "does not cover 'OTHER'"),
        (["get", "github"], "does not cover 'github'"),
        (["get", "GITHUB_TOKEN"], "irondome run"),  # showing it, under a use-only grant
        (["otp", "OTHER"], "does not cover 'OTHER/totp'"),
        (["otp", "GITHUB_TOKEN"], "does not cover 'GITHUB_TOKEN/totp'"),
    ):
        refused = fails(cli(*arguments, env=env), 5, fragment, "Nothing was used")
        assert not leaked(refused, "gh-value-1")
    assert "1 use left" in ok(cli("ls", env=env)).stderr  # all of that cost nothing
    # A one-time code may be shown under a use-only grant; that is its one use.
    codes = {"IRONDOME_GRANT": make_grant(["github/totp"], mode="use", uses=1, ttl=600)}
    fails(cli("otp", "aws/prod", env=codes), 5, "Nothing was used")
    assert re.fullmatch(r"\d{6}", ok(cli("otp", "github", env=codes)).stdout)
    fails(cli("otp", "github", env=codes), 4, "used up")


# ---------------------------------------------------------------------------
# No secret on the command line: --field NAME and --note-stdin
# ---------------------------------------------------------------------------


def test_a_field_value_on_the_command_line_is_refused_and_never_repeated(cli: Run, vault: str) -> None:
    before = paths.vault_file().read_bytes()
    for command in (["add", "new", "--generate"], ["edit", "github"]):
        refused = fails(owner(cli, *command, "--field", "pin=4711-secret-pin"), 2,
                        "--field takes only the field's name", "shell history or the process list", "--field pin")
        assert not leaked(refused, "4711-secret-pin")
    assert paths.vault_file().read_bytes() == before


def test_field_values_and_notes_are_read_from_stdin_in_the_documented_order(cli: Run, vault: str) -> None:
    ok(owner(
        cli, "add", "bank", "--value-stdin", "--totp-stdin", "--field", "pin", "--field", "iban", "--note-stdin",
        more=["bank-value", TOTP_SECRET, "4711", "DE00 1234 5678", "first line of the notes", "", "third line"],
    ))
    entry = as_json(owner(cli, "--json", "show", "bank", "--reveal"))
    assert entry["password"] == "bank-value" and entry["has_totp"] is True
    assert entry["fields"] == {"pin": "4711", "iban": "DE00 1234 5678"}
    assert entry["notes"] == "first line of the notes\n\nthird line"
    ok(owner(cli, "edit", "bank", "--field", "iban", "--field", "bic", "--note-stdin", more=["DE99", "BANKDEFF"]))
    entry = as_json(owner(cli, "--json", "show", "bank", "--reveal"))
    assert entry["fields"] == {"pin": "4711", "iban": "DE99", "bic": "BANKDEFF"} and entry["notes"] == ""
    # With --password-stdin and a generated value, the field values follow the master password directly.
    ok(owner(cli, "add", "generated", "--generate", "--field", "account", more=["acct-42"]))
    assert get(cli, "generated/account") == "acct-42"
    ok(owner(cli, "edit", "generated", "--note-stdin", more=["one", "two"]))
    assert get(cli, "generated/notes") == "one\ntwo"


# ---------------------------------------------------------------------------
# The clipboard
# ---------------------------------------------------------------------------


def test_copying_prints_nothing_secret_and_the_clipboard_is_cleared(cli: Run, vault: str, clipboard: Clipboard) -> None:
    ok(owner(cli, "config", "set", "clipboard_clear_seconds", "5"))
    result = ok(owner(cli, "get", "github", "-c", env=clipboard.env))
    assert result.stdout == "" and not leaked(result, "gh-value-1")
    assert "cleared in 5s" in result.stderr
    assert clipboard.text() == "gh-value-1"
    assert not any("gh-value-1" in " ".join(call["argv"]) for call in clipboard.calls())
    document = as_json(owner(cli, "--json", "get", "GITHUB_TOKEN", "--copy", env=clipboard.env))
    assert document == {"reference": "GITHUB_TOKEN", "field": "password", "value": None, "clipboard": "pbcopy"}

    deadline = time.monotonic() + 30
    while clipboard.text() and time.monotonic() < deadline:
        time.sleep(0.2)
    assert clipboard.text() == ""


def test_gen_and_otp_can_copy_instead_of_printing(cli: Run, vault: str, clipboard: Clipboard) -> None:
    ok(owner(cli, "config", "set", "clipboard_clear_seconds", "5"))
    generated = as_json(cli("--json", "gen", "--copy", env=clipboard.env))
    assert generated["value"] is None and generated["clipboard"] == "pbcopy" and len(clipboard.text()) == 20
    ok(owner(cli, "edit", "github", "--totp-stdin", more=[TOTP_SECRET]))
    copied = ok(owner(cli, "otp", "github", "-c", env=clipboard.env))
    assert copied.stdout == "" and re.fullmatch(r"\d{6}", clipboard.text())


# ---------------------------------------------------------------------------
# Help and usage
# ---------------------------------------------------------------------------

COMMANDS = ["init", "status", "add", "get", "show", "ls", "find", "edit", "rm", "gen", "otp", "passwd", "recovery",
            "auth", "config", "bunker", "recovery new", "recovery remove", "auth show", "auth touchid",
            "auth password", "config ls", "config get", "config set", "config reset", "bunker create", "bunker ls",
            "bunker use", "bunker current", "bunker rm"]


def _parser_for(command: str) -> argparse.ArgumentParser:
    from irondome.cli.main import build_parser

    parser = build_parser()
    for word in command.split():
        group = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
        parser = group.choices[word]
    return parser


@pytest.mark.parametrize("command", COMMANDS)
def test_every_command_explains_itself(cli: Run, command: str) -> None:
    result = ok(cli(*command.split(), "--help"))
    assert result.stdout.startswith("usage: irondome " + command)
    assert "!" not in result.stdout
    parser = _parser_for(command)
    description = " ".join((parser.description or "").split())
    sentences = [part for part in re.split(r"(?<=[a-z)])\.\s+", description + " ") if part.strip()]
    assert 2 <= len(sentences) <= 3, description
    for action in parser._actions:
        assert action.help and "\n" not in action.help, f"{command}: {action.option_strings or action.dest} has no help"
    *parent, last = command.split()
    group = next(action for action in _parser_for(" ".join(parent))._actions
                 if isinstance(action, argparse._SubParsersAction))
    summary = next(choice.help for choice in group._choices_actions if choice.dest == last)
    assert summary and "\n" not in summary and not summary.endswith(".")


def _examples(parser: argparse.ArgumentParser) -> List[str]:
    """The command lines in the examples of *parser*'s help."""
    epilog = parser.epilog or ""
    assert epilog.startswith("examples:\n"), epilog
    block = epilog.split("\n\n")[0].splitlines()[1:]
    return [re.split(r"\s{2,}", line.strip())[0] for line in block]


def _handler_of(command_line: str) -> Any:
    from irondome.cli.main import build_parser

    return build_parser().parse_args(shlex.split(command_line)[1:]).handler


@pytest.mark.parametrize("command", COMMANDS)
def test_every_command_shows_examples_that_run_as_that_command(command: str, monkeypatch: pytest.MonkeyPatch) -> None:
    parser = _parser_for(command)
    examples = _examples(parser)
    assert examples and all(line.startswith("irondome ") for line in examples)
    if parser.get_default("handler") is not None:  # a command: each example is that command
        assert all(_handler_of(line) is parser.get_default("handler") for line in examples), examples
        assert any(line.startswith(f"irondome {command}") for line in examples), examples
    else:  # a group of actions: each example runs one of them
        assert all(_handler_of(line) is not None for line in examples), examples
    assert [line for line in (parser.epilog or "").splitlines() if len(line) > 79] == []
    monkeypatch.setenv("COLUMNS", "50")  # a narrow terminal re-wraps the description, never an example
    shown = parser.format_help()
    assert all(line in shown for line in (parser.epilog or "").splitlines() if line.strip())


#: What --json prints for each list command: the document's keys, the key of its list, the keys of one item.
LIST_SHAPES = {
    "ls": ({"bunker", "entries"}, "entries", {"name", "id", "kind", "username", "url", "tags", "has_totp", "agent",
                                              "aliases", "created", "modified"}),
    "find": ({"bunker", "entries"}, "entries", {"name", "id", "kind", "username", "url", "tags", "has_totp",
                                                "agent", "aliases", "created", "modified"}),
    "bunker ls": ({"bunkers"}, "bunkers", {"name", "vault", "path", "mode", "device", "hardware", "sessions",
                                          "grants", "current", "default", "error"}),
    "config ls": ({"bunker", "settings"}, "settings", {"key", "value", "default", "minimum", "maximum", "help"}),
    "auth show": ({"bunker", "mode", "keyslots"}, "keyslots", {"id", "kind", "label", "describe", "created",
                                                              "backend", "policy", "hardware", "device_present"}),
}


@pytest.mark.parametrize("command", sorted(LIST_SHAPES))
def test_every_list_command_prints_one_object_with_a_named_list_as_its_help_says(
    cli: Run, vault: str, command: str
) -> None:
    keys, listed, item_keys = LIST_SHAPES[command]
    arguments = command.split() + (["git"] if command == "find" else [])
    document = as_json(owner(cli, "--json", *arguments))
    assert isinstance(document, dict) and set(document) == keys
    assert document[listed] and all(set(item) == item_keys for item in document[listed])
    epilog = _parser_for(command).epilog or ""
    for key in keys:
        assert f'"{key}"' in epilog, (command, key)
    for key in item_keys:
        assert re.search(rf"(?<![\w-]){key}(?![\w-])", epilog), (command, key)


def test_under_a_grant_ls_says_what_the_grant_is_and_names_references_not_entries(cli: Run, vault: str) -> None:
    env = {"IRONDOME_GRANT": make_grant(["GITHUB_TOKEN"], mode="use", uses=2)}
    document = as_json(cli("--json", "ls", env=env))
    assert set(document) == {"bunker", "grant", "references"}
    assert document["references"] == [{"reference": "GITHUB_TOKEN", "entry": "github", "field": "password"}]
    assert document["grant"]["uses_left"] == 2 and document["grant"]["mode"] == "use"
    epilog = _parser_for("ls").epilog or ""
    for key in ("grant", "references", "reference", "entry", "field", "uses_left", "mode", "expires"):
        assert key in epilog
    assert as_json(cli("--json", "ls", env=env))["grant"]["uses_left"] == 2  # listing used none


def test_show_and_ls_give_a_one_time_password_the_same_name(cli: Run, vault: str) -> None:
    ok(owner(cli, "edit", "github", "--totp-stdin", more=[TOTP_SECRET]))
    (row,) = [row for row in as_json(owner(cli, "--json", "ls"))["entries"] if row["name"] == "github"]
    shown = as_json(owner(cli, "--json", "show", "github"))
    assert row["has_totp"] is True and shown["has_totp"] is True
    assert "otp" not in row and "otp" not in shown


def test_counts_are_worded_for_one_and_for_many(cli: Run, vault: str) -> None:
    outputs = []
    shown = ok(owner(cli, "show", "github"))
    assert re.search(r"^history\s+-$", shown.stdout, re.M), shown.stdout
    ok(owner(cli, "edit", "github", "--generate"))
    outputs.append(ok(owner(cli, "show", "github")))
    assert "1 earlier password kept" in outputs[-1].stdout
    ok(owner(cli, "edit", "github", "--generate"))
    outputs.append(ok(owner(cli, "show", "github")))
    assert "2 earlier passwords kept" in outputs[-1].stdout
    outputs.append(ok(owner(cli, "show", "aws/prod")))
    assert "1 line, hidden" in outputs[-1].stdout
    ok(owner(cli, "edit", "github", "--totp-stdin", more=[TOTP_SECRET]))
    outputs.append(ok(owner(cli, "otp", "github")))
    assert re.fullmatch(r"valid for (1 more second|\d+ more seconds)\n", outputs[-1].stderr), outputs[-1].stderr
    one_use = {"IRONDOME_GRANT": make_grant(["GITHUB_TOKEN"], mode="use", uses=1)}
    outputs.append(ok(cli("ls", env=one_use)))
    assert "1 use left" in outputs[-1].stderr
    outputs.append(ok(owner(cli, "passwd", more=[PASSWORD2])))
    for result in outputs:
        assert "(s)" not in result.stdout + result.stderr and "(es)" not in result.stdout + result.stderr


def test_init_names_the_device_key_without_parentheses_inside_parentheses(cli: Run) -> None:
    result = ok(cli("init", "--password-stdin", stdin=lines(PASSWORD)))
    (line,) = [line for line in result.stderr.splitlines() if "Device key:" in line]
    assert "Device key: software, not hardware -- " in line, line
    assert not re.search(r"\([^)]*\(", line), line


def test_bad_usage_exits_2_and_names_the_help(cli: Run) -> None:
    fails(cli("add"), 2, "NAME", "irondome add --help")
    fails(cli("get", "x", "--bogus"), 2, "unrecognized arguments")
    fails(cli("auth"), 2, "<subcommand>")
    fails(cli("bunker", "nope"), 2, "invalid choice")


def test_quiet_keeps_only_the_result(cli: Run, vault: str) -> None:
    result = ok(owner(cli, "-q", "add", "quiet", "--generate"))
    assert result.stdout == "" and result.stderr == ""
    result = ok(cli("-q", "gen"))
    assert len(result.stdout) == 20 and result.stderr == ""


# ---------------------------------------------------------------------------
# At a terminal: a pseudo-terminal of the test's own, never the real one
# ---------------------------------------------------------------------------


class Terminal:
    """``irondome`` with a pseudo-terminal as its controlling terminal, answered by the test."""

    def __init__(self, args: Sequence[str], env: Dict[str, str]) -> None:
        import pty

        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # the child: become irondome at once
            try:
                os.execve(sys.executable, [sys.executable, "-m", "irondome", *args], env)  # noqa: S606 - no shell
            finally:
                os._exit(127)
        self.output = ""
        self.seen = 0
        self.closed = False
        self.status: Optional[int] = None

    def _read(self, deadline: float) -> bool:
        remaining = deadline - time.monotonic()
        if self.closed or remaining <= 0:
            return False
        ready, _, _ = select.select([self.fd], [], [], remaining)
        if not ready:
            return False
        try:
            chunk = os.read(self.fd, 4096)
        except OSError:  # Linux: the other side is gone
            chunk = b""
        if not chunk:
            self.closed = True
            return False
        self.output += chunk.decode("utf-8", "replace")
        return True

    def expect(self, text: str, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while text not in self.output[self.seen:]:
            if not self._read(deadline):
                raise AssertionError(f"{text!r} never appeared. The terminal showed:\n{self.output}")
        self.seen = self.output.index(text, self.seen) + len(text)

    def send(self, line: str) -> None:
        os.write(self.fd, line.encode("utf-8") + b"\r")

    def secret(self, prompt: str, value: str, timeout: float = 30.0) -> None:
        """Answer a hidden prompt once echo is off: input that arrives earlier is flushed by the prompt."""
        import termios

        self.expect(prompt, timeout)
        deadline = time.monotonic() + timeout
        while termios.tcgetattr(self.fd)[3] & termios.ECHO:
            assert time.monotonic() < deadline, f"echo never went off after {prompt!r}"
            time.sleep(0.01)
        self.send(value)

    def finish(self, timeout: float = 60.0) -> int:
        deadline = time.monotonic() + timeout
        while self._read(deadline):
            pass
        while self.status is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
                break
            if time.monotonic() > deadline:
                raise AssertionError(f"irondome did not exit. The terminal showed:\n{self.output}")
            time.sleep(0.02)
        return self.status

    def close(self) -> None:
        if self.status is None:
            try:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
            except OSError:
                pass
        os.close(self.fd)


def _line_prompts_are_broken() -> bool:
    """True while Context._read_line opens /dev/tty with open(..., "r+"): a tty cannot be seeked, so that raises."""
    from irondome.cli.context import Context

    return 'open("/dev/tty", "r+"' in inspect.getsource(Context._read_line)


#: Tests that answer a yes/no or typed-name question at the terminal. They fail for as long as
#: irondome.cli.context cannot read such an answer, and must pass once it can (strict).
needs_line_prompts = pytest.mark.xfail(
    _line_prompts_are_broken(),
    reason="irondome.cli.context.Context._read_line opens /dev/tty in 'r+' text mode, which raises "
    "io.UnsupportedOperation on every terminal",
    raises=AssertionError,
    strict=True,
)


@pytest.fixture
def terminal(isolated: Path) -> Iterator[Callable[..., Terminal]]:
    if not hasattr(os, "fork") or sys.platform == "win32":
        pytest.skip("needs a POSIX pseudo-terminal")
    started: List[Terminal] = []

    def start(*args: str, env: Optional[Dict[str, str]] = None) -> Terminal:
        merged = {name: value for name, value in os.environ.items() if name != "IRONDOME_NO_PROMPT"}
        merged.update(env or {})
        session = Terminal(args, merged)
        started.append(session)
        return session

    yield start
    for session in started:
        session.close()


@needs_line_prompts
def test_init_at_a_terminal_asks_twice_and_waits_until_the_key_is_kept(
    cli: Run, terminal: Callable[..., Terminal]
) -> None:
    session = terminal("init")
    session.expect("Checking for Touch ID")
    session.secret("New master password: ", PASSWORD)
    session.secret("Repeat it: ", PASSWORD)
    session.expect("shown this once")
    session.expect("Press Enter once you have written it down.")
    assert paths.vault_file().is_file()
    session.send("")
    assert session.finish() == 0, session.output
    assert PASSWORD not in session.output
    key = RECOVERY_KEY.search(session.output)
    assert key is not None
    unlock.unlock(VaultFile.load(), recovery_key=key.group(0)).wipe()
    assert status(cli)["mode"] == "password"


def test_init_at_a_terminal_refuses_two_different_passwords(terminal: Callable[..., Terminal]) -> None:
    session = terminal("init")
    session.secret("New master password: ", PASSWORD)
    session.secret("Repeat it: ", PASSWORD2)
    session.expect("do not match")
    assert session.finish() == 2
    assert not paths.vault_file().exists()


@needs_line_prompts
def test_init_at_a_terminal_offers_the_modes_where_touch_id_works(
    cli: Run, touch: Touch, terminal: Callable[..., Terminal]
) -> None:
    session = terminal("init", env=touch.env)
    session.expect("This machine can use Touch ID")
    session.expect("Choose 1, 2 or 3 [1]: ")
    session.send("3")
    session.secret("New master password: ", PASSWORD)
    session.secret("Repeat it: ", PASSWORD)
    session.expect("Press Enter once you have written it down.")
    session.send("")
    assert session.finish() == 0, session.output
    assert _slots(cli, touch.env) == [("password", "fake-touch", "biometry"), ("recovery", None, None)]
    assert touch.prompts()[0]["operation"] == "enroll"


def test_a_value_typed_at_the_hidden_prompt_is_never_echoed(
    cli: Run, vault: str, terminal: Callable[..., Terminal]
) -> None:
    session = terminal("add", "pasted", "--totp")
    session.secret("Master password: ", PASSWORD)
    session.secret("Value for pasted: ", "typed-secret-value")
    session.secret("One-time-password secret (base32, or an otpauth:// link): ", TOTP_SECRET)
    assert session.finish() == 0, session.output
    assert "typed-secret-value" not in session.output and PASSWORD not in session.output
    assert TOTP_SECRET not in session.output
    assert get(cli, "pasted") == "typed-secret-value"
    assert as_json(owner(cli, "--json", "show", "pasted"))["has_totp"] is True


@needs_line_prompts
def test_rm_asks_at_the_terminal_and_no_means_no(cli: Run, vault: str, terminal: Callable[..., Terminal]) -> None:
    session = terminal("rm", "github")
    session.secret("Master password: ", PASSWORD)
    session.expect("Remove 'github' and its alias GITHUB_TOKEN from bunker alpha? [y/N] ")
    session.send("n")
    session.expect("not confirmed")
    assert session.finish() == 1
    assert get(cli, "github") == "gh-value-1"
    session = terminal("rm", "github")
    session.secret("Master password: ", PASSWORD)
    session.expect("[y/N] ")
    session.send("y")
    assert session.finish() == 0, session.output
    fails(owner(cli, "get", "github"), 3)


@needs_line_prompts
def test_bunker_rm_at_the_terminal_needs_the_name_typed(
    cli: Run, two_bunkers: None, terminal: Callable[..., Terminal]
) -> None:
    session = terminal("bunker", "rm", "bravo")
    session.expect("Type bravo to continue: ")
    session.send("brav")
    session.expect("did not match")
    assert session.finish() == 1
    assert (paths.root() / "bunkers" / "bravo" / "vault.irondome").is_file()
    session = terminal("bunker", "rm", "bravo")
    session.expect("Type bravo to continue: ")
    session.send("bravo")
    session.expect("bunker bravo is gone")
    assert session.finish() == 0, session.output
    assert [row["name"] for row in _bunker_rows(cli)] == ["alpha"]


def test_bunker_rm_yes_at_a_terminal_without_the_password_is_refused_and_says_why(
    cli: Run, two_bunkers: None, terminal: Callable[..., Terminal]
) -> None:
    """An agent in the owner's terminal can pass -y; it cannot pass the password, so -y alone skips nothing."""
    for flag in ("-y", "--yes"):
        session = terminal("bunker", "rm", "bravo", flag)
        assert session.finish() == 2, session.output
        assert "-y skips the question only together with --password-stdin and bunker bravo's master password" in (
            " ".join(session.output.split())
        )
        assert "an agent can pass -y, it cannot pass your password" in session.output
        assert "Type bravo to continue" not in session.output
    assert (paths.root() / "bunkers" / "bravo" / "vault.irondome").is_file()


def test_a_field_value_typed_at_the_hidden_prompt_is_never_echoed(
    cli: Run, vault: str, terminal: Callable[..., Terminal]
) -> None:
    session = terminal("add", "typed", "--generate", "--field", "pin", "--field", "puk")
    session.secret("Master password: ", PASSWORD)
    session.secret("Value of the field pin: ", "4711-typed-pin")
    session.secret("Value of the field puk: ", "98765-typed-puk")
    assert session.finish() == 0, session.output
    assert "4711-typed-pin" not in session.output and "98765-typed-puk" not in session.output
    assert as_json(owner(cli, "--json", "show", "typed", "--reveal"))["fields"] == {
        "pin": "4711-typed-pin", "puk": "98765-typed-puk",
    }


@needs_line_prompts
def test_bunker_use_at_a_terminal_asks_and_without_a_yes_changes_nothing(
    cli: Run, two_bunkers: None, terminal: Callable[..., Terminal]
) -> None:
    """An agent in the owner's terminal can start `bunker use`; it cannot answer the question that follows."""
    session = terminal("bunker", "use", "bravo")
    session.expect("Make bunker bravo the default, for every command that names no bunker? [y/N] ")
    time.sleep(0.5)
    assert paths.default_bunker() == "alpha"  # nothing typed, nothing changed
    session.send("n")
    session.expect("not confirmed; the default bunker was not changed")
    assert session.finish() == 1
    assert paths.default_bunker() == "alpha"
    session = terminal("bunker", "use", "bravo")
    session.expect("[y/N] ")
    session.send("y")
    session.expect("bunker bravo is now the default")
    assert session.finish() == 0, session.output
    assert paths.default_bunker() == "bravo"
    session = terminal("bunker", "use", "bravo")
    session.expect("bunker bravo is the default already; nothing changed")
    assert session.finish() == 0, session.output


@needs_line_prompts
def test_recovery_new_at_a_terminal_says_what_re_keying_does_and_no_means_no(
    cli: Run, vault: str, terminal: Callable[..., Terminal]
) -> None:
    before = VaultFile.load().vault_id
    session = terminal("recovery", "new")
    session.secret("Master password: ", PASSWORD)
    session.expect("every session and grant ends")
    session.expect("[y/N] ")
    session.send("n")
    session.expect("not confirmed; nothing was changed")
    assert session.finish() == 1
    assert VaultFile.load().vault_id == before
    unlock.unlock(VaultFile.load(), recovery_key=vault).wipe()

    session = terminal("recovery", "new")
    session.secret("Master password: ", PASSWORD)
    session.expect("[y/N] ")
    session.send("y")
    session.expect("Press Enter once you have written it down.")
    session.send("")
    assert session.finish() == 0, session.output
    key = RECOVERY_KEY.search(session.output)
    assert key is not None and VaultFile.load().vault_id != before
    unlock.unlock(VaultFile.load(), recovery_key=key.group(0)).wipe()
    with pytest.raises(AuthError):
        unlock.unlock(VaultFile.load(), recovery_key=vault)
