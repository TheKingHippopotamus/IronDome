"""The Secure Enclave backend.

Two groups of tests.

*Stand-in helper.* A shell script that speaks the helper's protocol takes the
place of ``irondome-se``. These run on any POSIX machine and pin down what the
Python side does with every exit status, with malformed output, with a helper
that hangs, with hostile state files and with ``IRONDOME_NO_TOUCH``.

*Real hardware.* The ``secure_enclave`` fixture switches to the helper compiled
from ``irondome_se.swift`` and skips where there is no Secure Enclave. Nothing
here is ever started in interactive mode and no key is enrolled through the
backend under a biometric policy, so no Touch ID prompt can appear: the
biometric refusal is proved by driving the helper binary directly, creating a
biometry key and asking it to work without ``--interactive``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
import types
from pathlib import Path
from typing import Dict, Iterator, List, Optional

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from irondome import paths
from irondome.device import macos_se
from irondome.device.base import DEVICE_SECRET_LEN, POLICY_BIOMETRY, POLICY_DEVICE, POLICY_PRESENCE
from irondome.device.macos_se import SecureEnclaveBackend
from irondome.errors import AuthError, HardwareError, UsageError, VaultError

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the Secure Enclave backend is POSIX-only")

FAKE_SECRET = b"0123456789abcdef0123456789abcdef"
FAKE_KEY = base64.b64encode(b"an opaque blob from the stand-in helper").decode("ascii")
INFO_OK = '{"protocol":1,"secure_enclave":true,"biometry":"touchid","biometry_usable":true,"biometry_detail":""}'


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def uncompressed(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


# ---------------------------------------------------------------------------
# The stand-in helper
# ---------------------------------------------------------------------------


class StandIn:
    """A shell script in place of ``irondome-se``; each test decides how it answers."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.path = directory / "irondome-se-standin"
        self.log = directory / "calls.log"
        self.stdin_copy = directory / "stdin.bin"
        self.env_copy = directory / "env.txt"
        self.info = f"printf '%s\\n' '{INFO_OK}'"
        self.create = f"""printf '{{"key":"{FAKE_KEY}","public_key":"AAAA","policy":"%s"}}\\n' "$2\""""
        self.agree = f"printf '%s' '{FAKE_SECRET.decode()}'"
        self.write()

    def write(self) -> None:
        script = f"""#!/bin/sh
printf '%s\\n' "$*" >> '{self.log}'
env > '{self.env_copy}'
case "$1" in
  info) {self.info} ;;
  create) {self.create} ;;
  agree) cat > '{self.stdin_copy}'; {self.agree} ;;
  *) exit 2 ;;
esac
"""
        self.path.write_text(script)
        self.path.chmod(0o700)

    def answer(self, *, info: Optional[str] = None, create: Optional[str] = None, agree: Optional[str] = None) -> None:
        if info is not None:
            self.info = info
        if create is not None:
            self.create = create
        if agree is not None:
            self.agree = agree
        self.write()

    def fail(self, status: int, code: str = "x", message: str = "detail from the helper") -> str:
        """Shell text: report a failure the way the real helper does and exit with *status*."""
        return f"""printf '%s\\n' '{{"error":"{code}","message":"{message}"}}' >&2; exit {status}"""

    def calls(self) -> List[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []


@pytest.fixture
def standin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> StandIn:
    directory = tmp_path / "standin"
    directory.mkdir()
    helper = StandIn(directory)
    monkeypatch.setenv("IRONDOME_SE_HELPER", str(helper.path))
    # The backend refuses to do anything off macOS; the stand-in lets its
    # Python side be exercised on Linux as well.
    monkeypatch.setattr(macos_se, "sys", types.SimpleNamespace(platform="darwin"))
    return helper


@pytest.fixture
def backend() -> SecureEnclaveBackend:
    return SecureEnclaveBackend()


def state_file(descriptor: Dict[str, str]) -> Path:
    return paths.device_dir() / f"{descriptor['ref']}.json"


def enrolled(backend: SecureEnclaveBackend) -> Dict[str, str]:
    descriptor, secret = backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    secret.wipe()
    return descriptor


# -- the happy path through the stand-in -------------------------------------


def test_probe_with_a_working_helper(standin, backend):
    probe = backend.probe()
    assert (probe.name, probe.available, probe.hardware, probe.biometry) == ("macos-se", True, True, True)
    assert probe.detail == "Secure Enclave, Touch ID available"


def test_probe_reports_a_mac_without_a_secure_enclave(standin, backend):
    standin.answer(info="""printf '%s\\n' '{"secure_enclave":false,"biometry":"none","biometry_usable":false}'""")
    probe = backend.probe()
    assert probe.available is False and probe.hardware is True
    assert "no Secure Enclave" in probe.detail


def test_probe_without_usable_biometry(standin, backend):
    standin.answer(info="""printf '%s\\n' '{"secure_enclave":true,"biometry":"none","biometry_usable":false}'""")
    probe = backend.probe()
    assert probe.available is True and probe.biometry is False


@pytest.mark.parametrize("answer", ["printf 'not json'", "printf '[1, 2]'", "exit 3", "exit 1", "kill -9 $$"])
def test_probe_never_raises_on_a_broken_helper(standin, backend, answer):
    standin.answer(info=answer)
    probe = backend.probe()
    assert probe.available is False
    assert probe.detail


def test_enroll_writes_a_state_file_and_returns_the_secret(standin, backend):
    descriptor, secret = backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    with secret:
        assert bytes(secret.view()) == FAKE_SECRET
        assert len(secret) == DEVICE_SECRET_LEN
    assert descriptor["backend"] == "macos-se" and descriptor["policy"] == POLICY_DEVICE
    assert len(descriptor["ref"]) == 32 and set(descriptor) == {"backend", "policy", "ref"}
    path = state_file(descriptor)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    state = json.loads(path.read_text())
    assert state["backend"] == "macos-se" and state["policy"] == POLICY_DEVICE and state["key"] == FAKE_KEY
    peer = base64.b64decode(state["peer"])
    assert len(peer) == 65 and peer[0] == 4
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer)  # raises unless it is on the curve
    assert backend.exists(descriptor)


def test_unseal_repeats_the_agreement(standin, backend):
    descriptor = enrolled(backend)
    with backend.unseal(descriptor, auth=None, interactive=False, reason="test") as secret:
        assert bytes(secret.view()) == FAKE_SECRET
    assert standin.calls() == ["info", "create device", "agree", "agree"]


def test_the_key_and_peer_travel_on_stdin_never_in_the_arguments(standin, backend):
    descriptor = enrolled(backend)
    state = json.loads(state_file(descriptor).read_text())
    request = json.loads(standin.stdin_copy.read_text())
    assert request["key"] == state["key"] and request["peer"] == state["peer"]
    assert request["reason"] == "test"
    for call in standin.calls():
        assert state["key"] not in call and state["peer"] not in call


def test_the_helper_gets_a_minimal_environment(standin, backend, monkeypatch):
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    monkeypatch.setenv("IRONDOME_SESSION", "a-session-token")
    monkeypatch.setenv("PATH", "/tmp/evil-bin:" + os.environ.get("PATH", ""))
    enrolled(backend)
    seen = dict(line.split("=", 1) for line in standin.env_copy.read_text().splitlines() if "=" in line)
    assert seen["PATH"] == "/usr/bin:/bin"
    for name in ("DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "IRONDOME_SESSION", "IRONDOME_NO_TOUCH", "IRONDOME_HOME"):
        assert name not in seen
    allowed = {"HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "__CF_USER_TEXT_ENCODING", "PATH"}
    assert set(seen) - {"PWD", "SHLVL", "_", "OLDPWD"} <= allowed


def test_a_long_reason_is_cut_before_it_is_sent(standin, backend):
    descriptor, secret = backend.enroll(policy=POLICY_DEVICE, auth=None, reason="r" * 100_000)
    secret.wipe()
    assert len(json.loads(standin.stdin_copy.read_text())["reason"]) == 200
    assert backend.exists(descriptor)


# -- what each failure of the helper becomes ---------------------------------


@pytest.mark.parametrize(
    "status, expected, fragment",
    [
        (4, AuthError, "Touch ID is required"),
        (5, AuthError, "detail from the helper"),
        (6, HardwareError, "does not accept this device key"),
        (3, HardwareError, "detail from the helper"),
        (2, HardwareError, "failed (2)"),
        (1, HardwareError, "failed (1)"),
        (77, HardwareError, "failed (77)"),
    ],
)
def test_exit_statuses_of_agree(standin, backend, status, expected, fragment):
    descriptor = enrolled(backend)
    standin.answer(agree=standin.fail(status))
    with pytest.raises(expected) as caught:
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")
    assert fragment in str(caught.value)
    assert type(caught.value) is expected


def test_a_rejected_key_reports_what_the_enclave_said(standin, backend):
    descriptor = enrolled(backend)
    standin.answer(agree=standin.fail(6, "key_rejected", "the chip said no"))
    with pytest.raises(HardwareError, match="the chip said no"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


def test_a_locked_mac_is_reported_as_such(standin, backend):
    descriptor = enrolled(backend)
    standin.answer(agree=standin.fail(3, "device_locked", "this Mac is locked"))
    with pytest.raises(HardwareError, match="this Mac is locked"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


def test_a_helper_killed_by_a_signal(standin, backend):
    descriptor = enrolled(backend)
    standin.answer(agree="kill -9 $$")
    with pytest.raises(HardwareError, match="failed"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


def test_failure_text_that_is_not_json_is_still_reported(standin, backend):
    descriptor = enrolled(backend)
    standin.answer(agree="echo 'dyld: something went wrong' >&2; exit 9")
    with pytest.raises(HardwareError, match="something went wrong"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


@pytest.mark.parametrize(
    "output",
    ["true", "printf 'short'", f"printf '%s' '{FAKE_SECRET.decode()}X'", f"printf '%s' '{FAKE_SECRET.decode()[:-1]}'"],
    ids=["nothing", "five-bytes", "one-too-many", "one-too-few"],
)
def test_a_secret_of_the_wrong_length_is_refused(standin, backend, output):
    descriptor = enrolled(backend)
    standin.answer(agree=output)
    with pytest.raises(HardwareError, match="malformed secret"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


def test_a_helper_that_hangs_is_killed(standin, backend, monkeypatch):
    descriptor = enrolled(backend)
    pid_file = standin.directory / "pid"
    standin.answer(agree=f"echo $$ > '{pid_file}'; exec sleep 300")
    monkeypatch.setattr(macos_se, "_HELPER_TIMEOUT", 3.0)
    with pytest.raises(HardwareError, match="did not answer in time"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")
    if pid_file.exists():  # on a very busy machine it may be killed before it gets this far
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)


def test_an_unanswered_touch_prompt_is_an_auth_error(standin, backend, monkeypatch):
    monkeypatch.delenv("IRONDOME_NO_TOUCH")
    standin.answer(agree="exec sleep 300")
    monkeypatch.setattr(macos_se, "_TOUCH_TIMEOUT", 0.5)
    with pytest.raises(AuthError, match="not answered in time"):
        backend._agree(FAKE_KEY, "AAAA", interactive=True, reason="test")


def test_the_touch_timeout_comes_from_the_environment(standin, backend, monkeypatch):
    """The MCP server sets IRONDOME_TOUCH_TIMEOUT so that a prompt ends before its client gives up."""
    monkeypatch.delenv("IRONDOME_NO_TOUCH")
    monkeypatch.setenv("IRONDOME_TOUCH_TIMEOUT", "1")
    standin.answer(agree="exec sleep 300")
    started = time.monotonic()
    with pytest.raises(AuthError, match="not answered in time"):
        backend._agree(FAKE_KEY, "AAAA", interactive=True, reason="test")
    assert time.monotonic() - started < 30


@pytest.mark.parametrize("value", ["0", "3601", "-5", "1.5", "ten", "1e3"])
def test_a_touch_timeout_outside_its_range_is_refused_before_any_prompt(standin, backend, monkeypatch, value):
    monkeypatch.delenv("IRONDOME_NO_TOUCH")
    monkeypatch.setenv("IRONDOME_TOUCH_TIMEOUT", value)
    standin.answer(agree="echo started > started; exec sleep 300")
    with pytest.raises(UsageError, match="IRONDOME_TOUCH_TIMEOUT"):
        backend._agree(FAKE_KEY, "AAAA", interactive=True, reason="test")
    assert not (standin.directory / "started").exists()


def test_the_touch_timeout_defaults_and_accepts_its_bounds(monkeypatch):
    monkeypatch.delenv("IRONDOME_TOUCH_TIMEOUT", raising=False)
    assert macos_se._touch_timeout() == macos_se._TOUCH_TIMEOUT
    for value, expected in (("1", 1.0), (" 45 ", 45.0), ("3600", 3600.0), ("", macos_se._TOUCH_TIMEOUT)):
        monkeypatch.setenv("IRONDOME_TOUCH_TIMEOUT", value)
        assert macos_se._touch_timeout() == expected


def test_only_device_policy_keys_work_while_the_screen_is_locked():
    """device keys are AfterFirstUnlock (SSH, scheduled jobs, agents); finger and password keys need an unlocked Mac."""
    source = macos_se.helper_source().read_text()
    body = source[source.index("func accessControl"):source.index("func commandInfo")]
    assert "var protection = kSecAttrAccessibleWhenUnlockedThisDeviceOnly" in body
    device = body[body.index('case "device":'):body.index('case "biometry":')]
    assert "protection = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly" in device
    assert "SecAccessControlCreateWithFlags(nil, protection, flags, &error)" in body
    assert "ThisDeviceOnly" in body and "kSecAttrAccessibleAlways" not in source


def test_info_and_create_time_out_too(standin, backend, monkeypatch):
    standin.answer(info="exec sleep 300")
    monkeypatch.setattr(macos_se, "_HELPER_TIMEOUT", 0.5)
    with pytest.raises(HardwareError, match="did not answer in time"):
        backend.info()


# -- IRONDOME_NO_TOUCH -------------------------------------------------------


def test_no_touch_keeps_the_helper_out_of_interactive_mode(standin, backend):
    assert os.environ["IRONDOME_NO_TOUCH"] == "1"
    backend._agree(FAKE_KEY, "AAAA", interactive=True, reason="test").wipe()
    assert standin.calls() == ["agree"]


def test_interactive_mode_is_requested_only_when_allowed(standin, backend, monkeypatch):
    monkeypatch.delenv("IRONDOME_NO_TOUCH")
    backend._agree(FAKE_KEY, "AAAA", interactive=True, reason="test").wipe()
    backend._agree(FAKE_KEY, "AAAA", interactive=False, reason="test").wipe()
    assert standin.calls() == ["agree --interactive", "agree"]


def test_a_silent_key_is_never_unsealed_interactively(standin, backend, monkeypatch):
    monkeypatch.delenv("IRONDOME_NO_TOUCH")
    descriptor = enrolled(backend)
    backend.unseal(descriptor, auth=None, interactive=True, reason="test").wipe()
    assert standin.calls() == ["info", "create device", "agree", "agree"]


def test_a_refused_biometric_enrolment_leaves_nothing_behind(standin, backend):
    # With prompts switched off the helper is asked without --interactive, and
    # a key that needs a finger answers "interaction required".
    works_when_interactive = f"printf '%s' '{FAKE_SECRET.decode()}'"
    standin.answer(agree=f"""case "$2" in --interactive) {works_when_interactive} ;; *) {standin.fail(4)} ;; esac""")
    with pytest.raises(AuthError, match="Touch ID is required"):
        backend.enroll(policy=POLICY_BIOMETRY, auth=None, reason="test")
    assert standin.calls() == ["info", "create biometry", "agree"]
    assert list(paths.device_dir().glob("*.json")) == []


# -- enrolment refusals ------------------------------------------------------


def test_enroll_refuses_an_unknown_policy(standin, backend):
    with pytest.raises(HardwareError, match="policy"):
        backend.enroll(policy="psychic", auth=None, reason="test")
    assert standin.calls() == []


def test_enroll_needs_a_secure_enclave(standin, backend):
    standin.answer(info="""printf '%s\\n' '{"secure_enclave":false}'""")
    with pytest.raises(HardwareError, match="no usable Secure Enclave"):
        backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")


def test_biometric_enrolment_needs_usable_touch_id(standin, backend):
    standin.answer(
        info="""printf '%s\\n' '{"secure_enclave":true,"biometry_usable":false,"biometry_detail":"lid closed"}'"""
    )
    with pytest.raises(HardwareError, match="lid closed"):
        backend.enroll(policy=POLICY_BIOMETRY, auth=None, reason="test")
    assert standin.calls() == ["info"]


@pytest.mark.parametrize("answer", ["""printf '{"key":""}'""", """printf '{"key":7}'""", "printf '{}'", "printf '[]'"])
def test_enroll_refuses_a_helper_that_returns_no_key(standin, backend, answer):
    standin.answer(create=answer)
    with pytest.raises(HardwareError):
        backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    assert list(paths.device_dir().glob("*.json")) == []


def test_a_failed_agreement_during_enrolment_removes_the_state_file(standin, backend):
    standin.answer(agree=standin.fail(6))
    with pytest.raises(HardwareError):
        backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    assert list(paths.device_dir().glob("*.json")) == []


def test_enroll_reports_a_device_directory_it_cannot_write(standin, backend, monkeypatch):
    def refuse(path, data):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(paths, "write_atomic", refuse)
    with pytest.raises(HardwareError, match="could not store"):
        backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")


# -- which helper is run -----------------------------------------------------


def test_a_missing_helper_override_is_reported(backend, tmp_path, monkeypatch):
    monkeypatch.setattr(macos_se, "sys", types.SimpleNamespace(platform="darwin"))
    monkeypatch.setenv("IRONDOME_SE_HELPER", str(tmp_path / "nowhere"))
    with pytest.raises(HardwareError, match="does not exist"):
        macos_se.build_helper()
    assert backend.probe().available is False


@pytest.mark.parametrize("mode", [0o720, 0o702, 0o777])
def test_a_helper_others_can_write_is_refused(standin, backend, mode):
    standin.path.chmod(mode)
    with pytest.raises(HardwareError, match="writable by other users"):
        macos_se.build_helper()
    with pytest.raises(HardwareError):
        backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    assert standin.calls() == []


def test_a_helper_that_is_a_directory_is_refused(standin, backend):
    standin.path.unlink()
    standin.path.mkdir()
    with pytest.raises(HardwareError, match="not a regular file"):
        macos_se.build_helper()


def test_an_override_is_never_rebuilt(standin, monkeypatch):
    def no_compiler(*args, **kwargs):
        raise AssertionError("the compiler must not be looked for")

    monkeypatch.setattr(macos_se, "_find_swiftc", no_compiler)
    assert macos_se.build_helper(force=True) == standin.path


def test_off_macos_the_backend_refuses_without_running_anything(backend, monkeypatch):
    monkeypatch.setattr(macos_se, "sys", types.SimpleNamespace(platform="linux"))
    monkeypatch.setattr(macos_se.subprocess, "run", lambda *a, **k: pytest.fail("nothing may be run"))
    monkeypatch.setattr(macos_se.subprocess, "Popen", lambda *a, **k: pytest.fail("nothing may be run"))
    probe = backend.probe()
    assert probe.available is False and probe.detail == "not macOS"
    with pytest.raises(HardwareError, match="only works on macOS"):
        macos_se.build_helper()
    with pytest.raises(HardwareError, match="only works on macOS"):
        backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")


def test_without_developer_tools_the_compiler_stub_is_never_started(backend, monkeypatch):
    """/usr/bin/swiftc opens an install dialog when the tools are missing; it must not be run."""
    monkeypatch.setattr(macos_se, "sys", types.SimpleNamespace(platform="darwin"))
    started: List[List[str]] = []

    def fake_run(command, **kwargs):
        started.append(list(command))
        complaint = b"xcode-select: error: unable to get active developer directory"
        return subprocess.CompletedProcess(command, 2, b"", complaint)

    monkeypatch.setattr(macos_se.shutil, "which", lambda name, path=None: f"/usr/bin/{name}")
    monkeypatch.setattr(macos_se.subprocess, "run", fake_run)
    with pytest.raises(HardwareError, match="xcode-select --install"):
        macos_se.build_helper()
    assert started == [["/usr/bin/xcode-select", "-p"]]
    assert backend.probe().available is False


def test_the_compiler_is_looked_up_on_a_fixed_path_only(monkeypatch):
    lookups = []

    def which(name, path=None):
        lookups.append((name, path))
        return None

    monkeypatch.setattr(macos_se.shutil, "which", which)
    assert macos_se._find_swiftc() is None
    assert lookups and all(path == "/usr/bin:/bin" for _, path in lookups)


def test_helper_source_is_packaged_and_names_the_cached_binary():
    source = macos_se.helper_source()
    assert source.name == "irondome_se.swift" and source.is_file()
    assert "interactionNotAllowed" in source.read_text()
    assert macos_se._helper_path().parent == paths.helper_dir()
    assert macos_se._helper_path().name.startswith("irondome-se-")


def _no_side_effects(monkeypatch, *, compiler=None):
    """Make every way of building, running or prompting fail the test; *compiler* answers _find_swiftc."""
    def refuse(*args, **kwargs):
        raise AssertionError("helper_status built, ran or started something")

    monkeypatch.setattr(macos_se, "build_helper", refuse)
    monkeypatch.setattr(macos_se.subprocess, "Popen", refuse)
    monkeypatch.setattr(macos_se.subprocess, "run", refuse)
    monkeypatch.setattr(macos_se, "_find_swiftc", refuse if compiler is None else (lambda: compiler))


def test_helper_status_names_the_helper_and_builds_nothing(monkeypatch):
    monkeypatch.delenv("IRONDOME_SE_HELPER", raising=False)
    _no_side_effects(monkeypatch, compiler="/usr/bin/swiftc")
    status = macos_se.helper_status()
    source = macos_se.helper_source()
    assert status == {
        "source": str(source), "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "path": str(macos_se._helper_path()), "built": False, "from_environment": False, "compiler": True,
        "damaged": False, "error": None,
    }
    assert not paths.helper_dir().exists()  # nothing was written either
    helper = macos_se._helper_path()
    paths.ensure_dir(helper.parent)
    helper.write_bytes(b"#!/bin/sh\n")
    macos_se._record_path(helper).write_text(hashlib.sha256(b"#!/bin/sh\n").hexdigest())
    _no_side_effects(monkeypatch)  # a helper that is there needs no compiler to be looked for
    assert macos_se.helper_status()["built"] is True and macos_se.helper_status()["compiler"] is None


def test_helper_status_tells_a_cached_helper_that_is_not_the_one_compiled(monkeypatch):
    """A truncated or replaced cache file is not "compiled": it is reported, and a compiler is looked for."""
    monkeypatch.delenv("IRONDOME_SE_HELPER", raising=False)
    helper = macos_se._helper_path()
    paths.ensure_dir(helper.parent)
    helper.write_bytes(b"#!/bin/sh\n")
    macos_se._record_path(helper).write_text(hashlib.sha256(b"#!/bin/sh\n").hexdigest())
    record = macos_se._record_path(helper)

    def cut_off() -> None:
        helper.write_bytes(b"#!/bin")

    def without_its_record() -> None:
        helper.write_bytes(b"#!/bin/sh\n")  # whole again: only the record is gone
        record.unlink()

    def with_another_record() -> None:
        record.write_text("0" * 64)

    for spoil in (cut_off, without_its_record, with_another_record):
        spoil()
        _no_side_effects(monkeypatch, compiler="/usr/bin/swiftc")
        status = macos_se.helper_status()
        assert (status["built"], status["damaged"], status["compiler"]) == (False, True, True), spoil.__name__


def test_a_damaged_cached_helper_is_compiled_again(stand_in_compiler, backend):
    """Found by hand on a Mac: a cut-off helper failed every command with "(-9): no detail" and was never rebuilt."""
    helper = macos_se.build_helper()
    assert macos_se._intact(helper) and len(stand_in_compiler) == 2
    helper.write_bytes(helper.read_bytes()[:3])  # what a half-restored folder or a disk fault leaves
    assert backend.passive_probe().detail.startswith("not probed: the compiled Secure Enclave helper is damaged")
    assert macos_se.build_helper() == helper and len(stand_in_compiler) == 4  # announced and compiled once more
    assert macos_se._intact(helper)
    assert macos_se.build_helper() == helper and len(stand_in_compiler) == 4  # and cached again


def test_a_damaged_helper_that_cannot_be_compiled_again_says_what_to_install(stand_in_compiler, monkeypatch):
    helper = macos_se.build_helper()
    helper.write_bytes(b"")
    monkeypatch.setattr(macos_se, "_find_swiftc", lambda: None)
    with pytest.raises(HardwareError, match="is damaged, and compiling it again needs the Xcode Command Line Tools"):
        macos_se.build_helper()


def test_a_refused_key_names_the_remedy_that_fits_the_key():
    """Found by hand on a Mac: a password vault with a damaged key file was told to enrol Touch ID."""
    with pytest.raises(HardwareError) as device:
        macos_se._raise_for(6, b"", touch=False)
    assert "irondome recovery use" in str(device.value) and "touchid" not in str(device.value)
    assert "fingerprint" not in str(device.value)
    with pytest.raises(HardwareError) as touch:
        macos_se._raise_for(6, b"", touch=True)
    assert "irondome auth touchid" in str(touch.value)
    for kind in (True, False):  # a key refused the moment it was made is neither a damaged file nor a changed finger
        with pytest.raises(HardwareError) as fresh:
            macos_se._raise_for(6, b"", touch=kind, fresh=True)
        assert str(fresh.value) == "this Mac's Secure Enclave refused the key it had just made"


def test_a_key_refused_at_enrolment_is_not_called_a_damaged_file(standin, backend):
    standin.answer(agree=standin.fail(6))
    with pytest.raises(HardwareError, match="refused the key it had just made"):
        backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")


def test_a_helper_that_cannot_be_recorded_says_so_and_not_that_it_did_not_compile(stand_in_compiler, monkeypatch):
    real = paths.write_atomic

    def no_record(path, data):
        if str(path).endswith(".sha256"):
            raise OSError(28, "No space left on device", str(path))
        return real(path, data)

    monkeypatch.setattr(paths, "write_atomic", no_record)
    with pytest.raises(HardwareError, match="compiled the Secure Enclave helper, but could not record it"):
        macos_se.build_helper()


def test_a_helper_compiled_by_another_process_while_this_one_waited_is_not_compiled_again(
    stand_in_compiler, monkeypatch
):
    """Two first runs at once: the second finds the first one's helper once it has the build lock."""
    helper = macos_se._helper_path()
    real_lock = paths.file_lock
    from contextlib import contextmanager

    @contextmanager
    def lock_after_the_other_built(path=None):
        with real_lock(path):
            if not helper.exists():  # what the other process did while this one waited for the lock
                helper.write_bytes(b"#!/bin/sh\n")
                os.chmod(helper, 0o700)
                macos_se._record_path(helper).write_text(hashlib.sha256(b"#!/bin/sh\n").hexdigest())
            yield

    monkeypatch.setattr(paths, "file_lock", lock_after_the_other_built)
    assert macos_se.build_helper() == helper
    assert stand_in_compiler == []  # nothing announced, nothing compiled


def test_fault_tells_a_key_file_that_cannot_be_the_key(standin, backend):
    descriptor = enrolled(backend)
    assert backend.fault(descriptor) is None
    path = state_file(descriptor)
    whole = path.read_bytes()
    for spoiled in (whole[:200], b""):
        path.write_bytes(spoiled)
        assert backend.exists(descriptor) and backend.fault(descriptor) == "the Secure Enclave key file is damaged"
    path.unlink()
    assert backend.fault(descriptor) is None  # absent is what exists() reports


def test_helper_status_of_an_override_and_of_an_unreadable_source(monkeypatch, tmp_path):
    named = tmp_path / "my-helper"
    monkeypatch.setenv("IRONDOME_SE_HELPER", str(named))
    _no_side_effects(monkeypatch)
    status = macos_se.helper_status()
    assert (status["path"], status["built"], status["from_environment"], status["compiler"]) == (
        str(named), False, True, None,
    )
    monkeypatch.delenv("IRONDOME_SE_HELPER")
    monkeypatch.setattr(macos_se, "helper_source", lambda: tmp_path / "missing.swift")
    status = macos_se.helper_status()
    assert status["error"] and status["source_sha256"] is None and status["path"] is None and status["built"] is False


# -- the first compile is announced; a passive probe compiles nothing ---------


@pytest.fixture
def stand_in_compiler(monkeypatch: pytest.MonkeyPatch) -> Iterator[List[str]]:
    """A Mac without a helper yet, whose "swiftc" is a stand-in; returns what happened, in order."""
    from irondome import device as devices

    events: List[str] = []

    def compile_(command, **kwargs):
        events.append("compiler started")
        Path(command[command.index("-o") + 1]).write_bytes(b"#!/bin/sh\n")
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.delenv("IRONDOME_SE_HELPER", raising=False)
    monkeypatch.setattr(macos_se, "sys", types.SimpleNamespace(platform="darwin"))
    monkeypatch.setattr(macos_se, "_find_swiftc", lambda: "/stand-in/swiftc")
    monkeypatch.setattr(macos_se.subprocess, "run", compile_)
    previous = devices.set_progress(lambda message: events.append(f"said: {message}"))
    yield events
    devices.set_progress(previous)


def test_the_first_compile_says_so_before_the_compiler_starts(stand_in_compiler):
    helper = macos_se.build_helper()
    assert stand_in_compiler == [
        "said: Compiling the Secure Enclave helper (once, and again after an upgrade that changes it); "
        "this can take a minute...",
        "compiler started",
    ]
    assert macos_se.build_helper() == helper and len(stand_in_compiler) == 2  # cached: nothing to say or do


def test_a_forced_rebuild_is_announced_as_well(stand_in_compiler):
    macos_se.build_helper()
    macos_se.build_helper(force=True)
    assert [event.split(":")[0] for event in stand_in_compiler] == ["said", "compiler started"] * 2


def test_without_a_compiler_nothing_is_announced(stand_in_compiler, monkeypatch):
    monkeypatch.setattr(macos_se, "_find_swiftc", lambda: None)
    with pytest.raises(HardwareError, match="xcode-select --install"):
        macos_se.build_helper()
    assert stand_in_compiler == []


def test_passive_probe_reports_a_missing_helper_and_builds_nothing(backend, monkeypatch, tmp_path):
    monkeypatch.setattr(macos_se, "sys", types.SimpleNamespace(platform="darwin"))
    monkeypatch.delenv("IRONDOME_SE_HELPER", raising=False)
    _no_side_effects(monkeypatch, compiler=None)  # no build, no process, no compiler lookup unless allowed below
    monkeypatch.setattr(macos_se, "_find_swiftc", lambda: None)
    probe = backend.passive_probe()
    assert (probe.available, probe.hardware) == (False, True)
    assert probe.detail == (
        "Secure Enclave support needs the Xcode Command Line Tools to compile its helper. Run: xcode-select --install"
    )
    monkeypatch.setattr(macos_se, "_find_swiftc", lambda: "/usr/bin/swiftc")
    assert backend.passive_probe().detail.startswith("not probed: the Secure Enclave helper is not compiled yet")
    monkeypatch.setenv("IRONDOME_SE_HELPER", str(tmp_path / "nowhere"))
    expected = f"IRONDOME_SE_HELPER points at {tmp_path / 'nowhere'}, which does not exist"
    assert backend.passive_probe().detail == expected
    assert not paths.helper_dir().exists()


def test_passive_probe_is_the_probe_itself_once_the_helper_is_there(standin, backend):
    assert backend.passive_probe() == backend.probe()
    assert backend.passive_probe().available is True and "info" in standin.calls()


def test_passive_probe_off_macos(backend, monkeypatch):
    monkeypatch.setattr(macos_se, "sys", types.SimpleNamespace(platform="linux"))
    _no_side_effects(monkeypatch)
    assert backend.passive_probe().detail == "not macOS"


# -- state files read as hostile input ---------------------------------------


def descriptor_for(ref: str = "ab" * 16, policy: str = POLICY_DEVICE) -> Dict[str, str]:
    return {"backend": "macos-se", "policy": policy, "ref": ref}


def write_state(descriptor: Dict[str, str], content: bytes) -> Path:
    path = state_file(descriptor)
    paths.ensure_dir(path.parent)
    path.write_bytes(content)
    return path


def good_state(**changes: object) -> bytes:
    state: Dict[str, object] = {
        "v": 1,
        "backend": "macos-se",
        "policy": POLICY_DEVICE,
        "key": FAKE_KEY,
        "peer": b64(macos_se._random_point()),
    }
    state.update(changes)
    return json.dumps(state).encode()


def test_a_missing_state_file_says_the_key_is_not_on_this_mac(backend):
    with pytest.raises(HardwareError, match="not on this Mac"):
        backend.unseal(descriptor_for(), auth=None, interactive=False, reason="test")
    assert backend.exists(descriptor_for()) is False


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not json at all",
        b"\xff\xfe\x00garbage",
        b"[" * 100_000,
        b'{"backend": "macos-se"',
        good_state(key="not base64 !!"),
        good_state(key=""),
        good_state(peer="not base64 !!"),
        good_state(peer=b64(b"\x04" + b"\x01" * 63)),
        good_state(peer=b64(b"\x04" + b"\x01" * 65)),
        good_state() + b" " * (64 * 1024),
    ],
    ids=[
        "empty", "garbage", "not-utf8", "deeply-nested", "truncated", "key-not-base64", "key-empty",
        "peer-not-base64", "peer-too-short", "peer-too-long", "oversized",
    ],
)
def test_a_damaged_state_file_is_a_hardware_error(backend, content):
    descriptor = descriptor_for()
    write_state(descriptor, content)
    with pytest.raises(HardwareError, match="damaged"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


@pytest.mark.parametrize(
    "content",
    [
        b"[]",
        b'"a string"',
        b"null",
        good_state(backend="software"),
        good_state(policy=POLICY_BIOMETRY),
        good_state(key=5),
        good_state(key=None),
        good_state(peer=["a"]),
    ],
    ids=["list", "string", "null", "other-backend", "other-policy", "key-number", "key-null", "peer-list"],
)
def test_a_state_file_for_something_else_is_a_hardware_error(backend, content):
    descriptor = descriptor_for()
    write_state(descriptor, content)
    with pytest.raises(HardwareError, match="does not match"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


def test_a_state_path_that_is_a_directory_is_a_hardware_error(backend):
    descriptor = descriptor_for()
    paths.ensure_dir(state_file(descriptor))
    with pytest.raises(HardwareError):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


def test_a_weaker_policy_in_the_vault_file_does_not_match_the_key_file(backend):
    """Editing the descriptor from biometry to device must not make the key silent."""
    descriptor = descriptor_for(policy=POLICY_BIOMETRY)
    write_state(descriptor, good_state(policy=POLICY_BIOMETRY))
    tampered = dict(descriptor, policy=POLICY_DEVICE)
    with pytest.raises(HardwareError, match="does not match"):
        backend.unseal(tampered, auth=None, interactive=False, reason="test")


@pytest.mark.parametrize(
    "ref",
    [
        "../../etc/passwd", "..", "a" * 31, "a" * 33, "A" * 32, "g" * 32, "a" * 32 + "\n",
        "a" * 16 + "/" + "a" * 15, "", 7,
    ],
)
def test_a_reference_cannot_leave_the_device_directory(backend, ref):
    descriptor = {"backend": "macos-se", "policy": POLICY_DEVICE, "ref": ref}
    for call in (
        lambda: backend.unseal(descriptor, auth=None, interactive=False, reason="test"),
        lambda: backend.exists(descriptor),
        lambda: backend.destroy(descriptor),
    ):
        with pytest.raises((VaultError, HardwareError)):
            call()


@pytest.mark.parametrize(
    "descriptor",
    [None, [], "macos-se", {}, {"backend": "software", "policy": "device", "ref": "ab" * 16},
     {"backend": "macos-se", "policy": "none", "ref": "ab" * 16}, {"backend": "macos-se", "policy": "device"}],
)
def test_malformed_descriptors_are_refused(backend, descriptor):
    with pytest.raises((VaultError, HardwareError)):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


# -- destroying --------------------------------------------------------------


def test_destroy_removes_the_state_file(standin, backend):
    descriptor = enrolled(backend)
    assert backend.exists(descriptor)
    backend.destroy(descriptor)
    assert not backend.exists(descriptor)
    assert not state_file(descriptor).exists()
    backend.destroy(descriptor)  # nothing left: not an error
    with pytest.raises(HardwareError, match="not on this Mac"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


def test_destroy_all_takes_every_key_of_this_backend_and_nothing_else(standin, backend):
    first, second = enrolled(backend), enrolled(backend)
    device_dir = paths.device_dir()
    other = device_dir / ("cd" * 16 + ".json")
    other.write_text(json.dumps({"backend": "linux-tpm2", "policy": "device"}))
    software_key = device_dir / ("ef" * 16 + ".key")
    software_key.write_bytes(b"k" * 32)
    assert backend.destroy_all() == 2
    assert not backend.exists(first) and not backend.exists(second)
    assert other.exists() and software_key.exists()
    assert backend.destroy_all() == 0


def test_destroy_all_takes_damaged_state_files_too(standin, backend):
    """A file that no longer parses may still hold an intact key blob."""
    descriptor = enrolled(backend)
    path = state_file(descriptor)
    path.write_bytes(path.read_bytes() + b"trailing garbage")
    truncated = paths.device_dir() / ("12" * 16 + ".json")
    truncated.write_bytes(b'{"backend": "macos-se", "key": "QUJD')
    assert backend.destroy_all() == 2
    assert list(paths.device_dir().glob("*.json")) == []


def test_destroy_all_leaves_files_that_are_not_named_like_its_own(standin, backend):
    """Another backend's bookkeeping, damaged or not, is that backend's to deal with."""
    enrolled(backend)
    device_dir = paths.device_dir()
    registry = device_dir / "tpm2-nv-indices.json"
    registry.write_bytes(b"damaged beyond parsing {{{")
    notes = device_dir / "notes.json"
    notes.write_text(json.dumps({"backend": "macos-se", "key": "QUJD"}))
    upper = device_dir / ("AB" * 16 + ".json")
    upper.write_bytes(b"not json")
    assert backend.destroy_all() == 1
    assert sorted(item.name for item in device_dir.glob("*.json")) == sorted([registry.name, notes.name, upper.name])
    assert registry.read_bytes() == b"damaged beyond parsing {{{"


def test_destroy_all_goes_on_past_a_file_it_cannot_remove(standin, backend, monkeypatch):
    refs = sorted(enrolled(backend)["ref"] for _ in range(3))
    stubborn = paths.device_dir() / f"{refs[0]}.json"
    real_delete = paths.secure_delete

    def delete(path):
        if Path(path) == stubborn:
            raise PermissionError(1, "Operation not permitted")
        real_delete(path)

    monkeypatch.setattr(paths, "secure_delete", delete)
    with pytest.raises(HardwareError, match=refs[0]):
        backend.destroy_all()
    assert sorted(p.name for p in paths.device_dir().glob("*.json")) == [stubborn.name]


def test_destroy_all_without_a_device_directory(backend):
    assert not paths.device_dir().exists()
    assert backend.destroy_all() == 0


def test_destroy_reports_a_file_that_survives(standin, backend, monkeypatch):
    descriptor = enrolled(backend)
    monkeypatch.setattr(paths, "secure_delete", lambda path: None)
    with pytest.raises(HardwareError, match="still present"):
        backend.destroy(descriptor)


# -- the random peer point ---------------------------------------------------


def test_random_points_are_valid_distinct_and_uncompressed():
    points = [macos_se._random_point() for _ in range(64)]
    assert len(set(points)) == 64
    for point in points:
        assert len(point) == 65 and point[0] == 4
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        numbers = public.public_numbers()
        assert numbers.y % 2 == 0  # decompressed from the even-y encoding
        assert uncompressed(public) == point


def test_a_random_point_works_as_an_ecdh_peer():
    private = ec.generate_private_key(ec.SECP256R1())
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), macos_se._random_point())
    assert len(private.exchange(ec.ECDH(), peer)) == 32


def test_backend_declares_what_it_can_enforce(backend):
    assert backend.name == "macos-se" and backend.hardware is True
    assert backend.supports(POLICY_DEVICE) and backend.supports(POLICY_BIOMETRY) and backend.supports(POLICY_PRESENCE)
    assert not backend.supports("psychic")


# ---------------------------------------------------------------------------
# Real hardware
# ---------------------------------------------------------------------------


def run_helper(*arguments: str, request: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    """Run the real helper the way the backend does, never in interactive mode."""
    assert "--interactive" not in arguments
    return subprocess.run(
        [os.environ["IRONDOME_SE_HELPER"], *arguments],
        input=json.dumps(request).encode() if request is not None else None,
        stdin=subprocess.DEVNULL if request is None else None,
        capture_output=True,
        timeout=30,
        env=macos_se._clean_env(),
    )


def failure_code(result: subprocess.CompletedProcess) -> str:
    try:
        return str(json.loads(result.stderr.decode().strip().splitlines()[-1]).get("error", ""))
    except (ValueError, IndexError):
        return ""


@pytest.fixture
def enclave(secure_enclave) -> SecureEnclaveBackend:
    """The real backend, when it can make keys right now.

    Device keys are AfterFirstUnlockThisDeviceOnly and finger keys
    WhenUnlockedThisDeviceOnly, so before the first unlock after a restart (and,
    for finger keys, while the screen is locked) the Secure Enclave refuses them.
    That is a property of the machine's state, not a failure of the code under test.
    """
    result = run_helper("create", POLICY_DEVICE)
    if result.returncode == 3 and failure_code(result) == "device_locked":
        pytest.skip("this Mac is locked: the Secure Enclave makes and uses keys only while the screen is unlocked")
    assert result.returncode == 0, result.stderr.decode()
    return secure_enclave


def test_real_probe(secure_enclave):
    probe = secure_enclave.probe()
    assert probe.available is True and probe.hardware is True and probe.name == "macos-se"
    info = secure_enclave.info()
    assert info["secure_enclave"] is True and info["protocol"] == 1
    assert isinstance(info["biometry_usable"], bool)


def test_real_helper_is_owner_only_and_cached_by_source_hash(secure_enclave):
    helper = Path(os.environ["IRONDOME_SE_HELPER"])
    mode = stat.S_IMODE(helper.stat().st_mode)
    assert mode & 0o022 == 0 and mode & 0o100
    assert helper.stat().st_uid == os.getuid()
    assert helper.name.startswith("irondome-se-") and len(helper.name) == len("irondome-se-") + 16


def test_real_helper_rejects_bad_usage(secure_enclave):
    for arguments in ([], ["bogus"], ["create"], ["create", "psychic"], ["info", "extra"], ["agree", "--loud"]):
        result = run_helper(*arguments)
        assert result.returncode == 2, arguments
        assert result.stdout == b""
        assert failure_code(result) in ("usage", "bad_policy")


@pytest.mark.parametrize(
    "request_body",
    [b"", b"not json", b"[]", b'{"key": "QUJD"}', b'{"key": 5, "peer": "QUJD"}', b'{"key": "!!", "peer": "QUJD"}'],
)
def test_real_helper_rejects_malformed_requests(secure_enclave, request_body):
    result = subprocess.run(
        [os.environ["IRONDOME_SE_HELPER"], "agree"], input=request_body, capture_output=True, timeout=30,
        env=macos_se._clean_env(),
    )
    assert result.returncode == 2 and result.stdout == b""
    assert failure_code(result) == "bad_request"


def test_real_helper_rejects_a_peer_that_is_not_on_the_curve(enclave):
    created = json.loads(run_helper("create", POLICY_DEVICE).stdout)
    for peer in (b"\x04" + b"\x01" * 64, b"\x04" + b"\x00" * 64, b"\x02" + b"\x01" * 32, b"", b"\x04"):
        result = run_helper("agree", request={"key": created["key"], "peer": b64(peer), "reason": "test"})
        assert result.returncode == 2 and result.stdout == b"", peer
        assert failure_code(result) == "bad_peer"


def test_real_enroll_and_unseal_give_the_same_secret(enclave):
    descriptor, secret = enclave.enroll(policy=POLICY_DEVICE, auth=None, reason="run the IronDome test suite")
    with secret:
        first = bytes(secret.view())
    assert len(first) == DEVICE_SECRET_LEN == 32 and first != bytes(32)
    assert descriptor["backend"] == "macos-se" and descriptor["policy"] == POLICY_DEVICE
    for _ in range(2):
        with enclave.unseal(descriptor, auth=None, interactive=False, reason="run the IronDome test suite") as again:
            assert bytes(again.view()) == first
    path = state_file(descriptor)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert first not in path.read_bytes() and b64(first).encode() not in path.read_bytes()


def test_real_enrolments_are_independent(enclave):
    secrets = set()
    for _ in range(3):
        descriptor, secret = enclave.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
        with secret:
            secrets.add(bytes(secret.view()))
    assert len(secrets) == 3


def test_real_secret_is_an_ecdh_agreement_with_the_enclave_key(enclave):
    """What the chip returns equals ECDH computed in software against its public key."""
    created = json.loads(run_helper("create", POLICY_DEVICE).stdout)
    enclave_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), base64.b64decode(created["public_key"])
    )
    for _ in range(3):
        ours = ec.generate_private_key(ec.SECP256R1())
        expected = ours.exchange(ec.ECDH(), enclave_public)
        peer = b64(uncompressed(ours.public_key()))
        result = run_helper("agree", request={"key": created["key"], "peer": peer, "reason": "test"})
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout == expected and len(result.stdout) == 32
        with enclave._agree(created["key"], peer, interactive=False, reason="test") as through_backend:
            assert bytes(through_backend.view()) == expected


def test_real_same_key_and_peer_always_agree_on_the_same_secret(enclave):
    created = json.loads(run_helper("create", POLICY_DEVICE).stdout)
    request = {"key": created["key"], "peer": b64(macos_se._random_point()), "reason": "test"}
    outputs = {run_helper("agree", request=request).stdout for _ in range(3)}
    assert len(outputs) == 1 and len(outputs.pop()) == 32
    other = dict(request, peer=b64(macos_se._random_point()))
    assert run_helper("agree", request=other).stdout != run_helper("agree", request=request).stdout


@pytest.mark.parametrize("policy", [POLICY_BIOMETRY, POLICY_PRESENCE])
def test_real_key_under_a_user_policy_refuses_to_work_without_the_user(enclave, policy):
    """The proof that the fingerprint is enforced by the chip, not by this program.

    A key created with a biometric (or presence) access control is asked for
    a key agreement with user interaction forbidden. The Secure Enclave
    answers "authentication required" and produces no secret.
    """
    if policy == POLICY_BIOMETRY and not enclave.info().get("biometry_usable"):
        pytest.skip("no enrolled fingerprint: the Secure Enclave will not create a biometric key")
    created = run_helper("create", policy)
    assert created.returncode == 0, created.stderr.decode()
    key = json.loads(created.stdout)["key"]
    peer = b64(macos_se._random_point())

    result = run_helper("agree", request={"key": key, "peer": peer, "reason": "run the IronDome test suite"})
    assert result.returncode == 4, result.stderr.decode()
    assert result.stdout == b""
    assert failure_code(result) == "interaction_required"

    with pytest.raises(AuthError, match="Touch ID is required"):
        enclave._agree(key, peer, interactive=False, reason="run the IronDome test suite")

    descriptor = descriptor_for("9f" * 16, policy)
    state = {"v": 1, "backend": "macos-se", "policy": policy, "key": key, "peer": peer}
    write_state(descriptor, json.dumps(state).encode())
    with pytest.raises(AuthError, match="Touch ID is required"):
        enclave.unseal(descriptor, auth=None, interactive=False, reason="run the IronDome test suite")


def test_real_silent_key_needs_no_user(enclave):
    """The control for the test above: the same request against a device-policy key succeeds."""
    key = json.loads(run_helper("create", POLICY_DEVICE).stdout)["key"]
    result = run_helper("agree", request={"key": key, "peer": b64(macos_se._random_point()), "reason": "test"})
    assert result.returncode == 0 and len(result.stdout) == 32


def test_real_blob_from_another_machine_is_rejected(enclave):
    descriptor, secret = enclave.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    secret.wipe()
    path = state_file(descriptor)
    state = json.loads(path.read_text())
    real_blob = base64.b64decode(state["key"])
    flipped = bytearray(real_blob)
    flipped[len(flipped) // 2] ^= 0x01
    for foreign in (os.urandom(len(real_blob)), os.urandom(64), real_blob[:-1], bytes(flipped)):
        path.write_text(json.dumps(dict(state, key=b64(foreign))))
        with pytest.raises(HardwareError, match="does not accept this device key.*irondome recovery use"):
            enclave.unseal(descriptor, auth=None, interactive=False, reason="test")
    path.write_text(json.dumps(state))
    enclave.unseal(descriptor, auth=None, interactive=False, reason="test").wipe()


def test_real_changed_peer_changes_the_secret(enclave):
    descriptor, secret = enclave.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    with secret:
        original = bytes(secret.view())
    path = state_file(descriptor)
    state = json.loads(path.read_text())
    path.write_text(json.dumps(dict(state, peer=b64(macos_se._random_point()))))
    with enclave.unseal(descriptor, auth=None, interactive=False, reason="test") as changed:
        assert bytes(changed.view()) != original
    path.write_text(json.dumps(dict(state, peer=b64(b"\x04" + b"\x01" * 64))))
    with pytest.raises(HardwareError):
        enclave.unseal(descriptor, auth=None, interactive=False, reason="test")


def test_real_destroy_and_destroy_all(enclave):
    kept, kept_secret = enclave.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    gone, gone_secret = enclave.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    kept_secret.wipe()
    gone_secret.wipe()
    enclave.destroy(gone)
    assert not enclave.exists(gone) and enclave.exists(kept)
    with pytest.raises(HardwareError, match="not on this Mac"):
        enclave.unseal(gone, auth=None, interactive=False, reason="test")
    enclave.unseal(kept, auth=None, interactive=False, reason="test").wipe()
    assert enclave.destroy_all() == 1
    assert not enclave.exists(kept)
    assert list(paths.device_dir().glob("*.json")) == []


def test_real_vault_opens_only_with_its_own_enclave_key(enclave, make_vault):
    """End to end: a password vault on the Secure Enclave, then the same file without its key."""
    from conftest import PASSWORD, secret
    from irondome.unlock import open_vault

    vault, _ = make_vault(with_recovery=False)
    assert [slot.backend_name for slot in vault.file.slots] == ["macos-se"]
    descriptor = vault.file.slots[0].device
    vault.close()
    with secret(PASSWORD) as password:
        open_vault(password=password, interactive=False).close()
    with secret("the wrong password") as password, pytest.raises(AuthError, match="wrong master password"):
        open_vault(password=password, interactive=False)
    enclave.destroy(descriptor)
    with secret(PASSWORD) as password, pytest.raises(HardwareError, match="not on this Mac"):
        open_vault(password=password, interactive=False)


def test_real_locked_mac_is_reported_plainly(secure_enclave):
    """Runs only while the screen is locked: the refusal must say why."""
    result = run_helper("create", POLICY_DEVICE)
    if not (result.returncode == 3 and failure_code(result) == "device_locked"):
        pytest.skip("this Mac is unlocked")
    with pytest.raises(HardwareError, match="locked"):
        secure_enclave.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    assert list(paths.device_dir().glob("*.json")) == []


def test_python_interpreter_is_not_the_helper():
    """Guard for this file: the stand-in fixture must never leak into the real-hardware tests."""
    assert macos_se.sys is sys
