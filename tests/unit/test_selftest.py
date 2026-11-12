"""irondome.selftest and ``irondome verify``: the checks that run on a user's machine.

The suite runs them with the file-based backend (tests/conftest.py forces it).
What matters most here is where they work: only inside their own temporary
directory, whatever the environment points at.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Dict, Tuple

import pytest

from irondome import selftest
from irondome.cli import cmd_verify
from irondome.cli.context import Context
from irondome.cli.output import Output
from irondome.device.base import POLICY_BIOMETRY, DeviceBackend, Probe
from irondome.errors import AuthError, UsageError
from irondome.secmem import SecureBuffer

ENVIRONMENT = (
    "IRONDOME_HOME", "IRONDOME_DEVICE_DIR", "IRONDOME_LEGACY_DIR", "HOME", "XDG_STATE_HOME", "USERPROFILE",
    "IRONDOME_BUNKER", "IRONDOME_SESSION", "IRONDOME_GRANT", "IRONDOME_NO_TOUCH", "IRONDOME_KDF_MEMORY_MIB",
)


def snapshot(root: Path) -> Dict[str, Tuple[bytes, int, float]]:
    found = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        found[str(path)] = (path.read_bytes() if path.is_file() else b"", stat.S_IMODE(info.st_mode), info.st_mtime)
    return found


@pytest.fixture
def decoy(tmp_path, monkeypatch):
    """A real-looking IronDome installation that no check may touch, with every variable pointing at it."""
    root = tmp_path / "decoy"
    for sub in ("irondome/bunkers/alpha/caps", "device/bunkers/alpha", "legacy", "home"):
        (root / sub).mkdir(parents=True)
    (root / "irondome" / "bunkers" / "alpha" / "vault.irondome").write_bytes(b'{"format": "the user\'s real vault"}')
    (root / "irondome" / "bunkers" / "alpha" / "audit.log").write_bytes(b"the user's audit log\n")
    (root / "irondome" / "bunkers" / "alpha" / "caps" / ("ab" * 16 + ".json")).write_bytes(b"a grant of the user")
    (root / "device" / "bunkers" / "alpha" / ("cd" * 16 + ".key")).write_bytes(os.urandom(32))
    (root / "legacy" / "marker").write_text("the user's 3.x vault")
    (root / "home" / "marker").write_text("the user's home")
    monkeypatch.setenv("IRONDOME_HOME", str(root / "irondome"))
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", str(root / "device"))
    monkeypatch.setenv("IRONDOME_LEGACY_DIR", str(root / "legacy"))
    monkeypatch.setenv("HOME", str(root / "home"))
    monkeypatch.setenv("IRONDOME_BUNKER", "alpha")
    monkeypatch.setenv("IRONDOME_SESSION", "irondome_s_" + "ef" * 16 + "_" + "A" * 52)
    monkeypatch.setenv("IRONDOME_GRANT", "irondome_g_" + "ab" * 16 + "_" + "A" * 52)
    return root


def test_no_check_touches_anything_outside_its_temporary_directory(decoy, tmp_path):
    """Every check, against an environment that points at someone's real installation."""
    before = snapshot(decoy)
    environment = {name: os.environ.get(name) for name in ENVIRONMENT}
    report = selftest.run(root=tmp_path)
    assert snapshot(decoy) == before
    assert {name: os.environ.get(name) for name in ENVIRONMENT} == environment
    assert len(report.outcomes) == len(selftest.registry()["claims"])
    broken = [outcome for outcome in report.outcomes if "the check itself failed" in outcome.result.detail
              or "stopped before" in outcome.result.detail]
    assert broken == []
    assert [path for path in tmp_path.iterdir() if path.name.startswith("irondome-verify-")] == []


def test_a_check_that_reaches_outside_is_stopped_and_fails(decoy, tmp_path, monkeypatch):
    def escaping(box):
        with box.area("escape"):
            os.environ["IRONDOME_HOME"] = str(decoy / "irondome")
            box.guard()
            (decoy / "irondome" / "written-by-a-check").write_text("must never happen")
        return selftest.CheckResult(selftest.PASS, "escaped")

    before = snapshot(decoy)
    monkeypatch.setitem(selftest.CHECKS, "tamper_evident", escaping)
    report = selftest.run(["tamper-evident"], root=tmp_path)
    result = report.outcomes[0].result
    assert result.status == selftest.FAIL and "stopped before it could leave" in result.detail
    assert snapshot(decoy) == before
    assert os.environ["IRONDOME_HOME"] == str(decoy / "irondome")


def test_the_device_backend_is_only_ever_asked_from_inside_the_sandbox(decoy, tmp_path, monkeypatch):
    """A chip's probe compiles or runs the Secure Enclave helper under the device directory: never the user's.

    The suite's own backend is the file-based one, which is never probed; this
    stands in a chip for it. Asking it while building the report, after the
    last check, once compiled a helper into the user's device directory.
    """
    asked = []

    class Chip(FakeEnclave):
        def probe(self) -> Probe:
            asked.append(os.environ.get("IRONDOME_DEVICE_DIR", ""))
            return super().probe()

    before = snapshot(decoy)
    monkeypatch.setattr(selftest.devices, "choose_backend", lambda policy, preferred=None: Chip())
    monkeypatch.setitem(selftest.CHECKS, "tamper_evident", lambda box: selftest.CheckResult(selftest.PASS, "x"))
    report = selftest.run(["tamper-evident"], root=tmp_path)
    assert report.backend == "macos-se" and report.hardware is True
    assert asked and all(Path(where).is_relative_to(tmp_path) for where in asked), asked
    assert snapshot(decoy) == before


def test_inside_a_check_every_location_is_in_the_sandbox_and_tokens_are_gone(decoy, tmp_path):
    with selftest.Sandbox(root=tmp_path) as box:
        with box.area("probe") as base:
            from irondome import paths

            for location in (paths.root(), paths.device_root(), paths.home(), paths.device_dir(),
                             paths.legacy_v3_dir(), Path(os.environ["HOME"])):
                assert box.inside(location) and base in Path(os.path.realpath(location)).parents
            assert "IRONDOME_SESSION" not in os.environ and "IRONDOME_GRANT" not in os.environ
            assert os.environ["IRONDOME_NO_TOUCH"] == "1" and os.environ["IRONDOME_NO_PROMPT"] == "1"
            assert stat.S_IMODE(box.root.stat().st_mode) == 0o700
        root = box.root
    assert not root.exists()
    assert os.environ["IRONDOME_SESSION"].startswith("irondome_s_")


def test_the_guard_names_what_is_outside(tmp_path):
    with selftest.Sandbox(root=tmp_path) as box, box.area("guarded"):
        inside = os.environ["IRONDOME_LEGACY_DIR"]
        os.environ["IRONDOME_LEGACY_DIR"] = "/"
        try:
            with pytest.raises(selftest.SandboxError, match="3.x directory"):
                box.guard()
        finally:
            os.environ["IRONDOME_LEGACY_DIR"] = inside


def test_every_claim_is_reported_in_registry_order_and_unknown_claims_are_refused(tmp_path):
    with pytest.raises(UsageError, match="no claim is called no-such-claim"):
        selftest.run(["no-such-claim"], root=tmp_path)
    report = selftest.run(["migration", "tpm-rate-limit", "recovery"], root=tmp_path)
    assert [outcome.claim for outcome in report.outcomes] == ["tpm-rate-limit", "recovery", "migration"]
    assert [outcome.result.status for outcome in report.outcomes] == ["skipped", "pass", "skipped"]
    assert "test suite" in report.outcomes[0].result.detail
    assert report.backend == "software" and report.hardware is False


def test_hardware_claims_are_skipped_never_passed_on_the_file_based_backend(tmp_path):
    report = selftest.run(["key-in-hardware", "biometric-enforced-by-chip"], root=tmp_path)
    assert [outcome.result.status for outcome in report.outcomes] == ["skipped", "skipped"]
    assert report.outcomes[0].result.detail == selftest.NO_HARDWARE


@pytest.mark.parametrize("name", sorted(set(selftest.CHECKS) - {"keys_wiped", "grants_hold_no_keys"}))
def test_each_check_gives_a_verdict_with_a_reason(name, tmp_path):
    with selftest.Sandbox(root=tmp_path) as box:
        result = selftest.CHECKS[name](box)
    assert result.status in (selftest.PASS, selftest.FAIL, selftest.SKIPPED) and result.detail


class FakeEnclave(DeviceBackend):
    """A Secure Enclave stand-in: a biometric key works only when a prompt may be shown."""

    name = "macos-se"
    hardware = True
    policies = ("device", "biometry", "presence")

    def __init__(self) -> None:
        self.calls = []

    def probe(self) -> Probe:
        return Probe(self.name, True, True, True, "fake Secure Enclave with touchid")

    def info(self):
        return {"secure_enclave": True, "biometry_usable": True}

    def enroll(self, *, policy, auth, reason):
        silent = os.environ.get("IRONDOME_NO_TOUCH") == "1"
        self.calls.append((policy, silent))
        if policy == POLICY_BIOMETRY and silent:
            raise AuthError("Touch ID is required for this vault")
        return {"backend": self.name, "policy": policy, "ref": "ef" * 16}, SecureBuffer.random(32)

    def unseal(self, descriptor, *, auth, interactive, reason):
        raise AssertionError("not used")

    def destroy(self, descriptor):
        self.calls.append(("destroy", descriptor["policy"]))

    def exists(self, descriptor):
        return False

    def destroy_all(self):
        return 0


@pytest.mark.parametrize("touch", [False, True])
def test_the_biometric_check_proves_the_refusal_and_with_touch_the_acceptance(touch, tmp_path):
    fake = FakeEnclave()
    with selftest.Sandbox(touch=touch, root=tmp_path) as box:
        box.backend = fake
        result = selftest.check_biometric_enforced(box)
    assert result.status == selftest.PASS, result.detail
    assert (POLICY_BIOMETRY, True) in fake.calls  # the refusal: asked with no prompt allowed
    if touch:
        assert (POLICY_BIOMETRY, False) in fake.calls and "after one touch" in result.detail
    else:
        assert (POLICY_BIOMETRY, False) not in fake.calls and "--touch" in result.detail


def test_a_biometric_key_that_works_without_a_touch_is_a_failure(tmp_path):
    class Lenient(FakeEnclave):
        def enroll(self, *, policy, auth, reason):
            return {"backend": self.name, "policy": policy, "ref": "ef" * 16}, SecureBuffer.random(32)

    with selftest.Sandbox(root=tmp_path) as box:
        box.backend = Lenient()
        result = selftest.check_biometric_enforced(box)
    assert result.status == selftest.FAIL and "without a touch" in result.detail


def probe_document(**changes):
    clean = {
        "stats": {"whole_address_space": True, "truncated": False, "bytes_scanned": 1 << 30, "regions": 300},
        "needles": [
            {"label": "vault key", "kind": "key", "hits": [], "expected": None},
            {"label": "random key kept as bytes", "kind": "control-kept", "expected": 16,
             "hits": [{"address": 16, "where": "0x10 MALLOC_TINY rw-"}]},
        ],
    }
    clean.update(changes)
    control = {"needles": [{"label": "vault key kept as bytes", "kind": "control-kept", "expected": 32,
                            "hits": [{"address": 32, "where": "0x20 anonymous rw-"}]}]}
    return clean, control


def test_the_memory_verdict_passes_only_a_clean_scan_whose_controls_were_seen():
    clean, control = probe_document()
    assert selftest.evaluate_keys_probe(clean, control).status == selftest.PASS
    leaked = dict(clean, needles=[dict(clean["needles"][0], hits=[{"address": 8, "where": "0x8 [heap] rw-p"}]),
                                  clean["needles"][1]])
    verdict = selftest.evaluate_keys_probe(leaked, control)
    assert verdict.status == selftest.FAIL and "vault key" in verdict.detail and "[heap]" in verdict.detail
    blind = dict(clean, needles=[clean["needles"][0], dict(clean["needles"][1], hits=[])])
    assert "proves nothing" in selftest.evaluate_keys_probe(blind, control).detail
    partial, _ = probe_document(stats=dict(clean["stats"], whole_address_space=False))
    assert "whole address space" in selftest.evaluate_keys_probe(partial, control).detail


def test_on_macos_the_memory_verdict_does_not_rest_on_the_system_zeroing_freed_memory():
    """The third probe document, run with MallocZeroOnFree=0: a copy only it sees is still a failure."""
    clean, control = probe_document()
    assert "also with the system's zeroing" in selftest.evaluate_keys_probe(clean, control, clean).detail
    hidden = dict(clean, needles=[dict(clean["needles"][0], hits=[{"address": 8, "where": "0x8 MALLOC_TINY rw-"}]),
                                  clean["needles"][1]])
    verdict = selftest.evaluate_keys_probe(clean, control, hidden)
    assert verdict.status == selftest.FAIL and "MallocZeroOnFree=0" in verdict.detail and "vault key" in verdict.detail
    blind = dict(clean, needles=[clean["needles"][0], dict(clean["needles"][1], hits=[])])
    assert "proves nothing" in selftest.evaluate_keys_probe(clean, control, blind).detail


def test_the_memory_verdict_names_every_leftover_including_those_the_derivation_leaves():
    """The kdf run is searched right after Argon2id and HKDF; what it finds is reported with the rest."""
    clean, control = probe_document()
    derivation = dict(clean, needles=[{"label": "HKDF output", "kind": "key", "expected": None,
                                       "hits": [{"address": 64, "where": "0x40 anonymous rw-"}]}])
    verdict = selftest.evaluate_keys_probe(clean, control, None, derivation)
    assert verdict.status == selftest.FAIL and "right after Argon2id and HKDF" in verdict.detail
    assert "HKDF output" in verdict.detail
    leaked = dict(clean, needles=[dict(clean["needles"][0], hits=[{"address": 8, "where": "0x8 [heap] rw-p"}]),
                                  clean["needles"][1]])
    both = selftest.evaluate_keys_probe(leaked, control, None, derivation).detail
    assert "after the vault was locked" in both and "HKDF output" in both
    assert "none right after Argon2id and HKDF" in selftest.evaluate_keys_probe(clean, control, None, clean).detail


def test_the_import_check_finds_networking_and_computed_imports(tmp_path):
    package = tmp_path / "irondome"
    package.mkdir()
    (package / "fine.py").write_text("import os\nimport json\nfrom urllib.parse import quote\n")
    (package / "bad.py").write_text(
        "import socket\nfrom urllib.request import urlopen\nimport requests\nimport importlib\n"
        "importlib.import_module(name)\n__import__('http.client')\n"
    )
    found, problems = selftest.import_findings(package)
    assert "os" in found and "socket" in found
    text = "\n".join(problems)
    assert "irondome/bad.py imports socket, a networking module" in text
    assert "urllib.request" in text and "requests" in text
    assert "computed at run time" in text and "http.client dynamically" in text
    assert not [problem for problem in problems if "fine.py" in problem]


def test_the_probe_command_and_environment_are_minimal(tmp_path):
    command = selftest._probe_command("keys")
    assert command[1] == "-I" and command[-1] == "keys" and os.path.isabs(command[0])
    env = selftest._probe_environment(tmp_path, {"IRONDOME_SESSION": "x", "LD_PRELOAD": "/evil.so",
                                                 "IRONDOME_DEVICE_BACKEND": "software"})
    assert "IRONDOME_SESSION" not in env and "LD_PRELOAD" not in env
    assert env["PATH"] == "/usr/bin:/bin" and env["IRONDOME_DEVICE_BACKEND"] == "software"


# -- the command ------------------------------------------------------------------


def test_verify_prints_one_json_document_with_every_result(cli):
    result = cli("verify", "--claim", "tamper-evident", "--claim", "tpm-rate-limit", "--json")
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert set(report) == {"version", "python", "platform", "backend", "results", "passed", "failed", "skipped",
                           "notes"}
    assert [item["claim"] for item in report["results"]] == ["tpm-rate-limit", "tamper-evident"]
    assert set(report["results"][0]) == {"claim", "title", "check", "result", "detail", "seconds"}
    assert (report["passed"], report["failed"], report["skipped"]) == (1, 0, 1)
    assert "private temporary directory" in result.stderr


def test_verify_prints_a_table_of_claim_result_and_detail(cli):
    result = cli("verify", "--claim", "recovery")
    assert result.returncode == 0, result.stderr
    header, row = result.stdout.splitlines()[:2]
    assert header.split() == ["CLAIM", "RESULT", "DETAIL"]
    assert row.split()[:2] == ["recovery", "pass"]
    assert "1 claims on software" in result.stderr


def test_verify_refuses_an_unknown_claim_with_usage_status(cli):
    result = cli("verify", "--claim", "no-such-claim")
    assert result.returncode == 2 and "no claim is called no-such-claim" in result.stderr


def test_verify_exits_1_when_a_claim_does_not_hold(monkeypatch, capsys):
    failing = selftest.Report(
        outcomes=[selftest.Outcome("recovery", "t", "recovery", selftest.CheckResult(selftest.FAIL, "broken"), 0.1)],
        backend="software", hardware=False, backend_detail="file", notes=["a note"],
    )
    monkeypatch.setattr(selftest, "run", lambda claims, touch, progress: failing)
    args = argparse.Namespace(claims=["recovery"], touch=False, json=False)
    assert cmd_verify.verify(Context(args, Output()), args) == 1
    captured = capsys.readouterr()
    assert "recovery" in captured.out and "FAIL" in captured.out and "a note" in captured.err


def test_verify_leaves_the_users_own_vault_exactly_as_it_was(cli):
    from conftest import PASSWORD
    from irondome import paths

    assert cli("init", "--password-stdin", stdin=PASSWORD + "\n").returncode == 0
    before = snapshot(paths.root()) | snapshot(paths.device_root())
    result = cli("verify", "--claim", "crypto-erase", "--claim", "bunkers-isolated", "--claim", "owner-only-files")
    assert result.returncode == 0, result.stdout + result.stderr
    assert snapshot(paths.root()) | snapshot(paths.device_root()) == before


def test_verify_has_help_for_itself_and_its_option(cli):
    result = cli("verify", "--help")
    assert result.returncode == 0
    assert "--claim ID" in result.stdout and "never" in result.stdout and "--touch" in result.stdout
