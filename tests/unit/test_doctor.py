"""doctor: one report of this machine and this installation, built without changing anything."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import pytest

import irondome
from irondome import caps, doctor, paths
from irondome import device as devices
from irondome.device.base import Probe
from irondome.errors import UsageError

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")
mac_only = pytest.mark.skipif(sys.platform != "darwin", reason="the Secure Enclave helper exists on macOS only")

TOP_KEYS = {
    "irondome", "python", "cryptography", "openssl", "platform", "backends", "new_vault_backend",
    "secure_enclave_helper", "bunker", "bunkers", "paths", "vault", "sessions", "permissions", "memory",
    "clipboard", "tpm", "legacy_vault", "findings", "problems",
}


def findings(report: Dict[str, Any], severity: str, check: str = "") -> List[Dict[str, str]]:
    return [
        item for item in report["findings"] if item["severity"] == severity and (not check or item["check"] == check)
    ]


def tree(*roots: Path) -> Dict[str, Tuple[int, str]]:
    """Every path under *roots*: mode and content digest."""
    state: Dict[str, Tuple[int, str]] = {}
    for root in roots:
        if not root.exists():
            continue
        for current, directories, files in os.walk(root):
            for name in directories + files:
                path = Path(current) / name
                info = path.lstat()
                digest = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else ""
                state[str(path)] = (info.st_mode, digest)
    return state


@pytest.fixture
def report_of() -> Callable[[], Dict[str, Any]]:
    def run() -> Dict[str, Any]:
        report = doctor.collect()
        json.dumps(report)  # what `doctor --json` prints must always serialise
        return report

    return run


def test_report_shape(report_of: Callable[[], Dict[str, Any]]) -> None:
    report = report_of()
    assert set(report) == TOP_KEYS
    assert report["irondome"] == irondome.__version__
    assert report["openssl"].startswith(("OpenSSL", "LibreSSL", "BoringSSL", "unknown"))
    assert [item["name"] for item in report["backends"]] == devices.backend_names()
    for item in report["backends"]:
        assert set(item) == {"name", "available", "hardware", "biometry", "probed", "detail"}
    for item in report["findings"]:
        assert set(item) == {"severity", "check", "message", "remedy"}
        assert item["severity"] in doctor.SEVERITIES
        assert item["remedy"] or item["severity"] in ("ok", "note")
    assert report["bunker"] == paths.FIRST_BUNKER
    assert report["new_vault_backend"] == "software"  # the suite forces the file backend
    assert set(report["memory"]) == {"locking", "core_dumps_disabled", "dumpable"}
    assert report["problems"] == len(findings(report, "problem"))


def test_versions() -> None:
    import cryptography

    found = doctor.versions()
    assert set(found) == {"irondome", "python", "cryptography", "openssl"}
    assert found["cryptography"] == cryptography.__version__


def test_no_vault_is_a_note_with_a_remedy(report_of: Callable[[], Dict[str, Any]]) -> None:
    report = report_of()
    assert report["vault"]["present"] is False
    (note,) = findings(report, "note", "vault")
    assert "bunker alpha" in note["message"] and note["remedy"] == "create one with: irondome init"
    assert not doctor.has_problem(report)


def test_second_bunker_is_named(monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]) -> None:
    monkeypatch.setenv(paths.ENV_BUNKER, "bravo")
    (note,) = findings(report_of(), "note", "vault")
    assert "bunker bravo" in note["message"] and "--bunker bravo" in note["remedy"]


def test_vault_keyslots_and_device_keys(make_vault: Any, report_of: Callable[[], Dict[str, Any]]) -> None:
    vault, _ = make_vault()
    report = report_of()
    state = report["vault"]
    assert state["present"] and state["readable"] and state["generation"] == vault.file.generation
    assert [slot["kind"] for slot in state["keyslots"]] == ["password", "recovery"]
    password, recovery = state["keyslots"]
    assert (password["backend"], password["device_key_present"]) == ("software", True)
    assert recovery["device_key_present"] is None
    assert findings(report, "ok", "device-keys")
    assert not findings(report, "note", "recovery")
    assert not doctor.has_problem(report)


def test_missing_device_key_is_a_problem(make_vault: Any, report_of: Callable[[], Dict[str, Any]]) -> None:
    make_vault()
    for key in paths.device_dir().glob("*.key"):
        key.unlink()
    report = report_of()
    assert report["vault"]["keyslots"][0]["device_key_present"] is False
    (problem,) = findings(report, "problem", "device-keys")
    assert "recovery key" in problem["remedy"]
    assert doctor.has_problem(report)


def test_damaged_vault_is_a_problem(make_vault: Any, report_of: Callable[[], Dict[str, Any]]) -> None:
    make_vault()
    paths.vault_file().write_bytes(b"{ not a vault")
    report = report_of()
    assert report["vault"]["readable"] is False and report["vault"]["error"]
    assert findings(report, "problem", "vault")


def test_no_recovery_key_is_a_note(make_vault: Any, report_of: Callable[[], Dict[str, Any]]) -> None:
    make_vault(with_recovery=False)
    (note,) = findings(report_of(), "note", "recovery")
    assert note["remedy"] == "add one with: irondome recovery"


@posix_only
def test_loose_modes_on_the_vault_side_are_warnings(make_vault: Any, report_of: Callable[[], Dict[str, Any]]) -> None:
    make_vault()
    os.chmod(paths.home(), 0o755)  # noqa: S103 - the loose mode is what is being checked
    os.chmod(paths.vault_file(), 0o644)
    report = report_of()
    loose = {item["path"]: item for item in report["permissions"]["loose"]}
    assert loose[str(paths.home())]["mode"] == "0755" and loose[str(paths.home())]["expected"] == "0700"
    assert loose[str(paths.vault_file())]["severity"] == "warning"
    remedies = {item["remedy"] for item in findings(report, "warning", "permissions")}
    assert f"chmod 600 {paths.vault_file()}" in remedies and f"chmod 700 {paths.home()}" in remedies
    assert not doctor.has_problem(report)
    assert stat.S_IMODE(os.stat(paths.vault_file()).st_mode) == 0o644  # reported, not changed


@posix_only
def test_loose_modes_on_the_device_side_are_problems(make_vault: Any, report_of: Callable[[], Dict[str, Any]]) -> None:
    make_vault()
    (key,) = paths.device_dir().glob("*.key")
    os.chmod(key, 0o644)
    report = report_of()
    (problem,) = findings(report, "problem", "permissions")
    assert str(key) in problem["message"]
    assert doctor.has_problem(report)


@posix_only
def test_anything_writable_by_others_is_a_problem(make_vault: Any, report_of: Callable[[], Dict[str, Any]]) -> None:
    make_vault()
    os.chmod(paths.vault_file(), 0o662)  # noqa: S103 - the loose mode is what is being checked
    (problem,) = findings(report_of(), "problem", "permissions")
    assert "writable by other users" in problem["message"]


def test_doctor_changes_nothing(make_vault: Any, report_of: Callable[[], Dict[str, Any]], isolated: Path) -> None:
    vault, _ = make_vault()
    caps.create_session(vault, ttl=600)
    before = tree(isolated)
    report_of()
    report_of()
    assert tree(isolated) == before


@mac_only
def test_the_secure_enclave_helper_is_never_compiled(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    from irondome.device import macos_se

    def refuse(*args: Any, **kwargs: Any) -> Path:
        raise AssertionError("doctor started a compilation")

    monkeypatch.setattr(macos_se, "build_helper", refuse)
    report = report_of()
    (enclave,) = [item for item in report["backends"] if item["name"] == "macos-se"]
    assert enclave["probed"] is False and enclave["available"] is False
    helper = report["secure_enclave_helper"]
    assert helper["built"] is False and helper["from_environment"] is False
    assert helper["source_sha256"] == hashlib.sha256(macos_se.helper_source().read_bytes()).hexdigest()
    assert not paths.helper_dir().exists()


@mac_only
def test_a_compiled_helper_is_probed(monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]) -> None:
    from irondome.device import macos_se

    helper = macos_se._helper_path()
    paths.ensure_dir(helper.parent)
    helper.write_bytes(b"#!/bin/sh\n")
    backend = devices.get_backend("macos-se")
    monkeypatch.setattr(backend, "probe", lambda: Probe("macos-se", True, True, True, "Secure Enclave with Touch ID"))
    monkeypatch.delenv("IRONDOME_DEVICE_BACKEND")
    report = report_of()
    (enclave,) = [item for item in report["backends"] if item["name"] == "macos-se"]
    assert enclave["probed"] and enclave["available"] and enclave["biometry"]
    assert report["secure_enclave_helper"]["built"] is True
    assert report["new_vault_backend"] == "macos-se"


def test_unprobed_enclave_leaves_the_new_vault_backend_unknown(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    monkeypatch.delenv("IRONDOME_DEVICE_BACKEND")
    report = report_of()
    if sys.platform == "darwin" and report["secure_enclave_helper"]["compiler"]:
        assert report["new_vault_backend"] is None  # the enclave may well be there: no guess past it
    else:
        assert report["new_vault_backend"] in devices.backend_names()


@mac_only
def test_without_the_tools_to_build_the_helper_new_vaults_use_the_file_and_doctor_says_why(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    from irondome.device import macos_se

    real = macos_se.helper_status

    def no_compiler() -> Dict[str, Any]:
        status = dict(real())
        status.update(built=False, compiler=False)
        return status

    monkeypatch.setattr(macos_se, "helper_status", no_compiler)
    monkeypatch.delenv("IRONDOME_DEVICE_BACKEND")
    report = report_of()
    (enclave,) = [item for item in report["backends"] if item["name"] == "macos-se"]
    assert enclave["probed"] is False and "xcode-select --install" in enclave["detail"]
    assert report["new_vault_backend"] == "software", "nothing here could build the helper: no guess is needed"
    (warning,) = findings(report, "warning", "device-backend")
    assert warning["message"].startswith("no security chip would hold a new vault's device key: macos-se: ")
    assert warning["remedy"] == f"a chip needs {devices.chip_requirements()}"


def _tpm_in_use(monkeypatch: pytest.MonkeyPatch, status: Dict[str, Any]) -> None:
    backend = devices.get_backend("linux-tpm2")
    monkeypatch.setattr(backend, "probe", lambda: Probe("linux-tpm2", True, True, False, "TPM 2.0 (test)"))
    monkeypatch.setattr(backend, "lockout_status", lambda: dict(status))
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "linux-tpm2")


HEALTHY_TPM = {
    "max_tries": 32, "failed_tries": 0, "remaining_tries": 32, "recovery_seconds": 600,
    "lockout_recovery_seconds": 86400, "in_lockout": False, "seconds_until_retry": 0, "lockout_auth_set": True,
}


@pytest.mark.parametrize(
    "change, severity, words",
    [
        ({}, "ok", "32 more wrong passwords"),
        ({"in_lockout": True, "failed_tries": 32, "remaining_tries": 0, "seconds_until_retry": 600}, "problem",
         "lockout"),
        ({"failed_tries": 30, "remaining_tries": 2}, "warning", "only 2 more"),
        ({"recovery_seconds": 0}, "warning", "switched off"),
        ({"lockout_auth_set": False}, "note", "lockout authorisation is empty"),
    ],
)
def test_tpm_lockout_is_reported_when_the_tpm_is_in_use(
    monkeypatch: pytest.MonkeyPatch,
    report_of: Callable[[], Dict[str, Any]],
    change: Dict[str, Any],
    severity: str,
    words: str,
) -> None:
    _tpm_in_use(monkeypatch, {**HEALTHY_TPM, **change})
    report = report_of()
    assert report["new_vault_backend"] == "linux-tpm2"
    assert report["tpm"]["lockout"]["max_tries"] == 32
    assert any(words in item["message"] for item in findings(report, severity, "tpm"))


def test_tpm_is_not_asked_when_it_is_not_in_use(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    backend = devices.get_backend("linux-tpm2")

    def refuse() -> Dict[str, Any]:
        raise AssertionError("the TPM was queried")

    monkeypatch.setattr(backend, "lockout_status", refuse)
    assert report_of()["tpm"] is None


def test_forced_backend_that_is_missing_is_a_problem(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    backend = devices.get_backend("linux-tpm2")
    monkeypatch.setattr(backend, "probe", lambda: Probe("linux-tpm2", False, True, False, "no TPM here"))
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "linux-tpm2")
    report = report_of()
    assert report["new_vault_backend"] is None
    (problem,) = findings(report, "problem", "device-backend")
    assert "no TPM here" in problem["message"]


def test_memory_locking_refused_is_a_warning(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    class Unlocked:
        locked = False

        def __init__(self, size: int) -> None:
            self.size = size

        def __enter__(self) -> "Unlocked":
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    monkeypatch.setattr(doctor, "SecureBuffer", Unlocked)
    report = report_of()
    assert report["memory"]["locking"] is False
    assert findings(report, "warning", "memory")


@posix_only
def test_core_dumps_allowed_is_a_warning(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    import resource

    monkeypatch.setattr(resource, "getrlimit", lambda which: (1 << 20, 1 << 20))
    monkeypatch.setenv("IRONDOME_DEBUG", "1")
    report = report_of()
    assert report["memory"]["core_dumps_disabled"] is False
    (warning,) = findings(report, "warning", "core-dumps")
    assert "IRONDOME_DEBUG=1" in warning["message"]


def test_no_clipboard_tool_is_a_note(monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]) -> None:
    from irondome import clipboard

    def missing() -> Any:
        raise UsageError("cannot copy to the clipboard: no clipboard tool was found")

    monkeypatch.setattr(clipboard, "tools", missing)
    report = report_of()
    assert report["clipboard"] == {"tool": None, "reader": None}
    (note,) = findings(report, "note", "clipboard")
    assert "no clipboard tool was found" in note["message"]


def test_clipboard_reports_the_tools_copy_would_use(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    from irondome import clipboard

    monkeypatch.setattr(clipboard, "tools", lambda: ("wl-copy", "/usr/bin/wl-copy", "/usr/bin/wl-paste"))
    assert report_of()["clipboard"] == {"tool": "/usr/bin/wl-copy", "reader": "/usr/bin/wl-paste"}


def test_doctor_uses_only_the_public_clipboard_and_enclave_helper_interfaces(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    """clipboard.tools() and macos_se.helper_status() are the contract; their private helpers may change."""
    from irondome import clipboard
    from irondome.device import macos_se

    def private(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("doctor called a private helper")

    for module, name in ((clipboard, "_find_tool"), (macos_se, "_helper_path"), (macos_se, "_find_swiftc"),
                         (macos_se, "build_helper")):
        monkeypatch.setattr(module, name, private)
    monkeypatch.setattr(clipboard, "tools", lambda: ("pbcopy", "/usr/bin/pbcopy", "/usr/bin/pbpaste"))
    status = {"source": "/x/irondome_se.swift", "source_sha256": "ab" * 32, "path": "/x/helper", "built": False,
              "from_environment": False, "compiler": False, "error": None}
    monkeypatch.setattr(macos_se, "helper_status", lambda: dict(status))
    report = report_of()
    assert report["clipboard"] == {"tool": "/usr/bin/pbcopy", "reader": "/usr/bin/pbpaste"}
    if sys.platform == "darwin":
        assert report["secure_enclave_helper"] == {key: status[key] for key in status if key != "error"}
        (warning,) = findings(report, "warning", "secure-enclave-helper")
        assert "xcode-select --install" in warning["remedy"]
    else:
        assert report["secure_enclave_helper"] is None


@mac_only
def test_an_unreadable_helper_source_is_a_problem(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    from irondome.device import macos_se

    monkeypatch.setattr(macos_se, "helper_source", lambda: Path("/nonexistent/irondome_se.swift"))
    report = report_of()
    helper = report["secure_enclave_helper"]
    assert (helper["source_sha256"], helper["path"], helper["built"]) == (None, None, False)
    (problem,) = findings(report, "problem", "secure-enclave-helper")
    assert "cannot be read" in problem["message"] and problem["remedy"] == "reinstall IronDome"


def test_legacy_vault_is_noticed(report_of: Callable[[], Dict[str, Any]]) -> None:
    secrets_dir = paths.legacy_v3_dir() / "secrets"
    secrets_dir.mkdir(parents=True)
    (secrets_dir / "salt.bin").write_bytes(os.urandom(16))
    report = report_of()
    assert report["legacy_vault"]["present"] is True
    (note,) = findings(report, "note", "legacy-vault")
    assert note["remedy"] == "bring it over with: irondome migrate"


def test_damaged_legacy_vault_is_a_warning(report_of: Callable[[], Dict[str, Any]]) -> None:
    secrets_dir = paths.legacy_v3_dir() / "secrets"
    secrets_dir.mkdir(parents=True)
    (secrets_dir / "salt.bin").write_bytes(b"short")
    report = report_of()
    assert report["legacy_vault"]["error"]
    assert findings(report, "warning", "legacy-vault")


def test_invalid_default_bunker_is_a_problem(report_of: Callable[[], Dict[str, Any]]) -> None:
    paths.ensure_dir(paths.root())
    (paths.root() / "default-bunker").write_bytes(b"NOT A NAME\n")
    report = report_of()
    assert report["bunker"] is None and report["vault"] is None
    assert findings(report, "problem", "bunker")


def test_a_check_that_breaks_is_a_finding_not_a_crash(
    monkeypatch: pytest.MonkeyPatch, report_of: Callable[[], Dict[str, Any]]
) -> None:
    def broken(found: Any) -> Dict[str, Any]:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(doctor, "_clipboard", broken)
    report = report_of()
    assert report["clipboard"] is None
    (warning,) = findings(report, "warning", "clipboard")
    assert "could not run" in warning["message"]


def test_sessions_and_grants_are_counted(make_vault: Any, report_of: Callable[[], Dict[str, Any]]) -> None:
    from irondome.vault import Secret

    vault, _ = make_vault()
    vault.add("github", Secret(password="hunter2-Github!"))
    vault.commit()
    caps.create_session(vault, ttl=600)
    caps.create_grant(vault, ["github"], ttl=600)
    assert report_of()["sessions"] == {"sessions": 1, "grants": 1, "expired": 0}
