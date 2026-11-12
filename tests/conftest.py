"""Shared fixtures.

Every test runs against throwaway directories. Nothing in this suite can reach
a real vault, a real device key or a real keychain: ``HOME`` and every IronDome
path are redirected per test, the device backend is forced to the file-based
one, and Touch ID prompts are switched off. Tests that drive real hardware opt
in through a marker and still keep their state in the temporary directories.

Markers
-------
``secure_enclave``  needs an Apple Secure Enclave; runs automatically on a Mac
                    that has one, skipped everywhere else
``tpm``             needs a TPM 2.0 reachable through tpm2-tools; enabled by
                    ``IRONDOME_TEST_TPM=1`` (see ``scripts/test-linux.sh``,
                    which starts a software TPM in a container)
``interactive``     needs a person at the sensor; ``IRONDOME_TEST_INTERACTIVE=1``
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

import pytest

PASSWORD = "correct horse battery staple"

_SUPPORT = Path(__file__).resolve().parent / "support"

# A safety net under the per-test isolation below. From the moment pytest
# imports this file, HOME and every IronDome location point into one
# session-wide scratch directory. Each test then gets its own directories on
# top of that; if a test ever drops its own redirection (monkeypatch.undo(),
# a subprocess with a scrubbed environment) it lands here, never in the real
# home directory of whoever is running the suite.
_SESSION_ROOT = Path(tempfile.mkdtemp(prefix="irondome-tests-"))
_SAFE_ENV = {
    "HOME": str(_SESSION_ROOT / "home"),
    "USERPROFILE": str(_SESSION_ROOT / "home"),
    "XDG_STATE_HOME": str(_SESSION_ROOT / "home" / ".local" / "state"),
    "IRONDOME_HOME": str(_SESSION_ROOT / "irondome"),
    "IRONDOME_DEVICE_DIR": str(_SESSION_ROOT / "device"),
    "IRONDOME_LEGACY_DIR": str(_SESSION_ROOT / "legacy"),
    "IRONDOME_DEVICE_BACKEND": "software",
    "IRONDOME_KDF_MEMORY_MIB": "19",
    "IRONDOME_NO_TOUCH": "1",
    "IRONDOME_NO_PROMPT": "1",
    "HYPOTHESIS_STORAGE_DIRECTORY": str(_SESSION_ROOT / "hypothesis"),
}
(_SESSION_ROOT / "home").mkdir()
os.environ.update(_SAFE_ENV)
atexit.register(shutil.rmtree, str(_SESSION_ROOT), True)

_SCRUB = (
    "IRONDOME_BUNKER",
    "IRONDOME_SESSION",
    "IRONDOME_GRANT",
    "IRONDOME_SE_HELPER",
    "IRONDOME_DEBUG",
    "IRONDOME_PASSWORD_FILE",
    "SSH_CONNECTION",
    "SSH_TTY",
)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "secure_enclave: needs an Apple Secure Enclave")
    config.addinivalue_line("markers", "tpm: needs a TPM 2.0 (IRONDOME_TEST_TPM=1)")
    config.addinivalue_line("markers", "interactive: needs a person (IRONDOME_TEST_INTERACTIVE=1)")


def secret(text: str = PASSWORD):
    """A master password (or any secret) in locked memory, as the CLI would hold it."""
    from irondome.secmem import SecureBuffer

    return SecureBuffer.from_buffer(text.encode("utf-8"))


@pytest.fixture(autouse=True)
def isolated(tmp_path: Path) -> Iterator[Path]:
    """Redirect every path IronDome could touch into ``tmp_path``.

    Uses a MonkeyPatch of its own, so a test that undoes or replaces *its*
    monkeypatch cannot take the isolation down with it.
    """
    monkeypatch = pytest.MonkeyPatch()
    try:
        yield _isolate(tmp_path, monkeypatch)
    finally:
        monkeypatch.undo()


def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "userhome"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.setenv("IRONDOME_HOME", str(tmp_path / "irondome"))
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", str(tmp_path / "device"))
    monkeypatch.setenv("IRONDOME_LEGACY_DIR", str(tmp_path / "legacy"))
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "software")
    monkeypatch.setenv("IRONDOME_KDF_MEMORY_MIB", "19")
    monkeypatch.setenv("IRONDOME_NO_TOUCH", "1")
    monkeypatch.setenv("IRONDOME_NO_PROMPT", "1")  # a test must never block on the real terminal
    monkeypatch.setenv("NO_COLOR", "1")
    for name in _SCRUB:
        monkeypatch.delenv(name, raising=False)
    from irondome import device, paths

    device._instances.clear()
    assert paths.bunker_name() == paths.FIRST_BUNKER
    assert str(paths.root()).startswith(str(tmp_path))
    assert str(paths.device_root()).startswith(str(tmp_path))
    assert str(paths.legacy_v3_dir()).startswith(str(tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """IronDome makes no network calls: any attempt to create a socket fails the test."""
    import socket

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("IronDome code tried to create a network socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def password() -> str:
    return PASSWORD


@pytest.fixture
def make_vault() -> Callable[..., Tuple[object, Optional[str]]]:
    """Factory: ``make_vault(mode="password", password=PASSWORD, with_recovery=True)``.

    Returns ``(vault, recovery_key)``; every vault it made is closed at teardown.
    """
    from irondome.unlock import create_vault

    made: List[object] = []

    def factory(mode: str = "password", password: Optional[str] = PASSWORD, **kwargs):
        buffer = secret(password) if password is not None else None
        try:
            vault, recovery = create_vault(mode=mode, password=buffer, **kwargs)
        finally:
            if buffer is not None:
                buffer.wipe()
        made.append(vault)
        return vault, recovery

    yield factory
    for vault in made:
        vault.close()  # type: ignore[attr-defined]


@pytest.fixture
def vault(make_vault):
    """An open vault holding two entries and one alias, already committed."""
    from irondome.vault import Secret

    opened, _ = make_vault()
    github = opened.add(
        "github", Secret(password="hunter2-Github!", notes="personal"), username="king", url="https://github.com",
        tags=["dev"],
    )
    opened.add("aws/prod", Secret(password="AKIA-not-a-real-key", fields={"region": "eu-west-1"}), kind="secret")
    opened.set_alias("GITHUB_TOKEN", github, "password")
    opened.commit()
    return opened


@pytest.fixture
def cli(isolated: Path) -> Callable[..., subprocess.CompletedProcess]:
    """Run the real command line in a subprocess inside the isolated environment.

    ``cli("get", "github", stdin="password\\n")`` returns the CompletedProcess;
    stdout and stderr are text. ``--password-stdin`` is the caller's business.
    """

    def run(*args: str, stdin: str = "", env: Optional[Dict[str, str]] = None, timeout: float = 120.0):
        merged = dict(os.environ)
        if _SUPPORT.is_dir():
            # tests/support/sitecustomize.py refuses socket creation in the child.
            merged["PYTHONPATH"] = os.pathsep.join(filter(None, [str(_SUPPORT), merged.get("PYTHONPATH", "")]))
            merged["IRONDOME_TEST_BLOCK_SOCKETS"] = "1"
        merged.update(env or {})
        return subprocess.run(
            [sys.executable, "-m", "irondome", *args],
            input=stdin,
            capture_output=True,
            text=True,
            env=merged,
            timeout=timeout,
        )

    return run


# ---------------------------------------------------------------------------
# Real hardware, opt-in
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def _se_helper(tmp_path_factory: pytest.TempPathFactory) -> Optional[str]:
    """Compile the Secure Enclave helper once per test session."""
    if sys.platform != "darwin":
        return None
    saved = os.environ.get("IRONDOME_DEVICE_DIR")
    os.environ["IRONDOME_DEVICE_DIR"] = str(tmp_path_factory.mktemp("se-helper"))
    os.environ.pop("IRONDOME_SE_HELPER", None)
    try:
        from irondome.device.macos_se import build_helper

        return str(build_helper())
    except Exception:
        return None
    finally:
        if saved is None:
            os.environ.pop("IRONDOME_DEVICE_DIR", None)
        else:
            os.environ["IRONDOME_DEVICE_DIR"] = saved


@pytest.fixture
def secure_enclave(_se_helper: Optional[str], monkeypatch: pytest.MonkeyPatch):
    """Switch this test to the real Secure Enclave backend, or skip."""
    if _se_helper is None:
        pytest.skip("no Secure Enclave helper on this machine")
    monkeypatch.setenv("IRONDOME_SE_HELPER", _se_helper)
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "macos-se")
    from irondome import device

    device._instances.clear()
    backend = device.get_backend("macos-se")
    if not backend.probe().available:
        pytest.skip("this machine has no usable Secure Enclave")
    return backend


@pytest.fixture
def tpm(monkeypatch: pytest.MonkeyPatch):
    """Switch this test to the TPM 2.0 backend, or skip."""
    if os.environ.get("IRONDOME_TEST_TPM") != "1":
        pytest.skip("set IRONDOME_TEST_TPM=1 with a TPM reachable through tpm2-tools")
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "linux-tpm2")
    from irondome import device

    device._instances.clear()
    backend = device.get_backend("linux-tpm2")
    probe = backend.probe()
    if not probe.available:
        pytest.fail(f"IRONDOME_TEST_TPM=1 but the TPM is not usable: {probe.detail}")
    return backend


def pytest_collection_modifyitems(config: pytest.Config, items: List[pytest.Item]) -> None:
    interactive = os.environ.get("IRONDOME_TEST_INTERACTIVE") == "1"
    for item in items:
        if "interactive" in item.keywords and not interactive:
            item.add_marker(pytest.mark.skip(reason="needs a person: set IRONDOME_TEST_INTERACTIVE=1"))
