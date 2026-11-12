"""The file-based device key, the descriptor checks every backend shares, and backend selection."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from irondome import device, paths
from irondome.device import base
from irondome.device.base import (
    DEVICE_SECRET_LEN,
    POLICIES,
    POLICY_BIOMETRY,
    POLICY_DEVICE,
    POLICY_PRESENCE,
    DeviceBackend,
    Probe,
    check_descriptor,
    new_ref,
)
from irondome.device.software import SoftwareBackend
from irondome.errors import HardwareError, VaultError
from irondome.secmem import SecureBuffer

POSIX = os.name == "posix"
posix_only = pytest.mark.skipif(not POSIX, reason="POSIX permissions")
REF = "0123456789abcdef0123456789abcdef"


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def backend() -> SoftwareBackend:
    return SoftwareBackend()


@pytest.fixture
def umask_zero() -> Iterator[None]:
    original = os.umask(0)
    yield
    os.umask(original)


def enroll(backend: SoftwareBackend) -> Tuple[Dict[str, Any], bytes]:
    descriptor, secret = backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    with secret:
        return descriptor, bytes(secret.view())


def key_file(descriptor: Dict[str, Any]) -> Path:
    return paths.device_dir() / f"{descriptor['ref']}.key"


def descriptor_for(ref: Any = REF, **changes: Any) -> Dict[str, Any]:
    descriptor: Dict[str, Any] = {"backend": "software", "policy": POLICY_DEVICE, "ref": ref}
    descriptor.update(changes)
    return descriptor


# ---------------------------------------------------------------------------
# SoftwareBackend
# ---------------------------------------------------------------------------


def test_it_says_plainly_that_it_is_not_hardware(backend):
    probe = backend.probe()
    assert probe == Probe(name="software", available=True, hardware=False, biometry=False, detail=probe.detail)
    assert "no security chip" in probe.detail
    assert backend.name == "software" and backend.hardware is False
    assert backend.policies == (POLICY_DEVICE,)
    assert backend.supports(POLICY_DEVICE)
    assert not backend.supports(POLICY_BIOMETRY) and not backend.supports(POLICY_PRESENCE)


def test_enroll_creates_a_random_key_outside_the_vault_directory(backend):
    descriptor, secret = backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    with secret:
        assert isinstance(secret, SecureBuffer) and len(secret) == DEVICE_SECRET_LEN == 32
        value = bytes(secret.view())
    assert value != bytes(32)
    assert descriptor == {"backend": "software", "policy": POLICY_DEVICE, "ref": descriptor["ref"]}
    assert re.fullmatch(r"[0-9a-f]{32}", descriptor["ref"])
    path = key_file(descriptor)
    assert path.read_bytes() == value
    assert path.parent == paths.device_dir()
    assert paths.home() not in path.parents
    assert not paths.home().exists()  # nothing was put beside the vault


@posix_only
def test_the_key_file_is_owner_only_under_any_umask(backend, umask_zero):
    descriptor, _ = enroll(backend)
    assert mode(key_file(descriptor)) == 0o600
    assert mode(paths.device_dir()) == 0o700
    assert sorted(item.name for item in paths.device_dir().iterdir()) == [f"{descriptor['ref']}.key"]


def test_every_enrolment_is_independent(backend):
    seen = [enroll(backend) for _ in range(5)]
    assert len({descriptor["ref"] for descriptor, _ in seen}) == 5
    assert len({secret for _, secret in seen}) == 5
    assert len(list(paths.device_dir().glob("*.key"))) == 5


def test_unseal_returns_the_enrolled_secret_in_fresh_locked_memory(backend):
    descriptor, value = enroll(backend)
    first = backend.unseal(descriptor, auth=None, interactive=False, reason="test")
    second = backend.unseal(descriptor, auth=None, interactive=True, reason="another reason")
    assert first is not second
    assert isinstance(first, SecureBuffer) and len(first) == 32
    assert bytes(first.view()) == bytes(second.view()) == value
    first.wipe()
    assert bytes(second.view()) == value
    second.wipe()
    assert key_file(descriptor).read_bytes() == value  # reading does not disturb the file


def test_unseal_ignores_the_password_derived_value(backend):
    descriptor, value = enroll(backend)
    with SecureBuffer.random(32) as auth:
        with backend.unseal(descriptor, auth=auth, interactive=False, reason="test") as secret:
            assert bytes(secret.view()) == value


@pytest.mark.parametrize("policy", [POLICY_BIOMETRY, POLICY_PRESENCE, "psychic", "", None])
def test_it_refuses_policies_it_cannot_enforce(backend, policy):
    with pytest.raises(HardwareError, match="cannot enforce"):
        backend.enroll(policy=policy, auth=None, reason="test")
    assert not paths.device_dir().exists()


def test_unseal_without_the_key_file_says_where_the_key_is_not(backend):
    with pytest.raises(HardwareError, match="not on this machine"):
        backend.unseal(descriptor_for(), auth=None, interactive=False, reason="test")
    assert backend.exists(descriptor_for()) is False


@pytest.mark.parametrize("size", [0, 1, 16, 31, 33, 64, 4096])
def test_a_key_file_of_the_wrong_size_is_damaged(backend, size):
    descriptor, _ = enroll(backend)
    key_file(descriptor).write_bytes(os.urandom(size))
    with pytest.raises(HardwareError, match="damaged"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")


def test_a_directory_in_place_of_the_key_is_a_hardware_error(backend):
    descriptor = descriptor_for()
    paths.ensure_dir(key_file(descriptor))
    with pytest.raises(HardwareError):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")
    assert backend.exists(descriptor) is False


@posix_only
@pytest.mark.parametrize("writer", [False, True], ids=["nothing writes to it", "something writes to it"])
def test_a_pipe_in_place_of_the_key_is_refused_at_once(backend, writer):
    """Opening a pipe waits for a writer: every grant an agent opens, and every unlock, would hang on it."""
    descriptor = descriptor_for()
    pipe = key_file(descriptor)
    paths.ensure_dir(pipe.parent)
    os.mkfifo(str(pipe))

    def feed() -> None:
        try:
            with open(pipe, "wb") as handle:
                handle.write(os.urandom(DEVICE_SECRET_LEN))
        except OSError:
            pass  # the reader went away first

    if writer:
        threading.Thread(target=feed, daemon=True).start()
    outcome: Dict[str, object] = {}

    def attempt() -> None:
        try:
            backend.unseal(descriptor, auth=None, interactive=False, reason="test").wipe()
            outcome["result"] = "opened"
        except BaseException as exc:  # handed back to the test thread below
            outcome["result"] = exc

    thread = threading.Thread(target=attempt, daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(10)
    try:
        assert not thread.is_alive(), "unseal is still blocked on the pipe after 10 seconds"
        assert time.monotonic() - started < 5
        assert isinstance(outcome["result"], HardwareError), outcome["result"]
        assert "not a regular file" in str(outcome["result"])
    finally:
        try:  # lets anything still blocked on the pipe go on, so that nothing is left behind
            fd = os.open(str(pipe), os.O_RDWR | os.O_NONBLOCK)
        except OSError:
            pass
        else:
            time.sleep(0.2)
            os.close(fd)


@posix_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can read anything")
def test_an_unreadable_key_file_is_a_hardware_error(backend):
    descriptor, _ = enroll(backend)
    os.chmod(key_file(descriptor), 0)
    try:
        with pytest.raises(HardwareError, match="cannot read the device key"):
            backend.unseal(descriptor, auth=None, interactive=False, reason="test")
    finally:
        os.chmod(key_file(descriptor), 0o600)


def test_enroll_reports_a_device_directory_it_cannot_write(backend, monkeypatch):
    def refuse(path, data):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(paths, "write_atomic", refuse)
    with pytest.raises(HardwareError, match="could not store the device key"):
        backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")


def test_enroll_wipes_the_secret_it_could_not_store(backend, monkeypatch):
    made: List[SecureBuffer] = []
    real_random = SecureBuffer.random.__func__  # type: ignore[attr-defined]

    def recording_random(cls, size):
        buffer = real_random(cls, size)
        made.append(buffer)
        return buffer

    def interrupt(path, data):
        raise KeyboardInterrupt

    monkeypatch.setattr(SecureBuffer, "random", classmethod(recording_random))
    monkeypatch.setattr(paths, "write_atomic", interrupt)
    with pytest.raises(KeyboardInterrupt):
        backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    assert len(made) == 1 and made[0].wiped


# -- destroying --------------------------------------------------------------


def test_destroy_makes_unseal_impossible(backend):
    descriptor, _ = enroll(backend)
    assert backend.exists(descriptor) is True
    backend.destroy(descriptor)
    assert backend.exists(descriptor) is False
    assert not key_file(descriptor).exists()
    with pytest.raises(HardwareError, match="not on this machine"):
        backend.unseal(descriptor, auth=None, interactive=False, reason="test")
    backend.destroy(descriptor)  # already gone: not an error


@posix_only
def test_destroy_overwrites_the_key_before_removing_it(backend):
    descriptor, value = enroll(backend)
    witness = paths.device_dir() / "witness"
    os.link(key_file(descriptor), witness)
    backend.destroy(descriptor)
    assert len(witness.read_bytes()) == 32 and witness.read_bytes() != value


def test_destroy_leaves_other_keys_alone(backend):
    doomed, _ = enroll(backend)
    kept, kept_value = enroll(backend)
    backend.destroy(doomed)
    with backend.unseal(kept, auth=None, interactive=False, reason="test") as secret:
        assert bytes(secret.view()) == kept_value


def test_destroy_raises_when_the_key_survives(backend, monkeypatch):
    descriptor, _ = enroll(backend)
    monkeypatch.setattr(paths, "secure_delete", lambda path: None)
    with pytest.raises(HardwareError, match="still present"):
        backend.destroy(descriptor)


def test_destroy_raises_when_deletion_fails(backend, monkeypatch):
    descriptor, _ = enroll(backend)

    def refuse(path):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(paths, "secure_delete", refuse)
    with pytest.raises(HardwareError, match="could not destroy the device key"):
        backend.destroy(descriptor)


def test_destroy_all_takes_every_key_file_and_nothing_else(backend):
    descriptors = [enroll(backend)[0] for _ in range(4)]
    device_dir = paths.device_dir()
    state = device_dir / (REF + ".json")
    state.write_text('{"backend": "macos-se"}')
    helper = paths.ensure_dir(paths.helper_dir()) / "irondome-se-0000000000000000"
    helper.write_bytes(b"binary")
    assert backend.destroy_all() == 4
    assert all(not backend.exists(descriptor) for descriptor in descriptors)
    assert state.exists() and helper.exists()
    assert backend.destroy_all() == 0


def test_destroy_all_without_a_device_directory(backend):
    assert not paths.device_dir().exists()
    assert backend.destroy_all() == 0
    assert not paths.device_dir().exists()


@posix_only
def test_destroy_all_removes_a_link_without_following_it(backend, isolated):
    enroll(backend)
    victim = isolated / "victim"
    victim.write_bytes(b"must survive untouched")
    (paths.device_dir() / ("f" * 32 + ".key")).symlink_to(victim)
    assert backend.destroy_all() == 2
    assert victim.read_bytes() == b"must survive untouched"
    assert list(paths.device_dir().glob("*.key")) == []


def test_destroy_all_goes_on_past_a_key_it_cannot_remove(backend, monkeypatch):
    """One stubborn file must not leave the others readable; the failure is reported at the end."""
    refs = sorted(enroll(backend)[0]["ref"] for _ in range(4))
    stubborn = paths.device_dir() / f"{refs[0]}.key"
    real_delete = paths.secure_delete

    def delete(path):
        if Path(path) == stubborn:
            raise PermissionError(1, "Operation not permitted")
        real_delete(path)

    monkeypatch.setattr(paths, "secure_delete", delete)
    with pytest.raises(HardwareError, match=refs[0]):
        backend.destroy_all()
    assert [item.name for item in paths.device_dir().glob("*.key")] == [stubborn.name]


# -- descriptors read from a vault file are hostile input --------------------

TRAVERSALS = [
    "../outside",
    "../../outside",
    "..",
    ".",
    "/etc/passwd",
    "subdir/" + "a" * 25,
    "a" * 16 + "/" + "a" * 15,
    "..%2foutside",
    "a" * 31,
    "a" * 33,
    "a" * 64,
    "A" * 32,
    "g" * 32,
    "a" * 32 + "\n",
    "\n" + "a" * 32,
    "a" * 31 + " ",
    "a" * 30 + "\x00a",
    "a" * 31 + "١",  # an Arabic-Indic digit is a digit, but not a hex digit
    "",
    7,
    3.5,
    True,
    ["a" * 32],
    {"a": 1},
    b"a" * 32,
]


@pytest.mark.parametrize("ref", TRAVERSALS, ids=[repr(item)[:30] for item in TRAVERSALS])
def test_a_reference_cannot_name_anything_but_a_key_in_the_device_directory(backend, isolated, ref):
    paths.ensure_dir(paths.device_dir())
    outside = isolated / "outside.key"
    outside.write_bytes(b"k" * 32)
    descriptor = descriptor_for(ref)
    for operation in (
        lambda: backend.unseal(descriptor, auth=None, interactive=False, reason="test"),
        lambda: backend.destroy(descriptor),
        lambda: backend.exists(descriptor),
    ):
        with pytest.raises((VaultError, HardwareError)):
            operation()
    assert outside.read_bytes() == b"k" * 32
    assert list(paths.device_dir().iterdir()) == []


def test_a_descriptor_without_a_reference_is_refused(backend):
    for descriptor in (descriptor_for(None), {"backend": "software", "policy": POLICY_DEVICE}):
        with pytest.raises(HardwareError, match="no reference"):
            backend.unseal(descriptor, auth=None, interactive=False, reason="test")


@pytest.mark.parametrize(
    "descriptor",
    [
        None,
        "software",
        [],
        7,
        {},
        {"backend": "macos-se", "policy": POLICY_DEVICE, "ref": REF},
        {"backend": None, "policy": POLICY_DEVICE, "ref": REF},
        {"backend": "software", "policy": "none", "ref": REF},
        {"backend": "software", "policy": None, "ref": REF},
        {"backend": "software", "policy": ["device"], "ref": REF},
        {"backend": "software", "ref": REF},
        {"policy": POLICY_DEVICE, "ref": REF},
    ],
)
def test_malformed_descriptors_are_refused(backend, descriptor):
    for operation in (
        lambda: backend.unseal(descriptor, auth=None, interactive=False, reason="test"),
        lambda: backend.destroy(descriptor),
        lambda: backend.exists(descriptor),
    ):
        with pytest.raises(VaultError):
            operation()


@given(st.text(max_size=40))
@settings(max_examples=300, deadline=None)
def test_only_32_lowercase_hex_digits_are_a_reference(ref):
    valid = len(ref) == 32 and all(char in "0123456789abcdef" for char in ref)
    descriptor = {"backend": "software", "policy": POLICY_DEVICE, "ref": ref}
    if valid:
        assert check_descriptor(descriptor, "software") is descriptor
    else:
        with pytest.raises(VaultError):
            check_descriptor(descriptor, "software")


@given(st.sampled_from(["a" * 32, REF]), st.sampled_from(["\n", "\r", "\r\n", "\x00", " ", "/", "/..", "\\"]))
def test_a_valid_reference_with_anything_appended_is_refused(ref, suffix):
    with pytest.raises(VaultError):
        check_descriptor({"backend": "software", "policy": POLICY_DEVICE, "ref": ref + suffix}, "software")


# ---------------------------------------------------------------------------
# The shared contract (device/base.py)
# ---------------------------------------------------------------------------


def test_policies_and_secret_length():
    assert POLICIES == (POLICY_DEVICE, POLICY_BIOMETRY, POLICY_PRESENCE) == ("device", "biometry", "presence")
    assert DEVICE_SECRET_LEN == 32


def test_new_ref_is_random_and_always_passes_the_check():
    refs = [new_ref() for _ in range(200)]
    assert len(set(refs)) == 200
    for ref in refs:
        assert re.fullmatch(r"[0-9a-f]{32}", ref)
        check_descriptor({"backend": "x", "policy": POLICY_DEVICE, "ref": ref}, "x")


def test_check_descriptor_returns_the_descriptor_it_accepted():
    descriptor = {"backend": "x", "policy": POLICY_PRESENCE, "ref": REF, "extra": [1, 2]}
    assert check_descriptor(descriptor, "x") is descriptor
    assert check_descriptor({"backend": "x", "policy": POLICY_BIOMETRY}, "x")["policy"] == POLICY_BIOMETRY


def test_probe_is_an_immutable_record():
    probe = Probe(name="x", available=True, hardware=False, biometry=False, detail="d")
    with pytest.raises(AttributeError):
        probe.available = False  # type: ignore[misc]
    assert probe == Probe("x", True, False, False, "d")


def test_a_backend_must_implement_the_whole_contract():
    with pytest.raises(TypeError):
        DeviceBackend()  # type: ignore[abstract]

    class Partial(DeviceBackend):
        name = "partial"

        def probe(self) -> Probe:
            return Probe(self.name, True, False, False, "")

    with pytest.raises(TypeError):
        Partial()  # type: ignore[abstract]
    assert {"probe", "enroll", "unseal", "destroy", "exists", "destroy_all"} <= DeviceBackend.__abstractmethods__


def test_the_default_backend_supports_only_the_silent_policy():
    assert DeviceBackend.policies == (POLICY_DEVICE,) and DeviceBackend.hardware is False
    assert base._REF.fullmatch(REF) and not base._REF.fullmatch(REF + "\n")


# ---------------------------------------------------------------------------
# Choosing a backend (device/__init__.py)
# ---------------------------------------------------------------------------


class Fake(DeviceBackend):
    """A backend with scripted answers, registered for one test."""

    def __init__(
        self,
        name: str,
        *,
        available: bool = True,
        policies: Tuple[str, ...] = (POLICY_DEVICE,),
        detail: str = "",
        broken: Optional[Exception] = None,
    ) -> None:
        self.name = name
        self.policies = policies
        self._available = available
        self._detail = detail
        self._broken = broken

    def probe(self) -> Probe:
        if self._broken is not None:
            raise self._broken
        return Probe(self.name, self._available, False, False, self._detail)

    def enroll(self, *, policy, auth, reason):
        raise HardwareError(f"{self.name} is a stand-in and holds no keys")

    def unseal(self, descriptor, *, auth, interactive, reason):
        raise HardwareError(f"{self.name} is a stand-in and holds no keys")

    def destroy(self, descriptor) -> None:
        raise HardwareError(f"{self.name} is a stand-in and holds no keys")

    def exists(self, descriptor) -> bool:
        return False

    def destroy_all(self) -> int:
        return 0


def register(monkeypatch: pytest.MonkeyPatch, *fakes: Fake) -> None:
    """Replace the registry with *fakes*, strongest first."""
    monkeypatch.setattr(device, "_REGISTRY", tuple((fake.name, "irondome.no_such_module", "Nothing") for fake in fakes))
    monkeypatch.setattr(device, "_instances", {fake.name: fake for fake in fakes})


def test_the_registry_lists_backends_strongest_first():
    assert device.backend_names() == ["macos-se", "linux-tpm2", "software"]
    assert device.POLICIES == POLICIES


def test_get_backend_builds_each_backend_once():
    first = device.get_backend("software")
    assert isinstance(first, SoftwareBackend)
    assert device.get_backend("software") is first
    assert device._instances == {"software": first}


@pytest.mark.parametrize("name", ["", "Software", "software ", "tpm", "../software", "keychain"])
def test_get_backend_refuses_unknown_names(name):
    with pytest.raises(VaultError, match="unknown device backend"):
        device.get_backend(name)
    assert device._instances == {}


def test_a_backend_that_cannot_be_imported_is_a_hardware_error(monkeypatch):
    """A vault that names a backend this installation lacks must fail cleanly, not with a traceback."""
    monkeypatch.setattr(device, "_REGISTRY", (("ghost", "irondome.device.no_such_backend", "Ghost"),))
    with pytest.raises(HardwareError, match="ghost device backend cannot be loaded"):
        device.get_backend("ghost")
    assert device._instances == {}
    probes = device.probe_all()
    assert [probe.name for probe in probes] == ["ghost"] and probes[0].available is False
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "auto")
    with pytest.raises(HardwareError, match="cannot be loaded"):
        device.choose_backend(POLICY_DEVICE)
    with pytest.raises(HardwareError, match="cannot be loaded"):
        device.choose_backend(POLICY_DEVICE, "ghost")


def test_importing_one_backend_does_not_import_the_others():
    script = (
        "import sys\n"
        "from irondome import device\n"
        "device.get_backend('software')\n"
        "print(sorted(name for name in sys.modules if name.startswith('irondome.device.')))\n"
    )
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "['irondome.device.base', 'irondome.device.software']"


def test_the_environment_forces_a_backend():
    assert os.environ["IRONDOME_DEVICE_BACKEND"] == "software"
    assert isinstance(device.choose_backend(), SoftwareBackend)
    assert isinstance(device.choose_backend(POLICY_DEVICE), SoftwareBackend)


def test_an_explicit_preference_beats_the_environment(monkeypatch):
    register(monkeypatch, Fake("first"), Fake("second"))
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "first")
    assert device.choose_backend(POLICY_DEVICE, "second").name == "second"
    assert device.choose_backend(POLICY_DEVICE).name == "first"
    assert device.choose_backend(POLICY_DEVICE, None).name == "first"


def test_a_forced_backend_that_cannot_enforce_the_policy_is_refused():
    with pytest.raises(HardwareError, match="software cannot enforce the biometry policy"):
        device.choose_backend(POLICY_BIOMETRY)
    with pytest.raises(HardwareError, match="cannot enforce the presence policy"):
        device.choose_backend(POLICY_PRESENCE, "software")


def test_a_forced_backend_that_is_unavailable_is_refused_with_its_reason(monkeypatch):
    register(monkeypatch, Fake("chip", available=False, detail="no chip in this machine"), Fake("file"))
    with pytest.raises(HardwareError, match="chip is not available: no chip in this machine"):
        device.choose_backend(POLICY_DEVICE, "chip")


def test_a_forced_unknown_backend_is_refused(monkeypatch):
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "quantum")
    with pytest.raises(VaultError, match="unknown device backend 'quantum'"):
        device.choose_backend()


@pytest.mark.parametrize("policy", ["", "Device", "touch", None, 5])
def test_choose_backend_refuses_unknown_policies(policy):
    with pytest.raises(VaultError, match="unknown device policy"):
        device.choose_backend(policy)


@pytest.mark.parametrize("setting", ["auto", ""])
def test_automatic_choice_takes_the_strongest_backend_that_works(monkeypatch, setting):
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", setting)
    register(
        monkeypatch,
        Fake("broken", broken=RuntimeError("probe exploded")),
        Fake("absent", available=False, detail="not this platform"),
        Fake("chip", policies=(POLICY_DEVICE, POLICY_BIOMETRY)),
        Fake("file"),
    )
    assert device.choose_backend(POLICY_DEVICE).name == "chip"
    assert device.choose_backend(POLICY_BIOMETRY).name == "chip"
    with pytest.raises(HardwareError) as caught:
        device.choose_backend(POLICY_PRESENCE)
    message = str(caught.value)
    assert "no device backend can enforce the presence policy" in message
    assert "probe exploded" in message and "not this platform" in message


def test_automatic_choice_falls_back_to_the_file_backend(monkeypatch):
    monkeypatch.delenv("IRONDOME_DEVICE_BACKEND")
    register(monkeypatch, Fake("chip", available=False, detail="no chip"), Fake("file"))
    assert device.choose_backend().name == "file"


# -- why no chip holds the key: what init and status can tell the person -----


def test_choose_names_the_stronger_backends_it_passed_over_and_why(monkeypatch):
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "auto")
    register(
        monkeypatch,
        Fake("broken", broken=RuntimeError("probe exploded")),
        Fake("absent", available=False, detail="needs the vendor tools: install them"),
        Fake("file"),
    )
    choice = device.choose()
    assert choice.backend is device.get_backend("file") is device.choose_backend()
    assert choice.picked == "auto"
    assert [(probe.name, probe.available, probe.detail) for probe in choice.passed_over] == [
        ("broken", False, "probe exploded"), ("absent", False, "needs the vendor tools: install them"),
    ]
    assert choice.why_no_chip == "broken: probe exploded; absent: needs the vendor tools: install them"
    assert choice.chip_unknown is False  # every probe gave an answer


def test_a_backend_that_cannot_enforce_the_policy_says_so(monkeypatch):
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "auto")
    register(monkeypatch, Fake("chip", detail="TPM 2.0 (IFX)"), Fake("file", policies=POLICIES))
    choice = device.choose(POLICY_BIOMETRY)
    assert choice.backend.name == "file"
    assert [(probe.name, probe.available, probe.detail) for probe in choice.passed_over] == [
        ("chip", True, "cannot enforce the biometry policy"),
    ]


def test_a_backend_for_another_system_is_not_a_reason(monkeypatch):
    """"not Linux" tells a Mac user nothing; what the Mac's own chip lacks is the reason."""
    monkeypatch.delenv("IRONDOME_DEVICE_BACKEND")
    register(
        monkeypatch,
        Fake("macos-se", available=False, detail="the Secure Enclave helper is not compiled"),
        Fake("linux-tpm2", available=False, detail="tpm2-tools is not installed"),
        Fake("software"),
    )
    monkeypatch.setattr(device, "sys", types.SimpleNamespace(platform="linux"))
    assert device.choose().why_no_chip == "linux-tpm2: tpm2-tools is not installed"
    monkeypatch.setattr(device, "sys", types.SimpleNamespace(platform="darwin"))
    assert device.choose().why_no_chip == "macos-se: the Secure Enclave helper is not compiled"
    monkeypatch.setattr(device, "sys", types.SimpleNamespace(platform="freebsd14"))
    choice = device.choose()
    assert choice.passed_over == () and "no security-chip backend for this system" in str(choice.why_no_chip)


def test_a_backend_chosen_by_name_says_so(monkeypatch):
    assert os.environ["IRONDOME_DEVICE_BACKEND"] == "software"
    choice = device.choose()
    assert (choice.backend.name, choice.picked, choice.passed_over) == ("software", "environment", ())
    assert choice.why_no_chip == "IRONDOME_DEVICE_BACKEND is set to software, so no security chip was looked for"
    choice = device.choose(POLICY_DEVICE, "software")
    assert choice.picked == "caller" and "asked for by name" in str(choice.why_no_chip)


class Chip(Fake):
    """A chip backend; *real* says whether this machine's probe finds a chip behind it (a simulator does not)."""

    def __init__(self, name: str, *, real: bool = True, detail: str = "TPM 2.0 (IFX SLB9670)") -> None:
        super().__init__(name, detail=detail)
        self.hardware = True
        self.real = real

    def probe(self) -> Probe:
        return Probe(self.name, True, self.real, False, self._detail)


def test_a_chip_needs_no_explanation(monkeypatch):
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "auto")
    chip = Chip("chip")
    register(monkeypatch, chip, Fake("file"))
    choice = device.choose()
    assert choice.backend is chip and choice.hardware is True and choice.why_no_chip is None
    assert choice.passed_over == () and choice.probe == chip.probe()


def test_a_chip_backend_with_no_chip_behind_it_says_so(monkeypatch):
    """A TPM 2.0 simulator is the TPM backend, and it is software: the probe of this machine decides."""
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "auto")
    simulator = Chip("linux-tpm2", real=False, detail="TPM 2.0 simulator reached through swtpm: software, not a chip")
    register(monkeypatch, simulator, Fake("file"))
    choice = device.choose()
    assert choice.backend is simulator and choice.hardware is False
    assert choice.why_no_chip == "linux-tpm2: TPM 2.0 simulator reached through swtpm: software, not a chip"
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "linux-tpm2")  # named, and still no chip: the probe says why
    assert device.choose().why_no_chip == "linux-tpm2: TPM 2.0 simulator reached through swtpm: software, not a chip"


class Unbuilt(Fake):
    """A chip whose probe would first have to build something, as the Secure Enclave's helper."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.hardware = True
        self.asked: List[str] = []

    def probe(self) -> Probe:
        self.asked.append("probe")
        return Probe(self.name, True, True, False, "built and probed")

    def passive_probe(self) -> Probe:
        self.asked.append("passive_probe")
        return Probe(self.name, False, True, False, "not probed: its helper is not compiled yet")


def test_a_passive_choice_builds_nothing_and_the_real_one_does(monkeypatch):
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "auto")
    chip = Unbuilt("chip")
    register(monkeypatch, chip, Fake("file"))
    choice = device.choose(passive=True)
    assert choice.backend.name == "file" and choice.why_no_chip == "chip: not probed: its helper is not compiled yet"
    assert choice.chip_unknown is True  # the real choice may take the chip: status must not say there is none
    assert chip.asked == ["passive_probe"]
    choice = device.choose()
    assert choice.backend is chip and choice.why_no_chip is None and chip.asked == ["passive_probe", "probe"]
    with pytest.raises(HardwareError, match="chip is not available: not probed"):
        device.choose(POLICY_DEVICE, "chip", passive=True)


@pytest.mark.parametrize(
    "platform, words",
    [
        ("darwin", ["Secure Enclave", "Apple-silicon", "Intel Macs are untested",
                    "Xcode Command Line Tools", "xcode-select --install"]),
        ("linux", ["TPM 2.0", "firmware setup", "/dev/tpmrm0", "tss", "sudo apt install tpm2-tools"]),
        ("win32", ["no chip backend for this system"]),
    ],
)
def test_chip_requirements_say_what_this_system_needs(monkeypatch, platform, words):
    monkeypatch.setattr(device, "sys", types.SimpleNamespace(platform=platform))
    text = device.chip_requirements()
    assert all(word in text for word in words) and "\n" not in text


def test_progress_reaches_its_callback_and_a_dead_stream_stops_nothing():
    said: List[str] = []
    previous = device.set_progress(said.append)
    try:
        device.report_progress("Compiling...")
        assert said == ["Compiling..."]

        def gone(message: str) -> None:
            raise BrokenPipeError(32, "Broken pipe")

        device.set_progress(gone)
        device.report_progress("Compiling...")  # the work goes on
        assert device.set_progress(None) is gone
        device.report_progress("nobody hears this")
    finally:
        device.set_progress(previous)


def test_probe_all_reports_every_backend_and_never_raises(monkeypatch):
    register(
        monkeypatch,
        Fake("broken", broken=RuntimeError("probe exploded")),
        Fake("absent", available=False, detail="not this platform"),
        Fake("file"),
    )
    probes = device.probe_all()
    assert [probe.name for probe in probes] == ["broken", "absent", "file"]
    assert [probe.available for probe in probes] == [False, False, True]
    assert probes[0].detail == "probe exploded" and probes[0].hardware is False


def test_probe_all_on_this_machine_includes_the_file_backend():
    probes = {probe.name: probe for probe in device.probe_all()}
    assert set(probes) == {"macos-se", "linux-tpm2", "software"}
    assert probes["software"].available is True and probes["software"].hardware is False
    for probe in probes.values():
        assert isinstance(probe.available, bool) and isinstance(probe.detail, str)


def test_fakes_do_not_leak_into_the_real_registry():
    assert [name for name, _, _ in device._REGISTRY] == ["macos-se", "linux-tpm2", "software"]
    assert all(not isinstance(backend, Fake) for backend in device._instances.values())
