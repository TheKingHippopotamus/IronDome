"""Setting a vault up in each mode and getting back into it, with every factor and without."""

from __future__ import annotations

import os
import shutil
import types
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from conftest import PASSWORD, secret
from irondome import device, errors, keys, paths, unlock
from irondome.crypto import Argon2Params
from irondome.device.base import (
    POLICY_BIOMETRY,
    POLICY_DEVICE,
    POLICY_PRESENCE,
    DeviceBackend,
    Probe,
    check_descriptor,
    new_ref,
)
from irondome.errors import AuthError, HardwareError, IronDomeError, UsageError, VaultError
from irondome.secmem import SecureBuffer
from irondome.unlock import (
    MIN_PASSWORD_BYTES,
    MODE_PASSWORD,
    MODE_TOUCHID,
    MODE_TOUCHID_PASSWORD,
    MODES,
    can_ask_for_touch,
    check_new_password,
    open_vault,
)
from irondome.vault import Secret, Vault, VaultFile

REASON = "open the test vault"


class FakeTouch(DeviceBackend):
    """Stands in for a security chip with a fingerprint sensor.

    Secrets are kept in memory. ``finger`` is what the person at the sensor
    does: "present" touches it, "refuse" cancels the prompt. A key under a
    biometric or presence policy answers only after a prompt, and a prompt is
    possible only when the caller allows interaction.
    """

    name = "fake-touch"
    hardware = True
    policies = (POLICY_DEVICE, POLICY_BIOMETRY, POLICY_PRESENCE)

    def __init__(self) -> None:
        self.secrets: Dict[str, bytes] = {}
        self.finger = "present"
        self.prompts: List[Tuple[str, str]] = []

    def probe(self) -> Probe:
        return Probe(self.name, True, True, True, "stand-in chip with a fingerprint sensor")

    def _authorise(self, operation: str, policy: str, interactive: bool, reason: str) -> None:
        if policy == POLICY_DEVICE:
            return
        if not interactive:
            raise AuthError("a fingerprint is required, and it cannot be asked for here")
        self.prompts.append((operation, reason))
        if self.finger == "refuse":
            raise AuthError("the fingerprint prompt was cancelled")

    def enroll(self, *, policy, auth, reason):
        if not self.supports(policy):
            raise HardwareError(f"the stand-in chip has no {policy} policy")
        self._authorise("enroll", policy, True, reason)
        ref = new_ref()
        self.secrets[ref] = os.urandom(32)
        return {"backend": self.name, "policy": policy, "ref": ref}, SecureBuffer.from_buffer(self.secrets[ref])

    def unseal(self, descriptor, *, auth, interactive, reason):
        check_descriptor(descriptor, self.name)
        stored = self.secrets.get(descriptor.get("ref"))
        if stored is None:
            raise HardwareError("the stand-in chip does not hold this key")
        self._authorise("unseal", descriptor["policy"], interactive, reason)
        return SecureBuffer.from_buffer(stored)

    def destroy(self, descriptor) -> None:
        check_descriptor(descriptor, self.name)
        self.secrets.pop(descriptor.get("ref"), None)

    def exists(self, descriptor) -> bool:
        check_descriptor(descriptor, self.name)
        return descriptor.get("ref") in self.secrets

    def destroy_all(self) -> int:
        count = len(self.secrets)
        self.secrets.clear()
        return count

    def unseals(self) -> int:
        return sum(1 for operation, _ in self.prompts if operation == "unseal")


@pytest.fixture
def touch(monkeypatch: pytest.MonkeyPatch) -> FakeTouch:
    """A stand-in chip with a sensor, registered as a backend, with nobody forbidding prompts."""
    fake = FakeTouch()
    monkeypatch.setattr(device, "_REGISTRY", device._REGISTRY + (("fake-touch", "irondome.no_such_module", "X"),))
    monkeypatch.setitem(device._instances, "fake-touch", fake)
    monkeypatch.delenv("IRONDOME_NO_TOUCH")
    monkeypatch.setattr(unlock, "sys", types.SimpleNamespace(platform="darwin"))
    return fake


@pytest.fixture
def buffers(monkeypatch: pytest.MonkeyPatch) -> List[SecureBuffer]:
    """Every SecureBuffer created while the test runs."""
    made: List[SecureBuffer] = []
    real_init = SecureBuffer.__init__

    def recording_init(self, size):
        real_init(self, size)
        made.append(self)

    monkeypatch.setattr(SecureBuffer, "__init__", recording_init)
    return made


def alive(made: List[SecureBuffer], *keep: Optional[SecureBuffer]) -> List[SecureBuffer]:
    return [buffer for buffer in made if not buffer.wiped and all(buffer is not kept for kept in keep)]


def key_files() -> List[str]:
    directory = paths.device_dir()
    return sorted(item.name for item in directory.glob("*.key")) if directory.is_dir() else []


def same_key(first: SecureBuffer, second: SecureBuffer) -> bool:
    return bytes(first.view()) == bytes(second.view())


class Source:
    """A password prompt: counts how often it is asked and remembers what it handed out."""

    def __init__(self, text: Optional[str] = PASSWORD) -> None:
        self.text = text
        self.asked = 0
        self.handed: List[SecureBuffer] = []

    def __call__(self) -> Optional[SecureBuffer]:
        self.asked += 1
        if self.text is None:
            return None
        buffer = secret(self.text)
        self.handed.append(buffer)
        return buffer


def slots_of(vault: Vault) -> List[Tuple[str, Optional[str], Optional[str], str]]:
    return [(slot.kind, slot.backend_name, slot.policy, slot.label) for slot in vault.file.slots]


# ---------------------------------------------------------------------------
# Exit statuses (irondome.errors has no test file of its own)
# ---------------------------------------------------------------------------


def test_exit_statuses_are_frozen():
    """Scripts and agents branch on these numbers; they are part of the interface."""
    assert errors.EXIT_OK == 0 and errors.EXIT_INTERRUPTED == 130
    expected = {
        errors.IronDomeError: 1,
        errors.UsageError: 2,
        errors.NotFoundError: 3,
        errors.AuthError: 4,
        errors.LockedOutError: 4,
        errors.PolicyError: 5,
        errors.VaultError: 6,
        errors.HardwareError: 7,
        errors.DeviceLockedError: 7,
    }
    for error, status in expected.items():
        assert error.exit_code == status and error("message").exit_code == status
        assert issubclass(error, IronDomeError) and str(error("message")) == "message"
    assert issubclass(errors.LockedOutError, AuthError)
    assert issubclass(errors.DeviceLockedError, errors.HardwareError)  # a kind of it: the same status
    kinds = (errors.LockedOutError, errors.DeviceLockedError)
    distinct = [error for error in expected if error not in kinds]
    assert len({error.exit_code for error in distinct}) == len(distinct)
    assert set(errors.__all__) == {error.__name__ for error in expected} | {"EXIT_OK", "EXIT_INTERRUPTED"}


# ---------------------------------------------------------------------------
# Small rules
# ---------------------------------------------------------------------------


def test_modes():
    assert MODES == (MODE_PASSWORD, MODE_TOUCHID, MODE_TOUCHID_PASSWORD) == ("password", "touchid", "touchid+password")
    assert MIN_PASSWORD_BYTES == 8


@pytest.mark.parametrize("text", ["12345678", "correct horse", "סיסמ", "\U0001f511\U0001f511", "x" * 4096])
def test_a_new_password_of_eight_bytes_or_more_is_accepted(text):
    with secret(text) as password:
        assert check_new_password(password) is None


@pytest.mark.parametrize("text", ["1", "1234567", "סיס", "\U0001f511"])
def test_a_shorter_new_password_is_refused(text):
    with secret(text) as password, pytest.raises(UsageError, match="at least 8"):
        check_new_password(password)


@pytest.mark.parametrize(
    "platform, environment, expected",
    [
        ("darwin", {}, True),
        ("darwin", {"IRONDOME_NO_TOUCH": "1"}, False),
        ("darwin", {"IRONDOME_NO_TOUCH": "0"}, True),
        ("darwin", {"IRONDOME_NO_TOUCH": ""}, True),
        ("darwin", {"SSH_CONNECTION": "10.0.0.2 51234 10.0.0.1 22"}, False),
        ("darwin", {"SSH_TTY": "/dev/ttys003"}, False),
        ("darwin", {"SSH_CONNECTION": ""}, True),
        ("linux", {}, False),
        ("win32", {}, False),
        ("linux", {"IRONDOME_NO_TOUCH": "0"}, False),
    ],
)
def test_when_a_touch_prompt_can_be_shown(monkeypatch, platform, environment, expected):
    monkeypatch.setattr(unlock, "sys", types.SimpleNamespace(platform=platform))
    for name in ("IRONDOME_NO_TOUCH", "SSH_CONNECTION", "SSH_TTY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    assert can_ask_for_touch() is expected


def test_the_suite_itself_runs_with_touch_prompts_switched_off():
    assert os.environ["IRONDOME_NO_TOUCH"] == "1" and can_ask_for_touch() is False


# ---------------------------------------------------------------------------
# Password mode
# ---------------------------------------------------------------------------


def test_password_mode_makes_a_password_slot_and_a_recovery_slot(make_vault):
    vault, recovery = make_vault()
    assert isinstance(vault, Vault) and vault.entries == {}
    assert slots_of(vault) == [
        ("password", "software", "device", "master password"),
        ("recovery", None, None, "recovery key"),
    ]
    assert isinstance(recovery, str) and len(recovery) == 39 and len(keys.parse_recovery_key(recovery)) == 20
    assert paths.vault_file().is_file() and len(key_files()) == 1
    assert vault.file.slots[0].kdf["m"] == 19 * 1024  # the suite's reduced cost, taken from the environment
    assert recovery.encode() not in paths.vault_file().read_bytes()
    assert PASSWORD.encode() not in paths.vault_file().read_bytes()


def test_password_mode_without_a_recovery_key(make_vault):
    vault, recovery = make_vault(with_recovery=False)
    assert recovery is None
    assert slots_of(vault) == [("password", "software", "device", "master password")]


def test_the_cost_and_the_path_can_be_chosen(make_vault, isolated):
    params = Argon2Params(memory_kib=32 * 1024, iterations=2, lanes=2)
    target = isolated / "elsewhere" / "my.irondome"
    vault, _ = make_vault(params=params, path=target)
    assert vault.path == target and target.is_file() and not paths.vault_file().exists()
    kdf = vault.file.slots[0].kdf
    assert (kdf["m"], kdf["t"], kdf["p"]) == (32 * 1024, 2, 2)
    with secret() as password, open_vault(path=target, password=password, interactive=False) as opened:
        assert opened.vault_id == vault.vault_id


def test_password_mode_opens_with_the_password(make_vault):
    vault, _ = make_vault()
    file = VaultFile.load()
    with secret() as password, unlock.unlock(file, password=password, interactive=False) as key:
        assert same_key(key, vault.vault_key)
        assert not password.wiped  # the caller's buffer stays the caller's
    source = Source()
    with unlock.unlock(file, password_source=source, interactive=False) as key:
        assert same_key(key, vault.vault_key)
    assert source.asked == 1 and source.handed[0].wiped  # what unlock asked for, unlock wipes


@pytest.mark.parametrize("wrong", ["wrong password", PASSWORD + " ", PASSWORD.upper(), PASSWORD[:-1]])
def test_password_mode_refuses_a_wrong_password(make_vault, wrong):
    make_vault()
    file = VaultFile.load()
    with secret(wrong) as password, pytest.raises(AuthError, match="wrong master password"):
        unlock.unlock(file, password=password, interactive=False)
    source = Source(wrong)
    with pytest.raises(AuthError, match="wrong master password"):
        unlock.unlock(file, password_source=source)
    assert source.asked == 1 and source.handed[0].wiped


def test_without_a_password_or_a_way_to_ask_the_password_is_required(make_vault):
    make_vault()
    with pytest.raises(AuthError, match="the master password is required"):
        unlock.unlock(VaultFile.load())
    with pytest.raises(AuthError, match="the master password is required"):
        unlock.unlock(VaultFile.load(), interactive=False, allow_touch=False)


def test_a_prompt_that_yields_nothing_is_a_usage_error(make_vault):
    make_vault()
    source = Source(None)
    with pytest.raises(UsageError, match="needs the master password"):
        unlock.unlock(VaultFile.load(), password_source=source)
    assert source.asked == 1


def test_a_prompt_that_fails_is_not_swallowed(make_vault):
    make_vault()

    def interrupted() -> SecureBuffer:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        unlock.unlock(VaultFile.load(), password_source=interrupted)


def test_the_recovery_key_opens_the_vault_and_nothing_else_is_tried(make_vault):
    vault, recovery = make_vault()
    file = VaultFile.load()
    source = Source()
    with unlock.unlock(file, recovery_key=recovery.lower().replace("-", " "), password_source=source) as key:
        assert same_key(key, vault.vault_key)
    assert source.asked == 0
    wrong = "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"
    with pytest.raises(AuthError, match="does not open this vault"):
        unlock.unlock(file, recovery_key=wrong, password_source=source)
    with secret() as password, pytest.raises(AuthError, match="does not open this vault"):
        unlock.unlock(file, recovery_key=wrong, password=password)  # the right password does not rescue it
    with pytest.raises(AuthError, match="wrong length"):
        unlock.unlock(file, recovery_key="too short")
    assert source.asked == 0


def test_a_vault_without_a_recovery_key_says_so(make_vault):
    make_vault(with_recovery=False)
    with pytest.raises(AuthError, match="this vault has no recovery key"):
        unlock.unlock(VaultFile.load(), recovery_key="AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")


def test_any_of_several_recovery_keys_opens_the_vault(make_vault):
    vault, first = make_vault()
    slot, second = keys.create_recovery_slot(vault.vault_key, vault.vault_id)
    vault.add_slot(slot)
    vault.commit()
    file = VaultFile.load()
    for text in (first, second):
        with unlock.unlock(file, recovery_key=text) as key:
            assert same_key(key, vault.vault_key)


def test_a_vault_with_only_a_recovery_slot_needs_the_recovery_key(make_vault):
    vault, recovery = make_vault()
    removed = vault.remove_slot(vault.slots("password")[0].id)
    keys.destroy_slot_device(removed)
    vault.commit()
    file = VaultFile.load()
    with pytest.raises(VaultError, match="no keyslot that can be opened here"):
        unlock.unlock(file)
    with secret() as password, pytest.raises(VaultError, match="no keyslot that can be opened here"):
        unlock.unlock(file, password=password)
    unlock.unlock(file, recovery_key=recovery).wipe()


# ---------------------------------------------------------------------------
# What goes wrong when creating
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "arguments, error, message",
    [
        (dict(mode="pin"), UsageError, "unknown mode"),
        (dict(mode=""), UsageError, "unknown mode"),
        (dict(mode="PASSWORD"), UsageError, "unknown mode"),
        (dict(mode="password", password=None), UsageError, "needs a master password"),
        (dict(mode="touchid+password", password=None), UsageError, "needs a master password"),
        (dict(mode="password", password="short"), UsageError, "at least 8"),
        (dict(mode="touchid", password="short"), UsageError, "at least 8"),
        (dict(mode="password", backend_name="quantum"), VaultError, "unknown device backend"),
        (dict(mode="touchid"), HardwareError, "cannot enforce the biometry policy"),
        (dict(mode="touchid+password"), HardwareError, "cannot enforce the biometry policy"),
        (dict(mode="password", params=Argon2Params(memory_kib=1024)), VaultError, "memory cost"),
        (dict(mode="touchid", password=None, with_recovery=False), UsageError, "needs a second way in"),
    ],
)
def test_a_vault_that_cannot_be_created_leaves_nothing_behind(make_vault, buffers, arguments, error, message):
    with pytest.raises(error, match=message):
        make_vault(**arguments)
    assert not paths.vault_file().exists()
    assert key_files() == []
    assert alive(buffers) == []


def test_creating_over_an_existing_vault_is_refused_and_cleans_up_after_itself(make_vault):
    first, _ = make_vault()
    before = paths.vault_file().read_bytes()
    assert len(key_files()) == 1
    with pytest.raises(VaultError, match="already exists"):
        make_vault(password="another password entirely")
    assert paths.vault_file().read_bytes() == before
    assert len(key_files()) == 1  # the device key enrolled for the vault that never was is gone again
    with secret() as password:
        open_vault(password=password, interactive=False).close()


def test_a_failure_after_enrolment_destroys_what_was_enrolled(make_vault, buffers, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("the disk is full")

    monkeypatch.setattr(Vault, "create", classmethod(fail))
    with pytest.raises(OSError, match="the disk is full"):
        make_vault()
    assert key_files() == [] and alive(buffers) == []


def test_creating_a_vault_leaves_only_the_vaults_own_keys_alive(make_vault, buffers):
    vault, _ = make_vault()
    assert sorted(len(buffer) for buffer in alive(buffers)) == [32, 32]
    assert set(map(id, alive(buffers))) == {id(vault.vault_key), id(vault._index_key)}
    vault.close()
    assert alive(buffers) == []


# ---------------------------------------------------------------------------
# Touch ID mode
# ---------------------------------------------------------------------------


def touch_vault(make_vault, mode: str = MODE_TOUCHID, **kwargs) -> Tuple[Vault, Optional[str], VaultFile]:
    vault, recovery = make_vault(mode=mode, backend_name="fake-touch", **kwargs)
    return vault, recovery, VaultFile.load()


def test_touchid_mode_enrols_a_finger_and_keeps_the_password_as_a_fallback(make_vault, touch):
    vault, recovery, _ = touch_vault(make_vault)
    assert slots_of(vault) == [
        ("device", "fake-touch", "biometry", "Touch ID"),
        ("password", "fake-touch", "device", "master password (fallback)"),
        ("recovery", None, None, "recovery key"),
    ]
    assert touch.prompts == [("enroll", "enrol Touch ID for your IronDome vault")]
    assert len(touch.secrets) == 2 and recovery is not None


def test_touch_id_is_tried_first_and_the_password_is_never_asked_for(make_vault, touch):
    vault, _, file = touch_vault(make_vault)
    source = Source()
    with unlock.unlock(file, password_source=source, reason=REASON) as key:
        assert same_key(key, vault.vault_key)
    assert source.asked == 0
    assert touch.prompts[-1] == ("unseal", REASON) and touch.unseals() == 1
    with unlock.unlock(file) as key:  # and it needs no way to ask for a password at all
        assert same_key(key, vault.vault_key)
    assert touch.unseals() == 2


def test_a_cancelled_touch_falls_back_to_the_master_password(make_vault, touch):
    vault, _, file = touch_vault(make_vault)
    touch.finger = "refuse"
    source = Source()
    with unlock.unlock(file, password_source=source) as key:
        assert same_key(key, vault.vault_key)
    assert touch.unseals() == 1 and source.asked == 1 and source.handed[0].wiped
    wrong = Source("not the password")
    with pytest.raises(AuthError, match="wrong master password"):
        unlock.unlock(file, password_source=wrong)
    assert wrong.asked == 1 and wrong.handed[0].wiped


def test_a_cancelled_touch_with_no_way_to_ask_for_the_password_reports_the_cancellation(make_vault, touch):
    _, _, file = touch_vault(make_vault)
    touch.finger = "refuse"
    with pytest.raises(AuthError, match="cancelled"):
        unlock.unlock(file)


def test_a_password_supplied_up_front_means_no_touch_prompt(make_vault, touch):
    vault, _, file = touch_vault(make_vault)
    with secret() as password, unlock.unlock(file, password=password) as key:
        assert same_key(key, vault.vault_key)
    assert touch.unseals() == 0
    with secret("not the password") as password, pytest.raises(AuthError, match="wrong master password"):
        unlock.unlock(file, password=password)
    assert touch.unseals() == 0


@pytest.mark.parametrize(
    "why",
    ["allow_touch=False", "interactive=False", "IRONDOME_NO_TOUCH", "SSH_CONNECTION", "SSH_TTY", "not macOS"],
)
def test_no_prompt_appears_where_prompts_are_ruled_out(make_vault, touch, monkeypatch, why):
    vault, _, file = touch_vault(make_vault)
    arguments = {}
    if why == "allow_touch=False":
        arguments["allow_touch"] = False
    elif why == "interactive=False":
        arguments["interactive"] = False
    elif why == "IRONDOME_NO_TOUCH":
        monkeypatch.setenv("IRONDOME_NO_TOUCH", "1")
    elif why == "SSH_CONNECTION":
        monkeypatch.setenv("SSH_CONNECTION", "10.0.0.2 51234 10.0.0.1 22")
    elif why == "SSH_TTY":
        monkeypatch.setenv("SSH_TTY", "/dev/ttys003")
    else:
        monkeypatch.setattr(unlock, "sys", types.SimpleNamespace(platform="linux"))
    source = Source()
    with unlock.unlock(file, password_source=source, **arguments) as key:
        assert same_key(key, vault.vault_key)
    assert touch.unseals() == 0 and source.asked == 1
    with pytest.raises(AuthError, match="the master password is required"):
        unlock.unlock(file, **arguments)
    assert touch.unseals() == 0


def test_a_touch_slot_whose_key_is_gone_falls_back_to_the_password(make_vault, touch):
    vault, _, file = touch_vault(make_vault)
    finger_slot = file.slots[0]
    touch.destroy(finger_slot.device)
    source = Source()
    with unlock.unlock(file, password_source=source) as key:
        assert same_key(key, vault.vault_key)
    assert source.asked == 1
    with pytest.raises(HardwareError, match="does not hold this key"):
        unlock.unlock(file)


def test_a_damaged_touch_slot_does_not_block_the_password(make_vault, touch):
    """A descriptor the backend refuses is a damaged vault file, but the password slot is intact."""
    vault, _, _ = touch_vault(make_vault)
    for damage in ({"ref": "../../etc/passwd"}, {"policy": "nonsense"}, {"backend": "quantum"}):
        file = VaultFile.load()
        file.slots[0].device = dict(file.slots[0].device, **damage)
        source = Source()
        with unlock.unlock(file, password_source=source) as key:
            assert same_key(key, vault.vault_key)
        assert source.asked == 1
        with pytest.raises(VaultError):
            unlock.unlock(file)


def test_the_recovery_key_needs_neither_finger_nor_password(make_vault, touch):
    vault, recovery, file = touch_vault(make_vault)
    touch.finger = "refuse"
    touch.secrets.clear()  # the chip is gone altogether
    source = Source()
    with unlock.unlock(file, recovery_key=recovery, password_source=source) as key:
        assert same_key(key, vault.vault_key)
    assert touch.unseals() == 0 and source.asked == 0


def test_several_enrolled_fingers_are_tried_in_turn(make_vault, touch):
    vault, _, _ = touch_vault(make_vault)
    second = keys.create_device_slot(vault.vault_key, vault.vault_id, backend=touch, policy=POLICY_BIOMETRY)
    vault.add_slot(second)
    vault.commit()
    file = VaultFile.load()
    touch.destroy(file.slots[0].device)  # the first enrolment no longer works
    before = touch.unseals()
    with unlock.unlock(file) as key:
        assert same_key(key, vault.vault_key)
    assert touch.unseals() == before + 1


def test_a_cancelled_prompt_is_not_followed_by_another(make_vault, touch):
    """Two Touch ID slots, one cancel: the person is asked once, then the password takes over."""
    vault, _, _ = touch_vault(make_vault)
    second = keys.create_device_slot(vault.vault_key, vault.vault_id, backend=touch, policy=POLICY_BIOMETRY)
    vault.add_slot(second)
    vault.commit()
    file = VaultFile.load()
    assert [slot.kind for slot in file.slots].count("device") == 2
    touch.finger = "refuse"
    before = touch.unseals()
    source = Source()
    with unlock.unlock(file, password_source=source) as key:
        assert same_key(key, vault.vault_key)
    assert touch.unseals() == before + 1 and source.asked == 1
    with pytest.raises(AuthError, match="cancelled"):
        unlock.unlock(file)
    assert touch.unseals() == before + 2


# -- Touch ID with no password at all ----------------------------------------


def test_a_vault_can_be_touch_only(make_vault, touch):
    vault, recovery, file = touch_vault(make_vault, password=None)
    assert slots_of(vault) == [
        ("device", "fake-touch", "biometry", "Touch ID"),
        ("recovery", None, None, "recovery key"),
    ]
    with unlock.unlock(file) as key:
        assert same_key(key, vault.vault_key)
    with unlock.unlock(file, recovery_key=recovery) as key:
        assert same_key(key, vault.vault_key)


def test_a_touch_only_vault_says_clearly_when_it_cannot_ask(make_vault, touch, monkeypatch):
    vault, _, _ = touch_vault(make_vault, password=None)
    vault.remove_slot(vault.slots("recovery")[0].id)  # create_vault itself refuses to make such a vault
    vault.commit()
    file = VaultFile.load()
    assert [slot.kind for slot in file.slots] == ["device"]
    source = Source()
    for arguments in (dict(interactive=False), dict(allow_touch=False), dict(password_source=source)):
        if "password_source" in arguments:
            monkeypatch.setenv("IRONDOME_NO_TOUCH", "1")
        with pytest.raises(AuthError, match="opens with Touch ID only, and Touch ID cannot be asked for here") as why:
            unlock.unlock(file, **arguments)
        assert "desktop session" in str(why.value) and "Run the command there" in str(why.value)
    assert source.asked == 0 and touch.unseals() == 0
    monkeypatch.delenv("IRONDOME_NO_TOUCH")
    # A password was given, so Touch ID was not tried: the refusal says that, and offers no session or token
    # (a command that unlocks afresh refuses those anyway).
    with secret() as password, pytest.raises(AuthError, match="opens with Touch ID only: it has no master pass") as why:
        unlock.unlock(file, password=password)
    assert "cannot be asked for here" not in str(why.value)
    assert "session" not in str(why.value) and "token" not in str(why.value)
    assert "Leave the password out" in str(why.value) and touch.unseals() == 0
    touch.finger = "refuse"
    with pytest.raises(AuthError, match="cancelled"):
        unlock.unlock(file, password_source=source)
    assert source.asked == 0  # there is no password slot to ask a password for
    with pytest.raises(AuthError, match="no recovery key"):
        unlock.unlock(file, recovery_key="AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")


# ---------------------------------------------------------------------------
# Touch ID and password, both required
# ---------------------------------------------------------------------------


def test_touchid_plus_password_mode_binds_the_password_slot_to_the_finger(make_vault, touch):
    vault, _, _ = touch_vault(make_vault, MODE_TOUCHID_PASSWORD)
    assert slots_of(vault) == [
        ("password", "fake-touch", "biometry", "master password + Touch ID"),
        ("recovery", None, None, "recovery key"),
    ]
    assert touch.prompts == [("enroll", "protect your IronDome vault")]


def test_both_factors_open_the_vault(make_vault, touch):
    vault, _, file = touch_vault(make_vault, MODE_TOUCHID_PASSWORD)
    with secret() as password, unlock.unlock(file, password=password, reason=REASON) as key:
        assert same_key(key, vault.vault_key)
    assert touch.prompts[-1] == ("unseal", REASON) and touch.unseals() == 1
    source = Source()
    with unlock.unlock(file, password_source=source) as key:
        assert same_key(key, vault.vault_key)
    assert source.asked == 1 and touch.unseals() == 2


def test_the_password_alone_is_not_enough(make_vault, touch):
    _, _, file = touch_vault(make_vault, MODE_TOUCHID_PASSWORD)
    touch.finger = "refuse"
    with secret() as password, pytest.raises(AuthError, match="cancelled"):
        unlock.unlock(file, password=password)
    assert touch.unseals() == 1


def test_the_finger_alone_is_not_enough(make_vault, touch):
    _, _, file = touch_vault(make_vault, MODE_TOUCHID_PASSWORD)
    with pytest.raises(AuthError, match="the master password is required"):
        unlock.unlock(file)
    with secret("not the password") as password, pytest.raises(AuthError, match="wrong master password"):
        unlock.unlock(file, password=password)


@pytest.mark.parametrize(
    "why",
    ["allow_touch=False", "interactive=False", "IRONDOME_NO_TOUCH", "SSH_CONNECTION", "SSH_TTY", "not macOS"],
)
def test_a_required_touch_is_refused_not_prompted_where_prompts_are_ruled_out(make_vault, touch, monkeypatch, why):
    """IRONDOME_NO_TOUCH and friends must hold for a password slot that needs a finger too."""
    _, _, file = touch_vault(make_vault, MODE_TOUCHID_PASSWORD)
    arguments = {}
    if why == "allow_touch=False":
        arguments["allow_touch"] = False
    elif why == "interactive=False":
        arguments["interactive"] = False
    elif why == "IRONDOME_NO_TOUCH":
        monkeypatch.setenv("IRONDOME_NO_TOUCH", "1")
    elif why == "SSH_CONNECTION":
        monkeypatch.setenv("SSH_CONNECTION", "10.0.0.2 51234 10.0.0.1 22")
    elif why == "SSH_TTY":
        monkeypatch.setenv("SSH_TTY", "/dev/ttys003")
    else:
        monkeypatch.setattr(unlock, "sys", types.SimpleNamespace(platform="linux"))
    with secret() as password, pytest.raises(AuthError, match="cannot be asked for here"):
        unlock.unlock(file, password=password, **arguments)
    assert touch.unseals() == 0


def test_a_silent_device_key_is_used_whether_or_not_prompts_are_allowed(make_vault, touch, monkeypatch):
    """Ruling out prompts must not get in the way of a slot that needs none."""
    vault, _ = make_vault(mode=MODE_PASSWORD, backend_name="fake-touch")
    file = VaultFile.load()
    monkeypatch.setenv("IRONDOME_NO_TOUCH", "1")
    ways = (dict(), dict(interactive=False), dict(allow_touch=False), dict(interactive=False, allow_touch=False))
    for arguments in ways:
        with secret() as password, unlock.unlock(file, password=password, **arguments) as key:
            assert same_key(key, vault.vault_key)
    assert touch.prompts == []


# ---------------------------------------------------------------------------
# Which failure is reported
# ---------------------------------------------------------------------------


def vault_with_a_portable_slot(make_vault, portable_first: bool) -> Tuple[Vault, VaultFile]:
    """A device-bound password slot and a portable one for the same password."""
    vault, _ = make_vault(with_recovery=False)
    bound = vault.slots("password")[0]
    with secret() as password:
        portable = keys.create_password_slot(
            vault.vault_key, password, vault.vault_id, params=Argon2Params(memory_kib=19 * 1024), backend=None
        )
    vault.add_slot(portable)
    if portable_first:
        vault.file.slots.reverse()
    vault.commit()
    keys.destroy_slot_device(bound)  # this machine no longer has the device key
    return vault, VaultFile.load()


@pytest.mark.parametrize("portable_first", [False, True])
def test_a_wrong_password_is_reported_rather_than_a_missing_device(make_vault, portable_first):
    vault, file = vault_with_a_portable_slot(make_vault, portable_first)
    with secret("not the password") as password, pytest.raises(AuthError, match="wrong master password") as caught:
        unlock.unlock(file, password=password, interactive=False)
    assert type(caught.value) is AuthError
    with secret() as password, unlock.unlock(file, password=password, interactive=False) as key:
        assert same_key(key, vault.vault_key)  # and the slot that still works opens


def test_a_missing_device_is_reported_when_that_is_all_that_is_wrong(make_vault):
    vault, _ = make_vault()
    keys.destroy_slot_device(vault.slots("password")[0])
    for text in (PASSWORD, "not the password"):
        with secret(text) as password, pytest.raises(HardwareError, match="not on this machine"):
            unlock.unlock(VaultFile.load(), password=password, interactive=False)


def test_a_vault_file_naming_a_backend_this_machine_lacks_fails_cleanly(make_vault, monkeypatch):
    make_vault()
    file = VaultFile.load()
    file.slots[0].device = dict(file.slots[0].device, backend="quantum")
    with secret() as password, pytest.raises(VaultError, match="unknown device backend"):
        unlock.unlock(file, password=password, interactive=False)
    monkeypatch.setattr(device, "_REGISTRY", device._REGISTRY + (("ghost", "irondome.device.no_such_backend", "X"),))
    file.slots[0].device = dict(file.slots[0].device, backend="ghost")
    with secret() as password, pytest.raises(HardwareError, match="cannot be loaded"):
        unlock.unlock(file, password=password, interactive=False)


# ---------------------------------------------------------------------------
# Nothing derived along the way outlives the call
# ---------------------------------------------------------------------------


def test_unlocking_leaves_only_the_vault_key_alive(make_vault, touch, buffers):
    vault, recovery, file = touch_vault(make_vault)
    password = secret()
    vault.close()
    del buffers[:]
    source = Source()
    attempts = [
        dict(),
        dict(password=password),
        dict(password_source=source, allow_touch=False),
        dict(recovery_key=recovery),
    ]
    for arguments in attempts:
        key = unlock.unlock(file, **arguments)
        assert alive(buffers, password) == [key], arguments
        key.wipe()
    assert alive(buffers, password) == []
    password.wipe()


def test_a_failed_unlock_leaves_nothing_alive(make_vault, touch, buffers):
    vault, recovery, file = touch_vault(make_vault)
    wrong = secret("not the password")
    vault.close()
    del buffers[:]
    touch.finger = "refuse"
    failures = [
        (dict(), AuthError),
        (dict(password=wrong), AuthError),
        (dict(password_source=Source("also not the password")), AuthError),
        (dict(password_source=Source(None)), UsageError),
        (dict(recovery_key="AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"), AuthError),
        (dict(interactive=False), AuthError),
    ]
    for arguments, error in failures:
        with pytest.raises(error):
            unlock.unlock(file, **arguments)
        assert alive(buffers, wrong) == [], arguments
    wrong.wipe()


# ---------------------------------------------------------------------------
# open_vault, end to end
# ---------------------------------------------------------------------------


def test_open_vault_returns_an_open_vault(vault):
    vault.close()
    with secret() as password, open_vault(password=password, interactive=False) as opened:
        assert isinstance(opened, Vault)
        assert sorted(entry.name for entry in opened.list()) == ["aws/prod", "github"]
        assert opened.value(*opened.resolve("GITHUB_TOKEN")) == "hunter2-Github!"
        key = opened.vault_key
    assert key.wiped


def test_open_vault_without_a_vault(isolated):
    with secret() as password, pytest.raises(VaultError, match="there is no vault at .*irondome init"):
        open_vault(password=password)
    with pytest.raises(VaultError, match="there is no vault"):
        open_vault(path=isolated / "nowhere.irondome", recovery_key="AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")


def test_open_vault_with_the_wrong_password_opens_nothing(vault, buffers):
    vault.close()
    del buffers[:]
    with secret("not the password") as password:
        with pytest.raises(AuthError, match="wrong master password"):
            open_vault(password=password, interactive=False)
        assert alive(buffers, password) == []


def test_open_vault_passes_every_factor_through(make_vault, touch):
    vault, recovery, _ = touch_vault(make_vault)
    entry = vault.add("site", Secret(password="value"))
    vault.commit()
    vault.close()
    ways = [
        dict(reason=REASON),
        dict(password_source=Source(), allow_touch=False),
        dict(password_source=Source(), interactive=False),
        dict(recovery_key=recovery),
    ]
    for arguments in ways:
        with open_vault(**arguments) as opened:
            assert opened.value(opened.entries[entry.id]) == "value"
    assert touch.prompts[-1] == ("unseal", REASON) and touch.unseals() == 1


def test_a_vault_whose_index_was_altered_is_refused_and_the_key_is_wiped(vault, buffers):
    vault.close()
    file = VaultFile.load()
    file.generation += 1
    paths.write_atomic(paths.vault_file(), file.to_bytes())
    del buffers[:]
    with secret() as password:
        with pytest.raises(VaultError, match="index failed authentication"):
            open_vault(password=password, interactive=False)
        assert alive(buffers, password) == []


@pytest.mark.parametrize("mode", MODES)
def test_every_mode_round_trips_a_secret(make_vault, touch, mode):
    vault, recovery, _ = touch_vault(make_vault, mode)
    vault.add("אתר", Secret(password="סוד-\U0001f511"), username="user")
    vault.commit()
    vault.close()
    with secret() as password, open_vault(password=password, reason=REASON) as opened:
        assert opened.value(opened.find("אתר")) == "סוד-\U0001f511"
    with open_vault(recovery_key=recovery) as opened:
        assert opened.value(opened.find("אתר"), "username") == "user"


# ---------------------------------------------------------------------------
# The two properties the design exists for
# ---------------------------------------------------------------------------


def test_a_copy_of_the_vault_needs_the_device_or_the_recovery_key(vault, isolated, monkeypatch):
    """A stolen backup with the right password: no device secret, so no way in. Except by recovery key."""
    recovery_slot = vault.slots("recovery")[0]
    extra, recovery = keys.create_recovery_slot(vault.vault_key, vault.vault_id)
    vault.remove_slot(recovery_slot.id)
    vault.add_slot(extra)
    vault.commit()
    vault.close()
    stolen = isolated / "stolen"
    shutil.copytree(paths.home(), stolen)
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", str(isolated / "the-thiefs-machine"))
    device._instances.clear()
    for candidate in [stolen / "vault.irondome"] + sorted((stolen / "backups").glob("*.irondome")):
        with secret() as password, pytest.raises(HardwareError, match="not on this machine"):
            open_vault(path=candidate, password=password, interactive=False)
    with open_vault(path=stolen / "vault.irondome", recovery_key=recovery) as opened:
        assert opened.value(opened.find("github")) == "hunter2-Github!"
    assert not (isolated / "the-thiefs-machine").exists()


def test_destroying_the_device_secret_closes_every_copy_of_the_vault(vault, isolated):
    """Cryptographic erasure: a bit-perfect copy of everything but the device key no longer opens."""
    vault.remove_slot(vault.slots("recovery")[0].id)  # a vault with no recovery key: nothing is exempt
    vault.commit()
    vault.close()
    preserved = isolated / "perfect-copy"
    shutil.copytree(paths.home(), preserved)
    file = VaultFile.load()
    assert [slot.kind for slot in file.slots] == ["password"]
    for slot in file.slots:
        assert keys.destroy_slot_device(slot) is True
    assert key_files() == []
    candidates = [paths.vault_file(), preserved / "vault.irondome"] + sorted((preserved / "backups").glob("*.irondome"))
    assert len(candidates) >= 4
    for candidate in candidates:
        with secret() as password, pytest.raises(HardwareError, match="not on this machine"):
            open_vault(path=candidate, password=password, interactive=False)
        with pytest.raises((AuthError, VaultError)):
            open_vault(path=candidate, recovery_key="AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")


def test_the_vault_directory_and_the_device_directory_are_separate(make_vault):
    make_vault()
    home_files = sorted(str(item.relative_to(paths.home())) for item in paths.home().rglob("*"))
    assert home_files == [".lock", "vault.irondome"]
    assert len(key_files()) == 1
    assert not any(Path(name).suffix == ".key" for name in home_files)
