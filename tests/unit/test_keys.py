"""Keyslots: what opens each kind, what never does, and what is left in memory afterwards."""

from __future__ import annotations

import base64
import copy
import os
import re
import sys
import time
import unicodedata
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from irondome import crypto, device, keys, paths
from irondome.crypto import Argon2Params, b64d, b64e
from irondome.device.base import (
    POLICY_BIOMETRY,
    POLICY_DEVICE,
    POLICY_PRESENCE,
    DeviceBackend,
    Probe,
    check_descriptor,
    new_ref,
)
from irondome.errors import AuthError, HardwareError, UsageError, VaultError
from irondome.keys import (
    KIND_DEVICE,
    KIND_PASSWORD,
    KIND_RECOVERY,
    VAULT_ID_LEN,
    Keyslot,
    create_device_slot,
    create_password_slot,
    create_recovery_slot,
    destroy_slot_device,
    format_recovery_key,
    new_vault_key,
    normalise_password,
    open_slot,
    parse_recovery_key,
)
from irondome.secmem import SecureBuffer

CPYTHON = sys.implementation.name == "cpython"
FAST = Argon2Params(memory_kib=19 * 1024, iterations=2, lanes=4)  # the OWASP minimum
PASSWORD = b"correct horse battery staple"
VAULT_ID = bytes(range(16))


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
        self.auth_seen: List[Optional[bytes]] = []
        self.destroying = True

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
        self.auth_seen.append(None if auth is None else bytes(auth.view()))
        self._authorise("enroll", policy, True, reason)
        ref = new_ref()
        self.secrets[ref] = os.urandom(32)
        return {"backend": self.name, "policy": policy, "ref": ref}, SecureBuffer.from_buffer(self.secrets[ref])

    def unseal(self, descriptor, *, auth, interactive, reason):
        check_descriptor(descriptor, self.name)
        self.auth_seen.append(None if auth is None else bytes(auth.view()))
        secret = self.secrets.get(descriptor.get("ref"))
        if secret is None:
            raise HardwareError("the stand-in chip does not hold this key")
        self._authorise("unseal", descriptor["policy"], interactive, reason)
        return SecureBuffer.from_buffer(secret)

    def destroy(self, descriptor) -> None:
        check_descriptor(descriptor, self.name)
        if self.destroying:
            self.secrets.pop(descriptor.get("ref"), None)

    def exists(self, descriptor) -> bool:
        check_descriptor(descriptor, self.name)
        return descriptor.get("ref") in self.secrets

    def destroy_all(self) -> int:
        count = len(self.secrets)
        self.secrets.clear()
        return count


@pytest.fixture
def touch(monkeypatch: pytest.MonkeyPatch) -> FakeTouch:
    fake = FakeTouch()
    monkeypatch.setattr(device, "_REGISTRY", device._REGISTRY + (("fake-touch", "irondome.no_such_module", "X"),))
    monkeypatch.setitem(device._instances, "fake-touch", fake)
    return fake


@pytest.fixture
def software() -> DeviceBackend:
    return device.get_backend("software")


@pytest.fixture
def vault_key() -> Iterator[SecureBuffer]:
    key = new_vault_key()
    yield key
    key.wipe()


@pytest.fixture
def buffers(monkeypatch: pytest.MonkeyPatch) -> List[SecureBuffer]:
    """Every SecureBuffer created while the test runs, so it can be asked which are still alive."""
    made: List[SecureBuffer] = []
    real_init = SecureBuffer.__init__

    def recording_init(self, size):
        real_init(self, size)
        made.append(self)

    monkeypatch.setattr(SecureBuffer, "__init__", recording_init)
    return made


def alive(made: List[SecureBuffer], *keep: SecureBuffer) -> List[SecureBuffer]:
    return [buffer for buffer in made if not buffer.wiped and all(buffer is not kept for kept in keep)]


def key_files() -> List[str]:
    directory = paths.device_dir()
    return sorted(item.name for item in directory.glob("*.key")) if directory.is_dir() else []


def same_key(first: SecureBuffer, second: SecureBuffer) -> bool:
    return bytes(first.view()) == bytes(second.view())


def password_slot(vault_key: SecureBuffer, backend: Optional[DeviceBackend], password: bytes = PASSWORD, **kwargs):
    kwargs.setdefault("params", FAST)
    return create_password_slot(vault_key, password, VAULT_ID, backend=backend, **kwargs)


# ---------------------------------------------------------------------------
# The vault key
# ---------------------------------------------------------------------------


def test_a_vault_key_is_32_random_bytes_in_locked_memory():
    with new_vault_key() as first, new_vault_key() as second:
        assert isinstance(first, SecureBuffer) and len(first) == 32
        assert bytes(first.view()) != bytes(32)
        assert not same_key(first, second)


# ---------------------------------------------------------------------------
# Password slots
# ---------------------------------------------------------------------------


def test_a_password_slot_records_everything_needed_to_open_it_and_nothing_secret(vault_key, software):
    before = int(time.time())
    slot = password_slot(vault_key, software, label="master password")
    assert slot.kind == KIND_PASSWORD and slot.needs_password is True
    assert re.fullmatch(r"[0-9a-f]{32}", slot.id)
    assert before <= slot.created <= int(time.time()) and slot.label == "master password"
    assert slot.kdf is not None and slot.kdf["alg"] == "argon2id"
    assert (slot.kdf["m"], slot.kdf["t"], slot.kdf["p"]) == (19 * 1024, 2, 4)
    assert len(b64d(slot.kdf["salt"])) == 16
    assert slot.salt is None
    assert slot.device is not None and slot.device["backend"] == "software" and slot.device["policy"] == POLICY_DEVICE
    assert slot.backend_name == "software" and slot.policy == POLICY_DEVICE
    assert len(b64d(slot.wrap)) == 12 + 32 + 16
    assert slot.describe() == "master password + device key (software)"
    stored = repr(slot.to_dict()).encode()
    assert bytes(vault_key.view()) not in stored and PASSWORD not in stored
    assert b64e(vault_key) not in repr(slot.to_dict())
    assert key_files() == [f"{slot.device['ref']}.key"]


def test_a_password_slot_opens_with_the_password_on_this_device(vault_key, software):
    slot = password_slot(vault_key, software)
    with open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False) as opened:
        assert isinstance(opened, SecureBuffer) and same_key(opened, vault_key)
    restored = Keyslot.from_dict(slot.to_dict())
    with open_slot(restored, VAULT_ID, password=PASSWORD, interactive=False) as opened:
        assert same_key(opened, vault_key)


@pytest.mark.parametrize("kind", ["bytes", "bytearray", "memoryview", "securebuffer"])
def test_the_password_may_arrive_in_any_buffer(vault_key, software, kind):
    slot = password_slot(vault_key, software)
    source: Any = {
        "bytes": PASSWORD,
        "bytearray": bytearray(PASSWORD),
        "memoryview": memoryview(PASSWORD),
        "securebuffer": SecureBuffer.from_buffer(PASSWORD),
    }[kind]
    with open_slot(slot, VAULT_ID, password=source, interactive=False) as opened:
        assert same_key(opened, vault_key)
    if isinstance(source, SecureBuffer):
        assert bytes(source.view()) == PASSWORD  # the caller's buffer is neither changed nor wiped
        source.wipe()


@pytest.mark.parametrize(
    "wrong",
    [
        b"correct horse battery stapl",
        b"correct horse battery staple ",
        b" correct horse battery staple",
        b"Correct horse battery staple",
        b"correct horse battery staple\n",
        b"correct horse battery staple\x00",
        b"x",
        "correct horse battery stapl\xe9".encode(),
    ],
)
def test_a_wrong_password_is_refused(vault_key, software, wrong):
    slot = password_slot(vault_key, software)
    with pytest.raises(AuthError, match="wrong master password"):
        open_slot(slot, VAULT_ID, password=wrong, interactive=False)


def test_a_password_slot_needs_a_password(vault_key, software):
    slot = password_slot(vault_key, software)
    with pytest.raises(UsageError, match="needs the master password"):
        open_slot(slot, VAULT_ID, interactive=False)
    with pytest.raises(UsageError, match="needs the master password"):
        open_slot(slot, VAULT_ID, recovery_key="AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", interactive=False)
    with pytest.raises(UsageError, match="cannot be empty"):
        open_slot(slot, VAULT_ID, password=b"", interactive=False)


def test_the_right_password_is_not_enough_without_the_device_key(vault_key, software):
    """The property the whole design rests on: no device secret, no way in."""
    slot = password_slot(vault_key, software)
    path = paths.device_dir() / f"{slot.device['ref']}.key"
    original = path.read_bytes()
    path.unlink()
    with pytest.raises(HardwareError, match="not on this machine"):
        open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False)
    path.write_bytes(os.urandom(32))  # some other machine's key
    with pytest.raises(AuthError):
        open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False)
    flipped = bytearray(original)
    flipped[0] ^= 1
    path.write_bytes(bytes(flipped))
    with pytest.raises(AuthError):
        open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False)
    path.write_bytes(original)
    open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False).wipe()


def test_a_portable_slot_has_no_device_factor(vault_key):
    slot = password_slot(vault_key, None)
    assert slot.device is None and slot.backend_name is None and slot.policy is None
    assert slot.describe() == "master password"
    assert key_files() == []
    with open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False) as opened:
        assert same_key(opened, vault_key)
    with pytest.raises(AuthError, match="wrong master password"):
        open_slot(slot, VAULT_ID, password=b"something else", interactive=False)


def test_every_slot_gets_its_own_id_salt_device_key_and_wrap(vault_key, software):
    slots = [password_slot(vault_key, software) for _ in range(3)]
    for field in (lambda s: s.id, lambda s: s.wrap, lambda s: s.kdf["salt"], lambda s: s.device["ref"]):
        assert len({field(slot) for slot in slots}) == 3
    assert len(key_files()) == 3


def test_the_stored_cost_is_what_derivation_uses(vault_key, software):
    costly = Argon2Params(memory_kib=48 * 1024, iterations=2, lanes=2)
    slot = password_slot(vault_key, software, params=costly)
    assert (slot.kdf["m"], slot.kdf["t"], slot.kdf["p"]) == (48 * 1024, 2, 2)
    open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False).wipe()
    # A cheaper cost written into the file is a different derivation: the slot no longer opens.
    for key, value in (("m", 19 * 1024), ("t", 1), ("p", 4)):
        cheaper = copy.deepcopy(slot)
        cheaper.kdf[key] = value
        with pytest.raises(AuthError, match="wrong master password"):
            open_slot(cheaper, VAULT_ID, password=PASSWORD, interactive=False)
    # A cost below the OWASP minimum is refused before any derivation is attempted.
    below_floor = copy.deepcopy(slot)
    below_floor.kdf.update(m=19 * 1024, t=1)
    with pytest.raises(VaultError, match="OWASP"):
        open_slot(below_floor, VAULT_ID, password=PASSWORD, interactive=False)
    other_salt = copy.deepcopy(slot)
    other_salt.kdf["salt"] = b64e(bytes(16))
    with pytest.raises(AuthError):
        open_slot(other_salt, VAULT_ID, password=PASSWORD, interactive=False)


@pytest.mark.parametrize(
    "kdf",
    [
        {"alg": "argon2id", "salt": b64e(bytes(16)), "m": 1024, "t": 1, "p": 1},
        {"alg": "argon2id", "salt": b64e(bytes(16)), "m": 2**40, "t": 1, "p": 1},
        {"alg": "argon2id", "salt": b64e(bytes(16)), "m": 65536, "t": 1000, "p": 1},
        {"alg": "argon2id", "salt": b64e(bytes(8)), "m": 65536, "t": 1, "p": 1},
        {"alg": "argon2id", "salt": "not base64", "m": 65536, "t": 1, "p": 1},
        {"alg": "argon2id", "m": 65536, "t": 1, "p": 1},
        {"alg": "argon2id", "salt": b64e(bytes(16))},
    ],
)
def test_hostile_cost_parameters_are_refused_before_any_work_is_done(vault_key, software, kdf, monkeypatch):
    slot = password_slot(vault_key, software)
    slot.kdf = kdf
    monkeypatch.setattr(crypto, "Argon2id", lambda **kwargs: pytest.fail("derivation must not start"))
    with pytest.raises(VaultError):
        open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False)


def test_a_password_slot_without_parameters_is_a_damaged_vault_not_a_crash(vault_key, software):
    slot = password_slot(vault_key, software)
    slot.kdf = None
    with pytest.raises(VaultError, match="no Argon2id parameters"):
        open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False)


@pytest.mark.parametrize("vault_id", [b"", bytes(15), bytes(17), bytes(32)])
def test_the_vault_id_must_be_16_bytes(vault_key, software, vault_id):
    with pytest.raises(VaultError, match="vault id"):
        create_password_slot(vault_key, PASSWORD, vault_id, params=FAST, backend=software)
    with pytest.raises(VaultError, match="vault id"):
        create_recovery_slot(vault_key, vault_id)
    slot = password_slot(vault_key, software)
    with pytest.raises(VaultError, match="vault id"):
        open_slot(slot, vault_id, password=PASSWORD, interactive=False)
    assert VAULT_ID_LEN == 16


def test_the_device_gets_the_same_password_derived_value_at_enrolment_and_at_unlock(vault_key, touch):
    """Backends that can make the chip check the password (TPM) depend on this value being stable."""
    slot = password_slot(vault_key, touch)
    open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False).wipe()
    with pytest.raises(AuthError):
        open_slot(slot, VAULT_ID, password=b"a wrong password", interactive=False)
    enrolled, right, wrong = touch.auth_seen
    assert enrolled is not None and len(enrolled) == 32
    assert right == enrolled and wrong != enrolled
    assert enrolled != bytes(vault_key.view()) and PASSWORD not in enrolled
    other = password_slot(vault_key, touch)  # bound to its own slot: not reusable across slots
    assert touch.auth_seen[-1] != enrolled and other.id != slot.id


def test_a_password_slot_whose_device_key_needs_a_finger(vault_key, touch):
    slot = password_slot(vault_key, touch, policy=POLICY_BIOMETRY, reason="set up the test vault")
    assert touch.prompts == [("enroll", "set up the test vault")]
    assert slot.describe() == "master password + Touch ID (fake-touch)"
    with pytest.raises(AuthError, match="cannot be asked for here"):
        open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False)
    with open_slot(slot, VAULT_ID, password=PASSWORD, interactive=True, reason="open the test vault") as opened:
        assert same_key(opened, vault_key)
    assert touch.prompts[-1] == ("unseal", "open the test vault")
    touch.finger = "refuse"
    with pytest.raises(AuthError, match="cancelled"):
        open_slot(slot, VAULT_ID, password=PASSWORD, interactive=True)
    touch.finger = "present"
    with pytest.raises(AuthError, match="wrong master password"):
        open_slot(slot, VAULT_ID, password=b"not the password", interactive=True)


# ---------------------------------------------------------------------------
# Device (Touch ID) slots
# ---------------------------------------------------------------------------


def test_a_device_slot_opens_with_the_finger_alone(vault_key, touch):
    slot = create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY, label="Touch ID")
    assert slot.kind == KIND_DEVICE and slot.needs_password is False
    assert slot.kdf is None and slot.salt is None and slot.label == "Touch ID"
    assert slot.device["policy"] == POLICY_BIOMETRY and slot.describe() == "Touch ID (fake-touch)"
    assert touch.auth_seen == [None]
    with open_slot(slot, VAULT_ID, interactive=True, reason="open the test vault") as opened:
        assert same_key(opened, vault_key)
    assert touch.prompts == [("enroll", "enrol Touch ID for your IronDome vault"), ("unseal", "open the test vault")]
    with open_slot(Keyslot.from_dict(slot.to_dict()), VAULT_ID, password=b"ignored", interactive=True) as opened:
        assert same_key(opened, vault_key)


def test_a_device_slot_stays_shut_without_the_finger(vault_key, touch):
    slot = create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY)
    with pytest.raises(AuthError, match="cannot be asked for here"):
        open_slot(slot, VAULT_ID, interactive=False)
    touch.finger = "refuse"
    with pytest.raises(AuthError, match="cancelled"):
        open_slot(slot, VAULT_ID, interactive=True)
    touch.finger = "present"
    touch.secrets.clear()
    with pytest.raises(HardwareError, match="does not hold this key"):
        open_slot(slot, VAULT_ID, interactive=True)


def test_a_device_slot_opens_only_with_its_own_device_secret(vault_key, touch):
    slot = create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY)
    touch.secrets[slot.device["ref"]] = os.urandom(32)
    with pytest.raises(AuthError, match="device key does not open the vault"):
        open_slot(slot, VAULT_ID, interactive=True)


def test_a_presence_policy_slot(vault_key, touch):
    slot = create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_PRESENCE)
    assert slot.describe() == "Touch ID or login password (fake-touch)"
    with open_slot(slot, VAULT_ID, interactive=True) as opened:
        assert same_key(opened, vault_key)


def test_a_slot_with_no_password_must_require_a_person(vault_key, touch, software):
    with pytest.raises(UsageError, match="biometric or presence"):
        create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_DEVICE)
    with pytest.raises(UsageError):
        create_device_slot(vault_key, VAULT_ID, backend=software, policy=POLICY_DEVICE)
    assert touch.secrets == {} and key_files() == []


def test_a_backend_without_a_sensor_cannot_make_a_device_slot(vault_key, software):
    with pytest.raises(HardwareError, match="cannot enforce"):
        create_device_slot(vault_key, VAULT_ID, backend=software, policy=POLICY_BIOMETRY)
    assert key_files() == []


# ---------------------------------------------------------------------------
# Recovery slots and recovery keys
# ---------------------------------------------------------------------------

RECOVERY_SHAPE = re.compile(r"[A-Z2-7]{4}(-[A-Z2-7]{4}){7}")


def test_a_recovery_slot_and_its_key(vault_key):
    slot, text = create_recovery_slot(vault_key, VAULT_ID, label="recovery key")
    assert slot.kind == KIND_RECOVERY and slot.needs_password is False
    assert slot.device is None and slot.kdf is None and slot.label == "recovery key"
    assert len(b64d(slot.salt)) == 16
    assert slot.describe() == "recovery key"
    assert RECOVERY_SHAPE.fullmatch(text) and len(text) == 39
    assert len(parse_recovery_key(text)) == 20  # 160 bits
    assert text not in repr(slot.to_dict()) and text.replace("-", "") not in repr(slot.to_dict())
    with open_slot(slot, VAULT_ID, recovery_key=text) as opened:
        assert same_key(opened, vault_key)
    with open_slot(Keyslot.from_dict(slot.to_dict()), VAULT_ID, recovery_key=text) as opened:
        assert same_key(opened, vault_key)


def test_the_recovery_key_is_accepted_however_a_person_types_it(vault_key):
    slot, text = create_recovery_slot(vault_key, VAULT_ID)
    bare = text.replace("-", "")
    variants = [
        text.lower(),
        bare,
        bare.lower(),
        text.replace("-", " "),
        "  " + text + "\n",
        text.replace("-", " - "),
        text.replace("-", "."),
        "\t".join(bare[i : i + 8] for i in range(0, 32, 8)),
        "".join(char.lower() if index % 2 else char for index, char in enumerate(text)),
    ]
    for variant in variants:
        with open_slot(slot, VAULT_ID, recovery_key=variant) as opened:
            assert same_key(opened, vault_key), variant


def test_look_alike_characters_are_read_as_the_letters_they_resemble():
    """Base32 has no 0, 1 or 8, so a typed 0, 1 or 8 can only have been O, I or B."""
    text = "OOOO-IIII-BBBB-OIBO-IBOI-BOIB-ABCD-2345"
    raw = parse_recovery_key(text)
    assert format_recovery_key(raw) == text
    assert parse_recovery_key("0000-1111-8888-0180-1801-8018-ABCD-2345") == raw
    assert parse_recovery_key("0o0O-1i1I-8b8B-oIb0-i8O1-80ib-abcd-2345") == raw


def test_a_wrong_recovery_key_is_refused(vault_key):
    slot, text = create_recovery_slot(vault_key, VAULT_ID)
    _, other = create_recovery_slot(vault_key, VAULT_ID)
    assert other != text
    with pytest.raises(AuthError, match="does not open this vault"):
        open_slot(slot, VAULT_ID, recovery_key=other)
    last = "B" if text[-1] != "B" else "C"
    with pytest.raises(AuthError, match="does not open this vault"):
        open_slot(slot, VAULT_ID, recovery_key=text[:-1] + last)
    with pytest.raises(UsageError, match="needs the recovery key"):
        open_slot(slot, VAULT_ID, password=PASSWORD)
    with pytest.raises(UsageError, match="needs the recovery key"):
        open_slot(slot, VAULT_ID)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "    ",
        "AAAA",
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAA",
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAAA",
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA",
        "correct horse battery staple",
        "----------------------------------------",
    ],
)
def test_a_recovery_key_of_the_wrong_length_is_refused(text):
    with pytest.raises(AuthError, match="wrong length"):
        parse_recovery_key(text)


@pytest.mark.parametrize(
    "text",
    [
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAA9",  # 9 is not in the alphabet and resembles nothing in it
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAA\xe9",
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAא",
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAA\uff12",  # a full-width digit
        "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAß",
    ],
)
def test_a_recovery_key_with_impossible_characters_is_refused(text):
    with pytest.raises(AuthError, match="not a valid recovery key"):
        parse_recovery_key(text)


def test_recovery_key_formatting():
    assert format_recovery_key(bytes(20)) == "-".join(["AAAA"] * 8)
    assert format_recovery_key(b"\xff" * 20) == "-".join(["7777"] * 8)
    assert parse_recovery_key("-".join(["7777"] * 8)) == b"\xff" * 20


@given(st.binary(min_size=20, max_size=20), st.sampled_from(["", " ", "-", "  -  ", ".", "\n"]), st.booleans())
@settings(max_examples=200, deadline=None)
def test_any_recovery_key_survives_formatting_and_retyping(raw, separator, lower):
    text = format_recovery_key(raw)
    assert RECOVERY_SHAPE.fullmatch(text)
    typed = separator.join(text.split("-"))
    typed = typed.lower() if lower else typed
    assert parse_recovery_key(typed) == raw
    assert parse_recovery_key(text.replace("O", "0").replace("I", "1").replace("B", "8")) == raw


@given(st.binary(min_size=20, max_size=20))
@settings(max_examples=200, deadline=None)
def test_the_recovery_key_is_written_as_standard_base32_in_groups_of_four(raw):
    """Encoded by hand, so that no copy is left behind: the same text base64 gives, so keys on paper keep working."""
    text = format_recovery_key(raw)
    standard = base64.b32encode(raw).decode("ascii")
    assert text == "-".join(standard[i : i + 4] for i in range(0, 32, 4))
    assert parse_recovery_key(text) == raw == parse_recovery_key(text.lower().replace("-", " "))


@given(st.text(max_size=60))
@settings(max_examples=300, deadline=None)
def test_parse_recovery_key_on_arbitrary_text_decodes_or_raises_auth_error(text):
    try:
        raw = parse_recovery_key(text)
    except AuthError:
        return
    assert isinstance(raw, bytes) and len(raw) == 20


def test_a_recovery_slot_does_not_depend_on_the_device(vault_key, software, monkeypatch, isolated):
    """Its purpose: it must open a copy of the vault on a machine that never had the device key."""
    password = password_slot(vault_key, software)
    recovery, text = create_recovery_slot(vault_key, VAULT_ID)
    software.destroy_all()
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", str(isolated / "another-machine"))
    with pytest.raises(HardwareError):
        open_slot(password, VAULT_ID, password=PASSWORD, interactive=False)
    with open_slot(recovery, VAULT_ID, recovery_key=text) as opened:
        assert same_key(opened, vault_key)
    assert not (isolated / "another-machine").exists()


def test_the_raw_recovery_key_is_zeroed_once_used(vault_key, monkeypatch):
    """Made, and decoded from what was typed, straight into locked memory: never a bytes object, wiped after HKDF."""
    fed: List[Any] = []
    real_hkdf = keys.hkdf

    def recording_hkdf(ikm, info, salt=None, length=crypto.KEY_LEN):
        if info == keys._LABEL_RECOVERY:
            fed.append(ikm)
        return real_hkdf(ikm, info, salt, length)

    monkeypatch.setattr(keys, "hkdf", recording_hkdf)
    slot, text = create_recovery_slot(vault_key, VAULT_ID)
    assert len(fed) == 1
    open_slot(slot, VAULT_ID, recovery_key=text).wipe()
    assert len(fed) == 2
    assert all(isinstance(ikm, SecureBuffer) and ikm.wiped for ikm in fed)


# ---------------------------------------------------------------------------
# A wrap belongs to one slot of one vault
# ---------------------------------------------------------------------------


def test_a_slot_does_not_open_under_another_vault_id(vault_key, software, touch):
    other_id = bytes(range(1, 17))
    password = password_slot(vault_key, software)
    with pytest.raises(AuthError):
        open_slot(password, other_id, password=PASSWORD, interactive=False)
    portable = password_slot(vault_key, None)
    with pytest.raises(AuthError):
        open_slot(portable, other_id, password=PASSWORD, interactive=False)
    recovery, text = create_recovery_slot(vault_key, VAULT_ID)
    with pytest.raises(AuthError):
        open_slot(recovery, other_id, recovery_key=text)
    finger = create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY)
    with pytest.raises(AuthError):
        open_slot(finger, other_id, interactive=True)


def test_a_wrap_moved_into_another_slot_does_not_open(vault_key, software):
    """Two slots, same password, same vault: the wrapped keys are still not interchangeable."""
    first, second = password_slot(vault_key, software), password_slot(vault_key, software)
    moved = copy.deepcopy(second)
    moved.wrap = first.wrap
    with pytest.raises(AuthError):
        open_slot(moved, VAULT_ID, password=PASSWORD, interactive=False)
    renamed = copy.deepcopy(first)
    renamed.id = second.id
    with pytest.raises(AuthError):
        open_slot(renamed, VAULT_ID, password=PASSWORD, interactive=False)
    crossed = copy.deepcopy(first)
    crossed.device = second.device
    with pytest.raises(AuthError):
        open_slot(crossed, VAULT_ID, password=PASSWORD, interactive=False)
    portable_first, portable_second = password_slot(vault_key, None), password_slot(vault_key, None)
    for field in ("wrap", "id"):
        mixed = copy.deepcopy(portable_first)
        setattr(mixed, field, getattr(portable_second, field))
        with pytest.raises(AuthError):
            open_slot(mixed, VAULT_ID, password=PASSWORD, interactive=False)


def test_a_slot_cannot_be_relabelled_as_a_weaker_kind(vault_key, software, touch):
    """Turning a password slot into a device-only or portable slot must not skip the missing factor."""
    slot = password_slot(vault_key, software)
    as_device = copy.deepcopy(slot)
    as_device.kind, as_device.kdf = KIND_DEVICE, None
    with pytest.raises(AuthError):
        open_slot(as_device, VAULT_ID, interactive=True)
    without_device = copy.deepcopy(slot)
    without_device.device = None
    with pytest.raises(AuthError):
        open_slot(without_device, VAULT_ID, password=PASSWORD, interactive=False)

    both = password_slot(vault_key, touch, policy=POLICY_BIOMETRY)
    silent = copy.deepcopy(both)
    silent.device = dict(both.device, policy=POLICY_DEVICE)  # the stand-in would now answer without a finger
    with open_slot(silent, VAULT_ID, password=PASSWORD, interactive=False) as opened:
        assert same_key(opened, vault_key)  # which is why a real chip binds the policy to the key itself

    recovery, text = create_recovery_slot(vault_key, VAULT_ID)
    as_password = copy.deepcopy(slot)
    as_password.wrap = recovery.wrap
    with pytest.raises(AuthError):
        open_slot(as_password, VAULT_ID, password=PASSWORD, interactive=False)
    recovery_with_other_wrap = copy.deepcopy(recovery)
    recovery_with_other_wrap.wrap = slot.wrap
    with pytest.raises(AuthError):
        open_slot(recovery_with_other_wrap, VAULT_ID, recovery_key=text)


@given(data=st.data())
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_any_change_to_the_wrap_is_detected(data, vault_key):
    slot, text = create_recovery_slot(vault_key, VAULT_ID)
    wrap = bytearray(b64d(slot.wrap))
    position = data.draw(st.integers(min_value=0, max_value=len(wrap) - 1))
    wrap[position] ^= data.draw(st.integers(min_value=1, max_value=255))
    slot.wrap = b64e(bytes(wrap))
    with pytest.raises(AuthError):
        open_slot(slot, VAULT_ID, recovery_key=text)


# ---------------------------------------------------------------------------
# A failed enrolment leaves nothing behind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("failing", ["_wrap", "seal", "_kek", "_device_key"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_a_failed_password_enrolment_destroys_the_device_secret(vault_key, software, monkeypatch, failing, error):
    def fail(*args, **kwargs):
        raise error("enrolment interrupted")

    monkeypatch.setattr(keys, failing, fail)
    with pytest.raises(error):
        password_slot(vault_key, software)
    assert key_files() == []


@pytest.mark.parametrize("failing", ["_wrap", "seal", "_kek", "_device_key"])
def test_a_failed_device_enrolment_destroys_the_device_secret(vault_key, touch, monkeypatch, failing):
    def fail(*args, **kwargs):
        raise RuntimeError("enrolment interrupted")

    monkeypatch.setattr(keys, failing, fail)
    with pytest.raises(RuntimeError):
        create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY)
    assert touch.secrets == {}


def test_a_vault_key_of_the_wrong_size_is_refused_and_nothing_is_enrolled(software, touch):
    with SecureBuffer.random(16) as short:
        with pytest.raises(ValueError, match="32 bytes"):
            create_password_slot(short, PASSWORD, VAULT_ID, params=FAST, backend=software)
        with pytest.raises(ValueError, match="32 bytes"):
            create_device_slot(short, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY)
        with pytest.raises(ValueError, match="32 bytes"):
            create_recovery_slot(short, VAULT_ID)
    assert key_files() == [] and touch.secrets == {}


def test_a_refused_enrolment_prompt_creates_no_slot(vault_key, touch):
    touch.finger = "refuse"
    with pytest.raises(AuthError, match="cancelled"):
        create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY)
    with pytest.raises(AuthError, match="cancelled"):
        password_slot(vault_key, touch, policy=POLICY_BIOMETRY)
    assert touch.secrets == {}


def test_the_original_error_wins_when_cleanup_fails_too(vault_key, monkeypatch):
    class Stubborn(FakeTouch):
        def destroy(self, descriptor) -> None:
            raise OSError("cleanup failed as well")

    backend = Stubborn()
    monkeypatch.setattr(keys, "_wrap", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("the real problem")))
    with pytest.raises(RuntimeError, match="the real problem"):
        create_password_slot(vault_key, PASSWORD, VAULT_ID, params=FAST, backend=backend)
    assert keys._discard(backend, {"backend": "fake-touch", "policy": POLICY_DEVICE, "ref": "ab" * 16}) is False
    assert keys._discard(FakeTouch(), {"backend": "fake-touch", "policy": POLICY_DEVICE, "ref": "ab" * 16}) is True


# ---------------------------------------------------------------------------
# destroy_slot_device
# ---------------------------------------------------------------------------


def test_destroying_the_device_secret_closes_the_slot_for_good(vault_key, software):
    slot = password_slot(vault_key, software)
    kept = password_slot(vault_key, software)
    assert destroy_slot_device(slot) is True
    assert key_files() == [f"{kept.device['ref']}.key"]
    with pytest.raises(HardwareError, match="not on this machine"):
        open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False)
    open_slot(kept, VAULT_ID, password=PASSWORD, interactive=False).wipe()
    assert destroy_slot_device(slot) is True  # nothing left to destroy is still "destroyed"


def test_slots_without_a_device_have_nothing_to_destroy(vault_key):
    recovery, _ = create_recovery_slot(vault_key, VAULT_ID)
    assert destroy_slot_device(recovery) is False
    assert destroy_slot_device(password_slot(vault_key, None)) is False


def test_a_device_secret_that_survives_destruction_is_an_error(vault_key, touch):
    slot = create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY)
    touch.destroying = False
    with pytest.raises(HardwareError, match="survived destruction"):
        destroy_slot_device(slot)
    touch.destroying = True
    assert destroy_slot_device(slot) is True and touch.secrets == {}


def test_destroying_through_an_unknown_backend_is_refused(vault_key, software):
    slot = password_slot(vault_key, software)
    slot.device = dict(slot.device, backend="quantum")
    with pytest.raises(VaultError, match="unknown device backend"):
        destroy_slot_device(slot)
    assert len(key_files()) == 1


# ---------------------------------------------------------------------------
# normalise_password
# ---------------------------------------------------------------------------


def normalised(password: Any) -> bytes:
    with normalise_password(password) as buffer:
        return bytes(buffer.view())


@given(st.binary(min_size=1, max_size=200).map(lambda data: bytes(byte & 0x7F for byte in data)))
@settings(max_examples=200, deadline=None)
def test_ascii_passwords_are_used_exactly_as_typed(password):
    assert normalised(password) == password


def test_ascii_details_that_must_not_be_normalised_away():
    for password in (b"  leading and trailing  ", b"UPPER lower", b"tab\there", b"nul\x00inside", b"\x7f\x01"):
        assert normalised(password) == password


@pytest.mark.parametrize(
    "forms",
    [
        ["caf\xe9", "cafe\u0301"],  # precomposed and decomposed e-acute
        ["\xc5", "A\u030a", "\u212b"],  # A-ring, A + ring, the Angstrom sign
        ["\ud55c", "\u1112\u1161\u11ab"],  # a Hangul syllable and its jamo
        ["\u05e9\u05bc\u05c1", "\u05e9\u05c1\u05bc"],  # Hebrew shin with dagesh and shin dot, in either order
        ["\uff50\uff41\uff53\uff53", "pass"],  # full-width letters
        ["\ufb01le", "file"],  # the fi ligature
        ["x\xb2", "x2"],  # superscript two
        ["\u1e69", "s\u0323\u0307", "s\u0307\u0323"],  # two combining marks in either order
    ],
)
def test_the_same_passphrase_in_different_unicode_forms_gives_the_same_bytes(forms):
    results = {normalised(form.encode("utf-8")) for form in forms}
    assert len(results) == 1
    assert results.pop() == unicodedata.normalize("NFKC", forms[0]).encode("utf-8")


def test_unicode_forms_open_the_same_slot(vault_key):
    slot = password_slot(vault_key, None, password="caf\xe9 \u05e9\u05bc\u05c1 key".encode("utf-8"))
    with open_slot(slot, VAULT_ID, password="cafe\u0301 \u05e9\u05c1\u05bc key".encode("utf-8")) as opened:
        assert same_key(opened, vault_key)
    with pytest.raises(AuthError):
        open_slot(slot, VAULT_ID, password="cafe \u05e9\u05bc\u05c1 key".encode("utf-8"))


@given(st.text(min_size=1, max_size=60))
@settings(max_examples=300, deadline=None)
def test_normalisation_does_not_depend_on_the_form_typed(text):
    composed = unicodedata.normalize("NFC", text).encode("utf-8")
    decomposed = unicodedata.normalize("NFD", text).encode("utf-8")
    result = normalised(composed)
    assert result == normalised(decomposed)
    assert normalised(result) == result  # idempotent
    assert len(result) >= 1


def test_bytes_that_are_not_text_are_used_as_they_are():
    for password in (b"\xff\xfe\xfd", b"caf\xe9", b"\xed\xa0\xbd\xed\xb4\x91", b"ok\x80"):
        assert normalised(password) == password


@pytest.mark.parametrize("empty", [b"", bytearray(), memoryview(b"")])
def test_an_empty_password_is_refused(empty):
    with pytest.raises(UsageError, match="cannot be empty"):
        normalise_password(empty)


def test_normalise_password_returns_a_copy_in_locked_memory():
    source = bytearray(b"correct horse")
    with SecureBuffer.from_buffer("caf\xe9".encode("utf-8")) as locked:
        for password in (source, memoryview(source), locked):
            result = normalise_password(password)
            assert isinstance(result, SecureBuffer)
            result.view()[0] = 0
            result.wipe()
        assert source == b"correct horse" and bytes(locked.view()) == "caf\xe9".encode("utf-8")


@pytest.mark.skipif(not CPYTHON, reason="in-place zeroing of immutable objects is CPython-specific")
def test_the_transient_copies_made_while_normalising_are_zeroed(monkeypatch):
    """A non-ASCII password passes through two str objects, which may not outlive the call, and no bytes object."""
    strings: List[str] = []
    encoded: List[bytes] = []
    real_normalize = unicodedata.normalize
    real_from_buffer = SecureBuffer.from_buffer.__func__  # type: ignore[attr-defined]

    def spying_normalize(form, text):
        result = real_normalize(form, text)
        strings.extend([text, result])
        return result

    def spying_from_buffer(cls, data):
        if type(data) is bytes:
            encoded.append(data)
        return real_from_buffer(cls, data)

    password = "\u05e1\u05d9\u05e1\u05de\u05d4-\u05e1\u05d5\u05d3\u05d9\u05ea-cafe\u0301".encode("utf-8")
    with monkeypatch.context() as scoped:
        scoped.setattr(unicodedata, "normalize", spying_normalize)
        scoped.setattr(SecureBuffer, "from_buffer", classmethod(spying_from_buffer))
        result = normalised(password)

    assert result == unicodedata.normalize("NFKC", password.decode("utf-8")).encode("utf-8")
    assert len(strings) == 2 and encoded == [], "a bytes copy of the password was made"
    for text in strings:
        assert len(text) >= 2 and all(ord(char) == 0 for char in text), "a str copy of the password survived"


@given(st.binary(min_size=1, max_size=80))
@settings(max_examples=500, deadline=None)
def test_the_hand_made_utf8_decoder_accepts_exactly_what_python_accepts(data):
    from irondome.keys import _decode_utf8

    try:
        expected = data.decode("utf-8")
    except UnicodeDecodeError:
        expected = None
    assert _decode_utf8(memoryview(data)) == expected


@given(st.text(min_size=1, max_size=60))
@settings(max_examples=300, deadline=None)
def test_the_hand_made_utf8_encoder_matches_python(text):
    from irondome.keys import _encode_utf8

    with _encode_utf8(text) as buffer:
        assert bytes(buffer.view()) == text.encode("utf-8", "surrogatepass")


# ---------------------------------------------------------------------------
# Nothing derived along the way outlives the call
# ---------------------------------------------------------------------------


def test_creating_slots_leaves_no_key_material_alive(vault_key, software, touch, buffers):
    password_slot(vault_key, software)
    password_slot(vault_key, None, password="caf\xe9-סיסמה".encode("utf-8"))
    password_slot(vault_key, touch, policy=POLICY_BIOMETRY)
    create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY)
    create_recovery_slot(vault_key, VAULT_ID)
    assert len(buffers) > 20
    assert alive(buffers) == []


def test_opening_a_slot_leaves_only_the_vault_key_alive(vault_key, software, touch, buffers):
    slots = [
        (password_slot(vault_key, software), dict(password=PASSWORD, interactive=False)),
        (password_slot(vault_key, None), dict(password=PASSWORD)),
        (create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY), dict(interactive=True)),
    ]
    recovery, text = create_recovery_slot(vault_key, VAULT_ID)
    slots.append((recovery, dict(recovery_key=text)))
    del buffers[:]
    for slot, factors in slots:
        opened = open_slot(slot, VAULT_ID, **factors)
        assert alive(buffers) == [opened]
        opened.wipe()
    assert alive(buffers) == []


def test_a_failed_open_leaves_nothing_alive(vault_key, software, touch, buffers):
    password = password_slot(vault_key, software)
    finger = create_device_slot(vault_key, VAULT_ID, backend=touch, policy=POLICY_BIOMETRY)
    recovery, text = create_recovery_slot(vault_key, VAULT_ID)
    del buffers[:]
    attempts = [
        (password, dict(password=b"wrong password", interactive=False), AuthError),
        (password, dict(interactive=False), UsageError),
        (finger, dict(interactive=False), AuthError),
        (recovery, dict(recovery_key="AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"), AuthError),
        (recovery, dict(recovery_key="too short"), AuthError),
    ]
    for slot, factors, error in attempts:
        with pytest.raises(error):
            open_slot(slot, VAULT_ID, **factors)
    software.destroy_all()
    with pytest.raises(HardwareError):
        open_slot(password, VAULT_ID, password=PASSWORD, interactive=False)
    assert len(buffers) > 5
    assert alive(buffers) == []


def test_a_failed_enrolment_leaves_nothing_alive(vault_key, software, buffers, monkeypatch):
    monkeypatch.setattr(keys, "seal", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("no")))
    with pytest.raises(RuntimeError):
        password_slot(vault_key, software)
    with pytest.raises(RuntimeError):
        create_recovery_slot(vault_key, VAULT_ID)
    assert len(buffers) > 4 and alive(buffers) == []


# ---------------------------------------------------------------------------
# Keyslot.from_dict: a keyslot read from disk is hostile input
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def documents_once() -> Dict[str, Dict[str, Any]]:
    """One well-formed document of each kind, made once: the tests below only parse them."""
    chip = FakeTouch()
    with new_vault_key() as vault_key:
        recovery, _ = create_recovery_slot(vault_key, VAULT_ID)
        return {
            "password": password_slot(vault_key, chip).to_dict(),
            "portable": password_slot(vault_key, None).to_dict(),
            "device": create_device_slot(vault_key, VAULT_ID, backend=chip, policy=POLICY_BIOMETRY).to_dict(),
            "recovery": recovery.to_dict(),
        }


@pytest.fixture
def documents(documents_once) -> Dict[str, Dict[str, Any]]:
    return copy.deepcopy(documents_once)


def test_every_kind_of_slot_survives_a_round_trip(documents):
    for name, document in documents.items():
        slot = Keyslot.from_dict(document)
        assert slot.to_dict() == document, name
        assert Keyslot.from_dict(slot.to_dict()) == slot
    assert set(documents["password"]) == {"id", "kind", "created", "label", "wrap", "kdf", "device"}
    assert set(documents["portable"]) == {"id", "kind", "created", "label", "wrap", "kdf"}
    assert set(documents["device"]) == {"id", "kind", "created", "label", "wrap", "device"}
    assert set(documents["recovery"]) == {"id", "kind", "created", "label", "wrap", "salt"}


def test_optional_metadata_has_defaults(documents):
    document = dict(documents["recovery"])
    del document["created"], document["label"]
    slot = Keyslot.from_dict(document)
    assert slot.created == 0 and slot.label == ""


@pytest.mark.parametrize("document", [None, [], "slot", 7, 1.5, True, b"{}"])
def test_a_keyslot_must_be_a_mapping(document):
    with pytest.raises(VaultError, match="malformed"):
        Keyslot.from_dict(document)


SHORT_WRAP = b64e(bytes(59))
LONG_WRAP = b64e(bytes(61))

BROKEN_FIELDS = [
    ("id", None), ("id", 7), ("id", ""), ("id", "a" * 31), ("id", "a" * 33), ("id", "A" * 32), ("id", "g" * 32),
    ("id", "a" * 32 + "\n"), ("id", "aa " * 10 + "aa"), ("id", ["a" * 32]),
    ("kind", None), ("kind", "Password"), ("kind", "session"), ("kind", ""), ("kind", 1), ("kind", ["password"]),
    ("kind", {"password": 1}),
    ("wrap", None), ("wrap", 7), ("wrap", ""), ("wrap", "not base64 !"), ("wrap", SHORT_WRAP), ("wrap", LONG_WRAP),
    ("wrap", b64e(b"")), ("wrap", ["x"]),
    ("created", "now"), ("created", 1.5), ("created", True), ("created", None), ("created", -1), ("created", 2**64),
    ("created", [1]),
    ("label", None), ("label", 7), ("label", ["x"]), ("label", {"x": 1}),
]


@pytest.mark.parametrize("field, value", BROKEN_FIELDS, ids=[f"{f}={v!r}"[:40] for f, v in BROKEN_FIELDS])
def test_a_malformed_field_is_refused_in_every_kind_of_slot(documents, field, value):
    for document in documents.values():
        broken = copy.deepcopy(document)
        broken[field] = value
        with pytest.raises(VaultError):
            Keyslot.from_dict(broken)


@pytest.mark.parametrize("field", ["id", "kind", "wrap"])
def test_a_missing_required_field_is_refused(documents, field):
    for document in documents.values():
        broken = dict(document)
        del broken[field]
        with pytest.raises(VaultError):
            Keyslot.from_dict(broken)


@pytest.mark.parametrize(
    "kdf",
    [
        None, [], "argon2id", 7,
        {}, {"alg": "argon2id"}, {"alg": "scrypt", "salt": b64e(bytes(16)), "m": 65536, "t": 3, "p": 4},
        {"alg": "argon2id", "salt": b64e(bytes(16)), "m": 65536, "t": 3},
        {"alg": "argon2id", "salt": b64e(bytes(16)), "m": 1024, "t": 3, "p": 4},
        {"alg": "argon2id", "salt": b64e(bytes(16)), "m": 65536, "t": 0, "p": 4},
        {"alg": "argon2id", "salt": b64e(bytes(16)), "m": 65536, "t": 3, "p": 99},
        {"alg": "argon2id", "salt": b64e(bytes(16)), "m": "65536", "t": 3, "p": 4},
        {"alg": "argon2id", "salt": b64e(bytes(16)), "m": True, "t": 3, "p": 4},
        {"alg": "argon2id", "salt": b64e(bytes(15)), "m": 65536, "t": 3, "p": 4},
        {"alg": "argon2id", "salt": b64e(bytes(17)), "m": 65536, "t": 3, "p": 4},
        {"alg": "argon2id", "salt": None, "m": 65536, "t": 3, "p": 4},
        {"alg": "argon2id", "salt": 5, "m": 65536, "t": 3, "p": 4},
        {"alg": "argon2id", "salt": "!!", "m": 65536, "t": 3, "p": 4},
    ],
)
def test_a_password_slot_needs_sane_argon2_parameters(documents, kdf):
    for name in ("password", "portable"):
        broken = copy.deepcopy(documents[name])
        broken["kdf"] = kdf
        with pytest.raises(VaultError):
            Keyslot.from_dict(broken)


def test_fields_that_do_not_belong_to_a_kind_are_refused(documents):
    cases = [
        ("device", "kdf", documents["password"]["kdf"]),
        ("recovery", "kdf", documents["password"]["kdf"]),
        ("recovery", "device", documents["password"]["device"]),
        ("password", "salt", documents["recovery"]["salt"]),
        ("portable", "salt", documents["recovery"]["salt"]),
        ("device", "salt", documents["recovery"]["salt"]),
        ("password", "salt", [1, 2, 3]),
    ]
    for name, field, value in cases:
        broken = copy.deepcopy(documents[name])
        broken[field] = value
        with pytest.raises(VaultError):
            Keyslot.from_dict(broken)


@pytest.mark.parametrize(
    "device_value", [None, "software", [], 7, {}, {"backend": None}, {"backend": 5}, {"policy": "device"}]
)
def test_a_device_slot_needs_a_device_descriptor(documents, device_value):
    broken = copy.deepcopy(documents["device"])
    broken["device"] = device_value
    with pytest.raises(VaultError):
        Keyslot.from_dict(broken)
    if device_value is not None:
        broken = copy.deepcopy(documents["password"])
        broken["device"] = device_value
        with pytest.raises(VaultError):
            Keyslot.from_dict(broken)


@pytest.mark.parametrize("salt", [None, 5, "", "!!", b64e(bytes(15)), ["x"]])
def test_a_recovery_slot_needs_a_salt(documents, salt):
    broken = copy.deepcopy(documents["recovery"])
    broken["salt"] = salt
    with pytest.raises(VaultError):
        Keyslot.from_dict(broken)


JUNK = st.recursive(
    st.one_of(
        st.none(), st.booleans(), st.integers(), st.floats(allow_nan=True), st.text(max_size=40),
        st.binary(max_size=8).map(lambda data: base64.b64encode(data).decode("ascii")),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=3), st.dictionaries(st.text(max_size=6), children, max_size=3)
    ),
    max_leaves=6,
)


def mutate(document: Dict[str, Any], data: Any) -> Dict[str, Any]:
    """Replace, delete or add one value somewhere in *document*, at any depth."""
    mutated = copy.deepcopy(document)
    target: Any = mutated
    for _ in range(data.draw(st.integers(min_value=0, max_value=2), label="depth")):
        nested = [key for key, value in target.items() if isinstance(value, dict)]
        if not nested:
            break
        target = target[data.draw(st.sampled_from(sorted(nested)), label="descend")]
    action = data.draw(st.sampled_from(["replace", "delete", "add"]), label="action")
    if action == "add" or not target:
        target[data.draw(st.text(max_size=8), label="new key")] = data.draw(JUNK, label="new value")
    else:
        key = data.draw(st.sampled_from(sorted(target)), label="key")
        if action == "delete":
            del target[key]
        else:
            target[key] = data.draw(JUNK, label="value")
    return mutated


@given(data=st.data())
@settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_a_mutated_keyslot_is_refused_or_still_well_formed(data, documents):
    """Whatever is done to a keyslot document, the answer is a Keyslot or a VaultError. Nothing else."""
    document = documents[data.draw(st.sampled_from(sorted(documents)), label="kind")]
    mutated = mutate(document, data)
    for _ in range(data.draw(st.integers(min_value=0, max_value=2), label="more mutations")):
        mutated = mutate(mutated, data)
    try:
        slot = Keyslot.from_dict(mutated)
    except VaultError:
        return
    assert re.fullmatch(r"[0-9a-f]{32}", slot.id)
    assert slot.kind in (KIND_PASSWORD, KIND_DEVICE, KIND_RECOVERY)
    assert len(b64d(slot.wrap)) == 60
    assert isinstance(slot.created, int) and slot.created >= 0 and isinstance(slot.label, str)
    assert (slot.kdf is not None) == (slot.kind == KIND_PASSWORD)
    assert (slot.salt is not None) == (slot.kind == KIND_RECOVERY)
    if slot.kind == KIND_DEVICE:
        assert isinstance(slot.device, dict)
    if slot.device is not None:
        assert isinstance(slot.device.get("backend"), str)
    assert Keyslot.from_dict(slot.to_dict()) == slot
    assert isinstance(slot.describe(), str)


@given(JUNK)
@settings(max_examples=200, deadline=None)
def test_arbitrary_values_are_never_a_keyslot(junk):
    with pytest.raises(VaultError):
        Keyslot.from_dict(junk)


def test_an_accepted_slot_with_a_hostile_descriptor_fails_cleanly_when_opened(documents):
    """from_dict checks the shape; the backend checks the descriptor before acting on it."""
    for bad in (
        {"backend": "software", "policy": "device", "ref": "../../etc/passwd"},
        {"backend": "software", "policy": "nonsense", "ref": "ab" * 16},
        {"backend": "quantum", "policy": "device", "ref": "ab" * 16},
        {"backend": "software"},
    ):
        document = copy.deepcopy(documents["password"])
        document["device"] = bad
        slot = Keyslot.from_dict(document)
        with pytest.raises((VaultError, HardwareError)):
            open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False)
        with pytest.raises((VaultError, HardwareError)):
            destroy_slot_device(slot)


# ---------------------------------------------------------------------------
# The password factor: Argon2id over a prehash, never over the password
# ---------------------------------------------------------------------------


def test_the_password_factor_is_argon2id_over_an_hkdf_prehash_of_the_password() -> None:
    """The derivation, pinned: it is part of the vault format.

    Worked out here without IronDome: RFC 5869 by hand with the standard
    library's HMAC, then Argon2id from pyca/cryptography over the 32 bytes.
    """
    import hmac

    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    password, salt = b"correct horse battery staple", bytes(range(16))
    extracted = hmac.digest(salt, password, "sha256")
    prehash = hmac.digest(extracted, b"irondome/v4/password\x01", "sha256")
    assert prehash.hex() == "e96fdf1fc7d8d21cac95f4c20be0e16189c50b6d4b152b09d85f857c1eb8a86b"
    expected = Argon2id(salt=salt, length=32, iterations=2, lanes=1, memory_cost=19 * 1024).derive(prehash)
    assert expected.hex() == "4a9de2077b77447f76ab31e434b60c6d486a5364b1c2e5193b88f68f505e972c"
    with keys.stretch_password(password, salt, Argon2Params(memory_kib=19 * 1024, iterations=2, lanes=1)) as key:
        assert bytes(key.view()) == expected
    plain = Argon2id(salt=salt, length=32, iterations=2, lanes=1, memory_cost=19 * 1024).derive(password)
    assert plain != expected


@pytest.mark.parametrize("length", [1, 8, 64, 700, 4000])
def test_argon2id_is_never_given_the_master_password(monkeypatch: pytest.MonkeyPatch, length: int) -> None:
    """Making a password keyslot and opening it: every input Argon2id gets is 32 bytes, and none is the password.

    Argon2id in pyca/cryptography copies what it is given into memory it
    frees without overwriting. What it is given is the prehash, and after it
    32 zero bytes (the repeat that has the library overwrite that copy).
    """
    given: List[bytes] = []
    real = crypto.Argon2id

    def spying(**kwargs: Any) -> Any:
        kdf = real(**kwargs)

        class Recorder:
            def derive_into(self, material: Any, buffer: Any) -> Any:
                given.append(bytes(material))
                return kdf.derive_into(material, buffer)

        return Recorder()

    monkeypatch.setattr(crypto, "Argon2id", spying)
    monkeypatch.setattr(crypto, "_stretch_in_child", lambda *arguments: False)  # so that the spy sees every run
    password = (b"a long master password, " * 200)[:length]
    vault_id = os.urandom(VAULT_ID_LEN)
    with keys.new_vault_key() as vault_key:
        slot = create_password_slot(vault_key, password, vault_id, params=FAST, backend=None)
        with open_slot(slot, vault_id, password=password) as opened:
            assert bytes(opened.view()) == bytes(vault_key.view())
    assert len(given) == 4 and all(len(material) == 32 for material in given)
    assert given[1] == given[3] == bytes(32) and given[0] == given[2] != bytes(32)
    for material in given[::2]:
        assert material != password and material not in password
        # A password of a few bytes can turn up in 32 pseudorandom ones by chance: 16 bytes cannot.
        assert len(password) < 16 or all(password[at : at + 16] not in material for at in range(len(password) - 15))


@pytest.mark.skipif(not hasattr(os, "fork"), reason="there is no fork on this system")
@pytest.mark.parametrize("length", [8, 64, 4000])
def test_the_child_that_runs_argon2id_is_sent_the_prehash_never_the_master_password(
    monkeypatch: pytest.MonkeyPatch, length: int
) -> None:
    sent: List[bytes] = []
    real = crypto._stretch_in_child

    def spying(view: Any, salt: bytes, params: Any, out: Any) -> bool:
        sent.append(bytes(view))
        return real(view, salt, params, out)

    monkeypatch.setattr(crypto, "_stretch_in_child", spying)
    password = (b"a long master password, " * 200)[:length]
    vault_id = os.urandom(VAULT_ID_LEN)
    with keys.new_vault_key() as vault_key:
        slot = create_password_slot(vault_key, password, vault_id, params=FAST, backend=None)
        with open_slot(slot, vault_id, password=password) as opened:
            assert bytes(opened.view()) == bytes(vault_key.view())

    assert len(sent) == 2 and sent[0] == sent[1] and len(sent[0]) == 32
    assert password[:8] not in sent[0] and sent[0] not in password


# ---------------------------------------------------------------------------
# What a change of one line would have got past the tests above
#
# The two property tests of the hand-made UTF-8 code compare it with Python on
# random input, and random input almost never lands on the first or the last
# code point of a length, on a surrogate, or on an overlong form. Each value
# below is one where a single changed comparison in keys.py went unnoticed.
# ---------------------------------------------------------------------------

UTF8_EDGES = [0x00, 0x7F, 0x80, 0xBF, 0x7FF, 0x800, 0xD7FF, 0xE000, 0xFFFF, 0x10000, 0x10FFFF]


@pytest.mark.parametrize("point", UTF8_EDGES, ids=[f"U+{point:04X}" for point in UTF8_EDGES])
def test_the_hand_made_utf8_code_agrees_with_python_on_the_first_and_last_code_point_of_every_length(point):
    from irondome.keys import _decode_utf8, _encode_utf8

    for text in (chr(point), "a" + chr(point) + "א" + chr(point) + "z"):
        encoded = text.encode("utf-8")
        assert _decode_utf8(memoryview(encoded)) == text
        with _encode_utf8(text) as buffer:
            assert bytes(buffer.view()) == encoded


NOT_UTF8 = [
    b"\x80", b"\xbf", b"\xc0\x80", b"\xc1\xbf",  # a continuation byte alone; two bytes for what fits in one
    b"\xe0\x80\x80", b"\xe0\x9f\xbf",  # three bytes for what fits in two
    b"\xed\xa0\x80", b"\xed\xbf\xbf",  # the first and the last surrogate
    b"\xf0\x80\x80\x80", b"\xf0\x8f\xbf\xbf",  # four bytes for what fits in three
    b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80", b"\xf7\xbf\xbf\xbf", b"\xf8\x88\x80\x80\x80", b"\xff",  # past U+10FFFF
    b"\xc2", b"\xe0\xa0", b"\xf0\x90\x80",  # cut short
    b"\xc2\x41", b"\xe0\xa0\x41", b"\xf0\x90\x80\x41", b"\xc2\xc2", b"\xe0\x41\x80",  # not followed as it must be
]


@pytest.mark.parametrize("data", NOT_UTF8, ids=[data.hex() for data in NOT_UTF8])
def test_the_hand_made_utf8_decoder_refuses_every_malformed_form_python_refuses(data):
    from irondome.keys import _decode_utf8

    for sample in (data, b"\xc3\xa9" + data, data + b"a", b"abc" + data + b"\xd7\x90"):
        with pytest.raises(UnicodeDecodeError):
            sample.decode("utf-8")
        assert _decode_utf8(memoryview(sample)) is None


@pytest.mark.parametrize("text", [
    "µ",  # MICRO SIGN: its lead byte is the lowest there is, and NFKC changes it
    "pass word", "ª", "ࠀ", "￿", "\U00010000", "\U0010ffff", "ﬁ", "①\U0001d7d8",
])
def test_a_password_with_a_character_at_an_edge_of_utf8_is_normalised_like_any_other(text):
    import unicodedata

    assert normalised(text.encode("utf-8")) == unicodedata.normalize("NFKC", text).encode("utf-8")


def test_the_hand_made_utf8_encoder_wipes_what_it_wrote_when_it_fails(monkeypatch):
    import irondome.keys as keys_module

    wiped = []

    class Failing(SecureBuffer):
        def view(self):
            raise MemoryError

        def wipe(self):
            wiped.append(self)
            super().wipe()

    monkeypatch.setattr(keys_module, "SecureBuffer", Failing)
    with pytest.raises(MemoryError) as raised:
        keys_module._encode_utf8("סיסמה")
    # Wiped by the encoder itself, while the failure (and the frame the buffer was in) is still held.
    assert raised.value is not None and len(wiped) == 1 and wiped[0].wiped


@pytest.mark.parametrize("size", [0, 19, 21, 32])
def test_only_twenty_bytes_can_be_written_as_a_recovery_key(size):
    with pytest.raises(ValueError, match="a recovery key is 20 bytes"):
        format_recovery_key(bytes(size))


def test_writing_and_reading_a_recovery_key_wipe_their_working_copies(monkeypatch):
    import irondome.keys as keys_module

    wiped = []
    real = keys_module.wipe_bytes
    monkeypatch.setattr(keys_module, "wipe_bytes", lambda data: (real(data), wiped.append(data))[0])
    raw = bytes(range(1, 21))

    text = format_recovery_key(raw)
    assert len(wiped) == 1 and isinstance(wiped[0], bytearray) and wiped[0] == bytes(len(text))

    assert parse_recovery_key(text) == raw
    assert len(wiped) == 2 and isinstance(wiped[1], bytearray) and wiped[1] == bytes(20)


@pytest.mark.parametrize("created, accepted", [(0, True), (2**63 - 1, True), (2**63, False), (-1, False)])
def test_a_creation_time_is_any_number_a_signed_64_bit_field_holds_and_no_other(documents, created, accepted):
    for document in documents.values():
        document["created"] = created
        if accepted:
            assert Keyslot.from_dict(document).created == created
        else:
            with pytest.raises(VaultError, match="keyslot metadata is malformed"):
                Keyslot.from_dict(document)


def test_a_keyslot_made_without_a_time_or_a_label_has_time_zero_and_no_label():
    slot = Keyslot(id="a" * 32, kind="recovery", wrap="")
    assert slot.created == 0 and slot.label == "" and slot.kdf is None and slot.device is None and slot.salt is None


@pytest.mark.parametrize("failure", [MemoryError(), KeyboardInterrupt(), RuntimeError("the library broke")])
def test_opening_a_slot_that_fails_for_another_reason_than_a_wrong_key_wipes_the_vault_key_and_says_so(
    monkeypatch, vault_key, failure
):
    import irondome.keys as keys_module

    slot = password_slot(vault_key, None)
    made: List[SecureBuffer] = []
    wiped: List[SecureBuffer] = []
    written_into: List[SecureBuffer] = []

    class Watched(SecureBuffer):
        def __init__(self, size):
            super().__init__(size)
            made.append(self)

        def wipe(self):
            if not self.wiped:
                wiped.append(self)
            super().wipe()

    def failing(kek, blob, aad, out):
        written_into.append(out)
        out.view()[:] = b"\x55" * len(out)  # the cipher writes before it checks
        raise failure

    monkeypatch.setattr(keys_module, "SecureBuffer", Watched)
    monkeypatch.setattr(keys_module, "open_sealed_into", failing)
    with pytest.raises(type(failure)) as raised:
        open_slot(slot, VAULT_ID, password=PASSWORD, interactive=False)

    assert raised.value is failure  # the failure itself, not "wrong master password" in its place
    # While the failure is still held: the buffer the vault key was being written into is already wiped.
    assert len(written_into) == 1 and written_into[0] in made and written_into[0] in wiped
