"""Retiring device keys across an interruption: ``keys.record_retirement`` and ``keys.finish_retirement``.

A keyslot change records every device secret it involves before it writes the vault file, and
finishing destroys exactly those that the file on disk does not use. Each test stops a change where
a crash, a power cut or a failed write could stop it, and checks what finishing does from there.
"""

from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple

import pytest

from conftest import PASSWORD, secret
from irondome import device, keys, paths, unlock
from irondome.crypto import Argon2Params
from irondome.errors import AuthError, HardwareError, VaultError
from irondome.keys import KIND_PASSWORD, KIND_RECOVERY, Keyslot
from irondome.vault import Vault

FAST = Argon2Params(memory_kib=19 * 1024, iterations=2, lanes=4)
NEW_PASSWORD = "a brand new passphrase for this test"


def key_files() -> List[str]:
    folder = paths.device_dir()
    return sorted(path.name for path in folder.glob("*.key")) if folder.is_dir() else []


def key_file(slot: Keyslot) -> str:
    assert slot.device is not None
    return f"{slot.device['ref']}.key"


def record() -> Path:
    return paths.home() / keys.RETIREMENT_FILE


def opens(password: str, path: Optional[Path] = None) -> bool:
    with secret(password) as buffer:
        try:
            unlock.open_vault(path=path, password=buffer, interactive=False).close()
        except (AuthError, HardwareError):
            return False
    return True


@pytest.fixture
def change(make_vault) -> Tuple[Vault, Keyslot, Keyslot]:
    """A vault, its password keyslot, and a keyslot for a new password made for it but not yet written."""
    vault, _recovery = make_vault()
    old = vault.slots(KIND_PASSWORD)[0]
    with secret(NEW_PASSWORD) as password:
        new = keys.create_password_slot(
            vault.vault_key, password, vault.vault_id, params=FAST, backend=device.get_backend("software"),
            label="master password",
        )
    assert sorted(key_files()) == sorted([key_file(old), key_file(new)])
    return vault, old, new


def write(vault: Vault, old: Keyslot, new: Keyslot) -> None:
    vault.add_slot(new)
    vault.remove_slot(old.id)
    vault.commit(snapshots=0)


def test_once_the_new_file_is_written_the_old_device_key_goes_and_the_new_one_stays(change, tmp_path):
    vault, old, new = change
    earlier = tmp_path / "earlier.irondome"
    earlier.write_bytes(paths.vault_file().read_bytes())
    with paths.file_lock():
        assert keys.record_retirement([old, new]) is True
        write(vault, old, new)
    # A crash here leaves both keys. Until the change is finished, a copy made before it opens with the old password.
    assert sorted(key_files()) == sorted([key_file(old), key_file(new)])
    assert opens(PASSWORD, earlier)
    assert keys.finish_retirement() == []
    assert key_files() == [key_file(new)]
    assert not record().exists()
    assert opens(NEW_PASSWORD) and not opens(PASSWORD)
    assert not opens(PASSWORD, earlier)


def test_when_the_new_file_was_never_written_the_new_device_key_goes_and_the_old_one_stays(change):
    vault, old, new = change
    with paths.file_lock():
        keys.record_retirement([old, new])
    # ... and here the process died, before the vault file was written.
    assert keys.finish_retirement() == []
    assert key_files() == [key_file(old)]
    assert not record().exists()
    assert opens(PASSWORD)


def test_nothing_is_destroyed_while_the_vault_file_cannot_be_read(change):
    vault, old, new = change
    with paths.file_lock():
        keys.record_retirement([old, new])
        write(vault, old, new)
    live = paths.vault_file()
    content = live.read_bytes()
    live.rename(live.with_name("moved-away"))
    assert keys.finish_retirement() == []
    live.write_bytes(b"{ damaged")
    assert keys.finish_retirement() == []
    assert sorted(key_files()) == sorted([key_file(old), key_file(new)]) and record().exists()
    live.write_bytes(content)
    assert keys.finish_retirement() == []
    assert key_files() == [key_file(new)] and not record().exists()


def test_a_device_key_that_cannot_be_destroyed_yet_stays_recorded_for_the_next_command(change, monkeypatch):
    vault, old, new = change
    with paths.file_lock():
        keys.record_retirement([old, new])
        write(vault, old, new)
    backend = device.get_backend("software")

    def refuse(descriptor):
        raise HardwareError("the device directory is read-only")

    monkeypatch.setattr(backend, "destroy", refuse)
    problems = keys.finish_retirement()
    assert len(problems) == 1
    assert "could not be destroyed yet" in problems[0] and "read-only" in problems[0]
    assert "next command" in problems[0]
    assert json.loads(record().read_text())["devices"] == [old.device]
    monkeypatch.undo()
    assert keys.finish_retirement() == []
    assert key_files() == [key_file(new)] and not record().exists()


def test_finishing_waits_for_a_change_that_is_being_written(change):
    """Another command must not judge a change halfway: before its write it would destroy the new device key."""
    vault, old, new = change
    finished: List[List[str]] = []
    with paths.file_lock():
        keys.record_retirement([old, new])
        other = threading.Thread(target=lambda: finished.append(keys.finish_retirement()))
        other.start()
        time.sleep(0.3)
        assert other.is_alive() and finished == []
        write(vault, old, new)
        assert keys.finish_retirement() == []  # the change finishes itself, holding the lock throughout
    other.join(30)
    assert finished == [[]]
    assert key_files() == [key_file(new)]
    assert opens(NEW_PASSWORD)


def test_a_damaged_record_is_reported_and_removed_and_a_new_change_refuses_to_write_over_it(change):
    vault, old, new = change
    record().write_text("not a record", encoding="utf-8")
    with pytest.raises(VaultError, match="cannot be read"):
        keys.record_retirement([old, new])
    (problem,) = keys.finish_retirement()
    assert "damaged" in problem and "may still be on this machine" in problem
    assert not record().exists()
    assert sorted(key_files()) == sorted([key_file(old), key_file(new)])  # nothing was destroyed on its word


def test_a_record_left_by_an_interrupted_change_is_kept_by_the_next_one(change):
    vault, old, new = change
    with paths.file_lock():
        keys.record_retirement([old])
        keys.record_retirement([old, new])  # the same secret is recorded once
    assert json.loads(record().read_text())["devices"] == [old.device, new.device]


def test_the_record_names_device_keys_only_and_is_the_owners_alone(change):
    vault, old, new = change
    with paths.file_lock():
        keys.record_retirement([old, new])
    document = json.loads(record().read_text())
    assert set(document) == {"format", "version", "devices"}
    assert document["devices"] == [old.device, new.device]
    assert all(set(item) == {"backend", "policy", "ref"} for item in document["devices"])
    if os.name != "nt":
        assert stat.S_IMODE(record().stat().st_mode) == 0o600


def test_keyslots_without_a_device_key_need_no_record(make_vault):
    vault, _recovery = make_vault()
    assert keys.record_retirement(vault.slots(KIND_RECOVERY)) is False
    assert not record().exists()
    assert keys.finish_retirement() == []


# ---------------------------------------------------------------------------
# What the record itself must be
#
# The one damaged record above is not JSON at all. A change of any single
# condition in keys._read_retirement went unnoticed: each of them is tried
# alone here, on a record that is well formed in every other way.
# ---------------------------------------------------------------------------

DEVICE = {"backend": "software", "ref": "0" * 32}


def well_formed() -> dict:
    return {"format": "irondome-keyslot-retirement", "version": 1, "devices": [dict(DEVICE)]}


def record_holding(document: object) -> Path:
    record().write_text(json.dumps(document), encoding="utf-8")
    return record()


def test_a_well_formed_record_is_read_and_the_one_written_is_exactly_that_document(make_vault):
    make_vault()
    assert keys._read_retirement(record_holding(well_formed())) == [DEVICE]
    keys._write_retirement(record(), [DEVICE])
    assert json.loads(record().read_text(encoding="utf-8")) == well_formed()


@pytest.mark.parametrize("document", [
    [], "record", 7, None, [well_formed()],
    {**well_formed(), "format": "irondome-keyslot"}, {**well_formed(), "format": None},
    {"version": 1, "devices": []},
    {**well_formed(), "version": 2}, {**well_formed(), "version": "1"}, {**well_formed(), "version": 0},
    {"format": "irondome-keyslot-retirement", "devices": []},
    {**well_formed(), "devices": {"0": DEVICE}}, {**well_formed(), "devices": None},
    {**well_formed(), "devices": "software"},
    {"format": "irondome-keyslot-retirement", "version": 1},
    {**well_formed(), "devices": [DEVICE] * 257},
], ids=lambda document: json.dumps(document)[:48])
def test_a_document_that_is_not_such_a_record_in_any_one_way_is_refused(make_vault, document):
    make_vault()
    with pytest.raises(VaultError, match="^it is not a record of device keys to retire$"):
        keys._read_retirement(record_holding(document))


@pytest.mark.parametrize("descriptor", [
    "software", None, 7, ["software"], {}, {"ref": "0" * 32}, {"backend": None}, {"backend": 7},
    {"backend": ["software"]},
], ids=lambda descriptor: json.dumps(descriptor))
def test_a_record_that_names_a_device_key_without_describing_it_is_refused(make_vault, descriptor):
    make_vault()
    for devices in ([descriptor], [DEVICE, descriptor], [descriptor, DEVICE]):
        with pytest.raises(VaultError, match="^it names a device key it does not describe$"):
            keys._read_retirement(record_holding({**well_formed(), "devices": devices}))


@pytest.mark.parametrize("content", [b"", b"{", b"not a record", b"\xff\xfe{}", b"[" * 100_000])
def test_a_record_that_is_not_json_is_refused_as_that(make_vault, content):
    make_vault()
    record().write_bytes(content)
    with pytest.raises(VaultError, match="^it is not valid JSON$"):
        keys._read_retirement(record())


def test_a_record_holds_256_device_keys_and_a_change_that_would_make_it_257_is_refused_whole(change):
    vault, old, new = change
    others = [{"backend": "software", "ref": f"{number:032x}"} for number in range(255)]
    record_holding({**well_formed(), "devices": others})

    with paths.file_lock():
        assert keys.record_retirement([old]) is True  # the 256th
        assert len(keys._read_retirement(record())) == 256
        before = record().read_bytes()
        with pytest.raises(VaultError, match="already names 256 device keys to retire; nothing was changed"):
            keys.record_retirement([new])  # would be the 257th
    assert record().read_bytes() == before
    assert sorted(key_files()) == sorted([key_file(old), key_file(new)])


def test_one_device_key_is_one_entry_whatever_the_order_its_description_was_written_in(change):
    vault, old, new = change
    assert old.device is not None and len(old.device) >= 2
    assert keys._identity(old.device) == keys._identity(dict(reversed(list(old.device.items()))))
    record_holding({**well_formed(), "devices": [dict(reversed(list(old.device.items())))]})
    with paths.file_lock():
        keys.record_retirement([old])
    assert len(keys._read_retirement(record())) == 1


def test_a_record_that_cannot_be_updated_is_reported_with_the_reason(change, monkeypatch):
    vault, old, new = change
    with paths.file_lock():
        keys.record_retirement([old, new])
        write(vault, old, new)

    def refuse(descriptor):
        raise HardwareError("the device directory is read-only")

    def no_write(path, descriptors):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(device.get_backend("software"), "destroy", refuse)
    monkeypatch.setattr(keys, "_write_retirement", no_write)
    problems = keys.finish_retirement()
    assert len(problems) == 2
    assert "could not be destroyed yet" in problems[0]
    assert "could not be updated: Permission denied" in problems[1] and str(record()) in problems[1]
