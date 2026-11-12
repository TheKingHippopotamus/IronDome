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
