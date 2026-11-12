"""Claim ``recovery``: the recovery key opens the vault without the device.

Statement: a 160-bit recovery key, shown once at setup and stored nowhere,
opens a copy of the vault on any machine, so a lost laptop, a dead chip or a
changed fingerprint is not the end of your data.

The recovery key is used through the public kernel API
(``irondome.unlock.unlock(file, recovery_key=...)``).
"""

from __future__ import annotations

import re

import pytest

from conftest import PASSWORD, secret
from irondome import keys, unlock
from irondome.errors import AuthError, HardwareError
from irondome.vault import Vault, VaultFile
from support.claimkit import add, contents, copy_tree, document, fails, init, irondome_dirs, ok


def copy_elsewhere(tmp_path):
    copy_tree(irondome_dirs()["home"], tmp_path / "elsewhere")
    return tmp_path / "elsewhere" / "bunkers" / "alpha" / "vault.irondome"


def test_the_recovery_key_opens_a_copy_of_the_vault_on_a_machine_without_the_device(cli, tmp_path, monkeypatch):
    created = init(cli)
    add(cli, "bank", "the-bank-password-5678")
    add(cli, "mail", "the-mail-password-9012")
    path = copy_elsewhere(tmp_path)
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", str(tmp_path / "another-machines-device-directory"))
    file = VaultFile.load(path)
    with secret(PASSWORD) as password, pytest.raises(HardwareError):
        unlock.open_vault(path=path, password=password, interactive=False)
    with Vault(file, unlock.unlock(file, recovery_key=created["recovery_key"]), path) as recovered:
        assert recovered.value(recovered.find("bank")) == "the-bank-password-5678"
        assert recovered.value(recovered.find("mail")) == "the-mail-password-9012"


def test_the_recovery_key_is_160_bits_written_as_eight_groups(cli):
    created = init(cli)
    text = created["recovery_key"]
    assert re.fullmatch(r"([A-Z2-7]{4}-){7}[A-Z2-7]{4}", text)
    raw = keys.parse_recovery_key(text)
    assert len(raw) * 8 == 160


def test_it_is_typed_forgivingly_lower_case_and_without_dashes(cli, tmp_path):
    created = init(cli)
    add(cli, "bank", "the-bank-password-5678")
    path = copy_elsewhere(tmp_path)
    file = VaultFile.load(path)
    casual = created["recovery_key"].replace("-", " ").lower()
    unlock.unlock(file, recovery_key=casual).wipe()


def test_it_is_stored_nowhere(cli):
    created = init(cli)
    add(cli, "bank", "the-bank-password-5678")
    text = created["recovery_key"]
    raw = keys.parse_recovery_key(text)
    forms = [text.encode(), text.replace("-", "").encode(), text.lower().encode(), raw, raw.hex().encode()]
    stored = contents(irondome_dirs()["home"], irondome_dirs()["device"])
    assert {path for path, data in stored.items() if any(form in data for form in forms)} == set()


def test_it_is_shown_once_and_never_again(cli):
    created = init(cli)
    text = created["recovery_key"]
    for command in (("status", "--json"), ("ls", "--password-stdin"), ("audit", "--password-stdin", "-n", "0")):
        shown = ok(cli(*command, stdin=PASSWORD + "\n"))
        assert text not in shown.stdout + shown.stderr


def test_another_recovery_key_opens_nothing(cli, tmp_path):
    init(cli)
    path = copy_elsewhere(tmp_path)
    other = keys.format_recovery_key(bytes(20))
    with pytest.raises(AuthError, match="does not open this vault"):
        unlock.unlock(VaultFile.load(path), recovery_key=other)


def test_a_new_recovery_key_replaces_the_old_one(cli, tmp_path):
    first = init(cli)["recovery_key"]
    second = document(cli("recovery", "new", "--password-stdin", "--json", stdin=PASSWORD + "\n"))["recovery_key"]
    assert second != first
    file = VaultFile.load()
    unlock.unlock(file, recovery_key=second).wipe()
    with pytest.raises(AuthError):
        unlock.unlock(file, recovery_key=first)


# -- the boundary ------------------------------------------------------------------


def test_boundary_the_same_key_outlives_nuke_for_any_surviving_copy(cli, tmp_path):
    created = init(cli)
    add(cli, "bank", "the-bank-password-5678")
    path = copy_elsewhere(tmp_path)
    ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", stdin=PASSWORD + "\n"))
    file = VaultFile.load(path)
    with Vault(file, unlock.unlock(file, recovery_key=created["recovery_key"]), path) as recovered:
        assert recovered.value(recovered.find("bank")) == "the-bank-password-5678"


def test_boundary_a_vault_made_with_no_recovery_has_no_way_in_without_this_machine(cli, tmp_path):
    created = init(cli, "--no-recovery")
    assert created["recovery_key"] is None
    path = copy_elsewhere(tmp_path)
    with pytest.raises(AuthError, match="no recovery key"):
        unlock.unlock(VaultFile.load(path), recovery_key=keys.format_recovery_key(bytes(20)))
    refused = fails(cli("recovery", "remove", "--yes", "--password-stdin", stdin=PASSWORD + "\n"), 3)
    assert "no recovery key" in refused.stderr
