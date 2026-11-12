"""Claim ``device-bound``: a copy of the vault is useless without the machine.

Statement: every keyslot opened by a master password or a fingerprint also
needs a device secret that is not in the vault file. A complete copy of the
vault directory, together with the correct master password, does not open on
another machine and gives an attacker nothing to test password guesses
against.

"Another machine" is a fresh device directory: everything this machine binds
a vault to lives there, and nothing of it is in the vault directory.
"""

from __future__ import annotations

import os

import pytest

from conftest import PASSWORD, secret
from irondome import unlock
from irondome.errors import HardwareError
from irondome.keys import KIND_PASSWORD
from irondome.vault import VaultFile
from support.claimkit import add, contents, copy_tree, document, fails, found_in, init, irondome_dirs, ok


def another_machine(tmp_path, name: str = "elsewhere"):
    """The environment of a second machine that received a complete copy of the vault directory."""
    machine = tmp_path / name
    copy_tree(irondome_dirs()["home"], machine / "irondome")
    return {"IRONDOME_HOME": str(machine / "irondome"), "IRONDOME_DEVICE_DIR": str(machine / "device")}


def test_a_complete_copy_of_the_vault_directory_does_not_open_elsewhere_with_the_right_password(cli, tmp_path):
    init(cli)
    add(cli, "bank", "the-real-secret-value")
    assert ok(cli("get", "bank", "--password-stdin", stdin=PASSWORD + "\n")).stdout == "the-real-secret-value"
    elsewhere = another_machine(tmp_path)
    refused = fails(cli("get", "bank", "--password-stdin", stdin=PASSWORD + "\n", env=elsewhere), 7)
    assert "device key" in refused.stderr and "recovery key" in refused.stderr
    assert "the-real-secret-value" not in refused.stdout + refused.stderr


def test_a_copy_gives_nothing_to_test_a_password_guess_against(cli, tmp_path):
    """The right and a wrong password fail identically: the copy cannot tell them apart."""
    init(cli)
    add(cli, "bank", "the-real-secret-value")
    elsewhere = another_machine(tmp_path)
    right = cli("get", "bank", "--password-stdin", stdin=PASSWORD + "\n", env=elsewhere)
    wrong = cli("get", "bank", "--password-stdin", stdin="not the password at all\n", env=elsewhere)
    assert (right.returncode, right.stdout, right.stderr) == (wrong.returncode, wrong.stdout, wrong.stderr)


def test_every_password_keyslot_names_a_device_secret_kept_outside_the_vault_directory(make_vault):
    vault, _recovery = make_vault()
    with vault:
        slots = [slot for slot in vault.file.slots if slot.kind == KIND_PASSWORD]
        assert slots and all(slot.device is not None for slot in slots)
        from irondome import device

        backend = device.get_backend(slots[0].backend_name)
        with backend.unseal(slots[0].device, auth=None, interactive=False, reason="test") as raw:
            device_secret = bytes(raw.view())
    vault_side = contents(irondome_dirs()["home"])
    device_side = contents(irondome_dirs()["device"])
    assert not any(device_secret in data or device_secret.hex().encode() in data for data in vault_side.values())
    assert any(device_secret in data for data in device_side.values())


def test_with_the_device_secret_gone_neither_the_right_nor_a_wrong_password_opens_the_file(make_vault):
    vault, _recovery = make_vault(with_recovery=False)
    path = vault.path
    vault.close()
    for name in os.listdir(os.environ["IRONDOME_DEVICE_DIR"] + "/bunkers/alpha"):
        os.remove(os.path.join(os.environ["IRONDOME_DEVICE_DIR"], "bunkers", "alpha", name))
    errors = []
    for attempt in (PASSWORD, "a wrong guess", "another wrong guess"):
        with secret(attempt) as password, pytest.raises(HardwareError) as caught:
            unlock.open_vault(path=path, password=password, interactive=False)
        errors.append(str(caught.value))
    assert len(set(errors)) == 1


def test_the_vault_still_opens_on_its_own_machine(cli):
    init(cli)
    add(cli, "bank", "the-real-secret-value")
    assert document(cli("get", "bank", "--password-stdin", "--json", stdin=PASSWORD + "\n"))["value"] == (
        "the-real-secret-value"
    )


@pytest.mark.secure_enclave
def test_on_the_secure_enclave_a_copy_without_this_macs_key_blob_does_not_open(
    secure_enclave, make_vault, tmp_path, monkeypatch
):
    vault, _recovery = make_vault(with_recovery=False)
    assert vault.file.slots[0].backend_name == "macos-se"
    path = vault.path
    vault.close()
    copy = tmp_path / "copy"
    copy_tree(irondome_dirs()["home"], copy)
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", str(tmp_path / "other-mac"))
    with secret(PASSWORD) as password, pytest.raises(HardwareError, match="not on this Mac"):
        unlock.open_vault(path=copy / path.relative_to(irondome_dirs()["home"]), password=password, interactive=False)


# -- the boundary ------------------------------------------------------------------


def test_boundary_the_recovery_key_opens_the_copy_without_the_device(cli, tmp_path):
    created = init(cli)
    add(cli, "bank", "the-real-secret-value")
    elsewhere = another_machine(tmp_path)
    file = VaultFile.load(elsewhere["IRONDOME_HOME"] + "/bunkers/alpha/vault.irondome")
    vault_key = unlock.unlock(file, recovery_key=created["recovery_key"])
    from irondome.vault import Vault

    with Vault(file, vault_key, elsewhere["IRONDOME_HOME"] + "/bunkers/alpha/vault.irondome") as opened:
        assert opened.value(opened.find("bank")) == "the-real-secret-value"


def test_boundary_with_the_file_based_backend_a_copy_of_the_device_directory_too_does_open(cli, tmp_path):
    """The file-based device key protects copies of the vault directory, not a machine malware controls."""
    init(cli)
    add(cli, "bank", "the-real-secret-value")
    elsewhere = another_machine(tmp_path)
    copy_tree(irondome_dirs()["device"], tmp_path / "elsewhere" / "device")
    opened = ok(cli("get", "bank", "--password-stdin", stdin=PASSWORD + "\n", env=elsewhere))
    assert opened.stdout == "the-real-secret-value"
    assert found_in(b"".join(contents(irondome_dirs()["home"]).values()), ["the-real-secret-value"]) == []
