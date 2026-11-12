"""Claim ``crypto-erase``: nuke makes every copy of the vault unreadable.

Statement: nuke destroys the device secret before it deletes anything else.
Afterwards, restoring a complete, bit-perfect copy of the vault directory and
supplying the correct master password does not open the vault: what an SSD
kept of the old blocks no longer matters.

The SSD is modelled by copying the whole vault directory (live file,
snapshots, audit log, sessions and grants) before ``nuke`` and putting it back
afterwards.
"""

from __future__ import annotations

import pytest

from conftest import PASSWORD, secret
from irondome import device, nuke, paths, unlock
from irondome.errors import AuthError, HardwareError
from irondome.vault import Vault, VaultFile
from support.claimkit import add, copy_tree, document, fails, grant, init, irondome_dirs, ok, restore_tree, session


def nuke_everything(cli):
    report = document(cli("nuke", "--yes-destroy-everything", "--password-stdin", "--json", stdin=PASSWORD + "\n"))
    assert report["success"] and report["report"]["device_keys_destroyed"] >= 1
    return report


def open_with_password(path):
    with secret(PASSWORD) as password:
        return unlock.open_vault(path=path, password=password, interactive=False)


def test_a_restored_copy_of_the_whole_vault_directory_refuses_the_master_password(cli, tmp_path):
    init(cli)
    add(cli, "bank", "the-real-secret-value")
    add(cli, "mail", "another-secret-value")
    ok(cli("edit", "bank", "--username", "someone", "--password-stdin", stdin=PASSWORD + "\n"))
    snapshots = sorted(paths.backups_dir().glob("vault-*.irondome"))
    assert len(snapshots) >= 2
    ssd = tmp_path / "ssd"
    copy_tree(irondome_dirs()["home"], ssd)
    nuke_everything(cli)
    restore_tree(ssd, irondome_dirs()["home"])
    refused = fails(cli("get", "bank", "--password-stdin", stdin=PASSWORD + "\n"), 7)
    assert "the-real-secret-value" not in refused.stdout + refused.stderr
    for path in [paths.vault_file()] + snapshots:
        with pytest.raises(HardwareError):
            open_with_password(path)


def test_a_restored_session_or_grant_opens_nothing_after_nuke(cli, tmp_path):
    init(cli)
    add(cli, "bank", "the-real-secret-value", "--alias", "BANK")
    session_token = session(cli)
    grant_token = grant(cli, "BANK", args=("--uses", "5", "--reveal"))["token"]
    ssd = tmp_path / "ssd"
    copy_tree(irondome_dirs()["home"], ssd)
    nuke_everything(cli)
    restore_tree(ssd, irondome_dirs()["home"])
    through_session = fails(cli("get", "bank", env={"IRONDOME_SESSION": session_token}), 4)
    through_grant = fails(cli("get", "BANK", env={"IRONDOME_GRANT": grant_token}), 4)
    for result in (through_session, through_grant):
        assert "the-real-secret-value" not in result.stdout + result.stderr


def test_nuke_destroys_the_device_secret_before_anything_else(make_vault, monkeypatch):
    vault, _recovery = make_vault()
    vault.close()
    order = []
    real_delete = paths.secure_delete

    def recording(path):
        order.append(str(path))
        real_delete(path)

    monkeypatch.setattr(paths, "secure_delete", recording)
    report = nuke.execute()
    assert report.success
    device_root = str(paths.device_root())
    first_vault_file = next(index for index, path in enumerate(order) if not path.startswith(device_root))
    assert order[0].startswith(device_root) and order[0].endswith(".key")
    assert all(path.startswith(device_root) for path in order[:first_vault_file])
    assert not any(path.endswith(".key") for path in order[first_vault_file:])


def test_a_vault_whose_file_is_damaged_still_loses_its_device_secret(make_vault):
    """Erasure does not depend on reading the vault file."""
    vault, _recovery = make_vault()
    vault.close()
    assert len(list(paths.device_dir().glob("*.key"))) == 1
    paths.vault_file().write_bytes(b"not a vault any more")
    report = nuke.execute()
    assert report.device_keys_destroyed == 1
    assert not paths.device_dir().exists() or list(paths.device_dir().glob("*.key")) == []


@pytest.mark.secure_enclave
def test_on_the_secure_enclave_a_restored_copy_refuses_the_master_password(secure_enclave, make_vault, tmp_path):
    vault, _recovery = make_vault()
    path = vault.path
    vault.close()
    ssd = tmp_path / "ssd"
    copy_tree(irondome_dirs()["home"], ssd)
    assert nuke.execute().success
    restore_tree(ssd, irondome_dirs()["home"])
    with pytest.raises(HardwareError, match="not on this Mac"):
        open_with_password(path)


@pytest.mark.tpm
def test_on_the_tpm_even_a_restored_device_directory_opens_nothing(tpm, make_vault, tmp_path):
    """The secret was only ever inside the chip: copying every file back does not bring it back."""
    vault, _recovery = make_vault()
    path = vault.path
    vault.close()
    copy_tree(irondome_dirs()["home"], tmp_path / "ssd-home")
    copy_tree(irondome_dirs()["device"], tmp_path / "ssd-device")
    assert nuke.execute().success
    restore_tree(tmp_path / "ssd-home", irondome_dirs()["home"])
    restore_tree(tmp_path / "ssd-device", irondome_dirs()["device"])
    with pytest.raises(HardwareError):
        open_with_password(path)


# -- the boundary ------------------------------------------------------------------


def test_boundary_the_recovery_key_still_opens_a_surviving_copy_and_nuke_says_so(cli, tmp_path):
    created = init(cli)
    add(cli, "bank", "the-real-secret-value")
    ssd = tmp_path / "ssd"
    copy_tree(irondome_dirs()["home"], ssd)
    report = nuke_everything(cli)
    assert report["report"]["recovery_bunkers"] == ["alpha"]
    restore_tree(ssd, irondome_dirs()["home"])
    file = VaultFile.load()
    with Vault(file, unlock.unlock(file, recovery_key=created["recovery_key"])) as restored:
        assert restored.value(restored.find("bank")) == "the-real-secret-value"


def test_boundary_without_a_recovery_key_nothing_opens_a_surviving_copy(cli, tmp_path):
    init(cli, "--no-recovery")
    add(cli, "bank", "the-real-secret-value")
    ssd = tmp_path / "ssd"
    copy_tree(irondome_dirs()["home"], ssd)
    report = nuke_everything(cli)
    assert report["report"]["recovery_bunkers"] == []
    restore_tree(ssd, irondome_dirs()["home"])
    with pytest.raises(HardwareError):
        open_with_password(paths.vault_file())
    with pytest.raises(AuthError, match="no recovery key"):
        unlock.unlock(VaultFile.load(), recovery_key="AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")


def test_boundary_with_the_file_based_backend_a_device_file_an_ssd_kept_would_open_the_copy(make_vault, tmp_path):
    """Overwrite-and-unlink of the device key file is best effort on an SSD: if its blocks survive, so does access."""
    vault, _recovery = make_vault()
    path = vault.path
    backend = device.get_backend(vault.file.slots[0].backend_name)
    vault.close()
    assert backend.name == "software" and not backend.hardware
    copy_tree(irondome_dirs()["home"], tmp_path / "ssd-home")
    copy_tree(irondome_dirs()["device"], tmp_path / "ssd-device")
    assert nuke.execute().success
    restore_tree(tmp_path / "ssd-home", irondome_dirs()["home"])
    restore_tree(tmp_path / "ssd-device", irondome_dirs()["device"])
    open_with_password(path).close()


@pytest.mark.secure_enclave
def test_boundary_on_the_secure_enclave_a_recovered_key_blob_works_only_with_this_macs_enclave(
    secure_enclave, make_vault, tmp_path
):
    vault, _recovery = make_vault()
    path = vault.path
    vault.close()
    copy_tree(irondome_dirs()["home"], tmp_path / "ssd-home")
    copy_tree(irondome_dirs()["device"], tmp_path / "ssd-device")
    assert nuke.execute().success
    restore_tree(tmp_path / "ssd-home", irondome_dirs()["home"])
    restore_tree(tmp_path / "ssd-device", irondome_dirs()["device"])
    open_with_password(path).close()  # this Mac's Secure Enclave still accepts the blob it made
