"""Claim ``recovery``: the recovery key opens the vault without the device.

Statement: a 160-bit recovery key, shown once at setup and stored nowhere,
opens a copy of the vault on any machine, so a lost laptop, a dead chip or a
changed fingerprint is not the end of your data.

The person who holds the key uses it with ``irondome recovery use``, and the
first tests here do exactly that, through the real command line. Before
release every test in this file used the key through the kernel API
(``irondome.unlock.unlock(file, recovery_key=...)``) and all of them passed,
while no command accepted a recovery key at all: a trial by hand found that,
not a test. The tests of the key's properties below still use the API.
"""

from __future__ import annotations

import re

import pytest

from conftest import PASSWORD, secret
from irondome import keys, unlock
from irondome.errors import AuthError, HardwareError, NotFoundError
from irondome.vault import Vault, VaultFile
from support.claimkit import add, contents, copy_tree, document, fails, files, init, irondome_dirs, ok


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


def on_another_machine(tmp_path, name="laptop-2"):
    """The environment of a machine that has a copy of the vault directory and nothing else of this one."""
    copy_tree(irondome_dirs()["home"], tmp_path / name / "irondome")
    return {"IRONDOME_HOME": str(tmp_path / name / "irondome"), "IRONDOME_DEVICE_DIR": str(tmp_path / name / "device")}


NEW_PASSWORD = "a new master password 2"


def test_irondome_recovery_use_opens_a_copy_on_another_machine_and_sets_a_new_master_password(cli, tmp_path):
    """The whole of what a person does after losing the machine, with nothing but the command line."""
    created = init(cli)
    add(cli, "bank", "the-bank-password-5678")
    elsewhere = on_another_machine(tmp_path)
    refused = fails(cli("get", "bank", "--password-stdin", stdin=PASSWORD + "\n", env=elsewhere), 7)
    assert "irondome recovery use" in refused.stderr  # the refusal names the way out
    report = document(
        cli("recovery", "use", "--password-stdin", "--json", stdin=f"{created['recovery_key']}\n{NEW_PASSWORD}\n",
            env=elsewhere)
    )
    assert report["recovered"] is True and report["replaced"] == 1
    shown = ok(cli("get", "bank", "--password-stdin", stdin=NEW_PASSWORD + "\n", env=elsewhere))
    assert shown.stdout.strip() == "the-bank-password-5678"
    assert cli("get", "bank", "--password-stdin", stdin=PASSWORD + "\n", env=elsewhere).returncode != 0
    slots = document(cli("auth", "show", "--json", env=elsewhere))["keyslots"]
    assert sorted(slot["kind"] for slot in slots) == ["password", "recovery"]
    # The original machine is untouched: its vault still opens with the old password.
    assert ok(cli("get", "bank", "--password-stdin", stdin=PASSWORD + "\n")).stdout.strip() == "the-bank-password-5678"


def test_irondome_recovery_use_takes_the_key_as_a_person_types_it_and_the_key_keeps_working(cli, tmp_path):
    created = init(cli)
    add(cli, "bank", "the-bank-password-5678")
    casual = created["recovery_key"].replace("-", " ").lower()
    first = on_another_machine(tmp_path, "laptop-2")
    ok(cli("recovery", "use", "--password-stdin", stdin=f"  {casual} \n{NEW_PASSWORD}\n", env=first))
    second = on_another_machine(tmp_path, "laptop-3")
    said = ok(cli("recovery", "use", "--password-stdin", stdin=f"{created['recovery_key']}\n{NEW_PASSWORD}\n",
                  env=second))
    assert "still opens this vault and every copy of it" in said.stderr and "irondome recovery new" in said.stderr
    assert created["recovery_key"] not in said.stdout + said.stderr


def test_irondome_recovery_use_after_a_forgotten_password_destroys_the_old_device_key(cli):
    created = init(cli)
    add(cli, "bank", "the-bank-password-5678")
    device = irondome_dirs()["device"]
    before = {path.name for path in files(device) if path.suffix == ".key"}
    ok(cli("unlock", "--print-token", "--password-stdin", stdin=PASSWORD + "\n"))
    report = document(
        cli("recovery", "use", "--password-stdin", "--json", stdin=f"{created['recovery_key']}\n{NEW_PASSWORD}\n")
    )
    assert report["sessions_ended"] == 1
    after = {path.name for path in files(device) if path.suffix == ".key"}
    assert len(before) == 1 and before.isdisjoint(after) and after  # the old keyslot's device key is gone
    shown = ok(cli("get", "bank", "--password-stdin", stdin=NEW_PASSWORD + "\n"))
    assert shown.stdout.strip() == "the-bank-password-5678"
    assert cli("get", "bank", "--password-stdin", stdin=PASSWORD + "\n").returncode != 0
    history = ok(cli("audit", "--password-stdin", stdin=NEW_PASSWORD + "\n")).stdout
    assert "keyslot.recovery-use" in history


def test_irondome_recovery_use_leaves_alone_a_device_key_that_is_not_on_this_machine(cli, tmp_path):
    """On another machine there is no old device key to destroy, and nothing keeps trying to.

    A review of the command found that it recorded the old keyslot's device key for destruction wherever it
    ran: with a chip that had died, every later command warned that an old device key "could not be destroyed
    yet", for ever. Where the key is on the machine it is destroyed, as ``passwd`` does, and the command says so.
    """
    created = init(cli)
    add(cli, "bank", "the-bank-password-5678")
    elsewhere = on_another_machine(tmp_path)
    typed = f"{created['recovery_key']}\n{NEW_PASSWORD}\n"
    report = document(cli("recovery", "use", "--password-stdin", "--json", stdin=typed, env=elsewhere))
    assert report["replaced"] == 1 and report["device_keys_destroyed"] == 0
    assert not (tmp_path / "laptop-2" / "irondome" / "bunkers" / "alpha" / "retire-keyslots.json").exists()
    later = ok(cli("get", "bank", "--password-stdin", stdin=NEW_PASSWORD + "\n", env=elsewhere))
    assert "could not be destroyed" not in later.stderr and later.stdout.strip() == "the-bank-password-5678"
    # The machine the vault came from still has its device key, and still opens its own copy.
    assert ok(cli("get", "bank", "--password-stdin", stdin=PASSWORD + "\n")).stdout.strip() == "the-bank-password-5678"
    here = document(cli("recovery", "use", "--password-stdin", "--json", stdin=typed))
    assert here["device_keys_destroyed"] == 1
    said = ok(cli("recovery", "use", "--password-stdin", stdin=typed))
    assert "was on this machine and was destroyed" in said.stderr


def test_irondome_recovery_use_with_a_wrong_key_changes_nothing(cli, tmp_path):
    init(cli)
    elsewhere = on_another_machine(tmp_path)
    home = tmp_path / "laptop-2"
    before = contents(home)
    other = keys.format_recovery_key(bytes(20))
    for typed in (other, "not a recovery key", created_like := other[:-1]):
        refused = cli("recovery", "use", "--password-stdin", stdin=f"{typed}\n{NEW_PASSWORD}\n", env=elsewhere)
        assert refused.returncode != 0 and "Traceback" not in refused.stderr, created_like
    assert contents(home) == before


def test_irondome_recovery_use_is_not_for_a_process_with_no_terminal_and_no_piped_key(cli, tmp_path):
    created = init(cli)
    refused = fails(cli("recovery", "use", stdin=f"{created['recovery_key']}\n{NEW_PASSWORD}\n"), 5)
    assert "owner" in refused.stderr and "pipe the recovery key" in refused.stderr


def test_boundary_irondome_recovery_use_says_so_when_the_vault_has_no_recovery_key(cli, tmp_path):
    init(cli, "--no-recovery")
    elsewhere = on_another_machine(tmp_path)
    refused = fails(
        cli("recovery", "use", "--password-stdin",
            stdin=f"{keys.format_recovery_key(bytes(20))}\n{NEW_PASSWORD}\n", env=elsewhere),
        3,
    )
    assert "no recovery key" in refused.stderr


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


@pytest.mark.parametrize("action", ["new", "remove"])
def test_boundary_a_new_or_removed_recovery_key_re_keys_and_only_older_copies_open_with_the_old_one(
    cli, tmp_path, action
):
    """The vault is re-keyed, so the old key opens nothing from then on; a copy made before still opens with it."""
    first = init(cli)["recovery_key"]
    add(cli, "bank", "stored-before-the-change")
    older = copy_elsewhere(tmp_path)
    before = VaultFile.load().vault_id
    ok(cli("recovery", action, *(("--yes",) if action == "remove" else ()), "--password-stdin", "--json",
           stdin=PASSWORD + "\n"))
    assert VaultFile.load().vault_id != before  # a new vault key and vault id
    add(cli, "mail", "stored-after-the-change")
    with pytest.raises(AuthError):
        unlock.unlock(VaultFile.load(), recovery_key=first)
    old = VaultFile.load(older)
    with Vault(old, unlock.unlock(old, recovery_key=first), older) as copy:
        assert copy.value(copy.find("bank")) == "stored-before-the-change"
        with pytest.raises(NotFoundError):
            copy.find("mail")
