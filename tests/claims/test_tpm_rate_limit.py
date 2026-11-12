"""Claim ``tpm-rate-limit``: on Linux the TPM checks the password and rate-limits guesses.

Statement: the TPM verifies a value derived from the master password before
releasing the device secret, with dictionary-attack protection enabled on the
NV index: a wrong password is refused by the chip, and repeated failures put
the TPM into lockout.

These run against a TPM 2.0 (``tpm`` fixture): ``scripts/test-linux.sh`` starts
a software TPM in a container. Every test leaves the TPM out of lockout.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from conftest import PASSWORD, secret
from irondome import unlock
from irondome.errors import AuthError, LockedOutError

pytestmark = pytest.mark.tpm


def tpm2(tool: str, *arguments: str) -> subprocess.CompletedProcess:
    path = shutil.which(tool, path="/usr/bin:/bin:/usr/local/bin")
    assert path, f"{tool} is not installed"
    env = {"PATH": "/usr/bin:/bin"}
    if os.environ.get("TPM2TOOLS_TCTI"):
        env["TPM2TOOLS_TCTI"] = os.environ["TPM2TOOLS_TCTI"]
    return subprocess.run([path, *arguments], capture_output=True, text=True, timeout=60, env=env, check=False)


@pytest.fixture
def chip(tpm):
    tpm2("tpm2_dictionarylockout", "--clear-lockout")
    yield tpm
    tpm2("tpm2_dictionarylockout", "--clear-lockout")


def open_with(path, password: str):
    with secret(password) as typed:
        return unlock.open_vault(path=path, password=typed, interactive=False)


def test_the_vaults_nv_index_has_dictionary_attack_protection(chip, make_vault):
    vault, _recovery = make_vault(with_recovery=False)
    index = vault.file.slots[0].device["nv_index"]
    vault.close()
    public = tpm2("tpm2_nvreadpublic", index)
    assert public.returncode == 0, public.stderr
    attributes = public.stdout.split("attributes:")[1].split("size:")[0]
    assert "authread" in attributes and "authwrite" in attributes
    assert "no_da" not in attributes and "ownerread" not in attributes


def test_a_wrong_master_password_is_refused_by_the_chip_and_counted(chip, make_vault):
    vault, _recovery = make_vault(with_recovery=False)
    path = vault.path
    vault.close()
    before = chip.lockout_status()["failed_tries"]
    with pytest.raises(AuthError, match="wrong master password"):
        open_with(path, "not the master password")
    assert chip.lockout_status()["failed_tries"] == before + 1
    open_with(path, PASSWORD).close()


def test_repeated_wrong_passwords_put_the_tpm_into_lockout_even_for_the_right_one(chip, make_vault):
    vault, _recovery = make_vault(with_recovery=False)
    path = vault.path
    vault.close()
    limit = chip.lockout_status()["max_tries"]
    assert limit > 0
    for attempt in range(limit):
        with pytest.raises(AuthError):
            open_with(path, f"guess number {attempt}")
    status = chip.lockout_status()
    assert status["in_lockout"] and status["remaining_tries"] == 0
    with pytest.raises(LockedOutError):
        open_with(path, PASSWORD)
    tpm2("tpm2_dictionarylockout", "--clear-lockout")
    open_with(path, PASSWORD).close()


# -- the boundary ------------------------------------------------------------------


def test_boundary_the_thresholds_are_the_tpms_own_global_counter(chip, make_vault, monkeypatch):
    """Two vaults share one counter: a guess against either counts toward the same lockout."""
    first, _ = make_vault(with_recovery=False)
    first_path = first.path
    first.close()
    monkeypatch.setenv("IRONDOME_BUNKER", "bravo")
    second, _ = make_vault(with_recovery=False)
    second_path = second.path
    second.close()
    start = chip.lockout_status()["failed_tries"]
    for path in (first_path, second_path):
        with pytest.raises(AuthError):
            open_with(path, "a wrong guess")
    assert chip.lockout_status()["failed_tries"] == start + 2
    status = tpm2("tpm2_getcap", "properties-variable")
    assert "TPM2_PT_MAX_AUTH_FAIL" in status.stdout + tpm2("tpm2_getcap", "properties-fixed").stdout
