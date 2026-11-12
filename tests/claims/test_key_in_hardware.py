"""Claim ``key-in-hardware``: on a Mac or a PC with a TPM, the device secret is held by the security chip.

Statement: macOS: the device secret is the result of a key agreement with a
P-256 private key that is generated inside the Secure Enclave and never leaves
it; a key blob from any other Secure Enclave is rejected. Linux: the device
secret is stored in a TPM 2.0 NV index and appears nowhere on disk.

The real-chip tests run on a Mac with a Secure Enclave (``secure_enclave``)
and in the Linux container with a software TPM (``tpm``,
``scripts/test-linux.sh``).
"""

from __future__ import annotations

import base64
import json
import os

import pytest

from irondome import paths
from irondome.errors import HardwareError
from support.claimkit import contents, document, init, irondome_dirs, mac_screen_locked


def device_secret_of(vault):
    """The raw device secret behind the vault's password keyslot, unsealed the way the kernel does."""
    from irondome import device

    slot = vault.file.slots[0]
    backend = device.get_backend(slot.backend_name)
    with backend.unseal(slot.device, auth=None, interactive=False, reason="test") as raw:
        return backend, slot.device, bytes(raw.view())


@pytest.mark.secure_enclave
def test_on_a_mac_the_device_secret_comes_from_the_secure_enclave_and_is_in_no_file(secure_enclave, make_vault):
    vault, _recovery = make_vault(with_recovery=False)
    with vault:
        backend, descriptor, secret = device_secret_of(vault)
    assert backend.name == "macos-se" and backend.hardware
    stored = contents(irondome_dirs()["home"], irondome_dirs()["device"])
    assert all(secret not in data and secret.hex().encode() not in data for data in stored.values())
    state = json.loads((paths.device_dir() / f"{descriptor['ref']}.json").read_text())
    assert set(state) == {"v", "backend", "policy", "key", "peer"}
    assert len(base64.b64decode(state["peer"])) == 65  # an uncompressed P-256 point, not a key


@pytest.mark.secure_enclave
def test_on_a_mac_a_key_blob_this_enclave_did_not_make_is_rejected(secure_enclave, make_vault):
    vault, _recovery = make_vault(with_recovery=False)
    with vault:
        backend, descriptor, secret = device_secret_of(vault)
    path = paths.device_dir() / f"{descriptor['ref']}.json"
    state = json.loads(path.read_text())
    blob = bytearray(base64.b64decode(state["key"]))
    # Refused either way; the reason can only be told apart while the screen is unlocked.
    reason = "this Mac is locked" if mac_screen_locked() else "no longer accepts"
    for foreign in (bytes(blob[:-1]), os.urandom(len(blob)), bytes(blob[:8]) + os.urandom(len(blob) - 8)):
        path.write_text(json.dumps(dict(state, key=base64.b64encode(foreign).decode())))
        with pytest.raises(HardwareError, match=reason):
            backend.unseal(descriptor, auth=None, interactive=False, reason="test")
    path.write_text(json.dumps(state))
    with backend.unseal(descriptor, auth=None, interactive=False, reason="test") as again:
        assert bytes(again.view()) == secret


@pytest.mark.tpm
def test_on_linux_the_device_secret_is_in_a_tpm_nv_index_and_nowhere_on_disk(tpm, make_vault, monkeypatch):
    vault, _recovery = make_vault(with_recovery=False)
    slot = vault.file.slots[0]
    path = vault.path
    vault.close()
    assert slot.backend_name == "linux-tpm2" and tpm.exists(slot.device)
    seen = []
    original = type(tpm).unseal

    def recording(self, descriptor, **kwargs):
        secret = original(self, descriptor, **kwargs)
        seen.append(bytes(secret.view()))
        return secret

    monkeypatch.setattr(type(tpm), "unseal", recording)
    from conftest import PASSWORD, secret
    from irondome import unlock

    with secret(PASSWORD) as password:
        unlock.open_vault(path=path, password=password, interactive=False).close()
    assert len(seen) == 1 and len(seen[0]) == 32
    stored = contents(irondome_dirs()["home"], irondome_dirs()["device"])
    assert any(slot.device["nv_index"].encode() in data for data in stored.values())  # only the handle is on disk
    assert all(seen[0] not in data and seen[0].hex().encode() not in data for data in stored.values())
    tpm.destroy(slot.device)
    assert not tpm.exists(slot.device)


# -- the boundary ------------------------------------------------------------------


def test_boundary_without_a_chip_status_says_the_device_key_is_file_based(cli):
    init(cli)
    status = document(cli("status", "--json"))
    assert status["hardware"] is False
    assert [device["backend"] for device in status["device"]] == ["software"]
    assert all(slot["hardware"] in (False, None) for slot in status["keyslots"])


def test_boundary_irondome_verify_reports_the_claim_skipped_rather_than_passed_without_a_chip(cli):
    report = document(cli("verify", "--claim", "key-in-hardware", "--json"))
    assert [result["result"] for result in report["results"]] == ["skipped"]
    assert "file-based device key" in report["results"][0]["detail"]
    assert report["backend"] == {"name": "software", "hardware": False, "detail": report["backend"]["detail"]}
