"""Claim ``biometric-enforced-by-chip``: Touch ID is enforced by the Secure Enclave, not by IronDome.

Statement: a keyslot under the biometry policy uses a Secure Enclave key
created with the biometryCurrentSet access control. The chip refuses the key
operation until its sensor reports a match for a currently enrolled finger.
Asked to operate without user interaction, the key answers "authentication
required" instead of producing a secret.

Nothing here can show a Touch ID dialog: the helper is driven without
``--interactive``, and ``IRONDOME_NO_TOUCH=1`` is set for every test. The
acceptance (one touch makes the key work) needs a person and is marked
``interactive``; ``irondome verify --touch`` runs the same check on a Mac.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess

import pytest

from irondome import keys, selftest
from irondome.device import macos_se
from irondome.device.base import POLICY_BIOMETRY, POLICY_DEVICE
from irondome.errors import AuthError
from irondome.keys import KIND_DEVICE, Keyslot
from support.claimkit import document


def helper(*arguments: str, request=None) -> subprocess.CompletedProcess:
    """Run the compiled helper exactly as the backend does, never with --interactive."""
    assert "--interactive" not in arguments
    return subprocess.run(
        [os.environ["IRONDOME_SE_HELPER"], *arguments],
        input=json.dumps(request).encode() if request is not None else b"",
        capture_output=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"]},
    )


def biometric_key_or_skip(secure_enclave) -> str:
    if not secure_enclave.info().get("biometry_usable"):
        pytest.skip("no enrolled finger: the Secure Enclave will not create a biometric key")
    created = helper("create", POLICY_BIOMETRY)
    assert created.returncode == 0, created.stderr.decode()
    return json.loads(created.stdout)["key"]


def test_the_helper_creates_biometric_keys_with_biometry_current_set():
    source = macos_se.helper_source().read_text(encoding="utf-8")
    assert 'case "biometry": flags = [.privateKeyUsage, .biometryCurrentSet]' in source
    assert "kSecAttrAccessibleWhenUnlockedThisDeviceOnly" in source
    assert "context.interactionNotAllowed = !interactive" in source


def test_a_biometric_keyslot_asks_the_helper_for_a_biometric_key(monkeypatch):
    """What the kernel sends: the policy of the keyslot, to the helper's create command."""
    calls = []
    backend = macos_se.SecureEnclaveBackend()

    def run_json(arguments):
        calls.append(list(arguments))
        if arguments == ["info"]:
            return {"secure_enclave": True, "biometry_usable": True}
        return {"key": base64.b64encode(b"blob").decode()}

    def agree(key, peer, *, interactive, reason):
        calls.append(["agree", interactive])
        raise AuthError("Touch ID is required for this vault")

    monkeypatch.setattr(backend, "_run_json", run_json)
    monkeypatch.setattr(backend, "_agree", agree)
    with pytest.raises(AuthError):
        backend.enroll(policy=POLICY_BIOMETRY, auth=None, reason="test")
    assert ["create", POLICY_BIOMETRY] in calls
    assert ["agree", True] in calls  # a biometric key always goes to the chip asking for a person


@pytest.mark.secure_enclave
def test_the_secure_enclave_refuses_a_biometric_key_without_a_touch(secure_enclave):
    key = biometric_key_or_skip(secure_enclave)
    peer = base64.b64encode(macos_se._random_point()).decode()
    result = helper("agree", request={"key": key, "peer": peer, "reason": "run the IronDome test suite"})
    assert result.returncode == 4
    assert result.stdout == b""
    assert json.loads(result.stderr.decode().strip().splitlines()[-1])["error"] == "interaction_required"


@pytest.mark.secure_enclave
def test_a_keyslot_on_a_biometric_key_yields_no_vault_key_without_a_touch(secure_enclave, tmp_path):
    """The whole keyslot path: the refusal comes from the chip before any key exists in this process."""
    key = biometric_key_or_skip(secure_enclave)
    ref = "ab" * 16
    from irondome import paths

    state = {"v": 1, "backend": "macos-se", "policy": POLICY_BIOMETRY, "key": key,
             "peer": base64.b64encode(macos_se._random_point()).decode()}
    paths.write_atomic(paths.device_dir() / f"{ref}.json", json.dumps(state).encode())
    slot = Keyslot(id="cd" * 16, kind=KIND_DEVICE, wrap=base64.b64encode(os.urandom(60)).decode(),
                   device={"backend": "macos-se", "policy": POLICY_BIOMETRY, "ref": ref})
    with pytest.raises(AuthError, match="Touch ID is required"):
        keys.open_slot(slot, os.urandom(keys.VAULT_ID_LEN), interactive=False, reason="run the IronDome test suite")
    with pytest.raises(AuthError, match="Touch ID is required"):
        keys.open_slot(slot, os.urandom(keys.VAULT_ID_LEN), interactive=True, reason="run the IronDome test suite")


@pytest.mark.secure_enclave
def test_the_control_a_device_policy_key_works_without_anyone(secure_enclave):
    key = json.loads(helper("create", POLICY_DEVICE).stdout)["key"]
    peer = base64.b64encode(macos_se._random_point()).decode()
    result = helper("agree", request={"key": key, "peer": peer, "reason": "test"})
    assert result.returncode == 0 and len(result.stdout) == 32


@pytest.mark.secure_enclave
def test_irondome_verify_proves_the_refusal_on_this_mac_without_a_prompt(cli, secure_enclave):
    report = document(cli("verify", "--claim", "biometric-enforced-by-chip", "--json"))
    result = report["results"][0]
    assert report["backend"]["name"] == "macos-se"
    if not secure_enclave.info().get("biometry_usable"):
        assert result["result"] == "skipped"
    else:
        assert result["result"] == "pass", result["detail"]
        assert "refused by the Secure Enclave" in result["detail"] and "--touch" in result["detail"]


@pytest.mark.interactive
@pytest.mark.secure_enclave
def test_one_touch_makes_a_biometric_key_work(secure_enclave, monkeypatch):
    """Needs a finger on the sensor: IRONDOME_TEST_INTERACTIVE=1 on a Mac with Touch ID."""
    monkeypatch.delenv("IRONDOME_NO_TOUCH", raising=False)
    report = selftest.run(["biometric-enforced-by-chip"], touch=True)
    assert report.outcomes[0].result.status == selftest.PASS, report.outcomes[0].result.detail


# -- the boundary ------------------------------------------------------------------


def test_boundary_without_a_secure_enclave_the_claim_is_skipped_not_passed(cli):
    report = document(cli("verify", "--claim", "biometric-enforced-by-chip", "--json"))
    assert report["results"][0]["result"] == "skipped"
    assert "Secure Enclave" in report["results"][0]["detail"]

