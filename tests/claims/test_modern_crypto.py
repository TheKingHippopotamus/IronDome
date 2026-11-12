"""Claim ``modern-crypto``: Argon2id and AES-256-GCM, from one audited library.

Statement: master passwords are stretched with Argon2id (by default 256 MiB,
3 passes and 4 lanes, and 64 MiB, RFC 9106's low-memory choice, on a machine
with less than 3 GiB of RAM; never below the OWASP minimum), keys are derived
with HKDF-SHA256 and data is encrypted with AES-256-GCM using random 96-bit
nonces. IronDome implements no primitive itself; all of them come from
pyca/cryptography and are checked against published test vectors.

The suite sets ``IRONDOME_KDF_MEMORY_MIB=19`` to stay fast; the tests of the
default take it away first.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import irondome
from conftest import PASSWORD
from irondome import crypto, paths
from irondome.errors import VaultError
from irondome.vault import VaultFile
from support.claimkit import document, init

PACKAGE = Path(irondome.__file__).resolve().parent
REPOSITORY = Path(__file__).resolve().parents[2]
MIB = 1024**2
GIB = 1024**3

# RFC 5869, test case 1.
HKDF_IKM, HKDF_SALT, HKDF_INFO = "0b" * 22, "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9"
HKDF_OKM = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
# The GCM specification (McGrew and Viega), test case 16: AES-256, 96-bit IV, associated data.
GCM_KEY = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
GCM_IV = "cafebabefacedbaddecaf888"
GCM_AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
GCM_PLAINTEXT = (
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)
GCM_CIPHERTEXT_AND_TAG = (
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
    "76fc6ece0f4e1768cddf8853bb2d551b"
)
# RFC 9106, section 5.3 (Argon2id).
ARGON2ID_TAG = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


def test_hkdf_as_irondome_calls_it_matches_rfc_5869():
    with crypto.hkdf(bytes.fromhex(HKDF_IKM), info=bytes.fromhex(HKDF_INFO), salt=bytes.fromhex(HKDF_SALT),
                     length=42) as okm:
        assert bytes(okm.view()).hex() == HKDF_OKM


def test_aes_256_gcm_as_irondome_calls_it_matches_the_gcm_specification():
    sealed = bytes.fromhex(GCM_IV + GCM_CIPHERTEXT_AND_TAG)
    assert crypto.open_sealed(bytes.fromhex(GCM_KEY), sealed, bytes.fromhex(GCM_AAD)).hex() == GCM_PLAINTEXT


def test_the_argon2id_irondome_uses_is_rfc_9106_argon2id():
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    rfc = Argon2id(salt=b"\x02" * 16, length=32, iterations=3, lanes=4, memory_cost=32, ad=b"\x04" * 12,
                   secret=b"\x03" * 8)
    assert rfc.derive(b"\x01" * 32).hex() == ARGON2ID_TAG
    salt = b"s" * 16
    params = crypto.Argon2Params(memory_kib=19 * 1024, iterations=3, lanes=4)
    with crypto.argon2id(b"a password", salt, params) as ours:
        reference = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=19 * 1024)
        assert bytes(ours.view()) == reference.derive(b"a password")


@pytest.mark.parametrize(
    ("ram", "mib"),
    [(512 * MIB, 64), (2 * GIB, 64), (3 * GIB - 1, 64), (3 * GIB, 256), (16 * GIB, 256), (None, 256)],
    ids=["512MiB", "2GiB", "just-under-3GiB", "3GiB", "16GiB", "unknown"],
)
def test_the_default_is_256_mib_and_64_mib_on_a_machine_with_less_than_3_gib(monkeypatch, ram, mib):
    """Exactly the two costs the statement names, each on the machines it names (RAM unknown: the full cost)."""
    monkeypatch.delenv("IRONDOME_KDF_MEMORY_MIB")
    monkeypatch.setattr(crypto, "_physical_memory_bytes", lambda: ram)
    assert crypto.default_argon2() == crypto.Argon2Params(memory_kib=mib * 1024, iterations=3, lanes=4)


def test_a_new_vault_stores_the_default_cost(cli, monkeypatch):
    """A real ``init`` on this machine stores the default for this machine's RAM, and nothing else."""
    monkeypatch.delenv("IRONDOME_KDF_MEMORY_MIB")
    ram = crypto._physical_memory_bytes()
    expected = 64 * 1024 if ram is not None and ram < 3 * GIB else 256 * 1024
    assert crypto.default_argon2().memory_kib == expected
    init(cli)
    slot = [slot for slot in VaultFile.load().slots if slot.kind == "password"][0]
    assert slot.kdf is not None and slot.kdf["alg"] == "argon2id"
    assert (slot.kdf["m"], slot.kdf["t"], slot.kdf["p"]) == (expected, 3, 4)


@pytest.mark.parametrize("memory_kib", [19 * 1024 - 1, 1024, 8])
def test_a_cost_below_the_owasp_minimum_is_never_accepted(cli, memory_kib):
    with pytest.raises(VaultError):
        crypto.Argon2Params(memory_kib=memory_kib).validate()
    init(cli)
    raw = json.loads(paths.vault_file().read_text())
    for slot in raw["keyslots"]:
        if slot["kind"] == "password":
            slot["kdf"]["m"] = memory_kib
    paths.vault_file().write_text(json.dumps(raw))
    refused = cli("ls", "--password-stdin", stdin=PASSWORD + "\n")
    assert refused.returncode == 6 and "Argon2id memory cost" in refused.stderr


def test_the_kdf_option_cannot_go_below_the_minimum(cli):
    refused = cli("init", "--password-stdin", "--kdf-memory-mib", "8", stdin=PASSWORD + "\n")
    assert refused.returncode in (2, 6)
    assert not paths.vault_file().exists()


def test_records_carry_a_fresh_96_bit_nonce_and_a_128_bit_tag():
    key = b"k" * 32
    sealed = [crypto.seal(key, b"the same plaintext", b"the same context") for _ in range(64)]
    assert len({blob[: crypto.NONCE_LEN] for blob in sealed}) == 64
    assert all(len(blob) == 12 + len(b"the same plaintext") + 16 for blob in sealed)
    assert (crypto.NONCE_LEN, crypto.TAG_LEN, crypto.KEY_LEN) == (12, 16, 32)


def test_every_primitive_comes_from_cryptography():
    """The kernel's crypto module imports Argon2id, HKDF and AESGCM from pyca/cryptography, and defines none."""
    tree = ast.parse((PACKAGE / "crypto.py").read_text(encoding="utf-8"))
    imported = {
        alias.name: node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) for alias in node.names
    }
    assert imported["Argon2id"] == "cryptography.hazmat.primitives.kdf.argon2"
    assert imported["HKDF"] == "cryptography.hazmat.primitives.kdf.hkdf"
    assert imported["AESGCM"] == "cryptography.hazmat.primitives.ciphers.aead"
    defined = {node.name for node in ast.walk(tree) if isinstance(node, (ast.ClassDef, ast.FunctionDef))}
    assert not defined & {"Argon2id", "HKDF", "AESGCM"}


def test_irondome_verify_runs_the_same_checks_on_this_machine(cli):
    report = document(cli("verify", "--claim", "modern-crypto", "--json"))
    assert report["results"][0]["result"] == "pass", report["results"][0]["detail"]
    assert "RFC 9106" in report["results"][0]["detail"]


# -- the boundary ------------------------------------------------------------------


def test_boundary_the_threat_model_says_that_nobody_has_audited_irondome():
    threat_model = (REPOSITORY / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "No independent audit" in threat_model


def test_boundary_the_environment_or_the_option_replaces_the_default_cost(cli, monkeypatch):
    """IRONDOME_KDF_MEMORY_MIB, or --kdf-memory-mib when a vault is made, sets any cost from 19 MiB to 4 GiB."""
    init(cli)  # the suite's IRONDOME_KDF_MEMORY_MIB=19
    slot = [slot for slot in VaultFile.load().slots if slot.kind == "password"][0]
    assert (slot.kdf["m"], slot.kdf["t"], slot.kdf["p"]) == (19 * 1024, 3, 4)
    made = cli("bunker", "create", "bravo", "--password-stdin", "--kdf-memory-mib", "20",
               stdin=f"{PASSWORD}\nbravo's own master password\n")  # the owner's password, then the new one
    assert made.returncode == 0, made.stderr
    raw = json.loads((paths.root() / "bunkers" / "bravo" / "vault.irondome").read_text())
    assert [slot["kdf"]["m"] for slot in raw["keyslots"] if slot["kind"] == "password"] == [20 * 1024]
    for mib, accepted in (("19", True), ("4096", True), ("18", False), ("4097", False)):
        monkeypatch.setenv("IRONDOME_KDF_MEMORY_MIB", mib)
        if accepted:
            assert crypto.default_argon2().memory_kib == int(mib) * 1024
        else:
            with pytest.raises(VaultError):
                crypto.default_argon2()
