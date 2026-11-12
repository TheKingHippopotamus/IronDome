"""Claim ``keys-wiped``: key material is wiped from memory.

Statement: the master password, the Argon2id output, the device secret, the
key-encryption key, the vault key and every subkey exist only in locked memory
outside the Python heap and are overwritten when the vault is locked. A scan
of the process's entire address space afterwards finds no copy of any of them.

How it is proved: a fresh interpreter (``irondome.selftest.probe_main``)
wraps ``irondome.crypto.argon2id`` and ``hkdf``, the device backend's
``enroll`` and ``unseal`` and ``keys.new_vault_key``, so that an XOR-masked
copy of every key the kernel makes is recorded as it is made; the recovery
key is recorded as the secret HKDF is given for the recovery keyslot, and as
the text the new vault hands back (as written down, and without its dashes).
It reads the master password from a pipe with ``secmem.read_secret_from_fd``,
creates a vault, adds an entry, closes it, reopens it, reads the entry,
starts a session and makes a grant and uses both, opens the vault once more
with its recovery key and zeroes that key's text, as the caller it was shown
to is to do, closes everything, and then searches its whole address space
with ``irondome.memscan``. Every key must have zero hits. The same run plants a
random key kept as ``bytes`` and one dropped as ``bytes`` without wiping, and
both must be found; a separate control run keeps the real vault key as
``bytes`` and that copy must be found where it is. Otherwise the scanner would
prove nothing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

from conftest import PASSWORD
from irondome import memscan, selftest
from irondome.secmem import wipe_bytes
from irondome.vault import Secret

pytestmark = pytest.mark.skipif(not memscan.supported()[0], reason=memscan.supported()[1] or "scanner unavailable")

#: What the statement names, as the probe labels it. Every one must be looked for, and found nowhere.
NAMED_KEYS = (
    "master password",
    "Argon2id output",
    "device secret",
    "device key",
    "key-encryption key of the password keyslot",
    "vault key",
    "index key",
    "entry key",
)
#: Subkeys beyond those: "every subkey".
OTHER_SUBKEYS = (
    "device authorisation value",
    "key-encryption key of the recovery keyslot",
    "recovery-slot subkey",
    "audit owner key",
    "audit sealing key",
    "audit key of a grant",
    "capability device key",
    "session wrapping key",
    "grant wrapping key",
)
#: The recovery key itself, as the probe records it, with its length: the 160-bit secret that opens any
#: copy of the vault without the device, and the text a person writes down and types back.
RECOVERY_KEY_FORMS = {"recovery key": 20, "recovery key as written down": 39, "recovery key without its dashes": 32}
#: Changes under NFKC (the ligature) and needs two- and four-byte str storage.
NON_ASCII_PASSWORD = "ﬁnal Pässwörd 日本語 \U0001d518nicode"


#: Current macOS zeroes small blocks as they are freed, which would hide a copy that some library
#: frees without wiping; glibc never does. This turns it off for one more probe.
UNZEROED = {"MallocZeroOnFree": "0"}


@pytest.fixture(scope="module")
def probes(tmp_path_factory: pytest.TempPathFactory) -> Dict[str, Dict[str, Any]]:
    """The probes of this file, run once and at the same time: each searches about 7 GiB on a Mac."""
    where = tmp_path_factory.mktemp("keys-wiped")
    runs: List[Any] = [("keys", PASSWORD), ("keys-control", PASSWORD), ("keys", NON_ASCII_PASSWORD)]
    names = ["clean", "control", "non-ascii"]
    if sys.platform == "darwin":
        runs.append(("keys", PASSWORD, UNZEROED))
        names.append("unzeroed")
    documents = selftest.memory_probes(where, runs, environment={"IRONDOME_DEVICE_BACKEND": "software"})
    return dict(zip(names, documents))


def key_needles(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [needle for needle in document["needles"] if needle["kind"] == "key"]


def leftovers(document: Dict[str, Any]) -> List[str]:
    return [
        f"{needle['label']}: {[hit['where'] for hit in needle['hits']]}"
        for needle in key_needles(document)
        if needle["hits"]
    ]


def labels(document: Dict[str, Any]) -> List[str]:
    return [needle["label"] for needle in key_needles(document)]


def test_no_key_is_left_anywhere_in_memory_after_the_vault_is_locked(probes):
    assert leftovers(probes["clean"]) == []


def test_every_key_the_statement_names_was_recorded_and_looked_for(probes):
    found = labels(probes["clean"])
    assert [name for name in NAMED_KEYS if name not in found] == []
    assert all(needle["recorded"] >= 1 and needle["length"] >= 8 for needle in key_needles(probes["clean"]))


def test_every_other_subkey_was_looked_for_too(probes):
    found = labels(probes["clean"])
    assert [name for name in OTHER_SUBKEYS if name not in found] == []


def test_the_recovery_key_itself_was_looked_for_in_every_form_and_left_nowhere(probes):
    """Not only the subkey made from it: the secret itself, recorded when made and again when it opens the vault."""
    for name in ("clean", "non-ascii", "unzeroed"):
        if name not in probes:
            continue
        found = {needle["label"]: needle for needle in key_needles(probes[name])}
        assert {label: found[label]["length"] for label in RECOVERY_KEY_FORMS if label in found} == RECOVERY_KEY_FORMS
        assert found["recovery key"]["recorded"] >= 2, "the probe did not open the vault with its recovery key"
        assert leftovers_of(probes[name], *RECOVERY_KEY_FORMS) == []


def test_the_search_covered_the_whole_address_space_without_disturbing_it(probes):
    stats = probes["clean"]["stats"]
    assert stats["whole_address_space"] and not stats["writable_only"]
    assert not stats["truncated"]
    assert stats["allocation_free"]
    assert stats["bytes_scanned"] > 32 << 20 and stats["regions"] > 10


def test_a_key_kept_as_bytes_is_found_exactly_where_it_is(probes):
    """The control: without it, zero hits could mean a blind scanner."""
    for document in (probes["clean"], probes["control"]):
        kept = [needle for needle in document["needles"] if needle["kind"] == "control-kept"]
        assert kept
        for needle in kept:
            assert needle["expected"] in [hit["address"] for hit in needle["hits"]], needle


def test_the_real_vault_key_kept_as_bytes_by_the_control_run_is_found(probes):
    kept = [needle for needle in probes["control"]["needles"] if needle["label"] == "vault key kept as bytes"]
    assert len(kept) == 1
    assert kept[0]["expected"] in [hit["address"] for hit in kept[0]["hits"]]


def test_a_key_dropped_as_bytes_without_wiping_is_still_found(probes):
    """What the claim rules out: a copy freed without being overwritten stays readable."""
    dropped = [needle for needle in probes["clean"]["needles"] if needle["kind"] == "control-dropped"]
    assert len(dropped) == 1 and dropped[0]["hits"]


def test_the_probe_judged_by_irondome_verify_passes(probes):
    result = selftest.evaluate_keys_probe(probes["clean"], probes["control"])
    assert result.status == selftest.PASS, result.detail


def test_a_non_ascii_master_password_leaves_no_copy_in_any_form(probes):
    document = probes["non-ascii"]
    forms = [label for label in labels(document) if label.startswith("master password")]
    assert "master password" in forms and "master password as stored in a str" in forms
    assert "master password as fed to Argon2id" in forms
    assert leftovers(document) == []


@pytest.mark.skipif(sys.platform != "darwin", reason="on Linux the allocator never zeroes what is freed")
def test_on_macos_no_key_is_left_even_when_the_system_does_not_zero_freed_memory(probes):
    """The statement says the keys are overwritten: by IronDome, not by the luck of the allocator.

    With ``MallocZeroOnFree=0`` macOS behaves like glibc: a block freed without
    wiping keeps its bytes until it is reused.
    """
    document = probes["unzeroed"]
    dropped = [needle for needle in document["needles"] if needle["kind"] == "control-dropped"]
    assert len(dropped) == 1 and dropped[0]["hits"]
    assert leftovers(document) == []


@pytest.fixture(scope="module")
def derivation(tmp_path_factory: pytest.TempPathFactory) -> Dict[str, Any]:
    """The first half of the statement, where the keys are made: they exist only in locked memory.

    The ``kdf`` probe normalises the master password, stretches it with
    Argon2id and expands that with HKDF, twice, as an unlock does, and
    searches its writable memory at once, leaving out only the four live
    buffers: whatever the derivation itself copied anywhere else is still there
    to be found, before later work happens to reuse the block. On macOS it runs
    with ``MallocZeroOnFree=0``, as glibc behaves.
    """
    environment = dict(UNZEROED) if sys.platform == "darwin" else {}
    where = tmp_path_factory.mktemp("derivation")
    return selftest.memory_probe(where, "kdf", secret=NON_ASCII_PASSWORD, environment=environment)


def leftovers_of(document: Dict[str, Any], *names: str) -> List[str]:
    return [entry for entry in leftovers(document) if entry.split(":")[0] in names]


def test_the_derivation_probe_recorded_every_form_and_saw_its_control(derivation):
    found = set(labels(derivation))
    assert {"master password", "master password as fed to Argon2id", "Argon2id output", "HKDF output"} <= found
    assert "master password as stored in a str" in found
    dropped = [needle for needle in derivation["needles"] if needle["kind"] == "control-dropped"]
    assert len(dropped) == 1 and dropped[0]["hits"]


def test_hkdf_leaves_no_copy_of_the_key_it_derives(derivation):
    assert leftovers_of(derivation, "HKDF output") == []


def test_argon2id_leaves_no_copy_of_the_password_or_of_its_output(derivation):
    assert leftovers_of(derivation, "master password", "master password as fed to Argon2id", "Argon2id output") == []


def test_normalising_a_non_ascii_password_leaves_no_str_copy_of_it(derivation):
    stored = ("master password as stored in a str", "master password as fed to Argon2id as stored in a str")
    assert leftovers_of(derivation, *stored) == []


@pytest.mark.secure_enclave
def test_with_the_secure_enclave_no_key_is_left_either(secure_enclave, tmp_path):
    environment = {"IRONDOME_DEVICE_BACKEND": "macos-se", "IRONDOME_SE_HELPER": os.environ["IRONDOME_SE_HELPER"]}
    document = selftest.memory_probe(tmp_path, "keys", secret=PASSWORD, environment=environment)
    assert document["backend"] == "macos-se"
    assert "device secret" in labels(document)
    assert leftovers(document) == []


@pytest.mark.tpm
def test_with_the_tpm_no_key_is_left_either(tpm, tmp_path):
    environment = {"IRONDOME_DEVICE_BACKEND": "linux-tpm2"}
    if os.environ.get("TPM2TOOLS_TCTI"):
        environment["TPM2TOOLS_TCTI"] = os.environ["TPM2TOOLS_TCTI"]
    document = selftest.memory_probe(tmp_path, "keys", secret=PASSWORD, environment=environment)
    assert document["backend"] == "linux-tpm2"
    assert leftovers(document) == []


# -- the boundary ------------------------------------------------------------------


def test_boundary_a_decrypted_entry_is_an_ordinary_string(vault):
    value = vault.value(vault.find("github"))
    assert type(value) is str
    assert wipe_bytes(value) is False  # strings are never wiped: the documented limit
    assert value == "hunter2-Github!"


def test_boundary_session_and_grant_tokens_are_ordinary_strings(vault):
    from irondome import caps

    token = caps.create_session(vault, ttl=600)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=600)
    assert type(token) is str and type(grant) is str
    assert token.startswith("irondome_s_") and grant.startswith("irondome_g_")


def test_boundary_a_value_still_in_use_is_readable_in_memory(vault):
    """Debugger rights over a running IronDome read anything: a decrypted value in use is plain text in memory."""
    scanner = memscan.open_scanner()
    try:
        table = memscan.NeedleTable(capacity=2, size=256)
        value = vault.value(vault.find("aws/prod"))
        encoded = value.encode("utf-8")
        index = table.add(encoded, "value")
        wipe_bytes(encoded)  # only the str the vault returned is left
        result = scanner.scan(table, writable_only=True)
    finally:
        scanner.close()
    assert result.hits[index]
    assert Secret(password=value).password == "AKIA-not-a-real-key"


def test_the_probe_runs_in_a_fresh_interpreter_with_a_minimal_environment(tmp_path):
    command = selftest._probe_command("keys")
    assert command[0] == sys.executable and command[1] == "-I"
    env = selftest._probe_environment(tmp_path, {"IRONDOME_DEVICE_BACKEND": "software", "PYTHONPATH": "/elsewhere"})
    assert env["IRONDOME_DEBUG"] == "1" and env["IRONDOME_NO_TOUCH"] == "1"
    assert "PYTHONPATH" not in env
    assert Path(env["IRONDOME_HOME"]).parent == tmp_path and Path(env["IRONDOME_DEVICE_DIR"]).parent == tmp_path
