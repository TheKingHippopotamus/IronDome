"""Claim ``keys-wiped``: key material is wiped from memory.

Statement: IronDome keeps its copies of the master password, the Argon2id
output, the device secret, the key-encryption key, the vault key and every
subkey only in memory outside the Python heap, locked into RAM where the system
allows it, and overwrites them when the vault is locked; Argon2id and HKDF write their output straight into those
buffers, and each derivation is run a second time on zeros (HKDF with an
all-zero key, Argon2id at its lowest cost with an all-zero password of the
same length), so that what the library leaves behind of the first run is
overwritten by the second. After a full session, a scan of the process's entire address space finds no copy of
any of them.

Boundary tested here: the copy pyca/cryptography (OpenSSL) makes of the master
password inside Argon2id, which IronDome cannot wipe, is the only one a scan
with freed memory unzeroed, or one made right after a derivation, may find.

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


def test_the_probe_judged_by_irondome_verify_passes(probes, derivation):
    result = selftest.evaluate_keys_probe(probes["clean"], probes["control"], probes.get("unzeroed"), derivation)
    assert result.status == selftest.PASS, result.detail


def test_a_non_ascii_master_password_leaves_no_copy_in_any_form(probes):
    document = probes["non-ascii"]
    forms = [label for label in labels(document) if label.startswith("master password")]
    assert "master password" in forms and "master password as stored in a str" in forms
    assert "master password as fed to Argon2id" in forms
    assert leftovers(document) == []


#: The copy the boundary names, as the probe labels it. Argon2id in pyca/cryptography (OpenSSL) copies the
#: password it is given into system-malloc memory and frees it without overwriting it. For an ASCII password
#: both labels are the same bytes. (HKDF leaves a copy of the key it derives too, on the C stack and in memory
#: it frees: IronDome derives again from zeros, which overwrites it, so that copy is not on this list.)
ARGON2_INPUT = ("master password", "master password as fed to Argon2id")


def found_labels(document: Dict[str, Any]) -> List[str]:
    return sorted(needle["label"] for needle in key_needles(document) if needle["hits"])


def assert_argon2_input_copies_are_in_system_malloc(document: Dict[str, Any]) -> None:
    """Python keeps objects this small in its own arenas (``anonymous`` memory), and IronDome its keys in locked
    pages: a copy in ``MALLOC_*`` memory is one that native code made with malloc."""
    for needle in key_needles(document):
        if needle["label"] in ARGON2_INPUT:
            assert all("MALLOC_" in hit["where"] for hit in needle["hits"]), needle


@pytest.mark.skipif(sys.platform != "darwin", reason="on Linux the allocator never zeroes what is freed")
def test_boundary_on_macos_without_zero_on_free_only_the_copy_argon2id_makes_of_the_password_can_be_left(probes):
    """With ``MallocZeroOnFree=0`` macOS behaves like glibc: a block freed without wiping keeps its bytes.

    Then the scan after the vault is locked may find the master password, in
    the copy Argon2id makes of it inside pyca/cryptography (OpenSSL) and frees
    without overwriting, and nothing else. Whether that block is still unused
    when the scan runs is up to the allocator, so this asserts what may be
    found and where, never that a copy is found.
    """
    document = probes["unzeroed"]
    dropped = [needle for needle in document["needles"] if needle["kind"] == "control-dropped"]
    assert len(dropped) == 1 and dropped[0]["hits"]
    assert [label for label in found_labels(document) if label not in ARGON2_INPUT] == []
    assert_argon2_input_copies_are_in_system_malloc(document)


@pytest.fixture(scope="module")
def derivation(tmp_path_factory: pytest.TempPathFactory) -> Dict[str, Any]:
    """The first half of the statement, where the keys are made: IronDome's copies exist only in locked memory.

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
    assert "key HKDF extracts" in found
    assert "master password as stored in a str" in found
    dropped = [needle for needle in derivation["needles"] if needle["kind"] == "control-dropped"]
    assert len(dropped) == 1 and dropped[0]["hits"]


def test_boundary_right_after_a_derivation_the_only_copy_is_the_one_argon2id_makes_of_the_password(derivation):
    """Searched at once, with freed memory unzeroed: what Argon2id copies inside pyca/cryptography is there.

    Argon2id's copy of the password it was fed, in system-malloc memory. No
    copy of the Argon2id output, of the HKDF output, of the password as typed,
    or of any form IronDome itself makes. Whether a run finds the named copy
    is up to the allocator, so this asserts only what may be found, and where.
    """
    assert [label for label in found_labels(derivation) if label not in ARGON2_INPUT] == []
    assert_argon2_input_copies_are_in_system_malloc(derivation)


def test_the_copy_hkdf_leaves_of_a_derived_key_is_overwritten_by_deriving_again_from_zeros(derivation):
    """HKDF inside pyca/cryptography leaves its working keys on the C stack and in memory it frees.

    Two of them: the intermediate key it extracts from its input, from which
    every key under the same input and salt can be made again, and the key it
    derives. IronDome runs every derivation a second time, from the same
    frame, with an all-zero key: the second run puts its working values where
    the first put them. The scan made right after a derivation, with freed
    memory unzeroed, finds neither anywhere outside the locked buffer.
    """
    working = {needle["label"]: needle["hits"] for needle in key_needles(derivation)}
    assert working["HKDF output"] == [] and working["key HKDF extracts"] == []


def test_boundary_argon2id_and_hkdf_are_handed_irondomes_locked_buffers_and_write_straight_into_them(monkeypatch):
    """What IronDome controls: pyca/cryptography gets views of IronDome's own buffers, in and out.

    ``derive_into``, never ``derive``: no immutable ``bytes`` of a key is ever
    handed back. What the library copies on the way is the boundary above.
    After each call comes its repeat on zeros, written into a buffer that is
    thrown away: Argon2id with an all-zero password and salt of the same
    lengths, HKDF with an all-zero key of the same length.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    from irondome import crypto
    from irondome.secmem import SecureBuffer

    calls: List[Any] = []

    def spying(real: Any) -> Any:
        def make(*args: Any, **kwargs: Any) -> Any:
            kdf = real(*args, **kwargs)

            class Recorder:
                def derive_into(self, material: Any, buffer: Any) -> Any:
                    written = kdf.derive_into(material, buffer)
                    calls.append((real.__name__, material, buffer))
                    return written

                def derive(self, *_: Any) -> Any:
                    raise AssertionError("derive returns the key as immutable bytes")

            return Recorder()

        return make

    monkeypatch.setattr(crypto, "Argon2id", spying(crypto.Argon2id))
    monkeypatch.setattr(crypto, "HKDF", spying(crypto.HKDF))
    salt = bytes(range(16))
    with SecureBuffer.from_buffer(b"a test password") as password:
        with crypto.argon2id(password, salt, crypto.Argon2Params(memory_kib=19 * 1024)) as stretched:
            with crypto.hkdf(stretched, b"irondome/test", salt) as derived:
                assert [name for name, _, _ in calls] == ["Argon2id", "Argon2id", "HKDF", "HKDF"]
                _, zeros, scratch = calls.pop()
                assert bytes(zeros) == bytes(len(stretched.view())) and len(scratch) == len(derived.view())
                assert bytes(scratch) != bytes(derived.view())
                _, zeros, scratch = calls.pop(1)
                assert bytes(zeros) == bytes(len(password.view())) and len(scratch) == len(stretched.view())
                assert bytes(scratch) != bytes(stretched.view())
                for (_, material, buffer), source, out in zip(calls, (password, stretched), (stretched, derived)):
                    assert type(material) is memoryview and type(buffer) is memoryview and not buffer.readonly
                    assert bytes(material) == bytes(source.view()) and bytes(buffer) == bytes(out.view())
                expected = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"irondome/test")
                assert bytes(derived.view()) == expected.derive(bytes(stretched.view()))


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
