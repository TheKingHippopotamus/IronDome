"""Claim ``tamper-evident``: altered, swapped or rolled-back records are rejected.

Statement: every record is authenticated with AES-256-GCM and bound to its
vault, its entry and its revision. Changing a byte, moving a record to another
entry, or restoring an older version of one record makes the vault refuse to
read it.

The file is changed the way an attacker with write access would: by editing
the JSON document on disk, never through IronDome.
"""

from __future__ import annotations

import pytest

from conftest import PASSWORD
from irondome import crypto, paths
from irondome.vault import VaultFile
from support.claimkit import add, document, fails, init, ok


def rewrite(change) -> None:
    file = VaultFile.load()
    change(file)
    paths.write_atomic(paths.vault_file(), file.to_bytes())


def flipped(text: str, at: int) -> str:
    raw = bytearray(crypto.b64d(text))
    raw[at % len(raw)] ^= 0x01
    return crypto.b64e(bytes(raw))


def get(cli, name: str):
    return cli("get", name, "--password-stdin", stdin=PASSWORD + "\n")


def ids(cli) -> dict:
    return {document(cli("show", name, "--password-stdin", "--json", stdin=PASSWORD + "\n"))["id"]: name
            for name in ("first", "second")}


@pytest.fixture
def two_entries(cli):
    init(cli)
    add(cli, "first", "the-first-value")
    add(cli, "second", "the-second-value")
    by_id = {name: entry_id for entry_id, name in ids(cli).items()}
    return by_id


@pytest.mark.parametrize("at", [0, 5, 12, 20, 40, -1])
def test_a_changed_byte_anywhere_in_a_record_is_refused(cli, two_entries, at):
    entry_id = two_entries["first"]
    rewrite(lambda file: file.records.__setitem__(entry_id, flipped(file.records[entry_id], at)))
    refused = fails(get(cli, "first"), 6)
    assert "failed authentication" in refused.stderr and "the-first-value" not in refused.stdout
    assert ok(get(cli, "second")).stdout == "the-second-value"


def test_a_record_moved_to_another_entry_is_refused(cli, two_entries):
    rewrite(lambda file: file.records.__setitem__(two_entries["second"], file.records[two_entries["first"]]))
    refused = fails(get(cli, "second"), 6)
    assert "the-first-value" not in refused.stdout + refused.stderr


def test_an_older_version_of_one_record_is_refused(cli, two_entries):
    old = VaultFile.load().records[two_entries["first"]]
    ok(cli("edit", "first", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\nthe-newer-value\n"))
    rewrite(lambda file: file.records.__setitem__(two_entries["first"], old))
    refused = fails(get(cli, "first"), 6)
    assert "stale copy" in refused.stderr
    assert "the-first-value" not in refused.stdout


def test_a_changed_byte_in_the_index_is_refused(cli, two_entries):
    rewrite(lambda file: setattr(file, "index", flipped(file.index, 30)))
    fails(cli("ls", "--password-stdin", stdin=PASSWORD + "\n"), 6)


def test_a_record_from_another_vault_is_refused(cli, two_entries, make_vault, tmp_path):
    from irondome.vault import Secret

    other, _recovery = make_vault(path=tmp_path / "other.irondome")
    with other:
        entry = other.add("first", Secret(password="planted"), entry_id=two_entries["first"])
        other.commit()
        foreign = other.file.records[entry.id]
    rewrite(lambda file: file.records.__setitem__(two_entries["first"], foreign))
    refused = fails(get(cli, "first"), 6)
    assert "planted" not in refused.stdout


# -- the boundary ------------------------------------------------------------------


def test_boundary_an_older_copy_of_the_whole_file_opens_as_the_older_vault(cli, two_entries):
    whole = paths.vault_file().read_bytes()
    ok(cli("edit", "first", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\nthe-newer-value\n"))
    assert ok(get(cli, "first")).stdout == "the-newer-value"
    paths.write_atomic(paths.vault_file(), whole)
    assert ok(get(cli, "first")).stdout == "the-first-value"
