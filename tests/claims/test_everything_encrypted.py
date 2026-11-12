"""Claim ``everything-encrypted``: names, usernames, URLs and tags are encrypted, not just passwords.

Statement: no entry name, username, URL, tag, alias, note or password appears
in the vault file, its snapshots or the audit log. Record sizes are padded so
they do not reveal password lengths.
"""

from __future__ import annotations

import json
import secrets

from conftest import PASSWORD
from irondome import crypto, paths
from irondome.vault import Secret, VaultFile
from support.claimkit import TOTP_SEED, add, contents, found_in, grant, init, irondome_dirs, ok, session


def distinctive() -> dict:
    marker = secrets.token_hex(6)
    return {
        "name": f"bank-{marker}",
        "username": f"user-{marker}@example.com",
        "url": f"https://site-{marker}.example",
        "tag": f"tag-{marker}",
        "alias": f"ALIAS_{marker}",
        "note": f"the note {marker}",
        "password": f"pw-{marker}-{secrets.token_urlsafe(10)}",
        "field": f"field-{marker}",
        "renamed": f"renamed-{marker}",
    }


def test_nothing_an_entry_holds_is_readable_in_any_file_the_vault_writes(cli):
    plain = distinctive()
    init(cli)
    add(cli, plain["name"], plain["password"], "--username", plain["username"], "--url", plain["url"],
        "--tag", plain["tag"], "--note", plain["note"], "--alias", plain["alias"],
        totp=TOTP_SEED, fields={"extra": plain["field"]})
    assert ok(cli("get", plain["name"], "--field", "extra", "--password-stdin", stdin=PASSWORD + "\n")).stdout == (
        plain["field"]
    )
    ok(cli("get", plain["alias"], "--password-stdin", stdin=PASSWORD + "\n"))
    ok(cli("otp", plain["name"], "--password-stdin", stdin=PASSWORD + "\n"))
    grant(cli, plain["alias"])
    session(cli)
    ok(cli("edit", plain["name"], "--name", plain["renamed"], "--password-stdin", stdin=PASSWORD + "\n"))
    files = contents(irondome_dirs()["home"])
    assert any(path.endswith("vault.irondome") for path in files)
    assert any("/backups/" in path for path in files)
    assert any(path.endswith("audit.log") for path in files)
    assert any("/caps/" in path for path in files)
    leaks = {path: found_in(data, list(plain.values()) + [TOTP_SEED]) for path, data in files.items()}
    assert {path: found for path, found in leaks.items() if found} == {}


def test_the_audit_log_names_nothing_either(cli):
    plain = distinctive()
    init(cli)
    add(cli, plain["name"], plain["password"], "--alias", plain["alias"])
    grant(cli, plain["alias"])
    log = paths.audit_file().read_bytes()
    assert found_in(log, list(plain.values())) == []
    for line in log.splitlines():
        record = json.loads(line)
        assert set(record) == {"seq", "ts", "prev", "kid", "data"}


def test_password_lengths_do_not_show_in_record_sizes(make_vault):
    vault, _recovery = make_vault()
    with vault:
        sizes = set()
        for length in (1, 2, 8, 16, 33, 64, 100, 150):
            entry = vault.add(f"length-{length}", Secret(password="x" * length))
            sizes.add(len(crypto.b64d(vault.file.records[entry.id])))
        vault.commit()
    assert len(sizes) == 1


def test_entry_names_do_not_show_in_the_size_of_the_index(make_vault):
    vault, _recovery = make_vault()
    with vault:
        vault.add("a", Secret(password="x" * 10))
        vault.commit()
        short = len(crypto.b64d(vault.file.index))
    vault2, _recovery = make_vault(path=paths.home() / "second.irondome")
    with vault2:
        vault2.add("a much longer name for the same kind of entry", Secret(password="x" * 10))
        vault2.commit()
        long = len(crypto.b64d(vault2.file.index))
    assert short == long


# -- the boundary ------------------------------------------------------------------


def test_boundary_the_number_of_entries_and_the_last_change_are_visible(cli):
    init(cli)
    before = VaultFile.load()
    for index in range(3):
        add(cli, f"entry-{index}", f"value-{index}-{secrets.token_hex(4)}")
    after = VaultFile.load()
    assert len(after.records) == 3 and len(before.records) == 0
    assert after.generation > before.generation
    assert paths.vault_file().stat().st_mtime > 0
