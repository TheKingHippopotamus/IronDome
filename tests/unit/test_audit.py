"""The audit log: what it records, what it hides, what verify() catches and what it cannot."""

from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, List, Optional

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from hypothesis import given, settings
from hypothesis import strategies as st

from irondome import audit, paths
from irondome.crypto import pad, seal
from irondome.errors import IronDomeError, UsageError, VaultError

GRANT_ID = "0123456789abcdef0123456789abcdef"
OTHER_GRANT_ID = "fedcba9876543210fedcba9876543210"

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes and special files")
not_root = pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file modes")


@pytest.fixture(autouse=True)
def still_isolated(isolated):
    """Fail any test that ends up pointing at paths outside its temporary directory."""
    yield
    assert str(paths.home()).startswith(str(isolated))
    assert str(paths.audit_file()).startswith(str(isolated))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write(vault, action: str = "vault.add", **fields) -> None:
    with audit.owner_key(vault) as key:
        audit.record(key, vault_id=vault.vault_id, kid=audit.KID_VAULT, action=action, **fields)


def fill(vault, count: int) -> bytes:
    """Write *count* owner records and return the log as bytes."""
    with audit.owner_key(vault) as key:
        for index in range(count):
            audit.record(
                key,
                vault_id=vault.vault_id,
                kid=audit.KID_VAULT,
                action="vault.add",
                actor="owner",
                target=f"entry-{index}",
                detail=f"detail {index}",
            )
    return paths.audit_file().read_bytes()


def log_lines() -> List[bytes]:
    data = paths.audit_file().read_bytes()
    assert data.endswith(b"\n")
    return data[:-1].split(b"\n")


def put_lines(lines: List[bytes]) -> None:
    paths.audit_file().write_bytes(b"".join(line + b"\n" for line in lines))


def sha(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def forge(vault_id: bytes, seq: int, prev: str, kid: str, key, *, ts: int = 1_800_000_000, action: str = "x") -> bytes:
    """A line built exactly as record() builds one, under whatever key the test holds."""
    body = json.dumps(
        {"action": action, "actor": "owner", "target": "", "detail": "", "ok": True},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    with audit._sealing_key(key) as sealing:
        blob = seal(sealing, pad(body, audit._PAD_BLOCK), audit._aad(vault_id, seq, ts, kid, prev))
    return audit._encode_line(seq, ts, prev, kid, blob)


def edit(line: bytes, **changes) -> bytes:
    """Change clear fields of a line and write it back in canonical form."""
    document = json.loads(line)
    document.update(changes)
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")


@contextmanager
def time_limit(seconds: float) -> Iterator[None]:
    """Fail instead of hanging if the body blocks (on a pipe, say)."""

    def expired(signum, frame):
        raise AssertionError(f"still blocked after {seconds} seconds")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


# ---------------------------------------------------------------------------
# Writing and reading back
# ---------------------------------------------------------------------------


def test_records_come_back_in_order_with_their_fields(vault, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1_800_000_123.9)
    write(vault, "vault.add", actor="owner", target="github", detail="first")
    write(vault, "vault.edit", actor="owner", target="aws/prod", detail="second", ok=False)
    write(vault, "vault.remove")

    events = audit.read(vault)

    assert [event.seq for event in events] == [1, 2, 3]
    assert [event.action for event in events] == ["vault.add", "vault.edit", "vault.remove"]
    assert events[0] == audit.AuditEvent(
        seq=1, ts=1_800_000_123, kid="vault", action="vault.add", actor="owner", target="github", detail="first",
        ok=True,
    )
    assert (events[1].target, events[1].detail, events[1].ok) == ("aws/prod", "second", False)
    assert (events[2].actor, events[2].target, events[2].detail, events[2].ok) == ("", "", "", True)


def test_each_line_is_the_documented_json_and_names_the_hash_of_the_line_before(vault):
    fill(vault, 4)

    lines = log_lines()

    assert len(lines) == 4
    previous = ""
    for number, line in enumerate(lines, start=1):
        document = json.loads(line)
        assert set(document) == {"seq", "ts", "prev", "kid", "data"}
        assert document["seq"] == number
        assert document["kid"] == "vault"
        assert document["prev"] == previous
        assert isinstance(document["ts"], int)
        base64.b64decode(document["data"], validate=True)
        previous = sha(line)


def test_a_line_opens_with_the_documented_keys_and_associated_data(vault):
    """Decrypt with nothing but `cryptography`, following the module docstring."""
    write(vault, "vault.init")
    write(vault, "vault.add", actor="owner", target="github", detail="known answer")
    first, second = log_lines()
    document = json.loads(second)
    vault_key = bytes(vault.vault_key.view())
    assert document["seq"] == 2 and document["prev"] == sha(first)

    owner = HKDF(hashes.SHA256(), 32, vault.vault_id, b"irondome/v4/audit").derive(vault_key)
    sealing = HKDF(hashes.SHA256(), 32, None, b"irondome/v4/audit/record").derive(owner)
    aad = (
        b"irondome/v4/audit\x00"
        + vault.vault_id
        + document["seq"].to_bytes(8, "big")
        + document["ts"].to_bytes(8, "big")
        + bytes([len(document["kid"])])
        + document["kid"].encode("ascii")
        + bytes.fromhex(document["prev"])
    )
    blob = base64.b64decode(document["data"])
    padded = AESGCM(sealing).decrypt(blob[:12], blob[12:], aad)

    length = int.from_bytes(padded[:4], "big")
    assert len(padded) % 256 == 0
    assert json.loads(padded[4 : 4 + length]) == {
        "action": "vault.add", "actor": "owner", "target": "github", "detail": "known answer", "ok": True,
    }


def test_a_grant_line_opens_with_the_documented_grant_key(vault):
    with audit.owner_key(vault) as owner, audit.grant_key(owner, GRANT_ID) as key:
        audit.record(key, vault_id=vault.vault_id, kid=GRANT_ID, action="grant.use", actor="grant")
        derived = bytes(key.view())
        owner_bytes = bytes(owner.view())
    document = json.loads(log_lines()[0])

    expected = HKDF(hashes.SHA256(), 32, None, b"irondome/v4/audit/grant\x00" + GRANT_ID.encode()).derive(owner_bytes)
    sealing = HKDF(hashes.SHA256(), 32, None, b"irondome/v4/audit/record").derive(expected)
    aad = (
        b"irondome/v4/audit\x00"
        + vault.vault_id
        + (1).to_bytes(8, "big")
        + document["ts"].to_bytes(8, "big")
        + bytes([32])
        + GRANT_ID.encode("ascii")
    )
    blob = base64.b64decode(document["data"])

    assert derived == expected
    assert document["kid"] == GRANT_ID
    assert b'"action":"grant.use"' in AESGCM(sealing).decrypt(blob[:12], blob[12:], aad)


@posix_only
@pytest.mark.parametrize("umask", [0o000, 0o022, 0o077])
def test_the_log_is_owner_only_whatever_the_umask(vault, umask):
    previous = os.umask(umask)
    try:
        write(vault)
    finally:
        os.umask(previous)

    assert stat.S_IMODE(paths.audit_file().stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.home().stat().st_mode) == 0o700
    lock = paths.audit_file().with_name("audit.log.lock")
    assert stat.S_IMODE(lock.stat().st_mode) & 0o077 == 0


@posix_only
def test_a_log_left_readable_by_others_is_tightened_on_the_next_write(vault):
    write(vault)
    os.chmod(paths.audit_file(), 0o644)

    write(vault)

    assert stat.S_IMODE(paths.audit_file().stat().st_mode) == 0o600


def test_nothing_that_was_recorded_can_be_read_in_the_file(vault):
    secrets = ["github", "hunter2-Github!", "GITHUB_TOKEN", "gh repo list --limit 5", "owner", "vault.add"]
    write(vault, "vault.add", actor="owner", target="github", detail="gh repo list --limit 5")
    write(vault, "use", actor="owner", target="GITHUB_TOKEN", detail="hunter2-Github!")
    raw = paths.audit_file().read_bytes()

    for text in secrets:
        encoded = text.encode("utf-8")
        for form in (encoded, base64.b64encode(encoded).rstrip(b"="), encoded.hex().encode("ascii")):
            assert form not in raw
    vault_key = bytes(vault.vault_key.view())
    assert vault_key not in raw and base64.b64encode(vault_key) not in raw and vault_key.hex().encode() not in raw


def test_line_length_does_not_follow_the_length_of_what_was_recorded(vault):
    write(vault, "use", target="a")
    write(vault, "use", target="a" * 100, detail="b" * 50)
    write(vault, "use", target="a" * 300)

    short, medium, long = (len(json.loads(line)["data"]) for line in log_lines())

    assert short == medium
    assert long > short


def test_an_absent_or_empty_log_verifies_as_ok_with_no_records(vault):
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=0, problems=[])
    assert audit.read(vault) == []

    paths.audit_file().write_bytes(b"")

    assert audit.verify(vault) == audit.AuditReport(ok=True, count=0, problems=[])
    assert audit.read(vault) == []


def test_an_untouched_log_verifies_and_count_is_what_read_returns(vault):
    fill(vault, 12)

    report = audit.verify(vault)

    assert report == audit.AuditReport(ok=True, count=12, problems=[])
    assert len(audit.read(vault)) == 12


def test_read_can_keep_only_the_newest_records(vault):
    fill(vault, 7)

    newest = audit.read(vault, limit=3)

    assert [event.seq for event in newest] == [5, 6, 7]
    assert [event.target for event in newest] == ["entry-4", "entry-5", "entry-6"]
    assert len(audit.read(vault, limit=100)) == 7


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "3"])
def test_read_refuses_a_limit_that_is_not_a_positive_whole_number(vault, limit):
    with pytest.raises(UsageError):
        audit.read(vault, limit=limit)


def test_the_time_recorded_is_the_clock_at_the_moment_of_writing(vault, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1_900_000_000.75)
    write(vault)
    monkeypatch.setattr(time, "time", lambda: 1_900_000_060.0)
    write(vault)

    assert [event.ts for event in audit.read(vault)] == [1_900_000_000, 1_900_000_060]


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def test_the_owner_key_belongs_to_one_vault_and_is_not_the_vault_key(vault, make_vault, tmp_path):
    other, _ = make_vault(path=tmp_path / "other" / "vault.irondome")

    with audit.owner_key(vault) as first, audit.owner_key(vault) as again, audit.owner_key(other) as foreign:
        assert len(first) == 32
        assert bytes(first.view()) == bytes(again.view())
        assert bytes(first.view()) != bytes(foreign.view())
        assert bytes(first.view()) != bytes(vault.vault_key.view())


def test_a_locked_vault_gives_no_owner_key(vault):
    vault.close()

    with pytest.raises(VaultError):
        audit.owner_key(vault)


def test_every_grant_has_its_own_key(vault):
    with audit.owner_key(vault) as owner:
        with audit.grant_key(owner, GRANT_ID) as one, audit.grant_key(owner, GRANT_ID) as same:
            with audit.grant_key(owner, OTHER_GRANT_ID) as other:
                assert bytes(one.view()) == bytes(same.view())
                assert bytes(one.view()) != bytes(other.view())
                assert bytes(one.view()) != bytes(owner.view())


@pytest.mark.parametrize("grant_id", ["", "vault", GRANT_ID[:-1], GRANT_ID.upper(), GRANT_ID + "0", "g" * 32, None, 7])
def test_a_grant_key_needs_a_well_formed_grant_id(vault, grant_id):
    with audit.owner_key(vault) as owner:
        with pytest.raises(UsageError):
            audit.grant_key(owner, grant_id)


def test_records_written_with_a_grant_key_verify_and_carry_the_grant_id(vault):
    write(vault, "grant.create", target=GRANT_ID)
    with audit.owner_key(vault) as owner, audit.grant_key(owner, GRANT_ID) as key:
        holder_key = bytes(key.view())
    # The holder has only its own key, as bytes out of the grant payload.
    audit.record(holder_key, vault_id=vault.vault_id, kid=GRANT_ID, action="grant.use", actor="grant", target="A")
    audit.record(holder_key, vault_id=vault.vault_id, kid=GRANT_ID, action="use", actor="grant", target="B")
    write(vault, "grant.revoke", target=GRANT_ID)

    report = audit.verify(vault)
    events = audit.read(vault)

    assert report == audit.AuditReport(ok=True, count=4, problems=[])
    assert [event.kid for event in events] == ["vault", GRANT_ID, GRANT_ID, "vault"]
    assert [event.action for event in events] == ["grant.create", "grant.use", "use", "grant.revoke"]


def test_a_grant_holder_cannot_write_a_line_that_passes_as_the_owners(vault):
    fill(vault, 2)
    lines = log_lines()
    with audit.owner_key(vault) as owner, audit.grant_key(owner, GRANT_ID) as key:
        forged = forge(vault.vault_id, 3, sha(lines[-1]), "vault", key, action="vault.export")
    put_lines(lines + [forged])

    report = audit.verify(vault)

    assert not report.ok
    assert report.count == 2
    assert any("line 3 failed authentication" in problem for problem in report.problems)
    assert [event.action for event in audit.read(vault)] == ["vault.add", "vault.add"]


def test_a_grant_holder_cannot_write_a_line_that_passes_as_another_grants(vault):
    fill(vault, 1)
    lines = log_lines()
    with audit.owner_key(vault) as owner, audit.grant_key(owner, GRANT_ID) as key:
        forged = forge(vault.vault_id, 2, sha(lines[-1]), OTHER_GRANT_ID, key)
    put_lines(lines + [forged])

    report = audit.verify(vault)

    assert not report.ok and report.count == 1
    assert any("line 2 failed authentication" in problem for problem in report.problems)


def test_a_grant_holder_who_rewrites_an_earlier_line_is_caught_by_the_line_after_it(vault):
    fill(vault, 4)
    lines = log_lines()
    with audit.owner_key(vault) as owner, audit.grant_key(owner, GRANT_ID) as key:
        # Same position, same link backwards, sealed with a key the holder really has.
        lines[1] = forge(vault.vault_id, 2, sha(lines[0]), GRANT_ID, key)
    put_lines(lines)

    report = audit.verify(vault)

    assert not report.ok
    assert any(problem.startswith("line 3 does not follow") for problem in report.problems)


def test_a_log_written_under_more_grant_keys_than_are_kept_at_once_verifies(vault):
    ids = ["%032x" % index for index in range(40)]
    with audit.owner_key(vault) as owner:
        for grant_id in ids + ids[:5] + ["vault"] + ids[-5:]:
            if grant_id == "vault":
                audit.record(owner, vault_id=vault.vault_id, kid="vault", action="vault.add")
                continue
            with audit.grant_key(owner, grant_id) as key:
                audit.record(key, vault_id=vault.vault_id, kid=grant_id, action="grant.use")

    assert audit.verify(vault) == audit.AuditReport(ok=True, count=51, problems=[])
    assert [event.kid for event in audit.read(vault)] == ids + ids[:5] + ["vault"] + ids[-5:]


def test_relinking_the_line_after_a_rewritten_one_is_caught_as_well(vault):
    """Why the link is sealed into each line: fixing it up in the clear does not hide a rewrite."""
    fill(vault, 4)
    lines = log_lines()
    with audit.owner_key(vault) as owner, audit.grant_key(owner, GRANT_ID) as key:
        lines[1] = forge(vault.vault_id, 2, sha(lines[0]), GRANT_ID, key)
    lines[2] = edit(lines[2], prev=sha(lines[1]))
    put_lines(lines)

    report = audit.verify(vault)

    assert not report.ok and report.count == 3
    assert report.problems == [
        "line 3 failed authentication: it was edited, or was not written with a key of this vault",
        "line 4 does not follow what is before it: a line was edited, removed, inserted or moved",
    ]


def test_renumbering_the_lines_after_a_removed_one_is_caught_as_well(vault):
    """The same for the sequence number: closing the gap in the clear does not hide a removal."""
    fill(vault, 4)
    lines = log_lines()
    relinked = edit(lines[2], seq=2, prev=sha(lines[0]))
    put_lines([lines[0], relinked, edit(lines[3], seq=3, prev=sha(relinked))])

    report = audit.verify(vault)

    assert not report.ok and report.count == 1
    assert [problem.split(":")[0] for problem in report.problems] == [
        "line 2 failed authentication", "line 3 failed authentication",
    ]


def test_the_log_of_another_vault_fails_authentication(vault, make_vault, tmp_path):
    other, _ = make_vault(path=tmp_path / "other" / "vault.irondome")
    fill(vault, 3)

    report = audit.verify(other)

    assert not report.ok
    assert report.count == 0
    assert len(report.problems) == 3
    assert audit.read(other) == []


# ---------------------------------------------------------------------------
# Tampering that verify() catches
# ---------------------------------------------------------------------------


def _flip_data(lines: List[bytes]) -> List[bytes]:
    data = json.loads(lines[2])["data"]
    swapped = ("B" if data[40] != "B" else "C").join((data[:40], data[41:]))
    return lines[:2] + [edit(lines[2], data=swapped)] + lines[3:]


def _noncanonical_base64(lines: List[bytes]) -> List[bytes]:
    """Same decoded bytes, different text: the unused bits of the last character are set."""
    data = json.loads(lines[-1])["data"]
    blob = base64.b64decode(data)
    assert data.endswith("=")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = len(data.rstrip("=")) - 1
    twin = data[:last] + alphabet[alphabet.index(data[last]) + 1] + data[last + 1 :]
    assert twin != data and base64.b64decode(twin) == blob
    return lines[:-1] + [edit(lines[-1], data=twin)]


TAMPERINGS = {
    "a character of the sealed record changed": _flip_data,
    "the time of the last line changed": lambda lines: lines[:-1]
    + [edit(lines[-1], ts=json.loads(lines[-1])["ts"] + 1)],
    "the time of a middle line changed": lambda lines: lines[:2] + [edit(lines[2], ts=5)] + lines[3:],
    "a sequence number changed": lambda lines: lines[:-1] + [edit(lines[-1], seq=99)],
    "the key id of the last line changed": lambda lines: lines[:-1] + [edit(lines[-1], kid=GRANT_ID)],
    "the link of the last line changed": lambda lines: lines[:-1] + [edit(lines[-1], prev=sha(b"other"))],
    "two neighbouring lines swapped": lambda lines: lines[:2] + [lines[3], lines[2]] + lines[4:],
    "two distant lines swapped": lambda lines: [lines[4]] + lines[1:4] + [lines[0]] + lines[5:],
    "a line removed from the middle": lambda lines: lines[:2] + lines[3:],
    "the first line removed": lambda lines: lines[1:],
    "the first two lines removed": lambda lines: lines[2:],
    "an earlier line repeated at the end": lambda lines: lines + [lines[1]],
    "the last line repeated": lambda lines: lines + [lines[-1]],
    "a line repeated in place": lambda lines: lines[:3] + [lines[2]] + lines[3:],
    "an empty line added at the end": lambda lines: lines + [b""],
    "an empty line added in the middle": lambda lines: lines[:3] + [b""] + lines[3:],
    "text that is not a record added": lambda lines: lines + [b"not a record"],
    "a JSON line that is not a record added": lambda lines: lines + [b'{"seq":7,"note":"hello"}'],
    "spaces added inside the last line": lambda lines: lines[:-1] + [lines[-1].replace(b'","', b'", "', 1)],
    "the keys of the last line reordered": lambda lines: lines[:-1]
    + [json.dumps(dict(reversed(list(json.loads(lines[-1]).items()))), separators=(",", ":")).encode()],
    "the last line re-encoded with other base64 text": _noncanonical_base64,
    "a field added to the last line": lambda lines: lines[:-1] + [edit(lines[-1], note="x")],
    "a field removed from the last line": lambda lines: lines[:-1]
    + [json.dumps({k: v for k, v in json.loads(lines[-1]).items() if k != "ts"}, sort_keys=True).encode()],
    "a line far longer than any record added": lambda lines: lines + [b"x" * 70_000],
    "a huge number in place of the time": lambda lines: lines[:-1]
    + [lines[-1].replace(b'"ts":', b'"ts":' + b"9" * 200_000, 1)],
}


@pytest.mark.parametrize("name", sorted(TAMPERINGS))
def test_verify_catches(vault, name):
    put_lines(TAMPERINGS[name](fill(vault, 6)[:-1].split(b"\n")))

    with time_limit(20):
        report = audit.verify(vault)
        events = audit.read(vault)

    assert not report.ok, name
    assert report.problems, name
    assert report.count == len(events)
    assert all(event.action == "vault.add" for event in events)


def test_a_line_forged_without_any_key_of_the_vault_is_caught(vault):
    lines = fill(vault, 3)[:-1].split(b"\n")
    forged = forge(vault.vault_id, 4, sha(lines[-1]), "vault", os.urandom(32), action="vault.export")
    put_lines(lines + [forged])

    report = audit.verify(vault)

    assert not report.ok and report.count == 3
    assert report.problems == [
        "line 4 failed authentication: it was edited, or was not written with a key of this vault"
    ]
    assert "vault.export" not in [event.action for event in audit.read(vault)]


def test_a_line_sealed_for_another_position_is_caught_when_moved_there(vault):
    """The right key is not enough: seq and prev are part of what is sealed."""
    lines = fill(vault, 3)[:-1].split(b"\n")
    with audit.owner_key(vault) as owner:
        elsewhere = forge(vault.vault_id, 9, sha(b"some other line"), "vault", owner)
    put_lines(lines + [edit(elsewhere, seq=4, prev=sha(lines[-1]))])

    report = audit.verify(vault)

    assert not report.ok and report.count == 3
    assert any("line 4 failed authentication" in problem for problem in report.problems)


def test_the_report_says_where_the_damage_is(vault):
    lines = fill(vault, 6)[:-1].split(b"\n")
    put_lines(lines[:2] + lines[3:])

    report = audit.verify(vault)

    assert report.count == 5
    assert report.problems == [
        "line 3 is record 4 where record 3 belongs: records were removed, repeated or reordered",
        "line 3 does not follow what is before it: a line was edited, removed, inserted or moved",
    ]


def test_a_log_whose_beginning_was_removed_says_so(vault):
    lines = fill(vault, 4)[:-1].split(b"\n")
    put_lines(lines[2:])

    report = audit.verify(vault)

    assert report.problems == [
        "line 1 is record 3 where record 1 belongs: the beginning of the log was removed",
        "line 1 does not follow what is before it: the beginning of the log was removed",
    ]


def test_an_incomplete_last_line_is_reported(vault):
    data = fill(vault, 3)
    paths.audit_file().write_bytes(data[:-40])

    report = audit.verify(vault)

    assert not report.ok and report.count == 2
    assert report.problems == [
        "line 3 is incomplete: a write was interrupted, or the end of the log was cut off"
    ]


def test_an_oversize_fragment_at_the_end_is_reported_as_incomplete_and_then_removed(vault):
    whole = fill(vault, 1)
    paths.audit_file().write_bytes(whole + b"y" * 100_000)

    report = audit.verify(vault)

    assert report.count == 1
    assert report.problems == [
        "line 2 is incomplete: a write was interrupted, or the end of the log was cut off"
    ]
    write(vault)
    assert paths.audit_file().read_bytes().startswith(whole + b"{")
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=2, problems=[])


def test_a_long_run_of_damage_gives_a_bounded_report(vault):
    put_lines(fill(vault, 2)[:-1].split(b"\n") + [b"junk %d" % index for index in range(500)])

    report = audit.verify(vault)

    assert not report.ok and report.count == 2
    assert len(report.problems) == 51
    assert report.problems[-1] == "and 450 more problems, not listed"


def test_a_log_too_large_to_read_is_reported_not_loaded(vault, monkeypatch):
    fill(vault, 3)
    monkeypatch.setattr(paths, "MAX_FILE_BYTES", 100)

    report = audit.verify(vault)

    assert not report.ok and report.count == 0
    assert report.problems == ["the log is larger than 100 bytes and was not read"]
    assert audit.read(vault) == []


def test_any_single_changed_byte_is_caught(vault):
    original = fill(vault, 5)
    path = paths.audit_file()

    @settings(max_examples=400, deadline=None)
    @given(data=st.data())
    def check(data):
        index = data.draw(st.integers(0, len(original) - 1))
        value = data.draw(st.integers(0, 255).filter(lambda byte: byte != original[index]))
        path.write_bytes(original[:index] + bytes([value]) + original[index + 1 :])

        report = audit.verify(vault)

        assert not report.ok
        assert report.count == len(audit.read(vault)) < 5 or report.count == 5

    check()


def test_any_inserted_or_removed_byte_is_caught(vault):
    original = fill(vault, 4)
    path = paths.audit_file()

    @settings(max_examples=300, deadline=None)
    @given(index=st.integers(0, len(original) - 1), extra=st.one_of(st.none(), st.integers(0, 255)))
    def check(index, extra):
        middle = b"" if extra is None else bytes([extra]) + original[index : index + 1]
        path.write_bytes(original[:index] + middle + original[index + 1 :])

        assert not audit.verify(vault).ok

    check()


def test_any_reordering_of_lines_is_caught(vault):
    lines = fill(vault, 6)[:-1].split(b"\n")

    @settings(max_examples=150, deadline=None)
    @given(order=st.permutations(range(6)).filter(lambda order: list(order) != list(range(6))))
    def check(order):
        put_lines([lines[index] for index in order])

        assert not audit.verify(vault).ok

    check()


def test_any_removal_that_is_not_just_the_newest_lines_is_caught(vault):
    lines = fill(vault, 7)[:-1].split(b"\n")

    def keeps_a_gap(mask: List[bool]) -> bool:
        kept = [index for index, keep in enumerate(mask) if keep]
        return kept != list(range(len(kept)))

    @settings(max_examples=150, deadline=None)
    @given(mask=st.lists(st.booleans(), min_size=7, max_size=7).filter(keeps_a_gap))
    def check(mask):
        put_lines([line for line, keep in zip(lines, mask) if keep])

        assert not audit.verify(vault).ok

    check()


# ---------------------------------------------------------------------------
# What verify() cannot catch (stated in its docstring; pinned here)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kept", [0, 1, 4])
def test_removal_of_the_newest_lines_is_not_detected(vault, kept):
    lines = fill(vault, 6)[:-1].split(b"\n")
    put_lines(lines[:kept])

    assert audit.verify(vault) == audit.AuditReport(ok=True, count=kept, problems=[])


def test_removal_of_the_whole_log_is_not_detected(vault):
    fill(vault, 3)
    paths.audit_file().unlink()

    assert audit.verify(vault) == audit.AuditReport(ok=True, count=0, problems=[])


def test_a_grant_holder_can_replace_the_newest_lines_with_its_own(vault):
    """Cutting the tail and appending is open to anyone who can write the file and holds a grant key."""
    lines = fill(vault, 4)[:-1].split(b"\n")
    with audit.owner_key(vault) as owner, audit.grant_key(owner, GRANT_ID) as key:
        replacement = forge(vault.vault_id, 4, sha(lines[2]), GRANT_ID, key)
    put_lines(lines[:3] + [replacement])

    report = audit.verify(vault)

    assert report.ok and report.count == 4
    assert audit.read(vault)[-1].kid == GRANT_ID  # but it cannot hide that a grant key wrote it


# ---------------------------------------------------------------------------
# Hostile and awkward content
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "arguments",
    [
        {"vault_id": b"short"},
        {"vault_id": "0123456789abcdef"},
        {"vault_id": None},
        {"kid": "owner"},
        {"kid": GRANT_ID.upper()},
        {"kid": ""},
        {"kid": None},
        {"action": ""},
        {"action": "x" * 65},
        {"action": None},
        {"action": b"use"},
        {"actor": None},
        {"target": 5},
        {"detail": b"bytes"},
        {"ok": 1},
        {"ok": None},
    ],
)
def test_record_refuses_arguments_that_cannot_form_a_record(vault, arguments):
    call = {"vault_id": vault.vault_id, "kid": "vault", "action": "use"}
    call.update(arguments)

    with audit.owner_key(vault) as key:
        with pytest.raises(UsageError):
            audit.record(key, **call)

    assert not paths.audit_file().exists()


@pytest.mark.parametrize("key", [b"", b"x" * 31, b"x" * 33, None, "a string of thirty-two characters"])
def test_record_refuses_a_key_of_the_wrong_shape(vault, key):
    with pytest.raises(UsageError):
        audit.record(key, vault_id=vault.vault_id, kid="vault", action="use")


def test_record_refuses_a_wiped_key(vault):
    key = audit.owner_key(vault)
    key.wipe()

    with pytest.raises(UsageError):
        audit.record(key, vault_id=vault.vault_id, kid="vault", action="use")


def test_over_long_fields_are_cut_and_marked_not_refused(vault):
    write(vault, "use", actor="a" * 500, target="t" * 5000, detail="d" * 50_000)

    event = audit.read(vault)[0]

    assert (len(event.actor), len(event.target), len(event.detail)) == (128, 1024, 4096)
    assert event.actor.endswith("a\u2026") and event.target.endswith("t\u2026") and event.detail.endswith("d\u2026")
    assert audit.verify(vault).ok


def test_the_longest_record_still_fits_in_one_line(vault):
    worst = "\x01"  # six bytes once escaped in JSON
    write(vault, worst * 64, actor=worst * 128, target=worst * 1024, detail=worst * 4096)
    write(vault, "\U0001f512" * 64, actor="\U0001f512" * 128, target="\U0001f512" * 1024, detail="\U0001f512" * 4096)

    assert all(len(line) <= audit._MAX_LINE for line in log_lines())
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=2, problems=[])


def test_what_read_returns_cannot_drive_a_terminal(vault):
    hostile = "ok\x1b[2J\x1b[1;1H\r\x07 \u202e\u2066 \x9b31m \x00 end"
    write(vault, "use", actor=hostile, target=hostile, detail=hostile)
    with audit.owner_key(vault) as owner, audit.grant_key(owner, GRANT_ID) as key:
        audit.record(key, vault_id=vault.vault_id, kid=GRANT_ID, action=hostile, detail=hostile)

    events = audit.read(vault)

    for event in events:
        for text in (event.action, event.actor, event.target, event.detail):
            assert text.isprintable()
            assert "\x1b" not in text and "\r" not in text and "\u202e" not in text and "\x9b" not in text
    assert events[0].detail == "ok\\x1b[2J\\x1b[1;1H\\r\\x07 \\u202e\\u2066 \\x9b31m \\x00 end"
    assert audit.verify(vault).ok


def test_text_that_cannot_be_encoded_is_recorded_escaped(vault):
    write(vault, "use", target="caf\udce9", detail="\ud800 alone")

    event = audit.read(vault)[0]

    assert event.target == "caf\\udce9"
    assert event.detail == "\\ud800 alone"
    assert audit.verify(vault).ok


def test_other_scripts_are_recorded_as_they_are(vault):
    hebrew = "\u05e1\u05d9\u05e1\u05de\u05d4 \u05e2\u05d1\u05e8\u05d9\u05ea"
    mixed = "\u00fcber \u65e5\u672c\u8a9e \U0001f512"
    write(vault, "use", target=hebrew, detail=mixed)

    event = audit.read(vault)[0]

    assert (event.target, event.detail) == (hebrew, mixed)


def test_any_text_can_be_recorded_and_comes_back_printable(vault):
    with audit.owner_key(vault) as owner:
        key = bytes(owner.view())
    path = paths.audit_file()
    printable = st.text(st.characters(blacklist_categories=("C", "Z")), max_size=40)

    @settings(max_examples=60, deadline=None)
    @given(
        action=st.text(min_size=1, max_size=64),
        actor=st.text(max_size=200),
        target=st.text(max_size=200),
        detail=st.text(max_size=300),
        plain=printable,
        ok=st.booleans(),
    )
    def check(action, actor, target, detail, plain, ok):
        if path.exists():
            path.unlink()
        common = {"vault_id": vault.vault_id, "kid": "vault"}
        audit.record(key, action=action, actor=actor, target=target, detail=detail, ok=ok, **common)
        audit.record(key, action="plain", target=plain, detail=plain, **common)

        first, second = audit.read(vault)

        assert all(text.isprintable() for text in (first.action, first.actor, first.target, first.detail))
        assert first.ok is ok
        assert (second.target, second.detail) == (plain, plain)
        assert audit.verify(vault) == audit.AuditReport(ok=True, count=2, problems=[])

    check()


def test_an_authentic_line_that_is_not_a_record_is_reported_and_left_out(vault):
    """A grant holder can seal anything with its own key; read() must not choke on it."""
    fill(vault, 1)
    lines = log_lines()
    bodies = [
        b"not json",
        b"[1,2,3]",
        b'{"action":"use"}',
        b'{"action":"","actor":"","target":"","detail":"","ok":true}',
        b'{"action":"use","actor":"","target":"","detail":"","ok":"yes"}',
        b'{"action":"use","actor":7,"target":"","detail":"","ok":true}',
        b'{"action":"use","actor":"","target":"' + b"t" * 2000 + b'","detail":"","ok":true}',
        b'{"action":"use","action":"use","actor":"","target":"","detail":"","ok":true}',
        b'{"action":"use","actor":"","target":"","detail":"","ok":true,"n":' + b"9" * 100 + b"}",
    ]
    with audit.owner_key(vault) as owner, audit.grant_key(owner, GRANT_ID) as key, audit._sealing_key(key) as sealing:
        for body in bodies:
            seq, prev = len(lines) + 1, sha(lines[-1])
            aad = audit._aad(vault.vault_id, seq, 1_800_000_000, GRANT_ID, prev)
            blob = seal(sealing, pad(body, audit._PAD_BLOCK), aad)
            lines.append(audit._encode_line(seq, 1_800_000_000, prev, GRANT_ID, blob))
        seq, prev = len(lines) + 1, sha(lines[-1])
        blob = seal(sealing, b"\xff\xff\xff\xff" + b"x" * 252, audit._aad(vault.vault_id, seq, 5, GRANT_ID, prev))
        lines.append(audit._encode_line(seq, 5, prev, GRANT_ID, blob))
    put_lines(lines)

    report = audit.verify(vault)

    assert not report.ok and report.count == 1
    assert len(report.problems) == len(bodies) + 1
    assert all("is authentic but is not a record IronDome writes" in problem for problem in report.problems)
    assert [event.seq for event in audit.read(vault)] == [1]


def test_an_authentic_line_with_extra_fields_is_still_a_record(vault):
    body = b'{"action":"use","actor":"","target":"x","detail":"","ok":true,"since":"4.1"}'
    with audit.owner_key(vault) as owner, audit._sealing_key(owner) as sealing:
        blob = seal(sealing, pad(body, audit._PAD_BLOCK), audit._aad(vault.vault_id, 1, 7, "vault", ""))
    put_lines([audit._encode_line(1, 7, "", "vault", blob)])

    assert audit.verify(vault) == audit.AuditReport(ok=True, count=1, problems=[])
    assert audit.read(vault)[0].target == "x"


# ---------------------------------------------------------------------------
# strict_loads and line parsing
# ---------------------------------------------------------------------------


def test_strict_loads_reads_ordinary_json():
    document = b'{"a":[1,2.5,"x",null,true],"b":{"c":-3}}'
    assert audit.strict_loads(document) == {"a": [1, 2.5, "x", None, True], "b": {"c": -3}}
    assert audit.strict_loads('{"a":1}') == {"a": 1}
    assert audit.strict_loads(bytearray(b"[]")) == []


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b"{",
        b"\xff\xfe",
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":-Infinity}',
        b'{"a":1,"a":2}',
        b'{"a":{"b":1,"b":1}}',
        b'{"a":123456789012345678901}',
        b'{"a":-12345678901234567890}',
        b"[" * 100_000,
        b'{"a":' * 50_000,
    ],
)
def test_strict_loads_refuses(document):
    with pytest.raises(ValueError):
        audit.strict_loads(document)


def test_strict_loads_refuses_a_huge_number_without_converting_it():
    document = b'{"n":' + b"7" * 5_000_000 + b"}"

    started = time.perf_counter()
    with pytest.raises(ValueError):
        audit.strict_loads(document)

    assert time.perf_counter() - started < 5


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=200))
def test_strict_loads_only_ever_raises_value_error(document):
    try:
        audit.strict_loads(document)
    except ValueError:
        pass


@settings(max_examples=300, deadline=None)
@given(st.one_of(st.binary(max_size=300), st.text(max_size=100).map(lambda text: text.encode("utf-8", "replace"))))
def test_a_line_is_either_refused_or_exactly_what_irondome_writes(raw):
    try:
        line = audit._parse_line(raw)
    except audit._BadLine:
        return
    assert audit._encode_line(line.seq, line.ts, line.prev, line.kid, line.blob) == raw


@settings(max_examples=200, deadline=None)
@given(
    seq=st.integers(1, 2**62),
    ts=st.integers(0, 2**40),
    prev=st.one_of(st.just(""), st.binary(min_size=32, max_size=32).map(bytes.hex)),
    kid=st.one_of(st.just("vault"), st.binary(min_size=16, max_size=16).map(bytes.hex)),
    blob=st.binary(min_size=28, max_size=400),
)
def test_every_line_irondome_writes_parses_back_to_itself(seq, ts, prev, kid, blob):
    line = audit._parse_line(audit._encode_line(seq, ts, prev, kid, blob))

    assert (line.seq, line.ts, line.prev, line.kid, line.blob) == (seq, ts, prev, kid, blob)


@pytest.mark.parametrize(
    "changes",
    [
        {"seq": 0},
        {"seq": -1},
        {"seq": 2**62 + 1},
        {"seq": 1.0},
        {"seq": True},
        {"seq": "1"},
        {"ts": -1},
        {"ts": 2**40 + 1},
        {"ts": None},
        {"prev": "abc"},
        {"prev": "A" * 64},
        {"prev": "g" * 64},
        {"prev": None},
        {"kid": "Vault"},
        {"kid": "0" * 31},
        {"kid": 5},
        {"data": ""},
        {"data": "AAAA"},
        {"data": "not base64!"},
        {"data": None},
    ],
)
def test_a_line_with_a_field_out_of_range_is_refused(changes):
    good = audit._encode_line(1, 7, "", "vault", b"\x00" * 40)

    with pytest.raises(audit._BadLine):
        audit._parse_line(edit(good, **changes))


# ---------------------------------------------------------------------------
# When the log cannot be written
# ---------------------------------------------------------------------------


def test_a_write_that_fails_part_way_raises_audit_error_and_leaves_no_partial_line(vault, monkeypatch):
    before = fill(vault, 3)
    real_write = os.write

    def full_disk(fd, data):
        real_write(fd, bytes(data[: len(data) // 2]))
        raise OSError(errno.ENOSPC, "No space left on device")

    with monkeypatch.context() as patch:
        patch.setattr(audit.os, "write", full_disk)
        with audit.owner_key(vault) as key:
            with pytest.raises(audit.AuditError) as caught:
                audit.record(key, vault_id=vault.vault_id, kid="vault", action="vault.add", target="lost")

    assert isinstance(caught.value, IronDomeError)
    assert "No space left on device" in str(caught.value)
    assert str(paths.audit_file()) in str(caught.value)
    assert "lost" not in str(caught.value)
    assert paths.audit_file().read_bytes() == before
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=3, problems=[])


def test_a_flush_that_fails_is_rolled_back_too(vault, monkeypatch):
    before = fill(vault, 2)

    def failing(fd):
        raise OSError(errno.EIO, "Input/output error")

    with monkeypatch.context() as patch:
        patch.setattr(audit, "_flush", failing)
        with pytest.raises(audit.AuditError):
            write(vault)

    assert paths.audit_file().read_bytes() == before
    write(vault)
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=3, problems=[])


def test_an_interrupted_record_is_rolled_back(vault, monkeypatch):
    before = fill(vault, 2)

    def interrupted(fd):
        raise KeyboardInterrupt

    with monkeypatch.context() as patch:
        patch.setattr(audit, "_flush", interrupted)
        with pytest.raises(KeyboardInterrupt):
            write(vault)

    assert paths.audit_file().read_bytes() == before


def test_a_fragment_that_could_not_be_rolled_back_is_removed_by_the_next_record(vault, monkeypatch):
    before = fill(vault, 2)
    real_write = os.write

    def full_disk(fd, data):
        real_write(fd, bytes(data[:10]))
        raise OSError(errno.ENOSPC, "No space left on device")

    def stuck(fd, length):
        raise OSError(errno.EIO, "Input/output error")

    with monkeypatch.context() as patch:
        patch.setattr(audit.os, "write", full_disk)
        patch.setattr(audit.os, "ftruncate", stuck)
        with pytest.raises(audit.AuditError, match="No space left on device"):
            write(vault)

    damaged = paths.audit_file().read_bytes()
    assert damaged.startswith(before) and len(damaged) == len(before) + 10
    assert not audit.verify(vault).ok
    write(vault)
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=3, problems=[])


@pytest.mark.skipif(sys.platform != "darwin", reason="F_FULLFSYNC is a macOS request")
def test_a_filesystem_that_cannot_flush_fully_gets_a_plain_fsync(vault, monkeypatch):
    import fcntl

    real_fcntl, real_fsync = fcntl.fcntl, os.fsync
    synced: List[int] = []

    def no_full_flush(fd, operation, *arguments):
        if operation == fcntl.F_FULLFSYNC:
            raise OSError(errno.ENOTSUP, "Operation not supported")
        return real_fcntl(fd, operation, *arguments)

    def counting(fd):
        synced.append(fd)
        real_fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(fcntl, "fcntl", no_full_flush)
        patch.setattr(audit.os, "fsync", counting)
        write(vault)

    assert synced
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=1, problems=[])


def test_reading_stops_at_the_end_of_a_file_that_is_shorter_than_expected(tmp_path):
    """The log is only read under its lock; if something else shortens it meanwhile, nothing loops."""
    path = tmp_path / "short.log"
    path.write_bytes(b"one\ntwo\n")
    fd = os.open(str(path), os.O_RDONLY)
    try:
        assert audit._read_at(fd, 4, 100) == b"two\n"
        assert audit._digest_range(fd, 0, 100) == (sha(b"one\ntwo\n"), b"one\ntwo\n")
        assert audit._count_lines(fd, 100) == 2
        assert audit._last_newline(fd, 8) == 7 and audit._last_newline(fd, 3) == -1
    finally:
        os.close(fd)


def test_the_first_record_failing_leaves_an_empty_log_that_still_works(vault, monkeypatch):
    def full_disk(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")

    with monkeypatch.context() as patch:
        patch.setattr(audit.os, "write", full_disk)
        with pytest.raises(audit.AuditError):
            write(vault)

    assert paths.audit_file().read_bytes() == b""
    write(vault)
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=1, problems=[])


@posix_only
@not_root
def test_a_log_that_cannot_be_opened_for_writing_raises_audit_error(vault):
    before = fill(vault, 1)
    os.chmod(paths.audit_file(), 0o400)

    with pytest.raises(audit.AuditError) as caught:
        write(vault)

    assert "Permission denied" in str(caught.value)
    assert paths.audit_file().read_bytes() == before


def test_a_home_that_cannot_be_a_directory_raises_audit_error(vault, tmp_path, monkeypatch):
    blocker = tmp_path / "a-file"
    blocker.write_bytes(b"")
    with audit.owner_key(vault) as key:
        monkeypatch.setenv("IRONDOME_HOME", str(blocker / "irondome"))
        with pytest.raises(audit.AuditError):
            audit.record(key, vault_id=vault.vault_id, kid="vault", action="use")
        with pytest.raises(audit.AuditError):
            audit.archive()

    assert blocker.read_bytes() == b""


@posix_only
def test_a_symbolic_link_in_place_of_the_log_is_not_followed(vault, tmp_path):
    elsewhere = tmp_path / "elsewhere.txt"
    elsewhere.write_bytes(b"someone else's file\n")
    os.symlink(str(elsewhere), str(paths.audit_file()))

    with pytest.raises(audit.AuditError) as caught:
        write(vault)
    with pytest.raises(audit.AuditError):
        audit.verify(vault)
    with pytest.raises(audit.AuditError):
        audit.read(vault)

    assert "symbolic link" in str(caught.value)
    assert elsewhere.read_bytes() == b"someone else's file\n"


@posix_only
def test_a_pipe_in_place_of_the_log_is_refused_without_waiting_on_it(vault):
    os.mkfifo(str(paths.audit_file()))

    with time_limit(10):
        with pytest.raises(audit.AuditError):
            write(vault)
        with pytest.raises(audit.AuditError):
            audit.verify(vault)


def test_a_directory_in_place_of_the_log_is_refused(vault):
    paths.audit_file().mkdir()

    with pytest.raises(audit.AuditError):
        write(vault)
    with pytest.raises(audit.AuditError):
        audit.verify(vault)


def test_an_interrupted_write_found_later_is_removed_by_the_next_record(vault):
    whole = fill(vault, 2)
    paths.audit_file().write_bytes(whole + b'{"data":"AAAA","kid":"vau')
    assert not audit.verify(vault).ok

    write(vault, "vault.edit")

    assert paths.audit_file().read_bytes().startswith(whole)
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=3, problems=[])
    assert [event.seq for event in audit.read(vault)] == [1, 2, 3]


def test_a_log_that_is_only_a_fragment_starts_over(vault):
    paths.audit_file().write_bytes(b"fragment without a newline")

    write(vault)

    assert audit.verify(vault) == audit.AuditReport(ok=True, count=1, problems=[])
    assert json.loads(log_lines()[0])["seq"] == 1


def test_recording_continues_after_a_last_line_that_is_not_a_record(vault):
    lines = fill(vault, 2)[:-1].split(b"\n")
    put_lines(lines + [b"scribble"])

    write(vault, "vault.edit")

    report = audit.verify(vault)
    newest = json.loads(log_lines()[-1])
    assert report.count == 3
    assert report.problems == ["line 3 is not an audit record (unreadable)"]
    assert newest["seq"] == 4 and newest["prev"] == sha(b"scribble")
    assert [event.action for event in audit.read(vault)] == ["vault.add", "vault.add", "vault.edit"]


def test_recording_continues_after_an_oversize_last_line(vault):
    lines = fill(vault, 1)[:-1].split(b"\n")
    huge = b"z" * 200_000
    put_lines(lines + [huge])

    write(vault, "vault.edit")

    newest = json.loads(log_lines()[-1])
    assert newest["seq"] == 3 and newest["prev"] == sha(huge)
    assert audit.verify(vault).problems == ["line 2 is longer than any record IronDome writes"]


def test_threads_writing_at_once_produce_one_unbroken_chain(vault):
    with audit.owner_key(vault) as owner:
        key = bytes(owner.view())
    failures: List[BaseException] = []

    def worker(name: int) -> None:
        try:
            for index in range(6):
                audit.record(key, vault_id=vault.vault_id, kid="vault", action="use", target=f"{name}-{index}")
        except BaseException as exc:  # reported below, in the main thread
            failures.append(exc)

    threads = [threading.Thread(target=worker, args=(name,)) for name in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)

    assert not failures
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=48, problems=[])
    assert sorted(event.target for event in audit.read(vault)) == sorted(f"{n}-{i}" for n in range(8) for i in range(6))


WRITER = """
import os, sys
from irondome import audit

key = bytes.fromhex(os.environ["TEST_AUDIT_KEY"])
vault_id = bytes.fromhex(os.environ["TEST_VAULT_ID"])
for index in range(int(sys.argv[1])):
    audit.record(key, vault_id=vault_id, kid=os.environ["TEST_KID"], action="grant.use", actor="grant",
                 target="%d-%d" % (os.getpid(), index))
"""


def test_processes_writing_at_once_produce_one_unbroken_chain(vault):
    write(vault, "grant.create", target=GRANT_ID)
    with audit.owner_key(vault) as owner, audit.grant_key(owner, GRANT_ID) as key:
        environment = dict(
            os.environ, TEST_AUDIT_KEY=bytes(key.view()).hex(), TEST_VAULT_ID=vault.vault_id.hex(), TEST_KID=GRANT_ID
        )
    writers = [
        subprocess.Popen([sys.executable, "-c", WRITER, "8"], env=environment, stderr=subprocess.PIPE)
        for _ in range(5)
    ]
    errors = [writer.communicate(timeout=120)[1] for writer in writers]

    assert [writer.returncode for writer in writers] == [0] * 5, errors
    report = audit.verify(vault)
    events = audit.read(vault)
    assert report == audit.AuditReport(ok=True, count=41, problems=[])
    assert [event.seq for event in events] == list(range(1, 42))
    assert len({event.target for event in events[1:]}) == 40


# ---------------------------------------------------------------------------
# Setting a damaged log aside
# ---------------------------------------------------------------------------


def test_archive_sets_the_log_aside_and_the_next_record_starts_a_new_chain(vault, monkeypatch):
    lines = fill(vault, 4)[:-1].split(b"\n")
    put_lines(lines[:1] + lines[2:])
    assert not audit.verify(vault).ok
    monkeypatch.setattr(time, "time", lambda: 1_800_000_000.0)

    archived = audit.archive()

    assert archived == paths.home() / "audit-20270115T080000Z.log"
    assert not paths.audit_file().exists()
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=0, problems=[])
    write(vault, "vault.edit")
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=1, problems=[])
    assert json.loads(log_lines()[0])["seq"] == 1 and json.loads(log_lines()[0])["prev"] == ""
    old = audit.verify(vault, path=archived)
    assert not old.ok and old.count == 3
    assert [event.target for event in audit.read(vault, path=archived)] == ["entry-0", "entry-2", "entry-3"]
    if os.name != "nt":
        assert stat.S_IMODE(archived.stat().st_mode) == 0o600


def test_archive_never_overwrites_an_earlier_archive(vault, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 1_800_000_000.0)
    names = []
    for _ in range(3):
        write(vault)
        names.append(audit.archive().name)

    assert names == ["audit-20270115T080000Z.log", "audit-20270115T080000Z-2.log", "audit-20270115T080000Z-3.log"]
    assert all(audit.verify(vault, path=paths.home() / name).count == 1 for name in names)


def test_archive_without_a_log_does_nothing(vault):
    assert audit.archive() is None
    assert not list(Path(paths.home()).glob("audit-*.log"))


def _which_time(stamp: int) -> Optional[str]:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(stamp))


def test_the_archive_name_is_the_utc_time(vault, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: 0.0)
    write(vault)

    assert audit.archive().name == f"audit-{_which_time(0)}.log" == "audit-19700101T000000Z.log"


# ---------------------------------------------------------------------------
# The promise made to callers
# ---------------------------------------------------------------------------


def _full_disk(*args, **kwargs):
    raise OSError(errno.ENOSPC, "No space left on device")


@pytest.mark.parametrize("breakage", [_full_disk])
def test_a_caller_that_has_finished_its_work_can_turn_the_failure_into_a_warning(vault, monkeypatch, breakage):
    """The contract: only IronDomeError escapes record(), so `except IronDomeError` is enough."""
    warnings: List[str] = []
    committed: List[str] = []

    def command(run: Callable[[], None]) -> None:
        committed.append("vault written")
        try:
            run()
        except IronDomeError as exc:
            warnings.append(str(exc))

    with monkeypatch.context() as patch:
        patch.setattr(audit.os, "write", breakage)
        command(lambda: write(vault, "vault.add", target="github"))

    assert committed == ["vault written"]
    assert len(warnings) == 1 and warnings[0].startswith("the audit log ")
