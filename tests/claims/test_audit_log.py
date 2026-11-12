"""Claim ``audit-log``: every agent access is recorded, and edits to the record are detected.

Statement: each use of a grant, a session or a Touch ID approval, and every
change to the vault, is appended to an encrypted, hash-chained log.
``irondome audit --verify`` detects edited, reordered, forged and removed
lines.
"""

from __future__ import annotations

import base64
import json
import os
import sys

import pytest

from conftest import PASSWORD
from irondome import paths
from support.claimkit import add, document, fails, grant, init, ok, session


@pytest.fixture
def history(cli):
    """A vault whose log holds owner changes, a grant's creation and use, and a session's use."""
    init(cli)
    add(cli, "github", "the-github-token-1234", "--alias", "GITHUB_TOKEN")
    add(cli, "bank", "the-bank-password-5678")
    token = grant(cli, "GITHUB_TOKEN", args=("--uses", "3"))["token"]
    ok(cli("run", "--env", "GITHUB_TOKEN", "--", sys.executable, "-c", "pass", env={"IRONDOME_GRANT": token}))
    session_token = session(cli)
    ok(cli("get", "bank", env={"IRONDOME_SESSION": session_token}))
    ok(cli("edit", "bank", "--username", "someone", "--password-stdin", stdin=PASSWORD + "\n"))
    return token


def audit(cli, *args):
    return cli("audit", "-n", "0", *args, "--password-stdin", stdin=PASSWORD + "\n")


def verify(cli):
    return audit(cli, "--verify")


def lines():
    return paths.audit_file().read_bytes().splitlines(keepends=True)


def write(parts):
    paths.audit_file().write_bytes(b"".join(parts))


def test_every_change_and_every_use_is_in_the_log_with_who_did_it(cli, history):
    events = document(audit(cli, "--json"))["events"]
    seen = {(event["action"], event["actor"]) for event in events}
    assert ("vault.create", "owner") in seen
    assert ("entry.add", "owner") in seen and ("entry.edit", "owner") in seen
    assert ("grant.create", "owner") in seen and ("grant.use", "grant") in seen
    assert ("session.start", "owner") in seen
    # The read through the session (made without a terminal, so recorded as an agent's) is in the log too.
    assert any(event["action"] == "reveal" and event["target"] == "bank/password" for event in events)
    grant_lines = [event for event in events if event["actor"] == "grant"]
    assert grant_lines and all(event["kid"] != "vault" for event in grant_lines)


def test_the_log_is_encrypted(cli, history):
    raw = paths.audit_file().read_bytes()
    for word in (b"github", b"bank", b"GITHUB_TOKEN", b"entry.add", b"grant.use", b"owner"):
        assert word not in raw


def test_an_untouched_log_verifies(cli, history):
    report = document(cli("audit", "--verify", "--json", "--password-stdin", stdin=PASSWORD + "\n"))
    assert report["verify"]["ok"] is True and report["verify"]["problems"] == []
    assert report["verify"]["count"] == len(lines())


def test_an_edited_line_is_detected(cli, history):
    parts = lines()
    record = json.loads(parts[2])
    data = bytearray(base64.b64decode(record["data"]))
    data[20] ^= 0x01
    record["data"] = base64.b64encode(bytes(data)).decode()
    parts[2] = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    write(parts)
    assert fails(verify(cli), 1)


def test_a_line_with_a_changed_time_is_detected(cli, history):
    parts = lines()
    record = json.loads(parts[1])
    record["ts"] -= 3600
    parts[1] = json.dumps(record, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    write(parts)
    fails(verify(cli), 1)


def test_reordered_lines_are_detected(cli, history):
    parts = lines()
    parts[1], parts[2] = parts[2], parts[1]
    write(parts)
    fails(verify(cli), 1)


def test_a_line_removed_from_the_middle_is_detected(cli, history):
    parts = lines()
    del parts[len(parts) // 2]
    write(parts)
    fails(verify(cli), 1)


def test_the_oldest_line_removed_is_detected(cli, history):
    write(lines()[1:])
    fails(verify(cli), 1)


def test_a_forged_line_is_detected(cli, history):
    parts = lines()
    last = json.loads(parts[-1])
    forged = dict(last, seq=last["seq"] + 1, data=base64.b64encode(os.urandom(300)).decode())
    write(parts + [json.dumps(forged, sort_keys=True, separators=(",", ":")).encode() + b"\n"])
    fails(verify(cli), 1)


def test_a_line_copied_from_another_vaults_log_is_detected(cli, history, tmp_path):
    foreign = tmp_path / "other"
    other = {"IRONDOME_HOME": str(foreign / "home"), "IRONDOME_DEVICE_DIR": str(foreign / "device")}
    init(cli, env=other)
    stranger = (foreign / "home" / "bunkers" / "alpha" / "audit.log").read_bytes().splitlines(keepends=True)
    write(lines() + stranger[-1:])
    fails(verify(cli), 1)


# -- the boundary ------------------------------------------------------------------


def test_boundary_removing_the_newest_lines_is_not_detected(cli, history):
    parts = lines()
    write(parts[:-2])
    assert ok(verify(cli)).returncode == 0


def test_boundary_removing_the_whole_log_is_not_detected(cli, history):
    paths.audit_file().unlink()
    report = document(cli("audit", "--verify", "--json", "--password-stdin", stdin=PASSWORD + "\n"))
    assert report["verify"]["ok"] is True and report["verify"]["count"] == 0


def test_boundary_a_grant_holder_can_append_records_of_its_own(cli, history):
    """The grant carries a key for its own records: what it writes verifies, under its own id."""
    from irondome import audit as audit_module
    from irondome import caps

    with caps.open_grant(history) as opened:
        audit_module.record(opened.audit_key, vault_id=opened.vault_id, kid=opened.id, action="anything",
                            actor="owner", target="whatever the holder likes")
    report = document(cli("audit", "--verify", "--json", "--password-stdin", stdin=PASSWORD + "\n"))
    assert report["verify"]["ok"] is True
    newest = report["events"][-1]
    assert newest["action"] == "anything" and newest["kid"] != "vault"
