"""What a person found by using IronDome by hand before release, kept as tests.

Every test here failed on the day it was written, while the whole suite
passed. A reviewer was given the built package, the published texts and a
machine to watch, and no source code. These are the faults of behaviour that
trial found; each test does what the person did, through the real command
line. (The recovery key that no command accepted is in
``tests/claims/test_recovery.py``, the encodings that got past the mask and
the processes a time limit left running in ``tests/unit/test_runner.py``.)
"""

from __future__ import annotations

import os
import subprocess
from typing import Callable, Dict, List

from conftest import PASSWORD
from support.claimkit import add, document, fails, init, irondome_dirs, ok

CLI = Callable[..., "subprocess.CompletedProcess[str]"]


def with_session(cli: CLI, *unlock_args: str) -> Dict[str, str]:
    token = ok(
        cli("unlock", "--print-token", "--password-stdin", *unlock_args, stdin=PASSWORD + "\n")
    ).stdout.strip()
    return {"IRONDOME_SESSION": token}


# -- a session cannot make what outlives it ---------------------------------------------


def test_a_session_cannot_mint_a_grant_that_outlives_it(cli: CLI) -> None:
    """A one-minute session made a 30-day, unlimited, reveal grant for everything, with no password.

    Whatever holds a session token for a minute could keep the whole vault
    for a month. Now a grant that would still work after the session has
    ended needs the master password again.
    """
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    env = with_session(cli, "--ttl", "2m")
    before = len(document(cli("grant", "ls", "--json", "--password-stdin", stdin=PASSWORD + "\n"))["grants"])
    refused = cli(
        "grant", "create", "stripe", "--ttl", "30d", "--unlimited", "--reveal", "--password-stdin",
        stdin="not the password\n", env=env,
    )
    assert refused.returncode != 0 and "wrong master password" in refused.stderr
    assert "outlast your session" in refused.stderr
    listed = document(cli("grant", "ls", "--json", "--password-stdin", stdin=PASSWORD + "\n"))["grants"]
    assert len(listed) == before
    made = ok(cli("grant", "create", "stripe", "--ttl", "30d", "--password-stdin", stdin=PASSWORD + "\n", env=env))
    assert "outlast your session" in made.stderr  # said, and then the right password was enough


def test_a_session_still_makes_a_grant_that_ends_before_it_does(cli: CLI) -> None:
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    env = with_session(cli, "--ttl", "10m")
    made = ok(cli("grant", "create", "stripe", "--ttl", "5m", "--password-stdin", stdin="not needed\n", env=env))
    assert "outlast" not in made.stderr


def test_a_session_cannot_change_what_agents_may_do_with_an_entry(cli: CLI) -> None:
    """``edit --agent reveal`` under a session would outlast the session too: it needs the password."""
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    env = with_session(cli)
    refused = cli("edit", "stripe", "--agent", "reveal", "--password-stdin", stdin="not the password\n", env=env)
    assert refused.returncode != 0 and "wrong master password" in refused.stderr
    shown = document(cli("show", "stripe", "--json", "--password-stdin", stdin=PASSWORD + "\n"))
    assert shown["agent"] == "deny"
    ok(cli("edit", "stripe", "--username", "me", "--password-stdin", stdin="\n", env=env))  # ordinary edits: yes
    ok(cli("edit", "stripe", "--agent", "use", "--password-stdin", stdin=PASSWORD + "\n", env=env))


# -- the audit log after a re-key ---------------------------------------------------------


def archived_logs() -> List[str]:
    return sorted(path.name for path in (irondome_dirs()["home"] / "bunkers" / "alpha").glob("audit-*.log"))


def test_the_audit_log_from_before_a_rekey_can_still_be_read_and_checked(cli: CLI) -> None:
    """After ``rekey`` no command could read the archived log: the cure for a replayed grant removed the evidence."""
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    said = ok(cli("rekey", "--yes", "--password-stdin", stdin=PASSWORD + "\n"))
    (name,) = archived_logs()
    assert f"irondome audit --archive {name}" in said.stderr
    current = ok(cli("audit", "-n", "0", "--password-stdin", stdin=PASSWORD + "\n"))
    assert "entry.add" not in current.stdout and name in current.stderr
    old = document(cli("audit", "-n", "0", "--verify", "--json", "--archive", name, "--password-stdin",
                       stdin=PASSWORD + "\n"))
    assert [event["action"] for event in old["events"]] == ["vault.create", "entry.add", "rekey"]
    assert old["verify"] == {"ok": True, "count": 3, "problems": []}


def test_a_second_rekey_keeps_the_first_log_readable_and_an_edited_archive_is_detected(cli: CLI) -> None:
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    ok(cli("rekey", "--yes", "--password-stdin", stdin=PASSWORD + "\n"))
    (first,) = archived_logs()
    add(cli, "bank", "the-bank-value-2")
    ok(cli("rekey", "--yes", "--password-stdin", stdin=PASSWORD + "\n"))
    assert len(archived_logs()) == 2 and first in archived_logs()
    old = document(cli("audit", "-n", "0", "--verify", "--json", "--archive", first, "--password-stdin",
                       stdin=PASSWORD + "\n"))
    assert old["verify"]["ok"] and [event["action"] for event in old["events"]][:2] == ["vault.create", "entry.add"]
    path = irondome_dirs()["home"] / "bunkers" / "alpha" / first
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(lines[0] + lines[2])  # the record of the entry removed
    os.chmod(path, 0o600)
    altered = fails(cli("audit", "-n", "0", "--verify", "--archive", first, "--password-stdin",
                        stdin=PASSWORD + "\n"), 1)
    assert "ALTERED" in altered.stdout


def test_an_archived_log_no_kept_key_reads_is_refused_with_the_reason_and_verify_says_altered(cli: CLI) -> None:
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    ok(cli("rekey", "--yes", "--password-stdin", stdin=PASSWORD + "\n"))
    (name,) = archived_logs()
    bunker = irondome_dirs()["home"] / "bunkers" / "alpha"
    lines = (bunker / name).read_bytes().splitlines(keepends=True)
    foreign = bunker / "audit-19990101T000000Z.log"  # the right kind of name, records no key here opens
    foreign.write_bytes(b"".join(line[:-9] + b"AAAAAAAA\n" for line in lines))
    os.chmod(foreign, 0o600)
    refused = cli("audit", "--archive", foreign.name, "--password-stdin", stdin=PASSWORD + "\n")
    assert refused.returncode != 0 and "no record in" in refused.stderr and "Traceback" not in refused.stderr
    checked = fails(cli("audit", "--verify", "--archive", foreign.name, "--password-stdin", stdin=PASSWORD + "\n"), 1)
    assert "ALTERED" in checked.stdout
    missing = cli("audit", "--archive", "audit-20000101T000000Z.log", "--password-stdin", stdin=PASSWORD + "\n")
    assert missing.returncode != 0 and "no archived audit log named" in missing.stderr
    outside = cli("audit", "--archive", "/etc/passwd", "--password-stdin", stdin=PASSWORD + "\n")
    assert outside.returncode != 0 and "no archived audit log named" in outside.stderr


def test_what_reads_an_archived_log_is_in_the_vault_and_nothing_is_written_beside_the_log(cli: CLI) -> None:
    """The key that reads an old log travels in the vault's encrypted index: no file beside the log to lose,
    swap or plant (a first version kept it in a side file, and a pipe planted under that name hung a re-key)."""
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    ok(cli("rekey", "--yes", "--password-stdin", stdin=PASSWORD + "\n"))
    (name,) = archived_logs()
    bunker = irondome_dirs()["home"] / "bunkers" / "alpha"
    assert sorted(path.name for path in bunker.iterdir() if path.name.startswith("audit")) == [
        name, "audit.log", "audit.log.lock"
    ]
    os.mkfifo(bunker / (name + ".key"))  # whatever is put beside the log is never opened
    old = document(cli("audit", "-n", "0", "--verify", "--json", "--archive", name, "--password-stdin",
                       stdin=PASSWORD + "\n", timeout=30))
    assert old["verify"]["ok"] and old["verify"]["count"] == 3
    ok(cli("rekey", "--yes", "--password-stdin", stdin=PASSWORD + "\n", timeout=60))
    again = document(cli("audit", "-n", "0", "--verify", "--json", "--archive", name, "--password-stdin",
                         stdin=PASSWORD + "\n"))
    assert again["verify"]["ok"] and again["verify"]["count"] == 3


# -- what the program says ------------------------------------------------------------------


def test_a_lifetime_setting_takes_a_duration_as_the_ttl_options_do(cli: CLI) -> None:
    """``config set grant_ttl`` wanted seconds while ``--ttl`` wants ``15m``: both now take either."""
    init(cli, "--no-recovery")
    for written, seconds in (("15m", 900), ("2H", 7200), ("600", 600), (" 90s ", 90)):
        ok(cli("config", "set", "grant_ttl", written, "--password-stdin", stdin=PASSWORD + "\n"))
        assert document(cli("config", "get", "grant_ttl", "--json"))["value"] == seconds
    for unusable in ("soon", "90 s", "\u0661\u0665m", "15 minutes"):  # as --ttl refuses them
        refused = fails(cli("config", "set", "grant_ttl", unusable, "--password-stdin", stdin=PASSWORD + "\n"), 2)
        assert "15m" in refused.stderr


def test_run_says_what_an_env_file_it_was_not_given_supplies(cli: CLI, tmp_path) -> None:
    """``.env.irondome`` in the working directory is used without being asked for: it is at least spelled out."""
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / ".env.irondome").write_text("STRIPE_KEY=irondome://stripe\nOTHER_KEY=irondome://stripe\n")
    ran = ok(cli("run", "--cwd", str(tmp_path / "repo"), "--password-stdin", "--", "/usr/bin/true",
                 stdin=PASSWORD + "\n"))
    assert "found in the working directory (from the vault: OTHER_KEY, STRIPE_KEY)" in ran.stderr
    named = ok(cli("run", "--env-file", str(tmp_path / "repo" / ".env.irondome"), "--password-stdin", "--",
                   "/usr/bin/true", stdin=PASSWORD + "\n"))
    assert "found in the working directory" not in named.stderr


def test_a_cost_below_the_default_is_shown_and_a_backup_made_with_it_says_so(cli: CLI, tmp_path) -> None:
    """A backup was written at 19 MiB because of an environment variable, without a word."""
    made = ok(cli("init", "--password-stdin", "--no-recovery", stdin=PASSWORD + "\n"))  # the tests run at 19 MiB
    assert "Password stretching: Argon2id, 19 MiB, 3 passes, 4 lanes (below the usual 256 MiB)" in made.stderr
    slots = document(cli("auth", "show", "--json"))["keyslots"]
    assert [slot["kdf"] for slot in slots] == ["Argon2id, 19 MiB, 3 passes, 4 lanes (below the usual 256 MiB)"]
    assert "19 MiB" in ok(cli("status")).stdout
    backup = ok(cli("export", str(tmp_path / "backup.irondome"), "--password-stdin",
                    stdin=f"{PASSWORD}\na long backup passphrase of six words\n"))
    assert "19 MiB of memory, not the usual 256 MiB (IRONDOME_KDF_MEMORY_MIB is set" in backup.stderr


def test_init_remarks_on_a_master_password_that_is_easy_to_guess_and_still_makes_the_vault(cli: CLI) -> None:
    made = ok(cli("init", "--password-stdin", "--no-recovery", stdin="12345678\n"))
    assert "that master password is very weak" in made.stderr and "irondome passwd" in made.stderr
    assert "created the vault" in made.stderr


def test_an_option_written_before_the_command_is_explained_not_guessed_at(cli: CLI) -> None:
    refused = fails(cli("--no-grant", "get", "x"), 2)
    assert "--no-grant is an option of the command: write it after its name" in refused.stderr
    assert "did you mean --no-grant" not in refused.stderr
    both = fails(cli("--copy", "--no-grant", "get", "x"), 2)
    assert "--copy, --no-grant are options of the command: write them after its name" in both.stderr


def test_a_value_too_long_to_read_names_the_limit(cli: CLI) -> None:
    init(cli, "--no-recovery")
    refused = cli("add", "big", "--kind", "secret", "--password-stdin", "--value-stdin", "--field", "pin",
                  stdin=PASSWORD + "\n" + "x" * 5000 + "\n1234\n")  # a value that is one line of several on stdin
    assert refused.returncode != 0 and "at most 4095 bytes" in refused.stderr


# -- found by the review of the fixes above ----------------------------------------------------


def test_a_session_cannot_add_an_entry_that_agents_may_see_either(cli: CLI) -> None:
    """``edit --agent`` asked for the password; removing the entry and adding it again with ``--agent`` did not."""
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    env = with_session(cli)
    ok(cli("rm", "stripe", "--yes", "--password-stdin", stdin="\n", env=env))  # a session removes entries
    refused = cli("add", "stripe", "--kind", "secret", "--agent", "reveal", "--password-stdin", "--value-stdin",
                  stdin="not the password\nthe-stripe-value-1\n", env=env)
    assert refused.returncode != 0 and "wrong master password" in refused.stderr
    ok(cli("add", "stripe", "--kind", "secret", "--password-stdin", "--value-stdin",
           stdin="\nthe-stripe-value-1\n", env=env))  # as an entry agents are denied, a session adds it
    shown = document(cli("show", "stripe", "--json", "--password-stdin", stdin=PASSWORD + "\n"))
    assert shown["agent"] == "deny"


def test_what_a_session_does_is_recorded_as_done_by_a_session(cli: CLI) -> None:
    """The log said ``owner`` for a grant that anything holding the session token could have made."""
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    env = with_session(cli, "--ttl", "10m")
    ok(cli("grant", "create", "stripe", "--ttl", "5m", "--password-stdin", stdin="\n", env=env))
    ok(cli("edit", "stripe", "--username", "me", "--password-stdin", stdin="\n", env=env))
    events = document(cli("audit", "-n", "0", "--json", "--password-stdin", stdin=PASSWORD + "\n"))["events"]
    who = {event["action"]: event["actor"] for event in events}
    assert who["grant.create"] == "session" and who["entry.edit"] == "session"
    assert who["vault.create"] == "owner" and who["entry.add"] == "owner"
