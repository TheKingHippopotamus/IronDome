"""What a second person found by using the final build by hand, kept as tests.

After the faults of the first trial were fixed, a second reviewer was given
the new package, the published texts, the first report and a machine to
watch, and again no source code. The first trial's blocker was gone; these
are the faults that pass found. Each test does what the person did, through
the real command line. (The self-check that failed on a TPM is in
``tests/unit/test_selftest.py``, the encodings that still got past the mask
in ``tests/unit/test_runner.py``, the temporary files a killed write leaves
in ``tests/unit/test_paths.py`` and ``tests/e2e/test_cli_rekey_interrupted.py``.)
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Callable, Dict

from conftest import PASSWORD
from support.claimkit import add, document, fails, init, irondome_dirs, ok

CLI = Callable[..., "subprocess.CompletedProcess[str]"]

PEM = (
    "-----BEGIN LAB PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n"
    "c2gtZWQyNTUxOQAAACDk1x0bq3mJ8mXo0m2nq1sJ0yq8Yb0yq8Yb0yq8Yb0yqAAA\n"
    "-----END LAB PRIVATE KEY-----\n"
)


def with_session(cli: CLI, *unlock_args: str) -> Dict[str, str]:
    token = ok(
        cli("unlock", "--print-token", "--password-stdin", *unlock_args, stdin=PASSWORD + "\n")
    ).stdout.strip()
    return {"IRONDOME_SESSION": token}


def value_of(cli: CLI, name: str) -> str:
    return ok(cli("get", name, "--password-stdin", stdin=PASSWORD + "\n")).stdout


# -- a key of several lines is stored whole ------------------------------------------------


def test_a_value_of_several_lines_on_stdin_is_stored_whole(cli: CLI) -> None:
    """``cat key.pem | irondome add k --value-stdin`` kept the first line, dropped four and said ``ok``."""
    init(cli, "--no-recovery")
    ok(cli("add", "deploy-key", "--kind", "secret", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\n" + PEM))
    assert value_of(cli, "deploy-key") == PEM  # every line, and the line break a key file ends with
    newer = PEM.replace("LAB", "NEW")
    ok(cli("edit", "deploy-key", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\n" + newer))
    assert value_of(cli, "deploy-key") == newer


def test_a_value_of_one_line_is_stored_without_its_line_break(cli: CLI) -> None:
    init(cli, "--no-recovery")
    for name, typed in (("unix", "one-line-value\n"), ("dos", "one-line-value\r\n"), ("bare", "one-line-value")):
        ok(cli("add", name, "--kind", "secret", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\n" + typed))
        assert value_of(cli, name) == "one-line-value"
    ok(cli("add", "blanks", "--kind", "secret", "--password-stdin", "--value-stdin",
           stdin=PASSWORD + "\ntok_blank\n\n\n"))  # a here-document or a file whose last lines are blank
    assert value_of(cli, "blanks") == "tok_blank"
    nothing = cli("add", "none", "--kind", "secret", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\n")
    assert nothing.returncode != 0 and "expected the value on stdin, and found nothing" in nothing.stderr


def test_a_value_of_nothing_but_line_breaks_is_refused_and_empties_nothing(cli: CLI) -> None:
    """``echo "$TOKEN" | irondome edit k --value-stdin`` with TOKEN unset said ``ok`` and emptied the value."""
    init(cli, "--no-recovery")
    add(cli, "token", "the-value-that-is-there")
    for breaks in ("\n", "\n\n\n", "\r\n"):
        refused = fails(cli("edit", "token", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\n" + breaks), 2)
        assert "the value cannot be empty: stdin held only line breaks" in refused.stderr
        added = fails(cli("add", "new", "--kind", "secret", "--password-stdin", "--value-stdin",
                          stdin=PASSWORD + "\n" + breaks), 2)
        assert "the value cannot be empty" in added.stderr
    assert value_of(cli, "token") == "the-value-that-is-there"
    assert "new" not in ok(cli("ls", "--password-stdin", stdin=PASSWORD + "\n")).stdout


def test_a_value_followed_by_other_input_on_stdin_is_one_line_and_help_says_so(cli: CLI) -> None:
    init(cli, "--no-recovery")
    ok(cli("add", "bank", "--password-stdin", "--value-stdin", "--field", "pin",
           stdin=PASSWORD + "\nthe-value\n4321\n"))
    assert value_of(cli, "bank") == "the-value"
    assert ok(cli("get", "bank/pin", "--password-stdin", stdin=PASSWORD + "\n")).stdout == "4321"
    said = ok(cli("add", "--help")).stdout
    assert "several lines exactly, one line without the line breaks after it" in " ".join(said.split())
    assert "a key of several lines is stored whole" in " ".join(said.split())


def test_a_value_read_to_the_end_of_stdin_has_a_limit_that_is_named(cli: CLI) -> None:
    init(cli, "--no-recovery")
    refused = cli("add", "big", "--kind", "secret", "--password-stdin", "--value-stdin",
                  stdin=PASSWORD + "\n" + "x" * (64 * 1024 + 1))
    assert refused.returncode != 0 and "the value is too long: at most 64 KiB" in refused.stderr
    ok(cli("add", "long", "--kind", "secret", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\n" + "y" * 9000))
    assert value_of(cli, "long") == "y" * 9000


# -- a session, and what it leaves ------------------------------------------------------------


def test_ending_a_session_revokes_the_grants_made_under_it(cli: CLI) -> None:
    """A grant made under a session went on working after ``irondome lock`` ended the session."""
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    owners = ok(cli("grant", "create", "stripe", "--ttl", "5m", "--unlimited", "--password-stdin",
                    stdin=PASSWORD + "\n")).stdout.strip()
    env = with_session(cli, "--ttl", "10m")
    made = ok(cli("grant", "create", "stripe", "--ttl", "2m", "--unlimited", "--label", "ci run",
                  "--password-stdin", stdin="\n", env=env))
    token = made.stdout.strip()
    ran = ok(cli("run", "--env", "S=stripe", "--", "/bin/sh", "-c", "test -n \"$S\"", env={"IRONDOME_GRANT": token}))
    assert ran.returncode == 0
    labels = [grant["label"] for grant in document(cli("grant", "ls", "--json"))["grants"]]
    assert any(label.startswith("ci run [session ") for label in labels)
    locked = ok(cli("lock", env=env))
    assert "revoked any grant made under it" in locked.stderr
    gone = cli("run", "--env", "S=stripe", "--", "/usr/bin/true", env={"IRONDOME_GRANT": token})
    assert gone.returncode != 0 and "opens nothing here" in gone.stderr
    ok(cli("run", "--env", "S=stripe", "--", "/usr/bin/true", env={"IRONDOME_GRANT": owners}))  # the owner's stays
    events = document(cli("audit", "-n", "0", "--json", "--password-stdin", stdin=PASSWORD + "\n"))["events"]
    assert [(event["action"], event["actor"]) for event in events
            if event["action"] in ("session.end", "grant.revoke")] == [
        ("session.end", "session"), ("grant.revoke", "session"),  # the session's token is all that asked
    ]


def test_a_label_cannot_imitate_the_mark_of_a_session(cli: CLI) -> None:
    """An owner's grant labelled like a session's was revoked when that session was locked."""
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    refused = fails(cli("grant", "create", "stripe", "--label", "mine [session 0123456789ab]", "--password-stdin",
                        stdin=PASSWORD + "\n"), 2)
    assert "a label cannot end with [session ...]" in refused.stderr
    env = with_session(cli, "--ttl", "10m")
    long_label = fails(cli("grant", "create", "stripe", "--ttl", "2m", "--label", "x" * 180, "--password-stdin",
                           stdin="\n", env=env), 2)
    assert "under a session a label is at most 177 characters" in long_label.stderr
    ok(cli("grant", "create", "stripe", "--ttl", "2m", "--label", "x" * 177, "--password-stdin", stdin="\n", env=env))


def test_a_session_used_without_a_terminal_is_recorded_as_a_session(cli: CLI) -> None:
    """The texts said ``session``; the log said ``agent`` whenever no terminal was attached."""
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    env = with_session(cli)
    assert ok(cli("get", "stripe", env=env)).stdout == "the-stripe-value-1"
    events = document(cli("audit", "-n", "0", "--json", "--password-stdin", stdin=PASSWORD + "\n"))["events"]
    reads = [(event["action"], event["actor"]) for event in events if event["target"].startswith("stripe/")]
    assert reads == [("reveal", "session")]


# -- a file found in the working directory ---------------------------------------------------


def test_the_notice_about_a_found_env_file_is_printed_with_quiet_too(cli: CLI, tmp_path) -> None:
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    (tmp_path / "repo").mkdir()
    ok(cli("alias", "set", "STRIPE_KEY", "stripe", "--password-stdin", stdin=PASSWORD + "\n"))
    (tmp_path / "repo" / ".env.irondome").write_text("STRIPE_KEY=irondome://STRIPE_KEY\n")
    (tmp_path / "repo" / ".env.irondome").chmod(0o644)  # whatever the umask of the machine the tests run on
    ran = ok(cli("-q", "run", "--cwd", str(tmp_path / "repo"), "--password-stdin", "--", "/usr/bin/true",
                 stdin=PASSWORD + "\n"))
    assert "found in the working directory (from the vault, each under its own name: STRIPE_KEY)" in ran.stderr


def test_a_found_env_file_may_only_ask_for_a_secret_under_its_own_name(cli: CLI, tmp_path) -> None:
    """A planted file set PATH, and ``irondome run -- make`` ran the planted ``make`` with the secret.

    A first fix refused a list of such variables; the reviewer got the secret out through LESSOPEN, which
    was not on it, and named thirty more. A second let the file point any variable at any entry; the
    reviewer pointed PATH at a user name anybody could guess, and planted a directory of that name. So a
    file nobody named may do one thing, the thing ``--env NAME`` does: ask for the secret the owner keeps
    under that very name. What a variable is called and what goes into it are then both the owner's choice.
    """
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    ok(cli("add", "gh", "--username", "octo", "--url", "https://gh.example.test", "--password-stdin", "--value-stdin",
           stdin=PASSWORD + "\nthe-gh-password-1\n"))
    ok(cli("alias", "set", "STRIPE_KEY", "stripe", "--password-stdin", stdin=PASSWORD + "\n"))
    repo = tmp_path / "repo"
    marker = tmp_path / "planted-ran"
    for directory in ("bin", "octo"):  # "octo": the directory PATH names once it holds gh's user name
        (repo / directory).mkdir(parents=True)
        (repo / directory / "make").write_text(f"#!/bin/sh\necho ran > '{marker}'\n")
        (repo / directory / "make").chmod(0o755)
    for planted, named in (
        (f"PATH={repo}/bin:/usr/bin:/bin\nLD_PRELOAD=/tmp/x.so", "LD_PRELOAD, PATH"),
        ("LESSOPEN=|/tmp/repo/h.sh %s", "LESSOPEN"),
        ("LOG_LEVEL=debug", "LOG_LEVEL"),  # harmless, and refused all the same: the rule has no list
        ("PATH=irondome://gh/username", "PATH"),  # a reference, and still the author's choice of what PATH holds
        ("BASH_ENV=irondome://gh/url", "BASH_ENV"),
        ("STRIPE=irondome://stripe", "STRIPE"),  # an entry under a name its owner did not give it
        ("STRIPE_KEY2=irondome://STRIPE_KEY", "STRIPE_KEY2"),
        ("GH=irondome://gh\nSTRIPE=irondome://STRIPE_KEY/password", "GH, STRIPE"),
    ):
        (repo / ".env.irondome").write_text(f"STRIPE_KEY=irondome://STRIPE_KEY\n{planted}\n")
        (repo / ".env.irondome").chmod(0o644)  # whatever the umask of the machine the tests run on
        refused = fails(cli("run", "--cwd", str(repo), "--password-stdin", "--", "/bin/sh", "-c", "make",
                            stdin=PASSWORD + "\n"), 2)
        assert f"sets {named} to something other than the secret you keep under that name" in refused.stderr
        assert "--env-file" in refused.stderr and not marker.exists()
        assert "the-stripe-value-1" not in refused.stderr + refused.stdout
        assert "octo" not in refused.stderr and "gh.example.test" not in refused.stderr  # no value is shown
    # What is allowed: an alias under its own name, and an entry under its own name (what --env does).
    (repo / ".env.irondome").write_text("STRIPE_KEY=irondome://STRIPE_KEY\ngh=irondome://gh\n")
    seen = ok(cli("run", "--cwd", str(repo), "--password-stdin", "--", "/bin/sh", "-c",
                  'test "$STRIPE_KEY" = the-stripe-value-1 && test "$gh" = the-gh-password-1', stdin=PASSWORD + "\n"))
    assert "(from the vault, each under its own name: STRIPE_KEY, gh)" in seen.stderr
    # A file the owner names is the owner's choice, PATH and all.
    (repo / ".env.irondome").write_text(f"STRIPE_KEY=irondome://stripe\nPATH={repo}/bin:/usr/bin:/bin\n")
    named_file = ok(cli("run", "--cwd", str(repo), "--env-file", str(repo / ".env.irondome"), "--password-stdin",
                        "--", "make", stdin=PASSWORD + "\n"))
    assert marker.exists() and "found in the working directory" not in named_file.stderr


# -- remarks that were missing ------------------------------------------------------------------


def test_every_command_that_takes_a_new_master_password_remarks_on_a_weak_one(cli: CLI) -> None:
    """``init`` remarked on ``password``; ``passwd`` and ``recovery use`` took it without a word."""
    key = init(cli)["recovery_key"]
    changed = ok(cli("passwd", "--password-stdin", stdin=f"{PASSWORD}\nabcdefgh\n"))
    assert "that master password is" in changed.stderr and "weak" in changed.stderr
    recovered = ok(cli("recovery", "use", "--password-stdin", stdin=f"{key}\npassword\n"))
    assert "that master password is" in recovered.stderr and "weak" in recovered.stderr
    strong = ok(cli("passwd", "--password-stdin", stdin=f"password\n{PASSWORD}\n"))
    assert "that master password is" not in strong.stderr


def test_an_unlock_says_when_other_users_can_reach_the_bunkers_files(cli: CLI) -> None:
    """``get`` said nothing after the vault and the device key had become world-readable; only ``doctor`` did."""
    init(cli, "--no-recovery")
    add(cli, "stripe", "the-stripe-value-1")
    quiet = ok(cli("get", "stripe", "--password-stdin", stdin=PASSWORD + "\n"))
    assert "other users of this machine" not in quiet.stderr
    device = next(path for path in sorted(irondome_dirs()["device"].rglob("*")) if path.is_file())
    device.chmod(0o644)
    loud = ok(cli("get", "stripe", "--password-stdin", stdin=PASSWORD + "\n"))
    assert "other users of this machine can reach" in loud.stderr and "irondome doctor" in loud.stderr
    assert "(mode 0644)" in loud.stderr
    assert loud.stdout == "the-stripe-value-1"


def test_the_clipboard_delay_takes_a_duration_as_the_other_time_settings_do(cli: CLI) -> None:
    init(cli, "--no-recovery")
    ok(cli("config", "set", "clipboard_clear_seconds", "45s", "--password-stdin", stdin=PASSWORD + "\n"))
    assert document(cli("config", "get", "clipboard_clear_seconds", "--json"))["value"] == 45


def test_a_cost_the_machine_cannot_give_is_a_plain_error(cli: CLI, tmp_path) -> None:
    """``IRONDOME_KDF_MEMORY_MIB=4096`` on a small machine ended in a traceback."""
    fault = (
        "import sys\n"
        "from cryptography.hazmat.primitives.kdf import argon2\n"
        "def refuse(self, *args, **kwargs):\n"
        "    raise MemoryError('Not enough memory to derive key.')\n"
        "argon2.Argon2id.derive_into = refuse\n"
        "from irondome.cli.main import main\n"
        "raise SystemExit(main(sys.argv[1:]))\n"
    )
    ran = subprocess.run(
        [sys.executable, "-c", fault, "init", "--password-stdin", "--no-recovery"], input=PASSWORD + "\n",
        capture_output=True, text=True, timeout=120,
    )
    assert ran.returncode != 0 and "Traceback" not in ran.stderr
    assert "not enough memory to stretch the password: Argon2id is set to use" in ran.stderr
    assert not (irondome_dirs()["home"] / "bunkers" / "alpha" / "vault.irondome").exists()


# -- what a killed write leaves ------------------------------------------------------------------


def test_the_next_write_removes_what_a_killed_write_left_in_the_bunker(cli: CLI) -> None:
    """A re-key killed at its last rename left a whole vault in ``.tmp-...``: it opened with a replaced recovery key."""
    init(cli, "--no-recovery")
    bunker = irondome_dirs()["home"] / "bunkers" / "alpha"
    old = time.time() - 300
    planted = [bunker / ".tmp-abcdefgh", bunker / "backups" / ".tmp-zyxwvu98"]
    (bunker / "backups").mkdir(exist_ok=True)
    for path in planted:
        path.write_bytes((bunker / "vault.irondome").read_bytes())
        os.utime(path, (old, old))
    fresh = bunker / ".tmp-12345678"  # every writer here holds the bunker's lock: a new one is abandoned too
    fresh.write_bytes(b"left a moment ago")
    kept = bunker / ".tmp-not-ours.txt"
    kept.write_bytes(b"someone else's file")
    os.utime(kept, (old, old))
    add(cli, "stripe", "the-stripe-value-1")
    assert not any(path.exists() for path in planted) and not fresh.exists()
    assert kept.exists()
