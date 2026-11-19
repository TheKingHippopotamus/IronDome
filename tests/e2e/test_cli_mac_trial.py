"""What a person found by using the final build by hand on a Mac, kept as tests.

Two trials on a Linux machine came first. This one was run on a Mac, against
its real Secure Enclave, in a throwaway home: the published texts, the release
wheel and no source code. Each test does what the person did, through the real
command line. (The backup mark of the device directory is in
``tests/unit/test_paths.py``, the helper that was never rebuilt and the advice
to enrol Touch ID in ``tests/unit/test_device_macos_se.py``, the two Unicode
forms of a name in ``tests/unit/test_vault.py``, what ``doctor`` says in
``tests/unit/test_doctor.py``, the notice ``verify`` gives in
``tests/unit/test_selftest.py``.)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable

import pytest

from conftest import PASSWORD
from support.claimkit import add, fails, init, irondome_dirs, ok

CLI = Callable[..., "subprocess.CompletedProcess[str]"]

NFC, NFD = "café", "café"  # one word: the accented letter as one code point, or as two


# -- nuke says what a copy of the device folder can still do ----------------------------------------------


def test_nuke_names_the_copy_it_cannot_reach(cli: CLI) -> None:
    """Both folders copied aside and copied back after ``nuke`` opened the vault again; nuke had said no copy would."""
    init(cli, "--no-recovery")
    result = ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", stdin=PASSWORD + "\n"))
    said = " ".join((result.stdout + result.stderr).split())
    assert "the device keys were files in " + str(irondome_dirs()["device"]) in said
    assert "A backup, clone or disk snapshot made before now that holds that folder together with the vault" in said
    assert ("out of Time Machine" in said) == (sys.platform == "darwin")
    again = json.loads(ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", "--json")).stdout)
    assert again["nothing_to_do"] is True  # and with nothing destroyed there is nothing to warn about


def test_nuke_gives_the_same_warning_in_json(cli: CLI) -> None:
    init(cli, "--no-recovery")
    done = json.loads(
        ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", "--json", stdin=PASSWORD + "\n")).stdout
    )
    assert "A backup, clone or disk snapshot made before now" in done["device_copy_caveat"]


# -- a key file that cannot be the key is not "present" -----------------------------------------------------


def test_status_and_doctor_tell_a_cut_off_device_key_file(cli: CLI) -> None:
    init(cli, "--no-recovery")
    (key,) = (irondome_dirs()["device"] / "bunkers" / "alpha").glob("*.key")
    key.write_bytes(key.read_bytes()[:7])
    status = ok(cli("status")).stdout
    assert "device key file DAMAGED: this keyslot cannot open" in status and "device key present" not in status
    doctor = cli("doctor")
    assert doctor.returncode == 1
    assert "DAMAGED" in doctor.stdout and "problem  device-keys" in doctor.stdout
    assert "irondome recovery use" in doctor.stdout
    shown = ok(cli("auth", "show")).stdout
    assert "DAMAGED" in shown and "present" not in shown


# -- one name, whichever way its accent was typed -----------------------------------------------------------


def test_a_name_typed_in_two_unicode_forms_is_one_entry(cli: CLI) -> None:
    """``add café`` typed and ``add café`` pasted made two rows that looked the same, each with its own password."""
    init(cli, "--no-recovery")
    add(cli, NFD, "the-one-value")
    again = fails(cli("add", NFC, "--generate", "--password-stdin", stdin=PASSWORD + "\n"), 2)
    assert "already" in again.stderr
    for typed in (NFC, NFD):
        assert ok(cli("get", typed, "--password-stdin", stdin=PASSWORD + "\n")).stdout == "the-one-value"
    listed = json.loads(ok(cli("ls", "--json", "--password-stdin", stdin=PASSWORD + "\n")).stdout)
    assert [entry["name"] for entry in listed["entries"]] == [NFC]


def test_an_imported_name_in_the_other_unicode_form_meets_the_entry_that_is_there(cli: CLI, isolated: Path) -> None:
    """The importer compared names by letter case alone: the twin was neither renamed nor replaced, but dropped."""
    init(cli, "--no-recovery")
    add(cli, NFC, "the-value-that-is-there")
    table = isolated / "other-manager.csv"
    table.write_text(f"Title;Username;Password;URL;Notes\n{NFD};me;the-imported-value;;\n", encoding="utf-8")
    ok(cli("import", str(table), "--on-conflict", "replace", "--password-stdin", stdin=PASSWORD + "\n"))
    assert ok(cli("get", NFC, "--password-stdin", stdin=PASSWORD + "\n")).stdout == "the-imported-value"
    table.write_text(f"Title;Username;Password;URL;Notes\n{NFD};me;a-third-value;;\n", encoding="utf-8")
    ok(cli("import", str(table), "--password-stdin", stdin=PASSWORD + "\n"))  # the default: renamed, both kept
    listed = json.loads(ok(cli("ls", "--json", "--password-stdin", stdin=PASSWORD + "\n")).stdout)
    assert sorted(entry["name"] for entry in listed["entries"]) == [NFC, NFC + " (imported)"]


# -- a closed stdout is not a traceback ---------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="a POSIX shell closes the stream")
@pytest.mark.parametrize("closed", [">&-", "2>&-", "<&-", ">&- 2>&-"])
def test_a_closed_standard_stream_is_not_a_traceback(cli: CLI, closed: str) -> None:
    """``irondome status >&-`` ended in ``AttributeError: 'NoneType' object has no attribute 'write'``."""
    init(cli, "--no-recovery")
    for command in ("status", "doctor", "ls --password-stdin"):
        result = subprocess.run(
            ["/bin/sh", "-c", f'exec "$0" -m irondome {command} {closed}', sys.executable],
            input="" if "<&-" in closed else PASSWORD + "\n", capture_output=True, text=True, timeout=120,
        )
        assert "Traceback" not in result.stderr and "NoneType" not in result.stderr, result.stderr
        assert result.returncode in (0, 1, 2, 4), (command, closed, result.returncode, result.stderr)


# -- small things said wrongly ------------------------------------------------------------------------------


def test_a_grant_for_one_minute_is_not_announced_as_59_seconds(cli: CLI) -> None:
    init(cli, "--no-recovery")
    add(cli, "stripe", "sk_live_0123456789abcdef")
    made = ok(cli("grant", "create", "stripe", "--ttl", "1m", "--password-stdin", stdin=PASSWORD + "\n"))
    assert ", in 60s" in made.stderr + made.stdout and "in 59s" not in made.stderr + made.stdout


def test_the_help_of_bunker_create_gives_the_whole_name_rule(cli: CLI) -> None:
    shown = " ".join(ok(cli("bunker", "create", "--help")).stdout.split())
    assert "a lower-case letter, then lower-case letters, digits or hyphens (32 characters at most)" in shown
    assert fails(cli("bunker", "create", "Bravo", "--password-stdin", stdin=PASSWORD + "\n"), 2)


def test_backup_ls_over_a_missing_vault_reads_as_a_sentence(cli: CLI) -> None:
    init(cli, "--no-recovery")
    add(cli, "one", "value-number-one")
    (irondome_dirs()["home"] / "bunkers" / "alpha" / "vault.irondome").write_bytes(b"not a vault")
    listed = cli("backup", "ls", "--password-stdin", stdin=PASSWORD + "\n")
    assert "the vault itself is missing or unreadable" in listed.stdout + listed.stderr
    assert "is at missing" not in listed.stdout + listed.stderr


# -- the by-hand Touch ID run: a vault that would need a touch is not started where none may be asked for ---


@pytest.mark.parametrize("mode", ["touchid", "touchid+password"])
@pytest.mark.parametrize("how", ["flag", "environment"])
def test_init_in_a_touch_id_mode_is_refused_up_front_where_the_prompt_is_forbidden(
    cli: CLI, mode: str, how: str
) -> None:
    """The owner chose never to be asked: no vault is made or half made, and the error names the switch."""
    arguments = ["init", "--mode", mode, "--password-stdin"] + (["--no-touch"] if how == "flag" else [])
    env = {"IRONDOME_NO_TOUCH": "1"} if how == "environment" else {}
    result = fails(cli(*arguments, stdin=PASSWORD + "\n", env=env), 2)
    switch = "--no-touch" if how == "flag" else "IRONDOME_NO_TOUCH=1"
    assert f"{switch} forbids the Touch ID prompt that enrolling needs" in result.stderr
    assert not list(irondome_dirs()["home"].rglob("vault.irondome"))


def test_auth_touchid_is_refused_by_the_environment_switch_as_by_the_flag(cli: CLI) -> None:
    init(cli, "--no-recovery")
    result = fails(cli("auth", "touchid", "--password-stdin", stdin=PASSWORD + "\n", env={"IRONDOME_NO_TOUCH": "1"}), 2)
    assert "IRONDOME_NO_TOUCH=1 forbids the Touch ID prompt that enrolling needs" in result.stderr


def test_a_second_bunker_in_a_touch_id_mode_is_refused_before_the_password_is_asked_for(cli: CLI) -> None:
    """``bunker create`` proves the owner with the first bunker's password; the refusal comes before that."""
    init(cli, "--no-recovery")
    result = fails(cli("bunker", "create", "bravo", "--mode", "touchid", "--no-touch", "--password-stdin"), 2)
    assert "--no-touch forbids the Touch ID prompt that enrolling needs" in result.stderr  # and no password was read

