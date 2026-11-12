"""Importing a file somebody else wrote: it may add entries, never change what the owner's references hand out.

Every case here is a red-team finding of the 4.0 release review, reproduced end to end through the real
command line (``python -m irondome`` in a subprocess, inside the isolated directories of ``conftest.py``):

* malicious-file:0  an imported entry named ``github/password`` (or a case or casefold variant of it) took
  over every reference to the password of ``github``;
* malicious-file:1  an imported alias took over an entry of the same name that the owner added later;
* malicious-file:2  alias names and entry names from the file reached the terminal raw: escape sequences that
  retitle the window, rewrite lines or fill the clipboard;
* dataloss:0        a CSV export lost custom fields with no value, and nothing said so;
* dataloss:1        a CSV import trimmed the spaces around a web address.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from conftest import PASSWORD, secret
from irondome.unlock import create_vault, open_vault
from irondome.vault import Secret

CLI = Callable[..., "subprocess.CompletedProcess[str]"]

OWNER_GITHUB = "OWNER-GITHUB-TOKEN-1"
OWNER_DB_URL = "postgres://db.internal.example:5432/prod"
OWNER_DB_PASSWORD = "OWNER-REAL-DB-PASSWORD-2"
OWNER_STRIPE = "OWNER-STRIPE-KEY-3"
ATTACKER = "ATTACKER-VALUE-"

#: What a terminal acts on: ESC, BEL, the C1 control introducer and a right-to-left override.
TERMINAL_CONTROLS = ("\x1b", "\x07", "\x9b", "‮")


def ok(result: "subprocess.CompletedProcess[str]", code: int = 0) -> "subprocess.CompletedProcess[str]":
    assert result.returncode == code, f"exit {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    return result


def owner(cli: CLI, *args: str, more: str = "") -> "subprocess.CompletedProcess[str]":
    """A command run by the vault's owner: the master password on the first line of stdin."""
    return cli("--password-stdin", *args, stdin=PASSWORD + "\n" + more)


def make_vault(entries: Dict[str, Dict[str, Any]], aliases: Optional[Dict[str, str]] = None) -> None:
    key = secret(PASSWORD)
    try:
        vault, _recovery = create_vault(password=key, with_recovery=False)
    finally:
        key.wipe()
    try:
        made = {}
        for name, item in entries.items():
            item = dict(item)
            password = item.pop("password", "")
            fields = item.pop("fields", {})
            made[name] = vault.add(name, Secret(password=password, fields=fields), **item)
        for alias, name in (aliases or {}).items():
            vault.set_alias(alias, made[name])
        vault.commit()
    finally:
        vault.close()


def values() -> Dict[str, Dict[str, Any]]:
    key = secret(PASSWORD)
    try:
        vault = open_vault(password=key, interactive=False, allow_touch=False)
    finally:
        key.wipe()
    try:
        found = {}
        for entry in vault.list():
            stored = vault.read_secret(entry)
            found[entry.name] = {"password": stored.password, "url": entry.url, "fields": dict(stored.fields)}
        found["(aliases)"] = {name: vault.entries[alias.entry].name for name, alias in vault.aliases.items()}
        return found
    finally:
        vault.close()


def export_file(tmp: Path, entries: List[Dict[str, Any]], name: str = "hostile.json") -> Path:
    path = tmp / name
    path.write_text(json.dumps({"format": "irondome-export", "version": 1, "entries": entries}), encoding="utf-8")
    return path


def get(cli: CLI, reference: str) -> "subprocess.CompletedProcess[str]":
    return owner(cli, "get", reference)


# ---------------------------------------------------------------------------
# malicious-file:0
# ---------------------------------------------------------------------------


def test_an_imported_entry_cannot_take_over_a_reference_to_another_entrys_field(cli: CLI, isolated: Path) -> None:
    make_vault({
        "github": {"password": OWNER_GITHUB},
        "prod-db": {"password": OWNER_DB_PASSWORD, "url": OWNER_DB_URL},
        "stripe": {"password": OWNER_STRIPE},
    })
    hostile = export_file(isolated, [
        {"name": "github/password", "password": ATTACKER + "1"},
        {"name": "Prod-DB/URL", "password": "postgres://collector.attacker.invalid:5432/loot"},
        {"name": "stripe/paſsword", "password": ATTACKER + "3"},  # U+017F long s casefolds to s
    ])
    result = ok(owner(cli, "--json", "import", str(hostile)))
    report = json.loads(result.stdout)
    assert (report["imported"], report["renamed"], report["skipped"]) == (3, 3, 0)
    for outcome in report["entries"]:
        assert outcome["action"] == "renamed" and outcome["name"].endswith(" (imported)")
        assert "already means the field" in outcome["reason"]
    assert ok(get(cli, "github/password")).stdout.strip() == OWNER_GITHUB
    assert ok(get(cli, "irondome://prod-db/url")).stdout.strip() == OWNER_DB_URL
    assert ok(get(cli, "stripe/password")).stdout.strip() == OWNER_STRIPE
    # The imported values are there, under names that mean nothing else.
    assert ok(get(cli, "github/password (imported)")).stdout.strip() == ATTACKER + "1"


def test_the_import_table_says_why_an_entry_was_renamed(cli: CLI, isolated: Path) -> None:
    make_vault({"github": {"password": OWNER_GITHUB}})
    hostile = export_file(isolated, [{"name": "GitHub/Password", "password": ATTACKER + "1"}])
    result = ok(owner(cli, "import", str(hostile)))
    assert "renamed" in result.stdout and "already means the field 'Password' of 'github'" in result.stdout
    assert ok(get(cli, "github/password")).stdout.strip() == OWNER_GITHUB
    again = json.loads(ok(owner(cli, "--json", "import", str(hostile))).stdout)
    assert [(item["action"], item["reason"]) for item in again["entries"]] == [("skipped", "already in the vault")]
    skipped = json.loads(ok(owner(cli, "--json", "import", str(hostile), "--on-conflict", "skip")).stdout)
    (outcome,) = skipped["entries"]
    assert outcome["action"] == "skipped" and "already means the field" in outcome["reason"]


# ---------------------------------------------------------------------------
# malicious-file:1
# ---------------------------------------------------------------------------


def test_an_imported_alias_cannot_take_over_an_entry_the_owner_adds_later(cli: CLI, isolated: Path) -> None:
    make_vault({"stripe-staging": {"password": "staging-value"}})
    hostile = export_file(isolated, [
        {"name": "helper", "password": ATTACKER + "2", "aliases": {"aws-prod": "password", "stripe-live": "password"}},
    ])
    assert json.loads(ok(owner(cli, "--json", "import", str(hostile))).stdout)["aliases"] == 2
    added = owner(cli, "add", "aws-prod", "--value-stdin", more="OWNER-AWS-SECRET-4\n")
    assert added.returncode == 2, added.stderr
    assert "the alias aws-prod (it points at 'helper') has that name" in added.stderr
    assert "irondome alias rm" in added.stderr
    renamed = owner(cli, "edit", "stripe-staging", "--name", "stripe-live")
    assert renamed.returncode == 2 and "the alias stripe-live" in renamed.stderr
    found = values()
    assert "aws-prod" not in found and "stripe-live" not in found and "stripe-staging" in found
    assert "OWNER-AWS-SECRET-4" not in json.dumps(found)  # nothing of the owner's went in under that name


def test_a_vault_already_holding_an_alias_and_an_entry_of_one_name_answers_neither(cli: CLI) -> None:
    """A vault written by an earlier build may hold both: `get` names the two, it does not pick one."""
    make_vault({"helper": {"password": ATTACKER + "2"}}, {"aws-prod": "helper"})
    key = secret(PASSWORD)
    try:
        vault = open_vault(password=key, interactive=False, allow_touch=False)
    finally:
        key.wipe()
    try:
        vault._add("aws-prod", Secret(password="OWNER-AWS-SECRET-4"), username="", url="", tags=None,
                   kind="login", agent="deny", entry_id=None, created=None, modified=None)
        vault.commit()
    finally:
        vault.close()
    refused = get(cli, "aws-prod")
    assert refused.returncode == 2 and refused.stdout == ""
    assert "could mean the alias aws-prod" in refused.stderr and "the entry 'aws-prod'" in refused.stderr


# ---------------------------------------------------------------------------
# malicious-file:2
# ---------------------------------------------------------------------------


def _no_terminal_controls(result: "subprocess.CompletedProcess[str]") -> None:
    for char in TERMINAL_CONTROLS:
        assert char not in result.stdout, f"{char!r} reached stdout: {result.stdout!r}"
        assert char not in result.stderr, f"{char!r} reached stderr: {result.stderr!r}"


def test_an_alias_holding_escape_sequences_is_refused_and_never_printed(cli: CLI, isolated: Path) -> None:
    make_vault({"github": {"password": OWNER_GITHUB}})
    before = values()
    hostile = export_file(isolated, [{
        "name": "helper", "password": ATTACKER + "2",
        "aliases": {
            "\x1b]0;PWNED-TITLE\x07\x1b[2K\rFAKE: all good\x1b[0m": "password",
            "\x1b]52;c;ZWNobyBwd25lZA==\x07": "password",
            "\x9b2K\rC1-CSI": "password",
        },
    }])
    for json_mode in ([], ["--json"]):
        result = owner(cli, *json_mode, "import", str(hostile))
        assert result.returncode == 2, result.stderr
        assert "entry 1" in result.stderr and "is not an alias" in result.stderr
        _no_terminal_controls(result)
    assert values() == before  # refused before anything was written


def test_names_from_the_file_reach_the_terminal_escaped(cli: CLI, isolated: Path) -> None:
    """A right-to-left override in an imported name, in the warnings, the table and the JSON report."""
    make_vault({"evil‮gnp.exe": {"password": "taken"}})
    hostile = export_file(isolated, [
        {"name": "evil‮gnp.exe", "password": "other", "totp": "otpauth://totp/x?secret=NOT-BASE32!"},
    ])
    text = ok(owner(cli, "import", str(hostile)))
    _no_terminal_controls(text)
    assert "evil\\u202egnp.exe" in text.stderr  # the warning about the one-time-password secret
    assert "evil\\u202egnp.exe" in text.stdout  # the table of renamed entries
    shown = ok(owner(cli, "--json", "import", str(hostile), "--on-conflict", "skip"))
    assert all("‮" not in warning for warning in json.loads(shown.stdout)["warnings"])
    _no_terminal_controls(subprocess.CompletedProcess(shown.args, 0, "", shown.stderr))


# ---------------------------------------------------------------------------
# dataloss:0 and dataloss:1
# ---------------------------------------------------------------------------


def test_a_csv_export_says_what_csv_cannot_carry(cli: CLI, isolated: Path) -> None:
    make_vault({"svc": {"password": "p", "fields": {"email": "x@y", "empty": ""}}}, {"SVC": "svc"})
    target = isolated / "plain.csv"
    result = ok(owner(cli, "export", str(target), "--plaintext", "csv", "--yes"))
    assert "CSV cannot carry" in result.stderr
    assert "1 custom field with no value" in result.stderr and "1 alias" in result.stderr
    assert "when each entry was created and changed" in result.stderr and "--plaintext json" in result.stderr
    exact = ok(owner(cli, "export", str(isolated / "plain.json"), "--plaintext", "json", "--yes"))
    assert "CSV cannot carry" not in exact.stderr


def test_a_csv_round_trip_keeps_a_web_address_exactly(cli: CLI, isolated: Path) -> None:
    make_vault({"spaces": {"password": "value-1", "url": " https://b.example "}})
    target = isolated / "plain.csv"
    ok(owner(cli, "export", str(target), "--plaintext", "csv", "--yes"))
    again = json.loads(ok(owner(cli, "--json", "import", str(target))).stdout)
    (outcome,) = again["entries"]
    assert (outcome["action"], outcome["reason"]) == ("skipped", "already in the vault")  # not a duplicate
    assert values()["spaces"]["url"] == " https://b.example "


def test_a_totp_secret_that_cannot_be_read_is_reported_once(cli: CLI, isolated: Path) -> None:
    """The warning names the entry, escaped, and the custom field the text was kept in; never the text."""
    make_vault({})
    bad = "otpauth://totp/x?secret=NOT-BASE32!"
    hostile = export_file(isolated, [{"name": "bank", "password": "pin", "totp": bad}])
    result = ok(owner(cli, "import", str(hostile)))
    assert result.stderr.count("one-time-password secret could not be read") == 1
    assert "totp_unparsed" in result.stderr and bad not in result.stderr + result.stdout
    assert values()["bank"]["fields"] == {"totp_unparsed": bad}
