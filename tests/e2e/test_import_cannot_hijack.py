"""What a hostile import file, or a name chosen later, can no longer do to a reference or to the terminal.

Regression tests for red-team findings, each of which these tests reproduced before the fix:

* malicious-file:0  an imported entry ``github/password`` (or ``Prod-DB/URL``, or ``stripe/paſsword``)
  took over what ``github/password`` handed out, in ``get``, ``run`` and env files;
* malicious-file:1  an imported alias ``aws-prod`` shadowed the entry ``aws-prod`` the owner made later;
* malicious-file:2  escape sequences in an import file's alias names, and bidi controls in its entry
  names, reached the owner's terminal unescaped;
* dataloss:0        a CSV export lost the custom fields that have no value, and nothing said so;
* dataloss:1        a CSV import trimmed the spaces around a web address the vault had kept.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

import pytest

from conftest import PASSWORD, secret
from irondome import interop, paths
from irondome.errors import UsageError
from irondome.unlock import create_vault, open_vault
from irondome.vault import Alias, Secret, Vault

CLI = Callable[..., "subprocess.CompletedProcess[str]"]
#: ESC, BEL, the C1 CSI and RIGHT-TO-LEFT OVERRIDE: none may reach the owner's terminal from a file.
RAW = ("\x1b", "\x07", "\x9b", "‮")


def build(*entries: Tuple[str, Secret, Dict[str, Any]]) -> None:
    """A committed vault in the default bunker holding *entries*: ``(name, secret, keyword arguments of add)``."""
    key = secret(PASSWORD)
    try:
        vault, _ = create_vault(password=key, with_recovery=False)
    finally:
        key.wipe()
    try:
        for name, value, extra in entries:
            vault.add(name, value, **extra)
        vault.commit()
    finally:
        vault.close()


def opened() -> Vault:
    key = secret(PASSWORD)
    try:
        return open_vault(password=key, interactive=False, allow_touch=False)
    finally:
        key.wipe()


def owner(cli: CLI, *args: str, more: str = "") -> "subprocess.CompletedProcess[str]":
    """The command line, run by the owner: the master password on the first line of stdin."""
    return cli("--password-stdin", *args, stdin=PASSWORD + "\n" + more)


def export(path: Path, *entries: Dict[str, Any]) -> Path:
    """An IronDome plaintext JSON export holding *entries*, as anyone can write one."""
    document = {"format": interop.EXPORT_FORMAT, "version": interop.EXPORT_VERSION, "entries": list(entries)}
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_an_imported_entry_cannot_take_over_a_reference(cli: CLI, tmp_path: Path) -> None:
    build(
        ("github", Secret(password="OWNER-GITHUB-TOKEN"), {}),
        ("prod-db", Secret(password="OWNER-DB-PASSWORD"), {"url": "postgres://db.internal.example:5432/prod"}),
        ("stripe", Secret(password="OWNER-STRIPE-KEY"), {}),
    )
    source = export(
        tmp_path / "hostile.json",
        {"name": "github/password", "password": "ATTACKER-GITHUB-TOKEN"},
        {"name": "Prod-DB/URL", "password": "postgres://collector.attacker.invalid:5432/loot"},
        {"name": "stripe/paſsword", "password": "ATTACKER-STRIPE-KEY"},  # U+017F casefolds to 's'
    )
    result = owner(cli, "--json", "import", str(source))
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert (report["imported"], report["renamed"]) == (3, 3), report
    assert all("already means the field" in item["reason"] for item in report["entries"]), report
    for reference, expected in (
        ("github/password", "OWNER-GITHUB-TOKEN"),
        ("irondome://prod-db/url", "postgres://db.internal.example:5432/prod"),
        ("stripe/password", "OWNER-STRIPE-KEY"),
    ):
        got = owner(cli, "get", reference)
        assert (got.returncode, got.stdout.strip()) == (0, expected), (reference, got.stderr)
    with opened() as vault:
        assert {entry.name for entry in vault.list()} >= {
            "github/password (imported)", "Prod-DB/URL (imported)", "stripe/paſsword (imported)"}


def test_a_reference_with_two_meanings_is_refused_never_guessed(make_vault: Callable[..., Any]) -> None:
    """A vault written before the rule may hold both meanings: resolve() refuses rather than pick one."""
    vault, _ = make_vault(with_recovery=False)
    github = vault.add("github", Secret(password="OWNER"))
    helper = vault.add("helper", Secret(password="ATTACKER"))
    with pytest.raises(UsageError, match="reference must mean one thing"):
        vault.add("GitHub/Password", Secret(password="ATTACKER"))
    late = dict(username="", url="", tags=None, kind="login", agent="deny", entry_id=None, created=None, modified=None)
    vault._add("github/password", Secret(password="ATTACKER"), **late)  # as an older build let an import add it
    with pytest.raises(UsageError, match="does not guess"):
        vault.resolve("irondome://github/password")
    vault.aliases["aws-prod"] = Alias(entry=helper.id, field="password")  # imported before aws-prod was made
    with pytest.raises(UsageError, match="alias aws-prod"):
        vault.add("AWS-Prod", Secret(password="OWNER-AWS"))
    vault._add("aws-prod", Secret(password="OWNER-AWS"), **late)
    with pytest.raises(UsageError, match="does not guess"):
        vault.resolve("aws-prod")
    assert vault.resolve("github") == (github, "password")


def test_an_imported_alias_cannot_shadow_an_entry_made_later(cli: CLI, tmp_path: Path) -> None:
    build(("mine", Secret(password="OWNER-OTHER"), {}))
    source = export(tmp_path / "squat.json", {"name": "helper", "password": "ATTACKER-VALUE-2",
                                               "aliases": {"aws-prod": "password", "stripe-live": "password"}})
    assert owner(cli, "import", str(source)).returncode == 0
    added = owner(cli, "add", "aws-prod", "--value-stdin", more="OWNER-AWS-SECRET\n")
    assert added.returncode == 2 and "alias aws-prod" in added.stderr, added.stderr
    assert "OWNER-AWS-SECRET" not in added.stdout + added.stderr
    assert owner(cli, "add", "stripe-staging", "--value-stdin", more="OWNER-STRIPE\n").returncode == 0
    renamed = owner(cli, "edit", "stripe-staging", "--name", "Stripe-Live")
    assert renamed.returncode == 2 and "alias stripe-live" in renamed.stderr, renamed.stderr
    with opened() as vault:
        assert not vault.has_name("aws-prod") and not vault.has_name("stripe-live")
        assert vault.value(vault.find("stripe-staging")) == "OWNER-STRIPE"


def test_an_import_file_cannot_write_to_the_terminal(cli: CLI, tmp_path: Path) -> None:
    build(("mine", Secret(password="OWNER"), {}))
    before = paths.vault_file().read_bytes()
    hostile = export(tmp_path / "escapes.json", {"name": "helper", "password": "x", "aliases": {
        "\x1b]0;PWNED-TITLE\x07\x1b[2K\rFAKE: all good\x1b[0m": "password",
        "\x1b]52;c;ZWNobyBwd25lZA==\x07": "password",  # OSC 52: write the clipboard
        "\x9b2K\rC1-CSI": "password",
    }})
    refused = owner(cli, "import", str(hostile))
    assert refused.returncode == 2 and "is not an alias" in refused.stderr, refused.stderr
    assert not any(char in refused.stdout + refused.stderr for char in RAW), repr(refused.stderr)
    assert paths.vault_file().read_bytes() == before
    bidi = export(tmp_path / "bidi.json", {"name": "‮gnp.exe", "password": "x", "totp": "steam://NOTSUPPORTED"})
    for args in ((), ("--json",)):
        result = owner(cli, *args, "import", str(bidi))
        assert result.returncode == 0, result.stderr
        assert "totp_unparsed" in result.stderr and "\\u202e" in result.stderr, result.stderr
        assert not any(char in result.stderr for char in RAW), repr(result.stderr)


@pytest.mark.parametrize("url", [" https://b.example ", "https://c.example\xa0", "　https://d.example", "   "])
def test_a_csv_import_keeps_a_web_address_exactly(url: str) -> None:
    (back,) = interop.parse(interop.dump([interop.ImportedEntry(name="spaces", url=url)], "csv"), "csv")
    assert (back.url, back.cleaned) == (url, [])
    (chrome,) = interop.parse(f"name,url,username,password\r\nx,{url},u,p\r\n", "chrome")
    assert chrome.url == url


def test_bitwarden_addresses_are_still_split_and_trimmed() -> None:
    text = 'name,login_uri,login_username,login_password\r\nx," https://a.example , https://b.example ",u,p\r\n'
    (entry,) = interop.parse(text, "bitwarden")
    assert (entry.url, entry.fields) == ("https://a.example", {"url_2": "https://b.example"})


def test_a_csv_export_says_what_it_cannot_carry(cli: CLI, tmp_path: Path) -> None:
    build(("svc", Secret(password="p", fields={"email": "x@y", "empty": ""}), {}))
    as_csv = owner(cli, "export", str(tmp_path / "out.csv"), "--plaintext", "csv", "--yes")
    assert as_csv.returncode == 0, as_csv.stderr
    assert "custom field with no value" in as_csv.stderr and "--plaintext json" in as_csv.stderr, as_csv.stderr
    as_json = owner(cli, "export", str(tmp_path / "out.json"), "--plaintext", "json", "--yes")
    assert as_json.returncode == 0 and "cannot carry" not in as_json.stderr, as_json.stderr
    (back,) = interop.parse(tmp_path / "out.json", "json")
    assert back.fields == {"email": "x@y", "empty": ""}
    assert "no value" in (interop.dump.__doc__ or "") and "no value" in (interop.__doc__ or "")
