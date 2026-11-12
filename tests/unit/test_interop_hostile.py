"""interop: what a hostile or merely unusual export can and cannot do (red-team findings of the 4.0 review).

* malicious-file:2  an alias in IronDome's JSON is a valid alias name, or the file is refused, and the
  refusal never carries the alias's text raw;
* dataloss:1        a web address comes back from CSV exactly as it was, spaces included;
* dataloss:0        what IronDome's CSV loses is exactly what ``interop.dump`` says it loses.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any, Dict, List

import pytest

from irondome import interop
from irondome.errors import UsageError
from irondome.interop import ImportedEntry

CONTROLS = ("\x1b", "\x07", "\x9b", "\r", "\n", "‮")


def irondome_json(aliases: Dict[str, Any]) -> str:
    return json.dumps(
        {"format": interop.EXPORT_FORMAT, "version": 1,
         "entries": [{"name": "ok", "password": "p"}, {"name": "helper", "password": "p", "aliases": aliases}]}
    )


@pytest.mark.parametrize(
    "alias",
    [
        "\x1b]0;PWNED-TITLE\x07\x1b[2K\rFAKE: all good\x1b[0m",
        "\x1b]52;c;ZWNobyBwd25lZA==\x07",
        "\x9b2K\rC1-CSI",
        "TOKEN\n",
        "has space",
        "a/b",
        "1abc",
        "gh‮TOKEN",
        "x" * 129,
        "",
    ],
    ids=repr,
)
def test_an_alias_that_is_not_an_alias_name_refuses_the_file(alias: str) -> None:
    with pytest.raises(UsageError) as refused:
        interop.parse(irondome_json({alias: "password"}), "json")
    message = str(refused.value)
    assert "entry 2" in message and "is not an alias" in message
    assert not any(char in message for char in CONTROLS), repr(message)


def test_valid_aliases_still_come_through() -> None:
    (_ok, helper) = interop.parse(irondome_json({"GITHUB_TOKEN": "password", "gh.user-2": "username"}), "json")
    assert helper.aliases == [("GITHUB_TOKEN", "password"), ("gh.user-2", "username")]


ADDRESSES = [" https://b.example ", "https://c.example\xa0", "　https://d.example", "   ", "\thttps://e.example"]


@pytest.mark.parametrize("address", ADDRESSES, ids=repr)
def test_a_web_address_comes_back_from_irondome_csv_exactly(address: str) -> None:
    entry = ImportedEntry(name="spaces", username="lead", password="value-1", url=address)
    (back,) = interop.parse(interop.dump([entry], "csv"), "csv")
    expected = interop.parse(interop.dump([entry], "json"), "json")[0].url  # what the vault would hold
    assert back.url == expected


@pytest.mark.parametrize(
    "fmt, text",
    [
        ("chrome", "name,url,username,password\r\nsite, https://b.example ,u,p\r\n"),
        ("firefox", "url,username,password,httpRealm,formActionOrigin,guid\n https://b.example ,u,p,,,{1}\n"),
        ("1password", "Title,Website,Username,Password,Favorite status\nsite, https://b.example ,u,p,\n"),
        ("csv", "name;url;username;password\nsite; https://b.example ;u;p\n"),
    ],
)
def test_other_managers_addresses_are_kept_as_written(fmt: str, text: str) -> None:
    (entry,) = interop.parse(text, fmt)
    assert entry.url == " https://b.example " and entry.cleaned == []


def test_a_bitwarden_address_list_is_still_split_and_each_address_trimmed() -> None:
    text = (
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
        'Work,,login,GitLab,,,0," https://a.example , https://b.example ",dev,pw,\n'
    )
    (entry,) = interop.parse(text, "bitwarden")
    assert entry.url == "https://a.example" and entry.fields == {"url_2": "https://b.example"}


def _everything() -> List[ImportedEntry]:
    return [
        ImportedEntry(
            name="svc", username="u ", password="p", url=" https://svc.example ", notes="line 1\nline 2",
            totp="otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", tags=["work", "prod"],
            fields={"email": "x@y", "empty": ""}, kind="secret", created=1_600_000_000, modified=1_650_000_000,
            history=[{"password": "old", "retired": 1_620_000_000}], aliases=[("SVC", "password")],
        ),
        ImportedEntry(name="other", password="q", fields={"email": ""}),
    ]


def test_csv_loses_exactly_what_dump_says_and_nothing_else() -> None:
    """History, aliases, created and modified times, and custom fields with no value; never anything else."""
    entries = _everything()
    back = interop.parse(interop.dump(entries, "csv"), "csv")
    lost = {"history": [], "aliases": [], "created": None, "modified": None, "origin": ""}
    for before, after in zip(entries, back):
        expected = dataclasses.replace(before, **lost)
        expected.fields = {name: value for name, value in before.fields.items() if value}
        assert dataclasses.replace(after, origin="") == expected
    assert interop.parse(interop.dump(entries, "json"), "json") == [  # and JSON loses nothing
        dataclasses.replace(entry, origin=f"entry {number}") for number, entry in enumerate(entries, start=1)
    ]
    documented = " ".join((interop.dump.__doc__ or "").split())
    for loss in ("the history", "the aliases", "the created and modified times", "custom fields that have no value"):
        assert loss in documented
    module = " ".join((interop.__doc__ or "").split())
    assert "a custom field with no value" in module and "created and last changed" in module
