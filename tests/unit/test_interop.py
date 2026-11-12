"""interop: other password managers' exports in, IronDome's own plaintext exports out.

The sample exports below are written the way each exporter writes them
(column order, quoting, byte order marks, the shape of each JSON item), with
made-up credentials. Nothing here reads a vault, except one test that writes
a portable backup to check that it is recognised and not parsed.
"""

from __future__ import annotations

import csv
import json
import os
import stat
from pathlib import Path
from typing import Any, Dict, List

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from irondome import interop
from irondome.errors import UsageError
from irondome.interop import ImportedEntry
from irondome.vault import FIELDS, validate_name

PROPERTY = settings(database=None, deadline=None, max_examples=150)
FUZZ = settings(database=None, deadline=None, max_examples=400)
PARSEABLE = ("auto", "json", "csv", "bitwarden", "1password", "chrome", "firefox")

# ---------------------------------------------------------------------------
# Sample exports
# ---------------------------------------------------------------------------

CHROME_CSV = (
    "name,url,username,password,note\r\n"
    "accounts.google.com,https://accounts.google.com/signin/v2,alice@gmail.com,G-Example-1,\r\n"
    'github.com,https://github.com/session,alice,"pa,ss""word\nsecond line",\r\n'
    "github.com,https://github.com/session,bob,Bob-Pass-2,shared machine\r\n"
    ",android://abc123@com.example.app/,alice,=HYPERLINK(\"http://evil.example\"),\r\n"
)

CHROME_OLD_CSV = "name,url,username,password\nexample.com,https://example.com/,user,Old-Chrome-1\n"

FIREFOX_CSV = (
    '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed",'
    '"timePasswordChanged"\r\n'
    '"https://accounts.firefox.com","fox@example.com","Fx-Example-1",,"https://accounts.firefox.com",'
    '"{0b0b0b0b-1111-2222-3333-444444444444}","1700000000000","1700000100000","1700000200000"\r\n'
    '"https://intranet.example","admin","Intra, ""2""","Intranet Realm",,'
    '"{5c5c5c5c-1111-2222-3333-444444444444}","1600000000000","1600000000000","1600000000000"\r\n'
)

ONEPASSWORD_CSV = (
    "Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\n"
    "Amazon,https://www.amazon.com,shopper@example.com,Amz-Example-1,,Not favorite,Not archived,shopping,\n"
    "Slack,https://example.slack.com,me@example.com,Slack-Example-2,"
    "otpauth://totp/Slack:me%40example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Slack,Favorite,Not archived,"
    '"work,chat","Line one\nLine two"\n'
)

BITWARDEN_CSV = (
    "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
    'Work,1,login,GitLab,"Self-hosted, behind the VPN","Team: platform\nPager: +1 555 0100",0,'
    '"https://gitlab.example.com,https://gitlab.example.com/users/sign_in",dev@example.com,'
    '"Gl-""quoted"",pass",JBSWY3DPEHPK3PXP\n'
    ',,note,Alarm code,"1234, then #",,0,,,,\n'
    "Personal,,login,Bank,,,1,https://bank.example,me,=SUM(A1:A9),\n"
)

BITWARDEN_JSON = json.dumps(
    {
        "encrypted": False,
        "folders": [
            {"id": "4a8f6c1e-0000-4000-8000-000000000001", "name": "Work"},
            {"id": "4a8f6c1e-0000-4000-8000-000000000002", "name": "Personal"},
        ],
        "items": [
            {
                "passwordHistory": [
                    {"lastUsedDate": "2024-03-01T09:15:00.000Z", "password": "Old-Pass-1"},
                    {"lastUsedDate": "2023-11-20T18:00:00.000Z", "password": "Older-Pass-0"},
                ],
                "revisionDate": "2024-03-01T09:15:12.345Z",
                "creationDate": "2023-01-10T08:00:00.000Z",
                "deletedDate": None,
                "id": "b1c2d3e4-0000-4000-8000-000000000001",
                "organizationId": None,
                "folderId": "4a8f6c1e-0000-4000-8000-000000000001",
                "type": 1,
                "reprompt": 0,
                "name": "GitHub",
                "notes": "Work account.\nRecovery codes are in the safe.",
                "favorite": True,
                "fields": [
                    {"name": "Recovery email", "value": "ops@example.com", "type": 0, "linkedId": None},
                    {"name": "API token", "value": "ghp_exampleexampleexample", "type": 1, "linkedId": None},
                    {"name": "SSO", "value": "true", "type": 2, "linkedId": None},
                    {"name": "Username", "value": None, "type": 3, "linkedId": 100},
                    {"name": "password", "value": "a field called password", "type": 0, "linkedId": None},
                ],
                "login": {
                    "fido2Credentials": [],
                    "uris": [
                        {"match": None, "uri": "https://github.com/login"},
                        {"match": 0, "uri": "https://github.example.com"},
                    ],
                    "username": "octo-worker",
                    "password": "Gh-Example-Pass-2024!",
                    "totp": "otpauth://totp/GitHub:octo-worker?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
                },
                "collectionIds": None,
            },
            {
                "id": "b1c2d3e4-0000-4000-8000-000000000002",
                "folderId": "4a8f6c1e-0000-4000-8000-000000000002",
                "type": 2,
                "name": "Wi-Fi",
                "notes": "SSID: home\nKey: example-wifi-key",
                "secureNote": {"type": 0},
                "favorite": False,
                "revisionDate": "2024-01-01T00:00:00.000Z",
                "creationDate": "2024-01-01T00:00:00.000Z",
            },
            {
                "id": "b1c2d3e4-0000-4000-8000-000000000003",
                "folderId": None,
                "type": 3,
                "name": "Visa",
                "notes": None,
                "card": {
                    "cardholderName": "A Person",
                    "brand": "Visa",
                    "number": "4111111111111111",
                    "expMonth": "12",
                    "expYear": "2030",
                    "code": "123",
                },
            },
            {
                "id": "b1c2d3e4-0000-4000-8000-000000000004",
                "type": 4,
                "name": "Passport",
                "identity": {
                    "title": "Mx", "firstName": "Alex", "middleName": None, "lastName": "Example",
                    "passportNumber": "X1234567", "username": "alexid", "email": "alex@example.com",
                },
            },
            {
                "id": "b1c2d3e4-0000-4000-8000-000000000005",
                "type": 5,
                "name": "Deploy key",
                "sshKey": {
                    "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
                    "publicKey": "ssh-ed25519 AAAAC3Nza example",
                    "keyFingerprint": "SHA256:abcdef",
                },
            },
            {
                "id": "b1c2d3e4-0000-4000-8000-000000000006",
                "type": 1,
                "name": "GitHub",
                "login": {"username": "octo-personal", "password": "Personal-Pass", "uris": [{"uri": "https://github.com"}]},
            },
        ],
    },
    indent=2,
)

KEEPASSXC_CSV = (
    '"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n'
    '"Root/Servers","nas","root","Nas-Pass-1","https://nas.local","rack 2",'
    '"otpauth://totp/nas?secret=GEZDGNBVGY3TQOJQ","0","2024-01-02T03:04:05Z","2023-01-02T03:04:05Z"\n'
)

SEMICOLON_CSV = 'name;username;password;url;API Key\nrouter;admin;"Router;Pass";http://192.168.1.1;k-1\n'


def by_name(entries: List[ImportedEntry]) -> Dict[str, ImportedEntry]:
    return {entry.name: entry for entry in entries}


def write(tmp_path: Path, name: str, content: Any) -> Path:
    """Write *content* byte for byte: no newline translation (and Path.write_text has no newline= on 3.9)."""
    path = tmp_path / name
    path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
    return path


# ---------------------------------------------------------------------------
# Each format
# ---------------------------------------------------------------------------


def test_chrome_export() -> None:
    entries = interop.parse(CHROME_CSV, "chrome")
    assert [entry.name for entry in entries] == [
        "accounts.google.com", "github.com (alice)", "github.com (bob)", "com.example.app",
    ]
    google, alice, bob, app = entries
    assert (google.username, google.password, google.url) == (
        "alice@gmail.com", "G-Example-1", "https://accounts.google.com/signin/v2",
    )
    assert alice.password == 'pa,ss"word\nsecond line'  # embedded comma, doubled quote, quoted newline
    assert bob.notes == "shared machine"
    assert app.password == '=HYPERLINK("http://evil.example")'  # a formula is data, kept byte for byte
    assert app.url == "android://abc123@com.example.app/"
    assert all(entry.kind == "login" and entry.origin.startswith("row ") for entry in entries)


def test_chrome_export_without_note_column() -> None:
    (entry,) = interop.parse(CHROME_OLD_CSV, "chrome")
    assert (entry.name, entry.password, entry.notes) == ("example.com", "Old-Chrome-1", "")


def test_firefox_export() -> None:
    firefox, intranet = interop.parse(FIREFOX_CSV, "firefox")
    assert firefox.name == "accounts.firefox.com"  # Firefox has no name column: the host stands in
    assert (firefox.username, firefox.password) == ("fox@example.com", "Fx-Example-1")
    assert (firefox.created, firefox.modified) == (1700000000, 1700000200)
    assert intranet.password == 'Intra, "2"'
    assert intranet.fields == {}  # httpRealm, guid and the times are not custom fields


def test_onepassword_export() -> None:
    amazon, slack = interop.parse(ONEPASSWORD_CSV, "1password")
    assert (amazon.name, amazon.url, amazon.tags) == ("Amazon", "https://www.amazon.com", ["shopping"])
    assert amazon.fields == {}  # favourite and archived status are not kept
    assert slack.totp.startswith("otpauth://totp/Slack:")
    assert slack.tags == ["work", "chat"]
    assert slack.notes == "Line one\nLine two"


def test_bitwarden_csv_export() -> None:
    gitlab, alarm, bank = interop.parse(BITWARDEN_CSV, "bitwarden")
    assert gitlab.url == "https://gitlab.example.com"
    assert gitlab.fields == {
        "url_2": "https://gitlab.example.com/users/sign_in", "Team": "platform", "Pager": "+1 555 0100",
    }
    assert gitlab.password == 'Gl-"quoted",pass'
    assert gitlab.totp == "JBSWY3DPEHPK3PXP"
    assert gitlab.tags == ["Work"]
    assert alarm.kind == "secret" and alarm.notes == "1234, then #"
    assert bank.password == "=SUM(A1:A9)"


def test_bitwarden_json_export() -> None:
    entries = by_name(interop.parse(BITWARDEN_JSON, "bitwarden"))
    assert sorted(entries) == [
        "Deploy key", "GitHub (octo-personal)", "GitHub (octo-worker)", "Passport", "Visa", "Wi-Fi",
    ]
    work = entries["GitHub (octo-worker)"]
    assert (work.username, work.password, work.url) == ("octo-worker", "Gh-Example-Pass-2024!", "https://github.com/login")
    assert work.totp.startswith("otpauth://totp/GitHub:octo-worker?")
    assert work.tags == ["Work"]
    assert work.fields == {
        "url_2": "https://github.example.com",
        "Recovery_email": "ops@example.com",
        "API_token": "ghp_exampleexampleexample",
        "SSO": "true",
        "password_2": "a field called password",  # the built-in name is taken by the password itself
    }
    assert [item["password"] for item in work.history] == ["Old-Pass-1", "Older-Pass-0"]
    assert work.history[0]["retired"] == 1709284500
    assert (work.created, work.modified) == (1673337600, 1709284512)
    assert entries["Wi-Fi"].kind == "secret" and entries["Wi-Fi"].tags == ["Personal"]
    assert entries["Visa"].fields == {
        "cardholder": "A Person", "brand": "Visa", "number": "4111111111111111", "expiry_month": "12",
        "expiry_year": "2030", "code": "123",
    }
    passport = entries["Passport"]
    assert passport.username == "alexid" and passport.fields["passport_number"] == "X1234567"
    assert "middle_name" not in passport.fields  # empty values are not kept
    assert entries["Deploy key"].fields["public_key"] == "ssh-ed25519 AAAAC3Nza example"


def test_encrypted_bitwarden_export_is_refused() -> None:
    document = json.dumps({"encrypted": True, "passwordProtected": True, "salt": "x", "data": "y"})
    with pytest.raises(UsageError, match="encrypted Bitwarden export"):
        interop.parse(document, "bitwarden")


def test_generic_csv_from_another_manager() -> None:
    (nas,) = interop.parse(KEEPASSXC_CSV, "csv")
    assert (nas.name, nas.username, nas.password, nas.url, nas.notes) == (
        "nas", "root", "Nas-Pass-1", "https://nas.local", "rack 2",
    )
    assert nas.tags == ["Root/Servers"]
    assert nas.totp == "otpauth://totp/nas?secret=GEZDGNBVGY3TQOJQ"
    assert (nas.created, nas.modified) == (1672628645, 1704164645)
    assert nas.fields == {}  # the icon number is noise


def test_generic_csv_with_semicolons_and_unknown_columns() -> None:
    (router,) = interop.parse(SEMICOLON_CSV, "csv")
    assert (router.name, router.username, router.password, router.url) == (
        "router", "admin", "Router;Pass", "http://192.168.1.1",
    )
    assert router.fields == {"API_Key": "k-1"}  # a column nobody knows is kept as a custom field


def test_generic_csv_needs_a_known_column() -> None:
    with pytest.raises(UsageError, match="names no column IronDome knows"):
        interop.parse("colour,shape\nred,round\n", "csv")


def test_wrong_format_is_named() -> None:
    with pytest.raises(UsageError, match="not a Chrome CSV export"):
        interop.parse(ONEPASSWORD_CSV, "chrome")


def test_irondome_json_round_trip_keeps_everything() -> None:
    entry = ImportedEntry(
        name="github", username="king", password="p", url="https://github.com", notes="n\nm",
        totp="otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", tags=["dev", "Work"], fields={"region": "eu", "empty": ""},
        kind="secret", created=1, modified=2, history=[{"password": "old", "retired": 3}],
        aliases=[("GITHUB_TOKEN", "password"), ("GITHUB_USER", "username")],
    )
    (back,) = interop.parse(interop.dump([entry], "json"), "json")
    assert back == ImportedEntry(**{**entry.__dict__, "origin": "entry 1"})


#: An escape sequence, a bell, DEL, a C1 control (NEL) and a Unicode line separator: what the vault refuses in
#: user names, addresses and tags, because a listing would hand them to the terminal.
_ESC, _BEL, _DEL, _NEL, _LSEP = "\x1b[2J", "\x07", "\x7f", "\x85", " "
_CONTROLLED = {
    "json": json.dumps({
        "format": interop.EXPORT_FORMAT, "version": 1,
        "entries": [{"name": "bank", "username": f"me{_ESC}", "url": f"https://bank.example{_BEL}/",
                     "tags": [f"money{_DEL}box"], "password": f"pass{_ESC}word", "notes": f"a{_ESC}b"}],
    }),
    "csv": (
        "name,username,password,url,tags\r\n"
        f'bank,"me{_ESC}","pass{_ESC}word","https://bank.example{_BEL}/","money{_DEL}box"\r\n'
    ),
    "bitwarden-json": json.dumps({
        "encrypted": False, "folders": [{"id": "f1", "name": f"money{_DEL}box"}],
        "items": [{"type": 1, "name": "bank", "folderId": "f1", "notes": f"a{_ESC}b",
                   "login": {"username": f"me{_ESC}", "password": f"pass{_ESC}word",
                             "uris": [{"uri": f"https://bank.example{_BEL}/"}]}}],
    }),
    "bitwarden": (
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
        f'"money{_DEL}box",,login,bank,,,0,"https://bank.example{_BEL}/","me{_ESC}","pass{_ESC}word",\n'
    ),
    "1password": (
        "Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\n"
        f'bank,"https://bank.example{_BEL}/","me{_ESC}","pass{_ESC}word",,Not favorite,Not archived,'
        f'"money{_DEL}box",\n'
    ),
    "chrome": f'name,url,username,password,note\nbank,"https://bank.example{_BEL}/","me{_NEL}","pass{_ESC}word",\n',
    "firefox": (
        '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed",'
        '"timePasswordChanged"\n'
        f'"https://bank.example{_LSEP}/","me{_ESC}","pass{_ESC}word",,,"{{0b0b}}","1700000000000",'
        '"1700000000000","1700000000000"\n'
    ),
}


@pytest.mark.parametrize("label", sorted(_CONTROLLED))
def test_control_characters_in_user_names_addresses_and_tags_are_dropped_never_the_entry(label: str) -> None:
    """The vault refuses them there; an import keeps the entry, takes them out, and says so in ``cleaned``."""
    fmt = "bitwarden" if label.startswith("bitwarden") else label
    for content in (_CONTROLLED[label], _CONTROLLED[label].encode("utf-8")):
        (entry,) = interop.parse(content, fmt)
        assert interop.parse(content, "auto") == [entry]
        assert entry.password == f"pass{_ESC}word"  # values are never changed
        # Only the control characters go: what follows an ESC is plain text once the ESC is gone.
        assert entry.username == ("me" if label == "chrome" else "me[2J") and entry.url == "https://bank.example/"
        assert set(entry.cleaned) <= {"username", "url", "tags"} and {"username", "url"} <= set(entry.cleaned)
        if label not in ("chrome", "firefox"):
            assert entry.tags == ["money box"] and "tags" in entry.cleaned  # as in names: a space
        if label in ("json", "bitwarden-json"):
            assert entry.notes == f"a{_ESC}b"
        for text in [entry.name, entry.username, entry.url, *entry.tags]:
            assert not any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F or char in "  " for char in text)


def test_an_entry_without_control_characters_is_not_marked_cleaned() -> None:
    (entry,) = interop.parse(CHROME_OLD_CSV, "chrome")
    assert entry.cleaned == []


def test_irondome_json_from_a_newer_version_is_refused() -> None:
    document = json.dumps({"format": interop.EXPORT_FORMAT, "version": interop.EXPORT_VERSION + 1, "entries": []})
    with pytest.raises(UsageError, match="newer IronDome"):
        interop.parse(document, "json")


# ---------------------------------------------------------------------------
# Telling formats apart
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content, expected",
    [
        (CHROME_CSV, "chrome"),
        (CHROME_OLD_CSV, "chrome"),
        (FIREFOX_CSV, "firefox"),
        (ONEPASSWORD_CSV, "1password"),
        (BITWARDEN_CSV, "bitwarden"),
        (BITWARDEN_JSON, "bitwarden"),
        (KEEPASSXC_CSV, "csv"),
        (SEMICOLON_CSV, "csv"),
        (interop.dump([ImportedEntry(name="a")], "json").decode("utf-8"), "json"),
        (interop.dump([ImportedEntry(name="a")], "csv").decode("utf-8"), "csv"),
    ],
    ids=["chrome", "chrome-old", "firefox", "1password", "bitwarden-csv", "bitwarden-json", "keepassxc", "semicolon",
         "irondome-json", "irondome-csv"],
)
def test_detect_format(tmp_path: Path, content: str, expected: str) -> None:
    assert interop.detect_format(content) == expected
    assert interop.detect_format(content.encode("utf-8")) == expected
    assert interop.detect_format(write(tmp_path, "export", content)) == expected
    # and parsing with auto reads what detection names
    assert interop.parse(content, "auto") == interop.parse(content, expected)


def test_portable_backup_is_recognised_and_not_parsed(tmp_path: Path, make_vault: Any) -> None:
    vault, _ = make_vault()
    path = Path(vault.path)
    assert interop.detect_format(path) == interop.FORMAT_IRONDOME
    assert interop.detect_format(path.read_bytes()) == interop.FORMAT_IRONDOME
    with pytest.raises(UsageError, match="opened with its password"):
        interop.parse(path, "auto")
    with pytest.raises(UsageError):
        interop.parse(path, interop.FORMAT_IRONDOME)


def test_unrecognised_inputs() -> None:
    for content in ("", "\n\n", "just some words\n", "[]", '{"some": "json"}'):
        with pytest.raises(UsageError):
            interop.detect_format(content)


def test_unknown_format_name() -> None:
    with pytest.raises(UsageError, match="unknown export format"):
        interop.parse(CHROME_CSV, "keepass")


# ---------------------------------------------------------------------------
# Hostile and unusual input
# ---------------------------------------------------------------------------


def test_byte_order_marks_and_utf16() -> None:
    plain = interop.parse(CHROME_CSV, "chrome")
    assert interop.parse("﻿" + CHROME_CSV, "chrome") == plain
    assert interop.parse(b"\xef\xbb\xbf" + CHROME_CSV.encode("utf-8"), "auto") == plain
    assert interop.parse(CHROME_CSV.encode("utf-16"), "auto") == plain  # with its byte order mark


def test_text_that_is_not_utf8_is_refused() -> None:
    with pytest.raises(UsageError, match="not UTF-8 text"):
        interop.parse(b"name,url,username,password\nx,y,z,\xe9t\xe9\n", "chrome")
    with pytest.raises(UsageError, match="NUL characters"):
        interop.parse(CHROME_CSV.encode("utf-16-le"), "chrome")  # UTF-16 without a byte order mark


def test_malformed_csv_names_the_row() -> None:
    with pytest.raises(UsageError, match="row 3 .*cannot be read as CSV"):
        interop.parse('name,url,username,password\na,b,c,d\n"unterminated,b,c,d\n', "chrome")
    with pytest.raises(UsageError, match="row 2 .*cannot be read as CSV"):
        interop.parse('name,url,username,password\n"a"b,c,d,e\n', "chrome")
    with pytest.raises(UsageError, match="row 3 has 6 cells, but the header"):
        interop.parse("name,url,username,password\na,b,c,d\na,b,c,d,e,f\n", "chrome")


def test_trailing_empty_cells_are_tolerated() -> None:
    (entry,) = interop.parse("name,url,username,password\na,https://a.example,c,d,,\n", "chrome")
    assert entry.password == "d"


def test_malformed_json_names_the_item() -> None:
    with pytest.raises(UsageError, match="item 2 is not an object"):
        interop.parse(json.dumps({"encrypted": False, "items": [{"name": "a"}, "b"]}), "bitwarden")
    with pytest.raises(UsageError, match="item 1: name is not text"):
        interop.parse(json.dumps({"items": [{"name": 7}]}), "bitwarden")
    with pytest.raises(UsageError, match="item 1: login is not an object"):
        interop.parse(json.dumps({"items": [{"name": "a", "login": []}]}), "bitwarden")
    with pytest.raises(UsageError, match="entry 1: kind must be login or secret"):
        interop.parse(json.dumps({"format": interop.EXPORT_FORMAT, "version": 1, "entries": [{"kind": "x"}]}), "json")
    with pytest.raises(UsageError, match="not valid JSON"):
        interop.parse('{"items": [', "bitwarden")


def test_deeply_nested_and_huge_numbers_are_refused() -> None:
    with pytest.raises(UsageError):
        interop.parse("[" * 100_000 + "]" * 100_000, "bitwarden")
    with pytest.raises(UsageError):
        interop.parse('{"items": [], "n": ' + "9" * 5000 + "}", "bitwarden")


def test_empty_files() -> None:
    with pytest.raises(UsageError, match="empty"):
        interop.parse("", "chrome")
    assert interop.parse("name,url,username,password\n", "chrome") == []
    assert interop.parse("name,url,username,password\n,,,\n\n", "chrome") == []


def test_names_are_made_valid(tmp_path: Path) -> None:
    rows = [
        "name,url,username,password",
        '"  padded\tname\x7f ",,u,p',
        f"{'x' * 250},,u,p",
        ",https://only.example/path,u,p",
        ",,only-user,p",
        ",,,p",
    ]
    entries = interop.parse("\n".join(rows) + "\n", "chrome")
    names = [entry.name for entry in entries]
    assert names == ["padded name", "x" * 200, "only.example", "only-user", "untitled"]
    for name in names:
        assert validate_name(name) == name


def test_names_with_lone_surrogates_are_repaired() -> None:
    document = '{"format": "irondome-export", "version": 1, "entries": [{"name": "a\\ud800b", "password": "x\\udc00"}]}'
    (entry,) = interop.parse(document, "json")
    assert entry.name == "a�b"
    assert entry.password == "x\udc00"  # values are never changed


def test_duplicate_names_are_told_apart() -> None:
    text = "name,url,username,password\nsite,,alice,1\nSITE,,bob,2\nsite,,alice,3\nsite (alice),,x,4\n"
    assert [entry.name for entry in interop.parse(text, "chrome")] == [
        "site (alice)", "SITE (bob)", "site (alice) (2)", "site (alice) (3)",
    ]


def test_custom_field_names_are_made_valid() -> None:
    document = {
        "items": [
            {
                "name": "x",
                "fields": [
                    {"name": "2fa backup", "value": "a"},
                    {"name": "סיסמה", "value": "b"},
                    {"name": "url", "value": "c"},
                    {"name": "a" * 100, "value": "d"},
                    {"name": "x y", "value": "e"},
                    {"name": "x_y", "value": "f"},
                    {"name": None, "value": "g"},
                ],
            }
        ]
    }
    (entry,) = interop.parse(json.dumps(document), "bitwarden")
    assert entry.fields == {
        "_2fa_backup": "a", "field": "b", "url_2": "c", "a" * 64: "d", "x_y": "e", "x_y_2": "f", "field_2": "g",
    }
    assert not set(entry.fields) & set(FIELDS)


def test_history_is_capped() -> None:
    history = [{"password": f"p{index}", "lastUsedDate": "2024-01-01T00:00:00Z"} for index in range(9)]
    (entry,) = interop.parse(json.dumps({"items": [{"name": "x", "passwordHistory": history}]}), "bitwarden")
    assert [item["password"] for item in entry.history] == ["p0", "p1", "p2", "p3", "p4"]


def test_files_over_50_mb_are_refused_unread(tmp_path: Path) -> None:
    big = tmp_path / "big.csv"
    with open(big, "wb") as handle:
        handle.truncate(interop.MAX_FILE_BYTES + 1)  # sparse: nothing is written, and nothing must be read
    with pytest.raises(UsageError, match="larger than 50 MB"):
        interop.parse(big, "csv")
    with pytest.raises(UsageError, match="larger than 50 MB"):
        interop.detect_format(big)
    with pytest.raises(UsageError, match="larger than 50 MB"):
        interop.parse(b"x" * (interop.MAX_FILE_BYTES + 1), "csv")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_pipe_in_place_of_the_file_cannot_block(tmp_path: Path) -> None:
    fifo = tmp_path / "export.csv"
    os.mkfifo(fifo)
    with pytest.raises(UsageError, match="not a regular file"):
        interop.parse(fifo, "csv")
    with pytest.raises(UsageError, match="not a regular file"):
        interop.detect_format(fifo)


def test_missing_file_and_directory(tmp_path: Path) -> None:
    with pytest.raises(UsageError, match="there is no file"):
        interop.parse(tmp_path / "nothing.csv", "csv")
    with pytest.raises(UsageError, match="not a regular file"):
        interop.parse(tmp_path, "csv")


def test_csv_field_size_limit_is_restored() -> None:
    before = csv.field_size_limit()
    interop.parse("name,url,username,password\na,b,c," + "x" * 200_000 + "\n", "chrome")
    with pytest.raises(UsageError):
        interop.parse('name,url,username,password\n"a', "chrome")
    assert csv.field_size_limit() == before


def test_entry_repr_hides_secrets() -> None:
    entry = ImportedEntry(name="n", password="hunter2", notes="secret note", totp="JBSWY3DPEHPK3PXP",
                          fields={"pin": "1234"}, history=[{"password": "old-one", "retired": 0}])
    shown = repr(entry)
    for secret_value in ("hunter2", "secret note", "JBSWY3DPEHPK3PXP", "1234", "old-one"):
        assert secret_value not in shown


# ---------------------------------------------------------------------------
# dump
# ---------------------------------------------------------------------------


def test_dump_csv_layout() -> None:
    entries = [
        ImportedEntry(name="b", username="u", password="=cmd|' /C calc'!A0", fields={"zeta": "1", "alpha": "2"},
                      tags=["t1", "t2"]),
        ImportedEntry(name="a", kind="secret", notes='multi\nline, "quoted"'),
    ]
    rows = list(csv.reader(interop.dump(entries, "csv").decode("utf-8").splitlines(keepends=True)))
    assert rows[0] == [
        "name", "kind", "username", "password", "url", "notes", "totp", "tags", "field.alpha", "field.zeta",
    ]
    assert rows[1][3] == "=cmd|' /C calc'!A0"  # written as it is: the export is a faithful copy
    back = interop.parse(interop.dump(entries, "csv"), "auto")
    assert back[0].fields == {"zeta": "1", "alpha": "2"} and back[0].tags == ["t1", "t2"]
    assert back[1].notes == 'multi\nline, "quoted"' and back[1].kind == "secret"


def test_dump_refuses_what_csv_cannot_carry() -> None:
    with pytest.raises(UsageError, match="NUL character"):
        interop.dump([ImportedEntry(name="x", password="a\x00b")], "csv")
    with pytest.raises(UsageError, match="not valid Unicode"):
        interop.dump([ImportedEntry(name="x", password="a\udc80b")], "csv")
    with pytest.raises(UsageError):
        interop.dump([ImportedEntry(name="x")], "xml")


def test_dump_json_keeps_text_that_is_not_valid_unicode() -> None:
    entry = ImportedEntry(name="x", password="a\udc80b\x00")
    data = interop.dump([entry], "json")
    data.decode("ascii")  # written as escapes
    (back,) = interop.parse(data, "json")
    assert back.password == "a\udc80b\x00"


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

_NAME_CHARS = st.characters(blacklist_categories=("Cs", "Cc", "Zl", "Zp"))
_VALUE_CHARS = st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00")
_names = st.text(_NAME_CHARS, min_size=1, max_size=30).map(str.strip).filter(bool)
_values = st.text(_VALUE_CHARS, max_size=40)
#: What the vault keeps in a username: anything but control characters (see test_control_characters_...).
_usernames = st.text(st.characters(blacklist_categories=("Cs", "Cc", "Zl", "Zp")), max_size=40)
#: What the vault keeps in a URL, spaces at either end included: a round trip must not trim them (dataloss:1).
_urls = st.text(st.characters(blacklist_categories=("Cs", "Cc", "Zl", "Zp")), max_size=30)
_field_names = st.from_regex(r"[A-Za-z_][A-Za-z0-9_.-]{0,12}", fullmatch=True).filter(lambda name: name not in FIELDS)
_tags = st.lists(
    st.text(st.characters(blacklist_categories=("Cs", "Cc", "Zl", "Zp"), blacklist_characters=",;"), max_size=12)
    .map(str.strip)
    .filter(bool),
    max_size=3,
    unique_by=str.casefold,
)
_times = st.none() | st.integers(min_value=0, max_value=2**40)


@st.composite
def _entries(draw: Any, csv_safe: bool) -> List[ImportedEntry]:
    names = draw(st.lists(_names, min_size=1, max_size=5, unique_by=str.casefold))
    result = []
    for name in names:
        fields = draw(st.dictionaries(_field_names, _values.filter(bool) if csv_safe else _values, max_size=3))
        result.append(
            ImportedEntry(
                name=name,
                username=draw(_usernames),
                password=draw(_values),
                url=draw(_urls),
                notes=draw(_values),
                totp=draw(st.sampled_from(["", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"])),
                tags=draw(_tags),
                fields=fields,
                kind=draw(st.sampled_from(interop.KINDS)),
                created=None if csv_safe else draw(_times),
                modified=None if csv_safe else draw(_times),
                history=[] if csv_safe else draw(
                    st.lists(st.fixed_dictionaries({"password": _values, "retired": st.integers(0, 2**40)}), max_size=5)
                ),
                aliases=[] if csv_safe else draw(
                    st.lists(st.tuples(_field_names, st.sampled_from(["password", "username", "totp"])), max_size=2,
                             unique_by=lambda pair: pair[0])
                ),
            )
        )
    return result


def _without_origin(entries: List[ImportedEntry]) -> List[ImportedEntry]:
    return [ImportedEntry(**{**entry.__dict__, "origin": ""}) for entry in entries]


@PROPERTY
@given(_entries(csv_safe=False))
def test_json_round_trip_is_exact(entries: List[ImportedEntry]) -> None:
    assert _without_origin(interop.parse(interop.dump(entries, "json"), "auto")) == entries


@PROPERTY
@given(_entries(csv_safe=True))
def test_csv_round_trip_keeps_every_column(entries: List[ImportedEntry]) -> None:
    data = interop.dump(entries, "csv")
    assert interop.detect_format(data) == "csv"
    assert _without_origin(interop.parse(data, "csv")) == entries


@FUZZ
@given(st.binary(max_size=1024), st.sampled_from(PARSEABLE))
def test_fuzz_bytes_raise_nothing_but_usage_errors(data: bytes, fmt: str) -> None:
    try:
        interop.parse(data, fmt)
    except UsageError:
        pass
    try:
        interop.detect_format(data)
    except UsageError:
        pass


_CSV_ALPHABET = st.sampled_from(list(',;\t"\n\r =+-@{}[]:/') + ["﻿", "\x00", "é", "a", "b", "1"])


@FUZZ
@given(
    st.lists(st.sampled_from(["name", "url", "username", "password", "note", "title", "tags", "x", "login_uri",
                              "login_username", "login_password", "type", "fields", "timecreated", "field.a"]),
             min_size=1, max_size=8),
    st.lists(st.lists(st.text(_CSV_ALPHABET, max_size=8), max_size=10), max_size=6),
    st.sampled_from(PARSEABLE),
)
def test_fuzz_csv_grids_raise_nothing_but_usage_errors(header: List[str], rows: List[List[str]], fmt: str) -> None:
    text = ",".join(header) + "\n" + "\n".join(",".join(row) for row in rows)
    try:
        for entry in interop.parse(text, fmt):
            validate_name(entry.name)
            assert all(_is_field_name(name) for name in entry.fields)
    except UsageError:
        pass


def _is_field_name(name: str) -> bool:
    return bool(interop._FIELD_NAME.fullmatch(name)) and name not in FIELDS


_json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=8),
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=8), inner, max_size=3),
    max_leaves=12,
)
_item_keys = st.sampled_from(
    ["name", "login", "uris", "uri", "username", "password", "totp", "notes", "fields", "type", "value", "card",
     "identity", "sshKey", "folderId", "passwordHistory", "lastUsedDate", "creationDate", "kind", "tags",
     "aliases", "history", "retired", "created", "url"]
)
_items = st.dictionaries(_item_keys, _json_values, max_size=6)


@FUZZ
@given(st.lists(_items | _json_values, max_size=4), st.sampled_from(["bitwarden", "json", "auto"]))
def test_fuzz_json_items_raise_nothing_but_usage_errors(items: List[Any], fmt: str) -> None:
    for document in (
        {"encrypted": False, "folders": items, "items": items},
        {"format": interop.EXPORT_FORMAT, "version": 1, "entries": items},
    ):
        try:
            for entry in interop.parse(json.dumps(document), fmt):
                validate_name(entry.name)
        except UsageError:
            pass


def test_parse_reads_a_file_only_its_owner_wrote(tmp_path: Path) -> None:
    path = write(tmp_path, "chrome.csv", CHROME_CSV)
    os.chmod(path, stat.S_IRUSR)
    assert len(interop.parse(path, "auto")) == 4
