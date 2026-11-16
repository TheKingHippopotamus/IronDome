"""The vault file and the unlocked vault: what is hidden, what is detected, what survives."""

from __future__ import annotations

import base64
import copy
import errno
import json
import os
import re
import stat
import sys
import threading
import time
import types
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import irondome
from conftest import PASSWORD, secret
from irondome import keys, paths
from irondome.crypto import Argon2Params, b64d, b64e
from irondome.errors import NotFoundError, UsageError, VaultError
from irondome.keys import Keyslot
from irondome.secmem import SecureBuffer
from irondome.vault import (
    AGENT_POLICIES,
    FIELDS,
    FORMAT,
    VERSION,
    Alias,
    Entry,
    Secret,
    Vault,
    VaultFile,
    validate_alias,
    validate_name,
    vault_exists,
    without_control,
)

POSIX = os.name == "posix"
posix_only = pytest.mark.skipif(not POSIX, reason="POSIX permissions")
FAST = Argon2Params(memory_kib=19 * 1024, iterations=2, lanes=4)  # the OWASP minimum


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def within(seconds: float, call: Callable[[], object]) -> object:
    """Run *call* on a thread and fail, rather than hang the suite, if it blocks."""
    box: Dict[str, object] = {}

    def run() -> None:
        try:
            box["value"] = call()
        except BaseException as exc:  # handed back to the test thread below
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        pytest.fail(f"still blocked after {seconds} seconds")
    if "error" in box:
        raise box["error"]  # type: ignore[misc]
    return box.get("value")


class Vaults:
    """Makes vaults that need no password and no device, and closes them all at the end."""

    def __init__(self) -> None:
        self.made: List[Vault] = []

    def new(self, directory: Optional[Path] = None, **kwargs: Any) -> Vault:
        """A fresh vault opened by a recovery key alone: quick to make."""
        vault_id = os.urandom(keys.VAULT_ID_LEN)
        vault_key = keys.new_vault_key()
        slot, _ = keys.create_recovery_slot(vault_key, vault_id)
        path = (directory / "vault.irondome") if directory is not None else None
        vault = Vault.create(vault_key, [slot], vault_id, path, **kwargs)
        self.made.append(vault)
        return vault

    def reopen(self, vault: Vault) -> Vault:
        """Read the file again and open it with a copy of the same key."""
        again = Vault(VaultFile.load(vault.path), vault.vault_key.copy(), vault.path)
        self.made.append(again)
        return again

    def close(self) -> None:
        for vault in self.made:
            vault.close()


@pytest.fixture
def vaults() -> Iterator[Vaults]:
    factory = Vaults()
    yield factory
    factory.close()


@pytest.fixture
def plain(vaults: Vaults) -> Vault:
    """An empty vault at the default location."""
    return vaults.new()


def document_of(vault: Vault) -> Dict[str, Any]:
    return json.loads(vault.path.read_bytes())


def rewrite(vault: Vault, document: Dict[str, Any]) -> None:
    paths.write_atomic(vault.path, json.dumps(document).encode("utf-8"))


def sealed_size(blob: str) -> int:
    return len(base64.b64decode(blob))


def temp_files(directory: Path) -> List[str]:
    return sorted(str(item.relative_to(directory)) for item in directory.rglob(".tmp-*"))


# ---------------------------------------------------------------------------
# The file
# ---------------------------------------------------------------------------


TOP_LEVEL_KEYS = {"format", "version", "vault_id", "created", "generation", "keyslots", "index", "records"}
HEBREW_NAME = "\u05d2\u05d9\u05d8\u05d4\u05d0\u05d1-\u05d4\u05e1\u05d5\u05d3\u05d9"
HEBREW_PASSWORD = "\u05e1\u05d9\u05e1\u05de\u05d4-\u05de\u05d0\u05d5\u05d3-\u05e1\u05d5\u05d3\u05d9\u05ea"
HEBREW_USER = "\u05de\u05e9\u05ea\u05de\u05e9-\u05e1\u05d5\u05d3\u05d9"
HEBREW_TAG = "\u05ea\u05d2\u05d9\u05ea-\u05e1\u05d5\u05d3\u05d9\u05ea"


def test_the_file_is_the_documented_json_document(vault):
    document = document_of(vault)
    assert set(document) == TOP_LEVEL_KEYS
    assert document["format"] == FORMAT == "irondome-vault"
    assert document["version"] == VERSION == 4
    assert len(b64d(document["vault_id"])) == 16 and b64d(document["vault_id"]) == vault.vault_id
    assert document["generation"] == 2  # written once by create, once by the fixture's commit
    assert abs(document["created"] - time.time()) < 300
    assert [slot["kind"] for slot in document["keyslots"]] == ["password", "recovery"]
    assert set(document["records"]) == set(vault.entries) and len(document["records"]) == 2
    assert all(re.fullmatch(r"[0-9a-f]{32}", entry_id) for entry_id in document["records"])
    assert vault.path.read_bytes().endswith(b"\n")
    assert vault.path == paths.vault_file()


# Long or punctuated enough that none can turn up in random base64 by chance.
MARKERS = [
    "github", "hunter2-Github!", "personal", "https://github.com", "GITHUB_TOKEN", "aws/prod", "AKIA-not-a-real-key",
    "eu-west-1", "region", "JBSWY3DPEHPK3PXP", "note-with-a-secret", "MY_ALIAS", "custom-value-42",
    "old-password-one", "new-password-two", "example.invalid", "api_key", "king-of-the-hill", "tag-of-mine",
    HEBREW_NAME, HEBREW_PASSWORD, HEBREW_USER, HEBREW_TAG,
]
HEX32 = re.compile(r"[0-9a-f]{32}")


def test_nothing_about_an_entry_is_readable_in_the_file(vault):
    """Names, usernames, URLs, tags, aliases, notes, fields, TOTP seeds, history: all ciphertext."""
    hebrew = vault.add(
        HEBREW_NAME,
        Secret(password="old-password-one", notes="note-with-a-secret", totp={"secret": "JBSWY3DPEHPK3PXP"},
               fields={"api_key": "custom-value-42"}),
        username=HEBREW_USER, url="https://example.invalid/login", tags=[HEBREW_TAG, "tag-of-mine"],
    )
    vault.update(vault.find("github"), username="king-of-the-hill")
    vault.set_alias("MY_ALIAS", hebrew, "api_key")
    vault.commit()
    vault.update(hebrew, secret=Secret(password=HEBREW_PASSWORD, notes="new-password-two"))
    vault.commit()
    files = [vault.path] + vault.snapshots()
    assert len(files) == 4
    for path in files:
        data = path.read_bytes()
        document = json.loads(data)
        blobs = [base64.b64decode(document["index"])] + [base64.b64decode(r) for r in document["records"].values()]
        for marker in MARKERS:
            for form in (marker.encode("utf-8"), marker.encode("utf-16-le"), base64.b64encode(marker.encode("utf-8"))):
                assert form not in data, (marker, path.name)
                assert all(form not in blob for blob in blobs), (marker, path.name)

        # And structurally: besides the public keyslot table, the file holds
        # nothing but identifiers, counters and sealed blobs of padded size.
        assert set(document) == TOP_LEVEL_KEYS
        assert (len(base64.b64decode(document["index"])) - 28) % 1024 == 0
        for entry_id, record in document["records"].items():
            assert HEX32.fullmatch(entry_id) and (len(base64.b64decode(record)) - 28) % 256 == 0
        for slot in document["keyslots"]:
            assert set(slot) <= {"id", "kind", "created", "label", "wrap", "kdf", "device", "salt"}
            assert HEX32.fullmatch(slot["id"]) and slot["kind"] in ("password", "recovery")
            assert slot["label"] in ("master password", "recovery key")
            assert len(base64.b64decode(slot["wrap"])) == 60
            if "kdf" in slot:
                assert set(slot["kdf"]) == {"alg", "salt", "m", "t", "p"}
            if "device" in slot:
                assert set(slot["device"]) == {"backend", "policy", "ref"}
                assert (slot["device"]["backend"], slot["device"]["policy"]) == ("software", "device")


def test_ciphertext_sizes_do_not_reveal_password_length(plain):
    short = plain.add("short", Secret(password="x"))
    long = plain.add("long", Secret(password="y" * 40))
    empty = plain.add("empty", Secret())
    big = plain.add("big", Secret(password="z" * 300))
    records = plain.file.records
    assert sealed_size(records[short.id]) == sealed_size(records[long.id]) == sealed_size(records[empty.id])
    assert sealed_size(records[big.id]) > sealed_size(records[short.id])
    for blob in records.values():
        assert (sealed_size(blob) - 12 - 16) % 256 == 0  # nonce and tag around whole 256-byte blocks
    assert sealed_size(records[short.id]) == 12 + 256 + 16


def test_the_index_is_padded_too(plain):
    plain.commit()
    before = sealed_size(document_of(plain)["index"])
    plain.add("a", Secret(password="p"), username="someone", url="https://a.invalid", tags=["t"])
    plain.commit()
    after = sealed_size(document_of(plain)["index"])
    assert before == after == 12 + 1024 + 16
    for number in range(12):
        plain.add(f"entry number {number}", Secret(), username="u" * 60, url="https://example.invalid/" + "p" * 60)
    plain.commit()
    grown = sealed_size(document_of(plain)["index"])
    assert grown > after and (grown - 28) % 1024 == 0


def test_every_record_is_sealed_under_its_own_key_and_a_fresh_nonce(plain):
    first = plain.add("first", Secret(password="same password"))
    second = plain.add("second", Secret(password="same password"))
    assert plain.file.records[first.id] != plain.file.records[second.id]
    before = plain.file.records[first.id]
    plain.update(first, secret=Secret(password="same password"))
    assert plain.file.records[first.id] != before
    with plain._entry_key(first.id) as one, plain._entry_key(second.id) as two:
        assert bytes(one.view()) != bytes(two.view())
        assert bytes(one.view()) != bytes(plain.vault_key.view())


# ---------------------------------------------------------------------------
# Tampering is detected
# ---------------------------------------------------------------------------


def test_a_rolled_back_record_is_rejected(vault, vaults):
    """An attacker restores yesterday's ciphertext of one record: the old password must not come back."""
    github = vault.find("github")
    old = document_of(vault)["records"][github.id]
    vault.update(github, secret=Secret(password="the new password"))
    vault.commit()
    tampered = document_of(vault)
    assert tampered["records"][github.id] != old
    tampered["records"][github.id] = old
    rewrite(vault, tampered)
    reopened = vaults.reopen(vault)
    with pytest.raises(VaultError, match="stale copy"):
        reopened.read_secret(reopened.find("github"))
    with pytest.raises(VaultError):
        reopened.value(reopened.find("github"))
    assert reopened.value(reopened.find("aws/prod")) == "AKIA-not-a-real-key"  # the others are untouched


def test_records_swapped_between_entries_are_rejected(vault, vaults):
    github, aws = vault.find("github"), vault.find("aws/prod")
    tampered = document_of(vault)
    records = tampered["records"]
    records[github.id], records[aws.id] = records[aws.id], records[github.id]
    rewrite(vault, tampered)
    reopened = vaults.reopen(vault)
    for name in ("github", "aws/prod"):
        with pytest.raises(VaultError, match="failed authentication"):
            reopened.read_secret(reopened.find(name))


def test_a_deleted_record_is_noticed_when_the_vault_is_opened(vault, vaults):
    github = vault.find("github")
    tampered = document_of(vault)
    del tampered["records"][github.id]
    rewrite(vault, tampered)
    with pytest.raises(VaultError, match="missing the secret record for: github"):
        vaults.reopen(vault)


def test_a_record_from_another_vault_is_rejected(vault, vaults, isolated):
    """Same entry id, same plaintext, different vault: the ciphertext does not transplant."""
    github = vault.find("github")
    other = vaults.new(isolated / "other")
    other.add("github", vault.read_secret(github), entry_id=github.id)
    other.commit()
    tampered = document_of(vault)
    tampered["records"][github.id] = document_of(other)["records"][github.id]
    rewrite(vault, tampered)
    reopened = vaults.reopen(vault)
    with pytest.raises(VaultError, match="failed authentication"):
        reopened.read_secret(reopened.find("github"))


@pytest.mark.parametrize("damage", ["flip", "truncate", "empty", "garbage", "extend"])
def test_a_damaged_record_is_rejected(vault, vaults, damage):
    github = vault.find("github")
    tampered = document_of(vault)
    blob = bytearray(base64.b64decode(tampered["records"][github.id]))
    if damage == "flip":
        blob[len(blob) // 2] ^= 0x01
    elif damage == "truncate":
        blob = blob[:-1]
    elif damage == "empty":
        blob = bytearray()
    elif damage == "garbage":
        blob = bytearray(os.urandom(len(blob)))
    else:
        blob += b"\x00"
    tampered["records"][github.id] = b64e(bytes(blob))
    rewrite(vault, tampered)
    reopened = vaults.reopen(vault)
    with pytest.raises(VaultError):
        reopened.read_secret(reopened.find("github"))


@given(data=st.data())
@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_no_single_byte_change_to_a_record_or_the_index_goes_unnoticed(data, vault):
    document = document_of(vault)
    target = data.draw(st.sampled_from(["index"] + sorted(document["records"])), label="what")
    blob = bytearray(base64.b64decode(document["index"] if target == "index" else document["records"][target]))
    position = data.draw(st.integers(min_value=0, max_value=len(blob) - 1), label="where")
    blob[position] ^= data.draw(st.integers(min_value=1, max_value=255), label="how")
    file = VaultFile.load(vault.path)
    if target == "index":
        file.index = b64e(bytes(blob))
        with pytest.raises(VaultError, match="failed authentication"):
            Vault(file, vault.vault_key.copy(), vault.path)
    else:
        file.records[target] = b64e(bytes(blob))
        opened = Vault(file, vault.vault_key.copy(), vault.path)
        try:
            with pytest.raises(VaultError, match="failed authentication"):
                opened.read_secret(opened.entries[target])
        finally:
            opened.close()


def test_a_tampered_index_is_rejected(vault, vaults):
    original = document_of(vault)
    for change in ("flip", "empty", "garbage"):
        tampered = copy.deepcopy(original)
        blob = bytearray(base64.b64decode(tampered["index"]))
        if change == "flip":
            blob[40] ^= 0x10
        elif change == "empty":
            blob = bytearray()
        else:
            blob = bytearray(os.urandom(len(blob)))
        tampered["index"] = b64e(bytes(blob))
        rewrite(vault, tampered)
        with pytest.raises(VaultError, match="index failed authentication"):
            vaults.reopen(vault)
    rewrite(vault, original)
    vaults.reopen(vault)


def test_an_older_index_does_not_pass_for_the_current_one(vault, vaults):
    """The index is bound to the generation counter: yesterday's index under today's counter fails."""
    old = document_of(vault)
    vault.add("new entry", Secret(password="p"))
    vault.commit()
    current = document_of(vault)
    assert current["generation"] == old["generation"] + 1
    mixed = copy.deepcopy(current)
    mixed["index"] = old["index"]
    rewrite(vault, mixed)
    with pytest.raises(VaultError, match="index failed authentication"):
        vaults.reopen(vault)
    for generation in (old["generation"], current["generation"] + 1, 0):
        renumbered = copy.deepcopy(current)
        renumbered["generation"] = generation
        rewrite(vault, renumbered)
        with pytest.raises(VaultError, match="index failed authentication"):
            vaults.reopen(vault)


def test_an_index_from_another_vault_is_rejected(vault, vaults, isolated):
    other = vaults.new(isolated / "other")
    other.commit()
    tampered = document_of(vault)
    tampered["index"] = document_of(other)["index"]
    rewrite(vault, tampered)
    with pytest.raises(VaultError, match="index failed authentication"):
        vaults.reopen(vault)
    renamed = document_of(vault)
    renamed["vault_id"] = b64e(os.urandom(16))
    rewrite(vault, renamed)
    with pytest.raises(VaultError):
        vaults.reopen(vault)


def test_the_wrong_key_opens_nothing_and_is_wiped(vault):
    wrong = keys.new_vault_key()
    with pytest.raises(VaultError, match="index failed authentication"):
        Vault(VaultFile.load(vault.path), wrong, vault.path)
    assert wrong.wiped  # a Vault owns the key it is given, also when it fails


def test_a_record_nobody_indexes_changes_nothing(vault, vaults):
    tampered = document_of(vault)
    tampered["records"]["ab" * 16] = tampered["records"][vault.find("github").id]
    rewrite(vault, tampered)
    reopened = vaults.reopen(vault)
    assert sorted(entry.name for entry in reopened.list()) == ["aws/prod", "github"]
    assert reopened.value(reopened.find("github")) == "hunter2-Github!"


def test_whole_file_rollback_is_not_detected_as_documented(vault, vaults):
    """The stated limit of the format: an older copy of the entire file is a valid older vault."""
    older = vault.path.read_bytes()
    vault.update(vault.find("github"), secret=Secret(password="the new password"))
    vault.commit()
    paths.write_atomic(vault.path, older)
    reopened = vaults.reopen(vault)
    assert reopened.value(reopened.find("github")) == "hunter2-Github!"


# ---------------------------------------------------------------------------
# Names, aliases, tags, fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["github", "aws/prod", "a", "My Bank (joint)", "גיטהאב", "日本語 のエントリ", "emoji \U0001f511 key", "x" * 200,
     "with\u200dzero-width-joiner", "a/b/c", "UPPER", "trailing.dot.", "-dash", "irondome://looks-like-a-reference"],
)
def test_names_that_are_accepted(name):
    assert validate_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["", " ", " leading", "trailing ", "\ttab", "newline\n", "line\nbreak", "x" * 201, "nul\x00byte", "bell\x07",
     "escape\x1b[31m", "delete\x7f", "c1 csi \x9b31m", "next line \x85 here", "line \u2028 separator",
     "paragraph \u2029 separator", "\xa0nbsp-leading", None, 5, b"bytes", ["list"], {"a": 1}],
)
def test_names_that_are_refused(name):
    with pytest.raises(UsageError):
        validate_name(name)


@pytest.mark.parametrize(
    "alias",
    ["GITHUB_TOKEN", "a", "_", "_private", "aws.prod", "db-password", "A1", "x" * 128, "Mixed_Case.v2-final"],
)
def test_aliases_that_are_accepted(alias):
    assert validate_alias(alias) == alias


@pytest.mark.parametrize(
    "alias",
    ["", "1abc", ".hidden", "-dash", "has space", "has/slash", "a=b", "a$b", "\xe9", "גיט",
     "x" * 129, "TOKEN\n", "\nTOKEN",
     "TOKEN\r\n", "TOKEN\x00", "TO KEN", "a\tb", "a:b", "a;b", "$(id)", "a`b", None, 5, b"TOKEN", ["TOKEN"]],
)
def test_aliases_that_are_refused(alias):
    with pytest.raises(UsageError, match="alias"):
        validate_alias(alias)


@given(st.text(max_size=140))
@settings(max_examples=400, deadline=None)
def test_an_alias_is_exactly_an_identifier(text):
    ok = (
        1 <= len(text) <= 128
        and text.isascii()
        and (text[0].isalpha() or text[0] == "_")
        and all(char.isalnum() or char in "_.-" for char in text)
    )
    if ok:
        assert validate_alias(text) == text
    else:
        with pytest.raises(UsageError):
            validate_alias(text)


def test_tags_are_trimmed_deduplicated_and_checked(plain):
    entry = plain.add("e", Secret(), tags=["  work ", "Work", "WORK", "", "   ", "personal", "עבודה"])
    assert entry.tags == ["work", "personal", "עבודה"]
    plain.update(entry, tags=[])
    assert entry.tags == []
    for bad in (["x" * 65], ["line\nbreak"], ["bell\x07"], ["del\x7f"], ["csi\x9b"], [5], [None], [["nested"]]):
        with pytest.raises(UsageError):
            plain.update(entry, tags=bad)
        with pytest.raises(UsageError):
            plain.add("other", Secret(), tags=bad)
    assert entry.tags == [] and not plain.has_name("other")
    assert plain.add("limit", Secret(), tags=["x" * 64]).tags == ["x" * 64]


CONTROL_CHARACTERS = ["\x00", "\t", "\n", "\r", "\x07", "\x1b[31m", "\x1b]0;title\x07", "\x7f", "\x85", "\x9b31m",
                      " ", " "]


@pytest.mark.parametrize("control", CONTROL_CHARACTERS, ids=repr)
def test_usernames_and_urls_refuse_control_characters_as_names_and_tags_do(plain, control):
    """A listing prints them; on a terminal these characters are escape sequences and line breaks, not text."""
    with pytest.raises(UsageError, match="the username cannot contain control characters"):
        plain.add("e", Secret(), username=f"king{control}")
    with pytest.raises(UsageError, match="the URL cannot contain control characters"):
        plain.add("e", Secret(), url=f"https://example.com/{control}")
    with pytest.raises(UsageError):
        plain.add("e", Secret(), tags=[f"tag{control}x"])
    assert plain.entries == {} and plain.file.records == {}
    entry = plain.add("e", Secret(), username="king", url="https://example.com")
    for change in ({"username": f"queen{control}"}, {"url": f"https://example.org{control}"}):
        with pytest.raises(UsageError, match="cannot contain control characters"):
            plain.update(entry, **change)
    assert (entry.username, entry.url) == ("king", "https://example.com")


def test_values_and_notes_may_hold_anything(plain):
    """Only what is listed is checked: a secret, its notes and its custom fields are stored as given."""
    odd = "".join(CONTROL_CHARACTERS)
    entry = plain.add("e", Secret(password=odd, notes=f"line 1\nline 2{odd}", fields={"blob": odd}),
                      username="ok", url="https://example.com/ünïcode", tags=["work"])
    stored = plain.read_secret(entry)
    assert (stored.password, stored.notes, stored.fields) == (odd, f"line 1\nline 2{odd}", {"blob": odd})
    assert entry.url == "https://example.com/ünïcode"


def test_without_control_drops_exactly_what_is_refused():
    assert without_control("".join(CONTROL_CHARACTERS) + "me") == "[31m]0;title31mme"
    assert without_control("plain text, ünïcode, ‍ and \xa0 stay") == "plain text, ünïcode, ‍ and \xa0 stay"


def test_copy_into_carries_a_username_written_before_control_characters_were_refused(vault, vaults, isolated):
    """A re-key or a portable backup copies what is there; it must never refuse, and so lose, an entry."""
    github = vault.find("github")
    github.username, github.url = "king\x1b[31m", "https://github.com/\x07"  # as an older 4.0 build stored them
    destination = vaults.new(isolated / "copy")
    assert vault.copy_into(destination) == 2
    copied = destination.find("github")
    assert (copied.username, copied.url) == ("king\x1b[31m", "https://github.com/\x07")


@pytest.mark.parametrize("field", ["region", "api_key", "_x", "a.b-c", "Key2", "x" * 64])
def test_custom_field_names_that_are_accepted(plain, field):
    entry = plain.add("e", Secret(fields={field: "value"}))
    assert plain.value(entry, field) == "value"


@pytest.mark.parametrize(
    "field",
    ["password", "username", "url", "notes", "totp", "name", "", "1x", "has space", "a/b", "x" * 65, "\xe9", "k\n"]
)
def test_custom_field_names_that_are_refused(plain, field):
    with pytest.raises(UsageError, match="custom field"):
        plain.add("e", Secret(fields={field: "value"}))
    assert plain.entries == {} and plain.file.records == {}
    assert FIELDS == ("password", "username", "url", "notes", "totp", "name")


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------


def test_add_creates_an_entry_and_its_record(plain):
    before = int(time.time())
    entry = plain.add("github", Secret(password="pw", notes="n"), username="king", url="https://github.com",
                      tags=["dev"], kind="login", agent="use")
    assert isinstance(entry, Entry) and re.fullmatch(r"[0-9a-f]{32}", entry.id)
    assert (entry.name, entry.username, entry.url, entry.tags) == ("github", "king", "https://github.com", ["dev"])
    assert (entry.kind, entry.agent, entry.rev, entry.has_totp) == ("login", "use", 1, False)
    assert before <= entry.created == entry.modified <= int(time.time())
    assert plain.entries == {entry.id: entry} and set(plain.file.records) == {entry.id}
    secret_read = plain.read_secret(entry)
    assert (secret_read.password, secret_read.notes, secret_read.totp, secret_read.fields, secret_read.history) == (
        "pw", "n", None, {}, [])
    defaults = plain.add("plain", Secret())
    assert (defaults.username, defaults.url, defaults.tags) == ("", "", [])
    assert (defaults.kind, defaults.agent) == ("login", "deny")
    assert AGENT_POLICIES == ("deny", "use", "reveal")


def test_entry_names_are_unique_whatever_the_case(plain):
    plain.add("GitHub", Secret())
    for name in ("GitHub", "github", "GITHUB", "gitHUB"):
        with pytest.raises(UsageError, match="already exists"):
            plain.add(name, Secret())
    plain.add("Straße", Secret())
    with pytest.raises(UsageError, match="already exists"):
        plain.add("STRASSE", Secret())
    assert len(plain.entries) == 2 and len(plain.file.records) == 2


@pytest.mark.parametrize(
    "arguments, message",
    [
        (dict(kind="note"), "unknown entry kind"),
        (dict(agent="always"), "unknown agent policy"),
        (dict(entry_id="xyz"), "entry id"),
        (dict(entry_id="A" * 32), "entry id"),
        (dict(entry_id="a" * 32 + "\n"), "entry id"),
        (dict(entry_id=7), "entry id"),
        (dict(username=None), "username must be text"),
        (dict(username=5), "username must be text"),
        (dict(username=b"king"), "username must be text"),
        (dict(url=None), "URL must be text"),
        (dict(url=["https://x"]), "URL must be text"),
        (dict(username="u" * 100_001), "too long"),
        (dict(created=-1), "creation time"),
        (dict(created=1.5), "creation time"),
        (dict(created="yesterday"), "creation time"),
        (dict(created=True), "creation time"),
        (dict(created=2**64), "creation time"),
        (dict(modified=time.time()), "modification time"),
        (dict(modified=-5), "modification time"),
        (dict(tags="dev"), "tags must be a list"),
        (dict(tags=[5]), "tags must be text"),
    ],
)
def test_add_refuses_arguments_it_could_not_store(plain, arguments, message):
    """Most of these used to be written out and then made the whole vault unreadable."""
    with pytest.raises(UsageError, match=message):
        plain.add("entry", Secret(password="p"), **arguments)
    assert plain.entries == {} and plain.file.records == {}
    plain.commit()


@pytest.mark.parametrize(
    "bad_secret",
    [
        None, "password", {"password": "p"}, 5,
        Secret(password=None),  # type: ignore[arg-type]
        Secret(password=5),  # type: ignore[arg-type]
        Secret(password=b"bytes"),  # type: ignore[arg-type]
        Secret(password="p" * 100_001),
        Secret(notes=None),  # type: ignore[arg-type]
        Secret(notes="n" * 1_000_001),
        Secret(totp="JBSWY3DPEHPK3PXP"),  # type: ignore[arg-type]
        Secret(totp={"secret": b"raw bytes"}),
        Secret(totp={"when": {1, 2}}),
        Secret(fields=None),  # type: ignore[arg-type]
        Secret(fields=["a", "b"]),  # type: ignore[arg-type]
        Secret(fields={"region": 5}),  # type: ignore[dict-item]
        Secret(fields={"region": None}),  # type: ignore[dict-item]
        Secret(fields={5: "x"}),  # type: ignore[dict-item]
        Secret(history="old"),  # type: ignore[arg-type]
        Secret(history=["old-password"]),  # type: ignore[list-item]
        Secret(history=[{"password": b"old"}]),
    ],
)
def test_a_secret_that_could_not_be_read_back_is_never_written(plain, bad_secret):
    with pytest.raises(UsageError):
        plain.add("entry", bad_secret)
    assert plain.entries == {} and plain.file.records == {}
    entry = plain.add("entry", Secret(notes="kept"))
    record = plain.file.records[entry.id]
    if bad_secret is not None:  # for update, None means "leave the secret alone"
        with pytest.raises(UsageError):
            plain.update(entry, secret=bad_secret)
    assert entry.rev == 1 and plain.file.records[entry.id] == record
    assert plain.read_secret(entry).notes == "kept"
    plain.commit()


def test_add_with_a_chosen_id_and_times(plain):
    entry = plain.add(
        "imported", Secret(password="p"), entry_id="ab" * 16, created=1_600_000_000, modified=1_650_000_000
    )
    assert (entry.id, entry.created, entry.modified) == ("ab" * 16, 1_600_000_000, 1_650_000_000)
    with pytest.raises(UsageError, match="already in use"):
        plain.add("another", Secret(), entry_id="ab" * 16)
    assert plain.add("epoch", Secret(), created=0, modified=0).created == 0


def test_value_resolves_every_field(vault, monkeypatch):
    github, aws = vault.find("github"), vault.find("aws/prod")
    assert vault.value(github) == "hunter2-Github!"
    assert vault.value(github, "password") == "hunter2-Github!"
    assert vault.value(github, "username") == "king"
    assert vault.value(github, "url") == "https://github.com"
    assert vault.value(github, "notes") == "personal"
    assert vault.value(github, "name") == "github"
    assert vault.value(aws, "region") == "eu-west-1"
    assert vault.value(aws, "notes") == "" and vault.value(aws, "username") == ""
    with pytest.raises(NotFoundError, match="no field named 'missing'"):
        vault.value(github, "missing")
    with pytest.raises(NotFoundError, match="no field named 'region'"):
        vault.value(github, "region")
    with pytest.raises(NotFoundError, match="no one-time-password secret"):
        vault.value(github, "totp")


def test_a_totp_reference_is_computed_from_the_stored_settings(plain, monkeypatch):
    seen: List[Any] = []
    stand_in = types.ModuleType("irondome.otp")
    stand_in.code_for = lambda settings: seen.append(settings) or "123456"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "irondome.otp", stand_in)
    monkeypatch.setattr(irondome, "otp", stand_in, raising=False)
    entry = plain.add("2fa", Secret(password="p", totp={"secret": "JBSWY3DPEHPK3PXP", "digits": 6}))
    assert entry.has_totp is True
    assert plain.value(entry, "totp") == "123456"
    assert seen == [{"secret": "JBSWY3DPEHPK3PXP", "digits": 6}]
    plain.update(entry, secret=Secret(password="p"))
    assert entry.has_totp is False


def test_find_prefers_the_exact_name_then_ignores_case(vault):
    github = vault.find("github")
    assert vault.find("GitHub") is github and vault.find("GITHUB") is github
    assert vault.find("AWS/Prod").name == "aws/prod"
    for missing in ("gitlab", "", "github ", "git"):
        with pytest.raises(NotFoundError, match="no entry named"):
            vault.find(missing)
    assert vault.has_name("GITHUB") and vault.has_name("github") and not vault.has_name("gitlab")


def test_names_that_differ_only_in_case_are_ambiguous(plain):
    """add() never lets this happen; a vault written by something else might contain it."""
    first = plain.add("Mail", Secret(password="one"))
    second = Entry(id="cd" * 16, name="MAIL", rev=0)
    plain.entries[second.id] = second
    plain._write_secret(second, Secret(password="two"))
    assert plain.find("Mail") is first and plain.find("MAIL") is second  # exact names still work
    with pytest.raises(UsageError, match="differ only in case"):
        plain.find("mail")
    with pytest.raises(UsageError, match="differ only in case"):
        plain.resolve("mail")
    with pytest.raises(UsageError, match="differ only in case"):
        plain.resolve("mail/username")
    assert plain.resolve("Mail/username") == (first, "username")


def test_resolve_alias_then_name_then_name_and_field(vault):
    github, aws = vault.find("github"), vault.find("aws/prod")
    assert vault.resolve("GITHUB_TOKEN") == (github, "password")
    assert vault.resolve("github") == (github, "password")
    assert vault.resolve("github/username") == (github, "username")
    assert vault.resolve("github/notes") == (github, "notes")
    assert vault.resolve("aws/prod") == (aws, "password")  # a name containing a slash is a name first
    assert vault.resolve("aws/prod/region") == (aws, "region")
    assert vault.resolve("GITHUB_TOKEN/username") == (github, "username")  # an alias may be asked for another field
    assert vault.resolve("irondome://GITHUB_TOKEN") == (github, "password")
    assert vault.resolve("irondome://github/url") == (github, "url")
    assert vault.resolve("irondome://aws/prod/region") == (aws, "region")
    assert vault.resolve("GITHUB", default_field="username") == (github, "username")
    assert vault.resolve("github/does-not-exist") == (github, "does-not-exist")  # value() reports the missing field


def test_an_alias_and_an_entry_never_share_a_name(vault):
    """A reference must mean one thing (red-team malicious-file:1): an alias used to win, silently."""
    github, aws = vault.find("github"), vault.find("aws/prod")
    for alias in ("github", "GitHub"):
        with pytest.raises(UsageError, match="has that name"):
            vault.set_alias(alias, aws, "region")
    with pytest.raises(UsageError, match="alias GITHUB_TOKEN"):
        vault.add("github_token", Secret())
    with pytest.raises(UsageError, match="alias GITHUB_TOKEN"):
        vault.update(aws, name="GITHUB_TOKEN")
    assert sorted(vault.aliases) == ["GITHUB_TOKEN"] and aws.name == "aws/prod"
    vault.set_alias("GITHUB", github, "username")  # an alias may share the name of the entry it points at
    assert vault.resolve("GITHUB") == (github, "username") and vault.resolve("github") == (github, "password")
    vault.aliases["github"] = Alias(entry=aws.id, field="region")  # as a vault written before the rule may hold
    for reference in ("github", "github/password", "irondome://github"):
        with pytest.raises(UsageError, match="does not guess"):
            vault.resolve(reference)
    assert vault.find("github") is github
    vault.remove_alias("github")
    assert vault.resolve("github") == (github, "password")


def test_a_name_with_a_slash_never_hides_a_field(plain):
    """'db/prod' is the entry or the field 'prod' of 'db', never both (red-team malicious-file:0)."""
    parent = plain.add("db", Secret(password="parent", fields={"prod": "the field"}))
    for name in ("db/prod", "DB/Prod", "db/password", "Db/URL", "db/paſsword"):  # U+017F casefolds to s
        with pytest.raises(UsageError, match="reference must mean one thing"):
            plain.add(name, Secret(password="child"))
    assert plain.value(*plain.resolve("db/prod")) == "the field"
    child = plain.add("db/staging", Secret(password="child"))  # 'db' has no field 'staging': nothing competes
    assert plain.resolve("db/staging") == (child, "password")
    with pytest.raises(UsageError, match="reference must mean one thing"):
        plain.update(parent, secret=Secret(password="parent", fields={"prod": "the field", "staging": "x"}))
    with pytest.raises(UsageError, match="reference must mean one thing"):
        plain.update(child, name="db/notes")
    with pytest.raises(UsageError, match="reference must mean one thing"):
        plain.set_alias("db", child)
    plain.add("dbx/prod", Secret())
    with pytest.raises(UsageError, match="reference must mean one thing"):
        plain.set_alias("dbx", parent)  # dbx/prod would then also mean the field prod of db
    assert plain.read_secret(parent).fields == {"prod": "the field"} and child.name == "db/staging"
    plain._add("db/prod", Secret(password="child"), username="", url="", tags=None, kind="login", agent="deny",
               entry_id=None, created=None, modified=None)  # what an older build let an import write
    with pytest.raises(UsageError, match="does not guess"):
        plain.resolve("db/prod")
    assert plain.value(*plain.resolve("db/staging")) == "child"


@pytest.mark.parametrize("reference", ["", None, 5, ["github"], b"github"])
def test_resolve_refuses_an_empty_or_non_text_reference(vault, reference):
    with pytest.raises(UsageError, match="empty reference"):
        vault.resolve(reference)


@pytest.mark.parametrize(
    "reference", ["nothing", "nothing/password", "irondome://", "irondome://nothing", "/", "a/", "/b"]
)
def test_resolve_reports_what_it_could_not_find(vault, reference):
    with pytest.raises(NotFoundError):
        vault.resolve(reference)


def test_list_sorts_and_filters(plain):
    plain.add("zeta", Secret(), tags=["Work"], username="alice@example.invalid")
    plain.add("Alpha", Secret(), tags=["work", "bank"], url="https://bank.invalid")
    middle = plain.add("beta", Secret(), tags=["personal"])
    plain.add("alpha2", Secret())
    plain.set_alias("DEPLOY_KEY", middle)
    assert [entry.name for entry in plain.list()] == ["Alpha", "alpha2", "beta", "zeta"]
    assert [entry.name for entry in plain.list(tag="WORK")] == ["Alpha", "zeta"]
    assert [entry.name for entry in plain.list(tag="none")] == []
    assert [entry.name for entry in plain.list(query="ALPHA")] == ["Alpha", "alpha2"]
    assert [entry.name for entry in plain.list(query="alice")] == ["zeta"]
    assert [entry.name for entry in plain.list(query="BANK")] == ["Alpha"]
    assert [entry.name for entry in plain.list(query="deploy")] == ["beta"]
    assert [entry.name for entry in plain.list(query="personal")] == ["beta"]
    assert [entry.name for entry in plain.list(tag="work", query="zet")] == ["zeta"]
    assert plain.list(query="no such thing") == []
    assert [entry.name for entry in plain.list(query="")] == ["Alpha", "alpha2", "beta", "zeta"]


def test_update_changes_metadata_without_touching_the_record(vault):
    github = vault.find("github")
    record = vault.file.records[github.id]
    github.modified = 0
    returned = vault.update(github, username="queen", url="https://example.invalid", tags=["a", "b"], kind="secret",
                            agent="reveal")
    assert returned is github
    assert (github.username, github.url, github.tags, github.kind, github.agent) == (
        "queen", "https://example.invalid", ["a", "b"], "secret", "reveal")
    assert github.rev == 1 and vault.file.records[github.id] == record
    assert github.modified >= int(time.time()) - 5
    assert vault.read_secret(github).password == "hunter2-Github!"


def test_update_renames(vault):
    github = vault.find("github")
    vault.update(github, name="GitHub")  # a change of case only is allowed
    assert github.name == "GitHub"
    vault.update(github, name="code hosting")
    assert vault.find("code hosting") is github and not vault.has_name("github")
    with pytest.raises(UsageError, match="already exists"):
        vault.update(github, name="AWS/PROD")
    for bad in ("", " padded ", "x" * 201, "line\nbreak"):
        with pytest.raises(UsageError):
            vault.update(github, name=bad)
    assert github.name == "code hosting"


def test_a_failed_update_changes_nothing(vault):
    """Every argument is checked before the first one is applied."""
    github = vault.find("github")
    before = copy.deepcopy(github)
    record = vault.file.records[github.id]
    failures = [
        dict(name="renamed", tags=["bad\x01tag"]),
        dict(username="someone", url=5),
        dict(name="renamed", kind="note"),
        dict(username="someone", agent="always"),
        dict(name="renamed", username=7),
        dict(name="renamed", secret=Secret(password="new", fields={"password": "shadow"})),
        dict(name="renamed", secret=Secret(password=None)),  # type: ignore[arg-type]
        dict(username="someone", secret="not a secret"),
        dict(name="aws/prod"),
    ]
    for arguments in failures:
        with pytest.raises(UsageError):
            vault.update(github, **arguments)
        assert github == before, arguments
        assert vault.file.records[github.id] == record
    assert vault.read_secret(github).password == "hunter2-Github!"
    assert vault.find("github") is github


def test_a_failed_secret_write_does_not_strand_the_entry(vault, vaults, monkeypatch):
    """The revision moves only together with the record; otherwise the entry would become unreadable."""
    import irondome.vault as vault_module

    github = vault.find("github")

    def broken_seal(*args, **kwargs):
        raise MemoryError("out of memory while sealing")

    with monkeypatch.context() as scoped:
        scoped.setattr(vault_module, "seal", broken_seal)
        with pytest.raises(MemoryError):
            vault.update(github, secret=Secret(password="never stored"))
        with pytest.raises(MemoryError):
            vault.add("never added", Secret(password="p"))
    assert github.rev == 1 and not vault.has_name("never added")
    assert vault.read_secret(github).password == "hunter2-Github!"
    vault.commit()
    reopened = vaults.reopen(vault)
    assert reopened.value(reopened.find("github")) == "hunter2-Github!"


def test_updating_through_a_stale_copy_of_an_entry_cannot_corrupt_it(vault, vaults):
    """An Entry object from another Vault instance used to desynchronise revision and record."""
    stale = copy.deepcopy(vault.find("github"))
    other = vaults.reopen(vault)
    returned = other.update(stale, secret=Secret(password="changed through a stale copy"), username="queen")
    assert returned is other.entries[stale.id] and returned is not stale
    assert returned.rev == 2 and returned.username == "queen"
    assert other.read_secret(stale).password == "changed through a stale copy"
    other.commit()
    fresh = vaults.reopen(other)
    assert fresh.value(fresh.find("github")) == "changed through a stale copy"
    assert fresh.find("github").username == "queen"


def test_password_history_is_kept_newest_first_and_capped_at_five(plain):
    entry = plain.add("site", Secret(password="pw0"))
    for number in range(1, 8):
        plain.update(entry, secret=Secret(password=f"pw{number}"))
        history = plain.read_secret(entry).history
        assert [item["password"] for item in history] == [f"pw{n}" for n in range(number - 1, -1, -1)][:5]
        assert all(isinstance(item["retired"], int) and abs(item["retired"] - time.time()) < 300 for item in history)
    assert entry.rev == 8
    assert plain.read_secret(entry).password == "pw7"
    assert [item["password"] for item in plain.read_secret(entry).history] == ["pw6", "pw5", "pw4", "pw3", "pw2"]


def test_history_is_untouched_when_the_password_does_not_change(plain):
    entry = plain.add("site", Secret(password="first"))
    plain.update(entry, secret=Secret(password="second"))
    history = plain.read_secret(entry).history
    assert [item["password"] for item in history] == ["first"]
    plain.update(entry, secret=Secret(password="second", notes="only the notes changed"))
    after = plain.read_secret(entry)
    assert after.history == history and after.notes == "only the notes changed"
    edited = plain.read_secret(entry)
    edited.fields["region"] = "eu"
    plain.update(entry, secret=edited)  # read, change a field, write back
    assert plain.read_secret(entry).history == history
    plain.update(entry, username="someone")  # no secret at all
    assert plain.read_secret(entry).history == history


def test_history_starts_only_once_there_is_a_password_to_retire(plain):
    entry = plain.add("site", Secret())
    plain.update(entry, secret=Secret(password="first"))
    assert plain.read_secret(entry).history == []
    plain.update(entry, secret=Secret(password=""))
    assert [item["password"] for item in plain.read_secret(entry).history] == ["first"]


def test_update_tells_the_caller_what_history_was_stored(plain):
    entry = plain.add("site", Secret(password="first"))
    replacement = Secret(password="second")
    plain.update(entry, secret=replacement)
    assert [item["password"] for item in replacement.history] == ["first"]


def test_remove_takes_the_record_and_the_aliases_with_it(vault):
    github = vault.find("github")
    vault.set_alias("SECOND", github, "username")
    vault.set_alias("AWS", vault.find("aws/prod"))
    vault.remove(github)
    assert github.id not in vault.entries and github.id not in vault.file.records
    assert sorted(vault.aliases) == ["AWS"]
    for call in (lambda: vault.remove(github), lambda: vault.update(github, username="x"),
                 lambda: vault.set_alias("X", github)):
        with pytest.raises(NotFoundError):
            call()
    with pytest.raises(VaultError, match="missing"):
        vault.read_secret(github)
    with pytest.raises(NotFoundError):
        vault.resolve("GITHUB_TOKEN")
    vault.add("github", Secret(password="a new one"))  # the name is free again


def test_aliases(vault):
    github, aws = vault.find("github"), vault.find("aws/prod")
    vault.set_alias("AWS_REGION", aws, "region")
    vault.set_alias("GH_USER", github, "username")
    vault.set_alias("GH_OTP", github, "totp")
    assert vault.aliases["AWS_REGION"] == Alias(entry=aws.id, field="region")
    assert vault.value(*vault.resolve("AWS_REGION")) == "eu-west-1"
    assert vault.value(*vault.resolve("GH_USER")) == "king"
    assert vault.aliases_of(github) == ["GH_OTP", "GH_USER", "GITHUB_TOKEN"] and vault.aliases_of(aws) == ["AWS_REGION"]
    vault.set_alias("GITHUB_TOKEN", aws)  # pointing an alias somewhere else replaces it
    assert vault.resolve("GITHUB_TOKEN") == (aws, "password")
    vault.remove_alias("GITHUB_TOKEN")
    with pytest.raises(NotFoundError, match="no alias named"):
        vault.remove_alias("GITHUB_TOKEN")
    assert Alias(entry="x").field == "password"


@pytest.mark.parametrize("field", ["name", "", "has space", "1x", "a/b", "x" * 65, None, 5, ["password"]])
def test_an_alias_must_point_at_a_value(vault, field):
    with pytest.raises(UsageError):
        vault.set_alias("VALID_ALIAS", vault.find("github"), field)
    assert "VALID_ALIAS" not in vault.aliases


def test_an_alias_needs_a_valid_name_and_a_live_entry(vault):
    github = vault.find("github")
    for bad in ("", "1abc", "has space", "TOKEN\n", "a/b"):
        with pytest.raises(UsageError):
            vault.set_alias(bad, github)
    ghost = Entry(id="ee" * 16, name="ghost")
    with pytest.raises(NotFoundError):
        vault.set_alias("GHOST", ghost)
    assert sorted(vault.aliases) == ["GITHUB_TOKEN"]


def test_everything_survives_a_commit_and_a_reopen(vault, vaults):
    hebrew = vault.add("גיטהאב", Secret(password="סיסמה-\U0001f511", notes="שורה\nשנייה", fields={"token": "ערך"},
                                         totp={"secret": "JBSWY3DPEHPK3PXP", "digits": 6}),
                       username="משתמש", url="https://דוגמה.invalid", tags=["עבודה"], kind="secret", agent="use")
    vault.set_alias("HEBREW", hebrew, "token")
    vault.update(vault.find("github"), secret=Secret(password="rotated"))
    vault.meta["note"] = {"nested": [1, 2, 3]}
    vault.commit()
    reopened = vaults.reopen(vault)
    assert reopened.entries == vault.entries and reopened.entries is not vault.entries
    assert reopened.aliases == vault.aliases
    assert reopened.meta == vault.meta and reopened.meta["created_by"] == irondome.__version__
    for entry in vault.list():
        assert reopened.read_secret(reopened.entries[entry.id]) == vault.read_secret(entry)
    again = reopened.find("גיטהאב")
    assert reopened.value(again) == "סיסמה-\U0001f511" and reopened.value(*reopened.resolve("HEBREW")) == "ערך"
    assert again.has_totp is True and again.kind == "secret" and again.agent == "use"
    assert reopened.read_secret(reopened.find("github")).history[0]["password"] == "hunter2-Github!"


def test_reading_a_record_that_is_not_there(plain):
    ghost = Entry(id="ee" * 16, name="ghost")
    with pytest.raises(VaultError, match="secret record for 'ghost' is missing"):
        plain.read_secret(ghost)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_close_wipes_the_keys_and_locks_the_vault(vault):
    vault_key = vault.vault_key
    index_key = vault._index_key
    github = vault.find("github")
    assert not vault_key.wiped and not index_key.wiped
    vault.close()
    assert vault_key.wiped and index_key.wiped
    vault.close()  # idempotent
    for call in (lambda: vault.vault_key, lambda: vault.read_secret(github), lambda: vault.commit(),
                 lambda: vault.add("x", Secret()), lambda: vault.update(github, secret=Secret(password="p")),
                 lambda: vault.value(github)):
        with pytest.raises(VaultError, match="locked"):
            call()
    assert vault.value(github, "username") == "king"  # the index stays readable in memory, as documented


def test_a_vault_is_a_context_manager(vaults, isolated):
    with vaults.new(isolated / "ctx") as opened:
        key = opened.vault_key
        opened.add("x", Secret(password="p"))
        opened.commit()
    assert key.wiped
    with pytest.raises(RuntimeError):
        with vaults.new(isolated / "ctx2") as opened:
            key = opened.vault_key
            raise RuntimeError("boom")
    assert key.wiped


def test_dropping_a_vault_wipes_its_keys(vaults, isolated):
    opened = vaults.new(isolated / "dropped")
    key = opened.vault_key
    vaults.made.remove(opened)
    del opened
    import gc

    gc.collect()
    assert key.wiped


def test_create_refuses_to_overwrite_unless_told_to(plain, vaults):
    plain.add("precious", Secret(password="p"))
    plain.commit()
    before = plain.path.read_bytes()
    key = keys.new_vault_key()
    vault_id = os.urandom(16)
    slot, _ = keys.create_recovery_slot(key, vault_id)
    with pytest.raises(VaultError, match="already exists"):
        Vault.create(key, [slot], vault_id)
    assert key.wiped  # create owns the key it was given
    assert plain.path.read_bytes() == before
    replacement = vaults.new(overwrite=True)
    assert replacement.entries == {} and replacement.vault_id != plain.vault_id
    assert document_of(replacement)["generation"] == 1


def test_create_needs_a_keyslot_and_a_proper_vault_id(isolated):
    key = keys.new_vault_key()
    with pytest.raises(VaultError, match="at least one keyslot"):
        Vault.create(key, [], os.urandom(16))
    slot, _ = keys.create_recovery_slot(key, os.urandom(16))
    with pytest.raises(VaultError, match="vault id"):
        Vault.create(key, [slot], b"short")
    assert not paths.vault_file().exists()
    assert temp_files(isolated) == []


def test_vault_exists(plain, isolated):
    assert vault_exists() is True and vault_exists(plain.path) is True and vault_exists(str(plain.path)) is True
    assert vault_exists(isolated / "nothing.irondome") is False
    assert vault_exists(isolated) is False  # a directory is not a vault


# ---------------------------------------------------------------------------
# Keyslots of an open vault
# ---------------------------------------------------------------------------


def test_slots_can_be_added_listed_and_removed(plain, vaults):
    first = plain.slots()[0]
    second, text = keys.create_recovery_slot(plain.vault_key, plain.vault_id)
    portable = keys.create_password_slot(
        plain.vault_key, b"a master password", plain.vault_id, params=FAST, backend=None
    )
    plain.add_slot(second)
    plain.add_slot(portable)
    assert plain.slots() == [first, second, portable]
    assert plain.slots("recovery") == [first, second] and plain.slots("password") == [portable]
    assert plain.slots("device") == []
    with pytest.raises(VaultError, match="already exists"):
        plain.add_slot(second)
    plain.commit()
    file = VaultFile.load(plain.path)
    assert [slot.id for slot in file.slots] == [first.id, second.id, portable.id]
    with keys.open_slot(file.slots[1], file.vault_id, recovery_key=text) as opened:
        assert bytes(opened.view()) == bytes(plain.vault_key.view())
    with keys.open_slot(file.slots[2], file.vault_id, password=b"a master password") as opened:
        assert bytes(opened.view()) == bytes(plain.vault_key.view())
    assert plain.remove_slot(second.id) is second
    with pytest.raises(NotFoundError):
        plain.remove_slot(second.id)
    plain.remove_slot(first.id)
    with pytest.raises(VaultError, match="last keyslot"):
        plain.remove_slot(portable.id)
    assert plain.slots() == [portable]


def test_a_vault_holds_at_most_32_keyslots(plain, vaults):
    """One more used to be written out, after which the file was refused by its own reader."""
    for _ in range(31):
        slot, _ = keys.create_recovery_slot(plain.vault_key, plain.vault_id)
        plain.add_slot(slot)
    extra, _ = keys.create_recovery_slot(plain.vault_key, plain.vault_id)
    with pytest.raises(VaultError, match="at most 32 keyslots"):
        plain.add_slot(extra)
    plain.commit()
    assert len(vaults.reopen(plain).slots()) == 32
    plain.remove_slot(plain.slots()[5].id)
    plain.add_slot(extra)
    plain.commit()


# ---------------------------------------------------------------------------
# Commit
# ---------------------------------------------------------------------------


def test_commit_bumps_the_generation_and_keeps_the_previous_file(plain):
    assert document_of(plain)["generation"] == 1 and plain.snapshots() == []
    previous = plain.path.read_bytes()
    plain.add("x", Secret(password="p"))
    plain.commit()
    assert document_of(plain)["generation"] == 2 == plain.file.generation
    snapshots = plain.snapshots()
    assert [item.name for item in snapshots] == ["vault-0000000001.irondome"]
    assert snapshots[0].parent == paths.backups_dir()
    assert snapshots[0].read_bytes() == previous  # byte for byte what was there before
    assert VaultFile.from_bytes(snapshots[0].read_bytes()).generation == 1


def test_two_vault_objects_cannot_both_commit(vault, vaults):
    """Whoever commits second is refused rather than allowed to overwrite the first."""
    other = vaults.reopen(vault)
    vault.add("from the first", Secret(password="1"))
    other.add("from the second", Secret(password="2"))
    vault.commit()
    winner = vault.path.read_bytes()
    with pytest.raises(VaultError, match="changed on disk"):
        other.commit()
    with pytest.raises(VaultError, match="changed on disk"):
        other.commit()  # and it stays refused
    assert vault.path.read_bytes() == winner
    fresh = vaults.reopen(vault)
    assert fresh.has_name("from the first") and not fresh.has_name("from the second")
    vault.add("first again", Secret())
    vault.commit()  # the winner carries on


def test_commit_refuses_a_vault_that_was_replaced_or_removed(vault, vaults, isolated):
    stranger = vaults.new(isolated / "stranger")
    original = vault.path.read_bytes()
    paths.write_atomic(vault.path, stranger.path.read_bytes())
    with pytest.raises(VaultError, match="replaced by a different one"):
        vault.commit()
    vault.path.unlink()
    with pytest.raises(VaultError, match="disappeared"):
        vault.commit()
    assert not vault.path.exists()
    paths.write_atomic(vault.path, b"not a vault at all")
    with pytest.raises(VaultError, match="not an IronDome vault file"):
        vault.commit()
    vault.path.unlink()
    vault.path.mkdir()
    with pytest.raises(VaultError, match="cannot read the vault"):
        vault.commit()
    vault.path.rmdir()
    paths.write_atomic(vault.path, original)
    vault.commit()


def test_commit_can_be_called_while_holding_the_lock(vault, vaults):
    """The lock is documented for a read-modify-write of the vault; commit must not deadlock under it."""

    def locked_update() -> str:
        with paths.file_lock():
            vault.update(vault.find("github"), username="changed under the lock")
            vault.commit()
        return "done"

    assert within(60, locked_update) == "done"
    assert vaults.reopen(vault).find("github").username == "changed under the lock"


def test_snapshots_rotate(plain):
    for number in range(1, 8):
        plain.add(f"entry {number}", Secret(password="p"))
        plain.commit(snapshots=3)
    assert [item.name for item in plain.snapshots()] == [f"vault-{n:010d}.irondome" for n in (5, 6, 7)]
    kept = [VaultFile.from_bytes(item.read_bytes()).generation for item in plain.snapshots()]
    assert kept == [5, 6, 7]
    plain.commit(snapshots=0)  # 0 writes no snapshot and leaves the existing ones
    assert len(plain.snapshots()) == 3
    plain.commit()  # the default keeps ten
    assert len(plain.snapshots()) == 4
    for _ in range(12):
        plain.commit()
    assert len(plain.snapshots()) == 10


def test_a_snapshot_is_a_complete_older_vault(vault, vaults, isolated):
    vault.update(vault.find("github"), secret=Secret(password="changed"))
    vault.commit()
    snapshot = vault.snapshots()[-1]
    restored_path = isolated / "restored" / "vault.irondome"
    paths.write_atomic(restored_path, snapshot.read_bytes())
    restored = Vault(VaultFile.load(restored_path), vault.vault_key.copy(), restored_path)
    vaults.made.append(restored)
    assert restored.value(restored.find("github")) == "hunter2-Github!"


def test_purge_removes_every_snapshot_and_nothing_else(plain):
    for _ in range(4):
        plain.commit()
    backups = paths.backups_dir()
    bystanders = ["vault-portable-backup.irondome", "vault-2026-11-11.irondome", "vault-12345.irondome", "notes.txt",
                  "vault-0000000001.irondome.bak", "my-vault-0000000001.irondome"]
    for name in bystanders:
        (backups / name).write_bytes(b"not a snapshot")
    assert len(plain.snapshots()) == 4
    assert plain.purge_snapshots() == 4
    assert plain.snapshots() == [] and plain.purge_snapshots() == 0
    assert sorted(item.name for item in backups.iterdir()) == sorted(bystanders)
    for _ in range(14):
        plain.commit()  # rotation leaves them alone as well
    assert len(plain.snapshots()) == 10
    assert all((backups / name).read_bytes() == b"not a snapshot" for name in bystanders)


def test_snapshots_of_a_replaced_vault_are_rotated_out_first(plain, vaults):
    """After a vault is re-created its numbering restarts; the old vault's snapshots must not crowd out the new."""
    for _ in range(8):
        plain.commit(snapshots=5)
    assert [item.name[6:16] for item in plain.snapshots()] == [f"{n:010d}" for n in (4, 5, 6, 7, 8)]
    replacement = vaults.new(overwrite=True)
    for round_number in range(1, 4):
        replacement.add(f"e{round_number}", Secret())
        replacement.commit(snapshots=5)
        just_written = paths.backups_dir() / f"vault-{round_number:010d}.irondome"
        assert just_written in replacement.snapshots()
        assert VaultFile.from_bytes(just_written.read_bytes()).vault_id == replacement.vault_id
    for _ in range(6):
        replacement.commit(snapshots=5)
    survivors = [VaultFile.from_bytes(item.read_bytes()).vault_id for item in replacement.snapshots()]
    assert survivors == [replacement.vault_id] * 5  # nothing of the replaced vault is left


def test_snapshots_without_a_backups_directory(vaults, isolated):
    fresh = vaults.new(isolated / "fresh")
    assert fresh.snapshots() == [] and fresh.purge_snapshots() == 0
    assert not (isolated / "fresh" / "backups").exists()


@posix_only
def test_every_file_is_owner_only_under_a_permissive_umask(make_vault):
    original = os.umask(0)
    try:
        opened, _ = make_vault()
        entry = opened.add("x", Secret(password="p"))
        opened.commit()
        opened.update(entry, secret=Secret(password="q"))
        opened.commit()
    finally:
        os.umask(original)
    seen = 0
    for root in (paths.home(), paths.device_dir()):
        assert mode(root) == 0o700
        for item in root.rglob("*"):
            seen += 1
            assert mode(item) == (0o700 if item.is_dir() else 0o600), item
    names = sorted(str(item.relative_to(paths.home())) for item in paths.home().rglob("*"))
    assert names == [".lock", "backups", "backups/vault-0000000001.irondome", "backups/vault-0000000002.irondome",
                     "vault.irondome"]
    assert seen == 6  # those five and the device key


@pytest.mark.parametrize("failing_call", [1, 2])
def test_a_crash_while_writing_leaves_the_old_vault_and_no_debris(vault, vaults, monkeypatch, failing_call):
    """os.replace fails (first for the snapshot, then for the vault itself): the old file is what remains."""
    before = vault.path.read_bytes()
    generation = vault.file.generation
    vault.add("lost in the crash", Secret(password="p"))
    real_replace = os.replace
    calls: List[str] = []

    def crashing_replace(source, destination):
        calls.append(str(destination))
        if len(calls) == failing_call:
            raise OSError(errno.EIO, "power cut")
        return real_replace(source, destination)

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "replace", crashing_replace)
        with pytest.raises(OSError, match="power cut"):
            vault.commit()
    assert vault.path.read_bytes() == before
    assert temp_files(paths.home()) == []
    assert vault.file.generation == generation
    survivor = vaults.reopen(vault)
    assert not survivor.has_name("lost in the crash") and survivor.value(survivor.find("github")) == "hunter2-Github!"
    vault.commit()  # the same object can simply try again
    assert vaults.reopen(vault).has_name("lost in the crash")
    assert document_of(vault)["generation"] == generation + 1


def test_a_vault_at_a_custom_path_keeps_everything_beside_it(vaults, isolated):
    directory = isolated / "second vault"
    opened = vaults.new(directory)
    opened.add("x", Secret(password="p"))
    opened.commit()
    assert sorted(item.name for item in directory.iterdir()) == [".lock", "backups", "vault.irondome"]
    assert [item.parent for item in opened.snapshots()] == [directory / "backups"]
    assert not paths.home().exists()


# ---------------------------------------------------------------------------
# A vault is never written in a state it could not read back
# ---------------------------------------------------------------------------


def poisons() -> List[Tuple[str, Callable[[Vault], None]]]:
    def entry_of(vault: Vault) -> Entry:
        return vault.find("github")

    return [
        ("username is not text", lambda v: setattr(entry_of(v), "username", None)),
        ("url is not text", lambda v: setattr(entry_of(v), "url", 5)),
        ("name is too long", lambda v: setattr(entry_of(v), "name", "x" * 201)),
        ("creation time is a float", lambda v: setattr(entry_of(v), "created", time.time())),
        ("revision is negative", lambda v: setattr(entry_of(v), "rev", -1)),
        ("revision is enormous", lambda v: setattr(entry_of(v), "rev", 2**70)),
        ("kind is unknown", lambda v: setattr(entry_of(v), "kind", "note")),
        ("agent policy is unknown", lambda v: setattr(entry_of(v), "agent", "always")),
        ("tags hold a number", lambda v: setattr(entry_of(v), "tags", [1, 2])),
        ("TOTP flag is not a flag", lambda v: setattr(entry_of(v), "has_totp", "yes")),
        ("alias name is not an identifier", lambda v: v.aliases.update({"bad name": Alias(entry=entry_of(v).id)})),
        ("alias points nowhere", lambda v: v.aliases.update({"DANGLING": Alias(entry="ee" * 16)})),
        ("alias field is not text", lambda v: v.aliases.update({"X": Alias(entry=entry_of(v).id, field=None)})),  # type: ignore[arg-type]
        ("meta is not a mapping", lambda v: setattr(v, "meta", "text")),
        ("meta is not JSON", lambda v: v.meta.update({"when": {1, 2}})),
        ("an entry has no record", lambda v: v.file.records.pop(entry_of(v).id)),
        ("a record id is malformed", lambda v: v.file.records.update({"not-an-id": v.file.records[entry_of(v).id]})),
        ("a record is not base64", lambda v: v.file.records.update({entry_of(v).id: "!!"})),
        ("a keyslot is malformed", lambda v: setattr(v.file.slots[0], "wrap", "AAAA")),
        ("a keyslot id repeats", lambda v: v.file.slots.append(copy.deepcopy(v.file.slots[0]))),
        ("there are no keyslots", lambda v: v.file.slots.clear()),
        ("there are too many keyslots", lambda v: v.file.slots.extend(
            keys.create_recovery_slot(v.vault_key, v.vault_id)[0] for _ in range(40))),
        ("the creation time is negative", lambda v: setattr(v.file, "created", -1)),
    ]


@pytest.mark.parametrize("label, poison", poisons(), ids=[label for label, _ in poisons()])
def test_commit_refuses_to_write_what_it_could_not_open_again(vault, vaults, label, poison):
    """Whatever a caller does to the in-memory objects, the file on disk stays a vault that opens."""
    before = vault.path.read_bytes()
    snapshots_before = [item.name for item in vault.snapshots()]
    poison(vault)
    with pytest.raises(VaultError, match="refusing to write"):
        vault.commit()
    assert vault.path.read_bytes() == before, label
    assert [item.name for item in vault.snapshots()] == snapshots_before
    assert temp_files(paths.home()) == []
    survivor = Vault(VaultFile.load(vault.path), vault.vault_key.copy(), vault.path)
    vaults.made.append(survivor)
    assert survivor.value(survivor.find("github")) == "hunter2-Github!"


# ---------------------------------------------------------------------------
# copy_into
# ---------------------------------------------------------------------------


def test_copy_into_re_encrypts_everything_under_another_key(vault, vaults, isolated):
    github = vault.find("github")
    vault.update(github, secret=Secret(password="second password", notes="personal"), agent="use")
    vault.set_alias("AWS_REGION", vault.find("aws/prod"), "region")
    github.created, github.modified = 1_600_000_000, 1_650_000_000
    destination = vaults.new(isolated / "copy")
    assert vault.copy_into(destination) == 2
    assert destination.entries.keys() == vault.entries.keys()
    for entry_id, original in vault.entries.items():
        copied = destination.entries[entry_id]
        assert copied is not original
        for attribute in ("name", "username", "url", "tags", "kind", "agent", "created", "modified", "has_totp"):
            assert getattr(copied, attribute) == getattr(original, attribute), attribute
        assert copied.rev == 1
        assert destination.read_secret(copied) == vault.read_secret(original)
        assert destination.file.records[entry_id] != vault.file.records[entry_id]
    assert destination.read_secret(destination.find("github")).history[0]["password"] == "hunter2-Github!"
    assert destination.aliases == vault.aliases and destination.aliases is not vault.aliases
    destination.commit()
    reopened = vaults.reopen(destination)
    assert reopened.value(*reopened.resolve("GITHUB_TOKEN")) == "second password"
    assert reopened.value(*reopened.resolve("AWS_REGION")) == "eu-west-1"
    with pytest.raises(VaultError, match="failed authentication"):
        Vault(VaultFile.load(destination.path), vault.vault_key.copy(), destination.path)  # the old key is useless
    assert vault.value(github) == "second password"  # and the source is untouched


def test_copy_into_needs_an_empty_destination(vault, vaults, isolated):
    destination = vaults.new(isolated / "copy")
    destination.add("already here", Secret())
    with pytest.raises(VaultError, match="not empty"):
        vault.copy_into(destination)
    assert [entry.name for entry in destination.list()] == ["already here"]
    empty_source = vaults.new(isolated / "empty")
    assert empty_source.copy_into(vaults.new(isolated / "copy2")) == 0


# ---------------------------------------------------------------------------
# VaultFile.from_bytes: the file is hostile input
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def valid_file() -> bytes:
    """A well-formed vault file with every kind of keyslot and a few records, made once."""
    vault_id = os.urandom(16)
    with keys.new_vault_key() as vault_key:
        recovery, _ = keys.create_recovery_slot(vault_key, vault_id)
        portable = keys.create_password_slot(vault_key, b"a master password", vault_id, params=FAST, backend=None)
        device = Keyslot(id="de" * 16, kind="device", wrap=recovery.wrap, created=1,
                         device={"backend": "macos-se", "policy": "biometry", "ref": "ab" * 16})
        records = {os.urandom(16).hex(): b64e(os.urandom(12 + 256 + 16)) for _ in range(3)}
        file = VaultFile(vault_id=vault_id, created=1_700_000_000, generation=7, slots=[portable, device, recovery],
                         index=b64e(os.urandom(12 + 1024 + 16)), records=records)
        return file.to_bytes()


def test_a_valid_file_round_trips(valid_file):
    file = VaultFile.from_bytes(valid_file)
    assert file.to_bytes() == valid_file
    assert (file.generation, file.created, len(file.slots), len(file.records)) == (7, 1_700_000_000, 3, 3)
    assert VaultFile.from_bytes(file.to_bytes()) == file


def changed(valid_file: bytes, **changes: Any) -> bytes:
    document = json.loads(valid_file)
    for key, value in changes.items():
        if value is ...:
            del document[key]
        else:
            document[key] = value
    return json.dumps(document).encode("utf-8")


@pytest.mark.parametrize(
    "data",
    [b"", b" ", b"null", b"[]", b"7", b'"irondome-vault"', b"{}", b"{", b"\xff\xfe\x00\x00", b"\x00" * 100,
     b"not json", b'{"format": "irondome-vault"', b"[" * 100_000, b'{"a":' * 50_000, b"{" + b'"a":{' * 10_000,
     b'{"format": "something-else", "version": 4}', b'{"format": NaN}', b'{"format": "irondome-vault"}'],
)
def test_things_that_are_not_a_vault_file(data):
    with pytest.raises(VaultError):
        VaultFile.from_bytes(data)


def test_a_newer_format_asks_for_an_upgrade(valid_file):
    for version in (5, 6, 99, 2**40):
        with pytest.raises(VaultError, match=f"newer IronDome \\(format {version}\\); upgrade to open it"):
            VaultFile.from_bytes(changed(valid_file, version=version))


def test_an_older_format_points_at_migrate(valid_file):
    for version in (3, 2, 1, 0, -1):
        with pytest.raises(VaultError, match="run: irondome migrate"):
            VaultFile.from_bytes(changed(valid_file, version=version))


@pytest.mark.parametrize("version", [None, "4", 4.0, True, [4], {"v": 4}, ...])
def test_a_file_without_a_usable_version(valid_file, version):
    with pytest.raises(VaultError, match="no version"):
        VaultFile.from_bytes(changed(valid_file, version=version))


FILE_DAMAGE = [
    ("format", "IRONDOME-VAULT"), ("format", None), ("format", ...),
    ("vault_id", None), ("vault_id", 5), ("vault_id", ""), ("vault_id", "!!"), ("vault_id", b64e(bytes(15))),
    ("vault_id", b64e(bytes(17))), ("vault_id", ...),
    ("keyslots", None), ("keyslots", []), ("keyslots", {}), ("keyslots", "slots"), ("keyslots", [None]),
    ("keyslots", [{}]), ("keyslots", [[]]), ("keyslots", ...),
    ("records", None), ("records", []), ("records", "records"), ("records", ...),
    ("records", {"short": "AAAA"}), ("records", {"A" * 32: "AAAA"}), ("records", {"a" * 32 + "\n": "AAAA"}),
    ("records", {"a" * 32: None}), ("records", {"a" * 32: 5}), ("records", {"a" * 32: "!!"}),
    ("records", {"a" * 32: ["AAAA"]}), ("records", {"../../etc/passwd": "AAAA"}),
    ("index", None), ("index", 5), ("index", "!!"), ("index", ["AAAA"]), ("index", ...),
    ("generation", -1), ("generation", "7"), ("generation", 7.0), ("generation", True), ("generation", None),
    ("generation", 2**63), ("generation", 2**70), ("generation", [7]),
    ("created", -1), ("created", "now"), ("created", 1.5), ("created", False), ("created", 2**64),
]


@pytest.mark.parametrize("field, value", FILE_DAMAGE, ids=[f"{f}={v!r}"[:44] for f, v in FILE_DAMAGE])
def test_a_malformed_field_makes_the_file_a_damaged_vault(valid_file, field, value):
    with pytest.raises(VaultError):
        VaultFile.from_bytes(changed(valid_file, **{field: value}))


def test_optional_counters_default_to_zero(valid_file):
    file = VaultFile.from_bytes(changed(valid_file, generation=..., created=...))
    assert file.generation == 0 and file.created == 0
    assert VaultFile.from_bytes(changed(valid_file, generation=2**63 - 1)).generation == 2**63 - 1


def test_keyslot_table_limits(valid_file):
    document = json.loads(valid_file)
    slot = document["keyslots"][2]
    many = [dict(slot, id=os.urandom(16).hex()) for _ in range(32)]
    assert len(VaultFile.from_bytes(changed(valid_file, keyslots=many)).slots) == 32
    with pytest.raises(VaultError, match="no usable keyslots"):
        VaultFile.from_bytes(changed(valid_file, keyslots=many + [dict(slot, id=os.urandom(16).hex())]))
    with pytest.raises(VaultError, match="duplicate keyslots"):
        VaultFile.from_bytes(changed(valid_file, keyslots=[slot, slot]))
    broken = dict(slot, wrap="AAAA")
    with pytest.raises(VaultError, match="keyslot"):
        VaultFile.from_bytes(changed(valid_file, keyslots=[slot, broken]))


def test_a_generation_too_large_for_its_field_is_refused_not_a_crash(vault, vaults):
    """It used to pass the parser and then raise OverflowError while the index was authenticated."""
    document = document_of(vault)
    for generation in (2**63, 2**64, 2**70, 10**30):
        document["generation"] = generation
        rewrite(vault, document)
        with pytest.raises(VaultError):
            vaults.reopen(vault)


@pytest.mark.parametrize("digits", [20, 400, 5_000, 300_000])
def test_an_absurd_number_is_refused_quickly(valid_file, digits):
    """Converting a huge decimal is quadratic on older interpreters; the file must be rejected, not chewed on."""
    text = valid_file.decode().replace('"generation": 7', '"generation": ' + "9" * digits)
    assert "9" * digits in text
    started = time.perf_counter()
    with pytest.raises(VaultError):
        VaultFile.from_bytes(text.encode())
    nested = valid_file.decode().replace('"created": 1700000000', '"created": [' + "1" * digits + "]")
    with pytest.raises(VaultError):
        VaultFile.from_bytes(nested.encode())
    assert time.perf_counter() - started < 20


def test_unknown_top_level_keys_are_ignored_and_duplicates_take_the_last(valid_file):
    file = VaultFile.from_bytes(changed(valid_file, future_field={"x": 1}))
    assert file.to_bytes() == valid_file
    doubled = valid_file.decode().replace('"generation": 7', '"generation": 3, "generation": 7')
    assert VaultFile.from_bytes(doubled.encode()).generation == 7


@given(st.binary(max_size=3000))
@settings(max_examples=400, deadline=None)
def test_arbitrary_bytes_are_never_a_vault_and_never_a_crash(data):
    with pytest.raises(VaultError):
        VaultFile.from_bytes(data)


@given(data=st.data())
@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_a_valid_file_with_random_byte_damage_is_refused_or_still_well_formed(data, valid_file):
    damaged = bytearray(valid_file)
    for _ in range(data.draw(st.integers(min_value=1, max_value=4), label="edits")):
        action = data.draw(st.sampled_from(["flip", "delete", "insert", "truncate", "duplicate"]), label="action")
        position = data.draw(st.integers(min_value=0, max_value=max(0, len(damaged) - 1)), label="position")
        if action == "flip" and damaged:
            damaged[position] ^= data.draw(st.integers(min_value=1, max_value=255), label="bits")
        elif action == "delete":
            del damaged[position : position + data.draw(st.integers(min_value=1, max_value=200), label="span")]
        elif action == "insert":
            damaged[position:position] = data.draw(st.binary(min_size=1, max_size=40), label="inserted")
        elif action == "truncate":
            del damaged[position:]
        else:
            span = data.draw(st.integers(min_value=1, max_value=300), label="span")
            damaged[position:position] = damaged[position : position + span]
    try:
        file = VaultFile.from_bytes(bytes(damaged))
    except VaultError:
        return
    assert VaultFile.from_bytes(file.to_bytes()) == file


JUNK = st.recursive(
    st.one_of(
        st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False, allow_infinity=False), st.text(max_size=40),
        st.binary(max_size=8).map(lambda raw: base64.b64encode(raw).decode("ascii")),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=3), st.dictionaries(st.text(max_size=6), children, max_size=3)
    ),
    max_leaves=6,
)


def containers_of(document: Any) -> List[Any]:
    found = [document]
    for value in document.values() if isinstance(document, dict) else document:
        if isinstance(value, (dict, list)):
            found.extend(containers_of(value))
    return found


@given(data=st.data())
@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_a_valid_file_with_random_structural_damage_is_refused_or_still_well_formed(data, valid_file):
    """Replace, delete or add values anywhere in the JSON tree: the answer is a VaultFile or a VaultError."""
    document = json.loads(valid_file)
    for _ in range(data.draw(st.integers(min_value=1, max_value=3), label="edits")):
        target = data.draw(st.sampled_from(containers_of(document)), label="container")
        action = data.draw(st.sampled_from(["replace", "delete", "add"]), label="action")
        if isinstance(target, list):
            if action == "add" or not target:
                target.append(data.draw(JUNK, label="appended"))
            else:
                index = data.draw(st.integers(min_value=0, max_value=len(target) - 1), label="index")
                if action == "delete":
                    del target[index]
                else:
                    target[index] = data.draw(JUNK, label="value")
        elif action == "add" or not target:
            target[data.draw(st.text(max_size=8), label="new key")] = data.draw(JUNK, label="new value")
        else:
            key = data.draw(st.sampled_from(sorted(target)), label="key")
            if action == "delete":
                del target[key]
            else:
                target[key] = data.draw(JUNK, label="value")
    try:
        file = VaultFile.from_bytes(json.dumps(document).encode("utf-8"))
    except VaultError:
        return
    assert len(file.vault_id) == 16 and 1 <= len(file.slots) <= 32
    assert 0 <= file.generation < 2**63 and 0 <= file.created < 2**63
    assert all(re.fullmatch(r"[0-9a-f]{32}", entry_id) for entry_id in file.records)
    assert VaultFile.from_bytes(file.to_bytes()) == file


# -- the decrypted index and records are checked as well ----------------------


@pytest.mark.parametrize(
    "entry_id, data",
    [
        ("short", {"name": "x"}), ("A" * 32, {"name": "x"}), ("a" * 32 + "\n", {"name": "x"}), ("a" * 32, None),
        ("a" * 32, []), ("a" * 32, "x"), ("a" * 32, {}), ("a" * 32, {"name": None}), ("a" * 32, {"name": 5}),
        ("a" * 32, {"name": "x" * 201}), ("a" * 32, {"name": "x", "username": None}),
        ("a" * 32, {"name": "x", "url": ["u"]}), ("a" * 32, {"name": "x", "tags": "dev"}),
        ("a" * 32, {"name": "x", "tags": [1]}), ("a" * 32, {"name": "x", "kind": "note"}),
        ("a" * 32, {"name": "x", "kind": ["login"]}), ("a" * 32, {"name": "x", "agent": "always"}),
        ("a" * 32, {"name": "x", "has_totp": 1}), ("a" * 32, {"name": "x", "created": -1}),
        ("a" * 32, {"name": "x", "created": 1.5}), ("a" * 32, {"name": "x", "modified": "now"}),
        ("a" * 32, {"name": "x", "rev": True}), ("a" * 32, {"name": "x", "rev": 2**63}),
        ("a" * 32, {"name": "x", "rev": -3}),
    ],
)
def test_malformed_index_entries_are_refused(entry_id, data):
    with pytest.raises(VaultError):
        Entry.from_dict(entry_id, data)


def test_an_index_entry_has_defaults_and_round_trips():
    entry = Entry.from_dict("a" * 32, {"name": "x"})
    assert entry == Entry(id="a" * 32, name="x")
    full = Entry(id="b" * 32, name="n", username="u", url="l", tags=["t"], kind="secret", created=1, modified=2, rev=3,
                 has_totp=True, agent="reveal")
    assert Entry.from_dict(full.id, full.to_dict()) == full
    assert "id" not in full.to_dict()


@pytest.mark.parametrize(
    "data",
    [None, [], "x", 5, {"password": None}, {"password": 5}, {"password": "p" * 100_001}, {"notes": None},
     {"notes": "n" * 1_000_001}, {"totp": "seed"}, {"totp": []}, {"fields": None}, {"fields": []},
     {"fields": {"a": 1}}, {"fields": {"a": None}}, {"history": None}, {"history": {}}, {"history": ["old"]},
     {"history": [None]}],
)
def test_malformed_secret_records_are_refused(data):
    with pytest.raises(VaultError):
        Secret.from_dict(data)


def test_a_secret_record_has_defaults_and_round_trips():
    assert Secret.from_dict({}) == Secret()
    full = Secret(password="p", totp={"secret": "s"}, notes="n", fields={"a": "b"}, history=[{"password": "o"}])
    assert Secret.from_dict(full.to_dict()) == full
    copied = full.to_dict()
    copied["fields"]["a"] = "changed"
    assert full.fields == {"a": "b"}  # to_dict hands out copies


def sealed_index(vault: Vault, document: Any) -> None:
    """Replace the vault's index with an authentic encryption of *document* (as a holder of the key could)."""
    from irondome.crypto import pad, seal

    padded = pad(json.dumps(document).encode("utf-8"), 1024)
    file = document_of(vault)
    file["index"] = b64e(seal(vault._index_key, padded, vault._index_aad(file["generation"])))
    rewrite(vault, file)


@pytest.mark.parametrize(
    "index",
    [
        None, [], "index", 5,
        {"entries": []}, {"aliases": []}, {"meta": []}, {"entries": {"short": {"name": "x"}}},
        {"aliases": {"A": {"entry": "ee" * 16, "field": "password"}}},
        {"aliases": {"A": None}}, {"aliases": {"A": {"entry": ["x"], "field": "password"}}},
        {"aliases": {"A": {"entry": {"x": 1}, "field": "password"}}},
        {"aliases": {"bad name": {"entry": "x", "field": "password"}}},
    ],
)
def test_an_authentic_but_malformed_index_is_a_damaged_vault(vault, vaults, index):
    sealed_index(vault, index)
    with pytest.raises(VaultError, match="index"):
        vaults.reopen(vault)


def test_an_authentic_index_that_is_not_json_is_a_damaged_vault(vault, vaults):
    from irondome.crypto import pad, seal

    file = document_of(vault)
    for plaintext in (b"not json", b"\xff\xfe", b"[" * 200_000):
        padded = pad(plaintext, 1024)
        file["index"] = b64e(seal(vault._index_key, padded, vault._index_aad(file["generation"])))
        rewrite(vault, file)
        with pytest.raises(VaultError, match="index is unreadable"):
            vaults.reopen(vault)
    lying_length = b"\xff\xff\xff\xff" + bytes(1020)
    file["index"] = b64e(seal(vault._index_key, lying_length, vault._index_aad(file["generation"])))
    rewrite(vault, file)
    with pytest.raises(VaultError, match="inconsistent"):
        vaults.reopen(vault)


def test_an_authentic_alias_must_point_at_an_entry_of_this_vault(vault, vaults):
    github = vault.find("github")
    entries = {entry_id: entry.to_dict() for entry_id, entry in vault.entries.items()}
    sealed_index(vault, {"entries": entries, "aliases": {"OK": {"entry": github.id, "field": "username"}}, "meta": {}})
    reopened = vaults.reopen(vault)
    assert reopened.value(*reopened.resolve("OK")) == "king"
    sealed_index(vault, {"entries": entries, "aliases": {"OK": {"entry": github.id, "field": 5}}, "meta": {}})
    with pytest.raises(VaultError, match="malformed alias"):
        vaults.reopen(vault)


# ---------------------------------------------------------------------------
# VaultFile.load
# ---------------------------------------------------------------------------


def test_load_reads_the_default_or_a_given_path(vault):
    assert VaultFile.load().vault_id == vault.vault_id
    assert VaultFile.load(vault.path) == VaultFile.load(str(vault.path))
    loaded = VaultFile.load()
    assert loaded.generation == 2 and [slot.kind for slot in loaded.slots] == ["password", "recovery"]


def test_load_says_how_to_create_a_vault_that_is_not_there(isolated):
    with pytest.raises(VaultError, match="there is no vault at .*Create one with: irondome init"):
        VaultFile.load()
    with pytest.raises(VaultError, match="there is no vault"):
        VaultFile.load(isolated / "missing" / "vault.irondome")


def test_load_of_something_unreadable_is_a_vault_error_not_a_traceback(vault, isolated):
    with pytest.raises(VaultError, match="cannot read the vault"):
        VaultFile.load(isolated)  # a directory
    if POSIX and not (hasattr(os, "geteuid") and os.geteuid() == 0):
        os.chmod(vault.path, 0)
        try:
            with pytest.raises(VaultError, match="cannot read the vault .*Permission denied"):
                VaultFile.load()
        finally:
            os.chmod(vault.path, 0o600)
    garbage = isolated / "garbage.irondome"
    garbage.write_bytes(os.urandom(500))
    with pytest.raises(VaultError, match="not an IronDome vault file"):
        VaultFile.load(garbage)


def test_load_refuses_a_file_too_large_to_be_a_vault(vault, monkeypatch):
    monkeypatch.setattr(paths, "MAX_FILE_BYTES", 100)
    with pytest.raises(VaultError, match="too large"):
        VaultFile.load()


# ---------------------------------------------------------------------------
# Whatever is done to a vault, what was put in comes back out
# ---------------------------------------------------------------------------

NAMES = ["alpha", "Beta", "aws/prod", "גיטהאב", "x y", "ALPHA"]
ALIASES = ["TOKEN", "db.password", "_k"]
OPERATION = st.one_of(
    st.tuples(st.just("add"), st.sampled_from(NAMES), st.text(max_size=30)),
    st.tuples(st.just("password"), st.sampled_from(NAMES), st.text(max_size=30)),
    st.tuples(st.just("rename"), st.sampled_from(NAMES), st.sampled_from(NAMES)),
    st.tuples(st.just("remove"), st.sampled_from(NAMES), st.none()),
    st.tuples(st.just("alias"), st.sampled_from(ALIASES), st.sampled_from(NAMES)),
    st.tuples(st.just("unalias"), st.sampled_from(ALIASES), st.none()),
    st.tuples(st.just("commit"), st.none(), st.none()),
    st.tuples(st.just("reopen"), st.none(), st.none()),
)


@given(operations=st.lists(OPERATION, min_size=1, max_size=10))
@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow]
)
def test_a_vault_behaves_like_a_dictionary_of_entries(operations, vaults, isolated):
    vault = vaults.new(isolated / uuid.uuid4().hex)
    model: Dict[str, str] = {}  # exact name -> password
    aliases: Dict[str, str] = {}  # alias -> exact name

    def exact(name: str) -> Optional[str]:
        if name in model:
            return name
        matches = [known for known in model if known.casefold() == name.casefold()]
        return matches[0] if len(matches) == 1 else None

    for kind, first, second in operations:
        if kind == "add":
            if any(known.casefold() == first.casefold() for known in model):
                with pytest.raises(UsageError):
                    vault.add(first, Secret(password=second))
            else:
                vault.add(first, Secret(password=second))
                model[first] = second
        elif kind == "password":
            target = exact(first)
            if target is None:
                with pytest.raises(NotFoundError):
                    vault.find(first)
            else:
                vault.update(vault.find(first), secret=Secret(password=second))
                model[target] = second
        elif kind == "rename":
            target = exact(first)
            if target is None:
                continue
            clash = any(known.casefold() == second.casefold() and known != target for known in model)
            if clash:
                with pytest.raises(UsageError):
                    vault.update(vault.find(target), name=second)
            else:
                vault.update(vault.find(target), name=second)
                model[second] = model.pop(target)
                aliases = {alias: (second if name == target else name) for alias, name in aliases.items()}
        elif kind == "remove":
            target = exact(first)
            if target is not None:
                vault.remove(vault.find(target))
                del model[target]
                aliases = {alias: name for alias, name in aliases.items() if name != target}
        elif kind == "alias":
            target = exact(second)
            if target is not None:
                vault.set_alias(first, vault.find(target))
                aliases[first] = target
        elif kind == "unalias":
            if first in aliases:
                vault.remove_alias(first)
                del aliases[first]
            else:
                with pytest.raises(NotFoundError):
                    vault.remove_alias(first)
        elif kind == "commit":
            vault.commit(snapshots=2)
        else:
            vault.commit(snapshots=2)
            vault = vaults.reopen(vault)

    vault.commit(snapshots=2)
    final = vaults.reopen(vault)
    assert sorted(entry.name for entry in final.list()) == sorted(model)
    for name, password in model.items():
        assert final.value(final.find(name)) == password
    assert {alias: final.entries[target.entry].name for alias, target in final.aliases.items()} == aliases
    for alias, name in aliases.items():
        assert final.value(*final.resolve(alias)) == model[name]
    assert set(final.file.records) == set(final.entries)


def test_helpers_use_the_conftest_password():
    with secret(PASSWORD) as buffer:
        assert isinstance(buffer, SecureBuffer) and bytes(buffer.view()) == PASSWORD.encode()


# -- one Unicode form for names (found by hand on a Mac) ----------------------------------------------------


NFC, NFD = "café", "café"  # the same word: one code point for the accented letter, or two


def test_a_name_typed_in_either_unicode_form_is_one_entry(plain):
    """macOS file names and many pastes carry the two-code-point form; both gave two rows that looked alike."""
    made = plain.add(NFD, Secret(password="one"))
    assert made.name == NFC  # stored in one form
    with pytest.raises(UsageError, match="already exists"):
        plain.add(NFC, Secret())
    with pytest.raises(UsageError, match="already exists"):
        plain.add(NFD.upper(), Secret())
    assert plain.find(NFD) is plain.find(NFC) is made
    assert plain.has_name(NFD) and plain.has_name(NFC)
    assert plain.resolve(f"irondome://{NFD}/password")[0] is made
    assert [entry.name for entry in plain.list(query=NFD)] == [NFC]


def test_renaming_to_the_other_unicode_form_changes_nothing_and_clashes_are_seen(plain):
    first = plain.add(NFC, Secret())
    plain.update(first, name=NFD)
    assert plain.find(NFC).name == NFC
    other = plain.add("tea", Secret())
    with pytest.raises(UsageError, match="already exists"):
        plain.update(other, name=NFD)


def test_a_name_stored_in_the_other_form_by_an_older_vault_is_still_reached(plain):
    """A vault written before names were stored in one form may hold both; each is reached as it is typed."""
    old = plain.add("tea", Secret(password="old"))
    old.name = NFD  # as such a vault holds it
    assert plain.find(NFD) is old and plain.find(NFC) is old  # alone, either spelling reaches it
    new = plain.add("coffee", Secret(password="new"))
    new.name = NFC
    assert plain.find(NFD) is old and plain.find(NFC) is new
    with pytest.raises(UsageError, match="differ only in case or Unicode form"):
        plain.find(NFC.upper())


def test_search_matches_a_username_typed_in_the_other_unicode_form(plain):
    plain.add("mail", Secret(), username=NFD + "@example.com", tags=[NFD])
    assert [entry.name for entry in plain.list(query=NFC)] == ["mail"]
    assert [entry.name for entry in plain.list(query=NFD.upper())] == ["mail"]


def test_a_name_clash_names_the_alias_spelled_the_same_way(plain):
    """With aliases API_KEY and api_key, adding an entry api_key was refused naming API_KEY."""
    first = plain.add("one", Secret())
    second = plain.add("two", Secret())
    plain.set_alias("API_KEY", first)
    plain.set_alias("api_key", second)
    assert "the alias api_key (it points at 'two')" in plain.conflict("api_key")
    assert "the alias API_KEY (it points at 'one')" in plain.conflict("API_KEY")
