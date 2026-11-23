"""Sessions and grants: what a token opens, for how long, how often, and what it never holds."""

from __future__ import annotations

import base64
import dataclasses
import errno
import gc
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from hypothesis import given, settings
from hypothesis import strategies as st

from irondome import audit, caps, otp, paths
from irondome.crypto import pad, seal
from irondome.errors import AuthError, IronDomeError, NotFoundError, PolicyError, UsageError, VaultError
from irondome.vault import Secret, Vault, VaultFile

#: A moment that is not on a 30-second boundary.
T0 = 1_800_000_007
SEED = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
GITHUB_PASSWORD = "hunter2-Github!"

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes and special files")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def still_isolated(isolated):
    """Fail any test that ends up pointing at paths outside its temporary directory."""
    yield
    assert str(paths.home()).startswith(str(isolated))
    assert str(paths.caps_dir()).startswith(str(isolated))


class Clock:
    """Stands in for time.time(): caps, audit and otp all read the clock through it."""

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch) -> Clock:
    fake = Clock(float(T0))
    monkeypatch.setattr(time, "time", fake)
    return fake


@pytest.fixture
def bank(vault):
    """The shared vault plus an entry with a one-time-password secret and an alias for its codes."""
    entry = vault.add("bank", Secret(password="pin-4711", totp=otp.make_totp(SEED, issuer="Bank", account="king")))
    vault.set_alias("BANK_OTP", entry, "totp")
    vault.commit()
    return vault


def make_token(kind: str, cap_id: bytes, secret: bytes) -> str:
    return "irondome_%s_%s_%s" % (kind[0], cap_id.hex(), base64.b32encode(secret).decode("ascii").rstrip("="))


def id_of(token: str) -> str:
    return caps.parse_token(token)[1]


def cap_path(token_or_id: str) -> Path:
    cap_id = token_or_id if len(token_or_id) == 32 else id_of(token_or_id)
    return paths.caps_dir() / f"{cap_id}.json"


def canonical(document: Dict[str, Any]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def header_of(token: str) -> Dict[str, Any]:
    return json.loads(cap_path(token).read_bytes())


def rewrite(token: str, change: Callable[[Dict[str, Any]], None]) -> None:
    """Edit the clear header and write it back exactly as IronDome formats a file."""
    document = header_of(token)
    change(document)
    cap_path(token).write_bytes(canonical(document))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def device_secret_of(descriptor: Dict[str, Any]) -> bytes:
    """The device secret a descriptor names, read the way only the file-based backend allows."""
    assert descriptor["backend"] == "software"
    return (paths.device_dir() / f"{descriptor['ref']}.key").read_bytes()


def device_key_of(descriptor: Dict[str, Any], vault_id: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, vault_id, b"irondome/v4/cap/device").derive(device_secret_of(descriptor))


def open_independently(token: str, raw: bytes) -> bytes:
    """Decrypt a capability file with `cryptography` alone, from the format the module documents."""
    _, letter, cap_id, encoded = token.split("_")
    kind = {"s": "session", "g": "grant"}[letter]
    document = json.loads(raw)
    vault_id = base64.b64decode(document["vault_id"])
    material = base64.b32decode(encoded + "====") + device_key_of(document["device"], vault_id)
    key = HKDF(
        hashes.SHA256(), 32, base64.b64decode(document["salt"]), b"irondome/v4/cap/" + kind.encode() + b"/token+device"
    ).derive(material)
    uses = document["uses_left"]
    device = json.dumps(document["device"], sort_keys=True, separators=(",", ":")).encode("ascii")
    aad = b"".join(
        [
            b"irondome/v4/cap\x00",
            b"\x02",
            kind.encode("ascii") + b"\x00",
            bytes.fromhex(cap_id),
            vault_id,
            document["created"].to_bytes(8, "big"),
            document["expires"].to_bytes(8, "big"),
            b"\x00" if uses is None else b"\x01" + uses.to_bytes(8, "big"),
            len(device).to_bytes(2, "big"),
            device,
            document["label"].encode("utf-8"),
        ]
    )
    wrap = base64.b64decode(document["wrap"])
    return AESGCM(key).decrypt(wrap[:12], wrap[12:], aad)


def plaintext_of(token: str) -> bytes:
    """The JSON a grant holds, as bytes."""
    padded = open_independently(token, cap_path(token).read_bytes())
    assert len(padded) % 256 == 0
    length = int.from_bytes(padded[:4], "big")
    return padded[4 : 4 + length]


def forms_of(secret: bytes) -> List[bytes]:
    """The ways a byte string usually shows up when it leaks into text."""
    return [
        secret,
        secret.hex().encode("ascii"),
        secret.hex().upper().encode("ascii"),
        base64.b64encode(secret).rstrip(b"="),
        base64.urlsafe_b64encode(secret).rstrip(b"="),
        base64.b32encode(secret).rstrip(b"="),
        base64.b32encode(secret).rstrip(b"=").lower(),
    ]


def everything_on_disk() -> bytes:
    return b"\x00".join(path.read_bytes() for path in sorted(paths.home().rglob("*")) if path.is_file())


def craft(vault, payload: Any, *, uses_left: Optional[int] = 1, ttl: int = 900, padded: Optional[bytes] = None) -> str:
    """A grant file sealed under a token the test knows, holding whatever the test puts in it.

    This is what anyone who holds a grant token can do: the format is public.
    """
    cap_id, secret, salt = os.urandom(16), os.urandom(32), os.urandom(16)
    now = int(time.time())
    if padded is None:
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        padded = bytes(pad(body, 256))
    device, device_key = caps._bound_device(vault)
    with device_key:
        header = caps._Header(
            kind="grant", id=cap_id.hex(), vault_id=vault.vault_id, created=now, expires=now + ttl,
            uses_left=uses_left, label="", device=device, salt=salt, wrap=b"",
        )
        with caps._wrap_key("grant", secret, device_key, salt) as key:
            header = dataclasses.replace(header, wrap=seal(key, padded, header.aad()))
    paths.write_atomic(cap_path(cap_id.hex()), header.to_bytes())
    return make_token("grant", cap_id, secret)


def good_payload(vault) -> Dict[str, Any]:
    return {
        "vault_id": b64(vault.vault_id),
        "mode": "use",
        "items": {"A": {"entry": "a", "field": "password", "value": "v"}},
        "audit_key": b64(b"k" * 32),
    }


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


def audit_trail(vault) -> List[tuple]:
    return [(event.kid, event.action, event.ok) for event in audit.read(vault)]


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

token_parts = st.tuples(
    st.sampled_from(["session", "grant"]), st.binary(min_size=16, max_size=16), st.binary(min_size=32, max_size=32)
)
token_alphabet = st.sampled_from("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_=- \n")


def parses(text: Any) -> bool:
    try:
        caps.parse_token(text)
    except AuthError:
        return False
    return True


@settings(max_examples=300, deadline=None)
@given(token_parts)
def test_every_token_parses_back_to_what_it_was_made_from(parts):
    kind, cap_id, secret = parts
    token = make_token(kind, cap_id, secret)

    assert caps.parse_token(token) == (kind, cap_id.hex(), secret)
    assert len(token) == 96
    assert re.fullmatch(caps.TOKEN_PATTERN, token)


@settings(max_examples=500, deadline=None)
@given(
    st.one_of(
        st.text(max_size=120), st.from_regex(caps.TOKEN_PATTERN), st.from_regex(r"irondome_[sg]_\w{0,40}_\w{0,60}")
    )
)
def test_text_either_is_refused_or_is_the_one_spelling_of_a_token(text):
    try:
        kind, cap_id, secret = caps.parse_token(text)
    except AuthError:
        assert not re.fullmatch(caps.TOKEN_PATTERN, text)
        return
    assert make_token(kind, bytes.fromhex(cap_id), secret) == text
    assert re.fullmatch(caps.TOKEN_PATTERN, text)


@settings(max_examples=500, deadline=None)
@given(token_parts, st.data())
def test_a_token_with_one_character_changed_is_refused_or_is_a_different_token(parts, data):
    token = make_token(*parts)
    index = data.draw(st.integers(0, len(token) - 1))
    replacement = data.draw(token_alphabet.filter(lambda char: char != token[index]))
    changed = token[:index] + replacement + token[index + 1 :]

    try:
        result = caps.parse_token(changed)
    except AuthError:
        assert not re.fullmatch(caps.TOKEN_PATTERN, changed)
        return
    assert result != caps.parse_token(token)
    assert make_token(result[0], bytes.fromhex(result[1]), result[2]) == changed


@settings(max_examples=300, deadline=None)
@given(token_parts, st.data())
def test_a_token_with_a_character_added_or_removed_is_refused(parts, data):
    token = make_token(*parts)
    index = data.draw(st.integers(0, len(token)))
    if data.draw(st.booleans()):
        changed = token[:index] + data.draw(token_alphabet) + token[index:]
    else:
        changed = token[: max(index - 1, 0)] + token[max(index, 1) :]

    assert not parses(changed)


@pytest.mark.parametrize(
    "text",
    [
        None,
        b"irondome_s_" + b"0" * 32 + b"_" + b"A" * 52,
        5,
        "",
        "irondome",
        "irondome_s_",
        "irondome_x_" + "0" * 32 + "_" + "A" * 52,
        "IRONDOME_s_" + "0" * 32 + "_" + "A" * 52,
        "irondome_s_" + "0" * 31 + "_" + "A" * 52,
        "irondome_s_" + "0" * 32 + "_" + "A" * 51,
        "irondome_s_" + "0" * 32 + "_" + "A" * 53,
        "irondome_s_" + "A" * 32 + "_" + "A" * 52,
        "irondome_s_" + "0" * 32 + "_" + "a" * 52,
        "irondome_s_" + "0" * 32 + "_" + "A" * 51 + "B",
        "irondome_s_" + "0" * 32 + "_" + "A" * 51 + "7",
        "irondome_s_" + "0" * 32 + "_" + "A" * 48 + "====",
        "irondome_s_" + "0" * 32 + "_" + "1" * 52,
        " irondome_s_" + "0" * 32 + "_" + "A" * 52,
        "irondome_s_" + "0" * 32 + "_" + "A" * 52 + "\n",
        "irondome_s_" + "0" * 32 + "_" + "A" * 52 + " ",
        "irondome-s-" + "0" * 32 + "-" + "A" * 52,
        "irondome_s_" + "\u0660" * 32 + "_" + "A" * 52,
    ],
)
def test_text_that_is_not_a_token_is_refused(text):
    with pytest.raises(AuthError):
        caps.parse_token(text)


def test_the_refusal_does_not_repeat_what_was_given():
    almost = "irondome_g_" + "ab" * 16 + "_" + "SECRETSECRETSECRETSECRETSECRETSECRETSECRETSECRETSEC" + "B"

    with pytest.raises(AuthError) as caught:
        caps.parse_token(almost)

    assert "SECRET" not in str(caught.value) and "abab" not in str(caught.value)


def test_the_pattern_finds_a_token_inside_other_text(vault):
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    leaked = f"export IRONDOME_SESSION={session}\nIRONDOME_GRANT='{grant}' irondome run -- env\n"

    assert re.findall(caps.TOKEN_PATTERN, leaked) == [session, grant]
    assert session.startswith("irondome_s_") and grant.startswith("irondome_g_")
    assert caps.parse_token(session)[0] == "session" and caps.parse_token(grant)[0] == "grant"


def test_tokens_and_ids_are_never_reused(vault):
    tokens = [caps.create_session(vault) for _ in range(5)]
    tokens += [caps.create_grant(vault, ["GITHUB_TOKEN"])[0] for _ in range(5)]

    assert len({caps.parse_token(token)[1] for token in tokens}) == 10
    assert len({caps.parse_token(token)[2] for token in tokens}) == 10


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def test_a_session_token_gives_back_the_vault_key(vault):
    token = caps.create_session(vault)

    with caps.open_session(token, VaultFile.load()) as first, caps.open_session(token, vault.file) as second:
        assert bytes(first.view()) == bytes(second.view()) == bytes(vault.vault_key.view())
        assert len(first) == 32


def test_the_key_from_a_session_opens_the_vault(vault):
    token = caps.create_session(vault, ttl=60, label="my shell")
    file = VaultFile.load()

    with Vault(file, caps.open_session(token, file)) as reopened:
        assert reopened.value(*reopened.resolve("GITHUB_TOKEN")) == GITHUB_PASSWORD
        assert sorted(entry.name for entry in reopened.list()) == ["aws/prod", "github"]


def test_a_session_file_opens_with_the_documented_key_and_associated_data(vault):
    token = caps.create_session(vault, label="format check")

    assert open_independently(token, cap_path(token).read_bytes()) == bytes(vault.vault_key.view())


def test_a_session_file_holds_only_the_documented_fields(vault, clock):
    token = caps.create_session(vault, ttl=300, label="laptop")

    document = header_of(token)

    assert set(document) == {
        "v", "kind", "id", "vault_id", "created", "expires", "uses_left", "label", "device", "salt", "wrap",
    }
    assert document["v"] == 2 and document["kind"] == "session" and document["id"] == id_of(token)
    assert base64.b64decode(document["vault_id"]) == vault.vault_id
    assert (document["created"], document["expires"]) == (T0, T0 + 300)
    assert document["uses_left"] is None and document["label"] == "laptop"
    assert document["device"] == vault.meta["cap_device"]
    assert set(document["device"]) == {"backend", "policy", "ref"}
    assert (document["device"]["backend"], document["device"]["policy"]) == ("software", "device")
    assert len(base64.b64decode(document["salt"])) == 16
    assert len(base64.b64decode(document["wrap"])) == 12 + 32 + 16
    assert cap_path(token).read_bytes() == canonical(document)


@pytest.mark.parametrize("ttl", [60, 61, 900, 43_199, 43_200])
def test_a_session_lasts_from_a_minute_to_twelve_hours(vault, clock, ttl):
    token = caps.create_session(vault, ttl=ttl)

    assert header_of(token)["expires"] == T0 + ttl


@pytest.mark.parametrize("ttl", [0, 1, 59, 43_201, 10**9, -900, True, 900.0, "900", None])
def test_a_session_of_any_other_length_is_refused(vault, ttl):
    with pytest.raises(UsageError):
        caps.create_session(vault, ttl=ttl)

    assert caps.list_caps() == []


@pytest.mark.parametrize(
    "label",
    ["\x1b[31mred", "two\nlines", "tab\there", "x" * 201, "\x9b", "\ud800", "\u202egnp.exe", "a\u200bb", None, 5, b"x"],
)
def test_a_label_must_be_short_printable_text(vault, label):
    with pytest.raises(UsageError):
        caps.create_session(vault, label=label)
    with pytest.raises(UsageError):
        caps.create_grant(vault, ["GITHUB_TOKEN"], label=label)

    assert caps.list_caps() == []


def test_a_label_may_be_in_any_script(vault):
    label = "\u05d4\u05de\u05d7\u05e9\u05d1 \u05e9\u05dc\u05d9 \u2013 \u65e5\u672c \U0001f512" + "x" * 180
    token = caps.create_session(vault, label=label)

    assert [info.label for info in caps.list_caps()] == [label]
    caps.open_session(token, vault.file).wipe()


def test_a_label_with_quotes_and_backslashes_survives_exactly(vault):
    label = 'say "hi" \\ and / {"v":2} \\u0041'
    session = caps.create_session(vault, label=label)
    grant, info = caps.create_grant(vault, ["GITHUB_TOKEN"], label=label)

    assert sorted(found.label for found in caps.list_caps()) == [label, label]
    assert info.label == label and caps.open_grant(grant).label == label
    caps.open_session(session, vault.file).wipe()
    assert audit.read(vault)[0].detail == f"ttl=900s label={label}"


def test_a_session_is_refused_from_the_second_it_expires_and_its_file_is_deleted(vault, clock):
    token = caps.create_session(vault, ttl=900)
    path = cap_path(token)

    clock.advance(899.9)
    caps.open_session(token, vault.file).wipe()
    clock.advance(0.1)

    with pytest.raises(AuthError, match="expired"):
        caps.open_session(token, vault.file)
    assert not path.exists()
    with pytest.raises(AuthError, match="opens nothing here"):
        caps.open_session(token, vault.file)


def test_a_token_with_the_right_id_and_the_wrong_secret_is_refused(vault):
    token = caps.create_session(vault)
    kind, cap_id, _ = caps.parse_token(token)
    before = cap_path(token).read_bytes()

    with pytest.raises(AuthError, match="does not open its session"):
        caps.open_session(make_token(kind, bytes.fromhex(cap_id), os.urandom(32)), vault.file)

    assert cap_path(token).read_bytes() == before
    caps.open_session(token, vault.file).wipe()


def test_a_token_nobody_issued_is_refused(vault):
    caps.create_session(vault)

    with pytest.raises(AuthError, match="opens nothing here"):
        caps.open_session(make_token("session", os.urandom(16), os.urandom(32)), vault.file)


def test_a_session_does_not_open_another_vault(vault, make_vault, tmp_path):
    other, _ = make_vault(path=tmp_path / "other" / "vault.irondome")
    token = caps.create_session(vault)

    with pytest.raises(AuthError, match="different vault"):
        caps.open_session(token, other.file)

    caps.open_session(token, vault.file).wipe()


def test_a_session_relabelled_for_another_vault_still_does_not_open(vault, make_vault, tmp_path):
    """The vault id is part of what is sealed, not just a field that is compared."""
    other, _ = make_vault(path=tmp_path / "other" / "vault.irondome")
    token = caps.create_session(vault)
    rewrite(token, lambda document: document.update(vault_id=b64(other.vault_id)))

    with pytest.raises(AuthError, match="does not open its session"):
        caps.open_session(token, other.file)


def test_a_grant_token_does_not_unlock_the_vault(vault):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    kind, cap_id, secret = caps.parse_token(token)

    with pytest.raises(AuthError, match="grant token"):
        caps.open_session(token, vault.file)
    with pytest.raises(AuthError):
        caps.open_session(make_token("session", bytes.fromhex(cap_id), secret), vault.file)

    assert caps.open_grant(token).value("GITHUB_TOKEN") == GITHUB_PASSWORD


def test_a_session_token_is_not_a_grant(vault):
    token = caps.create_session(vault)
    kind, cap_id, secret = caps.parse_token(token)

    with pytest.raises(AuthError, match="session token"):
        caps.open_grant(token)
    with pytest.raises(AuthError):
        caps.open_grant(make_token("grant", bytes.fromhex(cap_id), secret))

    caps.open_session(token, vault.file).wipe()


def test_a_locked_vault_cannot_start_a_session_or_make_a_grant(vault):
    vault.close()

    with pytest.raises(VaultError):
        caps.create_session(vault)
    with pytest.raises(IronDomeError):
        caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert caps.list_caps() == []


SESSION_EDITS: Dict[str, Callable[[Dict[str, Any]], None]] = {
    "expires an hour later": lambda document: document.update(expires=document["expires"] + 3600),
    "expires a minute sooner": lambda document: document.update(expires=document["expires"] - 60),
    "created a second earlier": lambda document: document.update(created=document["created"] - 1),
    "another label": lambda document: document.update(label="trusted"),
    "another salt": lambda document: document.update(salt=b64(b"\x01" * 16)),
    "one bit of the wrap flipped": lambda document: document.update(
        wrap=b64(bytes([base64.b64decode(document["wrap"])[0] ^ 1]) + base64.b64decode(document["wrap"])[1:])
    ),
    "the wrap of another session": lambda document: document.update(wrap=b64(os.urandom(60))),
}


@pytest.mark.parametrize("name", sorted(SESSION_EDITS))
def test_a_session_whose_header_was_edited_no_longer_opens(vault, name):
    token = caps.create_session(vault, ttl=900)
    original = cap_path(token).read_bytes()
    rewrite(token, SESSION_EDITS[name])
    edited = cap_path(token).read_bytes()

    assert edited != original
    assert caps._Header.from_bytes(edited, id_of(token))  # well-formed: only the cryptography can refuse it
    with pytest.raises(AuthError, match="does not open its session"):
        caps.open_session(token, vault.file)
    cap_path(token).write_bytes(original)
    caps.open_session(token, vault.file).wipe()


@pytest.mark.parametrize(
    "change",
    [
        lambda document: document.update(kind="grant"),
        lambda document: document.update(kind="root"),
        lambda document: document.update(uses_left=3),
        lambda document: document.update(v=1),
        lambda document: document.update(v=3),
        lambda document: document.update(v=True),
        lambda document: document.update(id="0" * 32),
        lambda document: document.update(expires=document["created"] + 43_201),
        lambda document: document.update(expires=document["created"]),
        lambda document: document.update(created=-1),
        lambda document: document.update(created=1.5),
        lambda document: document.update(expires=2**41),
        lambda document: document.update(label="\x1b[2J"),
        lambda document: document.update(label="\u202etxt.exe"),
        lambda document: document.update(label="x" * 201),
        lambda document: document.update(label=None),
        lambda document: document.update(vault_id=b64(b"\x00" * 15)),
        lambda document: document.update(salt=b64(b"\x00" * 17)),
        lambda document: document.update(wrap=b64(b"\x00" * 59)),
        lambda document: document.update(wrap=""),
        lambda document: document.update(extra=1),
        lambda document: document.pop("label"),
        lambda document: document.pop("device"),
        lambda document: document.update(device=None),
        lambda document: document.update(device={}),
        lambda document: document.update(device="software"),
        lambda document: document.update(device=[document["device"]]),
        lambda document: document["device"].update(policy="biometry"),
        lambda document: document["device"].update(policy="presence"),
        lambda document: document["device"].update(backend="windows-tpm"),
        lambda document: document["device"].update(backend="linux-tpm2"),
        lambda document: document["device"].update(nv_index="0x018abcde"),
        lambda document: document["device"].update(extra="x"),
        lambda document: document["device"].pop("ref"),
        lambda document: document["device"].update(ref=document["device"]["ref"].upper()),
        lambda document: document["device"].update(ref=document["device"]["ref"][:31]),
        lambda document: document["device"].update(ref=5),
        lambda document: document["device"].update(ref=None),
        lambda document: document["device"].update(ref=document["device"]["ref"] + "\n"),
        lambda document: document["device"].update(ref="../" + document["device"]["ref"][3:]),
    ],
)
def test_a_session_file_that_is_not_what_irondome_writes_is_refused(vault, change):
    token = caps.create_session(vault)
    rewrite(token, change)

    with pytest.raises(AuthError, match="damaged or was altered"):
        caps.open_session(token, vault.file)

    assert caps.list_caps() == []
    assert cap_path(token).exists()  # evidence is left in place; revoke or sweep cannot be tricked by it


def _twin_salt(raw: bytes) -> bytes:
    """The same salt bytes in other base64 text: the unused bits of the last character are set."""
    document = json.loads(raw)
    salt = document["salt"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    twin = salt[:-3] + alphabet[alphabet.index(salt[-3]) + 1] + "=="
    assert twin != salt and base64.b64decode(twin) == base64.b64decode(salt)
    return canonical(dict(document, salt=twin))


RESPELLINGS: Dict[str, Callable[[bytes], bytes]] = {
    "a second newline at the end": lambda raw: raw + b"\n",
    "no newline at the end": lambda raw: raw[:-1],
    "a space in front": lambda raw: b" " + raw,
    "a space after a comma": lambda raw: raw.replace(b'","', b'", "', 1),
    "indented": lambda raw: json.dumps(json.loads(raw), indent=1, sort_keys=True).encode() + b"\n",
    "keys in another order": lambda raw: (
        json.dumps(dict(reversed(list(json.loads(raw).items()))), separators=(",", ":")) + "\n"
    ).encode(),
    "a letter of the label written as an escape": lambda raw: raw.replace(
        b'"label":"laptop"', b'"label":"\\u006captop"'
    ),
    "the salt in other base64 text": _twin_salt,
}


@pytest.mark.parametrize("name", sorted(RESPELLINGS))
def test_a_file_that_says_the_same_in_other_bytes_is_refused(vault, name):
    """Every byte of a file is determined by what it says, so there is nothing to edit unnoticed."""
    token = caps.create_session(vault, label="laptop")
    original = cap_path(token).read_bytes()
    respelled = RESPELLINGS[name](original)
    same_content = json.loads(respelled) == json.loads(original) or name == "the salt in other base64 text"
    cap_path(token).write_bytes(respelled)

    assert respelled != original and same_content
    with pytest.raises(AuthError, match="damaged or was altered"):
        caps.open_session(token, vault.file)
    assert caps.list_caps() == []
    cap_path(token).write_bytes(original)
    caps.open_session(token, vault.file).wipe()


def tracked_buffers(monkeypatch) -> List[Any]:
    """Every SecureBuffer caps itself allocates from here on (the vault key, a grant's audit key, key material)."""
    made: List[Any] = []

    class Tracked(caps.SecureBuffer):
        __slots__ = ()

        def __init__(self, size: int) -> None:
            super().__init__(size)
            made.append(self)

    monkeypatch.setattr(caps, "SecureBuffer", Tracked)
    return made


def alive(made: List[Any]) -> List[Any]:
    return [buffer for buffer in made if not buffer.wiped]


def test_the_vault_key_is_wiped_when_a_session_does_not_open(vault, monkeypatch):
    token = caps.create_session(vault)
    kind, cap_id, _ = caps.parse_token(token)
    made = tracked_buffers(monkeypatch)

    with pytest.raises(AuthError):
        caps.open_session(make_token(kind, bytes.fromhex(cap_id), os.urandom(32)), vault.file)
    assert made and alive(made) == []

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    before = len(made)
    with monkeypatch.context() as patch:
        patch.setattr(caps, "open_sealed_into", interrupted)
        with pytest.raises(KeyboardInterrupt):
            caps.open_session(token, vault.file)
    assert len(made) > before and alive(made) == []

    key = caps.open_session(token, vault.file)
    survivors = alive(made)
    assert len(survivors) == 1 and survivors[0] is key
    key.wipe()


def test_a_grants_audit_key_is_wiped_when_the_grant_is_not_handed_over(vault, monkeypatch):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=2)
    made = tracked_buffers(monkeypatch)

    def unwritable(*args, **kwargs):
        raise audit.AuditError("the audit log could not be written (No space left on device)")

    with monkeypatch.context() as patch:
        patch.setattr(audit, "record", unwritable)
        with pytest.raises(audit.AuditError):
            caps.open_grant(token)
    assert made and alive(made) == []

    grant = caps.open_grant(token)
    survivors = alive(made)
    assert len(survivors) == 1 and survivors[0] is grant.audit_key
    grant.close()
    assert alive(made) == []


def live_text_and_bytes() -> Iterator[Any]:
    """Every str, bytes and bytearray some live Python object still refers to."""
    gc.collect()
    seen = set()
    for holder in gc.get_objects():
        for child in gc.get_referents(holder):
            if isinstance(child, (str, bytes, bytearray)) and id(child) not in seen:
                seen.add(id(child))
                yield child


def test_no_live_object_holds_key_material_once_capabilities_are_made_used_and_closed(vault):
    """Keys stay in locked memory: what caps copies out of it for a moment is zeroed, not just dropped."""
    session = caps.create_session(vault, label="laptop")
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN", "aws/prod"], uses=2)
    caps.open_session(session, vault.file).wipe()
    with caps.open_grant(token, consume=False):
        pass
    with caps.open_grant(token) as grant:
        assert grant.value("GITHUB_TOKEN") == GITHUB_PASSWORD
        audit.record(grant.audit_key, vault_id=grant.vault_id, kid=grant.id, action="use", target="GITHUB_TOKEN")
    caps.end_sessions(session, vault=vault)
    assert audit.verify(vault).ok

    with audit.owner_key(vault) as owner, audit.grant_key(owner, info.id) as holder:
        keys = [bytes(vault.vault_key.view()), bytes(owner.view()), bytes(holder.view())]
    descriptor = vault.meta["cap_device"]
    keys += [device_secret_of(descriptor), device_key_of(descriptor, vault.vault_id)]
    needles = [form for key in keys for form in forms_of(key)]
    texts = [needle.decode("latin-1") for needle in needles]
    ours = {id(item) for item in keys + needles + texts}

    for blob in live_text_and_bytes():
        if id(blob) in ours:
            continue
        haystack = blob if isinstance(blob, str) else bytes(blob).decode("latin-1")
        for text in texts:
            assert text not in haystack, "key material is still referenced by a live object"


def test_any_single_changed_byte_makes_a_session_unusable(vault):
    token = caps.create_session(vault)
    path = cap_path(token)
    original = path.read_bytes()

    @settings(max_examples=300, deadline=None)
    @given(data=st.data())
    def check(data):
        index = data.draw(st.integers(0, len(original) - 1))
        value = data.draw(st.integers(0, 255).filter(lambda byte: byte != original[index]))
        path.write_bytes(original[:index] + bytes([value]) + original[index + 1 :])

        with pytest.raises(AuthError):
            caps.open_session(token, vault.file)

    check()
    path.write_bytes(original)
    caps.open_session(token, vault.file).wipe()


def test_starting_a_session_is_recorded_and_the_record_holds_no_token(vault):
    token = caps.create_session(vault, ttl=120, label="laptop")

    (event,) = audit.read(vault)

    assert (event.kid, event.action, event.actor, event.ok) == ("vault", "session.start", "owner", True)
    assert event.target == id_of(token)
    assert event.detail == "ttl=120s label=laptop"
    assert audit.verify(vault).ok


def test_no_session_is_started_if_it_cannot_be_recorded(vault, monkeypatch):
    def unwritable(*args, **kwargs):
        raise audit.AuditError("the audit log could not be written (No space left on device)")

    with monkeypatch.context() as patch:
        patch.setattr(audit, "record", unwritable)
        with pytest.raises(audit.AuditError, match="no session was started"):
            caps.create_session(vault)

    assert caps.list_caps() == []
    assert not list(paths.caps_dir().glob("*.json"))


def test_an_interrupted_creation_leaves_no_capability_behind(vault, monkeypatch):
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    with monkeypatch.context() as patch:
        patch.setattr(audit, "record", interrupted)
        with pytest.raises(KeyboardInterrupt):
            caps.create_session(vault)
        with pytest.raises(KeyboardInterrupt):
            caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert not list(paths.caps_dir().glob("*.json"))
    assert caps.list_caps() == []


def test_ending_a_session_by_its_token(vault):
    first = caps.create_session(vault)
    second = caps.create_session(vault)

    assert caps.end_sessions(first) == 1

    assert not cap_path(first).exists()
    with pytest.raises(AuthError):
        caps.open_session(first, vault.file)
    caps.open_session(second, vault.file).wipe()
    assert caps.end_sessions(first) == 0


def test_ending_a_session_needs_only_its_id(vault):
    token = caps.create_session(vault)
    kind, cap_id, _ = caps.parse_token(token)

    assert caps.end_sessions(make_token(kind, bytes.fromhex(cap_id), os.urandom(32))) == 1
    assert not cap_path(token).exists()


def test_ending_every_session_leaves_grants_alone(vault):
    sessions = [caps.create_session(vault) for _ in range(3)]
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert caps.end_sessions() == 3

    assert [info.kind for info in caps.list_caps()] == ["grant"]
    for token in sessions:
        with pytest.raises(AuthError):
            caps.open_session(token, vault.file)
    assert caps.open_grant(grant).value("GITHUB_TOKEN") == GITHUB_PASSWORD
    assert caps.end_sessions() == 0


def test_end_sessions_refuses_what_is_not_a_session_token(vault):
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])

    with pytest.raises(UsageError):
        caps.end_sessions(grant)
    with pytest.raises(AuthError):
        caps.end_sessions("not a token")

    assert cap_path(grant).exists()


def test_ending_sessions_is_recorded_when_the_vault_is_passed(vault):
    first = caps.create_session(vault)
    second = caps.create_session(vault)

    caps.end_sessions(first, vault=vault)
    caps.end_sessions(vault=vault)
    caps.end_sessions(vault=vault)

    events = audit.read(vault)
    assert [event.action for event in events] == ["session.start", "session.start", "session.end", "session.end"]
    assert [event.target for event in events[2:]] == [id_of(first), id_of(second)]
    assert audit.verify(vault).ok


def test_a_session_is_ended_even_if_that_cannot_be_recorded(vault, monkeypatch):
    token = caps.create_session(vault)

    def unwritable(*args, **kwargs):
        raise audit.AuditError("the audit log could not be written (No space left on device)")

    with monkeypatch.context() as patch:
        patch.setattr(audit, "record", unwritable)
        with pytest.raises(audit.AuditError, match=r"1 session ended, but that could not be recorded"):
            caps.end_sessions(token, vault=vault)

    assert not cap_path(token).exists()


# ---------------------------------------------------------------------------
# Grants: scope
# ---------------------------------------------------------------------------


def test_a_grant_opens_exactly_what_was_named(vault, clock):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN", "github/username", "aws/prod/region"], uses=None)

    assert info == caps.GrantInfo(
        id=id_of(token), mode="use", created=T0, expires=T0 + 900, uses_left=None, label="",
        references=("GITHUB_TOKEN", "github/username", "aws/prod/region"),
    )
    with caps.open_grant(token) as grant:
        assert grant.names() == ["GITHUB_TOKEN", "aws/prod/region", "github/username"]
        assert grant.value("GITHUB_TOKEN") == GITHUB_PASSWORD
        assert grant.value("github/username") == "king"
        assert grant.value("aws/prod/region") == "eu-west-1"
        assert grant.source("GITHUB_TOKEN") == ("github", "password")
        assert grant.source("aws/prod/region") == ("aws/prod", "region")
        assert (grant.id, grant.mode, grant.created, grant.expires, grant.uses_left, grant.label) == (
            info.id, "use", T0, T0 + 900, None, "",
        )
        assert grant.vault_id == vault.vault_id
        assert not grant.is_totp("GITHUB_TOKEN")


@pytest.mark.parametrize(
    "outside",
    ["github", "github/password", "aws/prod", "github/notes", "GITHUB_TOKEN/username", "github_token", "", "*",
     "irondome://github", "GITHUB_TOKEN ", None, 5, ["GITHUB_TOKEN"]],
)
def test_a_grant_refuses_everything_that_was_not_named(vault, outside):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)

    with caps.open_grant(token) as grant:
        assert not grant.has(outside)
        assert not grant.is_totp(outside)
        with pytest.raises(PolicyError, match="does not cover"):
            grant.value(outside)
        with pytest.raises(PolicyError):
            grant.source(outside)


def test_a_grant_holds_nothing_but_the_named_values(vault):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN", "github/username"], mode="reveal")

    plain = plaintext_of(token)
    payload = json.loads(plain)

    assert set(payload) == {"vault_id", "mode", "items", "audit_key"}
    assert payload["mode"] == "reveal"
    assert payload["items"] == {
        "GITHUB_TOKEN": {"entry": "github", "field": "password", "value": GITHUB_PASSWORD},
        "github/username": {"entry": "github", "field": "username", "value": "king"},
    }
    assert base64.b64decode(payload["vault_id"]) == vault.vault_id
    for other in (b"AKIA-not-a-real-key", b"eu-west-1", b"personal", b"https://github.com", b"aws/prod",
                  b"correct horse battery staple"):
        assert other not in plain
    for form in forms_of(bytes(vault.vault_key.view())):
        assert form not in plain


def test_the_audit_key_in_a_grant_is_that_grants_and_not_the_owners(vault):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"])
    embedded = base64.b64decode(json.loads(plaintext_of(token))["audit_key"])

    with audit.owner_key(vault) as owner, audit.grant_key(owner, info.id) as expected:
        assert embedded == bytes(expected.view())
        assert embedded != bytes(owner.view())
    with caps.open_grant(token) as grant:
        assert bytes(grant.audit_key.view()) == embedded


def test_a_grant_is_a_snapshot_taken_when_it_was_made(vault):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    vault.update(vault.find("github"), secret=Secret(password="rotated-since"))
    vault.commit()

    assert caps.open_grant(token).value("GITHUB_TOKEN") == GITHUB_PASSWORD
    newer, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    assert caps.open_grant(newer).value("GITHUB_TOKEN") == "rotated-since"


def test_a_reference_may_carry_the_irondome_scheme(vault):
    token, info = caps.create_grant(vault, ["irondome://GITHUB_TOKEN", "github/username"], uses=None)

    assert info.references == ("GITHUB_TOKEN", "github/username")
    with caps.open_grant(token) as grant:
        assert grant.names() == ["GITHUB_TOKEN", "github/username"]
        assert grant.has("irondome://GITHUB_TOKEN") and grant.has("GITHUB_TOKEN")
        assert grant.has("IRONDOME://GITHUB_TOKEN") and grant.value("IronDome://GITHUB_TOKEN") == GITHUB_PASSWORD
        assert grant.value("irondome://github/username") == "king"
        assert not grant.has("irondome://irondome://GITHUB_TOKEN")


def test_a_grant_can_cover_sixty_four_references(vault):
    for index in range(64):
        vault.add(f"service-{index}", Secret(password=f"password-{index}"))
    references = [f"service-{index}" for index in range(64)]

    token, info = caps.create_grant(vault, references)

    assert len(info.references) == 64
    with caps.open_grant(token) as grant:
        assert [grant.value(reference) for reference in references] == [f"password-{index}" for index in range(64)]


@pytest.mark.parametrize(
    "references",
    [
        [],
        ["GITHUB_TOKEN", "GITHUB_TOKEN"],
        ["GITHUB_TOKEN", "github/username", "irondome://GITHUB_TOKEN"],
        "GITHUB_TOKEN",
        None,
        {"GITHUB_TOKEN"},
        [5],
        [None],
        [""],
        ["irondome://"],
        ["irondome://irondome://GITHUB_TOKEN"],
        ["Irondome://IRONDOME://GITHUB_TOKEN"],
        [" GITHUB_TOKEN"],
        ["GITHUB_TOKEN\u00a0"],
        ["bad\nname"],
        ["bad\x7fname"],
        ["bad\x85name"],
        ["bad\u2028name"],
        ["x" * 513],
        [f"service-{index}" for index in range(65)],
    ],
)
def test_references_that_cannot_be_granted_are_refused(vault, references):
    with pytest.raises(UsageError):
        caps.create_grant(vault, references)

    assert caps.list_caps() == []
    assert audit.read(vault) == []


@pytest.mark.parametrize(
    "reference", ["nope", "github/nofield", "aws/prod/username", "github/totp", "aws/prod/url", "NOPE/password"]
)
def test_a_reference_with_nothing_behind_it_is_refused(vault, reference):
    with pytest.raises(NotFoundError):
        caps.create_grant(vault, ["GITHUB_TOKEN", reference])

    assert caps.list_caps() == []


@pytest.mark.parametrize("mode", ["admin", "", "USE", "use ", None, 1, ["use"]])
def test_a_mode_other_than_use_or_reveal_is_refused(vault, mode):
    with pytest.raises(UsageError):
        caps.create_grant(vault, ["GITHUB_TOKEN"], mode=mode)


@pytest.mark.parametrize("mode", ["use", "reveal"])
def test_the_mode_is_sealed_inside_the_grant(vault, mode):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"], mode=mode, uses=None)

    assert info.mode == mode
    assert caps.open_grant(token).mode == mode
    assert caps.open_grant(token, consume=False).mode == mode
    assert "mode" not in header_of(token) and b"reveal" not in cap_path(token).read_bytes()


# ---------------------------------------------------------------------------
# Grants: uses
# ---------------------------------------------------------------------------


def test_a_grant_is_single_use_unless_told_otherwise(vault):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"])
    path = cap_path(token)

    grant = caps.open_grant(token)

    assert info.uses_left == 1 and grant.uses_left == 0
    assert grant.value("GITHUB_TOKEN") == GITHUB_PASSWORD
    assert not path.exists()
    assert caps.list_caps() == []
    with pytest.raises(AuthError, match="opens nothing here"):
        caps.open_grant(token)
    with pytest.raises(AuthError, match="opens nothing here"):
        caps.open_grant(token, consume=False)


def test_a_grant_counts_its_uses_down_and_is_destroyed_after_the_last(vault):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=3)
    path = cap_path(token)
    versions = [path.read_bytes()]

    for expected in (2, 1):
        with caps.open_grant(token) as grant:
            assert grant.uses_left == expected
            assert grant.value("GITHUB_TOKEN") == GITHUB_PASSWORD
        assert header_of(token)["uses_left"] == expected
        assert caps.list_caps()[0].uses_left == expected
        versions.append(path.read_bytes())
    with caps.open_grant(token) as grant:
        assert grant.uses_left == 0
        assert grant.value("GITHUB_TOKEN") == GITHUB_PASSWORD

    assert not path.exists()
    with pytest.raises(AuthError):
        caps.open_grant(token)
    documents = [json.loads(version) for version in versions]
    assert len({document["wrap"] for document in documents}) == 3
    assert len({document["salt"] for document in documents}) == 3


def test_an_earlier_copy_of_the_wrap_does_not_open_under_a_later_count(vault):
    """The count is sealed in: a file cannot be given uses back by editing the number."""
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=2)
    caps.open_grant(token).close()

    for count in (2, 3, 1000, None):
        rewrite(token, lambda document, count=count: document.update(uses_left=count))
        with pytest.raises(AuthError, match="does not open its grant"):
            caps.open_grant(token)


def test_a_grant_without_a_limit_can_be_used_again_and_again(vault):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    before = cap_path(token).read_bytes()

    for _ in range(5):
        with caps.open_grant(token) as grant:
            assert grant.uses_left is None
            assert grant.value("GITHUB_TOKEN") == GITHUB_PASSWORD

    assert info.uses_left is None
    assert cap_path(token).read_bytes() == before
    assert [action for _, action, _ in audit_trail(vault)] == ["grant.create"] + ["grant.use"] * 5


@pytest.mark.parametrize("uses", [0, -1, True, False, 1.0, "1", 1_000_001, 10**12])
def test_a_use_count_that_is_not_a_positive_whole_number_is_refused(vault, uses):
    with pytest.raises(UsageError):
        caps.create_grant(vault, ["GITHUB_TOKEN"], uses=uses)

    assert caps.list_caps() == []


def test_the_largest_use_count_is_a_million(vault):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=1_000_000)

    assert info.uses_left == 1_000_000
    assert caps.open_grant(token).uses_left == 999_999


def test_looking_at_a_grant_spends_nothing_records_nothing_and_shows_no_values(vault):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN", "github/username"], uses=2, label="for claude")
    before = cap_path(token).read_bytes()
    trail = audit_trail(vault)

    for _ in range(3):
        with caps.open_grant(token, consume=False) as grant:
            assert not grant.consumed
            assert grant.names() == ["GITHUB_TOKEN", "github/username"]
            assert (grant.id, grant.mode, grant.uses_left, grant.label) == (info.id, "use", 2, "for claude")
            assert grant.has("GITHUB_TOKEN") and not grant.has("github")
            assert grant.source("github/username") == ("github", "username")
            with pytest.raises(PolicyError, match="holds no values"):
                grant.value("GITHUB_TOKEN")
            assert GITHUB_PASSWORD not in repr(vars(grant))

    assert cap_path(token).read_bytes() == before
    assert audit_trail(vault) == trail
    assert caps.open_grant(token).uses_left == 1


def test_a_closed_grant_gives_nothing_more(vault):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    grant = caps.open_grant(token)
    assert grant.consumed and grant.value("GITHUB_TOKEN") == GITHUB_PASSWORD

    grant.close()
    grant.close()

    assert grant.audit_key.wiped
    assert grant.names() == ["GITHUB_TOKEN"] and grant.has("GITHUB_TOKEN")
    with pytest.raises(PolicyError, match="closed"):
        grant.value("GITHUB_TOKEN")
    assert GITHUB_PASSWORD not in repr(vars(grant)) and GITHUB_PASSWORD not in repr(grant)


def test_a_token_with_the_right_id_and_the_wrong_secret_spends_nothing(vault):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    kind, cap_id, _ = caps.parse_token(token)
    before = cap_path(token).read_bytes()
    trail = audit_trail(vault)
    wrong = make_token(kind, bytes.fromhex(cap_id), os.urandom(32))

    with pytest.raises(AuthError, match="does not open its grant"):
        caps.open_grant(wrong)
    with pytest.raises(AuthError, match="does not open its grant"):
        caps.open_grant(wrong, consume=False)

    assert cap_path(token).read_bytes() == before
    assert audit_trail(vault) == trail
    assert caps.open_grant(token).value("GITHUB_TOKEN") == GITHUB_PASSWORD


RACER = """
import os, sys, time
from irondome import caps
from irondome.errors import AuthError

time.sleep(max(0.0, float(sys.argv[1]) - time.time()))
try:
    grant = caps.open_grant(os.environ["IRONDOME_GRANT"])
except AuthError:
    print("refused")
else:
    print("opened", grant.uses_left, grant.value("GITHUB_TOKEN"))
"""


def race(token: str, racers: int) -> List[str]:
    environment = dict(os.environ, IRONDOME_GRANT=token)
    start = repr(time.time() + 3.0)
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", RACER, start], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(racers)
    ]
    results = [process.communicate(timeout=120) for process in processes]
    assert [process.returncode for process in processes] == [0] * racers, [error for _, error in results]
    return sorted(output.strip() for output, _ in results)


def test_of_processes_racing_for_a_single_use_grant_exactly_one_wins(vault):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"])

    outcomes = race(token, 8)

    assert outcomes == [f"opened 0 {GITHUB_PASSWORD}"] + ["refused"] * 7
    assert not cap_path(token).exists()
    assert audit_trail(vault) == [("vault", "grant.create", True), (info.id, "grant.use", True)]
    assert audit.verify(vault).ok


def test_processes_racing_for_a_three_use_grant_get_exactly_three_uses(vault):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=3)

    outcomes = race(token, 8)

    assert outcomes == [f"opened {left} {GITHUB_PASSWORD}" for left in (0, 1, 2)] + ["refused"] * 5
    assert not cap_path(token).exists()
    assert audit_trail(vault) == [("vault", "grant.create", True)] + [(info.id, "grant.use", True)] * 3
    assert [event.detail for event in audit.read(vault)[1:]] == ["uses left: 2", "uses left: 1", "uses left: 0"]


def test_of_threads_racing_for_a_single_use_grant_exactly_one_wins(vault):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    outcomes: List[str] = []
    gate = threading.Barrier(8)

    def attempt() -> None:
        gate.wait(30)
        try:
            outcomes.append(caps.open_grant(token).value("GITHUB_TOKEN"))
        except AuthError:
            outcomes.append("refused")

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)

    assert sorted(outcomes) == sorted([GITHUB_PASSWORD] + ["refused"] * 7)


# ---------------------------------------------------------------------------
# Grants: lifetime
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ttl", [60, 900, 86_400, 2_592_000])
def test_a_grant_lasts_from_a_minute_to_thirty_days(vault, clock, ttl):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=ttl)

    assert info.expires == header_of(token)["expires"] == T0 + ttl
    clock.advance(ttl - 1)
    assert caps.open_grant(token).value("GITHUB_TOKEN") == GITHUB_PASSWORD


@pytest.mark.parametrize("ttl", [0, 59, 2_592_001, -60, True, 900.0, "15m", None])
def test_a_grant_of_any_other_length_is_refused(vault, ttl):
    with pytest.raises(UsageError):
        caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=ttl)

    assert caps.list_caps() == []


def test_a_grant_is_refused_from_the_second_it_expires_and_its_file_is_deleted(vault, clock):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=600, uses=None)
    path = cap_path(token)

    clock.advance(599)
    caps.open_grant(token).close()
    clock.advance(1)

    with pytest.raises(AuthError, match="expired"):
        caps.open_grant(token)
    assert not path.exists()
    with pytest.raises(AuthError, match="opens nothing here"):
        caps.open_grant(token)


def test_an_expired_grant_is_deleted_even_when_only_looked_at_or_given_a_wrong_secret(vault, clock):
    first, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    second, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    kind, cap_id, _ = caps.parse_token(second)
    clock.advance(60)

    with pytest.raises(AuthError, match="expired"):
        caps.open_grant(first, consume=False)
    with pytest.raises(AuthError, match="expired"):
        caps.open_grant(make_token(kind, bytes.fromhex(cap_id), os.urandom(32)))

    assert not cap_path(first).exists() and not cap_path(second).exists()


def test_a_grant_opened_in_time_stops_giving_values_when_it_expires(vault, clock):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=300, uses=None)
    grant = caps.open_grant(token)

    clock.advance(299)
    assert grant.value("GITHUB_TOKEN") == GITHUB_PASSWORD
    clock.advance(1)

    with pytest.raises(AuthError, match="expired"):
        grant.value("GITHUB_TOKEN")


def test_presenting_an_expired_grant_is_recorded_for_the_owner(vault, clock):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    clock.advance(61)

    with pytest.raises(AuthError):
        caps.open_grant(token)

    events = audit.read(vault)
    assert audit_trail(vault) == [("vault", "grant.create", True), (info.id, "grant.use", False)]
    assert events[1].ts == T0 + 61 and events[1].detail == "refused: the grant had expired; it was destroyed"
    assert audit.verify(vault).ok


def test_an_expired_grant_is_refused_the_same_whether_or_not_that_can_be_recorded(vault, clock, monkeypatch):
    first, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    made_up = craft(vault, {"anything": "at all"}, ttl=60)
    clock.advance(61)
    log = paths.audit_file().read_bytes()

    def unwritable(*args, **kwargs):
        raise audit.AuditError("the audit log could not be written (No space left on device)")

    with monkeypatch.context() as patch:
        patch.setattr(audit, "record", unwritable)
        with pytest.raises(AuthError, match="expired"):
            caps.open_grant(first)
    with pytest.raises(AuthError, match="expired"):
        caps.open_grant(made_up)

    assert not cap_path(first).exists() and not cap_path(made_up).exists()
    assert paths.audit_file().read_bytes() == log


def test_an_expiry_pushed_back_in_the_header_does_not_revive_a_grant(vault, clock):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    clock.advance(61)
    rewrite(token, lambda document: document.update(expires=document["expires"] + 86_400))

    with pytest.raises(AuthError, match="does not open its grant"):
        caps.open_grant(token)


# ---------------------------------------------------------------------------
# Grants: one-time passwords
# ---------------------------------------------------------------------------


def test_a_grant_for_a_one_time_password_holds_codes_and_never_the_seed(bank, clock):
    token, _ = caps.create_grant(bank, ["BANK_OTP", "bank/totp", "GITHUB_TOKEN"], ttl=600)

    plain = plaintext_of(token)
    item = json.loads(plain)["items"]["BANK_OTP"]
    settings_ = bank.read_secret(bank.find("bank")).totp

    assert set(item) == {"entry", "field", "period", "digits", "codes"}
    assert (item["entry"], item["field"], item["period"], item["digits"]) == ("bank", "totp", 30, 6)
    for form in forms_of(base64.b32decode(SEED)):
        assert form not in plain
    assert SEED.encode() not in plain and SEED.lower().encode() not in plain
    assert b"secret" not in plain and b"SHA1" not in plain and b"algorithm" not in plain
    first, last = T0 // 30, (T0 + 599) // 30
    assert item["codes"] == {str(counter): otp.code_at(settings_, counter * 30) for counter in range(first, last + 1)}
    assert len(item["codes"]) == 21
    assert json.loads(plain)["items"]["bank/totp"]["codes"] == item["codes"]
    on_disk = everything_on_disk()
    assert SEED.encode() not in on_disk and base64.b32decode(SEED) not in on_disk


def test_the_codes_from_a_grant_are_the_real_ones_for_every_moment_of_its_life(bank, clock):
    settings_ = bank.read_secret(bank.find("bank")).totp
    token, _ = caps.create_grant(bank, ["BANK_OTP"], ttl=600, uses=None)

    with caps.open_grant(token) as grant:
        assert grant.is_totp("BANK_OTP")
        assert grant.source("BANK_OTP") == ("bank", "totp")
        for moment in list(range(T0, T0 + 600, 7)) + [T0 + 599, T0 + 599.99]:
            clock.now = moment
            assert grant.value("BANK_OTP") == otp.code_at(settings_, moment) == otp.code_for(settings_)
        clock.now = T0 + 600
        with pytest.raises(AuthError):
            grant.value("BANK_OTP")


def test_a_grant_tells_the_time_step_of_its_one_time_passwords(bank, clock):
    token, _ = caps.create_grant(bank, ["BANK_OTP", "bank"], ttl=600, uses=None)
    with caps.open_grant(token) as grant:
        assert grant.period("BANK_OTP") == grant.period("irondome://BANK_OTP") == 30
        with pytest.raises(PolicyError, match="not a one-time password"):
            grant.period("bank")
        with pytest.raises(PolicyError, match="does not cover"):
            grant.period("SOMETHING_ELSE")
    with pytest.raises(PolicyError, match="holds no values"):
        grant.period("BANK_OTP")  # closed
    with pytest.raises(PolicyError, match="holds no values"):
        caps.open_grant(token, consume=False).period("BANK_OTP")


def test_no_code_is_stored_for_a_time_step_that_starts_when_the_grant_ends(bank, clock):
    clock.now = 1_800_000_000  # exactly on a 30-second boundary
    token, _ = caps.create_grant(bank, ["BANK_OTP"], ttl=60)

    codes = json.loads(plaintext_of(token))["items"]["BANK_OTP"]["codes"]

    assert sorted(codes) == [str(60_000_000), str(60_000_001)]


def test_a_grant_with_a_one_time_password_lasts_a_day_at_most(bank, clock):
    with pytest.raises(UsageError, match="at most 86400 seconds"):
        caps.create_grant(bank, ["GITHUB_TOKEN", "BANK_OTP"], ttl=86_401)
    assert caps.list_caps() == []

    token, info = caps.create_grant(bank, ["BANK_OTP"], ttl=86_400, uses=None)

    assert info.expires == T0 + 86_400
    assert len(json.loads(plaintext_of(token))["items"]["BANK_OTP"]["codes"]) == 2881
    clock.advance(86_399)
    settings_ = bank.read_secret(bank.find("bank")).totp
    assert caps.open_grant(token).value("BANK_OTP") == otp.code_at(settings_, T0 + 86_399)


def test_a_fast_changing_one_time_password_limits_the_grant_further(vault, clock):
    entry = vault.add("fast", Secret(totp=otp.make_totp(SEED, period=1, digits=8)))
    vault.set_alias("FAST_OTP", entry, "totp")

    with pytest.raises(UsageError, match="shorter window"):
        caps.create_grant(vault, ["FAST_OTP"], ttl=5001)
    token, _ = caps.create_grant(vault, ["FAST_OTP"], ttl=5000, uses=None)

    item = json.loads(plaintext_of(token))["items"]["FAST_OTP"]
    assert (item["period"], item["digits"], len(item["codes"])) == (1, 8, 5000)
    clock.advance(4999)
    assert caps.open_grant(token).value("FAST_OTP") == otp.code_at(vault.read_secret(entry).totp, T0 + 4999)


def test_a_one_time_password_for_a_moment_before_the_grant_was_made_is_refused(bank, clock):
    token, _ = caps.create_grant(bank, ["BANK_OTP"], ttl=600, uses=None)
    grant = caps.open_grant(token)
    clock.now = T0 - 3600  # the clock was set back

    with pytest.raises(AuthError):
        grant.value("BANK_OTP")


def test_looking_at_a_grant_does_not_load_its_codes(bank):
    token, _ = caps.create_grant(bank, ["BANK_OTP"], uses=2)

    with caps.open_grant(token, consume=False) as grant:
        assert grant.is_totp("BANK_OTP")
        with pytest.raises(PolicyError):
            grant.value("BANK_OTP")
        assert all(not item.codes and not item.value for item in grant._items.values())


# ---------------------------------------------------------------------------
# Grants: tampering, and content a token holder made up
# ---------------------------------------------------------------------------


GRANT_EDITS: Dict[str, Callable[[Dict[str, Any]], None]] = {
    "expires a day later": lambda document: document.update(expires=document["expires"] + 86_400),
    "expires a minute sooner": lambda document: document.update(expires=document["expires"] - 60),
    "created a second earlier": lambda document: document.update(created=document["created"] - 1),
    "more uses": lambda document: document.update(uses_left=1000),
    "one use fewer": lambda document: document.update(uses_left=1),
    "unlimited uses": lambda document: document.update(uses_left=None),
    "another label": lambda document: document.update(label="approved by the owner"),
    "another vault": lambda document: document.update(vault_id=b64(b"\x07" * 16)),
    "another salt": lambda document: document.update(salt=b64(b"\x01" * 16)),
    "one bit of the wrap flipped": lambda document: document.update(
        wrap=b64(base64.b64decode(document["wrap"])[:-1] + bytes([base64.b64decode(document["wrap"])[-1] ^ 0x80]))
    ),
    "a block of the wrap cut off": lambda document: document.update(
        wrap=b64(base64.b64decode(document["wrap"])[:-256])
    ),
}


@pytest.mark.parametrize("consume", [True, False])
@pytest.mark.parametrize("name", sorted(GRANT_EDITS))
def test_a_grant_whose_header_was_edited_no_longer_opens(vault, name, consume):
    for index in range(3):
        vault.add(f"filler-{index}", Secret(password="x" * 200))
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN", "filler-0", "filler-1", "filler-2"], uses=2)
    original = cap_path(token).read_bytes()
    trail = audit_trail(vault)
    rewrite(token, GRANT_EDITS[name])
    edited = cap_path(token).read_bytes()

    assert edited != original
    assert caps._Header.from_bytes(edited, id_of(token))  # well-formed: only the cryptography can refuse it
    with pytest.raises(AuthError, match="does not open its grant"):
        caps.open_grant(token, consume=consume)
    assert cap_path(token).read_bytes() == edited
    assert audit_trail(vault) == trail
    cap_path(token).write_bytes(original)
    assert caps.open_grant(token).uses_left == 1


@pytest.mark.parametrize(
    "change",
    [
        lambda document: document.update(kind="session"),
        lambda document: document.update(kind=["grant"]),
        lambda document: document.update(uses_left=0),
        lambda document: document.update(uses_left=-1),
        lambda document: document.update(uses_left=1_000_001),
        lambda document: document.update(uses_left=True),
        lambda document: document.update(uses_left="1"),
        lambda document: document.update(expires=document["created"] + 2_592_001),
        lambda document: document.update(expires=document["created"] + 59),
        lambda document: document.update(wrap=b64(os.urandom(12 + 255 + 16))),
        lambda document: document.update(wrap=b64(os.urandom(28))),
        lambda document: document.update(wrap=12),
        lambda document: document.update(salt="not base64"),
    ],
)
def test_a_grant_file_that_is_not_what_irondome_writes_is_refused(vault, change):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    rewrite(token, change)

    with pytest.raises(AuthError, match="damaged or was altered"):
        caps.open_grant(token)
    with pytest.raises(AuthError, match="damaged or was altered"):
        caps.open_grant(token, consume=False)

    assert caps.list_caps() == []


def test_any_single_changed_byte_makes_a_grant_unusable(vault):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=3)
    path = cap_path(token)
    original = path.read_bytes()
    trail = audit_trail(vault)

    @settings(max_examples=300, deadline=None)
    @given(data=st.data(), consume=st.booleans())
    def check(data, consume):
        index = data.draw(st.integers(0, len(original) - 1))
        value = data.draw(st.integers(0, 255).filter(lambda byte: byte != original[index]))
        path.write_bytes(original[:index] + bytes([value]) + original[index + 1 :])

        with pytest.raises(AuthError):
            caps.open_grant(token, consume=consume)

    check()
    assert audit_trail(vault) == trail
    path.write_bytes(original)
    assert caps.open_grant(token).uses_left == 2


def without(document: Dict[str, Any], key: str) -> Dict[str, Any]:
    return {name: value for name, value in document.items() if name != key}


def with_item(document: Dict[str, Any], item: Any, name: str = "A") -> Dict[str, Any]:
    return dict(document, items={name: item})


TOTP_ITEM = {"entry": "a", "field": "totp", "period": 30, "digits": 6, "codes": {"60000000": "123456"}}

BAD_PAYLOADS: Dict[str, Callable[[Dict[str, Any]], Any]] = {
    "not JSON": lambda p: b"not json",
    "bytes that are not text": lambda p: b"\xff\xfe\x00",
    "a list": lambda p: b"[]",
    "nothing": lambda p: b"",
    "a missing key": lambda p: without(p, "mode"),
    "an extra key": lambda p: dict(p, vault_key="x"),
    "another vault": lambda p: dict(p, vault_id=b64(b"\x00" * 16)),
    "a vault id that is not base64": lambda p: dict(p, vault_id="!!"),
    "a vault id that is not text": lambda p: dict(p, vault_id=5),
    "an unknown mode": lambda p: dict(p, mode="admin"),
    "a mode that is not text": lambda p: dict(p, mode=["use"]),
    "no items": lambda p: dict(p, items={}),
    "items that are a list": lambda p: dict(p, items=["A"]),
    "too many items": lambda p: dict(p, items={f"n{i}": p["items"]["A"] for i in range(65)}),
    "an item that is text": lambda p: with_item(p, "v"),
    "an item without a value": lambda p: with_item(p, {"entry": "a", "field": "password"}),
    "a value that is a number": lambda p: with_item(p, {"entry": "a", "field": "password", "value": 5}),
    "an empty value": lambda p: with_item(p, {"entry": "a", "field": "password", "value": ""}),
    "an item with an extra field": lambda p: with_item(p, {"entry": "a", "field": "password", "value": "v", "x": 1}),
    "an entry that is a number": lambda p: with_item(p, {"entry": 5, "field": "password", "value": "v"}),
    "an empty entry": lambda p: with_item(p, {"entry": "", "field": "password", "value": "v"}),
    "an entry that is too long": lambda p: with_item(p, {"entry": "e" * 201, "field": "password", "value": "v"}),
    "a field that is too long": lambda p: with_item(p, {"entry": "a", "field": "f" * 65, "value": "v"}),
    "a field that is missing": lambda p: with_item(p, {"entry": "a", "value": "v"}),
    "a reference with a control character": lambda p: with_item(p, p["items"]["A"], "A\x07"),
    "a reference with the scheme": lambda p: with_item(p, p["items"]["A"], "irondome://A"),
    "a reference with the scheme in capitals": lambda p: with_item(p, p["items"]["A"], "IRONDOME://A"),
    "a reference with a space at the end": lambda p: with_item(p, p["items"]["A"], "A "),
    "a reference with a line separator": lambda p: with_item(p, p["items"]["A"], "A\u2028B"),
    "an empty reference": lambda p: with_item(p, p["items"]["A"], ""),
    "a reference that is too long": lambda p: with_item(p, p["items"]["A"], "r" * 513),
    "a one-time password with a value": lambda p: with_item(p, {"entry": "a", "field": "totp", "value": "123456"}),
    "a one-time password without codes": lambda p: with_item(p, without(TOTP_ITEM, "codes")),
    "a one-time password with a seed beside it": lambda p: with_item(p, dict(TOTP_ITEM, secret=SEED)),
    "a period of zero": lambda p: with_item(p, dict(TOTP_ITEM, period=0)),
    "a period that is too long": lambda p: with_item(p, dict(TOTP_ITEM, period=301)),
    "a period that is text": lambda p: with_item(p, dict(TOTP_ITEM, period="30")),
    "a period that is true": lambda p: with_item(p, dict(TOTP_ITEM, period=True)),
    "five digits": lambda p: with_item(p, dict(TOTP_ITEM, digits=5, codes={"1": "12345"})),
    "digits that are true": lambda p: with_item(p, dict(TOTP_ITEM, digits=True)),
    "no codes": lambda p: with_item(p, dict(TOTP_ITEM, codes={})),
    "codes that are a list": lambda p: with_item(p, dict(TOTP_ITEM, codes=["123456"])),
    "too many codes": lambda p: with_item(p, dict(TOTP_ITEM, codes={str(i): "000000" for i in range(5001)})),
    "a counter with a leading zero": lambda p: with_item(p, dict(TOTP_ITEM, codes={"007": "123456"})),
    "a negative counter": lambda p: with_item(p, dict(TOTP_ITEM, codes={"-1": "123456"})),
    "a counter that is not a number": lambda p: with_item(p, dict(TOTP_ITEM, codes={"now": "123456"})),
    "a counter beyond 64 bits": lambda p: with_item(p, dict(TOTP_ITEM, codes={str(2**64): "123456"})),
    "a code of the wrong length": lambda p: with_item(p, dict(TOTP_ITEM, codes={"1": "1234567"})),
    "a code that is not digits": lambda p: with_item(p, dict(TOTP_ITEM, codes={"1": "12345x"})),
    "a code in other digits": lambda p: with_item(
        p, dict(TOTP_ITEM, codes={"1": "\u0661\u0662\u0663\u0664\u0665\u0666"})
    ),
    "a code that is a number": lambda p: with_item(p, dict(TOTP_ITEM, codes={"1": 123456})),
    "an audit key that is not base64": lambda p: dict(p, audit_key="!!"),
    "an audit key that is too short": lambda p: dict(p, audit_key=b64(b"k" * 31)),
    "an audit key that is too long": lambda p: dict(p, audit_key=b64(b"k" * 33)),
    "an audit key that is a number": lambda p: dict(p, audit_key=5),
    "a key given twice": lambda p: json.dumps(p).encode().replace(b'"mode": "use"', b'"mode": "use", "mode": "reveal"'),
    "a number too long to convert": lambda p: json.dumps(dict(p, n=0))
    .encode()
    .replace(b'"n": 0', b'"n": ' + b"9" * 100),
    "nesting without end": lambda p: b'{"items":' + b"[" * 100_000,
    "NaN": lambda p: json.dumps(dict(p, n=0)).encode().replace(b'"n": 0', b'"n": NaN'),
}


def test_a_well_formed_grant_made_by_hand_opens(vault):
    """The control for the test below: the crafting itself is sound."""
    token = craft(vault, good_payload(vault))
    totp = craft(vault, with_item(good_payload(vault), TOTP_ITEM), uses_left=None)

    assert caps.open_grant(token).value("A") == "v"
    assert caps.open_grant(totp, consume=False).is_totp("A")


@pytest.mark.parametrize("consume", [True, False])
@pytest.mark.parametrize("name", sorted(BAD_PAYLOADS))
def test_a_grant_holding_what_irondome_would_not_write_is_refused(vault, name, consume):
    token = craft(vault, BAD_PAYLOADS[name](good_payload(vault)), uses_left=2)
    before = cap_path(token).read_bytes()

    with time_limit(20):
        with pytest.raises(AuthError, match="is not what IronDome writes"):
            caps.open_grant(token, consume=consume)

    assert cap_path(token).read_bytes() == before
    assert not paths.audit_file().exists()


@pytest.mark.parametrize("padded", [b"\x00\x00\x01\x2c" + b"x" * 252, b"\xff" * 256, b"\x00" * 256])
def test_a_grant_whose_padding_is_wrong_is_refused(vault, padded):
    token = craft(vault, None, padded=padded)

    with pytest.raises(AuthError, match="is not what IronDome writes"):
        caps.open_grant(token)


def test_values_too_large_for_a_grant_are_refused(vault, monkeypatch):
    vault.add("certificate", Secret(notes="x" * 5000))
    monkeypatch.setattr(caps, "_MAX_PAYLOAD", 4096)

    with pytest.raises(UsageError, match="grant fewer of them"):
        caps.create_grant(vault, ["certificate/notes"])

    assert caps.list_caps() == []


def test_a_large_value_survives_the_round_trip(vault):
    key = "-----BEGIN KEY-----\n" + "\n".join("Q" * 64 for _ in range(4000)) + "\n-----END KEY-----\n"
    vault.add("deploy", Secret(notes=key, password="\u05e1\u05d9\u05e1\u05de\u05d4 \U0001f512 \u00fc"))

    token, _ = caps.create_grant(vault, ["deploy/notes", "deploy"], uses=2)

    for _ in range(2):
        with caps.open_grant(token) as grant:
            assert grant.value("deploy/notes") == key
            assert grant.value("deploy") == "\u05e1\u05d9\u05e1\u05de\u05d4 \U0001f512 \u00fc"


def test_the_size_of_a_grant_file_does_not_follow_the_length_of_a_short_value(vault):
    vault.add("short", Secret(password="a"))
    vault.add("longer", Secret(password="a" * 64))
    one, _ = caps.create_grant(vault, ["short"])
    two, _ = caps.create_grant(vault, ["longer"])

    assert len(header_of(one)["wrap"]) == len(header_of(two)["wrap"])


# ---------------------------------------------------------------------------
# Grants and the audit log
# ---------------------------------------------------------------------------


def test_making_and_using_a_grant_is_recorded(vault):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN", "github/username"], uses=2, ttl=120, label="claude")
    caps.open_grant(token).close()
    caps.open_grant(token, consume=False).close()
    caps.open_grant(token).close()

    events = audit.read(vault)

    assert audit_trail(vault) == [
        ("vault", "grant.create", True), (info.id, "grant.use", True), (info.id, "grant.use", True),
    ]
    assert (events[0].actor, events[0].target) == ("owner", info.id)
    assert events[0].detail == "mode=use uses=2 ttl=120s label=claude references: GITHUB_TOKEN, github/username"
    assert [(event.actor, event.target, event.detail) for event in events[1:]] == [
        ("grant", info.id, "uses left: 1"), ("grant", info.id, "uses left: 0"),
    ]
    assert audit.verify(vault) == audit.AuditReport(ok=True, count=3, problems=[])


def test_a_grant_holder_can_add_its_own_records_with_what_the_grant_gives_it(vault):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"])

    with caps.open_grant(token) as grant:
        audit.record(
            grant.audit_key, vault_id=grant.vault_id, kid=grant.id, action="use", actor="grant",
            target="GITHUB_TOKEN", detail="gh repo list",
        )

    events = audit.read(vault)
    assert [(event.kid, event.action) for event in events] == [
        ("vault", "grant.create"), (info.id, "grant.use"), (info.id, "use"),
    ]
    assert events[2].detail == "gh repo list"
    assert audit.verify(vault).ok


def test_nothing_secret_reaches_the_disk_in_the_clear(vault):
    session = caps.create_session(vault, label="laptop")
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN", "aws/prod"], uses=3, label="ci")
    caps.open_grant(token).close()
    caps.open_session(session, vault.file).wipe()

    disk = everything_on_disk()

    for text in (GITHUB_PASSWORD, "AKIA-not-a-real-key", "GITHUB_TOKEN", "aws/prod", "github"):
        for form in forms_of(text.encode()):
            assert form not in disk
    for bearer in (session, token):
        secret = caps.parse_token(bearer)[2]
        assert bearer.encode() not in disk and bearer.rsplit("_", 1)[1].encode() not in disk
        for form in forms_of(secret):
            assert form not in disk
    for form in forms_of(bytes(vault.vault_key.view())):
        assert form not in disk
    descriptor = vault.meta["cap_device"]
    for key in (device_secret_of(descriptor), device_key_of(descriptor, vault.vault_id)):
        for form in forms_of(key):
            assert form not in disk, "the device secret is never kept beside the vault"


def test_no_grant_is_made_if_it_cannot_be_recorded(vault, monkeypatch):
    def unwritable(*args, **kwargs):
        raise audit.AuditError("the audit log could not be written (No space left on device)")

    with monkeypatch.context() as patch:
        patch.setattr(audit, "record", unwritable)
        with pytest.raises(audit.AuditError, match="no grant was made"):
            caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert caps.list_caps() == []
    assert not list(paths.caps_dir().glob("*.json"))


def test_a_grant_is_not_used_if_the_use_cannot_be_recorded(vault, monkeypatch):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=2)
    before = cap_path(token).read_bytes()

    def unwritable(*args, **kwargs):
        raise audit.AuditError("the audit log could not be written (No space left on device)")

    with monkeypatch.context() as patch:
        patch.setattr(audit, "record", unwritable)
        with pytest.raises(audit.AuditError, match="that grant was not used"):
            caps.open_grant(token)

    assert cap_path(token).read_bytes() == before
    assert caps.open_grant(token).uses_left == 1


def test_a_real_full_disk_refuses_the_use_and_spends_nothing(vault, monkeypatch):
    """The same, with the failure where it would really happen: in the write to the log."""
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    before = cap_path(token).read_bytes()
    log = paths.audit_file().read_bytes()

    def full_disk(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")

    with monkeypatch.context() as patch:
        patch.setattr(audit.os, "write", full_disk)
        with pytest.raises(audit.AuditError, match="No space left on device"):
            caps.open_grant(token)

    assert cap_path(token).read_bytes() == before
    assert paths.audit_file().read_bytes() == log
    assert caps.open_grant(token).value("GITHUB_TOKEN") == GITHUB_PASSWORD


def test_a_use_whose_count_cannot_be_written_gives_nothing_and_says_so_in_the_log(vault, monkeypatch):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=2)
    before = cap_path(token).read_bytes()

    def read_only(path, data):
        raise OSError(errno.EROFS, "Read-only file system")

    with monkeypatch.context() as patch:
        patch.setattr(paths, "write_atomic", read_only)
        with pytest.raises(VaultError, match="that grant was not used"):
            caps.open_grant(token)

    assert cap_path(token).read_bytes() == before
    assert audit_trail(vault) == [
        ("vault", "grant.create", True), (info.id, "grant.use", True), (info.id, "grant.use", False),
    ]
    assert caps.open_grant(token).uses_left == 1


def test_a_use_that_can_neither_be_counted_nor_corrected_in_the_log_still_gives_nothing(vault, monkeypatch):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=2)
    before = cap_path(token).read_bytes()
    real_record = audit.record
    calls: List[str] = []

    def once(*args, **kwargs):
        calls.append(kwargs["action"])
        if len(calls) > 1:
            raise audit.AuditError("the audit log could not be written (No space left on device)")
        real_record(*args, **kwargs)

    def read_only(path, data):
        raise OSError(errno.EROFS, "Read-only file system")

    with monkeypatch.context() as patch:
        patch.setattr(audit, "record", once)
        patch.setattr(paths, "write_atomic", read_only)
        with pytest.raises(VaultError, match="that grant was not used"):
            caps.open_grant(token)

    assert calls == ["grant.use", "grant.use"]
    assert cap_path(token).read_bytes() == before
    assert audit_trail(vault) == [("vault", "grant.create", True), (info.id, "grant.use", True)]


def test_a_last_use_whose_file_cannot_be_deleted_gives_nothing(vault, monkeypatch):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"])

    def stuck(path):
        raise OSError(errno.EPERM, "Operation not permitted")

    with monkeypatch.context() as patch:
        patch.setattr(paths, "secure_delete", stuck)
        with pytest.raises(VaultError, match="that grant was not used"):
            caps.open_grant(token)

    assert cap_path(token).exists()
    assert audit_trail(vault)[-1] == (info.id, "grant.use", False)
    assert caps.open_grant(token).value("GITHUB_TOKEN") == GITHUB_PASSWORD


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


@posix_only
@pytest.mark.parametrize("umask", [0o000, 0o022, 0o077])
def test_capability_files_are_owner_only_whatever_the_umask(vault, umask):
    previous = os.umask(umask)
    try:
        session = caps.create_session(vault)
        grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=3)
        caps.open_grant(grant).close()  # rewritten with the new count
    finally:
        os.umask(previous)

    assert stat.S_IMODE(paths.caps_dir().stat().st_mode) == 0o700
    assert stat.S_IMODE(cap_path(session).stat().st_mode) == 0o600
    assert stat.S_IMODE(cap_path(grant).stat().st_mode) == 0o600
    for path in paths.caps_dir().iterdir():
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0, path.name
    assert sorted(path.name for path in paths.caps_dir().iterdir()) == sorted(
        [".lock", f"{id_of(session)}.json", f"{id_of(grant)}.json"]
    )


def junk(name: str, content: bytes) -> Path:
    paths.ensure_dir(paths.caps_dir())
    path = paths.caps_dir() / name
    path.write_bytes(content)
    return path


def scatter_junk(tmp_path: Path, real: str) -> Dict[str, Path]:
    """Things that are not capabilities, under names and in places a capability could be."""
    target = tmp_path / "outside.txt"
    target.write_bytes(b"not IronDome's\n")
    made = {
        "empty": junk("0" * 32 + ".json", b""),
        "noise": junk("1" * 32 + ".json", os.urandom(300)),
        "empty object": junk("2" * 32 + ".json", b"{}\n"),
        "deep": junk("3" * 32 + ".json", b"[" * 200_000),
        "huge number": junk("4" * 32 + ".json", b'{"created":' + b"9" * 3_000_000 + b"}"),
        "wrong types": junk("5" * 32 + ".json", canonical(dict.fromkeys(["v", "kind", "id", "vault_id", "created",
                                                                         "expires", "uses_left", "label", "device",
                                                                         "salt", "wrap"], []))),
        "copy under another name": junk("6" * 32 + ".json", cap_path(real).read_bytes()),
        "not json name": junk("notes.txt", b"hello"),
        "short name": junk("abc.json", b"{}"),
        "other extension": junk("b" * 32 + ".txt", b"{}"),
        "interrupted write": junk(".tmp-abc123", cap_path(real).read_bytes()),
    }
    directory = paths.caps_dir() / ("7" * 32 + ".json")
    directory.mkdir()
    made["directory"] = directory
    if os.name != "nt":
        link = paths.caps_dir() / ("8" * 32 + ".json")
        os.symlink(str(cap_path(real)), str(link))
        made["link to a real one"] = link
        outside = paths.caps_dir() / ("9" * 32 + ".json")
        os.symlink(str(target), str(outside))
        made["link outside"] = outside
        pipe = paths.caps_dir() / ("a" * 32 + ".json")
        os.mkfifo(str(pipe))
        made["pipe"] = pipe
    made["outside target"] = target
    return made


def test_listing_shows_capabilities_and_ignores_everything_else(vault, clock, tmp_path):
    session = caps.create_session(vault, ttl=600, label="laptop")
    clock.advance(5)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60, uses=3, label="ci")
    scatter_junk(tmp_path, grant)

    with time_limit(20):
        listed = caps.list_caps()

    assert listed == [
        caps.CapInfo(id=id_of(session), kind="session", created=T0, expires=T0 + 600, uses_left=None,
                     label="laptop", expired=False),
        caps.CapInfo(id=id_of(grant), kind="grant", created=T0 + 5, expires=T0 + 65, uses_left=3, label="ci",
                     expired=False),
    ]
    clock.advance(60)
    assert [(info.kind, info.expired) for info in caps.list_caps()] == [("session", False), ("grant", True)]


def test_listing_an_absent_directory_is_empty(vault):
    assert not paths.caps_dir().exists()
    assert caps.list_caps() == []
    assert caps.sweep() == 0
    assert caps.end_sessions() == 0
    assert caps.destroy_all() == 0


def test_a_token_whose_file_is_not_a_capability_is_refused_without_waiting(vault, tmp_path):
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    made = scatter_junk(tmp_path, grant)

    with time_limit(30):
        for name, path in made.items():
            match = re.fullmatch(r"([0-9a-f]{32})\.json", path.name)
            if match is None:
                continue
            cap_id = bytes.fromhex(match.group(1))
            with pytest.raises(AuthError):
                caps.open_grant(make_token("grant", cap_id, os.urandom(32)))
            with pytest.raises(AuthError):
                caps.open_session(make_token("session", cap_id, os.urandom(32)), vault.file)
            assert os.path.lexists(str(path)), name

    assert made["outside target"].read_bytes() == b"not IronDome's\n"
    assert caps.open_grant(grant).value("GITHUB_TOKEN") == GITHUB_PASSWORD


@posix_only
def test_a_capability_reached_through_a_symbolic_link_is_refused(vault, tmp_path):
    """Even a genuine file: a capability is a file in the directory, not whatever a link points at."""
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    for token in (session, grant):
        moved = tmp_path / cap_path(token).name
        cap_path(token).rename(moved)
        os.symlink(str(moved), str(cap_path(token)))

    with pytest.raises(AuthError, match="damaged or was altered"):
        caps.open_session(session, vault.file)
    with pytest.raises(AuthError, match="damaged or was altered"):
        caps.open_grant(grant)
    assert caps.list_caps() == []
    assert caps.sweep() == 0

    assert caps.destroy_all() == 2
    assert (tmp_path / cap_path(session).name).exists() and (tmp_path / cap_path(grant).name).exists()


def test_a_real_token_does_not_open_a_copy_of_its_file_under_another_name(vault):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    kind, _, secret = caps.parse_token(token)
    junk("6" * 32 + ".json", cap_path(token).read_bytes())

    with pytest.raises(AuthError):
        caps.open_grant(make_token(kind, bytes.fromhex("6" * 32), secret))


@posix_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can read any file")
def test_a_capability_file_that_cannot_be_read_is_refused_and_not_listed(vault):
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    os.chmod(cap_path(session), 0o000)
    os.chmod(cap_path(grant), 0o000)

    with pytest.raises(AuthError, match="Permission denied"):
        caps.open_session(session, vault.file)
    with pytest.raises(AuthError, match="Permission denied"):
        caps.open_grant(grant)
    assert caps.list_caps() == []
    assert caps.sweep() == 0

    assert caps.revoke(id_of(grant)) == 1
    assert caps.end_sessions(session) == 1
    assert not cap_path(session).exists() and not cap_path(grant).exists()


def test_a_directory_entry_that_cannot_be_examined_is_still_looked_at(vault, monkeypatch):
    token = caps.create_session(vault)
    real_scandir = os.scandir

    class Unknowable:
        def __init__(self, entry) -> None:
            self.name, self.path = entry.name, entry.path

        def is_dir(self, follow_symlinks: bool = True) -> bool:
            raise PermissionError(errno.EACCES, "Permission denied")

    @contextmanager
    def scandir(path):
        with real_scandir(path) as entries:
            yield [Unknowable(entry) for entry in entries]

    monkeypatch.setattr(caps.os, "scandir", scandir)

    assert [info.id for info in caps.list_caps()] == [id_of(token)]
    assert caps.end_sessions() == 1


def test_a_file_too_large_to_be_a_capability_is_not_read(vault, monkeypatch):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    monkeypatch.setattr(caps, "_MAX_FILE", 64)

    assert caps.list_caps() == []
    with pytest.raises(AuthError, match="damaged or was altered"):
        caps.open_grant(token)


# ---------------------------------------------------------------------------
# Revoking, sweeping, destroying
# ---------------------------------------------------------------------------


def test_revoking_by_the_start_of_an_id(vault):
    keep, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    assert info.id[:6] != id_of(keep)[:6]

    assert caps.revoke(info.id[:6]) == 1

    assert not cap_path(token).exists()
    with pytest.raises(AuthError, match="opens nothing here"):
        caps.open_grant(token)
    assert [found.id for found in caps.list_caps()] == [id_of(keep)]


def test_revoking_accepts_the_whole_id_in_either_case_and_works_on_sessions(vault):
    session = caps.create_session(vault)
    grant, info = caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert caps.revoke(info.id.upper()) == 1
    assert caps.revoke(id_of(session)) == 1

    assert caps.list_caps() == []
    with pytest.raises(AuthError):
        caps.open_session(session, vault.file)


@pytest.mark.parametrize("prefix", ["", "abcde", "abcdeg", "abc de", "0x1234", "a" * 33, None, 123456, b"abcdef"])
def test_revoking_needs_at_least_six_hexadecimal_characters(vault, prefix):
    caps.create_grant(vault, ["GITHUB_TOKEN"])

    with pytest.raises(UsageError):
        caps.revoke(prefix)

    assert len(caps.list_caps()) == 1


def test_revoking_what_does_not_exist_or_is_ambiguous_is_refused(vault):
    caps.create_grant(vault, ["GITHUB_TOKEN"])
    junk("abcdef" + "0" * 26 + ".json", b"one")
    junk("abcdef" + "1" * 26 + ".json", b"two")

    with pytest.raises(NotFoundError):
        caps.revoke("123456")
    with pytest.raises(UsageError, match="2 grants or sessions"):
        caps.revoke("abcdef")

    assert caps.revoke("abcdef0") == 1
    assert caps.revoke("abcdef") == 1
    assert len(caps.list_caps()) == 1


def test_a_damaged_file_can_still_be_revoked(vault):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"])
    cap_path(token).write_bytes(b"damaged")

    assert caps.revoke(info.id[:8]) == 1
    assert not cap_path(token).exists()


def test_revoking_is_recorded_when_the_vault_is_passed(vault):
    session = caps.create_session(vault)
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"])
    junk("abcdef" + "0" * 26 + ".json", b"damaged")

    caps.revoke(info.id, vault=vault)
    caps.revoke(id_of(session), vault=vault)
    caps.revoke("abcdef", vault=vault)

    events = audit.read(vault)[2:]
    assert [(event.action, event.target, event.actor) for event in events] == [
        ("grant.revoke", info.id, "owner"),
        ("session.end", id_of(session), "owner"),
        ("capability.revoke", "abcdef" + "0" * 26, "owner"),
    ]
    assert audit.verify(vault).ok


def test_a_grant_is_revoked_even_if_that_cannot_be_recorded(vault, monkeypatch):
    token, info = caps.create_grant(vault, ["GITHUB_TOKEN"])

    def unwritable(*args, **kwargs):
        raise audit.AuditError("the audit log could not be written (No space left on device)")

    with monkeypatch.context() as patch:
        patch.setattr(audit, "record", unwritable)
        with pytest.raises(audit.AuditError, match=f"the grant {info.id} was revoked, but that could not be recorded"):
            caps.revoke(info.id, vault=vault)

    assert not cap_path(token).exists()


def test_sweeping_removes_what_has_expired_and_nothing_else(vault, clock, tmp_path):
    short_session = caps.create_session(vault, ttl=60)
    long_session = caps.create_session(vault, ttl=3600)
    short_grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=120)
    long_grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=7200, uses=None)
    made = scatter_junk(tmp_path, long_grant)

    assert caps.sweep() == 0
    clock.advance(60)
    with time_limit(20):
        assert caps.sweep() == 1
    clock.advance(60)
    assert caps.sweep() == 1
    assert caps.sweep() == 0

    assert not cap_path(short_session).exists() and not cap_path(short_grant).exists()
    assert sorted(info.id for info in caps.list_caps()) == sorted([id_of(long_session), id_of(long_grant)])
    assert caps.open_grant(long_grant).value("GITHUB_TOKEN") == GITHUB_PASSWORD
    for name, path in made.items():
        assert os.path.lexists(str(path)) == (name != "interrupted write"), name


def test_sweeping_is_recorded_when_the_vault_is_passed(vault, clock):
    session = caps.create_session(vault, ttl=60)
    grant, info = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    clock.advance(60)

    assert caps.sweep(vault=vault) == 2

    assert sorted((event.action, event.target) for event in audit.read(vault)[2:]) == sorted(
        [("session.expire", id_of(session)), ("grant.expire", info.id)]
    )
    assert audit.verify(vault).ok


def test_destroying_everything_leaves_no_capability_and_nothing_of_irondomes(vault, tmp_path):
    session = caps.create_session(vault)
    first, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    second, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    made = scatter_junk(tmp_path, second)
    named_like_capabilities = sum(
        1 for name, path in made.items() if re.fullmatch(r"[0-9a-f]{32}\.json", path.name) and name != "directory"
    )

    with time_limit(30):
        destroyed = caps.destroy_all()

    assert destroyed == 3 + named_like_capabilities
    assert sorted(path.name for path in paths.caps_dir().iterdir()) == sorted(
        ["notes.txt", "abc.json", "b" * 32 + ".txt", "7" * 32 + ".json"]
    )
    assert made["outside target"].read_bytes() == b"not IronDome's\n"
    for token in (first, second):
        with pytest.raises(AuthError):
            caps.open_grant(token)
    with pytest.raises(AuthError):
        caps.open_session(session, vault.file)
    assert caps.destroy_all() == 0


def test_destroying_everything_removes_the_directory_when_only_irondomes_files_were_in_it(vault):
    caps.create_session(vault)
    caps.create_grant(vault, ["GITHUB_TOKEN"], uses=3)
    junk(".tmp-left-behind", b"a copy of a capability")

    assert caps.destroy_all() == 2

    assert not paths.caps_dir().exists()
    assert caps.list_caps() == []


def test_a_capability_renamed_in_another_case_is_still_found_and_destroyed(vault):
    """On macOS and Windows a token opens its file whatever the case of the name."""
    tokens = [caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)[0] for _ in range(3)]
    for token in tokens:
        cap_path(token).rename(cap_path(token).with_name(id_of(token).upper() + ".JSON"))

    assert sorted(info.id for info in caps.list_caps()) == sorted(id_of(token) for token in tokens)
    assert caps.revoke(id_of(tokens[0])[:8]) == 1
    assert sorted(info.id for info in caps.list_caps()) == sorted(id_of(token) for token in tokens[1:])
    assert caps.destroy_all() == 2
    for token in tokens:
        with pytest.raises(AuthError):
            caps.open_grant(token)


@posix_only
def test_destroying_everything_leaves_other_peoples_files_alone_even_through_a_linked_directory(vault, tmp_path):
    elsewhere = tmp_path / "someone-elses-folder"
    elsewhere.mkdir()
    (elsewhere / "thesis.txt").write_bytes(b"years of work\n")
    paths.ensure_dir(paths.home())
    os.symlink(str(elsewhere), str(paths.caps_dir()))
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    (elsewhere / ".tmp-interrupted").write_bytes(b"a copy of a capability")

    assert caps.destroy_all() == 1

    assert sorted(path.name for path in elsewhere.iterdir()) == ["thesis.txt"]
    assert (elsewhere / "thesis.txt").read_bytes() == b"years of work\n"
    with pytest.raises(AuthError):
        caps.open_grant(token)


def test_destroying_everything_says_so_if_a_capability_survives(vault, monkeypatch):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])

    def stuck(path):
        raise OSError(errno.EPERM, "Operation not permitted")

    with monkeypatch.context() as patch:
        patch.setattr(paths, "secure_delete", stuck)
        with pytest.raises(VaultError, match="could not be deleted"):
            caps.destroy_all()

    assert cap_path(token).exists()
    assert caps.destroy_all() == 1


def test_removing_a_capability_fails_loudly_if_its_file_will_not_go(vault, monkeypatch):
    session = caps.create_session(vault)
    grant, info = caps.create_grant(vault, ["GITHUB_TOKEN"])

    def stuck(path):
        raise OSError(errno.EPERM, "Operation not permitted")

    with monkeypatch.context() as patch:
        patch.setattr(paths, "secure_delete", stuck)
        with pytest.raises(VaultError, match="could not be deleted"):
            caps.revoke(info.id)
        with pytest.raises(VaultError, match="could not be deleted"):
            caps.end_sessions(session)
        with pytest.raises(VaultError, match="could not be deleted"):
            caps.end_sessions()

    assert len(caps.list_caps()) == 2


def test_a_capability_directory_that_cannot_be_used_is_reported_not_crashed_on(vault, tmp_path, monkeypatch):
    token = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    blocker = tmp_path / "a-file"
    blocker.write_bytes(b"")
    monkeypatch.setenv("IRONDOME_HOME", str(blocker / "irondome"))

    with pytest.raises(AuthError, match="could not be used"):
        caps.open_session(token, vault.file)
    with pytest.raises(AuthError, match="could not be used"):
        caps.open_grant(grant)
    with pytest.raises(VaultError):
        caps.create_session(vault)
    with pytest.raises(VaultError):
        caps.create_grant(vault, ["GITHUB_TOKEN"])
    for call in (caps.sweep, caps.end_sessions, caps.list_caps, lambda: caps.revoke("abcdef")):
        with pytest.raises(VaultError):
            call()
    assert caps.destroy_all() == 0
    assert blocker.read_bytes() == b""


# ---------------------------------------------------------------------------
# What a change of one line would have got past the tests above
#
# Each test here was written because a line of caps.py could be changed, or
# removed, with every test above and every end-to-end test still passing.
# ---------------------------------------------------------------------------


def parsed(document: Dict[str, Any]) -> Any:
    return caps._Header.from_bytes(canonical(document), document["id"])


def test_a_header_gives_its_times_as_whole_numbers(vault):
    """JSON has numbers that are equal to a whole number and are not one: 900.0 is written back as 900.0."""
    document = header_of(caps.create_session(vault))
    assert parsed(document).expires == document["expires"]

    for field in ("created", "expires"):
        with pytest.raises(caps._Malformed):
            parsed(dict(document, **{field: float(document[field])}))


def test_a_header_holds_a_time_from_zero_to_two_to_the_fortieth_and_no_other(vault):
    document = header_of(caps.create_session(vault, ttl=900))
    latest = 2**40

    assert parsed(dict(document, created=0, expires=900)).created == 0
    assert parsed(dict(document, created=latest - 900, expires=latest)).expires == latest
    with pytest.raises(caps._Malformed):
        parsed(dict(document, created=-1, expires=899))
    with pytest.raises(caps._Malformed):
        parsed(dict(document, created=latest - 899, expires=latest + 1))


def test_a_label_of_two_hundred_characters_is_kept_and_one_more_is_refused(vault):
    assert caps.MAX_LABEL == 200
    longest = "l" * caps.MAX_LABEL

    session = caps.create_session(vault, label=longest)
    grant, info = caps.create_grant(vault, ["GITHUB_TOKEN"], label=longest)

    assert info.label == longest
    assert sorted(cap.label for cap in caps.list_caps()) == [longest, longest]
    caps.open_session(session, vault.file).wipe()
    assert caps.open_grant(grant).value("GITHUB_TOKEN") == GITHUB_PASSWORD
    with pytest.raises(UsageError):
        caps.create_session(vault, label=longest + "l")
    with pytest.raises(UsageError):
        caps.create_grant(vault, ["GITHUB_TOKEN"], label=longest + "l")


def test_a_file_is_read_up_to_the_largest_a_capability_can_be_and_not_one_byte_past(vault, monkeypatch):
    token = caps.create_session(vault)
    size = cap_path(token).stat().st_size

    monkeypatch.setattr(caps, "_MAX_FILE", size)
    assert [cap.id for cap in caps.list_caps()] == [id_of(token)]
    caps.open_session(token, vault.file).wipe()

    monkeypatch.setattr(caps, "_MAX_FILE", size - 1)
    assert caps.list_caps() == []
    with pytest.raises(AuthError, match="damaged or was altered"):
        caps.open_session(token, vault.file)


@posix_only
def test_a_directory_in_a_capabilitys_place_is_refused_as_a_damaged_file(vault):
    caps.create_session(vault)  # so that the capability directory is there
    cap_id = os.urandom(16)
    cap_path(cap_id.hex()).mkdir()

    with pytest.raises(AuthError, match="damaged or was altered"):
        caps.open_session(make_token("session", cap_id, os.urandom(32)), vault.file)
    with pytest.raises(AuthError, match="damaged or was altered"):
        caps.open_grant(make_token("grant", cap_id, os.urandom(32)))
    assert caps.session_expires(make_token("session", cap_id, os.urandom(32))) is None
    assert cap_path(cap_id.hex()).is_dir()


@posix_only
def test_a_link_to_a_directory_under_a_capabilitys_name_is_destroyed_as_a_file_and_never_followed(vault, tmp_path):
    token = caps.create_session(vault)
    outside = tmp_path / "somebody-elses"
    outside.mkdir()
    (outside / "kept.txt").write_bytes(b"not IronDome's\n")
    link = cap_path(os.urandom(16).hex())
    link.symlink_to(outside, target_is_directory=True)

    assert [cap.id for cap in caps.list_caps()] == [id_of(token)]
    assert caps.destroy_all() == 2

    assert not os.path.lexists(str(link))
    assert (outside / "kept.txt").read_bytes() == b"not IronDome's\n"


def test_the_refusal_of_a_lifetime_says_the_longest_in_hours_or_days(vault):
    with pytest.raises(UsageError, match=r"from 60 to 43200 \(12 hours\)"):
        caps.create_session(vault, ttl=59)
    with pytest.raises(UsageError, match=r"from 60 to 2592000 \(30 days\)"):
        caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=59)


def test_the_refusal_of_a_long_grant_for_a_one_time_password_says_a_day_in_hours(bank):
    with pytest.raises(UsageError, match=r"at most 86400 seconds \(24 hours\)"):
        caps.create_grant(bank, ["BANK_OTP"], ttl=86_401)


REFUSED_IN_A_REFERENCE = [0x00, 0x1F, 0x7F, 0x80, 0x9F, 0x2028, 0x2029]
ALLOWED_IN_A_REFERENCE = [0x20, 0x7E, 0xA0, 0x2027]


@pytest.mark.parametrize("point", REFUSED_IN_A_REFERENCE, ids=[f"U+{point:04X}" for point in REFUSED_IN_A_REFERENCE])
def test_a_reference_holds_no_control_character_at_either_edge_of_their_ranges(point):
    with pytest.raises(UsageError, match="no control characters"):
        caps._reference(f"a{chr(point)}b")


@pytest.mark.parametrize("point", ALLOWED_IN_A_REFERENCE, ids=[f"U+{point:04X}" for point in ALLOWED_IN_A_REFERENCE])
def test_a_reference_may_hold_the_characters_next_to_the_control_ranges(point):
    assert caps._reference(f"a{chr(point)}b") == f"a{chr(point)}b"


def test_a_reference_is_512_characters_at_most():
    assert caps._reference("r" * 512) == "r" * 512
    assert caps._reference("irondome://" + "r" * 512) == "r" * 512
    with pytest.raises(UsageError, match="1 to 512 characters"):
        caps._reference("r" * 513)


GOOD_ITEMS: Dict[str, Any] = {
    "an entry name of one character": {"entry": "e", "field": "password", "value": "v"},
    "an entry name of 200 characters": {"entry": "e" * 200, "field": "password", "value": "v"},
    "a field name of one character": {"entry": "a", "field": "f", "value": "v"},
    "a field name of 64 characters": {"entry": "a", "field": "f" * 64, "value": "v"},
    "the shortest time step": dict(TOTP_ITEM, period=otp.MIN_PERIOD),
    "the longest time step": dict(TOTP_ITEM, period=otp.MAX_PERIOD),
    "the last counter 64 bits hold": dict(TOTP_ITEM, codes={str(2**64 - 1): "123456"}),
}
BAD_ITEMS: Dict[str, Any] = {
    "an entry name of 201 characters": {"entry": "e" * 201, "field": "password", "value": "v"},
    "a field name of 65 characters": {"entry": "a", "field": "f" * 65, "value": "v"},
    "a time step below the shortest": dict(TOTP_ITEM, period=otp.MIN_PERIOD - 1),
    "a time step above the longest": dict(TOTP_ITEM, period=otp.MAX_PERIOD + 1),
    "a counter 64 bits do not hold": dict(TOTP_ITEM, codes={str(2**64): "123456"}),
}


@pytest.mark.parametrize("name", sorted(GOOD_ITEMS))
def test_a_grant_made_by_hand_at_an_edge_of_what_irondome_writes_opens(vault, name):
    token = craft(vault, with_item(good_payload(vault), GOOD_ITEMS[name]), uses_left=None)
    grant = caps.open_grant(token)
    assert grant.is_totp("A") is (GOOD_ITEMS[name]["field"] == "totp")


@pytest.mark.parametrize("name", sorted(BAD_ITEMS))
def test_a_grant_made_by_hand_one_step_past_that_edge_is_refused(vault, name):
    token = craft(vault, with_item(good_payload(vault), BAD_ITEMS[name]), uses_left=None)
    with pytest.raises(AuthError, match="is not what IronDome writes"):
        caps.open_grant(token)


@pytest.mark.parametrize("stray", ["\n", " ", "-", "!"])
def test_an_audit_key_with_a_character_base64_does_not_have_is_refused(vault, stray):
    """A lenient decoder skips such a character and still finds 32 bytes."""
    payload = good_payload(vault)
    key = payload["audit_key"]
    token = craft(vault, dict(payload, audit_key=key[:8] + stray + key[8:]))
    with pytest.raises(AuthError, match="is not what IronDome writes"):
        caps.open_grant(token)


@pytest.mark.parametrize("secret, device_key", [(31, 32), (33, 32), (32, 31), (32, 33), (0, 32), (32, 0)])
def test_a_capability_key_is_made_from_two_keys_of_32_bytes_and_nothing_else(secret, device_key):
    with pytest.raises(ValueError, match="32-byte token secret and a 32-byte device key"):
        caps._wrap_key("grant", b"s" * secret, b"d" * device_key, b"salt" * 4)
    with caps._wrap_key("grant", b"s" * 32, b"d" * 32, b"salt" * 4) as key:
        assert len(key) == 32


def test_closing_a_grant_drops_the_values_it_held_and_does_not_only_refuse_them(bank):
    token, _ = caps.create_grant(bank, ["GITHUB_TOKEN", "BANK_OTP"])
    grant = caps.open_grant(token)
    held = list(grant._items.values())
    assert any(item.value == GITHUB_PASSWORD for item in held) and any(item.codes for item in held)

    grant.close()

    assert sorted(grant._items) == ["BANK_OTP", "GITHUB_TOKEN"]
    assert all(item.value == "" and item.codes == {} for item in grant._items.values())


def test_a_granted_value_is_not_in_what_its_item_prints_as():
    item = caps._Item(entry="github", field="password", value=GITHUB_PASSWORD, period=30, codes={60000000: "492039"})
    for shown in (repr(item), str(item), f"{item}", f"{[item]}", f"{ {'A': item} }"):
        assert GITHUB_PASSWORD not in shown and "492039" not in shown


def test_what_describes_a_capability_cannot_be_edited_once_made(vault):
    session = caps.create_session(vault)
    _, info = caps.create_grant(vault, ["GITHUB_TOKEN"])
    header = caps._Header.from_bytes(cap_path(session).read_bytes(), id_of(session))
    item = caps._Item(entry="github", field="password")

    for thing, field in ((caps.list_caps()[0], "expires"), (info, "references"), (header, "expires"), (item, "value")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(thing, field, None)


# -- what a session token alone says, and the grants made under a session ----


def test_the_end_of_a_session_is_read_from_its_token_and_from_nothing_else(vault, clock):
    session = caps.create_session(vault, ttl=1200)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert caps.session_expires(session) == T0 + 1200
    assert caps.session_expires(grant) is None
    assert caps.session_expires("not a token") is None
    # A session token that names a grant's file: the kind is in the file as well, and must agree.
    assert caps.session_expires(make_token("session", bytes.fromhex(id_of(grant)), os.urandom(32))) is None
    assert caps.session_expires(make_token("session", os.urandom(16), os.urandom(32))) is None

    cap_path(session).write_bytes(cap_path(session).read_bytes()[:-2])
    assert caps.session_expires(session) is None
    caps.end_sessions(session)
    assert caps.session_expires(session) is None


def test_the_mark_of_a_session_is_the_first_twelve_characters_of_its_id(vault):
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert caps.session_mark(session) == f"[session {id_of(session)[:12]}]"
    assert caps.SESSION_MARK.search("ci run " + caps.session_mark(session))
    with pytest.raises(AuthError, match="that is a grant token, not a session token"):
        caps.session_mark(grant)


def test_ending_a_session_revokes_the_grants_made_under_it_and_no_other(vault):
    session = caps.create_session(vault)
    other = caps.create_session(vault, label="not a grant " + caps.session_mark(session))
    mark = caps.session_mark(session)
    under, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], label="ci run " + mark, uses=None)
    bare, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], label=mark, uses=None)
    of_another, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], label="ci run " + caps.session_mark(other), uses=None)
    unmarked, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], label="ci run", uses=None)
    mentioned, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], label=mark + " and more", uses=None)

    assert caps.end_sessions(session, vault=vault) == 1

    for gone in (session, under, bare):
        assert not cap_path(gone).exists()
    for kept in (other, of_another, unmarked, mentioned):
        assert cap_path(kept).exists()
    with pytest.raises(AuthError):
        caps.open_grant(under)
    assert caps.open_grant(of_another).value("GITHUB_TOKEN") == GITHUB_PASSWORD
    ended = [(event.action, event.target) for event in audit.read(vault)
             if event.action in ("session.end", "grant.revoke")]
    assert len(ended) == 3 and ended[0] == ("session.end", id_of(session))
    assert sorted(ended[1:]) == sorted([("grant.revoke", id_of(under)), ("grant.revoke", id_of(bare))])
    assert audit.verify(vault).ok


def test_ending_every_session_revokes_the_grants_made_under_each(vault):
    first, second = caps.create_session(vault), caps.create_session(vault)
    under_first, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], label="a " + caps.session_mark(first))
    under_second, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], label="b " + caps.session_mark(second))
    unmarked, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert caps.end_sessions() == 2

    assert [cap.id for cap in caps.list_caps()] == [id_of(unmarked)]
    assert caps.end_sessions() == 0
    assert [cap.id for cap in caps.list_caps()] == [id_of(unmarked)]


# -- every copy of a secret that is made on the way is handed to the wipe -----


@pytest.fixture
def handed_to_wipe(monkeypatch) -> List[tuple]:
    """What caps passes to wipe_bytes, as (kind, content at that moment), before the real wipe runs."""
    seen: List[tuple] = []
    real = caps.wipe_bytes

    def record(data: Any) -> Any:
        if isinstance(data, str):
            seen.append(("str", data.encode("utf-8")))
        else:
            seen.append((type(data).__name__, bytes(bytearray(data))))
        return real(data)

    monkeypatch.setattr(caps, "wipe_bytes", record)
    return seen


def secret_of(token: str) -> bytes:
    return bytes(bytearray(caps.parse_token(token)[2]))


def test_the_secret_of_a_token_is_wiped_by_everything_that_takes_a_token(vault, handed_to_wipe):
    session = caps.create_session(vault)
    assert ("bytes", secret_of(session)) in handed_to_wipe  # the copy the token was written from
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    assert ("bytes", secret_of(grant)) in handed_to_wipe

    calls: Dict[str, Callable[[], Any]] = {
        "open_session": lambda: caps.open_session(session, vault.file).wipe(),
        "session_expires": lambda: caps.session_expires(session),
        "session_mark": lambda: caps.session_mark(session),
        "open_grant": lambda: caps.open_grant(grant).close(),
        "looking at a grant": lambda: caps.open_grant(grant, consume=False).close(),
        "end_sessions": lambda: caps.end_sessions(session),
    }
    for name, call in calls.items():
        secret = secret_of(grant if "grant" in name else session)
        del handed_to_wipe[:]
        call()
        assert ("bytes", secret) in handed_to_wipe, name


def test_making_a_grant_wipes_every_copy_of_what_it_seals(vault, handed_to_wipe):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    sealed = plaintext_of(token)
    key_text = json.loads(sealed)["audit_key"].encode("ascii")
    value = GITHUB_PASSWORD.encode("ascii")
    assert value in sealed and len(key_text) == 44

    texts = [content for kind, content in handed_to_wipe if kind == "str" and value in content]
    assert len(texts) == 1 and key_text not in texts[0]  # the JSON text, made before the audit key is added
    assert ("bytes", texts[0]) in handed_to_wipe  # its encoding
    assert ("bytes", key_text) in handed_to_wipe  # the audit key as text
    assert ("bytearray", sealed) in handed_to_wipe  # the whole payload
    padded = [content for kind, content in handed_to_wipe if kind != "str" and sealed in content and content != sealed]
    assert len(padded) == 1 and len(padded[0]) % 256 == 0


@pytest.mark.parametrize("consume", [True, False])
def test_opening_a_grant_wipes_every_copy_of_what_it_unsealed(vault, handed_to_wipe, consume):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    sealed = plaintext_of(token)
    key_text = json.loads(sealed)["audit_key"].encode("ascii")
    del handed_to_wipe[:]

    caps.open_grant(token, consume=consume).close()

    assert ("str", sealed) in handed_to_wipe  # the JSON text
    assert sum(1 for kind, content in handed_to_wipe if kind != "str" and content == sealed) == 1  # and its bytes
    padded = [content for kind, content in handed_to_wipe if kind != "str" and sealed in content and content != sealed]
    assert len(padded) == 1 and len(padded[0]) % 256 == 0
    assert ("str", key_text) in handed_to_wipe and ("bytes", key_text) in handed_to_wipe
    assert ("bytes", base64.b64decode(key_text)) in handed_to_wipe


def test_an_expired_grant_that_is_presented_has_what_was_unsealed_from_it_wiped(vault, clock, handed_to_wipe):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    sealed = plaintext_of(token)
    clock.advance(60)
    del handed_to_wipe[:]

    with pytest.raises(AuthError, match="expired"):
        caps.open_grant(token)

    padded = [content for kind, content in handed_to_wipe if kind != "str" and sealed in content and content != sealed]
    assert len(padded) == 1 and len(padded[0]) % 256 == 0
    assert ("bytes", secret_of(token)) in handed_to_wipe


# -- the device key ----------------------------------------------------------


def test_the_device_key_is_never_asked_for_in_a_way_that_could_put_a_question_to_the_owner(vault, monkeypatch):
    """A session or a grant is used by a program, often with nobody there: no prompt, no dialog."""
    backend = caps.devices.get_backend("software")
    real = backend.unseal
    asked: List[Dict[str, Any]] = []

    def unseal(descriptor: Dict[str, Any], **settings: Any) -> Any:
        asked.append(settings)
        return real(descriptor, **settings)

    monkeypatch.setattr(backend, "unseal", unseal)
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    caps.open_session(session, vault.file).wipe()
    caps.open_grant(grant).close()

    assert len(asked) >= 3
    assert all(settings["interactive"] is False and settings["auth"] is None for settings in asked)


def test_a_backend_that_cannot_be_loaded_means_the_capability_is_not_of_this_machine(vault, monkeypatch):
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    before = cap_path(grant).read_bytes()

    def unavailable(name: str) -> Any:
        raise IronDomeError(f"the {name} backend cannot be loaded here")

    monkeypatch.setattr(caps.devices, "get_backend", unavailable)
    with pytest.raises(AuthError, match="that session token cannot be used here: the session belongs to another"):
        caps.open_session(session, vault.file)
    with pytest.raises(AuthError, match="that grant token cannot be used here: the grant belongs to another"):
        caps.open_grant(grant)
    assert cap_path(grant).read_bytes() == before


def test_a_device_key_the_backend_describes_wrongly_is_refused_and_destroyed_again(vault, monkeypatch):
    backend = caps.devices.get_backend("software")
    real = backend.enroll
    made: List[Dict[str, Any]] = []

    def enroll(**settings: Any) -> Any:
        descriptor, raw = real(**settings)
        made.append(dict(descriptor))
        return dict(descriptor, surprise="not a field of a descriptor"), raw

    monkeypatch.setattr(backend, "enroll", enroll)
    with pytest.raises(caps.HardwareError, match="made a device key that sessions and grants cannot be bound to"):
        caps.create_session(vault)

    assert len(made) == 1 and not backend.exists(made[0])
    assert "cap_device" not in vault.meta and caps.list_caps() == []


def test_the_key_made_for_a_binding_that_cannot_be_recorded_is_wiped(vault, monkeypatch):
    real = caps._derived_device_key
    derived: List[Any] = []  # held here, so nothing but an explicit wipe can zero them

    def derive(raw: Any, vault_id: bytes) -> Any:
        derived.append(real(raw, vault_id))
        return derived[-1]

    def refuse(*arguments: Any, **settings: Any) -> None:
        raise VaultError("the index could not be written")

    monkeypatch.setattr(caps, "_derived_device_key", derive)
    monkeypatch.setattr(caps, "_record", refuse)
    with pytest.raises(VaultError, match="the index could not be written"):
        caps._bound_device(vault)

    assert len(derived) == 1 and derived[0].wiped


def test_only_what_is_a_file_itself_counts_as_the_staging_file_of_a_rekey(vault, tmp_path):
    home = paths.home()
    real = home / f"{caps.REKEY_STAGING_PREFIX}real{caps.REKEY_STAGING_SUFFIX}"
    real.write_bytes(b"staged")
    (home / f"{caps.REKEY_STAGING_PREFIX}directory{caps.REKEY_STAGING_SUFFIX}").mkdir()
    target = tmp_path / "elsewhere"
    target.write_bytes(b"not IronDome's")
    if os.name != "nt":
        (home / f"{caps.REKEY_STAGING_PREFIX}link{caps.REKEY_STAGING_SUFFIX}").symlink_to(target)
    (home / f"{caps.REKEY_STAGING_PREFIX}other.txt").write_bytes(b"another suffix")

    assert caps.rekey_staging_files() == [real]


@pytest.mark.parametrize("failure, reason", [
    (PermissionError(errno.EACCES, "Permission denied"), "Permission denied"),
    (OSError(), "OSError"),
])
def test_a_capability_directory_that_cannot_be_listed_is_reported_with_the_reason(vault, monkeypatch, failure, reason):
    def refuse() -> Any:
        raise failure

    monkeypatch.setattr(caps, "_capability_files", refuse)
    with pytest.raises(VaultError, match=rf"could not be read \({reason}\)$"):
        caps.list_caps()


def test_destroying_everything_names_five_of_the_files_that_would_not_go(vault, monkeypatch):
    for _ in range(7):
        caps.create_session(vault)
    names = sorted(path.name for _, path in caps._capability_files())
    monkeypatch.setattr(caps, "_destroy_quietly", lambda path: False)

    with pytest.raises(VaultError) as raised:
        caps.destroy_all()

    assert "7 capability files" in str(raised.value)
    assert re.findall(r"[0-9a-f]{32}\.json", str(raised.value)) == names[:5]


def test_a_grant_holds_values_up_to_the_largest_payload_exactly(vault, monkeypatch):
    first, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    size = len(plaintext_of(first))

    monkeypatch.setattr(caps, "_MAX_PAYLOAD", size)
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    assert caps.open_grant(token).value("GITHUB_TOKEN") == GITHUB_PASSWORD

    monkeypatch.setattr(caps, "_MAX_PAYLOAD", size - 1)
    with pytest.raises(UsageError, match=f"come to {size} bytes and a grant holds at most {size - 1}"):
        caps.create_grant(vault, ["GITHUB_TOKEN"])
