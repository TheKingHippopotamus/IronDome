"""One-time passwords: published test vectors, an independent implementation, and hostile input."""

from __future__ import annotations

import ast
import atexit
import base64
import hmac as std_hmac
import json
import math
import os
import shutil
import tempfile
import types
from pathlib import Path
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from hypothesis import HealthCheck, given, settings
from hypothesis import configuration as hypothesis_configuration
from hypothesis import strategies as st

from irondome import otp
from irondome.errors import AuthError, IronDomeError, UsageError, VaultError


def property_settings(examples: int = 100) -> settings:
    """No example database (it would be written to the working directory) and no time limits:
    a loaded machine must not turn a correct property into a failure.
    """
    return settings(database=None, deadline=None, max_examples=examples, suppress_health_check=[HealthCheck.too_slow])


PROPERTY = property_settings()

# RFC 6238 Appendix B uses these ASCII keys; RFC 4226 Appendix D uses the first.
RFC_KEYS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}

RFC_6238 = [
    (59, "SHA1", "94287082"),
    (59, "SHA256", "46119246"),
    (59, "SHA512", "90693936"),
    (1111111109, "SHA1", "07081804"),
    (1111111109, "SHA256", "68084774"),
    (1111111109, "SHA512", "25091201"),
    (1111111111, "SHA1", "14050471"),
    (1111111111, "SHA256", "67062674"),
    (1111111111, "SHA512", "99943326"),
    (1234567890, "SHA1", "89005924"),
    (1234567890, "SHA256", "91819424"),
    (1234567890, "SHA512", "93441116"),
    (2000000000, "SHA1", "69279037"),
    (2000000000, "SHA256", "90698825"),
    (2000000000, "SHA512", "38618901"),
    (20000000000, "SHA1", "65353130"),
    (20000000000, "SHA256", "77737706"),
    (20000000000, "SHA512", "47863826"),
]

RFC_4226 = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]

SECRET = "JBSWY3DPEHPK3PXP"  # the example secret of the key-URI format: ten bytes


def b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def rfc_totp(algorithm: str = "SHA1", digits: int = 8, period: int = 30) -> dict:
    return otp.make_totp(b32(RFC_KEYS[algorithm]), algorithm=algorithm, digits=digits, period=period)


def _keep_hypothesis_out_of_the_working_directory() -> None:
    """Send Hypothesis's cache to a temporary directory that is removed at exit.

    Hypothesis keeps Unicode tables and constants it found in the source
    under ``./.hypothesis``, and writes the latter while pytest is still
    collecting tests. A fixture would be too late, so this runs on import.
    It does nothing if the directory has already been chosen elsewhere.
    """
    if os.environ.get("HYPOTHESIS_STORAGE_DIRECTORY"):
        return
    directory = tempfile.mkdtemp(prefix="irondome-hypothesis-")
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    os.environ["HYPOTHESIS_STORAGE_DIRECTORY"] = directory
    hypothesis_configuration.set_hypothesis_home_dir(directory)


_keep_hypothesis_out_of_the_working_directory()


@pytest.fixture
def clock(monkeypatch):
    """Set what the otp module believes the time to be, without touching the real clock."""

    def set_time(now: float) -> None:
        monkeypatch.setattr(otp, "time", types.SimpleNamespace(time=lambda: now))

    return set_time


# -- strategies ---------------------------------------------------------------

raw_secrets = st.binary(min_size=otp.MIN_SECRET_BYTES, max_size=64)
words = st.text(alphabet=st.characters(exclude_categories=("C", "Z")), min_size=1, max_size=8)
labels = st.lists(words, max_size=4).map(" ".join)
totps = st.builds(
    lambda raw, algorithm, digits, period, issuer, account: otp.make_totp(
        b32(raw), algorithm=algorithm, digits=digits, period=period, issuer=issuer, account=account
    ),
    raw_secrets,
    st.sampled_from(otp.ALGORITHMS),
    st.sampled_from(otp.DIGITS),
    st.integers(otp.MIN_PERIOD, otp.MAX_PERIOD),
    labels,
    labels,
)
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=20),
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=8,
)


# -- published vectors and an independent implementation -------------------


@pytest.mark.parametrize(("when", "algorithm", "expected"), RFC_6238)
def test_rfc_6238_appendix_b(when, algorithm, expected):
    assert otp.code_at(rfc_totp(algorithm), when) == expected


@pytest.mark.parametrize(("counter", "expected"), list(enumerate(RFC_4226)))
def test_rfc_4226_appendix_d(counter, expected):
    # HOTP with counter c is TOTP at any moment of time step c.
    six_digits = rfc_totp(digits=6)
    assert otp.code_at(six_digits, counter * 30) == expected
    assert otp.code_at(six_digits, counter * 30 + 29.999) == expected
    assert otp.code_at(rfc_totp(digits=6, period=7), counter * 7) == expected


def test_rfc_4226_through_the_counter_function():
    with otp._decode(b32(RFC_KEYS["SHA1"])) as key:
        assert [otp._hotp(key, counter, 6, "SHA1") for counter in range(10)] == RFC_4226


@PROPERTY
@given(
    raw=raw_secrets,
    algorithm=st.sampled_from(otp.ALGORITHMS),
    digits=st.sampled_from(otp.DIGITS),
    period=st.integers(otp.MIN_PERIOD, otp.MAX_PERIOD),
    when=st.integers(0, 2**40) | st.floats(0, 2**40),
)
def test_agrees_with_the_cryptography_package(raw, algorithm, digits, period, when):
    reference = TOTP(raw, digits, getattr(hashes, algorithm)(), period, enforce_key_length=False)
    mine = otp.code_at(otp.make_totp(b32(raw), algorithm=algorithm, digits=digits, period=period), when)
    assert mine == reference.generate(when).decode("ascii")
    assert len(mine) == digits and mine.isdigit()


def test_codes_keep_their_leading_zeros():
    assert otp.code_at(rfc_totp("SHA1"), 1111111109) == "07081804"
    assert otp.code_at(rfc_totp("SHA1", digits=6), 1111111109) == "081804"
    assert otp.code_at(rfc_totp("SHA1", digits=7), 1111111109) == "7081804"


def test_a_code_lasts_exactly_one_period():
    totp = rfc_totp()
    assert otp.code_at(totp, 30) == otp.code_at(totp, 59) == otp.code_at(totp, 59.999) == "94287082"
    assert otp.code_at(totp, 29.999) != "94287082"
    assert otp.code_at(totp, 60) != "94287082"


def test_without_openssl_hmac_gives_the_same_codes(monkeypatch):
    """Interpreters built without OpenSSL cannot HMAC a memoryview; the fallback must agree."""
    seen = []

    def refuse(key, message, digest):
        seen.append(type(key))
        raise TypeError("unsupported operand type(s) for +: 'memoryview' and 'bytes'")

    def new(key, message, digest):
        assert isinstance(key, bytearray), "the fallback must work on a copy it can wipe"
        seen.append(key)
        return std_hmac.new(key, message, digest)

    monkeypatch.setattr(otp, "hmac", types.SimpleNamespace(digest=refuse, new=new))
    for when, algorithm, expected in RFC_6238:
        assert otp.code_at(rfc_totp(algorithm), when) == expected
    copies = [item for item in seen if isinstance(item, bytearray)]
    assert seen.count(memoryview) == len(copies) == len(RFC_6238)
    assert all(len(copy) >= 20 and not any(copy) for copy in copies), "every lent copy of the key must be wiped"


# -- the decoded secret --------------------------------------------------------


@PROPERTY
@given(raw=st.binary(min_size=otp.MIN_SECRET_BYTES, max_size=otp.MAX_SECRET_BYTES))
def test_decoding_matches_the_standard_library(raw):
    text = b32(raw)
    with otp._decode(text) as key:
        assert bytes(key.view()) == raw
        assert bytes(key.view()) == base64.b32decode(text + "=" * (-len(text) % 8))


def test_the_decoded_secret_is_wiped_after_every_use(monkeypatch):
    made = []
    real = otp._decode

    def spy(secret):
        made.append(real(secret))
        return made[-1]

    monkeypatch.setattr(otp, "_decode", spy)
    totp = rfc_totp()
    otp.code_at(totp, 59)
    otp.code_for(totp)
    otp.codes_for_window(totp, 0, 600)
    otp.verify(totp, "94287082", 59)
    assert len(made) == 4
    assert all(buffer.wiped for buffer in made)


def test_the_decoded_secret_is_wiped_when_computing_fails(monkeypatch):
    made = []
    real = otp._decode

    def spy(secret):
        made.append(real(secret))
        return made[-1]

    def broken(key, message, algorithm):
        raise RuntimeError("no HMAC today")

    monkeypatch.setattr(otp, "_decode", spy)
    monkeypatch.setattr(otp, "_hmac", broken)
    totp = rfc_totp()
    for call in (
        lambda: otp.code_at(totp, 59),
        lambda: otp.codes_for_window(totp, 0, 600),
        lambda: otp.verify(totp, "94287082", 59),
    ):
        with pytest.raises(RuntimeError):
            call()
    assert len(made) == 3
    assert all(buffer.wiped for buffer in made)


# -- normalise_secret ------------------------------------------------------


@pytest.mark.parametrize(
    "pasted",
    [
        "JBSWY3DPEHPK3PXP",
        "jbswy3dpehpk3pxp",
        "jbsw y3dp ehpk 3pxp",
        "JBSW-Y3DP-EHPK-3PXP",
        "  JBSWY3DPEHPK3PXP\n",
        "JBSW\tY3DP\u00a0EHPK\u20033PXP",
        "JBSWY3DPEHPK3PXP======",
        "jbsw y3dp ehpk 3pxp =",
    ],
)
def test_normalise_accepts_what_people_paste(pasted):
    assert otp.normalise_secret(pasted) == SECRET


def test_normalise_strips_padding_of_longer_secrets():
    raw = bytes(range(32))
    padded = base64.b32encode(raw).decode("ascii")
    assert padded.endswith("====")
    assert otp.normalise_secret(padded.lower()) == b32(raw)


def test_normalise_zeroes_the_unused_bits_of_the_last_character():
    raw = bytes(range(16))  # 26 characters: the last one carries two unused bits
    canonical = b32(raw)
    assert len(canonical) == 26
    loose = canonical[:-1] + otp._BASE32[otp._BASE32_VALUE[canonical[-1]] | 0b11]
    assert loose != canonical
    assert otp.normalise_secret(loose) == canonical
    with pytest.raises(VaultError):
        otp.validate({**otp.make_totp(canonical), "secret": loose})


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "====",
        "JBSWY3DPEHPK3PX",  # fifteen characters: nine bytes
        "JBSWY3DPEHPK3PXP0",  # zero is not in the alphabet
        "JBSWY3DPEHPK3PX1",
        "JBSWY3DPEHPK3PX8",
        "JBSWY3DPEHPK3PX9",
        "JBSWY3DP!EHPK3PXP",
        "JBSWY3DP=EHPK3PXP",  # padding in the middle
        "JBSWY3DPEHPK3PXPA",  # 17 characters: not a whole number of bytes
        "JBSWY3DPEHPK3PXPABC",  # 19
        "JBSWY3DPEHPK3PXPABCDEF",  # 22
        "JBSWY3DPEHPK3PXP\u0131",  # dotless i upper-cases to I
        "JBSWY3DPEHPK3PX\u017f",  # long s upper-cases to S
        "JBSWY3DPEHPK3PX\u00e9",
        "A" * (otp._MAX_SECRET_CHARS + 2),
        "A" * 100_000,
        None,
        b"JBSWY3DPEHPK3PXP",
        12345678901234567890,
        ["JBSWY3DPEHPK3PXP"],
    ],
)
def test_normalise_refuses(bad):
    with pytest.raises(UsageError):
        otp.normalise_secret(bad)


def test_secret_size_limits():
    assert otp.normalise_secret("A" * 16) == "A" * 16
    longest = "A" * otp._MAX_SECRET_CHARS
    assert otp.normalise_secret(longest) == longest
    assert len(longest) * 5 // 8 == otp.MAX_SECRET_BYTES
    with pytest.raises(UsageError, match="too long"):
        otp.normalise_secret(b32(bytes(otp.MAX_SECRET_BYTES + 1)))
    with pytest.raises(UsageError, match="too short"):
        otp.normalise_secret(b32(bytes(otp.MIN_SECRET_BYTES - 1)))


@property_settings(80)
@given(raw=st.binary(min_size=otp.MIN_SECRET_BYTES, max_size=80), data=st.data())
def test_normalise_is_canonical_and_idempotent(raw, data):
    canonical = b32(raw)
    messy = "".join(
        data.draw(st.sampled_from([char, char.lower(), char + " ", "-" + char, char + "\n"])) for char in canonical
    ) + "=" * data.draw(st.integers(0, 8))
    assert otp.normalise_secret(messy) == canonical
    assert otp.normalise_secret(canonical) == canonical
    assert otp.validate(otp.make_totp(messy))["secret"] == canonical


# -- make_totp and validate ------------------------------------------------


def test_make_totp_defaults():
    assert otp.make_totp(SECRET) == {
        "secret": SECRET,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
        "issuer": "",
        "account": "",
    }


@pytest.mark.parametrize(
    ("given_name", "stored"),
    [
        ("SHA1", "SHA1"),
        ("sha1", "SHA1"),
        ("Sha-256", "SHA256"),
        (" sha512 ", "SHA512"),
        ("SHA-512", "SHA512"),
        ("HmacSHA256", "SHA256"),
        ("HMAC-SHA-1", "SHA1"),
    ],
)
def test_make_totp_accepts_algorithm_spellings(given_name, stored):
    assert otp.make_totp(SECRET, algorithm=given_name)["algorithm"] == stored


@pytest.mark.parametrize("algorithm", ["MD5", "SHA224", "SHA3-256", "", "SHA", None, 1, b"SHA1", "\u017fha1"])
def test_make_totp_refuses_other_algorithms(algorithm):
    with pytest.raises(UsageError, match="SHA1, SHA256 and SHA512"):
        otp.make_totp(SECRET, algorithm=algorithm)


@pytest.mark.parametrize("digits", [5, 9, 0, -6, 6.0, "6", None, True, [6]])
def test_make_totp_refuses_other_digit_counts(digits):
    with pytest.raises(UsageError, match="6, 7 or 8 digits"):
        otp.make_totp(SECRET, digits=digits)


@pytest.mark.parametrize("period", [0, -30, 301, 10**9, 30.0, "30", None, True, False])
def test_make_totp_refuses_other_periods(period):
    with pytest.raises(UsageError, match="from 1 to 300"):
        otp.make_totp(SECRET, period=period)


def test_make_totp_accepts_the_whole_range():
    for digits in otp.DIGITS:
        for period in (otp.MIN_PERIOD, 30, 60, otp.MAX_PERIOD):
            settings_ = otp.make_totp(SECRET, digits=digits, period=period)
            assert (settings_["digits"], settings_["period"]) == (digits, period)
            assert len(otp.code_at(settings_, 1_700_000_000)) == digits


def test_make_totp_tidies_labels():
    made = otp.make_totp(SECRET, issuer="  ACME\t\tCo \n", account="john\u00a0doe\u200b@\x00example.com\x1b[31m\u202e")
    assert made["issuer"] == "ACME Co"
    assert made["account"] == "john doe@example.com[31m"
    assert otp.validate(made) == made


@pytest.mark.parametrize("field", ["issuer", "account"])
def test_make_totp_refuses_unusable_labels(field):
    for bad in (None, 7, b"ACME", ["ACME"], "x" * 256, "x" * 100_000):
        with pytest.raises(UsageError):
            otp.make_totp(SECRET, **{field: bad})
    assert otp.make_totp(SECRET, **{field: "x" * 255})[field] == "x" * 255


def test_settings_survive_json_as_the_vault_stores_them():
    made = otp.make_totp(SECRET, algorithm="SHA256", digits=8, period=60, issuer="\u05d1\u05e0\u05e7", account="a@b.c")
    assert otp.validate(json.loads(json.dumps(made))) == made


def test_validate_returns_a_fresh_dict():
    made = otp.make_totp(SECRET, issuer="ACME")
    checked = otp.validate(made)
    assert checked == made and checked is not made
    checked["issuer"] = "changed"
    assert made["issuer"] == "ACME"


@pytest.mark.parametrize("not_a_dict", [None, [], "JBSWY3DPEHPK3PXP", 6, b"", (), {"secret"}, 1.5])
def test_validate_refuses_anything_but_a_dict(not_a_dict):
    with pytest.raises(VaultError):
        otp.validate(not_a_dict)


@pytest.mark.parametrize("missing", ["secret", "algorithm", "digits", "period", "issuer", "account"])
def test_validate_needs_every_field(missing):
    record = otp.make_totp(SECRET)
    del record[missing]
    with pytest.raises(VaultError, match=missing):
        otp.validate(record)


def test_validate_refuses_fields_it_does_not_know():
    for extra in ("type", "counter", "encoder", 7, ""):
        with pytest.raises(VaultError, match="does not know"):
            otp.validate({**otp.make_totp(SECRET), extra: "hotp"})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("secret", "jbswy3dpehpk3pxp"),
        ("secret", "JBSWY3DPEHPK3PXP===="),
        ("secret", "JBSW Y3DP EHPK 3PXP"),
        ("secret", "JBSWY3DPEHPK3PX"),
        ("secret", "JBSWY3DPEHPK3PXPA"),
        ("secret", ""),
        ("secret", None),
        ("secret", 1234567890123456),
        ("secret", b"JBSWY3DPEHPK3PXP"),
        ("secret", ["J"] * 16),
        ("secret", "A" * 1000),
        ("secret", "A" * 1_000_000),
        ("algorithm", "sha1"),
        ("algorithm", "SHA-1"),
        ("algorithm", "MD5"),
        ("algorithm", None),
        ("algorithm", 1),
        ("algorithm", ["SHA1"]),
        ("algorithm", {"name": "SHA1"}),
        ("digits", 5),
        ("digits", 9),
        ("digits", "6"),
        ("digits", 6.0),
        ("digits", True),
        ("digits", None),
        ("digits", [6]),
        ("digits", 10**100),
        ("period", 0),
        ("period", 301),
        ("period", -30),
        ("period", "30"),
        ("period", 30.0),
        ("period", True),
        ("period", None),
        ("period", 10**100),
        ("issuer", None),
        ("issuer", 7),
        ("issuer", ["ACME"]),
        ("issuer", "x" * 256),
        ("issuer", " ACME"),
        ("issuer", "ACME "),
        ("issuer", "ACME  Co"),
        ("issuer", "ACME\nCo"),
        ("issuer", "ACME\x00"),
        ("issuer", "ACME\x1b[2J"),
        ("issuer", "AC\u202eME"),
        ("issuer", "ACME\u00a0Co"),
        ("issuer", "\ud800"),
        ("account", None),
        ("account", 0),
        ("account", "x" * 256),
        ("account", "tab\there"),
        ("account", "\ufeffalice"),
    ],
)
def test_validate_refuses_malformed_fields(field, value):
    record = {**otp.make_totp(SECRET), field: value}
    with pytest.raises(VaultError):
        otp.validate(record)
    with pytest.raises(VaultError):
        otp.code_at(record, 59)
    with pytest.raises(VaultError):
        otp.to_otpauth(record)


@PROPERTY
@given(value=json_values)
def test_validate_only_ever_raises_vault_error(value):
    try:
        checked = otp.validate(value)
    except VaultError:
        return
    assert set(checked) == set(otp._FIELDS)


@PROPERTY
@given(totp=totps, field=st.sampled_from(otp._FIELDS), value=json_values)
def test_validate_judges_every_field_of_a_plausible_record(totp, field, value):
    record = {**totp, field: value}
    try:
        checked = otp.validate(record)
    except VaultError:
        return
    assert checked == record
    assert len(otp.code_at(checked, 0)) == checked["digits"]


# -- parse_otpauth ---------------------------------------------------------------


def test_parse_the_examples_of_the_key_uri_format():
    assert otp.parse_otpauth("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example") == {
        "secret": SECRET,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
        "issuer": "Example",
        "account": "alice@google.com",
    }
    assert otp.parse_otpauth(
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
        "&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
    ) == {
        "secret": "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
        "issuer": "ACME Co",
        "account": "john.doe@email.com",
    }


def test_parse_reads_every_parameter():
    parsed = otp.parse_otpauth("otpauth://totp/x?secret=" + SECRET + "&algorithm=SHA512&digits=8&period=60")
    assert (parsed["algorithm"], parsed["digits"], parsed["period"]) == ("SHA512", 8, 60)
    assert otp.parse_otpauth("otpauth://totp/x?secret=" + SECRET + "&digits=7")["digits"] == 7


@pytest.mark.parametrize(
    ("link", "issuer", "account"),
    [
        ("otpauth://totp/alice?secret={s}", "", "alice"),
        ("otpauth://totp/Example:alice?secret={s}", "Example", "alice"),
        ("otpauth://totp/Example%3Aalice?secret={s}", "Example", "alice"),
        ("otpauth://totp/Example%3aalice?secret={s}", "Example", "alice"),
        ("otpauth://totp/Example:%20%20alice?secret={s}", "Example", "alice"),
        ("otpauth://totp/Example: alice?secret={s}", "Example", "alice"),
        ("otpauth://totp/Old:alice?secret={s}&issuer=New", "New", "alice"),
        ("otpauth://totp/Prefix:alice?secret={s}&issuer=", "Prefix", "alice"),
        ("otpauth://totp/alice?secret={s}&issuer=My+Company", "My Company", "alice"),
        ("otpauth://totp/alice?secret={s}&issuer=A%2BB%26C", "A+B&C", "alice"),
        ("otpauth://totp/alice+work@example.com?secret={s}", "", "alice+work@example.com"),
        ("otpauth://totp/Big%20Co:al%3Aice?secret={s}", "Big Co", "al:ice"),
        ("otpauth://totp/Big%20Co:a:b:c?secret={s}", "Big Co", "a:b:c"),
        ("otpauth://totp/Team/Dept:alice?secret={s}", "Team/Dept", "alice"),
        ("otpauth://totp/?secret={s}", "", ""),
        ("otpauth://totp?secret={s}", "", ""),
        ("otpauth://totp/%D7%91%D7%A0%D7%A7:%D7%93%D7%A0%D7%94?secret={s}", "\u05d1\u05e0\u05e7", "\u05d3\u05e0\u05d4"),
        ("otpauth://totp/\u00dftra\u00dfe%3Abob?secret={s}", "\u00dftra\u00dfe", "bob"),
        ("otpauth://totp/a%0Ab:c%09d?secret={s}", "a b", "c d"),
    ],
)
def test_parse_labels_and_issuers(link, issuer, account):
    parsed = otp.parse_otpauth(link.format(s=SECRET))
    assert (parsed["issuer"], parsed["account"]) == (issuer, account)
    assert parsed["secret"] == SECRET


@pytest.mark.parametrize(
    "link",
    [
        "otpauth://totp/x?secret=jbswy3dpehpk3pxp",
        "otpauth://totp/x?secret=JBSW%20Y3DP%20EHPK%203PXP",
        "otpauth://totp/x?secret=JBSW+Y3DP+EHPK+3PXP",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP%3D%3D%3D",
        "OTPAUTH://TOTP/x?SECRET=JBSWY3DPEHPK3PXP",
        "  otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP#fragment",
        "otpauth://totp/x?image=https%3A%2F%2Fexample.com%2Flogo.png&secret=JBSWY3DPEHPK3PXP&lock=true&novalue",
        "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=&digits=&period=",
    ],
)
def test_parse_is_lenient_about_form(link):
    parsed = otp.parse_otpauth(link)
    assert parsed["secret"] == SECRET
    assert (parsed["algorithm"], parsed["digits"], parsed["period"]) == ("SHA1", 6, 30)


@pytest.mark.parametrize(
    ("link", "message"),
    [
        ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "counter-based"),
        ("otpauth://HOTP/x?secret=JBSWY3DPEHPK3PXP", "counter-based"),
        ("otpauth://steam/x?secret=JBSWY3DPEHPK3PXP", "unsupported otpauth type 'steam'"),
        ("otpauth://totp:8080/x?secret=JBSWY3DPEHPK3PXP", "unsupported otpauth type"),
        ("otpauth:///x?secret=JBSWY3DPEHPK3PXP", "unsupported otpauth type ''"),
        ("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8", "export link"),
        ("https://example.com/totp/x?secret=JBSWY3DPEHPK3PXP", "not an otpauth link"),
        ("otpauth:totp/x?secret=JBSWY3DPEHPK3PXP", "not an otpauth link"),
        ("JBSWY3DPEHPK3PXP", "not an otpauth link"),
        ("", "not an otpauth link"),
        ("otpauth://totp/x", "no secret"),
        ("otpauth://totp/x?secret=", "no secret"),
        ("otpauth://totp/x?issuer=Example", "no secret"),
        ("otpauth://totp/x#?secret=JBSWY3DPEHPK3PXP", "no secret"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXQ", "more than once"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&Secret=JBSWY3DPEHPK3PXP", "more than once"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6&digits=8", "more than once"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=A&issuer=B", "more than once"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=six", "digits value"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=%D9%A6", "digits value"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=-6", "digits value"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6.0", "digits value"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5", "6, 7 or 8 digits"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5&encoder=steam", "6, 7 or 8 digits"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0", "from 1 to 300"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=3600", "from 1 to 300"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=99999", "period value"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "unsupported one-time-password algorithm"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PX0", "not base32"),
        ("otpauth://totp/x?secret=JBSWY3DP", "too short"),
        ("otpauth://totp/%FF%FE?secret=JBSWY3DPEHPK3PXP", "not valid UTF-8"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=%FF", "cannot be read"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" + "&a=1" * 40, "cannot be read"),
        ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\x00", "control characters"),
        ("otpauth://totp/x\ty?secret=JBSWY3DPEHPK3PXP", "control characters"),
        ("otpauth://totp/x?secret=JBSW\nY3DPEHPK3PXP", "control characters"),
        ("otpauth://totp/" + "x" * 17000 + "?secret=JBSWY3DPEHPK3PXP", "too long"),
        ("otpauth://totp/" + "x" * 300 + "?secret=JBSWY3DPEHPK3PXP", "account name is too long"),
    ],
)
def test_parse_refuses_with_a_reason(link, message):
    with pytest.raises(UsageError, match=message):
        otp.parse_otpauth(link)


@pytest.mark.parametrize("not_text", [None, b"otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", 5, ["otpauth://"]])
def test_parse_refuses_what_is_not_text(not_text):
    with pytest.raises(UsageError):
        otp.parse_otpauth(not_text)


@PROPERTY
@given(text=st.text(max_size=200))
def test_parse_only_ever_raises_usage_error(text):
    for candidate in (text, "otpauth://totp/" + text, "otpauth://totp/x?secret=" + SECRET + "&" + text):
        try:
            parsed = otp.parse_otpauth(candidate)
        except UsageError:
            continue
        assert otp.validate(parsed) == parsed


# -- to_otpauth --------------------------------------------------------------------


def test_format_writes_every_parameter():
    link = otp.to_otpauth(otp.make_totp(SECRET, issuer="ACME Co", account="john.doe@email.com"))
    assert link == (
        "otpauth://totp/ACME%20Co:john.doe@email.com"
        "?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
    )
    assert otp.to_otpauth(otp.make_totp(SECRET, algorithm="sha512", digits=8, period=60, account="bob")) == (
        "otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512&digits=8&period=60"
    )


def test_format_escapes_what_would_break_the_link():
    made = otp.make_totp(SECRET, issuer="R&D #1 / 50% + more?", account="a:b c@d.e")
    link = otp.to_otpauth(made)
    label, _, query = link[len("otpauth://totp/") :].partition("?")
    assert label == "R%26D%20%231%20%2F%2050%25%20%2B%20more%3F:a%3Ab%20c@d.e"
    assert "issuer=R%26D%20%231%20%2F%2050%25%20%2B%20more%3F&" in query
    assert otp.parse_otpauth(link) == made


def test_format_with_a_label_of_the_callers_choice():
    made = otp.make_totp(SECRET, issuer="GitHub")
    assert otp.to_otpauth(made).startswith("otpauth://totp/GitHub:?secret=")
    link = otp.to_otpauth(made, label="work laptop")
    assert link.startswith("otpauth://totp/work%20laptop?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&")
    parsed = otp.parse_otpauth(link)
    assert (parsed["issuer"], parsed["account"]) == ("GitHub", "work laptop")
    assert otp.to_otpauth(made, label="GitHub:king").startswith("otpauth://totp/GitHub:king?")
    for bad in (7, b"label", "x" * 256):
        with pytest.raises(UsageError):
            otp.to_otpauth(made, label=bad)


@pytest.mark.parametrize(
    ("label_and_parameters", "issuer", "account"),
    [
        ("GitHub:octocat?secret={s}&issuer=GitHub", "GitHub", "octocat"),
        ("Google%3Aalice%40gmail.com?secret={s}&issuer=Google", "Google", "alice@gmail.com"),
        ("Microsoft:alice%40outlook.com?secret={s}&issuer=Microsoft", "Microsoft", "alice@outlook.com"),
        (
            "Amazon%20Web%20Services:alice@123456789012?secret={s}&issuer=Amazon%20Web%20Services",
            "Amazon Web Services",
            "alice@123456789012",
        ),
        ("Twitter:@alice?secret={s}&issuer=Twitter", "Twitter", "@alice"),
        ("alice@proton.me?secret={s}&issuer=Proton&algorithm=SHA1&digits=6&period=30", "Proton", "alice@proton.me"),
        (
            "Example%20Bank:alice?secret={s}&issuer=Example+Bank&image=https%3A%2F%2Fexample.com%2Flogo.png",
            "Example Bank",
            "alice",
        ),
        ("alice?secret={s}&period=30&digits=6&algorithm=SHA1&issuer=Self%2DHosted", "Self-Hosted", "alice"),
    ],
)
def test_parse_links_in_the_shapes_services_hand_out(label_and_parameters, issuer, account):
    parsed = otp.parse_otpauth("otpauth://totp/" + label_and_parameters.format(s=SECRET.lower()))
    assert parsed == otp.make_totp(SECRET, issuer=issuer, account=account)
    assert otp.parse_otpauth(otp.to_otpauth(parsed)) == parsed


def test_the_longest_settings_there_can_be_survive_the_round_trip():
    """Every limit at once: the link this writes must still be one that is read back."""
    wide = "\U0001f600" * 255  # each character becomes twelve in a link
    longest = otp.make_totp(
        "7" * otp._MAX_SECRET_CHARS, algorithm="SHA512", digits=8, period=300, issuer=wide, account=wide
    )
    link = otp.to_otpauth(longest)
    assert 9000 < len(link) < otp._MAX_URI
    assert otp.parse_otpauth(link) == longest
    assert len(otp.code_at(longest, 0)) == 8


@PROPERTY
@given(totp=totps)
def test_format_then_parse_gives_the_settings_back(totp):
    link = otp.to_otpauth(totp)
    assert otp.parse_otpauth(link) == totp
    assert link.isascii() and " " not in link
    assert otp.parse_otpauth("  " + link.replace("otpauth://totp/", "OTPAUTH://TOTP/") + "\n") == totp


@PROPERTY
@given(
    raw=raw_secrets,
    issuer=st.text(alphabet=":%3Aa +/@#?&=", max_size=12),
    account=st.text(alphabet=":%3Aa +/@#?&=", max_size=12),
)
def test_round_trip_with_the_characters_links_are_made_of(raw, issuer, account):
    totp = otp.make_totp(b32(raw), issuer=issuer, account=account)
    assert otp.parse_otpauth(otp.to_otpauth(totp)) == totp


@PROPERTY
@given(totp=totps, label=labels)
def test_parse_reads_links_written_by_others(totp, label):
    """A link built the way other software builds one: everything percent-encoded, defaults left out."""
    link = "otpauth://totp/" + quote(label, safe="") + "?secret=" + totp["secret"].lower()
    if totp["issuer"]:
        link += "&issuer=" + quote(totp["issuer"], safe="")
    if totp["algorithm"] != "SHA1":
        link += "&algorithm=" + totp["algorithm"]
    if totp["digits"] != 6:
        link += f"&digits={totp['digits']}"
    if totp["period"] != 30:
        link += f"&period={totp['period']}"
    parsed = otp.parse_otpauth(link)
    for field in ("secret", "algorithm", "digits", "period"):
        assert parsed[field] == totp[field]
    prefix, colon, rest = label.partition(":")
    assert parsed["account"] == (rest.strip() if colon else label)
    assert parsed["issuer"] == (totp["issuer"] or (prefix.strip() if colon else ""))


# -- time ----------------------------------------------------------------------------


@pytest.mark.parametrize("when", [None, "59", b"59", True, False, [59], float("nan"), float("inf"), -float("inf")])
def test_times_must_be_finite_numbers(when):
    totp = rfc_totp()
    with pytest.raises(UsageError, match="seconds since 1970"):
        otp.code_at(totp, when)
    if when is not None:
        for call in (otp.code_for, otp.seconds_remaining):
            with pytest.raises(UsageError, match="seconds since 1970"):
                call(totp, when)
        with pytest.raises(UsageError, match="seconds since 1970"):
            otp.verify(totp, "000000", when)
        with pytest.raises(UsageError, match="seconds since 1970"):
            otp.code_from_window({1: "94287082"}, 30, when)
    for window in ((when, 60), (0, when)):
        with pytest.raises(UsageError, match="seconds since 1970"):
            otp.codes_for_window(totp, *window)


@pytest.mark.parametrize("when", [-1, -0.001, -(10**30)])
def test_times_before_1970_are_refused(when):
    with pytest.raises(UsageError, match="before 1970"):
        otp.code_at(rfc_totp(), when)
    with pytest.raises(UsageError, match="before 1970"):
        otp.seconds_remaining(rfc_totp(), when)


@pytest.mark.parametrize("when", [2**64 * 30, 10**400, 1e300])
def test_times_beyond_the_counter_are_refused(when):
    with pytest.raises(UsageError, match="too far in the future"):
        otp.code_at(rfc_totp(), when)


def test_the_last_counter_value_still_works():
    code = otp.code_at(rfc_totp(), (2**64 - 1) * 30)
    assert len(code) == 8 and code.isdigit()


def test_code_for_and_seconds_remaining_use_the_clock(clock):
    totp = rfc_totp()
    clock(59.0)
    assert otp.code_for(totp) == "94287082"
    assert otp.seconds_remaining(totp) == 1
    clock(1111111111.5)
    assert otp.code_for(totp) == "14050471"
    assert otp.code_for(totp, 59) == "94287082"
    assert otp.seconds_remaining(totp) == 30 - 1111111111 % 30


@pytest.mark.parametrize(
    ("period", "at", "remaining"),
    [(30, 0, 30), (30, 0.5, 30), (30, 1, 29), (30, 29, 1), (30, 29.999, 1), (30, 30, 30), (30, 59, 1), (60, 61, 59),
     (1, 12345.678, 1), (300, 299, 1), (300, 300, 300)],
)  # fmt: skip
def test_seconds_remaining(period, at, remaining):
    assert otp.seconds_remaining(rfc_totp(period=period), at) == remaining


@PROPERTY
@given(totp=totps, at=st.integers(0, 2**40) | st.floats(0, 2**40))
def test_the_code_changes_when_seconds_remaining_says_so(totp, at):
    remaining = otp.seconds_remaining(totp, at)
    assert 1 <= remaining <= totp["period"]
    step = at // totp["period"]
    assert (math.floor(at) + remaining) // totp["period"] == step + 1
    assert (math.floor(at) + remaining - 1) // totp["period"] == step


# -- tables of codes for a window of time ------------------------------------------


def test_window_holds_one_code_per_time_step():
    totp = rfc_totp()
    table = otp.codes_for_window(totp, 59, 1000)
    assert list(table) == list(range(1, 34))
    assert table[1] == "94287082"
    assert all(table[counter] == otp.code_at(totp, counter * 30) for counter in table)


@pytest.mark.parametrize(
    ("start", "end", "counters"),
    [
        (0, 0, [0]),
        (0, 29.999, [0]),
        (0, 30, [0, 1]),
        (29.999, 30, [0, 1]),
        (30, 30, [1]),
        (45, 46, [1]),
        (59, 60, [1, 2]),
        (60, 149, [2, 3, 4]),
    ],
)
def test_window_covers_every_step_it_overlaps(start, end, counters):
    assert list(otp.codes_for_window(rfc_totp(), start, end)) == counters


def test_window_size_is_limited():
    every_second = rfc_totp(period=1)
    assert len(otp.codes_for_window(every_second, 0, otp.MAX_WINDOW_CODES - 1)) == otp.MAX_WINDOW_CODES
    with pytest.raises(UsageError, match="5001 one-time passwords and the limit is 5000"):
        otp.codes_for_window(every_second, 0, otp.MAX_WINDOW_CODES)
    with pytest.raises(UsageError, match="limit is 5000"):
        otp.codes_for_window(rfc_totp(), 0, 10**12)
    midnight = 1_700_006_400  # a multiple of 86400, so of 30 as well
    assert len(otp.codes_for_window(rfc_totp(), midnight, midnight + 86_400 - 1)) == 2880
    assert len(otp.codes_for_window(rfc_totp(), midnight + 10, midnight + 86_400 + 9)) == 2881


def test_window_must_not_end_before_it_starts():
    with pytest.raises(UsageError, match="ends before it starts"):
        otp.codes_for_window(rfc_totp(), 100, 99)
    with pytest.raises(UsageError, match="ends before it starts"):
        otp.codes_for_window(rfc_totp(), 59.5, 59.25)


def test_window_does_not_contain_the_secret():
    totp = otp.make_totp(SECRET, issuer="ACME", account="alice")
    stored = json.dumps(otp.codes_for_window(totp, 0, 3600))
    assert SECRET not in stored and SECRET.lower() not in stored
    assert set(stored) <= set('0123456789{}":, ')


def test_reading_a_window_exhaustively():
    totp = rfc_totp(digits=6, period=7)
    table = otp.codes_for_window(totp, 100, 163)
    for tenths in range(1000, 1640):
        at = tenths / 10
        assert otp.code_from_window(table, 7, at) == otp.code_at(totp, at)
    assert otp.code_from_window(table, 7, 98) == otp.code_at(totp, 98)  # still inside the first step
    assert otp.code_from_window(table, 7, 167.9) == otp.code_at(totp, 167.9)  # and inside the last
    for outside in (97.999, 0, 168, 10**9):
        with pytest.raises(AuthError, match="outside the time window"):
            otp.code_from_window(table, 7, outside)


@PROPERTY
@given(totp=totps, start=st.integers(0, 2**36), span=st.floats(0, 900), data=st.data())
def test_reading_a_window_agrees_with_code_at(totp, start, span, data):
    period = totp["period"]
    end = start + span
    table = otp.codes_for_window(totp, start, end)
    assert list(table) == list(range(start // period, int(end // period) + 1))
    at = data.draw(st.floats(start, end) | st.integers(start, math.floor(end)))
    assert otp.code_from_window(table, period, at) == otp.code_at(totp, at)
    through_json = json.loads(json.dumps(table))
    assert otp.code_from_window(through_json, period, at) == otp.code_at(totp, at)
    first, last = min(table) * period, (max(table) + 1) * period
    with pytest.raises(AuthError):
        otp.code_from_window(table, period, last)
    if first > 0:
        with pytest.raises(AuthError):
            otp.code_from_window(table, period, first - 0.001)


def test_reading_a_window_uses_the_clock(clock):
    totp = rfc_totp()
    table = otp.codes_for_window(totp, 0, 120)
    clock(59.0)
    assert otp.code_from_window(table, 30) == "94287082"
    clock(1e9)
    with pytest.raises(AuthError):
        otp.code_from_window(table, 30)


@pytest.mark.parametrize("table", [None, [], "94287082", 5, [("1", "94287082")], {1}])
def test_reading_refuses_what_is_not_a_table(table):
    with pytest.raises(VaultError, match="table is malformed"):
        otp.code_from_window(table, 30, 59)


@pytest.mark.parametrize("period", [0, 301, -30, 30.0, "30", None, True])
def test_reading_refuses_a_malformed_period(period):
    with pytest.raises(VaultError, match="malformed period"):
        otp.code_from_window({1: "94287082"}, period, 59)


@pytest.mark.parametrize(
    "code",
    [94287082, "942870821", "12345", "", "abcdef", "94 287", "+12345", "\u0661\u0662\u0663\u0664\u0665\u0666",
     ["942870"], b"942870", True, 0],
)  # fmt: skip
def test_reading_refuses_a_damaged_table(code):
    for table in ({1: code}, {"1": code}):
        with pytest.raises(VaultError, match="table is damaged"):
            otp.code_from_window(table, 30, 59)


# -- verify ----------------------------------------------------------------------


def test_verify_accepts_the_current_code_and_its_neighbours():
    totp = rfc_totp()
    now = 1111111111
    current = otp.code_at(totp, now)
    assert current == "14050471"
    assert otp.verify(totp, current, now)
    assert otp.verify(totp, "1405 0471", now)
    assert otp.verify(totp, " 14050471\n", now)
    assert otp.verify(totp, otp.code_at(totp, now - 30), now)
    assert otp.verify(totp, otp.code_at(totp, now + 30), now)
    assert not otp.verify(totp, otp.code_at(totp, now - 60), now)
    assert not otp.verify(totp, otp.code_at(totp, now + 60), now)
    assert otp.verify(totp, otp.code_at(totp, now + 60), now, drift=2)
    assert not otp.verify(totp, otp.code_at(totp, now - 30), now, drift=0)
    assert otp.verify(totp, current, now, drift=0)


@pytest.mark.parametrize("wrong", ["", "0", "1405047", "140504711", "14050472", "abcdefgh", "\u0661" * 8, "14050471x"])
def test_verify_rejects_wrong_codes(wrong):
    assert otp.verify(rfc_totp(), wrong, 1111111111) is False


def test_verify_at_the_start_of_time_and_with_the_clock(clock):
    totp = rfc_totp()
    assert otp.verify(totp, otp.code_at(totp, 0), 0)
    assert otp.verify(totp, otp.code_at(totp, 30), 0)
    clock(59.0)
    assert otp.verify(totp, "94287082")
    assert not otp.verify(totp, "94287083")


@pytest.mark.parametrize("drift", [-1, otp.MAX_DRIFT + 1, 1.0, "1", None, True])
def test_verify_refuses_other_drifts(drift):
    with pytest.raises(UsageError, match="drift"):
        otp.verify(rfc_totp(), "94287082", 59, drift=drift)


@pytest.mark.parametrize("code", [None, 94287082, b"94287082", ["94287082"]])
def test_verify_needs_text(code):
    with pytest.raises(UsageError, match="as text"):
        otp.verify(rfc_totp(), code, 59)


def test_verify_compares_every_candidate_in_constant_time(monkeypatch):
    calls = []

    def recording(left, right):
        calls.append((left, right))
        return std_hmac.compare_digest(left, right)

    monkeypatch.setattr(otp, "hmac", types.SimpleNamespace(digest=std_hmac.digest, compare_digest=recording))
    totp = rfc_totp()
    earliest = otp.code_at(totp, 1111111111 - 60)
    assert otp.verify(totp, earliest, 1111111111, drift=2)
    assert len(calls) == 5, "a match must not cut the comparison short"
    assert all(isinstance(left, bytes) and right == earliest.encode() for left, right in calls)
    calls.clear()
    assert not otp.verify(totp, "00000000", 1111111111, drift=0)
    assert len(calls) == 1


@PROPERTY
@given(totp=totps, at=st.integers(0, 2**40), drift=st.integers(0, otp.MAX_DRIFT), offset=st.integers(-12, 12))
def test_verify_accepts_exactly_the_steps_within_drift(totp, at, drift, offset):
    other = at + offset * totp["period"]
    if other < 0:
        return
    code = otp.code_at(totp, other)
    accepted = otp.verify(totp, code, at, drift=drift)
    if abs(offset) <= drift:
        assert accepted
    elif not accepted:
        return
    else:  # a code from outside the drift can only pass by colliding with one inside it
        step = at // totp["period"]
        shifts = [shift for shift in range(-drift, drift + 1) if step + shift >= 0]
        assert code in {otp.code_at(totp, (step + shift) * totp["period"]) for shift in shifts}


# -- what must never happen ---------------------------------------------------------


def test_error_messages_never_contain_the_secret():
    secret = "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U"
    lowered = secret.lower()
    attempts = [
        lambda: otp.normalise_secret(secret + "1"),
        lambda: otp.normalise_secret(secret + "!"),
        lambda: otp.normalise_secret(secret[:15]),
        lambda: otp.normalise_secret(secret + "A"),
        lambda: otp.make_totp(secret, digits=5),
        lambda: otp.make_totp(secret, period=0),
        lambda: otp.make_totp(secret, algorithm="MD5"),
        lambda: otp.make_totp(secret, issuer=7),
        lambda: otp.validate({**otp.make_totp(secret), "secret": lowered}),
        lambda: otp.validate({**otp.make_totp(secret), "extra": 1}),
        lambda: otp.validate({**otp.make_totp(secret), "digits": "6"}),
        lambda: otp.parse_otpauth("otpauth://hotp/x?secret=" + secret),
        lambda: otp.parse_otpauth("otpauth://totp/x?secret=" + secret + "&secret=" + secret),
        lambda: otp.parse_otpauth("otpauth://totp/x?secret=" + secret + "&digits=4"),
        lambda: otp.parse_otpauth("otpauth://totp/x?secret=" + secret + "0"),
        lambda: otp.parse_otpauth("otpauth://totp/x?secret=" + secret + "&issuer=%FF"),
        lambda: otp.parse_otpauth("otpauth://nope/" + secret + "?secret=" + secret),
        lambda: otp.code_at(otp.make_totp(secret), -1),
        lambda: otp.code_at(otp.make_totp(secret), "now"),
        lambda: otp.codes_for_window(otp.make_totp(secret), 0, 10**9),
        lambda: otp.code_from_window(otp.codes_for_window(otp.make_totp(secret), 0, 60), 30, 10**9),
        lambda: otp.verify(otp.make_totp(secret), secret, 0, drift=99),
        lambda: otp.to_otpauth(otp.make_totp(secret), label=7),
    ]
    for attempt in attempts:
        with pytest.raises(IronDomeError) as caught:
            attempt()
        shown = str(caught.value)
        assert secret not in shown and lowered not in shown and secret[:12] not in shown
        assert shown and shown == shown.strip() and "\n" not in shown


def test_the_module_imports_nothing_that_can_reach_a_network():
    tree = ast.parse(Path(otp.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
    assert imported == {
        "__future__",
        "hmac",
        "math",
        "struct",
        "time",
        "typing",
        "urllib.parse",
        "irondome.errors",
        "irondome.secmem",
    }


def test_the_sources_hold_no_hidden_characters():
    """Invisible and look-alike characters cannot hide in plain ASCII, so that is all these files hold."""
    for path in (Path(otp.__file__), Path(__file__)):
        assert path.read_bytes().isascii(), path.name


def test_public_names():
    assert set(otp.__all__) >= {
        "normalise_secret",
        "make_totp",
        "validate",
        "parse_otpauth",
        "to_otpauth",
        "code_at",
        "code_for",
        "seconds_remaining",
        "codes_for_window",
        "code_from_window",
    }
    assert all(hasattr(otp, name) for name in otp.__all__)
    assert (otp.ALGORITHMS, otp.DIGITS) == (("SHA1", "SHA256", "SHA512"), (6, 7, 8))
    assert (otp.MIN_PERIOD, otp.MAX_PERIOD) == (1, 300)
    assert otp.MAX_WINDOW_CODES == 5000 and otp.MIN_SECRET_BYTES == 10


# -- through the vault ---------------------------------------------------------------


def test_a_vault_entry_yields_the_current_code(vault, clock):
    from irondome.vault import Secret

    entry = vault.add("bank", Secret(password="correct horse", totp=rfc_totp()))
    assert entry.has_totp
    clock(59.0)
    assert vault.value(entry, "totp") == "94287082"
    clock(1234567890.0)
    assert vault.value(entry, "totp") == "89005924"
    assert otp.validate(vault.read_secret(entry).totp) == rfc_totp()
