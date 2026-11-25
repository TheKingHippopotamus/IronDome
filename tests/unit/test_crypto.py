"""The primitives, checked against published vectors and against their own contract.

The known answers in this file are the reason a change to a parameter, a
label or the underlying library cannot alter key derivation without a test
going red.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Optional

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from irondome import crypto
from irondome.crypto import (
    DEFAULT_ARGON2,
    KEY_LEN,
    NONCE_LEN,
    SALT_LEN,
    TAG_LEN,
    Argon2Params,
    DecryptError,
    argon2id,
    b64d,
    b64e,
    default_argon2,
    hkdf,
    open_sealed,
    open_sealed_into,
    pad,
    random_bytes,
    seal,
    unpad,
)
from irondome.errors import IronDomeError, VaultError
from irondome.secmem import SecureBuffer

SMALL = Argon2Params(memory_kib=19 * 1024, iterations=2, lanes=1)  # the OWASP minimum
KEY = bytes(range(32))


def h(text: str) -> bytes:
    return bytes.fromhex(text)


def reference_hkdf(ikm: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    """HKDF-SHA256 written out from RFC 5869 with nothing but ``hmac``."""
    prk = hmac.new(salt if salt else bytes(32), ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_sizes_are_the_documented_ones():
    assert (KEY_LEN, NONCE_LEN, TAG_LEN, SALT_LEN) == (32, 12, 16, 16)


def test_decrypt_error_is_a_plain_irondome_error():
    assert issubclass(DecryptError, IronDomeError)
    assert DecryptError("x").exit_code == 1


# ---------------------------------------------------------------------------
# HKDF-SHA256
# ---------------------------------------------------------------------------

RFC5869 = [
    # RFC 5869 appendix A.1: basic test case with SHA-256
    (
        "0b" * 22,
        "000102030405060708090a0b0c",
        "f0f1f2f3f4f5f6f7f8f9",
        42,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    ),
    # RFC 5869 appendix A.2: longer inputs and outputs
    (
        bytes(range(0x00, 0x50)).hex(),
        bytes(range(0x60, 0xB0)).hex(),
        bytes(range(0xB0, 0x100)).hex(),
        82,
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    ),
]


@pytest.mark.parametrize("ikm, salt, info, length, okm", RFC5869, ids=["A.1", "A.2"])
def test_hkdf_matches_rfc_5869(ikm, salt, info, length, okm):
    with hkdf(h(ikm), info=h(info), salt=h(salt), length=length) as derived:
        assert bytes(derived.view()) == h(okm)
        assert len(derived) == length


def test_hkdf_reference_implementation_matches_rfc_5869_a3():
    """A.3 has an empty label, which hkdf() refuses; it anchors the reference used below."""
    expected = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    assert reference_hkdf(h("0b" * 22), b"", b"", 42) == h(expected)
    for ikm, salt, info, length, okm in RFC5869:
        assert reference_hkdf(h(ikm), h(salt), h(info), length) == h(okm)


@given(
    ikm=st.binary(min_size=1, max_size=200),
    salt=st.one_of(st.none(), st.binary(max_size=100)),
    info=st.binary(min_size=1, max_size=100),
    length=st.integers(min_value=1, max_value=255),
)
@settings(max_examples=100, deadline=None)
def test_hkdf_agrees_with_the_reference_for_any_input(ikm, salt, info, length):
    with hkdf(ikm, info=info, salt=salt, length=length) as derived:
        assert bytes(derived.view()) == reference_hkdf(ikm, salt, info, length)


def test_hkdf_without_a_salt_is_hkdf_with_a_zero_salt():
    with hkdf(KEY, info=b"label") as no_salt, hkdf(KEY, info=b"label", salt=bytes(32)) as zero_salt:
        assert bytes(no_salt.view()) == bytes(zero_salt.view())


@pytest.mark.parametrize("info", [b"", None, ""])
def test_hkdf_needs_a_purpose_label(info):
    with pytest.raises(ValueError, match="purpose label"):
        hkdf(KEY, info=info)  # type: ignore[arg-type]


def test_hkdf_separates_purposes_salts_and_keys():
    outputs = set()
    for ikm, info, salt in [
        (KEY, b"irondome/v4/index", b"s1"),
        (KEY, b"irondome/v4/entry", b"s1"),
        (KEY, b"irondome/v4/index", b"s2"),
        (bytes(32), b"irondome/v4/index", b"s1"),
        (KEY, b"irondome/v4/index\x00", b"s1"),
    ]:
        with hkdf(ikm, info=info, salt=salt) as derived:
            assert len(derived) == KEY_LEN
            outputs.add(bytes(derived.view()))
    assert len(outputs) == 5


def test_hkdf_takes_key_material_from_locked_memory():
    with SecureBuffer.from_buffer(KEY) as locked, hkdf(locked, info=b"label", salt=b"salt") as from_locked:
        with hkdf(KEY, info=b"label", salt=b"salt") as from_bytes:
            assert bytes(from_locked.view()) == bytes(from_bytes.view())
        assert bytes(locked.view()) == KEY  # the input is left alone


@pytest.mark.parametrize("length", [0, -1, 255 * 32 + 1])
def test_hkdf_refuses_impossible_lengths(length):
    with pytest.raises(ValueError):
        hkdf(KEY, info=b"label", length=length)


def test_hkdf_longest_output():
    with hkdf(KEY, info=b"label", length=255 * 32) as derived:
        assert bytes(derived.view()) == reference_hkdf(KEY, None, b"label", 255 * 32)


# ---------------------------------------------------------------------------
# Argon2id
# ---------------------------------------------------------------------------

# Frozen known answers for argon2id() itself: password "correct horse battery
# staple", salt 00..0f. Computed once with cryptography 50.0.2 and confirmed
# with the reference C implementation (argon2-cffi 25.1.0). If one of these
# ever changes, every existing vault stops opening.
ARGON2_KNOWN_ANSWERS = [
    (19456, 2, 1, "818259b6310026a8e0dbac5d2e6927abcfdb07b32258fac4f61b18b80f929085"),
    (19456, 2, 4, "b9809d332460011400272cf67066fc2800f170cf066c02e22020c1f3d16fb576"),
    (32768, 3, 2, "6bebc900dbcdeac9a0d37379945ba63898490089fa7c03615aefc83edf7d286f"),
    (47104, 1, 1, "fdca024fae17b143175e4e725b9341fbbd176aaf77d79d78c44d28007d7b11a7"),
]


@pytest.mark.parametrize("memory, iterations, lanes, expected", ARGON2_KNOWN_ANSWERS)
def test_argon2id_known_answers_are_frozen(memory, iterations, lanes, expected):
    params = Argon2Params(memory_kib=memory, iterations=iterations, lanes=lanes)
    with argon2id(b"correct horse battery staple", bytes(range(16)), params) as key:
        assert bytes(key.view()) == h(expected)
        assert len(key) == KEY_LEN


def test_the_library_implements_rfc_9106():
    """RFC 9106 section 5.3. Its parameters are below IronDome's floor, so the library is asked directly."""
    kdf = Argon2id(salt=b"\x02" * 16, length=32, iterations=3, lanes=4, memory_cost=32, ad=b"\x04" * 12,
                   secret=b"\x03" * 8)
    assert kdf.derive(b"\x01" * 32) == h("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")


def test_argon2id_returns_locked_memory_and_accepts_it_as_input():
    salt = bytes(range(16))
    with SecureBuffer.from_buffer(b"correct horse battery staple") as password:
        with argon2id(password, salt, SMALL) as from_locked, argon2id(bytearray(b"correct horse battery staple"), salt,
                                                                      SMALL) as from_bytearray:
            assert isinstance(from_locked, SecureBuffer)
            assert bytes(from_locked.view()) == bytes(from_bytearray.view()) == h(ARGON2_KNOWN_ANSWERS[0][3])
        assert bytes(password.view()) == b"correct horse battery staple"


def test_argon2id_depends_on_password_salt_and_every_cost():
    base = dict(password=b"password", salt=bytes(16), params=SMALL)
    variants = [
        base,
        dict(base, password=b"passwore"),
        dict(base, salt=bytes(15) + b"\x01"),
        dict(base, salt=bytes(17)),
        dict(base, params=Argon2Params(memory_kib=19 * 1024 + 8, iterations=2, lanes=1)),
        dict(base, params=Argon2Params(memory_kib=19 * 1024, iterations=3, lanes=1)),
        dict(base, params=Argon2Params(memory_kib=19 * 1024, iterations=2, lanes=2)),
    ]
    outputs = set()
    for variant in variants:
        with argon2id(variant["password"], variant["salt"], variant["params"]) as key:  # type: ignore[arg-type]
            outputs.add(bytes(key.view()))
    assert len(outputs) == len(variants)


@pytest.mark.parametrize("salt", [b"", b"short", bytes(15)])
def test_argon2id_refuses_a_short_salt(salt):
    with pytest.raises(VaultError, match="salt is too short"):
        argon2id(b"password", salt, SMALL)


def test_argon2id_validates_its_parameters_before_working():
    with pytest.raises(VaultError):
        argon2id(b"password", bytes(16), Argon2Params(memory_kib=1024))
    with pytest.raises(VaultError):
        argon2id(b"password", bytes(16), Argon2Params(iterations=0))


def test_argon2id_wipes_its_output_when_derivation_fails(monkeypatch):
    made = []
    real = crypto.SecureBuffer

    class Recording(real):  # type: ignore[misc, valid-type]
        __slots__ = ()

        def __init__(self, size):
            super().__init__(size)
            made.append(self)

    class Broken:
        def __init__(self, **kwargs):
            pass

        def derive_into(self, key_material, buffer):
            buffer[:] = b"\xaa" * len(buffer)
            raise MemoryError("no memory for the cost that was asked")

    monkeypatch.setattr(crypto, "SecureBuffer", Recording)
    monkeypatch.setattr(crypto, "Argon2id", Broken)
    with pytest.raises(VaultError, match="not enough memory to stretch the password"):
        argon2id(b"password", bytes(16), SMALL)
    assert len(made) == 1 and made[0].wiped


# -- parameters --------------------------------------------------------------


def test_default_cost_is_the_documented_one():
    assert (DEFAULT_ARGON2.memory_kib, DEFAULT_ARGON2.iterations, DEFAULT_ARGON2.lanes) == (262_144, 3, 4)
    assert DEFAULT_ARGON2.validate() is DEFAULT_ARGON2
    assert DEFAULT_ARGON2.to_dict() == {"m": 262_144, "t": 3, "p": 4}


@pytest.mark.parametrize(
    "params",
    [
        Argon2Params(memory_kib=19 * 1024),
        Argon2Params(memory_kib=19 * 1024, iterations=2, lanes=1),
        Argon2Params(memory_kib=46 * 1024, iterations=1, lanes=1),
        Argon2Params(memory_kib=4 * 1024 * 1024),
        Argon2Params(iterations=1),
        Argon2Params(iterations=64),
        Argon2Params(lanes=1),
        Argon2Params(lanes=16),
    ],
)
def test_parameters_at_the_bounds_are_accepted(params):
    assert params.validate() is params
    assert Argon2Params.from_dict(params.to_dict()) == params


@pytest.mark.parametrize(
    "changes",
    [
        {"memory_kib": 19 * 1024 - 1},
        {"memory_kib": 19 * 1024, "iterations": 1},
        {"memory_kib": 46 * 1024 - 1, "iterations": 1},
        {"memory_kib": 4 * 1024 * 1024 + 1},
        {"memory_kib": 0},
        {"memory_kib": -1},
        {"memory_kib": 2**64},
        {"iterations": 0},
        {"iterations": 65},
        {"iterations": -3},
        {"lanes": 0},
        {"lanes": 17},
        {"memory_kib": True},
        {"iterations": True},
        {"lanes": False},
        {"memory_kib": 65536.0},
        {"iterations": "3"},
        {"lanes": None},
        {"memory_kib": [65536]},
    ],
)
def test_parameters_outside_the_bounds_are_refused(changes):
    values = {"memory_kib": 65536, "iterations": 3, "lanes": 4}
    values.update(changes)
    with pytest.raises(VaultError):
        Argon2Params(**values).validate()
    with pytest.raises(VaultError):
        Argon2Params.from_dict({"m": values["memory_kib"], "t": values["iterations"], "p": values["lanes"]})


@pytest.mark.parametrize("data", [None, [], "m=1", 7, {}, {"m": 65536}, {"m": 65536, "t": 3}, {"t": 3, "p": 4}])
def test_parameters_from_a_malformed_document_are_refused(data):
    with pytest.raises(VaultError):
        Argon2Params.from_dict(data)


def test_parameters_ignore_unrelated_keys():
    assert Argon2Params.from_dict({"m": 65536, "t": 2, "p": 1, "alg": "argon2id", "salt": "x"}) == Argon2Params(
        memory_kib=65536, iterations=2, lanes=1
    )


def test_parameters_are_immutable():
    with pytest.raises(AttributeError):
        DEFAULT_ARGON2.iterations = 1  # type: ignore[misc]


@given(st.integers(), st.integers(), st.integers())
@settings(max_examples=200, deadline=None)
def test_validate_accepts_exactly_the_documented_range(memory, iterations, lanes):
    params = Argon2Params(memory_kib=memory, iterations=iterations, lanes=lanes)
    acceptable = (19 * 1024 <= memory <= 4 * 1024 * 1024 and 1 <= iterations <= 64 and 1 <= lanes <= 16
                  and (iterations >= 2 or memory >= 46 * 1024))
    if acceptable:
        assert params.validate() is params
    else:
        with pytest.raises(VaultError):
            params.validate()


def test_default_argon2_follows_the_test_override():
    assert os.environ["IRONDOME_KDF_MEMORY_MIB"] == "19"
    assert default_argon2() == Argon2Params(memory_kib=19 * 1024)


@pytest.mark.parametrize("value, expected", [("64", 64 * 1024), ("4096", 4096 * 1024), (" 32 ", 32 * 1024)])
def test_default_argon2_env_override(monkeypatch, value, expected):
    monkeypatch.setenv("IRONDOME_KDF_MEMORY_MIB", value)
    params = default_argon2()
    assert params.memory_kib == expected
    assert (params.iterations, params.lanes) == (3, 4)


@pytest.mark.parametrize("value", ["abc", "12.5", "1e3", "0x40", "18", "0", "-64", "4097", "99999999999999999999"])
def test_default_argon2_refuses_a_bad_override(monkeypatch, value):
    monkeypatch.setenv("IRONDOME_KDF_MEMORY_MIB", value)
    with pytest.raises(VaultError):
        default_argon2()


def test_default_argon2_without_an_override(monkeypatch):
    monkeypatch.delenv("IRONDOME_KDF_MEMORY_MIB")
    monkeypatch.setattr(crypto, "_physical_memory_bytes", lambda: 16 * 1024**3)
    assert default_argon2() is DEFAULT_ARGON2
    monkeypatch.setattr(crypto, "_physical_memory_bytes", lambda: None)
    assert default_argon2() is DEFAULT_ARGON2
    monkeypatch.setattr(crypto, "_physical_memory_bytes", lambda: 2 * 1024**3)
    assert default_argon2() == Argon2Params(memory_kib=64 * 1024)
    assert default_argon2().validate()
    monkeypatch.setenv("IRONDOME_KDF_MEMORY_MIB", "")
    assert default_argon2() == Argon2Params(memory_kib=64 * 1024)


def test_physical_memory_is_a_number_or_unknown():
    total = crypto._physical_memory_bytes()
    assert total is None or total > 64 * 1024**2


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------

GCM_KEY = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
GCM_PLAINTEXT = (
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
)
GCM_CIPHERTEXT = (
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
)

# AES-256 test cases 13-16 of the GCM specification (McGrew and Viega), the
# document NIST SP 800-38D standardised: (key, nonce, plaintext, aad, ciphertext, tag).
GCM_VECTORS = [
    ("00" * 32, "00" * 12, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"),
    ("00" * 32, "00" * 12, "00" * 16, "", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"),
    (GCM_KEY, "cafebabefacedbaddecaf888", GCM_PLAINTEXT, "", GCM_CIPHERTEXT, "b094dac5d93471bdec1a502270e3cc6c"),
    (
        GCM_KEY,
        "cafebabefacedbaddecaf888",
        GCM_PLAINTEXT[:120],
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        GCM_CIPHERTEXT[:120],
        "76fc6ece0f4e1768cddf8853bb2d551b",
    ),
    # 256-bit key, 96-bit nonce, 128-bit associated data, in the layout of NIST's CAVP files.
    (
        "92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b",
        "ac93a1a6145299bde902f21a",
        "2d71bcfa914e4ac045b2aa60955fad24",
        "1e0889016f67601c8ebea4943bc23ad6",
        "8995ae2e6df3dbf96fac7b7137bae67f",
        "eca5aa77d51d4a0a14d9c51e1da474ab",
    ),
]
GCM_IDS = ["case-13-empty", "case-14-one-block", "case-15-no-aad", "case-16-with-aad", "cavp-layout-with-aad"]


@pytest.mark.parametrize("key, nonce, plaintext, aad, ciphertext, tag", GCM_VECTORS, ids=GCM_IDS)
def test_open_sealed_matches_published_vectors(key, nonce, plaintext, aad, ciphertext, tag):
    blob = h(nonce) + h(ciphertext) + h(tag)  # the layout seal() produces
    opened = open_sealed(h(key), blob, h(aad))
    assert isinstance(opened, bytearray)
    assert bytes(opened) == h(plaintext)


@pytest.mark.parametrize("key, nonce, plaintext, aad, ciphertext, tag", GCM_VECTORS, ids=GCM_IDS)
def test_published_vectors_fail_under_any_other_context(key, nonce, plaintext, aad, ciphertext, tag):
    blob = h(nonce) + h(ciphertext) + h(tag)
    with pytest.raises(DecryptError):
        open_sealed(h(key), blob, h(aad) + b"\x00")
    with pytest.raises(DecryptError):
        open_sealed(bytes(31) + b"\x01", blob, h(aad))
    damaged = bytearray(blob)
    damaged[-1] ^= 0x80
    with pytest.raises(DecryptError):
        open_sealed(h(key), bytes(damaged), h(aad))


def test_seal_writes_nonce_ciphertext_tag():
    blob = seal(KEY, b"attack at dawn", b"context")
    assert isinstance(blob, bytes)
    assert len(blob) == NONCE_LEN + len(b"attack at dawn") + TAG_LEN
    nonce, body = blob[:NONCE_LEN], blob[NONCE_LEN:]
    assert AESGCM(KEY).decrypt(nonce, body, b"context") == b"attack at dawn"  # readable by the plain library
    assert b"attack at dawn" not in blob


def test_seal_never_repeats_itself():
    blobs = {seal(KEY, b"same plaintext", b"same context") for _ in range(200)}
    assert len(blobs) == 200
    assert len({blob[:NONCE_LEN] for blob in blobs}) == 200  # every nonce is fresh
    assert len({blob[NONCE_LEN:] for blob in blobs}) == 200


@given(plaintext=st.binary(max_size=2048), aad=st.binary(max_size=200), key=st.binary(min_size=32, max_size=32))
@settings(max_examples=120, deadline=None)
def test_seal_then_open_round_trips(plaintext, aad, key):
    blob = seal(key, plaintext, aad)
    assert len(blob) == NONCE_LEN + len(plaintext) + TAG_LEN
    assert bytes(open_sealed(key, blob, aad)) == plaintext


@given(
    plaintext=st.binary(min_size=1, max_size=300),
    aad=st.binary(min_size=1, max_size=60),
    data=st.data(),
)
@settings(max_examples=150, deadline=None)
def test_any_single_byte_change_is_detected(plaintext, aad, data):
    blob = seal(KEY, plaintext, aad)
    position = data.draw(st.integers(min_value=0, max_value=len(blob) - 1), label="blob position")
    flip = data.draw(st.integers(min_value=1, max_value=255), label="blob flip")
    damaged = bytearray(blob)
    damaged[position] ^= flip
    with pytest.raises(DecryptError):
        open_sealed(KEY, bytes(damaged), aad)

    aad_position = data.draw(st.integers(min_value=0, max_value=len(aad) - 1), label="aad position")
    aad_flip = data.draw(st.integers(min_value=1, max_value=255), label="aad flip")
    other_aad = bytearray(aad)
    other_aad[aad_position] ^= aad_flip
    with pytest.raises(DecryptError):
        open_sealed(KEY, blob, bytes(other_aad))

    assert bytes(open_sealed(KEY, blob, aad)) == plaintext


def test_every_byte_of_a_blob_is_authenticated():
    aad = b"irondome/v4/slot\x00" + bytes(32)
    blob = seal(KEY, b"sixteen byte key" * 2, aad)
    for position in range(len(blob)):
        damaged = bytearray(blob)
        damaged[position] ^= 0x01
        with pytest.raises(DecryptError):
            open_sealed(KEY, bytes(damaged), aad)
    for position in range(len(aad)):
        other = bytearray(aad)
        other[position] ^= 0x01
        with pytest.raises(DecryptError):
            open_sealed(KEY, blob, bytes(other))


def test_associated_data_cannot_be_shortened_extended_or_dropped():
    blob = seal(KEY, b"plaintext", b"context")
    for other in (b"", b"contex", b"context\x00", b"contextcontext", b"CONTEXT"):
        with pytest.raises(DecryptError):
            open_sealed(KEY, blob, other)


def test_a_blob_cannot_be_truncated_or_extended():
    blob = seal(KEY, b"plaintext", b"context")
    for length in range(len(blob)):
        with pytest.raises(DecryptError):
            open_sealed(KEY, blob[:length], b"context")
    with pytest.raises(DecryptError):
        open_sealed(KEY, blob + b"\x00", b"context")
    with pytest.raises(DecryptError, match="truncated"):
        open_sealed(KEY, bytes(NONCE_LEN + TAG_LEN - 1), b"context")


def test_the_wrong_key_does_not_open_anything():
    blob = seal(KEY, b"plaintext", b"context")
    for position in range(KEY_LEN):
        other = bytearray(KEY)
        other[position] ^= 0x01
        with pytest.raises(DecryptError):
            open_sealed(bytes(other), blob, b"context")


def test_decrypt_errors_do_not_describe_the_data():
    blob = seal(KEY, b"TOP-SECRET-PLAINTEXT", b"context")
    with pytest.raises(DecryptError) as caught:
        open_sealed(bytes(32), blob, b"context")
    message = str(caught.value)
    assert "TOP-SECRET" not in message and KEY.hex() not in message and blob.hex() not in message
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


@pytest.mark.parametrize("length", [0, 1, 16, 24, 31, 33, 64])
def test_only_256_bit_keys_are_accepted(length):
    with pytest.raises(ValueError, match="32-byte key"):
        seal(bytes(length), b"plaintext", b"context")
    with pytest.raises(ValueError, match="32-byte key"):
        open_sealed(bytes(length), bytes(40), b"context")


def test_keys_and_plaintext_may_live_in_locked_memory():
    with SecureBuffer.from_buffer(KEY) as key, SecureBuffer.from_buffer(b"key material....") as plaintext:
        blob = seal(key, plaintext, b"context")
        assert bytes(open_sealed(key, blob, b"context")) == b"key material...."
        assert bytes(open_sealed(KEY, blob, b"context")) == b"key material...."
        assert bytes(key.view()) == KEY


def test_empty_plaintext_and_empty_context():
    blob = seal(KEY, b"", b"")
    assert len(blob) == NONCE_LEN + TAG_LEN
    assert open_sealed(KEY, blob, b"") == bytearray()
    with pytest.raises(DecryptError):
        open_sealed(KEY, blob, b"x")


# -- open_sealed_into --------------------------------------------------------


def test_open_sealed_into_writes_straight_into_locked_memory():
    with SecureBuffer.random(32) as inner:
        blob = seal(KEY, inner, b"slot")
        with SecureBuffer(32) as out:
            assert open_sealed_into(KEY, blob, b"slot", out) is None
            assert bytes(out.view()) == bytes(inner.view())


@pytest.mark.parametrize("size", [1, 16, 31, 33, 64])
def test_open_sealed_into_needs_a_buffer_of_exactly_the_right_size(size):
    blob = seal(KEY, bytes(32), b"slot")
    with SecureBuffer(size) as out:
        with pytest.raises(DecryptError, match="wrong length"):
            open_sealed_into(KEY, blob, b"slot", out)
        assert bytes(out.view()) == bytes(size)


def test_open_sealed_into_refuses_a_truncated_blob():
    with SecureBuffer(32) as out, pytest.raises(DecryptError, match="truncated"):
        open_sealed_into(KEY, bytes(27), b"slot", out)


@pytest.mark.parametrize("failure", ["aad", "key", "tag", "ciphertext", "nonce"])
def test_open_sealed_into_leaves_nothing_behind_when_it_fails(failure):
    """The cipher writes before it verifies. After a failure the buffer must not hold the plaintext."""
    with SecureBuffer.random(32) as inner:
        secret = bytes(inner.view())
        blob = bytearray(seal(KEY, inner, b"slot"))
    key, aad = bytearray(KEY), b"slot"
    if failure == "aad":
        aad = b"slot of another vault"
    elif failure == "key":
        key[0] ^= 1
    elif failure == "tag":
        blob[-1] ^= 1
    elif failure == "ciphertext":
        blob[NONCE_LEN] ^= 1
    else:
        blob[0] ^= 1
    with SecureBuffer(32) as out:
        out.view()[:] = b"\x55" * 32
        with pytest.raises(DecryptError):
            open_sealed_into(bytes(key), bytes(blob), aad, out)
        assert bytes(out.view()) == bytes(32)
        assert bytes(out.view()) != secret


def test_open_sealed_wipes_its_result_when_it_fails(monkeypatch):
    seen = []
    real_wipe = crypto.wipe_bytes

    def recording_wipe(obj):
        seen.append(bytes(obj))
        return real_wipe(obj)

    monkeypatch.setattr(crypto, "wipe_bytes", recording_wipe)
    blob = seal(KEY, b"PLAINTEXT-PLAINTEXT", b"right")
    with pytest.raises(DecryptError):
        open_sealed(KEY, blob, b"wrong")
    assert len(seen) == 1 and len(seen[0]) == len(b"PLAINTEXT-PLAINTEXT")


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------


@given(data=st.binary(max_size=3000), block=st.sampled_from([16, 64, 256, 1024]))
@settings(max_examples=200, deadline=None)
def test_pad_then_unpad_round_trips_and_aligns(data, block):
    padded = pad(data, block)
    assert isinstance(padded, bytearray)
    assert len(padded) % block == 0
    assert len(padded) >= len(data) + 4
    assert len(padded) - (len(data) + 4) < block  # never a whole block of waste
    assert int.from_bytes(padded[:4], "big") == len(data)
    assert bytes(padded[4 + len(data) :]) == bytes(len(padded) - 4 - len(data))  # zero filled
    unpadded = unpad(padded)
    assert isinstance(unpadded, bytearray) and bytes(unpadded) == data


def test_padding_hides_length_within_a_block():
    sizes = {len(pad(b"x" * length, 256)) for length in range(0, 253)}
    assert sizes == {256}
    assert len(pad(b"x" * 253, 256)) == 512  # 253 + 4 no longer fits one block
    assert len(pad(b"", 256)) == 256


def test_pad_accepts_locked_memory_and_returns_a_copy():
    with SecureBuffer.from_buffer(b"key material") as locked:
        padded = pad(locked, 64)
        assert bytes(unpad(padded)) == b"key material"
        padded[4] = 0
        assert bytes(locked.view()) == b"key material"


def test_unpad_returns_a_copy():
    padded = pad(b"abcdef", 16)
    plain = unpad(padded)
    plain[0] = 0
    assert bytes(unpad(padded)) == b"abcdef"


@pytest.mark.parametrize("data", [b"", b"\x00", b"\x00\x00", b"\x00\x00\x00"])
def test_unpad_refuses_data_too_short_for_a_length(data):
    with pytest.raises(VaultError, match="too short"):
        unpad(data)


@pytest.mark.parametrize(
    "data",
    [
        (1).to_bytes(4, "big"),
        (5).to_bytes(4, "big") + b"abcd",
        (2**32 - 1).to_bytes(4, "big") + bytes(252),
        (253).to_bytes(4, "big") + bytes(252),
        b"\xff\xff\xff\xff",
    ],
)
def test_unpad_refuses_a_length_that_does_not_fit(data):
    with pytest.raises(VaultError, match="inconsistent"):
        unpad(data)


def test_unpad_takes_exactly_the_stated_length():
    assert bytes(unpad((0).to_bytes(4, "big"))) == b""
    assert bytes(unpad((3).to_bytes(4, "big") + b"abcdef")) == b"abc"
    assert bytes(unpad((252).to_bytes(4, "big") + b"y" * 252)) == b"y" * 252


@given(st.binary(max_size=600))
@settings(max_examples=300, deadline=None)
def test_unpad_on_arbitrary_bytes_returns_data_or_raises_vault_error(data):
    try:
        result = unpad(data)
    except VaultError:
        return
    assert len(result) == int.from_bytes(data[:4], "big") <= len(data) - 4


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------


@given(st.binary(max_size=500))
@settings(max_examples=200, deadline=None)
def test_base64_round_trips(data):
    text = b64e(data)
    assert isinstance(text, str) and text.isascii()
    assert text == base64.b64encode(data).decode("ascii")
    assert b64d(text) == data


def test_b64e_reads_locked_memory():
    with SecureBuffer.from_buffer(b"\x00\x01\x02\xff") as locked:
        assert b64e(locked) == "AAEC/w=="


@pytest.mark.parametrize(
    "value",
    [None, 5, 5.0, b"QUJD", bytearray(b"QUJD"), ["QUJD"], {"a": 1}, True],
    ids=["none", "int", "float", "bytes", "bytearray", "list", "dict", "bool"],
)
def test_b64d_refuses_anything_that_is_not_text(value):
    with pytest.raises(VaultError, match="not a base64 string"):
        b64d(value)


@pytest.mark.parametrize(
    "text",
    [
        "QUJ",  # missing padding
        "QUJD=",  # padding where none belongs
        "QUJD==",
        "QR==",  # unused bits that are not zero: decodes to the same byte as "QQ=="
        "QUJ=",
        "Q",  # too short to mean anything
        "QUJD QUJD",  # whitespace
        "QUJD\n",  # trailing newline
        "\nQUJD",
        "QUJD\x00",
        "QU-D",  # URL-safe alphabet
        "QU_D",
        "QUJD!!",
        "=QUJD",  # padding first
        "QUJD=QUJ",  # data after padding
        "QUJD\xe9",  # not ASCII
        "QUJD\u200b",  # zero-width space
        "\uff31\uff35\uff2a\uff24",  # full-width letters
    ],
)
def test_b64d_is_strict(text):
    with pytest.raises(VaultError, match="not valid base64"):
        b64d(text)


def test_b64d_accepts_canonical_text():
    assert b64d("") == b""
    assert b64d("QUJD") == b"ABC"
    assert b64d("QUI=") == b"AB"
    assert b64d("QQ==") == b"A"
    assert b64d("+/+/") == b"\xfb\xff\xbf"


def test_b64d_names_what_it_was_reading():
    with pytest.raises(VaultError, match="keyslot wrap is not valid base64"):
        b64d("!!", what="keyslot wrap")
    with pytest.raises(VaultError, match="vault id is not a base64 string"):
        b64d(None, what="vault id")


@given(st.text(max_size=80))
@settings(max_examples=300, deadline=None)
def test_b64d_on_arbitrary_text_decodes_or_raises_vault_error(text):
    try:
        decoded = b64d(text)
    except VaultError:
        return
    assume(text.isascii())
    assert base64.b64decode(text) == decoded
    assert b64e(decoded) == text  # only the canonical spelling gets through


# ---------------------------------------------------------------------------
# Randomness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("length", [0, 1, 12, 16, 32, 1000])
def test_random_bytes(length):
    first, second = random_bytes(length), random_bytes(length)
    assert isinstance(first, bytes) and len(first) == len(second) == length
    if length >= 12:
        assert first != second


def test_where_argon2id_runs_in_this_process_it_is_run_again_on_zeros_even_when_the_derivation_fails(monkeypatch):
    """The library copies the password before it can fail (too little memory for the cost): the second run,
    which gets that copy overwritten, follows a failed derivation too, and its own failure changes nothing."""
    from irondome import crypto
    from irondome.secmem import SecureBuffer

    made = []

    class Fake:
        def __init__(self, **settings):
            self.settings = settings
            made.append(self)

        def derive_into(self, material, buffer):
            self.material = bytes(material)
            if len(made) == 1:
                raise MemoryError("not enough memory for this cost")
            raise RuntimeError("the second run fails as well")

    monkeypatch.setattr(crypto, "Argon2id", Fake)
    monkeypatch.setattr(crypto, "_stretch_in_child", lambda *arguments: False)  # this is about the run made here
    salt = bytes(range(16))
    with SecureBuffer.from_buffer(b"a test password") as password:
        with pytest.raises(VaultError, match="not enough memory to stretch the password"):
            crypto.argon2id(password, salt, crypto.Argon2Params(memory_kib=19 * 1024))
    first, second = made
    assert first.material == b"a test password" and first.settings["salt"] == salt
    assert second.material == bytes(len(b"a test password")) and second.settings["salt"] == bytes(16)
    assert second.settings["iterations"] == 1 and second.settings["memory_cost"] == 8 * second.settings["lanes"]


# ---- Argon2id in a child process: the copy the library leaves of its input ends with the child ------------

needs_fork = pytest.mark.skipif(not hasattr(os, "fork"), reason="there is no fork on this system")


def _open_descriptors() -> int:
    count = 0
    for descriptor in range(256):
        try:
            os.fstat(descriptor)
            count += 1
        except OSError:
            pass
    return count


def _no_child_is_left() -> bool:
    try:
        os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        return True
    return False


@pytest.fixture
def stretched_here(monkeypatch):
    """What the derivation gives when it is made in this process, and proof that the next one is not."""
    salt, password = bytes(range(16)), b"correct horse battery staple"
    expected = Argon2id(salt=salt, length=32, iterations=2, lanes=1, memory_cost=19 * 1024).derive(password)
    here = []
    real = crypto._stretch_here
    monkeypatch.setattr(crypto, "_stretch_here", lambda *arguments: (here.append(1), real(*arguments))[1])
    return salt, password, expected, here


@needs_fork
def test_argon2id_runs_in_a_child_and_the_key_is_the_one_argon2id_gives(monkeypatch, stretched_here):
    salt, password, expected, here = stretched_here
    before = _open_descriptors()
    runs = []
    real = crypto._derive
    monkeypatch.setattr(crypto, "_derive", lambda *arguments: (runs.append(os.getpid()), real(*arguments))[1])

    with SecureBuffer.from_buffer(password) as locked, argon2id(locked, salt, SMALL) as key:
        assert bytes(key.view()) == expected

    assert runs == [] and here == []  # Argon2id ran, and not in this process: a child's list is its own
    assert _open_descriptors() == before and _no_child_is_left()


@needs_fork
@pytest.mark.parametrize("length", [1, 32, 511, 513, 4096, 70_000])
def test_a_password_of_any_length_reaches_the_child_whole(length):
    """Longer than a pipe takes in one write, longer than a pipe holds: the child still stretches all of it."""
    password = bytes((index * 7 + 3) % 251 for index in range(length))
    salt = bytes(range(16, 32))
    expected = Argon2id(salt=salt, length=32, iterations=2, lanes=1, memory_cost=19 * 1024).derive(password)

    with SecureBuffer.from_buffer(password) as locked, argon2id(locked, salt, SMALL) as key:
        assert bytes(key.view()) == expected
    assert _no_child_is_left()


@needs_fork
def test_with_another_thread_running_argon2id_runs_here_and_gives_the_same_key(stretched_here):
    import threading

    salt, password, expected, here = stretched_here
    release = threading.Event()
    other = threading.Thread(target=release.wait, daemon=True)
    other.start()
    try:
        with argon2id(password, salt, SMALL) as key:
            assert bytes(key.view()) == expected
    finally:
        release.set()
        other.join()
    assert here == [1]


@needs_fork
def test_when_neither_a_process_nor_a_thread_can_be_started_the_limit_is_named_not_memory(monkeypatch):
    """At the account's process limit the fork is refused and then Argon2id's own threads are too. A by-hand
    trial got "not enough memory ... Free some memory" there, with 1.5 GiB free."""
    def refused(*arguments):
        raise OSError(35, "Resource temporarily unavailable")

    def no_threads(*arguments):
        raise crypto._no_memory(SMALL)

    monkeypatch.setattr(crypto, "_stretch_here", no_threads)
    with pytest.raises(VaultError, match="not enough memory"):  # no fork was tried: memory is the likely cause
        monkeypatch.setattr(crypto, "_stretch_in_child", lambda *arguments: False)
        argon2id(b"correct horse battery staple", bytes(16), SMALL)
    monkeypatch.undo()
    monkeypatch.setattr(crypto, "_stretch_here", no_threads)
    monkeypatch.setattr(os, "fork", refused)
    with pytest.raises(VaultError, match="ulimit -u") as caught:
        argon2id(b"correct horse battery staple", bytes(16), SMALL)
    assert "Resource temporarily unavailable" in str(caught.value)
    assert "not enough memory" not in str(caught.value) and "not a lack of memory" in str(caught.value)


@needs_fork
@pytest.mark.parametrize("failing", ["fork", "pipe"])
def test_where_the_system_refuses_a_child_argon2id_runs_here_and_no_descriptor_is_left_open(
    monkeypatch, stretched_here, failing
):
    salt, password, expected, here = stretched_here
    before = _open_descriptors()
    made = []
    real_pipe = os.pipe

    def refused(*arguments):
        raise OSError(35, "Resource temporarily unavailable")

    def second_pipe_refused():
        if made:
            refused()
        made.append(real_pipe())
        return made[-1]

    if failing == "fork":
        monkeypatch.setattr(os, "fork", refused)
    else:
        monkeypatch.setattr(os, "pipe", second_pipe_refused)

    with argon2id(password, salt, SMALL) as key:
        assert bytes(key.view()) == expected
    monkeypatch.undo()
    assert here == [1] and _open_descriptors() == before


def _child_that(action):
    """A stand-in for the derivation that runs only in the child (the parent never calls it)."""

    def derive(kdf, view, out):
        action()

    return derive


@needs_fork
@pytest.mark.parametrize(
    ("what", "message"),
    [
        ("memory", "not enough memory to stretch the password: Argon2id is set to use 19 MiB"),
        ("killed", "not enough memory to stretch the password"),  # what the kernel does to a process it cannot feed
        ("terminated", "the process running Argon2id was ended by signal 15"),
        ("error", "the process running Argon2id ended with status 4"),
        ("exit", "the process running Argon2id ended with status 4"),
    ],
)
def test_a_child_that_does_not_finish_is_reported_and_no_key_is_returned(monkeypatch, what, message):
    import signal

    def memory():
        raise MemoryError

    def error():
        raise RuntimeError("something in the library")

    def leave():
        raise SystemExit(0)  # even this is not taken for success: no key was sent

    actions = {
        "memory": memory,
        "killed": lambda: os.kill(os.getpid(), signal.SIGKILL),
        "terminated": lambda: (signal.signal(signal.SIGTERM, signal.SIG_DFL), os.kill(os.getpid(), signal.SIGTERM)),
        "error": error,
        "exit": leave,
    }
    before = _open_descriptors()
    wiped = []
    real_wipe = SecureBuffer.wipe
    monkeypatch.setattr(SecureBuffer, "wipe", lambda self: (wiped.append(len(self)), real_wipe(self))[1])
    monkeypatch.setattr(crypto, "_derive", _child_that(actions[what]))

    with pytest.raises(VaultError, match=message):
        argon2id(b"correct horse battery staple", bytes(16), SMALL)

    monkeypatch.undo()
    assert 32 in wiped  # the buffer the key would have been in
    assert _open_descriptors() == before and _no_child_is_left()


@needs_fork
def test_a_child_that_sends_only_part_of_a_key_is_not_believed(monkeypatch):
    real_write = os.write

    def half(kdf, view, out):
        # Runs in the child only, so the os.write replaced here is the child's own.
        os.write = lambda descriptor, data: real_write(descriptor, bytes(data)[:16])  # type: ignore[assignment]

    monkeypatch.setattr(crypto, "_derive", half)

    with pytest.raises(VaultError, match="the password was not stretched: the process running Argon2id ended"):
        argon2id(b"correct horse battery staple", bytes(16), SMALL)
    assert os.write is real_write and _no_child_is_left()


@needs_fork
def test_an_interrupt_while_the_child_works_ends_the_child_and_leaves_nothing_open(monkeypatch, tmp_path):
    import time

    before = _open_descriptors()
    parent = os.getpid()
    alive = tmp_path / "child"

    def working(kdf, view, out):
        alive.write_text(str(os.getpid()))
        time.sleep(120)

    real_read = crypto._read_exactly

    def interrupted(descriptor, target):
        if os.getpid() != parent:
            return real_read(descriptor, target)  # the child reads the password as it always does
        while not alive.exists():
            time.sleep(0.01)
        raise KeyboardInterrupt  # Ctrl-C while the parent waits for the key

    monkeypatch.setattr(crypto, "_derive", working)
    monkeypatch.setattr(crypto, "_read_exactly", interrupted)
    started = time.monotonic()

    with pytest.raises(KeyboardInterrupt):
        argon2id(b"correct horse battery staple", bytes(16), SMALL)

    monkeypatch.undo()
    assert time.monotonic() - started < 60
    with pytest.raises(ProcessLookupError):
        os.kill(int(alive.read_text()), 0)  # the child was ended and reaped, not left to finish
    assert _open_descriptors() == before and _no_child_is_left()


@needs_fork
def test_a_library_that_cannot_do_argon2id_says_so_in_this_process_before_any_child_is_made(monkeypatch):
    forked = []
    real_fork = os.fork

    class Unsupported(Exception):
        pass

    def refusing(**settings):
        raise Unsupported("this build of the library has no Argon2id")

    monkeypatch.setattr(os, "fork", lambda: (forked.append(1), real_fork())[1])
    monkeypatch.setattr(crypto, "Argon2id", refusing)

    with pytest.raises(Unsupported, match="has no Argon2id"):
        argon2id(b"correct horse battery staple", bytes(16), SMALL)
    assert forked == []


# ---------------------------------------------------------------------------
# What a change of one line would have got past the tests above
#
# Each test here was written because a line of crypto.py could be changed, or
# removed, with every other test still passing.
# ---------------------------------------------------------------------------


def test_argon2id_memory_must_cover_its_lanes_wherever_the_floor_would_allow_less(monkeypatch):
    """Argon2 needs 8 KiB a lane. Today's floor of 19 MiB always covers 16 lanes: the rule must not depend on it."""
    monkeypatch.setattr(crypto, "_MIN_MEMORY_KIB", 8)
    assert Argon2Params(memory_kib=8 * 4, iterations=3, lanes=4).validate()
    with pytest.raises(VaultError, match="too small for its lane count"):
        Argon2Params(memory_kib=8 * 4 - 1, iterations=3, lanes=4).validate()


def test_a_single_pass_below_the_owasp_minimum_is_refused_and_the_message_names_46_mib():
    assert Argon2Params(memory_kib=46 * 1024, iterations=1, lanes=1).validate()
    with pytest.raises(VaultError, match="single pass needs at least 46 MiB"):
        Argon2Params(memory_kib=46 * 1024 - 1, iterations=1, lanes=1).validate()


def test_the_smaller_default_is_for_machines_with_less_than_three_gibibytes_exactly(monkeypatch):
    monkeypatch.delenv("IRONDOME_KDF_MEMORY_MIB")
    monkeypatch.setattr(crypto, "_physical_memory_bytes", lambda: 3 * 1024**3)
    assert default_argon2() is DEFAULT_ARGON2
    monkeypatch.setattr(crypto, "_physical_memory_bytes", lambda: 3 * 1024**3 - 1)
    assert default_argon2() == Argon2Params(memory_kib=64 * 1024)


class _RecordedHKDF:
    """Stands in for the library's HKDF: records what each derivation was given, and can fail on one of them."""

    runs: list = []
    fail_on: Optional[int] = None

    def __init__(self, **settings):
        self.settings = settings

    def derive_into(self, key_material, out):
        type(self).runs.append((bytes(key_material), self.settings, out))
        out[:] = b"\x55" * len(out)
        if type(self).fail_on == len(type(self).runs):
            raise MemoryError


@pytest.fixture
def recorded_hkdf(monkeypatch):
    _RecordedHKDF.runs, _RecordedHKDF.fail_on = [], None
    monkeypatch.setattr(crypto, "HKDF", _RecordedHKDF)
    return _RecordedHKDF


def test_hkdf_is_run_a_second_time_on_zeros_with_the_same_settings_and_not_into_the_key(recorded_hkdf):
    with hkdf(b"\x07" * 32, info=b"purpose", salt=b"salt", length=48) as key:
        (first, settings, into), (second, again, scratch) = recorded_hkdf.runs
        assert first == b"\x07" * 32 and second == bytes(32)
        assert settings["length"] == again["length"] == 48
        assert settings["salt"] == again["salt"] == b"salt" and settings["info"] == again["info"] == b"purpose"
        assert into.obj is not scratch and len(scratch) == 48 and len(key) == 48


@pytest.mark.parametrize("failing_run", [1, 2])
def test_hkdf_that_fails_in_either_run_wipes_the_key_it_was_writing(monkeypatch, recorded_hkdf, failing_run):
    wiped = []

    class Watched(SecureBuffer):
        def wipe(self):
            wiped.append(self)
            super().wipe()

    monkeypatch.setattr(crypto, "SecureBuffer", Watched)
    recorded_hkdf.fail_on = failing_run
    with pytest.raises(MemoryError) as raised:
        hkdf(b"\x07" * 32, info=b"purpose", length=32)
    assert len(recorded_hkdf.runs) == failing_run
    # While the failure is still held, and with it the frame the key was in: wiped by hkdf itself,
    # not whenever the last reference to the buffer happens to go.
    assert raised.value is not None and len(wiped) == 1 and wiped[0].wiped


class _CipherThatFailsAfterWriting:
    """Writes a plaintext into the output, as the real cipher does before it checks, then fails some other way."""

    def __init__(self, failure):
        self.failure = failure

    def decrypt_into(self, nonce, body, aad, out):
        out[:] = b"\x55" * len(out)
        raise self.failure


@pytest.mark.parametrize("failure", [MemoryError(), KeyboardInterrupt(), RuntimeError("the library broke")])
def test_open_sealed_that_fails_for_another_reason_than_the_tag_wipes_its_output_and_says_so(monkeypatch, failure):
    wiped = []
    real_wipe = crypto.wipe_bytes
    monkeypatch.setattr(crypto, "wipe_bytes", lambda out: (wiped.append(out), real_wipe(out))[1])
    blob = seal(KEY, b"PLAINTEXT-PLAINTEXT", b"aad")
    monkeypatch.setattr(crypto, "_cipher", lambda key: _CipherThatFailsAfterWriting(failure))

    with pytest.raises(type(failure)) as raised:
        open_sealed(KEY, blob, b"aad")

    assert raised.value is failure  # the same failure, not a "wrong key" in its place
    assert len(wiped) == 1 and bytes(wiped[0]) == bytes(len(b"PLAINTEXT-PLAINTEXT"))


@pytest.mark.parametrize("failure", [MemoryError(), KeyboardInterrupt(), RuntimeError("the library broke")])
def test_open_sealed_into_that_fails_for_another_reason_than_the_tag_zeroes_the_buffer_and_says_so(
    monkeypatch, failure
):
    with SecureBuffer.random(32) as inner:
        blob = seal(KEY, inner, b"slot")
    monkeypatch.setattr(crypto, "_cipher", lambda key: _CipherThatFailsAfterWriting(failure))

    with SecureBuffer(32) as out:
        with pytest.raises(type(failure)) as raised:
            open_sealed_into(KEY, blob, b"slot", out)
        assert raised.value is failure
        assert bytes(out.view()) == bytes(32)


@needs_fork
def test_on_a_system_without_readv_argon2id_runs_here(monkeypatch, stretched_here):
    """The key is read from the child with readv, straight into locked memory. Without it there is no child."""
    salt, password, expected, here = stretched_here
    monkeypatch.delattr(os, "readv")
    with argon2id(password, salt, SMALL) as key:
        assert bytes(key.view()) == expected
    assert here == [1]


@needs_fork
def test_a_child_that_finished_is_never_sent_a_signal(monkeypatch):
    """Its process id is free once it is reaped: a signal sent then could reach an unrelated process."""
    sent = []
    real_kill = os.kill
    parent = os.getpid()

    def recording_kill(pid, signum):
        if os.getpid() == parent:
            sent.append((pid, signum))
        return real_kill(pid, signum)

    monkeypatch.setattr(os, "kill", recording_kill)
    with argon2id(b"correct horse battery staple", bytes(16), SMALL):
        pass
    assert sent == []


@needs_fork
def test_if_irondome_is_killed_while_it_sends_the_password_the_child_ends_too(tmp_path):
    """The child must not wait for ever, with part of the input in its memory, for a parent that is gone."""
    import signal
    import subprocess
    import sys
    import time

    script = (
        "import os, signal\n"
        "from irondome import crypto\n"
        "parent = os.getpid()\n"
        "real = os.write\n"
        "def write(descriptor, data):\n"
        "    if os.getpid() == parent and descriptor > 2:\n"
        "        os.kill(parent, signal.SIGKILL)\n"
        "    return real(descriptor, data)\n"
        "os.write = write\n"
        "crypto.argon2id(b'correct horse battery staple', bytes(16),\n"
        "                crypto.Argon2Params(memory_kib=19 * 1024, iterations=2, lanes=1))\n"
    )
    process = subprocess.Popen([sys.executable, "-c", script], start_new_session=True,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert process.wait(timeout=60) == -signal.SIGKILL  # it was killed before a byte was sent
        deadline = time.monotonic() + 30
        while True:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break  # nothing is left of its process group: the child has ended
            except PermissionError:
                pass
            assert time.monotonic() < deadline, "the child is still waiting for a parent that was killed"
            time.sleep(0.05)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
