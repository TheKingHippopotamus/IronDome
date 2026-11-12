"""Time-based one-time passwords (TOTP, RFC 6238).

An entry can carry the settings a site hands out when two-factor
authentication is switched on. They live in the entry's encrypted secret
record as a plain dict::

    {"secret": "JBSWY3DPEHPK3PXP",     base32, upper case, no padding
     "algorithm": "SHA1",              or "SHA256", "SHA512"
     "digits": 6,                      or 7, 8
     "period": 30,                     seconds, 1 to 300
     "issuer": "Example",              free text, may be empty
     "account": "alice@example.com"}   free text, may be empty

:func:`make_totp` and :func:`parse_otpauth` build that dict from what a
person types or scans, :func:`validate` checks one that was read from disk,
and :func:`code_at` computes a code: HOTP (RFC 4226) over the number of whole
periods since 1970, using HMAC from the standard library.

A grant handed to an agent must not hold the secret, because the secret
produces codes forever. :func:`codes_for_window` computes the codes for a
span of time in advance and :func:`code_from_window` picks the current one
out of that table, so a grant can carry codes that stop working when it
expires and nothing else.

Limits: only time-based codes are handled (no counter-based HOTP, no Steam
variant), and a code is only as right as the system clock. While a code is
computed the decoded secret sits in locked memory that is wiped afterwards;
the base32 text of the secret is part of the decrypted entry and stays an
ordinary string for as long as the caller keeps that entry.
"""

from __future__ import annotations

import hmac
import math
import struct
import time
from typing import Any, Dict, Mapping, Optional, Tuple, Type, Union
from urllib.parse import parse_qsl, quote, unquote

from irondome.errors import AuthError, IronDomeError, UsageError, VaultError
from irondome.secmem import SecureBuffer, wipe_bytes

__all__ = [
    "ALGORITHMS",
    "DIGITS",
    "MIN_PERIOD",
    "MAX_PERIOD",
    "MIN_SECRET_BYTES",
    "MAX_SECRET_BYTES",
    "MAX_WINDOW_CODES",
    "MAX_DRIFT",
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
    "verify",
]

ALGORITHMS = ("SHA1", "SHA256", "SHA512")
DIGITS = (6, 7, 8)
MIN_PERIOD = 1
MAX_PERIOD = 300
#: 80 bits, the shortest secret in real use (16 base32 characters).
MIN_SECRET_BYTES = 10
MAX_SECRET_BYTES = 256
#: The most codes one table may hold (about 41 hours of 30-second codes).
MAX_WINDOW_CODES = 5000
#: The most time steps either side of now that :func:`verify` will look at.
MAX_DRIFT = 10

Number = Union[int, float]

_FIELDS = ("secret", "algorithm", "digits", "period", "issuer", "account")
_DIGESTS = {"SHA1": "sha1", "SHA256": "sha256", "SHA512": "sha512"}
_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_BASE32_VALUE = {char: value for value, char in enumerate(_BASE32)}
_MAX_SECRET_CHARS = (MAX_SECRET_BYTES * 8 + 4) // 5
_MAX_SECRET_INPUT = 4 * _MAX_SECRET_CHARS  # room for the spaces and dashes people paste
_MAX_LABEL = 255
_MAX_LABEL_INPUT = 4096
_MAX_URI = 16384  # above the longest link to_otpauth can write: about 9700 characters
_MAX_URI_FIELDS = 32
_MAX_COUNTER = 2**64 - 1  # RFC 4226 feeds the counter to HMAC as eight bytes
_URI_PARAMETERS = ("secret", "issuer", "algorithm", "digits", "period")

_NOT_BASE32 = "the one-time-password secret is not base32: it may only hold the letters A-Z and the digits 2-7"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


def _secret_size(text: str, error: Type[IronDomeError]) -> int:
    """Check upper-case, unpadded base32 and return how many bytes it encodes."""
    if not text:
        raise error("the one-time-password secret is empty")
    if len(text) > _MAX_SECRET_CHARS:
        raise error(f"the one-time-password secret is too long (at most {MAX_SECRET_BYTES} bytes)")
    if any(char not in _BASE32_VALUE for char in text):
        raise error(_NOT_BASE32)
    if len(text) % 8 in (1, 3, 6):
        raise error("the one-time-password secret is not valid base32: a character is missing or one too many")
    size = len(text) * 5 // 8
    if size < MIN_SECRET_BYTES:
        raise error(
            f"the one-time-password secret is too short: it must hold at least {MIN_SECRET_BYTES} bytes (16 characters)"
        )
    return size


def normalise_secret(text: str) -> str:
    """Turn a secret as people paste it into canonical base32.

    Lower case, spaces, dashes and ``=`` padding at the end are accepted.
    The result is upper case without padding, with the unused bits of the
    last character set to zero, so the same key always has the same text.
    Characters that merely look like base32 (``0``, ``1``, ``8``, ``9``) are
    refused, not guessed at: a wrong guess would produce wrong codes.
    """
    if not isinstance(text, str):
        raise UsageError("a one-time-password secret must be text")
    if len(text) > _MAX_SECRET_INPUT:
        raise UsageError("that one-time-password secret is too long")
    compact = "".join(char for char in text if not char.isspace() and char != "-")
    if not compact.isascii():
        raise UsageError(_NOT_BASE32)
    compact = compact.upper().rstrip("=")
    size = _secret_size(compact, UsageError)
    spare = len(compact) * 5 - size * 8
    if spare:
        compact = compact[:-1] + _BASE32[_BASE32_VALUE[compact[-1]] >> spare << spare]
    return compact


def _clean_algorithm(algorithm: Any) -> str:
    """Accept the spellings in circulation: ``sha1``, ``SHA-256``, ``HmacSHA512``."""
    if isinstance(algorithm, str) and algorithm.isascii():
        name = algorithm.strip().upper().replace("-", "")
        if name.startswith("HMAC"):
            name = name[4:]
        if name in ALGORITHMS:
            return name
    raise UsageError("unsupported one-time-password algorithm: IronDome handles SHA1, SHA256 and SHA512")


def _clean_label(value: Any, what: str) -> str:
    """Tidy an issuer, account name or label: one space between words, nothing unprintable."""
    if not isinstance(value, str):
        raise UsageError(f"the one-time-password {what} must be text")
    if len(value) > _MAX_LABEL_INPUT:
        raise UsageError(f"the one-time-password {what} is too long (at most {_MAX_LABEL} characters)")
    cleaned = " ".join("".join(char for char in value if char.isprintable() or char.isspace()).split())
    if len(cleaned) > _MAX_LABEL:
        raise UsageError(f"the one-time-password {what} is too long (at most {_MAX_LABEL} characters)")
    return cleaned


def _checked(totp: Any, error: Type[IronDomeError]) -> Dict[str, Any]:
    """The one definition of a well-formed settings dict."""
    if not isinstance(totp, dict):
        raise error("one-time-password settings are malformed")
    for name in _FIELDS:
        if name not in totp:
            raise error(f"one-time-password settings are missing their {name}")
    if len(totp) != len(_FIELDS):
        raise error(
            "one-time-password settings hold a field this version of IronDome does not know; "
            "upgrade IronDome to use them"
        )
    secret = totp["secret"]
    if not isinstance(secret, str):
        raise error("the one-time-password secret is not text")
    size = _secret_size(secret, error)
    spare = len(secret) * 5 - size * 8
    if _BASE32_VALUE[secret[-1]] & ((1 << spare) - 1):
        raise error("the one-time-password secret is not in canonical base32")
    algorithm = totp["algorithm"]
    if not isinstance(algorithm, str) or algorithm not in ALGORITHMS:
        raise error("the one-time-password algorithm must be SHA1, SHA256 or SHA512")
    digits = totp["digits"]
    if isinstance(digits, bool) or not isinstance(digits, int) or digits not in DIGITS:
        raise error("one-time passwords have 6, 7 or 8 digits")
    period = totp["period"]
    if isinstance(period, bool) or not isinstance(period, int) or not MIN_PERIOD <= period <= MAX_PERIOD:
        raise error(f"the one-time-password period must be a whole number of seconds from {MIN_PERIOD} to {MAX_PERIOD}")
    for name, what in (("issuer", "issuer"), ("account", "account name")):
        value = totp[name]
        if not isinstance(value, str):
            raise error(f"the one-time-password {what} is not text")
        if len(value) > _MAX_LABEL:
            raise error(f"the one-time-password {what} is too long (at most {_MAX_LABEL} characters)")
        if not value.isprintable() or value != " ".join(value.split()):
            raise error(f"the one-time-password {what} holds characters that cannot be displayed")
    return {
        "secret": secret,
        "algorithm": algorithm,
        "digits": int(digits),
        "period": int(period),
        "issuer": totp["issuer"],
        "account": totp["account"],
    }


def validate(totp: Any) -> Dict[str, Any]:
    """Check settings read from disk and return them as a fresh dict.

    Strict: exactly the six documented fields, each of the right type and
    within range, and the secret in canonical form. Anything else raises
    :class:`VaultError`; no input makes it raise something else.
    """
    return _checked(totp, VaultError)


def make_totp(
    secret: str,
    *,
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30,
    issuer: str = "",
    account: str = "",
) -> Dict[str, Any]:
    """Build validated settings from what a person entered.

    The secret goes through :func:`normalise_secret`; the algorithm may be
    written in any case and with a dash (``sha-256``); issuer and account
    lose unprintable characters and surplus whitespace. Raises
    :class:`UsageError` for anything that cannot be used.
    """
    return _checked(
        {
            "secret": normalise_secret(secret),
            "algorithm": _clean_algorithm(algorithm),
            "digits": digits,
            "period": period,
            "issuer": _clean_label(issuer, "issuer"),
            "account": _clean_label(account, "account name"),
        },
        UsageError,
    )


# ---------------------------------------------------------------------------
# otpauth:// links
# ---------------------------------------------------------------------------


def _unquote_label(text: str) -> str:
    try:
        return unquote(text, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        raise UsageError("that otpauth link has a label that is not valid UTF-8") from None


def _split_label(raw: str) -> Tuple[str, str]:
    """Split a link's label into ``(issuer prefix, account name)``.

    The format allows the separating colon to be written as ``:`` or as
    ``%3A``. A literal colon is looked for first, so that a colon inside a
    name, which :func:`to_otpauth` always writes as ``%3A``, is not taken
    for the separator.
    """
    if ":" in raw:
        prefix, _, account = raw.partition(":")
    else:
        cuts = [cut for cut in (raw.find("%3A"), raw.find("%3a")) if cut >= 0]
        prefix, account = (raw[: min(cuts)], raw[min(cuts) + 3 :]) if cuts else ("", raw)
    return _unquote_label(prefix), _unquote_label(account)


def _small_number(text: str, what: str) -> int:
    if not text.isascii() or not text.isdigit() or len(text) > 4:
        raise UsageError(f"that otpauth link has a {what} value that is not a small whole number")
    return int(text)


def parse_otpauth(uri: str) -> Dict[str, Any]:
    """Read an ``otpauth://totp/...`` link, the text inside a setup QR code.

    This is the Google Authenticator key-URI format::

        otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30

    Only ``secret`` is required. The issuer is taken from the ``issuer``
    parameter, or from the label prefix when there is no such parameter.
    Parameters this module does not know are ignored; a parameter it does
    know may appear only once. ``otpauth://hotp/`` and every other type are
    refused with a :class:`UsageError` that says so.
    """
    if not isinstance(uri, str):
        raise UsageError("an otpauth link must be text")
    text = uri.strip()
    if len(text) > _MAX_URI:
        raise UsageError("that otpauth link is too long")
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise UsageError("that otpauth link contains control characters")
    scheme, marker, rest = text.partition("://")
    scheme = scheme.lower()
    if scheme == "otpauth-migration":
        raise UsageError(
            "that is a Google Authenticator export link, which packs several accounts into one. "
            "IronDome reads one otpauth://totp/ link per account"
        )
    if not marker or scheme != "otpauth":
        raise UsageError("that is not an otpauth link (expected otpauth://totp/LABEL?secret=...)")
    rest = rest.partition("#")[0]
    location, _, query = rest.partition("?")
    kind, _, raw_label = location.partition("/")
    kind = kind.lower()
    if kind == "hotp":
        raise UsageError(
            "that link is for counter-based one-time passwords (hotp), which IronDome does not handle; "
            "it handles time-based ones (otpauth://totp/)"
        )
    if kind != "totp":
        raise UsageError(f"unsupported otpauth type {kind[:20]!r}: IronDome handles otpauth://totp/ links")
    try:
        pairs = parse_qsl(
            query, keep_blank_values=True, encoding="utf-8", errors="strict", max_num_fields=_MAX_URI_FIELDS
        )
    except ValueError:
        raise UsageError("that otpauth link has parameters that cannot be read") from None
    given: Dict[str, str] = {}
    for name, value in pairs:
        name = name.lower()
        if name in _URI_PARAMETERS:
            if name in given:
                raise UsageError(f"that otpauth link gives its {name} more than once")
            given[name] = value
    if not given.get("secret"):
        raise UsageError("that otpauth link has no secret")
    prefix, account = _split_label(raw_label)
    return make_totp(
        given["secret"],
        algorithm=given.get("algorithm") or "SHA1",
        digits=_small_number(given["digits"], "digits") if given.get("digits") else 6,
        period=_small_number(given["period"], "period") if given.get("period") else 30,
        issuer=given.get("issuer") or prefix,
        account=account,
    )


def to_otpauth(totp: Dict[str, Any], label: Optional[str] = None) -> str:
    """Write settings as an ``otpauth://totp/`` link; the inverse of :func:`parse_otpauth`.

    The result contains the secret: treat it exactly like the secret.

    The label shown by an authenticator app is ``issuer:account``. Pass
    *label* to show something else, for instance the entry's name when no
    account name was recorded (several apps refuse a link whose label is
    empty). Without *label*, ``parse_otpauth(to_otpauth(totp))`` returns the
    same settings.
    """
    settings = validate(totp)
    issuer, account = settings["issuer"], settings["account"]
    if label is None:
        path = quote(account, safe="@")
        if issuer or ":" in account:
            path = quote(issuer, safe="@") + ":" + path
    else:
        path = quote(_clean_label(label, "label"), safe="@:")
    query = "secret=" + settings["secret"]
    if issuer:
        query += "&issuer=" + quote(issuer, safe="")
    query += f"&algorithm={settings['algorithm']}&digits={settings['digits']}&period={settings['period']}"
    return f"otpauth://totp/{path}?{query}"


# ---------------------------------------------------------------------------
# Codes
# ---------------------------------------------------------------------------


def _decode(secret: str) -> SecureBuffer:
    """Decode canonical base32 straight into locked memory.

    Done by hand so that the key never exists as an immutable ``bytes``
    object, which is all that ``base64.b32decode`` can return.
    """
    key = SecureBuffer(len(secret) * 5 // 8)
    try:
        view = key.view()
        pending = bits = index = 0
        for char in secret:
            pending = (pending << 5 | _BASE32_VALUE[char]) & 0xFFF
            bits += 5
            if bits >= 8:
                bits -= 8
                view[index] = pending >> bits & 0xFF
                index += 1
    except BaseException:
        key.wipe()
        raise
    return key


def _hmac(key: SecureBuffer, message: bytes, algorithm: str) -> bytes:
    digest = _DIGESTS[algorithm]
    try:
        return hmac.digest(key.view(), message, digest)
    except TypeError:
        # An interpreter built without OpenSSL computes HMAC in Python, which
        # cannot read a memoryview. Lend it a copy and wipe the copy.
        copy = bytearray(key.view())
        try:
            return hmac.new(copy, message, digest).digest()
        finally:
            wipe_bytes(copy)


def _hotp(key: SecureBuffer, counter: int, digits: int, algorithm: str) -> str:
    """RFC 4226 section 5.3: HMAC the counter, truncate dynamically, keep *digits* digits."""
    mac = _hmac(key, struct.pack(">Q", counter), algorithm)
    offset = mac[-1] & 0x0F
    number = struct.unpack_from(">I", mac, offset)[0] & 0x7FFFFFFF
    return str(number % 10**digits).zfill(digits)


def _number(value: Any) -> Number:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or (isinstance(value, float) and not math.isfinite(value))
    ):
        raise UsageError("a time must be given as a number of seconds since 1970")
    return value


def _counter(moment: Number, period: int) -> int:
    """The time step *moment* falls in: whole periods since 1970."""
    if moment < 0:
        raise UsageError("one-time passwords are not defined for times before 1970")
    counter = int(moment // period)
    if counter > _MAX_COUNTER:
        raise UsageError("that time is too far in the future for a one-time password")
    return counter


def _moment(at: Optional[Number]) -> Number:
    return time.time() if at is None else _number(at)


def code_at(totp: Dict[str, Any], when: float) -> str:
    """The code that is valid at *when* (seconds since 1970)."""
    settings = validate(totp)
    counter = _counter(_number(when), settings["period"])
    with _decode(settings["secret"]) as key:
        return _hotp(key, counter, settings["digits"], settings["algorithm"])


def code_for(totp: Dict[str, Any], at: Optional[float] = None) -> str:
    """The code that is valid now, or at *at* when it is given."""
    return code_at(totp, _moment(at))


def seconds_remaining(totp: Dict[str, Any], at: Optional[float] = None) -> int:
    """Whole seconds until the current code changes: from the period down to 1."""
    period: int = validate(totp)["period"]
    moment = _moment(at)
    _counter(moment, period)
    return period - int(moment % period)


def codes_for_window(totp: Dict[str, Any], start: float, end: float) -> Dict[int, str]:
    """Every code that is valid at some moment from *start* to *end*.

    The keys are time-step counters (seconds since 1970 divided by the
    period, rounded down); read the table back with :func:`code_from_window`.
    The table does not contain the secret and cannot be extended past *end*.
    A window that needs more than :data:`MAX_WINDOW_CODES` codes is refused.
    """
    settings = validate(totp)
    period = settings["period"]
    first = _counter(_number(start), period)
    last = _counter(_number(end), period)
    if end < start:
        raise UsageError("the time window ends before it starts")
    count = last - first + 1
    if count > MAX_WINDOW_CODES:
        raise UsageError(
            f"that time window needs {count} one-time passwords and the limit is {MAX_WINDOW_CODES}; "
            "choose a shorter window"
        )
    with _decode(settings["secret"]) as key:
        return {
            counter: _hotp(key, counter, settings["digits"], settings["algorithm"])
            for counter in range(first, last + 1)
        }


def code_from_window(codes: Mapping[Any, str], period: int, at: Optional[float] = None) -> str:
    """Pick the code for now (or *at*) out of a :func:`codes_for_window` table.

    The table may have been through JSON, which turns its integer keys into
    strings; both forms are found. Raises :class:`AuthError` when the moment
    lies outside the window the table was made for, and :class:`VaultError`
    when the table or the period is not what :func:`codes_for_window` makes.
    """
    if not isinstance(codes, Mapping):
        raise VaultError("the one-time-password table is malformed")
    if isinstance(period, bool) or not isinstance(period, int) or not MIN_PERIOD <= period <= MAX_PERIOD:
        raise VaultError("the one-time-password table has a malformed period")
    counter = _counter(_moment(at), period)
    code = codes.get(counter)
    if code is None:
        code = codes.get(str(counter))
    if code is None:
        raise AuthError(
            "there is no one-time password for this moment: it lies outside the time window these codes were issued for"
        )
    if not isinstance(code, str) or len(code) not in DIGITS or not code.isascii() or not code.isdigit():
        raise VaultError("the one-time-password table is damaged")
    return code


def verify(totp: Dict[str, Any], code: str, at: Optional[float] = None, *, drift: int = 1) -> bool:
    """True if *code* is right for now (or *at*), give or take *drift* time steps.

    For checking that a secret was entered correctly: compare with the code
    another authenticator shows. Spaces in *code* are ignored. Every
    candidate is compared in constant time and all of them are compared.
    This is not a login check: it does not remember codes it has accepted.
    """
    settings = validate(totp)
    if isinstance(drift, bool) or not isinstance(drift, int) or not 0 <= drift <= MAX_DRIFT:
        raise UsageError(f"drift must be a whole number of time steps from 0 to {MAX_DRIFT}")
    if not isinstance(code, str):
        raise UsageError("a one-time password must be given as text")
    offered = "".join(code.split()).encode("utf-8", "replace")
    current = _counter(_moment(at), settings["period"])
    matched = False
    with _decode(settings["secret"]) as key:
        for counter in range(max(0, current - drift), min(_MAX_COUNTER, current + drift) + 1):
            expected = _hotp(key, counter, settings["digits"], settings["algorithm"]).encode("ascii")
            matched = hmac.compare_digest(expected, offered) or matched
    return matched
