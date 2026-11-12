"""Random passwords, passphrases, user names and mail aliases, and a rough
judgement of passwords a person made up.

Everything random here comes from :mod:`secrets`, the operating system's
CSPRNG. Nothing in this module touches the vault or the network.

**Passwords** are drawn uniformly from all strings of the requested length
that contain at least one character of every enabled class. A whole candidate
is drawn and thrown away if a class is missing (the recipe in the ``secrets``
documentation), so no position and no character within a class is favoured.
:func:`password_entropy_bits` is the exact base-2 logarithm of the number of
such strings.

**Passphrases** are drawn from the EFF large word list: 7776 words, one per
roll of five dice, so each word adds log2(7776), about 12.9 bits. The list is
shipped inside the package and is used only if its SHA-256 is
:data:`WORDLIST_SHA256`.

:func:`estimate_strength` is a different kind of thing: an estimate, not a
measurement. Its docstring says what it can and cannot tell.
"""

from __future__ import annotations

import hashlib
import math
import secrets
import string
import struct
from dataclasses import dataclass
from itertools import islice
from typing import Any, Dict, FrozenSet, Iterator, List, Optional, Sequence, Set, Tuple, Union

from irondome.errors import IronDomeError, UsageError
from irondome.secmem import BufferLike, SecureBuffer, as_view

__all__ = [
    "MIN_LENGTH",
    "MAX_LENGTH",
    "MIN_WORDS",
    "MAX_WORDS",
    "DEFAULT_SYMBOLS",
    "AMBIGUOUS",
    "WORDLIST_SHA256",
    "Strength",
    "generate_password",
    "generate_passphrase",
    "generate_username",
    "email_alias",
    "entropy_bits",
    "password_entropy_bits",
    "passphrase_entropy_bits",
    "estimate_strength",
    "strength_label",
    "wordlist",
]

MIN_LENGTH = 8
MAX_LENGTH = 512
MIN_WORDS = 3
MAX_WORDS = 24

#: Symbols that almost every site accepts and that survive being pasted.
DEFAULT_SYMBOLS = "!@#$%^&*-_"
#: Characters that are easily mistaken for one another when read or typed.
AMBIGUOUS = "0Oo1lI|"
#: SHA-256 of the bundled ``data/eff_large_wordlist.txt``; the note beside that file says where it came from.
WORDLIST_SHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"

_LOWER = string.ascii_lowercase
_UPPER = string.ascii_uppercase
_DIGITS = string.digits
#: Candidates drawn before the random source is declared broken. Even with the
#: least favourable options one candidate in thirteen is kept, so a working
#: source never comes near this.
_MAX_DRAWS = 10_000
_WORDLIST_FILE = "eff_large_wordlist.txt"
_WORDLIST_BYTES = 108_800
_WORDLIST_WORDS = 7776
_USERNAME_LENGTHS = (3, 64)
_TAG_LENGTH = 8
_MAX_TAG = 32
_MAX_SEPARATOR = 8


def _whole(value: Any, low: int, high: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise UsageError(f"{what} must be a whole number from {low} to {high}")
    return value


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


def _classes(
    lower: bool, upper: bool, digits: bool, symbols: bool, exclude_ambiguous: bool, symbol_set: str
) -> List[str]:
    """The enabled character classes, each as a string of distinct characters."""
    classes = [chars for enabled, chars in ((lower, _LOWER), (upper, _UPPER), (digits, _DIGITS)) if enabled]
    if symbols:
        if not isinstance(symbol_set, str) or not symbol_set:
            raise UsageError("the symbol set must be a non-empty string of punctuation characters")
        if any(char not in string.punctuation for char in symbol_set):
            raise UsageError("the symbol set may only hold ASCII punctuation: " + string.punctuation)
        classes.append("".join(dict.fromkeys(symbol_set)))
    if not classes:
        raise UsageError("a password needs at least one kind of character: enable letters, digits or symbols")
    if exclude_ambiguous:
        classes = ["".join(char for char in chars if char not in AMBIGUOUS) for chars in classes]
        if not all(classes):
            raise UsageError("nothing is left of the symbol set once look-alike characters are excluded")
    return classes


def generate_password(
    length: int = 20,
    *,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
    symbol_set: str = DEFAULT_SYMBOLS,
) -> str:
    """A random password of *length* characters (8 to 512).

    It contains at least one character from every enabled class and is
    otherwise uniformly random: every string that meets that rule is equally
    likely. *exclude_ambiguous* drops the characters in :data:`AMBIGUOUS`;
    *symbol_set* replaces the symbols used (ASCII punctuation only, repeats
    ignored). Options that cannot be met raise :class:`UsageError`.
    """
    length = _whole(length, MIN_LENGTH, MAX_LENGTH, "a password length")
    classes = _classes(lower, upper, digits, symbols, exclude_ambiguous, symbol_set)
    alphabet = "".join(classes)
    required = [frozenset(chars) for chars in classes]
    for _ in range(_MAX_DRAWS):
        candidate = [secrets.choice(alphabet) for _ in range(length)]
        if all(not chars.isdisjoint(candidate) for chars in required):
            return "".join(candidate)
    raise IronDomeError(
        "the system's random source keeps returning unusable output; no password was generated. "
        "Check the operating system's random number generator"
    )


def entropy_bits(length: int, alphabet_size: int) -> float:
    """Bits in *length* characters drawn independently and uniformly from *alphabet_size* characters."""
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        raise UsageError("a length must be a whole number that is not negative")
    if isinstance(alphabet_size, bool) or not isinstance(alphabet_size, int) or alphabet_size < 1:
        raise UsageError("an alphabet must hold at least one character")
    return length * math.log2(alphabet_size)


def password_entropy_bits(
    length: int = 20,
    *,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
    symbol_set: str = DEFAULT_SYMBOLS,
) -> float:
    """The exact entropy of :func:`generate_password` called with the same arguments.

    It is the base-2 logarithm of the number of strings of that length that
    hold at least one character of every enabled class (counted by inclusion
    and exclusion). That is a little less than ``entropy_bits(length,
    alphabet size)``: with the default classes about 1.2 bits less at length
    8 and 0.15 bits less at the default length of 20.
    """
    length = _whole(length, MIN_LENGTH, MAX_LENGTH, "a password length")
    sizes = [len(chars) for chars in _classes(lower, upper, digits, symbols, exclude_ambiguous, symbol_set)]
    total = sum(sizes)
    count = 0
    for subset in range(1 << len(sizes)):
        excluded = [size for position, size in enumerate(sizes) if subset >> position & 1]
        count += (-1) ** len(excluded) * (total - sum(excluded)) ** length
    return math.log2(count)


# ---------------------------------------------------------------------------
# The word list
# ---------------------------------------------------------------------------

_words: Optional[Tuple[str, ...]] = None


def _wordlist_file() -> Any:
    """The bundled list as a readable resource, whether the package is installed as files or inside a zip."""
    from importlib import resources  # imported here: only passphrases and estimates need it

    return resources.files("irondome") / "data" / _WORDLIST_FILE


def _load_wordlist() -> Tuple[str, ...]:
    try:
        with _wordlist_file().open("rb") as handle:
            data = handle.read(2 * _WORDLIST_BYTES)
    except (OSError, KeyError):
        raise IronDomeError("IronDome's word list is missing from this installation; reinstall IronDome") from None
    data = data.replace(b"\r\n", b"\n")  # a checkout may have rewritten the line endings
    if hashlib.sha256(data).hexdigest() != WORDLIST_SHA256:
        raise IronDomeError("IronDome's word list has been altered or damaged; reinstall IronDome")
    return tuple(line.partition("\t")[2] for line in data.decode("ascii").splitlines())


def wordlist() -> Tuple[str, ...]:
    """The 7776 words of the EFF large word list, in the list's own (alphabetical) order.

    Read from the package on first use and kept. Raises :class:`IronDomeError`
    if the file is missing or its SHA-256 is not :data:`WORDLIST_SHA256`, so a
    replaced or truncated list can never weaken a passphrase unnoticed.
    """
    global _words
    if _words is None:
        _words = _load_wordlist()
    return _words


# ---------------------------------------------------------------------------
# Passphrases, user names, mail aliases
# ---------------------------------------------------------------------------


def generate_passphrase(words: int = 6, *, separator: str = "-", capitalize: bool = False, number: bool = False) -> str:
    """A passphrase of *words* (3 to 24) random words from the EFF large word list.

    *separator* joins the words: up to 8 characters, spaces or ASCII
    punctuation, or the empty string. *capitalize* gives every word a capital
    first letter and *number* appends one random digit to one randomly chosen
    word; both exist to satisfy sites that demand them and add little or no
    strength. No word of the list is the beginning of another, so the phrase
    splits into its words in only one way whatever the separator.
    """
    count = _whole(words, MIN_WORDS, MAX_WORDS, "the number of words in a passphrase")
    if (
        not isinstance(separator, str)
        or len(separator) > _MAX_SEPARATOR
        or any(char != " " and char not in string.punctuation for char in separator)
    ):
        raise UsageError(f"a separator is at most {_MAX_SEPARATOR} characters, each a space or ASCII punctuation")
    source = wordlist()
    chosen = [secrets.choice(source) for _ in range(count)]
    if capitalize:
        chosen = [word.capitalize() for word in chosen]
    if number:
        chosen[secrets.randbelow(count)] += secrets.choice(_DIGITS)
    return separator.join(chosen)


def passphrase_entropy_bits(words: int, *, number: bool = False) -> float:
    """The exact entropy of :func:`generate_passphrase`: log2(7776) bits per word.

    The separator and *capitalize* add nothing. *number* adds the choice of
    one digit and of the word it follows: log2(10 * words) bits.
    """
    count = _whole(words, MIN_WORDS, MAX_WORDS, "the number of words in a passphrase")
    bits = count * math.log2(_WORDLIST_WORDS)
    return bits + math.log2(10 * count) if number else bits


def generate_username(length: int = 10) -> str:
    """A random user name: a lower-case letter followed by lower-case letters and digits.

    Meant for sites where the user name need not be memorable, so that it is
    not shared between accounts. It is an identifier, not a secret.
    """
    low, high = _USERNAME_LENGTHS
    count = _whole(length, low, high, "a user name length")
    return secrets.choice(_LOWER) + "".join(secrets.choice(_LOWER + _DIGITS) for _ in range(count - 1))


_LOCAL_PART = frozenset(string.ascii_letters + string.digits + "!#$%&'*+/=?^_`{|}~-.")
_TAG = frozenset(string.ascii_letters + string.digits + "._-")
_NOT_AN_ADDRESS = "that does not look like an email address (expected something like name@example.com)"


def _beyond_ascii(char: str) -> bool:
    return ord(char) > 127 and char.isprintable()


def _dotted(text: str) -> bool:
    """True if *text* does not start or end with a dot and has no two dots in a row."""
    return not text.startswith(".") and not text.endswith(".") and ".." not in text


def _split_address(address: Any) -> Tuple[str, str]:
    if not isinstance(address, str):
        raise UsageError(_NOT_AN_ADDRESS)
    text = address.strip()
    local, at, domain = text.rpartition("@")
    labels = domain.split(".")
    if (
        not at
        or len(text) > 254
        or not 1 <= len(local) <= 64
        or not _dotted(local)
        or not all(char in _LOCAL_PART or _beyond_ascii(char) for char in local)
        or len(labels) < 2
        or not all(
            1 <= len(label) <= 63
            and all(char == "-" or char.isalnum() for char in label)
            and not label.startswith("-")
            and not label.endswith("-")
            for label in labels
        )
        or len(labels[-1]) < 2
        or labels[-1].isdigit()
    ):
        raise UsageError(_NOT_AN_ADDRESS)
    return local, domain


def email_alias(address: str, tag: Optional[str] = None) -> str:
    """Turn ``name@example.com`` into the plus-address ``name+tag@example.com``.

    Without *tag*, eight random lower-case letters and digits are used. A tag
    already present in *address* is replaced. This is string handling only:
    nothing is sent or looked up. Most mail providers deliver plus-addresses
    to the base mailbox, but not all do, some sites refuse the ``+``, and
    anyone can strip the tag to find the base address. It shows which site
    passed an address on; it does not hide the mailbox.
    """
    local, domain = _split_address(address)
    base = local.partition("+")[0]
    if not base:
        raise UsageError("that email address has nothing before its '+', so there is no mailbox to add a tag to")
    if tag is None:
        tag = "".join(secrets.choice(_LOWER + _DIGITS) for _ in range(_TAG_LENGTH))
    elif (
        not isinstance(tag, str)
        or not 1 <= len(tag) <= _MAX_TAG
        or not _dotted(tag)
        or not all(char in _TAG for char in tag)
    ):
        raise UsageError(f"a tag is 1 to {_MAX_TAG} letters, digits, '.', '_' or '-', without a dot at either end")
    if len(base) + 1 + len(tag) > 64:
        raise UsageError("with that tag the part before the '@' would be longer than the 64 characters mail allows")
    return f"{base}+{tag}@{domain}"


# ---------------------------------------------------------------------------
# Strength of a password somebody chose
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Strength:
    """What :func:`estimate_strength` made of a password."""

    #: Estimated base-2 logarithm of the guesses needed, to one decimal place.
    bits: float
    #: "very weak", "weak", "fair", "strong" or "very strong".
    label: str
    #: Why the estimate is low, in plain words; empty for strong passwords.
    warnings: List[str]


#: A password is given the first label whose limit its bits fall below.
_LABELS = ((28.0, "very weak"), (44.0, "weak"), (64.0, "fair"), (90.0, "strong"))
_TOP_LABEL = "very strong"
_ANALYSED_CHARS = 512
_SHORT = 12
_LONGEST_UNIT = 32


def strength_label(bits: float) -> str:
    """The word :func:`estimate_strength` uses for *bits*.

    For showing an exact figure, such as :func:`password_entropy_bits`, on
    the same scale as an estimate: under 28 "very weak", under 44 "weak",
    under 64 "fair", under 90 "strong", otherwise "very strong".
    """
    if isinstance(bits, bool) or not isinstance(bits, (int, float)) or not bits >= 0:
        raise UsageError("a strength in bits must be a number that is not negative")
    return next((name for limit, name in _LABELS if bits < limit), _TOP_LABEL)


# A few hundred passwords of the kinds that lead the rankings of leaked
# passwords: digit and keyboard runs, first names, teams, pets, default
# credentials. Written out by hand for this module; matching ignores case.
_COMMON = tuple(
    sorted(
        set(
            """
    123 1234 12345 123456 1234567 12345678 123456789 1234567890 0123456789 012345 0123456 01234567
    0987654321 09876543 987654321 987654 87654321 654321 54321 4321 123123 123123123 123321 12341234
    12121212 121212 112233 11223344 1122334455 111222 111222333 112211 123654 123000 100200 102030
    010203 010101 101010 000000 00000000 00000 0000 111111 1111111 11111111 111111111 11111 1111
    222222 22222 333333 444444 555555 55555 666666 777777 7777777 77777 888888 88888888 999999
    999999999 696969 6969 131313 232323 212121 420420 123456a 123456789a 12345a a123456 a12345
    a1234567 a12345678 a123456789 aa123456 1234567a 12345678a 123456789q 123abc abc123 abc1234
    abc12345 abcd1234 1234abcd abcabc abcdef abcdefg abcdefgh abcd a1b2c3 a1b2c3d4 aaa111 aaaaaa
    aaaaaaaa zzzzzz qqqqqq 147258 147258369 147852 147852369 159753 159357 741852963
    963852741 852456 789456 789456123 456789 456123 321654 321321 135790 1357924680 13579 24680
    2468 1029384756 5201314 520520 1314520 7758521 woaini woaini1314 8675309 314159 31415926
    271828 1337 007 007007 bond007 james007 qwerty qwerty1 qwerty12 qwerty123 qwerty1234
    qwerty12345 qwertyui qwertyuiop qwert qwer qwer1234 1234qwer qwerqwer qweqwe qwe123 123qwe
    qweasd qweasdzxc qazwsx qazwsxedc qazxsw qazxswedc qaz123 qwaszx zaqwsx zaq12wsx zaq1zaq1
    1qaz2wsx 1qazxsw2 1qaz@wsx !qaz2wsx 1q2w3e 1q2w3e4r 1q2w3e4r5t 1q2w3e4r5t6y q1w2e3 q1w2e3r4
    q1w2e3r4t5 asdfgh asdfghjkl asdfghjkl123 asdfg asdf asdf1234 asdasd asd123 zxcvbn zxcvbnm
    zxcvbnm123 zxcvb zxcv poiuytrewq lkjhgfdsa mnbvcxz password password1 password12 password123
    password1234 password2 password01 password11 password99 password! passw0rd p@ssw0rd p@ssword
    pa$$word pa55word p@55w0rd passwort passwd pass pass123 pass1234 passpass secret secret123
    s3cret s3cr3t letmein letmein1 letmein123 welcome welcome1 welcome123 admin admin1 admin12
    admin123 admin1234 admin@123 administrator root root123 toor login user user123 guest test
    test1 test123 test1234 test@123 testing tester demo temp temp123 changeme change default
    master master1 master123 access access123 server system computer internet network security
    private public backup service support manager supervisor oracle postgres mysql redis docker
    jenkins tomcat vagrant ansible alpine kali raspberry ubnt nagios zabbix elastic mongodb
    hello hello1 hello123 iloveyou iloveyou1 iloveu loveyou love love123 lovely loveme lover
    trustno1 whatever nothing something anything forever always never dragon dragon1 dragon123
    monkey monkey1 monkey123 shadow shadow1 shadow123 sunshine sunshine1 princess princess1
    football football1 baseball baseball1 basketball soccer hockey tennis golf superman
    superman1 superman123 batman batman123 spiderman ironman starwars pokemon pokemon123 pikachu
    naruto minecraft fortnite nintendo playstation xbox google facebook twitter instagram
    youtube amazon apple apple123 iphone samsung android windows linux ubuntu microsoft cisco
    money cash dollar freedom liberty america god god123 jesus christ heaven angel angel1 angels
    devil lucifer ninja ninja123 killer killer123 hunter hunter2 ranger soldier warrior wizard
    knight king queen prince tiger lion eagle falcon wolf bear panther jaguar mustang ferrari
    porsche mercedes corvette harley yamaha honda toyota nissan ford chevy jordan jordan1
    jordan23 michael michael1 jennifer jessica michelle ashley ashley1 amanda nicole daniel
    thomas robert joshua matthew andrew anthony charlie charlie1 george william david james john
    richard joseph alex alexander maria anna sarah emma olivia sophia hannah taylor morgan
    bailey maggie buster buddy max rocky lucky lucky7 ginger pepper cookie cheese chocolate
    banana orange flower rose summer winter spring autumn monday friday sunday january february
    march april june july august september october november december blue red green black white
    purple silver golden gold diamond star stars moon sun sunset rainbow thunder storm lightning
    fire fireball ice snow matrix phoenix genesis legend magic mystery ghost zombie vampire
    pirate cowboy rockstar rock music guitar piano dance party fuckyou fuck fuckoff asshole
    bitch shit sex sexy hottie babygirl baby daddy mommy family friend friends happy smile peace
    hope faith trust london paris berlin madrid moscow tokyo newyork chicago boston dallas texas
    florida california israel jerusalem telaviv shalom liverpool arsenal chelsea barcelona
    realmadrid juventus manchester united yankees lakers cowboys steelers patriots eagles redsox
    hacker hacked hack anonymous leet l33t h4x0r
    """.split()
        )
    )
)
_COMMON_REVERSED = tuple(sorted({word[::-1] for word in _COMMON if len(word) >= 5} - set(_COMMON)))
_COMMON_BITS = math.log2(len(_COMMON))
_WORD_BITS = math.log2(_WORDLIST_WORDS)

# Character classes of the estimate: 0 lower-case (and every character
# outside ASCII), 1 upper-case, 2 digit, 3 symbol (punctuation and space).
_CLASS_SIZES = (26, 26, 10, 33)
_CLASS_BITS = tuple(math.log2(size) for size in _CLASS_SIZES)
_CLASS = [
    0 if chr(code) in _LOWER else 1 if chr(code) in _UPPER else 2 if chr(code) in _DIGITS else 3 for code in range(128)
]
_SEPARATORS = frozenset(map(ord, " -_.,"))
_SEPARATOR_BITS = math.log2(len(_SEPARATORS))
_REPEATED_SYMBOL_BITS = 0.5
_WORD_RUN = 4

# How a password is read when it is looked up in the word lists: as typed
# apart from case, or with the usual look-alikes turned back into letters.
_SUBSTITUTIONS = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s", "+": "t"}
_ONE_LIKE = "1!|"  # stands for an i in some words and for an l in others
_SUBSTITUTED = frozenset(map(ord, "".join(_SUBSTITUTIONS) + _ONE_LIKE))
_PLAIN: List[Optional[str]] = [chr(code).lower() if 32 <= code < 127 else None for code in range(128)]


def _substituting(one_as: str) -> List[Optional[str]]:
    table = [char if char is not None and char.isalpha() else None for char in _PLAIN]
    for char, letter in _SUBSTITUTIONS.items():
        table[ord(char)] = letter
    for char in _ONE_LIKE:
        table[ord(char)] = one_as
    return table


_AS_I = _substituting("i")
_AS_L = _substituting("l")


def _keyboard() -> Tuple[Dict[int, Tuple[int, int]], FrozenSet[int]]:
    """The keys of a US keyboard, and the characters that need Shift.

    Each character maps to (row, position), the position counted in quarter
    key widths because each row is shifted sideways against the one above.
    """
    rows = (
        ("`1234567890-=", "~!@#$%^&*()_+", 0),
        ("qwertyuiop[]\\", "QWERTYUIOP{}|", 6),
        ("asdfghjkl;'", 'ASDFGHJKL:"', 7),
        ("zxcvbnm,./", "ZXCVBNM<>?", 9),
    )
    keys: Dict[int, Tuple[int, int]] = {}
    for row, (plain, shifted, offset) in enumerate(rows):
        for column, (low, high) in enumerate(zip(plain, shifted)):
            keys[ord(low)] = keys[ord(high)] = (row, offset + 4 * column)
    return keys, frozenset(ord(char) for _, shifted, _ in rows for char in shifted)


_KEYS, _SHIFTED = _keyboard()
_KEYBOARD_START_BITS = math.log2(len(_KEYS) // 2)

_OBVIOUS_STARTS = frozenset(map(ord, "aAzZ019"))
_YEAR_BITS = math.log2(200)
_DATE_BITS = math.log2(366 * 200)
_SHORT_DATE_BITS = math.log2(366 * 100)
_DATE_SEPARATORS = frozenset(map(ord, "/-."))

_WARNINGS = (
    ("common", "it contains one of the most common passwords"),
    ("word", "it contains dictionary words"),
    ("keyboard", "it follows keys that sit next to each other on the keyboard"),
    ("sequence", "it contains a run of consecutive letters or digits"),
    ("repeat", "it repeats a character or a group of characters"),
    ("date", "it contains a date or a year"),
)

#: A pattern found in a password: (start, end, bits, kind).
_Token = Tuple[int, int, float, str]
#: Patterns grouped by the position they end at: end -> [(start, bits, kind)].
_ByEnd = Dict[int, List[Tuple[int, float, str]]]


def _class_of(code: int) -> int:
    return _CLASS[code] if code < 128 else 0


def _char_bits(codes: Sequence[int], count: int) -> Tuple[List[float], int]:
    """What each character costs to guess on its own, and how many classes are in use.

    A character costs log2 of the size of its own class plus log2(classes in
    use) for the choice of that class, and never more than log2 of the
    combined size of the classes in use. The choice of class is not charged
    where it is no choice: for a digit or symbol that follows another one,
    and for a letter inside a run of four or more letters of the same case,
    which is how words look and how random strings rarely do. A symbol that
    already occurred costs half a bit and the usual separators cost little,
    so that what holds a passphrase together is not counted as if it were
    random.
    """
    present = 0
    runs = [0] * count  # for each character, the length of the run of its class that it stands in
    start = 0
    for index in range(count):
        kind = _class_of(codes[index])
        present |= 1 << kind
        if index + 1 == count or _class_of(codes[index + 1]) != kind:
            for position in range(start, index + 1):
                runs[position] = index + 1 - start
            start = index + 1
    kinds = bin(present).count("1")
    choice = math.log2(kinds)
    ceiling = math.log2(sum(size for kind, size in enumerate(_CLASS_SIZES) if present >> kind & 1))
    bits: List[float] = []
    symbols_seen: Set[int] = set()
    previous = -1
    for index in range(count):
        code = codes[index]
        kind = _class_of(code)
        if kind == 3 and code in symbols_seen:
            bits.append(_REPEATED_SYMBOL_BITS)
        elif code in _SEPARATORS:
            bits.append(_SEPARATOR_BITS)
        elif kind == previous and (kind >= 2 or runs[index] >= _WORD_RUN):
            bits.append(_CLASS_BITS[kind])
        else:
            bits.append(min(_CLASS_BITS[kind] + choice, ceiling))
        if kind == 3:
            symbols_seen.add(code)
        previous = kind
    return bits, kinds


def _narrow(words: Sequence[str], low: int, high: int, depth: int, char: str) -> Tuple[int, int]:
    """Narrow ``words[low:high]``, which share *depth* leading characters, to those that continue with *char*.

    *words* is sorted, so the survivors are again one contiguous range.
    """
    if low < high and len(words[low]) == depth:
        low += 1  # that word ends here; it has no next character
    first, last = low, high
    while first < last:
        middle = (first + last) // 2
        if words[middle][depth] < char:
            first = middle + 1
        else:
            last = middle
    start, last = first, high
    while first < last:
        middle = (first + last) // 2
        if words[middle][depth] <= char:
            first = middle + 1
        else:
            last = middle
    return start, first


def _word_ends(
    codes: Sequence[int], count: int, start: int, words: Sequence[str], table: Sequence[Optional[str]]
) -> Iterator[int]:
    """Where each word of the sorted list *words* that begins at *start* ends.

    The password is read one character at a time through *table*; no piece
    of it is ever assembled into a string to be looked up.
    """
    low, high = 0, len(words)
    for depth in range(count - start):
        code = codes[start + depth]
        char = table[code] if code < 128 else None
        if char is None:
            return
        low, high = _narrow(words, low, high, depth, char)
        if low == high:
            return
        if len(words[low]) == depth + 1:
            yield start + depth + 1


def _case_bits(codes: Sequence[int], start: int, end: int) -> float:
    """Extra guesses for capital letters in a word: none, one bit for the usual ways, more for odd ones."""
    upper = lower = 0
    for index in range(start, end):
        code = codes[index]
        if 65 <= code <= 90:
            upper += 1
        elif 97 <= code <= 122:
            lower += 1
    if not upper:
        return 0.0
    if not lower or (upper == 1 and 65 <= codes[start] <= 90):
        return 1.0
    return 1.0 + min(upper, lower)


def _dictionary_tokens(codes: Sequence[int], count: int, tokens: List[_Token]) -> None:
    """Common passwords (also backwards) and dictionary words, as typed or with letters swapped for look-alikes."""
    words = wordlist()
    lookups: List[Tuple[Sequence[str], Sequence[Optional[str]], float, str, FrozenSet[int]]] = [
        (_COMMON, _PLAIN, _COMMON_BITS, "common", frozenset()),
        (_COMMON_REVERSED, _PLAIN, _COMMON_BITS + 1.0, "common", frozenset()),
        (words, _PLAIN, _WORD_BITS, "word", frozenset()),
    ]
    if any(codes[index] in _SUBSTITUTED for index in range(count)):
        # A stretch read with substitutions counts only if it holds one;
        # the second table differs from the first only in what "1" means.
        for reading, needed in ((_AS_I, _SUBSTITUTED), (_AS_L, frozenset(map(ord, _ONE_LIKE)))):
            lookups.append((_COMMON, reading, _COMMON_BITS + 1.0, "common", needed))
            lookups.append((words, reading, _WORD_BITS + 1.0, "word", needed))
    for start in range(count):
        for source, table, bits, kind, needed in lookups:
            for end in _word_ends(codes, count, start, source, table):
                if needed and not any(codes[index] in needed for index in range(start, end)):
                    continue
                tokens.append((start, end, bits + _case_bits(codes, start, end), kind))


def _sequence_tokens(codes: Sequence[int], count: int, tokens: List[_Token]) -> None:
    """Runs of three or more consecutive letters or digits, up or down: abc, 7654."""
    index = 0
    while index < count - 2:
        step = codes[index + 1] - codes[index]
        kind = _class_of(codes[index]) if codes[index] < 128 else 3
        end = index + 1
        if step in (1, -1) and kind != 3:
            while end < count and codes[end] - codes[end - 1] == step and _class_of(codes[end]) == kind:
                end += 1
        if end - index >= 3:
            bits = 1.0 if codes[index] in _OBVIOUS_STARTS else _CLASS_BITS[kind]
            tokens.append((index, end, bits + (1.0 if step < 0 else 0.0) + math.log2(end - index), "sequence"))
        index = max(end - 1, index + 1)


def _key_move(before: int, after: int) -> Optional[Tuple[int, int]]:
    """The direction from one key to a neighbouring key, or None if they do not touch."""
    here, there = _KEYS.get(before), _KEYS.get(after)
    if here is None or there is None:
        return None
    rows, across = there[0] - here[0], there[1] - here[1]
    if (rows == 0 and abs(across) == 4) or (abs(rows) == 1 and abs(across) < 4):
        return rows, 1 if across > 0 else -1
    return None


def _keyboard_tokens(codes: Sequence[int], count: int, tokens: List[_Token]) -> None:
    """Runs of four or more neighbouring keys: qwerty, 1qaz, zxcvbn."""
    index = 0
    while index < count - 3:
        end = index + 1
        turns = 0
        heading = None
        while end < count:
            move = _key_move(codes[end - 1], codes[end])
            if move is None:
                break
            if heading is not None and move != heading:
                turns += 1
            heading = move
            end += 1
        if end - index >= 4:
            bits = _KEYBOARD_START_BITS + 2.0 * (turns + 1) + math.log2(end - index)
            if any(codes[position] in _SHIFTED for position in range(index, end)):
                bits += 1.0
            tokens.append((index, end, bits, "keyboard"))
        index = end


def _digits_at(codes: Sequence[int], count: int, start: int, most: int) -> int:
    """How many digits, up to *most*, stand at *start*."""
    size = 0
    while size < most and start + size < count and 48 <= codes[start + size] <= 57:
        size += 1
    return size


def _pair(codes: Sequence[int], start: int, size: int = 2) -> int:
    """The number written by one or two digits."""
    value = codes[start] - 48
    return value * 10 + codes[start + 1] - 48 if size == 2 else value


def _day_and_month(first: int, second: int) -> bool:
    return (1 <= first <= 31 and 1 <= second <= 12) or (1 <= first <= 12 and 1 <= second <= 31)


def _century(codes: Sequence[int], start: int) -> bool:
    return _pair(codes, start) in (19, 20)


def _separated_date(codes: Sequence[int], count: int, start: int) -> int:
    """The end of a date such as 3/11/1994, 03.11.94 or 1994-11-03 at *start*, or -1."""
    first = _digits_at(codes, count, start, 4)
    if first not in (1, 2, 4) or start + first >= count or codes[start + first] not in _DATE_SEPARATORS:
        return -1
    separator = codes[start + first]
    middle_at = start + first + 1
    middle = _digits_at(codes, count, middle_at, 2)
    last_at = middle_at + middle + 1
    if not middle or last_at > count or codes[last_at - 1] != separator:
        return -1
    last = _digits_at(codes, count, last_at, 2 if first == 4 else 4)
    second = _pair(codes, middle_at, middle)
    if first == 4:
        valid = bool(last) and _century(codes, start) and 1 <= second <= 12 and 1 <= _pair(codes, last_at, last) <= 31
    else:
        valid = (
            last in (2, 4)
            and (last == 2 or _century(codes, last_at))
            and _day_and_month(_pair(codes, start, first), second)
        )
    return last_at + last if valid else -1


def _date_tokens(codes: Sequence[int], count: int, tokens: List[_Token]) -> None:
    """Years from 1900 to 2099 and dates written as digits, with or without separators."""
    for start in range(count):
        digits = _digits_at(codes, count, start, 8)
        if not digits:
            continue
        if digits >= 4 and _century(codes, start):
            tokens.append((start, start + 4, _YEAR_BITS, "date"))
        if digits >= 6:
            one, two, three = _pair(codes, start), _pair(codes, start + 2), _pair(codes, start + 4)
            if _day_and_month(one, two) or (1 <= two <= 12 and 1 <= three <= 31):
                tokens.append((start, start + 6, _SHORT_DATE_BITS, "date"))
            if digits == 8 and (
                (_day_and_month(one, two) and three in (19, 20))
                or (one in (19, 20) and 1 <= three <= 12 and 1 <= _pair(codes, start + 6) <= 31)
            ):
                tokens.append((start, start + 8, _DATE_BITS, "date"))
        end = _separated_date(codes, count, start)
        if end > 0:
            tokens.append((start, end, _DATE_BITS + math.log2(len(_DATE_SEPARATORS)), "date"))


def _cheapest(
    char_bits: Sequence[float], by_end: _ByEnd, low: int, high: int
) -> Tuple[float, List[Tuple[int, int, str]]]:
    """The fewest bits that account for characters *low* to *high*, and the patterns that reading uses.

    Every character is either guessed on its own or covered by one pattern;
    of all ways to split the stretch up, the cheapest is what an attacker
    who tries likely things first would exploit.
    """
    best = [0.0] * (high - low + 1)
    reached: List[Optional[Tuple[int, str]]] = [None] * (high - low + 1)
    for end in range(low + 1, high + 1):
        cost, choice = best[end - 1 - low] + char_bits[end - 1], None
        for start, bits, kind in by_end.get(end, ()):
            if start >= low and best[start - low] + bits < cost:
                cost, choice = best[start - low] + bits, (start, kind)
        best[end - low], reached[end - low] = cost, choice
    used = []
    end = high
    while end > low:
        choice = reached[end - low]
        if choice is None:
            end -= 1
        else:
            used.append((choice[0], end, choice[1]))
            end = choice[0]
    return best[high - low], used


def _repeat_tokens(codes: Sequence[int], count: int, char_bits: Sequence[float], by_end: _ByEnd) -> List[_Token]:
    """Stretches that repeat one character or one group of characters: aaaa, abcabc, hunter2hunter2.

    A repeat costs what its first unit costs, plus the choice of how often.
    """
    tokens: List[_Token] = []
    for unit in range(1, min(_LONGEST_UNIT, count // 2) + 1):
        start = -1
        for index in range(unit, count + 1):
            if index < count and codes[index] == codes[index - unit]:
                if start < 0:
                    start = index - unit
                continue
            if start >= 0:
                length = index - start
                if length >= max(2 * unit, 3):
                    once = _cheapest(char_bits, by_end, start, start + unit)[0]
                    tokens.append((start, index, once + math.log2(length / unit), "repeat"))
                start = -1
    return tokens


def _estimate(codes: Sequence[int], count: int) -> Strength:
    """Estimate from the characters' code points; reads *codes* one index at a time."""
    if count == 0:
        return Strength(0.0, "very weak", ["it is empty"])
    char_bits, kinds = _char_bits(codes, count)
    tokens: List[_Token] = []
    _dictionary_tokens(codes, count, tokens)
    _sequence_tokens(codes, count, tokens)
    _keyboard_tokens(codes, count, tokens)
    _date_tokens(codes, count, tokens)
    by_end: _ByEnd = {}
    for start, end, bits, kind in tokens:
        by_end.setdefault(end, []).append((start, bits, kind))
    for start, end, bits, kind in _repeat_tokens(codes, count, char_bits, by_end):
        by_end.setdefault(end, []).append((start, bits, kind))
    total, used = _cheapest(char_bits, by_end, 0, count)
    total = round(total, 1)
    label = strength_label(total)
    warnings: List[str] = []
    if label not in ("strong", _TOP_LABEL):
        found = {kind for _, _, kind in used}
        if used == [(0, count, "common")]:
            warnings.append("it is one of the most common passwords")
            found.discard("common")
        warnings.extend(text for kind, text in _WARNINGS if kind in found)
        if kinds == 1 and count >= 3:
            warnings.append("it uses only one kind of character")
        if count < _SHORT:
            warnings.append("it is short")
    return Strength(total, label, warnings)


def _decode_utf8(data: memoryview, codes: memoryview) -> int:
    """Write the code points of UTF-8 *data* into *codes*; return how many were written.

    A byte that is not part of well-formed UTF-8 is kept as one character of
    its own, so any byte string can be judged. Stops when *codes* is full.
    """
    size, room = len(data), len(codes)
    index = written = 0
    while index < size and written < room:
        lead = data[index]
        extra = 0 if lead < 0xC2 or lead > 0xF4 else 1 if lead < 0xE0 else 2 if lead < 0xF0 else 3
        code = lead if lead < 0x80 else 0xDC00 + lead
        if extra and index + extra < size:
            code = lead & (0x3F >> extra)
            for offset in range(1, extra + 1):
                follow = data[index + offset]
                if follow & 0xC0 != 0x80:
                    code, extra = 0xDC00 + lead, 0
                    break
                code = code << 6 | follow & 0x3F
        else:
            extra = 0
        codes[written] = code
        written += 1
        index += extra + 1
    return written


def estimate_strength(password: Union[str, BufferLike]) -> Strength:
    """A rough estimate, leaning low, of how hard a chosen password is to guess.

    It is an estimate from a short list of rules, not a guarantee: a password
    it calls strong can still be weak for reasons it cannot see (it has been
    leaked before, it is a quotation, a name, a word that is not in its
    lists, something about you). Use it to catch bad passwords, not to
    certify good ones. For secrets IronDome generated, use the exact figures
    from :func:`password_entropy_bits` and :func:`passphrase_entropy_bits`.

    How it counts. A character is worth log2 of the size of its class (26
    lower-case letters, 26 capitals, 10 digits, 33 symbols; characters outside
    ASCII count as lower-case letters) plus the choice of that class, and
    never more than the familiar "pool of every class used, times length".
    The choice of class is free inside a run of four or more letters of one
    case and inside a run of digits or symbols, because that is the shape of
    words and numbers. From there the estimate only goes down: a stretch is
    replaced by something cheaper when it is

    * one of a few hundred very common passwords, forwards or backwards;
    * a word of the EFF word list (log2(7776) bits, as in a passphrase);
    * either of those with capitals or look-alike characters (``p@ssw0rd``);
    * a repeated character or group (``aaaa``, ``abcabc``);
    * a run of consecutive letters or digits (``abcd``, ``9876``);
    * a run of neighbouring keys on a US keyboard (``qwerty``, ``1qaz``);
    * a year from 1900 to 2099, or a date.

    The result is the cheapest way to account for the whole password, in
    bits, labelled: under 28 "very weak", under 44 "weak", under 64 "fair",
    under 90 "strong", otherwise "very strong". The warnings say which rules
    fired and never quote the password; a password rated strong has none.
    Only the first 512 characters are examined; anything after them adds
    nothing.

    *password* may be a ``str``, or bytes in a :class:`SecureBuffer` or any
    other buffer (read as UTF-8). A buffer is examined one byte at a time
    and its decoded characters are held in locked memory that is wiped before
    returning: the password is never copied into a ``str`` or ``bytes``
    object. Numbers derived from it (costs, positions in the word list) are
    ordinary Python objects.
    """
    if isinstance(password, str):
        points = [ord(char) for char in islice(password, _ANALYSED_CHARS)]
        return _estimate(points, len(points))
    try:
        data = as_view(password).cast("B")
    except (TypeError, ValueError):
        raise UsageError("a password must be given as text or as bytes") from None
    try:
        if not len(data):
            return _estimate((), 0)
        with SecureBuffer(struct.calcsize("I") * min(len(data), _ANALYSED_CHARS)) as scratch:
            codes = scratch.view().cast("I")
            try:
                return _estimate(codes, _decode_utf8(data, codes))
            finally:
                codes.release()
    finally:
        data.release()
