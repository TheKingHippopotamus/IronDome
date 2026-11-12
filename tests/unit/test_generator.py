"""Generated secrets (what is promised about them, measured) and the strength estimate."""

from __future__ import annotations

import ast
import atexit
import collections
import dataclasses
import hashlib
import itertools
import math
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import types
import zipfile
from importlib import resources
from pathlib import Path
from typing import Dict, List, Optional

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import configuration as hypothesis_configuration
from hypothesis import strategies as st

from conftest import secret
from irondome import generator
from irondome.errors import IronDomeError, UsageError
from irondome.generator import Strength, estimate_strength


def property_settings(examples: int = 100) -> settings:
    """No example database (it would be written to the working directory) and no time limits:
    a loaded machine must not turn a correct property into a failure.
    """
    return settings(database=None, deadline=None, max_examples=examples, suppress_health_check=[HealthCheck.too_slow])


PROPERTY = property_settings()

LABELS = ("very weak", "weak", "fair", "strong", "very strong")
KNOWN_WARNINGS = {
    "it is empty",
    "it is one of the most common passwords",
    "it contains one of the most common passwords",
    "it contains dictionary words",
    "it follows keys that sit next to each other on the keyboard",
    "it contains a run of consecutive letters or digits",
    "it repeats a character or a group of characters",
    "it contains a date or a year",
    "it uses only one kind of character",
    "it is short",
}
COMMON_BITS = math.log2(len(generator._COMMON))
WORD_BITS = math.log2(7776)


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


# -- helpers ---------------------------------------------------------------------


def chi_square(counts, expected: float) -> float:
    return sum((count - expected) ** 2 / expected for count in counts)


def chi_square_limit(degrees: int) -> float:
    """A value a chi-square variable exceeds with probability below e**-50 (Laurent and Massart, 2000).

    Tests that compare against it cannot fail by chance in practice, yet a
    generator with any real bias lands far beyond it at these sample sizes.
    """
    return degrees + 2 * math.sqrt(50 * degrees) + 100


def expected_classes(
    lower=True, upper=True, digits=True, symbols=True, exclude_ambiguous=False, symbol_set=generator.DEFAULT_SYMBOLS
) -> List[str]:
    """The character classes the documented options stand for, worked out independently of the module."""
    classes = []
    if lower:
        classes.append("abcdefghijklmnopqrstuvwxyz")
    if upper:
        classes.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if digits:
        classes.append("0123456789")
    if symbols:
        classes.append("".join(sorted(set(symbol_set))))
    if exclude_ambiguous:
        classes = ["".join(char for char in chars if char not in "0Oo1lI|") for chars in classes]
    return classes


def count_strings(sizes: List[int], length: int) -> int:
    """How many strings of *length* use every class at least once, counted one position at a time."""
    states: Dict[int, int] = {0: 1}
    for _ in range(length):
        following: Dict[int, int] = collections.Counter()
        for used, ways in states.items():
            for index, size in enumerate(sizes):
                following[used | 1 << index] += ways * size
        states = following
    return states[(1 << len(sizes)) - 1]


def split_phrase(phrase: str, separator: str) -> List[str]:
    """Split a passphrase back into list words. No word starts another, so there is one way."""
    words = generator.wordlist()
    found = []
    rest = phrase
    while True:
        (word,) = [candidate for candidate in words if rest.startswith(candidate)]
        found.append(word)
        rest = rest[len(word) :]
        if not rest:
            return found
        assert rest.startswith(separator), rest
        rest = rest[len(separator) :]


def pool_bits(password: str) -> float:
    """The textbook figure: log2 of the pool of every class used, times the length."""
    pool = 0
    if any(char in string.ascii_lowercase or ord(char) > 127 for char in password):
        pool += 26
    if any(char in string.ascii_uppercase for char in password):
        pool += 26
    if any(char in string.digits for char in password):
        pool += 10
    if any(ord(char) < 128 and char not in string.ascii_letters + string.digits for char in password):
        pool += 33
    return len(password) * math.log2(pool) if pool else 0.0


def bundled_wordlist_bytes() -> bytes:
    return (resources.files("irondome") / "data" / "eff_large_wordlist.txt").read_bytes()


@pytest.fixture
def fake_wordlist(monkeypatch, tmp_path):
    """Make the module look for its word list in a directory the test controls."""

    def install(content: Optional[bytes]) -> None:
        target = tmp_path / "package" / "data" / "eff_large_wordlist.txt"
        target.parent.mkdir(parents=True, exist_ok=True)
        if content is not None:
            target.write_bytes(content)
        monkeypatch.setattr(generator, "_wordlist_file", lambda: target)
        monkeypatch.setattr(generator, "_words", None)

    return install


class CountingSecrets:
    """Stands in for the ``secrets`` module and counts what is asked of it."""

    def __init__(self) -> None:
        self.calls: Dict[str, int] = collections.Counter()
        self.sequences = []

    def choice(self, sequence):
        self.calls["choice"] += 1
        self.sequences.append(sequence)
        return secrets.choice(sequence)

    def randbelow(self, limit):
        self.calls["randbelow"] += 1
        return secrets.randbelow(limit)


# -- generate_password: what it promises -----------------------------------------


def test_default_password():
    password = generator.generate_password()
    assert len(password) == 20
    assert set(password) <= set(string.ascii_letters + string.digits + generator.DEFAULT_SYMBOLS)
    for chars in expected_classes():
        assert set(password) & set(chars)


@pytest.mark.parametrize("flags", [flags for flags in itertools.product((True, False), repeat=4) if any(flags)])
def test_every_enabled_class_appears_and_no_other(flags):
    lower, upper, digits, symbols = flags
    classes = expected_classes(lower, upper, digits, symbols)
    alphabet = set("".join(classes))
    for _ in range(300):
        password = generator.generate_password(8, lower=lower, upper=upper, digits=digits, symbols=symbols)
        assert len(password) == 8
        assert set(password) <= alphabet
        assert all(set(password) & set(chars) for chars in classes)


def test_no_class_enabled_is_refused():
    with pytest.raises(UsageError, match="at least one kind of character"):
        generator.generate_password(lower=False, upper=False, digits=False, symbols=False)
    with pytest.raises(UsageError, match="at least one kind of character"):
        generator.password_entropy_bits(lower=False, upper=False, digits=False, symbols=False)


@pytest.mark.parametrize("length", [8, 9, 20, 64, 511, 512])
def test_length_is_honoured(length):
    assert len(generator.generate_password(length)) == length


@pytest.mark.parametrize("length", [7, 0, -1, 513, 10**6, 8.0, 20.5, "20", None, True, False, [20]])
def test_length_outside_8_to_512_is_refused(length):
    with pytest.raises(UsageError, match="from 8 to 512"):
        generator.generate_password(length)
    with pytest.raises(UsageError, match="from 8 to 512"):
        generator.password_entropy_bits(length)


def test_ambiguous_characters_can_be_excluded():
    assert generator.AMBIGUOUS == "0Oo1lI|"
    seen = set()
    for _ in range(400):
        password = generator.generate_password(24, exclude_ambiguous=True, symbol_set="|!-")
        assert not set(password) & set(generator.AMBIGUOUS)
        seen |= set(password)
    assert seen == set("".join(expected_classes(exclude_ambiguous=True, symbol_set="|!-")))
    assert len(seen) == 24 + 24 + 8 + 2
    with pytest.raises(UsageError, match="look-alike"):
        generator.generate_password(exclude_ambiguous=True, symbol_set="|")
    assert "|" in generator.generate_password(64, lower=False, upper=False, digits=False, symbol_set="|")


def test_symbol_set_replaces_the_symbols():
    seen = set()
    for _ in range(300):
        seen |= set(generator.generate_password(16, symbol_set="+=?"))
    assert seen - set(string.ascii_letters + string.digits) == set("+=?")
    everything = set()
    for _ in range(300):
        everything |= set(generator.generate_password(64, symbol_set=string.punctuation))
    assert everything == set(string.ascii_letters + string.digits + string.punctuation)


def test_a_repeated_symbol_is_not_more_likely():
    counts = collections.Counter()
    for _ in range(2000):
        counts.update(generator.generate_password(32, lower=False, upper=False, digits=False, symbol_set="!!!!!!!!!?"))
    assert set(counts) == {"!", "?"}
    assert chi_square(counts.values(), sum(counts.values()) / 2) < chi_square_limit(1)


@pytest.mark.parametrize("symbol_set", ["", "abc", "!a", "!1", "! ", "!\n", "\u00a7", "!\u20ac", None, 5, ["!"], b"!"])
def test_symbol_set_must_be_ascii_punctuation(symbol_set):
    with pytest.raises(UsageError, match="symbol set"):
        generator.generate_password(symbol_set=symbol_set)
    assert len(generator.generate_password(symbols=False, symbol_set=symbol_set)) == 20  # unused, so not judged


def test_default_symbols_are_plain_punctuation():
    assert set(generator.DEFAULT_SYMBOLS) <= set(string.punctuation)
    assert len(set(generator.DEFAULT_SYMBOLS)) == len(generator.DEFAULT_SYMBOLS) == 10
    assert not set(generator.DEFAULT_SYMBOLS) & set("\"'`\\ <>")


def test_passwords_do_not_repeat():
    assert len({generator.generate_password() for _ in range(2000)}) == 2000


def test_all_randomness_comes_from_the_secrets_module(monkeypatch):
    counting = CountingSecrets()
    monkeypatch.setattr(generator, "secrets", counting)
    password = generator.generate_password(40)
    assert len(password) == 40
    assert counting.calls["choice"] >= 40 and counting.calls["choice"] % 40 == 0
    assert set(counting.calls) == {"choice"}
    alphabet = set("".join(expected_classes()))
    assert all(len(sequence) == 72 and set(sequence) == alphabet for sequence in counting.sequences)


def test_a_stuck_random_source_is_noticed(monkeypatch):
    stuck = types.SimpleNamespace(choice=lambda sequence: sequence[0])
    monkeypatch.setattr(generator, "secrets", stuck)
    monkeypatch.setattr(generator, "_MAX_DRAWS", 25)
    with pytest.raises(IronDomeError, match="random source") as caught:
        generator.generate_password()
    assert type(caught.value) is IronDomeError
    assert generator.generate_password(lower=True, upper=False, digits=False, symbols=False) == "a" * 20


def test_the_draw_limit_is_never_near_in_practice():
    """The least favourable options keep about one candidate in thirteen."""
    worst = generator.password_entropy_bits(8, symbol_set="!") - generator.entropy_bits(8, 63)
    assert 0.07 < 2**worst < 0.09
    assert (1 - 2**worst) ** generator._MAX_DRAWS < 1e-300


# -- generate_password: the distribution -------------------------------------------


@pytest.fixture(scope="module")
def sample():
    """4000 default passwords of 32 characters: 128000 characters to count."""
    return [generator.generate_password(32) for _ in range(4000)]


def test_characters_within_a_class_are_equally_likely(sample):
    counts = collections.Counter("".join(sample))
    for chars in expected_classes():
        observed = [counts[char] for char in chars]
        assert min(observed) > 0
        assert chi_square(observed, sum(observed) / len(chars)) < chi_square_limit(len(chars) - 1), chars


def test_classes_appear_in_their_share_of_the_alphabet(sample):
    counts = collections.Counter("".join(sample))
    total = sum(counts.values())
    for chars in expected_classes():
        share = sum(counts[char] for char in chars) / total
        assert abs(share - len(chars) / 72) < 0.02, chars


def test_no_position_favours_a_class(sample):
    for chars in expected_classes():
        per_position = [sum(password[position] in chars for password in sample) for position in range(32)]
        assert chi_square(per_position, sum(per_position) / 32) < chi_square_limit(31), chars


def test_no_position_favours_a_character(sample):
    for position in (0, 1, 15, 30, 31):
        counts = collections.Counter(password[position] for password in sample)
        for chars in expected_classes():
            observed = [counts[char] for char in chars]
            assert chi_square(observed, sum(observed) / len(chars)) < chi_square_limit(len(chars) - 1)


def test_every_valid_string_is_equally_likely(monkeypatch):
    """With an alphabet small enough to list every outcome, each one must come up equally often."""
    monkeypatch.setattr(generator, "MIN_LENGTH", 4)
    monkeypatch.setattr(generator, "_classes", lambda *options: ["ab", "c"])
    valid = {
        "".join(letters)
        for letters in itertools.product("abc", repeat=4)
        if "c" in letters and ("a" in letters or "b" in letters)
    }
    assert len(valid) == 64
    counts = collections.Counter(generator.generate_password(4) for _ in range(16_000))
    assert set(counts) == valid
    assert chi_square(counts.values(), 16_000 / 64) < chi_square_limit(63)
    assert generator.password_entropy_bits(4) == pytest.approx(6.0, abs=1e-12)


# -- entropy -------------------------------------------------------------------------


def test_entropy_bits():
    assert generator.entropy_bits(20, 72) == pytest.approx(20 * math.log2(72))
    assert generator.entropy_bits(1, 2) == 1.0
    assert generator.entropy_bits(0, 94) == 0.0
    assert generator.entropy_bits(10, 1) == 0.0


@pytest.mark.parametrize(("length", "size"), [(-1, 10), (True, 10), (2.0, 10), ("8", 10), (8, 0), (8, -3), (8, True),
                                               (8, 2.5), (None, 10), (8, None)])  # fmt: skip
def test_entropy_bits_refuses_nonsense(length, size):
    with pytest.raises(UsageError):
        generator.entropy_bits(length, size)


def test_password_entropy_is_the_logarithm_of_the_number_of_valid_strings():
    assert generator.password_entropy_bits() == pytest.approx(math.log2(count_strings([26, 26, 10, 10], 20)), abs=1e-9)
    assert generator.password_entropy_bits() == pytest.approx(123.2477, abs=1e-4)
    assert generator.password_entropy_bits(8) == pytest.approx(48.1382, abs=1e-4)
    assert generator.entropy_bits(8, 72) - generator.password_entropy_bits(8) == pytest.approx(1.2212, abs=1e-4)
    assert generator.entropy_bits(20, 72) - generator.password_entropy_bits(20) == pytest.approx(0.1508, abs=1e-4)
    one_class = generator.password_entropy_bits(16, upper=False, digits=False, symbols=False)
    assert one_class == pytest.approx(generator.entropy_bits(16, 26), abs=1e-9)
    longest = generator.password_entropy_bits(512)
    assert longest == pytest.approx(512 * math.log2(72), abs=1e-6) and longest <= 512 * math.log2(72)


option_sets = st.fixed_dictionaries(
    {
        "lower": st.booleans(),
        "upper": st.booleans(),
        "digits": st.booleans(),
        "symbols": st.booleans(),
        "exclude_ambiguous": st.booleans(),
        "symbol_set": st.text(alphabet=string.punctuation, min_size=1, max_size=12),
    }
).filter(lambda options: bool(expected_classes(**options)) and all(expected_classes(**options)))


@PROPERTY
@given(options=option_sets, length=st.integers(8, 64))
def test_generation_and_entropy_follow_the_options(options, length):
    classes = expected_classes(**options)
    password = generator.generate_password(length, **options)
    assert len(password) == length
    assert set(password) <= set("".join(classes))
    assert all(set(password) & set(chars) for chars in classes)
    exact = math.log2(count_strings([len(chars) for chars in classes], length))
    assert generator.password_entropy_bits(length, **options) == pytest.approx(exact, abs=1e-9)
    assert exact <= generator.entropy_bits(length, len("".join(classes))) + 1e-9


def test_passphrase_entropy():
    assert generator.passphrase_entropy_bits(6) == pytest.approx(6 * math.log2(7776))
    assert generator.passphrase_entropy_bits(6) == pytest.approx(77.5489, abs=1e-4)
    assert generator.passphrase_entropy_bits(3) == pytest.approx(38.7744, abs=1e-4)
    assert generator.passphrase_entropy_bits(6, number=True) == pytest.approx(6 * math.log2(7776) + math.log2(60))
    for words in (2, 25, 0, True, 6.0, "6", None):
        with pytest.raises(UsageError, match="from 3 to 24"):
            generator.passphrase_entropy_bits(words)


# -- the word list ----------------------------------------------------------------------


def test_wordlist_is_the_eff_large_list():
    words = generator.wordlist()
    assert len(words) == 7776 == 6**5
    assert len(set(words)) == 7776
    assert words[0] == "abacus" and words[-1] == "zoom"
    assert list(words) == sorted(words)
    assert all(re.fullmatch(r"[a-z]+(-[a-z]+)*", word) for word in words)
    assert {len(word) for word in words} == {3, 4, 5, 6, 7, 8, 9}
    assert [word for word in words if "-" in word] == ["drop-down", "felt-tip", "t-shirt", "yo-yo"]
    assert generator.wordlist() is words


def test_no_word_starts_another():
    """This is what makes a passphrase split into its words in one way only, for any separator."""
    words = generator.wordlist()
    assert not [(first, second) for first, second in zip(words, words[1:]) if second.startswith(first)]


def test_bundled_file_is_byte_for_byte_what_was_verified():
    data = bundled_wordlist_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(data).hexdigest() == generator.WORDLIST_SHA256
    assert generator.WORDLIST_SHA256 == "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
    assert len(data) == 108_800
    lines = data.decode("ascii").split("\n")
    assert lines.pop() == "" and len(lines) == 7776
    keys = ["".join(roll) for roll in itertools.product("123456", repeat=5)]
    assert keys[0] == "11111" and keys[-1] == "66666"
    assert [line.split("\t") for line in lines] == [[key, word] for key, word in zip(keys, generator.wordlist())]


def test_the_licence_note_travels_with_the_list():
    note = (resources.files("irondome") / "data" / "eff_large_wordlist.LICENSE.txt").read_text(encoding="utf-8")
    assert generator.WORDLIST_SHA256 in note
    assert "Electronic Frontier Foundation" in note
    assert "Creative Commons Attribution 3.0 United States" in note
    assert "https://creativecommons.org/licenses/by/3.0/us/" in note
    assert "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt" in note


def test_a_missing_wordlist_is_reported(fake_wordlist):
    fake_wordlist(None)
    for call in (generator.wordlist, generator.generate_passphrase, lambda: estimate_strength("whatever")):
        with pytest.raises(IronDomeError, match="word list is missing.*reinstall") as caught:
            call()
        assert type(caught.value) is IronDomeError


@pytest.mark.parametrize(
    "damage",
    [
        lambda data: data.replace(b"\tabacus\n", b"\tabacas\n"),
        lambda data: data[:-1],
        lambda data: data[: len(data) // 2],
        lambda data: data + b"66667\tzzz\n",
        lambda data: data + data,
        lambda data: b"11111\tabacus\n" * 7776,
        lambda data: data.replace(b"\t", b" "),
        lambda data: data.replace(b"\n", b"\r"),
        lambda data: b"",
        lambda data: b"\xff" * len(data),
    ],
)
def test_an_altered_wordlist_is_refused(fake_wordlist, damage):
    fake_wordlist(damage(bundled_wordlist_bytes()))
    for call in (generator.wordlist, lambda: generator.generate_passphrase(4), lambda: estimate_strength("whatever")):
        with pytest.raises(IronDomeError, match="altered or damaged") as caught:
            call()
        assert type(caught.value) is IronDomeError


def test_a_checkout_with_windows_line_endings_still_verifies(fake_wordlist):
    genuine = generator.wordlist()
    fake_wordlist(bundled_wordlist_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert generator.wordlist() == genuine


def test_the_wordlist_is_found_inside_a_zip_archive(tmp_path):
    """The same lookup an installed wheel uses, exercised through zipimport."""
    package = Path(generator.__file__).parent
    archive = tmp_path / "irondome.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for name in ("__init__.py", "errors.py", "secmem.py", "generator.py"):
            bundle.write(package / name, f"irondome/{name}")
        for name in ("eff_large_wordlist.txt", "eff_large_wordlist.LICENSE.txt"):
            bundle.write(package / "data" / name, f"irondome/data/{name}")
    script = (
        "import sys; sys.path.insert(0, sys.argv[1]); from irondome import generator; "
        "print(generator.__file__); print(len(generator.wordlist())); "
        "print(len(generator.generate_passphrase(5, separator=' ').split()))"
    )
    done = subprocess.run(
        [sys.executable, "-c", script, str(archive)], capture_output=True, text=True, timeout=300, cwd=str(tmp_path)
    )
    assert done.returncode == 0, done.stderr
    where, count, generated = done.stdout.split()
    assert where.startswith(str(archive)) and (count, generated) == ("7776", "5")


# -- generate_passphrase -------------------------------------------------------------------


def test_default_passphrase():
    phrase = generator.generate_passphrase()
    words = split_phrase(phrase, "-")
    assert len(words) == 6
    assert phrase == "-".join(words)
    assert phrase == phrase.lower()


@pytest.mark.parametrize("count", [3, 4, 6, 12, 24])
@pytest.mark.parametrize("separator", ["-", " ", "", ".", "_", "--", " - ", "/|\\", "!@#$%^&*"])
def test_passphrases_are_list_words_joined_by_the_separator(count, separator):
    phrase = generator.generate_passphrase(count, separator=separator)
    words = split_phrase(phrase, separator)
    assert len(words) == count
    assert separator.join(words) == phrase
    assert set(words) <= set(generator.wordlist())


@pytest.mark.parametrize("words", [2, 0, -6, 25, 100, 6.0, "6", None, True, [6]])
def test_word_count_outside_3_to_24_is_refused(words):
    with pytest.raises(UsageError, match="from 3 to 24"):
        generator.generate_passphrase(words)


@pytest.mark.parametrize(
    "separator",
    ["x", "1", "-a-", "\n", "\t", "\u00a0", "\u2014", "\u00e9", "-" * 9, None, 5, b"-"],
)
def test_separator_must_be_short_ascii_punctuation(separator):
    with pytest.raises(UsageError, match="separator"):
        generator.generate_passphrase(separator=separator)


def test_capitalize_and_number():
    capitalized = generator.generate_passphrase(5, separator=" ", capitalize=True)
    for word in capitalized.split(" "):
        assert word[0].isupper() and word[1:] == word[1:].lower()
        assert word.lower() in generator.wordlist()
    positions, digits = set(), set()
    for _ in range(600):
        parts = generator.generate_passphrase(3, separator=" ", number=True).split(" ")
        numbered = [index for index, part in enumerate(parts) if part[-1].isdigit()]
        assert len(numbered) == 1
        assert sum(char.isdigit() for part in parts for char in part) == 1
        assert [part.rstrip(string.digits) in generator.wordlist() for part in parts] == [True] * 3
        positions.add(numbered[0])
        digits.add(parts[numbered[0]][-1])
    assert positions == {0, 1, 2}
    assert digits == set(string.digits)
    both = generator.generate_passphrase(4, separator=".", capitalize=True, number=True)
    assert len(re.findall(r"[A-Z]", both)) == 4 and len(re.findall(r"[0-9]", both)) == 1


def test_every_word_is_drawn_from_the_whole_list(monkeypatch):
    counting = CountingSecrets()
    monkeypatch.setattr(generator, "secrets", counting)
    generator.generate_passphrase(7)
    assert counting.calls == {"choice": 7}
    assert all(sequence is generator.wordlist() for sequence in counting.sequences)
    counting.sequences.clear()
    generator.generate_passphrase(7, number=True)
    assert counting.calls == {"choice": 15, "randbelow": 1}
    assert counting.sequences[-1] == string.digits


def test_words_are_equally_likely():
    counts = collections.Counter()
    for _ in range(5000):
        counts.update(generator.generate_passphrase(24, separator=" ").split(" "))
    observed = [counts[word] for word in generator.wordlist()]
    assert sum(observed) == 120_000
    assert chi_square(observed, 120_000 / 7776) < chi_square_limit(7775)


def test_passphrases_do_not_repeat():
    assert len({generator.generate_passphrase(4) for _ in range(2000)}) == 2000


# -- generate_username ------------------------------------------------------------------------


def test_usernames():
    assert re.fullmatch(r"[a-z][a-z0-9]{9}", generator.generate_username())
    for length in (3, 4, 16, 64):
        assert re.fullmatch(r"[a-z][a-z0-9]{%d}" % (length - 1), generator.generate_username(length))
    assert len({generator.generate_username() for _ in range(2000)}) == 2000
    seen = set("".join(generator.generate_username(64) for _ in range(200)))
    assert seen == set(string.ascii_lowercase + string.digits)
    for length in (2, 0, 65, 10.0, "10", None, True):
        with pytest.raises(UsageError, match="from 3 to 64"):
            generator.generate_username(length)


# -- email_alias --------------------------------------------------------------------------------


def test_email_alias_with_a_tag():
    assert generator.email_alias("alice@example.com", "shop") == "alice+shop@example.com"
    assert generator.email_alias("  alice@example.com\n", "shop") == "alice+shop@example.com"
    assert generator.email_alias("alice+old@example.com", "new") == "alice+new@example.com"
    assert generator.email_alias("alice+a+b@example.com", "c") == "alice+c@example.com"
    assert generator.email_alias("Alice.Smith@Example.COM", "News-2026") == "Alice.Smith+News-2026@Example.COM"
    assert generator.email_alias("a.b-c_d@sub.example.co.uk", "x.y_z") == "a.b-c_d+x.y_z@sub.example.co.uk"
    assert generator.email_alias("o'brien@example.ie", "t") == "o'brien+t@example.ie"
    assert generator.email_alias("user@xn--bcher-kva.example", "t") == "user+t@xn--bcher-kva.example"
    local, domain = "\u05d3\u05e0\u05d4", "\u05d3\u05d5\u05d2\u05de\u05d4.\u05d9\u05e9\u05e8\u05d0\u05dc"
    assert generator.email_alias(f"{local}@{domain}", "t") == f"{local}+t@{domain}"


def test_email_alias_with_a_random_tag():
    aliases = {generator.email_alias("alice@example.com") for _ in range(500)}
    assert len(aliases) == 500
    assert all(re.fullmatch(r"alice\+[a-z0-9]{8}@example\.com", alias) for alias in aliases)
    assert re.fullmatch(r"alice\+[a-z0-9]{8}@example\.com", generator.email_alias("alice+old@example.com"))


@pytest.mark.parametrize(
    "address",
    [
        "",
        "alice",
        "alice@",
        "@example.com",
        "alice@example",
        "alice@@example.com",
        "alice@home@example.com",
        "alice smith@example.com",
        "alice@exa mple.com",
        "alice\t@example.com",
        ".alice@example.com",
        "alice.@example.com",
        "al..ice@example.com",
        "alice@-example.com",
        "alice@example-.com",
        "alice@example..com",
        "alice@.example.com",
        "alice@example.com.",
        "alice@example.c",
        "alice@example.123",
        "alice@[127.0.0.1]",
        "alice@exam_ple.com",
        '"alice"@example.com',
        "alice,bob@example.com",
        "alice@example.com, bob@example.com",
        "Alice <alice@example.com>",
        "a" * 65 + "@example.com",
        "alice@" + "a" * 64 + ".com",
        "alice@" + ".".join(["a" * 60] * 5),
        "alice\u00a0@example.com",
        "al\u202eice@example.com",
        None,
        5,
        b"alice@example.com",
        ["alice@example.com"],
    ],
)
def test_email_alias_refuses_what_is_not_an_address(address):
    with pytest.raises(UsageError, match="does not look like an email address") as caught:
        generator.email_alias(address, "tag")
    assert "alice" not in str(caught.value)


@pytest.mark.parametrize(
    "tag", ["", "a b", "a+b", "a@b", ".a", "a.", "a..b", "x" * 33, "t\u00e4g", "tag\n", 5, b"tag", ["t"]]
)
def test_email_alias_refuses_unusable_tags(tag):
    with pytest.raises(UsageError, match="a tag is"):
        generator.email_alias("alice@example.com", tag)


def test_email_alias_limits():
    assert generator.email_alias("alice@example.com", "x" * 32) == "alice+" + "x" * 32 + "@example.com"
    with pytest.raises(UsageError, match="nothing before"):
        generator.email_alias("+tag@example.com", "t")
    assert generator.email_alias("a" * 31 + "@example.com", "x" * 32).startswith("a" * 31 + "+" + "x" * 32 + "@")
    with pytest.raises(UsageError, match="64 characters"):
        generator.email_alias("a" * 32 + "@example.com", "x" * 32)
    with pytest.raises(UsageError, match="64 characters"):
        generator.email_alias("a" * 60 + "@example.com")


@PROPERTY
@given(
    address=st.text(max_size=40) | st.from_regex(r"[a-z+.]{1,12}@[a-z-]{1,10}(\.[a-z]{1,6}){1,3}", fullmatch=True),
    tag=st.none() | st.text(alphabet="abc.-_+@ ", max_size=8),
)
def test_email_alias_gives_a_plus_address_or_refuses(address, tag):
    try:
        alias = generator.email_alias(address, tag)
    except UsageError:
        return
    given_local, _, given_domain = address.strip().rpartition("@")
    local, at, domain = alias.rpartition("@")
    base, plus, used = local.partition("+")
    assert (at, plus, domain) == ("@", "+", given_domain)
    assert base == given_local.partition("+")[0] and "+" not in used
    assert used == tag if tag is not None else re.fullmatch(r"[a-z0-9]{8}", used)
    assert len(local) <= 64
    assert generator.email_alias(alias, used) == alias


# -- estimate_strength: the passwords it must catch -------------------------------------------


@pytest.mark.parametrize("password", ["Password1!aaaaaa", "qwerty123456"])
def test_the_two_passwords_that_must_never_look_strong(password):
    verdict = estimate_strength(password)
    assert verdict.label == "very weak"
    assert verdict.bits < 28 < pool_bits(password) / 2
    assert "it contains one of the most common passwords" in verdict.warnings


@pytest.mark.parametrize(
    "password",
    [
        "password", "PASSWORD", "Password", "123456", "123456789", "qwerty", "letmein", "iloveyou", "admin", "welcome1",
        "P@ssw0rd", "p4ssw0rd!", "Pa$$w0rd1", "passw0rd123", "drowssap", "nimda", "Summer2024!", "hunter2", "trustno1",
        "letmein2024!", "Dragon1!", "monkey123", "Welcome123!", "qwertyuiop", "1qaz2wsx3edc", "asdfghjkl;",
        "zxcvbnm,./", "mnbvcxz", "0987654321", "abcdefghijkl", "zyxwvutsrq", "aaaaaaaaaaaaaaaaaaaa", "abcabcabcabc",
        "hunter2hunter2hunter2", "a1a1a1a1a1a1", "!!!!!!!!!!!!", "111111", "8675309", "19900512", "12051990", "120590",
        "12/05/1990", "5.12.90", "1990-05-12", "2024", "Iloveyou2", "ROOT", "toor", "changeme", "Changeme123",
    ],
)  # fmt: skip
def test_very_weak_passwords(password):
    verdict = estimate_strength(password)
    assert verdict.label == "very weak", verdict
    assert verdict.warnings


@pytest.mark.parametrize(
    "password",
    ["kingHippo123", "iloveyou<3forever", "MyPassword2024", "summer-winter-spring", "Monkey!Dragon?2019",
     "qwerty-asdfgh-zxcvbn", "!QAZ@WSX#EDC"],
)  # fmt: skip
def test_weak_passwords(password):
    verdict = estimate_strength(password)
    assert verdict.label in ("very weak", "weak"), verdict
    assert verdict.warnings


@pytest.mark.parametrize(
    ("password", "labels"),
    [
        ("xkqjzvwpmhtrbnylcdfg", ("strong",)),
        ("q7#Vx2!mLp9$Zr4&", ("strong", "very strong")),
        ("XTCxD*xQw3Hn_#AaWtIO", ("very strong",)),
        ("q3D1SuEpNV7DzJUT#jZYtnGDydHp1Nh6", ("very strong",)),
        ("3f9a7c21e8b04d56a1c9", ("strong", "very strong")),
        ("550e8400-e29b-41d4-a716-446655440000", ("very strong",)),
        ("bridged-hyphen-reabsorb-curly-napping-unaware", ("strong",)),
        ("emblaze showgirl frenzy grab espresso trend roping", ("very strong",)),
        ("unblessedouttakesgossipborrowerhaiku", ("strong",)),
    ],
)
def test_strong_passwords_have_no_warnings(password, labels):
    verdict = estimate_strength(password)
    assert verdict.label in labels, verdict
    assert verdict.warnings == []


def test_generated_secrets_are_never_called_weak():
    for _ in range(100):
        assert estimate_strength(generator.generate_password(32)).label == "very strong"
        assert estimate_strength(generator.generate_passphrase(10)).label in ("strong", "very strong")
        assert estimate_strength(generator.generate_passphrase(24, separator="")).label == "very strong"


def test_a_generated_passphrase_is_rated_close_to_its_real_entropy():
    for words in (4, 6, 8):
        exact = generator.passphrase_entropy_bits(words)
        for separator in ("-", " ", ""):
            verdicts = [estimate_strength(generator.generate_passphrase(words, separator=separator)) for _ in range(40)]
            # Never above the real figure by more than the separators' few bits; below it only
            # when a list word is also a very common password or is drawn twice in a row.
            assert all(verdict.bits <= exact + 2.4 + 0.5 * (words - 2) + 0.05 for verdict in verdicts)
            assert sum(verdict.bits >= exact - 0.05 for verdict in verdicts) >= 20


# -- estimate_strength: how it counts ------------------------------------------------------------


def test_common_passwords_cost_the_size_of_the_list():
    assert estimate_strength("password").bits == round(COMMON_BITS, 1)
    assert estimate_strength("password") == Strength(
        round(COMMON_BITS, 1),
        "very weak",
        ["it is one of the most common passwords", "it uses only one kind of character", "it is short"],
    )
    assert estimate_strength("Password").bits == round(COMMON_BITS + 1, 1)
    assert estimate_strength("PASSWORD").bits == round(COMMON_BITS + 1, 1)
    assert estimate_strength("pAsSwOrD").bits == round(COMMON_BITS + 5, 1)
    assert estimate_strength("drowssap").bits == round(COMMON_BITS + 1, 1)
    assert estimate_strength("p4ssword").bits == round(COMMON_BITS + 1, 1)
    assert estimate_strength("pa55w0rd").bits == round(COMMON_BITS + 1, 1)
    assert estimate_strength("passwordpassword").bits == round(COMMON_BITS + 1, 1)
    assert estimate_strength("passwordpasswordpasswordpassword").bits == round(COMMON_BITS + 2, 1)


def test_look_alike_characters_do_not_hide_a_word():
    for disguised in ("l3tm31n", "L3tMe1n", "!loveyou", "adm1n", "@dm!n", "h3llo", "he11o", "$ecret", "5un5h1n3"):
        verdict = estimate_strength(disguised)
        assert verdict.bits < 2 * COMMON_BITS, (disguised, verdict)
        assert "one of the most common passwords" in " ".join(verdict.warnings)


def test_dictionary_words_cost_a_roll_of_five_dice():
    assert estimate_strength("abacus").bits == round(WORD_BITS, 1)
    assert estimate_strength("Abacus").bits == round(WORD_BITS + 1, 1)
    assert estimate_strength("abacuszoom").bits == round(2 * WORD_BITS, 1)
    assert estimate_strength("drop-down").bits == round(WORD_BITS, 1)
    assert estimate_strength("4b4cu5").bits == round(WORD_BITS + 1, 1)
    assert estimate_strength("abacus").warnings == [
        "it contains dictionary words", "it uses only one kind of character", "it is short",
    ]  # fmt: skip
    spaced = estimate_strength("abacus zoom yo-yo unaware")
    assert spaced.bits == round(4 * WORD_BITS + math.log2(5) + 2 * 0.5, 1)


def test_what_holds_a_passphrase_together_is_cheap():
    plain = estimate_strength("abacuszoomunaware").bits
    for separator in " -_.,":
        joined = estimate_strength(separator.join(["abacus", "zoom", "unaware"])).bits
        assert joined == pytest.approx(plain + math.log2(5) + 0.5, abs=0.11)
    assert estimate_strength("abacus#zoom#unaware").bits < plain + 8


def test_repeats_cost_one_unit_and_a_count():
    assert estimate_strength("aaaa").bits == pytest.approx(math.log2(26) + 2, abs=0.05)
    assert estimate_strength("a" * 64).bits == pytest.approx(math.log2(26) + 6, abs=0.05)
    assert estimate_strength("abababab").bits < estimate_strength("ab").bits + 2.1
    once = estimate_strength("xk#9").bits
    assert estimate_strength("xk#9xk#9xk#9").bits == pytest.approx(once + math.log2(3), abs=0.11)
    for password in ("aaaa", "a" * 64, "abababab", "xk#9xk#9xk#9", "\u00e9" * 9, "\u05d0\u05d1" * 6):
        assert "it repeats a character or a group of characters" in estimate_strength(password).warnings
    assert "it repeats a character or a group of characters" not in estimate_strength("aa").warnings


def test_sequences_keyboard_runs_and_dates_are_recognised():
    for password in ("abcdefgh", "hgfedcba", "ABCDEF", "3456789", "wxyz", "cba"):
        assert "it contains a run of consecutive letters or digits" in estimate_strength(password).warnings, password
    for password in ("vbnm,.", "poiuyt", "1qaz", "zaq1", "MNBVCX", "qazse4", "plokij", "}{POIU"):
        verdict = estimate_strength(password)
        assert "it follows keys that sit next to each other on the keyboard" in verdict.warnings, password
        assert verdict.bits < 20
    for password in ("1983", "2031", "31121999", "12311999", "19991231", "311299", "991204", "31/12/1999", "1.2.03",
                     "2003-02-01", "x1999y", "born31.12.1999!"):  # fmt: skip
        assert "it contains a date or a year" in estimate_strength(password).warnings, password
    for password in ("1899", "2100", "7391", "99/99/9999", "32/13/7777", "45.67.89", "1-2", "12/34"):
        assert "it contains a date or a year" not in estimate_strength(password).warnings, password
    # A cheaper reading wins: 1987 is a 1 and the run 987, which costs less than a year.
    assert estimate_strength("1987").warnings[0] == "it contains a run of consecutive letters or digits"
    for password in ("qwe", "zxc", "xqz", "aXb"):
        assert "it follows keys that sit next to each other on the keyboard" not in estimate_strength(password).warnings


def test_words_cost_less_than_the_same_number_of_random_letters():
    assert estimate_strength("Tr0ub4dor&3").bits <= pool_bits("Tr0ub4dor&3")
    assert estimate_strength("Troubadour2024!").bits < pool_bits("Troubadour2024!") - 30
    assert estimate_strength("kzvtqwxj").bits == pytest.approx(8 * math.log2(26), abs=0.05)
    # The capital and the letter after it each cost the choice between two classes; the rest is a word-like run.
    assert estimate_strength("Kzvtqwxj").bits == pytest.approx(8 * math.log2(26) + 2, abs=0.05)


def test_empty_and_tiny():
    assert estimate_strength("") == Strength(0.0, "very weak", ["it is empty"])
    assert estimate_strength(b"") == Strength(0.0, "very weak", ["it is empty"])
    assert estimate_strength("a") == Strength(4.7, "very weak", ["it is short"])
    assert estimate_strength("7") == Strength(3.3, "very weak", ["it is short"])
    assert estimate_strength(" ").label == "very weak"


def test_labels_follow_the_documented_limits():
    expected = [(0, "very weak"), (27.9, "very weak"), (28, "weak"), (43.9, "weak"), (44, "fair"), (63.9, "fair"),
                (64, "strong"), (89.9, "strong"), (90, "very strong"), (4096.0, "very strong"),
                (float("inf"), "very strong")]  # fmt: skip
    for bits, label in expected:
        assert generator.strength_label(bits) == label
    for nonsense in (-0.1, float("nan"), "64", None, True, [64]):
        with pytest.raises(UsageError):
            generator.strength_label(nonsense)
    assert generator.strength_label(generator.password_entropy_bits()) == "very strong"
    assert generator.strength_label(generator.passphrase_entropy_bits(6)) == "strong"


def test_strength_is_immutable():
    verdict = estimate_strength("password")
    with pytest.raises(dataclasses.FrozenInstanceError):
        verdict.bits = 128.0


def test_only_the_first_512_characters_are_examined():
    start = generator.generate_password(512)
    assert estimate_strength(start + "x" * 5000) == estimate_strength(start)
    assert estimate_strength((start + "x" * 5000).encode()) == estimate_strength(start)
    floods = ("a" * 100_000, "ab" * 50_000, "qwerty" * 20_000, "1/1/11" * 20_000, "\u00e9" * 100_000, "aB3$" * 30_000)
    for flood in floods:
        assert estimate_strength(flood).bits < 44
        assert estimate_strength(flood.encode("utf-8")).bits < 44


# -- estimate_strength: any input --------------------------------------------------------------


@property_settings(80)
@given(password=st.text(max_size=80))
def test_any_text_gets_a_bounded_and_consistent_verdict(password):
    verdict = estimate_strength(password)
    assert verdict.label in LABELS
    assert verdict.label == generator.strength_label(verdict.bits)
    assert 0 <= verdict.bits <= pool_bits(password) + 0.05
    assert verdict.bits == round(verdict.bits, 1)
    assert set(verdict.warnings) <= KNOWN_WARNINGS
    assert len(verdict.warnings) == len(set(verdict.warnings))
    if verdict.label in ("strong", "very strong"):
        assert verdict.warnings == []
    assert estimate_strength(password) == verdict


@PROPERTY
@given(password=st.text(alphabet=st.sampled_from("aA1! qQwWeE-_.9@$0oOlL|\u00e9\u05d0"), max_size=40))
def test_any_text_made_of_the_characters_the_rules_look_at(password):
    verdict = estimate_strength(password)
    assert 0 <= verdict.bits <= pool_bits(password) + 0.05
    assert set(verdict.warnings) <= KNOWN_WARNINGS
    assert estimate_strength(password.encode("utf-8")) == verdict


@property_settings(60)
@given(password=st.text(max_size=600))
def test_text_and_its_utf8_bytes_get_the_same_verdict(password):
    verdict = estimate_strength(password)
    encoded = password.encode("utf-8")
    assert estimate_strength(encoded) == verdict
    assert estimate_strength(bytearray(encoded)) == verdict
    assert estimate_strength(memoryview(encoded)) == verdict
    if encoded:
        with secret(password) as locked:
            assert estimate_strength(locked) == verdict
            assert not locked.wiped, "the caller's buffer is the caller's to wipe"


@PROPERTY
@given(data=st.binary(max_size=200))
def test_any_bytes_get_a_verdict(data):
    verdict = estimate_strength(data)
    assert verdict.label in LABELS and verdict.bits >= 0
    assert set(verdict.warnings) <= KNOWN_WARNINGS


@pytest.mark.parametrize("not_a_password", [None, 5, 5.0, ["password"], ("p",), {"p": 1}, object()])
def test_what_is_neither_text_nor_bytes_is_refused(not_a_password):
    with pytest.raises(UsageError, match="text or as bytes"):
        estimate_strength(not_a_password)


def test_a_wiped_buffer_is_refused():
    locked = secret("correct horse battery staple")
    locked.wipe()
    with pytest.raises(UsageError, match="text or as bytes"):
        estimate_strength(locked)


def test_warnings_never_quote_the_password():
    for password in ("hunter2hunter2", "Summer2024!", "qwerty123456", "abacus-zoom", "31/12/1999", "zxcvbnm"):
        text = " ".join(estimate_strength(password).warnings).lower()
        assert text
        for size in range(4, len(password) + 1):
            for start in range(len(password) - size + 1):
                assert password[start : start + size].lower() not in text


# -- estimate_strength: a password in locked memory stays there -----------------------------------


class OneAtATime:
    """A sequence that can only be asked for one item by position, as the estimator promises to."""

    def __init__(self, items):
        self._items = list(items)
        self.reads = 0

    def __getitem__(self, index):
        if not isinstance(index, int):
            raise TypeError("the password must be read one character at a time")
        self.reads += 1
        return self._items[index]

    def __iter__(self):
        raise TypeError("the password must not be iterated into a copy")

    def __len__(self):
        raise TypeError("the length is passed separately")


@pytest.mark.parametrize(
    "password",
    ["Password1!aaaaaa", "qwerty123456", "correct horse battery staple", "Tr0ub4dor&3", "12/05/1990 abcabc zxcvbnm",
     "\u05e1\u05d9\u05e1\u05de\u05d4 \u05d7\u05d6\u05e7\u05d4", "XTCxD*xQw3Hn_#AaWtIO"],
)  # fmt: skip
def test_the_password_is_only_ever_read_one_character_at_a_time(password):
    codes = [ord(char) for char in password]
    watched = OneAtATime(codes)
    assert generator._estimate(watched, len(codes)) == estimate_strength(password)
    assert watched.reads > len(codes)


def test_a_buffer_is_decoded_into_locked_memory_that_is_wiped(monkeypatch):
    password = "Tr0ub4dor&3 \u05d0"
    made = []
    seen = []

    class Watched(generator.SecureBuffer):
        def __init__(self, size):
            super().__init__(size)
            made.append(self)

    real = generator._estimate

    def watching(codes, count):
        seen.append((type(codes), codes.format, made[-1].wiped, [codes[index] for index in range(count)]))
        return real(codes, count)

    monkeypatch.setattr(generator, "SecureBuffer", Watched)
    monkeypatch.setattr(generator, "_estimate", watching)
    with secret(password) as locked:
        verdict = estimate_strength(locked)
    assert verdict == real([ord(char) for char in password], len(password))
    assert seen == [(memoryview, "I", False, [ord(char) for char in password])], "it must read a view of locked memory"
    assert len(made) == 1 and made[0].wiped
    assert len(made[0]) == 4 * len(password.encode("utf-8"))


def test_locked_memory_is_wiped_when_estimating_fails(monkeypatch):
    made = []

    class Watched(generator.SecureBuffer):
        def __init__(self, size):
            super().__init__(size)
            made.append(self)

    def failing(codes, count):
        raise RuntimeError("no estimate today")

    monkeypatch.setattr(generator, "SecureBuffer", Watched)
    monkeypatch.setattr(generator, "_estimate", failing)
    with secret("correct horse battery staple") as locked:
        with pytest.raises(RuntimeError):
            estimate_strength(locked)
        assert not locked.wiped
        assert bytes(locked.view()) == b"correct horse battery staple"
    assert len(made) == 1 and made[0].wiped


@PROPERTY
@given(text=st.text(max_size=100))
def test_utf8_is_decoded_like_python_decodes_it(text):
    encoded = text.encode("utf-8")
    room = memoryview(bytearray(4 * max(len(text), 1))).cast("I")
    count = generator._decode_utf8(memoryview(encoded), room)
    assert [room[index] for index in range(count)] == [ord(char) for char in text]


@PROPERTY
@given(data=st.binary(max_size=100), room=st.integers(1, 100))
def test_any_bytes_decode_to_no_more_characters_than_bytes(data, room):
    codes = memoryview(bytearray(4 * room)).cast("I")
    count = generator._decode_utf8(memoryview(data), codes)
    assert count <= min(len(data), room)
    if room >= len(data):
        valid = data.decode("utf-8", "ignore")
        assert count >= len(valid)
        if valid.encode("utf-8") == data:
            assert [codes[index] for index in range(count)] == [ord(char) for char in valid]


@pytest.mark.parametrize(
    ("data", "characters"),
    [
        (b"\xff", 1),
        (b"\x80\x80", 2),
        (b"\xc3", 1),
        (b"\xc3(", 2),
        (b"\xe2\x82", 2),
        (b"\xf0\x9f\x98", 3),
        (b"a\xffb", 3),
        (b"\xc0\xaf", 2),
        (b"\xf5\x80\x80\x80", 4),
        (b"\xe2\x82\xac", 1),
        (b"\xf0\x9f\x98\x80", 1),
    ],
)
def test_bytes_that_are_not_utf8_count_one_character_each(data, characters):
    codes = memoryview(bytearray(4 * 8)).cast("I")
    assert generator._decode_utf8(memoryview(data), codes) == characters
    assert estimate_strength(data).label == "very weak"


# -- estimate_strength: the word lookup ----------------------------------------------------------


@property_settings(40)
@given(
    pieces=st.lists(st.sampled_from(generator.wordlist()[::97]) | st.text(alphabet="abcdest-", max_size=4), max_size=4)
)
def test_word_lookup_finds_exactly_the_words_that_are_there(pieces):
    text = "".join(pieces)
    codes = [ord(char) for char in text]
    words = generator.wordlist()
    for start in range(len(text)):
        found = set(generator._word_ends(codes, len(codes), start, words, generator._PLAIN))
        assert found == {start + len(word) for word in words if text.startswith(word, start)}


def test_word_lists_are_sorted_and_free_of_duplicates():
    for words in (generator._COMMON, generator._COMMON_REVERSED, generator.wordlist()):
        assert list(words) == sorted(set(words))
    assert 400 <= len(generator._COMMON) <= 1000
    assert all(3 <= len(word) <= 16 and word == word.lower() and word.isascii() for word in generator._COMMON)
    assert not set(generator._COMMON_REVERSED) & set(generator._COMMON)
    for known in ("password", "123456", "qwerty", "letmein", "admin", "iloveyou", "p@ssw0rd"):
        assert known in generator._COMMON
    assert "drowssap" in generator._COMMON_REVERSED and "nimda" in generator._COMMON_REVERSED


def test_keyboard_layout_is_complete():
    assert len(generator._KEYS) == 94 and len(generator._SHIFTED) == 47
    assert set(map(chr, generator._KEYS)) == set(string.ascii_letters + string.digits + string.punctuation)
    assert generator._key_move(ord("q"), ord("w")) == (0, 1)
    assert generator._key_move(ord("w"), ord("q")) == (0, -1)
    assert generator._key_move(ord("q"), ord("a")) == (1, 1)
    assert generator._key_move(ord("a"), ord("q")) == (-1, -1)
    assert generator._key_move(ord("w"), ord("a")) == (1, -1)
    assert generator._key_move(ord("1"), ord("q")) == (1, 1)
    assert generator._key_move(ord("2"), ord("q")) == (1, -1)
    assert generator._key_move(ord("Q"), ord("@")) == (-1, 1)
    assert generator._key_move(ord("a"), ord("z")) == (1, 1)
    for apart in ("qe", "qs", "ax", "aa", "q ", "1a", "pa", "m1", "a\u00e9"):
        assert generator._key_move(ord(apart[0]), ord(apart[1])) is None, apart


# -- the module itself -------------------------------------------------------------------------------


def test_the_module_imports_nothing_that_can_reach_a_network():
    tree = ast.parse(Path(generator.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module)
    assert imported == {
        "__future__",
        "dataclasses",
        "hashlib",
        "importlib",
        "itertools",
        "math",
        "secrets",
        "string",
        "struct",
        "typing",
        "irondome.errors",
        "irondome.secmem",
    }


def test_the_sources_hold_no_hidden_characters():
    """Invisible and look-alike characters cannot hide in plain ASCII, so that is all these files hold."""
    for path in (Path(generator.__file__), Path(__file__)):
        assert path.read_bytes().isascii(), path.name


def test_public_names():
    assert set(generator.__all__) >= {
        "DEFAULT_SYMBOLS",
        "Strength",
        "generate_password",
        "generate_passphrase",
        "generate_username",
        "email_alias",
        "entropy_bits",
        "passphrase_entropy_bits",
        "estimate_strength",
    }
    assert all(hasattr(generator, name) for name in generator.__all__)
    assert (generator.MIN_LENGTH, generator.MAX_LENGTH, generator.MIN_WORDS, generator.MAX_WORDS) == (8, 512, 3, 24)
    assert [field.name for field in dataclasses.fields(Strength)] == ["bits", "label", "warnings"]
