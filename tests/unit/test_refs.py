"""Secret references, env files and injection plans (irondome.agent.refs)."""

from __future__ import annotations

import re
import time
from typing import Dict, List

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from irondome.agent import refs
from irondome.agent.refs import (
    CONTROL_VARIABLES,
    SCHEME,
    InjectionPlan,
    format_reference,
    is_reference,
    parse_env_file,
    parse_reference,
    plan_injection,
    resolve_plan,
)
from irondome.errors import NotFoundError, PolicyError, UsageError
from irondome.vault import Secret

#: Stands in for a secret that must never be echoed back in an error message.
CANARY = "hunter2-CANARY-s3cret"

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

names = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc", "Zl", "Zp")), min_size=1, max_size=60
).filter(lambda text: text == text.strip() and not text.lower().startswith(SCHEME))
fields = st.from_regex(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", fullmatch=True)


# ---------------------------------------------------------------------------
# is_reference
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["irondome://github", "irondome://", "IRONDOME://GITHUB_TOKEN", "IronDome://a/b", "irondome://%zz"],
)
def test_is_reference_accepts_the_scheme_in_any_case(value: str) -> None:
    assert is_reference(value)


@pytest.mark.parametrize(
    "value",
    ["", "github", "irondome:/github", "irondome:github", " irondome://github", "xirondome://a", "https://irondome://",
     None, 7, b"irondome://github", ["irondome://github"]],
)
def test_is_reference_rejects_everything_else(value: object) -> None:
    assert not is_reference(value)


# ---------------------------------------------------------------------------
# parse_reference
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "bare"),
    [
        ("irondome://GITHUB_TOKEN", "GITHUB_TOKEN"),
        ("irondome://github", "github"),
        ("irondome://github/password", "github/password"),
        ("irondome://aws/prod/region", "aws/prod/region"),
        ("irondome://aws%2Fprod/region", "aws/prod/region"),
        ("irondome://aws%2fprod/region", "aws/prod/region"),
        ("irondome://My%20Bank/password", "My Bank/password"),
        ("irondome://My Bank/password", "My Bank/password"),
        ("IRONDOME://github", "github"),
        ("IronDome://github", "github"),
        ("irondome://100%25", "100%"),
        ("irondome://caf%C3%A9", "café"),
        ("irondome://café", "café"),
        ("irondome://a+b", "a+b"),
        ("irondome://what?", "what?"),
        ("irondome://entry#1", "entry#1"),
        ("irondome:///leading", "/leading"),
        ("irondome://%E2%82%AC", "€"),
        # Without the scheme the text is already a bare reference: nothing is decoded.
        ("github", "github"),
        ("My Bank/password", "My Bank/password"),
        ("50%", "50%"),
        ("a%20b", "a%20b"),
        ("aws/prod/region", "aws/prod/region"),
    ],
)
def test_parse_reference(text: str, bare: str) -> None:
    assert parse_reference(text) == bare


@pytest.mark.parametrize(
    "text",
    [
        "",
        "irondome://",
        "IRONDOME://",
        "irondome://%",
        "irondome://a%",
        "irondome://a%2",
        "irondome://a%zz",
        "irondome://a%2g",
        "irondome://a%+1",
        "irondome://%ff",  # not UTF-8
        "irondome://%C3",  # truncated UTF-8
        "irondome://a%00b",  # control characters can never be in a name
        "irondome://a%0Ab",
        "irondome://a%7Fb",
        "irondome://a%C2%85b",  # a C1 control character
        "irondome://a%E2%80%A8b",  # U+2028, the line separator
        "a\u2029b",
        "a\x9fb",
        "irondome://%20padded",
        "irondome://padded%20",
        "irondome:// padded",
        "irondome://irondome://github",
        "irondome://IRONDOME%3A//github",
        " github",
        "github ",
        "git\nhub",
        "git\x00hub",
        "\tgithub",
        "irondome://\ud800",  # a lone surrogate is not text
        "lone\udc80surrogate",
        "irondome://%ED%A0%80",
        pytest.param("x" * 513, id="513 characters"),
        pytest.param("irondome://" + "x" * 513, id="scheme and 513 characters"),
        pytest.param("irondome://" + "%41" * 5000, id="5000 escapes"),
    ],
)
def test_parse_reference_rejects_malformed(text: str) -> None:
    with pytest.raises(UsageError):
        parse_reference(text)


@pytest.mark.parametrize("value", [None, 7, b"irondome://github", ["github"], 1.5])
def test_parse_reference_rejects_non_text(value: object) -> None:
    with pytest.raises(UsageError):
        parse_reference(value)  # type: ignore[arg-type]


def test_parse_reference_accepts_the_longest_name_and_field_a_vault_can_hold() -> None:
    longest = "n" * 200 + "/" + "f" * 64
    assert parse_reference(longest) == longest
    assert parse_reference(SCHEME + longest) == longest
    assert parse_reference(SCHEME + "%6E" * 200) == "n" * 200


@pytest.mark.parametrize(
    "text",
    [f"irondome://{CANARY}%", f"irondome://{CANARY}%zz", f" {CANARY}", f"{CANARY}\n", f"irondome://%20{CANARY}"],
)
def test_parse_reference_errors_do_not_echo_the_text(text: str) -> None:
    # Someone who passes the secret itself by mistake must not see it repeated on stderr.
    with pytest.raises(UsageError) as caught:
        parse_reference(text)
    assert CANARY not in str(caught.value)


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=80))
def test_parse_reference_never_raises_anything_but_usage_error(text: str) -> None:
    for candidate in (text, SCHEME + text):
        try:
            bare = parse_reference(candidate)
        except UsageError:
            continue
        assert bare and bare == bare.strip() and len(bare) <= 512
        assert not any(ord(char) < 32 or 0x7F <= ord(char) <= 0x9F or ord(char) in (0x2028, 0x2029) for char in bare)
        assert not is_reference(bare)


# ---------------------------------------------------------------------------
# format_reference
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "field", "expected"),
    [
        ("GITHUB_TOKEN", None, "irondome://GITHUB_TOKEN"),
        ("github", "password", "irondome://github/password"),
        ("aws/prod", "region", "irondome://aws/prod/region"),
        ("My Bank", None, "irondome://My%20Bank"),
        ("My Bank", "totp", "irondome://My%20Bank/totp"),
        ("100%", None, "irondome://100%25"),
        ("café", None, "irondome://caf%C3%A9"),
        ("me@example.com", "password", "irondome://me@example.com/password"),
        ("https://github.com", None, "irondome://https://github.com"),
        ("it's \"quoted\" $HOME `x` #1", None, "irondome://it%27s%20%22quoted%22%20%24HOME%20%60x%60%20%231"),
        ("a=b&c", "api.key-2", "irondome://a%3Db%26c/api.key-2"),
    ],
)
def test_format_reference(name: str, field: object, expected: str) -> None:
    assert format_reference(name, field) == expected  # type: ignore[arg-type]
    assert parse_reference(expected) == (name if field is None else f"{name}/{field}")


@pytest.mark.parametrize(
    ("name", "field"),
    [
        ("", None),
        (" padded", None),
        ("padded ", None),
        ("new\nline", None),
        ("nul\x00", None),
        ("irondome://nested", None),
        pytest.param("x" * 513, None, id="name of 513 characters"),
        pytest.param("x" * 500, "f" * 20, id="name and field of 521 characters"),
        (None, None),
        (b"github", None),
        ("github", ""),
        ("github", "bad field"),
        ("github", "1starts-with-digit"),
        ("github", "a/b"),
        pytest.param("github", "f" * 65, id="field of 65 characters"),
        ("github", "field\n"),
        ("github", 7),
        ("lone\ud800surrogate", None),
    ],
)
def test_format_reference_rejects_what_cannot_be_referenced(name: object, field: object) -> None:
    with pytest.raises(UsageError):
        format_reference(name, field)  # type: ignore[arg-type]


@settings(max_examples=250, deadline=None)
@given(names, st.none() | fields)
def test_format_then_parse_is_the_identity(name: str, field: object) -> None:
    reference = format_reference(name, field)  # type: ignore[arg-type]
    # One token: nothing a shell, an env file or a JSON string would need quoted.
    assert re.fullmatch(r"irondome://[A-Za-z0-9._~/@:+,%-]+", reference)
    assert is_reference(reference)
    assert parse_reference(reference) == (name if field is None else f"{name}/{field}")
    # ... and it survives being written to an env file unquoted.
    assert parse_env_file(f"VAR={reference}\n") == {"VAR": reference}


def _accepts(check, text: str) -> bool:
    try:
        check(text)
    except UsageError:
        return False
    return True


@settings(max_examples=400, deadline=None)
@given(st.text(max_size=40) | st.text(max_size=40).map(lambda text: SCHEME + text))
def test_references_follow_the_same_rule_as_the_vault_and_as_grants(text: str) -> None:
    from irondome import caps
    from irondome.vault import validate_name

    # Bare text is a well-formed reference exactly when a vault would accept it as an entry name
    # (references may be longer than a name, because of the "/field" part).
    if not is_reference(text) and len(text) <= 200:
        assert _accepts(parse_reference, text) == _accepts(validate_name, text)
    # A grant names its values by the same strings: what it accepts, parse_reference accepts
    # (it is stricter only in rejecting broken percent-escapes), and they agree on the result
    # wherever nothing is percent-encoded.
    if _accepts(parse_reference, text) and "%" not in text:
        assert caps._reference(text) == parse_reference(text)
    if not _accepts(caps._reference, text):
        assert not _accepts(parse_reference, text) or "%" in text


def test_references_resolve_against_a_real_vault(make_vault) -> None:
    vault, _ = make_vault()
    bank = vault.add("My Bank", Secret(password="bank-password-1", fields={"pin.code": "4321"}))
    vault.add("aws/prod", Secret(password="aws-password-2", fields={"region": "eu-west-1"}), kind="secret")
    vault.add("100% café", Secret(password="cafe-password-3"))
    vault.set_alias("BANK_PIN", bank, "pin.code")
    vault.commit()

    def lookup(reference: str) -> str:
        entry, field = vault.resolve(reference)
        return vault.value(entry, field)

    cases = {
        format_reference("My Bank"): "bank-password-1",
        format_reference("My Bank", "pin.code"): "4321",
        format_reference("aws/prod"): "aws-password-2",
        format_reference("aws/prod", "region"): "eu-west-1",
        format_reference("100% café"): "cafe-password-3",
        format_reference("BANK_PIN"): "4321",
        "irondome://aws%2Fprod/region": "eu-west-1",
        "IRONDOME://BANK_PIN": "4321",
    }
    for reference, value in cases.items():
        assert lookup(parse_reference(reference)) == value, reference
    with pytest.raises(NotFoundError):
        lookup(parse_reference("irondome://no-such-entry"))


# ---------------------------------------------------------------------------
# parse_env_file: what is accepted
# ---------------------------------------------------------------------------

ENV_CASES = [
    ("", {}),
    ("\n\n  \n\t\n", {}),
    ("# only a comment", {}),
    ("   # indented comment\n", {}),
    ("A=1", {"A": "1"}),
    ("A=1\n", {"A": "1"}),
    ("A=1\r\nB=2\r\n", {"A": "1", "B": "2"}),
    ("A=1\rB=2\r", {"A": "1", "B": "2"}),
    ("A=1\n\nB=2", {"A": "1", "B": "2"}),
    ("_A1=x\na_b=y\nZ9=z", {"_A1": "x", "a_b": "y", "Z9": "z"}),
    # export and blanks
    ("export A=1", {"A": "1"}),
    ("export\tA=1", {"A": "1"}),
    ("  export   A=1", {"A": "1"}),
    ("export=1", {"export": "1"}),
    ("exported=1", {"exported": "1"}),
    ("  A=1  ", {"A": "1"}),
    ("A = 1", {"A": "1"}),
    ("A\t=\t1", {"A": "1"}),
    ("A=", {"A": ""}),
    ("A=   ", {"A": ""}),
    ("A=\nB=2", {"A": "", "B": "2"}),
    # later lines win
    ("A=1\nA=2", {"A": "2"}),
    ("A=1\nB=2\nA=3", {"A": "3", "B": "2"}),
    # unquoted values
    ("A=hello world", {"A": "hello world"}),
    ("A=a=b=c", {"A": "a=b=c"}),
    ("A==", {"A": "="}),
    ("A=it's", {"A": "it's"}),
    ('A=say "hi"', {"A": 'say "hi"'}),
    ("A=C:\\path\\n", {"A": "C:\\path\\n"}),
    ("A=$HOME/${X}", {"A": "$HOME/${X}"}),
    ("A=$(whoami)`id`", {"A": "$(whoami)`id`"}),
    ("A=irondome://github/password", {"A": "irondome://github/password"}),
    ("A=irondome://My Bank/pin", {"A": "irondome://My Bank/pin"}),
    # comments: only after a blank
    ("A=1 # comment", {"A": "1"}),
    ("A=1\t# comment", {"A": "1"}),
    ("A=1 #", {"A": "1"}),
    ("A=1#not-a-comment", {"A": "1#not-a-comment"}),
    ("A=#not-a-comment", {"A": "#not-a-comment"}),
    ("A= # comment", {"A": ""}),
    ("A=a # b # c", {"A": "a"}),
    ("A=url#frag # comment", {"A": "url#frag"}),
    ("A=1 # comment\nB=2", {"A": "1", "B": "2"}),
    ("# A=1\nB=2", {"B": "2"}),
    # single quotes: literal
    ("A='x'", {"A": "x"}),
    ("A=''", {"A": ""}),
    ("A='  spaced  '", {"A": "  spaced  "}),
    ("A='a # b'", {"A": "a # b"}),
    ("A='$HOME \\n \"q\"'", {"A": '$HOME \\n "q"'}),
    ("A='x' # comment", {"A": "x"}),
    ("A='x'   ", {"A": "x"}),
    ("A='line1\nline2'\nB=2", {"A": "line1\nline2", "B": "2"}),
    ("A = 'x'", {"A": "x"}),
    # double quotes: escapes
    ('A="x"', {"A": "x"}),
    ('A=""', {"A": ""}),
    ('A="  spaced  "', {"A": "  spaced  "}),
    ('A="a # b"', {"A": "a # b"}),
    ('A="a\\nb"', {"A": "a\nb"}),
    ('A="a\\tb\\rc"', {"A": "a\tb\rc"}),
    ('A="a\\\\b"', {"A": "a\\b"}),
    ('A="say \\"hi\\""', {"A": 'say "hi"'}),
    ('A="\\$HOME \\`id\\`"', {"A": "$HOME `id`"}),
    ('A="$HOME ${X} $(id)"', {"A": "$HOME ${X} $(id)"}),
    ('A="it\'s"', {"A": "it's"}),
    ('A="\\d+ \\x41 \\\'"', {"A": "\\d+ \\x41 \\'"}),
    ('A="\\\\n"', {"A": "\\n"}),
    ('A="x" # comment', {"A": "x"}),
    ('A="x"\t#c\nB=2', {"A": "x", "B": "2"}),
    ('A="line1\nline2"\nB=2', {"A": "line1\nline2", "B": "2"}),
    ('A="line1\r\nline2"\r\nB=2', {"A": "line1\r\nline2", "B": "2"}),
    (
        'A="-----BEGIN KEY-----\nabc\n-----END KEY-----"\nB=2',
        {"A": "-----BEGIN KEY-----\nabc\n-----END KEY-----", "B": "2"},
    ),
    ('A="{\\"k\\": \\"v\\"}"', {"A": '{"k": "v"}'}),
    ('export A="x y" # c', {"A": "x y"}),
    # other text
    ("A=ünïcödé ✓", {"A": "ünïcödé ✓"}),
    ("\ufeffA=1\nB=2", {"A": "1", "B": "2"}),
]


@pytest.mark.parametrize(("text", "expected"), ENV_CASES)
def test_parse_env_file(text: str, expected: Dict[str, str]) -> None:
    assert parse_env_file(text) == expected


def test_parse_env_file_keeps_the_order_of_the_file() -> None:
    assert list(parse_env_file("B=1\nA=2\nC=3\n")) == ["B", "A", "C"]


# ---------------------------------------------------------------------------
# parse_env_file: what is refused, and how it is reported
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "line"),
    [
        ("A", 1),
        ("A B=1", 1),
        ("=1", 1),
        ("1A=1", 1),
        ("A-B=1", 1),
        ("A.B=1", 1),
        ("A:1", 1),
        ("export", 1),
        ("export A", 1),
        ("export =1", 1),
        ("export = 1", 1),
        ("'A'=1", 1),
        ("ünï=1", 1),
        ("A=1\nB", 2),
        ("A=1\n\n# c\nnot an assignment\n", 4),
        ("A=1\r\nB=2\r\nC", 3),
        ("A=1\rB=2\rC", 3),
        ('A="unterminated', 1),
        ('A="unterminated\nB=2\n', 1),
        ("A='unterminated\nB=2\n", 1),
        ('A=1\nB="x\\"', 2),
        ('A="x"y', 1),
        ('A="x" y', 1),
        ('A="x"#c', 1),
        ("A='x'#c", 1),
        ("A='x''y'", 1),
        ('A="x"\'y\'', 1),
        ('A="a\nb" trailing', 2),
        ('A="a\nb\nc"x\nB=2', 3),
        ("A=x\x00y", 1),
        ('A=1\nB="x\x00y"', 2),
        ("A=1\nB='x\x00y'", 2),
        ("A=1\n\x00", 2),
    ],
)
def test_parse_env_file_names_the_line(text: str, line: int) -> None:
    with pytest.raises(UsageError) as caught:
        parse_env_file(text)
    assert f"line {line}:" in str(caught.value)


@pytest.mark.parametrize(
    "text",
    [
        CANARY,
        f"{CANARY} = oops",
        f"TOKEN {CANARY}",
        f'TOKEN="{CANARY}',
        f"TOKEN='{CANARY}",
        f'TOKEN="{CANARY}" {CANARY}',
        f"TOKEN={CANARY}\x00",
        f"A=1\nTOKEN={CANARY}\n3={CANARY}",
        f"A-{CANARY}=1",
    ],
)
def test_parse_env_file_errors_never_quote_the_file(text: str) -> None:
    with pytest.raises(UsageError) as caught:
        parse_env_file(text)
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize("value", [None, b"A=1", 7, ["A=1"]])
def test_parse_env_file_wants_text(value: object) -> None:
    with pytest.raises(UsageError):
        parse_env_file(value)  # type: ignore[arg-type]


def test_parse_env_file_refuses_an_implausibly_large_file() -> None:
    assert parse_env_file("A=" + "x" * (1024 * 1024 - 2)) == {"A": "x" * (1024 * 1024 - 2)}
    with pytest.raises(UsageError):
        parse_env_file("A=" + "x" * (1024 * 1024))


@pytest.mark.parametrize(
    "text",
    [
        pytest.param('A="' + "\\" * 500_000 + '"', id="backslashes in double quotes"),
        pytest.param("A='" + "\n" * 500_000 + "'", id="newlines in single quotes"),
        pytest.param("A=1 # c\n" * 100_000, id="many short assignments"),
        pytest.param('A="' + '\\"' * 250_000 + '"', id="escaped quotes"),
        pytest.param("\n" * 1_000_000, id="blank lines"),
        pytest.param("# " + "#" * 999_000, id="one long comment"),
        pytest.param("A=" + " #" * 400_000, id="comment markers"),
        pytest.param("\r" * 900_000, id="carriage returns"),
        pytest.param("A='x'\n" * 100_000, id="many quoted assignments"),
        pytest.param('A="' + "x" * 1_000_000, id="unterminated quote"),
        pytest.param("export " * 140_000, id="export repeated"),
    ],
)
def test_parse_env_file_is_linear_on_adversarial_input(text: str) -> None:
    # Processor time, not wall time: the bound must hold on a busy machine too.
    started = time.process_time()
    try:
        parse_env_file(text)
    except UsageError:
        pass
    assert time.process_time() - started < 10.0


fragments = st.sampled_from(
    ["A", "B_1", "=", '"', "'", "\\", "#", " ", "\t", "\n", "\r", "\r\n", "export ", "export", "$", "`", "x", "1",
     "\x00", "irondome://", "\\n", '\\"', "é", "\ufeff", "-"]
)


@settings(max_examples=400, deadline=None)
@given(st.text(max_size=200) | st.lists(fragments, max_size=60).map("".join))
def test_parse_env_file_never_raises_anything_but_usage_error(text: str) -> None:
    try:
        parsed = parse_env_file(text)
    except UsageError as exc:
        assert re.search(r"line \d+:", str(exc))
        return
    for name, value in parsed.items():
        assert _NAME.fullmatch(name)
        assert isinstance(value, str) and "\x00" not in value


values = st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), max_size=60)
variables = st.from_regex(_NAME, fullmatch=True).filter(lambda name: len(name) <= 30)


def _double_quoted(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return f'"{escaped}"'


@settings(max_examples=200, deadline=None)
@given(st.dictionaries(variables, values, max_size=6), st.data())
def test_parse_env_file_round_trips_quoted_values(expected: Dict[str, str], data: st.DataObject) -> None:
    lines: List[str] = []
    for name, value in expected.items():
        single = "'" not in value and data.draw(st.booleans())
        quoted = f"'{value}'" if single else _double_quoted(value)
        prefix = data.draw(st.sampled_from(["", "export ", "  ", "export\t"]))
        suffix = data.draw(st.sampled_from(["", " ", " # comment", "\t#"]))
        lines.append(f"{prefix}{name}={quoted}{suffix}")
    newline = data.draw(st.sampled_from(["\n", "\r\n"]))
    assert parse_env_file(newline.join(lines) + newline) == expected


@settings(max_examples=150, deadline=None)
@given(st.lists(st.tuples(variables, values), max_size=6))
def test_parse_env_file_counts_lines_through_multi_line_values(pairs: List[tuple]) -> None:
    # A broken line after any number of (possibly multi-line) assignments is reported where it is.
    body = "".join(f"{name}={_double_quoted(value)}\n" for name, value in pairs)
    lines_before = len(re.findall(r"\r\n|\r|\n", body))
    with pytest.raises(UsageError) as caught:
        parse_env_file(body + "this line is broken\n")
    assert f"line {lines_before + 1}:" in str(caught.value)


# ---------------------------------------------------------------------------
# plan_injection
# ---------------------------------------------------------------------------


def test_plan_takes_references_from_the_environment_and_nothing_else() -> None:
    environ = {
        "PATH": "/usr/bin",
        "HOME": "/home/king",
        "GITHUB_TOKEN": "irondome://GITHUB_TOKEN",
        "DB_URL": "IRONDOME://db/url",
        "NOT_ONE": "see irondome://x",
        "EMPTY": "",
    }
    plan = plan_injection(environ, None, [])
    assert plan.references == {"GITHUB_TOKEN": "GITHUB_TOKEN", "DB_URL": "db/url"}
    assert plan.literals == {}


def test_plan_splits_an_env_file_into_references_and_literals() -> None:
    env_file = parse_env_file(
        "NODE_ENV=production\nSTRIPE_KEY=irondome://stripe\nREGION='irondome://aws%2Fprod/region'\nEMPTY=\n"
    )
    plan = plan_injection({}, env_file, [])
    assert plan.references == {"STRIPE_KEY": "stripe", "REGION": "aws/prod/region"}
    assert plan.literals == {"NODE_ENV": "production", "EMPTY": ""}


@pytest.mark.parametrize(
    ("pair", "variable", "reference"),
    [
        ("GITHUB_TOKEN", "GITHUB_TOKEN", "GITHUB_TOKEN"),
        ("irondome://GITHUB_TOKEN", "GITHUB_TOKEN", "GITHUB_TOKEN"),
        ("TOKEN=GITHUB_TOKEN", "TOKEN", "GITHUB_TOKEN"),
        ("TOKEN=github/password", "TOKEN", "github/password"),
        ("TOKEN=irondome://github/password", "TOKEN", "github/password"),
        ("TOKEN=irondome://My%20Bank/pin", "TOKEN", "My Bank/pin"),
        ("TOKEN=My Bank/pin", "TOKEN", "My Bank/pin"),
        ("TOKEN=name=with=equals", "TOKEN", "name=with=equals"),
        ("TOKEN=50%", "TOKEN", "50%"),
        ("_x9=a", "_x9", "a"),
    ],
)
def test_plan_reads_command_line_pairs(pair: str, variable: str, reference: str) -> None:
    plan = plan_injection({}, None, [pair])
    assert plan.references == {variable: reference}
    assert plan.literals == {}


def test_plan_later_sources_win() -> None:
    environ = {
        "ONLY_ENV": "irondome://from-environ",
        "ENV_THEN_FILE": "irondome://from-environ",
        "ENV_THEN_LITERAL": "irondome://from-environ",
        "ENV_THEN_PAIR": "irondome://from-environ",
        "ALL_THREE": "irondome://from-environ",
        "PLAIN": "not-a-reference",
    }
    env_file = {
        "ONLY_FILE": "irondome://from-file",
        "ENV_THEN_FILE": "irondome://from-file",
        "ENV_THEN_LITERAL": "a literal",
        "FILE_THEN_PAIR": "irondome://from-file",
        "LITERAL_THEN_PAIR": "a literal",
        "ALL_THREE": "irondome://from-file",
        "PLAIN": "from-file",
    }
    pairs = [
        "ENV_THEN_PAIR=from-pair",
        "FILE_THEN_PAIR=from-pair",
        "LITERAL_THEN_PAIR=from-pair",
        "ALL_THREE=from-first-pair",
        "ALL_THREE=from-last-pair",
        "ONLY_PAIR",
    ]
    plan = plan_injection(environ, env_file, pairs)
    assert plan.references == {
        "ONLY_ENV": "from-environ",
        "ENV_THEN_FILE": "from-file",
        "ENV_THEN_PAIR": "from-pair",
        "ONLY_FILE": "from-file",
        "FILE_THEN_PAIR": "from-pair",
        "LITERAL_THEN_PAIR": "from-pair",
        "ALL_THREE": "from-last-pair",
        "ONLY_PAIR": "ONLY_PAIR",
    }
    assert plan.literals == {"ENV_THEN_LITERAL": "a literal", "PLAIN": "from-file"}
    assert not set(plan.references) & set(plan.literals)


def test_plan_only_the_winning_reference_has_to_be_well_formed() -> None:
    plan = plan_injection({"A": "irondome://", "B": "irondome://%zz"}, {"A": "irondome://good", "B": "literal"}, [])
    assert plan.references == {"A": "good"} and plan.literals == {"B": "literal"}
    plan = plan_injection({}, {"A": "irondome://%zz"}, ["A=fine"])
    assert plan.references == {"A": "fine"}


@pytest.mark.parametrize(
    ("environ", "env_file", "pairs", "variable"),
    [
        ({"BROKEN": "irondome://"}, None, [], "BROKEN"),
        ({"BROKEN": "irondome://a%zz"}, None, [], "BROKEN"),
        ({}, {"BROKEN": "irondome://%ff"}, [], "BROKEN"),
        ({}, None, ["BROKEN="], "BROKEN"),
        ({}, None, ["BROKEN=irondome://"], "BROKEN"),
        ({}, None, ["BROKEN= padded"], "BROKEN"),
        ({"OK": "irondome://fine"}, {"BROKEN": "irondome://x%2"}, ["OK"], "BROKEN"),
    ],
)
def test_plan_reports_which_variable_has_a_malformed_reference(environ, env_file, pairs, variable) -> None:
    with pytest.raises(UsageError) as caught:
        plan_injection(environ, env_file, pairs)
    assert str(caught.value).startswith(f"{variable}: ")


@pytest.mark.parametrize(
    "pair",
    ["", "=", "=reference", "MY-VAR=reference", "1VAR=reference", "my var=reference", "VAR.X=reference",
     "github/password", "github.token", "My Bank", "irondome://github/password", "irondome://", "ünï", None, 7, b"A=b"],
)
def test_plan_rejects_malformed_pairs(pair: object) -> None:
    with pytest.raises(UsageError):
        plan_injection({}, None, [pair])  # type: ignore[list-item]


@pytest.mark.parametrize("name", ["MY-VAR", "1VAR", "", "my var", "A=B", "ünï", "A\n", 7, None])
def test_plan_rejects_env_file_names_that_are_not_variables(name: object) -> None:
    with pytest.raises(UsageError):
        plan_injection({}, {name: "value"}, [])  # type: ignore[dict-item]


@pytest.mark.parametrize("value", [None, 7, b"bytes", ["list"]])
def test_plan_rejects_env_file_values_that_are_not_text(value: object) -> None:
    with pytest.raises(UsageError):
        plan_injection({}, {"A": value}, [])  # type: ignore[dict-item]


def test_plan_rejects_a_literal_with_a_nul() -> None:
    with pytest.raises(UsageError) as caught:
        plan_injection({}, {"A": f"{CANARY}\x00"}, [])
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize("name", CONTROL_VARIABLES)
def test_plan_never_sets_a_control_variable(name: str) -> None:
    for environ, env_file, pairs in (
        ({name: "irondome://token"}, None, []),
        ({}, {name: "irondome://token"}, []),
        ({}, {name: "a literal"}, []),
        ({}, None, [f"{name}=token"]),
        ({}, None, [name]),
    ):
        with pytest.raises(UsageError) as caught:
            plan_injection(environ, env_file, pairs)
        assert name in str(caught.value)
    # Holding a real token (not a reference) in the environment is the normal case and is not planned at all.
    assert plan_injection({name: "ird_g1_token"}, None, []) == InjectionPlan()


def test_control_variables_are_the_three_bearer_credentials() -> None:
    assert set(CONTROL_VARIABLES) == {"IRONDOME_SESSION", "IRONDOME_GRANT", "IRONDOME_PASSWORD_FILE"}


def test_plan_ignores_environment_values_that_are_not_text() -> None:
    assert plan_injection({"A": None, "B": 7, 3: "irondome://x"}, None, []) == InjectionPlan()  # type: ignore[dict-item]


def test_plan_of_nothing_is_empty() -> None:
    plan = plan_injection({}, None, [])
    assert plan == InjectionPlan() and plan.references == {} and plan.literals == {}
    assert plan_injection({"PATH": "/bin"}, {}, []) == InjectionPlan()


_COLLIDING = st.sampled_from(["A", "B", "C", "TOKEN", "_x"])
_MIXED = st.sampled_from(
    ["plain", "", "with space", "irondome://github", "IRONDOME://x", "irondome://My%20Bank/pin", "irondome://aws/prod/region",
     "irondome://", "irondome://%zz", "irondome://%20padded"]
)
_TARGETS = st.sampled_from(["github", "aws/prod/region", "irondome://GITHUB_TOKEN", "My Bank/pin", "", " padded", "irondome://%"])


@settings(max_examples=300, deadline=None)
@given(
    st.dictionaries(_COLLIDING, _MIXED, max_size=5),
    st.dictionaries(_COLLIDING, _MIXED, max_size=5),
    st.lists(st.tuples(_COLLIDING, _TARGETS), max_size=5),
)
def test_plan_precedence_property(environ: Dict[str, str], env_file: Dict[str, str], chosen: List[tuple]) -> None:
    # The last source to mention a variable decides alone what it gets.
    winners: Dict[str, tuple] = {}
    for name, value in environ.items():
        if is_reference(value):
            winners[name] = (True, value)
    for name, value in env_file.items():
        winners[name] = (is_reference(value), value)
    for name, target in chosen:
        winners[name] = (True, target)
    pairs = [f"{name}={target}" for name, target in chosen]
    try:
        references = {name: parse_reference(text) for name, (referenced, text) in winners.items() if referenced}
    except UsageError:
        with pytest.raises(UsageError):
            plan_injection(environ, env_file, pairs)
        return
    plan = plan_injection(environ, env_file, pairs)
    assert plan.references == references
    assert plan.literals == {name: text for name, (referenced, text) in winners.items() if not referenced}


# ---------------------------------------------------------------------------
# resolve_plan
# ---------------------------------------------------------------------------


def test_resolve_calls_lookup_once_per_distinct_reference_in_plan_order() -> None:
    plan = InjectionPlan(
        references={"A": "github", "B": "aws/prod/region", "C": "github", "D": "GITHUB_TOKEN"},
        literals={"PLAIN": "value"},
    )
    seen: List[str] = []

    def lookup(reference: str) -> str:
        seen.append(reference)
        return f"value-of-{reference}"

    assert resolve_plan(plan, lookup) == {
        "A": "value-of-github",
        "B": "value-of-aws/prod/region",
        "C": "value-of-github",
        "D": "value-of-GITHUB_TOKEN",
    }
    assert seen == ["github", "aws/prod/region", "GITHUB_TOKEN"]


def test_resolve_leaves_literals_out() -> None:
    plan = InjectionPlan(references={}, literals={"NODE_ENV": "production"})
    assert resolve_plan(plan, lambda reference: pytest.fail("nothing to look up")) == {}


@pytest.mark.parametrize("error", [NotFoundError("no entry named 'x'"), PolicyError("not covered"), UsageError("bad")])
def test_resolve_lets_lookup_errors_through_and_returns_nothing(error: Exception) -> None:
    plan = InjectionPlan(references={"A": "first", "B": "second", "C": "third"})
    asked: List[str] = []

    def lookup(reference: str) -> str:
        asked.append(reference)
        if reference == "second":
            raise error
        return CANARY

    with pytest.raises(type(error)) as caught:
        resolve_plan(plan, lookup)
    assert caught.value is error
    assert asked == ["first", "second"]


@pytest.mark.parametrize("returned", [None, b"bytes", 7, ["x"]])
def test_resolve_insists_on_text_from_lookup(returned: object) -> None:
    with pytest.raises(TypeError) as caught:
        resolve_plan(InjectionPlan(references={"A": "x"}), lambda reference: returned)  # type: ignore[arg-type,return-value]
    assert "bytes" not in str(caught.value) or returned != b"bytes"


def test_plan_and_resolve_against_a_real_vault(vault) -> None:
    environ = {"HOME": "/home/king", "GH": "irondome://GITHUB_TOKEN", "STALE": "irondome://no-such-entry"}
    env_file = parse_env_file(
        "# deployment\n"
        "NODE_ENV=production\n"
        "AWS_REGION=irondome://aws%2Fprod/region\n"
        "GH_USER='irondome://github/username'\n"
        "STALE=overridden-by-a-literal\n"
    )
    plan = plan_injection(environ, env_file, ["GITHUB_TOKEN", "AWS_KEY=aws/prod"])
    assert plan.literals == {"NODE_ENV": "production", "STALE": "overridden-by-a-literal"}

    def lookup(reference: str) -> str:
        entry, field = vault.resolve(reference)
        return vault.value(entry, field)

    assert resolve_plan(plan, lookup) == {
        "GH": "hunter2-Github!",
        "AWS_REGION": "eu-west-1",
        "GH_USER": "king",
        "GITHUB_TOKEN": "hunter2-Github!",
        "AWS_KEY": "AKIA-not-a-real-key",
    }
    with pytest.raises(NotFoundError):
        resolve_plan(plan_injection(environ, None, []), lookup)


def test_public_names() -> None:
    assert set(refs.__all__) == {
        "SCHEME", "CONTROL_VARIABLES", "InjectionPlan", "is_reference", "parse_reference", "format_reference",
        "parse_env_file", "plan_injection", "resolve_plan",
    }
    assert SCHEME == "irondome://"
