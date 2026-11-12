"""Secret references: naming a secret where its value would otherwise be written.

A reference is ``irondome://`` followed by what :meth:`irondome.vault.Vault.resolve`
and a grant understand -- an alias, an entry name, or ``name/field``::

    irondome://GITHUB_TOKEN           an alias
    irondome://github                 an entry (its password)
    irondome://aws/prod/region        one field of the entry "aws/prod"
    irondome://My%20Bank/password     percent-encoded where a space would not survive

It goes where the secret used to be: in an env file, in the environment of a
shell, in the configuration of an MCP server. ``irondome run`` replaces it with
the value at the last moment, in the environment of one child process, and
nowhere else.

This module parses references and env files and decides what a command's
environment is to receive (:func:`plan_injection`). It opens no vault. The only
function that touches a value is :func:`resolve_plan`, and it gets each one
from a ``lookup`` the caller supplies, so the caller's vault or grant decides
what may be read.

What a reference is not: a secret, or a permission. Anyone may write
``irondome://github``; whether it resolves is decided when it is looked up.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Callable, Dict, List, Mapping, Optional, Tuple

from irondome.errors import UsageError

__all__ = [
    "SCHEME",
    "CONTROL_VARIABLES",
    "InjectionPlan",
    "is_reference",
    "parse_reference",
    "format_reference",
    "parse_env_file",
    "plan_injection",
    "resolve_plan",
]

SCHEME = "irondome://"

#: Variables that carry IronDome's own bearer credentials. They are never
#: injected into a command and never inherited by one (see ``agent.runner``).
CONTROL_VARIABLES = ("IRONDOME_SESSION", "IRONDOME_GRANT", "IRONDOME_PASSWORD_FILE")

#: Entry names are at most 200 characters and field names 64 (irondome.vault).
_MAX_REFERENCE = 512
#: A percent-encoded reference is at most twelve times as long as what it encodes.
_MAX_ENCODED_REFERENCE = 12 * _MAX_REFERENCE + len(SCHEME)
#: The environment of a process is far smaller than this on every platform.
_MAX_ENV_FILE = 1024 * 1024

# All three are used with fullmatch or at an explicit position: "$" would also
# accept a trailing newline.
_VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}")
_NEWLINE = re.compile(r"\r\n|\r|\n")

_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
#: Left as they are by format_reference: safe unquoted in a shell, an env file and a URL.
_UNESCAPED = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/@:+,")

_BLANK = " \t"
_DOUBLE_QUOTE_STOP = re.compile(r'["\\]')
_DOUBLE_QUOTE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "$": "$", "`": "`"}
_INLINE_COMMENT = re.compile(r"[ \t]#")


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------


def is_reference(value: object) -> bool:
    """True if *value* is text that starts with ``irondome://`` (in any letter case)."""
    return isinstance(value, str) and value[: len(SCHEME)].lower() == SCHEME


def _is_control(char: str) -> bool:
    """What an entry name may not contain (see ``irondome.vault``), so no reference can either."""
    code = ord(char)
    return code < 32 or 0x7F <= code <= 0x9F or code in (0x2028, 0x2029)


def _checked(reference: str) -> str:
    """Refuse a bare reference that no alias, entry or field could ever match."""
    if not reference:
        raise UsageError("empty reference: name an alias, an entry, or entry/field")
    if len(reference) > _MAX_REFERENCE:
        raise UsageError(f"a reference cannot be longer than {_MAX_REFERENCE} characters")
    if reference != reference.strip():
        raise UsageError("a reference cannot start or end with whitespace")
    if any(_is_control(char) for char in reference):
        raise UsageError("a reference cannot contain control characters")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in reference):
        raise UsageError("a reference must be valid Unicode text")
    if is_reference(reference):
        raise UsageError("a name inside a reference cannot itself start with irondome://")
    return reference


def _percent_decode(text: str) -> str:
    if "%" not in text:
        return text
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        raise UsageError("malformed reference: it is not valid Unicode text") from None
    decoded = bytearray()
    index = 0
    while index < len(encoded):
        byte = encoded[index]
        if byte != 0x25:
            decoded.append(byte)
            index += 1
            continue
        digits = encoded[index + 1 : index + 3]
        if len(digits) != 2 or not all(digit in _HEX_DIGITS for digit in digits):
            raise UsageError(
                "malformed reference: '%' must be followed by two hexadecimal digits (write a literal % as %25)"
            )
        decoded.append(int(digits, 16))
        index += 3
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        raise UsageError("malformed reference: its percent-escapes do not decode to UTF-8 text") from None


def _percent_encode(text: str) -> str:
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        raise UsageError("a reference must be valid Unicode text") from None
    return "".join(chr(byte) if byte in _UNESCAPED else f"%{byte:02X}" for byte in encoded)


def parse_reference(text: str) -> str:
    """Return the bare reference in *text*: ``alias``, ``name`` or ``name/field``.

    With ``irondome://`` in front, the scheme is removed and the rest is
    percent-decoded (``%20`` is a space, ``%2F`` a slash, ``%25`` a literal
    ``%``); every other character stands for itself. Text without the scheme
    is taken to be a bare reference already and is returned as it is, so the
    same function serves ``--env VAR=irondome://github`` and ``--env VAR=github``.

    Raises :class:`UsageError` for a reference that is empty, too long, padded
    with whitespace, holds control characters or has a broken percent-escape.
    It does not check that the reference resolves: only a vault or a grant can.
    """
    if not isinstance(text, str):
        raise UsageError("a reference must be text")
    if len(text) > _MAX_ENCODED_REFERENCE:
        raise UsageError("that reference is too long")
    if is_reference(text):
        return _checked(_percent_decode(text[len(SCHEME) :]))
    return _checked(text)


def format_reference(name: str, field: Optional[str] = None) -> str:
    """Write the reference for the alias or entry *name*, or for one *field* of it.

    Everything except letters, digits and ``- . _ ~ / @ : + ,`` is
    percent-encoded, so the result is one token that needs no quoting in a
    shell, an env file or a JSON string, and
    ``parse_reference(format_reference(name, field))`` gives back ``name`` or
    ``name/field``.
    """
    if not isinstance(name, str):
        raise UsageError("a reference needs the name of an alias or an entry")
    _checked(name)
    bare = name
    if field is not None:
        if not isinstance(field, str) or not _FIELD.fullmatch(field):
            raise UsageError(
                "a field name starts with a letter or underscore and contains only letters, digits, "
                "'_', '.' and '-' (at most 64 characters)"
            )
        bare = _checked(f"{name}/{field}")
    return SCHEME + _percent_encode(bare)


# ---------------------------------------------------------------------------
# Env files
# ---------------------------------------------------------------------------


def _skip_blank(text: str, position: int) -> int:
    while position < len(text) and text[position] in _BLANK:
        position += 1
    return position


def _line_end(text: str, position: int) -> int:
    newline = _NEWLINE.search(text, position)
    return newline.start() if newline else len(text)


def _malformed(line: int, problem: str) -> UsageError:
    return UsageError(f"env file, line {line}: {problem}")


def _double_quoted(text: str, start: int, line: int, name: str) -> Tuple[str, int]:
    """The value of a double-quoted string opening at *start*, and where it ends."""
    parts: List[str] = []
    position = start + 1
    while True:
        stop = _DOUBLE_QUOTE_STOP.search(text, position)
        if stop is None:
            raise _malformed(line, f"the value of {name} has no closing double quote")
        parts.append(text[position : stop.start()])
        position = stop.end()
        if stop.group() == '"':
            return "".join(parts), position
        escaped = text[position : position + 1]
        if escaped in _DOUBLE_QUOTE_ESCAPES:
            parts.append(_DOUBLE_QUOTE_ESCAPES[escaped])
            position += 1
        else:
            parts.append("\\")  # not an escape: the backslash is an ordinary character


def _assignment(text: str, position: int, line: int) -> Tuple[str, str, int, int]:
    """Parse one ``NAME=VALUE`` starting at *position* on *line*.

    Returns the name, the value, the position just after the statement (at
    the end of its last line) and the number of that line.
    """
    if text.startswith("export", position) and text[position + 6 : position + 7] in ("\t", " "):
        position = _skip_blank(text, position + 6)
    match = _VARIABLE.match(text, position)
    equals = _skip_blank(text, match.end()) if match else position
    if match is None or text[equals : equals + 1] != "=":
        raise _malformed(
            line,
            "expected NAME=VALUE, where NAME is made of letters, digits and underscores "
            "and does not start with a digit",
        )
    name = match.group()
    start = _skip_blank(text, equals + 1)
    opening = text[start : start + 1]
    if opening in ('"', "'"):
        if opening == '"':
            value, position = _double_quoted(text, start, line, name)
        else:
            closing = text.find("'", start + 1)
            if closing == -1:
                raise _malformed(line, f"the value of {name} has no closing single quote")
            value, position = text[start + 1 : closing], closing + 1
        last_line = line + len(_NEWLINE.findall(text, start, position))
        rest = _skip_blank(text, position)
        if rest < len(text) and text[rest] not in "\r\n":
            if text[rest] != "#" or rest == position:
                raise _malformed(last_line, f"unexpected text after the closing quote of {name}")
            rest = _line_end(text, rest)
        position = rest
    else:
        last_line = line
        position = _line_end(text, start)
        value = text[start:position]
        comment = _INLINE_COMMENT.search(value)
        if value.startswith("#") and start > equals + 1:
            value = ""
        elif comment is not None:
            value = value[: comment.start()]
        value = value.rstrip(_BLANK)
    if "\x00" in value:
        raise _malformed(line, f"the value of {name} contains a NUL character, which no environment variable can hold")
    return name, value, position, last_line


def parse_env_file(text: str) -> Dict[str, str]:
    """Parse dotenv text into ``{name: value}``. Later lines win over earlier ones.

    ``NAME=VALUE``, one per line, optionally after ``export``; blanks around
    the ``=`` are ignored; blank lines and lines starting with ``#`` are
    skipped. NAME is letters, digits and underscores, not starting with a digit.

    =================  ========================================================
    unquoted           runs to the end of the line; surrounding blanks are
                       dropped; a ``#`` that follows a blank starts a comment;
                       backslashes and quotes inside are ordinary characters
    ``'single'``       taken literally, no escapes; may span lines
    ``"double"``       a backslash followed by ``n``, ``r`` or ``t`` is a
                       newline, carriage return or tab; a backslash followed by
                       a backslash, a double quote, ``$`` or a backtick is that
                       character; any other backslash is kept as it is; may
                       span lines
    =================  ========================================================

    After a closing quote only blanks and a ``#`` comment (after at least one
    blank) may follow. Values are otherwise passed through untouched: there is
    no ``$VARIABLE`` expansion and no command substitution. A byte order mark
    at the start of the text is ignored.

    Raises :class:`UsageError` giving the line number of anything else. The
    message never quotes the line, because env files hold secrets.
    """
    if not isinstance(text, str):
        raise UsageError("an env file must be text")
    if len(text) > _MAX_ENV_FILE:
        raise UsageError("that env file is too large (more than 1 MiB)")
    values: Dict[str, str] = {}
    position = 1 if text.startswith("\ufeff") else 0
    line = 1
    while position < len(text):
        position = _skip_blank(text, position)
        if position < len(text) and text[position] not in "\r\n#":
            name, value, position, line = _assignment(text, position, line)
            values[name] = value
        newline = _NEWLINE.search(text, position)
        if newline is None:
            break
        position = newline.end()
        line += 1
    return values


# ---------------------------------------------------------------------------
# Planning an injection
# ---------------------------------------------------------------------------


@dataclass
class InjectionPlan:
    """What a command's environment is to receive, before any secret is read.

    ``references`` maps a variable to the bare reference whose value it gets;
    ``literals`` maps a variable to plain text that is passed on as it is. A
    variable is in at most one of the two.
    """

    references: Dict[str, str] = dataclass_field(default_factory=dict)
    literals: Dict[str, str] = dataclass_field(default_factory=dict)


def _pair(pair: object) -> Tuple[str, str]:
    """Split a command-line ``VAR=REFERENCE`` or ``ALIAS`` into variable and reference text."""
    if not isinstance(pair, str) or not pair:
        raise UsageError("give each secret as VAR=REFERENCE, or as an alias that is also the variable's name")
    name, equals, reference = pair.partition("=")
    if not equals:
        name = parse_reference(pair)
        if not _VARIABLE.fullmatch(name):
            raise UsageError(
                "a reference given on its own must be an alias that can also name a variable "
                "(letters, digits and underscores); otherwise write VAR=REFERENCE"
            )
        return name, pair
    if not _VARIABLE.fullmatch(name):
        raise UsageError(
            "in VAR=REFERENCE, VAR must be made of letters, digits and underscores and not start with a digit"
        )
    return name, reference


def plan_injection(
    environ: Mapping[str, str], env_file: Optional[Dict[str, str]], pairs: List[str]
) -> InjectionPlan:
    """Decide what a command's environment gets. Reads no secret.

    Three sources, later ones winning over earlier ones for the same variable:

    1. every variable of *environ* whose value is an ``irondome://`` reference;
    2. every entry of *env_file* (as :func:`parse_env_file` returns it): a
       value that is a reference is planned for resolution, any other value is
       a literal and is passed on unchanged;
    3. *pairs* from the command line: ``VAR=REFERENCE`` (with or without
       ``irondome://``), or just ``ALIAS``, which means the variable ``ALIAS``
       gets the value of the alias ``ALIAS``.

    Only the reference that wins for a variable has to be well formed. Raises
    :class:`UsageError` for a malformed reference or variable name, and for
    any attempt to set one of :data:`CONTROL_VARIABLES`.
    """
    chosen: Dict[str, Tuple[bool, str]] = {}
    for name, value in environ.items():
        if isinstance(name, str) and is_reference(value):
            chosen[name] = (True, value)
    for name, value in (env_file or {}).items():
        if not isinstance(name, str) or not _VARIABLE.fullmatch(name):
            raise UsageError(
                "the env file names a variable that is not made of letters, digits and underscores"
            )
        if not isinstance(value, str):
            raise UsageError(f"the env file value of {name} is not text")
        chosen[name] = (is_reference(value), value)
    for pair in pairs or []:
        name, reference = _pair(pair)
        chosen[name] = (True, reference)

    plan = InjectionPlan()
    for name, (referenced, text) in chosen.items():
        if name in CONTROL_VARIABLES:
            raise UsageError(f"{name} is reserved by IronDome and is never passed to a command")
        if referenced:
            try:
                plan.references[name] = parse_reference(text)
            except UsageError as exc:
                raise UsageError(f"{name}: {exc}") from None
        elif "\x00" in text:
            raise UsageError(f"the value of {name} contains a NUL character, which no environment variable can hold")
        else:
            plan.literals[name] = text
    return plan


def resolve_plan(plan: InjectionPlan, lookup: Callable[[str], str]) -> Dict[str, str]:
    """Read the secrets of *plan*: ``{variable: value}`` for each of its references.

    ``lookup(reference)`` is called once per distinct reference, in the order
    the plan lists them, and whatever it raises (not found, not allowed, the
    grant is spent) propagates unchanged; nothing is returned in that case.
    The caller supplies a lookup backed by a vault or by a grant, so scope and
    audit are enforced there.

    The literals of the plan are not in the result. They are not secret and
    must not be masked: give the result to ``agent.runner.run_command`` as
    ``injected`` and ``plan.literals`` as ``literals``.
    """
    fetched: Dict[str, str] = {}
    values: Dict[str, str] = {}
    for name, reference in plan.references.items():
        if reference not in fetched:
            value = lookup(reference)
            if not isinstance(value, str):
                raise TypeError("lookup() must return the secret as text")
            fetched[reference] = value
        values[name] = fetched[reference]
    return values
