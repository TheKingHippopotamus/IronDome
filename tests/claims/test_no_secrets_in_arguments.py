"""Claim ``no-secrets-in-arguments``: no secret value is ever a command-line argument.

Statement: no command takes a secret value (a password, key, token, TOTP seed
or custom field) as a command-line argument: values come from a hidden
prompt, standard input or a file, so they reach neither your shell history
nor the process list. IronDome hands them to the programs it runs itself
(clipboard tools, the Secure Enclave helper, tpm2-tools) the same way.

Proof: the real parser, ``irondome.cli.main.build_parser()``, is walked
through every command and subcommand, and every argument that takes a value
is collected: each positional, and each option whose ``nargs`` is not 0
(``store_true``, ``store_false``, ``store_const``, ``count``, ``help`` and
``version`` take none). Every one must be on the list below, with the reason
its value is not a secret, and the list must name nothing that no longer
exists. A new argument that takes a value therefore fails this test until
someone decides, in writing here, that what it takes is not a secret. The
custom field option, which once took ``KEY=VALUE``, is also checked from
the outside: it refuses a value, and does not repeat it. The programs
IronDome runs itself are covered by the tests of their own modules, listed
under this claim.
"""

from __future__ import annotations

import argparse
from typing import Dict, List, Tuple

from conftest import PASSWORD
from irondome.cli import main
from support.claimkit import add, fails, init

#: Options every command inherits (``main._common_options``), with why their values are not secrets.
GLOBAL: Dict[str, str] = {
    "bunker": "a bunker's name",
}

#: ``(command path, dest)`` of every other argument that takes a value, with why it is not a secret.
ALLOWED: Dict[Tuple[str, str], str] = {
    # making a vault
    ("init", "mode"): "a setup mode: password, touchid or touchid+password",
    ("init", "kdf_memory_mib"): "a number of MiB of memory for Argon2id",
    ("bunker create", "name"): "the new bunker's name",
    ("bunker create", "mode"): "a setup mode",
    ("bunker create", "kdf_memory_mib"): "a number of MiB of memory for Argon2id",
    ("bunker use", "name"): "a bunker's name",
    ("bunker rm", "name"): "a bunker's name",
    # entries: names, references, and what listings show
    ("add", "name"): "the entry's name, which listings show",
    ("add", "alias"): "an alias: a name for a value, not the value",
    ("add", "username"): "a user name, which listings show",
    ("add", "url"): "a web address, which listings show",
    ("add", "tag"): "a tag, which listings show",
    ("add", "note"): "notes typed there on purpose (its help says so); --note-stdin keeps private notes out of argv",
    ("add", "kind"): "login or secret",
    ("add", "agent"): "an agent policy: deny, use or reveal",
    ("add", "field"): "a custom field's name; its value is asked for at a hidden prompt or read from stdin",
    ("add", "length"): "a password length",
    ("add", "words"): "a number of words",
    ("edit", "name"): "the name of the entry to change",
    ("edit", "new_name"): "the entry's new name",
    ("edit", "username"): "a user name, which listings show",
    ("edit", "url"): "a web address, which listings show",
    ("edit", "tag"): "a tag",
    ("edit", "add_tag"): "a tag",
    ("edit", "rm_tag"): "a tag",
    ("edit", "note"): "notes typed there on purpose (its help says so); --note-stdin keeps private notes out of argv",
    ("edit", "kind"): "login or secret",
    ("edit", "agent"): "an agent policy",
    ("edit", "field"): "a custom field's name; its value is asked for at a hidden prompt or read from stdin",
    ("edit", "rm_field"): "the name of a custom field to remove",
    ("edit", "length"): "a password length",
    ("edit", "words"): "a number of words",
    ("get", "reference"): "a reference: an alias, an entry name or entry/field",
    ("get", "field"): "the name of the field to read",
    ("show", "name"): "an entry's name",
    ("ls", "tag"): "a tag to list by",
    ("find", "query"): "text looked for in names, user names, addresses, tags and aliases; values are never searched",
    ("find", "tag"): "a tag to list by",
    ("rm", "name"): "an entry's name",
    ("otp", "reference"): "a reference",
    ("gen", "length"): "a length",
    ("gen", "words"): "a number of words",
    ("gen", "email_alias"): "the e-mail address to make a plus-address of",
    ("config get", "key"): "a setting's name",
    ("config set", "key"): "a setting's name",
    ("config set", "value"): "a setting's value: a number of seconds, characters or snapshots",
    ("config reset", "keys"): "settings' names",
    # agents
    ("alias set", "alias"): "an alias",
    ("alias set", "reference"): "a reference",
    ("alias rm", "alias"): "an alias",
    ("run", "env"): "VAR=REF: a variable's name and a reference that irondome run resolves, never the value",
    ("run", "env_file"): "the path of a file of VAR=REF lines",
    ("run", "cwd"): "a directory",
    ("run", "timeout"): "a duration",
    ("run", "command"): "the program to run and its own arguments; the secrets reach it in its environment",
    ("approve", "references"): "references",
    ("approve", "ttl"): "a duration",
    ("grant create", "references"): "references",
    ("grant create", "ttl"): "a duration",
    ("grant create", "uses"): "a number of uses",
    ("grant create", "label"): "a label to recognise the grant by in grant ls",
    ("grant revoke", "id_prefix"): "the start of a grant's id, which grant ls shows to anyone",
    ("unlock", "ttl"): "a duration",
    ("audit", "count"): "a number of records",
    ("scan", "paths"): "files and directories to search",
    ("mcp", "touch_timeout"): "a number of seconds",
    ("mcp config", "client"): "an MCP client's name",
    # maintenance
    ("backup restore", "snapshot"): "a snapshot's number or file name",
    ("export", "path"): "the path of the file to write",
    ("export", "plaintext"): "json or csv",
    ("import", "path"): "the path of the file to read",
    ("import", "format"): "an export format's name",
    ("import", "on_conflict"): "rename, skip or replace",
    ("migrate", "from_dir"): "a directory",
    ("migrate", "legacy_username"): "the IronDome 3.x master user name: a name, the password is asked for",
    ("migrate", "mode"): "a setup mode",
    ("migrate", "kdf_memory_mib"): "a number of MiB of memory for Argon2id",
    ("completion", "shell"): "bash, zsh or fish",
    ("verify", "claims"): "a claim's id",
}

_TAKES_NOTHING = (
    argparse._StoreConstAction,  # store_true and store_false too
    argparse._AppendConstAction,
    argparse._CountAction,
    argparse._HelpAction,
    argparse._VersionAction,
)


def _takes_a_value(action: argparse.Action) -> bool:
    if isinstance(action, (argparse._SubParsersAction,) + _TAKES_NOTHING):
        return False
    return not action.option_strings or action.nargs != 0


def value_arguments(parser: argparse.ArgumentParser, path: str = "") -> List[Tuple[str, str, str]]:
    """``(command path, dest, how it is written)`` of each argument of *parser* or a subcommand that takes a value."""
    found: List[Tuple[str, str, str]] = []
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                found.extend(value_arguments(sub, f"{path} {name}".strip()))
        elif _takes_a_value(action):
            found.append((path, action.dest, "/".join(action.option_strings) or action.dest))
    return found


def global_options() -> Dict[str, str]:
    """dest -> how it is written, for the options every command inherits."""
    return {
        action.dest: "/".join(action.option_strings)
        for action in main._common_options()._actions
        if _takes_a_value(action)
    }


def test_every_argument_that_takes_a_value_is_known_not_to_be_a_secret():
    inherited = global_options()
    assert set(inherited) == set(GLOBAL), f"global options that take a value: {inherited}"
    found = value_arguments(main.build_parser())
    present = {(path, dest) for path, dest, _written in found}
    assert {("add", "field"), ("run", "env"), ("grant create", "references"), ("nuke", "bunker")} <= present  # walked
    undecided = [
        f"irondome {path} {written} (dest {dest!r})"
        for path, dest, written in found
        if dest not in GLOBAL and (path, dest) not in ALLOWED
    ]
    assert undecided == [], (
        "these arguments take a value and nobody has said why it is not a secret; read the value from a hidden "
        "prompt or stdin instead, or add it to ALLOWED with the reason: " + "; ".join(undecided)
    )
    assert sorted(set(ALLOWED) - present) == [], "ALLOWED names arguments that no longer exist: remove them"
    for (path, dest), reason in ALLOWED.items():
        assert reason.strip() and "\n" not in reason, f"{path} {dest}: give one line of reason"


def test_every_command_inherits_only_the_global_options_it_should():
    """--bunker is inherited by every command; no command may grow a value-taking global option silently."""
    for path, dest, written in value_arguments(main.build_parser()):
        if dest in GLOBAL:
            assert written == global_options()[dest], f"irondome {path}: {written}"


def test_a_custom_fields_value_on_the_command_line_is_refused_and_not_repeated(cli):
    init(cli)
    add(cli, "bank", "the-bank-password-1234")
    for command in (("add", "card", "--generate"), ("edit", "bank")):
        refused = fails(
            cli(*command, "--field", "pin=4711-the-pin-value", "--password-stdin", stdin=PASSWORD + "\n"), 2
        )
        assert "--field takes only the field's name" in refused.stderr
        assert "4711-the-pin-value" not in refused.stdout + refused.stderr
    # The same field, by name, with its value where the claim says it goes: stdin.
    taken = cli("add", "card", "--generate", "--field", "pin", "--password-stdin", stdin=f"{PASSWORD}\n4711\n")
    assert taken.returncode == 0, taken.stderr
    shown = cli("get", "card/pin", "--password-stdin", stdin=PASSWORD + "\n")
    assert shown.returncode == 0 and shown.stdout == "4711"


# -- the boundary ------------------------------------------------------------------


def test_boundary_a_note_given_as_an_option_is_on_the_command_line_and_note_stdin_keeps_it_off(cli):
    """--note TEXT is taken from argv, as its help says; --note-stdin takes the same note from standard input."""
    init(cli)
    on_the_line = cli("add", "one", "--generate", "--note", "typed on the command line", "--password-stdin",
                      stdin=PASSWORD + "\n")
    assert on_the_line.returncode == 0, on_the_line.stderr
    off_the_line = cli("add", "two", "--generate", "--note-stdin", "--password-stdin",
                       stdin=f"{PASSWORD}\nread from stdin\n")
    assert off_the_line.returncode == 0, off_the_line.stderr
    for name, note in (("one", "typed on the command line"), ("two", "read from stdin")):
        shown = cli("get", f"{name}/notes", "--password-stdin", stdin=PASSWORD + "\n")
        assert shown.returncode == 0 and shown.stdout == note
