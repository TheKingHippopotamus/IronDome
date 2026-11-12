"""Claim ``agents-cannot-escalate``: an agent cannot widen its own access.

Statement: without a terminal or the master password, IronDome refuses to
create sessions, aliases or entries, to change keyslots, to export, and to
read entries the owner has not marked for agents. The one thing an agent can
ask for is a time-boxed, use-only grant for entries marked for agents
(``irondome approve``), and only the owner's Touch ID creates it.

The suite never has a terminal (``IRONDOME_NO_PROMPT=1``), so every command
below that is not given ``--password-stdin`` runs as an agent would. Each is
given a valid grant as well: holding one must not help.
"""

from __future__ import annotations

import argparse

import pytest

from conftest import PASSWORD
from irondome import paths
from support.claimkit import add, fails, grant, init, ok, session

OWNER_ONLY = [
    ("grant", "create", "GITHUB_TOKEN"),
    ("unlock", "--print-token"),
    ("alias", "set", "OTHER", "bank"),
    ("add", "planted", "--generate"),
    ("edit", "github", "--agent", "reveal"),
    ("edit", "bank", "--agent", "use"),
    ("rm", "bank", "--yes"),
    ("export", "exported.irondome"),
    ("export", "exported.json", "--plaintext", "json", "--yes"),
    ("passwd",),
    ("recovery", "new"),
    ("auth", "touchid"),
    ("auth", "password"),
    ("rekey",),
    ("show", "bank"),
    ("config", "set", "grant_ttl", "86400"),
    ("bunker", "create", "charlie"),
    ("bunker", "rm", "alpha", "--yes"),
    ("nuke", "--yes-destroy-everything"),
    ("backup", "ls"),
]


@pytest.fixture
def agent(cli):
    init(cli)
    add(cli, "github", "the-github-token-1234", "--alias", "GITHUB_TOKEN")
    add(cli, "bank", "the-bank-password-5678")
    token = grant(cli, "GITHUB_TOKEN", args=("--uses", "100"))["token"]
    return {"IRONDOME_GRANT": token}


@pytest.mark.parametrize("command", OWNER_ONLY, ids=[" ".join(command) for command in OWNER_ONLY])
def test_an_agent_with_a_grant_is_refused_every_owner_command(cli, agent, command):
    before = {
        path: path.read_bytes() for path in paths.home().rglob("*") if path.is_file() and "caps" not in path.parts
    }
    refused = fails(cli(*command, env=agent), 5)
    assert "owner" in refused.stderr
    assert "the-bank-password-5678" not in refused.stdout + refused.stderr
    after = {path: path.read_bytes() for path in before if path.exists()}
    assert set(after) == set(before)
    changed = [str(path) for path in before if path.name == "vault.irondome" and after[path] != before[path]]
    assert changed == []


def test_without_a_grant_an_agent_cannot_read_anything_and_is_told_about_grants(cli):
    init(cli)
    add(cli, "bank", "the-bank-password-5678")
    refused = fails(cli("get", "bank"), 4)
    assert "grant" in refused.stderr and "the-bank-password-5678" not in refused.stdout


def test_the_entries_an_agent_may_use_are_the_ones_the_owner_marked(make_vault):
    """Touch ID access (the --touch path) is limited by each entry's agent policy; the default is deny."""
    from irondome.cli.context import Access, Context
    from irondome.cli.output import Output
    from irondome.errors import PolicyError
    from irondome.vault import Secret

    vault, _recovery = make_vault()
    vault.add("denied", Secret(password="denied-value"))
    vault.add("usable", Secret(password="usable-value"), agent="use")
    vault.add("showable", Secret(password="showable-value"), agent="reveal")
    vault.commit()
    ctx = Context(argparse.Namespace(), Output())
    access = Access(ctx, vault=vault, restricted=True)
    assert "denied" not in access.names() and {"usable", "showable"} <= set(access.names())
    with pytest.raises(PolicyError, match="not available to agents"):
        access.value("denied", "use")
    with pytest.raises(PolicyError, match="not shown to them"):
        access.value("usable", "reveal")
    assert access.value("showable", "reveal") == "showable-value"


def test_approve_needs_a_touch_id_keyslot_and_says_to_ask_the_owner_instead(cli, agent):
    refused = fails(cli("approve", "GITHUB_TOKEN", env=agent), 4)
    assert "Touch ID" in refused.stderr and "grant create" in refused.stderr


def test_a_session_cannot_be_started_from_a_grant_or_from_nothing(cli, agent):
    fails(cli("unlock", "--print-token", env=agent), 5)
    fails(cli("unlock", "--print-token"), 5)


# -- the boundary ------------------------------------------------------------------


def test_boundary_a_session_token_handed_to_an_agent_is_full_access(cli):
    init(cli)
    add(cli, "bank", "the-bank-password-5678")
    token = session(cli)
    assert ok(cli("get", "bank", env={"IRONDOME_SESSION": token})).stdout == "the-bank-password-5678"


def test_boundary_the_password_on_stdin_is_the_owner(cli):
    init(cli)
    add(cli, "bank", "the-bank-password-5678")
    ok(cli("alias", "set", "BANK_PASSWORD", "bank", "--password-stdin", stdin=PASSWORD + "\n"))
