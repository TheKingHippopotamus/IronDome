"""Claim ``grants-are-scoped``: a grant opens only what it names, for as long as it says.

Statement: a grant token gives access to the values named when it was created
and to nothing else, until it expires or its uses run out. A used-up or
expired grant is destroyed, and its token no longer opens anything.

Everything an agent does here runs with only ``IRONDOME_GRANT`` in its
environment: no terminal (the suite never has one) and no password.
"""

from __future__ import annotations

import sys
import time

import pytest

from irondome import caps, paths
from irondome.errors import AuthError
from support.claimkit import add, copy_tree, document, fails, grant, init, ok, restore_tree

SHOW = "import os; print(os.environ.get('VALUE', 'missing'))"


@pytest.fixture
def two_entries(cli):
    init(cli)
    add(cli, "github", "the-github-token-1234", "--alias", "GITHUB_TOKEN")
    add(cli, "bank", "the-bank-password-5678")


def run_as_agent(cli, token, reference, **kwargs):
    return cli("run", "--env", f"VALUE={reference}", "--", sys.executable, "-c", SHOW,
               env={"IRONDOME_GRANT": token}, **kwargs)


def caps_files():
    return sorted(paths.caps_dir().glob("*.json")) if paths.caps_dir().exists() else []


def test_a_grant_hands_over_exactly_the_value_it_names(cli, two_entries):
    token = grant(cli, "GITHUB_TOKEN")["token"]
    ran = ok(run_as_agent(cli, token, "GITHUB_TOKEN"))
    assert "[irondome:VALUE]" in ran.stdout  # the child got it; what it printed is masked


def test_nothing_the_grant_does_not_name_is_reachable_through_it(cli, two_entries):
    token = grant(cli, "GITHUB_TOKEN", args=("--uses", "10", "--reveal"))["token"]
    agent = {"IRONDOME_GRANT": token}
    for reference in ("bank", "github", "github/username", "BANK", "irondome://bank"):
        refused = fails(cli("get", reference, env=agent), 5)
        assert "the-bank-password-5678" not in refused.stdout + refused.stderr
    refused = fails(run_as_agent(cli, token, "bank"), 5)
    assert "the-bank-password-5678" not in refused.stdout + refused.stderr
    listed = document(cli("ls", "--json", env=agent))
    assert "bank" not in str(listed) and "GITHUB_TOKEN" in str(listed)


def test_a_use_grant_injects_but_never_prints(cli, two_entries):
    token = grant(cli, "GITHUB_TOKEN", args=("--uses", "3"))["token"]
    refused = fails(cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": token}), 5)
    assert "the-github-token-1234" not in refused.stdout


def test_its_uses_run_out_and_then_the_grant_is_destroyed(cli, two_entries):
    created = grant(cli, "GITHUB_TOKEN", args=("--uses", "2"))
    token = created["token"]
    path = paths.caps_dir() / f"{created['id']}.json"
    assert path.exists()
    ok(run_as_agent(cli, token, "GITHUB_TOKEN"))
    ok(run_as_agent(cli, token, "GITHUB_TOKEN"))
    assert not path.exists()
    dead = fails(run_as_agent(cli, token, "GITHUB_TOKEN"), 4)
    assert "used up, expired or revoked" in dead.stderr
    assert "the-github-token-1234" not in dead.stdout + dead.stderr


def test_a_request_the_grant_refuses_spends_none_of_its_uses(cli, two_entries):
    """Only what the grant allows counts against it: an agent asking for the wrong thing burns nothing."""
    created = grant(cli, "GITHUB_TOKEN", args=("--uses", "1"))
    token = created["token"]
    agent = {"IRONDOME_GRANT": token}
    fails(cli("get", "GITHUB_TOKEN", env=agent), 5)  # a use-only grant never reveals
    fails(cli("get", "bank", env=agent), 5)  # nor reads what it does not name
    fails(run_as_agent(cli, token, "bank"), 5)
    assert (paths.caps_dir() / f"{created['id']}.json").exists()
    ok(run_as_agent(cli, token, "GITHUB_TOKEN"))  # its one use was still there
    assert not (paths.caps_dir() / f"{created['id']}.json").exists()


def test_an_expired_grant_is_refused_and_destroyed(two_entries, monkeypatch):
    from conftest import PASSWORD, secret
    from irondome import unlock

    with secret(PASSWORD) as password, unlock.open_vault(password=password, interactive=False) as vault:
        token, info = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60, uses=None)
    path = paths.caps_dir() / f"{info.id}.json"
    with caps.open_grant(token) as opened:
        assert opened.value("GITHUB_TOKEN") == "the-github-token-1234"
    later = time.time() + 61
    monkeypatch.setattr(caps.time, "time", lambda: later)
    with pytest.raises(AuthError, match="expired"):
        caps.open_grant(token)
    assert not path.exists()
    with pytest.raises(AuthError, match="opens nothing here"):
        caps.open_grant(token)


def test_a_grant_opened_in_time_stops_giving_values_when_it_expires(two_entries, monkeypatch):
    from conftest import PASSWORD, secret
    from irondome import unlock

    with secret(PASSWORD) as password, unlock.open_vault(password=password, interactive=False) as vault:
        token, _info = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60, uses=None)
    opened = caps.open_grant(token)
    later = time.time() + 61
    monkeypatch.setattr(caps.time, "time", lambda: later)
    with pytest.raises(AuthError, match="expired"):
        opened.value("GITHUB_TOKEN")
    opened.close()


def test_a_revoked_grant_opens_nothing(cli, two_entries):
    created = grant(cli, "GITHUB_TOKEN", args=("--uses", "5"))
    ok(cli("grant", "revoke", created["id"][:12], "--password-stdin", stdin="correct horse battery staple\n"))
    fails(run_as_agent(cli, created["token"], "GITHUB_TOKEN"), 4)


def test_the_values_are_a_snapshot_later_changes_do_not_reach_the_grant(cli, two_entries):
    token = grant(cli, "GITHUB_TOKEN", args=("--uses", "2", "--reveal"))["token"]
    ok(cli("edit", "github", "--password-stdin", "--value-stdin", stdin="correct horse battery staple\nchanged-9\n"))
    assert ok(cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": token})).stdout == "the-github-token-1234"


# -- the boundary ------------------------------------------------------------------


def test_boundary_the_token_is_a_bearer_secret_any_process_holding_it_can_use_it(cli, two_entries):
    token = grant(cli, "GITHUB_TOKEN", args=("--reveal",))["token"]
    stranger = {"IRONDOME_GRANT": token, "HOME": "/nonexistent-home-of-another-program"}
    assert ok(cli("get", "GITHUB_TOKEN", env=stranger)).stdout == "the-github-token-1234"


def test_boundary_use_counts_are_enforced_by_deleting_the_file_not_by_hardware(cli, two_entries, tmp_path):
    """Whoever can copy the grant file before a use and put it back afterwards gets the use back."""
    token = grant(cli, "GITHUB_TOKEN", args=("--uses", "1"))["token"]
    copy_tree(paths.caps_dir(), tmp_path / "caps-copy")
    ok(run_as_agent(cli, token, "GITHUB_TOKEN"))
    fails(run_as_agent(cli, token, "GITHUB_TOKEN"), 4)
    restore_tree(tmp_path / "caps-copy", paths.caps_dir())
    ok(run_as_agent(cli, token, "GITHUB_TOKEN"))


def test_boundary_revoking_one_grant_is_enforced_by_deleting_its_file(cli, two_entries, tmp_path):
    """Whoever copies the grant file before ``grant revoke`` and puts it back has the grant again, until it expires."""
    created = grant(cli, "GITHUB_TOKEN", args=("--uses", "5"))
    copy_tree(paths.caps_dir(), tmp_path / "caps-copy")
    ok(cli("grant", "revoke", created["id"][:12], "--password-stdin", stdin="correct horse battery staple\n"))
    fails(run_as_agent(cli, created["token"], "GITHUB_TOKEN"), 4)
    restore_tree(tmp_path / "caps-copy", paths.caps_dir())
    ran = ok(run_as_agent(cli, created["token"], "GITHUB_TOKEN"))
    assert "[irondome:VALUE]" in ran.stdout  # the child got the value again; what it printed came back masked


def test_boundary_rekey_ends_a_grant_even_when_its_file_is_put_back(cli, two_entries, tmp_path):
    """rekey destroys the device secret every grant is bound to: a copy of the file put back opens nothing."""
    created = grant(cli, "GITHUB_TOKEN", args=("--uses", "5"))
    copy_tree(paths.caps_dir(), tmp_path / "caps-copy")
    ok(cli("rekey", "--password-stdin", "--yes", stdin="correct horse battery staple\n"))
    restore_tree(tmp_path / "caps-copy", paths.caps_dir())
    dead = fails(run_as_agent(cli, created["token"], "GITHUB_TOKEN"), 4)
    assert "the-github-token-1234" not in dead.stdout + dead.stderr
