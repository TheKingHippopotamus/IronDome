"""Claim ``bunkers-isolated``: several bunkers on one machine, each sealed from the others.

Statement: every bunker has its own vault key, master password, device
secret, recovery key, sessions, grants and audit log. Opening one bunker, or
holding a session or grant for it, gives no access to any other, and
``irondome bunker rm`` destroys one bunker's device secret without touching
the rest.
"""

from __future__ import annotations

import os
import shutil
import sys

import pytest

from conftest import PASSWORD
from irondome import paths
from support.claimkit import add, contents, document, fails, grant, init, irondome_dirs, ok, session

BRAVO_PASSWORD = "a different password for bravo"
BRAVO = {"IRONDOME_BUNKER": "bravo"}


@pytest.fixture
def two_bunkers(cli):
    alpha = init(cli)
    add(cli, "alpha-entry", "alpha-secret-value-1", "--alias", "ALPHA")
    # The owner proves who they are with the default bunker's password, then chooses bravo's.
    created = cli("bunker", "create", "bravo", "--password-stdin", "--json", stdin=f"{PASSWORD}\n{BRAVO_PASSWORD}\n")
    bravo = document(created)
    add(cli, "bravo-entry", "bravo-secret-value-2", "--alias", "BRAVO", password=BRAVO_PASSWORD, env=BRAVO)
    return {"alpha": alpha, "bravo": bravo}


def bunker_dir(root: str, name: str):
    return irondome_dirs()[root] / "bunkers" / name


def assert_no_bravo(result):
    assert "bravo-secret-value-2" not in result.stdout + result.stderr


def test_each_bunker_has_its_own_password(cli, two_bunkers):
    assert_no_bravo(fails(cli("get", "bravo-entry", "--password-stdin", stdin=PASSWORD + "\n", env=BRAVO), 4))
    assert ok(cli("get", "bravo-entry", "--password-stdin", stdin=BRAVO_PASSWORD + "\n", env=BRAVO)).stdout == (
        "bravo-secret-value-2"
    )


def test_each_bunker_has_its_own_recovery_key_and_device_secret(cli, two_bunkers):
    assert two_bunkers["alpha"]["recovery_key"] != two_bunkers["bravo"]["recovery_key"]
    alpha_device = contents(bunker_dir("device", "alpha"))
    bravo_device = contents(bunker_dir("device", "bravo"))
    assert alpha_device and bravo_device
    assert not set(alpha_device.values()) & set(bravo_device.values())


def test_a_session_of_one_bunker_opens_no_other(cli, two_bunkers):
    token = session(cli)
    for env in (dict(BRAVO, IRONDOME_SESSION=token), {"IRONDOME_SESSION": token, "IRONDOME_BUNKER": "bravo"}):
        assert_no_bravo(fails(cli("get", "bravo-entry", env=env), 4))


def test_a_grant_of_one_bunker_reads_nothing_in_another(cli, two_bunkers):
    token = grant(cli, "ALPHA", args=("--uses", "10", "--reveal"))["token"]
    as_agent = {"IRONDOME_GRANT": token}
    assert ok(cli("get", "ALPHA", env=as_agent)).stdout == "alpha-secret-value-1"  # found its own bunker
    assert_no_bravo(fails(cli("get", "BRAVO", env=as_agent), 5))
    assert_no_bravo(cli("get", "BRAVO", env=dict(as_agent, IRONDOME_BUNKER="bravo")))
    ran = cli("run", "--env", "X=BRAVO", "--", sys.executable, "-c", "print('ran')", env=dict(as_agent, **BRAVO))
    assert ran.returncode != 0 and "ran" not in ran.stdout


def test_capability_files_copied_into_another_bunker_open_nothing_there(cli, two_bunkers):
    session_token = session(cli)
    grant_token = grant(cli, "ALPHA", args=("--uses", "10", "--reveal"))["token"]
    paths.ensure_dir(bunker_dir("home", "bravo") / "caps")
    for path in (bunker_dir("home", "alpha") / "caps").glob("*.json"):
        shutil.copy2(str(path), str(bunker_dir("home", "bravo") / "caps" / path.name))
    assert_no_bravo(fails(cli("get", "bravo-entry", env=dict(BRAVO, IRONDOME_SESSION=session_token)), 4))
    through_grant = cli("get", "BRAVO", env=dict(BRAVO, IRONDOME_GRANT=grant_token))
    assert through_grant.returncode in (4, 5)
    assert_no_bravo(through_grant)


def test_creating_or_removing_a_bunker_needs_the_owners_password(cli, two_bunkers):
    refused = fails(cli("bunker", "create", "charlie", "--password-stdin",
                        stdin=f"{BRAVO_PASSWORD}-not-alphas\nanything-123\n"), 4)
    assert "charlie" not in paths.bunkers() and "charlie" not in refused.stdout
    fails(cli("bunker", "rm", "bravo", "--yes", "--password-stdin", stdin=PASSWORD + "\n"), 4)
    assert "bravo" in paths.bunkers()


def test_each_bunker_has_its_own_audit_log(cli, two_bunkers):
    alpha_log = bunker_dir("home", "alpha") / "audit.log"
    bravo_log = bunker_dir("home", "bravo") / "audit.log"
    assert alpha_log.exists() and bravo_log.exists()
    ok(cli("audit", "--verify", "--password-stdin", stdin=PASSWORD + "\n"))
    ok(cli("audit", "--verify", "--password-stdin", stdin=BRAVO_PASSWORD + "\n", env=BRAVO))


def test_removing_one_bunker_destroys_its_device_secret_and_leaves_the_other_working(cli, two_bunkers):
    grant_token = grant(cli, "ALPHA", args=("--uses", "5", "--reveal"))["token"]
    removed = document(cli("bunker", "rm", "bravo", "--yes", "--password-stdin", "--json", stdin=BRAVO_PASSWORD + "\n"))
    assert removed["success"] and removed["device_keys_destroyed"] >= 1
    assert not bunker_dir("device", "bravo").exists() and not bunker_dir("home", "bravo").exists()
    assert "bravo" not in paths.bunkers()
    assert ok(cli("get", "alpha-entry", "--password-stdin", stdin=PASSWORD + "\n")).stdout == "alpha-secret-value-1"
    assert ok(cli("get", "ALPHA", env={"IRONDOME_GRANT": grant_token})).stdout == "alpha-secret-value-1"


# -- the boundary ------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership")
def test_boundary_every_bunker_belongs_to_the_same_user_account(cli, two_bunkers):
    """Bunkers separate vaults, not users: one account owns, and can read, all of them."""
    owners = {os.stat(str(path)).st_uid for path in (bunker_dir("home", "alpha"), bunker_dir("home", "bravo"),
                                                    bunker_dir("device", "alpha"), bunker_dir("device", "bravo"))}
    assert owners == {os.getuid()}
    assert contents(bunker_dir("device", "alpha")) and contents(bunker_dir("device", "bravo"))
