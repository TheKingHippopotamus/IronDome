"""Claim ``migration``: a 3.x vault migrates completely, and the old vault is left alone.

Statement: ``irondome migrate`` reads a 3.x vault in any of its three modes,
writes every entry into a v4 vault, compares each migrated value with the
original and only then reports success. The 3.x directory is not modified
unless you ask for it to be destroyed after a clean verification.

The 3.x vaults are the fixtures in ``tests/fixtures/v3``, written by the 3.x
code itself (see their README). Only modes that need no OS keychain are run
end to end here; the keychain mode is covered by the unit tests.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Dict

import pytest

from conftest import secret
from irondome import unlock
from support.claimkit import document, fails, ok

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "v3"
sys.path.insert(0, str(FIXTURES))
import archive  # noqa: E402 - the fixtures' own loader, which lives beside them

NEW_PASSWORD = "the new master password"


def unpack(name: str, where: Path):
    fixture = archive.load(FIXTURES / f"{name}.json")
    return fixture, archive.unpack(fixture, where / name)


def digests(root: Path) -> Dict[str, str]:
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def migrate(cli, legacy: Path, fixture, *extra: str, password=None):
    lines = [password or fixture["master_password"], NEW_PASSWORD]
    return cli("migrate", "--from", str(legacy), "--legacy-username", fixture["master_username"],
               "--new-password", "--password-stdin", "--json", *extra, stdin="\n".join(lines) + "\n")


@pytest.mark.parametrize("name", ["password_only", "biometric_password", "unicode", "two_hundred", "collisions"])
def test_every_entry_arrives_and_is_verified_and_the_old_vault_is_untouched(cli, tmp_path, name):
    fixture, legacy = unpack(name, tmp_path)
    before = digests(legacy)
    report = document(migrate(cli, legacy, fixture))
    assert report["verified"] is True and report["legacy_destroyed"] is False
    assert report["imported"] == len(fixture["entries"]) and report["skipped"] == [] and report["problems"] == []
    assert digests(legacy) == before
    listing = document(cli("ls", "--password-stdin", "--json", stdin=NEW_PASSWORD + "\n"))["entries"]
    assert len(listing) == len(fixture["entries"])
    first = listing[0]["name"]
    shown = document(cli("get", first, "--password-stdin", "--json", stdin=NEW_PASSWORD + "\n"))
    with secret(NEW_PASSWORD) as password, unlock.open_vault(password=password, interactive=False) as vault:
        migrated = sorted(vault.read_secret(entry).password for entry in vault.list())
        assert shown["value"] == vault.read_secret(vault.find(first)).password
    assert migrated == sorted(entry["password"] for entry in fixture["entries"])


def test_a_wrong_legacy_password_creates_nothing_and_changes_nothing(cli, tmp_path):
    fixture, legacy = unpack("password_only", tmp_path)
    before = digests(legacy)
    refused = migrate(cli, legacy, fixture, password="not the 3.x password")
    assert refused.returncode == 4
    assert digests(legacy) == before
    fails(cli("ls", "--password-stdin", stdin=NEW_PASSWORD + "\n"), 6)


def test_the_old_vault_is_destroyed_only_when_asked_and_only_after_a_clean_verification(cli, tmp_path):
    fixture, legacy = unpack("password_only", tmp_path)
    report = document(migrate(cli, legacy, fixture, "--destroy-old", "--yes"))
    assert report["verified"] is True and report["legacy_destroyed"] is True
    left = [path for path in legacy.rglob("*") if path.is_file()] if legacy.exists() else []
    assert left == []
    ok(cli("ls", "--password-stdin", stdin=NEW_PASSWORD + "\n"))


# -- the boundary ------------------------------------------------------------------


@pytest.mark.parametrize("name", ["v1_1_0", "v1_0_0", "script_2025"])
def test_boundary_vaults_written_before_3x_are_read_too(cli, tmp_path, name):
    """Vaults written before the 3.x format (1.x, and the 2025 script's) need no 3.2.2 first: migrate reads them."""
    fixture, legacy = unpack(name, tmp_path)
    before = digests(legacy)
    report = document(migrate(cli, legacy, fixture))
    assert report["verified"] is True
    assert digests(legacy) == before
