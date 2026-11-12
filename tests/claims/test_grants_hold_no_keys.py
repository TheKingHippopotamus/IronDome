"""Claim ``grants-hold-no-keys``: a grant never contains the vault key, the master password or an OTP seed.

Statement: a grant is a separate encrypted snapshot of the named values. It
cannot be turned into access to the rest of the vault: it holds neither the
vault key nor the master password. A grant for a one-time-password field
contains only the codes valid during its lifetime, never the seed that
generates them.

How "it holds no X" is shown without reading IronDome's file format: a fresh
process that has only the grant token opens the grant and reads every value,
then searches its own writable memory (``irondome.memscan``) for the vault
key (raw, base64, hex), the master password and the seed (base32 and raw).
Whatever the grant held, that process decrypted and parsed. The granted value
itself must be found there, or the search would prove nothing.
"""

from __future__ import annotations

import base64
import os
import time

import pytest

from conftest import PASSWORD, secret
from irondome import audit, caps, memscan, otp, selftest, unlock
from irondome.errors import AuthError
from irondome.vault import Secret, VaultFile
from support.claimkit import TOTP_SEED, add, fails, grant, init, ok, session

pytestmark = pytest.mark.skipif(not memscan.supported()[0], reason=memscan.supported()[1] or "scanner unavailable")


@pytest.fixture
def granted(make_vault):
    vault, _recovery = make_vault()
    with vault:
        entry = vault.add("github", Secret(password="the-granted-value-1234", totp=otp.make_totp(TOTP_SEED)))
        vault.add("bank", Secret(password="never-granted-5678"))
        vault.set_alias("GITHUB_TOKEN", entry, "password")
        vault.commit()
        token, info = caps.create_grant(vault, ["GITHUB_TOKEN", "github/totp"], ttl=900, uses=3)
        vault_key = bytes(vault.vault_key.view())
    return token, info, vault_key


def test_a_process_holding_only_the_grant_has_no_key_password_or_seed_in_memory(granted, tmp_path):
    token, _info, vault_key = granted
    needles = {
        "vault key": vault_key,
        "vault key, base64": base64.b64encode(vault_key),
        "vault key, hex": vault_key.hex().encode(),
        "master password": PASSWORD.encode(),
        "seed": TOTP_SEED.encode(),
        "seed, bytes": base64.b32decode(TOTP_SEED),
    }
    environment = {"IRONDOME_DEVICE_BACKEND": "software", "IRONDOME_HOME": os.environ["IRONDOME_HOME"],
                   "IRONDOME_DEVICE_DIR": os.environ["IRONDOME_DEVICE_DIR"]}
    report = selftest.memory_probe(tmp_path, "grant", secret=token, needles=needles,
                                   controls={"granted value": "the-granted-value-1234"}, environment=environment)
    held = {needle["label"]: needle["hits"] for needle in report["needles"] if needle["kind"] == "key"}
    assert set(held) == set(needles)
    assert {label: hits for label, hits in held.items() if hits} == {}
    seen = [needle for needle in report["needles"] if needle["kind"] == "value" and needle["hits"]]
    assert seen, "the search did not find the granted value either, so it proves nothing"
    freed = [needle for needle in report["needles"] if needle["kind"] == "control-dropped"]
    assert freed and all(needle["hits"] for needle in freed), "the search missed a copy freed just before it"
    assert report["session_refused"] is True


def test_a_grant_token_is_not_a_session_token(granted):
    token, _info, _key = granted
    with pytest.raises(AuthError, match="grant token, not a session token"):
        caps.open_session(token, VaultFile.load())


def test_an_agent_with_the_grant_and_a_copy_of_everything_on_disk_reads_nothing_else(cli):
    init(cli)
    add(cli, "github", "the-granted-value-1234", "--alias", "GITHUB_TOKEN")
    add(cli, "bank", "never-granted-5678")
    token = grant(cli, "GITHUB_TOKEN", args=("--uses", "10", "--reveal"))["token"]
    as_session = fails(cli("get", "bank", env={"IRONDOME_SESSION": token}), 4)
    as_grant = fails(cli("get", "bank", env={"IRONDOME_GRANT": token}), 5)
    for result in (as_session, as_grant):
        assert "never-granted-5678" not in result.stdout + result.stderr
    assert ok(cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": token})).stdout == "the-granted-value-1234"


def test_a_one_time_password_grant_gives_the_right_codes_for_its_lifetime_and_no_longer(cli, monkeypatch):
    init(cli)
    add(cli, "github", "a-password-1234", totp=TOTP_SEED)
    created = grant(cli, "github/totp", args=("--uses", "5", "--ttl", "2m"))
    agent = {"IRONDOME_GRANT": created["token"]}
    code = ok(cli("otp", "github/totp", env=agent)).stdout.strip()
    settings = otp.make_totp(TOTP_SEED)
    now = time.time()
    assert code in {otp.code_at(settings, now + drift) for drift in (-30, 0, 30)}
    with caps.open_grant(created["token"], consume=False) as looked_at:
        assert looked_at.is_totp("github/totp")
    later = created["expires"] + 31
    monkeypatch.setattr(caps.time, "time", lambda: later)
    with pytest.raises(AuthError, match="expired"):
        caps.open_grant(created["token"])


# -- the boundary ------------------------------------------------------------------


def test_boundary_the_grant_signs_its_own_audit_records_and_only_those(granted):
    token, info, _key = granted
    with caps.open_grant(token) as opened:
        opened.value("GITHUB_TOKEN")
    with secret(PASSWORD) as password, unlock.open_vault(password=password, interactive=False) as vault:
        events = audit.read(vault)
        report = audit.verify(vault)
    assert report.ok
    by_grant = [event for event in events if event.kid == info.id]
    assert by_grant and all(event.actor == "grant" for event in by_grant)
    assert [event for event in events if event.kid == audit.KID_VAULT and event.actor == "grant"] == []


def test_boundary_a_session_token_is_different_it_wraps_the_vault_key(cli):
    init(cli)
    add(cli, "bank", "never-granted-5678")
    token = session(cli)
    assert ok(cli("get", "bank", env={"IRONDOME_SESSION": token})).stdout == "never-granted-5678"
