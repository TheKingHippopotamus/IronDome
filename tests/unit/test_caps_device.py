"""Sessions and grants are bound to the machine they were made on.

A capability is sealed under a key made from its token *and* the vault's
capability device secret. These tests check what follows from that: taken to
another machine, or kept after the device secret was destroyed (by ``nuke``
above all), a capability opens nothing, whichever token is presented, while
on this machine it works exactly as before.

Backends
--------
* the file-based backend, everywhere: another device directory is another machine;
* the TPM backend against the FakeTpm of ``test_device_tpm``, everywhere, and
  against a software TPM in the Linux container (``tpm``; scripts/test-linux.sh);
* this Mac's real Secure Enclave (``secure_enclave``), under the device policy
  only: nothing here can put a Touch ID prompt on the screen.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pytest
from test_device_tpm import FakeTpm, another_tpm, failed_tries, nv_handles, tpm2

from conftest import PASSWORD, secret
from irondome import audit, caps, device, nuke, paths
from irondome.device import linux_tpm
from irondome.device.base import Probe
from irondome.device.linux_tpm import Tpm2Backend
from irondome.errors import AuthError, HardwareError, IronDomeError, LockedOutError, NotFoundError, VaultError
from irondome.secmem import SecureBuffer
from irondome.unlock import open_vault
from irondome.vault import Secret, Vault, VaultFile

GITHUB_PASSWORD = "hunter2-Github!"
DEAD = "belongs to another machine or to a vault that was destroyed"
DAMAGED = "damaged or was altered"

posix_only = pytest.mark.skipif(os.name == "nt", reason="the TPM backend and its FakeTpm need POSIX")


@pytest.fixture(autouse=True)
def still_isolated(isolated):
    """Fail any test that ends up pointing at paths outside its temporary directory."""
    yield
    for path in (paths.home(), paths.caps_dir(), paths.device_dir()):
        assert str(path).startswith(str(isolated))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def cap_path(token: str) -> Path:
    return paths.caps_dir() / f"{caps.parse_token(token)[1]}.json"


def header_of(token: str) -> Dict[str, Any]:
    return json.loads(cap_path(token).read_bytes())


def rewrite(token: str, change: Callable[[Dict[str, Any]], None]) -> None:
    """Edit the clear header and write it back exactly as IronDome formats a file."""
    document = header_of(token)
    change(document)
    cap_path(token).write_bytes((json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"))


def bound(vault: Vault) -> Dict[str, Any]:
    """The capability device descriptor the vault's encrypted index records."""
    return vault.meta["cap_device"]


def key_files() -> List[str]:
    """The file-based backend's device secrets on this machine."""
    directory = paths.device_dir()
    return sorted(path.name for path in directory.glob("*.key")) if directory.is_dir() else []


def files_under(directory: Path) -> Dict[str, bytes]:
    """Every file below *directory*, by relative name, with its exact bytes."""
    found = sorted(path for path in directory.rglob("*") if path.is_file())
    return {str(path.relative_to(directory)): path.read_bytes() for path in found}


def reopen(password: str = PASSWORD) -> Vault:
    with secret(password) as typed:
        return open_vault(password=typed, interactive=False)


def filled(make_vault: Callable[..., Tuple[Vault, Optional[str]]]) -> Tuple[Vault, Optional[str]]:
    """A new vault (on whatever backend is selected) with one login and an alias for its password."""
    opened, recovery = make_vault()
    github = opened.add("github", Secret(password=GITHUB_PASSWORD), username="king")
    opened.set_alias("GITHUB_TOKEN", github)
    opened.commit()
    return opened, recovery


class Machine:
    """Switch this process between the machine the vault was made on and others."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self.monkeypatch = monkeypatch
        self.tmp_path = tmp_path
        self.home = (os.environ["IRONDOME_HOME"], os.environ["IRONDOME_DEVICE_DIR"])

    def elsewhere(self, name: str = "another-machine") -> Path:
        """Copy the vault side (vault, capabilities, log) to another machine, whose device side is its own."""
        machine = self.tmp_path / name
        shutil.copytree(paths.root(), machine / "irondome")
        self._use(str(machine / "irondome"), str(machine / "device"))
        return machine

    def back(self) -> None:
        self._use(*self.home)

    def _use(self, home: str, device_dir: str) -> None:
        self.monkeypatch.setenv("IRONDOME_HOME", home)
        self.monkeypatch.setenv("IRONDOME_DEVICE_DIR", device_dir)
        device._instances.clear()


@pytest.fixture
def machine(monkeypatch, tmp_path) -> Machine:
    return Machine(monkeypatch, tmp_path)


def assert_dead(session: Optional[str], grant: Optional[str], file: Optional[VaultFile] = None) -> None:
    """Neither token opens anything, and the refusal says why without repeating either token."""
    attempts: List[Tuple[str, Callable[[], Any]]] = []
    if session is not None:
        attempts.append((session, lambda: caps.open_session(session, file or VaultFile.load())))
    if grant is not None:
        attempts.append((grant, lambda: caps.open_grant(grant)))
        attempts.append((grant, lambda: caps.open_grant(grant, consume=False)))
    for token, attempt in attempts:
        with pytest.raises(AuthError, match=DEAD) as caught:
            attempt()
        assert type(caught.value) is AuthError and caught.value.exit_code == 4
        assert token not in str(caught.value) and token.rsplit("_", 1)[1] not in str(caught.value)


def assert_alive(session: Optional[str], grant: Optional[str], file: Optional[VaultFile] = None) -> None:
    if session is not None:
        caps.open_session(session, file or VaultFile.load()).wipe()
    if grant is not None:
        with caps.open_grant(grant, consume=False) as looked_at:
            assert looked_at.has("GITHUB_TOKEN")


# ---------------------------------------------------------------------------
# Binding: made once per vault, recorded in its index, copied into every header
# ---------------------------------------------------------------------------


def test_a_vault_has_no_capability_device_secret_until_its_first_session(vault):
    assert "cap_device" not in vault.meta
    keyslot_keys = key_files()
    assert len(keyslot_keys) == 1, "the password keyslot's own device key"
    generation = vault.file.generation

    token = caps.create_session(vault)

    descriptor = bound(vault)
    assert set(descriptor) == {"backend", "policy", "ref"}
    assert (descriptor["backend"], descriptor["policy"]) == ("software", "device")
    assert key_files() == sorted(keyslot_keys + [f"{descriptor['ref']}.key"])
    assert vault.file.generation == generation + 1, "recorded by committing the vault"
    with reopen() as again:
        assert again.meta["cap_device"] == descriptor
    assert header_of(token)["device"] == descriptor
    assert descriptor["ref"].encode() not in paths.vault_file().read_bytes(), "the index that records it is encrypted"


def test_later_sessions_and_grants_reuse_it_and_leave_the_vault_alone(vault):
    first = caps.create_session(vault)
    generation, keys_now = vault.file.generation, key_files()

    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    second = caps.create_session(vault, ttl=60)

    assert vault.file.generation == generation and key_files() == keys_now
    assert header_of(first)["device"] == header_of(grant)["device"] == header_of(second)["device"] == bound(vault)
    assert_alive(first, grant, vault.file)
    caps.open_session(second, vault.file).wipe()


def test_the_first_grant_binds_the_vault_as_well(vault):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert header_of(token)["device"] == bound(vault)
    assert caps.open_grant(token).value("GITHUB_TOKEN") == GITHUB_PASSWORD


def test_a_grant_that_cannot_be_made_binds_nothing_and_commits_nothing(vault):
    vault.add("pending", Secret(password="not committed"))
    keys_now, generation = key_files(), vault.file.generation

    with pytest.raises(NotFoundError):
        caps.create_grant(vault, ["GITHUB_TOKEN", "nope"])

    assert "cap_device" not in vault.meta and key_files() == keys_now and vault.file.generation == generation
    with reopen() as again:
        assert not again.has_name("pending")


def test_the_first_capability_commits_what_is_pending_in_the_vault(vault):
    """The documented side effect: recording the device secret commits the vault object passed in."""
    vault.add("pending", Secret(password="written together with the binding"))

    caps.create_session(vault)

    with reopen() as again:
        assert again.has_name("pending") and again.meta["cap_device"] == bound(vault)


def test_a_locked_vault_binds_nothing(vault):
    keys_now = key_files()
    vault.close()

    with pytest.raises(VaultError):
        caps.create_session(vault)
    with pytest.raises(IronDomeError):
        caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert key_files() == keys_now and caps.list_caps() == []


def test_a_binding_that_cannot_be_recorded_is_destroyed_again(vault):
    """Another process changed the vault in the meantime: the device secret made for it is not left behind."""
    with reopen() as other:
        other.add("meanwhile", Secret(password="written by another process"))
        other.commit()
    keys_now = key_files()

    with pytest.raises(VaultError, match="changed on disk"):
        caps.create_session(vault)

    assert key_files() == keys_now and "cap_device" not in vault.meta
    assert caps.list_caps() == [] and audit.read(vault) == []
    with reopen() as again:
        assert "cap_device" not in again.meta
        token = caps.create_session(again)
    caps.open_session(token, VaultFile.load()).wipe()


def test_two_vault_objects_racing_to_bind_end_with_one_device_secret(vault):
    other = reopen()
    try:
        first = caps.create_session(vault)
        with pytest.raises(VaultError, match="changed on disk"):
            caps.create_session(other)
    finally:
        other.close()
    with reopen() as again:
        second = caps.create_session(again)
        assert again.meta["cap_device"] == bound(vault)

    assert len(key_files()) == 2, "the keyslot's and one for every capability"
    assert_alive(first, None)
    assert_alive(second, None)


# ---------------------------------------------------------------------------
# Another machine
# ---------------------------------------------------------------------------


def test_a_session_and_a_grant_taken_to_another_machine_open_nothing(vault, machine):
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=3)

    machine.elsewhere()
    capabilities, log = files_under(paths.caps_dir()), paths.audit_file().read_bytes()
    assert_dead(session, grant)
    assert files_under(paths.caps_dir()) == capabilities, "nothing was spent, nothing deleted"
    assert paths.audit_file().read_bytes() == log

    machine.back()
    assert_alive(session, grant)
    assert caps.open_grant(grant).uses_left == 2


def test_a_device_key_planted_under_the_same_name_on_another_machine_opens_nothing(vault, machine):
    """The descriptor in a header is public; the secret is not. A file planted under its name gives another key."""
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    reference = bound(vault)["ref"]

    machine.elsewhere()
    paths.ensure_dir(paths.device_dir())
    (paths.device_dir() / f"{reference}.key").write_bytes(os.urandom(32))

    with pytest.raises(AuthError, match="does not open its session"):
        caps.open_session(session, VaultFile.load())
    with pytest.raises(AuthError, match="does not open its grant"):
        caps.open_grant(grant)


def test_another_machine_with_a_vault_of_its_own_opens_nothing_of_this_one(vault, machine, make_vault):
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])
    copied = machine.elsewhere()

    theirs, _ = make_vault(path=copied / "their-vault.irondome")
    caps.open_session(caps.create_session(theirs), theirs.file).wipe()
    assert bound(theirs)["ref"] != bound(vault)["ref"]

    assert_dead(session, grant)


OPENER = """
import os
from irondome import caps
from irondome.errors import IronDomeError
from irondome.vault import VaultFile

try:
    caps.open_session(os.environ["IRONDOME_SESSION"], VaultFile.load()).wipe()
    print("session opened")
except IronDomeError as exc:
    print(f"session refused with exit status {exc.exit_code}: {exc}")
try:
    with caps.open_grant(os.environ["IRONDOME_GRANT"]) as grant:
        print("grant opened, value of", len(grant.value("GITHUB_TOKEN")), "characters")
except IronDomeError as exc:
    print(f"grant refused with exit status {exc.exit_code}: {exc}")
"""


def test_another_process_with_another_device_directory_is_refused_and_told_why(vault, tmp_path):
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)

    def run(device_root: Path) -> "subprocess.CompletedProcess[str]":
        environment = dict(
            os.environ, IRONDOME_SESSION=session, IRONDOME_GRANT=grant, IRONDOME_DEVICE_DIR=str(device_root)
        )
        return subprocess.run(
            [sys.executable, "-c", OPENER], env=environment, capture_output=True, text=True, timeout=120
        )

    here = run(paths.device_root())
    elsewhere = run(tmp_path / "another-machine" / "device")

    assert (here.returncode, here.stderr) == (0, "")
    assert here.stdout.splitlines() == ["session opened", f"grant opened, value of {len(GITHUB_PASSWORD)} characters"]
    assert (elsewhere.returncode, elsewhere.stderr) == (0, "")
    refused = elsewhere.stdout.splitlines()
    assert len(refused) == 2
    assert refused[0].startswith("session refused with exit status 4: that session token cannot be used here")
    assert refused[1].startswith("grant refused with exit status 4: that grant token cannot be used here")
    assert all(DEAD in line for line in refused)
    for output in (here.stdout, elsewhere.stdout):
        assert GITHUB_PASSWORD not in output
        for token in (session, grant):
            assert token not in output and token.rsplit("_", 1)[1] not in output


# ---------------------------------------------------------------------------
# A destroyed device secret
# ---------------------------------------------------------------------------


def test_once_the_device_secret_is_destroyed_a_restored_copy_of_the_capabilities_opens_nothing(vault, tmp_path):
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    copy = tmp_path / "copy-of-caps"
    shutil.copytree(paths.caps_dir(), copy)
    descriptor = dict(bound(vault))

    device.get_backend("software").destroy(descriptor)
    shutil.rmtree(paths.caps_dir())
    shutil.copytree(copy, paths.caps_dir())

    assert files_under(paths.caps_dir()) == files_under(copy), "bit for bit, tokens unchanged"
    assert_dead(session, grant, vault.file)
    fresh = caps.create_session(vault)
    assert bound(vault)["ref"] != descriptor["ref"]
    caps.open_session(fresh, vault.file).wipe()
    assert_dead(session, grant, vault.file)


def test_destroying_every_device_secret_kills_them_and_only_the_recovery_key_opens_the_vault(make_vault, tmp_path):
    opened, recovery = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"])
    copy = tmp_path / "copy-of-caps"
    shutil.copytree(paths.caps_dir(), copy)
    assert recovery is not None

    assert device.get_backend("software").destroy_all() == 2, "the keyslot's and the capabilities'"
    shutil.rmtree(paths.caps_dir())
    shutil.copytree(copy, paths.caps_dir())

    assert_dead(session, grant)
    with pytest.raises(HardwareError, match="not on this machine"):
        reopen()
    with open_vault(recovery_key=recovery) as recovered:
        assert recovered.value(recovered.find("github")) == GITHUB_PASSWORD
        fresh = caps.create_session(recovered)
    caps.open_session(fresh, VaultFile.load()).wipe()


def test_nuke_then_a_bit_perfect_copy_of_the_vault_directory_opens_with_the_recovery_key_only(make_vault, tmp_path):
    """The hole the lead found: a session token opened a vault restored after nuke."""
    opened, recovery = filled(make_vault)
    session = caps.create_session(opened, ttl=3600)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"], uses=None, ttl=3600)
    assert_alive(session, grant)
    assert caps.open_grant(grant).value("GITHUB_TOKEN") == GITHUB_PASSWORD
    old_reference = bound(opened)["ref"]
    opened.close()
    copy = tmp_path / "copy-of-the-vault-directory"
    shutil.copytree(paths.root(), copy)
    assert recovery is not None

    report = nuke.execute()

    assert report.success, report.errors
    assert report.device_keys_destroyed == 2, "the keyslot's device secret and the capabilities'"
    assert not paths.root().exists()
    shutil.copytree(copy, paths.root())
    assert files_under(paths.root()) == files_under(copy), "a complete, bit-perfect copy is back"
    log = paths.audit_file().read_bytes()

    assert_dead(session, grant)
    with pytest.raises(HardwareError, match="not on this machine"):
        reopen()
    assert paths.audit_file().read_bytes() == log and files_under(paths.caps_dir()) == files_under(
        copy / "bunkers" / "alpha" / "caps"
    )
    with open_vault(recovery_key=recovery) as recovered:
        assert recovered.value(recovered.find("github")) == GITHUB_PASSWORD
        fresh = caps.create_session(recovered)
        assert bound(recovered)["ref"] != old_reference, "a new device secret was bound"
    caps.open_session(fresh, VaultFile.load()).wipe()
    assert_dead(session, grant)


def test_destroy_device_kills_every_capability_of_the_vault_and_every_copy(vault, tmp_path):
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    copy = tmp_path / "copy-of-caps"
    shutil.copytree(paths.caps_dir(), copy)
    keys_now, generation = key_files(), vault.file.generation

    assert caps.destroy_device(vault) == 1

    assert len(key_files()) == len(keys_now) - 1 and vault.file.generation == generation, "nothing is committed"
    assert files_under(paths.caps_dir()) == files_under(copy), "the files are left to destroy_all"
    assert_dead(session, grant, vault.file)
    assert caps.destroy_device(vault) == 0, "already gone"
    fresh = caps.create_session(vault)
    caps.open_session(fresh, vault.file).wipe()
    assert_dead(session, grant, vault.file)


def test_destroy_device_of_a_vault_that_was_never_bound_does_nothing(vault):
    keys_now = key_files()

    assert caps.destroy_device(vault) == 0

    assert key_files() == keys_now


def test_a_vault_that_copied_the_index_of_one_whose_device_secret_was_destroyed_binds_anew(vault, make_vault, tmp_path):
    """What rekey does: the new vault copies the old index, and the old capabilities must die with the old keys."""
    old_session = caps.create_session(vault)
    rekeyed, _ = make_vault(path=tmp_path / "rekeyed" / "vault.irondome")
    rekeyed.meta = dict(vault.meta)
    rekeyed.commit()

    assert caps.destroy_device(vault) == 1
    token = caps.create_session(rekeyed)

    assert bound(rekeyed)["ref"] != bound(vault)["ref"]
    caps.open_session(token, rekeyed.file).wipe()
    assert_dead(old_session, None, vault.file)


def test_dead_capabilities_can_still_be_listed_ended_revoked_and_swept(vault, monkeypatch):
    session = caps.create_session(vault, ttl=60)
    grant, info = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    other, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    assert caps.destroy_device(vault) == 1

    assert sorted(found.kind for found in caps.list_caps()) == ["grant", "grant", "session"]
    assert caps.revoke(info.id) == 1 and caps.end_sessions(session) == 1
    later = time.time() + 61
    monkeypatch.setattr(time, "time", lambda: later)
    assert caps.sweep(vault=vault) == 1
    assert caps.list_caps() == [] and not cap_path(grant).exists() and not cap_path(other).exists()


def test_an_expired_grant_whose_device_secret_is_gone_is_still_refused_and_destroyed(vault, monkeypatch):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=60)
    assert caps.destroy_device(vault) == 1
    log = paths.audit_file().read_bytes()
    later = time.time() + 61
    monkeypatch.setattr(time, "time", lambda: later)

    with pytest.raises(AuthError, match="expired"):
        caps.open_grant(token)

    assert not cap_path(token).exists()
    assert paths.audit_file().read_bytes() == log, "without the device secret the refusal cannot be signed"


# ---------------------------------------------------------------------------
# Through the command line (the `cli` fixture: `python -m irondome` in a subprocess)
# ---------------------------------------------------------------------------

OWNER = PASSWORD + "\n"


def cli_vault(cli: Callable[..., "subprocess.CompletedProcess[str]"]) -> Dict[str, str]:
    """A vault made with the real command line: one login, a reveal grant for it, a session. Returns the tokens."""
    made = cli("init", "--password-stdin", "--json", stdin=OWNER)
    assert made.returncode == 0, made.stderr
    value = OWNER + GITHUB_PASSWORD + "\n"
    added = cli("add", "github", "--value-stdin", "--alias", "GITHUB_TOKEN", "--password-stdin", stdin=value)
    assert added.returncode == 0, added.stderr
    granted = cli(
        "grant", "create", "GITHUB_TOKEN", "--unlimited", "--reveal", "--json", "--password-stdin", stdin=OWNER
    )
    assert granted.returncode == 0, granted.stderr
    started = cli("unlock", "--json", "--password-stdin", stdin=OWNER)
    assert started.returncode == 0, started.stderr
    return {
        "grant": json.loads(granted.stdout)["token"],
        "session": json.loads(started.stdout)["token"],
        "recovery": json.loads(made.stdout)["recovery_key"],
    }


def assert_nothing_leaked(tokens: Dict[str, str], *runs: "subprocess.CompletedProcess[str]") -> None:
    for run in runs:
        for output in (run.stdout, run.stderr):
            assert GITHUB_PASSWORD not in output and tokens["recovery"] not in output
            for name in ("grant", "session"):
                assert tokens[name] not in output and tokens[name].rsplit("_", 1)[1] not in output


def test_cli_a_grant_used_from_another_machine_is_refused_with_exit_status_4(cli, tmp_path):
    tokens = cli_vault(cli)

    here = cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": tokens["grant"]})
    elsewhere = cli(
        "get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": tokens["grant"], "IRONDOME_DEVICE_DIR": str(tmp_path / "other")}
    )
    session_elsewhere = cli(
        "ls", env={"IRONDOME_SESSION": tokens["session"], "IRONDOME_DEVICE_DIR": str(tmp_path / "other")}
    )

    assert (here.returncode, here.stdout.strip()) == (0, GITHUB_PASSWORD)
    assert (elsewhere.returncode, elsewhere.stdout) == (4, "") and DEAD in elsewhere.stderr
    assert session_elsewhere.returncode == 4 and session_elsewhere.stdout == ""
    assert "ignoring IRONDOME_SESSION" in session_elsewhere.stderr and DEAD in session_elsewhere.stderr
    assert_nothing_leaked(tokens, elsewhere, session_elsewhere)


def test_cli_nuke_then_a_restored_copy_of_the_vault_directory_refuses_both_tokens(cli, tmp_path):
    """The lead's test, end to end: nuke, put a bit-perfect copy of the vault directory back, present the tokens."""
    tokens = cli_vault(cli)
    assert cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": tokens["grant"]}).returncode == 0
    copy = tmp_path / "copy-of-the-vault-directory"
    shutil.copytree(paths.root(), copy)

    nuked = cli("nuke", "--yes-destroy-everything", "--password-stdin", "--json", stdin=OWNER)
    assert nuked.returncode == 0, nuked.stderr
    assert json.loads(nuked.stdout)["success"] is True and not paths.root().exists()
    shutil.copytree(copy, paths.root())
    assert files_under(paths.root()) == files_under(copy)

    grant = cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": tokens["grant"]})
    session = cli("ls", env={"IRONDOME_SESSION": tokens["session"]})
    password = cli("ls", "--password-stdin", stdin=OWNER)

    assert (grant.returncode, grant.stdout) == (4, "") and DEAD in grant.stderr
    assert (session.returncode, session.stdout) == (4, "") and DEAD in session.stderr
    assert (password.returncode, password.stdout) == (7, "") and "not on this machine" in password.stderr
    assert_nothing_leaked(tokens, grant, session, password)
    assert files_under(paths.root()) == files_under(copy), "the refusals changed nothing"


# ---------------------------------------------------------------------------
# The descriptor in the header: hostile input, and sealed in
# ---------------------------------------------------------------------------


def test_a_descriptor_pointed_at_another_device_secret_of_this_machine_opens_nothing(vault):
    """Not even at the vault's own keyslot secret: what the key was made from is bound into the file."""
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=2)
    keyslot = next(slot.device for slot in vault.file.slots if slot.device is not None)
    assert keyslot is not None

    for token, refusal in ((session, "does not open its session"), (grant, "does not open its grant")):
        original = cap_path(token).read_bytes()
        rewrite(token, lambda document: document["device"].update(ref=keyslot["ref"]))
        with pytest.raises(AuthError, match=refusal):
            caps.open_session(token, vault.file) if token == session else caps.open_grant(token)
        cap_path(token).write_bytes(original)

    assert caps.open_grant(grant).uses_left == 1, "the refused attempt spent nothing"


def test_the_descriptor_is_sealed_in_even_where_the_device_key_it_gives_is_the_same(vault):
    """A copy of the very secret under another name: only the associated data differs, and it is refused."""
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    reference = bound(vault)["ref"]
    twin = "e" * 32 if reference != "e" * 32 else "f" * 32
    shutil.copyfile(paths.device_dir() / f"{reference}.key", paths.device_dir() / f"{twin}.key")

    rewrite(session, lambda document: document["device"].update(ref=twin))
    rewrite(grant, lambda document: document["device"].update(ref=twin))

    with pytest.raises(AuthError, match="does not open its session"):
        caps.open_session(session, vault.file)
    with pytest.raises(AuthError, match="does not open its grant"):
        caps.open_grant(grant)


@pytest.mark.parametrize(
    "backend, extra",
    [("macos-se", {}), ("linux-tpm2", {"nv_index": "0x018abcde"})],
    ids=["secure enclave", "tpm"],
)
def test_a_descriptor_moved_to_another_backend_finds_nothing_and_opens_nothing(vault, backend, extra):
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"])

    for token in (session, grant):
        rewrite(token, lambda document: document["device"].update(backend=backend, **extra))

    assert_dead(session, grant, vault.file)


DESCRIPTOR_EDITS: Dict[str, Callable[[Dict[str, Any]], None]] = {
    "a biometric policy": lambda device_: device_.update(policy="biometry"),
    "an unknown backend": lambda device_: device_.update(backend="windows-tpm"),
    "an extra field": lambda device_: device_.update(extra="x"),
    "no reference": lambda device_: device_.pop("ref"),
    "an upper-case reference": lambda device_: device_.update(ref=device_["ref"].upper()),
    "a reference that is a path": lambda device_: device_.update(ref="../../" + device_["ref"][6:]),
    "a reference that is a number": lambda device_: device_.update(ref=7),
    "an index on a backend without them": lambda device_: device_.update(nv_index="0x018abcde"),
}


@pytest.mark.parametrize("consume", [True, False])
@pytest.mark.parametrize("name", sorted(DESCRIPTOR_EDITS))
def test_a_grant_whose_descriptor_is_not_what_irondome_writes_is_refused_as_altered(vault, name, consume):
    token, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=2)
    log = paths.audit_file().read_bytes()
    rewrite(token, lambda document: DESCRIPTOR_EDITS[name](document["device"]))

    with pytest.raises(AuthError, match=DAMAGED):
        caps.open_grant(token, consume=consume)

    assert caps.list_caps() == [] and paths.audit_file().read_bytes() == log


# ---------------------------------------------------------------------------
# Re-creating the device secret
# ---------------------------------------------------------------------------


def test_a_recorded_device_secret_that_is_gone_is_replaced_and_recorded(vault):
    old = caps.create_session(vault)
    descriptor = dict(bound(vault))
    device.get_backend("software").destroy(descriptor)
    generation = vault.file.generation

    new = caps.create_session(vault)

    assert bound(vault)["ref"] != descriptor["ref"] and vault.file.generation == generation + 1
    with reopen() as again:
        assert again.meta["cap_device"] == bound(vault)
    caps.open_session(new, vault.file).wipe()
    assert_dead(old, None, vault.file)


@pytest.mark.parametrize(
    "recorded",
    [
        {"backend": "linux-tpm2", "policy": "device", "ref": "ab" * 16, "nv_index": "0x018abcde"},
        {"backend": "macos-se", "policy": "device", "ref": "ab" * 16},
        {"backend": "software", "policy": "device", "ref": "ab" * 16},
        {"backend": "windows-tpm", "policy": "device", "ref": "ab" * 16},
        {"backend": "software", "policy": "biometry", "ref": "ab" * 16},
        {},
        "software",
        ["software"],
    ],
    ids=["tpm of another machine", "mac of another machine", "file of another machine", "unknown backend",
         "biometric policy", "empty", "text", "list"],
)
def test_a_recorded_device_secret_this_machine_cannot_give_is_replaced(vault, recorded):
    """The vault was restored here with its recovery key from another machine, or written by something else."""
    vault.meta["cap_device"] = recorded
    vault.commit()

    token = caps.create_session(vault)

    assert bound(vault)["backend"] == "software" and bound(vault)["ref"] != "ab" * 16
    caps.open_session(token, vault.file).wipe()
    descriptor = isinstance(recorded, dict) and recorded.get("policy") == "device" and recorded.get("backend") in (
        "linux-tpm2", "macos-se", "software")
    assert retired(vault) == ([recorded] if descriptor else []), "a descriptor is kept; anything else cannot be"
    if isinstance(recorded, dict) and recorded.get("backend") == "linux-tpm2" and device.applies_here("linux-tpm2"):
        try:
            device.get_backend("linux-tpm2").exists(recorded)
        except IronDomeError:
            # Linux, and no TPM that can be asked (GitHub's Linux machines have neither the chip nor
            # tpm2-tools). The index could be in this machine's own chip, so it is not called gone.
            with pytest.raises(HardwareError, match=r"\(1 was\).*linux-tpm2 device key.*could not be checked"):
                caps.destroy_device(vault)
            return
    assert caps.destroy_device(vault) == 1, "the one made here; the other machine's is not here to destroy"


def test_a_damaged_device_secret_is_replaced_and_its_capabilities_say_it_cannot_be_used(vault):
    old = caps.create_session(vault)
    descriptor = dict(bound(vault))
    damaged = paths.device_dir() / f"{bound(vault)['ref']}.key"
    damaged.write_bytes(b"short")

    with pytest.raises(HardwareError, match="cannot be used: the device key file is damaged") as caught:
        caps.open_session(old, vault.file)
    assert caught.value.exit_code == 7

    new = caps.create_session(vault)
    assert bound(vault)["ref"] != damaged.stem
    caps.open_session(new, vault.file).wipe()
    assert retired(vault) == [descriptor]
    assert caps.destroy_device(vault) == 2 and not damaged.exists(), "the damaged one is destroyed with the new one"


def test_a_device_secret_that_is_here_but_cannot_be_used_now_refuses_without_spending(vault, monkeypatch):
    """A locked Mac, a busy TPM: the capability is fine and says so, and nothing is used up or recorded."""
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=2)
    before, log = cap_path(grant).read_bytes(), paths.audit_file().read_bytes()

    def locked(*args: Any, **kwargs: Any) -> SecureBuffer:
        raise HardwareError("Secure Enclave unavailable: this Mac is locked")

    with monkeypatch.context() as patch:
        patch.setattr(device.get_backend("software"), "unseal", locked)
        for attempt in (lambda: caps.open_session(session, vault.file), lambda: caps.open_grant(grant)):
            with pytest.raises(HardwareError, match="cannot be used: Secure Enclave unavailable: this Mac is locked"):
                attempt()

    assert cap_path(grant).read_bytes() == before and paths.audit_file().read_bytes() == log
    assert caps.open_grant(grant).uses_left == 1
    caps.open_session(session, vault.file).wipe()


# ---------------------------------------------------------------------------
# A replaced device secret is not forgotten (red team round 1, filesystem:2)
# ---------------------------------------------------------------------------


def retired(vault: Vault) -> List[Dict[str, Any]]:
    """The descriptors the vault's index keeps of the capability device secrets it replaced."""
    return list(vault.meta.get("cap_device_retired", []))


def key_of(descriptor: Dict[str, Any]) -> Path:
    return paths.device_dir() / f"{descriptor['ref']}.key"


def fail_once(patch: pytest.MonkeyPatch, name: str, descriptor: Dict[str, Any], error: IronDomeError) -> None:
    """The file-based backend's *name* (``unseal``, ``exists``) fails once for *descriptor*: a busy chip, a crashed
    helper. Every other call goes through."""
    backend = device.get_backend("software")
    real = getattr(backend, name)
    pending = [True]

    def flaky(asked: Dict[str, Any], *args: Any, **kwargs: Any) -> Any:
        if pending and asked.get("ref") == descriptor["ref"]:
            pending.clear()
            raise error
        return real(asked, *args, **kwargs)

    patch.setattr(backend, name, flaky)


def test_a_secret_replaced_after_one_failed_unseal_is_kept_and_destroyed_with_the_new_one(vault, tmp_path, monkeypatch):
    """The red team's case: one transient failure bound a second secret and forgot the first, which then outlived
    every rekey, so a token and a copy of its file that had leaked went on opening the grant."""
    first, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], mode="reveal", uses=5)
    old = dict(bound(vault))
    copy_of_first = tmp_path / "copy-of-the-first-grant.json"
    shutil.copyfile(cap_path(first), copy_of_first)

    with monkeypatch.context() as patch:
        fail_once(patch, "unseal", old, HardwareError("the device key could not be read now"))
        second, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], mode="reveal")

    new = dict(bound(vault))
    assert new["ref"] != old["ref"], "a secret this machine could not unseal was replaced"
    assert retired(vault) == [old]
    with reopen() as again:
        assert again.meta["cap_device"] == new and again.meta["cap_device_retired"] == [old], "committed"
    assert caps.open_grant(first).value("GITHUB_TOKEN") == GITHUB_PASSWORD, "the first grant's own secret is fine"

    assert caps.destroy_device(vault) == 2

    assert not key_of(old).exists() and not key_of(new).exists()
    shutil.copyfile(copy_of_first, cap_path(first))  # the copy of its file, put back
    assert_dead(None, first, vault.file)
    assert_dead(None, second, vault.file)


def test_a_secret_that_was_missing_for_a_moment_is_kept_and_destroyed_with_the_new_one(vault, tmp_path):
    first = caps.create_session(vault)
    old = dict(bound(vault))
    hidden = tmp_path / "moved-away.key"
    os.rename(str(key_of(old)), str(hidden))  # another program moves it away...

    second = caps.create_session(vault)
    os.rename(str(hidden), str(key_of(old)))  # ...and back

    assert bound(vault)["ref"] != old["ref"] and retired(vault) == [old]
    assert_alive(first, None, vault.file)
    assert caps.destroy_device(vault) == 2
    assert_dead(first, None, vault.file)
    assert_dead(second, None, vault.file)


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs file permissions that apply to this process")
def test_a_secret_unreadable_for_a_moment_is_kept_and_destroyed_with_the_new_one(vault):
    """The red team's reproduction: the key file was made unreadable while a grant was made, then readable again."""
    first, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], mode="reveal", uses=None)
    old = dict(bound(vault))
    os.chmod(str(key_of(old)), 0)
    try:
        second, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], mode="reveal", uses=None)
    finally:
        os.chmod(str(key_of(old)), 0o600)

    assert retired(vault) == [old]
    assert caps.destroy_device(vault) == 2
    assert_dead(None, first, vault.file)
    assert_dead(None, second, vault.file)


def test_when_the_backend_cannot_say_whether_the_secret_is_here_nothing_is_replaced(vault, monkeypatch):
    """A chip that does not answer: replacing the secret would be a guess. Refused, nothing made, try again."""
    session = caps.create_session(vault)
    recorded, keys_now, generation = dict(bound(vault)), key_files(), vault.file.generation
    listed, log = caps.list_caps(), paths.audit_file().read_bytes()

    def cannot_tell(descriptor: Dict[str, Any]) -> bool:
        raise HardwareError("the TPM did not answer")

    with monkeypatch.context() as patch:
        patch.setattr(device.get_backend("software"), "exists", cannot_tell)
        for attempt in (lambda: caps.create_session(vault), lambda: caps.create_grant(vault, ["GITHUB_TOKEN"])):
            with pytest.raises(HardwareError, match="cannot be checked now") as caught:
                attempt()
            assert caught.value.exit_code == 7
            assert "the TPM did not answer" in str(caught.value) and "Try again" in str(caught.value)

    assert bound(vault) == recorded and retired(vault) == []
    assert key_files() == keys_now and vault.file.generation == generation
    assert caps.list_caps() == listed and paths.audit_file().read_bytes() == log
    caps.open_session(caps.create_session(vault), vault.file).wipe()
    assert bound(vault) == recorded, "once it answers, the same secret is used"
    caps.open_session(session, vault.file).wipe()


def test_a_secret_that_cannot_be_used_while_its_backend_is_down_is_not_replaced(vault, monkeypatch):
    """A helper that does not run: a replacement now could be bound with a weaker backend. Refused, nothing made."""
    caps.create_session(vault)
    recorded, keys_now, generation = dict(bound(vault)), key_files(), vault.file.generation
    backend = device.get_backend("software")

    def down(*args: Any, **kwargs: Any) -> SecureBuffer:
        raise HardwareError("the helper did not run")

    with monkeypatch.context() as patch:
        patch.setattr(backend, "unseal", down)
        patch.setattr(backend, "probe", lambda: Probe("software", False, False, False, "down"))
        with pytest.raises(HardwareError, match="cannot be used now") as caught:
            caps.create_grant(vault, ["GITHUB_TOKEN"])

    assert "the helper did not run" in str(caught.value) and "Try again" in str(caught.value)
    assert bound(vault) == recorded and retired(vault) == [] and key_files() == keys_now
    assert vault.file.generation == generation


def test_a_replacement_that_cannot_be_recorded_leaves_the_index_and_the_old_secret_as_they_were(vault, tmp_path):
    caps.create_session(vault)
    old, keys_before = dict(bound(vault)), key_files()
    with reopen() as other:
        other.add("meanwhile", Secret(password="written by another process"))
        other.commit()
    hidden = tmp_path / "moved-away.key"
    os.rename(str(key_of(old)), str(hidden))

    with pytest.raises(VaultError, match="changed on disk"):
        caps.create_session(vault)

    os.rename(str(hidden), str(key_of(old)))
    assert bound(vault) == old and "cap_device_retired" not in vault.meta
    assert key_files() == keys_before, "the secret made for the replacement was destroyed again"


def test_destroy_device_tries_every_secret_and_says_which_it_could_not_destroy(vault, tmp_path, monkeypatch):
    caps.create_session(vault)
    old = dict(bound(vault))
    hidden = tmp_path / "moved-away.key"
    os.rename(str(key_of(old)), str(hidden))
    caps.create_session(vault)
    os.rename(str(hidden), str(key_of(old)))
    new = dict(bound(vault))
    backend = device.get_backend("software")
    real = backend.destroy

    def stubborn(descriptor: Dict[str, Any]) -> None:
        if descriptor["ref"] == old["ref"]:
            raise HardwareError("could not destroy the device key: Operation not permitted")
        real(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(backend, "destroy", stubborn)
        with pytest.raises(HardwareError) as caught:
            caps.destroy_device(vault)

    assert str(caught.value) == (
        "1 of the 2 device keys of this vault's sessions and grants could not be destroyed (1 was): "
        "could not destroy the device key: Operation not permitted"
    )
    assert not key_of(new).exists() and key_of(old).exists(), "the one that could be destroyed was"
    assert caps.destroy_device(vault) == 1, "the other goes once it can"


@pytest.mark.parametrize("ours", [True, False], ids=["this system's own chip", "another system's chip"])
def test_a_secret_whose_backend_cannot_be_asked_now_is_never_taken_for_gone(vault, monkeypatch, ours):
    """tpm2-tools gone, the TPM closed to you: this system's chip may still hold the secret, so neither
    destroy_device nor a re-key counts it as destroyed (the re-key keeps it in its plan); a chip that belongs
    to another system holds nothing here."""
    from irondome.cli import cmd_admin

    caps.create_session(vault)
    recorded = dict(bound(vault))
    backend = device.get_backend("software")

    def cannot_tell(descriptor: Dict[str, Any]) -> bool:
        raise HardwareError("the TPM did not answer")

    with monkeypatch.context() as patch:
        patch.setattr(backend, "exists", cannot_tell)
        patch.setattr(backend, "probe", lambda: Probe("software", False, False, False, "down"))
        patch.setattr(device, "applies_here", lambda name: ours)
        if ours:
            with pytest.raises(HardwareError, match="could not be checked: the TPM did not answer"):
                caps.destroy_device(vault)
            with pytest.raises(HardwareError, match="could not be checked: the TPM did not answer"):
                cmd_admin._destroy_device(recorded)
        else:
            assert caps.destroy_device(vault) == 0
            assert cmd_admin._destroy_device(recorded) is False
    assert key_of(recorded).exists(), "nothing was destroyed while the backend could not be asked"
    assert caps.destroy_device(vault) == 1, "once it answers, it goes"


def test_bound_devices_names_the_recorded_secret_then_every_one_it_replaced(vault, tmp_path):
    """What a re-key destroys for the vault it replaces: read from the authenticated index, never from a header."""
    assert caps.bound_devices(vault) == []
    caps.create_session(vault)
    first = dict(bound(vault))
    assert caps.bound_devices(vault) == [first]
    hidden = tmp_path / "moved-away.key"
    os.rename(str(key_of(first)), str(hidden))
    caps.create_session(vault)
    os.rename(str(hidden), str(key_of(first)))
    second = dict(bound(vault))

    assert caps.bound_devices(vault) == [second, first]
    caps.bound_devices(vault)[0]["ref"] = "0" * 32
    assert bound(vault) == second, "fresh copies"
    vault.meta["cap_device_retired"] = [first, "not a descriptor", {"backend": "software"}, first, second]
    assert caps.bound_devices(vault) == [second, first], "what cannot name a secret is left out, and nothing twice"


def test_cli_rekey_after_a_replacement_leaves_no_grant_alive(cli, tmp_path):
    """End to end, as the red team ran it: a grant, its secret away while a second grant is made, then rekey."""
    tokens = cli_vault(cli)
    with reopen() as opened:
        old = dict(bound(opened))
    copy = tmp_path / "copy-of-the-grant-file.json"
    shutil.copyfile(cap_path(tokens["grant"]), copy)
    hidden = tmp_path / "moved-away.key"
    os.rename(str(key_of(old)), str(hidden))
    second = cli("grant", "create", "GITHUB_TOKEN", "--reveal", "--json", "--password-stdin", stdin=OWNER)
    assert second.returncode == 0, second.stderr
    os.rename(str(hidden), str(key_of(old)))
    before = cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": tokens["grant"]})
    assert (before.returncode, before.stdout.strip()) == (0, GITHUB_PASSWORD)

    rekeyed = cli("rekey", "--yes", "--password-stdin", "--json", stdin=OWNER)

    assert rekeyed.returncode == 0, rekeyed.stderr
    assert json.loads(rekeyed.stdout)["leftovers"] == []
    assert not key_of(old).exists(), "the secret the first grant is bound to went with the rest"
    paths.ensure_dir(paths.caps_dir())
    shutil.copyfile(copy, cap_path(tokens["grant"]))  # the copy of its file, put back
    after = cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": tokens["grant"]})
    assert (after.returncode, after.stdout) == (4, "") and DEAD in after.stderr
    assert_nothing_leaked(tokens, rekeyed, after)


# ---------------------------------------------------------------------------
# Key material stays in locked memory and is wiped
# ---------------------------------------------------------------------------


@pytest.fixture
def every_secure_buffer(monkeypatch) -> List[SecureBuffer]:
    """Every SecureBuffer made from here on by any module: device secret, device key, every subkey."""
    made: List[SecureBuffer] = []
    original = SecureBuffer.__init__

    def remember(self: SecureBuffer, size: int) -> None:
        original(self, size)
        made.append(self)

    monkeypatch.setattr(SecureBuffer, "__init__", remember)
    return made


def alive(made: List[SecureBuffer]) -> List[SecureBuffer]:
    return [buffer for buffer in made if not buffer.wiped]


def test_every_buffer_made_to_bind_or_open_a_capability_is_wiped_but_the_key_handed_back(vault, every_secure_buffer):
    made = every_secure_buffer
    session = caps.create_session(vault)
    grant, _ = caps.create_grant(vault, ["GITHUB_TOKEN"], uses=None)
    assert made and alive(made) == []

    key = caps.open_session(session, vault.file)
    survivors = alive(made)
    assert len(survivors) == 1 and survivors[0] is key
    key.wipe()

    opened = caps.open_grant(grant)
    survivors = alive(made)
    assert len(survivors) == 1 and survivors[0] is opened.audit_key
    opened.close()

    kind, cap_id, _ = caps.parse_token(session)
    wrong = "irondome_s_%s_%s" % (cap_id, "A" * 52)
    with pytest.raises(AuthError):
        caps.open_session(wrong, vault.file)
    assert caps.destroy_device(vault) == 1
    with pytest.raises(AuthError, match=DEAD):
        caps.open_grant(grant)
    assert alive(made) == []


# ---------------------------------------------------------------------------
# The TPM backend, against the FakeTpm
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_tpm(monkeypatch) -> FakeTpm:
    """Bind on the TPM backend, which talks to a FakeTpm (see test_device_tpm) instead of running tools."""
    tpm = FakeTpm()
    monkeypatch.setattr(linux_tpm, "_run", tpm.run)
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "linux-tpm2")
    monkeypatch.setattr(Tpm2Backend, "probe", lambda self: Probe("linux-tpm2", True, True, False, "FakeTpm"))
    device._instances.clear()
    return tpm


@posix_only
def test_on_the_tpm_capabilities_are_bound_to_an_index_that_needs_no_password(fake_tpm, make_vault):
    opened, _ = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"])

    descriptor = bound(opened)
    assert set(descriptor) == {"backend", "policy", "ref", "nv_index"} and descriptor["backend"] == "linux-tpm2"
    index = fake_tpm.indices[int(descriptor["nv_index"], 16)]
    assert index["auth"] == b"" and "no_da" in index["attributes"]
    keyslot = next(slot.device for slot in opened.file.slots if slot.device is not None)
    assert keyslot is not None and "no_da" not in fake_tpm.indices[int(keyslot["nv_index"], 16)]["attributes"]
    assert sorted(linux_tpm._load_registry()) == sorted([descriptor["nv_index"], keyslot["nv_index"]])
    assert header_of(session)["device"] == header_of(grant)["device"] == descriptor
    assert_alive(session, grant)
    assert fake_tpm.failed_tries == 0


@posix_only
def test_on_the_tpm_capabilities_are_dead_with_another_machines_tpm(fake_tpm, make_vault, monkeypatch):
    opened, _ = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"])

    elsewhere = FakeTpm()
    with monkeypatch.context() as patch:
        patch.setattr(linux_tpm, "_run", elsewhere.run)
        assert_dead(session, grant)
    assert elsewhere.failed_tries == 0
    assert_alive(session, grant)


@posix_only
def test_on_the_tpm_capabilities_keep_working_while_the_tpm_refuses_every_password(fake_tpm, make_vault):
    opened, _ = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"], uses=None)
    fake_tpm.failed_tries = fake_tpm.max_tries

    with pytest.raises(LockedOutError):
        reopen()
    assert_alive(session, grant)
    assert caps.open_grant(grant).value("GITHUB_TOKEN") == GITHUB_PASSWORD


@posix_only
def test_on_the_tpm_a_descriptor_pointed_at_the_keyslots_index_costs_no_guess(fake_tpm, make_vault):
    """An empty authorisation presented to the password keyslot's index would be a wrong guess: it is never sent."""
    opened, _ = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"])
    keyslot = next(slot.device for slot in opened.file.slots if slot.device is not None)
    assert keyslot is not None
    fake_tpm.calls.clear()

    for token in (session, grant):
        rewrite(token, lambda document: document["device"].update(nv_index=keyslot["nv_index"]))
    with pytest.raises(AuthError, match=DAMAGED):
        caps.open_session(session, opened.file)
    with pytest.raises(AuthError, match=DAMAGED):
        caps.open_grant(grant)

    assert fake_tpm.failed_tries == 0
    assert ["tpm2_nvread", keyslot["nv_index"], "-C", keyslot["nv_index"], "-s", "32"] not in fake_tpm.calls


@posix_only
def test_on_the_tpm_nuke_leaves_a_restored_copy_of_the_vault_directory_dead(fake_tpm, make_vault, tmp_path):
    opened, recovery = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"], uses=None)
    opened.close()
    copy = tmp_path / "copy-of-the-vault-directory"
    shutil.copytree(paths.root(), copy)
    assert recovery is not None

    report = nuke.execute()

    assert report.success and report.device_keys_destroyed == 2 and report.hardware_backed
    assert fake_tpm.handles() == set(), "the TPM holds nothing of the bunker any more"
    shutil.copytree(copy, paths.root())
    assert_dead(session, grant)
    with pytest.raises(HardwareError, match="recovery key"):
        reopen()
    with open_vault(recovery_key=recovery) as recovered:
        assert recovered.value(recovered.find("github")) == GITHUB_PASSWORD
    assert fake_tpm.failed_tries == 0


# ---------------------------------------------------------------------------
# A real TPM 2.0 (scripts/test-linux.sh runs these against swtpm)
# ---------------------------------------------------------------------------


@pytest.fixture
def chip(tpm) -> Iterator[Tpm2Backend]:
    """The real backend on a TPM simulator; any index a test leaves behind is removed afterwards.

    One test fails authorisations on purpose, so anything but a simulator is skipped.
    """
    if not linux_tpm._is_simulator(os.environ.get("TPM2TOOLS_TCTI", "")):
        pytest.skip("fails authorisations on purpose: only runs against a TPM simulator")
    tpm2("tpm2_dictionarylockout", "--clear-lockout")
    before = nv_handles()
    yield tpm
    tpm2("tpm2_dictionarylockout", "--clear-lockout", check=False)
    for index in nv_handles() - before:
        tpm2("tpm2_nvundefine", index, "-C", "o", check=False)


@pytest.mark.tpm
def test_real_tpm_binds_capabilities_to_an_index_any_process_of_the_machine_can_read(chip, make_vault):
    opened, _ = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"])

    index = bound(opened)["nv_index"]
    public = tpm2("tpm2_nvreadpublic", index).stdout.decode("ascii")
    assert "authwrite|authread|no_da|written" in public, public
    assert index in nv_handles() and index in linux_tpm._load_registry()
    assert_alive(session, grant)
    assert caps.open_grant(grant).value("GITHUB_TOKEN") == GITHUB_PASSWORD
    assert failed_tries() == 0


@pytest.mark.tpm
def test_real_tpm_capabilities_are_dead_with_another_machines_tpm(chip, make_vault, monkeypatch):
    opened, _ = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"], uses=None)
    home = os.environ["TPM2TOOLS_TCTI"]

    with another_tpm() as elsewhere:
        monkeypatch.setenv("TPM2TOOLS_TCTI", elsewhere)
        try:
            assert_dead(session, grant)
        finally:
            monkeypatch.setenv("TPM2TOOLS_TCTI", home)
    assert_alive(session, grant)


@pytest.mark.tpm
def test_real_tpm_capabilities_keep_working_while_the_tpm_refuses_every_password(chip, make_vault):
    opened, _ = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"], uses=None)
    limit = int(chip.lockout_status()["max_tries"])
    assert 0 < limit <= 32
    for _ in range(limit):
        with pytest.raises(AuthError, match="^wrong master password$"):
            reopen("not the master password")
    with pytest.raises(LockedOutError):
        reopen()

    assert_alive(session, grant)
    assert caps.open_grant(grant).value("GITHUB_TOKEN") == GITHUB_PASSWORD
    tpm2("tpm2_dictionarylockout", "--clear-lockout")
    reopen().close()


@pytest.mark.tpm
def test_real_tpm_nuke_leaves_a_restored_copy_of_the_vault_directory_dead(chip, make_vault, tmp_path):
    opened, recovery = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"], uses=None)
    indices = {bound(opened)["nv_index"]} | {slot.device["nv_index"] for slot in opened.file.slots if slot.device}
    opened.close()
    copy = tmp_path / "copy-of-the-vault-directory"
    shutil.copytree(paths.root(), copy)
    assert recovery is not None and len(indices) == 2

    report = nuke.execute()

    assert report.success and report.device_keys_destroyed == 2
    # "Held by a security chip" is what the TPM's own probe says of this machine: a simulator is software.
    assert report.hardware_backed is device.hardware_here(chip)
    assert not indices & nv_handles(), "both indices are gone from the chip"
    shutil.copytree(copy, paths.root())
    assert_dead(session, grant)
    with pytest.raises(HardwareError, match="recovery key"):
        reopen()
    with open_vault(recovery_key=recovery) as recovered:
        assert recovered.value(recovered.find("github")) == GITHUB_PASSWORD
    assert failed_tries() == 0


# ---------------------------------------------------------------------------
# This Mac's Secure Enclave (device policy only: no prompt can appear)
# ---------------------------------------------------------------------------


def test_secure_enclave_binds_capabilities_to_this_mac(secure_enclave, make_vault, machine, tmp_path):
    opened, _ = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"], uses=None)
    descriptor = dict(bound(opened))
    assert (descriptor["backend"], descriptor["policy"]) == ("macos-se", "device")
    assert caps.open_grant(grant).value("GITHUB_TOKEN") == GITHUB_PASSWORD

    machine.elsewhere()
    assert_dead(session, grant)
    machine.back()
    assert_alive(session, grant)

    copy = tmp_path / "copy-of-caps"
    shutil.copytree(paths.caps_dir(), copy)
    secure_enclave.destroy(descriptor)
    shutil.rmtree(paths.caps_dir())
    shutil.copytree(copy, paths.caps_dir())
    assert_dead(session, grant, opened.file)
    fresh = caps.create_session(opened)
    assert bound(opened)["ref"] != descriptor["ref"]
    caps.open_session(fresh, opened.file).wipe()


def test_secure_enclave_nuke_leaves_a_restored_copy_of_the_vault_directory_dead(secure_enclave, make_vault, tmp_path):
    opened, recovery = filled(make_vault)
    session = caps.create_session(opened)
    grant, _ = caps.create_grant(opened, ["GITHUB_TOKEN"], uses=None)
    assert bound(opened)["backend"] == "macos-se"
    opened.close()
    copy = tmp_path / "copy-of-the-vault-directory"
    shutil.copytree(paths.root(), copy)
    assert recovery is not None

    report = nuke.execute()

    assert report.success and report.device_keys_destroyed == 2 and report.hardware_backed, report.errors
    shutil.copytree(copy, paths.root())
    assert_dead(session, grant)
    with pytest.raises(HardwareError, match="not on this Mac"):
        reopen()
    with open_vault(recovery_key=recovery) as recovered:
        assert recovered.value(recovered.find("github")) == GITHUB_PASSWORD
