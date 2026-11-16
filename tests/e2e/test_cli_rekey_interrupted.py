"""A re-key that is stopped part way (red-team filesystem:0).

``irondome rekey`` puts the new vault in place first and then destroys what opened the old one. Before the fix
an interruption in between left a vault whose new recovery key nobody had seen, kept the old device keys and
the capability device secret alive (so old grants and old copies of the vault went on opening), and a second
re-key could not find them any more. Now the new vault carries a plan of what is left to destroy from the moment
it is live, every keyslot device key involved is recorded before the switch, an interruption the process sees
still ends with the new recovery key shown, and the next re-key finishes the job.

Faults are injected into the real command line (``python -c`` running ``irondome.cli.main.main``): SIGKILL
stands for kill -9 or a power cut, KeyboardInterrupt for Ctrl-C.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

import pytest

from conftest import PASSWORD, secret
from irondome import caps, keys, paths
from irondome.errors import AuthError, HardwareError
from irondome.unlock import create_vault, open_vault, unlock
from irondome.vault import Secret, Vault, VaultFile

CLI = Callable[..., "subprocess.CompletedProcess[str]"]
SUPPORT = Path(__file__).resolve().parents[1] / "support"
RECOVERY_KEY = re.compile(r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}")
TOKEN = "the-github-token-1234"

pytestmark = pytest.mark.skipif(not hasattr(signal, "SIGKILL"), reason="needs POSIX signals")

FAULTS = textwrap.dedent(
    """
    import os
    import signal
    import sys

    from irondome import vault
    from irondome.cli import cmd_admin

    def kill(*args, **kwargs):
        sys.stdout.flush()
        sys.stderr.flush()
        os.kill(os.getpid(), signal.SIGKILL)

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    fault = sys.argv[1]
    if fault == "kill-after-switch":
        cmd_admin._retire = kill
    elif fault == "interrupt-after-switch":
        cmd_admin._retire = interrupt
    elif fault == "kill-before-switch":
        vault.Vault.copy_into = kill
    from irondome.cli.main import main

    raise SystemExit(main(sys.argv[2:]))
    """
)


def run_with_fault(fault: str, *args: str) -> "subprocess.CompletedProcess[str]":
    merged = dict(os.environ)
    if SUPPORT.is_dir():
        merged["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SUPPORT), merged.get("PYTHONPATH", "")]))
        merged["IRONDOME_TEST_BLOCK_SOCKETS"] = "1"
    return subprocess.run(
        [sys.executable, "-c", FAULTS, fault, *args], input=PASSWORD + "\n", capture_output=True, text=True,
        env=merged, timeout=120,
    )


def ok(result: "subprocess.CompletedProcess[str]", code: int = 0) -> "subprocess.CompletedProcess[str]":
    assert result.returncode == code, f"exit {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    return result


@contextlib.contextmanager
def opened(path: Optional[Path] = None) -> Iterator[Vault]:
    key = secret(PASSWORD)
    try:
        vault = open_vault(path=path, password=key, interactive=False, allow_touch=False)
    finally:
        key.wipe()
    try:
        yield vault
    finally:
        vault.close()


def build() -> str:
    """A vault opened by the master password and this machine, with a recovery key. Returns that key."""
    key = secret(PASSWORD)
    try:
        vault, recovery = create_vault(password=key, with_recovery=True)
    finally:
        key.wipe()
    try:
        github = vault.add("github", Secret(password=TOKEN))
        vault.add("aws/prod", Secret(password="AKIA-not-a-real-key"))
        vault.set_alias("GITHUB_TOKEN", github)
        vault.commit()
    finally:
        vault.close()
    assert recovery is not None
    return recovery


def device_keys() -> List[str]:
    return sorted(path.name for path in paths.device_dir().glob("*.key"))


def staging_files() -> List[Path]:
    return sorted(paths.home().glob(".tmp-rekey-*.irondome"))


def taken_before(isolated: Path) -> Tuple[str, str, bytes, List[str], Path]:
    """What someone could have kept before the re-key: a session, a grant, their files, a copy of the vault."""
    with opened() as vault:
        session = caps.create_session(vault, ttl=600)
        grant, _info = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=600)
    with caps.open_grant(grant, consume=False):
        pass  # it opens now
    stolen = isolated / "stolen-caps"
    shutil.copytree(str(paths.caps_dir()), str(stolen))
    return session, grant, paths.vault_file().read_bytes(), device_keys(), stolen


def rekey(cli: CLI) -> Dict[str, object]:
    return json.loads(ok(cli("rekey", "--yes", "--password-stdin", "--json", stdin=PASSWORD + "\n")).stdout)


def nothing_taken_before_opens(session: str, grant: str, old_copy: bytes, old_keys: List[str], stolen: Path) -> None:
    assert not set(old_keys) & set(device_keys()), "a device key from before the re-key is still here"
    shutil.copytree(str(stolen), str(paths.caps_dir()), dirs_exist_ok=True)  # copies of the files, put back
    with pytest.raises(AuthError):
        caps.open_grant(grant)
    with pytest.raises(AuthError):
        caps.open_session(session, VaultFile.from_bytes(old_copy))
    with pytest.raises((HardwareError, AuthError)):
        unlock(VaultFile.from_bytes(old_copy), password=secret(PASSWORD), interactive=False, allow_touch=False)
    assert staging_files() == [] and not (paths.home() / keys.RETIREMENT_FILE).exists()
    with opened() as vault:
        assert "rekey" not in vault.meta  # nothing left to destroy
        assert vault.value(*vault.resolve("GITHUB_TOKEN")) == TOKEN


def test_a_rekey_killed_after_the_switch_is_finished_by_the_next_one(cli: CLI, isolated: Path) -> None:
    old_recovery = build()
    old_id = VaultFile.load().vault_id
    session, grant, old_copy, old_keys, stolen = taken_before(isolated)
    assert len(old_keys) == 2  # the password keyslot's, and the one sessions and grants are bound to

    killed = run_with_fault("kill-after-switch", "rekey", "--yes", "--password-stdin", "--json")
    assert killed.returncode == -signal.SIGKILL, killed.stderr
    assert VaultFile.load().vault_id != old_id  # the switch happened
    assert staging_files(), "nothing on disk says that this re-key did not finish"

    document = rekey(cli)
    assert document["leftovers"] == [] and document["finished"] is True
    new_recovery = document["recovery_keys"]
    assert isinstance(new_recovery, list) and len(new_recovery) == 1
    nothing_taken_before_opens(session, grant, old_copy, old_keys, stolen)
    current = VaultFile.load()
    with Vault(current, unlock(current, recovery_key=new_recovery[0])) as vault:
        assert len(vault.entries) == 2
    with pytest.raises(AuthError):
        unlock(current, recovery_key=old_recovery)


def test_the_audit_history_survives_a_rekey_killed_after_the_switch(cli: CLI) -> None:
    """What reads the old log is in the new vault from the switch on, so a kill right after it loses no history.

    The killed re-key never set the log aside, so the records made next, under the new vault key, follow the
    old ones in the same file. The re-key that finishes the job archives that file; each of its lines is read
    with the key it was written under, and the whole of it verifies.
    """
    ok(cli("init", "--password-stdin", "--no-recovery", stdin=PASSWORD + "\n"))
    ok(cli("add", "first", "--kind", "secret", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\nvalue-1\n"))
    killed = run_with_fault("kill-after-switch", "rekey", "--yes", "--password-stdin", "--json")
    assert killed.returncode == -signal.SIGKILL, killed.stderr
    ok(cli("add", "second", "--kind", "secret", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\nvalue-2\n"))
    assert rekey(cli)["leftovers"] == []
    ok(cli("add", "third", "--kind", "secret", "--password-stdin", "--value-stdin", stdin=PASSWORD + "\nvalue-3\n"))
    assert rekey(cli)["leftovers"] == []
    from irondome import audit

    archives = [path.name for path in audit.archives()]  # oldest first
    assert len(archives) == 2
    seen: List[str] = []
    for name in archives:
        shown = json.loads(
            ok(cli("audit", "-n", "0", "--verify", "--json", "--archive", name, "--password-stdin",
                   stdin=PASSWORD + "\n")).stdout
        )
        assert shown["verify"]["ok"], (name, shown["verify"])
        seen += [f"{event['action']} {event['target']}".strip() for event in shown["events"]]
    assert [line for line in seen if line.startswith(("vault.create", "entry.add"))] == [
        "vault.create alpha", "entry.add first", "entry.add second", "entry.add third",
    ]


@pytest.mark.parametrize("json_mode", [False, True], ids=["text", "json"])
def test_a_rekey_interrupted_after_the_switch_still_shows_the_new_recovery_key(
    cli: CLI, isolated: Path, json_mode: bool
) -> None:
    build()
    old_id = VaultFile.load().vault_id
    session, grant, old_copy, old_keys, stolen = taken_before(isolated)
    flags = ["--json"] if json_mode else []
    interrupted = run_with_fault("interrupt-after-switch", *flags, "rekey", "--yes", "--password-stdin")
    assert interrupted.returncode == 130, interrupted.stderr
    assert "interrupted" in interrupted.stderr and "Run irondome rekey again" in interrupted.stderr
    if json_mode:
        document = json.loads(interrupted.stdout)  # still one JSON document
        assert document["finished"] is False
        shown = document["recovery_keys"]
    else:
        shown = RECOVERY_KEY.findall(interrupted.stdout)
    assert len(shown) == 1, interrupted.stdout
    current = VaultFile.load()
    assert current.vault_id != old_id
    with Vault(current, unlock(current, recovery_key=shown[0])) as vault:  # the key shown opens the live vault
        assert len(vault.entries) == 2

    rekey(cli)
    nothing_taken_before_opens(session, grant, old_copy, old_keys, stolen)


def test_a_rekey_killed_before_the_switch_leaves_nothing_behind_after_the_next_one(cli: CLI) -> None:
    build()
    before = paths.vault_file().read_bytes()
    keys_before = device_keys()
    killed = run_with_fault("kill-before-switch", "rekey", "--yes", "--password-stdin")
    assert killed.returncode == -signal.SIGKILL, killed.stderr
    assert paths.vault_file().read_bytes() == before  # the old vault is still the vault
    orphans = sorted(set(device_keys()) - set(keys_before))
    assert orphans and staging_files()  # a device key and a staging file nothing will ever use
    with opened() as vault:
        assert vault.value(vault.find("github")) == TOKEN

    document = rekey(cli)
    assert document["leftovers"] == []
    assert staging_files() == [] and not (paths.home() / keys.RETIREMENT_FILE).exists()
    assert not (set(device_keys()) & (set(orphans) | set(keys_before)))  # only the new vault's key is left
    assert len(device_keys()) == 1


# A re-key killed after its switch, before it could end anything (red-team filesystem:0, the part re-verification
# found open): the new recovery key was never shown, status, doctor and ls said nothing, and a grant made before
# it went on returning the secret until the owner happened to re-key again. Now the recovery key goes out right
# after the switch, every session and grant is refused while the re-key's staging file holds the live vault's id,
# and every owner command says so and how to finish.

KILLED_AFTER_SWITCH = {
    "rekey": ["rekey", "--yes", "--password-stdin"],
    "rekey-json": ["--json", "rekey", "--yes", "--password-stdin"],
    "recovery-new": ["recovery", "new", "--password-stdin"],
}


@pytest.mark.parametrize("command", sorted(KILLED_AFTER_SWITCH))
def test_a_rekey_killed_after_the_switch_fails_closed_and_every_owner_command_says_so(
    cli: CLI, isolated: Path, command: str
) -> None:
    build()
    old_id = VaultFile.load().vault_id
    session, grant, old_copy, old_keys, stolen = taken_before(isolated)

    killed = run_with_fault("kill-after-switch", *KILLED_AFTER_SWITCH[command])
    assert killed.returncode == -signal.SIGKILL, killed.stderr
    current = VaultFile.load()
    assert current.vault_id != old_id
    staged = staging_files()
    assert len(staged) == 1 and VaultFile.load(staged[0]).vault_id == current.vault_id

    # The new recovery key was out before the kill, and it is the one that opens the vault now. With --json,
    # stdout holds one document, written at the end, so it was never shown: the warnings below and the master
    # password remain, and the next re-key shows a new one.
    shown = RECOVERY_KEY.findall(killed.stdout)
    if command == "rekey-json":
        assert killed.stdout == ""
        with opened() as vault:
            assert len(vault.entries) == 2
    else:
        assert len(shown) == 1, killed.stdout
        with Vault(current, unlock(current, recovery_key=shown[0])) as vault:
            assert len(vault.entries) == 2

    # Fail closed: the grant made before the re-key, through the real command line and the library.
    used = cli("get", "GITHUB_TOKEN", env={"IRONDOME_GRANT": grant})
    assert used.returncode == AuthError.exit_code and TOKEN not in used.stdout + used.stderr
    assert "a re-key of its vault has not finished" in used.stderr and "irondome rekey" in used.stderr
    with pytest.raises(AuthError, match="has not finished"):
        caps.open_grant(grant, consume=False)
    with pytest.raises(AuthError, match="has not finished"):
        caps.open_grant(grant)
    made = cli("grant", "create", "github", "--ttl", "10m", "--password-stdin", stdin=PASSWORD + "\n")
    assert made.returncode == AuthError.exit_code and "has not finished" in made.stderr, made.stderr

    # Every owner command says so, and how to finish: status and doctor without a key, ls once unlocked.
    status = cli("status")
    assert "UNFINISHED" in status.stdout and "irondome rekey" in status.stdout
    assert "stopped after the new vault key took over" in status.stderr
    document = json.loads(ok(cli("status", "--json")).stdout)
    assert document["unfinished_rekey"] == str(staged[0])
    doctor = cli("doctor", "--json")
    assert doctor.returncode == 1
    finding = json.loads(doctor.stdout)["findings"][0]
    assert finding["severity"] == "problem" and finding["check"] == "rekey" and finding["remedy"] == "irondome rekey"
    listed = ok(cli("ls", "--password-stdin", stdin=PASSWORD + "\n"))
    assert listed.stderr.count("stopped after the new vault key took over") == 1, listed.stderr
    assert "Finish it with: irondome rekey" in listed.stderr

    # The next re-key finishes it: a new recovery key, nothing from before opens, and nothing warns any more.
    document = rekey(cli)
    assert document["finished"] is True and len(document["recovery_keys"]) == 1
    nothing_taken_before_opens(session, grant, old_copy, old_keys, stolen)
    assert "re-key" not in cli("status").stdout + cli("status").stderr
    assert "re-key" not in ok(cli("ls", "--password-stdin", stdin=PASSWORD + "\n")).stderr


def test_a_session_or_grant_is_refused_only_while_the_staging_file_holds_the_live_vault_id(isolated: Path) -> None:
    build()
    with opened() as vault:
        grant, _info = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=600)
        session = caps.create_session(vault, ttl=600)
    live = paths.vault_file()
    other = paths.home() / ".tmp-rekey-0000000000000000.irondome"
    other.write_bytes(b"torn: a re-key killed while writing it, before any switch")
    assert caps.unfinished_rekey() is None
    with caps.open_grant(grant, consume=False):
        pass
    staged = paths.home() / ".tmp-rekey-1111111111111111.irondome"
    shutil.copyfile(str(live), str(staged))  # the live vault's own id: a re-key that switched and did not finish
    assert caps.unfinished_rekey() == staged
    with pytest.raises(AuthError, match="has not finished"):
        caps.open_session(session, VaultFile.load())
    with pytest.raises(AuthError, match="has not finished"):
        caps.open_grant(grant, consume=False)
    with opened() as vault, pytest.raises(AuthError, match="has not finished"):
        caps.create_session(vault, ttl=600)
    staged.unlink()
    with caps.open_grant(grant, consume=False):
        pass


def test_a_rekey_plan_left_in_the_index_is_reported_by_the_next_unlock(cli: CLI) -> None:
    """A re-key that finished except for an old device key it could not destroy leaves its plan in the index."""
    build()
    with opened() as vault:
        vault.meta[caps.REKEY_PLAN] = {
            "from": "00" * 16, "devices": [{"label": "the keyslot 'password'", "device": {"backend": "software"}}],
        }
        vault.commit()
    assert caps.unfinished_rekey() is None  # no staging file: sessions and grants are not refused for this
    listed = ok(cli("ls", "--password-stdin", stdin=PASSWORD + "\n"))
    assert "the last re-key of bunker alpha did not finish: 1 old device key of the vault it replaced could not " \
        "be destroyed. Finish it with: irondome rekey" in " ".join(listed.stderr.split())
