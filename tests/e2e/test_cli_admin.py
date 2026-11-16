"""The maintenance commands, end to end through the real command line.

Every command runs as ``python -m irondome ...`` in a subprocess (the ``cli``
fixture) inside the isolated directories of ``conftest.py``, with no terminal
(``IRONDOME_NO_PROMPT=1``). The vault each test starts from is made with the
library in this process, so a test depends on no command but the ones it is
about; what a command did is then checked by opening the result with the
library again.

The owner is whoever pipes the master password with ``--password-stdin``.
Without it every one of these commands, except doctor, completion and
version, must refuse (no terminal and no password: an agent).
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pytest

from conftest import PASSWORD, secret
from irondome import audit, caps, interop, keys, otp, paths
from irondome import device as devices
from irondome.crypto import default_argon2
from irondome.errors import AuthError, HardwareError
from irondome.unlock import create_vault, open_vault, unlock
from irondome.vault import Secret, Vault, VaultFile, vault_exists

CLI = Callable[..., "subprocess.CompletedProcess[str]"]

TOTP_SECRET = "JBSWY3DPEHPK3PXP"
GITHUB_PASSWORD = "hunter2-Github!"
OLD_GITHUB_PASSWORD = "previous-Github-1"
AWS_KEY = "AKIA-not-a-real-key"
REGION = "eu-west-1"
EXPORT_PASSWORD = "a long export passphrase 1"
FRESH_PASSWORD = "a fresh master password 2"
BRAVO_PASSWORD = "bravo's own master password"
SECRETS = (PASSWORD, GITHUB_PASSWORD, OLD_GITHUB_PASSWORD, AWS_KEY, TOTP_SECRET, EXPORT_PASSWORD, FRESH_PASSWORD)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "v3"
SUPPORT = Path(__file__).resolve().parents[1] / "support"
RECOVERY_KEY = re.compile(r"[A-Z2-7]{4}(?:-[A-Z2-7]{4}){7}")

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def lines(*values: str) -> str:
    return "".join(value + "\n" for value in values)


def quiet(result: "subprocess.CompletedProcess[str]", *values: str) -> None:
    """No secret appears in what the command printed."""
    for value in SECRETS + values:
        assert value not in result.stdout, f"a secret was printed on stdout: {value!r}"
        assert value not in result.stderr, f"a secret was printed on stderr: {value!r}"


def ok(result: "subprocess.CompletedProcess[str]", code: int = 0) -> "subprocess.CompletedProcess[str]":
    assert result.returncode == code, f"exit {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    return result


@contextlib.contextmanager
def in_bunker(name: Optional[str]) -> Iterator[None]:
    """Point the library in this process at bunker *name* for the duration."""
    saved = os.environ.get(paths.ENV_BUNKER)
    if name is not None:
        os.environ[paths.ENV_BUNKER] = name
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop(paths.ENV_BUNKER, None)
        else:
            os.environ[paths.ENV_BUNKER] = saved


def build(password: str = PASSWORD, *, bunker: Optional[str] = None, recovery: bool = True,
          entries: bool = True) -> Optional[str]:
    """A committed vault: two entries, two aliases, a TOTP seed, a password history. Returns its recovery key."""
    with in_bunker(bunker):
        key = secret(password)
        try:
            vault, recovery_key = create_vault(password=key, with_recovery=recovery)
        finally:
            key.wipe()
        try:
            if entries:
                github = vault.add(
                    "github",
                    Secret(password=OLD_GITHUB_PASSWORD, notes="personal", totp=otp.make_totp(TOTP_SECRET),
                           fields={"region": REGION}),
                    username="king", url="https://github.com", tags=["dev"],
                )
                vault.commit()
                current = vault.read_secret(github)
                current.password = GITHUB_PASSWORD
                vault.update(github, secret=current)
                vault.add("aws/prod", Secret(password=AWS_KEY), kind="secret")
                vault.set_alias("GITHUB_TOKEN", github, "password")
                vault.set_alias("GITHUB_OTP", github, "totp")
            vault.commit()
        finally:
            vault.close()
    return recovery_key


@contextlib.contextmanager
def opened(password: str = PASSWORD, *, bunker: Optional[str] = None, path: Optional[Path] = None) -> Iterator[Vault]:
    with in_bunker(bunker):
        key = secret(password)
        try:
            vault = open_vault(path=path, password=key, interactive=False, allow_touch=False)
        finally:
            key.wipe()
    try:
        yield vault
    finally:
        vault.close()


def contents(vault: Vault) -> Dict[str, Dict[str, Any]]:
    """Every entry with every value, by name, as a test compares them."""
    found = {}
    for entry in vault.list():
        value = vault.read_secret(entry)
        found[entry.name] = {
            "username": entry.username, "url": entry.url, "tags": list(entry.tags), "kind": entry.kind,
            "password": value.password, "notes": value.notes, "totp": value.totp, "fields": dict(value.fields),
            "history": [item["password"] for item in value.history],
            "aliases": vault.aliases_of(entry),
        }
    return found


def alias_targets(vault: Vault) -> Dict[str, Tuple[str, str]]:
    return {name: (vault.entries[alias.entry].name, alias.field) for name, alias in vault.aliases.items()}


def wipe_machine() -> None:
    for root in (paths.root(), paths.device_root()):
        shutil.rmtree(str(root), ignore_errors=True)


def tree(root: Path) -> Dict[str, Tuple[int, int, str]]:
    """Everything under *root*: type, mode, and content digest."""
    state: Dict[str, Tuple[int, int, str]] = {}
    for current, directories, files in os.walk(root):
        for name in directories + files:
            path = Path(current) / name
            info = path.lstat()
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else ""
            state[path.relative_to(root).as_posix()] = (stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), digest)
    return state


def device_keys() -> List[str]:
    return sorted(path.name for path in paths.device_dir().glob("*.key"))


def _load_archive() -> Any:
    spec = importlib.util.spec_from_file_location("irondome_v3_fixture_archive_e2e", FIXTURES / "archive.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ARCHIVE = _load_archive()


def unpack_legacy(name: str) -> Dict[str, Any]:
    fixture = ARCHIVE.load(FIXTURES / f"{name}.json")
    ARCHIVE.unpack(fixture, paths.legacy_v3_dir())
    return fixture


# ---------------------------------------------------------------------------
# backup ls / backup restore
# ---------------------------------------------------------------------------


def test_backup_ls_lists_the_snapshots(cli: CLI) -> None:
    build()
    result = ok(cli("backup", "ls", "--password-stdin", "--json"))
    document = json.loads(result.stdout)
    assert document["bunker"] == "alpha"
    live = VaultFile.load()
    assert document["generation"] == live.generation
    assert [item["snapshot"] for item in document["snapshots"]] == list(range(1, live.generation))
    for item in document["snapshots"]:
        assert set(item) == {"snapshot", "file", "path", "generation", "written", "size", "vault"}
        assert item["vault"] == "this vault" and item["size"] > 0 and Path(item["path"]).is_file()
    table = ok(cli("backup", "ls", "--password-stdin"))
    assert table.stdout.splitlines()[0].split() == ["SNAPSHOT", "WRITTEN", "SIZE", "VAULT"]
    assert "Bunker alpha" in table.stderr


def test_backup_ls_when_there_are_none(cli: CLI) -> None:
    result = ok(cli("backup", "ls", "--password-stdin", "--bunker", "bravo"))
    assert result.stdout == "" and "Bunker bravo has no snapshots" in result.stderr


def test_backup_commands_are_the_owners(cli: CLI) -> None:
    build()
    before = paths.vault_file().read_bytes()
    for command in (("backup", "ls"), ("backup", "restore", "1", "--yes")):
        result = ok(cli(*command), 5)
        assert "needs the vault's owner" in result.stderr
    assert paths.vault_file().read_bytes() == before


def test_backup_restore_puts_a_snapshot_back_and_can_be_undone(cli: CLI) -> None:
    build()
    with opened() as vault:
        vault.add("later", Secret(password="added later"))
        vault.commit()
        newest = vault.file.generation
    snapshot = newest - 1  # taken just before "later" was added
    result = ok(cli("backup", "restore", str(snapshot), "--password-stdin", "--yes", "--json",
                    stdin=lines(PASSWORD)))
    quiet(result)
    document = json.loads(result.stdout)
    assert document["restored"] == snapshot and document["kept"] == newest and document["bunker"] == "alpha"
    with opened() as vault:
        assert "later" not in contents(vault)
        assert contents(vault)["github"]["password"] == GITHUB_PASSWORD
    assert (paths.backups_dir() / f"vault-{newest:010d}.irondome").is_file()
    undo = ok(cli("backup", "restore", f"vault-{newest:010d}.irondome", "--password-stdin", "--yes",
                  stdin=lines(PASSWORD)))
    assert f"Restored snapshot {newest} of bunker alpha" in undo.stderr
    with opened() as vault:
        assert contents(vault)["later"]["password"] == "added later"


def test_backup_restore_refuses_a_snapshot_the_current_password_does_not_open(cli: CLI) -> None:
    build()
    with opened() as vault:  # change the master password the way `passwd` does: a new slot, the old one gone
        new = secret(FRESH_PASSWORD)
        try:
            slot = keys.create_password_slot(
                vault.vault_key, new, vault.vault_id, params=default_argon2(),
                backend=devices.choose_backend(), label="master password",
            )
        finally:
            new.wipe()
        old = vault.slots("password")[0]
        vault.add_slot(slot)
        vault.remove_slot(old.id)
        vault.commit()
    before = paths.vault_file().read_bytes()
    result = cli("backup", "restore", "1", "--password-stdin", "--yes", stdin=lines(FRESH_PASSWORD))
    assert result.returncode in (4, 7), result.stderr
    assert paths.vault_file().read_bytes() == before


def test_backup_restore_failures_change_nothing(cli: CLI) -> None:
    build()
    before = paths.vault_file().read_bytes()
    assert ok(cli("backup", "restore", "1", "--password-stdin", "--yes", stdin=lines("wrong password")), 4)
    assert "no snapshot '99'" in ok(
        cli("backup", "restore", "99", "--password-stdin", "--yes", stdin=lines(PASSWORD)), 3
    ).stderr
    assert "--yes" in ok(cli("backup", "restore", "1", "--password-stdin", stdin=lines(PASSWORD)), 2).stderr
    (paths.backups_dir() / "vault-0000000001.irondome").write_bytes(b"{ damaged")
    assert ok(cli("backup", "restore", "1", "--password-stdin", "--yes", stdin=lines(PASSWORD)), 6)
    assert paths.vault_file().read_bytes() == before


# ---------------------------------------------------------------------------
# export / import: portable backups
# ---------------------------------------------------------------------------


def test_portable_backup_survives_the_loss_of_the_machine(cli: CLI, isolated: Path) -> None:
    build()
    with opened() as vault:
        original = contents(vault)
        aliases = alias_targets(vault)
    target = isolated / "out" / "backup.irondome"
    result = ok(cli("export", str(target), "--password-stdin", stdin=lines(PASSWORD, EXPORT_PASSWORD)))
    quiet(result)
    assert result.stdout == ""
    assert "bunker alpha (2 entries, 2 aliases)" in result.stderr
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert sorted(path.name for path in target.parent.iterdir()) == ["backup.irondome"]  # nothing left beside it
    assert not RECOVERY_KEY.search(result.stdout + result.stderr)

    file = VaultFile.load(target)
    assert [slot.kind for slot in file.slots] == ["password"] and file.slots[0].device is None
    with pytest.raises(AuthError):
        unlock(file, password=secret(PASSWORD), interactive=False, allow_touch=False)

    wipe_machine()  # the computer is gone; only the backup is left
    build(FRESH_PASSWORD, entries=False)
    imported = ok(
        cli("import", str(target), "--password-stdin", "--json", stdin=lines(FRESH_PASSWORD, EXPORT_PASSWORD))
    )
    quiet(imported)
    document = json.loads(imported.stdout)
    assert (document["imported"], document["renamed"], document["skipped"], document["aliases"]) == (2, 0, 0, 2)
    assert document["format"] == "irondome"
    with opened(FRESH_PASSWORD) as vault:
        assert contents(vault) == original
        assert alias_targets(vault) == aliases
        github = vault.find("github")
        assert vault.value(github, "totp") == otp.code_for(otp.make_totp(TOTP_SECRET))


def test_portable_backup_with_a_recovery_key(cli: CLI, isolated: Path) -> None:
    build()
    target = isolated / "backup.irondome"
    result = ok(cli("export", str(target), "--recovery", "--password-stdin", stdin=lines(PASSWORD, EXPORT_PASSWORD)))
    recovery = RECOVERY_KEY.fullmatch(result.stdout.strip())
    assert recovery is not None and "shown only this once" in result.stderr
    file = VaultFile.load(target)
    assert sorted(slot.kind for slot in file.slots) == ["password", "recovery"]
    with Vault(file, unlock(file, recovery_key=recovery.group(0)), path=target) as vault:
        assert contents(vault)["aws/prod"]["password"] == AWS_KEY


def test_export_overwrites_only_with_yes(cli: CLI, isolated: Path) -> None:
    build()
    target = isolated / "backup.irondome"
    target.write_bytes(b"something else")
    refused = ok(cli("export", str(target), "--password-stdin", stdin=lines(PASSWORD, EXPORT_PASSWORD)), 2)
    assert "already exists" in refused.stderr and target.read_bytes() == b"something else"
    ok(cli("export", str(target), "--yes", "--password-stdin", stdin=lines(PASSWORD, EXPORT_PASSWORD)))
    assert interop.detect_format(target) == "irondome"


def test_export_refusals_write_nothing(cli: CLI, isolated: Path) -> None:
    build()
    with opened() as unlocked:
        session = caps.create_session(unlocked, ttl=600)  # the first session commits the vault: read it after
    vault = VaultFile.load()
    target = isolated / "backup.irondome"
    assert "needs the vault's owner" in ok(cli("export", str(target)), 5).stderr
    # a session token is not enough to export: the master password is asked for, and checked
    wrong = cli("export", str(target), "--password-stdin", stdin=lines("not the password", EXPORT_PASSWORD),
                env={"IRONDOME_SESSION": session})
    ok(wrong, 4)
    short = cli("export", str(target), "--password-stdin", stdin=lines(PASSWORD, "short"))
    assert "at least 8 characters" in ok(short, 2).stderr
    inside = paths.home() / "copy.irondome"
    refused = ok(cli("export", str(inside), "--password-stdin", stdin=lines(PASSWORD)), 2)
    assert "IronDome's own directory" in refused.stderr
    assert "no vault in bunker bravo" in ok(
        cli("export", str(target), "--bunker", "bravo", "--password-stdin", stdin=lines(PASSWORD)), 6
    ).stderr
    assert not target.exists() and not inside.exists()
    assert VaultFile.load().generation == vault.generation


def test_import_with_a_session_reads_only_the_backup_password(cli: CLI, isolated: Path) -> None:
    build()
    target = isolated / "backup.irondome"
    ok(cli("export", str(target), "--password-stdin", stdin=lines(PASSWORD, EXPORT_PASSWORD)))
    wipe_machine()
    build(FRESH_PASSWORD, entries=False)
    with opened(FRESH_PASSWORD) as vault:
        session = caps.create_session(vault, ttl=600)
    result = ok(cli("import", str(target), "--password-stdin", stdin=lines(EXPORT_PASSWORD),
                    env={"IRONDOME_SESSION": session}))
    assert "Imported 2 entries" in result.stderr


def test_import_refusals_change_nothing(cli: CLI, isolated: Path) -> None:
    build()
    target = isolated / "backup.irondome"
    ok(cli("export", str(target), "--password-stdin", stdin=lines(PASSWORD, EXPORT_PASSWORD)))
    before = paths.vault_file().read_bytes()
    assert "needs the vault's owner" in ok(cli("import", str(target)), 5).stderr
    wrong = ok(cli("import", str(target), "--password-stdin", stdin=lines(PASSWORD, "not the backup password")), 4)
    assert "does not open the backup" in wrong.stderr
    device_bound = isolated / "device-bound.irondome"
    with in_bunker("bravo"):
        build(BRAVO_PASSWORD, bunker="bravo")
        shutil.copy(str(paths.vault_file()), str(device_bound))
    not_portable = ok(cli("import", str(device_bound), "--format", "irondome", "--password-stdin",
                          stdin=lines(PASSWORD, BRAVO_PASSWORD)), 2)
    assert "not a portable backup" in not_portable.stderr
    assert "there is no file" in ok(cli("import", str(isolated / "missing.csv"), "--password-stdin",
                                        stdin=lines(PASSWORD)), 2).stderr
    assert paths.vault_file().read_bytes() == before


# ---------------------------------------------------------------------------
# export --plaintext and import of plaintext and third-party exports
# ---------------------------------------------------------------------------


def test_plaintext_export_needs_a_confirmation(cli: CLI, isolated: Path) -> None:
    build()
    target = isolated / "plain.json"
    refused = ok(cli("export", str(target), "--plaintext", "json", "--password-stdin", stdin=lines(PASSWORD)), 2)
    assert "EXPORT" in refused.stderr and not target.exists()
    with_recovery = cli("export", str(target), "--plaintext", "json", "--recovery", "--yes", "--password-stdin",
                        stdin=lines(PASSWORD))
    assert ok(with_recovery, 2) and not target.exists()


@pytest.mark.parametrize("fmt", ["json", "csv"])
def test_plaintext_export_round_trips_through_import(cli: CLI, isolated: Path, fmt: str) -> None:
    build()
    with opened() as vault:
        original = contents(vault)
        aliases = alias_targets(vault)
    target = isolated / f"plain.{fmt}"
    result = ok(cli("export", str(target), "--plaintext", fmt, "--yes", "--password-stdin", stdin=lines(PASSWORD)))
    quiet(result)
    assert "unencrypted" in result.stderr and "warning" in result.stderr
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    text = target.read_text(encoding="utf-8")
    assert GITHUB_PASSWORD in text and AWS_KEY in text and TOTP_SECRET in text and REGION in text

    wipe_machine()
    build(FRESH_PASSWORD, entries=False)
    imported = ok(cli("import", str(target), "--password-stdin", "--json", stdin=lines(FRESH_PASSWORD)))
    quiet(imported)
    assert json.loads(imported.stdout)["format"] == fmt
    with opened(FRESH_PASSWORD) as vault:
        restored = contents(vault)
        if fmt == "json":
            assert restored == original
            assert alias_targets(vault) == aliases
        else:  # CSV carries every value, but neither the history nor the aliases
            for name, values in original.items():
                assert restored[name] == {**values, "history": [], "aliases": []}


SAMPLES = {
    "chrome": (
        "name,url,username,password,note\r\n"
        "github.com,https://github.com/session,alice,\"pa,ss\"\"word\",\r\n"
        "github.com,https://github.com/session,bob,Bob-Pass-2,shared\r\n"
    ),
    "firefox": (
        '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed",'
        '"timePasswordChanged"\n'
        '"https://accounts.firefox.com","fox@example.com","Fx-Example-1",,"https://accounts.firefox.com",'
        '"{0b0b}","1700000000000","1700000100000","1700000200000"\n'
    ),
    "1password": (
        "Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\n"
        "Slack,https://example.slack.com,me@example.com,Slack-Example-2,"
        "otpauth://totp/Slack:me?secret=GEZDGNBVGY3TQOJQ&issuer=Slack,Favorite,Not archived,work,\n"
    ),
    "bitwarden-csv": (
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
        "Work,1,login,GitLab,,\"Team: platform\",0,https://gitlab.example.com,dev@example.com,Gl-Example-3,"
        "steam://NOTSUPPORTED\n"
    ),
    "bitwarden-json": json.dumps(
        {
            "encrypted": False,
            "folders": [],
            "items": [
                {"type": 1, "name": "Vercel", "notes": "n",
                 "login": {"username": "v", "password": "Vercel-Example-4", "totp": TOTP_SECRET,
                           "uris": [{"uri": "https://vercel.com"}]}},
                {"type": 2, "name": "Recovery codes", "notes": "1111-2222"},
            ],
        }
    ),
    "csv": "Title;Username;Password;URL;Notes\nrouter;admin;Router-Example-5;http://192.168.1.1;rack\n",
}

EXPECTED = {
    "chrome": {"github.com (alice)": ("alice", 'pa,ss"word'), "github.com (bob)": ("bob", "Bob-Pass-2")},
    "firefox": {"accounts.firefox.com": ("fox@example.com", "Fx-Example-1")},
    "1password": {"Slack": ("me@example.com", "Slack-Example-2")},
    "bitwarden-csv": {"GitLab": ("dev@example.com", "Gl-Example-3")},
    "bitwarden-json": {"Vercel": ("v", "Vercel-Example-4"), "Recovery codes": ("", "")},
    "csv": {"router": ("admin", "Router-Example-5")},
}


@pytest.mark.parametrize("sample", sorted(SAMPLES))
def test_import_of_other_managers_exports(cli: CLI, isolated: Path, sample: str) -> None:
    build(entries=False)
    source = isolated / f"export-{sample}.{'json' if sample.endswith('json') else 'csv'}"
    source.write_bytes(SAMPLES[sample].encode("utf-8"))
    result = ok(cli("import", str(source), "--password-stdin", stdin=lines(PASSWORD)))
    values = [password for _, password in EXPECTED[sample].values() if password]
    quiet(result, *values)
    with opened() as vault:
        found = contents(vault)
        assert {name: (item["username"], item["password"]) for name, item in found.items()} == EXPECTED[sample]
        assert all(entry.agent == "deny" for entry in vault.entries.values())  # agents get nothing imported
    if sample == "1password":
        assert found["Slack"]["totp"]["issuer"] == "Slack" and found["Slack"]["tags"] == ["work"]
    if sample == "bitwarden-json":
        assert found["Vercel"]["totp"]["secret"] == TOTP_SECRET and found["Recovery codes"]["kind"] == "secret"
    if sample == "bitwarden-csv":  # a Steam code is not a TOTP IronDome can compute: kept, and said so
        assert found["GitLab"]["totp"] is None
        assert found["GitLab"]["fields"] == {"Team": "platform", "totp_unparsed": "steam://NOTSUPPORTED"}
        assert "totp_unparsed" in result.stderr


def test_import_conflict_policies(cli: CLI, isolated: Path) -> None:
    build()
    source = isolated / "chrome.csv"
    source.write_bytes(
        b"name,url,username,password\r\n"
        b"github,https://github.com,king,changed-elsewhere-1\r\n"
        b"aws/prod,,,AKIA-not-a-real-key\r\n"
    )
    renamed = json.loads(ok(cli("import", str(source), "--format", "chrome", "--password-stdin", "--json",
                                stdin=lines(PASSWORD))).stdout)
    assert (renamed["imported"], renamed["renamed"], renamed["skipped"]) == (1, 1, 1)
    actions = {item["source"]: (item["action"], item["name"], item["reason"]) for item in renamed["entries"]}
    assert actions == {
        "github": ("renamed", "github (imported)", ""),
        "aws/prod": ("skipped", "aws/prod", "already in the vault"),
    }
    again = json.loads(ok(cli("import", str(source), "--password-stdin", "--json", stdin=lines(PASSWORD))).stdout)
    assert (again["imported"], again["skipped"]) == (0, 2)  # importing the same file twice adds nothing

    with opened() as vault:
        vault.remove(vault.find("github (imported)"))
        vault.commit()
    skipped = json.loads(ok(cli("import", str(source), "--on-conflict", "skip", "--password-stdin", "--json",
                                stdin=lines(PASSWORD))).stdout)
    assert (skipped["imported"], skipped["skipped"]) == (0, 2)
    with opened() as vault:
        assert contents(vault)["github"]["password"] == GITHUB_PASSWORD and len(vault.entries) == 2

    replaced = json.loads(ok(cli("import", str(source), "--on-conflict", "replace", "--password-stdin", "--json",
                                 stdin=lines(PASSWORD))).stdout)
    assert (replaced["imported"], replaced["replaced"], replaced["skipped"]) == (1, 1, 1)
    with opened() as vault:
        github = contents(vault)["github"]
        assert github["password"] == "changed-elsewhere-1"
        assert github["history"][0] == GITHUB_PASSWORD  # the replaced password is kept in the history
        assert alias_targets(vault)["GITHUB_TOKEN"] == ("github", "password")


def test_import_of_a_malformed_file_names_the_row_and_changes_nothing(cli: CLI, isolated: Path) -> None:
    build()
    before = paths.vault_file().read_bytes()
    source = isolated / "broken.csv"
    source.write_bytes(b'name,url,username,password\na,b,c,d\n"never closed,b,c,d\n')
    result = ok(cli("import", str(source), "--format", "chrome", "--password-stdin", stdin=lines(PASSWORD)), 2)
    assert "row 3" in result.stderr
    big = isolated / "big.csv"
    with open(big, "wb") as handle:
        handle.truncate(interop.MAX_FILE_BYTES + 1)
    assert "larger than 50 MB" in ok(cli("import", str(big), "--format", "csv", "--password-stdin",
                                         stdin=lines(PASSWORD)), 2).stderr
    assert paths.vault_file().read_bytes() == before


def test_import_into_another_bunker(cli: CLI, isolated: Path) -> None:
    build()
    build(BRAVO_PASSWORD, bunker="bravo", entries=False)
    source = isolated / "chrome.csv"
    source.write_bytes(SAMPLES["chrome"].encode("utf-8"))
    result = ok(cli("import", str(source), "--bunker", "bravo", "--password-stdin", stdin=lines(BRAVO_PASSWORD)))
    assert "into bunker bravo" in result.stderr
    with opened(BRAVO_PASSWORD, bunker="bravo") as vault:
        assert sorted(contents(vault)) == ["github.com (alice)", "github.com (bob)"]
    with opened() as vault:
        assert sorted(contents(vault)) == ["aws/prod", "github"]


def test_import_without_a_vault_names_the_bunker(cli: CLI, isolated: Path) -> None:
    source = isolated / "chrome.csv"
    source.write_bytes(SAMPLES["chrome"].encode("utf-8"))
    result = ok(cli("import", str(source), "--bunker", "bravo", "--password-stdin", stdin=lines(PASSWORD)), 6)
    assert "there is no vault in bunker bravo" in result.stderr
    assert "irondome --bunker bravo init" in result.stderr


def test_import_keeps_an_entry_whose_user_name_or_address_holds_control_characters(cli: CLI, isolated: Path) -> None:
    """The vault refuses them there (a listing would hand them to the terminal); the entry is never lost."""
    build()
    source = isolated / "chrome.csv"
    source.write_text(
        'name,url,username,password,note\nbank,"https://bank.example/\x07","me\x1b[31m","bank-pass-\x1b-1",\n',
        encoding="utf-8",
    )
    result = ok(cli("--password-stdin", "import", str(source), stdin=lines(PASSWORD)))
    assert "control characters were taken out of its user name and web address" in result.stderr
    assert "\x1b" not in result.stdout + result.stderr and "\x07" not in result.stdout + result.stderr
    with opened() as vault:
        entry = vault.find("bank")
        assert (entry.username, entry.url) == ("me[31m", "https://bank.example/")
        assert vault.read_secret(entry).password == "bank-pass-\x1b-1"  # a value is never changed


def test_import_of_a_backup_written_before_the_rule_keeps_such_an_entry(cli: CLI, isolated: Path) -> None:
    build()
    target = isolated / "older.irondome"
    vault_id = os.urandom(keys.VAULT_ID_LEN)
    vault_key = keys.new_vault_key()
    password = secret(EXPORT_PASSWORD)
    try:
        slot = keys.create_password_slot(vault_key, password, vault_id, params=default_argon2(), backend=None)
    finally:
        password.wipe()
    with Vault.create(vault_key, [slot], vault_id, target) as older:
        entry = older.add("legacy-login", Secret(password="legacy-pass-1"), username="someone")
        entry.username, entry.url = "someone\x1b]0;owned\x07", "https://legacy.example/\x9b"  # as a 4.0 beta kept them
        older.commit(snapshots=0)
    result = ok(cli("--password-stdin", "import", str(target), stdin=lines(PASSWORD, EXPORT_PASSWORD)))
    assert "legacy-login: control characters were taken out of its user name and web address" in result.stderr
    with opened() as vault:
        imported = vault.find("legacy-login")
        assert (imported.username, imported.url) == ("someone]0;owned", "https://legacy.example/")
        assert vault.read_secret(imported).password == "legacy-pass-1"


# ---------------------------------------------------------------------------
# migrate
# ---------------------------------------------------------------------------


def legacy_values(fixture: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    return sorted((item["username"], item["password"], item["notes"]) for item in fixture["entries"])


def vault_values(vault: Vault) -> List[Tuple[str, str, str]]:
    return sorted((item["username"], item["password"], item["notes"]) for item in contents(vault).values())


@pytest.mark.parametrize("mode", ["password_only", "biometric_password", "biometric_only"])
def test_migrate_each_mode_of_3x(cli: CLI, mode: str) -> None:
    fixture = unpack_legacy(mode)
    before = tree(paths.legacy_v3_dir())
    if mode == "biometric_only":
        # No master password: the key 3.x kept in the keychain. The keychain this test can reach is not the
        # one 3.x used (HOME is not the account's own), so the key is asked for and piped in.
        args = ["--legacy-key"]
        stdin = lines(fixture["keyring"]["master_key"], FRESH_PASSWORD)
        password = FRESH_PASSWORD
    else:
        args = ["--legacy-username", fixture["master_username"]]
        stdin = lines(fixture["master_password"])
        password = fixture["master_password"]  # kept for the new vault, the default
    result = ok(cli("migrate", *args, "--password-stdin", "--json", stdin=stdin))
    quiet(result, *(item["password"] for item in fixture["entries"]))
    if mode == "biometric_only":
        # A keychain that cannot be asked is said to be one, never one without the key, and the way to give
        # the key is named.
        assert "not the one IronDome 3.x used" in result.stderr, result.stderr
        assert "--legacy-key --password-stdin" in result.stderr and "does not hold" not in result.stderr
    document = json.loads(result.stdout)
    assert {"imported", "renamed", "skipped", "verified", "legacy_destroyed"} <= set(document)
    assert document["imported"] == len(fixture["entries"]) and document["verified"] is True
    assert document["legacy_destroyed"] is False and document["created"] is True
    assert RECOVERY_KEY.fullmatch(document["recovery_key"])
    with opened(password) as vault:
        assert vault_values(vault) == legacy_values(fixture)
        assert all(entry.agent == "deny" for entry in vault.entries.values())
    assert tree(paths.legacy_v3_dir()) == before


def test_migrate_reports_in_words(cli: CLI) -> None:
    fixture = unpack_legacy("collisions")
    result = ok(cli("migrate", "--legacy-username", fixture["master_username"], "--password-stdin",
                    stdin=lines(fixture["master_password"])))
    quiet(result, *(item["password"] for item in fixture["entries"]))
    assert "verified  yes" in result.stdout and "renamed   " in result.stdout
    assert "was not changed" in result.stderr and "irondome migrate --destroy-old" in result.stderr
    assert RECOVERY_KEY.search(result.stdout)


def test_wrong_legacy_password_creates_nothing(cli: CLI) -> None:
    fixture = unpack_legacy("password_only")
    before = tree(paths.legacy_v3_dir())
    result = ok(cli("migrate", "--legacy-username", fixture["master_username"], "--password-stdin",
                    stdin=lines("not the 3.x password")), 4)
    assert "--legacy-key" in result.stderr  # the hint for a vault that may have no master password
    assert not paths.root().exists() and not paths.device_root().exists()
    unknown_user = ok(cli("migrate", "--password-stdin", stdin=lines(fixture["master_password"])), 2)
    assert "--legacy-username" in unknown_user.stderr
    assert not paths.root().exists()
    assert tree(paths.legacy_v3_dir()) == before


def test_migrate_into_an_existing_vault(cli: CLI) -> None:
    build()
    fixture = unpack_legacy("password_only")
    taken = fixture["entries"][0]["website"]
    with opened() as vault:
        vault.add(taken, Secret(password="not the 3.x value"))
        vault.commit()
    creating = cli("migrate", "--legacy-username", fixture["master_username"], "--new-password", "--password-stdin",
                   stdin=lines(fixture["master_password"], PASSWORD))
    assert "only when migrate creates the vault" in ok(creating, 2).stderr
    result = ok(cli("migrate", "--legacy-username", fixture["master_username"], "--password-stdin", "--json",
                    stdin=lines(fixture["master_password"], PASSWORD)))
    document = json.loads(result.stdout)
    assert document["created"] is False and document["verified"] is True and document["recovery_key"] is None
    assert {"from": taken, "to": f"{taken} (2)"} in document["renamed"]
    with opened() as vault:
        found = contents(vault)
        assert found["github"]["password"] == GITHUB_PASSWORD and found[taken]["password"] == "not the 3.x value"
        assert len(found) == 3 + len(fixture["entries"])
    again = json.loads(ok(cli("migrate", "--legacy-username", fixture["master_username"], "--password-stdin",
                              "--json", stdin=lines(fixture["master_password"], PASSWORD))).stdout)
    assert again["imported"] == 0 and again["verified"] is True  # a second run adds nothing


def test_migrate_with_a_new_password(cli: CLI) -> None:
    fixture = unpack_legacy("password_only")
    ok(cli("migrate", "--legacy-username", fixture["master_username"], "--new-password", "--no-recovery",
           "--kdf-memory-mib", "20", "--password-stdin", stdin=lines(fixture["master_password"], FRESH_PASSWORD)))
    with opened(FRESH_PASSWORD) as vault:
        (slot,) = vault.file.slots
        assert slot.kind == "password" and slot.kdf is not None and slot.kdf["m"] == 20 * 1024
        assert [event.action for event in audit.read(vault)] == ["vault.create", "migrate"]
        assert audit.verify(vault).ok
    with pytest.raises(AuthError):
        with opened(fixture["master_password"]):
            pass


def test_migrate_checks_the_options_of_a_new_vault_first(cli: CLI) -> None:
    fixture = unpack_legacy("password_only")
    for options in (["--no-password"], ["--mode", "touchid", "--no-password", "--no-recovery"],
                    ["--kdf-memory-mib", "1"], ["--keep-password", "--new-password"]):
        result = cli("migrate", "--legacy-username", fixture["master_username"], *options, "--password-stdin",
                     stdin=lines(fixture["master_password"]))
        ok(result, 2)
    assert not paths.root().exists() and not paths.device_root().exists()


def test_migrate_that_fails_after_creating_the_vault_leaves_nothing() -> None:
    fixture = unpack_legacy("password_only")
    result = run_with_fault("migrate", "migrate", "--legacy-username", fixture["master_username"], "--password-stdin",
                            stdin=lines(fixture["master_password"]))
    assert result.returncode == 1 and "injected" in result.stderr, result.stderr
    assert not vault_exists() and device_keys() == [] and not paths.audit_file().exists()
    assert not list(paths.backups_dir().glob("vault-*.irondome"))
    assert tree(paths.legacy_v3_dir())  # the 3.x vault is still there, untouched


def test_migrate_destroys_the_old_vault_only_when_asked(cli: CLI) -> None:
    fixture = unpack_legacy("password_only")
    unconfirmed = cli("migrate", "--legacy-username", fixture["master_username"], "--destroy-old", "--password-stdin",
                      stdin=lines(fixture["master_password"]))
    assert "DESTROY" in ok(unconfirmed, 2).stderr and not paths.root().exists()
    result = ok(cli("migrate", "--legacy-username", fixture["master_username"], "--destroy-old", "--yes",
                    "--password-stdin", "--json", stdin=lines(fixture["master_password"])))
    document = json.loads(result.stdout)
    assert document["verified"] is True and document["legacy_destroyed"] is True
    assert document["destroy"]["errors"] == [] and document["destroy"]["leftovers"] == []
    assert document["destroy"]["keychain_cleared"] is None  # not the keychain of a real ~/.password_manager
    assert not paths.legacy_v3_dir().exists()
    with opened(fixture["master_password"]) as vault:
        assert vault_values(vault) == legacy_values(fixture)


def test_migrate_without_a_3x_vault(cli: CLI, isolated: Path) -> None:
    assert "no IronDome 3.x vault" in ok(cli("migrate", "--password-stdin", stdin=lines(PASSWORD)), 3).stderr
    elsewhere = isolated / "elsewhere"
    elsewhere.mkdir()
    result = ok(cli("migrate", "--from", str(elsewhere), "--password-stdin", stdin=lines(PASSWORD)), 3)
    assert str(elsewhere) in result.stderr
    assert "needs the vault's owner" in ok(cli("migrate"), 5).stderr


# ---------------------------------------------------------------------------
# rekey
# ---------------------------------------------------------------------------


def test_rekey_leaves_nothing_taken_before_able_to_open_the_vault(cli: CLI, isolated: Path) -> None:
    old_recovery = build()
    with opened() as vault:
        original = contents(vault)
        aliases = alias_targets(vault)
        session = caps.create_session(vault, ttl=600)
        grant, _info = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=600)
        old_id = vault.vault_id
    old_copy = paths.vault_file().read_bytes()
    old_keys = device_keys()
    assert len(old_keys) == 2  # the password slot's, and the one the session and the grant are bound to
    assert [path for path in paths.backups_dir().iterdir()]  # snapshots exist before
    stolen_caps = isolated / "stolen-caps"
    shutil.copytree(str(paths.caps_dir()), str(stolen_caps))

    result = ok(cli("rekey", "--yes", "--password-stdin", "--json", stdin=lines(PASSWORD)))
    quiet(result)
    document = json.loads(result.stdout)
    assert document["entries"] == 2 and document["leftovers"] == []
    assert document["sessions_and_grants_ended"] == 2 and document["device_keys_destroyed"] == 2
    assert document["snapshots_deleted"] >= 1
    assert [slot["kind"] for slot in document["keyslots"]] == ["password", "recovery"]
    (new_recovery,) = document["recovery_keys"]
    assert "OLD recovery key" in result.stderr  # said even when the result is JSON

    with opened() as vault:  # the same master password, a new vault key
        assert vault.vault_id != old_id and vault.vault_id.hex() == document["vault_id"]
        assert contents(vault) == original
        assert alias_targets(vault) == aliases
        assert audit.verify(vault).ok
    assert not set(old_keys) & set(device_keys()) and len(device_keys()) == 1
    assert list(paths.backups_dir().glob("vault-*.irondome")) == []
    assert not list(paths.home().glob(".tmp-*"))
    archived = Path(document["audit_archive"])
    assert archived.is_file() and archived.parent == paths.home()

    with pytest.raises(AuthError):
        caps.open_session(session, VaultFile.load())
    with pytest.raises(AuthError):
        caps.open_grant(grant)
    shutil.copytree(str(stolen_caps), str(paths.caps_dir()), dirs_exist_ok=True)  # copies of the files, put back
    with pytest.raises(AuthError):
        caps.open_grant(grant)  # the grant's values stay sealed: the device secret it was bound to is gone
    with pytest.raises(AuthError):
        caps.open_session(session, VaultFile.from_bytes(old_copy))
    old_file = VaultFile.from_bytes(old_copy)  # a copy of the vault taken before: the master password opens nothing
    with pytest.raises((HardwareError, AuthError)):
        unlock(old_file, password=secret(PASSWORD), interactive=False, allow_touch=False)
    with Vault(old_file, unlock(old_file, recovery_key=old_recovery)) as stale:  # the stated limit, still true
        assert len(stale.entries) == 2
    current = VaultFile.load()
    with Vault(current, unlock(current, recovery_key=new_recovery)) as vault:
        assert len(vault.entries) == 2
    with pytest.raises(AuthError):
        unlock(current, recovery_key=old_recovery)


def test_rekey_without_a_recovery_key_and_in_words(cli: CLI) -> None:
    build(recovery=False)
    result = ok(cli("rekey", "--yes", "--password-stdin", stdin=lines(PASSWORD)))
    assert "Re-keyed bunker alpha" in result.stderr and "archived" in result.stderr
    assert "OLD recovery key" not in result.stderr and result.stdout == ""
    with opened() as vault:
        assert [slot.kind for slot in vault.file.slots] == ["password"]


FAULTS = textwrap.dedent(
    """
    import sys

    from irondome import migrate_v3, paths, vault
    from irondome.errors import IronDomeError

    fault = sys.argv[1]
    if fault == "migrate":
        def broken_verify(opened, entries):
            raise IronDomeError("injected: the comparison with the 3.x vault failed")

        migrate_v3.verify = broken_verify
    elif fault == "copy":
        def broken(self, other):
            raise IronDomeError("injected: copying the entries failed")

        vault.Vault.copy_into = broken
    elif fault == "replace":
        real = paths.write_atomic

        def refuse_live(path, data):
            if str(path) == str(paths.vault_file()):
                raise OSError(28, "No space left on device")
            return real(path, data)

        paths.write_atomic = refuse_live
    elif fault == "keychain":
        import os

        # The keychain of the account's real home, as 3.x left it: within reach, and it hands the key over
        # without a word.
        migrate_v3.keychain_unreachable = lambda: None
        migrate_v3.keychain_master_key = lambda: bytearray(os.environ["IRONDOME_TEST_LEGACY_KEY"].encode("ascii"))
    elif fault == "keychain-refused":
        from irondome.errors import AuthError

        # Within reach, but the person clicked "Deny" (or the keychain is locked, over SSH).
        def refuse():
            raise AuthError(
                "the operating system did not release the IronDome 3.x key from the keychain (security exited "
                "with status 51). Unlock the login keychain and allow the request, or supply the key yourself"
            )

        migrate_v3.keychain_unreachable = lambda: None
        migrate_v3.keychain_master_key = refuse
    from irondome.cli.main import main

    raise SystemExit(main(sys.argv[2:]))
    """
)


def run_with_fault(
    fault: str, *args: str, stdin: str, env: Optional[Dict[str, str]] = None
) -> "subprocess.CompletedProcess[str]":
    """The real command line, with one failure injected into the library first."""
    merged = dict(os.environ)
    if SUPPORT.is_dir():
        merged["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SUPPORT), merged.get("PYTHONPATH", "")]))
        merged["IRONDOME_TEST_BLOCK_SOCKETS"] = "1"
    merged.update(env or {})
    return subprocess.run(
        [sys.executable, "-c", FAULTS, fault, *args], input=stdin, capture_output=True, text=True, env=merged,
        timeout=120,
    )


def test_a_3x_key_from_the_keychain_is_no_proof_of_ownership(cli: CLI) -> None:
    """A biometric-only 3.x vault opens with a key any process running as you can read from the keychain.

    So that key proves nothing about who is asking: nothing piped on stdin may then choose the master
    password of the vault the entries go into, nor open one (the first vault on a machine may be a
    script's), and so nothing is created, copied or destroyed. A person at a terminal types the
    password at a hidden prompt instead, where a session does not count either.
    """
    fixture = unpack_legacy("biometric_only")
    legacy = tree(paths.legacy_v3_dir())
    key = {"IRONDOME_TEST_LEGACY_KEY": fixture["keyring"]["master_key"]}
    for extra in (["--destroy-old", "--yes"], []):
        refused = run_with_fault("keychain", "migrate", "--legacy-key", *extra, "--password-stdin",
                                 stdin=lines(FRESH_PASSWORD), env=key)
        assert refused.returncode == 5, refused.stderr
        assert "OS keychain" in refused.stderr and "at a terminal" in refused.stderr
        quiet(refused, *(item["password"] for item in fixture["entries"]))
    assert not vault_exists() and tree(paths.legacy_v3_dir()) == legacy
    build()
    before = paths.vault_file().read_bytes()
    into = run_with_fault("keychain", "migrate", "--legacy-key", "--password-stdin", stdin=lines(PASSWORD), env=key)
    assert into.returncode == 5, into.stderr
    assert paths.vault_file().read_bytes() == before and tree(paths.legacy_v3_dir()) == legacy


def test_a_keychain_that_refuses_the_3x_key_lets_you_give_it_instead() -> None:
    """The refusal ("supply the key yourself") can be acted on: it is shown, and the key is read as if absent."""
    fixture = unpack_legacy("biometric_only")
    result = run_with_fault("keychain-refused", "migrate", "--legacy-key", "--password-stdin", "--json",
                            stdin=lines(fixture["keyring"]["master_key"], FRESH_PASSWORD))
    assert result.returncode == 0, result.stderr
    assert "did not hand over the 3.x key: the operating system did not release" in result.stderr
    assert "--legacy-key --password-stdin" in result.stderr
    quiet(result, *(item["password"] for item in fixture["entries"]))
    document = json.loads(result.stdout)
    assert document["imported"] == len(fixture["entries"]) and document["verified"] is True
    with opened(FRESH_PASSWORD) as vault:
        assert vault_values(vault) == legacy_values(fixture)


@pytest.mark.parametrize("fault, code", [("copy", 1), ("replace", 6)])
def test_rekey_that_fails_before_the_switch_leaves_the_old_vault_working(fault: str, code: int) -> None:
    build()
    with opened() as vault:
        session = caps.create_session(vault, ttl=600)
        original = contents(vault)
    before = paths.vault_file().read_bytes()
    keys_before = device_keys()
    snapshots = sorted(path.name for path in paths.backups_dir().iterdir())
    result = run_with_fault(fault, "rekey", "--yes", "--password-stdin", stdin=lines(PASSWORD))
    assert result.returncode == code, result.stderr
    assert "Traceback" not in result.stderr
    assert paths.vault_file().read_bytes() == before
    assert device_keys() == keys_before  # the new device key was destroyed again
    assert not list(paths.home().glob(".tmp-*"))
    assert sorted(path.name for path in paths.backups_dir().iterdir()) == snapshots
    assert not list(paths.home().glob("audit-*.log"))
    with opened() as vault:
        assert contents(vault) == original
    vault_key = caps.open_session(session, VaultFile.load())
    vault_key.wipe()


def test_rekey_refusals_change_nothing(cli: CLI) -> None:
    build()
    with opened() as vault:
        session = caps.create_session(vault, ttl=600)
    before = paths.vault_file().read_bytes()
    assert "needs the vault's owner" in ok(cli("rekey", "--yes"), 5).stderr
    assert "REKEY" in ok(cli("rekey", "--password-stdin", stdin=lines(PASSWORD)), 2).stderr
    ok(cli("rekey", "--yes", "--password-stdin", stdin=lines("wrong password")), 4)
    # a session is not enough: the password is asked for and checked
    ok(cli("rekey", "--yes", "--password-stdin", stdin=lines("wrong password"), env={"IRONDOME_SESSION": session}), 4)
    assert "no vault in bunker bravo" in ok(
        cli("rekey", "--yes", "--bunker", "bravo", "--password-stdin", stdin=lines(PASSWORD)), 6
    ).stderr
    assert paths.vault_file().read_bytes() == before


# ---------------------------------------------------------------------------
# nuke
# ---------------------------------------------------------------------------


def test_nuke_destroys_every_bunker(cli: CLI, isolated: Path) -> None:
    # Without a terminal, --yes-destroy-everything needs one master password that opens every vault it destroys.
    build()
    build(bunker="bravo")
    with opened() as vault:
        session = caps.create_session(vault, ttl=600)
    with opened(bunker="bravo") as vault:
        grant, _info = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=600)
    paths.set_default_bunker("bravo")
    foreign = paths.root() / "my-notes.txt"
    foreign.write_text("not IronDome's\n", encoding="utf-8")
    copy = isolated / "stolen-copy"
    shutil.copytree(str(paths.root()), str(copy))  # a bit-perfect copy of the vault directory, taken before

    result = ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", stdin=lines(PASSWORD)))
    assert "alpha, bravo" in result.stdout
    assert str(foreign) in result.stderr and "not created by IronDome" in result.stderr
    assert "a recovery key still opens any copy of the vault files of bunkers alpha and bravo" in result.stderr
    assert sorted(str(path) for path in paths.root().rglob("*")) == [str(foreign)]
    assert not paths.device_root().exists()
    assert foreign.read_text(encoding="utf-8") == "not IronDome's\n"

    shutil.copytree(str(copy), str(paths.root()), dirs_exist_ok=True)  # the copy comes back
    for bunker, password in (("alpha", PASSWORD), ("bravo", PASSWORD)):
        with in_bunker(bunker):
            assert vault_exists()
            file = VaultFile.load()
            with pytest.raises((HardwareError, AuthError)):
                unlock(file, password=secret(password), interactive=False, allow_touch=False)
            if bunker == "alpha":  # the copied session file is back, with its token: it opens nothing either
                with pytest.raises(AuthError):
                    caps.open_session(session, file)
            else:
                with pytest.raises(AuthError):
                    caps.open_grant(grant)


def test_nuke_json(cli: CLI) -> None:
    build()
    result = ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", "--json", stdin=lines(PASSWORD)))
    document = json.loads(result.stdout)
    assert set(document) == {"plan", "report", "legacy", "success", "nothing_to_do", "device_copy_caveat"}
    assert document["success"] is True and document["nothing_to_do"] is False
    assert set(document["plan"]) == {
        "root", "device_root", "bunkers", "unreadable_vaults", "device_keys", "recovery_bunkers", "capabilities",
        "files", "foreign", "legacy_vault",
    }
    assert document["plan"]["bunkers"] == ["alpha"] and document["plan"]["recovery_bunkers"] == ["alpha"]
    (key,) = document["plan"]["device_keys"]
    assert key == {"bunker": "alpha", "backend": "software", "policy": "device", "hardware": False, "present": True}
    assert set(document["report"]) == {
        "success", "bunkers", "device_keys_destroyed", "hardware_backed", "files_deleted", "leftovers", "foreign",
        "errors", "recovery_bunkers",
    }
    assert document["report"]["device_keys_destroyed"] == 1 and document["report"]["leftovers"] == []
    again = json.loads(ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", "--json")).stdout)
    assert again["nothing_to_do"] is True and again["report"] is None


def test_nuke_refusals_destroy_nothing(cli: CLI) -> None:
    build()
    before = tree(paths.root())
    assert "needs the vault's owner" in ok(cli("nuke", "--yes-destroy-everything"), 5).stderr
    unconfirmed = ok(cli("nuke", "--password-stdin", stdin=lines(PASSWORD)), 2)
    assert "--yes-destroy-everything" in unconfirmed.stderr and "Nothing was destroyed" in unconfirmed.stderr
    assert tree(paths.root()) == before and device_keys()


@pytest.mark.parametrize("stdin", ["", "not the master password\n"], ids=["no-line", "wrong"])
def test_an_agent_with_password_stdin_and_no_password_cannot_nuke(cli: CLI, stdin: str) -> None:
    """--password-stdin is a flag any agent can pass; only the password itself proves the owner."""
    build()
    before = (tree(paths.root()), tree(paths.device_root()))
    refused = ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", stdin=stdin), 2 if stdin == "" else 4)
    assert ("nothing was entered" if stdin == "" else "Nothing was destroyed") in refused.stderr
    assert (tree(paths.root()), tree(paths.device_root())) == before and device_keys()


def test_nuke_needs_one_password_that_opens_every_vault_it_destroys(cli: CLI) -> None:
    build()
    build(BRAVO_PASSWORD, bunker="bravo")
    before = (tree(paths.root()), tree(paths.device_root()))
    for password in (PASSWORD, BRAVO_PASSWORD):
        refused = ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", stdin=lines(password)), 4)
        words = " ".join(refused.stderr.split())
        assert "one master password that opens every vault it destroys" in words
        assert "Run nuke at a terminal and type DESTROY" in words and "irondome bunker rm NAME" in words
        assert "Nothing was destroyed" in words
        quiet(refused, BRAVO_PASSWORD)
    assert (tree(paths.root()), tree(paths.device_root())) == before
    # One bunker at a time, each with its own password, works without a terminal.
    ok(cli("bunker", "rm", "bravo", "--yes", "--password-stdin", stdin=lines(BRAVO_PASSWORD)))
    ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", stdin=lines(PASSWORD)))
    assert not paths.root().exists() and not paths.device_root().exists()


def test_nuke_with_password_stdin_needs_a_vault_that_can_check_the_password(cli: CLI) -> None:
    """A damaged vault cannot check a password, so it cannot be what lets --yes-destroy-everything through."""
    build()
    paths.vault_file().write_bytes(b"{ damaged")
    before = (tree(paths.root()), tree(paths.device_root()))
    refused = ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", stdin=lines(PASSWORD)), 5)
    assert "cannot be checked against anything" in " ".join(refused.stderr.split())
    assert (tree(paths.root()), tree(paths.device_root())) == before


def test_nuke_reaches_a_3x_vault_only_when_asked(cli: CLI) -> None:
    build()
    unpack_legacy("password_only")
    legacy = tree(paths.legacy_v3_dir())
    first = ok(cli("nuke", "--yes-destroy-everything", "--password-stdin", stdin=lines(PASSWORD)))
    assert "is not touched; add --include-legacy" in first.stderr
    assert tree(paths.legacy_v3_dir()) == legacy and not paths.vault_file().exists()
    # With no vault of its own left to check the password against, a 3.x vault alone is not destroyed from stdin.
    alone = ok(
        cli("nuke", "--yes-destroy-everything", "--include-legacy", "--password-stdin", stdin=lines(PASSWORD)), 5
    )
    assert "Run nuke at a terminal" in alone.stderr and tree(paths.legacy_v3_dir()) == legacy
    build()
    second = ok(cli("nuke", "--yes-destroy-everything", "--include-legacy", "--password-stdin", "--json",
                    stdin=lines(PASSWORD)))
    document = json.loads(second.stdout)
    assert document["legacy"]["success"] is True and document["success"] is True
    assert not paths.legacy_v3_dir().exists() and not paths.vault_file().exists()


# ---------------------------------------------------------------------------
# doctor, completion, version
# ---------------------------------------------------------------------------


def test_doctor_json(cli: CLI) -> None:
    build()
    result = ok(cli("doctor", "--json"))  # open to anyone: it reads nothing secret and changes nothing
    document = json.loads(result.stdout)
    assert document["irondome"] and document["vault"]["present"] is True
    assert [slot["kind"] for slot in document["vault"]["keyslots"]] == ["password", "recovery"]
    assert document["new_vault_backend"] == "software" and document["problems"] == 0
    assert all(item["severity"] in ("ok", "note", "warning", "problem") for item in document["findings"])
    assert not paths.audit_file().exists()  # nothing was unlocked, so nothing was recorded
    words = ok(cli("doctor"))
    assert "BACKEND" in words.stdout and "KEYSLOT" in words.stdout


@posix_only
def test_doctor_finds_loose_permissions(cli: CLI) -> None:
    build()
    os.chmod(paths.home(), 0o755)  # noqa: S103 - the loose mode is what is being checked
    os.chmod(paths.vault_file(), 0o644)
    document = json.loads(ok(cli("doctor", "--json")).stdout)
    loose = {item["path"]: item["severity"] for item in document["permissions"]["loose"]}
    assert loose == {str(paths.home()): "warning", str(paths.vault_file()): "warning"}
    (key,) = paths.device_dir().glob("*.key")
    os.chmod(key, 0o644)
    result = ok(cli("doctor", "--json"), 1)  # a readable device key is a problem
    problems = [item for item in json.loads(result.stdout)["findings"] if item["severity"] == "problem"]
    assert [item["remedy"] for item in problems] == [f"chmod 600 {key}"]
    assert stat.S_IMODE(key.stat().st_mode) == 0o644  # reported, never changed


@posix_only
@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root can write anywhere")
def test_an_unwritable_home_is_one_line_with_the_path_and_the_reason_never_a_traceback(
    cli: CLI, isolated: Path
) -> None:
    locked = isolated / "locked"
    locked.mkdir()
    home = locked / "irondome"
    os.chmod(locked, 0o500)  # readable, not writable: IRONDOME_HOME cannot be created in it
    try:
        result = ok(cli("init", "--password-stdin", stdin=lines(PASSWORD), env={"IRONDOME_HOME": str(home)}), 1)
    finally:
        os.chmod(locked, 0o700)
    assert "Traceback" not in result.stderr and result.stdout == ""
    (error,) = [line for line in result.stderr.splitlines() if line.startswith("error")]
    assert f"{home}: Permission denied" in error and "writable" in error
    assert not home.exists() and device_keys() == []  # the device key enrolled for it was destroyed again


def _shell(name: str) -> Optional[str]:
    return shutil.which(name)


@pytest.mark.parametrize("shell, check", [("bash", ["-n"]), ("zsh", ["-n"]), ("fish", ["--no-execute"])])
def test_completion_scripts_parse(cli: CLI, isolated: Path, shell: str, check: List[str]) -> None:
    result = ok(cli("completion", shell))
    assert "irondome" in result.stdout and "completion" in result.stdout
    script = isolated / f"irondome.{shell}"
    script.write_text(result.stdout, encoding="utf-8")
    interpreters = [path for path in {_shell(shell), f"/bin/{shell}"} if path and os.path.exists(path)]
    if not interpreters:
        pytest.skip(f"{shell} is not installed here")
    for interpreter in interpreters:
        parsed = subprocess.run([interpreter, *check, str(script)], capture_output=True, text=True, timeout=60)
        assert parsed.returncode == 0, f"{interpreter}: {parsed.stderr}"


BASH_PROBE = r"""
source "$1"
probe() {
    COMP_WORDS=("$@"); COMP_CWORD=$((${#COMP_WORDS[@]} - 1)); COMPREPLY=()
    _irondome
    printf '%s|' "${COMPREPLY[@]}"
    printf '\n'
}
probe irondome ba
probe irondome backup ""
probe irondome --bunker bravo exp
probe irondome export --plaintext ""
probe irondome import --on-conflict r
probe irondome completion ""
probe irondome nuke --yes
cd "$2"
probe irondome export "my "
"""


BASHES = sorted({path for path in (_shell("bash"), "/bin/bash") if path and os.path.exists(path)})


@pytest.mark.parametrize("bash", BASHES)
def test_bash_completion_completes(cli: CLI, isolated: Path, bash: str) -> None:
    script = isolated / "irondome.bash"
    script.write_text(ok(cli("completion", "bash")).stdout, encoding="utf-8")
    folder = isolated / "files"
    folder.mkdir()
    (folder / "my backup.irondome").write_bytes(b"")
    probe = isolated / "probe.sh"
    probe.write_text(BASH_PROBE, encoding="utf-8")
    result = subprocess.run([bash, str(probe), str(script), str(folder)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "backup|",
        "ls|restore|",
        "export|",  # the value of --bunker is skipped
        "json|csv|",
        "rename|replace|",
        "bash|zsh|fish|",
        "--yes-destroy-everything|",
        "my backup.irondome|",  # a file name with a space stays one word
    ]


def test_completion_json_and_unknown_shell(cli: CLI) -> None:
    document = json.loads(ok(cli("completion", "zsh", "--json")).stdout)
    assert document["shell"] == "zsh" and document["script"].startswith("#compdef irondome")
    assert ok(cli("completion", "powershell"), 2)


def test_version(cli: CLI) -> None:
    import cryptography

    import irondome

    assert ok(cli("version")).stdout == f"irondome {irondome.__version__}\n"
    assert ok(cli("--version")).stdout.strip() == f"irondome {irondome.__version__}"
    document = json.loads(ok(cli("version", "--json")).stdout)
    assert set(document) == {"version", "python", "cryptography", "openssl"}
    assert document["version"] == irondome.__version__ and document["cryptography"] == cryptography.__version__


def test_every_admin_command_has_help(cli: CLI) -> None:
    for command in (["backup"], ["backup", "ls"], ["backup", "restore"], ["export"], ["import"], ["migrate"],
                    ["rekey"], ["nuke"], ["doctor"], ["completion"], ["version"]):
        result = ok(cli(*command, "--help"))
        assert result.stdout.startswith("usage: irondome " + " ".join(command))
        assert "!" not in result.stdout


# ---------------------------------------------------------------------------
# At a terminal: the questions a person answers
# ---------------------------------------------------------------------------


class Terminal:
    """``python -m irondome ARGS`` with a pseudo-terminal as its controlling terminal, and a person typing."""

    def __init__(self, args: Tuple[str, ...], env: Dict[str, str]) -> None:
        import pty

        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # the child: become irondome, or report that it could not
            try:
                os.execve(sys.executable, [sys.executable, "-m", "irondome", *args], env)  # noqa: S606 - no shell
            finally:
                os._exit(127)
        self.output = ""
        self.seen = 0
        self.status: Optional[int] = None

    def _read(self, deadline: float) -> bool:
        import select
        import time

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        ready, _, _ = select.select([self.fd], [], [], remaining)
        if not ready:
            return False
        try:
            chunk = os.read(self.fd, 4096)
        except OSError:  # Linux: the other side is gone
            chunk = b""
        if not chunk:
            return False
        self.output += chunk.decode("utf-8", "replace")
        return True

    def expect(self, text: str, timeout: float = 30.0) -> None:
        import time

        deadline = time.monotonic() + timeout
        while text not in self.output[self.seen:]:
            if not self._read(deadline):
                raise AssertionError(f"{text!r} never appeared. The terminal showed:\n{self.output}")
        self.seen = self.output.index(text, self.seen) + len(text)

    def send(self, line: str) -> None:
        os.write(self.fd, line.encode("utf-8") + b"\r")

    def secret(self, prompt: str, value: str, timeout: float = 30.0) -> None:
        """Answer a hidden prompt once echo is off (input that arrives earlier is flushed by the prompt)."""
        import termios
        import time

        self.expect(prompt, timeout)
        deadline = time.monotonic() + timeout
        while termios.tcgetattr(self.fd)[3] & termios.ECHO:
            assert time.monotonic() < deadline, f"echo never went off after {prompt!r}"
            time.sleep(0.01)
        self.send(value)

    def finish(self, timeout: float = 60.0) -> int:
        import time

        deadline = time.monotonic() + timeout
        while self._read(deadline):
            pass
        while self.status is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
                break
            if time.monotonic() > deadline:
                raise AssertionError(f"irondome did not exit. The terminal showed:\n{self.output}")
            time.sleep(0.02)
        return self.status

    def close(self) -> None:
        import signal

        if self.status is None:
            with contextlib.suppress(OSError):
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
        os.close(self.fd)


@pytest.fixture
def terminal(isolated: Path) -> Iterator[Callable[..., Terminal]]:
    if not hasattr(os, "fork") or sys.platform == "win32":
        pytest.skip("needs a POSIX pseudo-terminal")
    started: List[Terminal] = []

    def start(*args: str) -> Terminal:
        env = {name: value for name, value in os.environ.items() if name != "IRONDOME_NO_PROMPT"}
        if SUPPORT.is_dir():
            env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SUPPORT), env.get("PYTHONPATH", "")]))
            env["IRONDOME_TEST_BLOCK_SOCKETS"] = "1"
        session = Terminal(args, env)
        started.append(session)
        return session

    yield start
    for session in started:
        session.close()


def _line_prompts_are_broken() -> bool:
    """True while Context._read_line opens /dev/tty with open(..., "r+"): a tty cannot be seeked, so that raises."""
    import inspect

    from irondome.cli.context import Context

    return 'open("/dev/tty", "r+"' in inspect.getsource(Context._read_line)


#: Tests that answer a yes/no question or type a word at the terminal. They fail for as long as
#: irondome.cli.context cannot read such an answer (a frame bug, reported), and must pass once it can.
needs_line_prompts = pytest.mark.xfail(
    _line_prompts_are_broken(),
    reason="irondome.cli.context.Context._read_line opens /dev/tty in 'r+' text mode, which raises "
    "io.UnsupportedOperation on every terminal",
    raises=AssertionError,
    strict=True,
)


def test_portable_export_at_a_terminal_asks_for_the_password_twice(terminal: Callable[..., Terminal],
                                                                     isolated: Path) -> None:
    build()
    target = isolated / "backup.irondome"
    session = terminal("export", str(target))
    session.secret("Master password: ", PASSWORD)
    session.secret("Password for the backup: ", EXPORT_PASSWORD)
    session.secret("Repeat it: ", "not the same at all")
    assert session.finish() == 2 and "do not match" in session.output and not target.exists()
    session = terminal("export", str(target))
    session.secret("Master password: ", PASSWORD)
    session.secret("Password for the backup: ", EXPORT_PASSWORD)
    session.secret("Repeat it: ", EXPORT_PASSWORD)
    assert session.finish() == 0, session.output
    assert interop.detect_format(target) == "irondome"
    assert PASSWORD not in session.output and EXPORT_PASSWORD not in session.output  # echo was off


@needs_line_prompts
def test_nuke_at_a_terminal_needs_the_word_typed(terminal: Callable[..., Terminal]) -> None:
    build()
    session = terminal("nuke")
    session.expect("Type DESTROY to continue: ")
    session.send("destroy")  # close is not enough
    assert session.finish() == 1 and "Nothing was destroyed" in session.output
    assert paths.vault_file().exists() and device_keys()
    session = terminal("nuke")
    session.expect("Type DESTROY to continue: ")
    session.send("DESTROY")
    assert session.finish() == 0, session.output
    assert not paths.root().exists() and not paths.device_root().exists()


def test_nuke_yes_at_a_terminal_without_the_password_is_refused_and_says_why(terminal: Callable[..., Terminal]) -> None:
    """An agent running in the owner's terminal can pass the flag; it cannot pass the password."""
    build()
    before = (tree(paths.root()), tree(paths.device_root()))
    session = terminal("nuke", "--yes-destroy-everything")
    assert session.finish() == 2, session.output
    words = " ".join(session.output.split())
    assert "--yes-destroy-everything skips typing DESTROY only together with --password-stdin" in words
    assert "an agent can pass --yes-destroy-everything, it cannot pass your password" in words
    assert "Type DESTROY to continue" not in session.output and "Nothing was destroyed" in words
    assert (tree(paths.root()), tree(paths.device_root())) == before


@needs_line_prompts
def test_rekey_at_a_terminal(terminal: Callable[..., Terminal]) -> None:
    build()
    old_id = VaultFile.load().vault_id
    session = terminal("rekey")
    session.secret("Master password: ", PASSWORD)
    session.expect("Type REKEY to continue: ")
    session.send("REKEY")
    assert session.finish() == 0, session.output
    assert "Re-keyed bunker alpha" in session.output and RECOVERY_KEY.search(session.output)
    with opened() as vault:
        assert vault.vault_id != old_id and len(vault.entries) == 2


@needs_line_prompts
def test_plaintext_export_at_a_terminal_needs_the_word_typed(terminal: Callable[..., Terminal],
                                                              isolated: Path) -> None:
    build()
    target = isolated / "plain.json"
    session = terminal("export", str(target), "--plaintext", "json")
    session.secret("Master password: ", PASSWORD)
    session.expect("Type EXPORT to continue: ")
    session.send("no")
    assert session.finish() == 1 and "Nothing was written" in session.output and not target.exists()


@needs_line_prompts
def test_backup_restore_at_a_terminal_asks_first(terminal: Callable[..., Terminal]) -> None:
    build()
    before = paths.vault_file().read_bytes()
    session = terminal("backup", "restore", "1")
    session.secret("Master password: ", PASSWORD)
    session.expect("[y/N] ")
    session.send("")  # the default is no
    assert session.finish() == 1 and "Nothing was changed" in session.output
    assert paths.vault_file().read_bytes() == before


@needs_line_prompts
def test_migrate_at_a_terminal_offers_to_keep_the_password(terminal: Callable[..., Terminal]) -> None:
    fixture = unpack_legacy("password_only")
    session = terminal("migrate", "--legacy-username", fixture["master_username"])
    session.secret("IronDome 3.x master password: ", fixture["master_password"])
    session.expect("[Y/n] ")
    session.send("")  # yes: the same password
    assert session.finish() == 0, session.output
    with opened(fixture["master_password"]) as vault:
        assert vault_values(vault) == legacy_values(fixture)
