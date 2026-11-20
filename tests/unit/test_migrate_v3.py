"""migrate_v3: reading 1.x-3.x vaults, copying them into a version 4 vault, destroying them.

Every vault read here was written by the code that wrote such vaults for real
(``tests/fixtures/v3``: 3.2.2 in each of its three modes, 1.1.0, and both
forms of the first commit), or, where a test needs a vault no release would
have produced, forged with ``cryptography``'s own Fernet and PBKDF2. The old
package is never imported.

Two things hold for every test in this file and are enforced by fixtures, not
by convention:

* nothing can reach a real keychain: the module's one way to it, its
  subprocess runner, is replaced, and ``subprocess.run`` itself refuses the
  keychain commands;
* a legacy directory is never modified by anything but ``destroy_legacy``:
  every directory a test unpacks or forges is compared with its own snapshot
  when the test ends.

PBKDF2 at 600,000 iterations is what makes this file slow, so it is spent
only where the real thing is the point: on the fixtures. Tests about the
module's own logic run on forged vaults with the iteration counts scaled down
(the ``fast_kdf`` fixture), and tests that need a vault's description but not
its mode build it with ``found`` instead of ``detect``.
"""

from __future__ import annotations

import ast
import base64
import binascii
import calendar
import dataclasses
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pytest
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from conftest import PASSWORD, secret
from irondome import migrate_v3, paths
from irondome.errors import AuthError, UsageError, VaultError
from irondome.migrate_v3 import LegacyEntry, LegacyVault
from irondome.secmem import SecureBuffer
from irondome.unlock import open_vault
from irondome.vault import Secret, VaultFile, fold_name, validate_name

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "v3"

#: Fixtures opened with a master username and password.
PASSWORD_FIXTURES = (
    "password_only",
    "biometric_password",
    "device_id",
    "unicode",
    "collisions",
    "two_hundred",
    "v1_1_0",
    "v1_0_0",
    "script_2025",
)
WITH_ENTRIES = PASSWORD_FIXTURES + ("biometric_only",)
ALL = WITH_ENTRIES + ("empty",)

#: The three generations of the vault key, by their place in the module's tables.
ERAS = {"2.0.0-3.2.2": 0, "1.0.1-1.1.0": 1, "before 1.0.1": 2}

MACHINE = "fixture-user@fixture-host"
SHORT_PASSWORD = "pw"
FORGED_USERNAME = "forge-admin"
FORGED_PASSWORD = "forge-password-1"
PLACEHOLDER = b"biometric_only_placeholder"
WRONG = "wrong IronDome 3.x master username or password"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
NEW_YEAR_2026 = 1767225600  # 2026-01-01T00:00:00Z, where the 3.2.2 fixtures' clock starts

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX modes, links and special files")
not_root = pytest.mark.skipif(getattr(os, "geteuid", lambda: 1)() == 0, reason="root ignores file modes")
needs_tzset = pytest.mark.skipif(not hasattr(time, "tzset"), reason="the time zone cannot be set here")

# The module's own functions, kept before the fixtures below replace them.
REAL_RUN_TOOL = migrate_v3._run_tool
REAL_LOGIN_NAMES = migrate_v3._login_names
REAL_NODE_NAMES = migrate_v3._node_names
REAL_KEYCHAIN_TOOL = migrate_v3._keychain_tool
REAL_SUBPROCESS_RUN = subprocess.run


# conftest.py points Hypothesis's storage away from the working directory; no example database is kept at all.
PROPERTY = settings(database=None, deadline=None, max_examples=100)
WITH_FIXTURES = [HealthCheck.function_scoped_fixture]  # state is reset by hand at the start of each example


def _load_archive_module() -> Any:
    spec = importlib.util.spec_from_file_location("irondome_v3_fixture_archive", FIXTURE_DIR / "archive.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


archive = _load_archive_module()
_LOADED: Dict[str, Dict[str, Any]] = {}


def fixture_named(name: str) -> Dict[str, Any]:
    if name not in _LOADED:
        _LOADED[name] = archive.load(FIXTURE_DIR / f"{name}.json")
    return _LOADED[name]


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def no_real_keychain(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the real keychain unreachable, whatever a test or the module does."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("a test reached for the real OS keychain")

    def guarded_run(command: Any, *args: Any, **kwargs: Any) -> Any:
        if os.path.basename(str(command[0])) in ("security", "secret-tool"):
            refuse()
        return REAL_SUBPROCESS_RUN(command, *args, **kwargs)

    monkeypatch.setattr(migrate_v3, "_run_tool", refuse)
    monkeypatch.setattr(subprocess, "run", guarded_run)


@pytest.fixture(autouse=True)
def fixture_machine(monkeypatch: pytest.MonkeyPatch) -> None:
    """Be the machine the fixtures were written on, and offer no other identity."""
    monkeypatch.setattr(migrate_v3, "_MACHINE_ID_FILES", ())
    monkeypatch.setattr(migrate_v3, "_login_names", lambda: ["fixture-user"])
    monkeypatch.setattr(migrate_v3, "_node_names", lambda: ["fixture-host"])


@pytest.fixture(autouse=True)
def utc() -> Iterator[None]:
    """3.x wrote naive local times. In UTC what they convert to is a constant."""
    if not hasattr(time, "tzset"):
        yield
        return
    saved = os.environ.get("TZ")
    os.environ["TZ"] = "UTC"
    time.tzset()
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = saved
        time.tzset()


@pytest.fixture
def fast_kdf(monkeypatch: pytest.MonkeyPatch) -> None:
    """Scale every iteration count down, for forged vaults only.

    The three generations keep distinct parameters, so the logic that tells
    them apart is still exercised; what is skipped is OpenSSL's arithmetic,
    which the fixtures cover at the real counts. Never combine with a fixture.
    """
    monkeypatch.setattr(migrate_v3, "_VAULT_KEY_GENERATIONS", ((60, True), (60, False), (10, False)))
    monkeypatch.setattr(migrate_v3, "_SYSTEM_KEY_ITERATIONS", (60, 10))
    monkeypatch.setattr(migrate_v3, "_VERIFIER_ITERATIONS", 60)


def snapshot(root: Path) -> Dict[str, Tuple[int, int, str]]:
    """Everything under *root*: file type, mode, and content digest or link target."""
    state: Dict[str, Tuple[int, int, str]] = {}
    for current, directories, files in os.walk(root):
        for name in directories + files:
            path = Path(current) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                detail = os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                detail = hashlib.sha256(path.read_bytes()).hexdigest()
            else:
                detail = ""
            state[path.relative_to(root).as_posix()] = (stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), detail)
    return state


class LegacyDirectories:
    """Unpacks fixtures, and checks at the end of the test that nothing changed what it unpacked."""

    def __init__(self) -> None:
        self._watched: Dict[Path, Dict[str, Tuple[int, int, str]]] = {}

    def unpack(self, name: str, destination: Optional[Path] = None) -> Tuple[Path, Dict[str, Any]]:
        """Write the fixture to *destination* (default: where ``detect()`` looks) and start watching it."""
        fixture = fixture_named(name)
        target = archive.unpack(fixture, destination if destination is not None else paths.legacy_v3_dir())
        self.watch(target)
        return target, fixture

    def watch(self, root: Path) -> None:
        """Record *root* as it is now. Call again after arranging a directory on purpose."""
        self._watched[root] = snapshot(root)

    def release(self, root: Path) -> None:
        """Stop watching: the test is about to destroy this directory."""
        del self._watched[root]

    def check(self) -> None:
        for root, before in self._watched.items():
            assert snapshot(root) == before, f"{root} was modified by a test that only read it"


@pytest.fixture
def old(isolated: Path) -> Iterator[LegacyDirectories]:
    keeper = LegacyDirectories()
    yield keeper
    keeper.check()


@pytest.fixture
def empty_vault(make_vault: Callable[..., Any]) -> Any:
    opened, _ = make_vault()
    return opened


def found(path: Path) -> LegacyVault:
    """The vault in *path* as ``detect`` describes it, minus the mode: no key is derived to build it."""
    located = migrate_v3._locate(path)
    assert located is not None
    layout, salt, has_entries = located
    return LegacyVault(path=path, layout=layout, salt=salt, has_entries=has_entries, mode=None)


def epoch(text: Optional[str]) -> Optional[int]:
    """What a 3.x timestamp must convert to, computed without ``time.mktime``."""
    if text is None:
        return None
    parsed = time.strptime(text, TIME_FORMAT)
    return calendar.timegm(parsed) if hasattr(time, "tzset") else int(time.mktime(parsed))


def expected_entries(fixture: Dict[str, Any]) -> List[LegacyEntry]:
    """The fixture's entries as ``read_entries`` must return them, built from the recorded plaintext."""
    entries = []
    for item in fixture["entries"]:
        created = epoch(item.get("created_at"))
        entries.append(
            LegacyEntry(
                username=item["username"],
                website=item["website"],
                password=item["password"],
                notes=item["notes"],
                created=created,
                modified=epoch(item.get("updated_at")) or created,
            )
        )
    return entries


def credentials(fixture: Dict[str, Any]) -> Dict[str, Any]:
    """Keyword arguments that open the fixture."""
    if fixture["mode"] == "biometric_only":
        return {"master_key": fixture["keyring"]["master_key"].encode("ascii")}
    return {"username": fixture["master_username"], "password": fixture["master_password"].encode("utf-8")}


def salt_of(path: Path, fixture: Dict[str, Any]) -> bytes:
    base = path / "secrets" if fixture["layout"] == "secrets" else path
    return (base / "salt.bin").read_bytes()


def pbkdf2(material: bytes, salt: bytes, iterations: int) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations).derive(material)


def record(username: Any = "user", website: Any = "example.com", password: Any = SHORT_PASSWORD, notes: Any = "",
           **more: Any) -> Dict[str, Any]:
    """One entry as 3.x stored it, or as a damaged vault might hold it."""
    item: Dict[str, Any] = {"username": username, "website": website, "password": password, "notes": notes}
    item.update(more)
    return item


def forge(
    root: Path,
    *,
    entries: Optional[List[Dict[str, Any]]] = None,
    payload: Optional[bytes] = None,
    username: str = FORGED_USERNAME,
    password: str = FORGED_PASSWORD,
    machine_id: str = MACHINE,
    layout: str = "secrets",
    era: str = "2.0.0-3.2.2",
    verifier: Optional[bytes] = None,
    vault_key: Optional[bytes] = None,
    master: bool = True,
    salt: Optional[bytes] = None,
) -> None:
    """Write a vault in the old format with ``cryptography`` alone.

    The iteration counts are the module's own for the chosen era, so a vault
    forged under ``fast_kdf`` is read under ``fast_kdf``. A key is derived
    only for what is actually written: with ``master=False`` and a
    ``vault_key`` nothing is derived at all.
    """
    generation = ERAS[era]
    base = root / "secrets" if layout == "secrets" else root
    base.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(16) if salt is None else salt
    secret_bytes = password.encode("utf-8")
    (base / "salt.bin").write_bytes(salt)
    if master:
        iterations = migrate_v3._SYSTEM_KEY_ITERATIONS[0 if generation < 2 else 1]
        system = Fernet(base64.urlsafe_b64encode(pbkdf2(machine_id.encode("utf-8"), salt, iterations)))
        if verifier is None and generation == 2:
            verifier = hashlib.sha256(salt + secret_bytes).digest()  # what the first program stored
        elif verifier is None:
            verifier = pbkdf2(secret_bytes, salt, migrate_v3._VERIFIER_ITERATIONS)
        (base / ".master_user.enc").write_bytes(system.encrypt(username.encode("utf-8")))
        (base / ".master_hash.enc").write_bytes(system.encrypt(binascii.hexlify(verifier)))
    if payload is None and entries is not None:
        payload = json.dumps(entries).encode("utf-8")
    if payload is None:
        return
    if vault_key is None:
        iterations, prefixed = migrate_v3._VAULT_KEY_GENERATIONS[generation]
        name = username.encode("utf-8")
        head = len(name).to_bytes(8, "big") + name if prefixed else name + b":"
        vault_key = base64.urlsafe_b64encode(pbkdf2(head + secret_bytes, salt, iterations))
    (base / ".passwords.enc").write_bytes(Fernet(vault_key).encrypt(payload))


def forged_contents(root: Path, payload: bytes) -> Tuple[LegacyVault, bytes]:
    """A vault holding *payload* under a random key, with no master records: nothing to derive."""
    key = Fernet.generate_key()
    forge(root, payload=payload, vault_key=key, master=False)
    return found(root), key


def flip_byte(path: Path, index: int) -> None:
    """Change one byte of the decoded Fernet token in *path*, leaving its shape intact."""
    raw = bytearray(base64.urlsafe_b64decode(path.read_bytes()))
    raw[index] ^= 0x01
    path.write_bytes(base64.urlsafe_b64encode(bytes(raw)))


def finishes(action: Callable[[], Any], seconds: float = 120.0) -> Any:
    """Run *action* on a thread and return its result or exception; fail if it does not come back."""
    outcome: List[Any] = []

    def run() -> None:
        try:
            outcome.append(action())
        except Exception as exc:  # handed to the caller to assert on
            outcome.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), "the call blocked"
    return outcome[0]


def legacy_entry(website: str = "example.com", username: str = "user", password: str = SHORT_PASSWORD,
                 notes: str = "", created: Optional[int] = None, modified: Optional[int] = None) -> LegacyEntry:
    return LegacyEntry(username, website, password, notes, created, modified)


def names_in(vault: Any) -> List[str]:
    return sorted(entry.name for entry in vault.entries.values())


def from_json(text: str) -> bool:
    """True for text that can come out of a JSON document, which is where every legacy entry comes from.

    A high and a low surrogate side by side cannot: JSON reads the pair as
    one character. Lone surrogates can, and are kept.
    """
    return json.loads(json.dumps(text)) == text


# ---------------------------------------------------------------------------
# The fixtures themselves
# ---------------------------------------------------------------------------


def test_the_fixture_directory_holds_exactly_the_fixtures_these_tests_use() -> None:
    assert sorted(path.stem for path in FIXTURE_DIR.glob("*.json")) == sorted(ALL)


@pytest.mark.parametrize("name", ALL)
def test_a_fixture_unpacks_to_the_files_and_modes_it_records(name: str, old: LegacyDirectories) -> None:
    path, fixture = old.unpack(name)
    listed = sorted(item.relative_to(path).as_posix() for item in path.rglob("*") if item.is_file())
    assert listed == sorted(item["path"] for item in fixture["files"])
    if os.name != "nt":
        for item in fixture["files"]:
            assert stat.S_IMODE((path / item["path"]).stat().st_mode) == int(item["mode"], 8)


def test_a_fixture_whose_bytes_changed_is_refused_when_unpacked(tmp_path: Path) -> None:
    damaged = json.loads(json.dumps(fixture_named("password_only")))
    damaged["files"][0]["base64"] = [base64.b64encode(b"something else").decode("ascii")]
    with pytest.raises(ValueError, match="does not match its recorded digest"):
        archive.unpack(damaged, tmp_path / "damaged")


# ---------------------------------------------------------------------------
# detect
# ---------------------------------------------------------------------------


def test_detect_finds_nothing_where_there_is_no_vault(isolated: Path) -> None:
    assert migrate_v3.detect() is None  # the default directory does not exist
    bare = isolated / "bare"
    bare.mkdir()
    assert migrate_v3.detect(bare) is None
    (bare / "notes.txt").write_text("not a vault")
    (bare / "secrets").mkdir()
    (bare / "secrets" / ".login_attempts.dat").write_text("{}")  # 3.x started once, never set up
    (bare / "settings.json").write_text("{}")
    assert migrate_v3.detect(bare) is None
    a_file = isolated / "a-file"
    a_file.write_text("x")
    assert migrate_v3.detect(a_file) is None


@pytest.mark.parametrize("name", ALL)
def test_detect_describes_every_fixture_and_its_username_is_recovered(name: str, old: LegacyDirectories) -> None:
    path, fixture = old.unpack(name)
    legacy = migrate_v3.detect()
    assert legacy == LegacyVault(
        path=path,
        layout=fixture["layout"],
        salt=salt_of(path, fixture),
        has_entries=bool(fixture["entries"]),
        mode="biometric_only" if fixture["mode"] == "biometric_only" else None,
    )
    assert legacy == dataclasses.replace(found(path), mode=legacy.mode)
    assert migrate_v3.stored_username(legacy) == fixture["stored_username"]


def test_detect_takes_a_relative_path_as_text_and_reports_an_absolute_one(
    old: LegacyDirectories, isolated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = old.unpack("password_only", isolated / "somewhere")
    monkeypatch.chdir(isolated)
    legacy = migrate_v3.detect("somewhere")
    assert legacy is not None and legacy.path == path and legacy.path.is_absolute()


def test_on_another_machine_the_mode_and_the_username_are_unknown_not_wrong(
    isolated: Path, old: LegacyDirectories, fast_kdf: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, salt, key = isolated / "forged", os.urandom(16), Fernet.generate_key()
    forge(root, entries=[record()], username="bio_touch_id", vault_key=key, salt=salt,
          verifier=pbkdf2(PLACEHOLDER, salt, migrate_v3._VERIFIER_ITERATIONS))
    old.watch(root)
    here = migrate_v3.detect(root)
    assert here is not None and here.mode == "biometric_only"
    assert migrate_v3.stored_username(here) == "bio_touch_id"
    monkeypatch.setattr(migrate_v3, "_login_names", lambda: ["someone-else"])
    monkeypatch.setattr(migrate_v3, "_node_names", lambda: ["renamed-computer"])
    elsewhere = migrate_v3.detect(root)
    assert elsewhere is not None and elsewhere.mode is None and elsewhere.has_entries
    assert migrate_v3.stored_username(elsewhere) is None
    assert len(migrate_v3.read_entries(elsewhere, master_key=key)) == 1  # the key is all a biometric vault needs


@pytest.mark.parametrize(
    ("salt", "complaint"),
    [(None, "has no salt.bin"), (b"", "0 bytes long"), (b"x" * 15, "15 bytes long"), (b"x" * 17, "17 bytes long")],
    ids=["missing", "empty", "one byte short", "one byte long"],
)
def test_a_vault_with_a_missing_or_damaged_salt_is_reported_as_damaged_not_as_absent(
    salt: Optional[bytes], complaint: str, old: LegacyDirectories
) -> None:
    path, _ = old.unpack("password_only")
    target = path / "secrets" / "salt.bin"
    if salt is None:
        target.unlink()
    else:
        target.write_bytes(salt)
    old.watch(path)
    with pytest.raises(VaultError, match=complaint):
        migrate_v3.detect()


@posix_only
def test_a_salt_that_is_not_a_regular_file_is_refused_without_waiting(old: LegacyDirectories) -> None:
    path, _ = old.unpack("password_only")
    target = path / "secrets" / "salt.bin"
    target.unlink()
    target.mkdir()
    assert "not a regular file" in str(finishes(migrate_v3.detect))
    target.rmdir()
    os.mkfifo(target)  # opening a pipe for reading waits for a writer unless it is opened non-blocking
    old.watch(path)
    outcome = finishes(migrate_v3.detect)
    assert isinstance(outcome, VaultError) and "not a regular file" in str(outcome)


@posix_only
def test_a_link_to_a_missing_file_is_damage_not_absence(old: LegacyDirectories, isolated: Path) -> None:
    path, fixture = old.unpack("password_only")
    store = path / "secrets" / ".passwords.enc"
    store.unlink()
    store.symlink_to(isolated / "unplugged-drive" / "passwords.enc")
    old.watch(path)
    legacy = found(path)
    assert legacy.has_entries
    with pytest.raises(VaultError, match="symbolic link to something that is not there"):
        migrate_v3.read_entries(legacy, **credentials(fixture))


def test_the_secrets_directory_wins_over_the_copies_the_first_program_left_behind(old: LegacyDirectories) -> None:
    """Later code copied the four files into ``secrets/`` and never looked at the originals again."""
    path, fixture = old.unpack("script_2025")
    (path / "secrets").mkdir()
    for name in ("salt.bin", ".master_user.enc", ".master_hash.enc", ".passwords.enc", ".login_attempts.dat"):
        shutil.copy2(path / name, path / "secrets" / name)
    (path / ".passwords.enc").write_bytes(b"stale and unreadable")
    old.watch(path)
    legacy = found(path)
    assert legacy.layout == "secrets"
    assert migrate_v3.read_entries(legacy, **credentials(fixture)) == expected_entries(fixture)


def test_the_layout_and_the_key_derivation_are_independent(old: LegacyDirectories) -> None:
    """No release wrote 2.0+ keys into the old layout, but nothing in the reader ties the two together."""
    path, fixture = old.unpack("password_only")
    for item in sorted((path / "secrets").iterdir()):
        item.rename(path / item.name)
    (path / "secrets").rmdir()
    old.watch(path)
    legacy = found(path)
    assert legacy.layout == "flat"
    assert migrate_v3.stored_username(legacy) == fixture["stored_username"]
    assert migrate_v3.read_entries(legacy, **credentials(fixture)) == expected_entries(fixture)


def test_a_vault_that_got_no_further_than_its_salt_is_an_empty_vault(isolated: Path, old: LegacyDirectories) -> None:
    root = isolated / "interrupted"
    forge(root, master=False)
    old.watch(root)
    legacy = migrate_v3.detect(root)
    assert legacy is not None and (legacy.has_entries, legacy.mode) == (False, None)
    assert migrate_v3.stored_username(legacy) is None
    with pytest.raises(UsageError, match="username could not be recovered"):
        migrate_v3.read_entries(legacy, password=b"whatever-it-was")
    assert migrate_v3.read_entries(legacy, username="anyone", password=b"whatever-it-was") == []


def test_a_password_vault_is_not_taken_for_a_biometric_one_because_of_its_password(
    isolated: Path, old: LegacyDirectories, fast_kdf: None
) -> None:
    """The verifier of a biometric-only vault is that of a fixed string, which a person could also choose."""
    root = isolated / "odd-password"
    forge(root, entries=[record()], username="careful-user", password=PLACEHOLDER.decode())
    old.watch(root)
    legacy = migrate_v3.detect(root)
    assert legacy is not None and legacy.mode is None
    assert len(migrate_v3.read_entries(legacy, password=PLACEHOLDER)) == 1


def test_a_biometric_vault_is_recognised_even_when_its_username_record_is_damaged(old: LegacyDirectories) -> None:
    path, _ = old.unpack("biometric_only")
    (path / "secrets" / ".master_user.enc").write_bytes(b"scribbled over")
    old.watch(path)
    legacy = migrate_v3.detect()
    assert legacy is not None and legacy.mode == "biometric_only"
    assert migrate_v3.stored_username(legacy) is None


# ---------------------------------------------------------------------------
# The machine identifiers behind the stored username
# ---------------------------------------------------------------------------


def test_a_windows_style_vault_carries_its_machine_identifier_with_it(old: LegacyDirectories) -> None:
    path, fixture = old.unpack("device_id")
    assert (path / ".device_id").read_text() == fixture["machine_id"]
    assert migrate_v3._machine_ids(path)[:2] == [MACHINE.encode(), fixture["machine_id"].encode()]
    assert migrate_v3.stored_username(found(path)) == "fixture-admin"
    (path / ".device_id").unlink()
    old.watch(path)
    assert fixture["machine_id"].encode() not in migrate_v3._machine_ids(path)


def test_the_linux_machine_id_file_is_tried_and_its_newline_ignored(
    isolated: Path, old: LegacyDirectories, fast_kdf: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_id = "0123456789abcdef0123456789abcdef"
    root = isolated / "linux-vault"
    forge(root, entries=[record()], machine_id=machine_id, username="linux-user")
    old.watch(root)
    assert migrate_v3.stored_username(found(root)) is None
    id_file = isolated / "machine-id"
    id_file.write_text(machine_id + "\n")
    monkeypatch.setattr(migrate_v3, "_MACHINE_ID_FILES", (str(isolated / "absent"), str(id_file)))
    assert migrate_v3.stored_username(found(root)) == "linux-user"


def test_the_last_resort_identifier_of_3x_is_tried(isolated: Path, old: LegacyDirectories, fast_kdf: None) -> None:
    root = isolated / "fallback-vault"
    forge(root, entries=[record()], machine_id="fallback-" + os.path.expanduser("~"), username="nameless")
    old.watch(root)
    assert migrate_v3.stored_username(found(root)) == "nameless"


def test_machine_identifiers_are_tried_likeliest_first_and_once_each(
    isolated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second = isolated / "machine-id", isolated / "dbus-machine-id"
    first.write_text("abc123\n")
    second.write_text("abc123\n")  # the dbus file is usually a link to the first
    root = isolated / "vault"
    root.mkdir()
    (root / ".device_id").write_text("  9f1c-device  \n")
    monkeypatch.setattr(migrate_v3, "_MACHINE_ID_FILES", (str(first), str(second)))
    monkeypatch.setattr(migrate_v3, "_login_names", lambda: ["ada", "root"])
    monkeypatch.setattr(migrate_v3, "_node_names", lambda: ["mac.lan", "mac"])
    assert migrate_v3._machine_ids(root) == [
        b"abc123",
        b"ada@mac.lan",
        b"ada@mac",
        b"root@mac.lan",
        b"root@mac",
        b"9f1c-device",
        ("fallback-" + os.path.expanduser("~")).encode(),
        b"secure_password_manager_default_key",
    ]


@posix_only
def test_the_node_name_is_also_tried_in_the_forms_macos_switches_between(monkeypatch: pytest.MonkeyPatch) -> None:
    class Uname:
        def __init__(self, nodename: str) -> None:
            self.nodename = nodename

    monkeypatch.setattr(os, "uname", lambda: Uname("Kings-Mac.lan"))
    assert REAL_NODE_NAMES() == ["Kings-Mac.lan", "Kings-Mac.local", "Kings-Mac"]
    monkeypatch.setattr(os, "uname", lambda: Uname("Kings-Mac.local"))
    assert REAL_NODE_NAMES() == ["Kings-Mac.local", "Kings-Mac"]
    monkeypatch.setattr(os, "uname", lambda: Uname("server"))
    assert REAL_NODE_NAMES() == ["server", "server.local"]
    monkeypatch.setattr(os, "uname", lambda: Uname(""))
    assert REAL_NODE_NAMES() == []
    monkeypatch.delattr(os, "uname")  # Windows: 3.x fell through to the device-id file
    assert REAL_NODE_NAMES() == []


def test_login_names_come_from_both_calls_the_old_versions_used(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_terminal() -> str:
        raise OSError(25, "Inappropriate ioctl for device")

    def no_account() -> str:
        raise KeyError("getpwuid(): uid not found")

    monkeypatch.setattr(migrate_v3.getpass, "getuser", lambda: "ada")
    monkeypatch.setattr(os, "getlogin", lambda: "ada", raising=False)
    assert REAL_LOGIN_NAMES() == ["ada"]
    monkeypatch.setattr(os, "getlogin", lambda: "console-user", raising=False)
    assert REAL_LOGIN_NAMES() == ["ada", "console-user"]
    monkeypatch.setattr(os, "getlogin", no_terminal, raising=False)
    assert REAL_LOGIN_NAMES() == ["ada"]
    monkeypatch.setattr(migrate_v3.getpass, "getuser", no_account)
    assert REAL_LOGIN_NAMES() == []


# ---------------------------------------------------------------------------
# read_entries: the fixtures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", WITH_ENTRIES)
def test_every_fixture_reads_back_exactly_what_was_stored(name: str, old: LegacyDirectories) -> None:
    path, fixture = old.unpack(name)
    entries = migrate_v3.read_entries(found(path), **credentials(fixture))
    assert entries == expected_entries(fixture)
    assert [entry.password for entry in entries] == [item["password"] for item in fixture["entries"]]


@pytest.mark.parametrize("name", ["password_only", "unicode", "script_2025"])
def test_the_username_need_not_be_given_when_it_can_be_recovered(name: str, old: LegacyDirectories) -> None:
    path, fixture = old.unpack(name)
    with secret(fixture["master_password"]) as password:
        assert migrate_v3.read_entries(found(path), password=password) == expected_entries(fixture)
        assert not password.wiped  # the caller's buffer is the caller's to wipe
        assert bytes(password.view()) == fixture["master_password"].encode("utf-8")


@needs_tzset
def test_times_are_converted_from_local_time(old: LegacyDirectories) -> None:
    path, fixture = old.unpack("password_only")
    legacy = found(path)
    entries = migrate_v3.read_entries(legacy, **credentials(fixture))
    assert [(entry.created, entry.modified) for entry in entries] == [
        (NEW_YEAR_2026 + 60, NEW_YEAR_2026 + 60),
        (NEW_YEAR_2026 + 120, NEW_YEAR_2026 + 120),
        (NEW_YEAR_2026 + 180, NEW_YEAR_2026 + 3900),  # created 00:03, updated 01:05
    ]
    os.environ["TZ"] = "IST-2IDT,M3.4.4/26,M10.5.0"  # Israel, written out so no zone database is needed
    time.tzset()
    in_israel = migrate_v3.read_entries(legacy, **credentials(fixture))
    assert in_israel[0].created == NEW_YEAR_2026 + 60 - 2 * 3600
    assert migrate_v3._parse_time("2026-07-01 12:00:00") == calendar.timegm((2026, 7, 1, 9, 0, 0))  # summer time


def test_the_password_alone_opens_a_vault_on_another_machine_once_the_username_is_given(
    isolated: Path, old: LegacyDirectories, fast_kdf: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = isolated / "forged"
    forge(root, entries=[record(), record(website="other.example")])
    old.watch(root)
    monkeypatch.setattr(migrate_v3, "_node_names", lambda: ["renamed-computer"])
    legacy = migrate_v3.detect(root)
    assert legacy is not None and legacy.mode is None
    with pytest.raises(UsageError, match="pass username"):
        migrate_v3.read_entries(legacy, password=FORGED_PASSWORD.encode())
    assert len(migrate_v3.read_entries(legacy, username=FORGED_USERNAME, password=FORGED_PASSWORD.encode())) == 2


def test_master_records_are_not_needed_to_read_a_vault(old: LegacyDirectories) -> None:
    path, fixture = old.unpack("password_only")
    (path / "secrets" / ".master_user.enc").unlink()
    (path / "secrets" / ".master_hash.enc").unlink()
    old.watch(path)
    legacy = migrate_v3.detect()
    assert legacy is not None and legacy.mode is None
    assert migrate_v3.stored_username(legacy) is None
    assert migrate_v3.read_entries(legacy, **credentials(fixture)) == expected_entries(fixture)


@pytest.mark.parametrize("form", ["keychain", "fernet", "bytearray", "memoryview", "secure buffer", "with a newline"])
def test_a_biometric_vault_opens_with_its_key_in_any_form(form: str, old: LegacyDirectories) -> None:
    path, fixture = old.unpack("biometric_only")
    stored = fixture["keyring"]["master_key"].encode("ascii")
    assert len(stored) == 60 and len(fixture["vault_key"]) == 44
    assert base64.urlsafe_b64decode(stored) == fixture["vault_key"].encode("ascii")  # encoded twice
    key: Any = {
        "keychain": stored,
        "fernet": fixture["vault_key"].encode("ascii"),
        "bytearray": bytearray(stored),
        "memoryview": memoryview(stored),
        "secure buffer": SecureBuffer.from_buffer(stored),
        "with a newline": b"  " + stored + b"\n",
    }[form]
    assert migrate_v3.read_entries(found(path), master_key=key) == expected_entries(fixture)
    if isinstance(key, SecureBuffer):
        assert not key.wiped
        key.wipe()
    elif isinstance(key, bytearray):
        assert bytes(key) == stored  # read, not consumed


# ---------------------------------------------------------------------------
# read_entries: credentials that do not open the vault
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["password_only", "v1_0_0"])
def test_a_wrong_password_is_an_authentication_failure(name: str, old: LegacyDirectories) -> None:
    path, fixture = old.unpack(name)
    right = fixture["master_password"]
    with pytest.raises(AuthError, match=WRONG) as caught:
        migrate_v3.read_entries(found(path), username=fixture["master_username"], password=(right + "x").encode())
    assert right not in str(caught.value)
    assert caught.value.__context__ is None and caught.value.__cause__ is None


@pytest.mark.parametrize("era", sorted(ERAS))
def test_credentials_that_do_not_open_a_vault_are_refused_in_every_generation(
    era: str, isolated: Path, old: LegacyDirectories, fast_kdf: None
) -> None:
    root = isolated / "forged"
    forge(root, entries=[record()], username="right-user", password="right-password", era=era)
    old.watch(root)
    legacy = migrate_v3.detect(root)
    assert legacy is not None and legacy.mode is None
    assert migrate_v3.stored_username(legacy) == "right-user"
    assert len(migrate_v3.read_entries(legacy, password=b"right-password")) == 1
    assert len(migrate_v3.read_entries(legacy, username="right-user", password=b"right-password")) == 1
    for attempt in (
        {"password": b"wrong-password"},
        {"username": "right-user", "password": b"right-passwor"},
        {"username": "right-user", "password": b"right-password "},
        {"username": "right-user", "password": b"Right-password"},
        {"username": "wrong-user", "password": b"right-password"},
        {"username": "right-user ", "password": b"right-password"},
        {"username": "Right-user", "password": b"right-password"},
        {"username": "right-password", "password": b"right-user"},
    ):
        with pytest.raises(AuthError, match=WRONG) as caught:
            migrate_v3.read_entries(legacy, **attempt)
        assert attempt["password"].decode() not in str(caught.value)


@pytest.mark.parametrize(
    ("key", "complaint"),
    [
        (Fernet.generate_key(), "does not open"),
        (base64.urlsafe_b64encode(Fernet.generate_key()), "does not open"),
        (b"", "not an IronDome 3.x vault key"),
        (b"   \n", "not an IronDome 3.x vault key"),
        (b"not base64 at all!", "not an IronDome 3.x vault key"),
        (base64.urlsafe_b64encode(b"k" * 31), "not an IronDome 3.x vault key"),
        (base64.urlsafe_b64encode(b"k" * 33), "not an IronDome 3.x vault key"),
        (b"k" * 32, "not an IronDome 3.x vault key"),
    ],
    ids=["another key", "another key, keychain form", "empty", "blank", "not base64", "31 bytes", "33 bytes",
         "32 characters"],
)
def test_a_wrong_or_malformed_key_is_an_authentication_failure(
    key: bytes, complaint: str, old: LegacyDirectories
) -> None:
    path, _ = old.unpack("biometric_only")
    with pytest.raises(AuthError, match=complaint) as caught:
        migrate_v3.read_entries(found(path), master_key=key)
    if key.strip():
        assert key.decode("ascii") not in str(caught.value)


def test_a_password_cannot_open_a_vault_that_has_none(old: LegacyDirectories) -> None:
    old.unpack("biometric_only")
    legacy = migrate_v3.detect()
    assert legacy is not None
    with pytest.raises(UsageError, match="has no master password.*Pass master_key"):
        migrate_v3.read_entries(legacy)
    # The placeholder that 3.x hashed into this vault's verifier is not a password either.
    with pytest.raises(AuthError, match="has no master password.*Pass master_key"):
        migrate_v3.read_entries(legacy, password=PLACEHOLDER)


def test_what_is_missing_or_contradictory_is_a_usage_error(old: LegacyDirectories) -> None:
    path, fixture = old.unpack("password_only")
    legacy = found(path)
    with pytest.raises(UsageError, match="needs its master password"):
        migrate_v3.read_entries(legacy)
    with pytest.raises(UsageError, match="needs its master password"):
        migrate_v3.read_entries(legacy, username="fixture-admin")
    with pytest.raises(UsageError, match="not both"):
        migrate_v3.read_entries(legacy, password=b"x", master_key=b"y")
    with pytest.raises(UsageError, match="must be bytes or a SecureBuffer"):
        migrate_v3.read_entries(legacy, password=fixture["master_password"])  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="must be bytes or a SecureBuffer"):
        migrate_v3.read_entries(legacy, master_key="a" * 44)  # type: ignore[arg-type]
    with pytest.raises(UsageError, match="non-empty text"):
        migrate_v3.read_entries(legacy, username="", password=b"x")
    with pytest.raises(UsageError, match="not valid text"):
        migrate_v3.read_entries(legacy, username="bad" + chr(0xD800), password=b"x")
    for call in (migrate_v3.read_entries, migrate_v3.stored_username, migrate_v3.destroy_legacy):
        with pytest.raises(UsageError, match="returned by migrate_v3.detect"):
            call(str(legacy.path))  # type: ignore[arg-type]


def test_every_key_derived_while_reading_is_wiped_whether_reading_succeeds_or_not(
    old: LegacyDirectories, monkeypatch: pytest.MonkeyPatch
) -> None:
    made: List[SecureBuffer] = []

    class Tracked(SecureBuffer):
        def __init__(self, size: int) -> None:
            super().__init__(size)
            made.append(self)

    _, fixture = old.unpack("password_only")
    monkeypatch.setattr(migrate_v3, "SecureBuffer", Tracked)
    legacy = migrate_v3.detect()
    assert legacy is not None
    assert len(made) == 1 and made[0].wiped  # the system key
    made.clear()
    assert len(migrate_v3.read_entries(legacy, **credentials(fixture))) == 3
    assert len(made) == 2 and all(buffer.wiped for buffer in made)  # the key material and the vault key
    made.clear()
    with pytest.raises(AuthError):
        migrate_v3.read_entries(legacy, password=b"not the password")
    assert len(made) >= 6 and all(buffer.wiped for buffer in made)  # three generations tried, then the verifier
    made.clear()
    with pytest.raises(AuthError):
        migrate_v3.read_entries(legacy, master_key=Fernet.generate_key())
    assert len(made) == 1 and made[0].wiped


# ---------------------------------------------------------------------------
# read_entries: damaged vaults
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "damage",
    [b"", b"this is not a vault", b"gAAAAA", b"gAAAAABpVbkA77W5544EqQsl8jcmSVGqC11lFOxL4ZpoGoVKllcw77g2oCTE"],
    ids=["empty", "not base64", "too short", "cut off"],
)
def test_a_store_that_is_not_a_token_is_damage_whatever_the_credentials(
    damage: bytes, old: LegacyDirectories
) -> None:
    path, fixture = old.unpack("password_only")
    (path / "secrets" / ".passwords.enc").write_bytes(damage)
    old.watch(path)
    legacy = found(path)
    for attempt in (credentials(fixture), {"username": "nobody", "password": b"wrong"}, {"master_key": b"k" * 44}):
        with pytest.raises(VaultError, match="not a Fernet token: the file is damaged or was replaced"):
            migrate_v3.read_entries(legacy, **attempt)


def test_a_token_of_another_version_is_damage(old: LegacyDirectories) -> None:
    path, fixture = old.unpack("password_only")
    flip_byte(path / "secrets" / ".passwords.enc", 0)  # 0x80, the Fernet version
    old.watch(path)
    with pytest.raises(VaultError, match="not a Fernet token"):
        migrate_v3.read_entries(found(path), **credentials(fixture))


def test_a_changed_byte_in_a_real_vault_is_reported_as_damage_not_as_a_wrong_password(
    old: LegacyDirectories
) -> None:
    path, fixture = old.unpack("password_only")
    flip_byte(path / "secrets" / ".passwords.enc", 40)
    old.watch(path)
    with pytest.raises(VaultError, match="are right, but .*does not decrypt with them: the file is damaged"):
        migrate_v3.read_entries(found(path), **credentials(fixture))


@pytest.mark.parametrize("index", [1, 9, 25, 40, -1], ids=["timestamp", "iv", "first block", "ciphertext", "mac"])
def test_one_changed_byte_is_told_apart_from_wrong_credentials_only_when_the_verifier_can_be_read(
    index: int, isolated: Path, old: LegacyDirectories, fast_kdf: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = isolated / "forged"
    forge(root, entries=[record(notes="long enough to fill several cipher blocks")])
    flip_byte(root / "secrets" / ".passwords.enc", index)
    old.watch(root)
    legacy = found(root)
    right = FORGED_PASSWORD.encode()
    with pytest.raises(VaultError, match="are right, but .*does not decrypt with them: the file is damaged"):
        migrate_v3.read_entries(legacy, password=right)
    with pytest.raises(AuthError, match=WRONG):
        migrate_v3.read_entries(legacy, password=b"not the password")
    with pytest.raises(AuthError, match=WRONG):
        migrate_v3.read_entries(legacy, username="someone-else", password=right)
    # Without the verifier (another machine) a damaged store and a wrong password look the same.
    monkeypatch.setattr(migrate_v3, "_node_names", lambda: ["renamed-computer"])
    with pytest.raises(AuthError, match=WRONG):
        migrate_v3.read_entries(legacy, username=FORGED_USERNAME, password=right)


def test_a_changed_byte_in_a_biometric_vault_cannot_be_told_from_a_wrong_key(old: LegacyDirectories) -> None:
    path, fixture = old.unpack("biometric_only")
    flip_byte(path / "secrets" / ".passwords.enc", 40)
    old.watch(path)
    with pytest.raises(AuthError, match="does not open"):
        migrate_v3.read_entries(found(path), **credentials(fixture))


@posix_only
def test_a_store_that_is_not_a_regular_file_is_refused_without_waiting(old: LegacyDirectories) -> None:
    path, fixture = old.unpack("password_only")
    store = path / "secrets" / ".passwords.enc"
    store.unlink()
    os.mkfifo(store)
    old.watch(path)
    legacy = found(path)
    outcome = finishes(lambda: migrate_v3.read_entries(legacy, **credentials(fixture)))
    assert isinstance(outcome, VaultError) and "not a regular file" in str(outcome)


def test_a_store_larger_than_any_vault_is_refused_before_it_is_read(
    old: LegacyDirectories, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, fixture = old.unpack("password_only")
    legacy = found(path)
    size = (path / "secrets" / ".passwords.enc").stat().st_size
    monkeypatch.setattr(migrate_v3, "_MAX_STORE_BYTES", size - 1)
    with pytest.raises(VaultError, match="too large"):
        migrate_v3.read_entries(legacy, **credentials(fixture))
    monkeypatch.setattr(migrate_v3, "_MAX_STORE_BYTES", size)
    assert len(migrate_v3.read_entries(legacy, **credentials(fixture))) == 3


def test_the_bounded_reader_stops_at_its_limit_and_tells_missing_from_unreadable(isolated: Path) -> None:
    target = isolated / "blob"
    target.write_bytes(b"x" * 1000)
    assert migrate_v3._read_regular(target, 1000) == b"x" * 1000
    with pytest.raises(VaultError, match="too large"):
        migrate_v3._read_regular(target, 999)
    assert migrate_v3._read_regular(isolated / "absent", 10) is None
    assert migrate_v3._read_regular(target / "below-a-file", 10) is None


# ---------------------------------------------------------------------------
# read_entries: a vault with no store, and what a store may contain
# ---------------------------------------------------------------------------


def test_a_real_vault_that_was_never_used_is_empty_and_still_checks_the_password(old: LegacyDirectories) -> None:
    path, fixture = old.unpack("empty")
    assert not (path / "secrets" / ".passwords.enc").exists()
    legacy = found(path)
    assert not legacy.has_entries
    assert migrate_v3.read_entries(legacy, **credentials(fixture)) == []
    with pytest.raises(AuthError, match=WRONG):
        migrate_v3.read_entries(legacy, username=fixture["master_username"], password=b"not the password")


@pytest.mark.parametrize("era", ["2.0.0-3.2.2", "before 1.0.1"])
def test_with_no_store_a_password_is_checked_against_the_verifier_when_there_is_one_to_read(
    era: str, isolated: Path, old: LegacyDirectories, fast_kdf: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = isolated / "forged"
    forge(root, era=era)
    old.watch(root)
    legacy = migrate_v3.detect(root)
    assert legacy is not None and (legacy.has_entries, legacy.mode) == (False, None)
    right = FORGED_PASSWORD.encode()
    assert migrate_v3.read_entries(legacy, password=right) == []
    assert migrate_v3.read_entries(legacy, username=FORGED_USERNAME, password=right) == []
    with pytest.raises(AuthError, match=WRONG):
        migrate_v3.read_entries(legacy, password=b"not the password")
    with pytest.raises(AuthError, match=WRONG):
        migrate_v3.read_entries(legacy, username="someone-else", password=right)
    assert migrate_v3.read_entries(legacy, master_key=Fernet.generate_key()) == []
    # On another machine the verifier cannot be read, so there is nothing to check a password against.
    monkeypatch.setattr(migrate_v3, "_node_names", lambda: ["renamed-computer"])
    assert migrate_v3.read_entries(legacy, username=FORGED_USERNAME, password=b"anything") == []


def test_the_verifier_of_the_first_program_is_understood(old: LegacyDirectories) -> None:
    """Before 1.0.1 the verifier was SHA-256(salt || password); it tells damage from a wrong password too."""
    path, fixture = old.unpack("script_2025")
    flip_byte(path / ".passwords.enc", 40)
    old.watch(path)
    with pytest.raises(VaultError, match="are right, but"):
        migrate_v3.read_entries(found(path), **credentials(fixture))


@pytest.mark.parametrize(
    ("payload", "complaint"),
    [
        (b"", "does not hold a list of entries"),
        (b"not json", "does not hold a list of entries"),
        (b"\xff\xfe\xfd", "does not hold a list of entries"),
        (b'{"username": "u"}', "does not hold a list of entries"),
        (b'"a string"', "does not hold a list of entries"),
        (b"null", "does not hold a list of entries"),
        (b"[" * 100_000, "does not hold a list of entries"),
        (b'[["a", "list"]]', "entry 1 .* is not a record"),
        (b"[null]", "entry 1 .* is not a record"),
        (json.dumps([record(), {"website": "w", "password": "p"}]).encode(), "entry 2 .* has no usable username"),
        (json.dumps([record(website=None)]).encode(), "entry 1 .* has no usable website"),
        (json.dumps([record(password=12345)]).encode(), "entry 1 .* has no usable password"),
        (json.dumps([record(notes=["a", "list"])]).encode(), "entry 1 .* has notes that are not text"),
    ],
    ids=["empty", "not json", "not utf-8", "an object", "a string", "null", "nested too deep", "a list in the list",
         "null in the list", "no username", "website is null", "password is a number", "notes are a list"],
)
def test_a_store_that_decrypts_to_something_else_is_damage(
    payload: bytes, complaint: str, isolated: Path, old: LegacyDirectories
) -> None:
    legacy, key = forged_contents(isolated / "forged", payload)
    old.watch(legacy.path)
    with pytest.raises(VaultError, match=complaint) as caught:
        migrate_v3.read_entries(legacy, master_key=key)
    assert caught.value.__context__ is None and caught.value.__cause__ is None  # nothing carrying the plaintext


def test_an_error_about_an_entry_names_its_position_and_never_its_contents(
    isolated: Path, old: LegacyDirectories
) -> None:
    payload = json.dumps([record(password="Tr0ub4dor&3", notes=5)]).encode()
    legacy, key = forged_contents(isolated / "forged", payload)
    old.watch(legacy.path)
    with pytest.raises(VaultError) as caught:
        migrate_v3.read_entries(legacy, master_key=key)
    assert "Tr0ub4dor" not in str(caught.value) and "entry 1" in str(caught.value)


@needs_tzset
def test_fields_that_3x_did_not_always_write_are_optional(isolated: Path, old: LegacyDirectories) -> None:
    payload = json.dumps(
        [
            {"username": "u", "website": "no-notes.example", "password": "p"},
            record(website="null-notes.example", notes=None),
            record(website="created.example", created_at="2026-01-01 00:01:00"),
            record(website="both.example", created_at="2026-01-01 00:01:00", updated_at="2026-03-01 12:00:00"),
            record(website="updated-only.example", updated_at="2026-03-01 12:00:00"),
            record(website="nonsense.example", created_at="yesterday", updated_at=20260101),
            record(website="before-1970.example", created_at="1960-01-01 00:00:00"),
            record(website="extra.example", created_at="2026-01-01 00:01:00", favourite=True, tags=["x"]),
        ]
    ).encode()
    legacy, key = forged_contents(isolated / "forged", payload)
    old.watch(legacy.path)
    entries = migrate_v3.read_entries(legacy, master_key=key)
    march = calendar.timegm((2026, 3, 1, 12, 0, 0))
    assert [(entry.website, entry.notes, entry.created, entry.modified) for entry in entries] == [
        ("no-notes.example", "", None, None),
        ("null-notes.example", "", None, None),
        ("created.example", "", NEW_YEAR_2026 + 60, NEW_YEAR_2026 + 60),
        ("both.example", "", NEW_YEAR_2026 + 60, march),
        ("updated-only.example", "", march, march),
        ("nonsense.example", "", None, None),
        ("before-1970.example", "", None, None),
        ("extra.example", "", NEW_YEAR_2026 + 60, NEW_YEAR_2026 + 60),
    ]


def test_the_decrypted_list_is_zeroed_once_parsed_and_also_when_it_cannot_be() -> None:
    good = bytearray(json.dumps([record(password="Tr0ub4dor&3")]).encode())
    assert migrate_v3._entries_from(good)[0].password == "Tr0ub4dor&3"
    assert good == bytearray(len(good))
    bad = bytearray(b'[{"password": "Tr0ub4dor&3"')
    with pytest.raises(VaultError):
        migrate_v3._entries_from(bad)
    assert bad == bytearray(len(bad))


def test_an_entry_does_not_show_its_password_or_notes_when_printed() -> None:
    entry = LegacyEntry("alice", "github.com", "Tr0ub4dor&3", "recovery codes: 1234 5678", 1, 2)
    assert "Tr0ub4dor" not in repr(entry) and "1234" not in repr(entry) and "Tr0ub4dor" not in str(entry)
    assert repr(entry) == "LegacyEntry(username='alice', website='github.com', created=1, modified=2)"
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.password = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# The Fernet reader, against the reference implementation
# ---------------------------------------------------------------------------


def raw_key(fernet_key: bytes) -> SecureBuffer:
    return SecureBuffer.from_buffer(base64.urlsafe_b64decode(fernet_key))


@PROPERTY
@given(key=st.binary(min_size=32, max_size=32), plaintext=st.binary(max_size=600), when=st.integers(0, 2**40))
def test_whatever_fernet_encrypts_is_decrypted_identically(key: bytes, plaintext: bytes, when: int) -> None:
    token = Fernet(base64.urlsafe_b64encode(key)).encrypt_at_time(plaintext, when)
    with SecureBuffer.from_buffer(key) as buffer:
        opened = migrate_v3._open_token(migrate_v3._parse_token(token, "token"), buffer)
    assert opened == plaintext and isinstance(opened, bytearray)
    with SecureBuffer.from_buffer(bytes(byte ^ 0xFF for byte in key)) as other:
        assert migrate_v3._open_token(migrate_v3._parse_token(token, "token"), other) is None


@PROPERTY
@given(plaintext=st.binary(max_size=200), position=st.integers(min_value=0), bit=st.integers(0, 7))
def test_a_token_with_any_one_bit_changed_never_decrypts(plaintext: bytes, position: int, bit: int) -> None:
    key = Fernet.generate_key()
    raw = bytearray(base64.urlsafe_b64decode(Fernet(key).encrypt(plaintext)))
    raw[position % len(raw)] ^= 1 << bit
    token = base64.urlsafe_b64encode(bytes(raw))
    with raw_key(key) as buffer:
        try:
            assert migrate_v3._open_token(migrate_v3._parse_token(token, "token"), buffer) is None
        except VaultError as exc:
            assert "not a Fernet token" in str(exc)  # the version byte


@PROPERTY
@given(data=st.one_of(st.binary(max_size=300), st.text(max_size=300).map(lambda text: text.encode("utf-8"))))
def test_arbitrary_bytes_are_a_damaged_token_or_one_that_fernet_accepts_too(data: bytes) -> None:
    key = Fernet.generate_key()
    try:
        token = migrate_v3._parse_token(data, "token")
    except VaultError:
        return
    with raw_key(key) as buffer:
        opened = migrate_v3._open_token(token, buffer)
    if opened is not None:
        assert Fernet(key).decrypt(data) == opened
    else:
        with pytest.raises(InvalidToken):
            Fernet(key).decrypt(data)


def test_a_token_wrapped_or_padded_with_whitespace_is_still_read() -> None:
    key = Fernet.generate_key()
    token = Fernet(key).encrypt(b"wrapped by an editor")
    wrapped = b"\n".join(token[start : start + 40] for start in range(0, len(token), 40)) + b"\r\n"
    with raw_key(key) as buffer:
        assert migrate_v3._open_token(migrate_v3._parse_token(wrapped, "token"), buffer) == b"wrapped by an editor"


def test_a_token_that_authenticates_but_is_not_padded_is_refused() -> None:
    """Only something holding the key could make one; it is still not allowed to become an entry list."""
    from cryptography.hazmat.primitives import hmac as crypto_hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = os.urandom(32)
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key[16:]), modes.CBC(iv)).encryptor()
    body = b"\x80" + (0).to_bytes(8, "big") + iv + encryptor.update(b"\x00" * 16) + encryptor.finalize()
    mac = crypto_hmac.HMAC(key[:16], hashes.SHA256())
    mac.update(body)
    token = base64.urlsafe_b64encode(body + mac.finalize())
    with SecureBuffer.from_buffer(key) as buffer, pytest.raises(VaultError, match="not padded as Fernet pads"):
        migrate_v3._open_token(migrate_v3._parse_token(token, "token"), buffer)


@PROPERTY
@given(raw=st.binary(min_size=32, max_size=32), spaces=st.sampled_from([b"", b"\n", b" \t", b"\r\n"]))
def test_both_text_forms_of_a_key_give_the_same_raw_key(raw: bytes, spaces: bytes) -> None:
    fernet_form = base64.urlsafe_b64encode(raw)
    keychain_form = base64.urlsafe_b64encode(fernet_form)
    for text in (fernet_form, keychain_form, spaces + fernet_form + spaces, spaces + keychain_form + spaces):
        buffer = migrate_v3._master_key_buffer(text)
        assert buffer is not None
        with buffer:
            assert bytes(buffer.view()) == raw


@PROPERTY
@given(data=st.binary(max_size=120))
def test_anything_else_given_as_a_key_is_refused_without_an_exception(data: bytes) -> None:
    buffer = migrate_v3._master_key_buffer(data)
    if buffer is not None:
        with buffer:
            assert len(buffer) == 32


# ---------------------------------------------------------------------------
# Whole vaults, forged
# ---------------------------------------------------------------------------

any_text = st.text(max_size=30)
credential_text = st.text(min_size=1, max_size=20)
stored_entries = st.lists(
    st.fixed_dictionaries(
        {"username": any_text, "website": any_text, "password": any_text, "notes": any_text},
        optional={"created_at": st.just("2026-01-01 00:01:00"), "updated_at": st.just("2026-02-02 02:02:02")},
    ),
    max_size=5,
)


@pytest.mark.parametrize("era", sorted(ERAS))
@settings(parent=PROPERTY, max_examples=25, suppress_health_check=WITH_FIXTURES)
@given(layout=st.sampled_from(["secrets", "flat"]), username=credential_text, password=credential_text,
       entries=stored_entries)
def test_any_credentials_and_entries_survive_a_vault_of_any_generation(
    era: str, layout: str, username: str, password: str, entries: List[Dict[str, str]], tmp_path: Path, fast_kdf: None
) -> None:
    root = Path(tempfile.mkdtemp(dir=str(tmp_path)))
    forge(root, entries=entries, username=username, password=password, layout=layout, era=era)
    before = snapshot(root)
    legacy = migrate_v3.detect(root)
    assert legacy is not None and (legacy.layout, legacy.has_entries) == (layout, True)
    assert migrate_v3.stored_username(legacy) == username
    for attempt in ({"password": password.encode("utf-8")},
                    {"username": username, "password": SecureBuffer.from_buffer(password.encode("utf-8"))}):
        read = migrate_v3.read_entries(legacy, **attempt)
        assert [(entry.username, entry.website, entry.password, entry.notes) for entry in read] == [
            (item["username"], item["website"], item["password"], item["notes"]) for item in entries
        ]
    with pytest.raises(AuthError):
        migrate_v3.read_entries(legacy, username=username, password=(password + "!").encode("utf-8"))
    assert snapshot(root) == before


core_file = st.one_of(st.none(), st.binary(max_size=80), st.binary(min_size=16, max_size=16))


@settings(parent=PROPERTY, max_examples=80, suppress_health_check=WITH_FIXTURES)
@given(salt=core_file, user=core_file, digest=core_file, store=core_file, layout=st.sampled_from(["secrets", "flat"]))
def test_a_directory_of_arbitrary_files_only_ever_raises_the_documented_errors(
    salt: Optional[bytes], user: Optional[bytes], digest: Optional[bytes], store: Optional[bytes], layout: str,
    tmp_path: Path, fast_kdf: None,
) -> None:
    root = Path(tempfile.mkdtemp(dir=str(tmp_path)))
    base = root / "secrets" if layout == "secrets" else root
    base.mkdir(exist_ok=True)
    for name, data in (("salt.bin", salt), (".master_user.enc", user), (".master_hash.enc", digest),
                       (".passwords.enc", store)):
        if data is not None:
            (base / name).write_bytes(data)
    before = snapshot(root)
    try:
        legacy = migrate_v3.detect(root)
    except VaultError:
        legacy = None
    if legacy is not None:
        assert len(legacy.salt) == 16 and legacy.mode is None
        assert migrate_v3.stored_username(legacy) is None
        for attempt in ({"username": "u", "password": b"p"}, {"master_key": Fernet.generate_key()}):
            try:
                assert migrate_v3.read_entries(legacy, **attempt) == []
            except (VaultError, AuthError):
                continue
    assert snapshot(root) == before


json_values = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text(max_size=10)),
    lambda children: st.one_of(st.lists(children, max_size=4),
                               st.dictionaries(st.text(max_size=8), children, max_size=4)),
    max_leaves=12,
)


@PROPERTY
@given(document=json_values)
def test_any_json_in_a_store_gives_entries_or_a_vault_error(document: Any) -> None:
    plain = bytearray(json.dumps(document).encode("utf-8"))
    try:
        entries = migrate_v3._entries_from(plain)
    except VaultError:
        entries = None
    assert plain == bytearray(len(plain))
    if entries is not None:
        assert isinstance(document, list) and len(entries) == len(document)
        assert all(isinstance(entry, LegacyEntry) for entry in entries)


@PROPERTY
@given(value=st.one_of(st.none(), st.integers(), st.text(max_size=30), st.datetimes().map(str),
                       st.datetimes().map(lambda moment: moment.strftime(TIME_FORMAT))))
def test_a_timestamp_is_a_non_negative_time_or_unknown(value: Any) -> None:
    parsed = migrate_v3._parse_time(value)
    assert parsed is None or (isinstance(parsed, int) and parsed >= 0)


@needs_tzset
@PROPERTY
@given(moment=st.integers(min_value=0, max_value=4_000_000_000))
def test_a_timestamp_written_by_3x_converts_back_to_the_moment_it_was_written(moment: int) -> None:
    assert migrate_v3._parse_time(time.strftime(TIME_FORMAT, time.gmtime(moment))) == moment


# ---------------------------------------------------------------------------
# keychain_master_key (fakes only: nothing here can reach a real keychain)
# ---------------------------------------------------------------------------


class KeyringLeftBehind(types.ModuleType):
    """The third-party ``keyring`` package, as 3.x left it importable: records every use, hands out a wrong value.

    Dunder lookups are introspection by the interpreter or by pytest, not use, and are not recorded.
    """

    def __init__(self) -> None:
        super().__init__("keyring")
        self.uses: List[str] = []

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        self.uses.append(name)
        return lambda *args, **kwargs: "a-value-from-the-keyring-package"


class FakeTool:
    """Stands in for ``/usr/bin/security`` or ``secret-tool``, with the exit statuses the real ones use."""

    def __init__(self, platform: str, entries: Optional[Dict[str, bytes]] = None, *,
                 statuses: Optional[Dict[str, int]] = None, sticky: Tuple[str, ...] = ()) -> None:
        self.platform = platform
        self.store = dict(entries or {})
        self.statuses = statuses or {}  # verb -> exit status to answer with instead
        self.sticky = sticky  # accounts that survive deletion
        self.commands: List[List[str]] = []
        self.outputs: List[bytes] = []

    def __call__(self, command: List[str]) -> Tuple[int, bytes]:
        self.commands.append(list(command))
        verb = command[1]
        if self.platform == "darwin":
            assert command[0] == "/usr/bin/security" and command[2:4] == ["-s", "IronDome"] and command[4] == "-a"
            account, reveal = command[5], command[6:] == ["-w"]
            assert reveal or command[6:] == []
            status, output = self._darwin(verb, account, reveal)
        else:
            assert command[0] == "/usr/bin/secret-tool" and command[2:5] == ["service", "IronDome", "username"]
            status, output = self._linux(verb, command[5])
        if verb in self.statuses:
            status, output = self.statuses[verb], b""
        output = bytes(bytearray(output))  # a fresh object: the module zeroes what it is handed
        self.outputs.append(output)
        return status, output

    def _darwin(self, verb: str, account: str, reveal: bool) -> Tuple[int, bytes]:
        present = account in self.store
        if verb == "find-generic-password":
            if not present:
                return 44, b""
            return 0, (self.store[account] + b"\n") if reveal else b'keychain: "login.keychain-db"\nclass: "genp"\n'
        assert verb == "delete-generic-password"
        if not present:
            return 44, b""
        if account not in self.sticky:
            del self.store[account]
        return 0, b"password has been deleted.\n"

    def _linux(self, verb: str, account: str) -> Tuple[int, bytes]:
        if verb == "lookup":
            return (0, self.store[account]) if account in self.store else (1, b"")
        assert verb == "clear"
        if account not in self.sticky:
            self.store.pop(account, None)
        return 0, b""


@pytest.fixture
def our_keychain(monkeypatch: pytest.MonkeyPatch) -> Callable[[FakeTool], FakeTool]:
    """Pretend the keychain is this account's own, and put a fake system command in front of it."""

    def install(tool: FakeTool) -> FakeTool:
        command = "/usr/bin/security" if tool.platform == "darwin" else "/usr/bin/secret-tool"
        monkeypatch.setattr(migrate_v3, "_keychain_is_ours", lambda: True)
        monkeypatch.setattr(migrate_v3, "_PLATFORM", tool.platform)
        monkeypatch.setattr(migrate_v3, "_keychain_tool", lambda: command)
        monkeypatch.setattr(migrate_v3, "_run_tool", tool)
        return tool

    return install


def keychain_of(fixture: Dict[str, Any]) -> Dict[str, bytes]:
    return {account: value.encode("ascii") for account, value in fixture["keyring"].items()}


def test_under_a_redirected_home_the_keychain_is_not_consulted_at_all() -> None:
    """The suite's isolation points HOME elsewhere; the autouse guard would fail this test on any attempt."""
    assert migrate_v3._keychain_is_ours() is False
    assert migrate_v3.keychain_master_key() is None
    assert migrate_v3.keychain_unreachable() == (
        "$HOME is not this account's home directory, so the keychain within reach is not the one IronDome 3.x used"
    )


@posix_only
def test_the_keychain_is_ours_only_when_home_is_the_accounts_own_home(
    isolated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = os.path.expanduser("~")
    monkeypatch.setattr(migrate_v3, "_account_home", lambda: home)
    assert migrate_v3._keychain_is_ours() is True
    link = isolated / "link-to-home"
    link.symlink_to(home)
    monkeypatch.setattr(migrate_v3, "_account_home", lambda: str(link))
    assert migrate_v3._keychain_is_ours() is True
    monkeypatch.setattr(migrate_v3, "_account_home", lambda: str(isolated / "the-real-home"))
    assert migrate_v3._keychain_is_ours() is False
    monkeypatch.setattr(migrate_v3, "_account_home", lambda: None)  # an account with no entry in the database
    assert migrate_v3._keychain_is_ours() is False


@posix_only
def test_only_the_vault_at_the_standard_place_owns_the_keychain_entries(
    isolated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    standard = Path(os.path.expanduser("~")) / ".password_manager"
    assert migrate_v3._owns_keychain(standard) is False  # HOME is redirected
    monkeypatch.setattr(migrate_v3, "_keychain_is_ours", lambda: True)
    assert migrate_v3._owns_keychain(standard) is True
    assert migrate_v3._owns_keychain(paths.legacy_v3_dir()) is False  # IRONDOME_LEGACY_DIR: a copy
    assert migrate_v3._owns_keychain(isolated / "restored-backup" / ".password_manager") is False


def test_the_key_is_fetched_with_security_on_macos_and_what_it_printed_is_zeroed(
    old: LegacyDirectories, our_keychain: Callable[..., Any]
) -> None:
    path, fixture = old.unpack("biometric_only")
    tool = our_keychain(FakeTool("darwin", keychain_of(fixture)))
    key = migrate_v3.keychain_master_key()
    assert key == fixture["vault_key"].encode("ascii") and type(key) is bytes
    assert tool.commands == [
        ["/usr/bin/security", "find-generic-password", "-s", "IronDome", "-a", "master_key", "-w"]
    ]
    assert len(tool.outputs[0]) == 61 and not any(tool.outputs[0])
    assert migrate_v3.read_entries(found(path), master_key=key) == expected_entries(fixture)


def test_the_key_is_fetched_with_secret_tool_on_linux_which_prints_no_newline(
    our_keychain: Callable[..., Any]
) -> None:
    fixture = fixture_named("biometric_only")
    tool = our_keychain(FakeTool("linux", keychain_of(fixture)))
    assert migrate_v3.keychain_master_key() == fixture["vault_key"].encode("ascii")
    assert tool.commands == [["/usr/bin/secret-tool", "lookup", "service", "IronDome", "username", "master_key"]]
    assert len(tool.outputs[0]) == 60 and not any(tool.outputs[0])


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_no_entry_in_the_keychain_is_none(platform: str, our_keychain: Callable[..., Any]) -> None:
    tool = our_keychain(FakeTool(platform, {"auth_mode": b"password_only"}))
    assert migrate_v3.keychain_master_key() is None
    assert len(tool.commands) == 1


@pytest.mark.parametrize(("status", "words"), [(51, "exited with status 51"), (128, "exited with status 128"),
                                               (36, "exited with status 36"), (-1, "did not finish")])
def test_a_refusal_by_macos_is_an_authentication_failure_not_a_missing_key(
    status: int, words: str, our_keychain: Callable[..., Any]
) -> None:
    our_keychain(FakeTool("darwin", {"master_key": b"irrelevant"}, statuses={"find-generic-password": status}))
    with pytest.raises(AuthError, match=f"did not release the IronDome 3.x key.*{words}"):
        migrate_v3.keychain_master_key()


def test_secret_tool_failing_is_none_because_it_cannot_say_why(our_keychain: Callable[..., Any]) -> None:
    our_keychain(FakeTool("linux", {"master_key": b"irrelevant"}, statuses={"lookup": 1}))
    assert migrate_v3.keychain_master_key() is None


@pytest.mark.parametrize("value", [b"not a key", base64.urlsafe_b64encode(b"k" * 20), b"password_only"])
def test_an_entry_that_is_not_a_key_is_reported_as_such(value: bytes, our_keychain: Callable[..., Any]) -> None:
    our_keychain(FakeTool("darwin", {"master_key": value}))
    with pytest.raises(VaultError, match="IronDome/master_key entry in the OS keychain is not an") as caught:
        migrate_v3.keychain_master_key()
    assert value.decode() not in str(caught.value)


def test_a_keyring_package_left_behind_by_3x_is_never_imported_or_used(
    old: LegacyDirectories, our_keychain: Callable[[FakeTool], FakeTool], monkeypatch: pytest.MonkeyPatch
) -> None:
    """IronDome depends on cryptography alone (claims one-dependency and no-network).

    3.x depended on ``keyring``, and an upgrade in place leaves it importable. The key is still read, and the
    entries still cleared, with the system's own command only.
    """
    left_behind = KeyringLeftBehind()
    monkeypatch.setitem(sys.modules, "keyring", left_behind)
    legacy, fixture = standard_vault(old, "biometric_only")
    tool = our_keychain(FakeTool("darwin", keychain_of(fixture)))
    assert migrate_v3.keychain_master_key() == fixture["vault_key"].encode("ascii")
    report = migrate_v3.destroy_legacy(legacy)
    assert (report.success, report.keychain_cleared, report.errors) == (True, True, [])
    assert left_behind.uses == [] and tool.store == {}
    assert tool.commands[0] == [
        "/usr/bin/security", "find-generic-password", "-s", "IronDome", "-a", "master_key", "-w"
    ]


def test_with_the_systems_command_at_hand_nothing_stands_in_the_way_of_asking_the_keychain(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(migrate_v3, "_keychain_is_ours", lambda: True)
    for platform, command in (("darwin", "/usr/bin/security"), ("linux", "/usr/bin/secret-tool")):
        monkeypatch.setattr(migrate_v3, "_PLATFORM", platform)
        monkeypatch.setattr(migrate_v3, "_keychain_tool", lambda command=command: command)
        assert migrate_v3.keychain_unreachable() is None


@pytest.mark.parametrize(
    ("platform", "reason"),
    [
        ("darwin", "/usr/bin/security, the macOS keychain command, cannot be run here"),
        ("linux", "secret-tool is not installed in /usr/bin or /bin "
                  "(it comes with libsecret; on Debian and Ubuntu the package is libsecret-tools)"),
        ("win32", "IronDome has no way to read the Windows Credential Manager, where 3.x kept it"),
        ("freebsd14", "IronDome reads the OS keychain only on macOS, with /usr/bin/security, "
                      "and on Linux, with secret-tool"),
    ],
    ids=["macos", "linux", "windows", "elsewhere"],
)
def test_without_the_systems_command_there_is_no_key_and_the_reason_says_why_in_plain_words(
    platform: str, reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing is run (the autouse guard refuses every command) and nothing else is tried."""
    monkeypatch.setattr(migrate_v3, "_keychain_is_ours", lambda: True)
    monkeypatch.setattr(migrate_v3, "_PLATFORM", platform)
    monkeypatch.setattr(migrate_v3.shutil, "which", lambda *args, **kwargs: None)
    assert migrate_v3.keychain_master_key() is None
    assert migrate_v3.keychain_unreachable() == reason


def test_the_systems_command_is_looked_up_on_fixed_paths_and_only_where_one_exists(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    asked: List[Tuple[str, Optional[str]]] = []

    def which(name: str, path: Optional[str] = None) -> str:
        asked.append((name, path))
        return name if os.path.isabs(name) else f"/usr/bin/{name}"

    monkeypatch.setattr(migrate_v3.shutil, "which", which)
    monkeypatch.setattr(migrate_v3, "_PLATFORM", "darwin")
    assert REAL_KEYCHAIN_TOOL() == "/usr/bin/security"
    monkeypatch.setattr(migrate_v3, "_PLATFORM", "linux")
    assert REAL_KEYCHAIN_TOOL() == "/usr/bin/secret-tool"
    for elsewhere in ("win32", "cygwin", "freebsd14"):
        monkeypatch.setattr(migrate_v3, "_PLATFORM", elsewhere)
        assert REAL_KEYCHAIN_TOOL() is None
    # macOS: the one fixed path, checked as it is; Linux: two fixed directories. $PATH is never searched.
    assert asked == [("/usr/bin/security", None), ("secret-tool", "/usr/bin:/bin")]


@pytest.mark.skipif(sys.platform != "darwin", reason="where macOS keeps its own keychain command")
def test_on_this_mac_the_keychain_command_is_where_the_module_runs_it_from() -> None:
    """Only looked at, never run (the autouse guard would fail the test); a sandbox may forbid running it."""
    assert migrate_v3._MACOS_TOOL == "/usr/bin/security" and os.path.isfile(migrate_v3._MACOS_TOOL)


@posix_only
def test_a_keychain_command_gets_a_minimal_environment_and_no_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IRONDOME_SESSION", "a-session-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "not-for-children")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
    monkeypatch.setenv("PATH", "/tmp/planted:/usr/bin")
    status, output = REAL_RUN_TOOL(["/usr/bin/env"])
    assert status == 0
    passed = dict(line.split("=", 1) for line in output.decode().splitlines() if "=" in line)
    assert passed["PATH"] == "/usr/bin:/bin"
    assert set(passed) <= set(migrate_v3._TOOL_ENVIRONMENT) | {"PATH"}
    assert passed.get("HOME") == os.environ["HOME"]


@posix_only
def test_a_keychain_command_that_cannot_run_or_does_not_finish_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    assert REAL_RUN_TOOL(["/nonexistent/keychain-tool"]) == (-1, b"")
    monkeypatch.setattr(migrate_v3, "_TOOL_TIMEOUT", 0.3)
    started = time.monotonic()
    assert REAL_RUN_TOOL(["/bin/sleep", "60"]) == (-1, b"")
    assert time.monotonic() - started < 50


# ---------------------------------------------------------------------------
# import_into: the fixtures' entries
# ---------------------------------------------------------------------------


def test_the_three_entries_of_a_plain_vault_keep_their_websites_as_names_and_urls(empty_vault: Any) -> None:
    fixture = fixture_named("password_only")
    report = migrate_v3.import_into(empty_vault, expected_entries(fixture))
    assert (report.imported, report.renamed, report.skipped) == (3, [], [])
    assert [(entry.name, entry.url, entry.username) for entry in empty_vault.list()] == [
        ("github.com", "github.com", "alice@example.com"),
        ("https://mail.example.org/login", "https://mail.example.org/login", "alice"),
        ("nas.local", "nas.local", "root"),
    ]


def test_colliding_and_invalid_websites_get_the_names_the_rules_say(empty_vault: Any) -> None:
    entries = expected_entries(fixture_named("collisions"))
    long_name = "a-very-long-service-name-" * 10
    expected = [
        # (website, name, url)
        ("github.com", "github.com (alice@example.com)", "github.com"),
        ("github.com", "github.com (bob@example.com)", "github.com"),
        ("GitHub.com", "GitHub.com (carol)", "GitHub.com"),
        ("GITHUB.COM", "GITHUB.COM (alice@example.com) (2)", "GITHUB.COM"),
        ("github.com (bob@example.com)", "github.com (bob@example.com) (2)", ""),
        ("  padded.example.com  ", "padded.example.com", "padded.example.com"),
        ("tab\tand\nnewline", "tab and newline", ""),
        (long_name, long_name[:192] + " (frank)", ""),
        (long_name, long_name[:192] + " (grace)", ""),
        ("My Bank (personal)", "My Bank (personal)", ""),
        ("192.168.1.10:8443/admin", "192.168.1.10:8443/admin", "192.168.1.10:8443/admin"),
        ("ssh://git@example.com:2222/repo.git", "ssh://git@example.com:2222/repo.git",
         "ssh://git@example.com:2222/repo.git"),
    ]
    assert [entry.website for entry in entries] == [website for website, _, _ in expected]
    report = migrate_v3.import_into(empty_vault, entries)
    assert (report.imported, report.skipped) == (12, [])
    assert report.renamed == [(website, name) for website, name, _ in expected if website != name]
    assert len(report.renamed) == 9
    for (_, name, url), legacy in zip(expected, entries):
        entry = empty_vault.find(name)
        assert (entry.name, entry.url, entry.username) == (name, url, legacy.username)
        assert len(entry.name) <= 200 and validate_name(entry.name) == entry.name
        assert empty_vault.read_secret(entry).password == legacy.password
    assert migrate_v3.verify(empty_vault, entries) == []


def test_hebrew_names_and_addresses_are_kept_as_they_are(empty_vault: Any) -> None:
    entries = expected_entries(fixture_named("unicode"))
    report = migrate_v3.import_into(empty_vault, entries)
    assert (report.imported, report.renamed, report.skipped) == (4, [], [])
    by_name = {entry.name: entry for entry in empty_vault.entries.values()}
    assert set(by_name) == {entry.website for entry in entries}
    hebrew_domain, hebrew_url, phrase, plain = (entry.website for entry in entries)
    assert by_name[hebrew_domain].url == hebrew_domain  # a host name in Hebrew letters is still a host name
    assert by_name[hebrew_url].url == hebrew_url
    assert by_name[phrase].url == ""  # words with spaces are a name, not an address
    assert by_name[plain].url == "example.com"
    for legacy in entries:
        assert empty_vault.read_secret(by_name[legacy.website]).password == legacy.password
        assert by_name[legacy.website].username == legacy.username


def test_two_hundred_entries_arrive_with_unique_names(empty_vault: Any) -> None:
    entries = expected_entries(fixture_named("two_hundred"))
    report = migrate_v3.import_into(empty_vault, entries)
    assert (report.imported, report.skipped) == (200, [])
    assert len(empty_vault.entries) == 200
    assert len({entry.name.casefold() for entry in empty_vault.entries.values()}) == 200
    assert sorted(name for _, name in report.renamed) == sorted(
        f"shared.example.com ({entries[index].username})" for index in range(0, 200, 25)
    )
    assert migrate_v3.verify(empty_vault, entries) == []
    assert max(len(empty_vault.read_secret(entry).notes) for entry in empty_vault.entries.values()) == 5000


# ---------------------------------------------------------------------------
# import_into: its rules, on entries made for the purpose
# ---------------------------------------------------------------------------


def test_importing_twice_adds_nothing_the_second_time(empty_vault: Any) -> None:
    entries = expected_entries(fixture_named("collisions"))
    assert migrate_v3.import_into(empty_vault, entries).imported == 12
    before = names_in(empty_vault)
    again = migrate_v3.import_into(empty_vault, entries)
    assert (again.imported, again.renamed) == (0, [])
    assert len(again.skipped) == 12 and all(line.endswith(": already in the vault") for line in again.skipped)
    assert names_in(empty_vault) == before


def test_a_name_held_by_a_different_entry_is_never_reused_or_overwritten(vault: Any) -> None:
    vault.add("github.com", Secret(password="set-up-by-hand", notes="mine"), username="king")
    legacy = [legacy_entry("github.com", "alice", "from-the-old-vault"), legacy_entry("GITHUB", "bob", "another")]
    report = migrate_v3.import_into(vault, legacy)
    assert (report.imported, report.skipped) == (2, [])
    assert report.renamed == [("github.com", "github.com (2)"), ("GITHUB", "GITHUB (2)")]  # "github" was there too
    assert vault.read_secret(vault.find("github.com")).password == "set-up-by-hand"
    assert vault.read_secret(vault.find("github")).password == "hunter2-Github!"
    assert vault.read_secret(vault.find("github.com (2)")).password == "from-the-old-vault"
    assert vault.find("GITHUB (2)").username == "bob"
    assert migrate_v3.verify(vault, legacy) == []
    assert migrate_v3.import_into(vault, legacy).imported == 0  # and it is found again under that name


def test_an_entry_already_there_with_the_same_contents_is_left_alone(empty_vault: Any) -> None:
    empty_vault.add("example.com", Secret(password="pw", notes="n"), username="user", tags=["kept"])
    report = migrate_v3.import_into(empty_vault, [legacy_entry("example.com", "user", "pw", "n")])
    assert (report.imported, report.skipped) == (0, ["example.com (user): already in the vault"])
    assert empty_vault.find("example.com").tags == ["kept"]


def test_nothing_reaches_the_disk_until_the_caller_commits(empty_vault: Any) -> None:
    on_disk = paths.vault_file().read_bytes()
    migrate_v3.import_into(empty_vault, expected_entries(fixture_named("password_only")))
    assert paths.vault_file().read_bytes() == on_disk
    assert VaultFile.load().records == {}
    empty_vault.commit()
    assert len(VaultFile.load().records) == 3


def test_a_failure_part_way_leaves_the_vault_as_it_was(vault: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    entries = expected_entries(fixture_named("collisions"))
    before = (names_in(vault), set(vault.file.records), dict(vault.aliases))
    real_add = vault.add
    calls: List[str] = []

    def add_until_the_fourth(name: str, *args: Any, **kwargs: Any) -> Any:
        if len(calls) == 3:
            raise OSError(28, "No space left on device")
        calls.append(name)
        return real_add(name, *args, **kwargs)

    monkeypatch.setattr(vault, "add", add_until_the_fourth)
    with pytest.raises(OSError, match="No space left"):
        migrate_v3.import_into(vault, entries)
    assert len(calls) == 3
    assert (names_in(vault), set(vault.file.records), dict(vault.aliases)) == before
    monkeypatch.setattr(vault, "add", real_add)
    assert migrate_v3.import_into(vault, entries).imported == 12


def test_an_entry_the_vault_refuses_is_skipped_reported_and_missed_by_verify(empty_vault: Any) -> None:
    entries = [
        legacy_entry("fine.example", "user", "pw"),
        legacy_entry("long-password.example", "user", "x" * 100_001),
        legacy_entry("long-username.example", "u" * 100_001, "pw"),
        legacy_entry("long-notes.example", "user", "pw", "n" * 1_000_001),
        legacy_entry("https://long-url.example/" + "p" * 100_000, "user", "pw"),
        legacy_entry("bad-time.example", "user", "pw", created=-1),
        legacy_entry("at-the-limit.example", "u" * 100_000, "x" * 100_000, "n" * 1_000_000),
    ]
    report = migrate_v3.import_into(empty_vault, entries)
    assert report.imported == 2
    reasons = [line.split(": ", 1)[1] for line in report.skipped]
    words = ("password", "username", "notes", "URL", "time")
    assert [word in reason for word, reason in zip(words, reasons)] == [True] * 5
    assert all(len(line) < 250 for line in report.skipped)  # the reason names the field and never holds its value
    problems = migrate_v3.verify(empty_vault, entries)
    assert len(problems) == 5 and all(line.endswith(": is not in the vault") for line in problems)
    empty_vault.commit()
    empty_vault.close()
    with secret(PASSWORD) as new_password:
        reopened = open_vault(password=new_password, interactive=False)
    try:
        assert names_in(reopened) == ["at-the-limit.example", "fine.example"]
        assert len(reopened.read_secret(reopened.find("at-the-limit.example")).notes) == 1_000_000
    finally:
        reopened.close()


def test_a_username_with_control_characters_is_migrated_without_them_and_verified(empty_vault: Any) -> None:
    """The vault refuses control characters in a username; the entry comes over without them, never skipped."""
    entries = [
        legacy_entry("bank.example", "me\x1b[31m\t", "bank-pw-1", "notes\x07stay"),
        legacy_entry("plain.example", "you", "plain-pw-2"),
    ]
    report = migrate_v3.import_into(empty_vault, entries)
    assert report.imported == 2 and report.skipped == []
    assert report.cleaned == ["bank.example (me [31m): control characters were taken out of its username"]
    bank = empty_vault.find("bank.example")
    assert bank.username == "me[31m" and empty_vault.read_secret(bank).notes == "notes\x07stay"
    assert migrate_v3.verify(empty_vault, entries) == []
    assert migrate_v3.import_into(empty_vault, entries).imported == 0  # found again: importing twice adds nothing


def test_a_website_that_cannot_be_a_name_at_all_becomes_untitled(empty_vault: Any) -> None:
    entries = [
        legacy_entry("", "ann"),
        legacy_entry("   ", "bob"),
        legacy_entry("\x00\x01", ""),
        legacy_entry("\t", ""),
        legacy_entry(chr(0x85) + chr(0x2028), "eve"),
    ]
    report = migrate_v3.import_into(empty_vault, entries)
    assert names_in(empty_vault) == sorted(
        ["untitled (ann)", "untitled (bob)", "untitled", "untitled (2)", "untitled (eve)"]
    )
    assert report.imported == 5 and len(report.renamed) == 5
    assert migrate_v3.verify(empty_vault, entries) == []


def test_characters_an_entry_name_may_not_hold_become_spaces_and_nothing_else_changes(empty_vault: Any) -> None:
    websites = {
        "tab\there": "tab here",
        "nul\x00byte": "nul byte",
        "del" + chr(0x7F) + "ete": "del ete",
        "c1" + chr(0x9B) + "control": "c1 control",
        "line" + chr(0x2028) + "separator": "line separator",
        "paragraph" + chr(0x2029) + "separator": "paragraph separator",
        chr(0xD800) + "half a character": "\N{REPLACEMENT CHARACTER}half a character",
        "  spaces  inside   stay  ": "spaces  inside   stay",
        "caf\N{LATIN SMALL LETTER E WITH ACUTE} \N{LOCK} \N{HEBREW LETTER ALEF}": None,
        "zero\N{ZERO WIDTH JOINER}width \N{RIGHT-TO-LEFT MARK}marks": None,
    }
    entries = [legacy_entry(website, f"user-{number}") for number, website in enumerate(websites)]
    report = migrate_v3.import_into(empty_vault, entries)
    expected = [name if name is not None else website for website, name in websites.items()]
    assert names_in(empty_vault) == sorted(expected)
    assert report.renamed == [(website, name) for website, name in websites.items() if name is not None]
    for name in expected:
        assert validate_name(name) == name


def test_times_are_carried_over_and_unknown_ones_become_now(empty_vault: Any) -> None:
    started = int(time.time())
    migrate_v3.import_into(
        empty_vault,
        [legacy_entry("dated.example", created=1_600_000_000, modified=1_700_000_000), legacy_entry("undated.example"),
         legacy_entry("epoch.example", created=0, modified=0)],
    )
    dated, undated, at_epoch = (empty_vault.find(name) for name in ("dated.example", "undated.example",
                                                                    "epoch.example"))
    assert (dated.created, dated.modified) == (1_600_000_000, 1_700_000_000)
    assert started <= undated.created <= int(time.time()) and undated.modified == undated.created
    assert (at_epoch.created, at_epoch.modified) == (0, 0)


def test_import_and_verify_insist_on_a_vault_and_on_entries(empty_vault: Any) -> None:
    entries = [legacy_entry()]
    for call in (migrate_v3.import_into, migrate_v3.verify):
        with pytest.raises(UsageError, match="needs an open IronDome vault"):
            call("not a vault", entries)  # type: ignore[arg-type]
        with pytest.raises(UsageError, match="returned by migrate_v3.read_entries"):
            call(empty_vault, [record()])  # type: ignore[list-item]
        with pytest.raises(UsageError, match="returned by migrate_v3.read_entries"):
            call(empty_vault, "github.com")  # type: ignore[arg-type]
    assert empty_vault.entries == {}
    assert migrate_v3.import_into(empty_vault, []).imported == 0 and migrate_v3.verify(empty_vault, []) == []


@pytest.mark.parametrize(
    ("website", "is_address"),
    [
        ("github.com", True),
        ("GitHub.COM", True),
        ("nas.local", True),
        ("sub.domain.example.co.uk", True),
        ("example.com/login?next=/home", True),
        ("example.com:8443", True),
        ("192.168.1.10", True),
        ("192.168.1.10:8443/admin", True),
        ("https://example.com", True),
        ("https://mail.example.org/login", True),
        ("ssh://git@example.com:2222/repo.git", True),
        ("otpauth://totp/Example:alice?secret=x", True),
        ("xn--4dbrk0ce.xn--9dbq2a", True),
        ("github", False),
        ("localhost", False),
        ("localhost:3000", False),
        ("My Bank", False),
        ("my bank.com", False),
        ("alice@example.com", False),
        ("example..com", False),
        (".example.com", False),
        ("-bad.example.com", False),
        ("bad-.example.com", False),
        ("example.com:port", False),
        ("example.com:123456", False),
        ("1.2", False),
        ("version 1.2.3", False),
        ("999.1.1.1", False),
        ("1.2.3.4.5", False),
        ("https://", False),
        ("://example.com", False),
        ("https://exa mple.com", False),
        ("example.com\n", False),
        ("exa\x00mple.com", False),
        ("https://exa" + chr(0x9B) + "mple.com", False),
        ("a" * 64 + ".com", False),
        ("", False),
    ],
)
def test_what_counts_as_an_address(website: str, is_address: bool) -> None:
    assert migrate_v3._looks_like_address(website) is is_address


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def test_verify_names_what_differs_without_showing_any_value(empty_vault: Any) -> None:
    entries = [
        legacy_entry("password.example", "ann", "S3cret-one", "note one"),
        legacy_entry("username.example", "bob", "S3cret-two", "note two"),
        legacy_entry("notes.example", "cat", "S3cret-three", "note three"),
        legacy_entry("removed.example", "dan", "S3cret-four", "note four"),
        legacy_entry("damaged.example", "eve", "S3cret-five", "note five"),
        legacy_entry("untouched.example", "fay", "S3cret-six", "note six"),
    ]
    migrate_v3.import_into(empty_vault, entries)
    assert migrate_v3.verify(empty_vault, entries) == []

    vault = empty_vault
    vault.update(vault.find("password.example"), secret=Secret(password="rotated-since", notes="note one"))
    vault.update(vault.find("username.example"), username="robert")
    vault.update(vault.find("notes.example"), secret=Secret(password="S3cret-three", notes="edited"))
    vault.remove(vault.find("removed.example"))
    vault.file.records[vault.find("damaged.example").id] = vault.file.records[vault.find("untouched.example").id]

    problems = migrate_v3.verify(vault, entries)
    assert problems[:4] == [
        "password.example (ann): the password differs",
        "username.example (bob): the username differs",
        "notes.example (cat): the notes differ",
        "removed.example (dan): is not in the vault",
    ]
    assert problems[4].startswith("damaged.example (eve): its record cannot be read (")
    assert len(problems) == 5
    report = " ".join(problems)
    assert "S3cret" not in report and "rotated" not in report and "note " not in report and "edited" not in report


def test_verify_reads_what_the_vault_holds_rather_than_trusting_the_import(empty_vault: Any) -> None:
    """A value no JSON document can produce, and that the vault's own JSON does not keep: verify must notice."""
    odd = legacy_entry("odd.example", notes=chr(0xD800) + chr(0xDFFF))
    fine = legacy_entry("fine.example", notes="lone " + chr(0xD800) + " surrogates survive")
    assert not from_json(odd.notes) and from_json(fine.notes)
    migrate_v3.import_into(empty_vault, [odd, fine])
    problems = migrate_v3.verify(empty_vault, [odd, fine])
    assert len(problems) == 1 and problems[0].startswith("odd.example (user): ")


def test_verify_looks_under_the_numbered_names_too(empty_vault: Any) -> None:
    empty_vault.add("example.com", Secret(password="someone else's"), username="other")
    empty_vault.add("example.com (2)", Secret(password="and another"), username="other")
    entry = legacy_entry("example.com", "user", "the-migrated-one")
    assert migrate_v3.verify(empty_vault, [entry]) == ["example.com (user): the username differs"]
    assert migrate_v3.import_into(empty_vault, [entry]).renamed == [("example.com", "example.com (3)")]
    assert migrate_v3.verify(empty_vault, [entry]) == []


# ---------------------------------------------------------------------------
# Names and imports, for any entries at all
# ---------------------------------------------------------------------------

awkward = st.sampled_from(
    ["\x00", "\t", "\n", "\x7f", chr(0x80), chr(0x85), chr(0x9F), chr(0x2028), chr(0x2029), " ",
     "\N{NO-BREAK SPACE}", chr(0xD800), chr(0xDFFF), "\N{RIGHT-TO-LEFT OVERRIDE}", "A", "a",
     "\N{LATIN SMALL LETTER SHARP S}", "(", ")", "2"]
)

field_text = st.text(alphabet=st.one_of(st.characters(), awkward), max_size=24).filter(from_json)
few_websites = st.sampled_from(["github.com", "GitHub.com", "GITHUB.COM ", "", " ", "x" * 199, "x" * 200, "x" * 260,
                                "github.com (a)", "github.com (2)", "untitled"])
legacy_entries = st.builds(
    LegacyEntry,
    username=st.one_of(field_text, st.sampled_from(["", "a", "A", "2"])),
    website=st.one_of(field_text, few_websites),
    password=field_text,
    notes=field_text,
    created=st.one_of(st.none(), st.integers(0, 2**40)),
    modified=st.one_of(st.none(), st.integers(0, 2**40)),
)


@settings(parent=PROPERTY, max_examples=150)
@given(entries=st.lists(legacy_entries, max_size=14))
def test_planned_names_are_always_valid_unique_and_repeatable(entries: List[LegacyEntry]) -> None:
    names = migrate_v3._plan_names(entries)
    assert len(names) == len(entries)
    for name in names:
        assert validate_name(name) == name and not any(0xD800 <= ord(char) <= 0xDFFF for char in name)
    assert len({name.casefold() for name in names}) == len(names)
    assert migrate_v3._plan_names(list(entries)) == names


@settings(parent=PROPERTY, max_examples=150)
@given(websites=st.lists(st.text(max_size=20), unique_by=fold_name, max_size=10))
def test_websites_that_are_already_distinct_valid_names_are_used_unchanged(websites: List[str]) -> None:
    usable = []
    for website in websites:
        try:
            usable.append(validate_name(website))
        except UsageError:
            continue
    assert migrate_v3._plan_names([legacy_entry(website) for website in usable]) == usable


@settings(parent=PROPERTY, max_examples=60, suppress_health_check=WITH_FIXTURES)
@given(entries=st.lists(legacy_entries, max_size=10), already=st.lists(legacy_entries, max_size=3))
def test_any_entries_import_into_any_vault_verify_and_import_only_once(
    entries: List[LegacyEntry], already: List[LegacyEntry], empty_vault: Any
) -> None:
    vault = empty_vault
    for existing in list(vault.entries.values()):
        vault.remove(existing)
    migrate_v3.import_into(vault, already)  # whatever was in the vault before the migration
    before = {
        entry.id: (entry.name, entry.username, vault.read_secret(entry).password) for entry in vault.entries.values()
    }

    report = migrate_v3.import_into(vault, entries)
    assert report.imported + len(report.skipped) == len(entries)
    assert all(line.endswith(": already in the vault") for line in report.skipped)
    assert migrate_v3.verify(vault, entries) == []
    assert len(vault.entries) == len(before) + report.imported
    for entry_id, (name, username, password) in before.items():
        kept = vault.entries[entry_id]
        assert (kept.name, kept.username, vault.read_secret(kept).password) == (name, username, password)
    for entry in vault.entries.values():
        assert validate_name(entry.name) == entry.name
    assert len({entry.name.casefold() for entry in vault.entries.values()}) == len(vault.entries)
    for website, name in report.renamed:
        assert name != website
    again = migrate_v3.import_into(vault, entries)
    assert (again.imported, len(again.skipped)) == (0, len(entries))


@PROPERTY
@given(text=st.one_of(field_text, st.text(max_size=80)))
def test_the_address_test_accepts_any_text_and_never_one_with_space_in_it(text: str) -> None:
    looks = migrate_v3._looks_like_address(text)
    assert isinstance(looks, bool)
    if any(char.isspace() for char in text) or not text:
        assert looks is False
    assert migrate_v3._url(legacy_entry(text)) in ("", text.strip())


# ---------------------------------------------------------------------------
# destroy_legacy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["password_only", "biometric_only", "device_id", "v1_0_0", "script_2025", "empty"])
def test_destroying_a_vault_leaves_nothing_and_says_what_it_deleted(name: str, old: LegacyDirectories) -> None:
    path, fixture = old.unpack(name)
    legacy = found(path)
    old.release(path)
    report = migrate_v3.destroy_legacy(legacy)  # the default asks for the keychain too: see the next test
    assert not path.exists()
    assert sorted(report.files_deleted) == sorted(str(path / item["path"]) for item in fixture["files"])
    assert (report.success, report.leftovers, report.errors) == (True, [], [])
    assert report.keychain_cleared is None
    assert migrate_v3.detect() is None
    with pytest.raises(VaultError, match="does not hold the IronDome 3.x vault that was detected"):
        migrate_v3.destroy_legacy(legacy)


def test_a_vault_that_is_not_at_the_standard_place_never_has_the_keychain_cleared_for_it(
    old: LegacyDirectories, our_keychain: Callable[[FakeTool], FakeTool]
) -> None:
    """Even with the keychain command to hand and the account's own home: these entries belong to another vault."""
    path, fixture = old.unpack("biometric_only")
    tool = our_keychain(FakeTool("darwin", keychain_of(fixture)))
    legacy = found(path)
    old.release(path)
    report = migrate_v3.destroy_legacy(legacy, keychain=True)
    assert (report.success, report.keychain_cleared) == (True, None)
    assert tool.commands == [] and sorted(tool.store) == ["auth_mode", "master_key", "recovery_hash"]


def standard_vault(old: LegacyDirectories, name: str) -> Tuple[LegacyVault, Dict[str, Any]]:
    """Unpack a fixture where 3.x itself kept its vault: ``~/.password_manager`` of the (redirected) home."""
    path, fixture = old.unpack(name, Path(os.path.expanduser("~")) / ".password_manager")
    old.release(path)
    return found(path), fixture


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_the_keychain_entries_go_with_the_vault_they_belong_to_key_first_and_before_any_file(
    platform: str, old: LegacyDirectories, our_keychain: Callable[[FakeTool], FakeTool],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy, fixture = standard_vault(old, "biometric_only")
    tool = our_keychain(FakeTool(platform, keychain_of(fixture)))
    salt = migrate_v3._base_dir(legacy.path, legacy.layout) / "salt.bin"
    salt_there: List[bool] = []

    def watched(command: List[str]) -> Tuple[int, bytes]:
        salt_there.append(salt.exists())
        return tool(command)

    monkeypatch.setattr(migrate_v3, "_run_tool", watched)
    report = migrate_v3.destroy_legacy(legacy)
    assert (report.success, report.keychain_cleared, report.errors) == (True, True, [])
    assert tool.store == {} and not legacy.path.exists()
    deleted = [command[5] for command in tool.commands if command[1] in ("delete-generic-password", "clear")]
    assert deleted == ["master_key", "recovery_hash", "auth_mode"]
    assert salt_there == [True] * 6  # every command ran while the salt was still there


def test_keychain_false_leaves_the_keychain_alone(
    old: LegacyDirectories, our_keychain: Callable[[FakeTool], FakeTool]
) -> None:
    legacy, fixture = standard_vault(old, "biometric_only")
    tool = our_keychain(FakeTool("darwin", keychain_of(fixture)))
    report = migrate_v3.destroy_legacy(legacy, keychain=False)
    assert (report.success, report.keychain_cleared) == (True, None)
    assert tool.commands == [] and len(tool.store) == 3


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_entries_that_were_never_there_count_as_cleared(
    platform: str, old: LegacyDirectories, our_keychain: Callable[[FakeTool], FakeTool]
) -> None:
    legacy, _ = standard_vault(old, "v1_1_0")  # written before the keychain was used at all
    tool = our_keychain(FakeTool(platform, {}))
    report = migrate_v3.destroy_legacy(legacy)
    assert (report.success, report.keychain_cleared, report.errors) == (True, True, [])
    assert len(tool.commands) == 6  # each of the three deleted, then confirmed absent


def test_a_keychain_entry_that_survives_makes_the_run_a_failure_but_the_files_still_go(
    old: LegacyDirectories, our_keychain: Callable[[FakeTool], FakeTool]
) -> None:
    legacy, fixture = standard_vault(old, "biometric_only")
    tool = our_keychain(FakeTool("darwin", keychain_of(fixture), sticky=("master_key",)))
    report = migrate_v3.destroy_legacy(legacy)
    assert (report.success, report.keychain_cleared, report.leftovers) == (False, False, [])
    assert report.errors == ["OS keychain entry IronDome/master_key is still there after deletion"]
    assert sorted(tool.store) == ["master_key"] and not legacy.path.exists()
    assert fixture["keyring"]["master_key"] not in " ".join(report.errors)


@pytest.mark.parametrize("platform", ["darwin", "linux"])
def test_the_systems_tool_clears_the_keychain_and_each_deletion_is_confirmed(
    platform: str, old: LegacyDirectories, our_keychain: Callable[..., Any]
) -> None:
    legacy, fixture = standard_vault(old, "biometric_password")  # holds auth_mode and recovery_hash, no key
    tool = our_keychain(FakeTool(platform, keychain_of(fixture)))
    report = migrate_v3.destroy_legacy(legacy)
    assert (report.success, report.keychain_cleared, report.errors) == (True, True, [])
    assert tool.store == {}
    verbs = [command[1] for command in tool.commands]
    if platform == "darwin":
        assert verbs == ["delete-generic-password", "find-generic-password"] * 3
        assert all("-w" not in command for command in tool.commands)  # presence is checked without the secret
    else:
        assert verbs == ["clear", "lookup"] * 3
    accounts = [command[5] for command in tool.commands]
    assert accounts == ["master_key", "master_key", "recovery_hash", "recovery_hash", "auth_mode", "auth_mode"]
    assert all(not any(output) for output in tool.outputs)


@pytest.mark.parametrize(
    ("platform", "tool_options", "complaint"),
    [
        ("darwin", {"statuses": {"delete-generic-password": 51}},
         "could not be deleted (security exited with status 51)"),
        ("darwin", {"statuses": {"delete-generic-password": -1}},
         "could not be deleted (security exited with status -1)"),
        ("darwin", {"sticky": ("auth_mode",)}, "is still there after deletion"),
        ("darwin", {"statuses": {"find-generic-password": 36}},
         "could not be confirmed deleted (security exited with status 36)"),
        ("linux", {"statuses": {"clear": 1}}, "could not be deleted (secret-tool exited with status 1)"),
        ("linux", {"sticky": ("auth_mode",)}, "is still there after deletion"),
        ("linux", {"statuses": {"lookup": 2}}, "could not be confirmed deleted (secret-tool exited with status 2)"),
    ],
    ids=["macos refuses", "macos does not answer", "macos entry survives", "macos cannot confirm",
         "linux refuses", "linux entry survives", "linux cannot confirm"],
)
def test_a_keychain_that_cannot_be_cleared_or_confirmed_is_never_reported_as_cleared(
    platform: str, tool_options: Dict[str, Any], complaint: str, old: LegacyDirectories,
    our_keychain: Callable[..., Any],
) -> None:
    legacy, fixture = standard_vault(old, "password_only")
    our_keychain(FakeTool(platform, keychain_of(fixture), **tool_options))
    report = migrate_v3.destroy_legacy(legacy)
    assert (report.success, report.keychain_cleared, report.leftovers) == (False, False, [])
    assert any(error.endswith(complaint) and error.startswith("OS keychain entry IronDome/") for error in report.errors)
    assert not legacy.path.exists()


@pytest.mark.parametrize("platform", ["darwin", "linux", "win32"])
def test_with_no_way_to_examine_the_keychain_the_run_does_not_claim_it_is_clean_and_says_why(
    platform: str, old: LegacyDirectories, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy, _ = standard_vault(old, "password_only")
    monkeypatch.setattr(migrate_v3, "_keychain_is_ours", lambda: True)
    monkeypatch.setattr(migrate_v3, "_PLATFORM", platform)
    monkeypatch.setattr(migrate_v3, "_keychain_tool", lambda: None)
    reason = migrate_v3.keychain_unreachable()
    assert reason is not None
    report = migrate_v3.destroy_legacy(legacy)
    assert (report.success, report.keychain_cleared, report.leftovers) == (False, False, [])
    assert report.errors == [
        f"OS keychain entry IronDome/{account} could not be examined: {reason}"
        for account in ("master_key", "recovery_hash", "auth_mode")
    ]
    assert not legacy.path.exists()


def test_the_salt_goes_first_then_the_stores_and_every_file_is_overwritten(
    old: LegacyDirectories, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, fixture = old.unpack("script_2025")
    (path / "secrets").mkdir()
    for name in ("salt.bin", ".passwords.enc"):
        shutil.copy2(path / name, path / "secrets" / name)
    legacy = found(path)
    old.release(path)
    order: List[str] = []
    real_delete = paths.secure_delete

    def recording_delete(target: Any) -> None:
        order.append(Path(target).relative_to(path).as_posix())
        real_delete(target)

    monkeypatch.setattr(paths, "secure_delete", recording_delete)
    report = migrate_v3.destroy_legacy(legacy)
    assert report.success and len(order) == len(fixture["files"]) + 2
    assert order[:2] == ["salt.bin", "secrets/salt.bin"]
    kinds = [0 if name.endswith("salt.bin") else 1 if name.endswith(".enc") else 2 for name in order]
    assert kinds == sorted(kinds)


def test_a_file_that_cannot_be_removed_is_reported_and_everything_else_is_still_destroyed(
    old: LegacyDirectories, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, fixture = old.unpack("password_only")
    stubborn = path / "backups" / ".passwords_backup_20260101-000400.enc"
    legacy = found(path)
    old.release(path)
    real_delete = paths.secure_delete

    def delete_all_but_one(target: Any) -> None:
        if Path(target) == stubborn:
            raise PermissionError(1, "Operation not permitted", str(target))
        real_delete(target)

    monkeypatch.setattr(paths, "secure_delete", delete_all_but_one)
    report = migrate_v3.destroy_legacy(legacy)
    assert report.success is False
    assert report.leftovers == [str(path), str(path / "backups"), str(stubborn)]
    assert report.errors == [f"could not delete {stubborn}: Operation not permitted"]
    assert len(report.files_deleted) == len(fixture["files"]) - 1 and str(stubborn) not in report.files_deleted
    assert sorted(item.relative_to(path).as_posix() for item in path.rglob("*")) == [
        "backups", "backups/.passwords_backup_20260101-000400.enc"
    ]
    assert not (path / "secrets").exists()


@pytest.mark.skipif(not hasattr(os, "chflags") or not hasattr(stat, "UF_IMMUTABLE"), reason="needs BSD file flags")
def test_a_file_the_system_will_not_let_go_is_a_leftover_for_real(old: LegacyDirectories) -> None:
    path, _ = old.unpack("password_only")
    locked = path / "settings.json"
    legacy = found(path)
    old.release(path)
    os.chflags(locked, stat.UF_IMMUTABLE)
    try:
        report = migrate_v3.destroy_legacy(legacy)
        assert report.success is False
        assert report.leftovers == [str(path), str(locked)]
        assert len(report.errors) == 1 and report.errors[0].startswith(f"could not delete {locked}: ")
        assert locked.exists() and not (path / "secrets").exists() and not (path / "backups").exists()
    finally:
        os.chflags(locked, 0)


@posix_only
@not_root
def test_read_only_files_and_directories_do_not_survive(old: LegacyDirectories) -> None:
    path, _ = old.unpack("password_only")
    legacy = found(path)
    old.release(path)
    for item in (path / "secrets").iterdir():
        item.chmod(0o400)
    (path / "secrets").chmod(0o500)
    (path / "backups").chmod(0o500)
    path.chmod(0o500)
    report = migrate_v3.destroy_legacy(legacy)
    assert (report.success, report.leftovers, report.errors) == (True, [], [])
    assert not path.exists()


def test_what_a_file_manager_leaves_behind_goes_with_the_vault(old: LegacyDirectories) -> None:
    path, fixture = old.unpack("password_only")
    for litter in (".DS_Store", "._settings.json", "secrets/.DS_Store", "backups/Thumbs.db", "desktop.ini"):
        (path / litter).write_bytes(b"\x00\x01")
    legacy = found(path)
    old.release(path)
    report = migrate_v3.destroy_legacy(legacy)
    assert report.success and not path.exists()
    assert len(report.files_deleted) == len(fixture["files"]) + 5


@posix_only
def test_a_link_is_removed_and_what_it_points_to_is_reported_not_touched(
    old: LegacyDirectories, isolated: Path
) -> None:
    path, fixture = old.unpack("password_only")
    synced = isolated / "cloud-folder"
    synced.mkdir()
    store = path / "secrets" / ".passwords.enc"
    shutil.move(str(store), str(synced / "passwords.enc"))
    store.symlink_to(synced / "passwords.enc")
    shutil.move(str(path / "backups"), str(synced / "backups"))
    (path / "backups").symlink_to(synced / "backups", target_is_directory=True)
    outside = snapshot(synced)
    old.watch(path)
    legacy = found(path)
    assert migrate_v3.read_entries(legacy, **credentials(fixture)) == expected_entries(fixture)  # links are followed
    old.check()
    old.release(path)

    report = migrate_v3.destroy_legacy(legacy)
    assert not path.exists() and snapshot(synced) == outside
    assert report.success is False
    targets = sorted([os.path.realpath(synced / "passwords.enc"), os.path.realpath(synced / "backups")])
    assert sorted(report.leftovers) == targets
    assert len(report.errors) == 2 and all("was a symbolic link" in error for error in report.errors)
    assert str(store) in report.files_deleted and str(path / "backups") in report.files_deleted


@posix_only
def test_a_file_with_a_second_name_is_unlinked_but_never_overwritten(old: LegacyDirectories, isolated: Path) -> None:
    """Overwriting through a hard link would destroy whatever the other name is, wherever it is."""
    path, _ = old.unpack("password_only")
    kept = isolated / "kept-elsewhere.json"
    os.link(path / "settings.json", kept)
    contents = kept.read_bytes()
    legacy = found(path)
    old.release(path)
    report = migrate_v3.destroy_legacy(legacy)
    assert not path.exists() and kept.read_bytes() == contents
    assert (report.success, report.leftovers) == (False, [])
    linked = path / "settings.json"
    assert report.errors == [f"{linked} has another name (a hard link); its contents remain under that name"]
    assert str(path / "settings.json") in report.files_deleted


@posix_only
def test_a_vault_reached_through_a_link_is_destroyed_along_with_the_link(
    old: LegacyDirectories, isolated: Path
) -> None:
    real, fixture = old.unpack("password_only", isolated / "encrypted-volume")
    paths.legacy_v3_dir().symlink_to(real, target_is_directory=True)
    legacy = migrate_v3.detect()
    assert legacy is not None and legacy.path == paths.legacy_v3_dir()
    assert migrate_v3.read_entries(legacy, **credentials(fixture)) == expected_entries(fixture)
    old.check()
    old.release(real)
    report = migrate_v3.destroy_legacy(legacy)
    assert (report.success, report.leftovers, report.errors) == (True, [], [])
    assert not real.exists() and not os.path.lexists(paths.legacy_v3_dir())


# ---------------------------------------------------------------------------
# destroy_legacy: what it refuses to do
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stranger",
    ["notes.txt", "vault-export.csv", "secrets/extra.key", "secrets/nested/salt.bin", "backups/readme.txt",
     "photos/holiday.jpg", ".passwords.enc.bak", "secrets/.passwords.enc~"],
)
def test_a_directory_holding_anything_3x_did_not_create_is_not_touched(stranger: str, old: LegacyDirectories) -> None:
    path, _ = old.unpack("password_only")
    (path / stranger).parent.mkdir(exist_ok=True)
    (path / stranger).write_bytes(b"someone's own file")
    old.watch(path)
    with pytest.raises(UsageError, match="holds things IronDome 3.x did not put there.*Nothing was deleted") as caught:
        migrate_v3.destroy_legacy(found(path), keychain=False)
    assert str(path / stranger.split("/")[0]) in str(caught.value)


def test_a_folder_that_merely_contains_a_file_called_salt_bin_cannot_be_wiped(
    isolated: Path, old: LegacyDirectories
) -> None:
    documents = isolated / "Documents"
    (documents / "taxes" / "2025").mkdir(parents=True)
    (documents / "taxes" / "2025" / "return.pdf").write_bytes(b"%PDF")
    (documents / "thesis.docx").write_bytes(b"PK")
    (documents / "settings.json").write_text("{}")
    (documents / "salt.bin").write_bytes(os.urandom(16))  # enough to look like the first program's layout
    old.watch(documents)
    legacy = migrate_v3.detect(documents)
    assert legacy is not None and legacy.layout == "flat" and not legacy.has_entries
    with pytest.raises(UsageError, match="holds things IronDome 3.x did not put there"):
        migrate_v3.destroy_legacy(legacy)


def test_the_listing_of_strangers_is_short_however_many_there_are(old: LegacyDirectories) -> None:
    path, _ = old.unpack("password_only")
    for number in range(40):
        (path / f"file-{number:02d}.txt").write_text("x")
    old.watch(path)
    with pytest.raises(UsageError, match=r"file-04\.txt and 35 more\)") as caught:
        migrate_v3.destroy_legacy(found(path))
    assert "file-05.txt" not in str(caught.value)


def test_a_directory_that_no_longer_holds_the_detected_vault_is_not_touched(
    old: LegacyDirectories, isolated: Path
) -> None:
    path, _ = old.unpack("password_only")
    legacy = found(path)
    with pytest.raises(VaultError, match="does not hold the IronDome 3.x vault that was detected.*Nothing was deleted"):
        migrate_v3.destroy_legacy(dataclasses.replace(legacy, salt=b"another vault's!"))
    other, _ = old.unpack("biometric_only", isolated / "another")
    with pytest.raises(VaultError, match="does not hold the IronDome 3.x vault that was detected"):
        migrate_v3.destroy_legacy(dataclasses.replace(legacy, path=other))
    with pytest.raises(VaultError, match="does not hold the IronDome 3.x vault that was detected"):
        migrate_v3.destroy_legacy(dataclasses.replace(legacy, path=isolated / "nowhere"))
    assert path.exists() and other.exists()


def test_the_new_vault_and_the_home_directory_are_never_inside_what_is_destroyed(
    old: LegacyDirectories, isolated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = old.unpack("password_only")
    legacy = found(path)
    monkeypatch.setenv("IRONDOME_HOME", str(path / "v4"))
    with pytest.raises(UsageError, match="the IronDome vault .* is inside it. Nothing was deleted"):
        migrate_v3.destroy_legacy(legacy)
    monkeypatch.setenv("IRONDOME_HOME", str(isolated / "irondome"))
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", str(path))
    with pytest.raises(UsageError, match="the IronDome device keys .* is inside it"):
        migrate_v3.destroy_legacy(legacy)
    monkeypatch.setenv("IRONDOME_DEVICE_DIR", str(isolated / "device"))

    home = Path(os.path.expanduser("~"))
    forge(home, layout="flat", payload=b"[]", vault_key=Fernet.generate_key(), master=False)  # dropped into the home
    old.watch(home)
    with pytest.raises(UsageError, match="your home directory .* is inside it"):
        migrate_v3.destroy_legacy(found(home))
    monkeypatch.setenv("HOME", str(path / "home-inside"))
    with pytest.raises(UsageError, match="your home directory .* is inside it"):
        migrate_v3.destroy_legacy(legacy)


@posix_only
@not_root
def test_a_directory_that_cannot_be_examined_is_not_touched(old: LegacyDirectories) -> None:
    path, _ = old.unpack("password_only")
    legacy = found(path)
    (path / "backups").chmod(0)
    try:
        with pytest.raises(UsageError, match="could not list .*backups.*Nothing was deleted"):
            migrate_v3.destroy_legacy(legacy)
    finally:
        (path / "backups").chmod(0o700)


@pytest.mark.parametrize(
    ("relative", "known"),
    [
        ("salt.bin", True),
        (".passwords.enc", True),
        (".login_attempts.dat", True),
        ("settings.json", True),
        ("password_manager.log", True),
        (".device_id", True),
        ("passwords_backup_20250401-000300.enc", True),
        ("secrets/salt.bin", True),
        ("secrets/.airspace.session", True),
        ("backups/.passwords_backup_20260101-000400.enc", True),
        ("backups/custom-name.enc", True),
        ("secrets", True),  # listed among the files only when it is a link standing in for the directory
        (".DS_Store", True),
        ("secrets/._salt.bin", True),
        ("settings.json.bak", False),
        ("SALT.BIN", False),
        ("secrets/settings.json", False),
        ("secrets/passwords_backup_x.enc", False),
        ("backups/notes.txt", False),
        ("backups/deeper/x.enc", False),
        ("other/salt.bin", False),
    ],
)
def test_what_counts_as_something_3x_created(relative: str, known: bool, isolated: Path) -> None:
    top = isolated / "vault"
    parents = [top / parent for parent in Path(relative).parents if str(parent) != "."]
    strangers = migrate_v3._unexpected(top, [top / relative], [top] + [p for p in parents if p.parent == top])
    assert (strangers == []) is known


# ---------------------------------------------------------------------------
# The whole journey, and what the module is made of
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ALL)
def test_detect_read_import_commit_reopen_verify_destroy(
    name: str, old: LegacyDirectories, make_vault: Callable[..., Any]
) -> None:
    path, fixture = old.unpack(name)
    legacy = migrate_v3.detect()
    assert legacy is not None
    entries = migrate_v3.read_entries(legacy, **credentials(fixture))
    vault, _ = make_vault()
    report = migrate_v3.import_into(vault, entries)
    assert (report.imported, report.skipped) == (len(fixture["entries"]), [])
    assert migrate_v3.verify(vault, entries) == []
    vault.commit()
    vault.close()

    with secret(PASSWORD) as new_password:
        reopened = open_vault(password=new_password, interactive=False)
    try:
        assert migrate_v3.verify(reopened, entries) == []
        assert len(reopened.entries) == len(fixture["entries"])
        for stored, planned in zip(fixture["entries"], migrate_v3._plan_names(entries)):
            entry = reopened.find(planned)
            kept = reopened.read_secret(entry)
            assert entry.name == planned
            assert (entry.username, kept.password, kept.notes) == (
                stored["username"], stored["password"], stored["notes"]
            )
            assert entry.created == epoch(stored["created_at"])
            assert entry.modified == epoch(stored.get("updated_at") or stored["created_at"])
            assert entry.url in ("", stored["website"].strip())
            assert (entry.kind, entry.agent, entry.tags, entry.has_totp) == ("login", "deny", [], False)
            assert (kept.totp, kept.fields, kept.history) == (None, {}, [])

        old.check()  # everything up to here only read the old directory
        old.release(path)
        destroyed = migrate_v3.destroy_legacy(legacy)
        assert destroyed.success and not path.exists() and migrate_v3.detect() is None
        assert migrate_v3.verify(reopened, entries) == []
    finally:
        reopened.close()


def test_the_module_imports_nothing_that_reaches_a_network_or_the_old_package_and_never_prints() -> None:
    source = Path(migrate_v3.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"socket", "ssl", "http", "urllib", "ftplib", "smtplib", "xmlrpc", "asyncio", "requests",
                 "password_manager", "keyring", "logging"}
    assert imported & forbidden == set()
    assert imported - {"irondome", "cryptography"} <= {
        "__future__", "base64", "binascii", "collections", "contextlib", "dataclasses", "errno", "fnmatch", "getpass",
        "hashlib", "json", "os", "pathlib", "pwd", "re", "secrets", "shutil", "stat", "subprocess", "sys",
        "time", "typing",
    }
    called = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert called & {"print", "input", "eval", "exec", "open", "__import__"} == set()
    # Every module it uses is named in an import statement, where the checks above (and irondome verify) see it.
    dynamic = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Call)
               and isinstance(node.func, ast.Attribute) and node.func.attr in ("import_module", "__import__")]
    assert dynamic == []
    assert "shell=True" not in source


def test_the_check_irondome_verify_runs_on_your_machine_finds_nothing_in_this_module() -> None:
    """``irondome verify --claim no-network`` and ``--claim one-dependency`` parse every module the same way."""
    from irondome import selftest

    found, problems = selftest.import_findings()
    assert "irondome/migrate_v3.py" in found["subprocess"]  # the module was scanned: the check is not vacuous
    assert [problem for problem in problems if "irondome/migrate_v3.py" in problem] == []


def test_every_public_name_is_there() -> None:
    assert "keychain_unreachable" in migrate_v3.__all__
    assert all(callable(getattr(migrate_v3, name)) or isinstance(getattr(migrate_v3, name), str)
               for name in migrate_v3.__all__)
