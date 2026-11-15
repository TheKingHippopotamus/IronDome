"""nuke, proved: what opens afterwards, what is left on disk, and what was never touched.

Every test checks a result from the outside. The SSD that keeps every block
is modelled by copying the vault root and the device root before ``nuke`` and
putting the copies back afterwards, bit for bit.

Backends
--------
* the file-based one, everywhere;
* the TPM backend against the FakeTpm of ``test_device_tpm``, everywhere, and
  against a software TPM in the Linux container (``tpm``; scripts/test-linux.sh);
* this Mac's Secure Enclave (``secure_enclave``), under the device policy
  only: nothing here can put a Touch ID prompt on the screen.

Nothing here points ``nuke.execute`` at anything outside the test's own
temporary directory. The filesystem root is only ever given to ``nuke.plan``,
with every call that could read or change a file wired to fail.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from test_device_tpm import FakeTpm, nv_handles, tpm2

from conftest import PASSWORD, secret
from irondome import audit, caps, config, device, nuke, paths
from irondome.device import linux_tpm, macos_se
from irondome.device.base import POLICY_DEVICE, Probe
from irondome.device.linux_tpm import Tpm2Backend
from irondome.errors import AuthError, HardwareError, IronDomeError, UsageError
from irondome.unlock import create_vault, open_vault, unlock
from irondome.vault import Secret, VaultFile

BRAVO_PASSWORD = "bravo has a master password of its own"

posix_only = pytest.mark.skipif(os.name == "nt", reason="needs POSIX: the TPM backend, file modes, pipes, links")
not_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores the directory permissions this relies on"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@contextmanager
def in_bunker(name: str) -> Iterator[None]:
    saved = os.environ.get(paths.ENV_BUNKER)
    os.environ[paths.ENV_BUNKER] = name
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop(paths.ENV_BUNKER, None)
        else:
            os.environ[paths.ENV_BUNKER] = saved


@dataclass
class Made:
    """A bunker as a test built it, and what its owner holds afterwards."""

    bunker: str
    password: str
    recovery: Optional[str]
    session: Optional[str]
    grant: Optional[str]
    snapshots: List[Path]
    value: str  # what the login "github" holds now


def build(bunker: str = "alpha", password: str = PASSWORD, *, commits: int = 3, tokens: bool = True) -> Made:
    """A vault whose one login was changed *commits* times (a snapshot each time), with a session and a grant."""
    with in_bunker(bunker):
        with secret(password) as typed:
            vault, recovery = create_vault(password=typed)
        with vault:
            entry = vault.add("github", Secret(password=f"{bunker}-0"), username="king")
            vault.set_alias("GITHUB_TOKEN", entry)
            vault.commit()
            for number in range(1, commits + 1):
                entry = vault.update(entry, secret=Secret(password=f"{bunker}-{number}"))
                vault.commit()
            session = caps.create_session(vault, ttl=3600) if tokens else None
            grant = caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=3600, uses=None)[0] if tokens else None
        snapshots = sorted(paths.backups_dir().glob("vault-*.irondome"))
    return Made(bunker, password, recovery, session, grant, snapshots, f"{bunker}-{commits}")


def opens(made: Made) -> str:
    """What the master password of *made* reads from its bunker's live vault."""
    with in_bunker(made.bunker), secret(made.password) as typed:
        with open_vault(password=typed, interactive=False, allow_touch=False) as vault:
            return vault.value(vault.find("github"))


def granted(made: Made) -> str:
    """What the grant of *made* gives its holder."""
    assert made.grant is not None
    with in_bunker(made.bunker), caps.open_grant(made.grant) as grant:
        return grant.value("GITHUB_TOKEN")


def recovered(made: Made, path: Optional[Path] = None) -> str:
    """What the recovery key of *made* reads from a vault file."""
    with in_bunker(made.bunker), open_vault(path=path, recovery_key=made.recovery, interactive=False) as vault:
        return vault.value(vault.find("github"))


def refuses_password(made: Made, path: Path) -> None:
    """The correct master password does not open the vault file at *path*."""
    file = VaultFile.load(path)
    with in_bunker(made.bunker), secret(made.password) as typed, pytest.raises((HardwareError, AuthError)):
        unlock(file, password=typed, interactive=False, allow_touch=False).wipe()


def assert_tokens_dead(made: Made) -> None:
    assert made.session is not None and made.grant is not None
    with in_bunker(made.bunker):
        with pytest.raises(AuthError):
            caps.open_session(made.session, VaultFile.load()).wipe()
        with pytest.raises(AuthError):
            caps.open_grant(made.grant).close()


def home_of(bunker: str = "alpha") -> Path:
    return paths.root() / "bunkers" / bunker


def device_dir_of(bunker: str = "alpha") -> Path:
    return paths.device_root() / "bunkers" / bunker


def key_files(bunker: str = "alpha") -> List[Path]:
    """The file-based backend's device secrets of *bunker*."""
    directory = device_dir_of(bunker)
    found = directory.glob("*.key") if directory.is_dir() else []
    return sorted(path for path in found if re.fullmatch(r"[0-9a-f]{32}\.key", path.name))


def tree(top: Path) -> Dict[str, Tuple[Any, ...]]:
    """Everything below *top*, never following a link: kind, mode, modification time, and bytes or link target."""
    found: Dict[str, Tuple[Any, ...]] = {}
    for current, directories, files in os.walk(str(top)):
        for name in directories + files:
            path = Path(current) / name
            info = os.lstat(str(path))
            content: Any = None
            if stat.S_ISLNK(info.st_mode):
                content = os.readlink(str(path))
            elif stat.S_ISREG(info.st_mode):
                content = path.read_bytes()
            found[str(path.relative_to(top))] = (stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode),
                                                 info.st_mtime_ns, content)
    return found


def contents(top: Path) -> Dict[str, Any]:
    """The bytes of every file below *top*, by relative name."""
    return {name: entry[3] for name, entry in tree(top).items() if stat.S_ISREG(entry[0])}


def files_below(*tops: Path) -> List[str]:
    """Every entry that is not a real directory below *tops*, as nuke names paths."""
    found = []
    for top in tops:
        for current, directories, files in os.walk(str(top)):
            linked = [name for name in directories if os.path.islink(os.path.join(current, name))]
            found += [os.path.join(current, name) for name in files + linked]
    return sorted(found)


def ssd_copy(tmp_path: Path) -> Tuple[Path, Path]:
    """Every block of both roots, as an SSD that never erased anything would keep them."""
    vault_side, device_side = tmp_path / "ssd" / "vault-root", tmp_path / "ssd" / "device-root"
    shutil.copytree(str(paths.root()), str(vault_side), symlinks=True)
    shutil.copytree(str(paths.device_root()), str(device_side), symlinks=True)
    return vault_side, device_side


def restore(copy: Path, target: Path) -> None:
    shutil.copytree(str(copy), str(target), symlinks=True, dirs_exist_ok=True)
    assert contents(target) == contents(copy), "a complete, bit-perfect copy is back"


@pytest.fixture
def fake_tpm(monkeypatch: pytest.MonkeyPatch) -> FakeTpm:
    """The TPM backend, talking to a FakeTpm (see test_device_tpm) instead of running tpm2-tools."""
    tpm = FakeTpm()
    monkeypatch.setattr(linux_tpm, "_run", tpm.run)
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "linux-tpm2")
    monkeypatch.setattr(Tpm2Backend, "probe", lambda self: Probe("linux-tpm2", True, True, False, "FakeTpm"))
    device._instances.clear()
    return tpm


@pytest.fixture
def chip(tpm: Tpm2Backend) -> Iterator[Tpm2Backend]:
    """The real backend on a TPM simulator; any index a failed test leaves behind is removed afterwards."""
    before = nv_handles()
    yield tpm
    for index in nv_handles() - before:
        tpm2("tpm2_nvundefine", index, "-C", "o", check=False)


# ---------------------------------------------------------------------------
# The claim: after nuke, no copy of the vault side opens (crypto-erase)
# ---------------------------------------------------------------------------


def prove_erasure(tmp_path: Path) -> Tuple[Made, nuke.NukeReport, Path]:
    """Build a bunker, keep a copy of every block of both roots, nuke, and put the vault side back.

    Returns the bunker, the report, and the copy of the device side.
    """
    made = build()
    assert len(made.snapshots) >= 4 and opens(made) == made.value and granted(made) == made.value
    vault_side, device_side = ssd_copy(tmp_path)

    report = nuke.execute()

    assert report.success, report.errors
    assert report.bunkers == ["alpha"] and report.recovery_bunkers == ["alpha"]
    assert report.device_keys_destroyed == 2, "the keyslot's device secret and the one sessions and grants use"
    assert not paths.root().exists() and not paths.device_root().exists()
    restore(vault_side, paths.root())
    return made, report, device_side


def assert_erased(made: Made) -> None:
    """The live file and every snapshot refuse the master password, both tokens are dead, the recovery key opens."""
    for path in [home_of() / "vault.irondome"] + made.snapshots:
        refuses_password(made, path)
    assert_tokens_dead(made)
    assert recovered(made) == made.value, "the documented exception: a recovery key needs no device"


def test_after_nuke_a_restored_vault_side_opens_with_the_recovery_key_only(tmp_path):
    made, report, _device_side = prove_erasure(tmp_path)

    assert report.hardware_backed is False
    assert_erased(made)


def test_file_based_erasure_is_only_as_final_as_the_disk(tmp_path):
    """THREAT_MODEL 5: the file-based device key is overwritten and unlinked, which on an SSD is best effort.

    If the old blocks of the device directory survive too, the vault opens
    again. That is exactly the case in which the report must not claim a
    chip did the erasure, so that the caller can say it was best effort.
    """
    made, report, device_side = prove_erasure(tmp_path)
    restore(device_side, paths.device_root())

    assert report.hardware_backed is False
    assert opens(made) == made.value
    assert granted(made) == made.value


@posix_only
def test_on_the_tpm_nothing_restored_opens_not_even_with_the_device_directory(fake_tpm, tmp_path):
    made, report, device_side = prove_erasure(tmp_path)
    assert report.hardware_backed is True and fake_tpm.handles() == set(), "the chip holds nothing of the bunker"

    restore(device_side, paths.device_root())  # its index registry is back: numbers of indices that are gone

    assert_erased(made)
    assert fake_tpm.failed_tries == 0, "asking for an index that is gone costs no guess"


@pytest.mark.tpm
def test_real_tpm_nothing_restored_opens_not_even_with_the_device_directory(chip, tmp_path):
    made, report, device_side = prove_erasure(tmp_path)
    assert report.hardware_backed is True

    restore(device_side, paths.device_root())

    assert_erased(made)


@pytest.mark.secure_enclave
def test_secure_enclave_after_nuke_a_restored_vault_side_opens_with_the_recovery_key_only(secure_enclave, tmp_path):
    made, report, device_side = prove_erasure(tmp_path)
    assert report.hardware_backed is True
    assert_erased(made)

    # THREAT_MODEL 5: what nuke deletes is the sealed blob; recovered from the disk it works again, but only
    # inside this Mac's Secure Enclave.
    restore(device_side, paths.device_root())
    assert opens(made) == made.value


# ---------------------------------------------------------------------------
# Bunkers
# ---------------------------------------------------------------------------


def test_removing_one_bunker_destroys_it_and_leaves_the_other_exactly_as_it_was():
    alpha = build("alpha")
    bravo = build("bravo", BRAVO_PASSWORD)
    paths.set_default_bunker("bravo")
    bravo_keys = key_files("bravo")
    assert len(bravo_keys) == 2 and len(key_files("alpha")) == 2
    alpha_sides = [home_of("alpha"), device_dir_of("alpha")]
    before = [tree(side) for side in alpha_sides]
    planned = nuke.plan(bunker="bravo")

    report = nuke.execute(bunker="bravo")

    assert report.success, report.errors
    assert report.bunkers == ["bravo"] and report.recovery_bunkers == ["bravo"]
    assert report.files_deleted == planned.files
    assert report.device_keys_destroyed == sum(key.present for key in planned.device_keys) == 2
    assert not any(os.path.lexists(str(key)) for key in bravo_keys)
    assert not os.path.lexists(str(home_of("bravo"))) and not os.path.lexists(str(device_dir_of("bravo")))
    assert paths.bunkers() == ["alpha"]
    assert [tree(side) for side in alpha_sides] == before, "not one byte, mode or timestamp of alpha changed"
    assert opens(alpha) == alpha.value
    assert granted(alpha) == alpha.value
    with in_bunker("alpha"):
        caps.open_session(str(alpha.session), VaultFile.load()).wipe()

    again = nuke.execute(bunker="bravo")
    assert again.success and again.bunkers == [] and again.files_deleted == [] and again.device_keys_destroyed == 0
    assert (paths.root() / "default-bunker").is_file()

    report = nuke.execute()

    assert report.success, report.errors
    assert report.bunkers == ["alpha"]
    assert paths.bunkers() == []
    assert not paths.root().exists() and not paths.device_root().exists(), "the default-bunker setting went too"
    for made in (alpha, bravo):  # last, because opening a grant makes its bunker's capability directory again
        with in_bunker(made.bunker), pytest.raises(AuthError):
            caps.open_grant(str(made.grant))


# ---------------------------------------------------------------------------
# Completeness
# ---------------------------------------------------------------------------


def test_plan_lists_exactly_what_execute_deletes_and_nothing_of_irondome_is_left(monkeypatch):
    build("alpha")
    build("bravo", BRAVO_PASSWORD)
    paths.set_default_bunker("bravo")
    with in_bunker("alpha"):
        config.set_value("snapshots", "5")
        assert audit.archive() is not None
        with secret(PASSWORD) as typed, open_vault(password=typed, interactive=False, allow_touch=False) as vault:
            caps.create_grant(vault, ["GITHUB_TOKEN"], ttl=600)  # and a new audit log after the archived one
        # What a crash in the middle of paths.write_atomic leaves, named the way it names them, and a re-key's
        # staging file.
        for directory in (paths.home(), paths.backups_dir(), paths.caps_dir(), paths.device_dir(), paths.root()):
            handle, _name = tempfile.mkstemp(prefix=".tmp-", dir=str(directory))
            os.close(handle)
        shutil.copyfile(str(paths.vault_file()), str(paths.home() / f".tmp-rekey-{os.urandom(8).hex()}.irondome"))
    monkeypatch.delenv("IRONDOME_SE_HELPER", raising=False)
    helper = macos_se._helper_path()  # the compiled Secure Enclave helper, and an interrupted build of it
    paths.ensure_dir(helper.parent)
    helper.write_bytes(b"\xcf\xfa\xed\xfe a compiled helper")
    helper.with_name(f".build-{os.getpid()}-{helper.name}").write_bytes(b"half a helper")
    everything = files_below(paths.root(), paths.device_root())
    planned = nuke.plan()

    report = nuke.execute()

    assert report.success, report.errors
    assert report.files_deleted == planned.files
    assert sorted(planned.files) == everything, "everything IronDome made is in the plan, and nothing else"
    assert planned.foreign == report.foreign == [] and report.leftovers == []
    present = [key for key in planned.device_keys if key.present]
    assert len(present) == report.device_keys_destroyed == 4, "in each bunker: the keyslot's and the capabilities'"
    assert sorted((key.bunker, key.backend, key.policy) for key in present) == [
        ("alpha", "software", POLICY_DEVICE)] * 2 + [("bravo", "software", POLICY_DEVICE)] * 2
    assert planned.capabilities == 5 and planned.bunkers == ["alpha", "bravo"]
    assert not paths.root().exists() and not paths.device_root().exists()

    again = nuke.execute()
    assert again.success, again.errors
    assert again.bunkers == [] and again.files_deleted == [] and again.device_keys_destroyed == 0
    assert nuke.plan().nothing_to_do


# ---------------------------------------------------------------------------
# Safety: what is not IronDome's
# ---------------------------------------------------------------------------


def plant(files: Dict[Path, bytes]) -> None:
    for path, data in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def test_files_nuke_does_not_recognise_are_never_deleted_and_are_listed():
    build()
    home, device_dir, root, device_root = home_of(), device_dir_of(), paths.root(), paths.device_root()
    # Names close to IronDome's own, in each place it keeps files, and directories it does not make.
    near_misses = {
        root: ["Cargo.lock", ".tmp-not-ours", "default-bunker.bak", "notes.txt"],
        root / "bunkers": ["readme.txt"],
        home: ["yarn.lock", "vault.irondome.bak", "config.json~", ".tmp-x", "audit-notes.log"],
        home / "backups": ["vault-1.irondome", "export.irondome", "mine.lock"],
        home / "caps": ["notes.json", "0123abcd.json", "x.lock"],
        device_dir: ["server.key", "notes.lock", "settings.json", "ABCDEF0123456789ABCDEF0123456789.key"],
        device_root: ["notes.txt", "some.lock"],
        device_root / "helper": ["my-notes.txt", "irondome-se-short"],
    }
    planted = {directory / name: f"{directory.name}/{name} is not IronDome's\n".encode() for directory, names in
               near_misses.items() for name in names}
    strangers = {
        home / "photos": home / "photos" / "vault.irondome",
        root / "bunkers" / "Not A Bunker": root / "bunkers" / "Not A Bunker" / "vault.irondome",
        device_dir / "keys": device_dir / "keys" / ("0" * 32 + ".key"),
    }
    planted.update({inner: b"inside a directory IronDome did not make\n" for inner in strangers.values()})
    plant(planted)
    foreign = sorted([str(path) for path in planted if path.parent not in strangers] + list(map(str, strangers)))
    planned = nuke.plan()

    report = nuke.execute()

    assert report.success, report.errors
    assert all(path.read_bytes() == data for path, data in planted.items()), "every one of them is intact"
    assert sorted(planned.foreign) == sorted(report.foreign) == foreign
    assert not set(planned.files) & set(foreign)
    assert files_below(root, device_root) == sorted(str(path) for path in planted), "and nothing of IronDome's is left"
    assert report.device_keys_destroyed == 2 and key_files() == []


@posix_only
def test_a_link_where_irondome_keeps_a_file_is_removed_and_what_it_points_to_is_untouched(tmp_path):
    made = build()
    outside = tmp_path / "outside"
    plant({
        outside / "another-programs-settings.json": b'{"theme": "dark"}\n',
        outside / "a-document.txt": b"precious words\n",
        outside / "helper-elsewhere" / "irondome-se-0123456789abcdef": b"another helper\n",
    })
    assert made.grant is not None
    capability = home_of() / "caps" / f"{caps.parse_token(made.grant)[1]}.json"
    capability.unlink()
    links = {
        home_of() / "config.json": outside / "another-programs-settings.json",
        capability: outside / "a-document.txt",
        paths.device_root() / "helper": outside / "helper-elsewhere",
        home_of() / "audit.log.lock": outside / "nothing-there",
    }
    for link, target in links.items():
        link.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(str(link)):
            link.unlink()
        os.symlink(str(target), str(link))
    before = tree(outside)

    report = nuke.execute()

    assert report.success, report.errors
    assert tree(outside) == before, "byte for byte, mode for mode, timestamp for timestamp"
    assert not any(os.path.lexists(str(link)) for link in links)
    assert set(map(str, links)) <= set(report.files_deleted)
    assert key_files() == [] and not paths.root().exists() and not paths.device_root().exists()


@posix_only
def test_a_link_that_may_lead_to_a_vault_or_a_device_key_is_removed_untouched_and_reported(tmp_path):
    made = build()
    outside = tmp_path / "outside"
    outside.mkdir()
    live = home_of() / "vault.irondome"
    shutil.move(str(live), str(outside / "vault.irondome"))
    shutil.move(str(home_of() / "backups"), str(outside / "snapshots"))
    plant({
        outside / "key-lookalike": os.urandom(32),
        outside / "charlie" / "vault.irondome": b"what a link named charlie leads to\n",
    })
    links = {
        live: outside / "vault.irondome",
        home_of() / "backups": outside / "snapshots",
        device_dir_of() / ("e" * 32 + ".key"): outside / "key-lookalike",
        home_of("charlie"): outside / "charlie",
    }
    for link, target in links.items():
        os.symlink(str(target), str(link))
    before = tree(outside)

    report = nuke.execute()

    assert not report.success
    assert tree(outside) == before
    assert not any(os.path.lexists(str(link)) for link in links)
    for link, target in links.items():
        assert [error for error in report.errors if str(link) in error and str(target) in error], link
    assert len(report.errors) == len(links)
    assert report.device_keys_destroyed == 2 and key_files() == [], "alpha's real device keys are gone all the same"
    for path in [outside / "vault.irondome"] + sorted((outside / "snapshots").glob("vault-*.irondome")):
        refuses_password(made, path)  # what was left behind the links is crypto-erased with the rest


@posix_only
def test_a_second_name_of_a_file_keeps_its_contents_unless_the_file_is_a_device_key(tmp_path):
    """A hard link is the same file under two names: overwriting one overwrites the other.

    So a file of IronDome's that has a name outside the tree too is only
    unlinked, and the other name keeps every byte. A device key is the one
    exception: every name of it is the key, and erasing the key is the point.
    """
    made = build()
    outside = tmp_path / "outside"
    outside.mkdir()
    assert made.grant is not None
    capability = home_of() / "caps" / f"{caps.parse_token(made.grant)[1]}.json"
    shared = {home_of() / "audit.log": outside / "audit-kept-by-a-backup-tool.log",
              capability: outside / "capability-kept-by-a-backup-tool.json",
              made.snapshots[0]: outside / "snapshot-kept-by-a-backup-tool.irondome"}
    for inside, other in shared.items():
        os.link(str(inside), str(other))
    kept = {other: other.read_bytes() for other in shared.values()}
    key = key_files()[0]
    key_copy = outside / "device-key-kept-by-a-backup-tool"
    os.link(str(key), str(key_copy))
    secret_bytes = key_copy.read_bytes()

    report = nuke.execute()

    assert report.success, report.errors
    assert {other: other.read_bytes() for other in shared.values()} == kept, "the other names kept every byte"
    assert not any(os.path.lexists(str(inside)) for inside in shared)
    assert key_copy.read_bytes() != secret_bytes, "the key's other name held the key: it is destroyed too"
    refuses_password(made, outside / "snapshot-kept-by-a-backup-tool.irondome")


@posix_only
def test_a_link_in_place_of_a_bunkers_directory_is_never_followed(tmp_path):
    vault_elsewhere, device_elsewhere = tmp_path / "somebody" / "projects", tmp_path / "somebody" / "keys"
    plant({
        vault_elsewhere / "alpha" / "config.json": b'{"not": "irondome"}\n',
        vault_elsewhere / "alpha" / "vault.irondome": b"not a vault\n",
        device_elsewhere / "alpha" / ("a" * 32 + ".key"): os.urandom(32),
        device_elsewhere / "alpha" / ("b" * 32 + ".json"): b"{}",
    })
    for base, target in ((paths.root(), vault_elsewhere), (paths.device_root(), device_elsewhere)):
        base.mkdir(parents=True)
        os.symlink(str(target), str(base / "bunkers"))
    before = tree(tmp_path / "somebody")

    alone = nuke.execute(bunker="alpha")

    assert not alone.success and alone.device_keys_destroyed == 0
    assert len([error for error in alone.errors if "reached through the symbolic link" in error]) == 2
    assert os.path.islink(str(paths.root() / "bunkers")), "other bunkers share it: removing one leaves it"
    assert tree(tmp_path / "somebody") == before

    everything = nuke.execute()

    assert not everything.success and everything.device_keys_destroyed == 0
    assert not os.path.lexists(str(paths.root() / "bunkers")) and not os.path.lexists(str(paths.device_root() /
                                                                                          "bunkers"))
    assert len([error for error in everything.errors if "symbolic link" in error]) == 2
    assert tree(tmp_path / "somebody") == before


# ---------------------------------------------------------------------------
# Safety: roots that must never be cleaned
# ---------------------------------------------------------------------------

#: Everything that could read, write or remove a file: wired to fail while nuke is asked to run.
_TRIPPED = ("scandir", "listdir", "open", "unlink", "remove", "rmdir", "rename", "replace", "mkdir", "chmod", "link",
            "symlink")


@contextmanager
def tripwires(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def tripped(*args: Any, **kwargs: Any) -> None:
        raise AssertionError(f"nuke reached the filesystem before refusing: {args!r}")

    with monkeypatch.context() as wired:
        for name in _TRIPPED:
            wired.setattr(os, name, tripped)
        wired.setattr(paths, "secure_delete", tripped)
        yield


def irondome_shaped(top: Path) -> None:
    """Files under the names nuke deletes, as they would be if *top* were a root."""
    plant({
        top / "default-bunker": b"alpha\n",
        top / ".tmp-abcdefgh": b"half-written\n",
        top / "Cargo.lock": b"# a project lock file\n",
        top / "bunkers" / "alpha" / "vault.irondome": b"someone's file\n",
        top / "bunkers" / "alpha" / ("c" * 32 + ".key"): os.urandom(32),
        top / "helper" / "irondome-se-0123456789abcdef": b"a binary\n",
    })


@pytest.mark.parametrize("variable", ["IRONDOME_HOME", "IRONDOME_DEVICE_DIR"])
@pytest.mark.parametrize(
    "where",
    ["home", "home, relative", "home, with a tilde", "home, through a link", "a parent of home",
     "the account's home", "a parent of the account's home"],
)
def test_a_home_directory_or_a_parent_of_one_is_refused_before_anything_is_touched(
    variable, where, monkeypatch, tmp_path
):
    home = Path(os.environ["HOME"])
    account = tmp_path / "accounts" / "someone"  # what the account database says, whatever $HOME says
    for top in (home, account):
        irondome_shaped(top)
    monkeypatch.setattr(nuke, "_account_home", lambda: str(account))
    link = tmp_path / "link-to-home"
    os.symlink(str(home), str(link))
    value = {
        "home": str(home),
        "home, relative": ".",
        "home, with a tilde": "~",
        "home, through a link": str(link),
        "a parent of home": str(home.parent),
        "the account's home": str(account),
        "a parent of the account's home": str(account.parent),
    }[where]
    monkeypatch.chdir(str(home))
    monkeypatch.setenv(variable, value)
    before = tree(tmp_path)

    with tripwires(monkeypatch):
        for attempt in (nuke.plan, lambda: nuke.plan("alpha"), nuke.execute, lambda: nuke.execute(bunker="alpha")):
            with pytest.raises(UsageError, match=f"refusing to run nuke .*Check {variable}. Nothing was touched"):
                attempt()

    assert tree(tmp_path) == before


@pytest.mark.parametrize("variable", ["IRONDOME_HOME", "IRONDOME_DEVICE_DIR"])
def test_the_filesystem_root_is_refused_before_anything_is_read(variable, monkeypatch):
    """Only plan, which changes nothing, is ever pointed at "/"; execute shares its refusal (test above)."""
    top = os.path.abspath(os.sep)
    monkeypatch.setenv(variable, top)
    with tripwires(monkeypatch), pytest.raises(UsageError, match="not a filesystem root"):
        nuke.plan()


@pytest.mark.parametrize("top", ["/", "/tmp", "/Users", "/home", "/var", "/private"])
def test_top_level_directories_are_never_a_root(top):
    with pytest.raises(UsageError, match="refusing to run nuke"):
        nuke._checked_root(Path(top), "vault directory", "IRONDOME_HOME")


# ---------------------------------------------------------------------------
# Safety: what cannot be deleted, and what cannot be read
# ---------------------------------------------------------------------------


@posix_only
@not_root
def test_a_file_that_cannot_be_deleted_fails_the_run_and_is_named(tmp_path):
    made = build()
    backups = home_of() / "backups"
    snapshots = sorted(str(path) for path in backups.iterdir())
    assert len(snapshots) >= 4
    os.chmod(str(backups), 0o500)
    try:
        report = nuke.execute()
    finally:
        os.chmod(str(backups), 0o700)

    assert not report.success
    assert sorted(report.leftovers) == snapshots
    assert all([error for error in report.errors if snapshot in error] for snapshot in snapshots)
    assert report.device_keys_destroyed == 2 and key_files() == [], "the erasure did not wait for the files"
    for snapshot in snapshots:  # nothing that is left opens: its device key is gone, and it was overwritten
        with in_bunker("alpha"), secret(made.password) as typed, pytest.raises(IronDomeError):
            unlock(VaultFile.load(Path(snapshot)), password=typed, interactive=False, allow_touch=False).wipe()

    again = nuke.execute()
    assert again.success, again.errors
    assert not paths.root().exists() and not paths.device_root().exists()


@posix_only
@not_root
def test_a_device_key_that_cannot_be_unlinked_is_still_destroyed_in_place(tmp_path):
    made = build()
    vault_side, _device_side = ssd_copy(tmp_path)
    keys = key_files()
    os.chmod(str(device_dir_of()), 0o500)
    try:
        report = nuke.execute()
    finally:
        os.chmod(str(device_dir_of()), 0o700)

    assert not report.success
    assert [error for error in report.errors if "device key" in error]
    assert key_files() == keys and sorted(map(str, keys)) == sorted(path for path in report.leftovers
                                                                    if path.endswith(".key"))
    restore(vault_side, paths.root())
    with pytest.raises(AuthError, match="wrong master password"):  # the file is there; what it held is not
        opens(made)
    assert_tokens_dead(made)
    assert recovered(made) == made.value

    again = nuke.execute()
    assert again.success, again.errors


#: Ways a vault file can be damaged, applied to the live file and to every snapshot.
DAMAGE = {
    "truncated": lambda data: data[: len(data) // 2],
    "empty": lambda data: b"",
    "noise": lambda data: os.urandom(len(data)),
    "another document": lambda data: b'{"format": "irondome-vault", "version": 4, "keyslots": "none"}\n',
}


@pytest.mark.parametrize("damage", sorted(DAMAGE))
def test_a_damaged_vault_still_ends_with_every_device_secret_destroyed(damage):
    made = build()
    keys = key_files()
    for path in [home_of() / "vault.irondome"] + made.snapshots:
        path.write_bytes(DAMAGE[damage](path.read_bytes()))
    planned = nuke.plan()
    assert planned.unreadable_vaults == ["alpha"]
    assert [key.present for key in planned.device_keys] == [True, True], "found in the device directory instead"

    report = nuke.execute()

    assert report.success, report.errors
    assert report.device_keys_destroyed == 2 and not any(os.path.lexists(str(key)) for key in keys)
    assert not paths.root().exists() and not paths.device_root().exists()


@posix_only
def test_on_the_tpm_a_damaged_vault_still_ends_with_every_index_undefined(fake_tpm):
    made = build()
    assert len(fake_tpm.handles()) == 2
    for path in [home_of() / "vault.irondome"] + made.snapshots:
        path.write_bytes(b"")

    report = nuke.execute()

    assert report.success, report.errors
    assert report.device_keys_destroyed == 2 and fake_tpm.handles() == set()


@posix_only
def test_a_pipe_or_a_directory_in_place_of_a_vault_file_neither_stalls_nor_stops_nuke():
    made = build()
    live = home_of() / "vault.irondome"
    live.unlink()
    os.mkfifo(str(live))  # nobody will ever write to it: reading it would wait forever
    snapshot = made.snapshots[0]
    snapshot.unlink()
    snapshot.mkdir()  # a directory under a snapshot's name is not IronDome's

    def stalled(*_: Any) -> None:
        raise AssertionError("nuke waited on a pipe")

    previous = signal.signal(signal.SIGALRM, stalled)
    signal.alarm(60)
    try:
        planned = nuke.plan()
        report = nuke.execute()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)

    assert planned.unreadable_vaults == ["alpha"]
    assert report.success, report.errors
    assert report.device_keys_destroyed == 2 and key_files() == []
    assert not os.path.lexists(str(live)) and report.foreign == [str(snapshot)] and snapshot.is_dir()


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=40),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=12), inner, max_size=4),
    max_leaves=12,
)
_VALUES = st.one_of(
    _JSON,
    st.sampled_from(
        ["software", "macos-se", "linux-tpm2", "device", "biometry", "../../outside", "..", "/", "0x01800000",
         "0" * 32, "f" * 32, "F" * 32]
    ),
)
_DESCRIPTORS = st.one_of(_JSON, st.dictionaries(st.sampled_from(["backend", "policy", "ref", "nv_index"]), _VALUES))


@pytest.fixture
def template() -> Dict[str, Any]:
    """A real vault file and its device key, kept as bytes; nothing of them is left on disk."""
    build(commits=0, tokens=False)
    kept = {"document": json.loads((home_of() / "vault.irondome").read_bytes()),
            "keys": {path.name: path.read_bytes() for path in key_files()}}
    assert nuke.execute().success
    return kept


@settings(max_examples=40, deadline=None, database=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(descriptors=st.lists(_DESCRIPTORS, min_size=1, max_size=3), noise=st.binary(max_size=64), raw=st.booleans())
def test_whatever_a_vault_file_says_nuke_destroys_its_bunkers_keys_and_touches_nothing_else(
    template, tmp_path, monkeypatch, descriptors, noise, raw
):
    monkeypatch.setattr(linux_tpm, "_run", FakeTpm().run)  # a descriptor naming a TPM index meets an empty chip
    for top in (paths.root(), paths.device_root()):
        shutil.rmtree(str(top), ignore_errors=True)
    outside = tmp_path / "outside"
    shutil.rmtree(str(outside), ignore_errors=True)
    canaries = {outside / "canary": b"outside both roots\n", device_dir_of("bravo") / ("f" * 32 + ".key"): b"b" * 32}
    plant(canaries)
    plant({device_dir_of() / name: data for name, data in template["keys"].items()})
    document = json.loads(json.dumps(template["document"]))
    for index, slot in enumerate(document["keyslots"]):
        slot["device"] = descriptors[index % len(descriptors)]
    plant({home_of() / "vault.irondome": noise if raw else json.dumps(document).encode("utf-8")})

    nuke.plan(bunker="alpha")
    report = nuke.execute(bunker="alpha")

    assert key_files("alpha") == [], report.errors
    assert all(path.read_bytes() == data for path, data in canaries.items())
    assert files_below(paths.root(), paths.device_root(), outside) == sorted(map(str, canaries))


# ---------------------------------------------------------------------------
# Safety: one bunker's nuke never reaches another bunker's device secret
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", ["software", pytest.param("macos-se", marks=pytest.mark.secure_enclave)])
def test_a_vault_file_copied_from_another_bunker_cannot_make_nuke_touch_that_bunker(backend, request):
    """A file-based or Secure Enclave descriptor names a file in its own bunker's device directory, always."""
    if backend == "macos-se":
        request.getfixturevalue("secure_enclave")
    alpha = build("alpha")
    build("bravo", BRAVO_PASSWORD)
    shutil.copyfile(str(home_of("alpha") / "vault.irondome"), str(home_of("bravo") / "vault.irondome"))
    for snapshot in alpha.snapshots:
        shutil.copyfile(str(snapshot), str(home_of("bravo") / "backups" / snapshot.name))
    alpha_sides = [home_of("alpha"), device_dir_of("alpha")]
    before = [tree(side) for side in alpha_sides]

    report = nuke.execute(bunker="bravo")

    assert report.success, report.errors
    assert report.device_keys_destroyed == 2, "bravo's own two, and nothing of alpha's"
    assert not os.path.lexists(str(home_of("bravo"))) and not os.path.lexists(str(device_dir_of("bravo")))
    assert [tree(side) for side in alpha_sides] == before
    assert opens(alpha) == alpha.value and granted(alpha) == alpha.value


def keyslot_index(bunker: str) -> str:
    """The NV index of a bunker's password keyslot, as its vault file names it."""
    document = json.loads((home_of(bunker) / "vault.irondome").read_bytes())
    (index,) = [slot["device"]["nv_index"] for slot in document["keyslots"] if slot.get("device")]
    return str(index)


def name_alphas_index(how: str) -> None:
    """Make bravo name a TPM index of alpha's, the way an accident or an edit would."""
    if how == "vault file copied":
        shutil.copyfile(str(home_of("alpha") / "vault.irondome"), str(home_of("bravo") / "vault.irondome"))
    elif how == "descriptor edited":
        path = home_of("bravo") / "vault.irondome"
        document = json.loads(path.read_bytes())
        for slot in document["keyslots"]:
            if slot.get("device"):
                slot["device"]["nv_index"] = keyslot_index("alpha")
        path.write_bytes(json.dumps(document).encode("utf-8"))
    else:
        shutil.copyfile(str(device_dir_of("alpha") / "tpm2-nv-indices.json"),
                        str(device_dir_of("bravo") / "tpm2-nv-indices.json"))


@posix_only
@pytest.mark.parametrize("how", ["vault file copied", "descriptor edited", "device directory copied"])
def test_on_the_tpm_removing_one_bunker_never_destroys_an_index_another_bunker_uses(fake_tpm, how):
    alpha = build("alpha")
    alphas = fake_tpm.handles()
    build("bravo", BRAVO_PASSWORD)
    bravos = fake_tpm.handles() - alphas
    bravo_keyslot = keyslot_index("bravo")
    assert len(alphas) == len(bravos) == 2
    name_alphas_index(how)

    report = nuke.execute(bunker="bravo")

    assert alphas <= fake_tpm.handles(), "every index alpha uses is still in the chip"
    assert opens(alpha) == alpha.value and granted(alpha) == alpha.value
    assert not report.success and report.errors
    assert all("also used by bunker alpha" in error for error in report.errors)
    assert bravo_keyslot not in fake_tpm.handles(), "bravo's own keyslot index is gone"
    if how != "device directory copied":
        assert not bravos & fake_tpm.handles(), "and so is the one its sessions and grants used"
    assert not os.path.lexists(str(home_of("bravo"))) and not os.path.lexists(str(device_dir_of("bravo")))

    everything = nuke.execute()

    assert everything.success, everything.errors
    assert not alphas & fake_tpm.handles()


@pytest.mark.tpm
def test_real_tpm_removing_one_bunker_never_destroys_an_index_another_bunker_uses(chip):
    before = nv_handles()  # the suite shares one TPM: whatever earlier tests left in it is not alpha's
    alpha = build("alpha")
    alphas = nv_handles() - before
    assert len(alphas) == 2
    build("bravo", BRAVO_PASSWORD)
    name_alphas_index("vault file copied")

    report = nuke.execute(bunker="bravo")

    assert alphas <= nv_handles()
    assert opens(alpha) == alpha.value and granted(alpha) == alpha.value
    assert not report.success and all("also used by bunker alpha" in error for error in report.errors)
    assert nuke.execute().success
    assert not alphas & nv_handles()


# ---------------------------------------------------------------------------
# Through the command line
# ---------------------------------------------------------------------------


def test_the_command_line_reports_exactly_what_was_destroyed_and_what_was_left(cli):
    made = build()
    strays = {paths.root() / "Cargo.lock": b"# not IronDome's\n", device_dir_of() / "server.key": b"not ours\n"}
    plant(strays)

    result = cli("nuke", "--yes-destroy-everything", "--password-stdin", "--json", stdin=PASSWORD + "\n")

    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    planned, done = document["plan"], document["report"]
    assert document["success"] is True and done["files_deleted"] == planned["files"]
    assert done["device_keys_destroyed"] == sum(key["present"] for key in planned["device_keys"]) == 2
    assert sorted(done["foreign"]) == sorted(planned["foreign"]) == sorted(map(str, strays))
    assert all(path.read_bytes() == data for path, data in strays.items())
    told = result.stdout + result.stderr
    for value in (PASSWORD, made.value, made.recovery, made.session, made.grant):
        assert value and value not in told
    assert files_below(paths.root(), paths.device_root()) == sorted(map(str, strays))
