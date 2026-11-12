"""Claim ``owner-only-files``: every file is owner-only and every write is atomic.

Statement: every file IronDome creates is mode 0600 and every directory 0700
regardless of the process umask. The vault is replaced atomically: an
interrupted write leaves the previous vault intact, and a concurrent writer is
refused rather than overwritten.
"""

from __future__ import annotations

import os
import stat
import sys

import pytest

from conftest import PASSWORD, secret
from irondome import paths, unlock
from irondome.errors import VaultError
from irondome.vault import Secret
from support.claimkit import TOTP_SEED, add, grant, init, irondome_dirs, ok, session

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")


def modes(*roots):
    found = {}
    for root in roots:
        for current, dirs, names in os.walk(str(root)):
            for name in dirs + names:
                path = os.path.join(current, name)
                found[path] = stat.S_IMODE(os.lstat(path).st_mode)
    return found


@pytest.mark.parametrize("umask", [0o000, 0o022, 0o077])
def test_under_any_umask_every_file_is_0600_and_every_directory_0700(cli, umask):
    previous = os.umask(umask)
    try:
        init(cli)
        add(cli, "github", "a-token-value", "--alias", "GITHUB_TOKEN", totp=TOTP_SEED)
        ok(cli("edit", "github", "--username", "someone", "--password-stdin", stdin=PASSWORD + "\n"))
        grant(cli, "GITHUB_TOKEN")
        session(cli)
        ok(cli("config", "set", "snapshots", "5", "--password-stdin", stdin=PASSWORD + "\n"))
        ok(cli("bunker", "create", "bravo", "--password-stdin", stdin=f"{PASSWORD}\nbravo's own password\n"))
    finally:
        os.umask(previous)
    found = modes(irondome_dirs()["home"], irondome_dirs()["device"])
    assert len(found) > 10
    wrong = {path: oct(mode) for path, mode in found.items()
             if mode != (0o700 if os.path.isdir(path) else 0o600)}
    assert wrong == {}


def test_an_interrupted_write_leaves_the_previous_vault_intact(make_vault, monkeypatch):
    vault, _recovery = make_vault()
    with vault:
        vault.add("kept", Secret(password="the value that was committed"))
        vault.commit()
    before = paths.vault_file().read_bytes()
    live = os.path.realpath(str(paths.vault_file()))
    real_replace = os.replace

    def interrupted(source, target, **kwargs):
        if os.path.realpath(os.fspath(target)) == live:
            raise OSError("the machine lost power here")
        real_replace(source, target, **kwargs)

    with secret(PASSWORD) as password, unlock.open_vault(password=password, interactive=False) as opened:
        opened.add("lost", Secret(password="never written"))
        monkeypatch.setattr(os, "replace", interrupted)
        with pytest.raises(OSError, match="lost power"):
            opened.commit()
        monkeypatch.setattr(os, "replace", real_replace)
    assert paths.vault_file().read_bytes() == before
    assert [path.name for path in paths.home().iterdir() if path.name.startswith(".tmp-")] == []
    with secret(PASSWORD) as password, unlock.open_vault(password=password, interactive=False) as reopened:
        assert reopened.value(reopened.find("kept")) == "the value that was committed"
        assert not reopened.has_name("lost")


def test_a_writer_killed_mid_write_leaves_the_previous_vault_intact(cli, tmp_path):
    """A real process killed after writing half of a new vault: the old one is what is on disk."""
    init(cli)
    add(cli, "kept", "the value that was committed")
    before = paths.vault_file().read_bytes()
    code = (
        "import os, signal, sys\n"
        "from irondome import paths\n"
        "real = os.write\n"
        "def dying(fd, data):\n"
        "    real(fd, bytes(data)[: len(data) // 2])\n"
        "    os.kill(os.getpid(), signal.SIGKILL)\n"
        "os.write = dying\n"
        "paths.write_atomic(paths.vault_file(), b'x' * 100000)\n"
    )
    import subprocess

    killed = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=60)
    assert killed.returncode == -9
    assert paths.vault_file().read_bytes() == before
    assert ok(cli("get", "kept", "--password-stdin", stdin=PASSWORD + "\n")).stdout == "the value that was committed"


def test_a_concurrent_writer_is_refused_rather_than_overwritten(make_vault):
    vault, _recovery = make_vault()
    vault.close()
    with secret(PASSWORD) as password:
        first = unlock.open_vault(password=password, interactive=False)
        second = unlock.open_vault(password=password, interactive=False)
    with first, second:
        first.add("from the first", Secret(password="first value"))
        first.commit()
        second.add("from the second", Secret(password="second value"))
        with pytest.raises(VaultError, match="changed on disk"):
            second.commit()
    with secret(PASSWORD) as password, unlock.open_vault(password=password, interactive=False) as result:
        assert result.has_name("from the first") and not result.has_name("from the second")


def test_two_commands_writing_at_once_never_lose_a_change(cli):
    """Real processes: each add either lands or is refused; the vault always opens and holds what was reported."""
    import subprocess

    init(cli)
    base = [sys.executable, "-m", "irondome", "add"]
    env = dict(os.environ)
    processes = [
        subprocess.Popen(base + [f"entry-{index}", "--password-stdin", "--value-stdin"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        for index in range(4)
    ]
    landed = []
    for index, process in enumerate(processes):
        process.communicate(f"{PASSWORD}\nvalue-{index}\n".encode(), timeout=120)
        if process.returncode == 0:
            landed.append(f"entry-{index}")
        else:
            assert process.returncode == 6
    assert landed
    listing = ok(cli("ls", "--password-stdin", stdin=PASSWORD + "\n")).stdout
    assert all(name in listing for name in landed)


# -- the boundary ------------------------------------------------------------------


def test_boundary_the_files_are_ordinary_posix_files_of_this_user():
    """POSIX permissions are the protection: the owner, and root, can read them."""
    paths.ensure_dir(paths.home())
    paths.write_atomic(paths.home() / "probe", b"x")
    info = os.stat(str(paths.home() / "probe"))
    assert info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
