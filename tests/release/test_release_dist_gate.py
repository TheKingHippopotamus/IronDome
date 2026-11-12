"""The distribution check: ``scripts/check.sh --dist DIR [--release VERSION]``.

release.yml runs it on dist/ before anything is uploaded, and scripts/check.sh runs it on
every local build. Each test makes a small git repository in a temporary directory, copies
the real scripts/check.sh into it, writes an sdist and a wheel by hand (faithful ones, or
ones carrying the defect a finding described) and runs the check on them.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Iterable, Optional

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
VERSION = "4.0.0"
EXPRESSION = "GPL-3.0-only AND CC-BY-3.0-US"
NOTICE = "src/irondome/data/eff_large_wordlist.LICENSE.txt"
INFO = f"irondome-{VERSION}.dist-info/"
#: The shape of the LICENSE the first 4.0.0 builds carried: an abridged GPL text with a copyright line.
ABRIDGED_GPL = (
    b"                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n\n"
    b" Copyright (C) 2023 King Hippopotamus\n\n This program is free software: you can redistribute it.\n"
)
SOURCE = {
    "README.md": b"# IronDome\n",
    "pyproject.toml": b'[project]\nname = "IronDome"\ndynamic = ["version"]\n',
    "src/irondome/__init__.py": f'"""IronDome."""\n\n__version__ = "{VERSION}"\n'.encode(),
    "src/irondome/vault.py": b"VAULT = 1\n",
    "src/irondome/data/eff_large_wordlist.txt": b"11111\tabacus\n",
    "tests/test_vault.py": b"def test_vault():\n    assert True\n",
    ".gitignore": b".env*\n*.state\n.pytest_cache/\n",
}
GENERATED = {
    "PKG-INFO": None,
    "setup.cfg": b"[egg_info]\ntag_build = \ntag_date = 0\n\n",
    "src/IronDome.egg-info/PKG-INFO": None,
    "src/IronDome.egg-info/SOURCES.txt": b"LICENSE\nREADME.md\n",
    "src/IronDome.egg-info/dependency_links.txt": b"\n",
    "src/IronDome.egg-info/entry_points.txt": b"[console_scripts]\nirondome = irondome.cli.main:main\n",
    "src/IronDome.egg-info/requires.txt": b"cryptography>=50.0.2\n",
    "src/IronDome.egg-info/top_level.txt": b"irondome\n",
}

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None, reason="needs git and bash"
)


def environment() -> Dict[str, str]:
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")
    env["PATH"] = os.pathsep.join([str(Path(sys.executable).parent), env.get("PATH", "")])
    return env


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
         "-c", "init.defaultBranch=main", *args],
        cwd=repo, env=environment(), check=True, capture_output=True, timeout=60,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A committed repository with the shape of IronDome's, and the real scripts/check.sh."""
    root = tmp_path / "repo"
    files = dict(SOURCE)
    for name in ("LICENSE", NOTICE, "scripts/check.sh"):
        files[name] = (REPOSITORY / name).read_bytes()
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    git(root, "init", "--quiet")
    git(root, "add", "--all")
    git(root, "commit", "--quiet", "--message", "the release")
    return root


def metadata(expression: str = EXPRESSION, licence_files: Iterable[str] = ("LICENSE", NOTICE),
             version: str = VERSION) -> bytes:
    lines = ["Metadata-Version: 2.4", "Name: IronDome", f"Version: {version}", f"License-Expression: {expression}"]
    lines += [f"License-File: {name}" for name in licence_files]
    lines += ["Requires-Dist: cryptography>=50.0.2", "", "# IronDome", ""]
    return "\n".join(lines).encode()


def package(repo: Path) -> Dict[str, bytes]:
    base = repo / "src" / "irondome"
    files = sorted(path for path in base.rglob("*") if path.is_file())
    return {"irondome/" + path.relative_to(base).as_posix(): path.read_bytes() for path in files}


def make_wheel(repo: Path, out: Path, *, extra: Optional[Dict[str, bytes]] = None, drop: Iterable[str] = (),
               meta: Optional[bytes] = None, bad_record: bool = False) -> None:
    files = package(repo)
    files[INFO + "licenses/LICENSE"] = (repo / "LICENSE").read_bytes()
    files[INFO + "licenses/" + NOTICE] = (repo / NOTICE).read_bytes()
    files[INFO + "METADATA"] = meta or metadata()
    files[INFO + "WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: setuptools (84.2.1)\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
    )
    files[INFO + "entry_points.txt"] = b"[console_scripts]\nirondome = irondome.cli.main:main\n"
    files[INFO + "top_level.txt"] = b"irondome\n"
    files.update(extra or {})
    for name in drop:
        del files[name]
    rows = []
    for name, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(b"" if bad_record else data).digest()).rstrip(b"=").decode()
        rows.append(f"{name},sha256={digest},{len(data)}")
    rows.append(f"{INFO}RECORD,,")
    with zipfile.ZipFile(out / f"irondome-{VERSION}-py3-none-any.whl", "w") as wheel:
        for name, data in files.items():
            wheel.writestr(name, data)
        wheel.writestr(INFO + "RECORD", "\n".join(rows) + "\n")


def make_sdist(repo: Path, out: Path, *, extra: Optional[Dict[str, bytes]] = None) -> None:
    files = {name: (repo / name).read_bytes() for name in ("LICENSE", NOTICE, "README.md", "pyproject.toml",
                                                           "scripts/check.sh", "tests/test_vault.py")}
    files.update({"src/" + name: data for name, data in package(repo).items()})
    files.update({name: data if data is not None else metadata() for name, data in GENERATED.items()})
    files.update(extra or {})
    with tarfile.open(out / f"irondome-{VERSION}.tar.gz", "w:gz") as sdist:
        for name, data in files.items():
            member = tarfile.TarInfo(f"irondome-{VERSION}/{name}")
            member.size = len(data)
            member.mode = 0o644
            sdist.addfile(member, io.BytesIO(data))


def dist_of(repo: Path, name: str = "dist", **wheel: object) -> Path:
    out = repo.parent / name
    out.mkdir()
    make_wheel(repo, out, **wheel)  # type: ignore[arg-type]
    make_sdist(repo, out)
    return out


def check(repo: Path, dist: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(repo / "scripts" / "check.sh"), "--dist", str(dist), *args],
        cwd=repo, env=environment(), capture_output=True, text=True, timeout=120,
    )


def refused(result: subprocess.CompletedProcess, *messages: str) -> None:
    assert result.returncode == 1, f"exit {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    for message in messages:
        assert message in result.stderr, result.stderr


# -- what passes ---------------------------------------------------------------------------------


def test_a_faithful_build_passes(repo):
    result = check(repo, dist_of(repo))
    assert result.returncode == 0, result.stderr
    assert "hold only what git sees" in result.stdout


def test_a_faithful_build_passes_as_the_release(repo):
    result = check(repo, dist_of(repo), "--release", VERSION)
    assert result.returncode == 0, result.stderr
    assert "hold only what git tracks" in result.stdout


# -- supply:3: what a working tree must never give a distribution ---------------------------------

#: The red team's canaries: ignored files and files named like local state, under tests/ and data/.
CANARIES = [
    "tests/.env", "tests/.env.local", "tests/run.state", "tests/.pytest_cache/v/cache/lastfailed",
    "tests/.pytest_cache/README.md", "tests/fixtures/leftover.irondome", "tests/e2e/agent.local.json",
    "tests/.mcp.json", "tests/unit/.hypothesis/examples/0a1b2c3d/canary", "tests/.claude/settings.local.json",
]


@pytest.mark.parametrize("stray", CANARIES)
def test_a_stray_file_of_the_working_tree_in_the_sdist_is_refused(repo, stray):
    (repo / stray).parent.mkdir(parents=True, exist_ok=True)
    (repo / stray).write_bytes(b"CANARY: fake, not a secret\n")
    out = repo.parent / "dist"
    out.mkdir()
    make_wheel(repo, out)
    make_sdist(repo, out, extra={stray: b"CANARY: fake, not a secret\n"})
    refused(check(repo, out), stray)


@pytest.mark.parametrize("stray", ["docs/private-notes.md", "src/irondome/data/notes.txt", "scripts/.env.sh"])
def test_a_release_ships_only_what_git_tracks(repo, stray):
    (repo / stray).parent.mkdir(parents=True, exist_ok=True)
    (repo / stray).write_bytes(b"CANARY: fake, not a secret\n")
    out = repo.parent / "dist"
    out.mkdir()
    make_wheel(repo, out, drop=[stray.replace("src/", "", 1)] if stray.startswith("src/") else [])
    make_sdist(repo, out, extra={stray: b"CANARY: fake, not a secret\n"})
    refused(check(repo, out, "--release", VERSION), stray)


def test_a_release_is_built_from_the_commit_not_from_an_edited_file(repo):
    (repo / "src" / "irondome" / "vault.py").write_bytes(b"VAULT = 2  # not committed\n")
    out = dist_of(repo)
    assert check(repo, out).returncode == 0
    refused(check(repo, out, "--release", VERSION), "src/irondome/vault.py")


# -- supply:2 and supply:0: what a compromised test step or build backend could leave ---------------


def test_a_file_planted_next_to_the_distributions_is_refused(repo):
    out = dist_of(repo)
    (out / f"irondome-{VERSION}-cp313-cp313-manylinux_2_17_x86_64.whl").write_bytes(b"PK\x05\x06" + bytes(18))
    refused(check(repo, out, "--release", VERSION), "must hold exactly", "manylinux")


def test_the_marker_uv_build_leaves_in_its_output_is_the_only_other_file_allowed(repo):
    out = dist_of(repo)
    (out / ".gitignore").write_bytes(b"*")
    assert check(repo, out, "--release", VERSION).returncode == 0
    (out / ".gitignore").write_bytes(b"*\n!irondome-4.0.0-cp313-cp313-manylinux_2_17_x86_64.whl\n")
    refused(check(repo, out, "--release", VERSION), "must hold exactly", ".gitignore")


def test_a_wheel_whose_code_is_not_the_source_is_refused(repo):
    """The supply:0 proof: a build backend appended a line to irondome/__init__.py and rewrote RECORD to match."""
    injected = SOURCE["src/irondome/__init__.py"] + b"# INJECTED BY A FAKE setuptools BUILD BACKEND\n"
    refused(check(repo, dist_of(repo, extra={"irondome/__init__.py": injected})),
            "src/irondome/__init__.py is not the repository's")


@pytest.mark.parametrize(
    "name,message",
    [("evil.pth", "neither the irondome package nor its metadata"),
     ("sitecustomize.py", "neither the irondome package nor its metadata"),
     ("irondome/_startup.pth", "must never ship"),
     (INFO + "licenses/NOTES.txt", "neither the irondome package nor its metadata")],
)
def test_a_wheel_holding_anything_beyond_the_package_is_refused(repo, name, message):
    refused(check(repo, dist_of(repo, extra={name: b"import os\n"})), name, message)


def test_a_wheel_missing_a_module_is_refused(repo):
    refused(check(repo, dist_of(repo, drop=["irondome/vault.py"])), "src/irondome/vault.py is missing")


def test_a_wheel_whose_record_does_not_match_its_files_is_refused(repo):
    refused(check(repo, dist_of(repo, bad_record=True)), "RECORD does not match")


# -- the licence ------------------------------------------------------------------------------------


def test_a_licence_that_is_not_the_verbatim_gpl_is_refused_even_when_the_repository_has_it(repo):
    """The first 4.0.0 builds carried an abridged GPL text. The check compares with the GPL's own digest."""
    (repo / "LICENSE").write_bytes(ABRIDGED_GPL)
    git(repo, "commit", "--quiet", "--all", "--message", "an abridged licence")
    refused(check(repo, dist_of(repo), "--release", VERSION),
            f"irondome-{VERSION}-py3-none-any.whl: its LICENSE is not the verbatim GPL-3.0 text",
            f"irondome-{VERSION}.tar.gz: its LICENSE is not the verbatim GPL-3.0 text")


@pytest.mark.parametrize(
    "meta,message",
    [(metadata(expression="GPL-3.0-only"), "License-Expression is GPL-3.0-only"),
     (metadata(licence_files=("LICENSE",)), "License-File lists ['LICENSE']")],
)
def test_licence_metadata_that_leaves_out_the_word_list_is_refused(repo, meta, message):
    refused(check(repo, dist_of(repo, meta=meta)), message)


def test_a_wheel_without_the_word_lists_notice_is_refused(repo):
    refused(check(repo, dist_of(repo, drop=[INFO + "licenses/" + NOTICE])), f"{INFO}licenses/{NOTICE} is missing")


# -- the version -------------------------------------------------------------------------------------


def test_the_release_version_must_be_the_packages(repo):
    refused(check(repo, dist_of(repo), "--release", "4.0.1"),
            "the release is 4.0.1 but src/irondome/__init__.py says 4.0.0",
            "must hold exactly irondome-4.0.1-py3-none-any.whl and irondome-4.0.1.tar.gz")


def test_a_tag_name_is_not_a_version(repo):
    result = check(repo, dist_of(repo), "--release", f"v{VERSION}")
    assert result.returncode == 2 and f"--release {VERSION}" in result.stderr, result.stderr
