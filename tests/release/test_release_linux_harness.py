"""scripts/test-linux.sh and tests/linux/Containerfile: the Linux and TPM harness (supply:4).

The host half of the script runs here against a stand-in container engine that records what
it is asked to do: the arguments of each call, the files of the build context it receives and
the names in the tar stream piped into the container. The half that runs inside the image
needs swtpm, so its install and run steps are checked as text.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
HARNESS = REPOSITORY / "scripts" / "test-linux.sh"
CONTAINERFILE = REPOSITORY / "tests" / "linux" / "Containerfile"

#: The stand-in engine: call-<verb> holds the arguments of that call, NUL-separated; context
#: lists the build context (the last argument of `build`); stream lists what `run` was piped.
ENGINE = r"""#!/usr/bin/env bash
set -eu
here="$(dirname "$0")"
printf '%s\0' "$@" >"$here/call-$1"
case "$1" in
    build) for last; do :; done; (cd "$last" && ls -A) >"$here/context" ;;
    run) tar -t -f - >"$here/stream" ;;
esac
"""

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None or shutil.which("tar") is None,
    reason="needs git, bash and tar",
)


def git(repo: Path, *args: str) -> None:
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    subprocess.run(["git", "-c", "init.defaultBranch=main", *args], cwd=repo, env=env, check=True,
                   capture_output=True, timeout=60)


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    """A git checkout holding the real harness, an ignored .env and an untracked, unignored file."""
    root = tmp_path / "checkout"
    files: Dict[str, bytes] = {
        "scripts/test-linux.sh": HARNESS.read_bytes(),
        "tests/linux/Containerfile": CONTAINERFILE.read_bytes(),
        "uv.lock": b"version = 1\n",
        "pyproject.toml": b'[project]\nname = "IronDome"\n',
        "src/irondome/__init__.py": b'__version__ = "4.0.0"\n',
        ".gitignore": b".env\n",
    }
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    git(root, "init", "--quiet")
    git(root, "add", "--all")
    (root / ".env").write_bytes(b"CANARY=fake, not a secret\n")
    (root / "notes.md").write_bytes(b"untracked, not ignored\n")
    engine = tmp_path / "engine" / "fake-engine"
    engine.parent.mkdir()
    engine.write_text(ENGINE)
    engine.chmod(0o755)
    uv = engine.parent / "uv"  # the stand-in uv: records its arguments, exits with FAKE_UV_EXIT
    uv.write_text('#!/usr/bin/env bash\nprintf \'%s\\0\' "$@" >"$(dirname "$0")/call-uv"\nexit "${FAKE_UV_EXIT:-0}"\n')
    uv.chmod(0o755)
    return root


def run_harness(checkout: Path, *args: str, **env: str) -> "subprocess.CompletedProcess[str]":
    """Run the harness's host half with the stand-in engine and the stand-in uv."""
    records = checkout.parent / "engine"
    variables = {key: value for key, value in os.environ.items() if not key.startswith("IRONDOME_TEST_")}
    variables.update(IRONDOME_CONTAINER_ENGINE=str(records / "fake-engine"), GIT_CONFIG_NOSYSTEM="1",
                     GIT_CONFIG_GLOBAL=os.devnull, PATH=f"{records}{os.pathsep}{os.environ.get('PATH', '')}", **env)
    return subprocess.run(["bash", str(checkout / "scripts" / "test-linux.sh"), *args], cwd=checkout,
                          env=variables, capture_output=True, text=True, timeout=120)


def harness(checkout: Path, *args: str, **env: str) -> Path:
    """Run the harness's host half; it must succeed. Returns the folder of its records."""
    result = run_harness(checkout, *args, **env)
    assert result.returncode == 0, f"exit {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    return checkout.parent / "engine"


def arguments(records: Path, verb: str) -> List[str]:
    return (records / f"call-{verb}").read_bytes().decode().split("\0")[:-1]


def listing(records: Path, name: str) -> List[str]:
    return sorted((records / name).read_text().split())


def test_the_tests_run_in_a_container_with_no_network_and_no_capabilities(checkout):
    run = arguments(harness(checkout), "run")
    for flag in ("--rm", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges"):
        assert flag in run, run
    assert not [item for item in run if item.startswith(("--volume", "--mount", "--privileged", "--network=host"))]
    assert "-v" not in run


def test_the_image_is_built_from_the_containerfile_and_the_lockfile_alone(checkout):
    records = harness(checkout, "-p", "3.9", "-p", "3.14")
    build = arguments(records, "build")
    assert build[build.index("--build-arg") + 1] == "PYTHONS=3.9 3.14"
    assert build[build.index("--tag") + 1] == "localhost/irondome-linux-test:py3.9-3.14"
    assert listing(records, "context") == ["Containerfile", "pyproject.toml", "uv.lock"]
    assert "localhost/irondome-linux-test:py3.9-3.14" in arguments(records, "run")


def test_ignored_files_never_reach_the_container(checkout):
    stream = listing(harness(checkout), "stream")
    assert {"scripts/test-linux.sh", "uv.lock", "notes.md"} <= set(stream)
    assert ".env" not in stream


def test_a_given_image_is_used_as_it_is(checkout):
    records = harness(checkout, IRONDOME_TEST_IMAGE="localhost/prebuilt:1")
    assert not (records / "call-build").exists()
    assert "localhost/prebuilt:1" in arguments(records, "run")


# -- inside the image: what gets installed, and from where -----------------------------------------


def commands(path: Path) -> str:
    """The commands of a shell script or Containerfile: no comment lines, continuations joined."""
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("#")]
    return re.sub(r"\\\n\s*", " ", "\n".join(lines))


def test_the_image_installs_exactly_what_uv_lock_pins_hash_checked_and_builds_nothing():
    image = commands(CONTAINERFILE)
    installs = re.findall(r"uv pip install[^\n;&|]*", image)
    assert len(installs) == 1, installs
    for flag in ("--require-hashes", "--no-build", "-r requirements.txt"):
        assert flag in installs[0], installs
    assert "uv export --quiet --frozen --all-extras --no-emit-project --format requirements-txt" in image
    assert "COPY --chown=tester:tester uv.lock pyproject.toml /home/tester/lock/" in image


def test_the_lock_is_checked_against_pyproject_before_the_image_is_built(checkout):
    """The image exports uv.lock with --frozen, so the freshness check is made on the checkout, first."""
    records = harness(checkout)
    assert arguments(records, "uv")[:2] == ["lock", "--check"]
    (records / "call-build").unlink()
    stale = run_harness(checkout, FAKE_UV_EXIT="1")
    assert stale.returncode != 0
    assert "uv.lock does not match pyproject.toml" in stale.stderr
    assert not (records / "call-build").exists(), "nothing is built from a stale lock"


def test_the_harness_installs_nothing_and_fetches_nothing_at_run_time():
    harness_code = commands(HARNESS)
    assert "uv pip install" not in harness_code and "uv venv" not in harness_code
    assert "uv pip sync --quiet --offline --require-hashes" in harness_code
    assert "export UV_OFFLINE=1" in harness_code
    assert 'cmp -s "$HOME/lock/$file" "$file"' in harness_code  # the image's lockfile is this tree's


def test_the_harness_stops_when_every_tpm_test_would_be_skipped():
    harness_code = commands(HARNESS)
    assert 'get_backend("linux-tpm2").probe()' in harness_code
    assert re.search(r"start_tpm\n\s+check_tpm_usable ", harness_code)


def test_the_harness_says_what_it_does():
    result = subprocess.run(["bash", str(HARNESS), "--help"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0
    assert "This is the only step that uses the network" in " ".join(result.stdout.split())
    assert "The container has no network and no capabilities" in " ".join(result.stdout.split())
