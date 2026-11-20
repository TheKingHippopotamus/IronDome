"""The release pipeline as configured: CI, the release workflow, Dependabot and the packaging metadata.

These read the files as text (the suite has no YAML parser, on purpose: no dependency for it).
The workflows use two-space indentation, so a job is the block under ``jobs:`` that starts
with ``  <id>:``. What each test holds is named in its docstring, with the finding it closes.
"""

from __future__ import annotations

import hashlib
import re
import shlex
import sys
from pathlib import Path
from typing import Dict, List

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pytest itself depends on tomli before Python 3.11
    import tomli as tomllib

REPOSITORY = Path(__file__).resolve().parents[2]
CI = REPOSITORY / ".github" / "workflows" / "ci.yml"
RELEASE = REPOSITORY / ".github" / "workflows" / "release.yml"
CHECK = REPOSITORY / "scripts" / "check.sh"
#: The sdist ships the tests but not .github: run from an unpacked sdist, the CI tests have nothing to read.
#: In a checkout (or the Linux harness's copy of one) the files must be there.
needs_ci_config = pytest.mark.skipif(
    not CI.exists() and not (REPOSITORY / ".git").exists(), reason="the CI configuration is not in the sdist"
)
#: sha256 of the verbatim text of the GNU GPL version 3.
GPL3 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
WORD_LIST_NOTICE = "src/irondome/data/eff_large_wordlist.LICENSE.txt"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def code(path: Path) -> str:
    """A file without its comment lines (and without trailing comments in YAML)."""
    lines = []
    for line in text(path).splitlines():
        if line.lstrip().startswith("#"):
            continue
        if path.suffix == ".yml":
            line = re.sub(r"\s+#\s.*$", "", line)
        lines.append(line)
    return "\n".join(lines)


def jobs(path: Path) -> Dict[str, str]:
    """The text of every job of a workflow, by job id."""
    found: Dict[str, List[str]] = {}
    current = None
    inside = False
    for line in text(path).splitlines():
        if line == "jobs:":
            inside = True
            continue
        if not inside:
            continue
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if match:
            current = match.group(1)
            found[current] = []
        elif line and not line.startswith(" "):
            break
        elif current is not None:
            found[current].append(line)
    return {name: "\n".join(lines) for name, lines in found.items()}


def run_lines(block: str) -> List[str]:
    """Every command line of every ``run:`` in a block of workflow text."""
    commands: List[str] = []
    lines = block.splitlines()
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)(?:- )?run:\s*(.*)$", lines[index])
        index += 1
        if not match:
            continue
        indent, value = len(match.group(1)), match.group(2).strip()
        if value not in ("|", ">"):
            commands.append(value)
            continue
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            if line.strip():
                commands.append(line.strip())
            index += 1
    return commands


def shell_commands(path: Path) -> List[str]:
    """The commands of a shell script, with backslash continuations joined and comments dropped."""
    joined = re.sub(r"\\\n\s*", " ", code(path))
    return [line.strip() for line in joined.splitlines() if line.strip()]


def flags(command: str) -> set:
    tokens = [token.strip("();") for token in shlex.split(command)]
    return {token for token in tokens if token.startswith("--") and token != "--quiet"}


def version_tuple(version: str) -> tuple:
    return tuple(int(part) for part in version.split("."))


def build_constraints() -> List[str]:
    match = re.search(r"^BUILD_CONSTRAINTS='([^']*)'", text(CHECK), re.M)
    assert match, "scripts/check.sh has no BUILD_CONSTRAINTS"
    return shlex.split(match.group(1).replace("\\\n", " "))


def pyproject() -> dict:
    return tomllib.loads(text(REPOSITORY / "pyproject.toml"))


# -- supply:0, the build backend ------------------------------------------------------------


@needs_ci_config
def test_every_build_of_the_distributions_goes_through_the_pinned_recipe():
    """supply:0: no workflow runs ``uv build`` itself; scripts/check.sh is the one place that builds."""
    for workflow in (CI, RELEASE):
        for command in run_lines(code(workflow)):
            assert "uv build" not in command, f"{workflow.name}: {command}"
    builds = [command for command in shell_commands(CHECK) if re.search(r"\buv build\b", command)]
    assert len(builds) == 1, builds
    assert {"--build-constraints", "--require-hashes", "--no-sources"} <= flags(builds[0]), builds[0]
    assert "scripts/check.sh --build dist" in "\n".join(run_lines(jobs(CI)["checks"]))


def test_the_build_backend_is_pinned_by_hash_inside_the_range_pyproject_declares():
    """supply:0: one exact setuptools version, its wheel and sdist hashes, within [build-system] requires."""
    tokens = build_constraints()
    requirements = [token for token in tokens if not token.startswith("--")]
    hashes = [token for token in tokens if token.startswith("--hash=")]
    assert len(requirements) == 1, tokens
    name, _, pinned = requirements[0].partition("==")
    assert name == "setuptools" and re.fullmatch(r"\d+(\.\d+)*", pinned), requirements
    assert len(hashes) == 2 and all(re.fullmatch(r"--hash=sha256:[0-9a-f]{64}", item) for item in hashes), hashes
    system = pyproject()["build-system"]
    assert system["build-backend"] == "setuptools.build_meta"
    (declared,) = system["requires"]
    floor = re.fullmatch(r"setuptools>=(\d+(?:\.\d+)*)", declared.replace(" ", ""))
    assert floor, f"[build-system] requires should stay a range for packagers, not {declared!r}"
    assert version_tuple(pinned) >= version_tuple(floor.group(1))


def test_the_editable_builds_use_the_release_pin_and_one_that_still_runs_on_python_39():
    """The pin `uv sync` builds with is the release's; setuptools 83 dropped 3.9, the oldest Python tested."""
    (release_pin,) = [token for token in build_constraints() if not token.startswith("--")]
    pins = pyproject()["tool"]["uv"]["build-constraint-dependencies"]
    by_marker = {marker.strip(): pin.strip() for pin, _, marker in (item.partition(";") for item in pins)}
    assert set(by_marker) == {"python_full_version >= '3.10'", "python_full_version < '3.10'"}, pins
    assert by_marker["python_full_version >= '3.10'"] == release_pin
    older = re.fullmatch(r"setuptools==(\d+(?:\.\d+)*)", by_marker["python_full_version < '3.10'"])
    assert older and (77,) <= version_tuple(older.group(1)) < (83,), pins


# -- supply:2, the release workflow ----------------------------------------------------------


@needs_ci_config
def test_the_release_runs_the_whole_ci_first_then_builds_where_nothing_else_runs():
    """supply:2: tests and dev dependencies run in the ci job; the job that writes dist/ only builds and checks."""
    release = jobs(RELEASE)
    assert set(release) == {"ci", "build", "publish"}
    calls_ci = r"^    uses: \./\.github/workflows/ci\.yml(  # zizmor: ignore\[self-repository\])?$"
    assert re.search(calls_ci, release["ci"], re.M)
    assert re.search(r"^  workflow_call:", text(CI), re.M), "ci.yml must be callable from release.yml"
    build = release["build"]
    assert re.search(r"^    needs: ci$", build, re.M)
    assert "persist-credentials: false" in build
    commands = run_lines(build)
    assert any(re.search(r"scripts/check\.sh --build dist --release \S+", command) for command in commands), commands
    for command in commands:
        for forbidden in ("uv sync", "uv run", "uv pip", "uvx", "pytest", "--extra", "pip install"):
            assert forbidden not in command, f"the build job runs {forbidden!r}: {command}"


@needs_ci_config
def test_only_the_build_job_writes_the_artifact_and_only_the_publish_job_can_publish():
    release = jobs(RELEASE)
    assert "actions/upload-artifact@" in release["build"]
    assert "upload-artifact" not in release["publish"] and "actions/checkout" not in release["publish"]
    assert "id-token: write" in release["publish"] and "id-token" not in release["build"]
    assert re.search(r"^    needs: build$", release["publish"], re.M)
    assert re.search(r"^    environment: pypi$", release["publish"], re.M)
    assert re.search(r"^permissions: \{\}$", text(RELEASE), re.M) and re.search(r"^permissions: \{\}$", text(CI), re.M)


@needs_ci_config
def test_a_release_tag_must_point_at_a_commit_on_main():
    build = jobs(RELEASE)["build"]
    assert "fetch-depth: 0" in build
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main' in run_lines(build)


# -- supply:1 and supply:6, the audit and the tools ------------------------------------------


@needs_ci_config
def test_ci_and_check_sh_audit_the_same_scope_everything_the_lock_pins():
    """supply:1: the CI export and the local one have the same flags, and both include every extra and group."""
    ci_exports = [command for command in run_lines(jobs(CI)["checks"]) if command.startswith("uv export")]
    local_exports = [
        command for command in shell_commands(CHECK) if command.startswith("uv export") and "--all-extras" in command
    ]
    assert len(ci_exports) == 1 and len(local_exports) == 1, (ci_exports, local_exports)
    assert flags(ci_exports[0]) == flags(local_exports[0])
    assert {"--locked", "--all-extras", "--all-groups", "--no-emit-project"} <= flags(ci_exports[0])


@needs_ci_config
def test_every_tool_comes_from_the_lockfile():
    """supply:6: pip-audit and zizmor are installed from uv.lock (hash-checked), never resolved ad hoc."""
    everything = run_lines(code(CI)) + run_lines(code(RELEASE)) + shell_commands(CHECK)
    for command in everything:
        assert not re.search(r"(^|[\s;&|(])uvx\b|uv tool run", command), command
    audits = [command for command in everything if "pip-audit" in command]
    assert len(audits) == 2, audits  # ci.yml and scripts/check.sh
    zizmor = [command for command in everything if "zizmor" in command]
    assert len(zizmor) == 1, zizmor
    for command in audits + zizmor:
        assert re.search(r"\buv run\b.*--locked\b.*--only-group ci\b", command), command
    assert "zizmor-action" not in code(CI)


@needs_ci_config
def test_ci_installs_no_os_package_of_its_own():
    """supply:6: the TPM job is the Linux harness, whose image records the versions it was built with."""
    assert "apt-get" not in code(CI)
    assert any("bash scripts/test-linux.sh -p 3.9 -p 3.14" == command for command in run_lines(jobs(CI)["tpm"]))
    assert "/etc/irondome-test-image.versions" in text(REPOSITORY / "tests" / "linux" / "Containerfile")


# -- found by the first run of CI on GitHub: every job failed within seconds -----------------------


def test_the_lockfile_was_resolved_under_the_week_pyproject_sets():
    """uv.lock had been written by a shell with UV_NO_CONFIG set: without exclude-newer, so CI refused it."""
    assert pyproject()["tool"]["uv"]["exclude-newer"] == "7 days"
    options = re.search(r"^\[options\]\n((?:.+\n)+)", text(REPOSITORY / "uv.lock"), re.M)
    assert options, "uv.lock records no options: it was resolved without the settings in pyproject.toml"
    assert 'exclude-newer-span = "P7D"' in options.group(1).splitlines()


@needs_ci_config
def test_the_gates_read_the_uv_settings_ci_reads():
    """The local gate passed a lockfile CI refused: its shell had switched the project's uv settings off."""
    for script in (CHECK, REPOSITORY / "scripts" / "test-linux.sh"):
        commands = shell_commands(script)
        assert "unset UV_NO_CONFIG" in commands, script.name
        uses_uv = re.compile(r"(^|[\s;&|(])uv (lock|sync|run|export|build)\b")
        first_uv = next(index for index, command in enumerate(commands) if uses_uv.search(command))
        assert commands.index("unset UV_NO_CONFIG") < first_uv, script.name
    for workflow in (CI, RELEASE):
        assert "UV_NO_CONFIG" not in text(workflow) and "--no-config" not in text(workflow), workflow.name


@needs_ci_config
def test_every_job_that_runs_uv_installs_it():
    """The TPM job ran the harness, which checks uv.lock with uv, on a runner that had no uv."""
    for workflow in (CI, RELEASE):
        for name, block in jobs(workflow).items():
            needs_uv = any(
                re.search(r"(^|[\s;&|(])uv\b|scripts/test-linux\.sh|scripts/check\.sh", command)
                for command in run_lines(block)
            )
            if needs_uv:
                assert "uses: astral-sh/setup-uv@" in block, f"{workflow.name}: job {name}"


# -- ci-review: what CI must also do ----------------------------------------------------------


@needs_ci_config
def test_ci_tests_every_python_the_package_claims():
    """README and the classifiers claim 3.9 to 3.14: the matrix must test each of them on Linux and macOS."""
    classifiers = "\n".join(pyproject()["project"]["classifiers"])
    claimed = sorted(re.findall(r"Programming Language :: Python :: (3\.\d+)$", classifiers, re.M), key=version_tuple)
    match = re.search(r'^        python: \[([^\]]*)\]$', jobs(CI)["test"], re.M)
    assert match, "the test job has no python matrix"
    tested = [item.strip().strip('"') for item in match.group(1).split(",")]
    assert tested == claimed
    assert "os: [ubuntu-24.04, macos-15]" in jobs(CI)["test"]
    # Every runner installs from wheels: uv.lock has none of cryptography for Intel macOS.
    assert "macos-15-intel" not in code(CI) and "macos-13" not in code(CI)


@needs_ci_config
def test_ci_and_check_sh_type_check_the_package():
    """mypy was in the dev extra but nothing ran it."""
    assert "uv run --no-sync mypy src" in run_lines(jobs(CI)["checks"])
    assert any(re.fullmatch(r"uv run --no-sync mypy .*\bsrc", command) for command in shell_commands(CHECK))


@needs_ci_config
def test_every_job_has_a_timeout_and_no_run_line_expands_an_expression():
    for workflow in (CI, RELEASE):
        for name, block in jobs(workflow).items():
            if re.search(r"^    uses: ", block, re.M):
                continue  # a call of a reusable workflow takes no timeout of its own
            assert re.search(r"^    timeout-minutes: \d+$", block, re.M), f"{workflow.name}: job {name}"
        for command in run_lines(code(workflow)):
            assert "${{" not in command, f"{workflow.name}: {command}"


@needs_ci_config
def test_ci_runs_weekly_and_only_pull_request_runs_are_cancelled():
    ci = text(CI)
    assert re.search(r'^  schedule:\n    - cron: "[^"]+"', ci, re.M)
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in ci
    # Any other run gets a group of its own: never cancelled, never left pending behind another.
    group = "${{ github.event_name == 'pull_request' && github.ref || github.run_id }}"
    assert "group: ci-${{ github.workflow }}-" + group in ci


@needs_ci_config
def test_every_action_is_pinned_to_a_commit():
    for workflow in (CI, RELEASE):
        for line in text(workflow).splitlines():
            match = re.search(r"uses: (\S+)", line)
            if match and not match.group(1).startswith("./"):
                assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", match.group(1)), line
                assert re.search(r" # v\d+(\.\d+)*$", line), line


@needs_ci_config
def test_dependabot_also_moves_the_test_images_pins():
    dependabot = text(REPOSITORY / ".github" / "dependabot.yml")
    ecosystems = re.findall(r"- package-ecosystem: (\S+)\n    directory: \"([^\"]+)\"", dependabot)
    assert set(ecosystems) == {("uv", "/"), ("github-actions", "/"), ("docker", "/tests/linux")}
    assert dependabot.count("default-days: 7") == 3


# -- the licence ---------------------------------------------------------------------------------


def test_the_licence_metadata_covers_the_word_list_too():
    """The distributions ship the EFF word list (CC BY 3.0 US): the PEP 639 metadata must say so."""
    project = pyproject()["project"]
    assert project["license"] == "GPL-3.0-only AND CC-BY-3.0-US"
    assert project["license-files"] == ["LICENSE", WORD_LIST_NOTICE]
    assert hashlib.sha256((REPOSITORY / "LICENSE").read_bytes()).hexdigest() == GPL3
    notice = (REPOSITORY / WORD_LIST_NOTICE).read_text(encoding="utf-8")
    assert "Creative Commons Attribution 3.0 United States (CC BY 3.0 US)" in notice


def test_check_sh_refuses_a_licence_that_is_not_the_verbatim_gpl():
    assert GPL3 in text(CHECK)
    assert '"GPL-3.0-only AND CC-BY-3.0-US"' in text(CHECK)


# -- supply:3, what the distributions take from the tree ------------------------------------------


def test_the_package_data_is_named_file_by_file():
    data = pyproject()["tool"]["setuptools"]["package-data"]["irondome"]
    assert "data/eff_large_wordlist.txt" in data and "data/eff_large_wordlist.LICENSE.txt" in data
    assert not any(item.startswith("data/") and "*" in item for item in data), data


def test_the_sdist_takes_tests_by_file_type_and_never_local_state():
    manifest = [line.split() for line in code(REPOSITORY / "MANIFEST.in").splitlines() if line.strip()]
    assert not any(words[0] in ("graft", "global-include") for words in manifest), manifest
    assert ["recursive-include", "tests", "*.py", "*.json", "*.md"] in manifest
    excluded = {word for words in manifest if words[0] == "global-exclude" for word in words[1:]}
    assert {".env", ".env.*", "*.irondome", "*.state", "*.local.json", ".mcp.json"} <= excluded
    assert {".pytest_cache/**", ".hypothesis/**", ".claude/**"} <= excluded
