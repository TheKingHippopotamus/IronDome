#!/usr/bin/env bash
# Every release gate, on this machine: the same checks as .github/workflows/ci.yml
# and release.yml.
#
#   scripts/check.sh               lint, lockfile, claims, audit, tests on the oldest and
#                                  newest supported Python, build and check the distributions
#   scripts/check.sh --linux       also the whole suite in a Linux container against a
#                                  software TPM (scripts/test-linux.sh; needs podman or docker)
#   scripts/check.sh --build DIR   only build the sdist and the wheel into DIR (new or empty)
#                                  and check them
#   scripts/check.sh --dist DIR    only check the sdist and the wheel already in DIR
#
#   --release VERSION, with --build or --dist: the distributions are release VERSION.
#       They must be named for it, and hold only files git tracks, as committed.
#       release.yml runs `--build dist --release <tag without the v>`; check a build
#       made by hand the same way before uploading it.
#
# The distribution check: DIR holds exactly irondome-VERSION.tar.gz and
# irondome-VERSION-py3-none-any.whl; every file in them is a file git sees,
# byte for byte, or metadata setuptools writes; nothing that looks like local
# state or a secret ships; the wheel holds the whole package and nothing else;
# both LICENSE files are the repository's, the GPL one the verbatim GPL-3.0
# text; and the metadata says GPL-3.0-only AND CC-BY-3.0-US.
#
# Builds run on a copy of what git sees (tracked files, and untracked ones that
# are not ignored), never on the working tree itself, with the build backend
# pinned by hash (BUILD_CONSTRAINTS below).
#
# Needs uv 0.13.4 or newer, git and python3 (only git and python3 for --dist).
# Exits non-zero on the first failing gate.

set -euo pipefail

# The uv settings in pyproject.toml (exclude-newer, the week a release must be
# public) are part of what uv.lock is checked against, and CI reads them. A
# shell that sets UV_NO_CONFIG would check the lock without them.
unset UV_NO_CONFIG

# The build backend, pinned by hash. uv.lock does not cover build dependencies,
# and this is the one package whose code writes the shipped files. To move the
# pin, on a machine with network access, run
#   printf 'setuptools==X.Y.Z\n' | uv pip compile --quiet --no-header --universal --generate-hashes -
# paste the result here, and keep it inside [build-system] requires in pyproject.toml.
BUILD_CONSTRAINTS='setuptools==84.2.1 \
    --hash=sha256:3ff8b3b5492a0aa66960f4419365a86b84e013070d4313e4d4a6894f5d64d6bc \
    --hash=sha256:ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2'

usage() { sed -n '2,/^$/s/^# \{0,1\}//p' "$0"; }
usage_error() { printf 'check: %s\n' "$1" >&2; exit 2; }
die() { printf 'check: %s\n' "$1" >&2; exit 1; }
step() { printf '\n== %s\n' "$1"; }

linux=0
mode=all
dir=""
release=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --linux) linux=1; shift ;;
        --build | --dist)
            [ "$#" -ge 2 ] || usage_error "$1 needs a directory"
            [ "$mode" = all ] || usage_error "--build and --dist cannot be combined"
            mode="${1#--}"
            dir="$2"
            shift 2
            ;;
        --release)
            [ "$#" -ge 2 ] || usage_error "--release needs a version, for example: --release 4.0.0"
            release="$2"
            shift 2
            ;;
        -h | --help) usage; exit 0 ;;
        *) usage_error "unknown option: $1" ;;
    esac
done
[ -z "$release" ] || [ "$mode" != all ] || usage_error "--release goes with --build or --dist"
[ "$linux" = 0 ] || [ "$mode" = all ] || usage_error "--linux goes with the full run, not with --$mode"
case "$release" in
    v*) usage_error "--release takes the version without the v: --release ${release#v}" ;;
esac
case "$dir" in
    "" | /*) ;;
    *) dir="$PWD/$dir" ;;
esac

cd "$(dirname "$0")/.."
export GIT_OPTIONAL_LOCKS=0  # every git command here only reads

work="$(mktemp -d "${TMPDIR:-/tmp}/irondome-check.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# What git sees: tracked files, and untracked ones that are not ignored (a .env,
# a cache or an old build never are). For a release, tracked files only.
git_files() {
    local scope=(--cached --others --exclude-standard)
    [ -z "$release" ] || scope=(--cached)
    git ls-files -z "${scope[@]}" | while IFS= read -r -d '' path; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            printf '%s\0' "$path"
        fi
    done
}

# build OUT: the sdist and the wheel of what git sees, built in a copy of it.
build() {
    local out="$1" tree="$work/tree"
    if [ -d "$out" ] && [ -n "$(ls -A "$out")" ]; then
        die "$out is not empty: build into a new or empty directory"
    fi
    git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "$PWD is not a git checkout"
    if [ -n "$release" ] && ! git diff --quiet HEAD --; then
        die "tracked files differ from the last commit: a release is built from a commit"
    fi
    rm -rf "$tree"
    mkdir -p "$tree"
    git_files | COPYFILE_DISABLE=1 tar -c -f - --null -T - | tar -x -f - -C "$tree"
    printf '%s\n' "$BUILD_CONSTRAINTS" >"$work/build-constraints.txt"
    (cd "$tree" && uv build --quiet --no-sources --out-dir "$out" \
        --build-constraints "$work/build-constraints.txt" --require-hashes)
}

# check_dist DIR: the distribution check described at the top.
check_dist() {
    python3 -I - "$PWD" "$1" "$release" <<'PY'
import base64
import csv
import hashlib
import io
import re
import subprocess
import sys
import tarfile
import zipfile
from email.parser import HeaderParser
from pathlib import Path

repo, directory, release = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]

#: sha256 of the verbatim text of the GNU GPL version 3 (https://www.gnu.org/licenses/gpl-3.0.txt).
GPL3 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
EXPRESSION = "GPL-3.0-only AND CC-BY-3.0-US"
LICENSE_FILES = ["LICENSE", "src/irondome/data/eff_large_wordlist.LICENSE.txt"]
#: What setuptools writes into an sdist. Every other file in it must be one git sees, unchanged.
GENERATED = {"PKG-INFO", "setup.cfg"} | {
    "src/IronDome.egg-info/" + name
    for name in ("PKG-INFO", "SOURCES.txt", "dependency_links.txt", "entry_points.txt", "requires.txt", "top_level.txt")
}
#: Local state, secrets and caches: never shipped, even when git sees them.
FORBIDDEN = re.compile(
    r"(^|/)(\.env(\.[^/]*)?|\.envrc|[^/]*\.irondome|[^/]*\.state|[^/]*\.local\.json|\.mcp\.json|[^/]*\.pth"
    r"|[^/]*\.py[cod])$|(^|/)(\.claude|\.git|\.hypothesis|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.venv|__pycache__)/"
)
problems = []


def git(*args):
    try:
        return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        sys.exit(f"dist: `git {' '.join(args)}` failed in {repo}: {exc}")


def files_listed(*scope):
    names = git("ls-files", "-z", *scope).decode("utf-8", "surrogateescape").split("\0")
    return {name for name in names if name and (repo / name).is_file()}


def blob_id(data, length):
    """The id git gives *data* as a blob (SHA-1, or SHA-256 in a repository that uses it)."""
    header = b"blob %d\0" % len(data)
    if length == 40:
        return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()
    return hashlib.sha256(header + data).hexdigest()


committed = {}
if release:
    # A release ships the last commit: every file is compared with its blob at HEAD.
    for entry in git("ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0"):
        meta, _, name = entry.partition(b"\t")
        if entry and meta.split(b" ")[1] == b"blob":
            committed[name.decode("utf-8", "surrogateescape")] = meta.split(b" ")[2].decode()
    tracked = seen = set(committed)
    text = git("cat-file", "blob", "HEAD:src/irondome/__init__.py").decode("utf-8")
else:
    tracked = files_listed("--cached")
    seen = tracked | files_listed("--others", "--exclude-standard")
    text = (repo / "src" / "irondome" / "__init__.py").read_text(encoding="utf-8")
match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.M)
if match is None:
    sys.exit("dist: no __version__ in src/irondome/__init__.py")
version = release or match.group(1)
if version != match.group(1):
    problems.append(f"the release is {version} but src/irondome/__init__.py says {match.group(1)}")
package = {name for name in seen if name.startswith("src/irondome/")}
shipped_untracked = set()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def same_as_source(path, data, where):
    if FORBIDDEN.search(path):
        problems.append(f"{where}: {path} must never ship")
    elif path not in seen:
        problems.append(f"{where}: {path} is not a file git {'tracks' if release else 'sees'}")
    elif release:
        if blob_id(data, len(committed[path])) != committed[path]:
            problems.append(f"{where}: {path} is not the committed {path}")
    elif (repo / path).read_bytes() != data:
        problems.append(f"{where}: {path} is not the repository's {path}")
    elif path not in tracked:
        shipped_untracked.add(path)


def check_metadata(text, where):
    headers = HeaderParser().parsestr(text)
    if (headers.get("Name") or "").lower() != "irondome":
        problems.append(f"{where}: Name is {headers.get('Name')}")
    if headers.get("Version") != version:
        problems.append(f"{where}: Version is {headers.get('Version')}, not {version}")
    if headers.get("License-Expression") != EXPRESSION:
        problems.append(f"{where}: License-Expression is {headers.get('License-Expression')}, not {EXPRESSION}")
    if sorted(headers.get_all("License-File") or []) != sorted(LICENSE_FILES):
        problems.append(f"{where}: License-File lists {headers.get_all('License-File')}, not {LICENSE_FILES}")


def check_wheel(path):
    where = path.name
    info = f"irondome-{version}.dist-info/"
    licences = info + "licenses/"
    with zipfile.ZipFile(path) as wheel:
        files = {name: wheel.read(name) for name in wheel.namelist() if not name.endswith("/")}
    for name, data in sorted(files.items()):
        if name.startswith("irondome/"):
            same_as_source("src/" + name, data, where)
        elif name.startswith(licences) and name[len(licences):] in LICENSE_FILES:
            same_as_source(name[len(licences):], data, where)
        elif name[len(info):] not in ("METADATA", "WHEEL", "RECORD", "entry_points.txt", "top_level.txt") or (
            not name.startswith(info)
        ):
            problems.append(f"{where}: {name} is neither the irondome package nor its metadata")
    for name in sorted(package - {"src/" + name for name in files}):
        problems.append(f"{where}: {name} is missing")
    for licence in LICENSE_FILES:
        if licences + licence not in files:
            problems.append(f"{where}: {licences}{licence} is missing")
    gpl = files.get(licences + "LICENSE", b"")
    if sha256(gpl) != GPL3:
        problems.append(f"{where}: its LICENSE is not the verbatim GPL-3.0 text (sha256 {sha256(gpl)}, {len(gpl)} bytes)")
    if info + "METADATA" not in files or info + "RECORD" not in files:
        problems.append(f"{where}: {info}METADATA or {info}RECORD is missing")
        return
    check_metadata(files[info + "METADATA"].decode("utf-8"), where)
    tags = [line for line in files.get(info + "WHEEL", b"").decode("utf-8").splitlines() if line.startswith("Tag:")]
    if tags != ["Tag: py3-none-any"]:
        problems.append(f"{where}: WHEEL must name the one tag py3-none-any, not {tags}")
    if files.get(info + "top_level.txt", b"irondome").split() != [b"irondome"]:
        problems.append(f"{where}: top_level.txt must name the one package irondome")
    if files.get(info + "entry_points.txt", b"").split() != b"[console_scripts] irondome = irondome.cli.main:main".split():
        problems.append(f"{where}: entry_points.txt must declare the one command irondome = irondome.cli.main:main")
    recorded = {}
    for row in csv.reader(io.StringIO(files[info + "RECORD"].decode("utf-8"))):
        if row:
            recorded[row[0]] = row[1]
    for name, data in files.items():
        digest = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if name != info + "RECORD" and recorded.get(name) != digest:
            problems.append(f"{where}: RECORD does not match {name}")
    for name in sorted(set(recorded) - set(files)):
        problems.append(f"{where}: RECORD lists {name}, which is not in the wheel")


def check_sdist(path):
    where = path.name
    prefix = f"irondome-{version}/"
    files = {}
    with tarfile.open(path, "r:gz") as sdist:
        for member in sdist.getmembers():
            if member.isdir() and (member.name + "/").startswith(prefix):
                continue
            if not member.isfile() or not member.name.startswith(prefix):
                problems.append(f"{where}: {member.name} is not a regular file under {prefix}")
                continue
            files[member.name[len(prefix):]] = sdist.extractfile(member).read()
    for name, data in sorted(files.items()):
        if name not in GENERATED:
            same_as_source(name, data, where)
    for name in sorted((package | set(LICENSE_FILES) | {"pyproject.toml", "README.md", "PKG-INFO"}) - set(files)):
        problems.append(f"{where}: {name} is missing")
    if "LICENSE" in files and sha256(files["LICENSE"]) != GPL3:
        problems.append(f"{where}: its LICENSE is not the verbatim GPL-3.0 text")
    if "PKG-INFO" in files:
        check_metadata(files["PKG-INFO"].decode("utf-8"), where + " PKG-INFO")


if not directory.is_dir():
    sys.exit(f"dist: {directory} is not a directory")
expected = [f"irondome-{version}-py3-none-any.whl", f"irondome-{version}.tar.gz"]
# `uv build` marks its output directory with a .gitignore holding "*". It is never uploaded:
# the upload takes dist/*, which matches no dotfile.
present = sorted(
    entry.name for entry in directory.iterdir()
    if not (entry.name == ".gitignore" and entry.is_file() and entry.read_bytes().strip() == b"*")
)
if present != expected:
    problems.append(f"{directory} must hold exactly {' and '.join(expected)}; it holds: {', '.join(present) or 'nothing'}")
if expected[0] in present:
    check_wheel(directory / expected[0])
if expected[1] in present:
    check_sdist(directory / expected[1])
if problems:
    for problem in problems:
        print(f"dist: {problem}", file=sys.stderr)
    sys.exit(1)
print(f"dist: {' and '.join(expected)} hold only what git {'tracks' if release else 'sees'}, the whole package, "
      f"the verbatim GPL-3.0 LICENSE and the EFF word list's notice; licence metadata {EXPRESSION}")
if shipped_untracked:
    print(f"dist: note: {len(shipped_untracked)} shipped files are not committed yet")
PY
}

if [ "$mode" = dist ]; then
    step "check the distributions in $dir"
    check_dist "$dir"
    exit 0
fi

command -v uv >/dev/null || { echo "uv is required: https://docs.astral.sh/uv/" >&2; exit 2; }

if [ "$mode" = build ]; then
    step "build the distributions into $dir, with the build backend pinned by hash"
    build "$dir"
    step "check them"
    check_dist "$dir"
    exit 0
fi

step "lockfile matches pyproject.toml"
uv lock --check

for python in 3.9 3.14; do
    step "test suite on Python $python"
    UV_PROJECT_ENVIRONMENT="$work/venv-$python" uv sync --quiet --locked --extra dev --python "$python"
    UV_PROJECT_ENVIRONMENT="$work/venv-$python" uv run --no-sync pytest -q -p no:cacheprovider
done

export UV_PROJECT_ENVIRONMENT="$work/venv-3.14"

step "lint"
uv run --no-sync ruff check src tests scripts

step "type check"
uv run --no-sync mypy --cache-dir "$work/mypy-cache" src

step "the claims document matches the registry"
uv run --no-sync python scripts/claims.py --check

# The same scope and the same tool as ci.yml: everything uv.lock pins (runtime,
# the dev extra and the ci group), audited by the pip-audit uv.lock pins.
step "no known vulnerability in any locked dependency"
uv export --quiet --locked --all-extras --all-groups --no-emit-project --format requirements-txt -o "$work/requirements.txt"
UV_PROJECT_ENVIRONMENT="$work/venv-ci" uv run --quiet --locked --only-group ci --python 3.14 \
    pip-audit --disable-pip --require-hashes -r "$work/requirements.txt"

step "build the distributions, with the build backend pinned by hash, and check them"
build "$work/dist"
check_dist "$work/dist"
uv run --no-sync twine check --strict "$work"/dist/*

# The wheel's dependencies come from uv.lock, hash-checked; the wheel itself is
# installed without resolving anything, then the environment must be consistent.
step "the wheel installs and runs on its own"
uv export --quiet --locked --no-default-groups --no-emit-project --format requirements-txt -o "$work/runtime.txt"
uv venv --quiet --python 3.9 "$work/clean"
uv pip install --quiet --python "$work/clean/bin/python" --require-hashes -r "$work/runtime.txt"
uv pip install --quiet --python "$work/clean/bin/python" --no-deps "$work"/dist/*.whl
uv pip check --quiet --python "$work/clean/bin/python"
"$work/clean/bin/irondome" --version
IRONDOME_HOME="$work/home" IRONDOME_DEVICE_DIR="$work/device" IRONDOME_NO_PROMPT=1 \
    "$work/clean/bin/irondome" status >/dev/null

if [ "$linux" = 1 ]; then
    step "Linux container with a software TPM"
    scripts/test-linux.sh
fi

printf '\nall gates passed\n'
