#!/usr/bin/env bash
# Run IronDome's tests on Linux, in a container, against a software TPM 2.0.
#
#   scripts/test-linux.sh                              the whole suite, on Python 3.9 and 3.13
#   scripts/test-linux.sh tests/unit/test_device_tpm.py   only these paths
#   scripts/test-linux.sh -p 3.11 -p 3.12 -- -x -k tpm    other interpreters, any pytest arguments
#
# What it does, in order:
#   1. builds tests/linux/Containerfile (Ubuntu 24.04, tpm2-tools, swtpm, uv) for
#      the Python versions asked for, from a temporary directory that holds only
#      that file, uv.lock and pyproject.toml. The image gets one virtual
#      environment per version with exactly what uv.lock pins, hash-checked.
#      This is the only step that uses the network;
#   2. copies the repository into a fresh container as a tar stream. The
#      container has no network and no capabilities, and nothing is mounted, so
#      a test can neither reach anything nor write to your checkout. The copy
#      holds what git tracks plus untracked files that are not ignored; ignored
#      files such as .env never leave the machine;
#   3. for each Python version: checks that the environment holds exactly what
#      this tree's uv.lock pins (offline: nothing can be fetched), starts a new
#      swtpm on a Unix socket, exports TPM2TOOLS_TCTI and IRONDOME_TEST_TPM=1,
#      checks that IronDome's own probe can use that TPM (otherwise every TPM
#      test would be skipped), and runs pytest.
#
# The exit status is 0 only if every run passed.
#
# Environment:
#   IRONDOME_TEST_PYTHONS     versions to test when no -p is given (default "3.9 3.13")
#   IRONDOME_CONTAINER_ENGINE podman or docker (default: whichever is installed)
#   IRONDOME_TEST_IMAGE       use this existing image instead of building one; it must
#                             have been built from this tree's uv.lock, for these versions

set -eu

# The uv settings in pyproject.toml (exclude-newer, the week a release must be
# public) are part of what uv.lock is checked against, and CI reads them. A
# shell that sets UV_NO_CONFIG would check the lock without them.
unset UV_NO_CONFIG

DEFAULT_PYTHONS="3.9 3.13"
IMAGE_TAG="localhost/irondome-linux-test"
COPY_DIR="irondome"

die() {
    printf 'test-linux: %s\n' "$*" >&2
    exit 2
}

usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
}

# ---------------------------------------------------------------------------
# Inside the container
# ---------------------------------------------------------------------------

# The image holds one virtual environment per Python version, made when it was
# built from uv.lock. This tree's uv.lock and pyproject.toml must be those same
# files, and the environment must hold exactly what they pin: uv pip sync
# removes anything else and, with no network, fails rather than fetch anything.
check_environment() {
    venv="$HOME/venv-$1"
    [ -x "$venv/bin/python" ] ||
        die "the image has no environment for Python $1; build one with: scripts/test-linux.sh -p $1"
    for file in uv.lock pyproject.toml; do
        cmp -s "$HOME/lock/$file" "$file" ||
            die "the image was built from another $file than this tree's; rebuild it (run without IRONDOME_TEST_IMAGE)"
    done
    uv pip sync --quiet --offline --require-hashes --python "$venv/bin/python" "$HOME/lock/requirements.txt"
}

start_tpm() {
    tpm_dir="$(mktemp -d /tmp/irondome-swtpm.XXXXXX)"
    swtpm socket --tpm2 \
        --tpmstate "dir=$tpm_dir" \
        --server "type=unixio,path=$tpm_dir/sock" \
        --ctrl "type=unixio,path=$tpm_dir/sock.ctrl" \
        --flags not-need-init,startup-clear \
        --pid "file=$tpm_dir/pid" \
        --daemon
    export TPM2TOOLS_TCTI="swtpm:path=$tpm_dir/sock"
    tries=0
    until tpm2_getcap properties-variable >/dev/null 2>&1; do
        tries=$((tries + 1))
        [ "$tries" -lt 50 ] || die "the software TPM did not answer on $tpm_dir/sock"
        sleep 0.1
    done
}

# The probe the tests' tpm fixture uses. If it says no, every TPM test would be
# skipped and the run would still look green.
check_tpm_usable() {
    "$1" -c '
import sys
from irondome.device import get_backend
probe = get_backend("linux-tpm2").probe()
print("TPM probe:", probe.detail)
sys.exit(0 if probe.available else 1)
' || die "IronDome cannot use the software TPM, so every TPM test would be skipped"
}

stop_tpm() {
    if [ -f "$tpm_dir/pid" ]; then
        kill "$(cat "$tpm_dir/pid")" 2>/dev/null || true
    fi
    rm -rf "$tpm_dir"
    unset TPM2TOOLS_TCTI
}

run_in_container() {
    cd "$HOME/$COPY_DIR"
    command -v swtpm >/dev/null && command -v uv >/dev/null && [ -f "$HOME/lock/requirements.txt" ] ||
        die "this is not the IronDome test image"
    [ "$#" -gt 0 ] || set -- tests
    export IRONDOME_TEST_TPM=1
    export PYTHONPATH="$PWD/src"
    export PYTHONDONTWRITEBYTECODE=1
    export UV_OFFLINE=1
    pythons="${IRONDOME_TEST_PYTHONS:-$DEFAULT_PYTHONS}"
    printf 'test image: %s\n' "$(tr '\n' ' ' </etc/irondome-test-image.versions)"
    failed=""
    for version in $pythons; do
        check_environment "$version"
        venv="$HOME/venv-$version"
        start_tpm
        check_tpm_usable "$venv/bin/python"
        printf '\n===== %s, %s, %s =====\n' \
            "$("$venv/bin/python" -V 2>&1)" "$(tpm2_getcap --version | sed 's/ tctis=.*//')" "$TPM2TOOLS_TCTI"
        if "$venv/bin/python" -m pytest -p no:cacheprovider "$@"; then
            printf '===== Python %s: passed =====\n' "$version"
        else
            printf '===== Python %s: FAILED =====\n' "$version"
            failed="$failed $version"
        fi
        stop_tpm
    done
    if [ -n "$failed" ]; then
        printf '\ntest-linux: failed on Python%s\n' "$failed" >&2
        exit 1
    fi
    printf '\ntest-linux: passed on Python %s\n' "$pythons"
}

if [ "${1:-}" = "--in-container" ]; then
    shift
    run_in_container "$@"
    exit 0
fi

# ---------------------------------------------------------------------------
# On the host
# ---------------------------------------------------------------------------

pythons=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -p | --python)
            [ "$#" -ge 2 ] || die "$1 needs a version, for example: $1 3.12"
            pythons="$pythons $2"
            shift 2
            ;;
        --python=*)
            pythons="$pythons ${1#*=}"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            break
            ;;
    esac
done
checked=""
for version in ${pythons:-${IRONDOME_TEST_PYTHONS:-$DEFAULT_PYTHONS}}; do
    case "$version" in
        3.[0-9] | 3.[0-9][0-9]) checked="${checked:+$checked }$version" ;;
        *) die "not a Python version: $version (expected something like 3.12)" ;;
    esac
done
pythons="$checked"
[ -n "$pythons" ] || die "no Python version to test"

engine="${IRONDOME_CONTAINER_ENGINE:-}"
if [ -z "$engine" ]; then
    for candidate in podman /opt/podman/bin/podman docker; do
        if command -v "$candidate" >/dev/null 2>&1; then
            engine="$candidate"
            break
        fi
    done
fi
[ -n "$engine" ] || die "neither podman nor docker was found; install one, or set IRONDOME_CONTAINER_ENGINE"
command -v "$engine" >/dev/null 2>&1 || die "container engine not found: $engine"

repo="$(cd "$(dirname "$0")/.." && pwd -P)"
for file in tests/linux/Containerfile uv.lock pyproject.toml; do
    [ -f "$repo/$file" ] || die "$file is missing from $repo"
done

# The image, built from a directory that holds nothing but what it needs: no
# file of the checkout other than these three is ever sent to the engine.
image="${IRONDOME_TEST_IMAGE:-}"
if [ -z "$image" ]; then
    # The image exports uv.lock as it is (--frozen), so the lock is checked
    # against pyproject.toml here, where the source is.
    command -v uv >/dev/null 2>&1 || die "uv is needed to check uv.lock before the image is built"
    (cd "$repo" && uv lock --check --quiet) || die "uv.lock does not match pyproject.toml; run uv lock"
    image="$IMAGE_TAG:py$(printf '%s' "$pythons" | tr ' ' '-')"
    context="$(mktemp -d "${TMPDIR:-/tmp}/irondome-image.XXXXXX")"
    trap 'rm -rf "$context"' EXIT
    cp "$repo/tests/linux/Containerfile" "$repo/uv.lock" "$repo/pyproject.toml" "$context/"
    "$engine" build --tag "$image" --build-arg "PYTHONS=$pythons" --file "$context/Containerfile" "$context"
fi

# The list of files to copy, NUL-separated. Files that git lists but that are
# gone from the working tree are skipped, or tar would stop on them.
list_files() {
    if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        git -C "$repo" ls-files -z --cached --others --exclude-standard |
            while IFS= read -r -d '' path; do
                if [ -e "$repo/$path" ] || [ -L "$repo/$path" ]; then
                    printf '%s\0' "$path"
                fi
            done
    else
        (cd "$repo" && find . \
            \( -name .git -o -name .env -o -name '.env.*' -o -name .venv -o -name 'venv*' -o -name __pycache__ \
            -o -name '.*_cache' -o -name node_modules -o -name dist -o -name build -o -name '*.egg-info' \) -prune \
            -o \( -type f -o -type l \) -print0)
    fi
}

unpack_and_run='
set -eu
mkdir -p "$HOME/$1"
tar -x -f - -C "$HOME/$1" --warning=no-unknown-keyword
copy="$1"
shift
exec bash "$HOME/$copy/scripts/test-linux.sh" --in-container "$@"
'

# No network, no capabilities, no privilege escalation: the tests need none.
set +e
list_files |
    (cd "$repo" && COPYFILE_DISABLE=1 tar -c -f - --null -T -) |
    "$engine" run --rm --interactive --init --network=none --cap-drop=ALL --security-opt=no-new-privileges \
        --env "IRONDOME_TEST_PYTHONS=$pythons" \
        "$image" bash -c "$unpack_and_run" unpack "$COPY_DIR" "$@"
status=$?
set -e
exit "$status"
