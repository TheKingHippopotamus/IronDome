# Contributing to IronDome

Thank you for looking. Bug reports, tests, documentation fixes and code are
all welcome, and a small pull request that does one thing is the easiest kind
to review. Questions and bugs go to the
[issue tracker](https://github.com/Nir-Ghub/IronDome/issues).
Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).

IronDome is a security tool, so the bar for a change is simple to state: it
must keep every claim in [docs/CLAIMS.md](docs/CLAIMS.md) true, and it must
come with the tests that show it does.

**Security problems are not issues.** Report them privately, as
[SECURITY.md](SECURITY.md) describes, and not in a public issue or pull
request. Anything that makes a statement in docs/CLAIMS.md false counts.

## Set up

You need [uv](https://docs.astral.sh/uv/) 0.13.4 or newer (`uv --version`).
`pyproject.toml` requires it, so an older uv stops with an error. uv uses a
Python 3.9.2 or newer from your machine, or downloads one.

```console
$ git clone https://github.com/Nir-Ghub/IronDome.git
$ cd IronDome
$ uv sync --locked --extra dev
```

`--locked` installs exactly the hash-checked versions in `uv.lock` and stops
if the lockfile is out of date, instead of quietly resolving new ones.

## Run the tests

```console
$ uv run pytest -q -p no:cacheprovider                 # the whole suite
$ uv run pytest -q -p no:cacheprovider tests/claims    # only the claim tests
$ uv run ruff check src tests scripts                  # lint
```

`-p no:cacheprovider` keeps pytest from writing `.pytest_cache` into your
checkout. Nothing in the suite can reach a real vault: every test runs in
temporary directories, with network sockets disabled and Touch ID prompts
switched off.

Tests that need hardware are marked:

* `secure_enclave` runs automatically on a Mac with a Secure Enclave, once the
  Xcode Command Line Tools provide `swiftc` to compile the helper, and is
  skipped everywhere else. It never shows a Touch ID prompt.
* `tpm` runs against a TPM 2.0 when `IRONDOME_TEST_TPM=1`. The Linux harness
  does that for you, in a container with a software TPM:

  ```console
  $ scripts/test-linux.sh                         # the whole suite, Python 3.9 and 3.13
  $ scripts/test-linux.sh -p 3.12 -- -x -k tpm    # other Pythons, any pytest arguments
  ```

  It needs podman or docker, and network access to build the image, which
  installs exactly what `uv.lock` pins, hash-checked. The tests then run in a
  container with no network and no capabilities. The repository is copied in
  as a tar stream, so a test cannot write to your checkout; files git ignores,
  such as `.env`, are not copied.
* `interactive` needs a person at the sensor and runs only with
  `IRONDOME_TEST_INTERACTIVE=1`.

To run the release gates on your own machine, as CI does:

```console
$ scripts/check.sh            # lockfile, the suite on Python 3.9 and 3.14, lint, claims,
                              # dependency audit, build, and a clean install of the wheel
$ scripts/check.sh --linux    # the same, then scripts/test-linux.sh
$ scripts/check.sh --dist dist --release 4.0.0   # check a hand-made build before uploading it
```

It stops at the first gate that fails. It needs network access: the audit
asks PyPI about known vulnerabilities, and uv downloads Python 3.9 or 3.14 if
one of them is missing.

## Every claim has a test

[`src/irondome/claims.json`](src/irondome/claims.json) is the one list of
what IronDome promises. Each claim has an `id`, a `statement` (the promise), a
`boundary` (where the promise stops), its `platforms`, the pytest node ids
that hold it under `tests`, and `selfcheck`: the check `irondome verify` runs
for it on a user's own machine, or `null`.

* A claim with the id `some-claim` has a test file of its own,
  `tests/claims/test_some_claim.py`, and lists every test function in it.
* [docs/CLAIMS.md](docs/CLAIMS.md) is generated from the registry. Never edit
  it by hand.
* `tests/claims/test_registry.py` fails the build if a claim has no test, if a
  listed test does not exist, if a test in a claim's own file is not listed,
  if a claim file has no claim, or if docs/CLAIMS.md is not what the script
  renders.

If a change alters what IronDome can promise, change the registry, its tests
and the document in the same pull request:

```console
$ uv run python scripts/claims.py render     # rewrite docs/CLAIMS.md
$ uv run python scripts/claims.py --check    # what CI runs: fails if it is stale
```

A claim that says more than its tests show is a bug.

## Rules for code

* **Python 3.9.2 or newer.** CI runs the suite on Python 3.9 through 3.14,
  on Linux and macOS, so a feature newer than 3.9, such as `match` or an
  `X | Y` union evaluated at run time, fails there.
* **One direct runtime dependency.** The standard library and `cryptography`, nothing
  else; `tests/claims/test_one_dependency.py` enforces it. Development tools
  go in the `dev` extra. After changing a dependency, run `uv lock`; it only
  picks releases that have been public for at least seven days.
* **No network code**, anywhere in `src/`. `tests/claims/test_no_network.py`
  enforces that too.
* **Key material lives in `irondome.secmem.SecureBuffer`** and is wiped in a
  `with` block or a `finally`. Never put a key into a `bytes`, a `str`, an
  exception message, a log line, an environment variable or a subprocess
  argument.
* **Library code never prints.** It raises the exceptions in
  `irondome.errors`, whose messages are safe to show and say what to do next.
  The command line does all input and output.
* **Everything read from disk is hostile input.** Validate types, sizes and
  ranges; malformed input raises `VaultError` or `UsageError`, never an
  unhandled exception.
* **Lint clean.** `uv run ruff check src tests scripts` passes, with the rules
  in `ruff.toml`: Python 3.9 as the target, 120-character lines, sorted
  imports, and the bugbear and bandit (security) checks.
* **Made-up secrets only.** Never put a real password, key or token in a
  test, a fixture, an issue or a log you attach.
* **Say what the code does.** Docstrings, help text and documentation state
  guarantees and limits plainly.

## Pull requests

1. One change per pull request, with a description of what it changes and why.
2. Tests for the behaviour and for its failure paths; a bug fix comes with a
   test that fails without it.
3. These pass:
   `uv run pytest -q -p no:cacheprovider`,
   `uv run ruff check src tests scripts` and
   `uv run python scripts/claims.py --check`.
4. A changelog entry under the unreleased version at the top of
   [CHANGELOG.md](CHANGELOG.md).

By contributing you agree that your contribution is licensed under the
[GPL-3.0-only](LICENSE) license.
