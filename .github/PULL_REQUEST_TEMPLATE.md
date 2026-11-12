<!--
Fixing a vulnerability that is not public yet? Stop: do not open a public pull request.
Report it privately (see SECURITY.md); the fix is prepared in the advisory's private fork.

Never put a real token, recovery key, password, TOTP seed or bunker file in the diff,
a test fixture, a log or a screenshot.
-->

## What and why

<!-- One change per pull request: what it changes and why. Link the issue, e.g. "Fixes #123". -->

## Checklist

`scripts/check.sh` runs the mechanical gates on your machine: lockfile, tests on Python 3.9 and 3.14, ruff,
the claims check, the dependency audit and the build (`--linux` adds the TPM suite in a container).

- [ ] Tests for the new behaviour and for its failure paths; a bug fix comes with a test that fails without it.
- [ ] The suite passes on Python 3.9 and 3.14, the oldest and newest supported
      (`uv sync --locked --extra dev --python 3.9 && uv run --no-sync pytest -q`, then the same with `3.14`).
- [ ] `uv run ruff check src tests scripts` is clean.
- [ ] Promises stay true: this changes no guarantee or limit, **or** `src/irondome/claims.json` and the test
      that proves it in `tests/claims/` are updated here, and `docs/CLAIMS.md` is regenerated
      (`uv run python scripts/claims.py render`; `--check` passes).
- [ ] Docs match the code: help text, `README.md` and `docs/` (`docs/THREAT_MODEL.md` if a limit moves).
- [ ] A changelog entry under "unreleased" in `CHANGELOG.md`.
- [ ] Still one runtime dependency (`cryptography`) and no network code in `src/`.
- [ ] If a device backend changed: tested on the hardware (Secure Enclave on a Mac; `scripts/test-linux.sh`
      for the TPM), or say below which one you could not test.

## Security notes

<!-- Does this touch key material, the vault format, keyslots, grants or sessions, agent detection,
file permissions or a device backend? Say how, or write "None". -->
