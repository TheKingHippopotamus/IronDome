# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 4.x | Yes |
| 3.x and older | No. Move to 4.x with `irondome migrate` (claim [`migration`](docs/CLAIMS.md#migration)) |

IronDome 4 supports macOS and Linux.

## Reporting a vulnerability

Do not report a security problem in a public issue, pull request or
discussion.

Report it privately through GitHub's private vulnerability reporting for this
repository:
<https://github.com/TheKingHippopotamus/IronDome-Bunker/security/advisories/new>

Only you and the repository's maintainers can see the report until an
advisory is published. If that page shows no report form, private reporting
is switched off for the moment: open an issue that says only that you have a
security report and need a private channel, with no details. Reports go
through GitHub only; there is no security e-mail address and no PGP key.

Please include:

* what you found, and which claim in [docs/CLAIMS.md](docs/CLAIMS.md) it
  breaks, if one does;
* the steps to reproduce it;
* the version (`irondome --version`), the operating system and the device
  backend that `irondome status` reports;
* what you think the impact is.

Reproduce on a throwaway bunker. Never send a real vault, a recovery key, a
master password or any other real secret.

There is no bug bounty.

## What to expect

Everything in this section and the next is a goal, not a promise.

* An acknowledgement within 72 hours.
* News at each step: whether the problem is confirmed, when a fix is ready,
  when it ships.
* A fix as soon as the problem is verified, released as a new 4.x version
  with a changelog entry that says plainly what was wrong.

## Coordinated disclosure

* Please keep the details private until a fix is released, or for 90 days
  after your report if that comes first. If a fix needs longer, the date is
  agreed with you.
* The fix is published together with a GitHub security advisory for this
  repository, with a CVE ID where one applies.
* You are credited in the advisory and in the changelog, unless you would
  rather not be.
* If the problem is already public or being exploited, the fix and the
  advisory go out as soon as they are ready, without waiting for a date.

## Scope

### Vulnerabilities

Anything that makes a statement in [docs/CLAIMS.md](docs/CLAIMS.md) false is a
vulnerability, whatever its severity, and so is a claim whose limits ("Where
it stops") reach further in practice than they say. The same goes for a
security statement in the README or on the website that the code does not
back. In particular:

* an agent that gets more than its grant gives (other values, more uses, a
  longer life) or widens its own access;
* a copy of a vault opened without the device secret or the recovery key;
* a session or grant that opens anything on another machine, in another
  bunker or after `nuke`;
* the master password, the Argon2id output, the device secret, the
  key-encryption key, the vault key or a subkey found outside locked memory,
  or still in memory after the vault locks;
* an edit to the audit log that `irondome audit --verify` misses, beyond the
  truncation the [`audit-log`](docs/CLAIMS.md#audit-log) claim documents;
* a network connection made by IronDome itself;
* a file IronDome creates with wider permissions than 0600 (0700 for a
  directory), or an interrupted or concurrent write that damages a vault;
* a way to get code that is not in this repository into a published release,
  through the release workflow, the build or a dependency.

### Documented limits

The limits in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and each claim's
"Where it stops" line in [docs/CLAIMS.md](docs/CLAIMS.md) are documented
behaviour, not vulnerabilities. The main ones:

* malware or another program running as you while a vault is unlocked, a
  keylogger that captures the master password, and root, kernel or debugger
  access;
* a program that receives a secret and leaks it on purpose, including one
  started by `irondome run` that defeats output masking or uses the network;
* decrypted entries, which are ordinary Python strings while a command runs;
* tokens: a grant token is a bearer secret, so whoever holds it and can read
  the grant file has what it grants, and a session token in an agent's
  environment is full access;
* replacing the whole vault file with an older copy (whole-file rollback),
  and deleting the newest lines of the audit log or the whole log;
* the file-based device key, used where there is no security chip and on
  Windows, which has no hardware backend: a copy that includes the device
  directory opens with the master password, and on an SSD `nuke` erases that
  file only on a best-effort basis;
* a recovery key that survives `nuke` and opens a surviving copy of the vault;
* bunkers, which separate vaults, not operating-system accounts;
* Touch ID prompts, which name the helper program, not the caller.

Problems in `cryptography` or OpenSSL, the operating system, tpm2-tools or
the Swift compiler belong to those projects; report them there. How IronDome
uses them is in scope.

## How the project guards its own supply chain

* One runtime dependency, `cryptography>=50.0.2`. The floor is the first
  release with no known advisory. CI, every week and before every release,
  runs `pip-audit` (itself installed from `uv.lock`) over everything
  `uv.lock` pins: the runtime dependencies, the dev extra and the CI tools.
* No dependency release is used until it has been public for seven days
  (`exclude-newer` in `pyproject.toml`, a cooldown in Dependabot).
* No install-time code, no update check, no telemetry. IronDome itself makes
  no network connection (claim [`no-network`](docs/CLAIMS.md#no-network)).
* No compiled code in the package. Its only native code is the Secure Enclave
  helper, compiled on your Mac from the Swift source shipped with it.
  `cryptography` brings its own OpenSSL, and on Linux the TPM backend runs the
  system's tpm2-tools.
* Development, CI and the tests that gate a release run in the hash-locked
  environment from `uv.lock`. `uv.lock` does not cover build dependencies,
  so the build backend (`setuptools`) is pinned by hash in `scripts/check.sh`,
  the one build recipe CI, the release and a local build share.
* Workflow actions are pinned to commit hashes, and CI checks the workflows
  with zizmor. A release tag must be on main; the release runs the whole CI on
  it, then builds in a job that runs nothing but that recipe and a check of
  what it built (named for the tag, only committed files, the verbatim
  GPL-3.0 LICENSE), and uploads through PyPI Trusted Publishing; the release
  workflow uses no upload token.

IronDome has not been audited by an independent party.
