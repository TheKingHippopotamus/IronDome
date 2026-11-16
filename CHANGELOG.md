# Changelog

All notable changes to IronDome are recorded here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version number lives in exactly one place, `src/irondome/__init__.py`;
`pyproject.toml` reads it from there via `[tool.setuptools.dynamic]`.

## [4.0.0] — unreleased

A new vault, a new command line and a new purpose. Version 3 published six
things it could not do: five on its website, and the cipher on its PyPI page.
Version 4 exists to make five of them false, and to make the vault usable by AI
agents without handing them the vault. The sixth, no independent audit, still
stands.

**This is a breaking release.** The vault format, the data directory, the
Python package name and every command changed. `irondome migrate` converts a
3.x vault, verifies every entry and leaves the old vault untouched unless
`--destroy-old` is given and every entry matched.

### The five published limits, closed

Each is now a claim in `docs/CLAIMS.md` with the tests that hold it, and
`irondome verify` re-runs the checks on your own machine.

- **"Key protection is software-only."** Every keyslot opened by a master
  password or a fingerprint now also needs a *device secret*: derived from a
  P-256 key held by the Secure Enclave on macOS, a TPM 2.0 NV index on Linux,
  or a file in a separate device directory where there is no chip (reported as
  "software", never as hardware). A complete copy of the vault directory with
  the correct master password does not open on another machine and gives
  nothing to test password guesses against; only the recovery key opens a copy
  elsewhere, or, with the file-based backend, a copy that also includes the
  device directory.
- **"The biometric check is not cryptographic."** In 3.x Touch ID was a
  boolean in front of a key that any process running as you could read from
  the keychain. A Touch ID keyslot is now a Secure Enclave key created with
  `biometryCurrentSet`: the chip refuses the key operation until its sensor
  reports a match. The gate-only "biometric" modes for Windows Hello and
  fprintd are gone rather than kept as theatre.
- **"nuke cannot defeat an SSD controller."** `nuke` now destroys the device
  secret before it deletes anything else. Afterwards a bit-perfect copy of the
  vault directory does not open with the correct master password. With the
  file-based backend the device secret is itself a file, and erasing it on an
  SSD is best effort: whoever also recovers its old blocks can open the copy.
- **"The key is not zeroed in memory."** Key material is derived, decrypted
  and read directly into pages outside the Python heap, locked into RAM where
  the system allows it (`irondome doctor` warns when it does not), and
  overwritten when the vault locks. A test scans the whole address space of
  the process on macOS and Linux after a full session and requires zero hits.
  One copy is made outside IronDome's reach: Argon2id in `cryptography`
  (OpenSSL) copies what it is given into memory it frees without
  overwriting. So Argon2id is never given the master password: IronDome
  derives a 32-byte prehash from it with HKDF, in locked memory, and Argon2id
  stretches that. Searched for piece by piece right after a derivation, no
  part of an ASCII master password of up to 4,000 bytes is found. The copy that is
  left is of the prehash, and IronDome runs Argon2id a second time on zeros,
  so that the library, handed the blocks it just freed, overwrites it itself;
  macOS also zeroes small freed blocks. That is the allocator's choice, not a
  guarantee, and the claim's boundary says so. HKDF leaves its working keys, the one
  it extracts and the one it derives, on the C stack and in freed memory:
  IronDome derives again from zeros to overwrite them, and a scan made right
  after a derivation finds none.
- **"The cipher is AES-128."** (3.x PyPI page.) Fernet's AES-128-CBC with
  HMAC is replaced by AES-256-GCM, with one key per entry derived by HKDF.

### Security: fixed by the redesign

A read of 3.2.2 for this release found defects beyond the published limits.
The new architecture removes all of them:

- A "biometric only" vault could be opened without a fingerprint by any
  process running as the user (forged session file, or reading the keychain
  entry directly), and could be **destroyed** by logging in with the
  publicly derivable placeholder credentials and saving an entry.
- A decryption failure was swallowed as "empty vault"; the next save then
  overwrote the real one. Writes were in place, not atomic.
- The recovery key was a gate in front of the same keychain entry, not a way
  to recover: losing the keychain entry lost the vault.
- The lockout counter was keyed on a value that changes per process on
  current macOS, and deleting its file reset it.
- The log file recorded account names and raw search terms in plaintext.
- `bunker open <name>` printed every matching password without
  re-authentication.

### Added

- **Cryptography:** Argon2id (256 MiB, t=3, p=4 by default, 64 MiB on a
  machine with less than 3 GiB of RAM, never below the OWASP minimum) replaces
  PBKDF2; AES-256-GCM
  with a key per entry replaces Fernet (AES-128-CBC); names, usernames, URLs
  and tags are encrypted along with passwords; records are padded, bound to
  their vault, entry and revision, and written atomically with snapshots.
- **Keyslots:** master password, Touch ID and recovery key each wrap the same
  vault key. A real 160-bit recovery key. `passwd`, `auth`, `recovery`,
  `rekey`.
- **For agents:** aliases and `irondome://` references; `run`, which injects
  secrets into a command's environment and masks them in its output;
  **grants** (scoped, expiring, use-counted, single-use by default; a grant for
  a TOTP field holds codes, never the seed); sessions (`irondome unlock`);
  grants and sessions are sealed under a key that also needs this machine's
  device secret, so a copied token opens nothing elsewhere or after `nuke`;
  Touch ID approval for a single command and `irondome approve` (one touch, a
  grant in `use` mode with no use limit, for at most an hour); an MCP server
  over stdio that speaks both the 2026-07-28 protocol and the earlier
  `initialize` handshake, and stops a command when its request is cancelled;
  an encrypted, hash-chained audit log; `scan`, which finds vault secrets that
  leaked into files such as transcripts, logs and the files of a repository
  (not inside compressed files such as git objects).
- **One-time passwords:** TOTP (RFC 6238) on any entry, `otpauth://` import.
- **Verification:** `docs/CLAIMS.md`, generated from the registry the website
  is also checked against; `irondome verify`; `irondome doctor`. Among the
  claims: core dumps off and, on Linux, no same-user debugger
  (`process-hardened`); a copied secret taken off the clipboard
  (`clipboard-cleared`); no secret value as a command-line argument
  (`no-secrets-in-arguments`).
- **Bunkers:** several fully separate vaults on one machine
  (`irondome bunker create|ls|use|rm`, `--bunker`, `IRONDOME_BUNKER`), one per
  person or role, each with its own keys, grants and audit log.
- **Interchange:** portable encrypted backups, import from Bitwarden,
  1Password, Chrome and Firefox exports.
- **Settings:** `irondome config` per bunker. `config.json` is not
  authenticated, so its ranges contain no unsafe value: generated passwords
  default to at least 16 characters, passphrases to at least 5 words, and a
  grant's default lifetime is at most a day; longer or shorter takes a flag.
- A Linux container harness with a software TPM (`scripts/test-linux.sh`).

### Changed

- One command: `irondome`. In 3.x `irondome` opened the TUI and the real
  work was split between `irondome-cli` and `bunker`; both of those are gone.
- The package is now `irondome` (was `password_manager`) with a `src/` layout.
- Data lives in `~/.irondome/bunkers/<name>/`; device material lives in a
  separate device directory that must never be backed up or synced.
- On a Mac, keys under the plain device policy work whenever the Mac has been
  unlocked once since it started, also while the screen is locked (SSH,
  scheduled jobs, agents with a grant); Touch ID keys need an unlocked screen.
- **One direct runtime dependency:** `cryptography>=50.0.2`. `keyring` and `textual`
  are gone: a default install drops from 21 packages to 3 (`cryptography` and
  its own two, `cffi` and `pycparser`; on Python 3.9 and 3.10 `cryptography`
  also requires `typing-extensions`, so 4).
- Python 3.9.2 or newer (`cryptography` 50 does not support 3.9.0 and 3.9.1).
- Development installs with uv are hash-locked (`uv.lock`) and take no
  dependency release until it has been public for seven days.
- `--json` always prints one JSON document on stdout: the result, or, when a
  command fails, `{"ok": false, "error": "<message>", "exit_code": <n>}`.
  `--version --json` prints what `irondome version --json` prints. Each list
  command (`ls`, `find`, `bunker ls`, `config ls`, `auth show`) prints one
  object with a named list, for example `{"bunker": NAME, "entries": [...]}`,
  and `ls` and `show` both call the one-time-password field `has_totp`.
- Options must be written out in full: `--rev` is refused, not read as
  `--reveal`. A mistyped command, choice or option gets a did-you-mean.
- Durations refuse non-ASCII digits, and an empty `NO_COLOR` counts as unset.
- Where no security chip holds the device key, `init` warns and says why, and
  `status` adds why no chip is used and what would put the key on one.
  `irondome.device` gains `choose()` (a `Choice` that says why), `applies_here()`,
  `chip_requirements()` and `set_progress()` / `report_progress()` (the first
  compile of the Secure Enclave helper is announced before it starts).
- Prompts that ask the owner to approve something end with the bunker they are
  for, `(bunker NAME)`. `run --touch` shows the whole resolved path of the
  program, looks it up once and starts exactly that path; the program still
  sees the name it was called by as `argv[0]`.
- `recovery new` and `recovery remove` re-key the vault, so the old recovery
  key opens neither the vault as it is now nor anything stored in it later. A
  copy of the vault file made before then still opens with the old key and
  shows what it held then.
- An interrupted keyslot change (`passwd`, `auth`) is finished by the next
  command that opens the vault. A `rekey` that fails after the new vault key
  took over still shows the new recovery key, and the next `rekey` finishes
  destroying what the old key opened. Without `--json`, `rekey` and `recovery
  new` print the new recovery key as soon as the new vault is live. With
  `--json`, it is only in the final JSON document. If a re-key is killed
  after its switch (kill -9, a power cut), every session and grant is refused
  until `rekey` is run again. `status`, `doctor` and every owner command that
  unlocks say so, and say how to finish.
- `migrate` reads the 3.x key of a vault without a master password with
  `/usr/bin/security` on macOS and `secret-tool` on Linux; the `keyring`
  package is no longer used. Elsewhere, give the key with `--legacy-key`.

### Removed

- The Textual TUI, the web playground, its Docker/Caddy/cloudflared setup and
  the PyInstaller binaries. A terminal UI was the largest part of the code,
  the largest part of the dependency tree and the one part an agent cannot
  use.
- The interactive menus, the "airspace" session file and the software lockout
  counter.
- Windows from the list of supported platforms: there is no hardware backend
  for it yet and it is not covered by the test suite.

### Still true

No independent audit. Decrypted entries are ordinary Python strings while a
command runs. Argon2id inside `cryptography` leaves a copy of what it is
given: that is a prehash of the master password, never the password, and
IronDome gets the copy overwritten by deriving again from zeros, best effort. Intel Macs are untested, and installing
there builds `cryptography` from source. A recovery key, and a portable backup made with
`irondome export`, outlive `nuke`. Whole-file rollback is not detected. A
grant's use count and a revoke rest on deleting its file, so a copy of the
file put back works again until the grant expires (`rekey` ends it). See
`docs/THREAT_MODEL.md`.

## [3.2.2] — 2026-08-23

Closes three findings from an external review of the 3.2.1 release and its
website. No behaviour changes for anyone using the vault; one on-disk
permission change applies itself to existing vaults on next open.

### Security

- **Vault files were created world-readable.** `secrets/` was `0700`, so
  nothing leaked in practice, but the files inside it — `salt.bin`,
  `.master_hash.enc`, `.master_user.enc`, `.passwords.enc`, the login-attempt
  counters and every backup — were written by a plain `open()` and landed at
  `0644` under a default umask. The directory was the only thing protecting
  them; a permissive umask, a `chmod` on the parent, a backup tool or a copy
  out of the directory removed that single layer. Every write now goes through
  `password_manager/secure_io.py`, which opens with
  `O_CREAT|O_WRONLY|O_TRUNC` at `0600` and `fchmod`s the descriptor before any
  data is written. Directories are created and re-asserted at `0700`. Because
  `O_CREAT` does not touch the mode of a file that already exists, the
  `fchmod` also tightens vaults written by earlier versions the first time
  each file is rewritten, and reopening a vault re-applies `0700` to its
  directories. Covered by `tests/test_permissions.py`, which walks the whole
  data directory after building and using a vault and fails on any file that
  is not `0600` or any directory that is not `0700` — including files a future
  version adds without anyone remembering to update the test.

### Fixed

- **The sdist could not run its own tests.** `tests/conftest.py` holds the
  throwaway-HOME and in-memory-keyring fixtures that `test_nuke.py` and
  `test_keystore.py` depend on, and it was not in `MANIFEST.in`, so those two
  files failed from the published source distribution with
  `fixture 'data_dir' not found`. `MANIFEST.in` now ships `tests/` whole.
- **The website's numbers were typed in by hand and had drifted.** The page
  said 143 tests against a suite that collected 144. `scripts/counts.py` now
  derives the test count from `pytest --collect-only`, the screen count from
  the classes under `password_manager/tui/screens/`, and the version from
  `password_manager/__init__.py`, writing all three to
  `website/src/data/counts.json`. The page imports that file; the test count,
  the per-file breakdown, the screen count and every version string on the
  site now come from the artefacts they describe. `--check` fails a build on
  a stale JSON.

## [3.2.1] — 2026-08-23

A truth-in-advertising release. No new features: every change here either
corrects something the project claimed but did not do, or adds the machinery
that keeps such a gap from reopening.

### Fixed

- **`nuke` missed `.device_id` and still reported success.** `_TOP_LEVEL_FILES`
  did not include the persistent machine identifier written to
  `~/.password_manager/.device_id`, so it survived a command documented as
  erasing all data. Worse, the final step skipped its `rmdir` silently when the
  data directory was non-empty and appended no error, leaving `success: True`.
  `execute_nuke()` now enumerates the data directory and, if anything survives,
  returns `success: False` with every leftover named.
- **A DNS lookup ran on every login.** `get_machine_info()` called
  `socket.gethostbyname(socket.gethostname())` on each login and each
  failed-login accounting pass. On a host whose name is not in `/etc/hosts`
  that sends a query off the machine. The `socket` import is gone; the hostname
  now comes from `platform.node()`, which does not resolve it. The `ip_address`
  field is removed along with its two log-message consumers.
- **`tui/app.py` referenced `SplashScreen` in an annotation without importing
  it** (ruff F821). Now a `TYPE_CHECKING` import.
- **`build-binaries.yml` installed a `[binary]` extra that did not exist**, so
  PyInstaller was never installed and all four matrix legs failed. The extra is
  now defined in `pyproject.toml`.

### Changed

- **Package metadata now matches the code.** The PyPI summary said "AES-256
  encryption … zero-knowledge architecture"; Fernet splits its 32-byte key into
  a 16-byte AES key and a 16-byte HMAC key, so the cipher is AES-128-CBC. The
  description, the `aes-256` keyword and the `zero-knowledge` keyword are
  corrected or removed.
- **README.md and README_PYPI.md rewritten claim by claim.** Removed
  "zero-knowledge" (no such protocol, and no server to keep ignorant),
  "hardware binding" (it is a read of world-readable `/etc/machine-id`, and it
  wraps the master-user record, not the vault), "military-grade" framing,
  "Zero attack surface", and the absolute "Nothing leaves your device. Ever."
  The biometric feature is now described as an OS authentication gate
  (PAM / Touch ID / Windows Hello) in front of the keyring-stored vault key —
  an access gate, not key material. `mlockall` is scoped to the TUI. A new
  "What IronDome does not do" section states the limits up front, and the nuke
  section documents the SSD / copy-on-write erasure limit.
- **`publish.yml` gates on tests and lint.** A `test` job runs
  `pip install -e ".[dev]"`, `pytest -q` and `ruff check password_manager tests`;
  `publish` now `needs: test`. The gate job carries no `id-token` permission, so
  the trusted-publishing credential is minted only after the gate is green.
  Trusted publishing itself is unchanged.

### Removed

- **`zero_bytearray()`** (`tui/security/memory.py`). It had zero callers
  anywhere in the tree while the README advertised "bytearray zeroing" as a
  shipped control. Removed rather than wired up: the vault key is an immutable
  Python `bytes` inside a `Fernet` object and cannot be zeroed in place.

### Added

- **A test suite** — 143 tests in `tests/`, covering the encryption round-trip
  and tamper detection, the PBKDF2 parameters (600,000 iterations, 16-byte
  random salt, fresh IV per message), keystore create/unlock, `nuke`
  completeness in both directions, and a static proof that no module in
  `password_manager/` imports a networking library. No TTY, no biometric
  sensor, no real `HOME` and no real OS keychain are required.
- **`[dev]` and `[binary]` extras**, a `[tool.ruff.lint]` selection and
  `[tool.pytest.ini_options]`, so the lint and test commands mean the same
  thing locally and in CI.

## [3.2.0] — never published

Tagged in the repository (commit `3216a13`) but never released to PyPI: the
publish workflow did not produce a 3.2.0 artifact, so `pip install IronDome`
remained on 3.1.1 and the `nuke` command documented in the README was not
installable. Its contents ship as part of 3.2.1.

### Added

- **`irondome nuke` / `bunker nuke`** — self-destruct. Clears the three OS
  keychain entries first (while the salt is still readable), then overwrites
  each file with random bytes, `fsync`s and unlinks it, then removes the
  directory tree. See the erasure limits in the README: a single in-place
  overwrite is not a guaranteed erase on SSDs, copy-on-write filesystems or
  journaled ext4.

## [3.1.1] — 2026-04-10

Last version published to PyPI before 3.2.1.
