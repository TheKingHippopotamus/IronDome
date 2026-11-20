# Changelog

All notable changes to IronDome are recorded here.
This project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The version number lives in exactly one place, `src/irondome/__init__.py`;
`pyproject.toml` reads it from there via `[tool.setuptools.dynamic]`.

## [4.0.0] — 2026-11-20

A new vault, a new command line and a new purpose. Version 3 published six
things it could not do: five on its website, and the cipher on its PyPI page.
Version 4 exists to make five of them false, and to make the vault usable by AI
agents without handing them the vault. The sixth, no independent audit, still
stands.

**This is a breaking release.** The vault format, the data directory, the
Python package name and every command changed. `irondome migrate` converts a
3.x vault, verifies every entry and leaves the old vault untouched unless
`--destroy-old` is given and every entry matched.

**Published by hand.** The repository moved to its present home on the day of
this release, and the release workflow had never run there: the gate was run
on the maintainer's Mac, the files were built there and uploaded with a
project token, and PyPI holds no provenance attestation for them.
`SECURITY.md` says exactly what was run and how to check the files.

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

### Found by using it, before release

The whole test suite passed, and then a reviewer was given the built package,
the published texts and a machine to watch, and no source code. What that
found, and what was done:

- **No command accepted the recovery key.** The key was tested through the
  Python interface only. `irondome recovery use` now opens the vault with
  it, on any machine, and sets a new master password bound to that machine;
  the refusal that told people to "use your recovery key" names the command.
- **A session could make a grant that outlived it** (a one-minute session, a
  30-day grant, no password). Under a session alone the commands now refuse
  a grant that would outlast it, and any setting of what agents may do with
  an entry, until the master password is given again; what a session does is
  recorded as `session`. The token still unwraps the vault key, so this
  binds IronDome's commands, not a program that uses the token itself.
- **Masking missed ordinary encodings of a generated password**: percent-
  encoding as `encodeURI` and Python's `quote` write it, lower-case escapes,
  HTML escaping, JSON inside JSON, and a secret of several lines printed with
  a prefix on each line. All are masked now.
- **After a re-key nothing could read the audit log from before it.** The log
  is still set aside, and what reads it now travels in the new vault's
  encrypted index: `irondome audit --archive NAME`.
- **`run --timeout` stopped only the command itself** and left the programs it
  had started running with the secret in their environment. They are stopped
  with it.
- **The program contradicted itself about a software TPM** ("hardware" in
  `status`, "not a security chip" in `init`). Every place now asks the same
  question of the machine.
- **A lowered Argon2id cost and a weak master password went unmentioned.**
  `init` and `status` show the cost; `init` and `export` warn when it is
  below the default, and `init` remarks on a weak password.
- Stated as limits, not changed: anything running as you can push a TPM into
  lockout with wrong passwords; `.env.irondome` in the working directory is
  read without asking (the variables it supplies are now listed; what such
  a file may hold was narrowed later, below).

### Found by a second person, using the build with those fixes

A second reviewer got the fixed package, the changed texts, the first report
and the same kind of machine, and again no source code. The recovery key
now got them back in on a lost device key file, a cleared TPM and a TPM in
lockout. What that pass found, and what was done:

- **`irondome verify` printed FAIL for `bunkers-isolated` on a TPM**, every
  run, while the claim held: the check took the TPM's earlier refusal of
  another bunker's grant for a failure. The check accepts that refusal, and
  the suite now runs every self-check on the software TPM.
- **`--value-stdin` kept the first line of a key of several lines and said
  `ok`.** A value that is piped in and is the last thing on stdin is now
  read to the end of input, up to 64 KiB: several lines exactly as they
  came, one line without the line breaks after it; a value of nothing but
  line breaks is refused. With stdin a terminal, whatever a command would
  read from it (`--password-stdin`, `--value-stdin`, `--totp-stdin`, the
  value of a `--field`) is typed at a hidden prompt, and `--note-stdin`
  says that the notes are shown and how to finish them.
- **Masking still passed ordinary encodings**: bash's `printf %q`, JSON as
  Go and PHP write it, CSV quoting, a value percent-encoded twice, hex with
  a colon, a hyphen or a space between the bytes. These are masked now; the claim lists what
  is masked form by form, and what is not.
- **A re-key killed at its last step left a whole vault in a temporary
  file**, which opened with the recovery key that run had printed. The next
  write to the vault now removes such files.
- **While a re-key was unfinished, `audit --verify` said ALTERED.** It now
  says the log cannot be checked until the re-key is finished, and how.
- **`.env.irondome` could set `PATH`, and `-q` hid the notice about the
  file.** The notice is printed with `-q` too. A file nobody named may now
  only ask for a secret under the name its owner gave it
  (`NAME=irondome://NAME`, as `--env NAME` does); anything else is refused
  until the file is named with `--env-file`. (A first fix refused a list of
  dangerous names, and the reviewer got a secret out through `LESSOPEN`,
  which was not on it. A second allowed any reference, and the reviewer
  pointed `PATH` at a user name they could guess.)
- **A grant made under a session outlived `irondome lock`.** Ending a
  session now revokes the grants made under it, and a label may not
  imitate the mark that ties a grant to its session.
- **A session used without a terminal was logged as `agent`.** It is logged
  as `session`, as the texts said.
- **A memory cost the machine could not give ended in a traceback.** It is
  an error in one line.
- `passwd` and `recovery use` remark on a weak new master password as
  `init` does; every unlock says when other users can reach the bunker's
  files; `clipboard_clear_seconds` takes `45s`; a file-size limit is named
  as one.
- Stated, not changed: session and grant files and the audit log show
  their bookkeeping in clear (kind, times, uses left, label); the MCP
  server keeps the values it used in memory while it runs; `recovery use`
  does not revoke grants; a scripted `init` writes the recovery key to
  stdout.

The same reviewer then checked that build by hand, twice: every item above
held, and each time smaller faults in the fixes themselves were found (four,
then three). They are fixed in the entries above. A last pass ran the final
three fixes as a checklist and found no fault in them, only wording, which
was corrected.

### Found by using it on a Mac

Both trials above ran on Linux. A third one ran on a Mac, against its real
Secure Enclave, in a throwaway home inside a macOS sandbox: the published
texts, the release wheel, no source code, password mode only (nothing that
needs a finger). What it found, and what was done:

- **Copying both folders back undid `nuke`, on the same Mac.** The Secure
  Enclave key is a sealed file under `~/Library/Application Support`, and
  a whole-home backup holds it next to the vault. With both restored, the
  master password opened the vault again, and so did a grant token and a
  session token from before. `nuke` had printed that no copy of the vault
  files would open. The documents said this only as a forensic-lab case, and
  the tests restored the vault directory alone. Now the device directory is
  marked as left out of Time Machine when it is created (the mark
  `tmutil addexclusion` writes; `irondome doctor` reports it), `nuke` says
  which copy it cannot reach, and README, THREAT_MODEL and the
  `crypto-erase` claim say that a clone, a disk image, a local snapshot or a
  backup program that ignores the mark still holds the key. A restore from
  Time Machine then comes back without that folder (no backup was run to
  see it), and the recovery key is what opens the vault; a vault made with
  `--no-recovery` does not survive such a restore, and `init` and `doctor`
  say so.
- **A damaged Secure Enclave key file gave advice that could not work**: a
  password vault was told that fingerprints had changed and to run
  `irondome auth touchid`. For a key no finger releases the message now says
  what happened and names `irondome recovery use`.
- **A damaged compiled helper was never compiled again.** Every command
  failed with "helper failed (-9): no detail", `doctor` called the helper
  compiled and advised installing tools that were installed, and a new
  vault quietly got a file-based key. The helper's SHA-256 is now recorded
  beside it; one that does not match is compiled again (one build at a
  time), and `doctor` says so.
  This is a check against a damaged cache, not against a program running as
  you, which can replace the record as well.
- **"café" typed with one code point for the accented letter and with two
  were two entries that looked the same.** Entry names are now stored and
  compared in one Unicode form (NFC), as the master password already was.
- `irondome status >&-` (a closed stdout) ended in a traceback; a closed
  stdin, stdout or stderr is now the null device.
- `status`, `auth show` and `doctor` called a cut-off or empty device key
  file "present"; they now say it is damaged, and `doctor` exits 1 and names
  the recovery key.
- `import` compared names by letter case alone; a name in the other Unicode
  form now meets the entry that is there, under whichever `--on-conflict`.
- Wording: in password mode `init` no longer says "Secure Enclave with
  touchid" (now "Secure Enclave, Touch ID available"); `backup ls` over an
  unreadable vault reads as a sentence; a grant for `--ttl 1m` is announced
  as 60s, not 59s; `verify` says that it takes a minute or two; the help of
  `bunker create` gives the whole name rule; `--no-mask` says that without
  it the command's output is a pipe. ARCHITECTURE now lists the lock files,
  the environment variables a person sets, and how names are matched.
- Stated, not changed: with `IRONDOME_NO_TOUCH=1`, `init` still offers the
  Touch ID modes (creating such a vault raises no prompt); entry names
  ignore letter case while aliases and field names do not; IronDome puts its
  own modes (0700, 0600) back on its folders and files when it writes; the
  owner's own `get` and `otp` leave no audit record; `nuke` and `bunker rm`
  at a terminal ask for a typed word, not for the password.

An independent reviewer then read these changes and found three faults in
them (a grant still announced as 59s now and then, the importer and the
search not yet using the one Unicode form), which are fixed above.

Not covered by that trial: everything that needs a finger, the clipboard, a
second Mac, a locked screen, and memory (the tools for it raise dialogs or
need more rights than the lab had).

### Found with a finger on the sensor

No test can touch a sensor, and the trial on a Mac above ran with Touch ID
switched off. So the owner ran every Touch ID path by hand, once, on the
release build of the commit before this one, in a throwaway home: 15 steps,
seven touches, four presses of Cancel, each step's outcome written down
(`irondome verify --touch`, a vault that opens with a finger, Cancel falling
back to the master password, an agent refused without leave to ask,
`irondome approve` for one minute and the grant it makes, `irondome run
--touch`, the audit log, and a vault that needs the password and a finger
together). Every refusal and every acceptance was the one the documents
promise. What it found, and what was done:

- **Everything looked the same.** One font, one colour, long unbroken lines:
  hard to follow. At a terminal IronDome now lays its output out: prose is
  wrapped to the terminal's width (92 columns at most) and continues under
  where it began, a result carries a green mark, a warning a yellow one and
  an empty line between it and the messages before and after it, an error a
  red one and bold text, the commands a message tells you to type are
  coloured, progress lines are faint, the question of a prompt is bold (not
  on Windows), tables have ruled headings and coloured states, a long last
  column continues under itself, `doctor`'s findings carry the same marks,
  and a recovery key stands in a frame. Picking the commands out of a
  sentence is a judgement; it colours and changes nothing else. A value a
  person may copy is never wrapped or trimmed: what `show --reveal` prints
  is the value, character for character. A pipe and a file get exactly the
  lines they got before, and so does a terminal when colour is off
  (`--no-color`, `NO_COLOR`, `TERM=dumb`): that plain form is the stable
  one, and the whole test suite reads it. A program that drives a terminal
  of its own (expect, `script`) sees what a person sees, and sets `NO_COLOR`
  for the plain lines.
- **`init` in a Touch ID mode went as far as the chip before refusing** when
  the owner had forbidden Touch ID prompts: no dialog appeared, but the
  helper was compiled and the error spoke of "this vault", which did not
  exist. `init` and `bunker create` with `--mode touchid` or `--mode
  touchid+password` are now refused before anything is asked or made, by
  `--no-touch` and by `IRONDOME_NO_TOUCH=1` alike, in the words `auth
  touchid` already used; `auth touchid` honours the environment switch as it
  did the flag; and `init` no longer offers the Touch ID modes where the
  prompt is forbidden.

An independent reviewer then read the new output code. The first version
wrapped every long value, a password shown by `show --reveal` included: a
tab became spaces, spaces at the end were dropped, a long passphrase was
broken over two lines. It also took prose for part of a command in one
message and coloured only part of the command in six, read the terminal's
width before `COLUMNS`, and built two more copies of a recovery key than it
needed to. All of that is fixed above, each with a test.

One answer in that run is not explained: at step 4 the owner answered that
the enrolment dialog did not read "enrol Touch ID for your IronDome vault",
which is the text the code sends. The step-15 exit status the trial's script
flagged was the script's own mistake (it read the status of the wrong
command in a pipeline); the product had refused, as its error line shows.

Not covered by that run: adding or removing a fingerprint, the MCP server's
reveal path, a vault with no master password at all, a locked screen.

### Found by running it on machines it had not met

Everything above was run on one Mac and in one Linux container on it. The
suite then ran for the first time on GitHub's machines (Ubuntu 24.04 and
macOS 15, six Python versions) and on a Debian 13 machine under an ordinary
login. Most of what failed there was the tests' own assumptions about the
machine; two things were the product's:

- **With stdout or stderr closed (`>&-`), output could go into a file.**
  Python leaves a closed stream as nothing, and a file opened later takes
  its number. A closed stream now gets the null device, and what happens to
  hold descriptor 1 or 2 is not written to.
- **`.env.irondome` was refused on Debian and Ubuntu as soon as it was
  written.** Each user there has a group of their own and new files are
  writable by it, and `irondome run` refused any found file its group could
  write. A group that only the user is in is now accepted; a shared group,
  every-user write permission and another owner are refused as before, and
  the message says which of the three it was.

- **On macOS 15 a copy of the prehash of the master password stayed in
  memory after `lock`, in about half the runs.** Argon2id inside
  `cryptography` copies what it is given and frees the copy unwiped;
  IronDome had it overwritten by running Argon2id again on zeros, which
  works only when the allocator hands the same block back. That was a
  stated limit, said to need macOS's zeroing of freed memory turned off;
  GitHub's macOS 15 machines behaved that way as they are. Argon2id now runs in a child process made for the one
  derivation: it is sent the prehash through a pipe, sends the key back and
  exits, and the copy ends with it, whatever the allocator. Measured on a
  Mac with zeroing off: the copy was left in 7 of 10 derivations before;
  after, in none of 20, and in none of 6 whole sessions ending in `lock`.

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
it is left in a child process that exits when the key is made. Intel Macs are untested, and installing
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
