# Legacy vault fixtures

Vaults in the on-disk format of IronDome 1.x-3.x, used by
`tests/unit/test_migrate_v3.py` to test `irondome.migrate_v3`.

Every credential, key and entry in this directory was made up for the
fixtures. Nothing here came from a real vault.

## Where they come from

Each vault was written by the code that wrote such vaults for real. The
source of that code is taken out of this repository's own history with
`git archive` and driven, unmodified, through its ordinary code paths: first-run
setup, saving entries, a backup, a second login, an update. Nothing in this
directory encrypts anything itself.

| Written by | Commit | Driver | Vault key |
|---|---|---|---|
| 3.2.2 | `43b7d67` | `make_legacy_vault.py` | PBKDF2 x 600,000 over `len(username)` + username + password |
| 1.1.0 | `b611aad` | `make_old_vault.py --era v1` | PBKDF2 x 600,000 over `username:password` |
| first commit | `dccb4ed` | `make_old_vault.py --era original` | PBKDF2 x 100,000 over `username:password` |

2.0.0 changed the derivation and converted nothing, and so did 1.0.1 before
it. A vault written under an older derivation stayed that way, and the reader
has to try all three. The fixtures for the two older ones exist because of
that; `git show a981291 -- password_manager/encryption.py` and
`git show d95058a -- password_manager/encryption.py` are the two changes.

The drivers pin `os.urandom`, the clock, the machine identifier and the
process id, redirect `HOME`, and replace the keyring and the biometric prompt
with in-memory stand-ins, so a run touches no real vault, no keychain and no
sensor, and produces the same bytes on any machine. After each run a reader
that uses only `cryptography` decrypts the result; what it reads is recorded
in the fixture as the expected entries. That reader shares no code with
`irondome.migrate_v3`.

One file is altered after generation: `password_manager.log` records the
directory it was written in, and that path is replaced with
`/home/fixture-user`.

## The fixtures

| File | What it is |
|---|---|
| `password_only.json` | 3.2.2, master password only. Three entries; the last was updated after a second login, so it has `updated_at`. |
| `biometric_password.json` | 3.2.2, "Touch ID + master password". Read exactly like the one above; the keyring holds `auth_mode` and `recovery_hash`. |
| `biometric_only.json` | 3.2.2, no master password. The vault key is the keyring's `master_key` entry, base64-encoded twice. |
| `device_id.json` | 3.2.2 as it behaves on Windows: the machine identifier is a UUID in `.device_id` inside the vault. |
| `unicode.json` | 3.2.2 with a Hebrew master username and password, and Hebrew, emoji, combining and right-to-left characters in the entries. |
| `empty.json` | 3.2.2, set up and never used. There is no `.passwords.enc`. |
| `collisions.json` | 3.2.2 with websites that collide as entry names (same site, other case, other account) or are not valid entry names (padding, control characters, 250 characters). |
| `two_hundred.json` | 3.2.2 with 200 entries. Every 25th shares one website; one has 5,000 characters of notes. |
| `v1_1_0.json` | 1.1.0. Files in `secrets/`, the 1.0.1-1.1.0 derivation. |
| `v1_0_0.json` | The `password_manager` package of the first commit. Files in `secrets/`, the original derivation, verifier SHA-256(salt + password). |
| `script_2025.json` | The single-file program of the first commit. The four files sit directly in the data directory, and the machine identifier is the fixed fallback string (`os.getlogin()` failed, as it does without a terminal). |

The three modes of 3.2.2 use the generator's default credentials
(`fixture-admin` / `Correct-Horse-Battery-9`) on the machine
`fixture-user@fixture-host`. Each fixture records its own.

## The file format

A fixture is one JSON file, read and written by `archive.py`:

```
name, about            what the fixture is
written_by             version, commit and driver that produced it
mode, kdf, layout      how the vault is opened and laid out
machine_id             what the system key was derived from
master_username, master_password, stored_username
vault_key              the Fernet key of the password store
keyring                what the OS keychain held (service "IronDome")
recovery_key           the 3.x recovery key, where one was issued
entries                the plaintext entries, as the independent reader decrypted them
directories, files     the data directory itself: path, mode, SHA-256, base64 content
```

It is a file rather than a directory tree for three reasons. The repository's
`.gitignore` excludes `secrets/`, `backups/`, `*.enc`, `salt.bin` and
`password_manager.log`, so a tree would silently lose the files that matter.
Git records neither file modes nor empty directories, and line-ending
conversion would damage a 16-byte salt on some checkouts. And a test cannot
modify or destroy a fixture it can only unpack somewhere else.

## Rebuilding and checking

Needs `git`, this repository's history, and a Python with `cryptography`
(nothing else: not `keyring`, not `textual`).

```
python tests/fixtures/v3/build_fixtures.py check     # regenerate elsewhere, compare byte for byte
python tests/fixtures/v3/build_fixtures.py build     # regenerate in place
python tests/fixtures/v3/build_fixtures.py build --only unicode collisions
```

The committed files were built with CPython 3.11.15 and `cryptography` 50.0.2
and reproduced byte for byte with CPython 3.9.6 and 3.13.11.

To try a migration by hand on a throwaway copy:

```
python tests/fixtures/v3/build_fixtures.py unpack biometric_only /tmp/old-vault
IRONDOME_LEGACY_DIR=/tmp/old-vault irondome migrate
```

## Adding a fixture

Add a `Fixture(...)` to `FIXTURES` in `build_fixtures.py`, run `build`, add
the name to the lists at the top of `tests/unit/test_migrate_v3.py` and to the
table above.
