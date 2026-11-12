# Architecture

How IronDome 4 is put together. For what it defends against, read
[THREAT_MODEL.md](THREAT_MODEL.md); for the proof, [CLAIMS.md](CLAIMS.md).

## The idea in four lines

1. One random 256-bit **vault key** encrypts everything. It is never stored.
2. The vault file carries **keyslots**: wrapped copies of the vault key, each
   opened by a set of factors.
3. Every keyslot that involves you (your password, your finger) also needs a
   **device secret** that lives in, or is sealed to, this machine's security
   chip, or, where there is none, sits in a file in the device directory,
   outside the vault. Without the machine there is nothing to attack. The
   deliberate exceptions are portable: the recovery slot, and the one password
   slot of a file written by `irondome backup`.
4. An AI agent never gets the vault key or your password. It gets a **grant**:
   a separate, expiring snapshot of exactly the values you named, good for
   one use unless you allow more.

## Key hierarchy

```
 master password ──Argon2id──▶ password key ───────────────┐
                                                           ├─HKDF─▶ key-encryption key ─AES-256-GCM─▶ vault key
 chip or file ──▶ device secret ──HKDF──▶ device key ──────┘

 recovery key (160 bit) ──HKDF──▶ recovery factor ──HKDF──▶ key-encryption key ─AES-256-GCM─▶ vault key

 vault key ─┬─HKDF─▶ index key
            ├─HKDF─▶ entry key (one per entry)
            └─HKDF─▶ audit key ─HKDF─▶ per-grant audit keys
```

Every HKDF is HKDF-SHA256. In a keyslot the device key and the
key-encryption key are salted with the vault id and the slot id, and the
wrapped key's associated data names both and the slot's kind, so a wrapped
key cannot be moved to another slot or another vault. A device (Touch ID)
slot has the device key as its only factor. For a password slot the password
key also yields, through HKDF, the value handed to the device backend as its
`auth`: a TPM makes it the authorisation value of the NV index, so the chip
itself checks the password and counts wrong guesses; the Secure Enclave and
file backends ignore it.

| Keyslot | Factors | Opens with |
| --- | --- | --- |
| password | Argon2id(master password) + device secret | the password, on this machine |
| device | device secret under a biometric policy | Touch ID, on this machine |
| recovery | a 160-bit key shown once | the recovery key, on any machine |
| backup password | Argon2id(backup password), no device secret | the password, on any machine (only in a file written by `irondome backup`) |

Setup modes are just combinations of slots:

| `irondome init --mode` | Slots created |
| --- | --- |
| `password` (default) | password (device secret released without a prompt) + recovery |
| `touchid` | device (Touch ID) + password as fallback + recovery |
| `touchid+password` | one password slot whose device secret needs Touch ID + recovery |

The recovery slot is made unless `--no-recovery` is given. `--mode touchid
--no-password` makes no password slot, so the recovery key is the only
fallback; that combination refuses `--no-recovery`, because a Touch ID key is
invalidated for good when the enrolled fingers change.

Changing the password or enrolling a finger replaces keyslots and leaves the
records untouched: the vault is written with no snapshot of its old keyslots,
and the device secrets of the slots that went are destroyed (`passwd` also
deletes the snapshots and ends the sessions). Replacing or removing the
recovery key cannot work that way, because a copy of the old recovery slot
would go on giving the vault key to whoever kept one: `irondome recovery new`
and `irondome recovery remove` re-key the vault as `irondome rekey` does,
with a new vault key and vault id, every entry re-encrypted, every session
and grant ended and the snapshots deleted.

## Device backends

`irondome.device` defines one interface (`probe`, `enroll`, `unseal`,
`destroy`, `exists`, and `destroy_all`, which `nuke` calls so that erasure
does not depend on reading the vault) and three implementations, strongest
first:

| Backend | Where the secret is | Extra enforcement |
| --- | --- | --- |
| `macos-se` | A P-256 private key generated inside the Secure Enclave. The device secret is an ECDH shared secret that only the chip can compute. | Under the biometry policy the chip refuses the operation until a fingerprint matches. Device-policy keys work after the first unlock since boot, also while the screen is locked; biometry and presence keys only while it is unlocked. |
| `linux-tpm2` | A 32-byte value in a TPM 2.0 NV index. | For a password slot the index's authorisation value is derived from the password: the TPM verifies it and rate-limits wrong guesses (dictionary-attack lockout). The index that binds sessions and grants has an empty authorisation value and `no_da`: any process allowed to use the TPM can read it. |
| `software` | 32 random bytes in a `0600` file in the device directory. | None. Reported as "software", never as hardware. |

The Secure Enclave is reached through `irondome_se.swift`, about 250 lines and
the only native code in the project. It is compiled on your machine with
`swiftc` (Xcode Command Line Tools) from the source in the package the first
time it is needed, and cached under a name taken from the source's SHA-256; no
binary is downloaded. It does three things: report whether a Secure Enclave
and biometry are usable, create a key, and run one key agreement. It never
sees the vault, the password or the vault key.

The vaults and the device material are kept apart on purpose, so a backup or
sync of a vault never carries what binds it to the machine:

```
~/.irondome/                                   the vaults ($IRONDOME_HOME overrides)
  default-bunker                                set by `irondome bunker use`
  bunkers/alpha/vault.irondome, backups/, caps/, audit.log, config.json
  bunkers/bravo/...

~/Library/Application Support/IronDome/device/  macOS; on Linux $XDG_STATE_HOME/irondome/device
                                                (default ~/.local/state/irondome/device);
                                                $IRONDOME_DEVICE_DIR overrides
  helper/                                       the compiled Secure Enclave helper, shared
  bunkers/alpha/                                what binds alpha to this machine
  bunkers/bravo/
```

`backups/` holds the automatic snapshots of earlier versions of the vault
file (ten by default); `caps/` holds one file per session or grant.

A *bunker* is one vault with its own vault key, keyslots, device secrets,
sessions, grants, audit log and settings. Nothing is shared between bunkers
except the helper binary. Which bunker a command works on: `--bunker`, then
`IRONDOME_BUNKER`, then the bunker holding the session or grant token in the
environment, then the recorded default, then `alpha`.

## The vault file

One JSON document, `vault.irondome`:

```
format, version, vault_id, created, generation
keyslots:  [ ... ]
index:     AES-256-GCM( index key )   names, usernames, URLs, tags, revisions, aliases, agent policy
records:   { entry id: AES-256-GCM( entry key ) }   password, TOTP seed, notes, fields, history
```

* Everything about an entry is encrypted, including its name.
* Each ciphertext is bound to its place through the associated data (vault id,
  entry id, revision / generation), so records cannot be swapped between
  entries or rolled back individually.
* Plaintexts are length-prefixed and padded to fixed blocks (256 bytes for a
  record, 1024 for the index), so ciphertext sizes do not reveal password
  lengths.
* Writes are atomic (temp file, fsync, rename, fsync of the directory),
  serialised by a lock file, and the previous file is kept as a snapshot.
* Not detected: a rollback of the *whole* file to an earlier copy (that needs
  a counter outside the file). Not hidden: the number of entries.

## Memory

Key material — the password as typed, Argon2id output, device secret,
key-encryption key, vault key, subkeys — lives only in `SecureBuffer`s:
anonymous pages outside the Python heap, locked into RAM, filled in place
(the KDFs derive *into* them, the cipher decrypts *into* them, the Secure
Enclave helper's pipe is read *into* them) and overwritten with zeros as soon
as they are done with. On Linux those pages are also left out of core dumps
and read as zeros in a forked child. The process disables core dumps
(`RLIMIT_CORE = 0`) and, on Linux, marks itself non-dumpable, unless
`IRONDOME_DEBUG=1` is set.

Two things are not held that way. The recovery key exists as text, to be
shown once or typed; its decoded bytes are held in locked memory and zeroed
right after use. Decrypted
entries are ordinary Python strings for as long as a command runs (see
[THREAT_MODEL.md](THREAT_MODEL.md)).

## Agents

```
 owner ── irondome grant create GITHUB_TOKEN --ttl 15m ──▶ token ──▶ agent environment
 agent ── IRONDOME_GRANT=token irondome run --env GITHUB_TOKEN -- gh pr create
              │
              ├─ opens the grant (a counted grant loses one use; its file is deleted after the last)
              ├─ starts `gh` with GITHUB_TOKEN in its environment
              ├─ masks the value in everything `gh` prints
              └─ appends an encrypted record to the audit log
```

* **Alias** — the name an agent uses instead of a secret: one field of one
  entry (`irondome alias set GITHUB_TOKEN github`).
* **Reference** — `irondome://alias`, `irondome://entry` (its password) or
  `irondome://entry/field`, usable in environment variables and `.env` files,
  so those files hold no secrets.
* **Grant** — a bearer token plus a small encrypted file, `caps/<id>.json`,
  holding a snapshot of the named values, sealed under a key that needs both
  the token and the bunker's capability device secret (kept under the device
  policy, so this machine releases it without a prompt). Scoped, expiring,
  limited to one use unless it is given more (or `--unlimited`), mode `use`
  (inject only) or `reveal`. Its use count and a revoke are enforced by
  rewriting or deleting that file. A grant for a `totp` field holds only the codes for its lifetime,
  never the seed. A grant also carries its own audit key, so it can record its
  own uses but cannot write a line that passes as the owner's. Sessions
  (`irondome unlock`) are sealed the same way; a session's payload is the
  vault key.
* **Touch ID approval** — on a Mac, an agent with no grant can ask: the owner
  sees a Touch ID prompt naming the secret and the command. Only entries the
  owner marked for agents are reachable this way. `irondome approve` turns one
  touch into a use-only grant for at most an hour.
* **MCP server** — `irondome mcp` exposes `list_secrets`, `run_with_secrets`,
  `get_totp` and `reveal_secret` (only where the owner allowed showing the
  value) over stdio, under the same rules.
* **Audit log** — every use of a session or grant and every change, encrypted
  and hash-chained; `irondome audit --verify` detects an edited, inserted,
  reordered or removed line, but not the removal of the newest lines: nothing
  outside the log records how long it should be.

## Source map

| Module | Responsibility |
| --- | --- |
| `paths` | the two roots, bunkers, atomic writes, locks, secure deletion |
| `secmem` | locked, wipeable memory; reading secrets without `str` |
| `crypto` | Argon2id, HKDF-SHA256, AES-256-GCM wrappers; padding |
| `keys` | keyslots and key-encryption keys |
| `device/` | Secure Enclave (`macos_se`, `irondome_se.swift`), TPM 2.0 (`linux_tpm`) and file (`software`) backends |
| `vault` | file format, records, index, atomic commits, snapshots |
| `unlock` | setup modes and the unlock order |
| `caps` | sessions and grants |
| `audit` | encrypted, hash-chained log |
| `otp`, `generator` | TOTP; passwords and passphrases |
| `agent/refs`, `agent/runner` | references, env files, injection and output masking |
| `mcp` | Model Context Protocol server (stdio) |
| `scan` | finding vault secrets in files where they do not belong |
| `clipboard` | copying a secret to the clipboard and taking it off again |
| `config` | non-secret settings (`config.json`) |
| `errors` | every way IronDome refuses, and its exit status |
| `nuke` | cryptographic erasure and cleanup |
| `migrate_v3` | reading IronDome 3.x vaults |
| `interop` | import/export formats |
| `doctor`, `selftest` | diagnostics; `irondome verify` runs the checks behind `claims.json` |
| `memscan` | searching this process's whole address space for copies of a secret |
| `cli/` | the command line |

Runtime dependencies: the Python standard library and
[`cryptography`](https://cryptography.io). Nothing else. Each hardware backend
also uses a system tool: `swiftc` (Xcode Command Line Tools) builds the Secure
Enclave helper, and tpm2-tools talk to the TPM.
