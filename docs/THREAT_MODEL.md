# Threat model

What IronDome 4 protects, against whom, and where it stops. Every claim cited
below is held by the tests listed in [CLAIMS.md](CLAIMS.md). `irondome verify`
runs the checks for most of them again on your own machine; CLAIMS.md says
which ones only the test suite checks.

## What is being protected

| Asset | Where it lives |
| --- | --- |
| Your secrets: passwords, API keys, TOTP seeds, notes | Encrypted records in `~/.irondome/bunkers/<name>/vault.irondome`, one vault per bunker (the first is `alpha`) |
| The **vault key** (256-bit, random) that encrypts them | Never stored. Wrapped in *keyslots* inside the vault file |
| The **device secret** that every password/biometric keyslot needs | Secure Enclave (macOS), TPM 2.0 NV storage (Linux), or a file in the device directory where there is no chip |
| Your **master password** | Nowhere. A 32-byte prehash of it is stretched with Argon2id, and both are discarded |
| The **recovery key** | Shown once at setup. On paper, with you |

## Adversaries and what they get

### 1. Someone who obtains a copy of your vault file

A stolen backup, a synced folder, a disk image, a laptop thief who pulls the
SSD, a cloud provider.

They get ciphertext. Entry names, usernames, URLs and tags are encrypted too;
what stays visible is how many entries there are and their padded sizes, when
the vault was created and how often it has been written, and how it opens
(keyslot kinds, backend, Argon2id cost).

They **cannot guess your master password**, however weak, because the
key-encryption key is derived from the Argon2id-stretched password **and** the device
secret, and the device secret is not in the file. There is nothing to test a
guess against. This holds on every backend, including the file-based one, as
long as the device directory was not copied along with the vault.

*Exception, by design:* the recovery key opens a copy of the vault without
the device. That is its purpose. Guard it like the vault itself.

### 2. Someone with your computer, powered off or locked

With a Secure Enclave or TPM the device secret cannot be extracted from the
machine, so the attack must happen on the machine itself.

* **Linux + TPM 2.0:** each password guess must be presented to the TPM, which
  verifies a password-derived value and enforces its dictionary-attack lockout.
  Offline guessing is impossible; online guessing is rate-limited by the chip.
* **macOS + Secure Enclave, password mode:** the attacker must be able to run
  code as you on this Mac for the Secure Enclave to cooperate. The device key
  works once the Mac has been unlocked since it started, including while the
  screen is locked, so that SSH sessions, scheduled jobs and agents holding a
  grant keep working; before the first unlock after a restart it works for
  nobody. Then each guess costs one Argon2id evaluation.
* **macOS + Secure Enclave, Touch ID modes:** the Secure Enclave will not run
  the key operation until its sensor path reports a matching finger. The check
  happens inside the chip. No software, including the kernel, can skip it or
  read a key instead, because no key exists outside the chip.

### 3. Malware already running as you

This is the hard case for every password manager, and the honest answer has
two parts.

**While the vault is locked:**

* Touch ID modes: the malware cannot open the vault. It can pop up a Touch ID
  prompt and hope you touch the sensor, so read the prompt.
* Password mode: it must capture the master password (for example with a
  keylogger) the next time you type it. Nothing a userspace program does can
  prevent that.

**While a command is running:** IronDome keeps the window small. IronDome
holds key material only in memory outside the Python heap, locked into RAM
where the system allows it, and wipes it when the command
finishes (Argon2id inside `cryptography` copies what it is given, which is a
prehash and never the master password; that copy is overwritten afterwards,
best effort: see the limits below). IronDome
turns off core dumps for itself, and on Linux marks itself non-dumpable so
other processes of the same user cannot attach to it or read its memory
(claim [`process-hardened`](CLAIMS.md#process-hardened); `IRONDOME_DEBUG=1`
switches both off). A process with root or debugger rights can still read
anything, as with every program.

### 4. An AI agent you gave access to

The agent is assumed to be capable, well-meaning and **steerable by whatever
text it reads** (prompt injection). The design goal is that secrets never
enter its context window unless you chose that, and that anything it does is
limited, attributable and revocable, within the limits listed below.

* An agent never has the master password or the vault key. It has either a
  **grant** (a token for exactly the values you named, for a limited time and,
  unless you say otherwise, a single use) or the ability to ask you for
  **Touch ID**.
* A grant is a separate encrypted snapshot. It contains nothing that was not
  named. A grant for a one-time-password field contains only the codes valid
  during its lifetime, never the seed.
* `irondome run` puts secrets into a child process's environment and masks
  them in that process's output, so they do not land in the transcript.
* Every access is written to an encrypted, hash-chained audit log.
* Sessions and grants are bound to the machine. The key that seals a session
  or grant needs both its token and a device secret held by the Secure Enclave,
  the TPM or the device file, so a copied token and capability file open
  nothing on another machine, in another bunker, or after `rekey` or `nuke`. An
  agent in a container that can read the vault directory but not the device
  directory cannot use grants at all.
* Use counts and revoking a single grant are enforced by deleting the grant's
  file. An agent that can write the bunker's `caps/` directory can copy the
  file before a use or a revoke and put it back, and the grant works again
  until it expires; the audit log records each such use. To end a grant
  against such an agent, run `irondome rekey`, which destroys the device
  secret every grant is bound to, and rotate the secrets the grant covered.
* A re-key (`rekey`, `recovery new`, `recovery remove`) first puts the new
  vault in place, then destroys what opened the old one: its device keys,
  snapshots, sessions and grants. It builds the new vault in a staging file
  (`.tmp-rekey-*.irondome` in the bunker's directory) and deletes that file
  last. If it is stopped in between (kill -9, a crash, a power cut), that
  file still holds the live vault's id. While it does, IronDome fails closed:
  every session and grant is refused, old or new. `status`, `doctor` and
  every owner command that unlocks warn, and they say to run `irondome
  rekey`, which finishes the job. Without `--json`, the new recovery key is
  printed as soon as the new vault is live, before anything a crash could
  stop. With `--json`, it is only in the one JSON document printed at the
  end, so a re-key killed before then never shows it. The master password
  (or Touch ID) still opens the vault, and the next `rekey` shows a new
  recovery key. A re-key that finished, except for old device keys it could
  not destroy, keeps the list of those keys in the vault's encrypted index.
  Every unlock warns about them until a later `rekey` destroys them.

**An agent in your terminal.** Agent tools often run their commands in your
own terminal session, so IronDome treats such an agent as you for prompts. It
cannot answer a hidden password prompt or type a confirmation into that
terminal (short of injecting keystrokes, which is what malware does: see
section 3), and a flag proves nothing: it can pass `--yes` or
`--password-stdin` as easily as you. That is why every irreversible action
needs a typed confirmation, a password typed at a hidden prompt, or the master
password itself on stdin. A session token exported in that terminal is the one
exception, by design: it is full access, so never let an agent inherit one.

**Where this stops:** a process that receives a secret can leak it on
purpose. An agent told to run `sh -c 'echo $TOKEN | rev'` will defeat output
masking. Injection keeps secrets out of transcripts by default; it is not a
sandbox. Give agents narrow, short-lived grants, and rotate what they used.

### 5. Someone who gets the disk after you ran `irondome nuke`

`nuke` destroys the device secrets first (the vault's, and every one its
sessions and grants were bound to), then overwrites and deletes everything
else. Without the device secret, no keyslot that depends on your password or
fingerprint can ever be opened again, and no session or grant token opens
anything, so it no longer matters what an SSD's wear-levelling kept of the
vault ciphertext.

How final the destruction of the device secret is depends on the backend:

* **TPM 2.0:** the secret existed only inside the chip. The chip deletes it.
* **Secure Enclave:** the private key never left the chip, and what is deleted
  is the sealed blob that names it. A forensic lab that recovered that blob
  from the SSD would still need *this Mac's* Secure Enclave to use it, and
  under a Touch ID policy your finger as well.
* **File-based:** the device key file is overwritten and unlinked. On an SSD
  that is best effort. `irondome status` tells you which backend you have.

A recovery key on paper is not reachable by `nuke`. If a copy of the vault
file survives somewhere and the recovery key survives too, that copy opens.
Neither is a portable backup made with `irondome export`: it needs no device
secret and opens with its own password.

`irondome recovery new` and `irondome recovery remove` re-key the vault, so
the old recovery key opens neither the vault as it is now nor anything
stored in it later. A copy of the vault file made before then still opens
with the old key and shows what it held then.

## Non-goals and known limits

* **No independent audit.** The test suite is ours. Nobody outside the project
  has reviewed the cryptography. Treat IronDome as beta software.
* **Decrypted entries are ordinary Python strings** for as long as a command
  runs. Only IronDome's own copies of *key material* stay in locked, wiped
  memory.
* **Copies made inside `cryptography`.** Argon2id copies what it is given
  into memory it frees without overwriting. So IronDome never gives it the
  master password: it derives a 32-byte prehash from the password with HKDF
  and Argon2id stretches that. The copy is then of the prehash. By itself the
  prehash opens nothing but that one keyslot (with the vault file and the
  device; a portable backup file alone, since its keyslot has no device
  secret). Whoever reads it and has the keyslot's salt from the vault file
  can also test guesses of the password against it at the speed of SHA-256,
  with no device and no TPM counting wrong guesses, and a password found
  that way opens whatever it protects. IronDome cannot prevent that copy and does not
  write to the library's memory itself: it runs Argon2id a second time on
  zeros, and the library, asking for blocks of the same sizes, is handed the
  ones it just freed and overwrites the copy. That is the allocator's
  choice, not a guarantee: the tests find no copy left on Linux with glibc;
  macOS zeroes small freed blocks by default, and with that zeroing turned
  off its allocator does not hand the block back and the copy of the prehash
  is usually found. A copy that is left lasts until that memory is reused.
  Of an ASCII master password itself the tests find nothing after a
  derivation, whole or in part, up to 4,000 bytes. HKDF leaves its working keys, the one it extracts
  and the one it derives, on the C stack and in freed memory; IronDome
  overwrites them by deriving again from zeros, which holds as long as the library takes
  the same path through its code both times (the tests check that it does).
  A non-ASCII master
  password also leaves Python's `unicodedata` working copies in freed memory.
  See the boundary of [`keys-wiped`](CLAIMS.md#keys-wiped).
* **Intel Macs are untested.** `cryptography` publishes no macOS wheel for
  them, so installing there builds it from source (Rust and OpenSSL needed).
* **Whole-file rollback is not detected.** Restoring an older copy of the
  entire vault file yields a valid older vault. (Individual records cannot be
  rolled back or swapped.)
* **Windows has no hardware backend yet** and is not covered by the test
  suite. It runs with the file-based device key.
* **Bunkers separate vaults, not users.** Several bunkers on one machine have
  independent keys, so one bunker's password, session or grant opens nothing
  in another. They all belong to the same operating-system account, so
  malware running as that account is in the same position against each.
* **A compromised operating system** (root, kernel) can do anything a debugger
  can while a vault is unlocked.
* **Touch ID prompts name the helper program**, not the agent that triggered
  them. The reason text is supplied by the caller. Read it. IronDome's own
  prompts end with the bunker they are for ("(bunker NAME)"), and
  `run --touch` names the whole resolved path of the program it will start,
  and refuses a path too long to show in full; the program is looked up once
  and started by exactly that path.
* **Sessions and grants die together.** Every device secret a vault's sessions
  and grants were bound to is named in its encrypted index (normally one; when
  one has to be replaced, the old one stays listed); `nuke` and `rekey` destroy
  them all, which ends every one of them. Revoking a single one deletes its
  file and its wrapped snapshot.
* **Use counts and single revocations are only as final as the deletion of a
  file.** A copy of a grant's file put back into `caps/` brings back the uses
  it had and undoes a revoke, until the grant expires. Only `rekey` or `nuke`
  ends a grant against something that can write that directory.
* **`config.json` is not authenticated.** Anything that can write the bunker
  directory can change a setting within its range. The ranges hold no unsafe
  value: generated passwords of at least 16 characters, passphrases of at
  least 5 words, a default grant lifetime of at most a day.
* **The default Argon2id cost is lower on a small machine:** 64 MiB instead of
  256 MiB where there is less than 3 GiB of RAM, and `IRONDOME_KDF_MEMORY_MIB`
  or `--kdf-memory-mib` replaces it with any value from 19 MiB to 4 GiB. A
  keyslot keeps the cost it was made with.
* **The TPM index that binds sessions and grants has an empty authorisation**
  and is exempt from dictionary-attack lockout, so that a lockout cannot stop
  every grant. Any account allowed to use the TPM can read it; it is useless
  without the owner-only capability file and the token.

## Cryptography, in one table

| Purpose | Primitive | Parameters |
| --- | --- | --- |
| Password stretching | Argon2id (RFC 9106) | 256 MiB, t=3, p=4 by default (64 MiB, t=3, p=4 with less than 3 GiB of RAM); never below the OWASP minimum (19 MiB with t=2, or 46 MiB with t=1); stored per keyslot |
| Password prehash | HKDF-SHA256 (RFC 5869) | label `irondome/v4/password`, the keyslot's Argon2id salt; its 32 bytes are the only input Argon2id gets |
| Key derivation | HKDF-SHA256 (RFC 5869) | one label per purpose; salt binds vault and slot |
| Encryption | AES-256-GCM | random 96-bit nonce, 128-bit tag, context in associated data |
| Device binding (macOS) | ECDH on P-256 inside the Secure Enclave | against a random point with no known discrete log |
| Device binding (Linux) | TPM 2.0 NV index with auth value | dictionary-attack protection on |
| Session and grant binding | HKDF over the token secret and a device secret | macOS: a Secure Enclave key under the device policy; Linux: a TPM NV index with empty auth and no lockout |
| One-time passwords | TOTP (RFC 6238) | SHA-1/256/512, 6-8 digits |
| Randomness | Operating system CSPRNG | |

Argon2id, HKDF, AES-GCM and P-256 come from one dependency,
[`cryptography`](https://cryptography.io) (pyca), which wraps OpenSSL. One-time
codes are RFC 4226 and RFC 6238 over the standard library's HMAC, and
randomness is the operating system's. IronDome implements no cipher, hash or
key-derivation function itself.
