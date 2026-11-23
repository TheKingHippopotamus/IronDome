<div align="center">

<img src="static/irondome-readme.svg" alt="IronDome" width="120" />

# IronDome

**Give your AI agent one secret, once. Never the vault.**

A local vault for passwords, API keys and one-time codes, bound to your Mac's
Secure Enclave or a TPM 2.0 on Linux. No cloud, no account, no network code, one
direct dependency.

[![PyPI](https://img.shields.io/pypi/v/IronDome?color=9bae4a&label=pypi)](https://pypi.org/project/IronDome/)
[![Python](https://img.shields.io/pypi/pyversions/IronDome?color=9bae4a)](https://pypi.org/project/IronDome/)
[![License](https://img.shields.io/badge/license-GPL--3.0--only-9bae4a)](LICENSE)
[![Claims](https://img.shields.io/badge/claims-each%20with%20its%20tests-9bae4a)](docs/CLAIMS.md)

[Website](https://iron-dome-bunker.vercel.app) · [Threat model](docs/THREAT_MODEL.md) · [Architecture](docs/ARCHITECTURE.md) · [Every claim and its test](docs/CLAIMS.md)

</div>

```console
$ irondome add github --kind secret --alias GITHUB_TOKEN    # paste the token at the hidden prompt
Master password:
Value for github:
ok  added github to bunker alpha, with the alias GITHUB_TOKEN

$ export IRONDOME_GRANT="$(irondome grant create GITHUB_TOKEN --ttl 15m)"   # this one secret, one use, 15 minutes
Master password:
ok  grant ae1966316c57 created in bunker alpha
  covers   GITHUB_TOKEN (github/password)
  mode     use: the values can only be injected into a command by irondome run
  expires  2026-11-12 13:29, in 15m
  uses     1
  id       ae1966316c5734dbf401dae402229716
The token is a bearer secret: whoever holds it can use the grant. Give it to one agent, keep it out of files and chats, and revoke it with: irondome grant revoke ae1966316c57

$ irondome run --env GITHUB_TOKEN -- sh -c 'echo "got $GITHUB_TOKEN"'
got [irondome:GITHUB_TOKEN]

$ irondome run --env GITHUB_TOKEN -- sh -c 'echo "got $GITHUB_TOKEN"'
error  that grant token opens nothing here: the grant was used up, expired or revoked, or it was made on another machine. Its owner can make a new one with: irondome grant create
```

The command got the real token in its environment; what it printed came back
masked. The grant was destroyed after its one use. What the agent sees: an
alias and a masked result. What is left afterwards: encrypted records in the
audit log.

## Install

```console
$ pipx install IronDome        # or: uv tool install IronDome / pip install IronDome
```

Python 3.9.2 or newer, tested on 3.9 through 3.14. macOS on Apple silicon, and Linux.
Python 3.9 and 3.10 no longer get security fixes from python.org: IronDome runs on
them and `irondome doctor` says so, and a newer Python is the better place for it.
Intel Macs are untested: `cryptography` publishes no macOS wheel for them, so installing
there builds it from source, which needs Rust and OpenSSL. On a Mac, Touch ID
and Secure Enclave support compiles a Swift helper of about 250 lines on first use (needs the
Xcode Command Line Tools; nothing is downloaded). On Linux the TPM 2.0 is reached
through `tpm2-tools`. Without a usable chip or those tools, the device key is a
file in your home directory, and `irondome init` and `irondome status` say so.
Upgrading from 3.x: `irondome migrate`.

## Why another password manager

Because the way most of us give secrets to tools is a `.env` file, and an AI
coding agent can read that file, echo it into its transcript and send the
transcript to a server. IronDome is built around three ideas:

**1. The vault only works on your machine.** The key that encrypts it needs a
secret held by the Secure Enclave (macOS) or a TPM 2.0 (Linux), or, where
there is no chip, a file kept outside the vault directory. A copy of the vault
directory is useless anywhere else, even with your master password, and gives
an attacker nothing to guess against. The one exception is the recovery key,
which exists to open the vault without the machine.

**2. Agents get capabilities, not secrets.** An agent never holds your master
password or the vault key. It gets a *grant*: a token for exactly the values
you named, for a limited time and, unless you say otherwise, a single use.
`irondome run` puts the secret into the command's environment and masks it in
the command's output. On a Mac you can skip tokens entirely and approve each
use with Touch ID, enforced by the Secure Enclave itself.

**3. Every promise is a test you can run.** Each security claim in this README
and on the website is listed in [docs/CLAIMS.md](docs/CLAIMS.md) with the tests
that hold it, and `irondome verify` runs the checks that can run on your own
machine.

## Five minutes

```console
$ irondome init                          # choose: password, Touch ID, or both
$ irondome add github --generate         # a 20-character password, stored
$ irondome add stripe --kind secret      # paste an API key at the hidden prompt
$ irondome get github                    # print it   (-c copies it and clears the clipboard after 30 s)
$ irondome otp github                    # current one-time code, if the entry has a TOTP secret
$ irondome ls                            # names, usernames, URLs, tags; never secret values
$ irondome status                        # which chip protects the vault, keyslots, grants
```

Stop keeping secrets in `.env` files:

```console
$ irondome alias set STRIPE_KEY stripe   # the name a program knows this secret by
$ irondome alias set DATABASE_URL prod-db/url
$ cat .env.irondome
STRIPE_KEY=irondome://STRIPE_KEY
DATABASE_URL=irondome://DATABASE_URL

$ irondome run -- node server.js         # reads .env.irondome here, resolves each reference, starts the server
```

The file holds references, not values: it names aliases and opens none of
them, so an agent that reads it, or a repository it is committed to, learns
names and nothing else. A file that `irondome run` finds on its own may only
ask for a secret under the name you gave it, as above; a file that does more
(`DB=irondome://prod-db/url`, `DEBUG=1`) works when you name it with
`--env-file`.

## Bunkers: several vaults on one machine

A *bunker* is one vault with everything that belongs to it: its own master
password, device key, recovery key, grants and audit log. Keep one per
person, or one per role, on the same machine. Opening one gives no access to
the others.

```console
$ irondome init                          # the first bunker is called alpha
$ irondome bunker create bravo           # a second one, fully separate
$ irondome --bunker bravo add github     # work on it   (or: export IRONDOME_BUNKER=bravo)
$ irondome bunker use bravo              # make it the default
$ irondome bunker ls                     # every bunker here, and what protects each
$ irondome bunker rm bravo               # destroy one; the others are untouched
```

An agent holding a grant never has to name the bunker: the token is found in
the bunker that issued it.

## For AI agents

| You want | Run |
| --- | --- |
| Give a secret a name an agent can use | `irondome alias set GITHUB_TOKEN github` |
| Let an agent use it once, for 15 minutes | `irondome grant create GITHUB_TOKEN --ttl 15m` |
| Let it use several, all day, as often as needed | `irondome grant create A B C --ttl 8h --unlimited` |
| Give an agent 2FA codes without the seed | `irondome grant create github/totp --ttl 1h` |
| Approve each use with your fingerprint instead (Mac) | once: `irondome auth touchid` and `irondome edit github --agent use`; then the agent runs `irondome run --touch …` |
| Approve once, for ten minutes (Mac) | the agent runs `export IRONDOME_GRANT="$(irondome approve GITHUB_TOKEN --ttl 10m)"`; you touch the sensor once |
| See what agents did | `irondome audit` · `irondome audit --verify` |
| Find secrets that already leaked into transcripts | `irondome scan ~/.claude .` |
| Take access away | `irondome grant revoke <id>` (read the limits below) |

The agent side is one environment variable and one command:

```console
$ export IRONDOME_GRANT="$(irondome grant create GITHUB_TOKEN --ttl 15m)"   # you, in the shell that starts the agent
$ irondome run --env GITHUB_TOKEN -- gh pr create --fill                    # the agent
```

**MCP.** `irondome mcp` is a Model Context Protocol server (stdio, no extra
dependencies). It lists the names it may use, runs commands with secrets
injected and output masked, and returns one-time codes. It returns a secret's
value only under a grant created with `--reveal`, or, when you approve with
Touch ID, for an entry marked `--agent reveal`.
`irondome mcp config --client claude-code` prints the registration snippet
for Claude Code, Claude Desktop, Cursor, Codex, VS Code or Zed.

What this does and does not do: injection and masking keep secrets out of a
model's context by accident, not on purpose. A command that deliberately
transforms a secret before printing it will get it through. Give agents
narrow, short-lived grants, and rotate what they used.

## What protects the vault

| | |
| --- | --- |
| Encryption | AES-256-GCM; names, usernames, URLs, tags, aliases and notes are encrypted too, and record sizes are padded |
| Master password | Argon2id: 256 MiB, 3 passes, 4 lanes by default; 64 MiB on a machine with less than 3 GiB of RAM. It is applied to a 32-byte prehash of the password (HKDF-SHA256), never to the password itself |
| Device binding | Secure Enclave (macOS) · TPM 2.0 NV storage (Linux) · file-based fallback, labelled as such |
| Touch ID | Enforced by the Secure Enclave on the key operation, not by a prompt in front of a readable key |
| Wrong guesses | On a TPM, checked and rate-limited by the chip |
| Memory | IronDome keeps keys in pages outside the Python heap, locked into RAM where the system allows it, and wipes them; a test scans process memory to prove it. Argon2id inside the `cryptography` library leaves a copy of what it is given: IronDome gives it the prehash, never the master password, and runs it in a child process, so the copy ends when the child exits (see the claim's boundary) |
| Self-destruct | `irondome nuke` destroys the device secrets first: a restored copy of the vault files no longer opens with the master password (a recovery key you kept still opens it, and so does a backup made with `irondome export`; a copy of the device folder is the other thing to destroy, see the limits below) |
| Network | None: no module imports a networking library, and every command works with socket creation disabled |
| Dependencies | One direct dependency: [`cryptography`](https://cryptography.io), which brings `cffi` and `pycparser` (and `typing-extensions` on Python 3.9 and 3.10) |

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for who each of these stops
and who it does not.

## Verify it yourself

```console
$ irondome verify            # runs the claim checks against this machine (a minute or two)
$ irondome verify --touch    # also proves Touch ID with your finger
$ irondome doctor            # which chip, which backend, file modes, memory locking
```

For the full suite: `pip install -e ".[dev]" && pytest`, and
`scripts/test-linux.sh` runs it again in a container with a software TPM.

## What IronDome does not do

* **It has not been audited by a third party.** The tests are ours. Treat it as
  beta software.
* **It cannot protect you from malware that already runs as you** while a vault
  is open, or from a compromised operating system. A keylogger can capture a
  master password, and malware can raise a Touch ID prompt of its own: read
  the prompt before you touch.
* **Decrypted entries are ordinary strings** for as long as a command runs.
  Only IronDome's own copies of key material stay in locked, wiped memory:
  Argon2id inside `cryptography` leaves a copy of what it is given. IronDome
  gives it a 32-byte prehash of the master password, never the password, and
  runs it in a child process that exits when the key is made, so the copy
  goes with it. Where no child can be made the copy stays in IronDome's own
  process and is overwritten only if the allocator allows; whoever reads a
  prehash that was left can test guesses of the password against it.
* **Masking stops accidents, not intent.** A command that transforms a secret
  on purpose gets it through, as does an encoding that is not on the list;
  a `--reveal` grant or an entry marked `--agent reveal` lets an agent see
  the value. `irondome run` reads `.env.irondome` in the directory it runs
  in without being asked and lists what the file supplies, with `-q` too,
  and only if the file is yours and no other account can change it.
  Such a file may only ask for a secret under the name you gave it
  (`GITHUB_TOKEN=irondome://GITHUB_TOKEN`, as `--env GITHUB_TOKEN` does);
  one that sets anything as written, or points a variable at some other
  entry or field, is refused until you name it with `--env-file`. In a
  directory someone else wrote, read that file first: it still decides
  which of your named secrets the command receives.
* **Grant and session tokens are bearer secrets.** Whoever holds one, and can
  read its file, has what it grants; a session token in an agent's
  environment is full access while the session lasts: it unwraps the vault
  key. Under a session IronDome's commands will not make a grant that
  outlives it or set what agents may do with an entry without the master
  password again; a program that uses the token with its own code is not
  bound by that. Ending a session with `irondome lock` revokes the grants
  made under it.
* **Anything running as you can lock you out for a while.** On a TPM, a few
  wrong master passwords put the chip into lockout, whoever typed them; the
  vault then refuses the right password too until the TPM forgives them.
  A locked TPM takes no new keyslot either, so the recovery key gets you in
  meanwhile only with a file-based device key
  (`IRONDOME_DEVICE_BACKEND=software irondome recovery use`); `irondome
  rekey` moves the vault back onto the chip afterwards.
* **Revoking a grant, and its use count, rest on deleting its file.** A
  process that can write the bunker's `caps/` directory can put a copy back,
  and the grant works again until it expires. `irondome rekey` ends that: it
  destroys the device secret every session and grant is bound to.
* **A recovery key and an exported backup outlive `nuke`.** If you keep a
  recovery key on paper and a copy of the vault file survives somewhere, that
  copy opens; create the vault with `--no-recovery` if you would rather lose
  the data. A portable backup made with `irondome export` opens with its own
  password wherever it is.
* **A copy of the device folder outlives `nuke` as well.** On a Mac the
  device key is a sealed file that only this Mac's Secure Enclave can use,
  in `~/Library/Application Support/IronDome/device`; `nuke`, `rekey`,
  `passwd` and `bunker rm` destroy keys by deleting such files.
  IronDome marks that folder as left out of Time Machine when it creates
  it. A clone, a disk
  image, a local snapshot of the disk or a backup program that does not read
  the mark can still hold it: put back on this Mac together with the vault,
  it opens with the master password, or with a token that was valid when the
  copy was made. The file-based device key on any system is the same. The
  other side of it: a restore of the Mac from Time Machine comes back
  without that folder (that is what the mark asks for; no backup was run to
  see it), and then the recovery key is what opens the vault
  (`irondome recovery use`). A vault made with `--no-recovery` does not
  survive such a restore.
* **Bunkers separate vaults, not operating-system accounts.** Every bunker
  belongs to the same user; malware running as that user faces each of them
  the same way.
* **Restoring an older copy of the whole vault file is not detected**, and
  neither is deleting the newest lines of the audit log, or the whole log.
* **The vault file shows a little.** Anyone who can read it sees how many
  entries there are and the padded size of each, when the vault was created
  and how many times it has been written, and how it opens (keyslot kinds,
  backend, Argon2id cost). Names, usernames, URLs, tags and values are not
  visible. Session and grant files show, in clear, what kind they are,
  when they were made and expire, the uses left and the label you gave
  them; the audit log shows a time and a sequence number per line.
* **No hardware backend on Windows yet**, and Windows is not covered by the
  test suite.

## Commands

```
init  status  bunker  add  get  show  ls  find  edit  rm  gen  otp
alias  run  approve  grant  unlock  lock  audit  scan  mcp
passwd  recovery  auth  backup  export  import  migrate  rekey  nuke
doctor  verify  config  completion  version
```

`irondome <command> --help` documents each one. Every command accepts
`--json` and then prints one JSON document on stdout: the result (a list
command prints one object with a named list), or, when the command fails,
`{"ok": false, "error": "<message>", "exit_code": <n>}`. Options are written
out in full (`--reveal`, never `--rev`).

At a terminal the output is laid out for a person: prose wrapped to the
window (92 columns at most), a coloured mark on results, warnings and errors,
the commands to type coloured, tables ruled. A value you may copy is never
wrapped. A pipe or a file gets plain lines that do not depend on the
terminal, and so does a terminal with `--no-color`, `NO_COLOR` or
`TERM=dumb`: set one of them in a script that drives a terminal of its own.

Exit codes: 0 ok · 1 error, a check that found something (`doctor`, `scan`,
`audit --verify`, `verify`), a confirmation you declined, or work left
unfinished (`nuke`, `bunker rm`, `rekey`, `recovery`, `migrate --destroy-old`)
· 2 usage · 3 not found · 4 authentication · 5 denied by policy · 6 vault ·
7 device key · 130 interrupted. `irondome run` exits with the status of the
command it ran (128 plus the signal number when a signal ended it), or with
124 when `--timeout` stopped it, 126 when it could not be started and 127 when
it was not found.

## Upgrading from 3.x

IronDome 4 is a new vault format with a new command line. There is one
command, `irondome`. The Textual TUI is gone, and so are the 3.x commands
`irondome-cli` and `bunker`.

```console
$ pipx upgrade IronDome
$ irondome migrate            # reads ~/.password_manager, verifies every entry, leaves it untouched
```

A 3.x vault without a master password opens with the key 3.x kept in the OS
keychain: IronDome reads it with `/usr/bin/security` on macOS and
`secret-tool` on Linux. Where neither can give it, you type or pipe the key
yourself (`irondome migrate --legacy-key`).

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## License

[GPL-3.0-only](LICENSE). Copyright (C) 2023-2026 [King Hippopotamus](https://github.com/Nir-Ghub).

The passphrase word list, `src/irondome/data/eff_large_wordlist.txt`, is not
IronDome's and is not under the GPL: it is the EFF Large Wordlist by Joseph
Bonneau, Electronic Frontier Foundation (2016), included unchanged under
[CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/); see
[its notice](src/irondome/data/eff_large_wordlist.LICENSE.txt). Using it
implies no endorsement by EFF.
