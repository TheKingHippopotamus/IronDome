<div align="center">

<img src="static/irondome-readme.svg" alt="IronDome" width="120" />

# IronDome

**Give your AI agent one secret, once. Never the vault.**

A local vault for passwords, API keys and one-time codes, bound to your Mac's
Secure Enclave or a TPM 2.0 on Linux. No cloud, no account, no network code, one
dependency.

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

$ irondome grant create GITHUB_TOKEN --ttl 15m              # this one secret, one use, 15 minutes
Master password:
irondome_g_ae19…
ok  grant ae1966316c57 created in bunker alpha
  covers   GITHUB_TOKEN (github/password)
  mode     use: the values can only be injected into a command by irondome run
  expires  2026-11-12 13:29, in 15m
  uses     1
  id       ae1966316c5734dbf401dae402229716
The token is a bearer secret: whoever holds it can use the grant. Give it to one agent, keep it out of files and chats, and revoke it with: irondome grant revoke ae1966316c57

$ IRONDOME_GRANT=irondome_g_ae19… irondome run --env GITHUB_TOKEN -- sh -c 'echo "got $GITHUB_TOKEN"'
got [irondome:GITHUB_TOKEN]

$ IRONDOME_GRANT=irondome_g_ae19… irondome run --env GITHUB_TOKEN -- sh -c 'echo "got $GITHUB_TOKEN"'
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

Python 3.9.2 or newer, tested on 3.9 through 3.14. macOS and Linux. On a Mac, Touch ID
and Secure Enclave support compiles a 250-line Swift helper on first use (needs the
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
$ cat .env.irondome
STRIPE_KEY=irondome://stripe
DATABASE_URL=irondome://prod-db

$ irondome run -- node server.js         # reads .env.irondome here, resolves each reference, starts the server
```

The file holds references, not values: it names entries and opens none of
them, so an agent that reads it, or a repository it is committed to, learns
entry names and nothing else.

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
$ export IRONDOME_GRANT=irondome_g_…
$ irondome run --env GITHUB_TOKEN -- gh pr create --fill
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
| Master password | Argon2id: 256 MiB, 3 passes, 4 lanes by default; 64 MiB on a machine with less than 3 GiB of RAM |
| Device binding | Secure Enclave (macOS) · TPM 2.0 NV storage (Linux) · file-based fallback, labelled as such |
| Touch ID | Enforced by the Secure Enclave on the key operation, not by a prompt in front of a readable key |
| Wrong guesses | On a TPM, checked and rate-limited by the chip |
| Memory | Keys live in locked pages outside the Python heap and are wiped; a test scans process memory to prove it |
| Self-destruct | `irondome nuke` destroys the device secrets first: a restored copy of the vault no longer opens with the master password (a recovery key you kept still opens it) |
| Network | None: no module imports a networking library, and every command works with socket creation disabled |
| Dependencies | One: [`cryptography`](https://cryptography.io) |

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for who each of these stops
and who it does not.

## Verify it yourself

```console
$ irondome verify            # runs the claim checks against this machine
$ irondome verify --touch    # also proves Touch ID with your finger
$ irondome doctor            # which chip, which backend, file modes, memory locking
```

For the full suite: `pip install -e ".[dev]" && pytest`, and
`scripts/test-linux.sh` runs it again in a container with a software TPM.

## What IronDome does not do

* **It has not been audited by a third party.** The tests are ours. Treat it as
  beta software.
* **It cannot protect you from malware that already runs as you** while a vault
  is open, or from a compromised operating system.
* **Decrypted entries are ordinary strings** for as long as a command runs.
  Only key material is guaranteed to stay in locked, wiped memory.
* **Masking stops accidents, not intent.** A command that transforms a secret
  on purpose gets it through, and a `--reveal` grant or an entry marked
  `--agent reveal` lets an agent see the value.
* **Grant and session tokens are bearer secrets.** Whoever holds one, and can
  read its file, has what it grants; a session token in an agent's
  environment is full access.
* **Revoking a grant, and its use count, rest on deleting its file.** A
  process that can write the bunker's `caps/` directory can put a copy back,
  and the grant works again until it expires. `irondome rekey` ends that: it
  destroys the device secret every session and grant is bound to.
* **A recovery key outlives `nuke`.** If you keep one on paper and a copy of
  the vault file survives somewhere, that copy opens.
* **Bunkers separate vaults, not operating-system accounts.** Every bunker
  belongs to the same user; malware running as that user faces each of them
  the same way.
* **Restoring an older copy of the whole vault file is not detected**, and
  neither is deleting the newest lines of the audit log, or the whole log.
* **The number of entries and the time of the last change are visible** to
  anyone who can read the vault file.
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

[GPL-3.0-only](LICENSE). Copyright (C) 2023-2026 [King Hippopotamus](https://github.com/TheKingHippopotamus).

The passphrase word list, `src/irondome/data/eff_large_wordlist.txt`, is not
IronDome's and is not under the GPL: it is the EFF Large Wordlist by Joseph
Bonneau, Electronic Frontier Foundation (2016), included unchanged under
[CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/); see
[its notice](src/irondome/data/eff_large_wordlist.LICENSE.txt). Using it
implies no endorsement by EFF.
