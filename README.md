<div align="center">

<img src="static/irondome-logo.svg" alt="IronDome" width="120" />

# IronDome

**Secrets your AI agent can use but never see.**

A local vault for passwords, API keys and one-time codes, bound to your Mac's
Secure Enclave or your PC's TPM. No cloud, no account, no network code, one
dependency.

[![PyPI](https://img.shields.io/pypi/v/IronDome?color=9bae4a&label=pypi)](https://pypi.org/project/IronDome/)
[![Python](https://img.shields.io/pypi/pyversions/IronDome?color=9bae4a)](https://pypi.org/project/IronDome/)
[![License](https://img.shields.io/badge/license-GPL--3.0-9bae4a)](LICENSE)
[![Claims verified](https://img.shields.io/badge/claims-verified%20by%20tests-9bae4a)](docs/CLAIMS.md)

[Website](https://iron-dome-bunker.vercel.app) · [Threat model](docs/THREAT_MODEL.md) · [Architecture](docs/ARCHITECTURE.md) · [Every claim and its test](docs/CLAIMS.md)

</div>

```console
$ irondome add github --generate --alias GITHUB_TOKEN
ok  added github

$ irondome grant create GITHUB_TOKEN --ttl 15m        # a one-time token for exactly that secret
irondome_g_7c1e…

$ IRONDOME_GRANT=irondome_g_7c1e… irondome run --env GITHUB_TOKEN -- gh repo list
kinghippo/irondome   public   …                       # the command ran with the real token

$ IRONDOME_GRANT=irondome_g_7c1e… irondome run --env GITHUB_TOKEN -- printenv GITHUB_TOKEN
irondome: error: that grant has been used up            # one use, then it is destroyed
```

What the agent sees: an alias and a masked result. What the process gets: the
secret. What is left afterwards: an encrypted line in the audit log.

## Install

```console
$ pipx install IronDome        # or: uv tool install IronDome / pip install IronDome
$ irondome init
```

Python 3.9.2 or newer, tested on 3.9 through 3.14. macOS and Linux. On a Mac, Touch ID
and Secure Enclave support compiles a 250-line Swift helper on first use (needs the
Xcode Command Line Tools; nothing is downloaded). On Linux the TPM 2.0 is reached
through `tpm2-tools`. Without a usable chip or those tools, the device key is a
file in your home directory, and `irondome status` says so. Upgrading from 3.x:
`irondome migrate`.

## Why another password manager

Because the way most of us give secrets to tools is a `.env` file, and an AI
coding agent can read that file, echo it into its transcript and send the
transcript to a server. IronDome is built around three ideas:

**1. The vault only works on your machine.** The key that encrypts it needs a
secret held by the Secure Enclave (macOS) or a TPM 2.0 (Linux). A copy of the
vault file is useless anywhere else, even with your master password, and
gives an attacker nothing to guess against.

**2. Agents get capabilities, not secrets.** An agent never holds your master
password or the vault key. It gets a *grant*: a token for exactly the values
you named, for a limited time and number of uses. `irondome run` puts the
secret into the command's environment and masks it in the command's output.
On a Mac you can skip tokens entirely and approve each use with Touch ID,
enforced by the Secure Enclave itself.

**3. Every promise is a test you can run.** Each security claim in this README
and on the website is listed in [docs/CLAIMS.md](docs/CLAIMS.md) with the test
that holds it, and `irondome verify` runs the checks on your own machine.

## Five minutes

```console
$ irondome init                          # choose: password, Touch ID, or both
$ irondome add github --generate         # a 20-character password, stored
$ irondome add stripe --kind secret      # paste an API key at the hidden prompt
$ irondome get github                    # print it   (-c copies and auto-clears)
$ irondome otp github                    # current one-time code, if the entry has a TOTP secret
$ irondome ls                            # names, usernames, tags; never values
$ irondome status                        # which chip protects the vault, keyslots, grants
```

Stop keeping secrets in `.env` files:

```console
$ cat .env.irondome
STRIPE_KEY=irondome://stripe
DATABASE_URL=irondome://prod-db/url

$ irondome run -- node server.js         # resolves the references, starts the server
```

The file holds names, not secrets. It is safe to commit and safe for an agent
to read.

## Bunkers: several vaults on one machine

A *bunker* is one vault with everything that belongs to it: its own master
password, device key, recovery key, grants and audit log. Keep one per
person, or one per role, on the same machine. Opening one gives nothing about
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
| Approve each use with your fingerprint instead (Mac) | `irondome edit github --agent use`, then the agent runs `irondome run --touch …` |
| Approve once, for ten minutes (Mac) | the agent runs `irondome approve GITHUB_TOKEN --ttl 10m`; you touch the sensor once |
| See what agents did | `irondome audit` · `irondome audit --verify` |
| Find secrets that already leaked into transcripts | `irondome scan ~/.claude ~/.codex .` |
| Take access away | `irondome grant revoke <id>` |

The agent side is one environment variable and one command:

```console
$ export IRONDOME_GRANT=irondome_g_…
$ irondome run --env GITHUB_TOKEN -- gh pr create --fill
```

**MCP.** `irondome mcp` is a Model Context Protocol server (stdio, no extra
dependencies). It lists the names it may use, runs commands with secrets
injected and output masked, and returns one-time codes. It does not return
secret values unless you created the grant with `--reveal`.
`irondome mcp config --client claude-code` prints the registration snippet
for Claude Code, Claude Desktop, Cursor, Codex, VS Code or Zed.

What this does and does not do: injection and masking keep secrets out of a
model's context by accident. A command that deliberately transforms a secret
before printing it will get it through. Give agents narrow, short-lived
grants, and rotate what they used.

## What protects the vault

| | |
| --- | --- |
| Encryption | AES-256-GCM, a separate key per entry, names and metadata encrypted too |
| Master password | Argon2id, 256 MiB, 3 passes, 4 lanes |
| Device binding | Secure Enclave (macOS) · TPM 2.0 NV storage (Linux) · file-based fallback, labelled as such |
| Touch ID | Enforced by the Secure Enclave on the key operation, not by a prompt in front of a readable key |
| Wrong guesses | On a TPM, checked and rate-limited by the chip |
| Memory | Keys live in locked pages outside the Python heap and are wiped; a test scans process memory to prove it |
| Self-destruct | `irondome nuke` destroys the device key first: every copy of the ciphertext becomes unreadable |
| Network | None. No module can open a socket; a test enforces it |
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
* **A recovery key outlives `nuke`.** If you keep one on paper and a copy of
  the vault file survives somewhere, that copy opens.
* **Bunkers separate vaults, not operating-system accounts.** Every bunker
  belongs to the same user; malware running as that user faces each of them
  the same way.
* **Restoring an older copy of the whole vault file is not detected.**
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
out in full (`--reveal`, never `--rev`). Exit codes: 0 ok · 1 error ·
2 usage · 3 not found · 4 authentication · 5 denied by policy · 6 vault ·
7 device key · 130 interrupted.

## Upgrading from 3.x

IronDome 4 is a new vault format with a new command line. There is one
command, `irondome`. The Textual TUI is gone, and so are the 3.x commands
`irondome-cli` and `bunker`.

```console
$ pipx upgrade IronDome
$ irondome migrate            # reads ~/.password_manager, verifies every entry, leaves it untouched
```

## Security

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## License

[GPL-3.0-only](LICENSE). Copyright (C) 2023-2026 [King Hippopotamus](https://github.com/TheKingHippopotamus).
