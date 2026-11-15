"""The master password's bytes can be in memory for good reasons, and IronDome must leave those alone.

pyca/cryptography leaves a copy of the password it is given to Argon2id in the heap. Before release IronDome
searched the heap for that copy and zeroed it, and a review showed what that did, through the real command line:

* a master password that is also a word OpenSSL keeps in the heap (``provider``) had that word zeroed, every
  later algorithm lookup failed, and a vault whose password had been changed to it no longer opened;
* an entry being imported that contained the master password was stored with zero bytes in its place, and
  nothing said so.

IronDome no longer writes to memory it does not own: it has the library overwrite its own leftover by
deriving again from zeros (``crypto.argon2id``). These tests stay, so that nothing brings the search back.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable

CLI = Callable[..., "subprocess.CompletedProcess[str]"]

FIRST = "a good password 1"
WORD = "provider"  # a name OpenSSL's property parser keeps as a live C string


def ok(result: "subprocess.CompletedProcess[str]") -> "subprocess.CompletedProcess[str]":
    assert result.returncode == 0, f"exit {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    return result


def test_a_master_password_that_is_a_word_a_library_keeps_opens_the_vault(cli: CLI) -> None:
    ok(cli("init", "--password-stdin", "--no-recovery", stdin=WORD + "\n"))
    ok(cli("add", "github", "--kind", "secret", "--password-stdin", "--value-stdin", stdin=f"{WORD}\nthe-value-1\n"))
    assert ok(cli("get", "github", "--password-stdin", stdin=WORD + "\n")).stdout.strip() == "the-value-1"
    assert "github" in ok(cli("ls", "--password-stdin", stdin=WORD + "\n")).stdout


def test_a_vault_whose_password_is_changed_to_such_a_word_still_opens(cli: CLI) -> None:
    ok(cli("init", "--password-stdin", "--no-recovery", stdin=FIRST + "\n"))
    ok(cli("add", "github", "--kind", "secret", "--password-stdin", "--value-stdin", stdin=f"{FIRST}\nthe-value-2\n"))
    ok(cli("passwd", "--password-stdin", stdin=f"{FIRST}\n{WORD}\n"))
    assert ok(cli("get", "github", "--password-stdin", stdin=WORD + "\n")).stdout.strip() == "the-value-2"
    assert cli("get", "github", "--password-stdin", stdin=FIRST + "\n").returncode != 0


def test_an_imported_entry_that_contains_the_master_password_is_stored_unchanged(cli: CLI, tmp_path: Path) -> None:
    ok(cli("init", "--password-stdin", "--no-recovery", stdin=FIRST + "\n"))
    note = ("x" * 600) + FIRST + ("y" * 600)  # long enough for the C heap rather than Python's own arenas
    source = tmp_path / "import.csv"
    source.write_text(
        f"name,username,password,url,notes\nreused,me,{FIRST},https://example.test,short {FIRST} note\n"
        f"long,me,pw-0001,https://example.test,{note}\n",
        encoding="utf-8",
    )
    ok(cli("import", str(source), "--password-stdin", stdin=FIRST + "\n"))
    assert ok(cli("get", "reused", "--password-stdin", stdin=FIRST + "\n")).stdout.strip() == FIRST
    assert ok(cli("get", "long", "--field", "notes", "--password-stdin", stdin=FIRST + "\n")).stdout.strip() == note
    assert ok(cli("get", "reused", "--field", "notes", "--password-stdin", stdin=FIRST + "\n")).stdout.strip() == (
        f"short {FIRST} note"
    )
