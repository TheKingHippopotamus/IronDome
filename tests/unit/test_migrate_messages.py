"""What ``irondome migrate`` says to somebody coming from 3.x, where a by-hand trial found it untrue.

The trial (2026-11-25, the first that upgraded from the real 3.2.2) found no lost entry and four false
sentences. These tests hold the corrected ones: they call the functions that word the result, with a
stand-in for the terminal, so that each sentence is checked for the case it is said in.
"""

from __future__ import annotations

import types
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from irondome import migrate_v3
from irondome.cli import cmd_admin, cmd_vault
from irondome.errors import IronDomeError
from irondome.secmem import SecureBuffer
from irondome.unlock import MODE_PASSWORD

LEGACY = types.SimpleNamespace(path=Path("/home/alice/.password_manager"))


class Said:
    """Collects what a command would print, by kind."""

    json_mode = False

    def __init__(self) -> None:
        self.lines: List[Tuple[str, str]] = []

    def __getattr__(self, kind: str) -> Any:
        if kind not in ("info", "ok", "warn", "error"):
            raise AttributeError(kind)
        return lambda text: self.lines.append((kind, text))

    def of(self, kind: str) -> List[str]:
        return [text for said, text in self.lines if said == kind]


def destroyed(**changes: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {"done": True, "confirmed": True, "files_deleted": 7, "leftovers": [], "errors": [],
                              "notes": [], "keychain_cleared": None}
    result.update(changes)
    return result


def shown(result: Dict[str, Any]) -> Said:
    said = Said()
    cmd_admin._show_destroyed(types.SimpleNamespace(out=said), LEGACY, result)  # type: ignore[arg-type]
    return said


def test_a_destroyed_vault_that_kept_no_key_in_the_keychain_is_reported_as_destroyed() -> None:
    """Where the keychain could not be reached the trial read "was not completely destroyed"; the folder was gone."""
    notes = ["OS keychain entry IronDome/auth_mode could not be deleted (secret-tool exited with status 1)"]
    said = shown(destroyed(notes=notes))
    assert said.of("error") == [] and said.of("warn") == []
    assert said.of("info") == [f"Note: {notes[0]}."]
    (line,) = said.of("ok")
    assert line.startswith("Destroyed the 3.x vault in /home/alice/.password_manager: 7 files deleted; ")
    assert "nothing in the OS keychain opens it" in line and "named above" in line


def test_the_two_other_endings_of_a_successful_destruction() -> None:
    assert "its OS keychain entries were removed" in shown(destroyed(keychain_cleared=True)).of("ok")[0]
    assert "the OS keychain was not touched" in shown(destroyed()).of("ok")[0]


@pytest.mark.parametrize(
    "platform, command",
    [("linux", "secret-tool clear service IronDome username master_key"),
     ("darwin", "security delete-generic-password -s IronDome -a master_key"), ("win32", None)],
)
def test_when_only_the_key_in_the_keychain_is_in_doubt_that_is_what_is_said(
    platform: str, command: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(migrate_v3, "_PLATFORM", platform)
    errors = ["OS keychain entry IronDome/master_key could not be deleted (secret-tool exited with status 1)"]
    said = shown(destroyed(done=False, keychain_cleared=False, errors=errors))
    assert said.of("warn") == errors and said.of("ok") == []
    (line,) = said.of("error")
    assert "the files of the 3.x vault in /home/alice/.password_manager were destroyed (7 files deleted)" in line
    assert "its key may still be in the OS keychain" in line and "not completely destroyed" not in line
    assert (command in line) if command else ("remove it with" not in line)


def test_what_is_left_on_disk_is_still_an_incomplete_destruction() -> None:
    said = shown(destroyed(done=False, files_deleted=3, leftovers=["/home/alice/.password_manager/secrets/x"]))
    assert said.of("warn") == ["left on disk: /home/alice/.password_manager/secrets/x"]
    assert said.of("error") == ["the 3.x vault in /home/alice/.password_manager was not completely destroyed"]


def test_declining_changes_nothing_and_says_so() -> None:
    said = shown(destroyed(done=False, confirmed=False, files_deleted=0))
    assert said.lines == [("info", "Not confirmed: the 3.x vault in /home/alice/.password_manager was left as it was.")]


def test_whoever_is_asked_for_the_3x_key_is_told_how_to_get_it_and_what_is_not_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The trial typed the 3.x recovery key there, which 3.x had called "the ONLY way to access your vault"."""
    monkeypatch.setattr(migrate_v3, "_PLATFORM", "linux")
    text = cmd_admin._legacy_key_help()
    assert "secret-tool lookup service IronDome username master_key" in text
    assert "The recovery key 3.x gave you is not this key and opens nothing" in text
    monkeypatch.setattr(migrate_v3, "_PLATFORM", "win32")
    assert cmd_admin._legacy_key_help().startswith(" The recovery key 3.x gave you is not this key")


def test_a_3x_master_password_that_is_kept_gets_the_remark_a_new_one_gets() -> None:
    """3.x took any eight characters. The trial kept ``password`` as the master password of the new vault
    with one press of Enter and no remark."""
    remarked: List[bytes] = []
    ctx = types.SimpleNamespace(
        has_terminal=False, password_stdin=True, assume_yes=False,
        warn_if_weak=lambda password: remarked.append(bytes(password.view())),
    )
    args = types.SimpleNamespace(keep_password=False, new_password=False)
    with SecureBuffer.from_buffer(b"password") as legacy:
        kept = cmd_admin._migration_password(ctx, args, legacy, "alpha")  # type: ignore[arg-type]
        with kept:
            assert bytes(kept.view()) == b"password"
    assert remarked == [b"password"]


def test_without_a_vault_the_first_bunker_points_a_3x_user_at_migrate_not_at_init(
    isolated: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``irondome ls`` after the upgrade said "Create one with: irondome init", with the 3.x vault beside it."""
    with pytest.raises(IronDomeError, match="Create one with: irondome init"):
        cmd_vault._require_vault()
    monkeypatch.setattr(migrate_v3, "detect", lambda *arguments: LEGACY)
    with pytest.raises(IronDomeError) as caught:
        cmd_vault._require_vault()
    said = str(caught.value)
    assert "Your IronDome 3.x vault is in /home/alice/.password_manager" in said
    assert "bring it over with: irondome migrate" in said and "irondome init" in said
    monkeypatch.setenv("IRONDOME_BUNKER", "bravo")  # another bunker is not where a 3.x vault goes by default
    with pytest.raises(IronDomeError, match="Create one with: irondome bunker create bravo"):
        cmd_vault._require_vault()


@pytest.mark.parametrize("platform, said", [("darwin", True), ("linux", False)])
def test_touch_id_is_looked_for_out_loud_only_on_a_mac(
    platform: str, said: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On Linux ``init`` began with "Checking for Touch ID..." and then offered no such choice."""
    out = Said()
    ctx = types.SimpleNamespace(has_terminal=True, out=out, no_touch=False)
    monkeypatch.delenv("IRONDOME_NO_TOUCH", raising=False)
    monkeypatch.setattr(cmd_vault.sys, "platform", platform)

    def no_chip(policy: str) -> Any:
        raise IronDomeError("no chip here")

    monkeypatch.setattr(cmd_vault, "_choose_backend", no_chip)
    assert cmd_vault._offer_modes(ctx) == MODE_PASSWORD  # type: ignore[arg-type]
    assert out.of("info") == (["Checking for Touch ID..."] if said else [])
