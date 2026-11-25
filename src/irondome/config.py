"""User preferences: a small JSON file of non-secret settings.

Nothing here weakens the vault. The settings only choose defaults a flag can
already override, and every value is range-checked when read, so a damaged or
hostile ``config.json`` falls back to the built-in default instead of
crashing a command or stretching a timeout. That includes a file that is not
JSON IronDome could have written (nested without end, a number thousands of
digits long, a key given twice), one larger than 64 KiB, and a pipe or device
in the file's place, which is never waited on.

The file is not authenticated: any program running as you can edit it. The
ranges are therefore chosen so that no value in them is unsafe. A default
password is never shorter than 16 characters (about 100 bits), a default
passphrase never shorter than 5 words (about 64 bits), and a default grant
never lives longer than a day. Longer grants and shorter passwords are still
available, but only when asked for explicitly with a flag, and every command
prints the lifetime or length it used.

Changing a setting reads the file and writes it back while holding the
bunker's lock (the one a vault commit takes), so of two changes made at the
same time neither is lost.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, NamedTuple

from irondome import audit, paths
from irondome.errors import UsageError, VaultError

__all__ = ["Setting", "SETTINGS", "load", "get", "set_value", "reset"]

#: The largest config.json that is read. What IronDome writes is a few dozen bytes.
_MAX_BYTES = 64 * 1024


class Setting(NamedTuple):
    default: int
    minimum: int
    maximum: int
    help: str


SETTINGS: Dict[str, Setting] = {
    "clipboard_clear_seconds": Setting(15, 5, 600, "seconds before a copied secret is cleared from the clipboard"),
    "session_ttl": Setting(900, 60, 43_200, "default lifetime of `irondome unlock` sessions, in seconds"),
    "grant_ttl": Setting(900, 60, 86_400, "default lifetime of grants, in seconds"),
    "password_length": Setting(20, 16, 512, "default length of generated passwords"),
    "passphrase_words": Setting(6, 5, 24, "default number of words in generated passphrases"),
    "snapshots": Setting(10, 0, 100, "automatic vault snapshots to keep (0 disables them)"),
}


def _valid(key: str, value: Any) -> bool:
    setting = SETTINGS[key]
    return isinstance(value, int) and not isinstance(value, bool) and setting.minimum <= value <= setting.maximum


def load() -> Dict[str, int]:
    """Every setting, with defaults filled in and invalid values ignored.

    A file that cannot be read or parsed counts as no file: every setting is
    its default. Parsed with :func:`irondome.audit.strict_loads`, which
    refuses deep nesting, overlong number literals and repeated keys.
    """
    values = {key: setting.default for key, setting in SETTINGS.items()}
    try:
        stored = audit.strict_loads(paths.read_file(paths.config_file(), limit=_MAX_BYTES))
    except (OSError, ValueError, VaultError):  # UnicodeDecodeError is a ValueError
        return values
    if isinstance(stored, dict):
        for key, value in stored.items():
            if key in SETTINGS and _valid(key, value):
                values[key] = value
    return values


def get(key: str) -> int:
    if key not in SETTINGS:
        raise UsageError(f"unknown setting {key!r}; known settings: {', '.join(sorted(SETTINGS))}")
    return load()[key]


def _stored() -> Dict[str, int]:
    current = load()
    return {key: value for key, value in current.items() if value != SETTINGS[key].default}


_DURATION = re.compile(r"([0-9]{1,9})([smhd])")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def set_value(key: str, raw: str) -> int:
    """Validate and store one setting. Returns the stored value.

    The file is read and written back under the bunker's lock, so a change
    made at the same time by another process is kept, not overwritten.
    """
    if key not in SETTINGS:
        raise UsageError(f"unknown setting {key!r}; known settings: {', '.join(sorted(SETTINGS))}")
    setting = SETTINGS[key]
    text = str(raw).strip()
    # A lifetime is stored in seconds and may be given the way --ttl takes it: 90s, 15m, 2h, 1d.
    timed = key.endswith(("_ttl", "_seconds"))
    lifetime = _DURATION.fullmatch(text.lower()) if timed else None
    try:
        value = int(lifetime.group(1)) * _UNIT_SECONDS[lifetime.group(2)] if lifetime else int(text)
    except ValueError:
        how = " of seconds, or a duration such as 15m or 2h" if timed else ""
        raise UsageError(f"{key} must be a whole number{how}") from None
    if not setting.minimum <= value <= setting.maximum:
        raise UsageError(f"{key} must be between {setting.minimum} and {setting.maximum}")
    with paths.file_lock(paths.lock_file()):
        stored = _stored()
        if value == setting.default:
            stored.pop(key, None)
        else:
            stored[key] = value
        _write(stored)
    return value


def reset(keys: List[str]) -> None:
    """Return the named settings (or all, when the list is empty) to their defaults.

    Like :func:`set_value`, under the bunker's lock. Nothing changes if a name is unknown.
    """
    unknown = [key for key in keys if key not in SETTINGS]
    if unknown:
        raise UsageError(f"unknown setting {unknown[0]!r}")
    with paths.file_lock(paths.lock_file()):
        stored = _stored()
        for key in keys or list(stored):
            stored.pop(key, None)
        _write(stored)


def _write(stored: Dict[str, int]) -> None:
    path = paths.config_file()
    if not stored:
        try:
            os.unlink(str(path))  # a link in the file's place is removed, never followed
        except FileNotFoundError:
            pass
        return
    paths.write_atomic(path, (json.dumps(stored, indent=1, sort_keys=True) + "\n").encode("utf-8"))
