#!/usr/bin/env python3
"""Build, check or unpack the legacy-vault fixtures in this directory.

    build_fixtures.py build  [--only NAME ...]   regenerate fixtures in place
    build_fixtures.py check                      regenerate elsewhere and compare, byte for byte
    build_fixtures.py unpack NAME DESTINATION    write one fixture out as a data directory

Every vault is written by the code that wrote such vaults for real: the
commits listed in ``SOURCES`` are taken out of this repository's history with
``git archive`` and driven by ``make_legacy_vault.py`` (3.2.2) or
``make_old_vault.py`` (before 2.0). Nothing here contains encryption code of
its own. The interpreter that runs this script needs the ``cryptography``
package and nothing else; random bytes and the clock are pinned, so the same
fixtures come out on any machine.

``unpack`` is for trying a migration by hand::

    build_fixtures.py unpack biometric_only /tmp/old
    IRONDOME_LEGACY_DIR=/tmp/old irondome migrate

README.md describes each fixture.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import archive

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]

#: Where each generation of the format comes from in this repository's history.
SOURCES = {
    "3.2.2": ("43b7d67", ["password_manager"]),
    "1.1.0": ("b611aad", ["password_manager"]),
    "1.0.0": ("dccb4ed", ["password_manager", "password_manager.py"]),
}
KDF_NAMES = {"3.2.2": "2.0.0-3.2.2", "1.1.0": "1.0.1-1.1.0", "1.0.0": "before-1.0.1"}

#: Stands in for the directory a fixture was generated in, wherever the old log recorded it.
NEUTRAL_HOME = "/home/fixture-user"

Entry = Tuple[str, str, str, str]  # username, website, password, notes

HEBREW_USERNAME = "מנהל-כספת"
HEBREW_PASSWORD = "סיסמה-ראשית-חזקה-9"

UNICODE_ENTRIES: List[Entry] = [
    ("דוד@דוגמה.קום", "בנק-לדוגמה.co.il", "סיסמה־סודית־123", "הערה בעברית\nשורה שנייה"),
    (
        "משתמש",
        "https://דואר.דוגמה.קום/כניסה",
        "pässwörd-ñ-日本語-\N{CLOSED LOCK WITH KEY}",
        "combining: e\N{COMBINING ACUTE ACCENT}, emoji: \N{LOCK}",
    ),
    (
        "alice",
        "חשבון בנק (משותף)",
        "\N{RIGHT-TO-LEFT MARK}סוד\N{RIGHT-TO-LEFT MARK}-RTL-marks",
        "mixed עברית and English\ttab",
    ),
    ("ｆｕｌｌｗｉｄｔｈ", "example.com", "ｐａｓｓｗｏｒｄ １２３", "full-width forms must survive unchanged"),
]

LONG_NAME = "a-very-long-service-name-" * 10  # 250 characters; an entry name holds 200

COLLISION_ENTRIES: List[Entry] = [
    ("alice@example.com", "github.com", "gh-alice-1", "three accounts, one website"),
    ("bob@example.com", "github.com", "gh-bob-2", ""),
    ("carol", "GitHub.com", "gh-carol-3", "same website in another case"),
    ("alice@example.com", "GITHUB.COM", "gh-alice-4", "same username as the first, website in capitals"),
    ("mallory", "github.com (bob@example.com)", "gh-mallory-5", "a website that reads like a disambiguated name"),
    ("dave", "  padded.example.com  ", "padded-6", "website with spaces around it"),
    ("erin", "tab\tand\nnewline", "control-7", "website with control characters"),
    ("frank", LONG_NAME, "long-8", "website longer than an entry name may be"),
    ("grace", LONG_NAME, "long-9", "the same long website again"),
    ("heidi", "My Bank (personal)", "bank-10", "not an address"),
    ("ivan", "192.168.1.10:8443/admin", "nas-11", "an IP address with a port and a path"),
    ("judy", "ssh://git@example.com:2222/repo.git", "ssh-12", "a URL that is not http"),
]


def _generated(label: str, count: int, alphabet: str) -> str:
    """*count* characters of *alphabet*, chosen by SHA-256 of *label*: the same on every Python."""
    out = []
    block = 0
    while len(out) < count:
        digest = hashlib.sha256(f"{label}:{block}".encode()).digest()
        out.extend(alphabet[byte % len(alphabet)] for byte in digest)
        block += 1
    return "".join(out[:count])


def two_hundred_entries() -> List[Entry]:
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>/?"
    words = "abcdefghijklmnopqrstuvwxyz      \n"
    entries = []
    for index in range(200):
        username = f"user{index:03d}@example.com" if index % 3 else f"user{index:03d}"
        if index % 25 == 0:
            website = "shared.example.com"
        elif index % 2:
            website = f"https://app{index:03d}.example.org/login"
        else:
            website = f"site-{index:03d}.example.com"
        password = _generated(f"password:{index}", 12 + index % 40, letters)
        if index == 100:
            notes = _generated("notes:long", 5000, words)
        else:
            notes = "" if index % 4 else _generated(f"notes:{index}", 20 + (index * 37) % 300, words)
        entries.append((username, website, password, notes))
    return entries


class Fixture:
    def __init__(self, name: str, about: str, written_by: str, arguments: Sequence[str],
                 entries: Optional[List[Entry]] = None) -> None:
        self.name = name
        self.about = about
        self.written_by = written_by
        self.arguments = list(arguments)
        self.entries = entries


FIXTURES = (
    Fixture("password_only", "3.2.2, master password only. Three entries; the last was updated after a second login.",
            "3.2.2", ["--mode", "password_only"]),
    Fixture("biometric_password", "3.2.2, Touch ID as a gate in front of the master password. Same entries.",
            "3.2.2", ["--mode", "biometric_password"]),
    Fixture("biometric_only", "3.2.2, no master password: the vault key is the keyring's master_key entry.",
            "3.2.2", ["--mode", "biometric_only"]),
    Fixture("device_id", "3.2.2 as on Windows: the machine identifier is a UUID in .device_id inside the vault.",
            "3.2.2", ["--mode", "password_only", "--machine-id", "device-file"]),
    Fixture("unicode", "3.2.2 with a Hebrew master username and password and non-ASCII text in every field.",
            "3.2.2", ["--mode", "password_only", "--username", HEBREW_USERNAME, "--password", HEBREW_PASSWORD],
            UNICODE_ENTRIES),
    Fixture("empty", "3.2.2, set up and never used: no .passwords.enc at all.",
            "3.2.2", ["--mode", "password_only", "--no-extras"], []),
    Fixture("collisions", "3.2.2 with websites that collide as entry names or are not valid entry names.",
            "3.2.2", ["--mode", "password_only"], COLLISION_ENTRIES),
    Fixture("two_hundred", "3.2.2 with 200 entries; every 25th shares one website, one has 5,000 characters of notes.",
            "3.2.2", ["--mode", "password_only"], two_hundred_entries()),
    Fixture("v1_1_0", "1.1.0: PBKDF2 x 600,000 over username:password. 2.0.0 and later cannot open it.",
            "1.1.0", ["--era", "v1", "--flavor", "package"]),
    Fixture("v1_0_0", "The package of the first commit: PBKDF2 x 100,000 over username:password, SHA-256 verifier.",
            "1.0.0", ["--era", "original", "--flavor", "package"]),
    Fixture("script_2025", "The single-file program of the first commit: files directly in the data directory, "
            "machine identifier fallen back to the fixed string (no login name).",
            "1.0.0", ["--era", "original", "--flavor", "script", "--machine-id", "no-login-name"]),
)


def _checkout(version: str, work: Path) -> Path:
    """The source tree of *version*, taken from this repository's history into *work*."""
    commit, members = SOURCES[version]
    target = work / "src" / commit
    if target.is_dir():
        return target
    git = shutil.which("git")
    if git is None:
        sys.exit("git is needed to take the old source out of this repository's history")
    packed = subprocess.run([git, "-C", str(REPOSITORY), "archive", "--format=tar", commit, *members],
                            check=True, capture_output=True).stdout
    target.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(packed)) as tar:
        for member in tar.getmembers():
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts or not (member.isfile() or member.isdir()):
                sys.exit(f"unexpected member in the archive of {commit}: {member.name}")
            if member.isdir():
                (target / name).mkdir(parents=True, exist_ok=True)
            else:
                (target / name).parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                (target / name).write_bytes(source.read() if source else b"")
    return target


def _generate(fixture: Fixture, work: Path) -> Dict[str, Any]:
    """Run the driver for *fixture* and return its packed form."""
    source = _checkout(fixture.written_by, work)
    out = work / "out" / fixture.name
    if out.exists():
        shutil.rmtree(out)
    command = [sys.executable, "-B"]
    if fixture.written_by == "3.2.2":
        command += [str(HERE / "make_legacy_vault.py"), "--package-src", str(source)]
        produced = out / fixture.arguments[fixture.arguments.index("--mode") + 1]
    else:
        if fixture.arguments[fixture.arguments.index("--flavor") + 1] == "script":
            source = source / "password_manager.py"
        command += [str(HERE / "make_old_vault.py"), "--source", str(source)]
        produced = out
    command += ["--out", str(out), *fixture.arguments]
    if fixture.entries is not None:
        listing = work / f"{fixture.name}.entries.json"
        listing.write_text(json.dumps(fixture.entries), encoding="utf-8")
        command += ["--entries-json", str(listing)]
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    done = subprocess.run(command, env=environment, cwd=str(work), capture_output=True, text=True)
    if done.returncode != 0:
        sys.exit(f"generating {fixture.name} failed:\n{done.stdout}\n{done.stderr}")

    manifest = json.loads((produced / "manifest.json").read_text(encoding="utf-8"))
    data_dir = Path(manifest["data_dir"])
    log = data_dir / "password_manager.log"
    if log.exists():  # the one file that names the directory it was generated in
        log.write_bytes(log.read_bytes().replace(manifest["home"].encode(), NEUTRAL_HOME.encode()))
    packed: Dict[str, Any] = {
        "format": archive.FORMAT,
        "version": archive.VERSION,
        "name": fixture.name,
        "about": fixture.about,
        "written_by": {
            "irondome": manifest["package_version"],
            "commit": SOURCES[fixture.written_by][0],
            "driver": manifest["generator"],
        },
        "mode": manifest["mode"],
        "kdf": KDF_NAMES[fixture.written_by],
        "layout": manifest.get("layout", "secrets"),
        "machine_id": manifest["machine_id"],
        "master_username": manifest["master_username_input"],
        "master_password": manifest["master_password"],
        "stored_username": manifest["verify"]["master_username"],
        "vault_key": manifest["verify"]["vault_key_b64"],
        "keyring": {item["account"]: item["value"] for item in manifest["keyring"]},
        "recovery_key": manifest["recovery_key"],
        "entries": manifest["verify"]["entries"],
    }
    packed.update(archive.pack(data_dir))
    return packed


def _encode(packed: Dict[str, Any]) -> bytes:
    return (json.dumps(packed, indent=1) + "\n").encode("ascii")


def _selected(names: Optional[Sequence[str]]) -> List[Fixture]:
    known = {fixture.name: fixture for fixture in FIXTURES}
    for name in names or []:
        if name not in known:
            sys.exit(f"no fixture named {name!r}; known: {', '.join(known)}")
    return [known[name] for name in names] if names else list(FIXTURES)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "check"):
        sub = commands.add_parser(name)
        sub.add_argument("--only", nargs="+", metavar="NAME")
        sub.add_argument("--work", help="scratch directory (default: a new temporary directory, removed afterwards)")
    unpack = commands.add_parser("unpack")
    unpack.add_argument("name")
    unpack.add_argument("destination")
    args = parser.parse_args(argv)

    if args.command == "unpack":
        target = archive.unpack(archive.load(HERE / f"{args.name}.json"), args.destination)
        print(f"{args.name}: written to {target}")
        return 0

    work = Path(args.work).resolve() if args.work else Path(tempfile.mkdtemp(prefix="irondome-fixtures-"))
    work.mkdir(parents=True, exist_ok=True)
    os.umask(0o022)  # the code before 3.2.2 left file modes to the umask; pin it so the fixtures do not vary
    stale = []
    try:
        for fixture in _selected(args.only):
            encoded = _encode(_generate(fixture, work))
            target = HERE / f"{fixture.name}.json"
            current = target.read_bytes() if target.exists() else None
            if args.command == "build":
                target.write_bytes(encoded)
                print(f"{fixture.name}: {'unchanged' if current == encoded else 'written'} ({len(encoded)} bytes)")
            elif current != encoded:
                stale.append(fixture.name)
                print(f"{fixture.name}: DIFFERS from what the generators produce")
            else:
                print(f"{fixture.name}: reproduced byte for byte")
    finally:
        if not args.work:
            shutil.rmtree(work, ignore_errors=True)
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
