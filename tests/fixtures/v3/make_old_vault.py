#!/usr/bin/env python3
"""Generate vaults with the code that came before IronDome 2.0, for migration fixtures.

2.0.0 changed how the vault key is derived and converted nothing, so a vault
written by earlier code stayed in the earlier format for good. Two such
formats exist, and this script produces both by driving the code of the time,
unmodified, through first-run setup, a few saves, a backup and a fresh login:

  --era original   the first commit (dccb4ed), in use from April 2025 until
                   1.0.1: PBKDF2 x 100,000 over ``username:password``, verifier
                   SHA-256(salt || password), system key PBKDF2 x 100,000 over
                   ``<os.getlogin()>@<hostname>``, with a fixed string as the
                   fallback when the login name cannot be read.
  --era v1         1.0.1 - 1.1.0 (b611aad): the same joins with PBKDF2 x 600,000
                   everywhere, and the verifier is a PBKDF2 output too.

  --flavor package  the ``password_manager`` package of that commit; files in
                    ``secrets/``. ``--source`` is the directory holding it.
  --flavor script   the single-file ``password_manager.py`` of the first
                    commit; the four files directly in the data directory.
                    ``--source`` is that file.

Isolation and determinism are the ones ``make_legacy_vault.py`` describes:
HOME is redirected, ``os.urandom`` and the clock are pinned, the machine
description is a constant (the code of the time resolved the host name through
DNS on every login; that call is replaced, so nothing here touches a network).
``--machine-id no-login-name`` makes ``os.getlogin`` fail the way it does
without a controlling terminal, so the code takes its own fallback.

The result is checked by a reader that uses only ``cryptography``.

Usage:
  make_old_vault.py --era original|v1 --flavor package|script --source PATH --out DIR
"""

from __future__ import annotations

import argparse
import base64
import builtins
import datetime
import getpass
import hashlib
import importlib.util
import json
import logging
import os
import sys
import time

from make_legacy_vault import DEFAULT_ENTRIES, Clock, Drbg, Script, content_digest, file_tree

ERAS = {
    # era: (PBKDF2 iterations, how the verifier is computed)
    "original": (100_000, "sha256"),
    "v1": (600_000, "pbkdf2"),
}
NO_LOGIN_NAME = "no-login-name"
ORIGINAL_FALLBACK_ID = "secure_password_manager_default_key"


def _pbkdf2(secret: bytes, salt: bytes, iterations: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations).derive(secret)


def read_old_vault(base_dir, machine_id, username, password, era):
    """Decrypt a pre-2.0 vault without importing the code that wrote it."""
    from cryptography.fernet import Fernet

    iterations, verifier = ERAS[era]

    def blob(name):
        with open(os.path.join(base_dir, name), "rb") as fh:
            return fh.read()

    salt = blob("salt.bin")
    system = Fernet(base64.urlsafe_b64encode(_pbkdf2(machine_id.encode(), salt, iterations)))
    stored_hash = bytes.fromhex(system.decrypt(blob(".master_hash.enc")).decode())
    secret = password.encode()
    expected = hashlib.sha256(salt + secret).digest() if verifier == "sha256" else _pbkdf2(secret, salt, iterations)
    vault_key = base64.urlsafe_b64encode(_pbkdf2(f"{username}:{password}".encode(), salt, iterations))
    token = blob(".passwords.enc")
    return {
        "auth_mode": None,
        "salt_hex": salt.hex(),
        "master_username": system.decrypt(blob(".master_user.enc")).decode(),
        "password_verifier_matches": stored_hash == expected,
        "vault_key_b64": vault_key.decode(),
        "fernet_token_timestamp": int.from_bytes(base64.urlsafe_b64decode(token)[1:9], "big"),
        "entries": json.loads(Fernet(vault_key).decrypt(token)),
    }


class _OsWithoutLoginName:
    """``os``, except that ``getlogin`` fails as it does without a controlling terminal."""

    def __getattr__(self, name):
        if name == "getlogin":
            return self._getlogin
        return getattr(os, name)

    @staticmethod
    def _getlogin():
        raise OSError(25, "Inappropriate ioctl for device")


def build(args) -> dict:
    out = os.path.abspath(args.out)
    home = os.path.join(out, "home")
    if os.path.exists(out) and os.listdir(out):
        sys.exit(f"refusing: {out} already exists and is not empty (choose a fresh --out)")
    os.makedirs(home, mode=0o700)
    os.environ["HOME"] = home
    os.environ["USERPROFILE"] = home
    os.environ["TZ"] = "UTC"
    time.tzset()
    if os.path.expanduser("~") != home:
        sys.exit("refusing: HOME redirect did not take effect")
    sys.dont_write_bytecode = True

    clock = Clock(float(args.freeze_time))
    drbg = Drbg(f"irondome-fixture:{args.seed}:{args.era}:{args.flavor}")
    real_strftime = time.strftime
    time.time = lambda: clock.now
    time.time_ns = lambda: int(clock.now * 1e9)
    time.strftime = lambda fmt, t=None: real_strftime(fmt, time.gmtime(clock.now) if t is None else t)
    os.urandom = drbg

    class FrozenDatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls.fromtimestamp(clock.now, datetime.timezone.utc).replace(tzinfo=None)

    pinned_id = None if args.machine_id == NO_LOGIN_NAME else args.machine_id
    if pinned_id is None and args.era != "original":
        sys.exit(f"refusing: --machine-id {NO_LOGIN_NAME} needs --era original (later code does not call os.getlogin)")

    def machine_info():
        return {
            "hostname": "fixture-host",
            "ip_address": "192.0.2.1",
            "os_info": "Darwin 24.4.0",
            "mac_address": "02:00:00:00:00:01",
            "username": "fixture-user",
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    source = os.path.abspath(args.source)
    if args.flavor == "package":
        sys.path.insert(0, source)
        import password_manager
        from password_manager import auth, encryption, session, utils
        from password_manager.manager import SecurePasswordManager

        if not os.path.realpath(password_manager.__file__).startswith(os.path.realpath(source)):
            sys.exit(f"refusing: imported password_manager from {password_manager.__file__}, not --source")
        version = password_manager.__version__
        if pinned_id is None:
            encryption.os = _OsWithoutLoginName()
        else:
            encryption.get_machine_id = lambda: pinned_id
        utils.get_machine_info = session.get_machine_info = auth.get_machine_info = machine_info
        session.datetime = FrozenDatetime
        session.SessionManager.start_session_checker = lambda self: None  # a thread that only sleeps and prints
        layout = "secrets"
    else:
        spec = importlib.util.spec_from_file_location("legacy_script", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        SecurePasswordManager = module.SecurePasswordManager
        version = "script"
        if pinned_id is None:
            module.os = _OsWithoutLoginName()
        else:
            SecurePasswordManager._get_machine_id = lambda self: pinned_id
        SecurePasswordManager._get_machine_info = lambda self: machine_info()
        SecurePasswordManager.start_session_checker = lambda self: None
        module.datetime = FrozenDatetime
        layout = "flat"

    script = Script("password_only", args.username, args.password)
    builtins.input = script.answer
    getpass.getpass = script.answer
    builtins.print = lambda *a, **k: None  # the product narrates every step

    def new_process():
        """Drop state a fresh interpreter would not have (the log handler)."""
        logger = logging.getLogger("SecurePasswordManager")
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)

    entries = [tuple(entry) for entry in DEFAULT_ENTRIES]
    if args.entries_json:
        with open(args.entries_json) as fh:
            entries = [tuple(entry) for entry in json.load(fh)]
    if len(entries) < 2:
        sys.exit("refusing: give at least two entries (one is saved after the second login)")

    def authenticated(manager):
        return manager.session_authenticated if args.flavor == "script" else manager.session.session_authenticated

    # ---- first run: setup, saves, one backup ----------------------------
    manager = SecurePasswordManager()
    assert authenticated(manager), "setup did not authenticate"
    data_dir = manager.data_dir
    assert data_dir == os.path.join(home, ".password_manager")
    for username, website, password, notes in entries[:-1]:
        clock.advance(60)
        assert manager.save_password(username, website, password, notes), f"save failed: {website}"
    clock.advance(60)
    assert manager.backup_passwords()
    new_process()

    # ---- second run: log in with the stored credentials, save one more --
    clock.advance(3600)
    manager = SecurePasswordManager()
    assert authenticated(manager), "login with the credentials just created failed"
    clock.advance(60)
    username, website, password, notes = entries[-1]
    assert manager.save_password(username, website, password, notes), f"save failed: {website}"
    new_process()

    # ---- independent verification ---------------------------------------
    machine_id = ORIGINAL_FALLBACK_ID if pinned_id is None else pinned_id
    base_dir = os.path.join(data_dir, "secrets") if layout == "secrets" else data_dir
    verify = read_old_vault(base_dir, machine_id, args.username, args.password, args.era)
    assert verify["password_verifier_matches"], "stored verifier does not match the era's formula"
    assert verify["master_username"] == args.username
    got = [{key: entry[key] for key in ("username", "website", "password", "notes")} for entry in verify["entries"]]
    assert got == [dict(zip(("username", "website", "password", "notes"), entry)) for entry in entries], (
        "independent decrypt does not match what was saved"
    )

    import cryptography

    tree = file_tree(home)
    manifest = {
        "generator": os.path.basename(__file__),
        "mode": "password_only",
        "era": args.era,
        "flavor": args.flavor,
        "layout": layout,
        "package_version": version,
        "python": sys.version.split()[0],
        "cryptography_version": cryptography.__version__,
        "seed": args.seed,
        "frozen_start_epoch": float(args.freeze_time),
        "home": home,
        "data_dir": data_dir,
        "machine_id": machine_id,
        "master_username_input": args.username,
        "master_password": args.password,
        "recovery_key": None,
        "keyring": [],
        "verify": verify,
        "tree": tree,
        "content_digest": content_digest(tree),
    }
    with open(os.path.join(out, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    return manifest


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--era", required=True, choices=sorted(ERAS))
    ap.add_argument("--flavor", required=True, choices=("package", "script"))
    ap.add_argument("--source", required=True, help="directory holding password_manager/, or the script file")
    ap.add_argument("--out", required=True, help="output directory; must be empty or absent")
    ap.add_argument("--machine-id", default="fixture-user@fixture-host",
                    help=f'what the code\'s machine-id function returns, or "{NO_LOGIN_NAME}" to make os.getlogin fail')
    ap.add_argument("--username", default="fixture-admin")
    ap.add_argument("--password", default="Correct-Horse-Battery-9")
    ap.add_argument("--entries-json", help="JSON file: [[username, website, password, notes], ...]")
    ap.add_argument("--seed", default="0")
    ap.add_argument("--freeze-time", default="1743465600", help="start of the pinned clock (2025-04-01T00:00:00Z)")
    return ap.parse_args(argv)


if __name__ == "__main__":
    real_print = print
    result = build(parse_args())
    real_print(f"{result['era']}/{result['flavor']}: {len(result['verify']['entries'])} entries, "
               f"machine id {result['machine_id']!r}, content digest {result['content_digest']}")
