#!/usr/bin/env python3
"""Generate IronDome 3.2.2 vaults non-interactively, for migration fixtures.

Drives the *unmodified* 3.2.2 package (the directory given as
``--package-src``, which must contain ``password_manager/``) through its real
code paths:

  phase 1  ``SecurePasswordManager()``  -> first-run setup (the ``irondome
           create bunker`` / ``bunker`` CLI path, auth.py) with ``input`` /
           ``getpass`` scripted, then ``save_password`` x N and one backup.
  phase 2  ``AppState`` (the TUI state layer) -> a fresh login in the vault's
           own auth mode, one ``update_entry`` (adds ``updated_at``), a
           settings change, and the airspace session left open.
  verify   an independent reader that uses only ``cryptography`` -- no product
           code -- re-derives every key and decrypts every file.  It is the
           reference for the 3.x -> 4 migration reader.

Isolation (all enforced before the product package is imported):
  * HOME / USERPROFILE point at ``<out>/<mode>/home``; the script aborts if
    ``~`` still resolves to the real home.
  * ``sys.modules['keyring']`` is an in-memory fake, so the real ``keyring``
    package is never imported and no OS keychain is ever touched.
  * ``BiometricAuth`` is stubbed and ``biometric.subprocess.run`` raises, so no
    Touch ID / Hello / fprintd prompt can appear.
  * bytecode writing is disabled; the package directory is only read.

Determinism (default; ``--seed random`` / ``--freeze-time none`` turn it off):
  os.urandom, the recovery-key RNG, time.time, time.strftime, datetime.now,
  the machine id, the MAC/hostname/username record and the airspace pid are
  all pinned, so every file except ``password_manager.log`` (which embeds the
  output path) is byte-identical across runs.

Layout written per mode:
  <out>/<mode>/home/.password_manager/...   the vault, exactly as 3.2.2 wrote it
  <out>/<mode>/keyring.json                 what the OS keychain would hold
  <out>/<mode>/manifest.json                credentials, recovery key, plaintext
                                            entries, per-file sha256

An empty vault (``--entries-json`` holding ``[]``, with ``--no-extras``) is one
that was set up and never used: 3.2.2 writes no ``.passwords.enc`` for it.

Usage:
  make_legacy_vault.py --package-src DIR --out DIR [--mode all|biometric_only|biometric_password|password_only]

``build_fixtures.py`` next to this file runs it for every fixture in this
directory; see README.md.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import pwd
import stat
import subprocess
import sys
import types

MODES = ("biometric_only", "biometric_password", "password_only")
MODE_MENU_CHOICE = {"biometric_only": "1", "biometric_password": "2", "password_only": "3"}
MARKER = ".irondome-legacy-fixture"

DEFAULT_ENTRIES = [
    # (username, website, password, notes)
    ("alice@example.com", "github.com", "Gh!tHub-Pa55-0001", ""),
    ("alice", "https://mail.example.org/login", "c0rrect horse battery staple", "2FA: authenticator app"),
    ("root", "nas.local", 'p@ss"w\\ordéש', "unicode + quotes — שלום \U0001f512\nsecond line"),
]


# --------------------------------------------------------------------------
# Fakes and pins
# --------------------------------------------------------------------------

class PasswordDeleteError(Exception):
    pass


class FakeKeyring(types.ModuleType):
    """Drop-in for the ``keyring`` module, backed by a dict."""

    def __init__(self):
        super().__init__("keyring")
        self.store: dict[tuple[str, str], str] = {}
        self.errors = types.ModuleType("keyring.errors")
        self.errors.PasswordDeleteError = PasswordDeleteError
        self.errors.KeyringError = Exception

    def get_password(self, service, username):
        return self.store.get((service, username))

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.store:
            raise PasswordDeleteError(username)
        del self.store[(service, username)]

    def get_keyring(self):
        return self

    def dump(self):
        return [
            {"service": s, "account": a, "value": v}
            for (s, a), v in sorted(self.store.items())
        ]


class Drbg:
    """SHA-256 counter stream standing in for os.urandom."""

    def __init__(self, seed: str):
        self.seed = seed.encode()
        self.counter = 0

    def __call__(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.sha256(self.seed + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        return out[:n]


class Clock:
    """A clock that only moves when told to."""

    def __init__(self, epoch: float):
        self.now = float(epoch)

    def advance(self, seconds: float) -> None:
        self.now += seconds


class Script:
    """Answers the product's input()/getpass() prompts by prompt text."""

    def __init__(self, mode: str, username: str, password: str):
        self.rules = [
            ("Select (1/2/3)", MODE_MENU_CHOICE[mode]),
            ("Press Enter after saving", ""),
            ("Create master username", username),
            ("Create master password", password),
            ("Confirm master password", password),
            ("Enter username", username),
            ("Enter password", password),
            ("Enter your master password", password),
            ("Entry already exists", "n"),
        ]
        self.transcript: list[str] = []

    def answer(self, prompt: str = "") -> str:
        for needle, reply in self.rules:
            if needle in prompt:
                self.transcript.append(needle)
                return reply
        raise RuntimeError(f"unscripted prompt from product code: {prompt!r}")


# --------------------------------------------------------------------------
# Independent reader (cryptography only -- the migration reference)
# --------------------------------------------------------------------------

PBKDF2_ITERATIONS = 600_000


def _pbkdf2(secret: bytes, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=PBKDF2_ITERATIONS).derive(secret)


def read_legacy_vault(data_dir, keyring_entries, machine_id, password=None, vault_file=None):
    """Decrypt a 3.x vault without importing the product.

    keyring_entries: {account: value} for service "IronDome".
    Returns a dict describing everything recovered.
    """
    from cryptography.fernet import Fernet

    secrets_dir = os.path.join(data_dir, "secrets")

    def blob(name):
        with open(os.path.join(secrets_dir, name), "rb") as fh:
            return fh.read()

    salt = blob("salt.bin")
    auth_mode = keyring_entries.get("auth_mode")  # None => 3.x treats as password_only
    system_fernet = Fernet(base64.urlsafe_b64encode(_pbkdf2(machine_id.encode(), salt)))
    username = system_fernet.decrypt(blob(".master_user.enc")).decode()
    stored_hash = bytes.fromhex(system_fernet.decrypt(blob(".master_hash.enc")).decode())

    if auth_mode == "biometric_only":
        # keychain value = b64url( b64url(32 random bytes) ) -- decode ONCE.
        vault_key = base64.urlsafe_b64decode(keyring_entries["master_key"])
        password_ok = stored_hash == _pbkdf2(b"biometric_only_placeholder", salt)
    else:
        u, p = username.encode(), password.encode()
        vault_key = base64.urlsafe_b64encode(_pbkdf2(len(u).to_bytes(8, "big") + u + p, salt))
        password_ok = stored_hash == _pbkdf2(p, salt)

    store = os.path.join(secrets_dir, ".passwords.enc") if vault_file is None else vault_file
    if os.path.exists(store):
        with open(store, "rb") as fh:
            token = fh.read()
        entries = json.loads(Fernet(vault_key).decrypt(token))
        token_timestamp = int.from_bytes(base64.urlsafe_b64decode(token)[1:9], "big")
    else:  # set up, never used: 3.x reads a missing password store as an empty vault
        entries, token_timestamp = [], None

    return {
        "auth_mode": auth_mode,
        "salt_hex": salt.hex(),
        "master_username": username,
        "password_verifier_matches": password_ok,
        "vault_key_b64": vault_key.decode(),
        "fernet_token_timestamp": token_timestamp,
        "entries": entries,
        "recovery_ok": None,  # filled in by the caller when a recovery key is known
    }


def recovery_hash(recovery_key: str, salt: bytes) -> str:
    return _pbkdf2(recovery_key.strip().upper().replace("-", "").encode("ascii"), salt).hex()


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def file_tree(root):
    rows = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        st = os.lstat(dirpath)
        rows.append({"path": os.path.relpath(dirpath, root) + "/", "mode": oct(stat.S_IMODE(st.st_mode)),
                     "size": None, "head16": None, "sha256": None})
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            st = os.lstat(full)
            with open(full, "rb") as fh:
                data = fh.read()
            rows.append({"path": os.path.relpath(full, root), "mode": oct(stat.S_IMODE(st.st_mode)),
                         "size": st.st_size, "head16": data[:16].hex(),
                         "sha256": hashlib.sha256(data).hexdigest()})
    rows.sort(key=lambda r: r["path"])
    return rows


def content_digest(tree):
    """Digest over every file except the log, which embeds absolute paths."""
    h = hashlib.sha256()
    for row in tree:
        if row["sha256"] and not row["path"].endswith("password_manager.log"):
            h.update(f"{row['path']}\0{row['mode']}\0{row['sha256']}\n".encode())
    return h.hexdigest()


def print_report(manifest):
    print(f"\n=== mode: {manifest['mode']}  (IronDome {manifest['package_version']}, "
          f"cryptography {manifest['cryptography_version']}, python {manifest['python']}) ===")
    print(f"home: {manifest['home']}")
    print(f"{'mode':<7} {'size':>6}  {'first 16 bytes (hex)':<34} path")
    for row in manifest["tree"]:
        size = "" if row["size"] is None else row["size"]
        print(f"{row['mode']:<7} {size:>6}  {row['head16'] or '':<34} {row['path']}")
    print("keyring (service, account) -> value:")
    for item in manifest["keyring"]:
        print(f"  ({item['service']!r}, {item['account']!r}) -> {item['value']!r}  [len {len(item['value'])}]")
    print(f"independent decrypt: {len(manifest['verify']['entries'])} entries, "
          f"keys seen = {sorted({k for e in manifest['verify']['entries'] for k in e})}")
    print(f"content digest (all files but the log): {manifest['content_digest']}")


# --------------------------------------------------------------------------
# One mode, in this process
# --------------------------------------------------------------------------

def build_one(args) -> dict:
    mode = args.mode
    out_mode = os.path.join(os.path.abspath(args.out), mode)
    home = os.path.join(out_mode, "home")
    real_home = pwd.getpwuid(os.getuid()).pw_dir

    # ---- refuse anything that could land on the real vault ---------------
    if os.path.realpath(out_mode).startswith(os.path.realpath(os.path.join(real_home, ".password_manager"))):
        sys.exit("refusing: output directory is inside the real ~/.password_manager")
    if os.path.exists(out_mode) and os.listdir(out_mode):
        sys.exit(f"refusing: {out_mode} already exists and is not empty (choose a fresh --out)")
    os.makedirs(home, mode=0o700)
    open(os.path.join(out_mode, MARKER), "w").close()

    os.environ["HOME"] = home
    os.environ["USERPROFILE"] = home
    os.environ["TZ"] = "UTC"
    os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"  # belt and braces
    for var in ("CI", "GITHUB_ACTIONS", "JENKINS_URL", "CIRCLECI", "TRAVIS", "GITLAB_CI"):
        os.environ.pop(var, None)
    import time
    time.tzset()
    if os.path.expanduser("~") != home:
        sys.exit("refusing: HOME redirect did not take effect")

    sys.dont_write_bytecode = True
    fake_keyring = FakeKeyring()
    sys.modules["keyring"] = fake_keyring
    sys.modules["keyring.errors"] = fake_keyring.errors

    # ---- pins that must exist before the product is imported -------------
    clock = None if args.freeze_time == "none" else Clock(float(args.freeze_time))
    drbg = None if args.seed == "random" else Drbg(f"irondome-fixture:{args.seed}:{mode}")
    real_strftime = time.strftime
    if clock:
        import datetime as _dt
        time.time = lambda: clock.now
        time.time_ns = lambda: int(clock.now * 1e9)
        time.strftime = lambda fmt, t=None: real_strftime(fmt, time.gmtime(clock.now) if t is None else t)

        class FrozenDatetime(_dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls.fromtimestamp(clock.now, _dt.timezone.utc).replace(tzinfo=None)
    if drbg:
        os.urandom = drbg

    sys.path.insert(0, os.path.abspath(args.package_src))
    import builtins
    import getpass
    import logging

    import cryptography
    import password_manager
    from password_manager import auth, biometric, encryption, keystore, session, utils
    from password_manager.manager import SecurePasswordManager
    from password_manager.settings import Settings
    from password_manager.tui.state.app_state import AppState

    pkg_file = os.path.realpath(password_manager.__file__)
    if not pkg_file.startswith(os.path.realpath(args.package_src)):
        sys.exit(f"refusing: imported password_manager from {pkg_file}, not --package-src")
    assert keystore._keyring_lib is fake_keyring and keystore._KEYRING_IMPORT_OK

    # ---- biometric: always "present and passes", never reaches the OS ----
    bio_calls: list[str] = []

    def _blocked(*a, **k):
        raise RuntimeError("biometric subprocess blocked by fixture generator")

    biometric.subprocess = types.SimpleNamespace(run=_blocked, TimeoutExpired=subprocess.TimeoutExpired)
    biometric.BiometricAuth.is_available = lambda self: True
    biometric.BiometricAuth.get_type = lambda self: args.bio_type
    biometric.BiometricAuth.authenticate = lambda self, reason="": (bio_calls.append(reason), True)[1]

    # ---- identity pins ---------------------------------------------------
    if args.machine_id == "device-file":
        # Windows has no os.uname(): 3.2.2 then falls back to a uuid4 it writes
        # to ~/.password_manager/.device_id.  Reproduce that with its own code.
        class OsWithoutUname:
            def __getattr__(self, name):
                if name == "uname":
                    raise AttributeError("uname (emulating Windows)")
                return getattr(os, name)

        encryption.os = OsWithoutUname()
    elif args.machine_id != "real":
        encryption.get_machine_id = lambda: args.machine_id
    if args.machine_id != "real":
        user, _, host = args.machine_id.partition("@")
        if not host:
            user, host = "fixture-user", "fixture-host"

        def fake_machine_info():
            return {"hostname": host, "os_info": args.os_info, "mac_address": args.mac,
                    "username": user, "time": time.strftime("%Y-%m-%d %H:%M:%S")}

        utils.get_machine_info = session.get_machine_info = auth.get_machine_info = fake_machine_info
    if clock:
        session.datetime = utils.datetime = FrozenDatetime
    recovery_keys: list[str] = []
    real_generate_recovery_key = keystore.SecureKeyStore.generate_recovery_key
    if drbg:
        keystore.secrets = types.SimpleNamespace(
            token_hex=lambda n: drbg(n).hex(), compare_digest=keystore.secrets.compare_digest)

    def recording_generate_recovery_key(self):
        key = real_generate_recovery_key(self)
        recovery_keys.append(key)
        return key

    keystore.SecureKeyStore.generate_recovery_key = recording_generate_recovery_key

    script = Script(mode, args.username, args.password)
    builtins.input = script.answer
    getpass.getpass = script.answer

    def tick(seconds=60):
        if clock:
            clock.advance(seconds)

    def new_process():
        """Drop state a fresh interpreter would not have (log handlers)."""
        logger = logging.getLogger("SecurePasswordManager")
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)

    product_stdout = io.StringIO()
    entries = [tuple(e) for e in (json.load(open(args.entries_json)) if args.entries_json else DEFAULT_ENTRIES)]
    entries = entries[: args.entries] if args.entries else entries
    if not entries and not args.no_extras:
        sys.exit("refusing: a vault with no entries has nothing to back up or update; add --no-extras")

    with contextlib.redirect_stdout(sys.stdout if args.verbose else product_stdout):
        # ---- phase 1: CLI path -- setup + saves + backup -----------------
        mgr = SecurePasswordManager()
        data_dir = mgr.data_dir
        assert data_dir == os.path.join(home, ".password_manager")
        assert mgr.session.session_authenticated, "setup did not authenticate"
        for username, website, password, notes in entries:
            tick()
            assert mgr.save_password(username, website, password, notes), f"save failed: {website}"
        if not args.no_extras:
            tick()
            assert mgr.backup_passwords()
        new_process()

        # ---- phase 2: TUI state path -- login + update + settings --------
        if not args.no_extras:
            tick(3600)
            real_getpid = os.getpid
            if clock:
                os.getpid = lambda: 4242  # recorded in .airspace.session
            try:
                state = AppState()
                if mode == "password_only":
                    assert state.authenticate_password(args.username, args.password)
                else:
                    assert state.authenticate_biometric()
            finally:
                os.getpid = real_getpid
            tick()
            u, w, p, n = entries[-1]
            assert state.update_entry(u, w, u, w, p + "-rotated", n) is not None
            Settings(data_dir).set("password_length", 24)
            new_process()

    # ---- independent verification ---------------------------------------
    machine_id = encryption.get_machine_id()
    kr = {item["account"]: item["value"] for item in fake_keyring.dump() if item["service"] == "IronDome"}
    verify = read_legacy_vault(data_dir, kr, machine_id, password=args.password)
    expected = [{"username": u, "website": w, "password": p, "notes": n} for u, w, p, n in entries]
    if not args.no_extras:
        expected[-1]["password"] += "-rotated"
    got = sorted(({k: e[k] for k in ("username", "website", "password", "notes")} for e in verify["entries"]),
                 key=lambda e: e["website"])
    assert got == sorted(expected, key=lambda e: e["website"]), "independent decrypt does not match what was saved"
    backups = []
    backups_dir = os.path.join(data_dir, "backups")
    if os.path.isdir(backups_dir):
        for name in sorted(os.listdir(backups_dir)):
            b = read_legacy_vault(data_dir, kr, machine_id, password=args.password,
                                  vault_file=os.path.join(backups_dir, name))
            backups.append({"file": name, "entries": b["entries"]})
    if recovery_keys:
        salt = bytes.fromhex(verify["salt_hex"])
        verify["recovery_ok"] = recovery_hash(recovery_keys[-1], salt) == kr.get("recovery_hash")
        assert verify["recovery_ok"]

    tree = file_tree(home)
    manifest = {
        "generator": os.path.basename(__file__),
        "mode": mode,
        "package_version": password_manager.__version__,
        "package_src": os.path.abspath(args.package_src),
        "python": sys.version.split()[0],
        "cryptography_version": cryptography.__version__,
        "seed": args.seed,
        "frozen_start_epoch": None if clock is None else float(args.freeze_time),
        "home": home,
        "data_dir": data_dir,
        "machine_id": machine_id,
        "mac_address": None if args.machine_id == "real" else args.mac,
        "bio_type": args.bio_type,
        "master_username_input": args.username if mode != "biometric_only" else None,
        "master_password": args.password if mode != "biometric_only" else None,
        "recovery_key": recovery_keys[-1] if recovery_keys else None,
        "biometric_prompts": bio_calls,
        "prompts_answered": script.transcript,
        "keyring": fake_keyring.dump(),
        "verify": verify,
        "backups": backups,
        "tree": tree,
        "content_digest": content_digest(tree),
    }
    with open(os.path.join(out_mode, "keyring.json"), "w") as fh:
        json.dump(manifest["keyring"], fh, indent=2)
    with open(os.path.join(out_mode, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
    return manifest


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True, help="output directory (one sub-directory per mode)")
    ap.add_argument("--mode", default="all", choices=("all",) + MODES)
    ap.add_argument("--package-src", required=True,
                    help="directory that CONTAINS the 3.2.2 password_manager package (read-only)")
    ap.add_argument("--seed", default="0", help='RNG seed, or "random" for real os.urandom')
    ap.add_argument("--freeze-time", default="1767225600",
                    help='start epoch for the pinned clock (default 2026-01-01T00:00:00Z), or "none"')
    ap.add_argument("--machine-id", default="fixture-user@fixture-host",
                    help='value get_machine_id() returns ("user@host" on macOS, /etc/machine-id on Linux); '
                         '"device-file" = Windows-style uuid in .device_id; '
                         '"real" = this machine (leaks hostname/user/MAC into the fixture)')
    ap.add_argument("--os-info", default="Darwin 27.2.0", help="os_info recorded in the lockout file")
    ap.add_argument("--mac", default="02:00:00:00:00:01", help="MAC used as the lockout-file key")
    ap.add_argument("--bio-type", default="Touch ID", choices=("Touch ID", "Windows Hello", "Fingerprint"))
    ap.add_argument("--username", default="fixture-admin")
    ap.add_argument("--password", default="Correct-Horse-Battery-9")
    ap.add_argument("--entries", type=int, default=0, help="use only the first N entries (default: all)")
    ap.add_argument("--entries-json", help="JSON file: [[username, website, password, notes], ...]")
    ap.add_argument("--no-extras", action="store_true",
                    help="setup + saves only: no backup, re-login, update, settings or airspace file")
    ap.add_argument("--verbose", action="store_true", help="show the product's own stdout")
    ap.add_argument("--json", action="store_true", help="print the manifest(s) as JSON instead of the table")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.mode != "all":
        manifest = build_one(args)
        print(json.dumps(manifest, indent=2, ensure_ascii=False)) if args.json else print_report(manifest)
        return 0

    # One interpreter per mode: HOME, the logger and every pin start clean.
    rc = 0
    passthrough = [a for a in (argv or sys.argv[1:])]
    for mode in MODES:
        cmd = [sys.executable, "-B", os.path.abspath(__file__), *passthrough, "--mode", mode]
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        rc |= subprocess.run(cmd, env=env).returncode
    return rc


if __name__ == "__main__":
    sys.exit(main())
