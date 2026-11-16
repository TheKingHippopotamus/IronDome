"""Device keys held by the Apple Secure Enclave.

How it works
------------
``enroll`` asks the Secure Enclave for a new P-256 private key. The key is
generated inside the chip and never leaves it; what comes back is an opaque
blob only this Mac's Secure Enclave can use. IronDome then picks a random
point on the curve -- chosen so that *nobody* knows its discrete logarithm --
and asks the chip for the ECDH shared secret between its key and that point.
That shared secret is the device secret.

``unseal`` repeats the key agreement. Only the chip can: computing the secret
without it means solving the discrete-log problem on P-256.

Under the ``biometry`` policy the key is created with
``.biometryCurrentSet``. The Secure Enclave then refuses the key agreement
until its own sensor path reports a match for a currently enrolled finger.
There is no flag for a program to flip and no stored key for it to read: the
fingerprint is a precondition the chip enforces on the computation itself.
The automated suite proves the negative on real hardware -- a biometric key
asked to work without a prompt answers "authentication required" -- and
``irondome doctor --touch`` lets you prove the positive with your own finger.

The native side is ``irondome_se.swift``, about 250 lines, compiled on this
machine from the source shipped in the package (Xcode Command Line Tools
provide ``swiftc``). No prebuilt binary is downloaded or trusted.

Limits, stated plainly: the blob and the random point are stored on the same
disk as everything else, in the device directory. Deleting them is what
``nuke`` does. Should a forensic lab ever recover that file from the SSD, it
would still need this exact Mac's Secure Enclave -- and, under the biometry
policy, your finger -- to turn it back into a key.

Every key is ``ThisDeviceOnly``: it never leaves this Mac's chip. Keys under
the ``device`` policy are ``AfterFirstUnlock``: once the Mac has been unlocked
since it started they work while the screen is locked, so an SSH session, a
scheduled job or an agent holding a grant keeps working. ``biometry`` and
``presence`` keys are ``WhenUnlocked``: while the screen is locked the Secure
Enclave will neither create nor use one, and enrolling or unsealing fails with
a ``HardwareError`` that says the Mac is locked. Nothing is wrong with such a
key; it works again once the screen is unlocked. Before the first unlock after
a restart, no key works under any policy.

``IRONDOME_NO_TOUCH=1`` is honoured here as well as in ``irondome.unlock``:
with it set the helper is never started in interactive mode, so no code path
can put a Touch ID prompt on the screen.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from irondome import device as devices
from irondome import paths
from irondome.crypto import b64d, b64e
from irondome.device.base import (
    DEVICE_SECRET_LEN,
    POLICY_BIOMETRY,
    POLICY_DEVICE,
    POLICY_PRESENCE,
    DeviceBackend,
    Probe,
    check_descriptor,
    new_ref,
)
from irondome.errors import AuthError, HardwareError, UsageError, VaultError
from irondome.secmem import SecureBuffer

__all__ = ["SecureEnclaveBackend", "helper_source", "helper_status", "build_helper"]

_HELPER_TIMEOUT = 30.0
_TOUCH_TIMEOUT = 180.0
#: Overrides how long a Touch ID prompt may wait, in whole seconds from 1 to 3600. The MCP server
#: sets it below its client's request timeout, so a prompt never outlives the request.
ENV_TOUCH_TIMEOUT = "IRONDOME_TOUCH_TIMEOUT"
_BUILD_TIMEOUT = 600.0
#: Held while the helper is compiled, in the helper directory.
_BUILD_LOCK = ".build.lock"

#: Where system tools are looked up. The caller's PATH is never consulted.
_SAFE_PATH = "/usr/bin:/bin"
#: A state file is under 2 KiB. Anything much larger is not one.
_MAX_STATE_BYTES = 64 * 1024
#: The longest prompt text passed on; the helper shows no more than this.
_MAX_REASON = 200
#: How this backend names its state files: the descriptor's reference.
_STATE_NAME = re.compile(r"[0-9a-f]{32}\.json")

_NEEDS_TOOLS = (
    "Secure Enclave support needs the Xcode Command Line Tools to compile its helper. Run: xcode-select --install"
)
#: Said before swiftc runs: a first compile takes seconds, and up to a minute where swiftc has never run.
_COMPILING = (
    "Compiling the Secure Enclave helper (once, and again after an upgrade that changes it); "
    "this can take a minute..."
)

# Exit statuses of irondome-se (see the Failure enum in irondome_se.swift).
_EXIT_UNAVAILABLE = 3
_EXIT_INTERACTION = 4
_EXIT_DENIED = 5
_EXIT_KEY_UNUSABLE = 6


def _touch_timeout() -> float:
    """How long an interactive key agreement may wait for a finger."""
    raw = os.environ.get(ENV_TOUCH_TIMEOUT, "").strip()
    if not raw:
        return _TOUCH_TIMEOUT
    if not raw.isdigit() or not 1 <= int(raw) <= 3600:
        raise UsageError(f"{ENV_TOUCH_TIMEOUT} must be a whole number of seconds from 1 to 3600")
    return float(int(raw))


def helper_source() -> Path:
    return Path(__file__).with_name("irondome_se.swift")


def _clean_env() -> Dict[str, str]:
    """A minimal environment: nothing that could inject code into the helper."""
    keep = ("HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "__CF_USER_TEXT_ENCODING")
    env = {name: os.environ[name] for name in keep if name in os.environ}
    env["PATH"] = _SAFE_PATH
    return env


def _require_macos() -> None:
    if sys.platform != "darwin":
        raise HardwareError("the Secure Enclave backend only works on macOS")


def _helper_path() -> Path:
    override = os.environ.get("IRONDOME_SE_HELPER")
    if override:
        return Path(override)
    digest = hashlib.sha256(helper_source().read_bytes()).hexdigest()[:16]
    return paths.helper_dir() / f"irondome-se-{digest}"


def _record_path(helper: Path) -> Path:
    """Where the SHA-256 of the compiled helper is kept, beside it."""
    return helper.with_name(helper.name + ".sha256")


def _intact(helper: Path) -> bool:
    """Whether the cached *helper* is, byte for byte, the file that was compiled here.

    This catches a damaged cache (a truncated file, a disk fault, a half-restored folder), so that it is
    compiled again instead of failing every command. It is no defence against a program running as you:
    whatever can replace the helper can replace the record beside it.
    """
    try:
        recorded = paths.read_file(_record_path(helper), limit=256).decode("ascii").strip()
        return bool(recorded) and recorded == hashlib.sha256(paths.read_file(helper)).hexdigest()
    except (OSError, VaultError, ValueError):
        return False


def _check_helper(path: Path) -> None:
    """Refuse to execute a helper that someone else could have replaced."""
    try:
        info = path.stat()
    except OSError as exc:
        raise HardwareError(f"cannot use the Secure Enclave helper at {path}: {exc.strerror or exc}") from None
    if not path.is_file():
        raise HardwareError(f"{path} is not a regular file")
    if info.st_mode & 0o022:
        raise HardwareError(f"{path} is writable by other users; refusing to run it")
    if info.st_uid not in (os.getuid(), 0):
        raise HardwareError(f"{path} is owned by another user; refusing to run it")


def _find_swiftc() -> Optional[str]:
    """The Swift compiler, or None when the developer tools are not installed.

    ``/usr/bin/swiftc`` exists on every Mac, but without the tools it is a
    stub that opens Apple's "install the command line developer tools" dialog.
    ``xcode-select -p`` answers the same question without a dialog, so it is
    asked first and the stub is never run.
    """
    select = shutil.which("xcode-select", path=_SAFE_PATH)
    swiftc = shutil.which("swiftc", path=_SAFE_PATH)
    if not select or not swiftc:
        return None
    try:
        result = subprocess.run(
            [select, "-p"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=_HELPER_TIMEOUT,
            env=_clean_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    developer = Path(result.stdout.decode("utf-8", "replace").strip())
    compilers = (
        developer / "usr" / "bin" / "swiftc",
        developer / "Toolchains" / "XcodeDefault.xctoolchain" / "usr" / "bin" / "swiftc",
    )
    return swiftc if any(compiler.exists() for compiler in compilers) else None


def helper_status() -> Dict[str, Any]:
    """Where the Secure Enclave helper is and whether it is ready, without building or running it.

    Nothing is compiled, no helper is started and no prompt can appear: the source is hashed, the
    cached helper is looked for, and only when it is missing is ``xcode-select -p`` asked whether a
    compiler is installed (the ``swiftc`` stub, which opens Apple's install dialog, is never run).
    Works on any platform; off macOS the helper simply is not there. Keys:

    ``source``            the Swift source shipped in the package
    ``source_sha256``     its SHA-256, or None when it cannot be read
    ``path``              the helper this process would run (``IRONDOME_SE_HELPER`` or the cache), or
                          None when the source cannot be read to name the cached one
    ``built``             whether that helper exists
    ``from_environment``  whether ``IRONDOME_SE_HELPER`` names it
    ``compiler``          whether the Xcode Command Line Tools can compile it; None when not asked
                          (the helper is there, or is named by the environment)
    ``error``             why the source cannot be read, or None
    """
    source = helper_source()
    status: Dict[str, Any] = {
        "source": str(source),
        "source_sha256": None,
        "path": None,
        "built": False,
        "from_environment": bool(os.environ.get("IRONDOME_SE_HELPER")),
        "damaged": False,
        "compiler": None,
        "error": None,
    }
    try:
        status["source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    except OSError as exc:
        status["error"] = exc.strerror or str(exc)
    try:
        helper = _helper_path()
    except OSError:
        return status  # the cached helper is named after the source, which cannot be read
    status["path"] = str(helper)
    status["built"] = helper.is_file() and (status["from_environment"] or _intact(helper))
    status["damaged"] = helper.is_file() and not status["built"]
    if not status["built"] and not status["from_environment"]:
        status["compiler"] = _find_swiftc() is not None
    return status


def build_helper(force: bool = False) -> Path:
    """Compile the Secure Enclave helper from the packaged source, once.

    The binary is cached under the device directory and named after the hash
    of its source, so an upgraded IronDome never runs a stale helper. Its own
    SHA-256 is recorded beside it, and a cached helper that no longer matches
    the record (see :func:`_intact`) is compiled again. A helper named by
    ``IRONDOME_SE_HELPER`` is used as it is and never rebuilt. Before
    the compiler starts, :func:`irondome.device.report_progress` says so: the
    first compile can take a minute, and the person should not have to guess.
    """
    _require_macos()
    try:
        target = _helper_path()
    except OSError as exc:
        raise HardwareError(f"the Secure Enclave helper source cannot be read: {exc.strerror or exc}") from None
    if os.environ.get("IRONDOME_SE_HELPER"):
        if not target.exists():
            raise HardwareError(f"IRONDOME_SE_HELPER points at {target}, which does not exist")
        _check_helper(target)
        return target
    damaged = target.exists() and not _intact(target)
    if target.exists() and not force and not damaged:
        _check_helper(target)
        return target
    swiftc = _find_swiftc()
    if not swiftc:
        if damaged:
            raise HardwareError(
                f"the compiled Secure Enclave helper at {target} is damaged, and compiling it again needs the "
                "Xcode Command Line Tools. Run: xcode-select --install"
            )
        raise HardwareError(_NEEDS_TOOLS)
    try:
        paths.ensure_dir(target.parent)
        # One build at a time: two at once could leave one's binary beside the other's record.
        with paths.file_lock(target.parent / _BUILD_LOCK):
            if not force and target.exists() and _intact(target):
                _check_helper(target)  # another process compiled it while this one waited
                return target
            _compile(swiftc, target)
    except OSError as exc:
        raise HardwareError(f"could not compile the Secure Enclave helper: {exc.strerror or exc}") from None
    _check_helper(target)
    return target


def _compile(swiftc: str, target: Path) -> None:
    """Run the compiler, put its output at *target* and record that output's SHA-256 beside it."""
    scratch = target.with_name(f".build-{os.getpid()}-{target.name}")
    try:
        devices.report_progress(_COMPILING)
        result = subprocess.run(
            [swiftc, "-O", "-o", str(scratch), str(helper_source())],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_BUILD_TIMEOUT,
            env=_clean_env(),
        )
        if result.returncode != 0 or not scratch.exists():
            tail = result.stderr.decode("utf-8", "replace").strip().splitlines()[-5:]
            raise HardwareError("could not compile the Secure Enclave helper: " + " | ".join(tail))
        os.chmod(scratch, 0o700)
        digest = hashlib.sha256(paths.read_file(scratch)).hexdigest()
        os.replace(scratch, target)
    except subprocess.TimeoutExpired:
        raise HardwareError("compiling the Secure Enclave helper timed out") from None
    except OSError as exc:
        raise HardwareError(f"could not compile the Secure Enclave helper: {exc.strerror or exc}") from None
    finally:
        if scratch.exists():
            try:
                scratch.unlink()
            except OSError:
                pass
    try:
        paths.write_atomic(_record_path(target), digest.encode("ascii"))
    except OSError as exc:
        raise HardwareError(
            f"compiled the Secure Enclave helper, but could not record it beside it in {target.parent}: "
            f"{exc.strerror or exc}"
        ) from None


def _parse_failure(stderr: bytes) -> Tuple[str, str]:
    try:
        payload = json.loads(stderr.decode("utf-8", "replace").strip().splitlines()[-1])
        return str(payload.get("error", "")), str(payload.get("message", ""))
    except (ValueError, IndexError, AttributeError):
        return "", stderr.decode("utf-8", "replace").strip()[:200]


def _raise_for(status: int, stderr: bytes, *, touch: bool = True, fresh: bool = False) -> None:
    """Turn a failed helper run into the error a person can act on.

    *touch*: the key is one a finger releases. *fresh*: the key was made a moment ago, by enroll.
    """
    code, message = _parse_failure(stderr)
    if status == _EXIT_INTERACTION:
        raise AuthError(
            "Touch ID is required for this vault, and it can only be asked for in an "
            "interactive session on this Mac."
        )
    if status == _EXIT_DENIED:
        raise AuthError(f"Touch ID did not authorise this: {message or code or 'refused'}")
    said = f" (the Secure Enclave said: {message})" if message else ""
    if status == _EXIT_KEY_UNUSABLE and fresh:
        raise HardwareError(f"this Mac's Secure Enclave refused the key it had just made{said}")
    if status == _EXIT_KEY_UNUSABLE and not touch:
        # Said of any device key: a vault's, or the one its sessions and grants are bound to.
        raise HardwareError(
            "this Mac's Secure Enclave does not accept this device key: the key file is damaged, or another "
            "Mac's chip made it (a home folder copied or restored from elsewhere). A vault whose key it is does "
            f"not open with the master password here; the recovery key opens it: irondome recovery use{said}"
        )
    if status == _EXIT_KEY_UNUSABLE:
        raise HardwareError(
            "this Mac's Secure Enclave no longer accepts the vault's key. That happens when "
            "fingerprints are added or removed, or when the vault came from another Mac. "
            f"Unlock with your master password or recovery key, then run: irondome auth touchid{said}"
        )
    if status == _EXIT_UNAVAILABLE:
        raise HardwareError(f"Secure Enclave unavailable: {message or code}")
    raise HardwareError(f"Secure Enclave helper failed ({status}): {message or code or 'no detail'}")


def _random_point() -> bytes:
    """A random P-256 point whose discrete logarithm nobody knows.

    The x-coordinate is uniformly random among those on the curve and the
    even y is always taken, which loses nothing: the key agreement only uses
    the x-coordinate of the result. Decompressing a random x succeeds for
    about half of all values; no scalar is ever chosen, so there is no
    private key to protect or leak. P-256 has cofactor 1, so every point on
    the curve is in the right group.
    """
    while True:
        candidate = b"\x02" + os.urandom(32)
        try:
            point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), candidate)
        except ValueError:
            continue
        return point.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )


class SecureEnclaveBackend(DeviceBackend):
    name = "macos-se"
    hardware = True
    policies = (POLICY_DEVICE, POLICY_BIOMETRY, POLICY_PRESENCE)

    # -- helper plumbing ------------------------------------------------------

    def _run_json(self, arguments: List[str]) -> Dict[str, Any]:
        helper = build_helper()
        try:
            result = subprocess.run(
                [str(helper)] + arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=_HELPER_TIMEOUT,
                env=_clean_env(),
            )
        except subprocess.TimeoutExpired:
            raise HardwareError("the Secure Enclave helper did not answer in time") from None
        except OSError as exc:
            raise HardwareError(f"could not run the Secure Enclave helper: {exc.strerror or exc}") from None
        if result.returncode != 0:
            _raise_for(result.returncode, result.stderr)
        try:
            payload = json.loads(result.stdout.decode("utf-8"))
        except (ValueError, RecursionError):
            raise HardwareError("the Secure Enclave helper returned something unreadable") from None
        if not isinstance(payload, dict):
            raise HardwareError("the Secure Enclave helper returned something unexpected")
        return payload

    def _agree(
        self, key: str, peer: str, *, interactive: bool, reason: str, touch: bool = True, fresh: bool = False
    ) -> SecureBuffer:
        """Run one key agreement in the chip; read the result into locked memory.

        *touch* and *fresh* say what kind of key it is, for the error if the chip refuses it.
        """
        helper = build_helper()
        if os.environ.get("IRONDOME_NO_TOUCH") == "1":
            interactive = False  # a promise that no prompt appears, whoever is asking
        limit = _touch_timeout() if interactive else _HELPER_TIMEOUT
        request = json.dumps({"key": key, "peer": peer, "reason": reason[:_MAX_REASON]}).encode("utf-8")
        command = [str(helper), "agree"] + (["--interactive"] if interactive else [])
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                env=_clean_env(),
            )
        except OSError as exc:
            raise HardwareError(f"could not run the Secure Enclave helper: {exc.strerror or exc}") from None
        expired = threading.Event()

        def expire() -> None:
            expired.set()
            process.kill()

        watchdog = threading.Timer(limit, expire)
        watchdog.daemon = True
        watchdog.start()
        secret = SecureBuffer(DEVICE_SECRET_LEN)
        stdin, stdout, stderr = process.stdin, process.stdout, process.stderr
        try:
            if stdin is None or stdout is None or stderr is None:
                raise HardwareError("could not open a channel to the Secure Enclave helper")
            try:
                unsent = memoryview(request)
                while unsent:
                    sent = stdin.write(unsent)
                    if not sent:
                        break
                    unsent = unsent[sent:]
                stdin.close()
            except OSError:
                pass  # the helper exited early; its status says why
            view = secret.view()
            got = 0
            while got < DEVICE_SECRET_LEN:
                count = stdout.readinto(view[got:])  # type: ignore[attr-defined]
                if not count:
                    break
                got += count
            surplus = stdout.read(1)
            detail = stderr.read(8192) or b""
            status = process.wait()
            if expired.is_set():
                if interactive:
                    raise AuthError("the Touch ID prompt was not answered in time")
                raise HardwareError("the Secure Enclave helper did not answer in time")
            if status != 0:
                _raise_for(status, detail, touch=touch, fresh=fresh)
            if got != DEVICE_SECRET_LEN or surplus:
                raise HardwareError("the Secure Enclave helper returned a malformed secret")
        except BaseException:
            secret.wipe()
            raise
        finally:
            watchdog.cancel()
            if process.poll() is None:
                process.kill()
                process.wait()
            for stream in (stdin, stdout, stderr):
                try:
                    if stream:
                        stream.close()
                except OSError:
                    pass
        return secret

    # -- state files ----------------------------------------------------------

    def _state_path(self, descriptor: Dict[str, Any]) -> Path:
        check_descriptor(descriptor, self.name)
        ref = descriptor.get("ref")
        if not ref:
            raise HardwareError("Secure Enclave descriptor has no reference")
        return paths.device_dir() / f"{ref}.json"

    def _load_state(self, descriptor: Dict[str, Any]) -> Dict[str, str]:
        path = self._state_path(descriptor)
        try:
            raw = paths.read_file(path)
        except FileNotFoundError:
            raise HardwareError(
                "the Secure Enclave key for this vault is not on this Mac. "
                "Use your recovery key (irondome recovery use), or restore a portable backup."
            ) from None
        except OSError as exc:
            raise HardwareError(f"cannot read the Secure Enclave key file: {exc.strerror or exc}") from None
        except VaultError:
            raise HardwareError("the Secure Enclave key file is damaged") from None
        try:
            if len(raw) > _MAX_STATE_BYTES:
                raise ValueError("too large to be a key file")
            state = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise HardwareError("the Secure Enclave key file is damaged") from None
        if (
            not isinstance(state, dict)
            or state.get("backend") != self.name
            or state.get("policy") != descriptor.get("policy")
            or not isinstance(state.get("key"), str)
            or not isinstance(state.get("peer"), str)
        ):
            raise HardwareError("the Secure Enclave key file does not match this vault")
        try:
            key = b64d(state["key"], what="Secure Enclave key")
            peer = b64d(state["peer"], what="Secure Enclave peer point")
        except VaultError:
            raise HardwareError("the Secure Enclave key file is damaged") from None
        if not key or len(peer) != 65:
            raise HardwareError("the Secure Enclave key file is damaged")
        return state

    # -- DeviceBackend --------------------------------------------------------

    def info(self) -> Dict[str, Any]:
        return self._run_json(["info"])

    def probe(self) -> Probe:
        if sys.platform != "darwin":
            return Probe(self.name, False, True, False, "not macOS")
        try:
            info = self.info()
        except (HardwareError, AuthError) as exc:
            return Probe(self.name, False, True, False, str(exc))
        if not info.get("secure_enclave"):
            return Probe(self.name, False, True, False, "this Mac has no Secure Enclave")
        biometry = bool(info.get("biometry_usable"))
        sensors = {"touchid": "Touch ID", "faceid": "Face ID", "opticid": "Optic ID"}
        sensor = sensors.get(str(info.get("biometry")), "biometry")
        detail = "Secure Enclave" + (f", {sensor} available" if biometry else ", no usable biometry")
        return Probe(self.name, True, True, biometry, detail)

    def passive_probe(self) -> Probe:
        """:meth:`probe`, except that a helper that is not there is never compiled: it is reported.

        With the helper compiled (or named by ``IRONDOME_SE_HELPER``) this is the real probe, which
        runs the helper and shows no prompt. Without it, the reason is the one ``build_helper`` would
        give, found through :func:`helper_status` (which starts no compiler): the Xcode Command Line
        Tools are missing, ``IRONDOME_SE_HELPER`` names nothing, or the helper is merely not compiled
        yet, in which case the Secure Enclave is reported as not probed.
        """
        if sys.platform != "darwin":
            return Probe(self.name, False, True, False, "not macOS")
        status = helper_status()
        if status["built"]:
            return self.probe()
        if status["error"] is not None:
            detail = f"the Secure Enclave helper source cannot be read: {status['error']}"
        elif status["from_environment"]:
            detail = f"IRONDOME_SE_HELPER points at {status['path']}, which does not exist"
        elif status["damaged"]:
            detail = f"{devices.NOT_PROBED}: the compiled Secure Enclave helper is damaged" + (
                " (it is compiled again the next time a vault uses the chip)" if status["compiler"] else
                ", and compiling it again needs the Xcode Command Line Tools: xcode-select --install"
            )
        elif status["compiler"]:
            detail = (
                f"{devices.NOT_PROBED}: the Secure Enclave helper is not compiled yet (it is compiled the first "
                "time a vault uses the chip)"
            )
        else:
            detail = _NEEDS_TOOLS
        return Probe(self.name, False, True, False, detail)

    def enroll(
        self, *, policy: str, auth: Optional[SecureBuffer], reason: str
    ) -> Tuple[Dict[str, Any], SecureBuffer]:
        if not self.supports(policy):
            raise HardwareError(f"the Secure Enclave backend has no {policy} policy")
        info = self.info()
        if not info.get("secure_enclave"):
            raise HardwareError("this Mac has no usable Secure Enclave")
        if policy == POLICY_BIOMETRY and not info.get("biometry_usable"):
            raise HardwareError(
                "Touch ID is not usable right now (no enrolled finger, or the lid is closed): "
                + str(info.get("biometry_detail") or "")
            )
        created = self._run_json(["create", policy])
        key = created.get("key")
        if not isinstance(key, str) or not key:
            raise HardwareError("the Secure Enclave helper did not return a key")
        peer = b64e(_random_point())
        descriptor = {"backend": self.name, "policy": policy, "ref": new_ref()}
        state = {"v": 1, "backend": self.name, "policy": policy, "key": key, "peer": peer}
        path = self._state_path(descriptor)
        try:
            paths.write_atomic(path, json.dumps(state, sort_keys=True).encode("utf-8"))
        except OSError as exc:
            raise HardwareError(f"could not store the Secure Enclave key: {exc.strerror or exc}") from None
        try:
            needs_user = policy != POLICY_DEVICE
            secret = self._agree(key, peer, interactive=needs_user, reason=reason, touch=needs_user, fresh=True)
        except BaseException:
            try:
                paths.secure_delete(path)
            except OSError:
                pass
            raise
        return descriptor, secret

    def unseal(
        self,
        descriptor: Dict[str, Any],
        *,
        auth: Optional[SecureBuffer],
        interactive: bool,
        reason: str,
    ) -> SecureBuffer:
        state = self._load_state(descriptor)
        needs_user = descriptor["policy"] != POLICY_DEVICE
        return self._agree(
            state["key"], state["peer"], interactive=interactive and needs_user, reason=reason, touch=needs_user
        )

    def destroy(self, descriptor: Dict[str, Any]) -> None:
        path = self._state_path(descriptor)
        try:
            paths.secure_delete(path)
        except OSError as exc:
            raise HardwareError(f"could not destroy the Secure Enclave key: {exc}") from None
        if path.exists():
            raise HardwareError("the Secure Enclave key file is still present after deletion")

    def exists(self, descriptor: Dict[str, Any]) -> bool:
        return self._state_path(descriptor).is_file()

    def fault(self, descriptor: Dict[str, Any]) -> Optional[str]:
        if not self.exists(descriptor):
            return None
        try:
            self._load_state(descriptor)
        except HardwareError as exc:
            return str(exc)
        return None

    def destroy_all(self) -> int:
        directory = paths.device_dir()
        if not directory.is_dir():
            return 0
        destroyed = 0
        survivors = []
        for path in sorted(directory.glob("*.json")):
            if not _STATE_NAME.fullmatch(path.name) or not self._holds_key(path):
                continue
            try:
                paths.secure_delete(path)
            except OSError:
                pass  # counted below; one stubborn file must not shield the others
            if os.path.lexists(path):
                survivors.append(path.name)
            else:
                destroyed += 1
        if survivors:
            what = "the Secure Enclave key file" if len(survivors) == 1 else "the Secure Enclave key files"
            raise HardwareError(f"could not destroy {what}: {', '.join(survivors)}")
        return destroyed

    def _holds_key(self, path: Path) -> bool:
        """True for a state file of this backend, and for one that cannot be read.

        Only called for files named as this backend names its own. A damaged
        one may still hold an intact key blob, and nothing can be using it, so
        ``destroy_all`` takes it. A readable one that names another backend is
        left to that backend.
        """
        try:
            state = json.loads(paths.read_file(path).decode("utf-8"))
        except (OSError, VaultError, ValueError, UnicodeDecodeError, RecursionError):
            return True
        return isinstance(state, dict) and state.get("backend") == self.name
