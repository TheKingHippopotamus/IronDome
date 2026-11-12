"""Device secrets held by a TPM 2.0 chip, on Linux.

How it works
------------
``enroll`` generates 32 random bytes and stores them in a new NV index of the
TPM, at a random handle in the owner range (0x01800000-0x01BFFFFF). The device
secret is therefore on no disk: it is inside the chip, and the chip releases
it only to a caller that presents the index's authorisation value. There are
two kinds of index, chosen by *auth*:

*A password keyslot* (*auth* is a value derived from the master password,
which the kernel passes in). The index is created with the attributes
``authread|authwrite`` and that value as its authorisation. It is
deliberately created *without* ``no_da``, so every wrong value counts against
the TPM's dictionary-attack counter; once the counter reaches
``TPM2_PT_MAX_AUTH_FAIL`` the chip refuses every attempt, right or wrong,
until its recovery timer has forgiven one failure.

*A device key with no password* (``auth=None``: the ``device`` policy, which
sessions and grants are bound with). The index is created with the attributes
``authread|authwrite|no_da`` and an EMPTY authorisation value. That is what
the device policy means here: the TPM gives the secret to any process of any
account that can use the TPM, with no password and no prompt. What it does
not give it to is a copy of the disk, another machine, or anyone at all after
the index is undefined. ``no_da`` is set because an empty value cannot be
guessed wrong, so the dictionary-attack counter has nothing to protect, and
because without it the TPM refuses even an empty authorisation while it is in
lockout: every session and grant would stop working whenever someone had
spent the TPM's guesses. The owner hierarchy still cannot read it
(``ownerread`` is never set). Such an index is read with an empty
authorisation only after the TPM confirms its shape and only if this
installation recorded it; an empty value presented to a password keyslot's
index would cost one of the TPM's guesses.

``unseal`` asks the TPM to read the index. The TPM compares the authorisation
value itself.

``destroy`` undefines the index. The TPM discards the data, and nothing kept
outside the chip can produce the device secret again.

The work is done by tpm2-tools: ``tpm2_nvdefine``, ``tpm2_nvwrite``,
``tpm2_nvread``, ``tpm2_nvundefine``, ``tpm2_nvreadpublic`` and
``tpm2_getcap``. They are looked up in a fixed list of system directories,
never through ``$PATH``. The command forms used here exist since tpm2-tools
4.1; the tests run against 4.3, 5.2, 5.4, 5.6 and 5.7. An empty authorisation
is given by passing no ``-p`` or ``-P`` option at all.

How the two secrets reach the tools
-----------------------------------
Never through argv, never through the environment, never through a file on
disk.

* The authorisation value, when there is one, is hex-encoded inside a
  SecureBuffer and written to an anonymous in-memory file
  (``memfd_create``). The tool is told to read ``file:/dev/fd/N``.
  tpm2-tools require a seekable file there and reject a pipe. The memory
  file is overwritten with zeros and closed as soon as the tool has exited.
* The device secret goes to ``tpm2_nvwrite -i -`` through a pipe on stdin and
  comes back from ``tpm2_nvread`` through a pipe on stdout, which is read
  straight into a SecureBuffer.
* The tools run with a fixed, minimal environment. ``TSS2_LOG`` in particular
  is not inherited: at its trace level the TSS libraries print command
  buffers, which contain both values.
* The transport is pinned. ``TPM2TOOLS_TCTI`` is passed through when it is
  set; otherwise the tools are told to use ``/dev/tpmrm0`` and nothing else.
  Left to their defaults they fall back to a simulator on TCP port 2321 of
  localhost, which any local program could be listening on.

What this backend deletes
-------------------------
Every NV index it creates is recorded in a registry file in the device
directory before the index exists, so ``destroy_all`` can erase them when the
vault file is unreadable. ``destroy`` acts on an index named by a descriptor,
and descriptors come from a file that may have been altered; it therefore
deletes an index only if this installation created it or if the index has
exactly the shape of a password keyslot (``authread|authwrite``, 32 bytes).
It will not remove another program's NV index. A device key with no password
that is no longer in the registry is left alone too: an index with its
attributes is just as likely to be another program's.

Limits, stated plainly
----------------------
* A device key with no password protects against copies, other machines and
  ``nuke``, not against this machine: any process of any account that can
  use the TPM (on most distributions the members of the ``tss`` group, and
  root) can read it with ``tpm2_nvread`` and no password.
* While a tool runs, it holds the authorisation value and the device secret
  in ordinary process memory, and the in-memory file is not locked against
  swapping. This lasts for one tool invocation; nothing here can wipe the
  tool's own memory.
* The authorisation is a plain TPM password session. On a discrete TPM both
  values cross the bus between CPU and chip unencrypted, so someone with a
  logic analyser on that bus, at a moment when the vault is being unlocked,
  can record them.
* The guess limit is the TPM's global dictionary-attack counter. Any program
  that can use the TPM can drive it into lockout and so delay an unlock. More
  importantly, whoever knows the TPM's *lockout authorisation* can reset the
  counter, and on most Linux installations that authorisation is empty. Until
  one is set (``tpm2_changeauth -c lockout``), the limit holds back only
  attackers who cannot talk to the TPM; ``lockout_status()`` reports which
  case applies. What holds regardless is that every guess needs this TPM:
  guessing cannot be moved to other hardware or run in parallel.
* The TPM owner authorisation must be empty. This backend does not handle an
  owner password; ``probe`` reports the backend unavailable when one is set.
* Clearing the TPM -- from the firmware setup, with ``tpm2_clear``, or as a
  side effect of some firmware updates and operating-system installers --
  erases every NV index and with it the device secret. The vault then opens
  only with the recovery key or from a portable backup.
* A firmware TPM or a virtual TPM is exactly as trustworthy as the firmware or
  hypervisor that implements it. A simulator reached through
  ``TPM2TOOLS_TCTI`` is software, and ``probe`` says so.
"""

from __future__ import annotations

import errno
import hmac
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path
from typing import (
    Any,
    Callable,
    ContextManager,
    Dict,
    FrozenSet,
    List,
    NamedTuple,
    NoReturn,
    Optional,
    Sequence,
    Tuple,
)

from irondome import paths
from irondome.device.base import (
    DEVICE_SECRET_LEN,
    POLICY_DEVICE,
    DeviceBackend,
    Probe,
    check_descriptor,
    new_ref,
)
from irondome.errors import AuthError, HardwareError, IronDomeError, LockedOutError, VaultError
from irondome.secmem import SecureBuffer

__all__ = ["Tpm2Backend", "lockout_status"]

_NAME = "linux-tpm2"

#: Every tool this backend runs. ``probe`` requires all of them.
_TOOLS = (
    "tpm2_getcap",
    "tpm2_nvdefine",
    "tpm2_nvwrite",
    "tpm2_nvread",
    "tpm2_nvundefine",
    "tpm2_nvreadpublic",
)

#: Tools are looked up here and nowhere else.
_SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/run/current-system/sw/bin"
_INSTALL_HINT = (
    "Install tpm2-tools (Debian/Ubuntu: sudo apt install tpm2-tools; Fedora: sudo dnf install tpm2-tools; "
    "Arch: sudo pacman -S tpm2-tools)"
)

#: The kernel's TPM resource manager. Used unless TPM2TOOLS_TCTI names another transport.
_DEVICE_NODE = "/dev/tpmrm0"
_DEFAULT_TCTI = "device:" + _DEVICE_NODE
#: Where a child process finds the descriptors it inherited.
_FD_DIRECTORY = "/dev/fd"
_SIMULATORS = ("swtpm", "mssim", "libtpms")

_TIMEOUT = 30.0
_MAX_STDOUT = 1 << 20
_MAX_STDERR = 1 << 16

_AUTH_LEN = 32
_AUTH_PREFIX = b"hex:"
_HEX_DIGITS = b"0123456789abcdef"
_MFD_CLOEXEC = 0x0001
_MFD_NOEXEC_SEAL = 0x0008

_NV_FIRST = 0x01800000
_NV_MASK = 0x003FFFFF
_NV_INDEX = re.compile(r"0x01[89ab][0-9a-f]{5}")
#: A password keyslot's index: its authorisation value comes from the master password, every wrong one counts.
_NV_ATTRIBUTES = "authread|authwrite"
#: A device key with no password: an empty authorisation value, readable even while the TPM is in lockout.
_NV_OPEN_ATTRIBUTES = "authread|authwrite|no_da"
_ALLOCATION_ATTEMPTS = 8

_REGISTRY_NAME = "tpm2-nv-indices.json"
_REGISTRY_LOCK = "tpm2-nv-indices.lock"
_REGISTRY_MAX_BYTES = 1 << 20
_REGISTRY_MAX_ENTRIES = 4096

# TPM 2.0 response codes (TPM 2.0 Library, Part 2, section 6.6), with the bits
# that say which handle, session or parameter was at fault removed.
_RC_INITIALIZE = 0x100
_RC_NV_UNINITIALIZED = 0x14A
_RC_NV_SPACE = 0x14B
_RC_NV_DEFINED = 0x14C
_RC_HANDLE = 0x08B
_RC_AUTH_FAIL = 0x08E
_RC_BAD_AUTH = 0x0A2
_RC_NV_RATE = 0x920
_RC_LOCKOUT = 0x921
_RC_BUSY = frozenset({0x908, 0x909, 0x90A, 0x922, 0x923})  # yielded, cancelled, testing, retry, NV unavailable

#: TSS2 layers whose codes are TPM response codes: the TPM itself, and a resource manager relaying them.
_TPM_LAYERS = (0, 12)
#: tpm2-tools exit with this status when the TPM rejected an authorisation.
_EXIT_AUTH = 3

_CODE = re.compile(rb"\(0x([0-9A-Fa-f]{1,8})\)")
_CODE_TEXT = re.compile(r"\(0x[0-9A-Fa-f]{1,8}\)")
_LONG_HEX = re.compile(r"[0-9A-Fa-f]{32,}")
_PROPERTY = re.compile(r"(\s*)([A-Za-z0-9_]+):\s*(?:(0[xX][0-9A-Fa-f]{1,16})|([0-9]{1,20}))?\s*")

_RECOVERY_ADVICE = "Use your recovery key, or restore a portable backup."
_NO_MEMFD = "this system cannot create in-memory files (memfd_create), which the TPM backend needs"
_OWNER_AUTH_SET = (
    "the TPM has an owner password, and IronDome creates and deletes NV indices with an empty owner "
    "authorisation. Clear it with: tpm2_changeauth -c owner -p <owner password>"
)


# ---------------------------------------------------------------------------
# Running tpm2-tools
# ---------------------------------------------------------------------------


class _Result(NamedTuple):
    tool: str
    status: int
    stdout: bytes
    stderr: bytes
    filled: bool


def _on_linux() -> bool:
    return sys.platform.startswith("linux")


def _tool_path(tool: str) -> str:
    """The absolute path of a tpm2-tools program, refusing one that others could have replaced."""
    found = shutil.which(tool, path=_SAFE_PATH)
    if not found:
        raise HardwareError(f"{tool} was not found in {_SAFE_PATH}. {_INSTALL_HINT}")
    try:
        info = os.stat(found)  # follows symlinks: most distributions link every tool to one binary
    except OSError as exc:
        raise HardwareError(f"cannot inspect {found}: {exc.strerror}") from None
    if not stat.S_ISREG(info.st_mode):
        raise HardwareError(f"{found} is not a regular file; refusing to run it")
    if info.st_mode & 0o022:
        raise HardwareError(f"{found} is writable by other users; refusing to run it")
    if info.st_uid not in (0, os.getuid()):
        raise HardwareError(f"{found} is owned by another user; refusing to run it")
    return found


def _tcti() -> str:
    return os.environ.get("TPM2TOOLS_TCTI") or _DEFAULT_TCTI


def _is_simulator(tcti: str) -> bool:
    module = tcti.partition(":")[0].lower()
    return any(name in module for name in _SIMULATORS)


def _environment() -> Dict[str, str]:
    """What a tool is allowed to see: a fixed PATH and locale, and the TPM transport."""
    return {"PATH": _SAFE_PATH, "LC_ALL": "C", "TPM2TOOLS_TCTI": _tcti()}


def _auth_text(auth: SecureBuffer) -> SecureBuffer:
    """``hex:<digits>``, the form tpm2-tools parse from a password file, built in locked memory."""
    source = auth.view()
    text = SecureBuffer(len(_AUTH_PREFIX) + 2 * len(source))
    try:
        target = text.view()
        offset = len(_AUTH_PREFIX)
        target[:offset] = _AUTH_PREFIX
        for position in range(len(source)):
            byte = source[position]
            target[offset + 2 * position] = _HEX_DIGITS[byte >> 4]
            target[offset + 2 * position + 1] = _HEX_DIGITS[byte & 0x0F]
    except BaseException:
        text.wipe()
        raise
    return text


def _above_stdio(fd: int) -> int:
    """Move a descriptor out of 0-2, which a child process has reassigned by the time it starts."""
    if fd > 2:
        return fd
    import fcntl

    try:
        return fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
    finally:
        os.close(fd)


def _memfd_create() -> Optional[Callable[[str, int], int]]:
    """``memfd_create(2)``: from the os module, or from libc where Python was built without it.

    Interpreters built against an old C library for portability (the ones uv
    and some installers download, for instance) lack ``os.memfd_create`` even
    though the system they run on provides the call.
    """
    native: Optional[Callable[[str, int], int]] = getattr(os, "memfd_create", None)
    if native is not None:
        return native
    try:
        import ctypes

        function = ctypes.CDLL(None, use_errno=True).memfd_create
    except (ImportError, OSError, AttributeError, TypeError):
        return None
    function.argtypes = [ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int

    def create(name: str, flags: int) -> int:
        fd: int = function(name.encode("ascii"), flags)
        if fd < 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        return fd

    return create


def _memory_file(content: memoryview) -> int:
    """An anonymous in-memory file holding *content*. Never touches a filesystem."""
    create = _memfd_create()
    if create is None:
        raise HardwareError(_NO_MEMFD)
    try:
        try:
            fd = create("irondome-tpm2", _MFD_CLOEXEC | _MFD_NOEXEC_SEAL)
        except OSError as exc:
            if exc.errno != errno.EINVAL:
                raise
            fd = create("irondome-tpm2", _MFD_CLOEXEC)  # kernels older than 6.3 do not know the seal flag
        fd = _above_stdio(fd)
    except OSError as exc:
        raise HardwareError(f"cannot create an in-memory file for the TPM tools: {exc.strerror}") from None
    try:
        written = 0
        while written < len(content):
            written += os.write(fd, content[written:])
    except BaseException:
        _discard_memory_file(fd, len(content))
        raise
    return fd


def _discard_memory_file(fd: int, length: int) -> None:
    """Overwrite an in-memory file with zeros, then close it."""
    try:
        if length:
            os.pwrite(fd, bytes(length), 0)
    except OSError:
        pass  # the pages are freed by the close below either way
    finally:
        os.close(fd)


def _filled_pipe(content: memoryview) -> int:
    """The read end of a pipe that already holds *content*, with the write end closed."""
    if len(content) > 512:  # POSIX guarantees that writes this small are atomic and never block on an empty pipe
        raise HardwareError("refusing to queue that much data for a TPM tool")
    read_end, write_end = os.pipe()
    try:
        if os.write(write_end, content) != len(content):
            raise HardwareError("could not hand the device secret to the TPM tool")
    except BaseException:
        os.close(read_end)
        raise
    finally:
        os.close(write_end)
    return read_end


def _read_limited(stream: Any, limit: int, tool: str) -> bytes:
    collected = bytearray()
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return bytes(collected)
        collected += chunk
        if len(collected) > limit:
            raise HardwareError(f"{tool} produced more output than a TPM tool should")


def _read_secret(stream: Any, target: SecureBuffer) -> int:
    """Fill *target* from a pipe with no copy in between.

    Returns the number of bytes received, or ``len(target) + 1`` if the tool
    had more to say than the buffer holds.
    """
    raw = io.FileIO(stream.fileno(), "rb", closefd=False)
    view = target.view()
    received = 0
    while received < len(view):
        count = raw.readinto(view[received:])
        if not count:
            return received
        received += count
    return received + 1 if raw.read(1) else received


def _run(
    tool: str,
    arguments: Sequence[str],
    *,
    auth: Optional[SecureBuffer] = None,
    auth_option: str = "-P",
    data: Optional[SecureBuffer] = None,
    secret_out: Optional[SecureBuffer] = None,
) -> _Result:
    """Run one tpm2-tools command and return its exit status and output.

    *auth* is appended as ``<auth_option> file:/dev/fd/N`` (an in-memory file),
    *data* as ``-i -`` (a pipe on stdin), and the tool's stdout is read into
    *secret_out* when that is given. Raises HardwareError if the tool cannot
    be run, does not finish in time or floods its output; a non-zero exit
    status is returned for the caller to interpret.
    """
    if not _on_linux():
        raise HardwareError(
            f"this device key is held by the TPM of a Linux machine, and this is not that machine. {_RECOVERY_ADVICE}"
        )
    command = [_tool_path(tool)] + list(arguments)
    environment = _environment()
    expired = threading.Event()
    watchdog: Optional[threading.Timer] = None
    process: Optional["subprocess.Popen[bytes]"] = None
    auth_fd = -1
    auth_size = 0
    data_fd = -1
    stdout = b""
    filled = False
    try:
        if auth is not None:
            with _auth_text(auth) as text:
                auth_size = len(text)
                auth_fd = _memory_file(text.view())
            command += [auth_option, f"file:{_FD_DIRECTORY}/{auth_fd}"]
        if data is not None:
            data_fd = _filled_pipe(data.view())
            command += ["-i", "-"]
        try:
            process = subprocess.Popen(
                command,
                stdin=data_fd if data_fd >= 0 else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                env=environment,
                pass_fds=(auth_fd,) if auth_fd >= 0 else (),
            )
        except OSError as exc:
            raise HardwareError(f"could not run {tool}: {exc.strerror or exc}") from None
        running = process

        def expire() -> None:
            expired.set()
            try:
                running.kill()
            except OSError:
                pass  # it exited by itself in the meantime

        watchdog = threading.Timer(_TIMEOUT, expire)
        watchdog.daemon = True
        watchdog.start()
        if process.stdout is None or process.stderr is None:
            raise HardwareError(f"could not capture the output of {tool}")
        if secret_out is not None:
            received = _read_secret(process.stdout, secret_out)
            if received > len(secret_out):
                raise HardwareError(f"{tool} returned more data than a device secret holds")
            filled = received == len(secret_out)
        else:
            stdout = _read_limited(process.stdout, _MAX_STDOUT, tool)
        stderr = _read_limited(process.stderr, _MAX_STDERR, tool)
        status = process.wait()
    finally:
        if watchdog is not None:
            watchdog.cancel()
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        if data_fd >= 0:
            os.close(data_fd)
        if auth_fd >= 0:
            _discard_memory_file(auth_fd, auth_size)
    if expired.is_set() and status != 0:
        raise HardwareError(f"{tool} did not finish within {_TIMEOUT:g} seconds; the TPM is not responding")
    return _Result(tool, status, stdout, stderr, filled)


# ---------------------------------------------------------------------------
# Interpreting what the tools say
# ---------------------------------------------------------------------------


def _response_codes(stderr: bytes) -> List[int]:
    """The TPM response codes a failed tool printed, reduced to their error numbers.

    tpm2-tools and the TSS libraries print the code in hexadecimal inside
    parentheses, e.g. ``Esys_NV_Read(0x98E)`` and ``ErrorCode (0x0000098e)``.
    Format-one codes carry the number of the offending handle, session or
    parameter in bits 6 and 8-11; those bits are dropped so that 0x98E, 0xA8E
    and 0x08E all come back as 0x08E. Codes raised by the TSS software layers
    themselves (ESAPI, TCTI, ...) are not TPM responses and are left out.
    """
    found: List[int] = []
    for match in _CODE.finditer(stderr):
        value = int(match.group(1), 16)
        if value >> 16 not in _TPM_LAYERS:
            continue
        code = value & 0xFFFF
        number = code & 0x0BF if code & 0x080 else code & 0xFFF
        if number and number not in found:
            found.append(number)
    return found


def _summary(stderr: bytes) -> str:
    """One printable line saying why a tool failed. Never repeats anything shaped like key material."""
    tool_lines: List[str] = []
    library_lines: List[str] = []
    for raw in stderr.decode("ascii", "replace").splitlines():
        line = raw.strip()
        if line.startswith("ERROR: "):
            if not line.startswith("ERROR: Unable to run"):
                tool_lines.append(line[len("ERROR: ") :])
        elif line.startswith("ERROR:"):
            library_lines.append(line.rpartition("() ")[2])
    with_code = [line for line in tool_lines if _CODE_TEXT.search(line)]
    parts = (with_code or tool_lines)[:1]
    if not with_code:
        parts += library_lines[:1]
    text = _LONG_HEX.sub("[redacted]", ": ".join(parts))
    return "".join(char if " " <= char <= "~" else "?" for char in text)[:300]


def _duration(seconds: int) -> str:
    hours, rest = divmod(max(seconds, 0), 3600)
    minutes, secs = divmod(rest, 60)
    parts = [f"{value} {unit}" for value, unit in ((hours, "h"), (minutes, "min"), (secs, "s")) if value]
    return " ".join(parts) or "0 s"


def _locked_out() -> LockedOutError:
    try:
        status = lockout_status()
    except IronDomeError:
        return LockedOutError(
            "the TPM is refusing password attempts after too many wrong guesses. Wait and try again; "
            "tpm2_getcap properties-variable shows its lockout counters."
        )
    counted = f"{status['failed_tries']} failed attempts, limit {status['max_tries']}"
    wait = status["seconds_until_retry"]
    if wait is None:
        return LockedOutError(
            f"the TPM is refusing password attempts ({counted}), and with its current dictionary-attack settings "
            "waiting will not help. The machine's administrator can change them with tpm2_dictionarylockout "
            "--setup-parameters, or reset the counter with: tpm2_dictionarylockout --clear-lockout"
        )
    return LockedOutError(
        f"the TPM is refusing password attempts after too many wrong guesses ({counted}). It accepts the next "
        f"attempt in at most {_duration(wait)}: it forgives one failure every "
        f"{_duration(status['recovery_seconds'])} while the computer is on. The machine's administrator can reset "
        "it at once with: tpm2_dictionarylockout --clear-lockout"
    )


def _raise_for(
    result: _Result, *, index: Optional[str] = None, secret_auth: bool = False, no_auth: bool = False
) -> NoReturn:
    """Turn a failed tool run into the exception the caller should see.

    *secret_auth* says the command was authorised with the password-derived
    value, so a rejected authorisation means a wrong master password.
    *no_auth* says it was authorised with the index's own, empty,
    authorisation value, so a rejected one means the index is not a device
    key with no password. With neither, the only authorisation in play is the
    (empty) owner authorisation.
    """
    codes = _response_codes(result.stderr)
    if _RC_LOCKOUT in codes:
        raise _locked_out()
    if _RC_AUTH_FAIL in codes or _RC_BAD_AUTH in codes or (not codes and result.status == _EXIT_AUTH):
        if secret_auth:
            raise AuthError("wrong master password")
        if no_auth:
            raise HardwareError(
                f"TPM NV index {index} does not open with an empty authorisation, so it is not a device key "
                "that needs no password"
            )
        raise HardwareError(_OWNER_AUTH_SET)
    if _RC_HANDLE in codes and index is not None:
        raise HardwareError(
            f"this TPM does not hold the device key for this vault (NV index {index} is not defined): the vault "
            f"was created on another machine, or the TPM was cleared. {_RECOVERY_ADVICE}"
        )
    if _RC_NV_UNINITIALIZED in codes and index is not None:
        raise HardwareError(
            f"TPM NV index {index} exists but was never written, so it holds no device key. {_RECOVERY_ADVICE}"
        )
    if _RC_NV_SPACE in codes:
        raise HardwareError(
            "the TPM has no free NV storage. Remove NV indices you no longer need "
            "(tpm2_getcap handles-nv-index lists them) and try again"
        )
    if _RC_INITIALIZE in codes:
        raise HardwareError(
            "the TPM has not been started (TPM2_Startup has not run). Reboot, or check the "
            "TPM settings in the firmware setup"
        )
    if _RC_NV_RATE in codes:
        raise HardwareError("the TPM is rate-limiting writes to protect its storage. Wait a minute and try again")
    busy = [code for code in codes if code in _RC_BUSY]
    if busy:
        raise HardwareError(f"the TPM was busy (response code 0x{busy[0]:03x}). Try again")
    raise HardwareError(f"{result.tool} failed: {_summary(result.stderr) or f'exit status {result.status}'}")


def _parse_properties(output: bytes) -> Dict[str, int]:
    """Flatten ``tpm2_getcap`` output into ``{"NAME": n, "GROUP.member": n}``, numeric values only."""
    values: Dict[str, int] = {}
    group = ""
    for line in output.decode("ascii", "replace").splitlines():
        match = _PROPERTY.fullmatch(line)
        if match is None:
            continue
        indent, key, hexadecimal, decimal = match.groups()
        if not indent:
            group = key
        if hexadecimal is not None:
            values[f"{group}.{key}" if indent else key] = int(hexadecimal, 16)
        elif decimal is not None:
            values[f"{group}.{key}" if indent else key] = int(decimal)
    return values


def _properties(capability: str) -> Dict[str, int]:
    result = _run("tpm2_getcap", [capability])
    if result.status != 0:
        _raise_for(result)
    return _parse_properties(result.stdout)


def _permanent(properties: Dict[str, int], attribute: str) -> Optional[int]:
    """One attribute of TPM2_PT_PERMANENT, which tpm2-tools 4.x print under the name TPM2_PT_PERSISTENT."""
    for group in ("TPM2_PT_PERMANENT", "TPM2_PT_PERSISTENT"):
        value = properties.get(f"{group}.{attribute}")
        if value is not None:
            return value
    return None


class _Public(NamedTuple):
    attributes: FrozenSet[str]
    size: int


def _parse_public(output: bytes, index: str) -> Optional[_Public]:
    """Pick one index out of ``tpm2_nvreadpublic`` output; None if it is not listed."""
    wanted = int(index, 16)
    inside = False
    seen = False
    section = ""
    attributes: FrozenSet[str] = frozenset()
    size = -1
    for line in output.decode("ascii", "replace").splitlines():
        key, separator, value = line.strip().partition(":")
        value = value.strip()
        if not separator:
            continue
        if not line[:1].isspace():
            try:
                inside = int(key, 16) == wanted
            except ValueError:
                inside = False
            seen = seen or inside
            section = ""
        elif not inside:
            continue
        elif not value:
            section = key
        elif key == "friendly" and section == "attributes":
            attributes = frozenset(part for part in value.split("|") if part)
        elif key == "size" and value.isascii() and value.isdigit() and len(value) <= 9:
            size = int(value)
    return _Public(attributes, size) if seen else None


def _has_shape(public: Optional[_Public], attributes: str) -> bool:
    """True for an index with exactly *attributes* (written or not yet) and the size of a device secret."""
    return (
        public is not None
        and public.attributes - {"written"} == frozenset(attributes.split("|"))
        and public.size == DEVICE_SECRET_LEN
    )


def _is_irondome_shaped(public: Optional[_Public]) -> bool:
    """True for an index with exactly the attributes and size of a password keyslot's index."""
    return _has_shape(public, _NV_ATTRIBUTES)


def _attributes_for(auth: Optional[SecureBuffer]) -> str:
    """The attributes of a new index: a password keyslot's, or (no *auth*) a device key's that needs no password."""
    return _NV_ATTRIBUTES if auth is not None else _NV_OPEN_ATTRIBUTES


# ---------------------------------------------------------------------------
# NV index operations
# ---------------------------------------------------------------------------


def _public(index: str) -> Optional[_Public]:
    """The public area of an NV index, or None if the TPM has no such index."""
    result = _run("tpm2_nvreadpublic", [index])
    if result.status != 0:
        if _RC_HANDLE in _response_codes(result.stderr):
            return None
        _raise_for(result)
    return _parse_public(result.stdout, index)


def _undefine(index: str) -> None:
    """Delete an NV index and confirm with the TPM that it is gone. A missing index is not an error."""
    result = _run("tpm2_nvundefine", [index, "-C", "o"])
    if result.status != 0 and _RC_HANDLE not in _response_codes(result.stderr):
        _raise_for(result)
    if _public(index) is not None:
        raise HardwareError(f"TPM NV index {index} is still present after deletion")


def _read_into(index: str, auth: Optional[SecureBuffer], secret: SecureBuffer) -> None:
    """Read *index* into *secret*, with *auth* or, when it is ``None``, with an empty authorisation."""
    result = _run("tpm2_nvread", [index, "-C", index, "-s", str(len(secret))], auth=auth, secret_out=secret)
    if result.status != 0:
        _raise_for(result, index=index, secret_auth=auth is not None, no_auth=auth is None)
    if not result.filled:
        raise HardwareError("tpm2_nvread returned a malformed device secret")


def _store(index: str, auth: Optional[SecureBuffer], secret: SecureBuffer) -> None:
    """Write *secret* to a freshly defined index and read it back to prove that it can be unsealed."""
    attributes = _attributes_for(auth)
    public = _public(index)
    if public is None or public.attributes != frozenset(attributes.split("|")) or public.size != DEVICE_SECRET_LEN:
        raise HardwareError(
            f"the TPM did not create the NV index as requested ({attributes}, {DEVICE_SECRET_LEN} bytes); "
            "nothing was stored in it"
        )
    result = _run("tpm2_nvwrite", [index, "-C", index], auth=auth, data=secret)
    if result.status != 0:
        _raise_for(result, index=index, secret_auth=auth is not None, no_auth=auth is None)
    with SecureBuffer(DEVICE_SECRET_LEN) as check:
        _read_into(index, auth, check)
        if not hmac.compare_digest(check.view(), secret.view()):
            raise HardwareError("the TPM returned different bytes from the ones that were stored")


def _check_open_index(index: str) -> None:
    """Refuse to read *index* with an empty authorisation unless it is a device key with no password made here.

    Checked before anything is read: presented to a password keyslot's
    index, an empty authorisation would be a wrong guess, and the TPM would
    count it. The registry says this installation made the index; the TPM
    itself says what the index is. HardwareError when the index is not this
    installation's or not on this TPM; VaultError when the descriptor names
    an index of another kind, which only an altered descriptor does.
    """
    try:
        recorded = index in _load_registry()
    except VaultError as exc:
        raise HardwareError(str(exc)) from None
    if not recorded:
        raise HardwareError(
            f"TPM NV index {index} was not created by this IronDome installation (it is not in {_registry_path()}), "
            "so it is not read without a password"
        )
    public = _public(index)
    if public is None:
        raise HardwareError(
            f"this TPM does not hold that device key (NV index {index} is not defined): it was made on another "
            "machine, or it was destroyed, or the TPM was cleared"
        )
    if not _has_shape(public, _NV_OPEN_ATTRIBUTES):
        raise VaultError(
            f"TPM device descriptor names NV index {index}, which is not a device key that needs no password "
            f"({_NV_OPEN_ATTRIBUTES}, {DEVICE_SECRET_LEN} bytes); it is not read without one"
        )


def _random_index() -> str:
    return f"0x{_NV_FIRST | (int.from_bytes(os.urandom(3), 'big') & _NV_MASK):08x}"


def _define_index(auth: Optional[SecureBuffer]) -> str:
    """Create an empty index at a free random handle and record it. The caller holds the registry lock.

    The index's authorisation value is *auth*, or empty when *auth* is ``None``.
    """
    attributes = _attributes_for(auth)
    for _ in range(_ALLOCATION_ATTEMPTS):
        index = _random_index()
        recorded = _load_registry()
        if index in recorded or _public(index) is not None:
            continue
        _save_registry(recorded + [index])  # recorded first: a crash from here on cannot orphan the index
        try:
            result = _run(
                "tpm2_nvdefine",
                [index, "-C", "o", "-s", str(DEVICE_SECRET_LEN), "-a", attributes],
                auth=auth,
                auth_option="-p",
            )
        except BaseException:
            _discard_index(index, created=False, attributes=attributes)
            raise
        if result.status == 0:
            return index
        if _RC_NV_DEFINED not in _response_codes(result.stderr):
            _discard_index(index, created=False, attributes=attributes)
            _raise_for(result)
        # Someone else defined this handle between the check and the define. It is theirs: forget it, leave it.
        _save_registry(recorded)
    raise HardwareError("could not find a free TPM NV index; try again")


def _discard_index(index: str, *, created: bool, attributes: str) -> None:
    """Remove what a failed enrolment left behind. Never raises.

    *created* says the TPM confirmed that this process defined the index. When
    the define call ended without an answer, the index is deleted only if it
    has the shape that enrolment asked for, *attributes*. The registry entry
    goes once the index is known to be gone or known not to be ours; if the
    TPM cannot be asked it stays, so that ``destroy_all`` can finish the job.
    """
    try:
        if created or _has_shape(_public(index), attributes):
            _undefine(index)
        _forget(index)
    except IronDomeError:
        return


# ---------------------------------------------------------------------------
# The registry of indices this installation created
# ---------------------------------------------------------------------------


def _registry_path() -> Path:
    return paths.device_dir() / _REGISTRY_NAME


def _registry_lock() -> ContextManager[None]:
    return paths.file_lock(paths.device_dir() / _REGISTRY_LOCK)


def _load_registry() -> List[str]:
    """The recorded NV indices. A missing file is an empty registry; a damaged one is an error."""
    path = _registry_path()
    damaged = VaultError(
        f"the TPM index registry {path} is damaged. List the TPM's NV indices with "
        "`tpm2_getcap handles-nv-index` and remove IronDome's with `tpm2_nvundefine <index> -C o`"
    )
    try:
        if path.stat().st_size > _REGISTRY_MAX_BYTES:
            raise damaged
        raw = paths.read_file(path)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise VaultError(f"cannot read the TPM index registry {path}: {exc.strerror}") from None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise damaged from None
    if not isinstance(document, dict) or document.get("backend") != _NAME or type(document.get("v")) is not int:
        raise damaged
    indices = document.get("indices")
    if document["v"] != 1 or not isinstance(indices, list) or len(indices) > _REGISTRY_MAX_ENTRIES:
        raise damaged
    recorded: List[str] = []
    for item in indices:
        if not isinstance(item, str) or _NV_INDEX.fullmatch(item) is None:
            raise damaged
        if item not in recorded:
            recorded.append(item)
    return recorded


def _save_registry(indices: Sequence[str]) -> None:
    document = {"v": 1, "backend": _NAME, "indices": sorted(set(indices))}
    try:
        paths.write_atomic(_registry_path(), (json.dumps(document, indent=1, sort_keys=True) + "\n").encode("ascii"))
    except OSError as exc:
        raise HardwareError(f"cannot update the TPM index registry {_registry_path()}: {exc.strerror}") from None


def _forget(index: str) -> None:
    recorded = _load_registry()
    if index in recorded:
        recorded.remove(index)
        _save_registry(recorded)


# ---------------------------------------------------------------------------
# Descriptors and arguments
# ---------------------------------------------------------------------------


def _index_of(descriptor: Any) -> str:
    """Validate a descriptor read from a vault file and return its NV index."""
    check_descriptor(descriptor, _NAME)
    if descriptor.get("policy") != POLICY_DEVICE:
        raise VaultError("TPM device descriptor names a policy this backend cannot enforce")
    if descriptor.get("ref") is None:
        raise VaultError("TPM device descriptor has no reference")
    index = descriptor.get("nv_index")
    if not isinstance(index, str) or _NV_INDEX.fullmatch(index) is None:
        raise VaultError("TPM device descriptor has a malformed NV index")
    return index


def _checked_auth(auth: Optional[SecureBuffer]) -> Optional[SecureBuffer]:
    """*auth* when it is a usable authorisation value. ``None``, an empty authorisation, is passed on as it is."""
    if auth is None:
        return None
    if not isinstance(auth, SecureBuffer) or len(auth) != _AUTH_LEN:
        raise HardwareError(f"the TPM backend needs a {_AUTH_LEN}-byte authorisation value in a SecureBuffer")
    if not any(auth.view()):
        raise HardwareError("refusing an all-zero TPM authorisation value: the TPM would treat it as no password")
    return auth


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------


def _permission_remedy(mode: int, group: Optional[str]) -> str:
    if group and group != "root" and mode & 0o060 == 0o060:
        return (
            f"no permission to use {_DEVICE_NODE}. Add your user to the {group} group: "
            f"sudo usermod -aG {group} $USER, then log out and back in"
        )
    return (
        f"no permission to use {_DEVICE_NODE}, which only root may open here. Install your distribution's TPM "
        "udev rules (Debian/Ubuntu: tpm-udev; Fedora/Arch: tpm2-tss) so that the tss group can use it, then: "
        "sudo usermod -aG tss $USER, and log out and back in"
    )


def _device_problem(node: str) -> Optional[str]:
    """Why the kernel's TPM device cannot be used by this user, or None if it can."""
    try:
        info = os.stat(node)
    except FileNotFoundError:
        return (
            f"this machine has no TPM 2.0 device ({node} is missing). Enable the TPM in the firmware setup "
            "if it has one"
        )
    except OSError as exc:
        return f"cannot inspect {node}: {exc.strerror}"
    if not stat.S_ISCHR(info.st_mode):
        return f"{node} is not a device"
    if os.access(node, os.R_OK | os.W_OK):
        return None
    group: Optional[str] = None
    try:
        import grp

        group = grp.getgrgid(info.st_gid).gr_name
    except (ImportError, KeyError):
        group = None
    return _permission_remedy(info.st_mode, group)


def _maker(fixed: Dict[str, int]) -> str:
    """The manufacturer and vendor strings a TPM reports about itself, e.g. ``IFX SLB9670``."""

    def text(name: str) -> str:
        raw = fixed.get(f"{name}.raw", 0) & 0xFFFFFFFF
        return "".join(chr(byte) for byte in raw.to_bytes(4, "big") if 0x20 <= byte < 0x7F)

    manufacturer = text("TPM2_PT_MANUFACTURER").strip()
    vendor = " ".join("".join(text(f"TPM2_PT_VENDOR_STRING_{number}") for number in (1, 2, 3, 4)).split())
    return " ".join(part for part in (manufacturer, vendor) if part) or "unknown manufacturer"


def lockout_status() -> Dict[str, Any]:
    """The TPM's dictionary-attack counters, for telling the user where they stand.

    ==========================  ================================================
    ``max_tries``               wrong guesses that put the TPM into lockout
    ``failed_tries``            wrong guesses the TPM currently remembers
    ``remaining_tries``         wrong guesses left before lockout
    ``recovery_seconds``        the TPM forgives one failure per this many
                                seconds of uptime; 0 means it never counts
                                failures, so it does not limit guessing at all
    ``lockout_recovery_seconds``  how long the lockout authorisation itself is
                                blocked after it was given wrongly
    ``in_lockout``              True while the TPM refuses every attempt
    ``seconds_until_retry``     0 when not locked out; otherwise an upper bound
                                on the wait for one more attempt, or None when
                                waiting cannot help
    ``lockout_auth_set``        False when the lockout authorisation is empty,
                                which lets anyone who can use the TPM reset
                                the counter
    ==========================  ================================================

    The counter is shared by everything on this TPM that is protected against
    guessing, not only IronDome's keys. Raises HardwareError if the TPM cannot
    be queried.
    """
    properties = _properties("properties-variable")
    try:
        maximum = properties["TPM2_PT_MAX_AUTH_FAIL"]
        failed = properties["TPM2_PT_LOCKOUT_COUNTER"]
        interval = properties["TPM2_PT_LOCKOUT_INTERVAL"]
        recovery = properties["TPM2_PT_LOCKOUT_RECOVERY"]
    except KeyError as exc:
        raise HardwareError(f"tpm2_getcap did not report {exc.args[0]}; is tpm2-tools older than 4.1?") from None
    in_lockout = bool(_permanent(properties, "inLockout")) or failed >= maximum
    wait: Optional[int] = 0
    if in_lockout:
        # With no recovery timer, or a limit of zero, the TPM never comes out of lockout by itself.
        wait = max(failed - maximum + 1, 1) * interval if interval and maximum else None
    return {
        "max_tries": maximum,
        "failed_tries": failed,
        "remaining_tries": max(maximum - failed, 0),
        "recovery_seconds": interval,
        "lockout_recovery_seconds": recovery,
        "in_lockout": in_lockout,
        "seconds_until_retry": wait,
        "lockout_auth_set": bool(_permanent(properties, "lockoutAuthSet")),
    }


# ---------------------------------------------------------------------------
# The backend
# ---------------------------------------------------------------------------


class Tpm2Backend(DeviceBackend):
    name = _NAME
    hardware = True
    policies = (POLICY_DEVICE,)

    def lockout_status(self) -> Dict[str, Any]:
        """See :func:`lockout_status`."""
        return lockout_status()

    def probe(self) -> Probe:
        """Report whether a TPM 2.0 can be used here. Reads TPM properties; changes nothing."""

        def unavailable(detail: str) -> Probe:
            return Probe(self.name, False, True, False, detail)

        if not _on_linux():
            return unavailable("not Linux")
        if _memfd_create() is None:
            return unavailable(_NO_MEMFD)
        if not os.path.isdir(_FD_DIRECTORY):
            return unavailable(
                f"{_FD_DIRECTORY} is missing (is /proc mounted?); the TPM tools are handed the authorisation "
                "value through it"
            )
        missing = [tool for tool in _TOOLS if shutil.which(tool, path=_SAFE_PATH) is None]
        if missing:
            return unavailable(f"tpm2-tools is not installed ({', '.join(missing)} not found). {_INSTALL_HINT}")
        if not os.environ.get("TPM2TOOLS_TCTI"):
            problem = _device_problem(_DEVICE_NODE)
            if problem is not None:
                return unavailable(problem)
        try:
            variable = _properties("properties-variable")
            owner_auth_set = _permanent(variable, "ownerAuthSet")
            if owner_auth_set is None:
                return unavailable(
                    "tpm2_getcap did not report whether the TPM has an owner password; is tpm2-tools older than 4.1?"
                )
            if owner_auth_set:
                return unavailable(_OWNER_AUTH_SET)
            maker = _maker(_properties("properties-fixed"))
        except IronDomeError as exc:
            return unavailable(f"cannot use the TPM through {_printable(_tcti())}: {exc}")
        limit = variable.get("TPM2_PT_MAX_AUTH_FAIL", 0)
        if not variable.get("TPM2_PT_LOCKOUT_INTERVAL", 0):
            guessing = "its dictionary-attack protection is switched off, so it does not limit password guesses"
        elif not limit:
            return unavailable(
                "the TPM's dictionary-attack limit is zero, so it refuses every password. Raise it with: "
                "tpm2_dictionarylockout --setup-parameters --max-tries=<number>"
            )
        else:
            guessing = f"locks after {limit} wrong passwords"
        if _is_simulator(_tcti()):
            return Probe(
                self.name,
                True,
                False,
                False,
                f"TPM 2.0 simulator ({maker}) reached through {_printable(_tcti())}: software, not a security "
                f"chip; {guessing}",
            )
        return Probe(self.name, True, True, False, f"TPM 2.0 ({maker}); {guessing}")

    def enroll(self, *, policy: str, auth: Optional[SecureBuffer], reason: str) -> Tuple[Dict[str, Any], SecureBuffer]:
        """Store a new random device secret in a new NV index.

        With *auth* the index belongs to a password keyslot: *auth* is its
        authorisation value and the TPM counts every wrong one. With
        ``auth=None`` it is a device key that needs no password: an empty
        authorisation value and ``no_da``, which any process allowed to use
        the TPM can read (see the module docstring). Both kinds get the same
        descriptor. The index is read back before this returns, so a
        descriptor is only ever handed out for a secret that can be unsealed.
        On any failure the index is removed again; if the TPM cannot be
        reached for that, the index stays recorded so that ``destroy_all``
        removes it later.
        """
        if policy != POLICY_DEVICE:
            raise HardwareError(f"the TPM backend cannot enforce the {policy} policy")
        checked = _checked_auth(auth)
        secret = SecureBuffer.random(DEVICE_SECRET_LEN)
        try:
            with _registry_lock():
                index = _define_index(checked)
                try:
                    _store(index, checked, secret)
                except BaseException:
                    _discard_index(index, created=True, attributes=_attributes_for(checked))
                    raise
        except BaseException:
            secret.wipe()
            raise
        return {"backend": self.name, "policy": policy, "ref": new_ref(), "nv_index": index}, secret

    def unseal(
        self,
        descriptor: Dict[str, Any],
        *,
        auth: Optional[SecureBuffer],
        interactive: bool,
        reason: str,
    ) -> SecureBuffer:
        """Read the device secret back from the TPM.

        With *auth*, a password keyslot's value, exactly as before: AuthError
        when the TPM rejects it (which costs one of the TPM's guesses),
        LockedOutError when it is refusing all attempts. With ``auth=None``
        the index is read with an empty authorisation, and only once this
        installation's registry and the TPM have confirmed that it is a
        device key that needs no password; otherwise nothing is read and no
        guess is spent: VaultError when the descriptor names an index of
        another kind, HardwareError when it names one this installation did
        not make. HardwareError, too, when the index is not on this TPM.
        """
        index = _index_of(descriptor)
        checked = _checked_auth(auth)
        if checked is None:
            _check_open_index(index)
        secret = SecureBuffer(DEVICE_SECRET_LEN)
        try:
            _read_into(index, checked, secret)
        except BaseException:
            secret.wipe()
            raise
        return secret

    def destroy(self, descriptor: Dict[str, Any]) -> None:
        """Undefine the descriptor's NV index and confirm with the TPM that it is gone.

        An index that is already missing is fine. An index that this
        installation did not record and that does not have the shape of a
        password keyslot's index is left alone, and HardwareError is raised.
        """
        index = _index_of(descriptor)
        with _registry_lock():
            try:
                recorded = index in _load_registry()
            except VaultError:
                recorded = False  # a damaged registry must not stop an erasure; the shape check below applies
            public = _public(index)
            if public is not None:
                if not recorded and not _is_irondome_shaped(public):
                    raise HardwareError(
                        f"TPM NV index {index} was not created by this IronDome installation and does not look "
                        "like one of its device keys; refusing to delete it. If it is yours, remove it with: "
                        f"tpm2_nvundefine {index} -C o"
                    )
                _undefine(index)
            if recorded:
                _forget(index)

    def exists(self, descriptor: Dict[str, Any]) -> bool:
        """True while the TPM still has the descriptor's NV index. Raises if the TPM cannot be asked."""
        return _public(_index_of(descriptor)) is not None

    def destroy_all(self) -> int:
        """Undefine every NV index recorded in this installation's registry.

        Tries all of them even if one fails, then raises HardwareError naming
        the survivors. Returns how many indices were present and are now gone.
        """
        if not _registry_path().exists():
            return 0
        destroyed = 0
        survivors: List[str] = []
        with _registry_lock():
            for index in _load_registry():
                try:
                    present = _public(index) is not None
                    _undefine(index)
                    _forget(index)
                except HardwareError as exc:
                    survivors.append(f"{index}: {exc}")
                    continue
                destroyed += int(present)
        if survivors:
            shown = "; ".join(survivors[:3]) + (f"; and {len(survivors) - 3} more" if len(survivors) > 3 else "")
            counted = "1 TPM device key" if len(survivors) == 1 else f"{len(survivors)} TPM device keys"
            raise HardwareError(f"{counted} could not be erased ({shown})")
        return destroyed


def _printable(text: str) -> str:
    return "".join(char if " " <= char <= "~" else "?" for char in text)[:120]
