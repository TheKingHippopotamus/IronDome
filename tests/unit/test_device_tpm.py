"""The TPM 2.0 backend.

Four groups of tests.

*Pure.* Descriptor and NV-index validation, the parsers, the mapping from a
failed tool run to an exception, and the registry file. The tool output they
are checked against was captured from tpm2-tools 5.6 talking to swtpm 0.7.3
and is reproduced below byte for byte. These run on every POSIX machine.

*A TPM in a dictionary.* ``FakeTpm`` takes the place of ``linux_tpm._run``. It
keeps NV indices in memory under the TPM's rules and answers failures with
that same captured output, so every branch of enrolment, destruction and
clean-up can be driven anywhere, including failures that a real TPM cannot be
made to produce on demand. It also checks that each tool is called with the
arguments that were verified by hand.

*Stand-in tools.* Shell scripts replace the tpm2-tools binaries to pin down
how the tools are run: what is in argv, in the environment and behind
``/dev/fd/N``, and what happens when a tool hangs or floods its output. These
need Linux, because the authorisation value travels in a memfd.

*A real TPM 2.0.* The ``tpm`` fixture (``IRONDOME_TEST_TPM=1``) switches to
the real backend; ``scripts/test-linux.sh`` provides a software TPM for it.
These tests fail authorisations on purpose, so they refuse to run against
anything but a simulator: they cannot lock out the chip of the machine they
run on.
"""

from __future__ import annotations

import ast
import base64
import binascii
import contextlib
import errno
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

import pytest
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from irondome import device, keys, paths
from irondome.device import linux_tpm
from irondome.device.base import DEVICE_SECRET_LEN, POLICY_BIOMETRY, POLICY_DEVICE, POLICY_PRESENCE, DeviceBackend
from irondome.device.linux_tpm import Tpm2Backend
from irondome.errors import AuthError, HardwareError, IronDomeError, LockedOutError, VaultError
from irondome.secmem import SecureBuffer

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the TPM backend is Linux-only and these tests need POSIX")

ON_LINUX = sys.platform.startswith("linux")
needs_linux = pytest.mark.skipif(not ON_LINUX, reason="the tools get the authorisation value through a Linux memfd")

#: Property tests keep no example database: a test run leaves nothing behind in the checkout.
PROPERTY = settings(database=None, deadline=None)

AUTH = bytes(range(1, 33))
OTHER_AUTH = bytes(range(101, 133))
SECRET = bytes(range(200, 232))
INDEX = "0x018abcde"


def buffer(data: bytes) -> SecureBuffer:
    return SecureBuffer.from_buffer(data)


def contents(secret: SecureBuffer) -> bytes:
    return bytes(secret.view())


def descriptor(index: Any = INDEX, **changes: Any) -> Dict[str, Any]:
    made: Dict[str, Any] = {"backend": "linux-tpm2", "policy": "device", "ref": "ab" * 16, "nv_index": index}
    made.update(changes)
    return made


# ---------------------------------------------------------------------------
# Captured from tpm2-tools 5.6 (libtss2 4.0.1) against swtpm 0.7.3 / libtpms 0.9.3
# on Ubuntu 24.04: (tool, exit status, stderr), byte for byte.
# ---------------------------------------------------------------------------

FAILURES: Dict[str, Tuple[str, int, bytes]] = {
    "nvread_wrong_auth": (
        "tpm2_nvread",
        3,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_Read.c:315:Esys_NV_Read_Finish() Received TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_NV_Read.c:105:Esys_NV_Read() Esys Finish ErrorCode "
        b"(0x0000098e) \n"
        b"ERROR: Esys_NV_Read(0x98E) - tpm:session(1):the authorization HMAC check failed and DA counter "
        b"incremented\n"
        b"ERROR: Failed to read NVRAM area at index 0x1800123\n"
        b"ERROR: Unable to run tpm2_nvread\n",
    ),
    "nvwrite_wrong_auth": (
        "tpm2_nvwrite",
        3,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_Write.c:310:Esys_NV_Write_Finish() Received TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_NV_Write.c:110:Esys_NV_Write() Esys Finish ErrorCode "
        b"(0x0000098e) \n"
        b"ERROR: Failed to write NV area at index 0x1800123\n"
        b"ERROR: Tss2_Sys_NV_Write(0x98E) - tpm:session(1):the authorization HMAC check failed and DA "
        b"counter incremented\n"
        b"ERROR: Unable to run tpm2_nvwrite\n",
    ),
    "nvread_wrong_auth_no_da": (
        "tpm2_nvread",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_Read.c:315:Esys_NV_Read_Finish() Received TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_NV_Read.c:105:Esys_NV_Read() Esys Finish ErrorCode "
        b"(0x000009a2) \n"
        b"ERROR: Esys_NV_Read(0x9A2) - tpm:session(1):authorization failure without DA implications\n"
        b"ERROR: Failed to read NVRAM area at index 0x1800124\n"
        b"ERROR: Unable to run tpm2_nvread\n",
    ),
    "nvread_lockout": (
        "tpm2_nvread",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_Read.c:315:Esys_NV_Read_Finish() Received TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_NV_Read.c:105:Esys_NV_Read() Esys Finish ErrorCode "
        b"(0x00000921) \n"
        b"ERROR: Esys_NV_Read(0x921) - tpm:warn(2.0): authorizations for objects subject to DA protection "
        b"are not allowed at this time because the TPM is in DA lockout mode\n"
        b"ERROR: Failed to read NVRAM area at index 0x1800123\n"
        b"ERROR: Unable to run tpm2_nvread\n",
    ),
    "nvwrite_lockout": (
        "tpm2_nvwrite",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_Write.c:310:Esys_NV_Write_Finish() Received TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_NV_Write.c:110:Esys_NV_Write() Esys Finish ErrorCode "
        b"(0x00000921) \n"
        b"ERROR: Failed to write NV area at index 0x1800123\n"
        b"ERROR: Tss2_Sys_NV_Write(0x921) - tpm:warn(2.0): authorizations for objects subject to DA "
        b"protection are not allowed at this time because the TPM is in DA lockout mode\n"
        b"ERROR: Unable to run tpm2_nvwrite\n",
    ),
    "nvread_missing": (
        "tpm2_nvread",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_ReadPublic.c:309:Esys_NV_ReadPublic_Finish() Received "
        b"TPM Error \n"
        b"ERROR:esys:src/tss2-esys/esys_tr.c:243:Esys_TR_FromTPMPublic_Finish() Error NV_ReadPublic "
        b"ErrorCode (0x0000018b) \n"
        b"ERROR:esys:src/tss2-esys/esys_tr.c:398:Esys_TR_FromTPMPublic() Error TR FromTPMPublic ErrorCode "
        b"(0x0000018b) \n"
        b"ERROR: Esys_TR_FromTPMPublic(0x18B) - tpm:handle(1):the handle is not correct for the use\n"
        b"ERROR: Invalid handle authorization.\n"
        b"ERROR: Unable to run tpm2_nvread\n",
    ),
    "nvwrite_missing": (
        "tpm2_nvwrite",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_ReadPublic.c:309:Esys_NV_ReadPublic_Finish() Received "
        b"TPM Error \n"
        b"ERROR:esys:src/tss2-esys/esys_tr.c:243:Esys_TR_FromTPMPublic_Finish() Error NV_ReadPublic "
        b"ErrorCode (0x0000018b) \n"
        b"ERROR:esys:src/tss2-esys/esys_tr.c:398:Esys_TR_FromTPMPublic() Error TR FromTPMPublic ErrorCode "
        b"(0x0000018b) \n"
        b"ERROR: Esys_TR_FromTPMPublic(0x18B) - tpm:handle(1):the handle is not correct for the use\n"
        b"ERROR: Invalid handle or authorization.\n"
        b"ERROR: Unable to run tpm2_nvwrite\n",
    ),
    "nvread_uninitialized": (
        "tpm2_nvread",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_Read.c:315:Esys_NV_Read_Finish() Received TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_NV_Read.c:105:Esys_NV_Read() Esys Finish ErrorCode "
        b"(0x0000014a) \n"
        b"ERROR: Esys_NV_Read(0x14A) - tpm:error(2.0): an NV Index is used before being initialized or "
        b"the state saved by TPM2_ShutdownSTATE could not be restored\n"
        b"ERROR: Failed to read NVRAM area at index 0x1800123\n"
        b"ERROR: Unable to run tpm2_nvread\n",
    ),
    "nvdefine_already_defined": (
        "tpm2_nvdefine",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_DefineSpace.c:345:Esys_NV_DefineSpace_Finish() Received "
        b"TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_NV_DefineSpace.c:121:Esys_NV_DefineSpace() Esys Finish "
        b"ErrorCode (0x0000014c) \n"
        b"ERROR: Failed to define NV area at index 0x1800123\n"
        b"ERROR: Esys_NV_DefineSpace(0x14C) - tpm:error(2.0): NV Index or persistent object already "
        b"defined\n"
        b"ERROR: Failed to create NV index 0x1800123.\n"
        b"ERROR: Unable to run tpm2_nvdefine\n",
    ),
    "nvdefine_nv_space": (
        "tpm2_nvdefine",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_DefineSpace.c:345:Esys_NV_DefineSpace_Finish() Received "
        b"TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_NV_DefineSpace.c:121:Esys_NV_DefineSpace() Esys Finish "
        b"ErrorCode (0x0000014b) \n"
        b"ERROR: Failed to define NV area at index 0x1900044\n"
        b"ERROR: Esys_NV_DefineSpace(0x14B) - tpm:error(2.0): insufficient space for NV allocation\n"
        b"ERROR: Failed to create NV index 0x1900044.\n"
        b"ERROR: Unable to run tpm2_nvdefine\n",
    ),
    "nvdefine_owner_auth_set": (
        "tpm2_nvdefine",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_DefineSpace.c:345:Esys_NV_DefineSpace_Finish() Received "
        b"TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_NV_DefineSpace.c:121:Esys_NV_DefineSpace() Esys Finish "
        b"ErrorCode (0x000009a2) \n"
        b"ERROR: Failed to define NV area at index 0x1800124\n"
        b"ERROR: Esys_NV_DefineSpace(0x9A2) - tpm:session(1):authorization failure without DA "
        b"implications\n"
        b"ERROR: Failed to create NV index 0x1800124.\n"
        b"ERROR: Unable to run tpm2_nvdefine\n",
    ),
    "nvundefine_owner_auth_set": (
        "tpm2_nvundefine",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_UndefineSpace.c:305:Esys_NV_UndefineSpace_Finish() "
        b"Received TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_NV_UndefineSpace.c:108:Esys_NV_UndefineSpace() Esys Finish "
        b"ErrorCode (0x000009a2) \n"
        b"ERROR: Failed to release NV area at index 0x1800123\n"
        b"ERROR: Esys_NV_UndefineSpace(0x9A2) - tpm:session(1):authorization failure without DA "
        b"implications\n"
        b"ERROR: Unable to run tpm2_nvundefine\n",
    ),
    "nvundefine_missing": (
        "tpm2_nvundefine",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_ReadPublic.c:309:Esys_NV_ReadPublic_Finish() Received "
        b"TPM Error \n"
        b"ERROR:esys:src/tss2-esys/esys_tr.c:243:Esys_TR_FromTPMPublic_Finish() Error NV_ReadPublic "
        b"ErrorCode (0x0000018b) \n"
        b"ERROR:esys:src/tss2-esys/esys_tr.c:398:Esys_TR_FromTPMPublic() Error TR FromTPMPublic ErrorCode "
        b"(0x0000018b) \n"
        b"ERROR: Esys_TR_FromTPMPublic(0x18B) - tpm:handle(1):the handle is not correct for the use\n"
        b"ERROR: Failed to read the public part of NV index 0x1800123\n"
        b"ERROR: Unable to run tpm2_nvundefine\n",
    ),
    "nvreadpublic_missing": (
        "tpm2_nvreadpublic",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_NV_ReadPublic.c:309:Esys_NV_ReadPublic_Finish() Received "
        b"TPM Error \n"
        b"ERROR:esys:src/tss2-esys/esys_tr.c:243:Esys_TR_FromTPMPublic_Finish() Error NV_ReadPublic "
        b"ErrorCode (0x0000018b) \n"
        b"ERROR:esys:src/tss2-esys/esys_tr.c:398:Esys_TR_FromTPMPublic() Error TR FromTPMPublic ErrorCode "
        b"(0x0000018b) \n"
        b"ERROR: Esys_TR_FromTPMPublic(0x18B) - tpm:handle(1):the handle is not correct for the use\n"
        b"ERROR: Failed to read the public part of NV index 0x1800123\n"
        b"ERROR: Unable to run tpm2_nvreadpublic\n",
    ),
    "tcti_device_missing": (
        "tpm2_getcap",
        1,
        b"ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified "
        b"TCTI device file /dev/tpmrm0: No such file or directory \n"
        b"ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: "
        b"device \n"
        b"ERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI \n"
        b'ERROR: Could not load tcti, got: "device:/dev/tpmrm0"\n',
    ),
    "tcti_socket_dead": (
        "tpm2_getcap",
        1,
        b"WARNING:tcti:src/util/io.c:304:socket_connect_unix() Failed to connect to /tmp/nope.sock \n"
        b"ERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM "
        b"socket \n"
        b"ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: "
        b"swtpm \n"
        b"ERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI \n"
        b'ERROR: Could not load tcti, got: "swtpm:path=/tmp/nope.sock"\n',
    ),
    "tcti_default_fallbacks": (
        "tpm2_getcap",
        1,
        b"ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified "
        b"TCTI device file /dev/tpmrm0: No such file or directory \n"
        b"ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: "
        b"libtss2-tcti-device.so.0 \n"
        b"ERROR:tcti:src/tss2-tcti/tcti-device.c:451:Tss2_Tcti_Device_Init() Failed to open specified "
        b"TCTI device file /dev/tpm0: No such file or directory \n"
        b"ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: "
        b"libtss2-tcti-device.so.0 \n"
        b"WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: "
        b"errno 111: Connection refused \n"
        b"ERROR:tcti:src/tss2-tcti/tcti-swtpm.c:613:Tss2_Tcti_Swtpm_Init() Cannot connect to swtpm TPM "
        b"socket \n"
        b"ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: "
        b"libtss2-tcti-swtpm.so.0 \n"
        b"WARNING:tcti:src/util/io.c:262:socket_connect() Failed to connect to host 127.0.0.1, port 2321: "
        b"errno 111: Connection refused \n"
        b"ERROR:tcti:src/tss2-tcti/tctildr-dl.c:169:tcti_from_file() Could not initialize TCTI file: "
        b"libtss2-tcti-mssim.so.0 \n"
        b"ERROR:tcti:src/tss2-tcti/tctildr-dl.c:269:tctildr_get_default() No standard TCTI could be "
        b"loaded \n"
        b"ERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI \n"
        b'ERROR: Could not load tcti, got: "(null)"\n',
    ),
    "tcti_unknown": (
        "tpm2_getcap",
        1,
        b"ERROR:tcti:src/tss2-tcti/tctildr.c:430:Tss2_TctiLdr_Initialize_Ex() Failed to instantiate TCTI \n"
        b'ERROR: Could not load tcti, got: "bogus:foo"\n',
    ),
    "tpm_not_started": (
        "tpm2_getcap",
        1,
        b"WARNING:esys:src/tss2-esys/api/Esys_GetCapability.c:301:Esys_GetCapability_Finish() Received "
        b"TPM Error \n"
        b"ERROR:esys:src/tss2-esys/api/Esys_GetCapability.c:106:Esys_GetCapability() Esys Finish "
        b"ErrorCode (0x00000100) \n"
        b"ERROR: Esys_GetCapability(0x100) - tpm:error(2.0): TPM not initialized by TPM2_Startup or "
        b"already initialized\n"
        b"ERROR: Unable to run tpm2_getcap\n",
    ),
    "auth_file_missing": (
        "tpm2_nvread",
        1,
        b'ERROR: Could not open file "/tmp/does-not-exist" error No such file or directory\n'
        b"ERROR: get password\n"
        b"ERROR: Invalid handle authorization.\n"
        b"ERROR: Unable to run tpm2_nvread\n",
    ),
    "auth_file_not_hex": (
        "tpm2_nvread",
        1,
        b"ERROR: get password\nERROR: Invalid handle authorization.\nERROR: Unable to run tpm2_nvread\n",
    ),
    "nvwrite_too_long": (
        "tpm2_nvwrite",
        2,
        b"ERROR: The starting offset (0) and the size (33) are larger than the defined space: 32.\n",
    ),
}

GETCAP_VARIABLE = (
    b"TPM2_PT_PERMANENT:\n"
    b"  ownerAuthSet:              0\n"
    b"  endorsementAuthSet:        0\n"
    b"  lockoutAuthSet:            0\n"
    b"  reserved1:                 0\n"
    b"  disableClear:              0\n"
    b"  inLockout:                 0\n"
    b"  tpmGeneratedEPS:           1\n"
    b"  reserved2:                 0\n"
    b"TPM2_PT_STARTUP_CLEAR:\n"
    b"  phEnable:                  1\n"
    b"  shEnable:                  1\n"
    b"  ehEnable:                  1\n"
    b"  phEnableNV:                1\n"
    b"  reserved1:                 0\n"
    b"  orderly:                   1\n"
    b"TPM2_PT_HR_NV_INDEX: 0x0\n"
    b"TPM2_PT_HR_LOADED: 0x0\n"
    b"TPM2_PT_HR_LOADED_AVAIL: 0x3\n"
    b"TPM2_PT_HR_ACTIVE: 0x0\n"
    b"TPM2_PT_HR_ACTIVE_AVAIL: 0x40\n"
    b"TPM2_PT_HR_TRANSIENT_AVAIL: 0x3\n"
    b"TPM2_PT_HR_PERSISTENT: 0x0\n"
    b"TPM2_PT_HR_PERSISTENT_AVAIL: 0x41\n"
    b"TPM2_PT_NV_COUNTERS: 0x0\n"
    b"TPM2_PT_NV_COUNTERS_AVAIL: 0x19\n"
    b"TPM2_PT_ALGORITHM_SET: 0x0\n"
    b"TPM2_PT_LOADED_CURVES: 0x8\n"
    b"TPM2_PT_LOCKOUT_COUNTER: 0x0\n"
    b"TPM2_PT_MAX_AUTH_FAIL: 0x3\n"
    b"TPM2_PT_LOCKOUT_INTERVAL: 0x3E8\n"
    b"TPM2_PT_LOCKOUT_RECOVERY: 0x3E8\n"
    b"TPM2_PT_NV_WRITE_RECOVERY: 0x0\n"
    b"TPM2_PT_AUDIT_COUNTER_0: 0x0\n"
    b"TPM2_PT_AUDIT_COUNTER_1: 0x0\n"
)

GETCAP_FIXED_HEAD = (
    b"TPM2_PT_FAMILY_INDICATOR:\n"
    b"  raw: 0x322E3000\n"
    b'  value: "2.0"\n'
    b"TPM2_PT_LEVEL:\n"
    b"  raw: 0\n"
    b"TPM2_PT_REVISION:\n"
    b"  raw: 0xA4\n"
    b"  value: 1.64\n"
    b"TPM2_PT_DAY_OF_YEAR:\n"
    b"  raw: 0x4B\n"
    b"TPM2_PT_YEAR:\n"
    b"  raw: 0x7E5\n"
    b"TPM2_PT_MANUFACTURER:\n"
    b"  raw: 0x49424D00\n"
    b'  value: "IBM"\n'
    b"TPM2_PT_VENDOR_STRING_1:\n"
    b"  raw: 0x53572020\n"
    b'  value: "SW"\n'
    b"TPM2_PT_VENDOR_STRING_2:\n"
    b"  raw: 0x2054504D\n"
    b'  value: "TPM"\n'
    b"TPM2_PT_VENDOR_STRING_3:\n"
    b"  raw: 0x0\n"
    b'  value: ""\n'
    b"TPM2_PT_VENDOR_STRING_4:\n"
    b"  raw: 0x0\n"
    b'  value: ""\n'
)

NVREADPUBLIC_UNWRITTEN = (
    b"0x1800123:\n"
    b"  name: 000b61cfc1a361b54ef4116cfbda5446f2a90ac9355477b4c6292a7aa4ca2f17d3bc\n"
    b"  hash algorithm:\n"
    b"    friendly: sha256\n"
    b"    value: 0xB\n"
    b"  attributes:\n"
    b"    friendly: authwrite|authread\n"
    b"    value: 0x40004\n"
    b"  size: 32\n"
    b"\n"
)

NVREADPUBLIC_WRITTEN = (
    b"0x1800123:\n"
    b"  name: 000b0453742be4367fa25573f5bfd93f8c712bc73bdc1d38c996f345e3370108e86a\n"
    b"  hash algorithm:\n"
    b"    friendly: sha256\n"
    b"    value: 0xB\n"
    b"  attributes:\n"
    b"    friendly: authwrite|authread|written\n"
    b"    value: 0x20040004\n"
    b"  size: 32\n"
    b"\n"
)

NVREADPUBLIC_NO_DA = (
    b"0x1800124:\n"
    b"  name: 000b4a4368a4d32f50704a49239221286752cff64809c0e22a84ed8d978d3382d312\n"
    b"  hash algorithm:\n"
    b"    friendly: sha256\n"
    b"    value: 0xB\n"
    b"  attributes:\n"
    b"    friendly: authwrite|authread|no_da|written\n"
    b"    value: 0x22040004\n"
    b"  size: 32\n"
    b"\n"
)


def failed(name: str) -> linux_tpm._Result:
    tool, status, stderr = FAILURES[name]
    return linux_tpm._Result(tool, status, b"", stderr, False)


def succeeded(tool: str, stdout: bytes = b"", filled: bool = False) -> linux_tpm._Result:
    return linux_tpm._Result(tool, 0, stdout, b"", filled)


def getcap_variable(
    *,
    owner_auth: int = 0,
    lockout_auth: int = 0,
    in_lockout: int = 0,
    counter: int = 0,
    limit: int = 3,
    interval: int = 1000,
    recovery: int = 1000,
    group: str = "TPM2_PT_PERMANENT",
) -> bytes:
    """``tpm2_getcap properties-variable`` for a TPM in the given state.

    The output of a fresh TPM above is verbatim. In the outputs captured in
    other states (one failure, lockout, owner password set) exactly these
    lines differed from it, which is what is rewritten here. tpm2-tools 4.3.0
    prints the same text except that the first group is headed
    ``TPM2_PT_PERSISTENT``.
    """
    text = GETCAP_VARIABLE.decode("ascii")
    assert text.startswith("TPM2_PT_PERMANENT:\n")
    text = group + text[len("TPM2_PT_PERMANENT") :]
    for key, value in (
        ("ownerAuthSet", str(owner_auth)),
        ("lockoutAuthSet", str(lockout_auth)),
        ("inLockout", str(in_lockout)),
        ("TPM2_PT_LOCKOUT_COUNTER", f"0x{counter:X}"),
        ("TPM2_PT_MAX_AUTH_FAIL", f"0x{limit:X}"),
        ("TPM2_PT_LOCKOUT_INTERVAL", f"0x{interval:X}"),
        ("TPM2_PT_LOCKOUT_RECOVERY", f"0x{recovery:X}"),
    ):
        text, replaced = re.subn(rf"(?m)^(\s*{key}:\s*)\S+$", lambda match, new=value: match.group(1) + new, text)
        assert replaced == 1, key
    return text.encode("ascii")


def public_area(index: str, attributes: Sequence[str], size: int) -> bytes:
    """``tpm2_nvreadpublic`` output in the layout of the captured samples."""
    return (
        f"{int(index, 16):#x}:\n"
        f"  name: 000b{'5a' * 32}\n"
        "  hash algorithm:\n"
        "    friendly: sha256\n"
        "    value: 0xB\n"
        "  attributes:\n"
        f"    friendly: {'|'.join(attributes)}\n"
        "    value: 0x20040004\n"
        f"  size: {size}\n"
        "\n"
    ).encode("ascii")


def explode(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError(f"no TPM tool may be run here, but one was: {args!r}")


Hook = Callable[[List[str]], Optional[linux_tpm._Result]]


class FakeTpm:
    """An NV store that follows the TPM's rules, standing in for ``linux_tpm._run``.

    It answers failures with the stderr captured from the real tools, and it
    asserts that every tool is called with exactly the arguments that were
    verified by hand against swtpm.
    """

    def __init__(self) -> None:
        self.indices: Dict[int, Dict[str, Any]] = {}
        self.failed_tries = 0
        self.max_tries = 3
        self.interval = 1000
        self.owner_auth_set = False
        self.unreachable = False
        self.permanent_group = "TPM2_PT_PERMANENT"
        self.calls: List[List[str]] = []
        self.hooks: Dict[str, List[Hook]] = {}

    @property
    def locked(self) -> bool:
        return self.failed_tries >= self.max_tries

    def once(self, tool: str, hook: Hook) -> None:
        """Let *hook* answer the next call of *tool*; returning None falls through to the normal behaviour."""
        self.hooks.setdefault(tool, []).append(hook)

    def handles(self) -> Set[str]:
        return {f"0x{handle:08x}" for handle in self.indices}

    def define(
        self,
        index: str,
        *,
        attributes: str = "authwrite|authread",
        size: int = 32,
        auth: bytes = AUTH,
        data: Optional[bytes] = SECRET,
    ) -> None:
        """Put an index into the TPM directly, as another program or an earlier run would have."""
        names = attributes.split("|") + (["written"] if data is not None else [])
        self.indices[int(index, 16)] = {"auth": auth, "attributes": names, "size": size, "data": data}

    def run(
        self,
        tool: str,
        arguments: Sequence[str],
        *,
        auth: Optional[SecureBuffer] = None,
        auth_option: str = "-P",
        data: Optional[SecureBuffer] = None,
        secret_out: Optional[SecureBuffer] = None,
    ) -> linux_tpm._Result:
        listed = list(arguments)
        self.calls.append([tool] + listed)
        if self.unreachable:
            return failed("tcti_socket_dead")._replace(tool=tool)
        pending = self.hooks.get(tool)
        if pending:
            answer = pending.pop(0)(listed)
            if answer is not None:
                return answer
        handler = getattr(self, tool)
        result: linux_tpm._Result = handler(
            listed, auth=auth, auth_option=auth_option, data=data, secret_out=secret_out
        )
        return result

    @staticmethod
    def _handle(index: str) -> int:
        assert re.fullmatch(r"0x01[89ab][0-9a-f]{5}", index), f"a tool was given the index {index!r}"
        return int(index, 16)

    def _refusal(
        self, entry: Dict[str, Any], auth: Optional[SecureBuffer], wrong: str, locked: str
    ) -> Optional[linux_tpm._Result]:
        protected = "no_da" not in entry["attributes"]
        if protected and self.locked:
            return failed(locked)
        presented = b"" if auth is None else contents(auth)  # no -P option: the empty authorisation
        if presented.rstrip(b"\x00") == entry["auth"].rstrip(b"\x00"):  # the TPM ignores trailing zero bytes
            return None
        if not protected:
            return failed("nvread_wrong_auth_no_da")
        if self.interval:
            self.failed_tries += 1
        return failed(wrong)

    def tpm2_getcap(self, arguments: List[str], **given: Any) -> linux_tpm._Result:
        assert given["auth"] is None and given["data"] is None and given["secret_out"] is None
        if arguments == ["properties-fixed"]:
            return succeeded("tpm2_getcap", GETCAP_FIXED_HEAD)
        assert arguments == ["properties-variable"], arguments
        return succeeded(
            "tpm2_getcap",
            getcap_variable(
                owner_auth=int(self.owner_auth_set),
                in_lockout=int(self.locked),
                counter=self.failed_tries,
                limit=self.max_tries,
                interval=self.interval,
                group=self.permanent_group,
            ),
        )

    def tpm2_nvreadpublic(self, arguments: List[str], **given: Any) -> linux_tpm._Result:
        assert len(arguments) == 1, arguments
        assert given["auth"] is None and given["data"] is None and given["secret_out"] is None
        entry = self.indices.get(self._handle(arguments[0]))
        if entry is None:
            return failed("nvreadpublic_missing")
        return succeeded("tpm2_nvreadpublic", public_area(arguments[0], entry["attributes"], entry["size"]))

    def tpm2_nvdefine(self, arguments: List[str], **given: Any) -> linux_tpm._Result:
        index, *options = arguments
        open_index = given["auth"] is None  # a device key that needs no password: no -p, an empty authorisation
        wanted = "authread|authwrite|no_da" if open_index else "authread|authwrite"
        assert options == ["-C", "o", "-s", "32", "-a", wanted], options
        assert given["auth_option"] == "-p"
        assert given["data"] is None and given["secret_out"] is None
        handle = self._handle(index)
        if self.owner_auth_set:
            return failed("nvdefine_owner_auth_set")
        if handle in self.indices:
            return failed("nvdefine_already_defined")
        self.indices[handle] = {
            "auth": b"" if open_index else contents(given["auth"]),
            "attributes": ["authwrite", "authread"] + (["no_da"] if open_index else []),
            "size": 32,
            "data": None,
        }
        return succeeded("tpm2_nvdefine", f"nv-index: {handle:#x}\n".encode("ascii"))

    def tpm2_nvwrite(self, arguments: List[str], **given: Any) -> linux_tpm._Result:
        index, *options = arguments
        assert options == ["-C", index], options
        assert given["auth_option"] == "-P"
        assert given["data"] is not None and given["secret_out"] is None
        entry = self.indices.get(self._handle(index))
        if entry is None:
            return failed("nvwrite_missing")
        refusal = self._refusal(entry, given["auth"], "nvwrite_wrong_auth", "nvwrite_lockout")
        if refusal is not None:
            return refusal
        assert len(given["data"]) == entry["size"]
        entry["data"] = contents(given["data"])
        if "written" not in entry["attributes"]:
            entry["attributes"].append("written")
        return succeeded("tpm2_nvwrite")

    def tpm2_nvread(self, arguments: List[str], **given: Any) -> linux_tpm._Result:
        index, *options = arguments
        assert options == ["-C", index, "-s", "32"], options
        assert given["auth_option"] == "-P"
        assert given["data"] is None and given["secret_out"] is not None
        entry = self.indices.get(self._handle(index))
        if entry is None:
            return failed("nvread_missing")
        refusal = self._refusal(entry, given["auth"], "nvread_wrong_auth", "nvread_lockout")
        if refusal is not None:
            return refusal
        if entry["data"] is None:
            return failed("nvread_uninitialized")
        given["secret_out"].view()[:] = entry["data"]
        return succeeded("tpm2_nvread", filled=True)

    def tpm2_nvundefine(self, arguments: List[str], **given: Any) -> linux_tpm._Result:
        index, *options = arguments
        assert options == ["-C", "o"], options
        assert given["auth"] is None and given["data"] is None and given["secret_out"] is None
        handle = self._handle(index)
        if handle not in self.indices:
            return failed("nvundefine_missing")
        if self.owner_auth_set:
            return failed("nvundefine_owner_auth_set")
        del self.indices[handle]
        return succeeded("tpm2_nvundefine")


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeTpm:
    """The backend talks to a FakeTpm instead of running tools."""
    tpm = FakeTpm()
    monkeypatch.setattr(linux_tpm, "_run", tpm.run)
    return tpm


@pytest.fixture
def backend() -> Tpm2Backend:
    return Tpm2Backend()


def registry() -> List[str]:
    return linux_tpm._load_registry()


def enroll(backend: Tpm2Backend, auth: bytes = AUTH) -> Tuple[Dict[str, Any], bytes]:
    with buffer(auth) as value:
        made, secret = backend.enroll(policy=POLICY_DEVICE, auth=value, reason="test")
    with secret:
        return made, contents(secret)


def unseal(backend: Tpm2Backend, made: Dict[str, Any], auth: bytes = AUTH) -> bytes:
    with buffer(auth) as value, backend.unseal(made, auth=value, interactive=False, reason="test") as secret:
        return contents(secret)


def enroll_open(backend: Tpm2Backend) -> Tuple[Dict[str, Any], bytes]:
    """A device key that needs no password, as sessions and grants are bound with."""
    made, secret = backend.enroll(policy=POLICY_DEVICE, auth=None, reason="test")
    with secret:
        return made, contents(secret)


def unseal_open(backend: Tpm2Backend, made: Dict[str, Any]) -> bytes:
    with backend.unseal(made, auth=None, interactive=False, reason="test") as secret:
        return contents(secret)


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


def test_backend_is_registered_under_its_contract_name():
    found = device.get_backend("linux-tpm2")
    assert isinstance(found, Tpm2Backend) and isinstance(found, DeviceBackend)
    assert (found.name, found.hardware, found.policies) == ("linux-tpm2", True, (POLICY_DEVICE,))
    assert found.supports(POLICY_DEVICE)
    assert not found.supports(POLICY_BIOMETRY) and not found.supports(POLICY_PRESENCE)
    assert linux_tpm.__all__ == ["Tpm2Backend", "lockout_status"]
    assert "linux-tpm2" in device.backend_names()


def test_module_imports_nothing_that_can_open_a_network_connection():
    tree = ast.parse(Path(linux_tpm.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {
        "socket",
        "ssl",
        "http",
        "urllib",
        "ftplib",
        "smtplib",
        "poplib",
        "imaplib",
        "telnetlib",
        "xmlrpc",
        "socketserver",
        "asyncio",
        "selectors",
        "select",
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
        "webbrowser",
    }
    assert imported & forbidden == set()
    assert "password_manager" not in imported


def test_no_placeholders_are_left_in_the_module():
    source = Path(linux_tpm.__file__).read_text(encoding="utf-8")
    for marker in ("TODO", "FIXME", "XXX", "not implemented", "NotImplemented"):
        assert marker not in source


# ---------------------------------------------------------------------------
# Descriptors and NV indices: hostile input from the vault file
# ---------------------------------------------------------------------------

MALFORMED_DESCRIPTORS: List[Tuple[str, Any]] = [
    ("none", None),
    ("list", ["linux-tpm2"]),
    ("string", INDEX),
    ("number", 0x018ABCDE),
    ("other backend", descriptor(backend="software")),
    ("no backend", {"policy": "device", "ref": "ab" * 16, "nv_index": INDEX}),
    ("biometry policy", descriptor(policy="biometry")),
    ("presence policy", descriptor(policy="presence")),
    ("unknown policy", descriptor(policy="always")),
    ("no policy", descriptor(policy=None)),
    ("no ref", descriptor(ref=None)),
    ("short ref", descriptor(ref="abcd")),
    ("numeric ref", descriptor(ref=7)),
    ("upper-case ref", descriptor(ref="AB" * 16)),
    ("no index", descriptor(nv_index=None)),
    ("index as int", descriptor(0x018ABCDE)),
    ("index as bool", descriptor(True)),
    ("index as list", descriptor([INDEX])),
    ("index as bytes", descriptor(INDEX.encode())),
    ("upper-case digits", descriptor("0x018ABCDE")),
    ("upper-case prefix", descriptor("0X018abcde")),
    ("no prefix", descriptor("018abcde")),
    ("decimal", descriptor(str(0x018ABCDE))),
    ("seven digits", descriptor("0x18abcde")),
    ("nine digits", descriptor("0x018abcdef")),
    ("trailing newline", descriptor(INDEX + "\n")),
    ("leading space", descriptor(" " + INDEX)),
    ("trailing space", descriptor(INDEX + " ")),
    ("below the owner range", descriptor("0x017fffff")),
    ("above the owner range", descriptor("0x01c00000")),
    ("platform range", descriptor("0x01400001")),
    ("persistent object", descriptor("0x81000001")),
    ("owner hierarchy", descriptor("0x40000001")),
    ("zero", descriptor("0x00000000")),
    ("option injection", descriptor("-h")),
    ("extra arguments", descriptor(INDEX + " -C o")),
    ("path", descriptor("../../etc/passwd")),
    ("unicode digit", descriptor("0x018abcd٥")),
    ("fullwidth digit", descriptor("0x01８abcde")),
    ("nul byte", descriptor("0x018abcd\x00")),
    ("empty", descriptor("")),
]


@pytest.mark.parametrize(
    "bad", [case for _, case in MALFORMED_DESCRIPTORS], ids=[name for name, _ in MALFORMED_DESCRIPTORS]
)
def test_malformed_descriptor_is_refused_before_any_tool_runs(bad, backend, monkeypatch):
    monkeypatch.setattr(linux_tpm, "_run", explode)
    with pytest.raises(VaultError):
        backend.exists(bad)
    with pytest.raises(VaultError):
        backend.destroy(bad)
    with buffer(AUTH) as auth, pytest.raises(VaultError):
        backend.unseal(bad, auth=auth, interactive=False, reason="test")
    assert not paths.device_dir().exists(), "refusing a descriptor must not create anything"


@pytest.mark.parametrize("index", ["0x01800000", "0x01bfffff", "0x018abcde", "0x01a00000", "0x019f0f0f"])
def test_owner_range_indices_are_accepted(index):
    assert linux_tpm._index_of(descriptor(index)) == index
    assert linux_tpm._index_of(descriptor(index, extra="ignored", ref="0" * 32)) == index


@PROPERTY
@given(st.integers(min_value=0, max_value=0x3FFFFF))
def test_every_owner_range_handle_has_exactly_one_accepted_spelling(offset):
    handle = 0x01800000 + offset
    canonical = f"0x{handle:08x}"
    assert linux_tpm._index_of(descriptor(canonical)) == canonical
    for other in (
        f"0x{handle:x}",
        f"0x{handle:08X}",
        f"0X{handle:08x}",
        str(handle),
        f"{handle:08x}",
        canonical + "\n",
    ):
        if other != canonical:
            with pytest.raises(VaultError):
                linux_tpm._index_of(descriptor(other))


@PROPERTY
@given(st.one_of(st.text(max_size=16), st.integers(), st.none(), st.booleans(), st.binary(max_size=12)))
def test_anything_else_is_refused_as_an_index(value):
    accepted = isinstance(value, str) and re.fullmatch(r"0x01[89ab][0-9a-f]{5}", value) is not None
    if accepted:
        assert linux_tpm._index_of(descriptor(value)) == value
    else:
        with pytest.raises(VaultError):
            linux_tpm._index_of(descriptor(value))


@PROPERTY
@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
def test_handles_outside_the_owner_range_are_refused(handle):
    text = f"0x{handle:08x}"
    if 0x01800000 <= handle <= 0x01BFFFFF:
        assert linux_tpm._index_of(descriptor(text)) == text
    else:
        with pytest.raises(VaultError):
            linux_tpm._index_of(descriptor(text))


def test_new_indices_are_random_and_inside_the_owner_range():
    drawn = {linux_tpm._random_index() for _ in range(500)}
    assert len(drawn) > 490, "500 draws from 4 million handles should hardly ever repeat"
    for index in drawn:
        assert re.fullmatch(r"0x01[89ab][0-9a-f]{5}", index)
        assert 0x01800000 <= int(index, 16) <= 0x01BFFFFF
        assert linux_tpm._index_of(descriptor(index)) == index
    assert {index[4] for index in drawn} == set("89ab"), "the whole range is used, not one corner of it"


# ---------------------------------------------------------------------------
# The authorisation value
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad, fragment",
    [
        (b"\x01" * 32, "SecureBuffer"),
        (bytearray(b"\x01" * 32), "SecureBuffer"),
        ("x" * 32, "SecureBuffer"),
        (0, "SecureBuffer"),
    ],
)
def test_authorisation_value_must_be_a_secure_buffer(bad, fragment):
    with pytest.raises(HardwareError, match=fragment):
        linux_tpm._checked_auth(bad)


def test_no_authorisation_value_stands_for_the_empty_one():
    """``auth=None`` is how a device key that needs no password is asked for; it is not turned into anything."""
    assert linux_tpm._checked_auth(None) is None
    assert linux_tpm._attributes_for(None) == "authread|authwrite|no_da"
    with buffer(AUTH) as auth:
        assert linux_tpm._attributes_for(auth) == "authread|authwrite"


@pytest.mark.parametrize("length", [1, 16, 31, 33, 64])
def test_authorisation_value_must_be_32_bytes(length):
    with buffer(b"\x07" * length) as auth, pytest.raises(HardwareError, match="32-byte"):
        linux_tpm._checked_auth(auth)


def test_all_zero_authorisation_value_is_refused():
    with SecureBuffer(32) as auth, pytest.raises(HardwareError, match="all-zero"):
        linux_tpm._checked_auth(auth)
    with buffer(bytes(31) + b"\x01") as auth:
        assert linux_tpm._checked_auth(auth) is auth


@PROPERTY
@given(st.binary(min_size=1, max_size=64))
def test_authorisation_text_is_the_hex_form_the_tools_parse(raw):
    with buffer(raw) as auth, linux_tpm._auth_text(auth) as text:
        assert contents(text) == b"hex:" + binascii.hexlify(raw)
        assert isinstance(text, SecureBuffer)


def test_backend_refuses_calls_it_cannot_serve_without_running_a_tool(backend, monkeypatch):
    monkeypatch.setattr(linux_tpm, "_run", explode)
    with buffer(AUTH) as auth:
        for policy in (POLICY_BIOMETRY, POLICY_PRESENCE, "nonsense"):
            with pytest.raises(HardwareError, match="policy"):
                backend.enroll(policy=policy, auth=auth, reason="test")
    for policy in (POLICY_BIOMETRY, POLICY_PRESENCE):
        with pytest.raises(HardwareError, match="policy"):
            backend.enroll(policy=policy, auth=None, reason="test")
    with pytest.raises(HardwareError, match="not created by this IronDome installation"):
        backend.unseal(descriptor(), auth=None, interactive=True, reason="test")
    with SecureBuffer(32) as zero, pytest.raises(HardwareError, match="all-zero"):
        backend.enroll(policy=POLICY_DEVICE, auth=zero, reason="test")
    with buffer(b"short") as short, pytest.raises(HardwareError, match="32-byte"):
        backend.unseal(descriptor(), auth=short, interactive=False, reason="test")
    assert not paths.device_dir().exists()


# ---------------------------------------------------------------------------
# What the tools print when they fail
# ---------------------------------------------------------------------------

CODES_IN_SAMPLES = {
    "nvread_wrong_auth": [0x08E],
    "nvwrite_wrong_auth": [0x08E],
    "nvread_wrong_auth_no_da": [0x0A2],
    "nvread_lockout": [0x921],
    "nvwrite_lockout": [0x921],
    "nvread_missing": [0x08B],
    "nvwrite_missing": [0x08B],
    "nvread_uninitialized": [0x14A],
    "nvdefine_already_defined": [0x14C],
    "nvdefine_nv_space": [0x14B],
    "nvdefine_owner_auth_set": [0x0A2],
    "nvundefine_owner_auth_set": [0x0A2],
    "nvundefine_missing": [0x08B],
    "nvreadpublic_missing": [0x08B],
    "tcti_device_missing": [],
    "tcti_socket_dead": [],
    "tcti_default_fallbacks": [],
    "tcti_unknown": [],
    "tpm_not_started": [0x100],
    "auth_file_missing": [],
    "auth_file_not_hex": [],
    "nvwrite_too_long": [],
}


def test_every_captured_failure_has_an_expectation():
    assert set(CODES_IN_SAMPLES) == set(FAILURES)
    assert all(status != 0 and stderr for _, status, stderr in FAILURES.values())


@pytest.mark.parametrize("name", sorted(FAILURES))
def test_response_codes_are_read_from_captured_output(name):
    assert linux_tpm._response_codes(FAILURES[name][2]) == CODES_IN_SAMPLES[name]


@PROPERTY
@given(
    base=st.sampled_from([0x08E, 0x0A2, 0x08B, 0x084, 0x095, 0x082]),
    position=st.integers(min_value=0, max_value=7),
    kind=st.sampled_from(["handle", "session", "parameter"]),
    style=st.sampled_from(["(0x{:X})", "(0x{:x})", "(0x{:08x})", "(0x{:08X})"]),
)
def test_format_one_codes_lose_the_bits_that_say_where_the_fault_was(base, position, kind, style):
    code = base | (position << 8) | {"handle": 0, "session": 0x800, "parameter": 0x040}[kind]
    stderr = f"ERROR: Esys_NV_Read{style.format(code)} - tpm:{kind}({position}): whatever\n".encode("ascii")
    assert linux_tpm._response_codes(stderr) == [base]


@PROPERTY
@given(code=st.integers(min_value=1, max_value=0xFFF).filter(lambda value: not value & 0x080))
def test_format_zero_codes_are_kept_whole(code):
    assert linux_tpm._response_codes(f"ERROR: Esys_X(0x{code:X}) - text".encode("ascii")) == [code]


@PROPERTY
@given(code=st.integers(min_value=1, max_value=0xFFFF), layer=st.integers(min_value=1, max_value=255))
def test_codes_raised_by_the_tss_software_layers_are_not_tpm_responses(code, layer):
    stderr = f"ERROR:tcti:x.c:1:f() Failed: (0x{(layer << 16) | code:x})\n".encode("ascii")
    if layer == 12:  # a resource manager passing on what the TPM said
        assert len(linux_tpm._response_codes(stderr)) <= 1
    else:
        assert linux_tpm._response_codes(stderr) == []


def test_resource_manager_layer_carries_tpm_codes():
    assert linux_tpm._response_codes(b"ERROR: Esys_NV_Read(0xC098E) - rmtpm:session(1): x") == [0x08E]
    assert linux_tpm._response_codes(b"ERROR: Esys_NV_Read(0xC0921) - rmtpm:warn(2.0): x") == [0x921]


def test_hex_numbers_that_are_not_response_codes_are_ignored():
    stderr = b"ERROR: Failed to read the public part of NV index 0x1800123\nERROR: size 0x20 offset (0) (33)\n"
    assert linux_tpm._response_codes(stderr) == []
    assert linux_tpm._response_codes(b"") == []


LOCKED = {
    "max_tries": 3,
    "failed_tries": 3,
    "remaining_tries": 0,
    "recovery_seconds": 1000,
    "lockout_recovery_seconds": 1000,
    "in_lockout": True,
    "seconds_until_retry": 1000,
    "lockout_auth_set": False,
}

SECRET_AUTH = {"index": INDEX, "secret_auth": True}
OWNER_AUTH: Dict[str, Any] = {}

FAILURE_MAPPING = [
    # sample, how the command was authorised, exception, what the message must say
    ("nvread_wrong_auth", SECRET_AUTH, AuthError, r"^wrong master password$"),
    ("nvwrite_wrong_auth", SECRET_AUTH, AuthError, r"^wrong master password$"),
    ("nvread_wrong_auth_no_da", SECRET_AUTH, AuthError, r"^wrong master password$"),
    ("nvread_lockout", SECRET_AUTH, LockedOutError, r"at most 16 min 40 s"),
    ("nvwrite_lockout", SECRET_AUTH, LockedOutError, r"3 failed attempts, limit 3"),
    (
        "nvread_missing",
        SECRET_AUTH,
        HardwareError,
        r"NV index 0x018abcde is not defined.*recovery key.*portable backup",
    ),
    ("nvwrite_missing", SECRET_AUTH, HardwareError, r"recovery key"),
    ("nvread_uninitialized", SECRET_AUTH, HardwareError, r"never written.*recovery key"),
    ("nvdefine_owner_auth_set", OWNER_AUTH, HardwareError, r"owner password.*tpm2_changeauth -c owner -p"),
    ("nvundefine_owner_auth_set", OWNER_AUTH, HardwareError, r"owner password.*tpm2_changeauth -c owner -p"),
    ("nvdefine_nv_space", OWNER_AUTH, HardwareError, r"no free NV storage.*tpm2_getcap handles-nv-index"),
    ("nvdefine_already_defined", OWNER_AUTH, HardwareError, r"tpm2_nvdefine failed: .*already defined"),
    ("tpm_not_started", OWNER_AUTH, HardwareError, r"TPM2_Startup"),
    ("tcti_device_missing", OWNER_AUTH, HardwareError, r"/dev/tpmrm0: No such file or directory"),
    ("tcti_socket_dead", OWNER_AUTH, HardwareError, r"Cannot connect to swtpm TPM socket"),
    ("tcti_default_fallbacks", OWNER_AUTH, HardwareError, r"Could not load tcti"),
    ("tcti_unknown", OWNER_AUTH, HardwareError, r'Could not load tcti, got: "bogus:foo"'),
    ("auth_file_missing", SECRET_AUTH, HardwareError, r"tpm2_nvread failed: Could not open file"),
    ("auth_file_not_hex", SECRET_AUTH, HardwareError, r"tpm2_nvread failed: get password"),
    ("nvwrite_too_long", SECRET_AUTH, HardwareError, r"larger than the defined space"),
    ("nvreadpublic_missing", OWNER_AUTH, HardwareError, r"tpm2_nvreadpublic failed: .*handle is not correct"),
    ("nvundefine_missing", OWNER_AUTH, HardwareError, r"tpm2_nvundefine failed"),
]


def test_every_captured_failure_is_mapped():
    assert {name for name, _, _, _ in FAILURE_MAPPING} == set(FAILURES)


@pytest.mark.parametrize("name, context, expected, message", FAILURE_MAPPING, ids=[row[0] for row in FAILURE_MAPPING])
def test_captured_failure_becomes_the_right_exception(name, context, expected, message, monkeypatch):
    monkeypatch.setattr(linux_tpm, "lockout_status", lambda: dict(LOCKED))
    with pytest.raises(IronDomeError) as caught:
        linux_tpm._raise_for(failed(name), **context)
    assert type(caught.value) is expected
    assert re.search(message, str(caught.value)), str(caught.value)


def test_wrong_password_and_lockout_are_both_authentication_failures(monkeypatch):
    """The kernel tries the next keyslot on AuthError; LockedOutError must stay one."""
    monkeypatch.setattr(linux_tpm, "lockout_status", lambda: dict(LOCKED))
    with pytest.raises(AuthError) as caught:
        linux_tpm._raise_for(failed("nvread_lockout"), **SECRET_AUTH)
    assert isinstance(caught.value, LockedOutError) and caught.value.exit_code == 4


def test_lockout_takes_precedence_over_everything_else_in_the_output(monkeypatch):
    monkeypatch.setattr(linux_tpm, "lockout_status", lambda: dict(LOCKED))
    mixed = FAILURES["nvread_wrong_auth"][2] + FAILURES["nvread_missing"][2] + FAILURES["nvread_lockout"][2]
    with pytest.raises(LockedOutError):
        linux_tpm._raise_for(linux_tpm._Result("tpm2_nvread", 1, b"", mixed, False), **SECRET_AUTH)


def test_owner_authorisation_failure_is_never_reported_as_a_wrong_master_password():
    for name in ("nvdefine_owner_auth_set", "nvundefine_owner_auth_set"):
        with pytest.raises(HardwareError) as caught:
            linux_tpm._raise_for(failed(name), index=INDEX)
        assert not isinstance(caught.value, AuthError)


@pytest.mark.parametrize("name", ["nvread_wrong_auth", "nvwrite_wrong_auth", "nvread_wrong_auth_no_da"])
def test_a_refused_empty_authorisation_is_neither_a_wrong_password_nor_an_owner_password(name):
    """No password was given, so none can be wrong: the index is simply not a device key that needs none."""
    with pytest.raises(HardwareError, match=r"^TPM NV index 0x018abcde does not open with an empty") as caught:
        linux_tpm._raise_for(failed(name), index=INDEX, no_auth=True)
    assert not isinstance(caught.value, AuthError) and "owner password" not in str(caught.value)
    silent = linux_tpm._Result("tpm2_nvread", 3, b"", b"worded differently\n", False)
    with pytest.raises(HardwareError, match="does not open with an empty authorisation"):
        linux_tpm._raise_for(silent, index=INDEX, no_auth=True)


def test_exit_status_alone_identifies_a_rejected_authorisation():
    """tpm2-tools exit with 3 for an authorisation failure; used when no response code can be read."""
    silent = linux_tpm._Result("tpm2_nvread", 3, b"", b"something this version words differently\n", False)
    with pytest.raises(AuthError, match="^wrong master password$"):
        linux_tpm._raise_for(silent, **SECRET_AUTH)
    with pytest.raises(HardwareError, match="owner password"):
        linux_tpm._raise_for(silent._replace(tool="tpm2_nvdefine"))
    with pytest.raises(HardwareError, match="tpm2_nvread failed: exit status 1"):
        linux_tpm._raise_for(silent._replace(status=1, stderr=b""), **SECRET_AUTH)


@pytest.mark.parametrize("code", [0x908, 0x909, 0x90A, 0x922, 0x923])
def test_busy_tpm_is_reported_as_something_to_retry(code):
    result = linux_tpm._Result(
        "tpm2_nvread", 1, b"", f"ERROR: Esys_NV_Read(0x{code:X}) - tpm:warn(2.0): x\n".encode(), False
    )
    with pytest.raises(HardwareError, match=rf"busy \(response code 0x{code:03x}\)\. Try again"):
        linux_tpm._raise_for(result, **SECRET_AUTH)


def test_nv_rate_limit_is_explained():
    result = linux_tpm._Result(
        "tpm2_nvdefine", 1, b"", b"ERROR: Esys_NV_DefineSpace(0x920) - tpm:warn(2.0): x\n", False
    )
    with pytest.raises(HardwareError, match="rate-limiting writes"):
        linux_tpm._raise_for(result)


def test_lockout_message_without_a_readable_tpm(monkeypatch):
    def unreadable() -> Dict[str, Any]:
        raise HardwareError("cannot reach the TPM")

    monkeypatch.setattr(linux_tpm, "lockout_status", unreadable)
    with pytest.raises(LockedOutError, match="refusing password attempts.*Wait and try again"):
        linux_tpm._raise_for(failed("nvread_lockout"), **SECRET_AUTH)


def test_lockout_message_when_waiting_cannot_help(monkeypatch):
    stuck = dict(LOCKED, max_tries=0, failed_tries=0, recovery_seconds=0, seconds_until_retry=None)
    monkeypatch.setattr(linux_tpm, "lockout_status", lambda: stuck)
    with pytest.raises(LockedOutError, match="waiting will not help.*tpm2_dictionarylockout --clear-lockout") as caught:
        linux_tpm._raise_for(failed("nvread_lockout"), **SECRET_AUTH)
    assert "at most" not in str(caught.value), "no wait is promised when none will help"


def test_lockout_message_states_the_wait(monkeypatch):
    monkeypatch.setattr(
        linux_tpm,
        "lockout_status",
        lambda: dict(LOCKED, failed_tries=5, seconds_until_retry=21600, recovery_seconds=7200, max_tries=3),
    )
    with pytest.raises(LockedOutError) as caught:
        linux_tpm._raise_for(failed("nvread_lockout"), **SECRET_AUTH)
    message = str(caught.value)
    assert "5 failed attempts, limit 3" in message
    assert "at most 6 h" in message and "one failure every 2 h" in message


@PROPERTY
@given(
    stderr=st.binary(max_size=1500),
    status=st.integers(min_value=-15, max_value=255).filter(lambda value: value != 0),
    secret_auth=st.booleans(),
    no_auth=st.booleans(),
    index=st.sampled_from([None, INDEX]),
)
def test_any_failure_output_becomes_an_irondome_error_with_a_printable_message(
    stderr, status, secret_auth, no_auth, index
):
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(linux_tpm, "lockout_status", lambda: dict(LOCKED))
        with pytest.raises((AuthError, HardwareError)) as caught:
            linux_tpm._raise_for(
                linux_tpm._Result("tpm2_nvread", status, b"", stderr, False),
                index=index,
                secret_auth=secret_auth,
                no_auth=no_auth and not secret_auth,
            )
    message = str(caught.value)
    assert message and len(message) < 700
    assert all(" " <= char <= "~" for char in message)


@PROPERTY
@given(st.binary(min_size=16, max_size=64))
def test_key_shaped_text_in_tool_output_is_never_repeated(material):
    """If a tool ever echoed what it was given, the message must not carry it on."""
    for spelled in (binascii.hexlify(material).decode("ascii"), binascii.hexlify(material).decode("ascii").upper()):
        stderr = f'ERROR: Could not convert "{spelled}" from a hex string to byte array!\n'.encode("ascii")
        summary = linux_tpm._summary(stderr)
        assert spelled not in summary and "[redacted]" in summary
        with pytest.raises(HardwareError) as caught:
            linux_tpm._raise_for(linux_tpm._Result("tpm2_nvread", 1, b"", stderr, False), **SECRET_AUTH)
        assert spelled not in str(caught.value)


@PROPERTY
@given(st.binary(max_size=4000))
def test_summary_is_one_short_printable_line(stderr):
    summary = linux_tpm._summary(stderr)
    assert len(summary) <= 300
    assert all(" " <= char <= "~" for char in summary)
    assert all(0 < code <= 0xFFF for code in linux_tpm._response_codes(stderr))


def test_summary_prefers_the_line_that_names_the_response_code():
    assert linux_tpm._summary(FAILURES["nvdefine_already_defined"][2]) == (
        "Esys_NV_DefineSpace(0x14C) - tpm:error(2.0): NV Index or persistent object already defined"
    )
    assert linux_tpm._summary(FAILURES["tcti_device_missing"][2]) == (
        'Could not load tcti, got: "device:/dev/tpmrm0": Failed to open specified TCTI device file /dev/tpmrm0: '
        "No such file or directory"
    )
    assert linux_tpm._summary(b"") == ""
    assert linux_tpm._summary(b"ERROR: Unable to run tpm2_nvread\n") == ""


@pytest.mark.parametrize(
    "seconds, text",
    [
        (0, "0 s"),
        (1, "1 s"),
        (59, "59 s"),
        (60, "1 min"),
        (1000, "16 min 40 s"),
        (3600, "1 h"),
        (7200, "2 h"),
        (86400, "24 h"),
        (3661, "1 h 1 min 1 s"),
        (-5, "0 s"),
    ],
)
def test_durations_are_spelled_out(seconds, text):
    assert linux_tpm._duration(seconds) == text


@PROPERTY
@given(st.integers(min_value=0, max_value=10**7))
def test_duration_text_adds_up_to_the_seconds_it_describes(seconds):
    total = 0
    for amount, unit in re.findall(r"(\d+) (h|min|s)", linux_tpm._duration(seconds)):
        total += int(amount) * {"h": 3600, "min": 60, "s": 1}[unit]
    assert total == seconds


# ---------------------------------------------------------------------------
# What the tools print when they succeed
# ---------------------------------------------------------------------------


def test_variable_properties_are_parsed_from_captured_output():
    values = linux_tpm._parse_properties(GETCAP_VARIABLE)
    assert values["TPM2_PT_PERMANENT.ownerAuthSet"] == 0
    assert values["TPM2_PT_PERMANENT.lockoutAuthSet"] == 0
    assert values["TPM2_PT_PERMANENT.inLockout"] == 0
    assert values["TPM2_PT_PERMANENT.tpmGeneratedEPS"] == 1
    assert values["TPM2_PT_STARTUP_CLEAR.orderly"] == 1
    assert values["TPM2_PT_LOCKOUT_COUNTER"] == 0
    assert values["TPM2_PT_MAX_AUTH_FAIL"] == 3
    assert values["TPM2_PT_LOCKOUT_INTERVAL"] == 1000
    assert values["TPM2_PT_LOCKOUT_RECOVERY"] == 1000
    assert "TPM2_PT_PERMANENT" not in values, "a group header has no value of its own"


def test_fixed_properties_name_the_manufacturer():
    fixed = linux_tpm._parse_properties(GETCAP_FIXED_HEAD)
    assert fixed["TPM2_PT_MANUFACTURER.raw"] == 0x49424D00
    assert linux_tpm._maker(fixed) == "IBM SW TPM"
    infineon = {
        "TPM2_PT_MANUFACTURER.raw": 0x49465800,
        "TPM2_PT_VENDOR_STRING_1.raw": 0x534C4239,
        "TPM2_PT_VENDOR_STRING_2.raw": 0x36373000,
    }
    assert linux_tpm._maker(infineon) == "IFX SLB9670"
    assert linux_tpm._maker({}) == "unknown manufacturer"
    assert linux_tpm._maker({"TPM2_PT_MANUFACTURER.raw": 0x1B5B316D}) == "[1m", "control characters are dropped"
    assert linux_tpm._maker({"TPM2_PT_MANUFACTURER.raw": 2**40 + 0x414D4400}) == "AMD"


@PROPERTY
@given(st.binary(max_size=3000))
def test_property_parser_survives_anything(output):
    values = linux_tpm._parse_properties(output)
    assert all(isinstance(key, str) and type(value) is int and value >= 0 for key, value in values.items())


@PROPERTY
@given(
    st.dictionaries(
        st.from_regex(r"TPM2_PT_[A-Z_]{1,20}", fullmatch=True),
        st.integers(min_value=0, max_value=2**32 - 1),
        max_size=12,
    )
)
def test_properties_round_trip_through_the_getcap_layout(properties):
    rendered = "".join(f"{name}: 0x{value:X}\n" for name, value in properties.items()).encode("ascii")
    assert linux_tpm._parse_properties(rendered) == properties


def test_public_area_is_parsed_from_captured_output():
    written = linux_tpm._parse_public(NVREADPUBLIC_WRITTEN, "0x01800123")
    assert written == linux_tpm._Public(frozenset({"authwrite", "authread", "written"}), 32)
    unwritten = linux_tpm._parse_public(NVREADPUBLIC_UNWRITTEN, "0x01800123")
    assert unwritten == linux_tpm._Public(frozenset({"authwrite", "authread"}), 32)
    assert linux_tpm._is_irondome_shaped(written) and linux_tpm._is_irondome_shaped(unwritten)


def test_public_area_does_not_depend_on_the_attribute_number():
    """tpm2-tools 4.3.0 print the attribute value byte-swapped (0x4000420); only the names are used."""
    older = NVREADPUBLIC_WRITTEN.replace(b"value: 0x20040004", b"value: 0x4000420")
    assert older != NVREADPUBLIC_WRITTEN
    assert linux_tpm._parse_public(older, "0x01800123") == linux_tpm._parse_public(NVREADPUBLIC_WRITTEN, "0x01800123")


def test_an_index_without_dictionary_attack_protection_is_not_a_password_keyslots():
    """It has the shape of a device key that needs no password, which is never taken for a keyslot's."""
    exempt = linux_tpm._parse_public(NVREADPUBLIC_NO_DA, "0x01800124")
    assert exempt is not None and "no_da" in exempt.attributes
    assert not linux_tpm._is_irondome_shaped(exempt)
    assert linux_tpm._has_shape(exempt, linux_tpm._NV_OPEN_ATTRIBUTES)
    keyslot = linux_tpm._parse_public(NVREADPUBLIC_WRITTEN, "0x01800123")
    assert not linux_tpm._has_shape(keyslot, linux_tpm._NV_OPEN_ATTRIBUTES)


def test_public_area_of_another_index_is_not_mistaken_for_the_one_asked_about():
    """Some tool versions list every index; only the block of the requested handle counts."""
    assert linux_tpm._parse_public(NVREADPUBLIC_WRITTEN, "0x01800124") is None
    both = NVREADPUBLIC_NO_DA + NVREADPUBLIC_WRITTEN
    assert linux_tpm._parse_public(both, "0x01800123") == linux_tpm._Public(
        frozenset({"authwrite", "authread", "written"}), 32
    )
    listed = linux_tpm._parse_public(both, "0x01800124")
    assert listed is not None and "no_da" in listed.attributes
    assert linux_tpm._parse_public(both, "0x01800125") is None
    assert linux_tpm._parse_public(b"", INDEX) is None


@pytest.mark.parametrize(
    "attributes, size, ours",
    [
        (["authwrite", "authread"], 32, True),
        (["authread", "authwrite", "written"], 32, True),
        (["authwrite", "authread", "written"], 33, False),
        (["authwrite", "authread", "written"], 31, False),
        (["authwrite", "authread", "no_da", "written"], 32, False),
        (["ownerwrite", "ownerread", "written"], 32, False),
        (["authwrite", "authread", "ownerread"], 32, False),
        (["authread", "written"], 32, False),
        (["authwrite", "authread", "policydelete"], 32, False),
        ([], 32, False),
    ],
)
def test_only_the_exact_shape_this_backend_creates_counts_as_ours(attributes, size, ours):
    public = linux_tpm._parse_public(public_area(INDEX, attributes, size), INDEX)
    assert public is not None
    assert linux_tpm._is_irondome_shaped(public) is ours
    assert linux_tpm._is_irondome_shaped(None) is False


@pytest.mark.parametrize(
    "attributes, size, open_shaped",
    [
        (["authwrite", "authread", "no_da"], 32, True),
        (["authread", "authwrite", "no_da", "written"], 32, True),
        (["authwrite", "authread", "no_da", "written"], 33, False),
        (["authwrite", "authread", "written"], 32, False),
        (["authwrite", "authread", "no_da", "ownerread"], 32, False),
        (["ownerwrite", "ownerread", "no_da"], 32, False),
        (["authwrite", "authread", "no_da", "policywrite"], 32, False),
        (["authread", "no_da"], 32, False),
    ],
)
def test_only_the_exact_shape_of_a_device_key_without_a_password_is_read_without_one(attributes, size, open_shaped):
    public = linux_tpm._parse_public(public_area(INDEX, attributes, size), INDEX)
    assert linux_tpm._has_shape(public, linux_tpm._NV_OPEN_ATTRIBUTES) is open_shaped
    assert linux_tpm._has_shape(None, linux_tpm._NV_OPEN_ATTRIBUTES) is False


def test_the_fake_tpm_prints_public_areas_like_the_real_tool():
    def shape(text: bytes) -> List[str]:
        lines = text.decode("ascii").splitlines()
        return [re.sub(r"(name|value): \S+", r"\1: ?", line) for line in lines]

    assert shape(public_area("0x01800123", ["authwrite", "authread", "written"], 32)) == shape(NVREADPUBLIC_WRITTEN)


@PROPERTY
@given(st.binary(max_size=3000))
def test_public_area_parser_survives_anything(output):
    public = linux_tpm._parse_public(output, INDEX)
    assert public is None or (isinstance(public.size, int) and isinstance(public.attributes, frozenset))


# ---------------------------------------------------------------------------
# lockout_status
# ---------------------------------------------------------------------------


def answer_getcap(monkeypatch: pytest.MonkeyPatch, output: bytes) -> None:
    def run(tool: str, arguments: Sequence[str], **options: Any) -> linux_tpm._Result:
        assert (tool, list(arguments)) == ("tpm2_getcap", ["properties-variable"]) and not options
        return succeeded(tool, output)

    monkeypatch.setattr(linux_tpm, "_run", run)


def test_lockout_status_of_a_fresh_tpm(monkeypatch):
    answer_getcap(monkeypatch, GETCAP_VARIABLE)
    assert linux_tpm.lockout_status() == {
        "max_tries": 3,
        "failed_tries": 0,
        "remaining_tries": 3,
        "recovery_seconds": 1000,
        "lockout_recovery_seconds": 1000,
        "in_lockout": False,
        "seconds_until_retry": 0,
        "lockout_auth_set": False,
    }
    assert Tpm2Backend().lockout_status() == linux_tpm.lockout_status()


@pytest.mark.parametrize(
    "state, expected",
    [
        (dict(counter=1), dict(failed_tries=1, remaining_tries=2, in_lockout=False, seconds_until_retry=0)),
        (
            dict(counter=3, in_lockout=1),
            dict(failed_tries=3, remaining_tries=0, in_lockout=True, seconds_until_retry=1000),
        ),
        (dict(counter=3), dict(in_lockout=True, seconds_until_retry=1000)),
        (dict(counter=2, limit=1, in_lockout=1), dict(remaining_tries=0, in_lockout=True, seconds_until_retry=2000)),
        (dict(counter=5, limit=3, interval=7200), dict(in_lockout=True, seconds_until_retry=21600)),
        (dict(in_lockout=1), dict(in_lockout=True, seconds_until_retry=1000)),
        (dict(interval=0), dict(recovery_seconds=0, in_lockout=False, seconds_until_retry=0, remaining_tries=3)),
        (dict(limit=0, interval=0), dict(max_tries=0, remaining_tries=0, in_lockout=True, seconds_until_retry=None)),
        (dict(limit=0), dict(max_tries=0, remaining_tries=0, in_lockout=True, seconds_until_retry=None)),
        (
            dict(limit=32, interval=7200, recovery=86400),
            dict(max_tries=32, remaining_tries=32, recovery_seconds=7200, lockout_recovery_seconds=86400),
        ),
        (dict(lockout_auth=1), dict(lockout_auth_set=True)),
        (dict(owner_auth=1), dict(lockout_auth_set=False, in_lockout=False)),
    ],
)
def test_lockout_status_in_other_states(state, expected, monkeypatch):
    answer_getcap(monkeypatch, getcap_variable(**state))
    status = linux_tpm.lockout_status()
    for key, value in expected.items():
        assert status[key] == value, key


@PROPERTY
@given(limit=st.integers(0, 64), counter=st.integers(0, 80), interval=st.integers(0, 100_000))
def test_lockout_status_is_consistent(limit, counter, interval):
    with pytest.MonkeyPatch.context() as patch:
        answer_getcap(
            patch, getcap_variable(limit=limit, counter=counter, interval=interval, in_lockout=int(counter >= limit))
        )
        status = linux_tpm.lockout_status()
    assert status["remaining_tries"] == max(limit - counter, 0)
    assert status["in_lockout"] is (counter >= limit)
    assert (status["remaining_tries"] == 0) is status["in_lockout"]
    if not status["in_lockout"]:
        assert status["seconds_until_retry"] == 0
    elif interval == 0 or limit == 0:
        assert status["seconds_until_retry"] is None
    else:
        assert status["seconds_until_retry"] == (counter - limit + 1) * interval >= interval


def test_lockout_status_reads_the_group_name_that_tpm2_tools_4_print(monkeypatch):
    """Captured from tpm2-tools 4.3.0: the permanent attributes are headed TPM2_PT_PERSISTENT there."""
    answer_getcap(monkeypatch, getcap_variable(group="TPM2_PT_PERSISTENT", in_lockout=1, lockout_auth=1, counter=1))
    status = linux_tpm.lockout_status()
    assert status["in_lockout"] is True and status["lockout_auth_set"] is True and status["failed_tries"] == 1
    answer_getcap(monkeypatch, getcap_variable(group="TPM2_PT_PERSISTENT"))
    status = linux_tpm.lockout_status()
    assert status["in_lockout"] is False and status["lockout_auth_set"] is False


@pytest.mark.parametrize(
    "missing",
    ["TPM2_PT_MAX_AUTH_FAIL", "TPM2_PT_LOCKOUT_COUNTER", "TPM2_PT_LOCKOUT_INTERVAL", "TPM2_PT_LOCKOUT_RECOVERY"],
)
def test_lockout_status_needs_every_counter(missing, monkeypatch):
    text = "".join(line for line in GETCAP_VARIABLE.decode().splitlines(keepends=True) if not line.startswith(missing))
    answer_getcap(monkeypatch, text.encode())
    with pytest.raises(HardwareError, match=missing):
        linux_tpm.lockout_status()


def test_lockout_status_reports_an_unreachable_tpm(monkeypatch):
    monkeypatch.setattr(linux_tpm, "_run", lambda *args, **kwargs: failed("tcti_socket_dead"))
    with pytest.raises(HardwareError, match="Cannot connect to swtpm TPM socket"):
        linux_tpm.lockout_status()


# ---------------------------------------------------------------------------
# The registry file
# ---------------------------------------------------------------------------


def write_registry(content: bytes) -> Path:
    path = paths.device_dir() / "tpm2-nv-indices.json"
    paths.ensure_dir(path.parent)
    path.write_bytes(content)
    return path


def test_missing_registry_is_empty_and_reading_it_creates_nothing():
    assert registry() == []
    assert not paths.device_dir().exists()


def test_registry_round_trip_is_sorted_private_and_readable():
    linux_tpm._save_registry(["0x01b00000", "0x01800001", "0x01b00000"])
    assert registry() == ["0x01800001", "0x01b00000"]
    path = paths.device_dir() / "tpm2-nv-indices.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.device_dir().stat().st_mode) == 0o700
    assert json.loads(path.read_text()) == {"v": 1, "backend": "linux-tpm2", "indices": ["0x01800001", "0x01b00000"]}
    assert [entry.name for entry in paths.device_dir().iterdir()] == ["tpm2-nv-indices.json"], (
        "no temporary file is left"
    )


def test_forgetting_an_index():
    linux_tpm._save_registry(["0x01800001", "0x01800002"])
    linux_tpm._forget("0x01800001")
    linux_tpm._forget("0x01800009")
    assert registry() == ["0x01800002"]
    linux_tpm._forget("0x01800002")
    assert registry() == []
    assert (paths.device_dir() / "tpm2-nv-indices.json").is_file(), "an empty registry is kept, not deleted"


def test_registry_is_ignored_by_the_other_backends():
    """It lives in the shared device directory; their destroy_all must not take it for one of their keys."""
    linux_tpm._save_registry(["0x01800001"])
    assert device.get_backend("software").destroy_all() == 0
    assert device.get_backend("macos-se").destroy_all() == 0
    assert registry() == ["0x01800001"]


DAMAGED_REGISTRIES: List[Tuple[str, bytes]] = [
    ("empty file", b""),
    ("not json", b"0x01800001\n"),
    ("truncated", b'{"v": 1, "backend": "linux-tpm2", "indices": ["0x0180'),
    ("a list", b'["0x01800001"]'),
    ("a string", b'"0x01800001"'),
    ("null", b"null"),
    ("no indices", b'{"v": 1, "backend": "linux-tpm2"}'),
    ("no version", b'{"backend": "linux-tpm2", "indices": []}'),
    ("no backend", b'{"v": 1, "indices": []}'),
    ("other backend", b'{"v": 1, "backend": "macos-se", "indices": []}'),
    ("newer version", b'{"v": 2, "backend": "linux-tpm2", "indices": []}'),
    ("version as bool", b'{"v": true, "backend": "linux-tpm2", "indices": []}'),
    ("version as text", b'{"v": "1", "backend": "linux-tpm2", "indices": []}'),
    ("version as float", b'{"v": 1.0, "backend": "linux-tpm2", "indices": []}'),
    ("indices as object", b'{"v": 1, "backend": "linux-tpm2", "indices": {"0x01800001": 1}}'),
    ("indices as text", b'{"v": 1, "backend": "linux-tpm2", "indices": "0x01800001"}'),
    ("index as number", b'{"v": 1, "backend": "linux-tpm2", "indices": [25165825]}'),
    ("index as null", b'{"v": 1, "backend": "linux-tpm2", "indices": [null]}'),
    ("index as list", b'{"v": 1, "backend": "linux-tpm2", "indices": [["0x01800001"]]}'),
    ("upper-case index", b'{"v": 1, "backend": "linux-tpm2", "indices": ["0x018ABCDE"]}'),
    ("index outside the owner range", b'{"v": 1, "backend": "linux-tpm2", "indices": ["0x01c00000"]}'),
    ("persistent handle", b'{"v": 1, "backend": "linux-tpm2", "indices": ["0x81000001"]}'),
    ("index with a newline", b'{"v": 1, "backend": "linux-tpm2", "indices": ["0x01800001\\n"]}'),
    ("index with an option", b'{"v": 1, "backend": "linux-tpm2", "indices": ["0x01800001 -C p"]}'),
    ("one bad among good", b'{"v": 1, "backend": "linux-tpm2", "indices": ["0x01800001", "-h"]}'),
    ("not utf-8", b'{"v": 1, "backend": "linux-tpm2", "indices": ["\xff\xfe"]}'),
    ("nested too deep", b"[" * 200_000),
    (
        "too many entries",
        json.dumps(
            {"v": 1, "backend": "linux-tpm2", "indices": [f"0x{0x01800000 + n:08x}" for n in range(4097)]}
        ).encode(),
    ),
    ("too large", b'{"v": 1, "backend": "linux-tpm2", "indices": [' + b" " * (1 << 20) + b"]}"),
]


@pytest.mark.parametrize(
    "content", [case for _, case in DAMAGED_REGISTRIES], ids=[name for name, _ in DAMAGED_REGISTRIES]
)
def test_damaged_registry_is_a_vault_error_that_says_what_to_do(content, backend, monkeypatch):
    monkeypatch.setattr(linux_tpm, "_run", explode)
    path = write_registry(content)
    with pytest.raises(VaultError, match="tpm2_getcap handles-nv-index") as caught:
        registry()
    assert str(path) in str(caught.value)
    with pytest.raises(VaultError):
        backend.destroy_all()
    assert path.read_bytes() == content, "a damaged registry is left for a person to look at"


def test_registry_at_its_entry_limit_is_still_read():
    full = [f"0x{0x01800000 + number:08x}" for number in range(4096)]
    linux_tpm._save_registry(full)
    assert registry() == full


def test_duplicate_registry_entries_collapse():
    write_registry(b'{"v": 1, "backend": "linux-tpm2", "indices": ["0x01800002", "0x01800001", "0x01800002"]}')
    assert registry() == ["0x01800002", "0x01800001"]


def test_registry_that_is_not_a_file_is_reported():
    (paths.ensure_dir(paths.device_dir()) / "tpm2-nv-indices.json").mkdir()
    with pytest.raises(VaultError, match="cannot read the TPM index registry"):
        registry()


def test_registry_that_cannot_be_written_is_a_hardware_error(monkeypatch):
    def refuse(path: Any, data: Any) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(paths, "write_atomic", refuse)
    with pytest.raises(HardwareError, match="cannot update the TPM index registry.*No space left"):
        linux_tpm._save_registry(["0x01800001"])


@PROPERTY
@given(st.binary(max_size=400))
def test_registry_reader_survives_any_file_content(content):
    write_registry(content)
    try:
        recorded = registry()
    except VaultError:
        return
    assert all(re.fullmatch(r"0x01[89ab][0-9a-f]{5}", index) for index in recorded)


JSON_VALUES = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=False),
        st.text(max_size=12),
        st.sampled_from(["linux-tpm2", "0x01800001", "0x01bfffff", "0x01c00000", 1, 2]),
    ),
    lambda inner: st.one_of(
        st.lists(inner, max_size=4),
        st.dictionaries(st.sampled_from(["v", "backend", "indices", "x"]), inner, max_size=4),
    ),
    max_leaves=12,
)


@PROPERTY
@given(JSON_VALUES)
def test_registry_reader_survives_any_json_document(document):
    write_registry(json.dumps(document).encode("utf-8"))
    try:
        recorded = registry()
    except VaultError:
        return
    assert isinstance(document, dict) and document["v"] == 1 and document["backend"] == "linux-tpm2"
    assert recorded == list(dict.fromkeys(document["indices"]))
    assert all(re.fullmatch(r"0x01[89ab][0-9a-f]{5}", index) for index in recorded)


@PROPERTY
@given(st.sets(st.integers(min_value=0, max_value=0x3FFFFF), max_size=40))
def test_registry_keeps_exactly_what_was_saved(offsets):
    indices = [f"0x{0x01800000 + offset:08x}" for offset in offsets]
    linux_tpm._save_registry(indices)
    assert registry() == sorted(indices)


# ---------------------------------------------------------------------------
# Enrolment and unsealing, against the FakeTpm
# ---------------------------------------------------------------------------


def test_enroll_stores_a_random_secret_that_unseal_returns(fake, backend):
    made, secret = enroll(backend)
    assert set(made) == {"backend", "policy", "ref", "nv_index"}
    assert (made["backend"], made["policy"]) == ("linux-tpm2", "device")
    assert re.fullmatch(r"[0-9a-f]{32}", made["ref"])
    assert linux_tpm._index_of(made) == made["nv_index"]
    assert len(secret) == DEVICE_SECRET_LEN and secret != bytes(DEVICE_SECRET_LEN)
    assert unseal(backend, made) == secret
    assert backend.exists(made)
    assert fake.handles() == {made["nv_index"]} == set(registry())
    stored = fake.indices[int(made["nv_index"], 16)]
    assert stored["auth"] == AUTH and stored["data"] == secret
    assert sorted(stored["attributes"]) == ["authread", "authwrite", "written"], (
        "never no_da: the TPM must count guesses"
    )


def test_enroll_checks_shape_and_reads_back_before_handing_out_a_descriptor(fake, backend):
    made, _ = enroll(backend)
    index = made["nv_index"]
    assert fake.calls == [
        ["tpm2_nvreadpublic", index],
        ["tpm2_nvdefine", index, "-C", "o", "-s", "32", "-a", "authread|authwrite"],
        ["tpm2_nvreadpublic", index],
        ["tpm2_nvwrite", index, "-C", index],
        ["tpm2_nvread", index, "-C", index, "-s", "32"],
    ]


def test_index_is_recorded_before_it_exists(fake, backend):
    """A crash between recording and defining leaves a harmless entry; the reverse would orphan a key."""
    seen: Dict[str, Any] = {}

    def at_define(arguments: List[str]) -> None:
        seen["recorded"] = registry()
        seen["defined"] = fake.handles()
        seen["index"] = arguments[0]

    fake.once("tpm2_nvdefine", at_define)
    made, _ = enroll(backend)
    assert seen == {"recorded": [made["nv_index"]], "defined": set(), "index": made["nv_index"]}


def test_two_enrolments_share_nothing(fake, backend):
    first, first_secret = enroll(backend)
    second, second_secret = enroll(backend, OTHER_AUTH)
    assert first["nv_index"] != second["nv_index"] and first["ref"] != second["ref"]
    assert first_secret != second_secret
    assert registry() == sorted([first["nv_index"], second["nv_index"]])
    assert unseal(backend, first) == first_secret and unseal(backend, second, OTHER_AUTH) == second_secret
    with pytest.raises(AuthError):
        unseal(backend, first, OTHER_AUTH)


def test_wrong_authorisation_is_a_wrong_master_password_and_costs_a_guess(fake, backend):
    made, secret = enroll(backend)
    with pytest.raises(AuthError, match="^wrong master password$") as caught:
        unseal(backend, made, OTHER_AUTH)
    assert type(caught.value) is AuthError
    assert fake.failed_tries == 1 and backend.lockout_status()["remaining_tries"] == 2
    assert unseal(backend, made) == secret, "the right value still works"
    assert fake.failed_tries == 1, "a success does not forgive a failure"


def test_repeated_wrong_authorisation_ends_in_lockout(fake, backend):
    made, _ = enroll(backend)
    for _ in range(3):
        with pytest.raises(AuthError, match="^wrong master password$"):
            unseal(backend, made, OTHER_AUTH)
    with pytest.raises(LockedOutError, match=r"3 failed attempts, limit 3.*at most 16 min 40 s"):
        unseal(backend, made, OTHER_AUTH)
    with pytest.raises(LockedOutError):
        unseal(backend, made)
    assert fake.failed_tries == 3, "attempts made during lockout are not counted"
    status = backend.lockout_status()
    assert status["in_lockout"] and status["remaining_tries"] == 0 and status["seconds_until_retry"] == 1000


def test_unseal_of_an_index_this_tpm_does_not_have(fake, backend):
    with pytest.raises(HardwareError, match=r"NV index 0x018abcde is not defined.*recovery key") as caught:
        unseal(backend, descriptor())
    assert not isinstance(caught.value, AuthError)
    assert fake.failed_tries == 0


def test_unseal_of_an_index_that_was_never_written(fake, backend):
    fake.define(INDEX, data=None)
    with pytest.raises(HardwareError, match="never written"):
        unseal(backend, descriptor())


def test_unseal_refuses_a_short_answer(fake, backend):
    made, _ = enroll(backend)
    fake.once("tpm2_nvread", lambda arguments: succeeded("tpm2_nvread", filled=False))
    with pytest.raises(HardwareError, match="malformed device secret"):
        unseal(backend, made)


def test_secret_buffer_is_wiped_when_unsealing_fails(fake, backend, monkeypatch):
    made, _ = enroll(backend)
    created: List[SecureBuffer] = []
    original = SecureBuffer.__init__

    def remember(self: SecureBuffer, size: int) -> None:
        original(self, size)
        created.append(self)

    monkeypatch.setattr(SecureBuffer, "__init__", remember)
    with buffer(OTHER_AUTH) as wrong, pytest.raises(AuthError):
        backend.unseal(made, auth=wrong, interactive=False, reason="test")
    assert created and all(made_buffer.wiped for made_buffer in created)


# ---------------------------------------------------------------------------
# Enrolment that fails part-way must leave nothing behind
# ---------------------------------------------------------------------------


def assert_nothing_left(fake: FakeTpm) -> None:
    assert fake.handles() == set()
    assert registry() == []


def test_failed_write_removes_the_index(fake, backend):
    fake.once("tpm2_nvwrite", lambda arguments: failed("nvwrite_too_long"))
    with pytest.raises(HardwareError, match="larger than the defined space"):
        enroll(backend)
    assert_nothing_left(fake)
    assert fake.calls[-2][0] == "tpm2_nvundefine" and fake.calls[-1][0] == "tpm2_nvreadpublic", "erasure is confirmed"


def test_enrolment_during_lockout_removes_the_index(fake, backend):
    fake.failed_tries = 3
    with pytest.raises(LockedOutError, match="at most 16 min 40 s"):
        enroll(backend)
    assert_nothing_left(fake)


def test_read_back_that_differs_removes_the_index(fake, backend):
    fake.once("tpm2_nvread", lambda arguments: succeeded("tpm2_nvread", filled=True))  # 32 bytes, but not ours
    with pytest.raises(HardwareError, match="different bytes"):
        enroll(backend)
    assert_nothing_left(fake)


def test_read_back_that_is_malformed_removes_the_index(fake, backend):
    fake.once("tpm2_nvread", lambda arguments: succeeded("tpm2_nvread", filled=False))
    with pytest.raises(HardwareError, match="malformed device secret"):
        enroll(backend)
    assert_nothing_left(fake)


@pytest.mark.parametrize(
    "attributes, size",
    [(["authwrite", "authread", "no_da"], 32), (["authwrite", "authread"], 64), (["ownerwrite", "ownerread"], 32)],
)
def test_index_created_with_the_wrong_shape_is_removed_unused(attributes, size, fake, backend):
    """If the TPM (or a changed tool) did not create what was asked for, no secret is written into it."""
    fake.once("tpm2_nvreadpublic", lambda arguments: None)
    fake.once(
        "tpm2_nvreadpublic",
        lambda arguments: succeeded("tpm2_nvreadpublic", public_area(arguments[0], attributes, size)),
    )
    with pytest.raises(HardwareError, match="did not create the NV index as requested"):
        enroll(backend)
    assert_nothing_left(fake)
    assert "tpm2_nvwrite" not in [call[0] for call in fake.calls]


def test_owner_password_stops_enrolment_with_the_remedy(fake, backend):
    fake.owner_auth_set = True
    with pytest.raises(HardwareError, match="tpm2_changeauth -c owner -p") as caught:
        enroll(backend)
    assert not isinstance(caught.value, AuthError)
    assert_nothing_left(fake)


def test_full_nv_storage_stops_enrolment(fake, backend):
    fake.once("tpm2_nvdefine", lambda arguments: failed("nvdefine_nv_space"))
    with pytest.raises(HardwareError, match="no free NV storage"):
        enroll(backend)
    assert_nothing_left(fake)


def test_define_that_dies_after_the_tpm_acted_is_cleaned_up(fake, backend):
    """The tool timed out, but the TPM had already created the index: it has our shape, so it is removed."""

    def create_then_die(arguments: List[str]) -> linux_tpm._Result:
        with buffer(AUTH) as auth:
            fake.tpm2_nvdefine(arguments, auth=auth, auth_option="-p", data=None, secret_out=None)
        raise HardwareError("tpm2_nvdefine did not finish within 30 seconds; the TPM is not responding")

    fake.once("tpm2_nvdefine", create_then_die)
    with pytest.raises(HardwareError, match="did not finish"):
        enroll(backend)
    assert_nothing_left(fake)


def test_define_that_dies_with_the_tpm_gone_keeps_the_registry_entry(fake, backend):
    """Nobody can tell whether the index exists, so the record stays for destroy_all to settle."""

    def die(arguments: List[str]) -> linux_tpm._Result:
        fake.unreachable = True
        raise HardwareError("tpm2_nvdefine did not finish within 30 seconds; the TPM is not responding")

    fake.once("tpm2_nvdefine", die)
    with pytest.raises(HardwareError, match="did not finish"):
        enroll(backend)
    assert len(registry()) == 1
    fake.unreachable = False
    assert backend.destroy_all() == 0
    assert_nothing_left(fake)


def test_interrupt_during_enrolment_still_cleans_up(fake, backend):
    def interrupt(arguments: List[str]) -> linux_tpm._Result:
        raise KeyboardInterrupt

    fake.once("tpm2_nvwrite", interrupt)
    with pytest.raises(KeyboardInterrupt):
        enroll(backend)
    assert_nothing_left(fake)


def test_secret_is_wiped_when_enrolment_fails(fake, backend, monkeypatch):
    made_buffers: List[SecureBuffer] = []
    original = vars(SecureBuffer)["random"].__func__

    def remember(cls: Any, size: int) -> SecureBuffer:
        made_buffer = original(cls, size)
        made_buffers.append(made_buffer)
        return made_buffer

    monkeypatch.setattr(SecureBuffer, "random", classmethod(remember))
    fake.once("tpm2_nvwrite", lambda arguments: failed("nvwrite_too_long"))
    with buffer(AUTH) as auth, pytest.raises(HardwareError):
        backend.enroll(policy=POLICY_DEVICE, auth=auth, reason="test")
    assert len(made_buffers) == 1 and made_buffers[0].wiped


def choose_indices(monkeypatch: pytest.MonkeyPatch, *indices: str) -> None:
    """Make the next enrolments try these handles, in order."""
    queue = list(indices)
    monkeypatch.setattr(linux_tpm, "_random_index", lambda: queue.pop(0) if len(queue) > 1 else queue[0])


def test_taken_handle_is_skipped(fake, backend, monkeypatch):
    fake.define("0x01900001", attributes="ownerwrite|ownerread", size=8)
    choose_indices(monkeypatch, "0x01900001", "0x01900002")
    made, secret = enroll(backend)
    assert made["nv_index"] == "0x01900002" and unseal(backend, made) == secret
    assert fake.handles() == {"0x01900001", "0x01900002"}
    assert registry() == ["0x01900002"]
    assert "tpm2_nvdefine" not in [call[0] for call in fake.calls if "0x01900001" in call]


def test_handle_lost_in_a_race_is_never_deleted(fake, backend, monkeypatch):
    """Another IronDome defined the same handle between our check and our define. It is theirs."""
    fake.define("0x01900001", auth=OTHER_AUTH)
    choose_indices(monkeypatch, "0x01900001", "0x01900002")
    fake.once("tpm2_nvreadpublic", lambda arguments: failed("nvreadpublic_missing"))
    made, _ = enroll(backend)
    assert made["nv_index"] == "0x01900002"
    assert fake.handles() == {"0x01900001", "0x01900002"}
    assert fake.indices[0x01900001]["auth"] == OTHER_AUTH and fake.indices[0x01900001]["data"] == SECRET
    assert registry() == ["0x01900002"]
    assert ["tpm2_nvundefine", "0x01900001", "-C", "o"] not in fake.calls


def test_handle_already_in_the_registry_is_not_reused(fake, backend, monkeypatch):
    linux_tpm._save_registry(["0x01900001"])
    choose_indices(monkeypatch, "0x01900001", "0x01900002")
    made, _ = enroll(backend)
    assert made["nv_index"] == "0x01900002"
    assert registry() == ["0x01900001", "0x01900002"]


def test_enrolment_gives_up_when_no_handle_is_free(fake, backend, monkeypatch):
    fake.define("0x01900001", attributes="ownerwrite|ownerread", size=8)
    choose_indices(monkeypatch, "0x01900001")
    with pytest.raises(HardwareError, match="could not find a free TPM NV index"):
        enroll(backend)
    assert [call[0] for call in fake.calls] == ["tpm2_nvreadpublic"] * 8
    assert registry() == [] and fake.handles() == {"0x01900001"}


# ---------------------------------------------------------------------------
# Destruction, against the FakeTpm
# ---------------------------------------------------------------------------


def test_destroy_makes_unseal_impossible_and_confirms_with_the_tpm(fake, backend):
    made, _ = enroll(backend)
    fake.calls.clear()
    backend.destroy(made)
    index = made["nv_index"]
    assert fake.calls == [
        ["tpm2_nvreadpublic", index],
        ["tpm2_nvundefine", index, "-C", "o"],
        ["tpm2_nvreadpublic", index],
    ]
    assert_nothing_left(fake)
    assert not backend.exists(made)
    with pytest.raises(HardwareError, match="recovery key"):
        unseal(backend, made)
    backend.destroy(made)


def test_destroy_fails_loudly_when_the_index_survives(fake, backend):
    made, _ = enroll(backend)
    fake.once("tpm2_nvundefine", lambda arguments: succeeded("tpm2_nvundefine"))
    with pytest.raises(HardwareError, match="still present after deletion"):
        backend.destroy(made)
    assert backend.exists(made) and registry() == [made["nv_index"]]


def test_destroy_with_an_owner_password_set_fails_with_the_remedy(fake, backend):
    made, _ = enroll(backend)
    fake.owner_auth_set = True
    with pytest.raises(HardwareError, match="tpm2_changeauth -c owner -p"):
        backend.destroy(made)
    assert backend.exists(made) and registry() == [made["nv_index"]]


def test_destroy_with_the_tpm_unreachable_fails_and_keeps_the_record(fake, backend):
    made, _ = enroll(backend)
    fake.unreachable = True
    with pytest.raises(HardwareError, match="Cannot connect"):
        backend.destroy(made)
    with pytest.raises(HardwareError):
        backend.exists(made)
    assert registry() == [made["nv_index"]]


def test_destroy_forgets_a_recorded_index_that_is_already_gone(fake, backend):
    linux_tpm._save_registry([INDEX, "0x01900002"])
    backend.destroy(descriptor())
    assert registry() == ["0x01900002"]
    assert "tpm2_nvundefine" not in [call[0] for call in fake.calls]


def test_destroy_removes_an_unrecorded_index_that_has_our_shape(fake, backend):
    """The registry was lost with the device directory; the vault's own key can still be erased."""
    fake.define(INDEX)
    backend.destroy(descriptor())
    assert fake.handles() == set()


@pytest.mark.parametrize(
    "attributes, size",
    [
        ("ownerwrite|ownerread", 32),
        ("authwrite|authread|no_da", 32),
        ("authwrite|authread", 64),
        ("authwrite|authread|policydelete", 32),
        ("ppwrite|ppread", 8),
    ],
)
def test_destroy_refuses_an_index_that_is_not_ours(attributes, size, fake, backend):
    """A vault file can be edited to point at another program's NV index; it must survive."""
    fake.define(INDEX, attributes=attributes, size=size)
    with pytest.raises(HardwareError, match=r"refusing to delete it.*tpm2_nvundefine 0x018abcde -C o"):
        backend.destroy(descriptor())
    assert fake.handles() == {INDEX}
    assert "tpm2_nvundefine" not in [call[0] for call in fake.calls]


def test_destroy_removes_a_recorded_index_whatever_it_looks_like(fake, backend):
    """What this installation created is erased even if its public area cannot be recognised."""
    made, _ = enroll(backend)
    fake.indices[int(made["nv_index"], 16)]["attributes"] = ["something", "unknown"]
    backend.destroy(made)
    assert_nothing_left(fake)


def test_destroy_works_around_a_damaged_registry(fake, backend):
    fake.define(INDEX)
    damaged = write_registry(b"not a registry")
    backend.destroy(descriptor())
    assert fake.handles() == set()
    assert damaged.read_bytes() == b"not a registry"
    fake.define(INDEX, attributes="ownerwrite|ownerread")
    with pytest.raises(HardwareError, match="refusing to delete it"):
        backend.destroy(descriptor())


def test_exists_asks_the_tpm_and_raises_rather_than_guess(fake, backend):
    assert backend.exists(descriptor()) is False
    fake.define(INDEX)
    assert backend.exists(descriptor()) is True
    fake.unreachable = True
    with pytest.raises(HardwareError, match="Cannot connect"):
        backend.exists(descriptor())


def test_destroy_all_without_a_registry_touches_nothing(backend, monkeypatch):
    monkeypatch.setattr(linux_tpm, "_run", explode)
    assert backend.destroy_all() == 0
    assert not paths.device_dir().exists()


def test_destroy_all_erases_what_this_installation_created_and_nothing_else(fake, backend):
    made = [enroll(backend)[0] for _ in range(3)]
    fake.define("0x01900009", attributes="ownerwrite|ownerread", size=8)
    fake.define("0x0190000a", auth=OTHER_AUTH)
    backend.destroy(made[0])
    assert backend.destroy_all() == 2
    assert fake.handles() == {"0x01900009", "0x0190000a"}, "indices of other programs and other installations stay"
    assert registry() == []
    assert not any(backend.exists(item) for item in made)
    assert backend.destroy_all() == 0


def test_destroy_all_drops_records_of_indices_that_are_already_gone(fake, backend):
    made, _ = enroll(backend)
    linux_tpm._save_registry(registry() + ["0x01900001", "0x01900002"])
    assert backend.destroy_all() == 1
    assert_nothing_left(fake)
    assert made["nv_index"] not in fake.handles()


def test_destroy_all_raises_when_any_key_survives_and_keeps_its_record(fake, backend):
    made = [enroll(backend)[0] for _ in range(2)]
    fake.owner_auth_set = True
    with pytest.raises(HardwareError, match=r"2 TPM device key\(s\) could not be erased.*owner password"):
        backend.destroy_all()
    assert registry() == sorted(item["nv_index"] for item in made)
    assert all(backend.exists(item) for item in made)
    fake.owner_auth_set = False
    assert backend.destroy_all() == 2
    assert_nothing_left(fake)


def test_destroy_all_carries_on_past_a_failure(fake, backend):
    made = sorted(enroll(backend)[0]["nv_index"] for _ in range(3))
    fake.once("tpm2_nvundefine", lambda arguments: failed("nvundefine_owner_auth_set"))
    with pytest.raises(HardwareError, match=rf"1 TPM device key\(s\) could not be erased \({made[0]}: "):
        backend.destroy_all()
    assert registry() == [made[0]] and fake.handles() == {made[0]}


def test_destroy_all_with_the_tpm_unreachable_raises_and_keeps_every_record(fake, backend):
    made = sorted(enroll(backend)[0]["nv_index"] for _ in range(5))
    fake.unreachable = True
    with pytest.raises(HardwareError, match=r"5 TPM device key\(s\) could not be erased.*and 2 more"):
        backend.destroy_all()
    assert registry() == made


@settings(PROPERTY, max_examples=30)
@given(
    st.lists(st.sampled_from(["enroll", "destroy", "destroy_all", "wrong", "lose_registry", "foreign"]), max_size=12)
)
def test_registry_and_tpm_stay_in_step_through_any_sequence(steps):
    """Whatever is done, the TPM holds exactly the keys that are still alive, plus what was never ours."""
    with pytest.MonkeyPatch.context() as patch:
        tpm = FakeTpm()
        tpm.max_tries = 1000
        patch.setattr(linux_tpm, "_run", tpm.run)
        shutil.rmtree(paths.device_dir(), ignore_errors=True)
        backend = Tpm2Backend()
        alive: Dict[str, Tuple[Dict[str, Any], bytes]] = {}
        untracked: Set[str] = set()
        foreign: Set[str] = set()
        for step in steps:
            if step == "enroll":
                made, secret = enroll(backend)
                alive[made["nv_index"]] = (made, secret)
            elif step == "destroy" and alive:
                index = sorted(alive)[0]
                backend.destroy(alive.pop(index)[0])
                untracked.discard(index)
            elif step == "destroy_all":
                expected = len(set(alive) - untracked)
                assert backend.destroy_all() == expected
                for index in set(alive) - untracked:
                    del alive[index]
            elif step == "wrong" and alive:
                with pytest.raises(AuthError):
                    unseal(backend, alive[sorted(alive)[0]][0], OTHER_AUTH)
            elif step == "lose_registry":
                shutil.rmtree(paths.device_dir(), ignore_errors=True)
                untracked |= set(alive)
            elif step == "foreign":
                index = f"0x01a{len(foreign):05x}"
                tpm.define(index, attributes="ownerwrite|ownerread", size=8)
                foreign.add(index)
            assert tpm.handles() == set(alive) | foreign
            assert set(registry()) == set(alive) - untracked
            for made, secret in alive.values():
                assert unseal(backend, made) == secret


# ---------------------------------------------------------------------------
# A device key that needs no password (auth=None), against the FakeTpm
# ---------------------------------------------------------------------------


def test_device_key_without_a_password_has_an_empty_authorisation_and_no_dictionary_protection(fake, backend):
    made, secret = enroll_open(backend)
    assert set(made) == {"backend", "policy", "ref", "nv_index"}, "the same descriptor as a keyslot's"
    assert (made["backend"], made["policy"]) == ("linux-tpm2", "device")
    assert len(secret) == DEVICE_SECRET_LEN and secret != bytes(DEVICE_SECRET_LEN)
    stored = fake.indices[int(made["nv_index"], 16)]
    assert stored["auth"] == b"" and stored["data"] == secret
    assert sorted(stored["attributes"]) == ["authread", "authwrite", "no_da", "written"]
    assert registry() == [made["nv_index"]] and backend.exists(made)
    assert unseal_open(backend, made) == secret
    assert fake.failed_tries == 0


def test_device_key_without_a_password_is_made_and_read_with_no_authorisation_option(fake, backend):
    made, _ = enroll_open(backend)
    index = made["nv_index"]
    assert fake.calls == [
        ["tpm2_nvreadpublic", index],
        ["tpm2_nvdefine", index, "-C", "o", "-s", "32", "-a", "authread|authwrite|no_da"],
        ["tpm2_nvreadpublic", index],
        ["tpm2_nvwrite", index, "-C", index],
        ["tpm2_nvread", index, "-C", index, "-s", "32"],
    ]
    fake.calls.clear()
    unseal_open(backend, made)
    assert fake.calls == [["tpm2_nvreadpublic", index], ["tpm2_nvread", index, "-C", index, "-s", "32"]]


def test_tools_for_a_device_key_without_a_password_are_handed_no_authorisation(fake, backend, monkeypatch):
    seen: List[Tuple[str, bool]] = []
    real = fake.run

    def watch(tool: str, arguments: Sequence[str], **given: Any) -> linux_tpm._Result:
        seen.append((tool, given.get("auth") is not None))
        return real(tool, arguments, **given)

    monkeypatch.setattr(linux_tpm, "_run", watch)
    made, _ = enroll_open(backend)
    unseal_open(backend, made)
    backend.destroy(made)
    assert seen and not any(with_auth for _, with_auth in seen)


def test_an_empty_authorisation_is_never_presented_to_a_password_keyslots_index(fake, backend):
    """It would be a wrong guess the TPM counts. The TPM is asked what the index is first, and nothing is read."""
    keyslot, secret = enroll(backend)
    fake.calls.clear()
    with pytest.raises(VaultError, match="is not a device key that needs no password"):
        unseal_open(backend, keyslot)
    assert fake.calls == [["tpm2_nvreadpublic", keyslot["nv_index"]]]
    assert fake.failed_tries == 0 and unseal(backend, keyslot) == secret


@pytest.mark.parametrize(
    "attributes, size",
    [("authwrite|authread", 32), ("authwrite|authread|no_da", 64), ("ownerwrite|ownerread|no_da", 32)],
)
def test_a_recorded_index_of_any_other_shape_is_not_read_without_a_password(attributes, size, fake, backend):
    fake.define(INDEX, attributes=attributes, size=size, auth=b"")
    linux_tpm._save_registry([INDEX])
    with pytest.raises(VaultError, match="not a device key that needs no password"):
        unseal_open(backend, descriptor())
    assert "tpm2_nvread" not in [call[0] for call in fake.calls] and fake.failed_tries == 0


def test_an_index_this_installation_did_not_make_is_not_read_without_a_password(backend, monkeypatch, tmp_path):
    """Another account's or another program's index, or a descriptor someone edited: no tool is even run."""
    monkeypatch.setattr(linux_tpm, "_run", explode)
    with pytest.raises(HardwareError, match=r"0x018abcde was not created by this IronDome installation"):
        unseal_open(backend, descriptor())
    linux_tpm._save_registry(["0x01900001"])
    with pytest.raises(HardwareError, match="not created by this IronDome installation"):
        unseal_open(backend, descriptor())


def test_a_damaged_registry_refuses_the_read_as_a_hardware_error(backend, monkeypatch):
    monkeypatch.setattr(linux_tpm, "_run", explode)
    write_registry(b"not a registry")
    with pytest.raises(HardwareError, match="registry .* is damaged") as caught:
        unseal_open(backend, descriptor())
    assert not isinstance(caught.value, VaultError), "the descriptor is fine; the registry is not"


def test_a_device_key_without_a_password_that_is_gone_says_so(fake, backend):
    made, _ = enroll_open(backend)
    del fake.indices[int(made["nv_index"], 16)]
    with pytest.raises(HardwareError, match=r"does not hold that device key \(NV index 0x[0-9a-f]{8} is not defined\)"):
        unseal_open(backend, made)
    assert not backend.exists(made) and fake.failed_tries == 0


def test_an_index_replaced_between_the_check_and_the_read_is_still_no_wrong_password(fake, backend):
    made, _ = enroll_open(backend)
    fake.once("tpm2_nvread", lambda arguments: failed("nvread_wrong_auth_no_da"))
    with pytest.raises(HardwareError, match="does not open with an empty authorisation") as caught:
        unseal_open(backend, made)
    assert not isinstance(caught.value, AuthError)


def test_device_key_without_a_password_is_read_while_the_tpm_is_in_lockout(fake, backend):
    keyslot, _ = enroll(backend)
    made, secret = enroll_open(backend)
    for _ in range(3):
        with pytest.raises(AuthError):
            unseal(backend, keyslot, OTHER_AUTH)
    with pytest.raises(LockedOutError):
        unseal(backend, keyslot)
    assert unseal_open(backend, made) == secret, "sessions and grants do not stop when someone spent the guesses"
    assert fake.failed_tries == 3


def test_a_password_presented_to_a_device_key_without_one_is_refused_and_costs_no_guess(fake, backend):
    """The password path is unchanged: what the TPM refuses is a wrong master password, and no_da counts nothing."""
    made, _ = enroll_open(backend)
    with pytest.raises(AuthError, match="^wrong master password$"):
        unseal(backend, made, AUTH)
    assert fake.failed_tries == 0


def test_failed_enrolment_without_a_password_leaves_nothing_behind(fake, backend):
    fake.once("tpm2_nvwrite", lambda arguments: failed("nvwrite_too_long"))
    with pytest.raises(HardwareError, match="larger than the defined space"):
        enroll_open(backend)
    assert_nothing_left(fake)


def test_define_without_a_password_that_dies_after_the_tpm_acted_is_cleaned_up(fake, backend):
    def create_then_die(arguments: List[str]) -> linux_tpm._Result:
        fake.tpm2_nvdefine(arguments, auth=None, auth_option="-p", data=None, secret_out=None)
        raise HardwareError("tpm2_nvdefine did not finish within 30 seconds; the TPM is not responding")

    fake.once("tpm2_nvdefine", create_then_die)
    with pytest.raises(HardwareError, match="did not finish"):
        enroll_open(backend)
    assert_nothing_left(fake)


def test_index_created_without_dictionary_protection_for_a_keyslot_is_removed_unused(fake, backend):
    """And the other way round: each kind of enrolment insists on its own shape."""
    fake.once("tpm2_nvreadpublic", lambda arguments: None)
    fake.once(
        "tpm2_nvreadpublic",
        lambda arguments: succeeded("tpm2_nvreadpublic", public_area(arguments[0], ["authwrite", "authread"], 32)),
    )
    with pytest.raises(HardwareError, match=r"as requested \(authread\|authwrite\|no_da, 32 bytes\)"):
        enroll_open(backend)
    assert_nothing_left(fake)


def test_device_keys_without_a_password_are_destroyed_like_any_other(fake, backend):
    first, _ = enroll_open(backend)
    second, _ = enroll_open(backend)
    keyslot, _ = enroll(backend)
    backend.destroy(first)
    assert not backend.exists(first)
    with pytest.raises(HardwareError, match="not created by this IronDome installation"):
        unseal_open(backend, first)
    assert backend.destroy_all() == 2
    assert_nothing_left(fake)
    assert not backend.exists(second) and not backend.exists(keyslot)


def test_an_unrecorded_index_without_dictionary_protection_is_not_destroyed(fake, backend):
    """After its registry was lost it may as well be another program's: it is left for the owner to remove."""
    made, _ = enroll_open(backend)
    shutil.rmtree(paths.device_dir())
    with pytest.raises(HardwareError, match="refusing to delete it"):
        backend.destroy(made)
    assert backend.exists(made)


# ---------------------------------------------------------------------------
# The kernel on top of the backend, against the FakeTpm
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_backend_selected(fake, monkeypatch):
    """``choose_backend`` picks the TPM backend, which talks to the FakeTpm."""
    from irondome.device.base import Probe

    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "linux-tpm2")
    monkeypatch.setattr(Tpm2Backend, "probe", lambda self: Probe("linux-tpm2", True, True, False, "FakeTpm"))
    device._instances.clear()
    return fake


def test_vault_on_the_tpm_backend_needs_password_and_chip(fake_backend_selected, make_vault):
    from conftest import PASSWORD, secret
    from irondome.unlock import open_vault
    from irondome.vault import Secret, VaultFile

    fake = fake_backend_selected
    vault, recovery = make_vault()
    vault.add("github", Secret(password="hunter2"))
    vault.commit()
    vault.close()
    slot = VaultFile.load().slots[0]
    assert slot.backend_name == "linux-tpm2" and slot.describe() == "master password + device key (linux-tpm2)"
    assert fake.handles() == {slot.device["nv_index"]} == set(registry())
    with secret(PASSWORD) as password, open_vault(password=password, interactive=False) as opened:
        assert opened.value(opened.find("github")) == "hunter2"
    with secret("not the password") as password, pytest.raises(AuthError, match="^wrong master password$"):
        open_vault(password=password, interactive=False)
    assert fake.failed_tries == 1, "the chip, not IronDome, judged the guess"
    assert keys.destroy_slot_device(slot) is True
    with secret(PASSWORD) as password, pytest.raises(HardwareError, match="recovery key"):
        open_vault(password=password, interactive=False)
    open_vault(recovery_key=recovery).close()
    assert_nothing_left(fake)


def test_vault_creation_that_fails_leaves_no_key_in_the_tpm(fake_backend_selected, make_vault, monkeypatch):
    from irondome.vault import Vault

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise VaultError("disk full")

    monkeypatch.setattr(Vault, "create", refuse)
    with pytest.raises(VaultError, match="disk full"):
        make_vault()
    assert_nothing_left(fake_backend_selected)


def test_lockout_reaches_the_caller_of_unlock(fake_backend_selected, make_vault):
    from conftest import PASSWORD, secret
    from irondome.unlock import open_vault

    vault, _ = make_vault(with_recovery=False)
    vault.close()
    for _ in range(3):
        with secret("a wrong guess") as password, pytest.raises(AuthError, match="^wrong master password$"):
            open_vault(password=password, interactive=False)
    with secret(PASSWORD) as password, pytest.raises(LockedOutError, match="at most 16 min 40 s"):
        open_vault(password=password, interactive=False)


# ---------------------------------------------------------------------------
# probe()
# ---------------------------------------------------------------------------


@pytest.fixture
def pretend_linux(monkeypatch, tmp_path) -> Path:
    """Make ``probe`` believe this is a Linux machine with tpm2-tools installed and a transport configured."""
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in linux_tpm._TOOLS:
        (tools / name).write_text("#!/bin/sh\nexit 0\n")
        (tools / name).chmod(0o755)
    monkeypatch.setattr(linux_tpm, "_on_linux", lambda: True)
    monkeypatch.setattr(linux_tpm, "_memfd_create", lambda: lambda name, flags: -1)
    monkeypatch.setattr(linux_tpm, "_SAFE_PATH", str(tools))
    monkeypatch.setenv("TPM2TOOLS_TCTI", "swtpm:path=/run/irondome-test/sock")
    return tools


@pytest.mark.parametrize("platform", ["darwin", "win32", "freebsd14", "cygwin"])
def test_probe_elsewhere_than_linux(platform, backend, monkeypatch):
    monkeypatch.setattr(sys, "platform", platform)
    monkeypatch.setattr(linux_tpm, "_run", explode)
    found = backend.probe()
    assert (found.name, found.available, found.hardware, found.biometry, found.detail) == (
        "linux-tpm2",
        False,
        True,
        False,
        "not Linux",
    )


def test_probe_of_a_simulator_says_it_is_software(fake, backend, pretend_linux):
    found = backend.probe()
    assert found.available and found.name == "linux-tpm2" and not found.biometry
    assert found.hardware is False, "a simulator must never be reported as a security chip"
    assert found.detail == (
        "TPM 2.0 simulator (IBM SW TPM) reached through swtpm:path=/run/irondome-test/sock: "
        "software, not a security chip; locks after 3 wrong passwords"
    )


@pytest.mark.parametrize("tcti", ["device:/dev/tpmrm0", "tabrmd:bus_type=system", "device:/dev/tpm0"])
def test_probe_of_a_device_transport(tcti, fake, backend, pretend_linux, monkeypatch):
    monkeypatch.setenv("TPM2TOOLS_TCTI", tcti)
    found = backend.probe()
    assert (found.available, found.hardware, found.biometry) == (True, True, False)
    assert found.detail == "TPM 2.0 (IBM SW TPM); locks after 3 wrong passwords"


def test_probe_only_reads_properties_and_creates_nothing(fake, backend, pretend_linux):
    fake.define(INDEX)
    assert backend.probe().available
    assert fake.calls == [["tpm2_getcap", "properties-variable"], ["tpm2_getcap", "properties-fixed"]]
    assert fake.handles() == {INDEX}
    assert not paths.device_dir().exists()


def test_probe_uses_the_kernel_device_when_no_transport_is_configured(fake, backend, pretend_linux, monkeypatch):
    monkeypatch.delenv("TPM2TOOLS_TCTI")
    monkeypatch.setattr(linux_tpm, "_DEVICE_NODE", "/dev/null")
    found = backend.probe()
    assert found.available and found.hardware
    monkeypatch.setattr(linux_tpm, "_DEVICE_NODE", str(paths.home() / "no-such-device"))
    fake.calls.clear()
    found = backend.probe()
    assert not found.available and "has no TPM 2.0 device" in found.detail
    assert fake.calls == [], "no tool is run when there is no device to talk to"


def test_probe_understands_tpm2_tools_4(fake, backend, pretend_linux):
    fake.permanent_group = "TPM2_PT_PERSISTENT"
    assert backend.probe().available
    fake.owner_auth_set = True
    found = backend.probe()
    assert not found.available and "owner password" in found.detail


def test_probe_with_an_owner_password_gives_the_remedy(fake, backend, pretend_linux):
    fake.owner_auth_set = True
    found = backend.probe()
    assert not found.available
    assert found.detail.endswith("Clear it with: tpm2_changeauth -c owner -p <owner password>")
    assert fake.calls == [["tpm2_getcap", "properties-variable"]]


def test_probe_says_when_the_tpm_does_not_limit_guesses(fake, backend, pretend_linux):
    fake.interval = 0
    found = backend.probe()
    assert found.available
    assert "dictionary-attack protection is switched off, so it does not limit password guesses" in found.detail
    assert "locks after" not in found.detail


def test_probe_of_a_tpm_that_refuses_every_password(fake, backend, pretend_linux):
    fake.max_tries = 0
    found = backend.probe()
    assert not found.available
    assert "limit is zero" in found.detail and "tpm2_dictionarylockout --setup-parameters --max-tries=" in found.detail


def test_probe_of_an_unreachable_tpm(fake, backend, pretend_linux):
    fake.unreachable = True
    found = backend.probe()
    assert not found.available and found.hardware
    assert found.detail.startswith("cannot use the TPM through swtpm:path=/run/irondome-test/sock: ")
    assert "Cannot connect to swtpm TPM socket" in found.detail


def test_probe_with_output_it_cannot_read(fake, backend, pretend_linux):
    fake.once("tpm2_getcap", lambda arguments: succeeded("tpm2_getcap", b"TPM_PT_PERMANENT: 0x00000000\n"))
    found = backend.probe()
    assert not found.available and "tpm2-tools older than 4.1" in found.detail


def test_probe_names_the_missing_tools_and_how_to_get_them(backend, pretend_linux, monkeypatch):
    monkeypatch.setattr(linux_tpm, "_run", explode)
    (pretend_linux / "tpm2_nvread").unlink()
    (pretend_linux / "tpm2_getcap").chmod(0o644)
    found = backend.probe()
    assert not found.available
    assert "tpm2-tools is not installed (tpm2_getcap, tpm2_nvread not found)" in found.detail
    assert "sudo apt install tpm2-tools" in found.detail and "sudo dnf install tpm2-tools" in found.detail


def test_probe_without_memfd_support(backend, pretend_linux, monkeypatch):
    monkeypatch.setattr(linux_tpm, "_run", explode)
    monkeypatch.setattr(linux_tpm, "_memfd_create", lambda: None)
    found = backend.probe()
    assert not found.available and "memfd_create" in found.detail


def test_probe_without_a_descriptor_directory(backend, pretend_linux, monkeypatch):
    monkeypatch.setattr(linux_tpm, "_run", explode)
    monkeypatch.setattr(linux_tpm, "_FD_DIRECTORY", str(pretend_linux / "no-dev-fd"))
    found = backend.probe()
    assert not found.available and "is /proc mounted?" in found.detail


def test_probe_detail_is_printable_whatever_the_transport_is_called(fake, backend, pretend_linux, monkeypatch):
    monkeypatch.setenv("TPM2TOOLS_TCTI", "swtpm:path=/tmp/\x1b[31m\u00e9vil\nsock" + "x" * 500)
    for unreachable in (False, True):
        fake.unreachable = unreachable
        detail = backend.probe().detail
        assert all(" " <= char <= "~" for char in detail) and len(detail) < 700


def test_probe_never_raises(backend, pretend_linux, monkeypatch):
    for error in (HardwareError("the helper broke"), VaultError("odd"), AuthError("odd")):

        def fail(*args: Any, _error: IronDomeError = error, **kwargs: Any) -> Any:
            raise _error

        monkeypatch.setattr(linux_tpm, "_run", fail)
        found = backend.probe()
        assert not found.available and str(error) in found.detail


def test_choose_backend_takes_this_backend_only_when_it_can_work(fake, pretend_linux, monkeypatch):
    monkeypatch.setenv("IRONDOME_DEVICE_BACKEND", "linux-tpm2")
    device._instances.clear()
    assert isinstance(device.choose_backend(POLICY_DEVICE), Tpm2Backend)
    with pytest.raises(HardwareError, match="cannot enforce the biometry policy"):
        device.choose_backend(POLICY_BIOMETRY)
    fake.owner_auth_set = True
    with pytest.raises(HardwareError, match="linux-tpm2 is not available: .*owner password"):
        device.choose_backend(POLICY_DEVICE)


def test_device_node_problems_come_with_a_remedy(tmp_path, monkeypatch):
    assert "has no TPM 2.0 device" in linux_tpm._device_problem(str(tmp_path / "tpmrm0"))
    plain = tmp_path / "plain-file"
    plain.write_bytes(b"")
    assert linux_tpm._device_problem(str(plain)) == f"{plain} is not a device"
    assert linux_tpm._device_problem("/dev/null") is None
    monkeypatch.setattr(os, "access", lambda *args, **kwargs: False)
    assert linux_tpm._device_problem("/dev/null").startswith("no permission to use /dev/tpmrm0")


def test_permission_remedy_names_the_group_that_owns_the_device():
    assert linux_tpm._permission_remedy(0o020660, "tss") == (
        "no permission to use /dev/tpmrm0. Add your user to the tss group: sudo usermod -aG tss $USER, "
        "then log out and back in"
    )
    assert "sudo usermod -aG tpm $USER" in linux_tpm._permission_remedy(0o020660, "tpm")
    for mode, group in ((0o020600, "tss"), (0o020660, "root"), (0o020660, None), (0o020640, "tss")):
        remedy = linux_tpm._permission_remedy(mode, group)
        assert "only root may open" in remedy and "tpm-udev" in remedy and "sudo usermod -aG tss $USER" in remedy


@pytest.mark.parametrize(
    "tcti, simulated",
    [
        ("swtpm:path=/tmp/sock", True),
        ("swtpm", True),
        ("swtpm:host=127.0.0.1,port=2321", True),
        ("mssim:host=localhost,port=2321", True),
        ("libtpms", True),
        ("libtss2-tcti-swtpm.so.0:path=/tmp/sock", True),
        ("SWTPM:path=/tmp/sock", True),
        ("device:/dev/tpmrm0", False),
        ("device:/dev/swtpm0", False),
        ("tabrmd:bus_name=com.intel.tss2.Tabrmd", False),
        ("cmd:ssh host tpm2_send", False),
        ("", False),
    ],
)
def test_simulator_transports_are_recognised(tcti, simulated):
    assert linux_tpm._is_simulator(tcti) is simulated


# ---------------------------------------------------------------------------
# How the tools are found and what they are allowed to see
# ---------------------------------------------------------------------------


def test_tools_see_a_fixed_environment_and_a_pinned_transport(monkeypatch):
    for name, value in (
        ("TSS2_LOG", "all+trace"),
        ("TSS2_LOGFILE", "/tmp/tss.log"),
        ("TPM2TOOLS_ENABLE_ERRATA", "1"),
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("LD_LIBRARY_PATH", "/tmp"),
        ("PYTHONPATH", "/tmp"),
        ("PATH", "/tmp/evil:/usr/bin"),
        ("LANG", "de_DE.UTF-8"),
        ("IRONDOME_SESSION", "token"),
    ):
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("TPM2TOOLS_TCTI", "swtpm:path=/run/irondome-test/sock")
    assert linux_tpm._environment() == {
        "PATH": linux_tpm._SAFE_PATH,
        "LC_ALL": "C",
        "TPM2TOOLS_TCTI": "swtpm:path=/run/irondome-test/sock",
    }
    for unset in ("", None):
        if unset is None:
            monkeypatch.delenv("TPM2TOOLS_TCTI")
        else:
            monkeypatch.setenv("TPM2TOOLS_TCTI", unset)
        assert linux_tpm._environment()["TPM2TOOLS_TCTI"] == "device:/dev/tpmrm0", (
            "left to their defaults the tools try a simulator on localhost:2321"
        )


def test_tools_are_looked_up_in_system_directories_only():
    directories = linux_tpm._SAFE_PATH.split(":")
    assert directories[0] == "/usr/bin"
    assert all(directory.startswith("/") and ".." not in directory for directory in directories)
    assert not any(directory.startswith(("/home", "/tmp", "/var/tmp", "/Users")) for directory in directories)
    assert "" not in directories and "." not in directories


@pytest.fixture
def tool_directory(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "toolbin"
    directory.mkdir()
    monkeypatch.setattr(linux_tpm, "_SAFE_PATH", str(directory))
    return directory


def make_tool(directory: Path, name: str = "tpm2_nvread", mode: int = 0o755) -> Path:
    path = directory / name
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(mode)
    return path


def test_tool_path_is_absolute_and_ignores_the_callers_path(tool_directory, tmp_path, monkeypatch):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    make_tool(elsewhere, "tpm2_nvwrite")
    monkeypatch.setenv("PATH", f"{elsewhere}:{os.environ.get('PATH', '')}")
    tool = make_tool(tool_directory)
    assert linux_tpm._tool_path("tpm2_nvread") == str(tool)
    with pytest.raises(HardwareError, match="tpm2_nvwrite was not found.*Install tpm2-tools"):
        linux_tpm._tool_path("tpm2_nvwrite")


@pytest.mark.parametrize("mode", [0o757, 0o775, 0o777])
def test_tool_that_others_can_replace_is_not_run(mode, tool_directory):
    make_tool(tool_directory, mode=mode)
    with pytest.raises(HardwareError, match="writable by other users; refusing to run it"):
        linux_tpm._tool_path("tpm2_nvread")


def test_tool_reached_through_a_symlink_is_judged_by_its_target(tool_directory, tmp_path):
    target_directory = tmp_path / "real"
    target_directory.mkdir()
    target = make_tool(target_directory, "tpm2")
    (tool_directory / "tpm2_nvread").symlink_to(target)
    assert linux_tpm._tool_path("tpm2_nvread") == str(tool_directory / "tpm2_nvread")
    target.chmod(0o777)
    with pytest.raises(HardwareError, match="writable by other users"):
        linux_tpm._tool_path("tpm2_nvread")


@pytest.mark.skipif(not hasattr(os, "getuid") or os.getuid() == 0, reason="root may run anyone's tools")
def test_tool_owned_by_someone_else_is_not_run(tool_directory, monkeypatch):
    make_tool(tool_directory)
    monkeypatch.setattr(os, "getuid", lambda: 4_000_000)
    with pytest.raises(HardwareError, match="owned by another user; refusing to run it"):
        linux_tpm._tool_path("tpm2_nvread")


def test_nothing_runs_off_linux(backend, monkeypatch):
    monkeypatch.setattr(linux_tpm, "_on_linux", lambda: False)
    monkeypatch.setattr(linux_tpm, "_tool_path", explode)
    with pytest.raises(HardwareError, match="TPM of a Linux machine.*recovery key"):
        linux_tpm._run("tpm2_getcap", ["properties-variable"])
    with pytest.raises(HardwareError, match="TPM of a Linux machine.*recovery key"):
        unseal(backend, descriptor())
    with pytest.raises(HardwareError, match="TPM of a Linux machine"):
        backend.exists(descriptor())
    linux_tpm._save_registry([INDEX])
    with pytest.raises(HardwareError, match=r"1 TPM device key\(s\) could not be erased"):
        backend.destroy_all()
    assert registry() == [INDEX]


def test_concurrent_enrolments_lose_no_registry_entry(fake, backend):
    """The registry is read, changed and written under one lock."""
    import threading

    made: List[str] = []
    errors: List[BaseException] = []

    def work() -> None:
        try:
            for _ in range(5):
                made.append(enroll(backend)[0]["nv_index"])
        except BaseException as exc:  # reported below, in the main thread
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert errors == []
    assert len(set(made)) == 30
    assert registry() == sorted(made) and fake.handles() == set(made)


# ---------------------------------------------------------------------------
# Stand-in tools: how the real tools are run
# ---------------------------------------------------------------------------


def spellings(material: bytes) -> List[bytes]:
    """The forms in which key material could turn up in text."""
    lower = binascii.hexlify(material)
    encoded = base64.b64encode(material)
    return [material, lower, lower.upper(), encoded, encoded.rstrip(b"=")]


def octal(data: bytes) -> str:
    """*data* as the argument of a shell ``printf``."""
    return "".join(f"\\{byte:03o}" for byte in data)


RECORD = """#!/bin/sh
seen='@SEEN@'
/usr/bin/env > "$seen/env"
PATH=/usr/bin:/bin
printf '%s\\n' "$0" "$@" > "$seen/argv"
echo $$ >> "$seen/pids"
for argument in "$@"; do
    case "$argument" in
        file:/dev/fd/*)
            cat "${argument#file:}" > "$seen/auth"
            readlink "/proc/$$/fd/${argument#file:/dev/fd/}" > "$seen/auth-link"
            ;;
    esac
done
"""


class StandIns:
    """Shell scripts in place of the tpm2-tools binaries; each records how it was called."""

    def __init__(self, root: Path) -> None:
        self.bin = root / "bin"
        self.seen = root / "seen"
        self.bin.mkdir(parents=True)
        self.seen.mkdir()

    def tool(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(RECORD.replace("@SEEN@", str(self.seen)) + body + "\n")
        path.chmod(0o755)

    def saw(self, what: str) -> bytes:
        return (self.seen / what).read_bytes()

    def argv(self) -> List[str]:
        return self.saw("argv").decode("ascii").splitlines()

    def environment(self) -> Dict[str, str]:
        lines = self.saw("env").decode("ascii").splitlines()
        return dict(line.split("=", 1) for line in lines if "=" in line)


@pytest.fixture
def standins(tmp_path, monkeypatch) -> StandIns:
    tools = StandIns(tmp_path / "standins")
    monkeypatch.setattr(linux_tpm, "_SAFE_PATH", str(tools.bin))
    monkeypatch.setenv("TPM2TOOLS_TCTI", "swtpm:path=/run/irondome-test/sock")
    return tools


SHELL_VARIABLES = {"PWD", "OLDPWD", "SHLVL", "_"}


@needs_linux
def test_authorisation_value_reaches_the_tool_only_through_a_memory_file(standins, monkeypatch):
    for name, value in (("TSS2_LOG", "all+trace"), ("LD_PRELOAD", "/nonexistent.so"), ("IRONDOME_SESSION", "token")):
        monkeypatch.setenv(name, value)
    standins.tool("tpm2_nvread", f"printf '{octal(SECRET)}'")
    with buffer(AUTH) as auth, SecureBuffer(DEVICE_SECRET_LEN) as out:
        result = linux_tpm._run("tpm2_nvread", [INDEX, "-C", INDEX, "-s", "32"], auth=auth, secret_out=out)
        assert (result.status, result.filled, result.stdout, result.stderr) == (0, True, b"", b"")
        assert contents(out) == SECRET
    argv = standins.argv()
    assert argv[0] == str(standins.bin / "tpm2_nvread")
    assert argv[1:7] == [INDEX, "-C", INDEX, "-s", "32", "-P"]
    assert re.fullmatch(r"file:/dev/fd/\d+", argv[7]) and len(argv) == 8
    assert int(argv[7].rsplit("/", 1)[1]) > 2
    assert standins.saw("auth") == b"hex:" + binascii.hexlify(AUTH), "exactly the form tpm2-tools parse, no newline"
    assert standins.saw("auth-link").startswith(b"/memfd:irondome-tpm2"), "an anonymous memory file, not a path on disk"
    environment = standins.environment()
    assert set(environment) - SHELL_VARIABLES == {"PATH", "LC_ALL", "TPM2TOOLS_TCTI"}
    assert environment["LC_ALL"] == "C" and environment["PATH"] == str(standins.bin)
    assert environment["TPM2TOOLS_TCTI"] == "swtpm:path=/run/irondome-test/sock"
    told = standins.saw("argv") + standins.saw("env")
    assert not any(spelling in told for spelling in spellings(AUTH))


@needs_linux
def test_device_secret_reaches_the_tool_only_through_stdin(standins):
    standins.tool("tpm2_nvwrite", 'cat > "$seen/stdin"')
    with buffer(AUTH) as auth, buffer(SECRET) as data:
        result = linux_tpm._run("tpm2_nvwrite", [INDEX, "-C", INDEX], auth=auth, data=data)
    assert result.status == 0 and not result.filled
    assert standins.saw("stdin") == SECRET, "all of it, and then end of file"
    argv = standins.argv()
    assert argv[1:5] == [INDEX, "-C", INDEX, "-P"] and argv[6:] == ["-i", "-"]
    assert standins.saw("auth") == b"hex:" + binascii.hexlify(AUTH)
    told = standins.saw("argv") + standins.saw("env")
    assert not any(spelling in told for spelling in spellings(SECRET) + spellings(AUTH))


@needs_linux
def test_index_authorisation_for_a_new_index_uses_the_other_option(standins):
    standins.tool("tpm2_nvdefine", "exit 0")
    with buffer(AUTH) as auth:
        linux_tpm._run("tpm2_nvdefine", [INDEX, "-C", "o"], auth=auth, auth_option="-p")
    assert standins.argv()[1:5] == [INDEX, "-C", "o", "-p"]


@needs_linux
def test_tool_without_secrets_inherits_nothing_but_the_standard_streams(standins):
    standins.tool("tpm2_getcap", 'ls /proc/$$/fd > "$seen/fds"; echo out; echo err >&2; exit 7')
    extra = os.open(os.devnull, os.O_RDONLY)
    os.set_inheritable(extra, True)
    try:
        result = linux_tpm._run("tpm2_getcap", ["properties-variable"])
    finally:
        os.close(extra)
    assert (result.status, result.stdout, result.stderr, result.filled) == (7, b"out\n", b"err\n", False)
    assert standins.argv()[1:] == ["properties-variable"]
    assert not (standins.seen / "auth").exists()
    inherited = sorted(int(name) for name in standins.saw("fds").split())
    assert inherited[:3] == [0, 1, 2]
    assert all(number >= 10 for number in inherited[3:]), "only the shell's own descriptors, none of ours"


@needs_linux
@pytest.mark.parametrize(
    "count, message",
    [
        (0, "malformed device secret"),
        (1, "malformed device secret"),
        (31, "malformed device secret"),
        (33, "more data than a device secret holds"),
        (64, "more data than a device secret holds"),
        (5_000_000, "more data than a device secret holds"),
    ],
)
def test_answer_of_the_wrong_length_is_refused_at_once(count, message, standins, backend):
    standins.tool("tpm2_nvread", f"head -c {count} /dev/zero")
    started = time.monotonic()
    with pytest.raises(HardwareError, match=message):
        unseal(backend, descriptor())
    assert time.monotonic() - started < 10


@needs_linux
def test_failed_tool_with_a_partial_answer_is_reported_by_its_error(standins, backend):
    stderr = FAILURES["nvread_wrong_auth"][2].decode("ascii")
    (standins.seen / "stderr").write_text(stderr)
    standins.tool("tpm2_nvread", 'head -c 7 /dev/zero; cat "$seen/stderr" >&2; exit 3')
    with pytest.raises(AuthError, match="^wrong master password$"):
        unseal(backend, descriptor())


@needs_linux
@pytest.mark.parametrize(
    "body", ["exec sleep 60", "exec sleep 60 >/dev/null 2>&1"], ids=["streams open", "streams closed"]
)
def test_tool_that_hangs_is_killed_after_the_timeout(body, standins, backend, monkeypatch):
    monkeypatch.setattr(linux_tpm, "_TIMEOUT", 0.5)
    standins.tool("tpm2_nvread", body)
    started = time.monotonic()
    with pytest.raises(
        HardwareError, match=r"tpm2_nvread did not finish within 0\.5 seconds; the TPM is not responding"
    ):
        unseal(backend, descriptor())
    assert time.monotonic() - started < 10
    with pytest.raises(ProcessLookupError):
        os.kill(int(standins.saw("pids").split()[-1]), 0)


@needs_linux
@pytest.mark.parametrize(
    "body",
    ["head -c 5000000 /dev/zero", "exec >/dev/null; head -c 5000000 /dev/zero >&2; exit 1"],
    ids=["stdout", "stderr"],
)
def test_flood_of_output_is_cut_off_without_waiting_for_the_timeout(body, standins):
    standins.tool("tpm2_getcap", body)
    started = time.monotonic()
    with pytest.raises(HardwareError, match="tpm2_getcap produced more output than a TPM tool should"):
        linux_tpm._run("tpm2_getcap", ["properties-variable"])
    assert time.monotonic() - started < 15, "well inside the 30 second timeout"


@needs_linux
def test_tool_stuck_on_a_full_pipe_is_killed_after_the_timeout(standins, monkeypatch):
    """Flooding stderr while stdout stays open blocks the tool; the timeout ends it."""
    monkeypatch.setattr(linux_tpm, "_TIMEOUT", 1.0)
    standins.tool("tpm2_getcap", "head -c 5000000 /dev/zero >&2; exit 1")
    started = time.monotonic()
    with pytest.raises(HardwareError, match="more output than a TPM tool should|did not finish within 1 seconds"):
        linux_tpm._run("tpm2_getcap", ["properties-variable"])
    assert time.monotonic() - started < 15


@needs_linux
def test_tool_that_cannot_be_started_is_a_hardware_error(standins):
    (standins.bin / "tpm2_getcap").write_text("#!/nonexistent/interpreter\n")
    (standins.bin / "tpm2_getcap").chmod(0o755)
    with pytest.raises(HardwareError, match="could not run tpm2_getcap"):
        linux_tpm._run("tpm2_getcap", ["properties-variable"])


@needs_linux
def test_repeated_runs_leak_no_descriptors_and_leave_no_processes(standins):
    standins.tool("tpm2_nvread", f"printf '{octal(SECRET)}'")
    standins.tool("tpm2_nvwrite", "cat > /dev/null; exit 3")
    standins.tool("tpm2_getcap", "echo 'ERROR: no' >&2; exit 1")
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(20):
        with buffer(AUTH) as auth, SecureBuffer(DEVICE_SECRET_LEN) as out:
            assert linux_tpm._run("tpm2_nvread", [INDEX, "-C", INDEX, "-s", "32"], auth=auth, secret_out=out).filled
        with buffer(AUTH) as auth, buffer(SECRET) as data:
            assert linux_tpm._run("tpm2_nvwrite", [INDEX, "-C", INDEX], auth=auth, data=data).status == 3
        assert linux_tpm._run("tpm2_getcap", ["properties-variable"]).status == 1
    assert len(os.listdir("/proc/self/fd")) == before
    for pid in standins.saw("pids").split():
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid), 0)


@needs_linux
def test_memory_file_is_anonymous_private_and_zeroed_before_it_is_closed():
    text = b"hex:" + b"ab" * 32
    fd = linux_tpm._memory_file(memoryview(text))
    watcher = os.dup(fd)
    try:
        assert fd > 2 and not os.get_inheritable(fd)
        assert os.readlink(f"/proc/self/fd/{fd}").startswith("/memfd:irondome-tpm2")
        assert os.pread(watcher, 200, 0) == text
        linux_tpm._discard_memory_file(fd, len(text))
        assert os.pread(watcher, 200, 0) == bytes(len(text)), "overwritten in place, not merely closed"
        with pytest.raises(OSError):
            os.fstat(fd)
    finally:
        os.close(watcher)


@needs_linux
def test_memory_file_works_where_python_was_built_without_memfd_create(monkeypatch):
    monkeypatch.delattr(os, "memfd_create", raising=False)
    assert linux_tpm._memfd_create() is not None
    fd = linux_tpm._memory_file(memoryview(b"through libc"))
    try:
        assert os.pread(fd, 50, 0) == b"through libc"
        assert not os.get_inheritable(fd)
        assert os.readlink(f"/proc/self/fd/{fd}").startswith("/memfd:irondome-tpm2")
    finally:
        linux_tpm._discard_memory_file(fd, 12)


@needs_linux
def test_memory_file_on_a_kernel_that_does_not_know_the_seal_flag(monkeypatch):
    real = linux_tpm._memfd_create()
    asked: List[int] = []

    def old_kernel(name: str, flags: int) -> int:
        asked.append(flags)
        if flags & 0x0008:
            raise OSError(errno.EINVAL, "Invalid argument")
        return real(name, flags)

    monkeypatch.setattr(linux_tpm, "_memfd_create", lambda: old_kernel)
    fd = linux_tpm._memory_file(memoryview(b"x"))
    linux_tpm._discard_memory_file(fd, 1)
    assert asked == [0x0009, 0x0001]


@needs_linux
def test_memory_file_never_lands_on_a_standard_stream():
    """A caller may have closed stdin; descriptor 0 would be overwritten in the child."""
    code = (
        "import os\n"
        "os.close(0)\n"
        "from irondome.device import linux_tpm\n"
        "print(linux_tpm._memory_file(memoryview(b'x')))\n"
    )
    environment = dict(os.environ, PYTHONPATH=os.pathsep.join(entry for entry in sys.path if entry))
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=environment, timeout=60)
    assert result.returncode == 0, result.stderr
    assert int(result.stdout) > 2


def test_memory_file_that_cannot_be_created_is_a_hardware_error(monkeypatch):
    def refuse(name: str, flags: int) -> int:
        raise OSError(errno.EMFILE, "Too many open files")

    monkeypatch.setattr(linux_tpm, "_memfd_create", lambda: refuse)
    with pytest.raises(HardwareError, match="cannot create an in-memory file for the TPM tools: Too many open files"):
        linux_tpm._memory_file(memoryview(b"x"))
    monkeypatch.setattr(linux_tpm, "_memfd_create", lambda: None)
    with pytest.raises(HardwareError, match="memfd_create"):
        linux_tpm._memory_file(memoryview(b"x"))


def test_pipe_holds_the_data_and_then_ends():
    fd = linux_tpm._filled_pipe(memoryview(SECRET))
    try:
        assert not os.get_inheritable(fd)
        assert os.read(fd, 100) == SECRET
        assert os.read(fd, 100) == b"", "the write end is already closed"
    finally:
        os.close(fd)
    with pytest.raises(HardwareError):
        linux_tpm._filled_pipe(memoryview(bytes(513)))


@needs_linux
def test_without_a_configured_transport_only_the_kernel_device_is_tried(backend, monkeypatch):
    """The tools' own fallback is a simulator on TCP port 2321 of localhost; that must never be reached."""
    if shutil.which("tpm2_getcap", path=linux_tpm._SAFE_PATH) is None:
        pytest.skip("tpm2-tools is not installed")
    if os.path.exists("/dev/tpmrm0"):
        pytest.skip("this machine has a TPM device")
    monkeypatch.delenv("TPM2TOOLS_TCTI", raising=False)
    result = linux_tpm._run("tpm2_getcap", ["properties-variable"])
    assert result.status != 0 and b"/dev/tpmrm0" in result.stderr
    for elsewhere in (b"2321", b"127.0.0.1", b"localhost", b"swtpm", b"mssim", b"/dev/tpm0:", b"tabrmd"):
        assert elsewhere not in result.stderr
    found = backend.probe()
    assert not found.available and "has no TPM 2.0 device" in found.detail


# ---------------------------------------------------------------------------
# A real TPM 2.0 (scripts/test-linux.sh runs these against swtpm)
# ---------------------------------------------------------------------------

TOOL_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"


def tpm2(name: str, *arguments: str, check: bool = True) -> "subprocess.CompletedProcess[bytes]":
    """Run a tpm2-tools command directly, the way an administrator would."""
    path = shutil.which(name, path=TOOL_PATH)
    assert path is not None, f"{name} is not installed"
    environment = {"PATH": TOOL_PATH, "LC_ALL": "C", "TPM2TOOLS_TCTI": os.environ["TPM2TOOLS_TCTI"]}
    return subprocess.run([path, *arguments], env=environment, capture_output=True, check=check, timeout=60)


def nv_handles() -> Set[str]:
    listed = tpm2("tpm2_getcap", "handles-nv-index").stdout.decode("ascii")
    return {f"0x{int(handle, 16):08x}" for handle in re.findall(r"0x[0-9A-Fa-f]+", listed)}


def failed_tries() -> int:
    return int(linux_tpm.lockout_status()["failed_tries"])


def set_lockout_parameters(max_tries: int, recovery: int, lockout_recovery: int) -> None:
    tpm2(
        "tpm2_dictionarylockout",
        "--setup-parameters",
        f"--max-tries={max_tries}",
        f"--recovery-time={recovery}",
        f"--lockout-recovery-time={lockout_recovery}",
    )


@pytest.fixture
def chip(tpm) -> Iterator[Tpm2Backend]:
    """The real backend on a TPM simulator, with a clean lockout counter before and after.

    These tests fail authorisations on purpose. Against the chip of a real
    machine that would lock its owner out, so anything but a simulator is
    skipped.
    """
    if not linux_tpm._is_simulator(os.environ.get("TPM2TOOLS_TCTI", "")):
        pytest.skip("fails authorisations on purpose: only runs against a TPM simulator")
    tpm2("tpm2_dictionarylockout", "--clear-lockout")
    before = nv_handles()
    yield tpm
    tpm2("tpm2_dictionarylockout", "--clear-lockout", check=False)
    for index in nv_handles() - before:
        tpm2("tpm2_nvundefine", index, "-C", "o", check=False)


def lock_out(backend: Tpm2Backend, made: Dict[str, Any]) -> int:
    """Spend every guess the TPM allows; returns how many that was."""
    limit = int(backend.lockout_status()["max_tries"])
    assert 0 < limit <= 32
    for attempt in range(limit):
        with pytest.raises(AuthError, match="^wrong master password$") as caught:
            unseal(backend, made, OTHER_AUTH)
        assert not isinstance(caught.value, LockedOutError)
        assert failed_tries() == attempt + 1
    return limit


@pytest.mark.tpm
def test_real_round_trip_that_is_safe_on_a_real_chip(tpm):
    """No failed authorisation and nothing left behind: this one may run against real hardware."""
    made, secret = enroll(tpm)
    try:
        assert unseal(tpm, made) == secret and tpm.exists(made)
    finally:
        tpm.destroy(made)
    assert not tpm.exists(made) and registry() == []


@pytest.mark.tpm
def test_real_simulator_is_reported_as_software_and_probing_changes_nothing(chip):
    handles = nv_handles()
    counters = chip.lockout_status()
    found = chip.probe()
    assert found.available and found.name == "linux-tpm2" and not found.biometry
    assert found.hardware is False and "simulator" in found.detail and "not a security chip" in found.detail
    assert f"locks after {counters['max_tries']} wrong passwords" in found.detail
    assert nv_handles() == handles and chip.lockout_status() == counters
    assert not paths.device_dir().exists()


@pytest.mark.tpm
def test_real_enrolment_is_readable_only_with_its_authorisation_value(chip):
    made, secret = enroll(chip)
    index = made["nv_index"]
    assert index in nv_handles() and registry() == [index]
    assert unseal(chip, made) == secret and chip.exists(made)
    public = tpm2("tpm2_nvreadpublic", index).stdout.decode("ascii")
    assert re.search(r"friendly: authwrite\|authread\|written\n", public), public
    assert "no_da" not in public, "the TPM must count wrong guesses against this index"
    assert re.search(r"\n\s*size: 32\n", public)
    as_owner = tpm2("tpm2_nvread", index, "-C", "o", "-s", "32", check=False)
    assert as_owner.returncode != 0 and secret not in as_owner.stdout, "the owner hierarchy cannot read it"
    without_password = tpm2("tpm2_nvread", index, "-C", index, "-s", "32", check=False)
    assert without_password.returncode != 0 and secret not in without_password.stdout
    assert failed_tries() == 1, "and the empty password was counted as a guess"


WRAPPER = """#!/bin/sh
environment=$(/usr/bin/env)
PATH=/usr/bin:/bin
{
    printf 'ARGV'
    for argument in "$0" "$@"; do printf '\\t%s' "$argument"; done
    printf '\\n'
    printf '%s\\n' "$environment" | sed 's/^/ENV\\t/'
    for argument in "$@"; do
        case "$argument" in
            file:/dev/fd/*) printf 'FD\\t%s\\n' "$(readlink "/proc/$$/fd/${argument#file:/dev/fd/}")" ;;
        esac
    done
} >> '@LOG@'
exec '@REAL@' "$@"
"""


def install_wrappers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Put a logging wrapper in front of every tool the backend runs; returns the log."""
    log = tmp_path / "tool-calls.log"
    wrappers = tmp_path / "wrappers"
    wrappers.mkdir()
    for name in linux_tpm._TOOLS:
        real = shutil.which(name, path=linux_tpm._SAFE_PATH)
        assert real is not None
        (wrappers / name).write_text(WRAPPER.replace("@LOG@", str(log)).replace("@REAL@", real))
        (wrappers / name).chmod(0o755)
    monkeypatch.setattr(linux_tpm, "_SAFE_PATH", str(wrappers))
    return log


@pytest.mark.tpm
def test_real_tools_are_never_told_a_secret_in_argv_or_environment_and_none_reaches_the_disk(
    chip, tmp_path, monkeypatch
):
    log = install_wrappers(tmp_path, monkeypatch)
    monkeypatch.setenv("TSS2_LOG", "all+trace")
    shared = [directory for directory in ("/tmp", "/var/tmp", "/dev/shm") if os.path.isdir(directory)]
    present = {directory: set(os.listdir(directory)) for directory in shared}

    made, secret = enroll(chip)
    assert unseal(chip, made) == secret
    with pytest.raises(AuthError, match="^wrong master password$"):
        unseal(chip, made, OTHER_AUTH)
    chip.destroy(made)

    material = [spelling for value in (AUTH, OTHER_AUTH, secret) for spelling in spellings(value)]
    recorded = log.read_bytes()
    lines = recorded.splitlines()
    called = {os.path.basename(line.split(b"\t")[1]).decode("ascii") for line in lines if line.startswith(b"ARGV")}
    assert called == {"tpm2_nvreadpublic", "tpm2_nvdefine", "tpm2_nvwrite", "tpm2_nvread", "tpm2_nvundefine"}
    assert not any(spelling in recorded for spelling in material)
    links = [line.split(b"\t", 1)[1] for line in lines if line.startswith(b"FD")]
    assert len(links) == 5 and all(link.startswith(b"/memfd:irondome-tpm2") for link in links)
    variables = {line.split(b"\t", 1)[1].split(b"=", 1)[0].decode("ascii") for line in lines if line.startswith(b"ENV")}
    assert variables - SHELL_VARIABLES == {"PATH", "LC_ALL", "TPM2TOOLS_TCTI"}

    for path in tmp_path.rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            assert not any(spelling in content for spelling in material), f"key material in {path}"
    for directory in shared:
        for name in set(os.listdir(directory)) - present[directory]:
            created = Path(directory) / name
            if created.is_file() and os.access(created, os.R_OK):
                content = created.read_bytes()
                assert not any(spelling in content for spelling in material), f"key material in {created}"


@pytest.mark.tpm
def test_real_tools_for_a_device_key_without_a_password_get_no_authorisation_and_no_secret(
    chip, tmp_path, monkeypatch
):
    log = install_wrappers(tmp_path, monkeypatch)
    made, secret = enroll_open(chip)
    assert unseal_open(chip, made) == secret
    chip.destroy(made)

    lines = log.read_bytes().splitlines()
    commands = [line.split(b"\t")[1:] for line in lines if line.startswith(b"ARGV")]
    called = {os.path.basename(command[0]).decode("ascii") for command in commands}
    assert called == {"tpm2_nvreadpublic", "tpm2_nvdefine", "tpm2_nvwrite", "tpm2_nvread", "tpm2_nvundefine"}
    assert not any(option in command for command in commands for option in (b"-p", b"-P")), "no authorisation option"
    assert [line for line in lines if line.startswith(b"FD")] == [], "and no authorisation file"
    assert not any(spelling in log.read_bytes() for spelling in spellings(secret))


@pytest.mark.tpm
def test_real_round_trip_without_a_password_that_is_safe_on_a_real_chip(tpm):
    """A device key that needs no password: no authorisation can fail, and nothing is left behind."""
    made, secret = enroll_open(tpm)
    try:
        assert unseal_open(tpm, made) == secret and tpm.exists(made)
    finally:
        tpm.destroy(made)
    assert not tpm.exists(made) and registry() == []


@pytest.mark.tpm
def test_real_device_key_without_a_password_is_readable_by_any_process_that_can_use_the_tpm(chip):
    """What the device policy means on Linux, shown with the bare tool: no password, no prompt, not the owner's."""
    made, secret = enroll_open(chip)
    index = made["nv_index"]
    assert index in nv_handles() and registry() == [index]
    public = tpm2("tpm2_nvreadpublic", index).stdout.decode("ascii")
    assert re.search(r"friendly: authwrite\|authread\|no_da\|written\n", public), public
    assert re.search(r"\n\s*size: 32\n", public)
    anyone = tpm2("tpm2_nvread", index, "-C", index, "-s", "32")
    assert anyone.stdout == secret, "any process that may use the TPM reads it without a password"
    as_owner = tpm2("tpm2_nvread", index, "-C", "o", "-s", "32", check=False)
    assert as_owner.returncode != 0 and secret not in as_owner.stdout, "never through the owner hierarchy"
    assert unseal_open(chip, made) == secret
    assert failed_tries() == 0


@pytest.mark.tpm
def test_real_device_key_without_a_password_is_read_while_the_tpm_refuses_every_password(chip):
    keyslot, keyslot_secret = enroll(chip)
    made, secret = enroll_open(chip)
    lock_out(chip, keyslot)
    with pytest.raises(LockedOutError):
        unseal(chip, keyslot)
    assert unseal_open(chip, made) == secret, "sessions and grants keep working through a lockout"
    tpm2("tpm2_dictionarylockout", "--clear-lockout")
    assert unseal(chip, keyslot) == keyslot_secret


@pytest.mark.tpm
def test_real_empty_authorisation_is_never_presented_to_a_password_keyslots_index(chip):
    keyslot, secret = enroll(chip)
    with pytest.raises(VaultError, match="not a device key that needs no password"):
        unseal_open(chip, keyslot)
    assert failed_tries() == 0, "the TPM was never asked, so no guess was spent"
    assert unseal(chip, keyslot) == secret


@pytest.mark.tpm
def test_real_device_keys_without_a_password_are_destroyed_like_any_other(chip):
    first, _ = enroll_open(chip)
    second, _ = enroll_open(chip)
    keyslot, _ = enroll(chip)
    chip.destroy(first)
    assert first["nv_index"] not in nv_handles() and not chip.exists(first)
    assert chip.destroy_all() == 2
    assert not {item["nv_index"] for item in (first, second, keyslot)} & nv_handles()
    assert registry() == []
    with pytest.raises(HardwareError, match="not created by this IronDome installation"):
        unseal_open(chip, second)


@pytest.mark.tpm
def test_real_device_key_without_a_password_is_not_on_another_machines_tpm(chip, monkeypatch):
    made, secret = enroll_open(chip)
    home = os.environ["TPM2TOOLS_TCTI"]
    with another_tpm() as elsewhere:
        monkeypatch.setenv("TPM2TOOLS_TCTI", elsewhere)
        try:
            assert not chip.exists(made)
            with pytest.raises(HardwareError, match="is not defined"):
                unseal_open(chip, made)
        finally:
            monkeypatch.setenv("TPM2TOOLS_TCTI", home)
    assert unseal_open(chip, made) == secret


@pytest.mark.tpm
def test_real_wrong_authorisation_raises_auth_error_and_the_tpm_counts_it(chip):
    made, secret = enroll(chip)
    assert failed_tries() == 0
    with pytest.raises(AuthError, match="^wrong master password$") as caught:
        unseal(chip, made, OTHER_AUTH)
    assert type(caught.value) is AuthError
    status = chip.lockout_status()
    assert status["failed_tries"] == 1 and status["remaining_tries"] == status["max_tries"] - 1
    assert not status["in_lockout"] and status["seconds_until_retry"] == 0
    assert unseal(chip, made) == secret
    assert failed_tries() == 1, "the TPM does not forgive a failure because a later attempt succeeded"


@pytest.mark.tpm
def test_real_repeated_wrong_authorisation_ends_in_lockout(chip):
    made, secret = enroll(chip)
    limit = lock_out(chip, made)
    with pytest.raises(LockedOutError) as locked:
        unseal(chip, made, OTHER_AUTH)
    with pytest.raises(LockedOutError):
        unseal(chip, made)
    status = chip.lockout_status()
    assert status["in_lockout"] and status["remaining_tries"] == 0 and status["failed_tries"] == limit
    assert status["seconds_until_retry"] == status["recovery_seconds"] > 0
    message = str(locked.value)
    assert f"{limit} failed attempts, limit {limit}" in message
    assert f"at most {linux_tpm._duration(status['seconds_until_retry'])}" in message
    tpm2("tpm2_dictionarylockout", "--clear-lockout")
    assert unseal(chip, made) == secret


@pytest.mark.tpm
def test_real_enrolment_during_lockout_leaves_nothing_in_the_tpm(chip):
    made, _ = enroll(chip)
    lock_out(chip, made)
    handles = nv_handles()
    with pytest.raises(LockedOutError):
        enroll(chip)
    assert nv_handles() == handles and registry() == [made["nv_index"]]


@pytest.mark.tpm
def test_real_destroy_makes_unseal_impossible_and_the_index_is_gone(chip):
    made, _ = enroll(chip)
    index = made["nv_index"]
    chip.destroy(made)
    assert index not in nv_handles() and not chip.exists(made) and registry() == []
    assert tpm2("tpm2_nvreadpublic", index, check=False).returncode != 0
    with pytest.raises(HardwareError, match="recovery key") as caught:
        unseal(chip, made)
    assert not isinstance(caught.value, AuthError)
    assert failed_tries() == 0, "asking for a missing index is not a guess"
    chip.destroy(made)


@pytest.mark.tpm
def test_real_two_enrolments_get_different_indices_and_secrets(chip):
    first, first_secret = enroll(chip)
    second, second_secret = enroll(chip)
    assert first["nv_index"] != second["nv_index"] and first["ref"] != second["ref"]
    assert first_secret != second_secret
    assert {first["nv_index"], second["nv_index"]} <= nv_handles()
    assert registry() == sorted([first["nv_index"], second["nv_index"]])
    assert unseal(chip, first) == first_secret and unseal(chip, second) == second_secret


@pytest.mark.tpm
def test_real_destroy_all_erases_this_installations_keys_and_nothing_else(chip):
    made = [enroll(chip)[0] for _ in range(3)]
    foreign = "0x01a5a5a5"
    tpm2("tpm2_nvdefine", foreign, "-C", "o", "-s", "8", "-a", "ownerread|ownerwrite")
    try:
        chip.destroy(made[0])
        assert chip.destroy_all() == 2
        assert not {item["nv_index"] for item in made} & nv_handles()
        assert registry() == [] and chip.destroy_all() == 0
        with pytest.raises(HardwareError, match="refusing to delete it"):
            chip.destroy(descriptor(foreign))
        assert foreign in nv_handles(), "another program's index survives a tampered descriptor"
    finally:
        tpm2("tpm2_nvundefine", foreign, "-C", "o", check=False)


@pytest.mark.tpm
def test_real_key_can_be_destroyed_after_the_registry_was_lost(chip):
    made, _ = enroll(chip)
    shutil.rmtree(paths.device_dir())
    assert chip.destroy_all() == 0 and chip.exists(made), "without its registry destroy_all knows of nothing"
    chip.destroy(made)
    assert not chip.exists(made) and made["nv_index"] not in nv_handles()


@pytest.mark.tpm
def test_real_owner_password_makes_the_backend_unavailable_with_the_remedy(chip):
    made, secret = enroll(chip)
    tpm2("tpm2_changeauth", "-c", "owner", "an-owner-password")
    try:
        found = chip.probe()
        assert not found.available and "tpm2_changeauth -c owner -p" in found.detail
        with pytest.raises(HardwareError, match="owner password"):
            enroll(chip)
        assert registry() == [made["nv_index"]]
        with pytest.raises(HardwareError, match="owner password"):
            chip.destroy(made)
        with pytest.raises(HardwareError, match=r"1 TPM device key\(s\) could not be erased"):
            chip.destroy_all()
        assert chip.exists(made) and registry() == [made["nv_index"]]
        assert unseal(chip, made) == secret, "reading needs only the index's own authorisation"
    finally:
        tpm2("tpm2_changeauth", "-c", "owner", "-p", "an-owner-password")
    assert chip.probe().available
    assert chip.destroy_all() == 1


@pytest.mark.tpm
def test_real_tpm_with_its_protection_switched_off_is_reported(chip):
    original = chip.lockout_status()
    made, secret = enroll(chip)
    set_lockout_parameters(original["max_tries"], 0, original["lockout_recovery_seconds"])
    try:
        status = chip.lockout_status()
        assert status["recovery_seconds"] == 0 and not status["in_lockout"]
        assert "does not limit password guesses" in chip.probe().detail
        for _ in range(original["max_tries"] + 2):
            with pytest.raises(AuthError, match="^wrong master password$"):
                unseal(chip, made, OTHER_AUTH)
        assert failed_tries() == 0 and unseal(chip, made) == secret
    finally:
        set_lockout_parameters(
            original["max_tries"], original["recovery_seconds"], original["lockout_recovery_seconds"]
        )
    assert chip.lockout_status() == original


@pytest.mark.tpm
def test_real_wait_grows_with_the_failures_beyond_the_limit(chip):
    original = chip.lockout_status()
    if original["max_tries"] < 3:
        pytest.skip("needs a TPM that allows at least three guesses")
    made, _ = enroll(chip)
    for _ in range(2):
        with pytest.raises(AuthError):
            unseal(chip, made, OTHER_AUTH)
    set_lockout_parameters(1, original["recovery_seconds"], original["lockout_recovery_seconds"])
    try:
        status = chip.lockout_status()
        assert status["in_lockout"] and (status["failed_tries"], status["max_tries"]) == (2, 1)
        assert status["seconds_until_retry"] == 2 * status["recovery_seconds"]
        with pytest.raises(LockedOutError, match="2 failed attempts, limit 1"):
            unseal(chip, made)
    finally:
        set_lockout_parameters(
            original["max_tries"], original["recovery_seconds"], original["lockout_recovery_seconds"]
        )


@pytest.mark.tpm
def test_real_lockout_authorisation_is_reported(chip):
    assert chip.lockout_status()["lockout_auth_set"] is False
    tpm2("tpm2_changeauth", "-c", "lockout", "a-lockout-password")
    try:
        assert chip.lockout_status()["lockout_auth_set"] is True
    finally:
        tpm2("tpm2_changeauth", "-c", "lockout", "-p", "a-lockout-password")
    assert chip.lockout_status()["lockout_auth_set"] is False


@pytest.mark.tpm
def test_real_unreachable_tpm_is_an_error_and_never_an_empty_answer(chip, monkeypatch):
    made, _ = enroll(chip)
    reachable = os.environ["TPM2TOOLS_TCTI"]
    monkeypatch.setenv("TPM2TOOLS_TCTI", "swtpm:path=/nonexistent/irondome/sock")
    try:
        with pytest.raises(HardwareError):
            chip.exists(made)
        with pytest.raises(HardwareError):
            chip.destroy(made)
        with pytest.raises(HardwareError, match=r"1 TPM device key\(s\) could not be erased"):
            chip.destroy_all()
        with pytest.raises(HardwareError) as caught:
            unseal(chip, made)
        assert not isinstance(caught.value, AuthError)
        with pytest.raises(HardwareError):
            enroll(chip)
        assert not chip.probe().available
        assert registry() == [made["nv_index"]]
    finally:
        monkeypatch.setenv("TPM2TOOLS_TCTI", reachable)
    assert chip.destroy_all() == 1


@pytest.mark.tpm
def test_real_tools_trace_setting_of_the_caller_is_not_passed_on(chip, monkeypatch):
    """At trace level the TSS libraries print the command buffers, which hold the authorisation value."""
    monkeypatch.setenv("TSS2_LOG", "all+trace")
    made, _ = enroll(chip)
    with buffer(AUTH) as auth, SecureBuffer(DEVICE_SECRET_LEN) as out:
        result = linux_tpm._run(
            "tpm2_nvread", [made["nv_index"], "-C", made["nv_index"], "-s", "32"], auth=auth, secret_out=out
        )
    assert result.status == 0 and result.stderr == b""
    with buffer(OTHER_AUTH) as auth, SecureBuffer(DEVICE_SECRET_LEN) as out:
        result = linux_tpm._run(
            "tpm2_nvread", [made["nv_index"], "-C", made["nv_index"], "-s", "32"], auth=auth, secret_out=out
        )
    assert result.status != 0 and b"trace" not in result.stderr.lower()
    assert not any(spelling in result.stderr for spelling in spellings(OTHER_AUTH))


@pytest.mark.tpm
def test_real_concurrent_enrolments_all_succeed(chip):
    import threading

    made: List[Tuple[Dict[str, Any], bytes]] = []
    errors: List[BaseException] = []

    def work() -> None:
        try:
            made.append(enroll(chip))
        except BaseException as exc:  # reported below, in the main thread
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(120)
    assert errors == []
    indices = sorted(item["nv_index"] for item, _ in made)
    assert len(set(indices)) == 4 and registry() == indices
    for item, secret in made:
        assert unseal(chip, item) == secret


@pytest.mark.tpm
@settings(PROPERTY, max_examples=8, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(auth=st.binary(min_size=32, max_size=32).filter(any))
@example(auth=bytes(31) + b"\x01")
@example(auth=b"\x01" + bytes(31))
@example(auth=b"\xff" * 30 + b"\x00\x00")
@example(auth=b"\xff" * 32)
@example(auth=b"hex:" + bytes(range(1, 29)))
@example(auth=b"\n" * 32)
@example(auth=b"file:/etc/passwd".ljust(32, b" "))
def test_real_any_authorisation_value_round_trips_and_a_near_miss_fails(chip, auth):
    """The TPM drops trailing zero bytes of a password; values that end in them must still work."""
    made, secret = enroll(chip, auth)
    try:
        assert unseal(chip, made, auth) == secret
        near_miss = bytes([auth[0] ^ 0x80]) + auth[1:]
        if any(near_miss):
            with pytest.raises(AuthError, match="^wrong master password$"):
                unseal(chip, made, near_miss)
    finally:
        tpm2("tpm2_dictionarylockout", "--clear-lockout")
        chip.destroy(made)


@pytest.mark.tpm
def test_real_vault_cycle_on_the_tpm_backend(chip, make_vault):
    from conftest import PASSWORD, secret
    from irondome.unlock import open_vault
    from irondome.vault import Secret, VaultFile

    vault, recovery = make_vault()
    vault.add("github", Secret(password="hunter2-Github!", notes="personal"), username="king")
    vault.commit()
    vault.close()
    slot = next(slot for slot in VaultFile.load().slots if slot.device is not None)
    assert slot.backend_name == "linux-tpm2" and slot.describe() == "master password + device key (linux-tpm2)"
    assert slot.device["nv_index"] in nv_handles() and registry() == [slot.device["nv_index"]]
    assert b"hunter2" not in paths.vault_file().read_bytes()
    with secret(PASSWORD) as password, open_vault(password=password, interactive=False) as opened:
        assert opened.value(opened.find("github")) == "hunter2-Github!"
        assert opened.find("github").username == "king"
    with secret("the wrong password") as password, pytest.raises(AuthError, match="^wrong master password$"):
        open_vault(password=password, interactive=False)
    assert failed_tries() == 1, "the chip judged the guess"
    with secret(PASSWORD) as password:
        open_vault(password=password, interactive=False).close()
    open_vault(recovery_key=recovery).close()


@pytest.mark.tpm
def test_real_destroyed_device_key_cannot_be_restored_from_a_copy_of_the_disk(chip, make_vault, tmp_path):
    """Crypto-erase: after the key is destroyed, a perfect copy of everything on disk no longer opens."""
    from conftest import PASSWORD, secret
    from irondome.unlock import open_vault
    from irondome.vault import Secret, VaultFile

    vault, _ = make_vault(with_recovery=False)
    vault.add("github", Secret(password="hunter2"))
    vault.commit()
    vault.close()
    on_disk = {"vault": paths.home(), "device": paths.device_dir()}
    copies = {name: tmp_path / f"copy-of-{name}" for name in on_disk}
    for name, directory in on_disk.items():
        shutil.copytree(directory, copies[name])
    with secret(PASSWORD) as password:
        open_vault(password=password, interactive=False).close()
    slots = [slot for slot in VaultFile.load().slots if slot.device is not None]
    assert len(slots) == 1 and keys.destroy_slot_device(slots[0]) is True
    for name, directory in on_disk.items():
        shutil.rmtree(directory)
        shutil.copytree(copies[name], directory)
    assert paths.vault_file().read_bytes() == (copies["vault"] / "vault.irondome").read_bytes()
    assert registry() == [slots[0].device["nv_index"]], "the restored registry still names the key"
    with secret(PASSWORD) as password, pytest.raises(HardwareError, match="recovery key") as caught:
        open_vault(password=password, interactive=False)
    assert not isinstance(caught.value, AuthError)
    assert slots[0].device["nv_index"] not in nv_handles()
    assert failed_tries() == 0


@contextlib.contextmanager
def software_tpm(port: Optional[int] = None) -> Iterator[str]:
    """Start one more software TPM and yield how to reach it.

    Without *port* it listens on a Unix socket. With one it listens on that
    TCP port of localhost (and the next port for control), which is what an
    older tpm2-tss needs and what the tools fall back to by themselves.
    """
    swtpm = shutil.which("swtpm")
    getcap = shutil.which("tpm2_getcap", path=TOOL_PATH)
    if swtpm is None or getcap is None:
        pytest.skip("needs swtpm and tpm2-tools")
    directory = tempfile.mkdtemp(prefix="irondome-other-tpm-")
    if port is None:
        channels = [f"type=unixio,path={directory}/sock", f"type=unixio,path={directory}/sock.ctrl"]
        tcti = f"swtpm:path={directory}/sock"
    else:
        channels = [f"type=tcp,port={port}", f"type=tcp,port={port + 1}"]
        tcti = f"swtpm:host=127.0.0.1,port={port}"
    process = subprocess.Popen(
        [
            swtpm,
            "socket",
            "--tpm2",
            "--tpmstate",
            f"dir={directory}",
            "--server",
            channels[0],
            "--ctrl",
            channels[1],
            "--flags",
            "not-need-init,startup-clear",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 20
        while True:
            answer = subprocess.run(
                [getcap, "properties-variable"],
                capture_output=True,
                timeout=30,
                env={"PATH": TOOL_PATH, "TPM2TOOLS_TCTI": tcti},
            )
            if answer.returncode == 0:
                break
            assert time.monotonic() < deadline, f"the extra software TPM did not answer on {tcti}"
            time.sleep(0.1)
        yield tcti
    finally:
        process.terminate()
        process.wait(timeout=15)
        shutil.rmtree(directory, ignore_errors=True)


def another_tpm() -> Any:
    """A second, empty software TPM (the chip of some other machine), reached the way the first one is."""
    return software_tpm(None if "path=" in os.environ["TPM2TOOLS_TCTI"] else 23921)


@needs_linux
def test_simulator_listening_on_the_tools_default_port_is_never_used(backend, monkeypatch):
    """Control experiment included: the bare tool does use it; this backend, with the same environment, does not."""
    getcap = shutil.which("tpm2_getcap", path=TOOL_PATH)
    if getcap is None or shutil.which("swtpm") is None:
        pytest.skip("needs swtpm and tpm2-tools")
    if os.path.exists("/dev/tpmrm0") or os.path.exists("/dev/tpm0"):
        pytest.skip("this machine has a TPM device, which the tools would use first")

    def bare_tool_reaches_a_tpm() -> bool:
        answer = subprocess.run(
            [getcap, "properties-variable"], capture_output=True, timeout=60, env={"PATH": TOOL_PATH}
        )
        return answer.returncode == 0 and b"TPM2_PT_LOCKOUT_COUNTER" in answer.stdout

    with contextlib.ExitStack() as stack:
        if not bare_tool_reaches_a_tpm():  # nothing on port 2321 yet: put a simulator there
            stack.enter_context(software_tpm(2321))
        monkeypatch.delenv("TPM2TOOLS_TCTI", raising=False)
        assert bare_tool_reaches_a_tpm(), "left to its defaults, tpm2-tools talks to whatever listens on port 2321"
        result = linux_tpm._run("tpm2_getcap", ["properties-variable"])
        assert result.status != 0 and result.stdout == b"" and b"/dev/tpmrm0" in result.stderr
        found = backend.probe()
        assert not found.available and "has no TPM 2.0 device" in found.detail
        with pytest.raises(HardwareError, match="tpm2_nvread failed"):
            unseal(backend, descriptor())


@pytest.mark.tpm
def test_real_copy_of_the_vault_is_useless_with_another_machines_tpm(chip, make_vault, tmp_path, monkeypatch):
    from conftest import PASSWORD, secret
    from irondome.unlock import open_vault
    from irondome.vault import VaultFile

    vault, _ = make_vault(with_recovery=False)
    vault.close()
    index = VaultFile.load().slots[0].device["nv_index"]
    home = os.environ["TPM2TOOLS_TCTI"]
    with another_tpm() as elsewhere:
        monkeypatch.setenv("TPM2TOOLS_TCTI", elsewhere)
        try:
            assert index not in nv_handles()
            with secret(PASSWORD) as password, pytest.raises(HardwareError, match="recovery key"):
                open_vault(password=password, interactive=False)
            # Someone without the password defines an index of the same number on their TPM. It does not help.
            planted = tmp_path / "planted.bin"
            planted.write_bytes(b"\x42" * 32)
            tpm2("tpm2_nvdefine", index, "-C", "o", "-s", "32", "-a", "authread|authwrite", "-p", "guess")
            tpm2("tpm2_nvwrite", index, "-C", index, "-P", "guess", "-i", str(planted))
            with secret(PASSWORD) as password, pytest.raises(AuthError, match="^wrong master password$"):
                open_vault(password=password, interactive=False)
        finally:
            monkeypatch.setenv("TPM2TOOLS_TCTI", home)
    with secret(PASSWORD) as password:
        open_vault(password=password, interactive=False).close()
