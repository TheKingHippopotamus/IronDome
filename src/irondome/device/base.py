"""The contract every device-key backend implements.

A backend guards one 32-byte *device secret* per keyslot. The vault key can
only be unwrapped with that secret, so the vault file on its own -- a stolen
backup, a synced folder, a disk image, forensic remnants on an SSD -- is not
enough to open the vault or even to start guessing the master password.

Three operations:

``enroll``   create a new device secret and return a public *descriptor* for it
``unseal``   produce the secret again, on this machine only
``destroy``  make ``unseal`` impossible forever (cryptographic erasure)

The descriptor is stored in the vault file and is not secret. Because that
file can be tampered with, :func:`check_descriptor` validates every field
before a backend acts on it.
"""

from __future__ import annotations

import abc
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from irondome.errors import VaultError
from irondome.secmem import SecureBuffer

__all__ = [
    "POLICY_DEVICE",
    "POLICY_BIOMETRY",
    "POLICY_PRESENCE",
    "POLICIES",
    "DEVICE_SECRET_LEN",
    "Probe",
    "DeviceBackend",
    "check_descriptor",
    "new_ref",
]

#: Usable silently by the logged-in user on this machine.
POLICY_DEVICE = "device"
#: The chip itself demands a biometric match for every use.
POLICY_BIOMETRY = "biometry"
#: The chip demands a biometric match or the computer's login password.
POLICY_PRESENCE = "presence"
POLICIES = (POLICY_DEVICE, POLICY_BIOMETRY, POLICY_PRESENCE)

DEVICE_SECRET_LEN = 32

_REF = re.compile(r"[0-9a-f]{32}")  # used with fullmatch: "$" would also accept a trailing newline


@dataclass(frozen=True)
class Probe:
    """What a backend can do on this machine right now."""

    name: str
    available: bool
    hardware: bool
    biometry: bool
    detail: str


def new_ref() -> str:
    return os.urandom(16).hex()


def check_descriptor(descriptor: Any, backend_name: str) -> Dict[str, Any]:
    """Validate a descriptor read from a vault file before acting on it."""
    if not isinstance(descriptor, dict):
        raise VaultError("device descriptor is malformed")
    if descriptor.get("backend") != backend_name:
        raise VaultError("device descriptor belongs to another backend")
    if descriptor.get("policy") not in POLICIES:
        raise VaultError("device descriptor has an unknown policy")
    ref = descriptor.get("ref")
    if ref is not None and (not isinstance(ref, str) or not _REF.fullmatch(ref)):
        raise VaultError("device descriptor has a malformed reference")
    return descriptor


class DeviceBackend(abc.ABC):
    """See the module docstring. Implementations must be stateless objects."""

    #: Stable identifier written into descriptors.
    name: str = ""
    #: True when the secret is held by a security chip rather than by a file.
    hardware: bool = False
    #: Policies this backend can enforce.
    policies: Tuple[str, ...] = (POLICY_DEVICE,)

    @abc.abstractmethod
    def probe(self) -> Probe:
        """Report availability without side effects visible to the user."""

    @abc.abstractmethod
    def enroll(
        self, *, policy: str, auth: Optional[SecureBuffer], reason: str
    ) -> Tuple[Dict[str, Any], SecureBuffer]:
        """Create a device secret. Returns ``(descriptor, secret)``.

        *auth* is a password-derived value for backends that can make the chip
        check it (and rate-limit wrong guesses); others ignore it.
        """

    @abc.abstractmethod
    def unseal(
        self,
        descriptor: Dict[str, Any],
        *,
        auth: Optional[SecureBuffer],
        interactive: bool,
        reason: str,
    ) -> SecureBuffer:
        """Return the device secret, or raise AuthError / HardwareError."""

    @abc.abstractmethod
    def destroy(self, descriptor: Dict[str, Any]) -> None:
        """Erase the device secret. Must raise if it could not be erased."""

    @abc.abstractmethod
    def exists(self, descriptor: Dict[str, Any]) -> bool:
        """True while the material needed to unseal is still present."""

    @abc.abstractmethod
    def destroy_all(self) -> int:
        """Erase every device secret this backend holds for this user.

        ``nuke`` calls this so that cryptographic erasure does not depend on
        being able to read the vault file. Returns how many were destroyed and
        must raise if any survived.
        """

    def supports(self, policy: str) -> bool:
        return policy in self.policies
