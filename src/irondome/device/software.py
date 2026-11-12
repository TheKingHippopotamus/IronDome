"""The fallback device key: 32 random bytes in a file outside the vault.

Used where there is no security chip IronDome can drive. It is honest about
what it is: **not hardware**. A process running as you can read the file.

It still earns its place. The key lives in the device directory, not beside
the vault, so a copy of the vault alone -- a backup, a synced folder, a
leaked archive -- cannot be opened or brute-forced, and ``nuke`` has one small
file to destroy instead of having to trust an overwrite of the whole vault.
``irondome status`` reports this backend as "software" and never as hardware.
"""

from __future__ import annotations

import io
import os
import stat
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from irondome import paths
from irondome.device.base import (
    DEVICE_SECRET_LEN,
    POLICY_DEVICE,
    DeviceBackend,
    Probe,
    check_descriptor,
    new_ref,
)
from irondome.errors import HardwareError
from irondome.secmem import SecureBuffer

__all__ = ["SoftwareBackend"]


class SoftwareBackend(DeviceBackend):
    name = "software"
    hardware = False
    policies = (POLICY_DEVICE,)

    def _path(self, descriptor: Dict[str, Any]) -> Path:
        check_descriptor(descriptor, self.name)
        ref = descriptor.get("ref")
        if not ref:
            raise HardwareError("software device descriptor has no reference")
        return paths.device_dir() / f"{ref}.key"

    def probe(self) -> Probe:
        return Probe(
            name=self.name,
            available=True,
            hardware=False,
            biometry=False,
            detail="file-based device key (no security chip in use)",
        )

    def enroll(
        self, *, policy: str, auth: Optional[SecureBuffer], reason: str
    ) -> Tuple[Dict[str, Any], SecureBuffer]:
        if policy != POLICY_DEVICE:
            raise HardwareError("the software backend cannot enforce biometric policies")
        descriptor = {"backend": self.name, "policy": policy, "ref": new_ref()}
        secret = SecureBuffer.random(DEVICE_SECRET_LEN)
        try:
            paths.write_atomic(self._path(descriptor), secret.view())
        except OSError as exc:
            secret.wipe()
            raise HardwareError(f"could not store the device key: {exc.strerror or exc}") from None
        except BaseException:
            secret.wipe()
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
        path = self._path(descriptor)
        try:
            # O_NONBLOCK: a pipe planted in place of the key must not hold up the open (and with it every
            # grant and unlock) until something writes to it. It changes nothing for a regular file.
            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOCTTY", 0))
        except FileNotFoundError:
            raise HardwareError(
                "the device key for this vault is not on this machine. "
                "Use your recovery key, or restore a portable backup."
            ) from None
        except OSError as exc:
            raise HardwareError(f"cannot read the device key: {exc.strerror or exc}") from None
        secret = SecureBuffer(DEVICE_SECRET_LEN)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise HardwareError("the device key file is damaged: it is not a regular file")
            raw = io.FileIO(fd, "rb", closefd=False)
            view = secret.view()
            got = 0
            while got < DEVICE_SECRET_LEN:
                count = raw.readinto(view[got:])
                if not count:
                    break
                got += count
            if got != DEVICE_SECRET_LEN or raw.read(1):
                raise HardwareError("the device key file is damaged")
        except OSError as exc:
            secret.wipe()
            raise HardwareError(f"cannot read the device key: {exc.strerror or exc}") from None
        except BaseException:
            secret.wipe()
            raise
        finally:
            os.close(fd)
        return secret

    def destroy(self, descriptor: Dict[str, Any]) -> None:
        path = self._path(descriptor)
        try:
            paths.secure_delete(path)
        except OSError as exc:
            raise HardwareError(f"could not destroy the device key: {exc}") from None
        if path.exists():
            raise HardwareError("the device key file is still present after deletion")

    def exists(self, descriptor: Dict[str, Any]) -> bool:
        return self._path(descriptor).is_file()

    def destroy_all(self) -> int:
        directory = paths.device_dir()
        if not directory.is_dir():
            return 0
        destroyed = 0
        survivors = []
        for path in sorted(directory.glob("*.key")):
            try:
                paths.secure_delete(path)
            except OSError:
                pass  # counted below; one stubborn file must not shield the others
            if os.path.lexists(path):
                survivors.append(path.name)
            else:
                destroyed += 1
        if survivors:
            raise HardwareError(f"could not destroy the device key(s): {', '.join(survivors)}")
        return destroyed
