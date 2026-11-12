"""Device-key backends: what ties a vault to one machine.

==============  ========  ====================================================
``macos-se``    hardware  Apple Secure Enclave; optional Touch ID enforcement
``linux-tpm2``  hardware  TPM 2.0 NV storage; password checked by the chip
``software``    file      a random key in the device directory (no chip)
==============  ========  ====================================================

``choose_backend`` picks the strongest one that works here. Set
``IRONDOME_DEVICE_BACKEND`` to a name above to force a specific backend.
``choose`` makes the same choice and also says why: which stronger backends
were passed over, each with the reason its probe gave. ``chip_requirements``
says what this system needs before a chip can hold a device key.
"""

from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from irondome.device.base import (
    POLICIES,
    POLICY_BIOMETRY,
    POLICY_DEVICE,
    POLICY_PRESENCE,
    DeviceBackend,
    Probe,
)
from irondome.errors import HardwareError, VaultError

__all__ = [
    "ENV_BACKEND",
    "NOT_PROBED",
    "POLICIES",
    "POLICY_BIOMETRY",
    "POLICY_DEVICE",
    "POLICY_PRESENCE",
    "Choice",
    "DeviceBackend",
    "Probe",
    "applies_here",
    "backend_names",
    "chip_requirements",
    "choose",
    "choose_backend",
    "get_backend",
    "probe_all",
    "report_progress",
    "set_progress",
]

#: Names the backend new device keys go to; ``auto`` (or unset) means the strongest that works here.
ENV_BACKEND = "IRONDOME_DEVICE_BACKEND"
#: How the detail of a passive probe begins when the backend cannot tell without building something first.
NOT_PROBED = "not probed"

# Strongest first. Modules load lazily so that importing IronDome on one
# platform never imports another platform's code.
_REGISTRY = (
    ("macos-se", "irondome.device.macos_se", "SecureEnclaveBackend"),
    ("linux-tpm2", "irondome.device.linux_tpm", "Tpm2Backend"),
    ("software", "irondome.device.software", "SoftwareBackend"),
)

#: The system each chip backend works on (a ``sys.platform`` prefix). The others work anywhere. Why a
#: backend for another system was passed over ("not Linux", on a Mac) is no reason worth telling anyone.
_SYSTEMS = {"macos-se": "darwin", "linux-tpm2": "linux"}

_instances: Dict[str, DeviceBackend] = {}

#: Where a backend says that something slow has started; see :func:`set_progress`.
_progress: Optional[Callable[[str], None]] = None


def backend_names() -> List[str]:
    return [name for name, _, _ in _REGISTRY]


def get_backend(name: str) -> DeviceBackend:
    """The backend called *name*.

    Raises VaultError for an unknown name and HardwareError for a backend
    this installation cannot load.
    """
    if name in _instances:
        return _instances[name]
    for known, module_name, class_name in _REGISTRY:
        if known == name:
            try:
                module = importlib.import_module(module_name)
            except ImportError as exc:
                raise HardwareError(f"the {name} device backend cannot be loaded here: {exc}") from None
            backend: DeviceBackend = getattr(module, class_name)()
            _instances[name] = backend
            return backend
    raise VaultError(f"unknown device backend {name!r}")


def probe_all() -> List[Probe]:
    """Probe every backend, strongest first. Never raises."""
    results = []
    for name in backend_names():
        try:
            results.append(get_backend(name).probe())
        except Exception as exc:  # a broken backend must not hide the others
            results.append(Probe(name=name, available=False, hardware=False, biometry=False, detail=str(exc)))
    return results


@dataclass(frozen=True)
class Choice:
    """The backend :func:`choose` picked, and why it is that one."""

    #: Where new device keys go.
    backend: DeviceBackend
    #: How it was picked: ``"auto"`` (the strongest that works here), ``"environment"``
    #: (``IRONDOME_DEVICE_BACKEND`` names it) or ``"caller"`` (the code that asked named it).
    picked: str
    #: The stronger backends for this system that were passed over, strongest first, each as its probe
    #: with ``detail`` saying why it was not taken. Empty unless *picked* is ``"auto"``.
    passed_over: Tuple[Probe, ...] = ()
    #: The probe of *backend* itself, taken when it was chosen.
    probe: Optional[Probe] = None

    @property
    def hardware(self) -> bool:
        """Whether a security chip holds the device key. The probe of this machine decides where there is
        one: a TPM 2.0 simulator is the TPM backend, and it is software."""
        return self.probe.hardware if self.probe is not None else self.backend.hardware

    @property
    def chip_unknown(self) -> bool:
        """True when a passive choice could not tell whether a stronger backend works here without building
        something first (the Secure Enclave's helper is not compiled yet). The real choice may well take it."""
        return any(probe.detail.startswith(NOT_PROBED) for probe in self.passed_over)

    @property
    def why_no_chip(self) -> Optional[str]:
        """Why no security chip holds the device key, in one line; None when a chip does.

        For an automatic choice these are the probes' own words, which name what to install or switch
        on wherever a probe knows it (``xcode-select --install``, ``sudo apt install tpm2-tools``, the
        firmware setting). :func:`chip_requirements` says it for the system as a whole.
        """
        if self.hardware:
            return None
        if self.backend.hardware and self.probe is not None:  # a chip backend, and no chip behind it
            return f"{self.backend.name}: {self.probe.detail}"
        if self.picked == "environment":
            return f"{ENV_BACKEND} is set to {self.backend.name}, so no security chip was looked for"
        if self.picked == "caller":
            return f"the {self.backend.name} backend was asked for by name, so no security chip was looked for"
        if self.passed_over:
            return "; ".join(f"{probe.name}: {probe.detail}" for probe in self.passed_over)
        return "IronDome has no security-chip backend for this system (macOS: Secure Enclave; Linux: TPM 2.0)"


def chip_requirements() -> str:
    """What this system needs before a security chip can hold a device key, as one clause.

    It reads after "a chip needs": the same advice on every machine of this system, whatever its probe
    says. :attr:`Choice.why_no_chip` says what is missing on this one.
    """
    if sys.platform == "darwin":
        return (
            "an Apple-silicon Mac, for its Secure Enclave (Intel Macs are untested), and the Xcode "
            "Command Line Tools, which compile IronDome's helper for it: xcode-select --install"
        )
    if sys.platform.startswith("linux"):
        return (
            "a TPM 2.0 that is switched on in the firmware setup and that your user may open (/dev/tpmrm0, "
            "usually through the tss group), and tpm2-tools (Debian/Ubuntu: sudo apt install tpm2-tools; "
            "Fedora: sudo dnf install tpm2-tools; Arch: sudo pacman -S tpm2-tools)"
        )
    return "macOS with a Secure Enclave or Linux with a TPM 2.0; IronDome has no chip backend for this system"


def applies_here(name: str) -> bool:
    """Whether the backend called *name* belongs to this operating system: each chip backend works on its own
    system only (a TPM key named on a Mac is not on this machine), the file-based one everywhere."""
    system = _SYSTEMS.get(name)
    return system is None or sys.platform.startswith(system)


def _probe(backend: DeviceBackend, passive: bool) -> Probe:
    """*backend*'s probe; with *passive*, one that compiles and creates nothing (the backend's
    ``passive_probe``, where it has one: the Secure Enclave's needs a helper compiled first)."""
    if passive:
        quiet = getattr(backend, "passive_probe", None)
        if callable(quiet):
            found: Probe = quiet()
            return found
    return backend.probe()


def choose(policy: str = POLICY_DEVICE, prefer: Optional[str] = None, *, passive: bool = False) -> Choice:
    """What :func:`choose_backend` picks for *policy*, and why: see :class:`Choice`.

    With *passive* nothing is compiled, enrolled or changed to find out: a Secure Enclave whose helper
    is not compiled yet is reported as not probed rather than built (``status`` asks this way). Without
    it the choice is the real one, the one ``init`` makes. Raises what :func:`choose_backend` raises.
    """
    if policy not in POLICIES:
        raise VaultError(f"unknown device policy {policy!r}")
    forced = prefer or os.environ.get(ENV_BACKEND) or "auto"
    if forced != "auto":
        backend = get_backend(forced)
        probe = _probe(backend, passive)
        if not probe.available:
            raise HardwareError(f"device backend {forced} is not available: {probe.detail}")
        if not backend.supports(policy):
            raise HardwareError(f"device backend {forced} cannot enforce the {policy} policy")
        return Choice(backend, "caller" if prefer else "environment", (), probe)
    reasons = []
    passed_over: List[Probe] = []
    for name in backend_names():
        try:
            backend = get_backend(name)
            probe = _probe(backend, passive)
        except Exception as exc:
            reasons.append(f"{name}: {exc}")
            if applies_here(name):
                passed_over.append(Probe(name, False, name in _SYSTEMS, False, str(exc)))
            continue
        if probe.available and backend.supports(policy):
            return Choice(backend, "auto", tuple(passed_over), probe)
        reasons.append(f"{name}: {probe.detail or 'does not support this policy'}")
        if applies_here(name):
            why = (probe.detail or "not available") if not probe.available else f"cannot enforce the {policy} policy"
            passed_over.append(Probe(name, probe.available, probe.hardware, probe.biometry, why))
    raise HardwareError(f"no device backend can enforce the {policy} policy here ({'; '.join(reasons)})")


def choose_backend(policy: str = POLICY_DEVICE, prefer: Optional[str] = None) -> DeviceBackend:
    """The strongest available backend that can enforce *policy*."""
    return choose(policy, prefer).backend


def set_progress(callback: Optional[Callable[[str], None]]) -> Optional[Callable[[str], None]]:
    """Send what backends say when something slow starts to *callback*; None says nothing. Returns the
    callback it replaces.

    Compiling the Secure Enclave helper on first use takes seconds, and a minute on a machine whose
    compiler has never run; without a word the command just looks stuck. The command line points
    this at its progress output (``--quiet`` silences it); a library caller decides for itself.
    """
    global _progress
    previous, _progress = _progress, callback
    return previous


def report_progress(message: str) -> None:
    """Tell whoever :func:`set_progress` names that something slow has started. Never raises for a
    stream that cannot be written (a closed terminal must not stop the work it describes)."""
    callback = _progress
    if callback is None:
        return
    try:
        callback(message)
    except (OSError, ValueError):
        pass
