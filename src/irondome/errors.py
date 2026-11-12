"""Every way IronDome can refuse, and the exit status that goes with it.

The CLI maps an exception straight to ``exit_code``; scripts and agents can
branch on the number without parsing text. The numbers are part of the public
interface and do not change within a major version.
"""

from __future__ import annotations

__all__ = [
    "IronDomeError",
    "UsageError",
    "NotFoundError",
    "AuthError",
    "LockedOutError",
    "PolicyError",
    "VaultError",
    "HardwareError",
    "EXIT_OK",
    "EXIT_INTERRUPTED",
]

EXIT_OK = 0
EXIT_INTERRUPTED = 130


class IronDomeError(Exception):
    """Base class. ``str(error)`` is always safe to show: it never holds a secret."""

    exit_code = 1


class UsageError(IronDomeError):
    """The request itself is malformed: bad arguments, bad reference, bad input."""

    exit_code = 2


class NotFoundError(IronDomeError):
    """The named entry, alias, grant or backup does not exist."""

    exit_code = 3


class AuthError(IronDomeError):
    """Authentication failed: wrong password, refused biometric, dead token."""

    exit_code = 4


class LockedOutError(AuthError):
    """The security chip is rate-limiting guesses and will not answer yet."""


class PolicyError(IronDomeError):
    """Authenticated, but not allowed: outside a grant's scope or mode."""

    exit_code = 5


class VaultError(IronDomeError):
    """The vault is missing, damaged, already exists, or from an unknown version."""

    exit_code = 6


class HardwareError(IronDomeError):
    """The device key backend is unavailable or failed."""

    exit_code = 7
