from __future__ import annotations

class SecureError(Exception):
    """Base exception for all uxsp.secure operations."""


class SecureSendError(SecureError):
    """Raised when sending or packaging fails."""


class SecureReceiveError(SecureError):
    """Raised when receiving, opening, or verifying a package fails."""


class PeerNotFoundError(SecureError):
    """Raised when the target peer's PublicCard cannot be resolved."""


class TypeMismatchError(SecureReceiveError):
    """Raised when received payload type does not match the expected type."""


