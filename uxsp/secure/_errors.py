from __future__ import annotations

from uxsp.core.envelope import EnvelopeExpiredError
from uxsp.core.identity import CardExpiredError, CardRevokedError
from uxsp.core.replay import DuplicateNonceError, FutureEnvelopeError, StaleEnvelopeError


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


class MessageExpiredError(SecureReceiveError, StaleEnvelopeError, EnvelopeExpiredError, FutureEnvelopeError):
    """Raised when an incoming message has expired."""


class DuplicateMessageError(SecureReceiveError, DuplicateNonceError, EnvelopeExpiredError):
    """Raised when an incoming message was already received and processed (duplicate)."""


class InvalidSenderError(SecureReceiveError, CardRevokedError, CardExpiredError):
    """Raised when the sender identity or certificate card is invalid, expired, or revoked."""


