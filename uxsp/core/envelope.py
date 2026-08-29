"""
uxsp.core.envelope — Sealed Envelope Wrapper

What this file does:
    Defines the Envelope class, which represents a single sealed (encrypted +
    signed) UXSP message ready for transmission.  An Envelope is produced by
    seal() / Identity.seal_for() and consumed by open_seal() / Identity.open_from().

    The class is intentionally immutable once created: all eleven wire-level
    fields (version, sender_id, recipient_id, timestamp, envelope_nonce,
    ciphertext, nonce, ephemeral_pub, kem_ciphertext, classical_sig, pqc_sig)
    are blocked from post-construction mutation via a custom __setattr__.

    This file also defines:
        EnvelopeError           — Base exception for all envelope errors.
        EnvelopeValidationError — Missing fields or wrong version.
        EnvelopeTooLargeError   — Serialised size exceeds the configured cap.
        EnvelopeExpiredError    — Timestamp outside the acceptable freshness window.

Typical flow:
    1. Sender calls Identity.seal_for()  → returns an Envelope.
    2. Sender serialises with Envelope.to_json() or Envelope.to_bytes().
    3. Receiver deserialises with Envelope.from_json() / Envelope.from_bytes().
    4. Receiver calls Identity.open_from(envelope, sender_card, replay_guard)
       to decrypt and verify.
"""
from __future__ import annotations

import json
import time
from typing import Any, ClassVar

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

UXSP_VERSION = "UXSP-1"

_DEFAULT_MAX_BYTES = 64 * 1024  # 64 KB

# Required top-level fields in every sealed envelope dict.
_REQUIRED_FIELDS = frozenset(
    {
        "version",
        "sender_id",
        "recipient_id",
        "timestamp",
        "envelope_nonce",
        "ciphertext",
        "nonce",
        "ephemeral_pub",
        "kem_ciphertext",
        "classical_sig",
        "pqc_sig",
    }
)


# ─────────────────────────────────────────────
# ERRORS
# ─────────────────────────────────────────────


class EnvelopeError(Exception):
    """Base class for envelope errors."""

    pass


class EnvelopeValidationError(EnvelopeError):
    """Envelope dict is missing fields or has wrong version."""

    pass


class EnvelopeTooLargeError(EnvelopeError):
    """
    Serialised envelope exceeds the maximum allowed size.
    Reject before attempting any crypto — possible DoS payload.
    """

    pass


class EnvelopeExpiredError(EnvelopeError):
    """
    Envelope timestamp is outside the acceptable window.
    Use ReplayGuard for production replay detection;
    this is a quick pre-check for obviously stale envelopes.
    """

    pass


# ─────────────────────────────────────────────
# ENVELOPE
# ─────────────────────────────────────────────


class Envelope:
    """
    Immutable container for a sealed (encrypted + signed) UXSP message.

    What this class does:
        Wraps the eleven fields produced by seal() into a single object with
        helper methods for serialisation (to_dict, to_json, to_bytes), size
        checking, freshness checking, and recipient/sender assertions.

        All public fields are immutable after construction — mutating them raises
        AttributeError.  This prevents accidental or malicious field changes
        after the envelope has been verified.

    Class variable:
        MAX_BYTES — Global size cap (default 64 KiB). Raise this value only if
                    your application deliberately sends large payloads inside a
                    single envelope (prefer chunking instead).
    """
    MAX_BYTES: ClassVar[int] = _DEFAULT_MAX_BYTES
    __slots__ = (
        "version",
        "sender_id",
        "recipient_id",
        "timestamp",
        "envelope_nonce",
        "ciphertext",
        "nonce",
        "ephemeral_pub",
        "kem_ciphertext",
        "classical_sig",
        "pqc_sig",
        "_size_bytes_cache",
    )
    _size_bytes_cache: int | None

    version: str
    sender_id: str
    recipient_id: str
    timestamp: int
    envelope_nonce: str
    ciphertext: str
    nonce: str
    ephemeral_pub: str
    kem_ciphertext: str
    classical_sig: str
    pqc_sig: str

    # ─────────────────────────────────────────
    # CONSTRUCTION — internal
    # ─────────────────────────────────────────

    def __init__(
        self,
        version: str,
        sender_id: str,
        recipient_id: str,
        timestamp: int,
        envelope_nonce: str,
        ciphertext: str,
        nonce: str,
        ephemeral_pub: str,
        kem_ciphertext: str,
        classical_sig: str,
        pqc_sig: str,
    ) -> None:
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "sender_id", sender_id)
        object.__setattr__(self, "recipient_id", recipient_id)
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "envelope_nonce", envelope_nonce)
        object.__setattr__(self, "ciphertext", ciphertext)
        object.__setattr__(self, "nonce", nonce)
        object.__setattr__(self, "ephemeral_pub", ephemeral_pub)
        object.__setattr__(self, "kem_ciphertext", kem_ciphertext)
        object.__setattr__(self, "classical_sig", classical_sig)
        object.__setattr__(self, "pqc_sig", pqc_sig)
        object.__setattr__(self, "_size_bytes_cache", None)

    # ─────────────────────────────────────────
    # FROM DICT / RAW seal() OUTPUT
    # ─────────────────────────────────────────

    _IMMUTABLE_FIELDS = frozenset(
        {
            "version",
            "sender_id",
            "recipient_id",
            "timestamp",
            "envelope_nonce",
            "ciphertext",
            "nonce",
            "ephemeral_pub",
            "kem_ciphertext",
            "classical_sig",
            "pqc_sig",
        }
    )

    def __setattr__(self, name: str, value: Any) -> None:
        if name in Envelope._IMMUTABLE_FIELDS:
            raise AttributeError(f"Envelope field '{name}' is immutable.")
        if name != "_size_bytes_cache":
            object.__setattr__(self, "_size_bytes_cache", None)
        object.__setattr__(self, name, value)

    @classmethod
    def from_dict(cls, data: dict[str, Any], max_bytes: int | None = None) -> Envelope:
        """
        Construct an Envelope from a plain Python dict (e.g. from json.loads).

        Validates all required fields, their types, and the version string.
        Enforces the serialised size limit before accepting the data.
        Raises EnvelopeValidationError or EnvelopeTooLargeError on failure.
        """
        missing = _REQUIRED_FIELDS - data.keys()

        if missing:
            raise EnvelopeValidationError(
                f"Envelope missing required fields: "
                f"{', '.join(sorted(missing))}. "
                f"Was this produced by UXSP seal()?"
            )

        _STRING_FIELDS = (
            "version",
            "sender_id",
            "recipient_id",
            "envelope_nonce",
            "ciphertext",
            "nonce",
            "ephemeral_pub",
            "kem_ciphertext",
            "classical_sig",
            "pqc_sig",
        )

        for _f in _STRING_FIELDS:
            if not isinstance(data[_f], str):
                raise EnvelopeValidationError(
                    f"Envelope field '{_f}' must be a string, got {type(data[_f]).__name__}."
                )

        if data["version"] != UXSP_VERSION:
            raise EnvelopeValidationError(
                f"Unknown envelope version '{data['version']}'. Expected '{UXSP_VERSION}'."
            )

        limit = max_bytes if max_bytes is not None else cls.MAX_BYTES
        total_len = len(json.dumps(data, separators=(",", ":")))
        if total_len > limit:
            raise EnvelopeTooLargeError(
                f"Envelope total data ({total_len} bytes) exceeds limit of {limit} bytes."
            )

        try:
            timestamp = int(data["timestamp"])
        except (ValueError, TypeError) as e:
            raise EnvelopeValidationError(
                f"Invalid timestamp value: '{data['timestamp']}'. Must be a Unix integer."
            ) from e

        return cls(
            version=data["version"],
            sender_id=data["sender_id"],
            recipient_id=data["recipient_id"],
            timestamp=timestamp,  # already validated and cast above
            envelope_nonce=data["envelope_nonce"],
            ciphertext=data["ciphertext"],
            nonce=data["nonce"],
            ephemeral_pub=data["ephemeral_pub"],
            kem_ciphertext=data["kem_ciphertext"],
            classical_sig=data["classical_sig"],
            pqc_sig=data["pqc_sig"],
        )

    # ─────────────────────────────────────────
    # FROM JSON / BYTES
    # ─────────────────────────────────────────

    @classmethod
    def from_json(cls, json_str: str, max_bytes: int | None = None) -> Envelope:
        """
        Parse and construct an Envelope from a JSON string.

        Performs a fast character-count check before decoding to avoid spending
        CPU on parsing a string that is clearly too large. Then encodes to UTF-8
        bytes and delegates to from_dict().
        """
        limit = max_bytes if max_bytes is not None else cls.MAX_BYTES

        if len(json_str) > limit:
            raise EnvelopeTooLargeError(
                f"Envelope JSON exceeds {limit} bytes (preliminary character count check)."
            )

        raw = json_str.encode("utf-8")

        if len(raw) > limit:
            raise EnvelopeTooLargeError(
                f"Envelope JSON is {len(raw)} bytes, maximum allowed is {limit} bytes."
            )

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise EnvelopeValidationError("Invalid JSON payload structure.") from None

        if not isinstance(data, dict):
            raise EnvelopeValidationError("JSON payload must be an object/dictionary.")

        return cls.from_dict(data, max_bytes=limit)

    @classmethod
    def from_bytes(cls, raw: bytes, max_bytes: int | None = None) -> Envelope:
        """Reconstruct from raw UTF-8 bytes (WebSocket frame body)."""
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EnvelopeValidationError("Envelope bytes must be valid UTF-8 JSON.") from exc
        return cls.from_json(text, max_bytes=max_bytes)

    # ─────────────────────────────────────────
    # TO DICT / JSON / BYTES
    # ─────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """
        Return the raw dict suitable for open_seal() or transport.
        This is the exact structure that hybrid.py expects.
        """
        return {
            "version": self.version,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "timestamp": self.timestamp,
            "envelope_nonce": self.envelope_nonce,
            "ciphertext": self.ciphertext,
            "nonce": self.nonce,
            "ephemeral_pub": self.ephemeral_pub,
            "kem_ciphertext": self.kem_ciphertext,
            "classical_sig": self.classical_sig,
            "pqc_sig": self.pqc_sig,
        }

    def to_json(self, indent: int | None = None) -> str:
        """Serialise to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_bytes(self) -> bytes:
        """
        Serialise to UTF-8 bytes (suitable for a WebSocket frame body).

        Also caches the byte-length so the size_bytes property does not need to
        re-encode the JSON.
        """
        raw = self.to_json().encode("utf-8")
        object.__setattr__(self, "_size_bytes_cache", len(raw))
        return raw

    # ─────────────────────────────────────────
    # CONVENIENCE CHECKS
    # ─────────────────────────────────────────

    def age_seconds(self) -> float:
        """Seconds elapsed since this envelope was sealed."""
        return time.time() - self.timestamp

    def is_fresh(self, max_age_seconds: float = 300.0, clock_skew: float = 30.0) -> bool:
        """
        Return True if the envelope is within the freshness window.

        An envelope is fresh when its age (seconds since timestamp) satisfies:
            -clock_skew <= age <= max_age_seconds
        A negative age (future timestamp within the allowed skew) is acceptable
        to accommodate minor clock differences between machines.
        """
        if max_age_seconds < 0 or clock_skew < 0:
            raise ValueError("max_age_seconds and clock_skew must be non-negative.")
        age = self.age_seconds()
        return -clock_skew <= age <= max_age_seconds

    def assert_fresh(self, max_age_seconds: float = 300.0, clock_skew: float = 30.0) -> None:
        """Raise EnvelopeExpiredError if the envelope is not fresh."""
        if max_age_seconds < 0 or clock_skew < 0:
            raise ValueError("max_age_seconds and clock_skew must be non-negative.")
        age = self.age_seconds()  # single capture
        if not (-clock_skew <= age <= max_age_seconds):
            raise EnvelopeExpiredError(
                f"Envelope is {age:.1f}s old (max_age={max_age_seconds}s, skew={clock_skew}s)."
            )

    def addressed_to(self, entity_id: str) -> bool:
        """Return True if this envelope is addressed to entity_id."""
        return self.recipient_id == entity_id

    def sent_by(self, entity_id: str) -> bool:
        """Return True if this envelope claims to be from entity_id."""
        return self.sender_id == entity_id

    @property
    def size_bytes(self) -> int:
        if self._size_bytes_cache is None:
            raw = self.to_json().encode("utf-8")
            object.__setattr__(self, "_size_bytes_cache", len(raw))
        assert self._size_bytes_cache is not None  # narrows type for checkers
        return self._size_bytes_cache

    # ─────────────────────────────────────────
    # UTILITIES
    # ─────────────────────────────────────────

    @staticmethod
    def _safe_prefix(val: Any, n: int = 8) -> str:
        if not isinstance(val, str) or len(val) == 0:
            return "<invalid>"
        return val[:n] + ("..." if len(val) > n else "")

    def __repr__(self) -> str:
        return (
            f"Envelope("
            f"from={self._safe_prefix(self.sender_id)}, "
            f"to={self._safe_prefix(self.recipient_id)}, "
            f"ts={self.timestamp}, "
            f"nonce={self._safe_prefix(self.envelope_nonce)}, "
            f"size={self.size_bytes}B)"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Envelope):
            return False
        return (
            self.envelope_nonce == other.envelope_nonce
            and self.sender_id == other.sender_id
            and self.recipient_id == other.recipient_id
            and self.ciphertext == other.ciphertext
        )

    def __hash__(self) -> int:
        return hash((self.envelope_nonce, self.sender_id, self.recipient_id, self.ciphertext))
