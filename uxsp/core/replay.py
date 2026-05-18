"""
uxsp.core.replay — Replay-Attack Guard

What this file does:
    Provides the ReplayGuard class, which is the primary defence against replay
    attacks on sealed UXSP envelopes.  A replay attack occurs when an adversary
    captures a legitimate encrypted envelope and re-transmits it later, hoping
    the receiver will process the same plaintext twice.

    ReplayGuard combines two complementary checks:
        1. Freshness window — the envelope timestamp must be within
           [-clock_skew, +window_seconds] of the current time.  This limits the
           window during which a captured envelope is usable.
        2. Nonce uniqueness — every envelope carries a unique envelope_nonce.
           After the first successful open, the nonce is persisted in a
           NonceStore.  Any future envelope with the same nonce is rejected with
           DuplicateNonceError even if it arrives within the freshness window.

    Typical usage (two-phase):
        guard.precheck(envelope)   # cheap freshness + non-blocking nonce peek
        plaintext = open_seal(...)  # do the expensive crypto only if fresh
        guard.commit(envelope)     # atomically mark nonce as used

    Or one-shot:
        guard.check_and_open(envelope, recipient, sender_card)

Key classes:
    ReplayGuard        — Concrete replay guard implementation.
    DefaultReplayGuard — Protocol (structural type) for type-checking.

Key errors:
    ReplayError         — Base exception for all replay violations.
    StaleEnvelopeError  — Timestamp too old.
    DuplicateNonceError — Nonce already used (definite replay).
    FutureEnvelopeError — Timestamp too far in the future.
"""
from __future__ import annotations

import time
from typing import Any, Protocol, runtime_checkable

from uxsp.core.envelope import Envelope
from uxsp.crypto.hybrid import decrypt_verified_envelope, verify_envelope

from .nonce import NonceStore

# ─────────────────────────────────────────────
# REPLAY ERRORS
# ─────────────────────────────────────────────


class ReplayError(Exception):
    """Base class. Catch this to handle all replay violations."""

    pass


class StaleEnvelopeError(ReplayError):
    """Envelope timestamp is outside the acceptable window."""

    pass


class DuplicateNonceError(ReplayError):
    """Nonce already used — definite replay attack."""

    pass


class FutureEnvelopeError(ReplayError):
    """Envelope timestamp is in the future."""

    pass


# ─────────────────────────────────────────────
# REPLAY GUARD
# ─────────────────────────────────────────────


class ReplayGuard:
    """
    Stateful guard that prevents replay attacks on UXSP envelopes.

    What this class does:
        Combines a freshness-window check (envelope timestamp must be recent)
        with nonce tracking (each envelope_nonce may only be committed once).
        The two-phase API (precheck / commit) lets you perform the cheap
        checks before investing in expensive crypto, then atomically mark the
        nonce only after successful decryption.

    Constructor parameters:
        store          — A NonceStore backend (MemoryNonceStore for dev,
                          RedisNonceStore / PostgresNonceStore for production).
        window_seconds — Maximum allowed envelope age in seconds (default 300).
        clock_skew     — Tolerance for future timestamps in seconds (default 30).
    """
    def __init__(self, store: NonceStore, window_seconds: int = 300, clock_skew: int = 30) -> None:
        if not isinstance(window_seconds, int) or window_seconds <= 0:
            raise ValueError(f"window_seconds must be a positive integer, got {window_seconds!r}")
        if not isinstance(clock_skew, int) or clock_skew < 0:
            raise ValueError(f"clock_skew must be a non-negative integer, got {clock_skew!r}")
        if clock_skew >= window_seconds:
            raise ValueError(
                f"clock_skew ({clock_skew}s) must be less than "
                f"window_seconds ({window_seconds}s). "
                f"Otherwise future envelopes could exceed the window."
            )

        if store is None:
            raise TypeError("ReplayGuard requires a persistent NonceStore...")

        self._store = store
        self._window = window_seconds
        self._clock_skew = clock_skew

    def _normalise(self, envelope: dict[str, Any] | Envelope) -> dict[str, Any]:

        if isinstance(envelope, Envelope):
            d: dict[str, Any] = envelope.to_dict()
        else:
            d = envelope

        if not isinstance(d, dict):
            raise ValueError("Envelope must be a dictionary or Envelope instance.")

        for field in ("timestamp", "envelope_nonce"):
            if field not in d:
                raise ValueError(
                    f"Envelope missing required field: '{field}'. "
                    f"Was this envelope created with UXSP?"
                )

        try:
            ts = int(d["timestamp"])
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Envelope timestamp must be a Unix integer, got {d['timestamp']!r}."
            ) from exc

        nonce = d["envelope_nonce"]
        if not isinstance(nonce, str) or not nonce:
            raise ValueError("Envelope nonce must be a non-empty string.")

        return {**d, "timestamp": ts, "envelope_nonce": nonce}

    def _check_freshness_normalised(self, d: dict[str, Any]) -> None:
        ts = d["timestamp"]
        now = time.time()
        age = now - ts
        if age > self._window:
            raise StaleEnvelopeError(
                f"Envelope is {age:.0f}s old. "
                f"Maximum: {self._window}s. "
                f"Possible replay of a captured envelope."
            )
        if ts > now + self._clock_skew:
            raise FutureEnvelopeError(
                f"Envelope is {ts - now:.0f}s in the future. Allowed skew: {self._clock_skew}s."
            )

    def check_freshness(self, envelope: dict[str, Any] | Envelope) -> None:
        """
        Check only the envelope timestamp; do not touch the nonce store.

        Raises StaleEnvelopeError if the envelope is older than window_seconds.
        Raises FutureEnvelopeError if the timestamp is more than clock_skew
        seconds in the future.
        """
        d = self._normalise(envelope)
        self._check_freshness_normalised(d)

    def precheck(self, envelope: dict[str, Any] | Envelope) -> None:
        """
        Perform a non-blocking pre-flight check before expensive crypto.

        Verifies freshness (timestamp within window) and checks whether the
        nonce appears to already be in the store via is_seen() (a diagnostic
        hint, NOT an atomic replay check).  Call commit() after successful
        decryption to atomically record the nonce.

        Raises StaleEnvelopeError, FutureEnvelopeError, or DuplicateNonceError.
        """

        d = self._normalise(envelope)
        self._check_freshness_normalised(d)
        nonce = d["envelope_nonce"]
        if self._store.is_seen(nonce):
            raise DuplicateNonceError(f"Nonce '{nonce[:8]}...' already used. Replay rejected.")

    def commit(self, envelope: dict[str, Any] | Envelope) -> None:
        """
        Atomically mark the envelope nonce as used after successful decryption.

        Verifies freshness again (in case time advanced since precheck) then
        calls mark_used() on the NonceStore.  Raises DuplicateNonceError if
        another concurrent caller already committed the same nonce (definite
        replay).  This is the security-critical atomic step.
        """

        d = self._normalise(envelope)
        self._check_freshness_normalised(d)
        nonce = d["envelope_nonce"]
        first_use = self._store.mark_used(nonce, ttl_seconds=self._window + self._clock_skew)
        if not first_use:
            raise DuplicateNonceError(f"Nonce '{nonce[:8]}...' already used. Replay rejected.")

    def check_and_commit(self, envelope: dict[str, Any] | Envelope) -> None:
        """Atomically verify freshness AND mark nonce as used. One-shot."""
        self.commit(envelope)

    def check_and_open(
        self,
        envelope: dict[str, Any] | Envelope,
        recipient_identity: Any,
        sender_card: Any,
    ) -> bytes:
        """
        One-shot method that combines replay checking and decryption.

        Validates sender_id against sender_card, checks freshness, atomically
        marks the nonce as used, verifies the envelope signatures, and decrypts
        the ciphertext.  Returns the plaintext bytes on success.

        Raises StaleEnvelopeError, DuplicateNonceError, FutureEnvelopeError, or
        EnvelopeValidationError if any check fails.
        """

        d: dict[str, Any] = self._normalise(envelope)

        if d.get("sender_id") != sender_card.entity_id:
            raise ValueError("Envelope sender_id does not match sender card.")

        self._check_freshness_normalised(d)

        nonce = d["envelope_nonce"]
        first_use = self._store.mark_used(nonce, ttl_seconds=self._window + self._clock_skew)
        if not first_use:
            raise DuplicateNonceError(f"Nonce '{nonce[:8]}...' already used. Replay rejected.")

        verified = verify_envelope(
            envelope=d,
            sender_public_keys=sender_card.public_keys,
            expected_recipient_id=recipient_identity.entity_id,
            expected_sender_id=sender_card.entity_id,
            max_age_seconds=self._window,
            clock_skew_seconds=self._clock_skew,
        )

        return decrypt_verified_envelope(verified, recipient_identity.keypair)

    @property
    def store(self) -> NonceStore:
        return self._store

    @property
    def window_seconds(self) -> int:
        return self._window

    @property
    def clock_skew(self) -> int:
        return self._clock_skew


@runtime_checkable
class DefaultReplayGuard(Protocol):
    """
    Structural protocol type that any replay-guard-compatible object must satisfy.

    What this class does:
        Acts as a typing.Protocol so that type checkers accept any object
        implementing the replay guard API, not just ReplayGuard itself.  This
        allows dependency injection of alternative implementations (e.g. a
        distributed guard backed by a different nonce store).

        Methods required: check_freshness, precheck, commit, check_and_commit,
        check_and_open, and the store / window_seconds / clock_skew properties.
    """
    def check_freshness(self, envelope: dict[str, Any] | Envelope) -> None: ...
    def precheck(self, envelope: dict[str, Any] | Envelope) -> None: ...
    def commit(self, envelope: dict[str, Any] | Envelope) -> None: ...
    def check_and_commit(self, envelope: dict[str, Any] | Envelope) -> None: ...
    def check_and_open(
        self, envelope: dict[str, Any] | Envelope, recipient_identity: Any, sender_card: Any
    ) -> bytes: ...
    @property
    def store(self) -> NonceStore: ...
    @property
    def window_seconds(self) -> int: ...
    @property
    def clock_skew(self) -> int: ...
