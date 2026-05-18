"""
uxsp.core.nonce — Nonce Generation and In-Memory Nonce Store

What this file does:
    Provides the building blocks for one-time token (nonce) management used in
    replay-attack prevention.  Every UXSP envelope carries a 128-bit random
    nonce (envelope_nonce) that must be stored after first use so that any
    re-delivery of the same envelope is detected and rejected.

    This file is intentionally lightweight (no external dependencies beyond the
    standard library) so it can be used in resource-constrained environments.
    For production workloads needing shared state across multiple processes or
    servers, use the heavier backends in uxsp.storage.noncestore.

Key classes:
    NonceStore      — Abstract base class defining mark_used(), is_seen(), cleanup().
    MemoryNonceStore — Thread-safe in-process nonce store (dev/testing only).
    UXSPStoreError  — Raised when the backing store is unavailable.

Key function:
    generate_nonce() — Return a cryptographically random 128-bit hex nonce.
"""
from __future__ import annotations

import os
import threading
import time
import warnings
from abc import ABC, abstractmethod
from collections import OrderedDict

# ─────────────────────────────────────────────
# ERRORS
# ─────────────────────────────────────────────


class UXSPStoreError(Exception):
    pass


# ─────────────────────────────────────────────
# NONCE GENERATION
# ─────────────────────────────────────────────

NONCE_BYTES = 16  # 128 bits


def generate_nonce() -> str:
    """
    Generate a cryptographically random 128-bit nonce.

    Returns a 32-character lowercase hex string suitable for use as an
    envelope_nonce, handshake nonce, or any other single-use token.
    """

    return os.urandom(NONCE_BYTES).hex()


# ─────────────────────────────────────────────
# ABSTRACT STORE
# ─────────────────────────────────────────────


class NonceStore(ABC):
    """
    Abstract interface for nonce tracking backends.

    What this class does:
        Defines the contract that all nonce store implementations must satisfy.
        The critical method is mark_used(): it must be atomic — it should test
        whether a nonce is already present AND insert it in a single operation
        so that concurrent callers cannot both pass the replay check for the
        same nonce.

        Implementations:
          MemoryNonceStore  (this file)       — in-process, dev/test.
          RedisNonceStore   (storage layer)   — multi-process, production.
          PostgresNonceStore (storage layer)  — durable audit log.
          TieredNonceStore   (storage layer)  — Redis L1 + Postgres L2.
    """
    @abstractmethod
    def mark_used(self, nonce: str, ttl_seconds: int = 300) -> bool:
        """
        Atomically mark nonce as used.
        Returns True (first use) or False (replay).
        Raises UXSPStoreError if backend is unavailable.
        """
        ...

    @abstractmethod
    def is_seen(self, nonce: str) -> bool:
        """
        Diagnostic helper: return True if the nonce is currently tracked
        as used (i.e. it is stored AND has not yet expired).

        This is NOT a replay-protection check.  A nonce that was used but
        has since expired will return False — the same as a nonce that was
        never used.  Security-critical replay checks must go through
        mark_used(), which is the authoritative atomic test-and-set.
        """
        ...

    def is_used(self, nonce: str) -> bool:
        """Deprecated alias for is_seen(). Use is_seen() instead."""
        warnings.warn(
            "is_used() is deprecated; use is_seen() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.is_seen(nonce)

    @abstractmethod
    def cleanup(self) -> int:
        """Remove expired entries. Returns count removed."""
        ...


# ─────────────────────────────────────────────
# MEMORY STORE — development and testing
# ─────────────────────────────────────────────


class MemoryNonceStore(NonceStore):
    """
    A thread-safe, in-process nonce store backed by an OrderedDict.

    What this class does:
        Tracks which nonces have been used within their TTL window.  Expired
        nonces are lazily pruned every 1 000 mark_used() calls, or immediately
        when the store reaches MAX_NONCE_STORE_SIZE entries.

    Limitations:
        State is not shared between processes and is lost on restart.  Use only
        for development, unit tests, or single-process deployments.  Production
        multi-process systems should use RedisNonceStore or PostgresNonceStore.
    """
    MAX_NONCE_STORE_SIZE = 100_000
    def __init__(self) -> None:
        # OrderedDict maintains insertion order (oldest first)
        self._store: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.RLock()
        self._calls_since_cleanup: int = 0

    def mark_used(self, nonce: str, ttl_seconds: int = 300) -> bool:
        with self._lock:
            now = time.time()
            self._calls_since_cleanup += 1

            if self._calls_since_cleanup >= 1000:
                self._cleanup_unlocked(now)
                self._calls_since_cleanup = 0

            if nonce in self._store:
                return False

            if len(self._store) >= self.MAX_NONCE_STORE_SIZE:
                self._cleanup_unlocked(now)

                if len(self._store) >= self.MAX_NONCE_STORE_SIZE:
                    raise UXSPStoreError(
                        f"MemoryNonceStore is full ({self.MAX_NONCE_STORE_SIZE} entries). "
                        f"Call cleanup() to remove expired entries, or use a larger store."
                    )

            self._store[nonce] = now + ttl_seconds
            return True

    def is_seen(self, nonce: str) -> bool:
        """
        Diagnostic helper: return True if the nonce is currently tracked
        as used (i.e. stored AND not yet expired).

        NOT a replay-protection check — expired nonces return False even
        though they were previously used.  Use mark_used() for security.
        """
        with self._lock:
            exp = self._store.get(nonce)
            if exp is None:
                return False
            return time.time() < exp

    def _cleanup_unlocked(self, now: float) -> int:
        """Must be called with self._lock already held."""
        expired = [k for k, exp in self._store.items() if exp <= now]
        for k in expired:
            del self._store[k]
        return len(expired)

    def cleanup(self) -> int:
        """Removes expired nonces to free up memory."""
        with self._lock:
            return self._cleanup_unlocked(time.time())
