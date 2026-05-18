"""
Full-coverage pytest suite for nonce.py.

Coverage targets (every executable line):
  - generate_nonce()
  - NonceStore (abstract methods, deprecated is_used alias)
  - MemoryNonceStore.mark_used()       — first-use, replay, capacity guard,
                                         periodic cleanup trigger
  - MemoryNonceStore.is_seen()         — present+unexpired, present+expired, absent
  - MemoryNonceStore._cleanup_unlocked()
  - MemoryNonceStore.cleanup()
  - UXSPStoreError
"""

from __future__ import annotations

import threading
import time
import warnings
from unittest.mock import patch

import pytest

from uxsp.core.nonce import (
    NONCE_BYTES,
    MemoryNonceStore,
    NonceStore,
    UXSPStoreError,
    generate_nonce,
)

# ─────────────────────────────────────────────
# UXSPStoreError
# ─────────────────────────────────────────────

class TestUXSPStoreError:
    def test_is_exception_subclass(self):
        """UXSPStoreError must derive from Exception."""
        assert issubclass(UXSPStoreError, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(UXSPStoreError, match="boom"):
            raise UXSPStoreError("boom")

    def test_message_preserved(self):
        err = UXSPStoreError("detail msg")
        assert str(err) == "detail msg"


# ─────────────────────────────────────────────
# generate_nonce
# ─────────────────────────────────────────────

class TestGenerateNonce:
    def test_returns_hex_string(self):
        n = generate_nonce()
        assert isinstance(n, str)
        int(n, 16)  # raises ValueError if not valid hex

    def test_length_matches_nonce_bytes(self):
        # each byte → 2 hex chars
        assert len(generate_nonce()) == NONCE_BYTES * 2

    def test_uniqueness(self):
        nonces = {generate_nonce() for _ in range(1000)}
        assert len(nonces) == 1000

    def test_uses_os_urandom(self):
        """Verify generate_nonce calls os.urandom with NONCE_BYTES."""
        fake_bytes = b"\xab" * NONCE_BYTES
        with patch("uxsp.core.nonce.os.urandom", return_value=fake_bytes) as mock_rng:
            result = generate_nonce()
        mock_rng.assert_called_once_with(NONCE_BYTES)
        assert result == fake_bytes.hex()


# ─────────────────────────────────────────────
# NonceStore (abstract base)
# ─────────────────────────────────────────────

class TestNonceStoreAbstract:
    def test_cannot_be_instantiated_directly(self):
        with pytest.raises(TypeError):
            NonceStore()  # type: ignore[abstract]

    def test_is_used_deprecation_warning(self):
        """is_used() must emit DeprecationWarning and delegate to is_seen()."""
        store = MemoryNonceStore()
        nonce = generate_nonce()
        store.mark_used(nonce, ttl_seconds=60)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = store.is_used(nonce)

        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "is_used() is deprecated" in str(w[0].message)
        assert result is True  # delegates to is_seen()

    def test_is_used_returns_false_for_unseen(self):
        store = MemoryNonceStore()
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            assert store.is_used("nonexistent") is False


# ─────────────────────────────────────────────
# MemoryNonceStore — mark_used
# ─────────────────────────────────────────────

class TestMarkUsed:
    def setup_method(self):
        self.store = MemoryNonceStore()

    def test_first_use_returns_true(self):
        assert self.store.mark_used("abc", ttl_seconds=60) is True

    def test_replay_returns_false(self):
        self.store.mark_used("abc", ttl_seconds=60)
        assert self.store.mark_used("abc", ttl_seconds=60) is False

    def test_different_nonces_both_accepted(self):
        assert self.store.mark_used("n1", ttl_seconds=60) is True
        assert self.store.mark_used("n2", ttl_seconds=60) is True

    def test_default_ttl_is_300(self):
        """mark_used with default TTL stores expiry ~300 s in the future."""
        before = time.time()
        self.store.mark_used("x")
        after = time.time()
        exp = self.store._store["x"]
        assert before + 299 <= exp <= after + 301

    def test_expired_nonce_can_be_reused(self):
        """After TTL expires, the same nonce passes the replay check again."""
        self.store.mark_used("reuse", ttl_seconds=-1)  # already expired
        self.store.cleanup()  # remove expired entry
        assert self.store.mark_used("reuse", ttl_seconds=60) is True

    def test_full_store_raises_after_cleanup_still_full(self):
        """
        When the store is full and cleanup cannot free space
        (all entries unexpired), mark_used must raise UXSPStoreError.
        """
        cap = MemoryNonceStore.MAX_NONCE_STORE_SIZE
        store = MemoryNonceStore()
        # Fill to capacity with long TTLs so cleanup removes nothing
        for i in range(cap):
            store._store[f"nonce_{i}"] = time.time() + 9999

        with pytest.raises(UXSPStoreError, match="MemoryNonceStore is full"):
            store.mark_used("overflow_nonce", ttl_seconds=60)

    def test_full_store_accepts_after_expired_entries_freed(self):
        """
        When the store is full but entries are expired,
        cleanup inside mark_used frees room and the call succeeds.
        """
        cap = MemoryNonceStore.MAX_NONCE_STORE_SIZE
        store = MemoryNonceStore()
        # Fill with already-expired entries
        past = time.time() - 1
        for i in range(cap):
            store._store[f"old_{i}"] = past

        # mark_used triggers internal cleanup and succeeds
        assert store.mark_used("new_nonce", ttl_seconds=60) is True

    def test_periodic_cleanup_triggered_every_1000_calls(self):
        """
        After 999 mark_used calls the counter resets on the 1000th call,
        exercising the _calls_since_cleanup branch.
        """
        store = MemoryNonceStore()
        store._calls_since_cleanup = 999  # prime the counter

        # Add some expired entries so _cleanup_unlocked actually removes them
        store._store["stale"] = time.time() - 1

        store.mark_used("trigger_cleanup", ttl_seconds=60)

        # Counter should have been reset to 0 after cleanup
        assert store._calls_since_cleanup == 0
        # Stale entry should be gone
        assert "stale" not in store._store

    def test_thread_safety(self):
        """Concurrent mark_used calls must not corrupt state."""
        store = MemoryNonceStore()
        results = []
        errors = []

        def worker(nonce):
            try:
                r = store.mark_used(nonce, ttl_seconds=60)
                results.append(r)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"n{i}",)) for i in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert all(results)  # each unique nonce → True


# ─────────────────────────────────────────────
# MemoryNonceStore — is_seen
# ─────────────────────────────────────────────

class TestIsSeen:
    def setup_method(self):
        self.store = MemoryNonceStore()

    def test_unseen_nonce_returns_false(self):
        assert self.store.is_seen("ghost") is False

    def test_unexpired_nonce_returns_true(self):
        self.store.mark_used("active", ttl_seconds=300)
        assert self.store.is_seen("active") is True

    def test_expired_nonce_returns_false(self):
        """A nonce whose TTL has passed is treated as unseen."""
        self.store._store["dead"] = time.time() - 1  # already expired
        assert self.store.is_seen("dead") is False

    def test_nonce_not_in_store_early_return(self):
        """Exercises the `if exp is None: return False` branch explicitly."""
        # Confirm the nonce truly isn't in the underlying dict
        assert "missing" not in self.store._store
        assert self.store.is_seen("missing") is False


# ─────────────────────────────────────────────
# MemoryNonceStore — cleanup / _cleanup_unlocked
# ─────────────────────────────────────────────

class TestCleanup:
    def setup_method(self):
        self.store = MemoryNonceStore()

    def test_cleanup_removes_expired(self):
        self.store._store["expired"] = time.time() - 1
        removed = self.store.cleanup()
        assert removed == 1
        assert "expired" not in self.store._store

    def test_cleanup_keeps_unexpired(self):
        self.store.mark_used("live", ttl_seconds=300)
        removed = self.store.cleanup()
        assert removed == 0
        assert "live" in self.store._store

    def test_cleanup_returns_correct_count(self):
        now = time.time()
        for i in range(5):
            self.store._store[f"exp_{i}"] = now - 1   # expired
        for i in range(3):
            self.store._store[f"live_{i}"] = now + 300  # live
        removed = self.store.cleanup()
        assert removed == 5
        assert len(self.store._store) == 3

    def test_cleanup_on_empty_store(self):
        assert self.store.cleanup() == 0

    def test_cleanup_mixed_boundary(self):
        """Nonces expiring exactly at `now` count as expired (<= now)."""
        exact_now = time.time()
        self.store._store["boundary"] = exact_now
        with patch("uxsp.core.nonce.time.time", return_value=exact_now):
            removed = self.store.cleanup()
        assert removed == 1

    def test_cleanup_unlocked_called_with_lock_held(self):
        """_cleanup_unlocked must work when called directly (internal API)."""
        self.store._store["old"] = time.time() - 1
        now = time.time()
        removed = self.store._cleanup_unlocked(now)
        assert removed == 1
