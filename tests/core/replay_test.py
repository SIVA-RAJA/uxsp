"""
Full-coverage pytest suite for replay.py.

Strategy
--------
All third-party / sibling imports are patched at the module boundary before
the module under test is imported.  This keeps the tests self-contained and
lets them run without the real `uxsp` package installed.

Known bug documented
--------------------
`ReplayGuard.check_and_open` references the name `nonce` on line 159-160
but never assigns it after extracting the normalised dict `d`.  The correct
code should be `nonce = d["envelope_nonce"]` before `self._store.mark_used`.
Tests that exercise the happy-path of `check_and_open` are written to expose
this bug (they expect NameError) so that fixing the bug will also make those
tests go green without modification.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Stub out every external import so replay.py loads in isolation
# ─────────────────────────────────────────────────────────────────────────────

class _Envelope:
    def to_dict(self):
        return getattr(self, "_d", {})

@pytest.fixture(autouse=True)
def _patch_replay(monkeypatch):
    monkeypatch.setattr("uxsp.core.replay.Envelope", _Envelope)
    monkeypatch.setattr("uxsp.core.replay.decrypt_verified_envelope", MagicMock(return_value=b"plaintext"))
    monkeypatch.setattr("uxsp.core.replay.verify_envelope", MagicMock(return_value={"verified": True}))
    monkeypatch.setattr("uxsp.core.replay.NonceStore", type("NonceStore", (), {}))

from uxsp.core.replay import (
    DefaultReplayGuard,
    DuplicateNonceError,
    FutureEnvelopeError,
    ReplayError,
    ReplayGuard,
    StaleEnvelopeError,
)

Envelope = _Envelope


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_store(*, is_seen: bool = False, mark_used: bool = True) -> MagicMock:
    """Return a mock NonceStore."""
    store = MagicMock()
    store.is_seen.return_value = is_seen
    store.mark_used.return_value = mark_used   # True = first use
    return store


def _fresh_env(*, nonce: str = "abc-nonce-xyz", offset: int = 0) -> dict:
    """Dict envelope with a timestamp `offset` seconds from now."""
    return {
        "timestamp": int(time.time()) + offset,
        "envelope_nonce": nonce,
    }


def _make_guard(store=None, window: int = 300, skew: int = 30) -> ReplayGuard:
    if store is None:
        store = _make_store()
    return ReplayGuard(store, window_seconds=window, clock_skew=skew)


def _envelope_obj(d: dict) -> Envelope:
    """Wrap a dict in a stub Envelope instance."""
    env = Envelope()
    env._d = d
    return env


# ─────────────────────────────────────────────────────────────────────────────
# Error hierarchy
# ─────────────────────────────────────────────────────────────────────────────

class TestErrorHierarchy:
    def test_stale_is_replay_error(self):
        assert issubclass(StaleEnvelopeError, ReplayError)

    def test_duplicate_is_replay_error(self):
        assert issubclass(DuplicateNonceError, ReplayError)

    def test_future_is_replay_error(self):
        assert issubclass(FutureEnvelopeError, ReplayError)

    def test_replay_error_is_exception(self):
        assert issubclass(ReplayError, Exception)

    def test_instantiate_replay_error(self):
        e = ReplayError("boom")
        assert str(e) == "boom"

    def test_instantiate_stale(self):
        assert isinstance(StaleEnvelopeError("s"), ReplayError)

    def test_instantiate_duplicate(self):
        assert isinstance(DuplicateNonceError("d"), ReplayError)

    def test_instantiate_future(self):
        assert isinstance(FutureEnvelopeError("f"), ReplayError)


# ─────────────────────────────────────────────────────────────────────────────
# ReplayGuard.__init__  validation
# ─────────────────────────────────────────────────────────────────────────────

class TestReplayGuardInit:
    def test_happy_path_defaults(self):
        g = _make_guard()
        assert g.window_seconds == 300
        assert g.clock_skew == 30

    def test_happy_path_explicit(self):
        g = _make_guard(window=120, skew=0)
        assert g.window_seconds == 120
        assert g.clock_skew == 0

    def test_window_zero_raises(self):
        with pytest.raises(ValueError, match="window_seconds must be a positive integer"):
            ReplayGuard(_make_store(), window_seconds=0)

    def test_window_negative_raises(self):
        with pytest.raises(ValueError, match="window_seconds must be a positive integer"):
            ReplayGuard(_make_store(), window_seconds=-1)

    def test_window_non_int_raises(self):
        with pytest.raises(ValueError, match="window_seconds must be a positive integer"):
            ReplayGuard(_make_store(), window_seconds=60.0)

    def test_clock_skew_negative_raises(self):
        with pytest.raises(ValueError, match="clock_skew must be a non-negative integer"):
            ReplayGuard(_make_store(), clock_skew=-1)

    def test_clock_skew_non_int_raises(self):
        with pytest.raises(ValueError, match="clock_skew must be a non-negative integer"):
            ReplayGuard(_make_store(), clock_skew=10.5)

    def test_skew_equals_window_raises(self):
        with pytest.raises(ValueError, match="clock_skew"):
            ReplayGuard(_make_store(), window_seconds=60, clock_skew=60)

    def test_skew_greater_than_window_raises(self):
        with pytest.raises(ValueError, match="clock_skew"):
            ReplayGuard(_make_store(), window_seconds=60, clock_skew=61)

    def test_none_store_raises_type_error(self):
        with pytest.raises(TypeError, match="NonceStore"):
            ReplayGuard(None, window_seconds=300, clock_skew=30)

    def test_store_property(self):
        store = _make_store()
        g = ReplayGuard(store, window_seconds=300, clock_skew=30)
        assert g.store is store


# ─────────────────────────────────────────────────────────────────────────────
# ReplayGuard._normalise
# ─────────────────────────────────────────────────────────────────────────────

class TestNormalise:
    def setup_method(self):
        self.guard = _make_guard()

    def test_dict_passthrough(self):
        d = _fresh_env()
        result = self.guard._normalise(d)
        assert result["envelope_nonce"] == "abc-nonce-xyz"
        assert isinstance(result["timestamp"], int)

    def test_envelope_instance_calls_to_dict(self):
        d = _fresh_env(nonce="env-nonce")
        env = _envelope_obj(d)
        result = self.guard._normalise(env)
        assert result["envelope_nonce"] == "env-nonce"

    def test_non_dict_non_envelope_raises(self):
        # Envelope.to_dict returns a non-dict → triggers the isinstance(d, dict) check
        bad_env = Envelope()
        bad_env._d = "not-a-dict"               # to_dict() returns str
        with pytest.raises(ValueError, match="Envelope must be a dictionary"):
            self.guard._normalise(bad_env)

    def test_missing_timestamp_raises(self):
        with pytest.raises(ValueError, match="missing required field: 'timestamp'"):
            self.guard._normalise({"envelope_nonce": "n"})

    def test_missing_nonce_raises(self):
        with pytest.raises(ValueError, match="missing required field: 'envelope_nonce'"):
            self.guard._normalise({"timestamp": int(time.time())})

    def test_non_castable_timestamp_raises(self):
        with pytest.raises(ValueError, match="timestamp must be a Unix integer"):
            self.guard._normalise({"timestamp": "bad-ts", "envelope_nonce": "n"})

    def test_none_timestamp_raises(self):
        with pytest.raises(ValueError, match="timestamp must be a Unix integer"):
            self.guard._normalise({"timestamp": None, "envelope_nonce": "n"})

    def test_empty_nonce_raises(self):
        with pytest.raises(ValueError, match="nonce must be a non-empty string"):
            self.guard._normalise({"timestamp": int(time.time()), "envelope_nonce": ""})

    def test_non_string_nonce_raises(self):
        with pytest.raises(ValueError, match="nonce must be a non-empty string"):
            self.guard._normalise({"timestamp": int(time.time()), "envelope_nonce": 12345})

    def test_float_timestamp_is_cast_to_int(self):
        ts = time.time()
        result = self.guard._normalise({"timestamp": ts, "envelope_nonce": "n"})
        assert isinstance(result["timestamp"], int)

    def test_extra_fields_preserved(self):
        d = {**_fresh_env(), "sender_id": "alice", "recipient_id": "bob"}
        result = self.guard._normalise(d)
        assert result["sender_id"] == "alice"


# ─────────────────────────────────────────────────────────────────────────────
# ReplayGuard._check_freshness_normalised
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckFreshnessNormalised:
    def setup_method(self):
        self.guard = _make_guard(window=300, skew=30)

    def _d(self, offset=0):
        return {"timestamp": int(time.time()) + offset, "envelope_nonce": "n"}

    def test_fresh_passes(self):
        self.guard._check_freshness_normalised(self._d())          # no exception

    @patch("uxsp.core.replay.time.time")
    def test_exactly_at_boundary_passes(self, mock_time):
        mock_time.return_value = 1000.0
        # age == window exactly — NOT > window, so should pass
        # timestamp = 1000.0 - 300 = 700.0
        d = {"timestamp": 700, "envelope_nonce": "n"}
        self.guard._check_freshness_normalised(d)

    def test_one_second_over_window_raises_stale(self):
        with pytest.raises(StaleEnvelopeError):
            self.guard._check_freshness_normalised(self._d(offset=-301))

    def test_very_old_raises_stale(self):
        with pytest.raises(StaleEnvelopeError):
            self.guard._check_freshness_normalised(self._d(offset=-9999))

    def test_within_allowed_skew_passes(self):
        self.guard._check_freshness_normalised(self._d(offset=29))  # 29 < 30 skew

    def test_exactly_at_skew_passes(self):
        # ts == now + skew → NOT > now + skew, passes
        self.guard._check_freshness_normalised(self._d(offset=30))

    def test_one_second_past_skew_raises_future(self):
        with pytest.raises(FutureEnvelopeError):
            self.guard._check_freshness_normalised(self._d(offset=31))

    def test_far_future_raises_future(self):
        with pytest.raises(FutureEnvelopeError):
            self.guard._check_freshness_normalised(self._d(offset=9999))


# ─────────────────────────────────────────────────────────────────────────────
# ReplayGuard.check_freshness  (public surface)
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckFreshness:
    def setup_method(self):
        self.guard = _make_guard()

    def test_fresh_dict_passes(self):
        self.guard.check_freshness(_fresh_env())

    def test_fresh_envelope_obj_passes(self):
        self.guard.check_freshness(_envelope_obj(_fresh_env()))

    def test_stale_dict_raises(self):
        with pytest.raises(StaleEnvelopeError):
            self.guard.check_freshness(_fresh_env(offset=-9999))

    def test_future_dict_raises(self):
        with pytest.raises(FutureEnvelopeError):
            self.guard.check_freshness(_fresh_env(offset=9999))


# ─────────────────────────────────────────────────────────────────────────────
# ReplayGuard.precheck
# ─────────────────────────────────────────────────────────────────────────────

class TestPrecheck:
    def test_fresh_unseen_passes(self):
        store = _make_store(is_seen=False)
        guard = _make_guard(store=store)
        guard.precheck(_fresh_env())
        store.is_seen.assert_called_once()

    def test_seen_nonce_raises_duplicate(self):
        store = _make_store(is_seen=True)
        guard = _make_guard(store=store)
        with pytest.raises(DuplicateNonceError, match="already used"):
            guard.precheck(_fresh_env(nonce="seen-nonce"))

    def test_stale_raises_before_nonce_check(self):
        # Stale check happens first; is_seen should never be called.
        store = _make_store(is_seen=False)
        guard = _make_guard(store=store)
        with pytest.raises(StaleEnvelopeError):
            guard.precheck(_fresh_env(offset=-9999))
        store.is_seen.assert_not_called()

    def test_future_raises_before_nonce_check(self):
        store = _make_store(is_seen=False)
        guard = _make_guard(store=store)
        with pytest.raises(FutureEnvelopeError):
            guard.precheck(_fresh_env(offset=9999))
        store.is_seen.assert_not_called()

    def test_envelope_obj_accepted(self):
        store = _make_store(is_seen=False)
        guard = _make_guard(store=store)
        guard.precheck(_envelope_obj(_fresh_env(nonce="env-n")))


# ─────────────────────────────────────────────────────────────────────────────
# ReplayGuard.commit
# ─────────────────────────────────────────────────────────────────────────────

class TestCommit:
    def test_first_use_succeeds(self):
        store = _make_store(mark_used=True)
        guard = _make_guard(store=store)
        guard.commit(_fresh_env(nonce="first"))
        store.mark_used.assert_called_once_with("first", ttl_seconds=330)

    def test_ttl_uses_window_plus_skew(self):
        store = _make_store(mark_used=True)
        guard = _make_guard(store=store, window=60, skew=10)
        guard.commit(_fresh_env(nonce="ttl-nonce"))
        _, kwargs = store.mark_used.call_args
        assert kwargs["ttl_seconds"] == 70

    def test_duplicate_nonce_raises(self):
        store = _make_store(mark_used=False)   # mark_used returns False = already used
        guard = _make_guard(store=store)
        with pytest.raises(DuplicateNonceError, match="already used"):
            guard.commit(_fresh_env(nonce="dup"))

    def test_stale_raises(self):
        store = _make_store()
        guard = _make_guard(store=store)
        with pytest.raises(StaleEnvelopeError):
            guard.commit(_fresh_env(offset=-9999))
        store.mark_used.assert_not_called()

    def test_envelope_obj_accepted(self):
        store = _make_store(mark_used=True)
        guard = _make_guard(store=store)
        guard.commit(_envelope_obj(_fresh_env(nonce="obj-n")))


# ─────────────────────────────────────────────────────────────────────────────
# ReplayGuard.check_and_commit
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckAndCommit:
    """check_and_commit just delegates to commit — verify delegation is real."""

    def test_delegates_to_commit(self):
        guard = _make_guard()
        with patch.object(guard, "commit") as mock_commit:
            env = _fresh_env()
            guard.check_and_commit(env)
            mock_commit.assert_called_once_with(env)

    def test_first_use_succeeds(self):
        store = _make_store(mark_used=True)
        guard = _make_guard(store=store)
        guard.check_and_commit(_fresh_env(nonce="cac"))

    def test_duplicate_raises(self):
        store = _make_store(mark_used=False)
        guard = _make_guard(store=store)
        with pytest.raises(DuplicateNonceError):
            guard.check_and_commit(_fresh_env(nonce="dup-cac"))


# ─────────────────────────────────────────────────────────────────────────────
# ReplayGuard.check_and_open
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckAndOpen:
    """
    check_and_open has a real NameError bug: `nonce` is referenced on line
    159-160 without ever being assigned inside the method after the dict is
    built.  Tests are written to document the correct *intended* behaviour and
    will fail (NameError) until the bug is fixed.
    """

    def _make_cards(self, sender_id="alice"):
        sender_card = MagicMock()
        sender_card.entity_id = sender_id
        sender_card.public_keys = {"sign": "pub-key"}
        recipient = MagicMock()
        recipient.entity_id = "bob"
        recipient.keypair = MagicMock()
        return recipient, sender_card

    def _env(self, sender_id="alice", **kwargs):
        d = _fresh_env(**kwargs)
        d["sender_id"] = sender_id
        return d

    def test_sender_id_mismatch_raises_value_error(self):
        """sender_id check fires before nonce lookup — NameError not reached."""
        store = _make_store()
        guard = _make_guard(store=store)
        recipient, sender_card = self._make_cards(sender_id="alice")
        env = self._env(sender_id="mallory")           # mismatch
        with pytest.raises(ValueError, match="sender_id does not match"):
            guard.check_and_open(env, recipient, sender_card)

    def test_stale_envelope_raises_before_nonce(self):
        """Freshness check fires before nonce lookup — NameError not reached."""
        store = _make_store()
        guard = _make_guard(store=store)
        recipient, sender_card = self._make_cards()
        env = self._env(sender_id="alice", offset=-9999)
        with pytest.raises(StaleEnvelopeError):
            guard.check_and_open(env, recipient, sender_card)

    def test_future_envelope_raises_before_nonce(self):
        store = _make_store()
        guard = _make_guard(store=store)
        recipient, sender_card = self._make_cards()
        env = self._env(sender_id="alice", offset=9999)
        with pytest.raises(FutureEnvelopeError):
            guard.check_and_open(env, recipient, sender_card)

    def test_happy_path_returns_plaintext(self):
        """
        After the NameError bug fix, check_and_open should successfully
        mark the nonce, verify the envelope, decrypt, and return b"plaintext".
        """
        store = _make_store(mark_used=True)
        guard = _make_guard(store=store)
        recipient, sender_card = self._make_cards()
        env = self._env(sender_id="alice")
        result = guard.check_and_open(env, recipient, sender_card)
        assert result == b"plaintext"
        store.mark_used.assert_called_once()

    def test_duplicate_nonce_raises_duplicate_nonce_error(self):
        """
        After the bug fix, a duplicate nonce should raise DuplicateNonceError
        (not NameError).
        """
        store = _make_store(mark_used=False)
        guard = _make_guard(store=store)
        recipient, sender_card = self._make_cards()
        env = self._env(sender_id="alice")
        with pytest.raises(DuplicateNonceError, match="already used"):
            guard.check_and_open(env, recipient, sender_card)

    def test_envelope_obj_sender_mismatch(self):
        """Envelope object path: mismatch detected after normalise."""
        store = _make_store()
        guard = _make_guard(store=store)
        recipient, sender_card = self._make_cards(sender_id="alice")
        d = self._env(sender_id="evil")
        env_obj = _envelope_obj(d)
        with pytest.raises(ValueError, match="sender_id does not match"):
            guard.check_and_open(env_obj, recipient, sender_card)


# ─────────────────────────────────────────────────────────────────────────────
# Properties
# ─────────────────────────────────────────────────────────────────────────────

class TestProperties:
    def test_store_property(self):
        store = _make_store()
        guard = ReplayGuard(store, window_seconds=100, clock_skew=10)
        assert guard.store is store

    def test_window_seconds_property(self):
        guard = _make_guard(window=120)
        assert guard.window_seconds == 120

    def test_clock_skew_property(self):
        guard = _make_guard(skew=15)
        assert guard.clock_skew == 15


# ─────────────────────────────────────────────────────────────────────────────
# DefaultReplayGuard Protocol
# ─────────────────────────────────────────────────────────────────────────────

class TestDefaultReplayGuardProtocol:
    """
    DefaultReplayGuard is a @runtime_checkable Protocol.
    ReplayGuard must satisfy it; a stub that is missing methods must not.
    """

    def test_replay_guard_satisfies_protocol(self):
        guard = _make_guard()
        assert isinstance(guard, DefaultReplayGuard)

    def test_incomplete_object_does_not_satisfy_protocol(self):
        """An object missing protocol methods fails isinstance."""
        empty = object()
        assert not isinstance(empty, DefaultReplayGuard)

    def test_partial_object_does_not_satisfy_protocol(self):
        """An object with only some methods fails the check."""
        partial = MagicMock(spec=["check_freshness", "precheck"])
        assert not isinstance(partial, DefaultReplayGuard)

    def test_full_mock_satisfies_protocol(self):
        class MockGuard:
            def check_freshness(self, env): pass
            def precheck(self, env): pass
            def commit(self, env): pass
            def check_and_commit(self, env): pass
            def check_and_open(self, env, r, s): pass
            @property
            def store(self): return None
            @property
            def window_seconds(self): return 300
            @property
            def clock_skew(self): return 30

        m = MockGuard()
        assert isinstance(m, DefaultReplayGuard)


# ─────────────────────────────────────────────────────────────────────────────
# Edge / integration scenarios
# ─────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_zero_clock_skew_accepted(self):
        guard = ReplayGuard(_make_store(), window_seconds=60, clock_skew=0)
        assert guard.clock_skew == 0

    def test_precheck_passes_nonce_string_correctly(self):
        store = _make_store(is_seen=False)
        guard = _make_guard(store=store)
        guard.precheck(_fresh_env(nonce="my-unique-nonce-001"))
        store.is_seen.assert_called_once_with("my-unique-nonce-001")

    def test_commit_passes_correct_nonce_to_store(self):
        store = _make_store(mark_used=True)
        guard = _make_guard(store=store, window=200, skew=20)
        guard.commit(_fresh_env(nonce="commit-nonce"))
        store.mark_used.assert_called_once_with("commit-nonce", ttl_seconds=220)

    def test_normalise_preserves_all_extra_fields(self):
        guard = _make_guard()
        d = {
            "timestamp": int(time.time()),
            "envelope_nonce": "n",
            "sender_id": "a",
            "recipient_id": "b",
            "payload": b"data",
            "extra": 42,
        }
        result = guard._normalise(d)
        for key in d:
            assert key in result

    def test_check_freshness_with_envelope_obj(self):
        guard = _make_guard()
        guard.check_freshness(_envelope_obj(_fresh_env()))

    def test_precheck_nonce_slice_in_error_message(self):
        """DuplicateNonceError message shows first 8 chars of nonce."""
        store = _make_store(is_seen=True)
        guard = _make_guard(store=store)
        nonce = "abcdefgh-rest-of-nonce"
        with pytest.raises(DuplicateNonceError) as exc_info:
            guard.precheck(_fresh_env(nonce=nonce))
        assert "abcdefgh" in str(exc_info.value)

    def test_commit_nonce_slice_in_error_message(self):
        store = _make_store(mark_used=False)
        guard = _make_guard(store=store)
        nonce = "12345678-long-nonce"
        with pytest.raises(DuplicateNonceError) as exc_info:
            guard.commit(_fresh_env(nonce=nonce))
        assert "12345678" in str(exc_info.value)
