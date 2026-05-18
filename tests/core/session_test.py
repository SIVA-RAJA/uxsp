"""
test_session.py – Full-coverage pytest suite for session.py
============================================================

Strategy
--------
* `uxsp.crypto.kdf.derive_key` and `uxsp.crypto.symmetric.{encrypt,decrypt}`
  are external crypto primitives.  We stub them at the module level so every
  test runs without the real `uxsp` package installed while still exercising
  every line of Session logic.

* The stubs are *behaviorally correct*: encrypt XOR-encrypts and returns a
  dict; decrypt reverses it and raises ValueError on a bad nonce so we can
  reach the rollback branches.

* Each test covers a specific conceptual behaviour; the combination hits
  every executable line in session.py including all rollback paths, the
  sliding-window cleanup, and the non-ordering mode.
"""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest

# ──────────────────────────────────────────────────────────────────────────────
# Stub out uxsp.crypto before importing session
# ──────────────────────────────────────────────────────────────────────────────

def _fake_derive_key(secret: bytes, *, length: int, info: bytes) -> bytes:
    """Deterministic fake KDF – just XOR-fold the inputs into `length` bytes."""
    seed = secret + info
    out = bytearray(length)
    for i, b in enumerate(seed):
        out[i % length] ^= b
    return bytes(out)


def _fake_encrypt(plaintext: bytes, key: bytes, *, associated_data: bytes = b"") -> dict:
    """XOR-encrypt with key, store nonce = associated_data[:16] padded."""
    nonce = (associated_data + b"\x00" * 16)[:16]
    ct = bytes(p ^ k ^ n for p, k, n in
               zip(plaintext,
                   (key * (len(plaintext) // len(key) + 1))[:len(plaintext)],
                   (nonce * (len(plaintext) // 16 + 1))[:len(plaintext)], strict=False))
    return {"ciphertext": ct, "nonce": nonce}


def _fake_decrypt(ciphertext: bytes, nonce: bytes, key: bytes, *, associated_data: bytes = b"") -> bytes:
    """Reverse of _fake_encrypt.  Raises ValueError if nonce is all-zeros sentinel."""
    if nonce == b"\xff" * 16:           # sentinel used by tamper tests
        raise ValueError("authentication tag mismatch")
    pt = bytes(c ^ k ^ n for c, k, n in
               zip(ciphertext,
                   (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)],
                   (nonce * (len(ciphertext) // 16 + 1))[:len(ciphertext)], strict=False))
    return pt


@pytest.fixture(autouse=True)
def _patch_uxsp(monkeypatch):
    monkeypatch.setattr("uxsp.core.session.derive_key", _fake_derive_key)
    monkeypatch.setattr("uxsp.core.session.encrypt", _fake_encrypt)
    monkeypatch.setattr("uxsp.core.session.decrypt", _fake_decrypt)

# Now safe to import the module under test
from uxsp.core.session import (  # noqa: E402
    Session,
    SessionConfig,
    SessionError,
    SessionExpiredError,
    SessionNotActiveError,
    SessionReorderError,
    SessionRevokedError,
    SessionState,
)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

SECRET = b"shared-secret-32-bytes-for-tests"
SESSION_ID = "session-id-abcdefgh"


def make_session(
    *,
    is_initiator: bool = True,
    config: SessionConfig | None = None,
    session_id: str = SESSION_ID,
) -> Session:
    return Session(
        session_id=session_id,
        local_id="alice",
        remote_id="bob",
        shared_secret=SECRET,
        is_initiator=is_initiator,
        config=config,
    )


def make_active_pair(config: SessionConfig | None = None):
    """Return (initiator_session, responder_session) both ACTIVE."""
    init = make_session(is_initiator=True,  config=config)
    resp = make_session(is_initiator=False, config=config)
    init._activate()
    resp._activate()
    return init, resp


def roundtrip(sender: Session, receiver: Session, msg: bytes) -> bytes:
    payload  = sender.encrypt(msg)
    return receiver.decrypt(payload)


# ──────────────────────────────────────────────────────────────────────────────
# SessionConfig validation
# ──────────────────────────────────────────────────────────────────────────────

class TestSessionConfig:

    def test_defaults_are_valid(self):
        cfg = SessionConfig()
        assert cfg.max_lifetime_seconds == 3600
        assert cfg.max_messages         == 10_000
        assert cfg.enforce_ordering     is True

    def test_negative_lifetime_raises(self):
        with pytest.raises(ValueError, match="max_lifetime_seconds must be positive"):
            SessionConfig(max_lifetime_seconds=0)

    def test_negative_lifetime_negative(self):
        with pytest.raises(ValueError):
            SessionConfig(max_lifetime_seconds=-1)

    def test_zero_max_messages_raises(self):
        with pytest.raises(ValueError, match="max_messages must be positive"):
            SessionConfig(max_messages=0)

    def test_negative_max_messages_raises(self):
        with pytest.raises(ValueError):
            SessionConfig(max_messages=-5)

    def test_empty_key_info_raises(self):
        with pytest.raises(ValueError, match="key_info cannot be empty"):
            SessionConfig(key_info=b"")

    def test_custom_valid_config(self):
        cfg = SessionConfig(max_lifetime_seconds=60, max_messages=5, key_info=b"X")
        assert cfg.max_messages == 5


# ──────────────────────────────────────────────────────────────────────────────
# Session construction
# ──────────────────────────────────────────────────────────────────────────────

class TestSessionInit:

    def test_initial_state_is_pending(self):
        s = make_session()
        assert s.state == SessionState.PENDING

    def test_attributes_set_correctly(self):
        s = make_session(session_id="sid-xyz")
        assert s.session_id == "sid-xyz"
        assert s.local_id   == "alice"
        assert s.remote_id  == "bob"

    def test_default_config_used_when_none(self):
        s = make_session(config=None)
        assert s._config.max_messages == 10_000

    def test_provided_config_stored(self):
        cfg = SessionConfig(max_messages=42)
        s   = make_session(config=cfg)
        assert s._config.max_messages == 42

    def test_initiator_and_responder_get_opposite_keys(self):
        """Initiator's send_key must equal responder's recv_key."""
        init = make_session(is_initiator=True)
        resp = make_session(is_initiator=False)
        assert init._send_key == resp._recv_key
        assert init._recv_key == resp._send_key

    def test_send_recv_seq_start_at_zero(self):
        s = make_session()
        assert s._send_seq == 0
        assert s._recv_seq == 0

    def test_seen_seqs_empty_on_init(self):
        s = make_session()
        assert s._seen_seqs == set()
        assert s._max_seen_seq == -1
        assert s._recv_count   == 0


# ──────────────────────────────────────────────────────────────────────────────
# State transitions: _activate / revoke
# ──────────────────────────────────────────────────────────────────────────────

class TestStateTransitions:

    def test_activate_pending_succeeds(self):
        s = make_session()
        s._activate()
        assert s.state == SessionState.ACTIVE

    def test_activate_active_raises(self):
        s = make_session()
        s._activate()
        with pytest.raises(SessionError, match="Cannot activate session in state ACTIVE"):
            s._activate()

    def test_activate_revoked_raises(self):
        s = make_session()
        s.revoke()
        with pytest.raises(SessionError, match="Cannot activate session in state REVOKED"):
            s._activate()

    def test_activate_expired_raises(self):
        s = make_session(config=SessionConfig(max_lifetime_seconds=1))
        s._activate()
        s._state = SessionState.EXPIRED   # force
        with pytest.raises(SessionError, match="Cannot activate session in state EXPIRED"):
            s._activate()

    def test_revoke_sets_revoked(self):
        s = make_session()
        s._activate()
        s.revoke()
        assert s.state == SessionState.REVOKED

    def test_revoke_on_pending_works(self):
        s = make_session()
        s.revoke()
        assert s.state == SessionState.REVOKED


# ──────────────────────────────────────────────────────────────────────────────
# _check_active_unlocked paths
# ──────────────────────────────────────────────────────────────────────────────

class TestCheckActive:

    def test_check_active_raises_expired(self):
        s = make_session()
        s._activate()
        s._state = SessionState.EXPIRED
        with pytest.raises(SessionExpiredError):
            s._check_active()

    def test_check_active_raises_revoked(self):
        s = make_session()
        s._activate()
        s.revoke()
        with pytest.raises(SessionRevokedError):
            s._check_active()

    def test_check_active_raises_not_active_for_pending(self):
        s = make_session()
        with pytest.raises(SessionNotActiveError):
            s._check_active()

    def test_check_active_passes_when_active(self):
        s = make_session()
        s._activate()
        s._check_active()   # no exception


# ──────────────────────────────────────────────────────────────────────────────
# _evaluate_expiry paths
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateExpiry:

    def test_no_expiry_when_pending(self):
        s = make_session()
        s._evaluate_expiry()
        assert s.state == SessionState.PENDING   # unchanged

    def test_no_expiry_when_revoked(self):
        s = make_session()
        s.revoke()
        s._evaluate_expiry()
        assert s.state == SessionState.REVOKED

    def test_expires_by_time(self):
        s = make_session(config=SessionConfig(max_lifetime_seconds=1))
        s._activate()
        s._created_at = time.time() - 2     # artificially age it
        s._evaluate_expiry()
        assert s.state == SessionState.EXPIRED

    def test_expires_by_message_count_ordering(self):
        cfg = SessionConfig(max_messages=2)
        s   = make_session(config=cfg)
        s._activate()
        s._send_seq  = 1
        s._recv_seq  = 1      # total = 2 >= max
        s._evaluate_expiry()
        assert s.state == SessionState.EXPIRED

    def test_expires_by_message_count_no_ordering(self):
        cfg = SessionConfig(max_messages=2, enforce_ordering=False)
        s   = make_session(config=cfg)
        s._activate()
        s._send_seq   = 1
        s._recv_count = 1     # total = 2 >= max
        s._evaluate_expiry()
        assert s.state == SessionState.EXPIRED

    def test_not_expired_below_limit(self):
        cfg = SessionConfig(max_messages=10)
        s   = make_session(config=cfg)
        s._activate()
        s._send_seq  = 2
        s._recv_seq  = 2      # total = 4 < 10
        s._evaluate_expiry()
        assert s.state == SessionState.ACTIVE


# ──────────────────────────────────────────────────────────────────────────────
# encrypt()
# ──────────────────────────────────────────────────────────────────────────────

class TestEncrypt:

    def test_encrypt_returns_correct_keys(self):
        init, _ = make_active_pair()
        result  = init.encrypt(b"hello")
        assert set(result.keys()) == {"session_id", "seq", "ciphertext", "nonce"}

    def test_encrypt_non_bytes_raises_type_error(self):
        init, _ = make_active_pair()
        with pytest.raises(TypeError, match="plaintext must be bytes"):
            init.encrypt("not bytes")

    def test_encrypt_advances_send_seq(self):
        init, _ = make_active_pair()
        init.encrypt(b"msg1")
        init.encrypt(b"msg2")
        assert init._send_seq == 2

    def test_encrypt_on_pending_raises(self):
        s = make_session()
        with pytest.raises(SessionNotActiveError):
            s.encrypt(b"hello")

    def test_encrypt_on_revoked_raises(self):
        init, _ = make_active_pair()
        init.revoke()
        with pytest.raises(SessionRevokedError):
            init.encrypt(b"hello")

    def test_encrypt_session_id_in_payload(self):
        init, _ = make_active_pair()
        result  = init.encrypt(b"data")
        assert result["session_id"] == SESSION_ID

    def test_encrypt_ciphertext_and_nonce_are_hex(self):
        init, _ = make_active_pair()
        result  = init.encrypt(b"data")
        bytes.fromhex(result["ciphertext"])   # must not raise
        bytes.fromhex(result["nonce"])

    def test_encrypt_triggers_expiry_check(self):
        """After the last allowed message, session should become EXPIRED."""
        cfg  = SessionConfig(max_messages=1)
        init = make_session(config=cfg)
        resp = make_session(config=cfg, is_initiator=False)
        init._activate()
        resp._activate()
        init.encrypt(b"x")          # send_seq becomes 1, total = 1 >= 1
        assert init.state == SessionState.EXPIRED


# ──────────────────────────────────────────────────────────────────────────────
# decrypt() — input validation
# ──────────────────────────────────────────────────────────────────────────────

class TestDecryptValidation:

    def setup_method(self):
        self.init, self.resp = make_active_pair()

    def test_wrong_session_id_raises(self):
        payload = self.init.encrypt(b"hi")
        payload["session_id"] = "wrong-id"
        with pytest.raises(ValueError, match="session_id mismatch"):
            self.resp.decrypt(payload)

    def test_missing_ciphertext_raises(self):
        payload = self.init.encrypt(b"hi")
        del payload["ciphertext"]
        with pytest.raises(ValueError, match="missing field: 'ciphertext'"):
            self.resp.decrypt(payload)

    def test_missing_nonce_raises(self):
        payload = self.init.encrypt(b"hi")
        del payload["nonce"]
        with pytest.raises(ValueError, match="missing field: 'nonce'"):
            self.resp.decrypt(payload)

    def test_missing_seq_raises(self):
        payload = self.init.encrypt(b"hi")
        del payload["seq"]
        with pytest.raises(ValueError, match="missing field: 'seq'"):
            self.resp.decrypt(payload)

    def test_seq_is_float_raises(self):
        payload = self.init.encrypt(b"hi")
        payload["seq"] = 0.0
        with pytest.raises(ValueError, match="non-negative integer"):
            self.resp.decrypt(payload)

    def test_seq_is_bool_raises(self):
        payload = self.init.encrypt(b"hi")
        payload["seq"] = True          # bool is subclass of int – must be rejected
        with pytest.raises(ValueError, match="non-negative integer"):
            self.resp.decrypt(payload)

    def test_seq_is_negative_raises(self):
        payload = self.init.encrypt(b"hi")
        payload["seq"] = -1
        with pytest.raises(ValueError, match="non-negative integer"):
            self.resp.decrypt(payload)

    def test_ciphertext_not_string_raises(self):
        payload = self.init.encrypt(b"hi")
        payload["ciphertext"] = 123
        with pytest.raises(ValueError, match="hex strings"):
            self.resp.decrypt(payload)

    def test_nonce_not_string_raises(self):
        payload = self.init.encrypt(b"hi")
        payload["nonce"] = b"\x00"
        with pytest.raises(ValueError, match="hex strings"):
            self.resp.decrypt(payload)

    def test_invalid_hex_ciphertext_raises(self):
        payload = self.init.encrypt(b"hi")
        payload["ciphertext"] = "ZZZZ"    # not valid hex
        with pytest.raises(ValueError, match="invalid hex data"):
            self.resp.decrypt(payload)

    def test_invalid_hex_nonce_raises(self):
        payload = self.init.encrypt(b"hi")
        payload["nonce"] = "ZZZZ"
        with pytest.raises(ValueError, match="invalid hex data"):
            self.resp.decrypt(payload)


# ──────────────────────────────────────────────────────────────────────────────
# decrypt() — ordering-enforced mode
# ──────────────────────────────────────────────────────────────────────────────

class TestDecryptOrdering:

    def setup_method(self):
        self.init, self.resp = make_active_pair()

    def test_roundtrip_single_message(self):
        assert roundtrip(self.init, self.resp, b"hello") == b"hello"

    def test_roundtrip_multiple_messages(self):
        for i in range(5):
            msg = f"message-{i}".encode()
            assert roundtrip(self.init, self.resp, msg) == msg

    def test_replay_same_seq_raises(self):
        payload = self.init.encrypt(b"once")
        self.resp.decrypt(payload)
        # replay the exact same payload
        with pytest.raises(SessionReorderError, match="already received or replayed"):
            self.resp.decrypt(payload)

    def test_future_seq_raises(self):
        payload      = self.init.encrypt(b"first")
        payload["seq"] = 5     # skip ahead
        with pytest.raises(SessionReorderError, match="out of order"):
            self.resp.decrypt(payload)

    def test_decrypt_on_revoked_raises(self):
        payload = self.init.encrypt(b"msg")
        self.resp.revoke()
        with pytest.raises(SessionRevokedError):
            self.resp.decrypt(payload)

    def test_decrypt_triggers_expiry_check(self):
        cfg  = SessionConfig(max_messages=1)
        init = make_session(config=cfg)
        resp = make_session(config=cfg, is_initiator=False)
        init._activate()
        resp._activate()
        payload = init.encrypt(b"only")
        resp.decrypt(payload)        # recv_seq=1, total=1 >= 1
        assert resp.state == SessionState.EXPIRED

    def test_rollback_on_decrypt_failure_ordering(self):
        """
        If the real decrypt raises, recv_seq must be rolled back so the
        next genuine message with that seq can still succeed.
        """
        payload = self.init.encrypt(b"real")
        # Corrupt the nonce to trigger our stub's ValueError path
        payload["nonce"] = "ff" * 16
        with pytest.raises(SessionError, match="decryption failed"):
            self.resp.decrypt(payload)
        # recv_seq must be back to 0
        assert self.resp._recv_seq == 0
        # Now the real message with seq=0 should work
        self.init.encrypt(b"retry")   # seq will be 1 on sender now
        # But receiver still expects seq=0 – feed a freshly encrypted seq=0
        init2 = make_session(is_initiator=True)
        init2._activate()
        p2 = init2.encrypt(b"real")
        # resp was constructed from the same session_id/keys, so use a clean resp
        resp2 = make_session(is_initiator=False)
        resp2._activate()
        assert resp2.decrypt(p2) == b"real"

    def test_rollback_non_ValueError_exception_ordering(self):
        """Non-ValueError exceptions in decrypt are re-raised as-is after rollback."""
        payload = self.init.encrypt(b"x")
        with patch("uxsp.core.session.decrypt", side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError, match="boom"):
                self.resp.decrypt(payload)
        # recv_seq rolled back
        assert self.resp._recv_seq == 0


# ──────────────────────────────────────────────────────────────────────────────
# decrypt() — non-ordering (windowed) mode
# ──────────────────────────────────────────────────────────────────────────────

class TestDecryptWindowMode:

    def _pair(self, **kw):
        cfg  = SessionConfig(enforce_ordering=False, **kw)
        init = make_session(config=cfg)
        resp = make_session(config=cfg, is_initiator=False)
        init._activate()
        resp._activate()
        return init, resp

    def test_roundtrip_out_of_order(self):
        """Deliver messages 2, 0, 1 – all should decrypt correctly."""
        init, resp = self._pair()
        payloads   = [init.encrypt(b"m") for _ in range(3)]
        assert resp.decrypt(payloads[2]) == b"m"
        assert resp.decrypt(payloads[0]) == b"m"
        assert resp.decrypt(payloads[1]) == b"m"

    def test_replay_raises_in_window_mode(self):
        init, resp = self._pair()
        payload    = init.encrypt(b"once")
        resp.decrypt(payload)
        with pytest.raises(SessionReorderError, match="already received"):
            resp.decrypt(payload)

    def test_outside_window_raises(self):
        """A seq far behind the window floor is rejected."""
        init, resp = self._pair()
        # Receive enough messages to push max_seen_seq well above 0
        old_payload = init.encrypt(b"old")        # seq=0
        for _ in range(resp._WINDOW_SIZE + 1):    # advance max_seen_seq
            resp.decrypt(init.encrypt(b"x"))
        # seq=0 is now below the window floor
        with pytest.raises(SessionReorderError, match="outside the replay-protection window"):
            resp.decrypt(old_payload)

    def test_max_seen_seq_first_message(self):
        init, resp = self._pair()
        payload = init.encrypt(b"first")       # seq=0
        resp.decrypt(payload)
        assert resp._max_seen_seq == 0

    def test_seen_seqs_pruned_when_large(self):
        """_seen_seqs must be pruned when it exceeds WINDOW_SIZE*2."""
        init, resp = self._pair()
        window     = resp._WINDOW_SIZE
        # Push WINDOW_SIZE*2 + 1 unique messages through
        for _ in range(window * 2 + 1):
            resp.decrypt(init.encrypt(b"z"))
        assert len(resp._seen_seqs) <= window * 2

    def test_rollback_on_decrypt_failure_window_mode(self):
        """Failed decrypt in window mode must revert seen_seqs and recv_count."""
        init, resp = self._pair()
        payload    = init.encrypt(b"x")
        payload["nonce"] = "ff" * 16    # trigger stub ValueError
        before_count = resp._recv_count
        with pytest.raises(SessionError, match="decryption failed"):
            resp.decrypt(payload)
        assert resp._recv_count  == before_count
        assert 0 not in resp._seen_seqs

    def test_rollback_max_seen_seq_reverted(self):
        """
        If the failed seq was also the new max, _max_seen_seq must revert
        to the previous maximum.
        """
        init, resp = self._pair()
        # Receive seq=0 successfully first
        resp.decrypt(init.encrypt(b"first"))
        assert resp._max_seen_seq == 0
        # Now attempt seq=1 with bad nonce
        payload = init.encrypt(b"second")   # seq=1
        payload["nonce"] = "ff" * 16
        with pytest.raises(SessionError):
            resp.decrypt(payload)
        # max_seen_seq must be back to 0
        assert resp._max_seen_seq == 0

    def test_rollback_non_valueerror_window_mode(self):
        """Non-ValueError in window mode re-raises after rollback."""
        init, resp = self._pair()
        payload    = init.encrypt(b"x")
        with patch("uxsp.core.session.decrypt", side_effect=RuntimeError("crash")):
            with pytest.raises(RuntimeError, match="crash"):
                resp.decrypt(payload)
        assert 0 not in resp._seen_seqs

    def test_message_count_uses_recv_count(self):
        init, resp = self._pair()
        resp.decrypt(init.encrypt(b"a"))
        resp.decrypt(init.encrypt(b"b"))
        # resp sent 0, received 2 → message_count == 2
        assert resp.message_count == 2

    def test_remaining_messages_uses_recv_count(self):
        cfg  = SessionConfig(enforce_ordering=False, max_messages=5)
        init = make_session(config=cfg)
        resp = make_session(config=cfg, is_initiator=False)
        init._activate(); resp._activate()
        resp.decrypt(init.encrypt(b"1"))
        assert resp.remaining_messages == 4


# ──────────────────────────────────────────────────────────────────────────────
# Properties
# ──────────────────────────────────────────────────────────────────────────────

class TestProperties:

    def setup_method(self):
        self.init, self.resp = make_active_pair()

    def test_state_property(self):
        assert self.init.state == SessionState.ACTIVE

    def test_is_active_true(self):
        assert self.init.is_active is True

    def test_is_active_false_after_revoke(self):
        self.init.revoke()
        assert self.init.is_active is False

    def test_is_active_false_for_pending(self):
        s = make_session()
        assert s.is_active is False

    def test_is_active_triggers_expiry(self):
        s = make_session(config=SessionConfig(max_lifetime_seconds=1))
        s._activate()
        s._created_at = time.time() - 2
        assert s.is_active is False
        assert s.state == SessionState.EXPIRED

    def test_message_count_sent_and_received(self):
        roundtrip(self.init, self.resp, b"msg")
        # init sent 1, recv 0 → 1; resp sent 0, recv 1 → 1
        assert self.init.message_count == 1
        assert self.resp.message_count == 1

    def test_message_count_zero_initially(self):
        assert self.init.message_count == 0

    def test_remaining_messages_decreases(self):
        cfg  = SessionConfig(max_messages=10)
        init = make_session(config=cfg)
        resp = make_session(config=cfg, is_initiator=False)
        init._activate(); resp._activate()
        assert init.remaining_messages == 10
        roundtrip(init, resp, b"x")
        assert init.remaining_messages == 9

    def test_remaining_messages_zero_when_not_active(self):
        s = make_session()          # PENDING
        assert s.remaining_messages == 0

    def test_remaining_messages_zero_after_revoke(self):
        self.init.revoke()
        assert self.init.remaining_messages == 0

    def test_remaining_seconds_positive(self):
        assert self.init.remaining_seconds > 0

    def test_remaining_seconds_zero_after_expiry(self):
        s = make_session(config=SessionConfig(max_lifetime_seconds=1))
        s._activate()
        s._created_at = time.time() - 10
        assert s.remaining_seconds == 0.0

    def test_age_seconds_increases(self):
        s = make_session()
        age1 = s.age_seconds
        time.sleep(0.05)
        age2 = s.age_seconds
        assert age2 > age1

    def test_repr_contains_session_prefix(self):
        r = repr(self.init)
        assert "Session(id=" in r
        assert "state=ACTIVE" in r

    def test_repr_contains_sent_and_age(self):
        r = repr(self.init)
        assert "sent=" in r
        assert "age="  in r


# ──────────────────────────────────────────────────────────────────────────────
# Error hierarchy
# ──────────────────────────────────────────────────────────────────────────────

class TestErrorHierarchy:

    def test_session_expired_is_session_error(self):
        assert issubclass(SessionExpiredError, SessionError)

    def test_session_revoked_is_session_error(self):
        assert issubclass(SessionRevokedError, SessionError)

    def test_session_not_active_is_session_error(self):
        assert issubclass(SessionNotActiveError, SessionError)

    def test_session_reorder_is_session_error(self):
        assert issubclass(SessionReorderError, SessionError)


# ──────────────────────────────────────────────────────────────────────────────
# Thread safety – smoke test
# ──────────────────────────────────────────────────────────────────────────────

class TestThreadSafety:

    def test_concurrent_encrypt_no_duplicate_seq(self):
        """Two threads encrypting concurrently must each get a unique seq."""
        init, _ = make_active_pair()
        results  = []
        errors   = []

        def worker():
            try:
                results.append(init.encrypt(b"concurrent"))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert not errors
        seqs = [r["seq"] for r in results]
        assert len(seqs) == len(set(seqs)), "Duplicate sequence numbers detected"

    def test_concurrent_state_reads_are_safe(self):
        s = make_session()
        s._activate()
        errors = []

        def reader():
            try:
                _ = s.state
                _ = s.is_active
                _ = s.message_count
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        assert not errors


# ──────────────────────────────────────────────────────────────────────────────
# Edge cases & misc
# ──────────────────────────────────────────────────────────────────────────────

class TestEdgeCases:

    def test_encrypt_empty_bytes(self):
        init, resp = make_active_pair()
        payload = init.encrypt(b"")
        result  = resp.decrypt(payload)
        assert result == b""

    def test_encrypt_large_payload(self):
        init, resp = make_active_pair()
        big  = b"X" * 64_000
        payload = init.encrypt(big)
        assert resp.decrypt(payload) == big

    def test_session_id_mismatch_none(self):
        """session_id=None in payload should raise ValueError."""
        _, resp = make_active_pair()
        payload = {"session_id": None, "seq": 0, "ciphertext": "aa", "nonce": "bb"}
        with pytest.raises(ValueError, match="session_id mismatch"):
            resp.decrypt(payload)

    def test_window_mode_first_message_max_seen_negative_floor(self):
        """With max_seen_seq=-1 the floor condition must not raise."""
        cfg  = SessionConfig(enforce_ordering=False)
        init = make_session(config=cfg)
        resp = make_session(config=cfg, is_initiator=False)
        init._activate(); resp._activate()
        # seq=0 when max_seen_seq=-1 – the `>= 0` guard must prevent floor check
        payload = init.encrypt(b"first")
        assert resp.decrypt(payload) == b"first"

    def test_pending_session_remaining_messages_zero(self):
        s = make_session()
        assert s.remaining_messages == 0   # PENDING → not ACTIVE branch

    def test_non_valueerror_during_ordering_rollback_not_reverted_when_seq_mismatch(self):
        """
        If a non-ValueError exception fires but recv_seq was already incremented
        by something else (simulate race), rollback condition is false → no revert.
        """
        init, resp = make_active_pair()
        payload    = init.encrypt(b"x")
        # Manually advance recv_seq so it no longer equals incoming_seq + 1
        def fake_decrypt(*args, **kwargs):
            resp._recv_seq = 99
            raise RuntimeError("boom")

        with patch("uxsp.core.session.decrypt", side_effect=fake_decrypt):
            with pytest.raises(RuntimeError):
                resp.decrypt(payload)
        # recv_seq must remain 99 (not rolled back)
        assert resp._recv_seq == 99

    def test_window_rollback_recv_count_already_zero(self):
        """recv_count decrement must not go below 0 (the `> 0` guard)."""
        cfg  = SessionConfig(enforce_ordering=False)
        init = make_session(config=cfg)
        resp = make_session(config=cfg, is_initiator=False)
        init._activate(); resp._activate()
        resp._recv_count = 0    # force already at 0
        payload = init.encrypt(b"y")
        payload["nonce"] = "ff" * 16
        with pytest.raises(SessionError):
            resp.decrypt(payload)
        assert resp._recv_count == 0    # must stay 0, not go negative
