"""
Full-coverage pytest suite for handshake.py.

Strategy
--------
All external uxsp imports are mocked at the handshake module boundary so the
tests exercise every branch in handshake.py without needing the real crypto
stack.  Mocks are configured to behave correctly by default; individual tests
then break exactly one invariant at a time to drive each error branch.

Coverage targets (every executable line):
  - ExchangeResult TypedDict declaration
  - HandshakeError / HandshakeAuthError / HandshakeProofError / HandshakeExpiredError
  - _make_hello
  - _verify_hello_signature  (all 8 raise paths + happy path)
  - _derive_hello_secret
  - _make_ack
  - _verify_ack_signature    (all 8 raise paths + happy path)
  - _derive_ack_secret       (proof mismatch + happy path)
  - Handshake.__init__
  - Handshake.initiate
  - Handshake.respond        (invalid session_id + replay + happy path)
  - Handshake.complete       (all guard paths + replay + card mismatch + happy path)
  - Handshake.hello_message  (before and after initiate)
  - Handshake.ack_message    (before and after respond)
  - Handshake.session        (before and after respond/complete)
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Build stub modules so "import handshake" succeeds without the real uxsp lib
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

class _Identity:
    def __init__(self, entity_id, keypair=None):
        self.entity_id = entity_id
        self.keypair   = keypair or MagicMock()

class _PublicCard:
    def __init__(self, entity_id, public_keys=None):
        self.entity_id  = entity_id
        self.public_keys = public_keys or MagicMock()

class _NonceStore:
    def __init__(self):
        self._used: set[str] = set()
    def mark_used(self, key: str, ttl_seconds: int = 90) -> bool:
        if key in self._used:
            return False
        self._used.add(key)
        return True

class _SessionConfig:
    pass

class _Session:
    def __init__(self, *, session_id, local_id, remote_id,
                 shared_secret, is_initiator, config):
        self.session_id    = session_id
        self.local_id      = local_id
        self.remote_id     = remote_id
        self.shared_secret = shared_secret
        self.is_initiator  = is_initiator
        self.config        = config
        self.active        = False
    def _activate(self):
        self.active = True

class _EnvelopeValidationError(Exception):
    pass

def _bind_fields(*parts: bytes) -> bytes:
    sep = b"\x00"
    return sep.join(parts)

def _hybrid_sender_exchange(public_keys):
    return {
        "ephemeral_pub":  b"\xaa" * 32,
        "kem_ciphertext": b"\xbb" * 32,
        "shared_key":     b"\xcc" * 32,
    }

def _hybrid_recipient_exchange(ephemeral_pub, kem_ciphertext, keypair):
    return b"\xcc" * 32

def _hybrid_sign(signable, keypair):
    return {
        "classical_sig": b"classical",
        "pqc_sig":       b"pqc",
    }

def _hybrid_verify(signable, sigs, public_keys):
    return True

def _derive_key(*, ikm: bytes, info: bytes, length: int) -> bytes:
    return b"\xee" * length

@pytest.fixture(autouse=True)
def _patch_uxsp(monkeypatch):
    monkeypatch.setattr("uxsp.core.handshake.Identity", _Identity)
    monkeypatch.setattr("uxsp.core.handshake.PublicCard", _PublicCard)
    monkeypatch.setattr("uxsp.core.handshake.NonceStore", _NonceStore)
    monkeypatch.setattr("uxsp.core.handshake.Session", _Session)
    monkeypatch.setattr("uxsp.core.handshake.SessionConfig", _SessionConfig)
    monkeypatch.setattr("uxsp.core.handshake.EnvelopeValidationError", _EnvelopeValidationError)
    monkeypatch.setattr("uxsp.core.handshake.bind_fields", _bind_fields)
    monkeypatch.setattr("uxsp.core.handshake.hybrid_sender_exchange", _hybrid_sender_exchange)
    monkeypatch.setattr("uxsp.core.handshake.hybrid_recipient_exchange", _hybrid_recipient_exchange)
    monkeypatch.setattr("uxsp.core.handshake.hybrid_sign", _hybrid_sign)
    monkeypatch.setattr("uxsp.core.handshake.hybrid_verify", _hybrid_verify)
    monkeypatch.setattr("uxsp.core.handshake.derive_key", _derive_key)

from uxsp.core import handshake as hs_mod  # noqa: E402
from uxsp.core.handshake import (
    Handshake,
    HandshakeAuthError,
    HandshakeError,
    HandshakeExpiredError,
    HandshakeProofError,
    _derive_ack_secret,
    _derive_hello_secret,
    _make_ack,
    _make_hello,
    _verify_ack_signature,
    _verify_hello_signature,
)

Identity = _Identity
PublicCard = _PublicCard
NonceStore = _NonceStore
SessionConfig = _SessionConfig
EnvelopeValidationError = _EnvelopeValidationError


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture()
def initiator():
    return Identity("alice-id-1234")

@pytest.fixture()
def responder():
    return Identity("bob-id-5678")

@pytest.fixture()
def initiator_card(initiator):
    return PublicCard(initiator.entity_id)

@pytest.fixture()
def responder_card(responder):
    return PublicCard(responder.entity_id)

@pytest.fixture()
def nonce_store():
    return NonceStore()

@pytest.fixture()
def session_id():
    return str(uuid.uuid4())

@pytest.fixture()
def hello_msg(initiator, responder_card, session_id):
    """A freshly built, valid HelloMessage."""
    msg, _ = _make_hello(initiator, responder_card, session_id)
    return msg

@pytest.fixture()
def ack_msg(responder, session_id, initiator_card):
    """A freshly built, valid AckMessage."""
    shared_secret_A = b"\xcc" * 32
    msg, _ = _make_ack(responder, session_id, "alice-id-1234",
                       shared_secret_A, initiator_card)
    return msg


# ===========================================================================
# Exception hierarchy
# ===========================================================================

class TestExceptionHierarchy:
    def test_handshake_error_is_exception(self):
        e = HandshakeError("base")
        assert isinstance(e, Exception)

    def test_auth_error_is_handshake_error(self):
        e = HandshakeAuthError("auth")
        assert isinstance(e, HandshakeError)

    def test_proof_error_is_handshake_error(self):
        e = HandshakeProofError("proof")
        assert isinstance(e, HandshakeError)

    def test_expired_error_is_handshake_error(self):
        e = HandshakeExpiredError("expired")
        assert isinstance(e, HandshakeError)


# ===========================================================================
# _make_hello
# ===========================================================================

class TestMakeHello:
    def test_returns_correct_structure(self, initiator, responder_card, session_id):
        msg, exchange = _make_hello(initiator, responder_card, session_id)
        assert msg["type"]       == "UXSP-HELLO"
        assert msg["version"]    == "1"
        assert msg["session_id"] == session_id
        assert msg["initiator_id"] == initiator.entity_id
        assert msg["responder_id"] == responder_card.entity_id
        assert "ephemeral_pub"  in msg
        assert "kem_ciphertext" in msg
        assert "classical_sig"  in msg
        assert "pqc_sig"        in msg
        assert "timestamp"      in msg

    def test_exchange_result_keys(self, initiator, responder_card, session_id):
        _, exchange = _make_hello(initiator, responder_card, session_id)
        assert "ephemeral_pub"  in exchange
        assert "kem_ciphertext" in exchange
        assert "shared_key"     in exchange

    def test_ephemeral_pub_is_hex_string(self, initiator, responder_card, session_id):
        msg, _ = _make_hello(initiator, responder_card, session_id)
        # Must be decodable hex
        bytes.fromhex(msg["ephemeral_pub"])

    def test_timestamp_is_recent(self, initiator, responder_card, session_id):
        before = int(time.time())
        msg, _ = _make_hello(initiator, responder_card, session_id)
        after  = int(time.time())
        assert before <= msg["timestamp"] <= after


# ===========================================================================
# _verify_hello_signature
# ===========================================================================

class TestVerifyHelloSignature:

    def _valid_hello(self, initiator, responder_card, session_id):
        msg, _ = _make_hello(initiator, responder_card, session_id)
        return msg

    # --- missing fields ---
    def test_raises_auth_on_missing_field(self, initiator, responder_card,
                                          initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        del msg["pqc_sig"]
        with pytest.raises(HandshakeAuthError, match="missing required fields"):
            _verify_hello_signature(msg, initiator_card, responder)

    # --- wrong type ---
    def test_raises_auth_on_wrong_type(self, initiator, responder_card,
                                       initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        msg["type"] = "WRONG"
        with pytest.raises(HandshakeAuthError, match="Expected UXSP-HELLO"):
            _verify_hello_signature(msg, initiator_card, responder)

    # --- invalid timestamp (non-numeric) ---
    def test_raises_auth_on_bad_timestamp(self, initiator, responder_card,
                                           initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        msg["timestamp"] = "not-a-number"
        with pytest.raises(HandshakeAuthError, match="Invalid timestamp format"):
            _verify_hello_signature(msg, initiator_card, responder)

    # --- expired (too old) ---
    def test_raises_expired_when_too_old(self, initiator, responder_card,
                                          initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        msg["timestamp"] = int(time.time()) - 9999
        with pytest.raises(HandshakeExpiredError):
            _verify_hello_signature(msg, initiator_card, responder)

    # --- expired (future, negative age beyond max_age) ---
    def test_raises_expired_when_too_far_in_future(self, initiator, responder_card,
                                                    initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        msg["timestamp"] = int(time.time()) + 9999
        with pytest.raises(HandshakeExpiredError):
            _verify_hello_signature(msg, initiator_card, responder)

    # --- wrong initiator_id ---
    def test_raises_auth_on_wrong_initiator_id(self, initiator, responder_card,
                                                initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        msg["initiator_id"] = "wrong-id"
        with pytest.raises(HandshakeAuthError, match="does not match provided card"):
            _verify_hello_signature(msg, initiator_card, responder)

    # --- wrong responder_id ---
    def test_raises_auth_on_wrong_responder_id(self, initiator, responder_card,
                                                initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        msg["responder_id"] = "wrong-responder"
        with pytest.raises(HandshakeAuthError, match="not for this responder"):
            _verify_hello_signature(msg, initiator_card, responder)

    # --- wrong version ---
    def test_raises_auth_on_wrong_version(self, initiator, responder_card,
                                           initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        msg["version"] = "2"
        with pytest.raises(HandshakeAuthError, match="Unsupported hello version"):
            _verify_hello_signature(msg, initiator_card, responder)

    # --- malformed hex fields ---
    def test_raises_auth_on_malformed_hex(self, initiator, responder_card,
                                           initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        msg["ephemeral_pub"] = "not-valid-hex!!!"
        with pytest.raises(HandshakeAuthError, match="malformed or invalid field types"):
            _verify_hello_signature(msg, initiator_card, responder)

    # --- EnvelopeValidationError from hybrid_verify ---
    def test_raises_auth_on_envelope_error(self, initiator, responder_card,
                                            initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        with patch.object(hs_mod, "hybrid_verify",
                          side_effect=EnvelopeValidationError("bad envelope")):
            with pytest.raises(HandshakeAuthError, match="signature fields are invalid"):
                _verify_hello_signature(msg, initiator_card, responder)

    # --- signature returns False ---
    def test_raises_auth_when_signature_false(self, initiator, responder_card,
                                               initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        with patch.object(hs_mod, "hybrid_verify", return_value=False):
            with pytest.raises(HandshakeAuthError, match="signature invalid"):
                _verify_hello_signature(msg, initiator_card, responder)

    # --- happy path returns bytes ---
    def test_happy_path_returns_signable(self, initiator, responder_card,
                                          initiator_card, responder, session_id):
        msg = self._valid_hello(initiator, responder_card, session_id)
        result = _verify_hello_signature(msg, initiator_card, responder)
        assert isinstance(result, bytes)
        assert len(result) > 0


# ===========================================================================
# _derive_hello_secret
# ===========================================================================

class TestDeriveHelloSecret:
    def test_returns_bytes(self, initiator, responder_card, responder, session_id):
        msg, _ = _make_hello(initiator, responder_card, session_id)
        secret = _derive_hello_secret(msg, responder)
        assert isinstance(secret, bytes)

    def test_delegates_to_hybrid_recipient_exchange(self, initiator, responder_card,
                                                     responder, session_id):
        msg, _ = _make_hello(initiator, responder_card, session_id)
        with patch.object(hs_mod, "hybrid_recipient_exchange",
                          return_value=b"secret") as mock_ex:
            result = _derive_hello_secret(msg, responder)
        assert result == b"secret"
        mock_ex.assert_called_once()


# ===========================================================================
# _make_ack
# ===========================================================================

class TestMakeAck:
    def test_returns_correct_structure(self, responder, session_id, initiator_card):
        shared_secret_A = b"\xcc" * 32
        ack, exchange = _make_ack(responder, session_id, "alice-id-1234",
                                  shared_secret_A, initiator_card)
        assert ack["type"]        == "UXSP-ACK"
        assert ack["version"]     == "1"
        assert ack["session_id"]  == session_id
        assert ack["responder_id"] == responder.entity_id
        assert ack["initiator_id"] == "alice-id-1234"
        assert "proof"          in ack
        assert "ephemeral_pub"  in ack
        assert "kem_ciphertext" in ack
        assert "classical_sig"  in ack
        assert "pqc_sig"        in ack

    def test_proof_is_hmac_of_shared_secret(self, responder, session_id, initiator_card):
        shared_secret_A = b"\xcc" * 32
        ack, _ = _make_ack(responder, session_id, "alice-id-1234",
                            shared_secret_A, initiator_card)
        expected_proof = hmac.new(
            shared_secret_A,
            (session_id + ":responder-proof").encode(),
            digestmod=hashlib.sha256
        ).hexdigest()
        assert ack["proof"] == expected_proof

    def test_exchange_result_has_shared_key(self, responder, session_id, initiator_card):
        shared_secret_A = b"\xcc" * 32
        _, exchange = _make_ack(responder, session_id, "alice-id-1234",
                                shared_secret_A, initiator_card)
        assert "shared_key" in exchange


# ===========================================================================
# _verify_ack_signature
# ===========================================================================

class TestVerifyAckSignature:

    def _valid_ack(self, responder, session_id, initiator_card):
        shared_secret_A = b"\xcc" * 32
        msg, _ = _make_ack(responder, session_id, "alice-id-1234",
                            shared_secret_A, initiator_card)
        return msg

    # --- missing fields ---
    def test_raises_auth_on_missing_field(self, responder, session_id,
                                           initiator_card, responder_card):
        ack = self._valid_ack(responder, session_id, initiator_card)
        del ack["proof"]
        with pytest.raises(HandshakeAuthError, match="missing required fields"):
            _verify_ack_signature(ack, responder_card)

    # --- wrong type ---
    def test_raises_auth_on_wrong_type(self, responder, session_id,
                                        initiator_card, responder_card):
        ack = self._valid_ack(responder, session_id, initiator_card)
        ack["type"] = "WRONG"
        with pytest.raises(HandshakeAuthError, match="Expected UXSP-ACK"):
            _verify_ack_signature(ack, responder_card)

    # --- invalid timestamp ---
    def test_raises_auth_on_bad_timestamp(self, responder, session_id,
                                           initiator_card, responder_card):
        ack = self._valid_ack(responder, session_id, initiator_card)
        ack["timestamp"] = "NaN"
        with pytest.raises(HandshakeAuthError, match="Invalid timestamp format"):
            _verify_ack_signature(ack, responder_card)

    # --- expired ---
    def test_raises_expired_when_too_old(self, responder, session_id,
                                          initiator_card, responder_card):
        ack = self._valid_ack(responder, session_id, initiator_card)
        ack["timestamp"] = int(time.time()) - 9999
        with pytest.raises(HandshakeExpiredError):
            _verify_ack_signature(ack, responder_card)

    # --- too far in future ---
    def test_raises_expired_when_future(self, responder, session_id,
                                         initiator_card, responder_card):
        ack = self._valid_ack(responder, session_id, initiator_card)
        ack["timestamp"] = int(time.time()) + 9999
        with pytest.raises(HandshakeExpiredError):
            _verify_ack_signature(ack, responder_card)

    # --- wrong version ---
    def test_raises_auth_on_wrong_version(self, responder, session_id,
                                           initiator_card, responder_card):
        ack = self._valid_ack(responder, session_id, initiator_card)
        ack["version"] = "99"
        with pytest.raises(HandshakeAuthError, match="Unsupported ack version"):
            _verify_ack_signature(ack, responder_card)

    # --- malformed hex ---
    def test_raises_auth_on_malformed_hex(self, responder, session_id,
                                           initiator_card, responder_card):
        ack = self._valid_ack(responder, session_id, initiator_card)
        ack["ephemeral_pub"] = "ZZZZ"
        with pytest.raises(HandshakeAuthError, match="malformed or invalid field types"):
            _verify_ack_signature(ack, responder_card)

    # --- EnvelopeValidationError ---
    def test_raises_auth_on_envelope_error(self, responder, session_id,
                                            initiator_card, responder_card):
        ack = self._valid_ack(responder, session_id, initiator_card)
        with patch.object(hs_mod, "hybrid_verify",
                          side_effect=EnvelopeValidationError("oops")):
            with pytest.raises(HandshakeAuthError, match="signature fields are invalid"):
                _verify_ack_signature(ack, responder_card)

    # --- signature returns False ---
    def test_raises_auth_when_signature_false(self, responder, session_id,
                                               initiator_card, responder_card):
        ack = self._valid_ack(responder, session_id, initiator_card)
        with patch.object(hs_mod, "hybrid_verify", return_value=False):
            with pytest.raises(HandshakeAuthError, match="AckMessage signature invalid"):
                _verify_ack_signature(ack, responder_card)

    # --- happy path ---
    def test_happy_path_returns_bytes(self, responder, session_id,
                                       initiator_card, responder_card):
        ack = self._valid_ack(responder, session_id, initiator_card)
        result = _verify_ack_signature(ack, responder_card)
        assert isinstance(result, bytes)


# ===========================================================================
# _derive_ack_secret
# ===========================================================================

class TestDeriveAckSecret:

    def _valid_ack(self, responder, session_id, initiator_card):
        shared_secret_A = b"\xcc" * 32
        msg, _ = _make_ack(responder, session_id, "alice-id-1234",
                            shared_secret_A, initiator_card)
        return msg, shared_secret_A

    def test_proof_mismatch_raises(self, responder, session_id, initiator_card, initiator):
        ack, shared_secret_A = self._valid_ack(responder, session_id, initiator_card)
        ack["proof"] = "badhex0000"
        with pytest.raises(HandshakeProofError, match="man-in-the-middle"):
            _derive_ack_secret(ack, shared_secret_A, initiator)

    def test_happy_path_returns_bytes(self, responder, session_id, initiator_card, initiator):
        ack, shared_secret_A = self._valid_ack(responder, session_id, initiator_card)
        result = _derive_ack_secret(ack, shared_secret_A, initiator)
        assert isinstance(result, bytes)

    def test_calls_hybrid_recipient_exchange(self, responder, session_id,
                                              initiator_card, initiator):
        ack, shared_secret_A = self._valid_ack(responder, session_id, initiator_card)
        with patch.object(hs_mod, "hybrid_recipient_exchange",
                          return_value=b"secret2") as mock_ex:
            result = _derive_ack_secret(ack, shared_secret_A, initiator)
        assert result == b"secret2"
        mock_ex.assert_called_once()


# ===========================================================================
# Handshake class — __init__ / attribute defaults
# ===========================================================================

class TestHandshakeInit:
    def test_all_attributes_none(self):
        h = Handshake()
        assert h._hello_msg  is None
        assert h._ack_msg    is None
        assert h._session    is None
        assert h._exchange   is None
        assert h._session_id is None
        assert h._config     is None
        assert h._initiator  is None
        assert h._resp_card  is None


# ===========================================================================
# Handshake.initiate
# ===========================================================================

class TestHandshakeInitiate:

    def test_returns_handshake_instance(self, initiator, responder_card):
        h = Handshake.initiate(initiator, responder_card)
        assert isinstance(h, Handshake)

    def test_session_id_is_valid_uuid(self, initiator, responder_card):
        h = Handshake.initiate(initiator, responder_card)
        uuid.UUID(h._session_id)   # raises if invalid

    def test_hello_message_set(self, initiator, responder_card):
        h = Handshake.initiate(initiator, responder_card)
        assert h._hello_msg is not None
        assert h._hello_msg["type"] == "UXSP-HELLO"

    def test_exchange_set(self, initiator, responder_card):
        h = Handshake.initiate(initiator, responder_card)
        assert h._exchange is not None

    def test_uses_default_session_config_when_none(self, initiator, responder_card):
        h = Handshake.initiate(initiator, responder_card, config=None)
        assert h._config is not None

    def test_uses_provided_session_config(self, initiator, responder_card):
        cfg = SessionConfig()
        h = Handshake.initiate(initiator, responder_card, config=cfg)
        assert h._config is cfg

    def test_resp_card_stored(self, initiator, responder_card):
        h = Handshake.initiate(initiator, responder_card)
        assert h._resp_card is responder_card

    def test_initiator_stored(self, initiator, responder_card):
        h = Handshake.initiate(initiator, responder_card)
        assert h._initiator is initiator


# ===========================================================================
# Handshake.respond
# ===========================================================================

class TestHandshakeRespond:

    def test_happy_path(self, initiator, responder, responder_card, initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        resp_hs = Handshake.respond(responder, init_hs.hello_message, initiator_card, nonce_store)
        assert isinstance(resp_hs, Handshake)
        assert resp_hs._ack_msg is not None
        assert resp_hs._session is not None
        assert resp_hs._session.active

    def test_uses_default_config_when_none(self, initiator, responder, responder_card,
                                            initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        resp_hs = Handshake.respond(responder, init_hs.hello_message, initiator_card,
                                    nonce_store, config=None)
        assert resp_hs._config is not None

    def test_invalid_session_id_raises(self, initiator, responder, responder_card,
                                        initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        bad_hello = dict(init_hs.hello_message)
        bad_hello["session_id"] = "NOT-A-UUID"
        with pytest.raises(HandshakeAuthError, match="Invalid or malformed session_id"):
            Handshake.respond(responder, bad_hello, initiator_card, nonce_store)

    def test_replay_attack_raises(self, initiator, responder, responder_card,
                                   initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        hello   = init_hs.hello_message
        # First call succeeds
        Handshake.respond(responder, hello, initiator_card, nonce_store)
        # Second call with same nonce raises
        with pytest.raises(HandshakeExpiredError, match="Replay attack"):
            Handshake.respond(responder, hello, initiator_card, nonce_store)

    def test_session_is_not_initiator(self, initiator, responder, responder_card,
                                       initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        resp_hs = Handshake.respond(responder, init_hs.hello_message, initiator_card, nonce_store)
        assert resp_hs._session.is_initiator is False

    def test_session_remote_id_is_initiator(self, initiator, responder, responder_card,
                                              initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        resp_hs = Handshake.respond(responder, init_hs.hello_message, initiator_card, nonce_store)
        assert resp_hs._session.remote_id == initiator.entity_id

    def test_session_local_id_is_responder(self, initiator, responder, responder_card,
                                             initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        resp_hs = Handshake.respond(responder, init_hs.hello_message, initiator_card, nonce_store)
        assert resp_hs._session.local_id == responder.entity_id


# ===========================================================================
# Handshake.complete
# ===========================================================================

class TestHandshakeComplete:

    def _do_initiate_respond(self, initiator, responder, responder_card, initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        resp_hs = Handshake.respond(responder, init_hs.hello_message, initiator_card, nonce_store)
        return init_hs, resp_hs

    def test_happy_path(self, initiator, responder, responder_card, initiator_card, nonce_store):
        init_hs, resp_hs = self._do_initiate_respond(
            initiator, responder, responder_card, initiator_card, nonce_store)
        session = init_hs.complete(resp_hs.ack_message, responder_card, nonce_store)
        assert session.active
        assert session.is_initiator is True
        assert session.local_id  == initiator.entity_id
        assert session.remote_id == responder_card.entity_id

    def test_raises_if_called_before_initiate(self, responder_card, nonce_store, ack_msg):
        h = Handshake()          # never called initiate
        with pytest.raises(HandshakeError, match="complete\\(\\) called before initiate"):
            h.complete(ack_msg, responder_card, nonce_store)

    def test_raises_on_session_id_mismatch(self, initiator, responder, responder_card,
                                            initiator_card, nonce_store):
        init_hs, resp_hs = self._do_initiate_respond(
            initiator, responder, responder_card, initiator_card, nonce_store)
        bad_ack = dict(resp_hs.ack_message)
        bad_ack["session_id"] = str(uuid.uuid4())   # different UUID
        with pytest.raises(HandshakeAuthError, match="session_id does not match"):
            init_hs.complete(bad_ack, responder_card, nonce_store)

    def test_raises_on_initiator_id_mismatch(self, initiator, responder, responder_card,
                                              initiator_card, nonce_store):
        init_hs, resp_hs = self._do_initiate_respond(
            initiator, responder, responder_card, initiator_card, nonce_store)
        bad_ack = dict(resp_hs.ack_message)
        bad_ack["initiator_id"] = "wrong-initiator"
        with pytest.raises(HandshakeAuthError, match="initiator_id does not match"):
            init_hs.complete(bad_ack, responder_card, nonce_store)

    def test_raises_on_responder_id_mismatch(self, initiator, responder, responder_card,
                                              initiator_card, nonce_store):
        init_hs, resp_hs = self._do_initiate_respond(
            initiator, responder, responder_card, initiator_card, nonce_store)
        bad_ack = dict(resp_hs.ack_message)
        bad_ack["responder_id"] = "wrong-responder"
        with pytest.raises(HandshakeAuthError, match="responder_id does not match"):
            init_hs.complete(bad_ack, responder_card, nonce_store)

    def test_raises_on_replay(self, initiator, responder, responder_card,
                               initiator_card, nonce_store):
        init_hs, resp_hs = self._do_initiate_respond(
            initiator, responder, responder_card, initiator_card, nonce_store)
        ack = resp_hs.ack_message
        init_hs.complete(ack, responder_card, nonce_store)   # first call OK
        # Re-create initiator side (same session_id, same ack) — must fail
        init_hs2 = Handshake.initiate(initiator, responder_card)
        # forcibly set session_id to the same one so ack passes earlier checks
        init_hs2._session_id = init_hs._session_id
        init_hs2._exchange   = init_hs._exchange
        init_hs2._hello_msg  = init_hs._hello_msg
        with pytest.raises(HandshakeExpiredError, match="Replay attack"):
            init_hs2.complete(ack, responder_card, nonce_store)

    def test_raises_on_responder_card_mismatch(self, initiator, responder, responder_card,
                                                initiator_card, nonce_store):
        init_hs, resp_hs = self._do_initiate_respond(
            initiator, responder, responder_card, initiator_card, nonce_store)
        different_card = PublicCard("totally-different-id")
        # The ack still passes format checks (same responder_id), but the card
        # entity_id differs from what was used in initiate().
        # We patch _verify_ack_signature to not blow up on the forged card.
        ack = dict(resp_hs.ack_message)
        ack["responder_id"] = "totally-different-id"
        with patch.object(hs_mod, "_verify_ack_signature", return_value=b"signable"):
            with pytest.raises(HandshakeAuthError, match="responder_card does not match"):
                init_hs.complete(ack, different_card, nonce_store)

    def test_session_stored_on_instance(self, initiator, responder, responder_card,
                                         initiator_card, nonce_store):
        init_hs, resp_hs = self._do_initiate_respond(
            initiator, responder, responder_card, initiator_card, nonce_store)
        session = init_hs.complete(resp_hs.ack_message, responder_card, nonce_store)
        assert init_hs._session is session

    def test_uses_default_config_when_none(self, initiator, responder, responder_card,
                                            initiator_card, nonce_store):
        """Exercises the `self._config or SessionConfig()` branch in complete()."""
        init_hs, resp_hs = self._do_initiate_respond(
            initiator, responder, responder_card, initiator_card, nonce_store)
        init_hs._config = None   # force the fallback branch
        session = init_hs.complete(resp_hs.ack_message, responder_card, nonce_store)
        assert session is not None


# ===========================================================================
# Handshake properties
# ===========================================================================

class TestHandshakeProperties:

    # hello_message
    def test_hello_message_before_initiate_raises(self):
        h = Handshake()
        with pytest.raises(HandshakeError, match="No hello message"):
            _ = h.hello_message

    def test_hello_message_after_initiate(self, initiator, responder_card):
        h = Handshake.initiate(initiator, responder_card)
        msg = h.hello_message
        assert msg["type"] == "UXSP-HELLO"

    # ack_message
    def test_ack_message_before_respond_raises(self):
        h = Handshake()
        with pytest.raises(HandshakeError, match="No ack message"):
            _ = h.ack_message

    def test_ack_message_after_respond(self, initiator, responder, responder_card,
                                        initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        resp_hs = Handshake.respond(responder, init_hs.hello_message, initiator_card, nonce_store)
        msg = resp_hs.ack_message
        assert msg["type"] == "UXSP-ACK"

    # session
    def test_session_before_respond_or_complete_raises(self):
        h = Handshake()
        with pytest.raises(HandshakeError, match="Session not yet established"):
            _ = h.session

    def test_session_after_respond(self, initiator, responder, responder_card,
                                    initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        resp_hs = Handshake.respond(responder, init_hs.hello_message, initiator_card, nonce_store)
        assert resp_hs.session.active

    def test_session_after_complete(self, initiator, responder, responder_card,
                                     initiator_card, nonce_store):
        init_hs = Handshake.initiate(initiator, responder_card)
        resp_hs = Handshake.respond(responder, init_hs.hello_message, initiator_card, nonce_store)
        init_hs.complete(resp_hs.ack_message, responder_card, nonce_store)
        assert init_hs.session.active
