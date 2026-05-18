"""
Full-coverage pytest suite for websocket.py.

All uxsp.core.* modules are mocked at the sys.modules level so no real
UXSP installation is required.  Every reachable branch and line in the
source file is exercised.
"""

from __future__ import annotations

import json
import sys
import time
import warnings
from unittest.mock import MagicMock

import pytest

# ─────────────────────────────────────────────────────────────────
# Inject fake uxsp.core.* packages before importing the module under
# test so that the lazy `from uxsp.core.xxx import Yyy` statements
# inside the module bodies resolve without a real installation.
# ─────────────────────────────────────────────────────────────────

_MemoryNonceStore = MagicMock(name="MemoryNonceStore")
_Handshake = MagicMock(name="Handshake")

@pytest.fixture(autouse=True)
def patch_websocket_deps(monkeypatch):
    import uxsp.core.handshake as hs_mod
    import uxsp.core.nonce as nonce_mod
    monkeypatch.setattr(nonce_mod, "MemoryNonceStore", _MemoryNonceStore)
    monkeypatch.setattr(hs_mod, "Handshake", _Handshake)

# Now import the module under test
from uxsp.transport.websocket import (  # noqa: E402
    MAX_FRAME_BYTES,
    FrameTooLargeError,
    FrameType,
    SessionNotEstablishedError,
    UnexpectedFrameError,
    UXSPFrame,
    UXSPWebSocket,
    UXSPWebSocketError,
)

# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _valid_json(frame_type: str = "UXSP-DATA", payload: dict | None = None,
                timestamp: int | None = None) -> str:
    obj: dict = {"uxsp_frame": frame_type}
    if payload is not None:
        obj["payload"] = payload
    if timestamp is not None:
        obj["timestamp"] = timestamp
    return json.dumps(obj)


def _make_ws_with_session(session_mock: MagicMock | None = None) -> UXSPWebSocket:
    """Return a bare UXSPWebSocket whose _session is pre-set."""
    ws = UXSPWebSocket.__new__(UXSPWebSocket)
    ws._identity    = MagicMock()
    ws._config      = None
    ws._nonce_store = MagicMock()
    ws._hs          = None
    ws._role        = None
    ws._remote_card = None
    ws._limiter     = None
    ws._session     = session_mock if session_mock is not None else MagicMock()
    return ws


def _make_ws_no_session() -> UXSPWebSocket:
    ws = _make_ws_with_session()
    ws._session = None
    return ws


# ─────────────────────────────────────────────────────────────────
# FrameType
# ─────────────────────────────────────────────────────────────────

class TestFrameType:
    def test_all_values(self):
        assert FrameType.HANDSHAKE_HELLO    == "UXSP-HELLO"
        assert FrameType.HANDSHAKE_ACK      == "UXSP-ACK"
        assert FrameType.HANDSHAKE_COMPLETE == "UXSP-COMPLETE"
        assert FrameType.DATA               == "UXSP-DATA"
        assert FrameType.ERROR              == "UXSP-ERROR"
        assert FrameType.CLOSE              == "UXSP-CLOSE"
        assert FrameType.PING               == "UXSP-PING"
        assert FrameType.PONG               == "UXSP-PONG"


# ─────────────────────────────────────────────────────────────────
# Error hierarchy
# ─────────────────────────────────────────────────────────────────

class TestErrorHierarchy:
    def test_unexpected_frame_is_uxsp_error(self):
        assert issubclass(UnexpectedFrameError, UXSPWebSocketError)

    def test_session_not_established_is_uxsp_error(self):
        assert issubclass(SessionNotEstablishedError, UXSPWebSocketError)

    def test_frame_too_large_is_uxsp_error(self):
        assert issubclass(FrameTooLargeError, UXSPWebSocketError)


# ─────────────────────────────────────────────────────────────────
# UXSPFrame.__init__ and build
# ─────────────────────────────────────────────────────────────────

class TestUXSPFrameInit:
    def test_init_with_explicit_ts(self):
        f = UXSPFrame(FrameType.PING, {"k": "v"}, ts=12345)
        assert f.type      == FrameType.PING
        assert f.payload   == {"k": "v"}
        assert f.timestamp == 12345

    def test_init_without_ts_uses_current_time(self):
        before = int(time.time())
        f = UXSPFrame(FrameType.PING)
        after  = int(time.time())
        assert before <= f.timestamp <= after

    def test_init_none_payload_becomes_empty_dict(self):
        f = UXSPFrame(FrameType.DATA, payload=None)
        assert f.payload == {}

    def test_build_classmethod(self):
        f = UXSPFrame.build(FrameType.ERROR, {"x": 1})
        assert f.type    == FrameType.ERROR
        assert f.payload == {"x": 1}

    def test_build_without_payload(self):
        f = UXSPFrame.build(FrameType.CLOSE)
        assert f.payload == {}


# ─────────────────────────────────────────────────────────────────
# UXSPFrame.to_json
# ─────────────────────────────────────────────────────────────────

class TestUXSPFrameToJson:
    def test_round_trips(self):
        f    = UXSPFrame(FrameType.DATA, {"msg": "hi"}, ts=9999)
        text = f.to_json()
        obj  = json.loads(text)
        assert obj["uxsp_frame"] == "UXSP-DATA"
        assert obj["timestamp"]  == 9999
        assert obj["payload"]    == {"msg": "hi"}


# ─────────────────────────────────────────────────────────────────
# UXSPFrame.__repr__
# ─────────────────────────────────────────────────────────────────

class TestUXSPFrameRepr:
    def test_repr_contains_type_and_ts(self):
        f = UXSPFrame(FrameType.PING, ts=1111)
        r = repr(f)
        assert "UXSP-PING" in r
        assert "1111" in r


# ─────────────────────────────────────────────────────────────────
# UXSPFrame.from_json — happy paths
# ─────────────────────────────────────────────────────────────────

class TestFromJsonHappy:
    def test_parses_str(self):
        text = _valid_json("UXSP-PING", {}, timestamp=5000)
        f    = UXSPFrame.from_json(text)
        assert f.type      == FrameType.PING
        assert f.timestamp == 5000

    def test_parses_bytes(self):
        text = _valid_json("UXSP-PING", {}, timestamp=6000)
        f    = UXSPFrame.from_json(text.encode("utf-8"))
        assert f.type      == FrameType.PING
        assert f.timestamp == 6000

    def test_parses_bytearray(self):
        text = _valid_json("UXSP-PONG", {}, timestamp=7000)
        f    = UXSPFrame.from_json(bytearray(text.encode("utf-8")))
        assert f.type == FrameType.PONG

    def test_missing_timestamp_defaults_to_now(self):
        text = json.dumps({"uxsp_frame": "UXSP-DATA", "payload": {}})
        before = int(time.time())
        f = UXSPFrame.from_json(text)
        after  = int(time.time())
        assert before <= f.timestamp <= after

    def test_missing_payload_defaults_to_empty_dict(self):
        text = json.dumps({"uxsp_frame": "UXSP-DATA", "timestamp": 1})
        f = UXSPFrame.from_json(text)
        assert f.payload == {}


# ─────────────────────────────────────────────────────────────────
# UXSPFrame.from_json — error branches
# ─────────────────────────────────────────────────────────────────

class TestFromJsonErrors:
    def test_wrong_type_raises(self):
        with pytest.raises(UXSPWebSocketError, match="frame must be str or bytes"):
            UXSPFrame.from_json(12345)  # type: ignore[arg-type]

    def test_frame_too_large_raises(self):
        big = "x" * (MAX_FRAME_BYTES + 1)
        with pytest.raises(FrameTooLargeError, match="exceeds"):
            UXSPFrame.from_json(big)

    def test_invalid_json_raises(self):
        with pytest.raises(UXSPWebSocketError, match="Invalid JSON"):
            UXSPFrame.from_json("{not json}")

    def test_non_dict_json_raises(self):
        with pytest.raises(UXSPWebSocketError, match="object/dictionary"):
            UXSPFrame.from_json("[1,2,3]")

    def test_missing_uxsp_frame_key_raises(self):
        text = json.dumps({"payload": {}})
        with pytest.raises(UXSPWebSocketError, match="Missing 'uxsp_frame'"):
            UXSPFrame.from_json(text)

    def test_unknown_frame_type_raises(self):
        text = json.dumps({"uxsp_frame": "UNKNOWN-TYPE"})
        with pytest.raises(UXSPWebSocketError, match="Unknown frame type"):
            UXSPFrame.from_json(text)

    def test_non_dict_payload_raises(self):
        text = json.dumps({"uxsp_frame": "UXSP-DATA", "payload": [1, 2]})
        with pytest.raises(UXSPWebSocketError, match="payload must be an object"):
            UXSPFrame.from_json(text)

    def test_non_integer_timestamp_raises(self):
        text = json.dumps({"uxsp_frame": "UXSP-DATA",
                           "payload": {},
                           "timestamp": "not-an-int"})
        with pytest.raises(UXSPWebSocketError, match="timestamp must be a Unix integer"):
            UXSPFrame.from_json(text)

    def test_none_timestamp_raises(self):
        # None is not int-castable from dict.get path  →  int(None) → TypeError
        text = json.dumps({"uxsp_frame": "UXSP-DATA",
                           "payload": {},
                           "timestamp": None})
        with pytest.raises(UXSPWebSocketError, match="timestamp must be a Unix integer"):
            UXSPFrame.from_json(text)


# ─────────────────────────────────────────────────────────────────
# UXSPWebSocket.__init__ with and without nonce_store
# ─────────────────────────────────────────────────────────────────

class TestUXSPWebSocketInit:
    def test_init_without_nonce_store_creates_memory_store(self):
        _MemoryNonceStore.reset_mock()
        identity = MagicMock()
        ws = UXSPWebSocket(identity)
        _MemoryNonceStore.assert_called_once()
        assert ws._identity is identity
        assert ws._config is None
        assert ws._session is None
        assert ws._hs is None
        assert ws._role is None
        assert ws._remote_card is None
        assert ws._limiter is None

    def test_init_with_nonce_store_uses_provided(self):
        _MemoryNonceStore.reset_mock()
        ns = MagicMock()
        ws = UXSPWebSocket(MagicMock(), nonce_store=ns)
        _MemoryNonceStore.assert_not_called()
        assert ws._nonce_store is ns


# ─────────────────────────────────────────────────────────────────
# as_initiator / as_responder
# ─────────────────────────────────────────────────────────────────

class TestFactoryMethods:
    def test_as_initiator_sets_role_and_remote_card(self):
        identity    = MagicMock()
        remote_card = MagicMock()
        ns          = MagicMock()
        ws = UXSPWebSocket.as_initiator(identity, remote_card, config=None, nonce_store=ns)
        assert ws._role        == "initiator"
        assert ws._remote_card is remote_card

    def test_as_responder_with_limiter(self):
        limiter = MagicMock()
        ns      = MagicMock()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            ws = UXSPWebSocket.as_responder(MagicMock(), limiter=limiter, nonce_store=ns)
        assert ws._role    == "responder"
        assert ws._limiter is limiter
        # no UserWarning should have been emitted
        user_warnings = [x for x in w if issubclass(x.category, UserWarning)]
        assert len(user_warnings) == 0

    def test_as_responder_without_limiter_warns(self):
        ns = MagicMock()
        with pytest.warns(UserWarning, match="without a rate limiter"):
            ws = UXSPWebSocket.as_responder(MagicMock(), limiter=None, nonce_store=ns)
        assert ws._limiter is None


# ─────────────────────────────────────────────────────────────────
# start_handshake
# ─────────────────────────────────────────────────────────────────

class TestStartHandshake:
    def test_raises_without_remote_card(self):
        ws = _make_ws_no_session()
        ws._remote_card = None
        with pytest.raises(UXSPWebSocketError, match="No remote card"):
            ws.start_handshake()

    def test_returns_hello_frame(self):
        fake_hs              = MagicMock()
        fake_hs.hello_message = {"pub": "key"}
        _Handshake.initiate.return_value = fake_hs

        ws              = _make_ws_no_session()
        ws._remote_card = MagicMock()

        frame = ws.start_handshake()

        assert frame.type    == FrameType.HANDSHAKE_HELLO
        assert frame.payload == {"pub": "key"}
        assert ws._hs is fake_hs


# ─────────────────────────────────────────────────────────────────
# complete_handshake
# ─────────────────────────────────────────────────────────────────

class TestCompleteHandshake:
    def _prep(self) -> tuple[UXSPWebSocket, MagicMock]:
        fake_session         = MagicMock()
        fake_session.session_id = "sid-abc"
        fake_hs              = MagicMock()
        fake_hs.complete.return_value = fake_session

        ws              = _make_ws_no_session()
        ws._hs          = fake_hs
        ws._remote_card = MagicMock()
        return ws, fake_session

    def test_raises_if_no_hs(self):
        ws = _make_ws_no_session()
        ack = UXSPFrame.build(FrameType.HANDSHAKE_ACK, {})
        with pytest.raises(SessionNotEstablishedError, match="before start_handshake"):
            ws.complete_handshake(ack)

    def test_raises_if_no_remote_card(self):
        ws = _make_ws_no_session()
        ws._hs = MagicMock()
        ack = UXSPFrame.build(FrameType.HANDSHAKE_ACK, {})
        with pytest.raises(SessionNotEstablishedError):
            ws.complete_handshake(ack)

    def test_raises_on_wrong_frame_type(self):
        ws, _ = self._prep()
        wrong = UXSPFrame.build(FrameType.DATA, {})
        with pytest.raises(UnexpectedFrameError, match="HANDSHAKE_ACK"):
            ws.complete_handshake(wrong)

    def test_happy_path_returns_complete_frame(self):
        ws, fake_session = self._prep()
        ack = UXSPFrame.build(FrameType.HANDSHAKE_ACK, {"ack": True})

        frame = ws.complete_handshake(ack)

        assert frame.type == FrameType.HANDSHAKE_COMPLETE
        assert frame.payload["session_id"] == "sid-abc"
        assert ws._session is fake_session


# ─────────────────────────────────────────────────────────────────
# handle_hello
# ─────────────────────────────────────────────────────────────────

class TestHandleHello:
    def _make_responder(self, *, limiter=None) -> UXSPWebSocket:
        ws = _make_ws_no_session()
        ws._limiter = limiter
        return ws

    def test_raises_if_hs_already_set(self):
        ws     = self._make_responder()
        ws._hs = MagicMock()
        frame  = UXSPFrame.build(FrameType.HANDSHAKE_HELLO, {})
        with pytest.raises(UXSPWebSocketError, match="called twice"):
            ws.handle_hello(frame, MagicMock())

    def test_raises_on_wrong_frame_type(self):
        ws    = self._make_responder()
        frame = UXSPFrame.build(FrameType.DATA, {})
        with pytest.raises(UnexpectedFrameError, match="HANDSHAKE_HELLO"):
            ws.handle_hello(frame, MagicMock())

    def test_calls_limiter_check(self):
        limiter            = MagicMock()
        initiator_card     = MagicMock()
        initiator_card.entity_id = "entity-42"

        fake_hs            = MagicMock()
        fake_hs.ack_message = {"ack": "data"}
        _Handshake.respond.return_value = fake_hs

        ws    = self._make_responder(limiter=limiter)
        frame = UXSPFrame.build(FrameType.HANDSHAKE_HELLO, {"hello": True})
        ws.handle_hello(frame, initiator_card)

        limiter.check.assert_called_once_with("entity-42")

    def test_no_limiter_skips_check(self):
        fake_hs            = MagicMock()
        fake_hs.ack_message = {}
        _Handshake.respond.return_value = fake_hs

        ws    = self._make_responder(limiter=None)
        frame = UXSPFrame.build(FrameType.HANDSHAKE_HELLO, {})
        result = ws.handle_hello(frame, MagicMock())

        assert result.type == FrameType.HANDSHAKE_ACK

    def test_sets_hs_and_remote_card(self):
        fake_hs            = MagicMock()
        fake_hs.ack_message = {}
        _Handshake.respond.return_value = fake_hs

        initiator_card = MagicMock()
        ws    = self._make_responder()
        frame = UXSPFrame.build(FrameType.HANDSHAKE_HELLO, {})
        ws.handle_hello(frame, initiator_card)

        assert ws._hs is fake_hs
        assert ws._remote_card is initiator_card


# ─────────────────────────────────────────────────────────────────
# handle_complete
# ─────────────────────────────────────────────────────────────────

class TestHandleComplete:
    def _prep(self, session_id="sid-xyz") -> tuple[UXSPWebSocket, str]:
        fake_session           = MagicMock()
        fake_session.session_id = session_id
        fake_hs                = MagicMock()
        fake_hs.session        = fake_session

        ws     = _make_ws_no_session()
        ws._hs = fake_hs
        return ws, session_id

    def test_raises_if_no_hs(self):
        ws = _make_ws_no_session()
        frame = UXSPFrame.build(FrameType.HANDSHAKE_COMPLETE, {"session_id": "x"})
        with pytest.raises(SessionNotEstablishedError, match="before handle_hello"):
            ws.handle_complete(frame)

    def test_raises_on_wrong_frame_type(self):
        ws, _ = self._prep()
        frame = UXSPFrame.build(FrameType.HANDSHAKE_ACK, {})
        with pytest.raises(UnexpectedFrameError, match="HANDSHAKE_COMPLETE"):
            ws.handle_complete(frame)

    def test_raises_if_session_already_set(self):
        ws, sid = self._prep()
        ws._session = MagicMock()  # already established
        frame = UXSPFrame.build(FrameType.HANDSHAKE_COMPLETE, {"session_id": sid})
        with pytest.raises(UXSPWebSocketError, match="already completed"):
            ws.handle_complete(frame)

    def test_raises_on_session_id_mismatch(self):
        ws, _ = self._prep(session_id="correct-id")
        frame = UXSPFrame.build(FrameType.HANDSHAKE_COMPLETE, {"session_id": "wrong-id"})
        with pytest.raises(UXSPWebSocketError, match="does not match"):
            ws.handle_complete(frame)

    def test_happy_path_sets_session(self):
        ws, sid = self._prep()
        frame   = UXSPFrame.build(FrameType.HANDSHAKE_COMPLETE, {"session_id": sid})
        ws.handle_complete(frame)
        assert ws._session is ws._hs.session


# ─────────────────────────────────────────────────────────────────
# encode / decode
# ─────────────────────────────────────────────────────────────────

class TestEncodeDecodeData:
    def test_encode_raises_without_session(self):
        ws = _make_ws_no_session()
        with pytest.raises(SessionNotEstablishedError, match="before handshake"):
            ws.encode(b"hello")

    def test_encode_returns_data_frame(self):
        session          = MagicMock()
        session.encrypt.return_value = {"cipher": "text"}
        ws = _make_ws_with_session(session)

        frame = ws.encode(b"hello")
        assert frame.type    == FrameType.DATA
        assert frame.payload == {"cipher": "text"}
        session.encrypt.assert_called_once_with(b"hello")

    def test_decode_raises_without_session(self):
        ws    = _make_ws_no_session()
        frame = UXSPFrame.build(FrameType.DATA, {})
        with pytest.raises(SessionNotEstablishedError, match="before handshake"):
            ws.decode(frame)

    def test_decode_raises_on_wrong_frame_type(self):
        ws    = _make_ws_with_session()
        frame = UXSPFrame.build(FrameType.ERROR, {})
        with pytest.raises(UnexpectedFrameError, match="DATA frame"):
            ws.decode(frame)

    def test_decode_happy_path(self):
        session          = MagicMock()
        session.decrypt.return_value = b"plaintext"
        ws    = _make_ws_with_session(session)
        frame = UXSPFrame.build(FrameType.DATA, {"cipher": "abc"})

        result = ws.decode(frame)
        assert result == b"plaintext"
        session.decrypt.assert_called_once_with({"cipher": "abc"})


# ─────────────────────────────────────────────────────────────────
# ping / pong
# ─────────────────────────────────────────────────────────────────

class TestPingPong:
    def test_ping_returns_ping_frame_with_ts(self):
        ws    = _make_ws_no_session()
        before = int(time.time())
        frame  = ws.ping()
        after  = int(time.time())
        assert frame.type == FrameType.PING
        assert before <= frame.payload["ts"] <= after

    def test_pong_echoes_ping_ts(self):
        ws         = _make_ws_no_session()
        ping_frame = UXSPFrame.build(FrameType.PING, {"ts": 42})
        pong_frame = ws.pong(ping_frame)
        assert pong_frame.type             == FrameType.PONG
        assert pong_frame.payload["echo_ts"] == 42

    def test_pong_with_missing_ts_echoes_none(self):
        ws         = _make_ws_no_session()
        ping_frame = UXSPFrame.build(FrameType.PING, {})
        pong_frame = ws.pong(ping_frame)
        assert pong_frame.payload["echo_ts"] is None


# ─────────────────────────────────────────────────────────────────
# close (outgoing)
# ─────────────────────────────────────────────────────────────────

class TestClose:
    def test_close_without_session_unauthenticated(self):
        ws    = _make_ws_no_session()
        frame = ws.close("goodbye")
        assert frame.type            == FrameType.CLOSE
        assert frame.payload["reason"] == "goodbye"

    def test_close_without_session_default_reason(self):
        ws    = _make_ws_no_session()
        frame = ws.close()
        assert frame.payload["reason"] == "normal"

    def test_close_with_session_encrypts_and_revokes(self):
        session           = MagicMock()
        session.encrypt.return_value = {"c": "1"}
        ws = _make_ws_with_session(session)

        frame = ws.close("logout")

        session.encrypt.assert_called_once()
        # The call arg should be the JSON-encoded reason
        encoded_arg = session.encrypt.call_args[0][0]
        assert json.loads(encoded_arg) == {"reason": "logout"}
        session.revoke.assert_called_once()
        assert ws._session is None
        assert frame.type    == FrameType.CLOSE
        assert frame.payload == {"c": "1"}


# ─────────────────────────────────────────────────────────────────
# handle_close (incoming)
# ─────────────────────────────────────────────────────────────────

class TestHandleClose:
    def test_raises_on_wrong_frame_type(self):
        ws    = _make_ws_no_session()
        frame = UXSPFrame.build(FrameType.DATA, {})
        with pytest.raises(UnexpectedFrameError, match="CLOSE frame"):
            ws.handle_close(frame)

    def test_no_session_returns_payload_reason(self):
        ws    = _make_ws_no_session()
        frame = UXSPFrame.build(FrameType.CLOSE, {"reason": "server-shutdown"})
        result = ws.handle_close(frame)
        assert result == "server-shutdown"

    def test_no_session_missing_reason_returns_unknown(self):
        ws    = _make_ws_no_session()
        frame = UXSPFrame.build(FrameType.CLOSE, {})
        assert ws.handle_close(frame) == "unknown"

    def test_with_session_decrypts_reason(self):
        raw_payload   = json.dumps({"reason": "idle-timeout"}).encode()
        session       = MagicMock()
        session.decrypt.return_value = raw_payload
        ws = _make_ws_with_session(session)
        frame = UXSPFrame.build(FrameType.CLOSE, {"cipher": "data"})

        result = ws.handle_close(frame)

        session.decrypt.assert_called_once()
        session.revoke.assert_called_once()
        assert ws._session is None
        assert result == "idle-timeout"

    def test_with_session_missing_reason_returns_unknown(self):
        raw_payload   = json.dumps({}).encode()
        session       = MagicMock()
        session.decrypt.return_value = raw_payload
        ws = _make_ws_with_session(session)
        frame = UXSPFrame.build(FrameType.CLOSE, {})

        result = ws.handle_close(frame)
        assert result == "unknown"

    def test_with_session_decrypt_raises_returns_unauthenticated(self):
        session = MagicMock()
        session.decrypt.side_effect = Exception("crypto failure")
        ws = _make_ws_with_session(session)
        frame = UXSPFrame.build(FrameType.CLOSE, {})

        result = ws.handle_close(frame)

        session.revoke.assert_called_once()
        assert ws._session is None
        assert result == "unauthenticated-close"

    def test_with_session_non_dict_json_returns_unauthenticated(self):
        """Decryption succeeds but JSON root is a list, not a dict."""
        session = MagicMock()
        session.decrypt.return_value = json.dumps([1, 2, 3]).encode()
        ws = _make_ws_with_session(session)
        frame = UXSPFrame.build(FrameType.CLOSE, {})

        result = ws.handle_close(frame)

        session.revoke.assert_called_once()
        assert ws._session is None
        assert result == "unauthenticated-close"


# ─────────────────────────────────────────────────────────────────
# session property / is_ready
# ─────────────────────────────────────────────────────────────────

class TestProperties:
    def test_session_property_raises_without_session(self):
        ws = _make_ws_no_session()
        with pytest.raises(SessionNotEstablishedError, match="not yet established"):
            _ = ws.session

    def test_session_property_returns_session(self):
        session = MagicMock()
        ws = _make_ws_with_session(session)
        assert ws.session is session

    def test_is_ready_false_without_session(self):
        ws = _make_ws_no_session()
        assert ws.is_ready is False

    def test_is_ready_delegates_to_session_is_active(self):
        session           = MagicMock()
        session.is_active = True
        ws = _make_ws_with_session(session)
        assert ws.is_ready is True

    def test_is_ready_false_when_session_inactive(self):
        session           = MagicMock()
        session.is_active = False
        ws = _make_ws_with_session(session)
        assert ws.is_ready is False


# ─────────────────────────────────────────────────────────────────
# MAX_FRAME_BYTES constant
# ─────────────────────────────────────────────────────────────────

class TestConstants:
    def test_max_frame_bytes_is_one_mb(self):
        assert MAX_FRAME_BYTES == 1 * 1024 * 1024


class TestWebsocketStrEnumFallback:
    """Cover lines 19-21 of websocket.py (Python < 3.11 StrEnum shim)."""

    def test_strenum_fallback_branch_executes(self, monkeypatch):
        """
        Simulate Python 3.10 so the else-branch that defines the StrEnum
        compatibility shim runs, then verify FrameType still works.
        """
        # sys.version_info is not a true namedtuple — use a plain tuple
        fake_ver = (3, 10, 0, "final", 0)
        monkeypatch.setattr(sys, "version_info", fake_ver)

        orig = sys.modules.pop("uxsp.transport.websocket", None)
        try:
            import uxsp.transport.websocket as ws_mod
            # FrameType should still work correctly
            assert ws_mod.FrameType.DATA == "UXSP-DATA"
            # The compat shim (str, Enum) preserves the value for == comparison
            # but str() may give "FrameType.PING" instead of "UXSP-PING"
            assert ws_mod.FrameType.PING.value == "UXSP-PING"
        finally:
            sys.modules.pop("uxsp.transport.websocket", None)
            if orig is not None:
                sys.modules["uxsp.transport.websocket"] = orig
            else:
                import uxsp.transport.websocket  # noqa: F401  restore
