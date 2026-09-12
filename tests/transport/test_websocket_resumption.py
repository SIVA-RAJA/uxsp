"""
Tests for UXSP WebSocket Session Resumption.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from uxsp.core.identity import Identity
from uxsp.transport.websocket import (
    FrameType,
    SessionNotEstablishedError,
    UnexpectedFrameError,
    UXSPFrame,
    UXSPWebSocket,
    UXSPWebSocketError,
)


class TestWebSocketSessionResumption:
    def _create_established_pair(self):
        alice = Identity.create("Alice", "CLIENT")
        bob = Identity.create("Bob", "SERVER")
        alice_card = alice.public_card()
        bob_card = bob.public_card()

        ws_alice = UXSPWebSocket.as_initiator(alice, bob_card)
        ws_bob = UXSPWebSocket.as_responder(bob, limiter=MagicMock())

        hello = ws_alice.start_handshake()
        ack = ws_bob.handle_hello(hello, alice_card)
        comp = ws_alice.complete_handshake(ack)
        ws_bob.handle_complete(comp)

        return ws_alice, ws_bob, alice, bob

    def test_session_resumption_happy_path(self):
        ws_alice, ws_bob, alice, bob = self._create_established_pair()

        # Alice sends 2 messages to Bob before connection drop
        f1 = ws_alice.encode(b"msg 1")
        assert ws_bob.decode(f1) == b"msg 1"
        f2 = ws_alice.encode(b"msg 2")
        assert ws_bob.decode(f2) == b"msg 2"

        # Bob replies with 1 message
        f3 = ws_bob.encode(b"ack msg")
        assert ws_alice.decode(f3) == b"ack msg"

        # Simulate socket disconnection & reconnection
        # Alice initiates resumption
        resume_frame = ws_alice.start_resume()
        assert resume_frame.type == FrameType.RESUME
        assert resume_frame.payload["session_id"] == ws_alice.session.session_id
        assert resume_frame.payload["last_seq"] == ws_alice.session.recv_seq
        assert "auth_tag" in resume_frame.payload

        # Bob handles resumption
        resume_ack = ws_bob.handle_resume(resume_frame)
        assert resume_ack.type == FrameType.RESUME_ACK
        assert resume_ack.payload["session_id"] == ws_bob.session.session_id
        assert "auth_tag" in resume_ack.payload

        # Alice completes resumption
        ws_alice.complete_resume(resume_ack)

        # After resumption, communication continues seamlessly with correct sequences
        f4 = ws_alice.encode(b"msg 3 post resume")
        assert ws_bob.decode(f4) == b"msg 3 post resume"

        f5 = ws_bob.encode(b"msg 4 reply post resume")
        assert ws_alice.decode(f5) == b"msg 4 reply post resume"

    def test_resume_fails_on_tampered_tag(self):
        ws_alice, ws_bob, _, _ = self._create_established_pair()

        resume_frame = ws_alice.start_resume()
        # Tamper with the auth tag
        tampered_payload = dict(resume_frame.payload)
        tampered_payload["auth_tag"] = "0" * len(tampered_payload["auth_tag"])
        tampered_frame = UXSPFrame.build(FrameType.RESUME, tampered_payload)

        with pytest.raises(UXSPWebSocketError, match="Invalid resume authentication tag"):
            ws_bob.handle_resume(tampered_frame)

    def test_resume_fails_on_session_id_mismatch(self):
        ws_alice, ws_bob, _, _ = self._create_established_pair()

        resume_frame = ws_alice.start_resume()
        wrong_sid_payload = dict(resume_frame.payload)
        wrong_sid_payload["session_id"] = "non-existent-session-id"
        wrong_sid_frame = UXSPFrame.build(FrameType.RESUME, wrong_sid_payload)

        with pytest.raises(UXSPWebSocketError, match="Session ID mismatch"):
            ws_bob.handle_resume(wrong_sid_frame)

    def test_complete_resume_fails_on_tampered_ack(self):
        ws_alice, ws_bob, _, _ = self._create_established_pair()

        resume_frame = ws_alice.start_resume()
        resume_ack = ws_bob.handle_resume(resume_frame)

        tampered_ack_payload = dict(resume_ack.payload)
        tampered_ack_payload["auth_tag"] = "f" * len(tampered_ack_payload["auth_tag"])
        tampered_ack = UXSPFrame.build(FrameType.RESUME_ACK, tampered_ack_payload)

        with pytest.raises(UXSPWebSocketError, match="Invalid resume ack authentication tag"):
            ws_alice.complete_resume(tampered_ack)

    def test_resume_rejected_when_session_revoked(self):
        ws_alice, ws_bob, _, _ = self._create_established_pair()
        ws_alice.session.revoke()

        with pytest.raises(SessionNotEstablishedError):
            ws_alice.start_resume()

    def test_resume_unexpected_frames(self):
        ws_alice, ws_bob, _, _ = self._create_established_pair()

        # complete_resume with non-RESUME_ACK frame
        wrong_frame = UXSPFrame.build(FrameType.PING, {})
        with pytest.raises(UnexpectedFrameError):
            ws_alice.complete_resume(wrong_frame)

        # handle_resume with non-RESUME frame
        with pytest.raises(UnexpectedFrameError):
            ws_bob.handle_resume(wrong_frame)

    def test_complete_resume_inactive_or_mismatch(self):
        ws_alice, ws_bob, _, _ = self._create_established_pair()
        resume_frame = ws_alice.start_resume()
        resume_ack = ws_bob.handle_resume(resume_frame)

        # Test session ID mismatch in complete_resume (line 380)
        mismatched_ack_payload = dict(resume_ack.payload)
        mismatched_ack_payload["session_id"] = "wrong-session-id"
        mismatched_ack = UXSPFrame.build(FrameType.RESUME_ACK, mismatched_ack_payload)
        with pytest.raises(UXSPWebSocketError, match="RESUME_ACK session_id 'wrong-session-id' does not match"):
            ws_alice.complete_resume(mismatched_ack)

        # Test inactive session in complete_resume (line 374)
        ws_alice.session.revoke()
        with pytest.raises(SessionNotEstablishedError, match="Cannot complete resume: session is not active"):
            ws_alice.complete_resume(resume_ack)

    def test_handle_resume_session_not_active(self):
        ws_alice, ws_bob, _, _ = self._create_established_pair()
        resume_frame = ws_alice.start_resume()

        # Test inactive session in handle_resume (line 470)
        ws_bob.session.revoke()
        with pytest.raises(SessionNotEstablishedError, match="Cannot resume: session not found or expired"):
            ws_bob.handle_resume(resume_frame)

