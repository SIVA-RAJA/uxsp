"""
uxsp.transport.websocket — WebSocket Transport Layer for UXSP Sessions

What this file does:
    Provides UXSPWebSocket and UXSPFrame, which together implement the full
    UXSP protocol over a WebSocket connection — from the initial three-step
    handshake through to encrypted data exchange and authenticated session close.

    Message format:
        Each message is a UTF-8 JSON object with fields:
            uxsp_frame  — Frame type string (see FrameType enum).
            timestamp   — Unix timestamp (int).
            payload     — Dict; content varies by frame type.

    Handshake flow (initiator side):
        ws = UXSPWebSocket.as_initiator(my_identity, remote_card)
        hello_frame = ws.start_handshake()         # send this
        # receive ack_frame from remote
        complete_frame = ws.complete_handshake(ack_frame)  # send this
        # session is now active

    Handshake flow (responder side):
        ws = UXSPWebSocket.as_responder(my_identity, limiter=rate_limiter)
        # receive hello_frame from initiator
        ack_frame = ws.handle_hello(hello_frame, initiator_card)  # send this
        # receive complete_frame from initiator
        ws.handle_complete(complete_frame)
        # session is now active

    Data exchange (both sides):
        ws.send(ws.encode(b"hello").to_json())
        frame = UXSPFrame.from_json(received_text)
        plaintext = ws.decode(frame)

Key classes:
    UXSPFrame      — Typed WebSocket frame (build, serialise, deserialise).
    UXSPWebSocket  — Stateful session manager (initiator or responder).
    FrameType      — StrEnum of all valid frame type strings.

Key errors:
    UXSPWebSocketError       — Base.
    UnexpectedFrameError     — Wrong frame type for current protocol state.
    SessionNotEstablishedError — Data frame before handshake complete.
    FrameTooLargeError       — Frame exceeds MAX_FRAME_BYTES (1 MB).
"""
from __future__ import annotations

import json
import time
import warnings
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uxsp.core.handshake import Handshake
    from uxsp.core.identity import PublicCard
    from uxsp.core.nonce import NonceStore
    from uxsp.core.rate_limit import RateLimiterBase
    from uxsp.core.session import Session, SessionConfig


from enum import StrEnum

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

# Maximum allowed frame size in bytes.
# Protects against memory exhaustion from oversized frames.
MAX_FRAME_BYTES = 1 * 1024 * 1024  # 1 MB


# ─────────────────────────────────────────────
# FRAME TYPES
# ─────────────────────────────────────────────


class FrameType(StrEnum):
    """
    Enumeration of all UXSP WebSocket frame type strings.

    Frame types and their purpose:
        HANDSHAKE_HELLO    — Initiator sends its key material and signature.
        HANDSHAKE_ACK      — Responder replies with its key material, proof, and signature.
        HANDSHAKE_COMPLETE — Initiator confirms session establishment.
        DATA               — Application data (encrypted by the session key).
        ERROR              — Protocol error notification.
        CLOSE              — Authenticated session teardown.
        PING / PONG        — Keepalive messages.
    """
    HANDSHAKE_HELLO = "UXSP-HELLO"
    HANDSHAKE_ACK = "UXSP-ACK"
    HANDSHAKE_COMPLETE = "UXSP-COMPLETE"
    DATA = "UXSP-DATA"
    ERROR = "UXSP-ERROR"
    CLOSE = "UXSP-CLOSE"
    PING = "UXSP-PING"
    PONG = "UXSP-PONG"


# ─────────────────────────────────────────────
# ERRORS
# ─────────────────────────────────────────────


class UXSPWebSocketError(Exception):
    """Base class for WebSocket transport errors."""

    pass


class UnexpectedFrameError(UXSPWebSocketError):
    """Received a frame type not expected at this protocol state."""

    pass


class SessionNotEstablishedError(UXSPWebSocketError):
    """Tried to send/receive DATA before handshake completed."""

    pass


class FrameTooLargeError(UXSPWebSocketError):
    """
    Frame exceeds MAX_FRAME_BYTES.
    Reject immediately — do not parse.
    Possible memory exhaustion attack.
    """

    pass


# ─────────────────────────────────────────────
# FRAME
# ─────────────────────────────────────────────


class UXSPFrame:
    """
    Represents a single typed WebSocket frame.

    What this class does:
        Wraps a FrameType, a payload dict, and a Unix timestamp.  Provides:
            build(frame_type, payload) — Class method to construct a frame.
            to_json()                  — Serialise to a JSON string for sending.
            from_json(text)            — Deserialise + validate from received text/bytes.

        from_json() enforces the MAX_FRAME_BYTES limit before parsing to guard
        against memory exhaustion attacks from oversized frames.
    """
    __slots__ = ("type", "payload", "timestamp")

    def __init__(
        self, frame_type: FrameType, payload: dict[str, Any] | None = None, ts: int | None = None
    ) -> None:
        self.type = frame_type
        self.payload: dict[str, Any] = payload or {}
        self.timestamp = ts if ts is not None else int(time.time())

    @classmethod
    def build(cls, frame_type: FrameType, payload: dict[str, Any] | None = None) -> UXSPFrame:
        return cls(frame_type, payload)

    def to_json(self) -> str:
        return json.dumps(
            {"uxsp_frame": self.type, "timestamp": self.timestamp, "payload": self.payload}
        )

    @classmethod
    def from_json(cls, text: str | bytes, max_bytes: int = MAX_FRAME_BYTES) -> UXSPFrame:

        if isinstance(text, str):
            raw = text.encode("utf-8")
        elif isinstance(text, (bytes, bytearray)):
            raw = bytes(text)
        else:
            raise UXSPWebSocketError(f"frame must be str or bytes, got {type(text).__name__}")

        if len(raw) > max_bytes:
            raise FrameTooLargeError(
                f"Frame size {len(raw)} bytes exceeds "
                f"maximum {max_bytes} bytes. "
                f"Possible memory exhaustion attack."
            )

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise UXSPWebSocketError(f"Invalid JSON: {e}") from e

        if not isinstance(data, dict):
            raise UXSPWebSocketError("JSON payload must be an object/dictionary.")

        if "uxsp_frame" not in data:
            raise UXSPWebSocketError("Missing 'uxsp_frame' field. Is this a UXSP message?")
        try:
            frame_type = FrameType(data["uxsp_frame"])
        except ValueError as e:
            raise UXSPWebSocketError(f"Unknown frame type: '{data['uxsp_frame']}'") from e

        payload = data.get("payload", {})
        if not isinstance(payload, dict):
            raise UXSPWebSocketError("Frame payload must be an object/dictionary.")
        try:
            ts = int(data.get("timestamp", int(time.time())))
        except (TypeError, ValueError) as e:
            raise UXSPWebSocketError("Frame timestamp must be a Unix integer.") from e

        return cls(
            frame_type=frame_type,
            payload=payload,
            ts=ts,
        )

    def __repr__(self) -> str:
        return f"UXSPFrame(type={self.type}, ts={self.timestamp})"


# ─────────────────────────────────────────────
# WEBSOCKET SESSION MANAGER
# ─────────────────────────────────────────────


class UXSPWebSocket:
    """
    Manages a UXSP session over a WebSocket connection.
    """

    def __init__(
        self,
        identity: Any,
        config: SessionConfig | None = None,
        nonce_store: NonceStore | None = None,
    ) -> None:
        from uxsp.core.nonce import MemoryNonceStore

        self._identity = identity
        self._config = config
        self._nonce_store: NonceStore = (
            nonce_store if nonce_store is not None else MemoryNonceStore()
        )
        self._session: Session | None = None
        self._hs: Handshake | None = None
        self._role: str | None = None
        self._remote_card: PublicCard | None = None
        self._limiter: RateLimiterBase | None = None

    @classmethod
    def as_initiator(
        cls,
        identity: Any,
        remote_card: PublicCard,
        config: Any = None,
        nonce_store: NonceStore | None = None,
    ) -> UXSPWebSocket:
        """Create WebSocket manager for the initiating side."""
        ws = cls(identity, config, nonce_store)
        ws._role = "initiator"
        ws._remote_card = remote_card
        return ws

    @classmethod
    def as_responder(
        cls,
        identity: Any,
        limiter: RateLimiterBase | None = None,
        config: Any = None,
        nonce_store: NonceStore | None = None,
    ) -> UXSPWebSocket:

        if limiter is None:
            warnings.warn(
                "UXSPWebSocket.as_responder() called without a rate limiter. "
                "Production deployments should always pass a RateLimiterBase instance.",
                UserWarning,
                stacklevel=2,
            )
        ws = cls(identity, config, nonce_store)
        ws._role = "responder"
        ws._limiter = limiter
        return ws

    # ─────────────────────────────────────────
    # INITIATOR METHODS
    # ─────────────────────────────────────────

    def start_handshake(self) -> UXSPFrame:
        """
        Begin the handshake as the initiating party.

        Generates a fresh Handshake object (including ephemeral keys and
        a signature over all fields), and returns a HANDSHAKE_HELLO frame
        ready to send to the responder.  Must be called before complete_handshake().
        """

        if self._remote_card is None:
            raise UXSPWebSocketError(
                "No remote card. Use UXSPWebSocket.as_initiator() "
                "with a valid responder PublicCard."
            )
        from uxsp.core.handshake import Handshake

        self._hs = Handshake.initiate(self._identity, self._remote_card, self._config)
        return UXSPFrame.build(FrameType.HANDSHAKE_HELLO, self._hs.hello_message)

    def complete_handshake(self, ack_frame: UXSPFrame) -> UXSPFrame:
        """
        Complete the handshake as the initiating party after receiving the ACK.

        Verifies the responder’s ACK signature and HMAC proof, derives the
        final session key, and returns a HANDSHAKE_COMPLETE frame containing
        the session_id for the responder to confirm.

        Raises SessionNotEstablishedError if called before start_handshake().
        Raises UnexpectedFrameError if ack_frame is not a HANDSHAKE_ACK.
        """
        if self._hs is None or self._remote_card is None:
            raise SessionNotEstablishedError(
                "complete_handshake() called before start_handshake()."
            )
        if ack_frame.type != FrameType.HANDSHAKE_ACK:
            raise UnexpectedFrameError(f"Expected HANDSHAKE_ACK, got {ack_frame.type}")
        self._session = self._hs.complete(
            ack_frame.payload, self._remote_card, nonce_store=self._nonce_store
        )
        return UXSPFrame.build(
            FrameType.HANDSHAKE_COMPLETE, {"session_id": self._session.session_id}
        )

    # ─────────────────────────────────────────
    # RESPONDER METHODS
    # ─────────────────────────────────────────

    def handle_hello(self, hello_frame: UXSPFrame, initiator_card: PublicCard) -> UXSPFrame:
        """
        Process a HANDSHAKE_HELLO frame as the responder.

        Checks the rate limiter (if configured) for the initiator, verifies
        the HELLO signature, derives the partial shared secret, and returns a
        HANDSHAKE_ACK frame containing the responder’s exchange contribution
        and HMAC proof.

        Raises UnexpectedFrameError if hello_frame is not a HANDSHAKE_HELLO.
        Raises UXSPWebSocketError if handle_hello() is called twice (replay).
        Raises RateLimitExceededError (from the limiter) if the initiator is rate-limited.
        """

        if self._hs is not None:
            raise UXSPWebSocketError("handle_hello() called twice. Possible handshake replay.")
        if hello_frame.type != FrameType.HANDSHAKE_HELLO:
            raise UnexpectedFrameError(f"Expected HANDSHAKE_HELLO, got {hello_frame.type}")

        if self._limiter is not None:
            self._limiter.check(initiator_card.entity_id)

        from uxsp.core.handshake import Handshake

        self._hs = Handshake.respond(
            responder=self._identity,
            hello=hello_frame.payload,
            initiator_card=initiator_card,
            nonce_store=self._nonce_store,
            config=self._config,
        )
        self._remote_card = initiator_card
        return UXSPFrame.build(FrameType.HANDSHAKE_ACK, self._hs.ack_message)

    def handle_complete(self, complete_frame: UXSPFrame) -> None:
        """
        Finalise the handshake as the responder after receiving HANDSHAKE_COMPLETE.

        Verifies that the session_id in the COMPLETE frame matches the session
        established during handle_hello(), then activates the session.

        Raises SessionNotEstablishedError if called before handle_hello().
        Raises UnexpectedFrameError if complete_frame is not HANDSHAKE_COMPLETE.
        Raises UXSPWebSocketError if the session_id does not match.
        """

        if self._hs is None:
            raise SessionNotEstablishedError("handle_complete() called before handle_hello().")
        if complete_frame.type != FrameType.HANDSHAKE_COMPLETE:
            raise UnexpectedFrameError(f"Expected HANDSHAKE_COMPLETE, got {complete_frame.type}")

        if self._session is not None:
            raise UXSPWebSocketError(
                "Handshake already completed. Possible replay of COMPLETE frame."
            )

        expected_sid = self._hs.session.session_id
        received_sid = complete_frame.payload.get("session_id")
        if received_sid != expected_sid:
            raise UXSPWebSocketError(
                f"COMPLETE frame session_id '{received_sid}' "
                f"does not match handshake session '{expected_sid}'."
            )
        self._session = self._hs.session

    # ─────────────────────────────────────────
    # DATA FRAMES
    # ─────────────────────────────────────────

    def encode(self, plaintext: bytes) -> UXSPFrame:
        """Encrypt plaintext into a DATA frame via session key."""
        if self._session is None:
            raise SessionNotEstablishedError("Cannot send data before handshake is complete.")
        return UXSPFrame.build(FrameType.DATA, self._session.encrypt(plaintext))

    def decode(self, frame: UXSPFrame) -> bytes:
        """
        Decrypt and return the plaintext from a DATA frame.

        Validates the session state, verifies the frame type is DATA, then
        delegates to session.decrypt().

        Raises SessionNotEstablishedError if the session is not established.
        Raises UnexpectedFrameError if frame is not a DATA frame.
        """
        if self._session is None:
            raise SessionNotEstablishedError("Cannot receive data before handshake is complete.")
        if frame.type != FrameType.DATA:
            raise UnexpectedFrameError(f"Expected DATA frame, got {frame.type}")
        return self._session.decrypt(frame.payload)

    # ─────────────────────────────────────────
    # KEEPALIVE AND CLOSE
    # ─────────────────────────────────────────

    def ping(self) -> UXSPFrame:
        """
        Build a PING keepalive frame with the current Unix timestamp.

        Send this periodically on long-lived connections to detect broken TCP
        connections before the OS TCP keepalive timeout fires.  The remote
        peer should respond with a PONG frame via pong().
        """
        payload = {"ts": int(time.time())}
        if self._session is not None:  # pragma: no cover
            return UXSPFrame.build(FrameType.PING, self._session.encrypt(json.dumps(payload).encode("utf-8")))
        return UXSPFrame.build(FrameType.PING, payload)

    def pong(self, ping_frame: UXSPFrame) -> UXSPFrame:
        """
        Build a PONG response frame that echoes the timestamp from a PING frame.

        Call this when a PING frame is received from the remote peer.
        """
        if self._session is not None and "ciphertext" in ping_frame.payload:
            try:  # pragma: no cover
                raw = self._session.decrypt(ping_frame.payload)
                data = json.loads(raw.decode("utf-8"))
            except Exception:  # pragma: no cover
                data = ping_frame.payload
        else:
            data = ping_frame.payload

        payload = {"echo_ts": data.get("ts")}
        if self._session is not None:  # pragma: no cover
            return UXSPFrame.build(FrameType.PONG, self._session.encrypt(json.dumps(payload).encode("utf-8")))
        return UXSPFrame.build(FrameType.PONG, payload)

    def close(self, reason: str = "normal") -> UXSPFrame:
        """Build an authenticated CLOSE frame and revoke the local session."""
        if self._session is not None:
            close_payload = self._session.encrypt(json.dumps({"reason": reason}).encode("utf-8"))
            self._session.revoke()
            self._session = None
            return UXSPFrame.build(FrameType.CLOSE, close_payload)
        return UXSPFrame.build(FrameType.CLOSE, {"reason": reason})

    def handle_close(self, frame: UXSPFrame) -> str:
        """
        Process a CLOSE frame from the remote peer and tear down the local session.

        If the session is active, attempts to decrypt the close payload to
        extract the reason string.  Falls back to 'unauthenticated-close' if
        decryption fails.  Always revokes the local session regardless of whether
        the close payload was authenticated.

        Returns the reason string (e.g. 'normal', 'timeout', 'unauthenticated-close').
        """

        if frame.type != FrameType.CLOSE:
            raise UnexpectedFrameError(f"Expected CLOSE frame, got {frame.type}")
        if self._session is not None:
            try:
                raw = self._session.decrypt(frame.payload)
                data = json.loads(raw.decode("utf-8"))
            except Exception:
                self._session.revoke()
                self._session = None
                return "unauthenticated-close"

            if not isinstance(data, dict):
                self._session.revoke()
                self._session = None
                return "unauthenticated-close"
            reason = str(data.get("reason", "unknown"))
            self._session.revoke()
            self._session = None
            return reason
        return str(frame.payload.get("reason", "unknown"))

    # ─────────────────────────────────────────
    # PROPERTIES
    # ─────────────────────────────────────────

    @property
    def session(self) -> Session:
        if self._session is None:
            raise SessionNotEstablishedError(
                "Session not yet established. Complete handshake first."
            )
        return self._session

    @property
    def is_ready(self) -> bool:
        if self._session is None:
            return False
        return self._session.is_active
