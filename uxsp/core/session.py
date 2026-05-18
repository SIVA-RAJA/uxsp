"""
uxsp.core.session — Encrypted Session with Sequence Ordering

What this file does:
    Manages the encrypted communication channel that exists after a successful
    UXSP handshake.  A Session holds the derived send and receive AES-256-GCM
    keys and enforces strict message sequencing so that within-session replay
    and reordering attacks are impossible.

    Key behaviour:
        - Two separate 32-byte keys are derived from the shared secret: one for
          the initiator→responder direction and one for responder→initiator.
          Each direction uses a unique HKDF info string so the keys are
          cryptographically independent.
        - Every encrypt() call appends a monotonically increasing sequence
          number (seq) to the payload and uses session_id:seq as AEAD associated
          data, binding the ciphertext to its position in the stream.
        - decrypt() verifies that the seq arrives in the expected order
          (enforce_ordering=True, default) or within a sliding replay window
          (enforce_ordering=False).  Out-of-order or replayed messages raise
          SessionReorderError.
        - Sessions expire after max_lifetime_seconds (default 1 hour) or
          max_messages (default 10 000 total sent+received) — whichever comes
          first.  Expired sessions must be re-established via a new handshake.

Key classes:
    Session        — The live session object returned by Handshake.
    SessionConfig  — Dataclass controlling lifetime, message cap, key derivation.
    SessionState   — Enum: PENDING, ACTIVE, EXPIRED, REVOKED.

Key errors:
    SessionError         — Base.
    SessionExpiredError  — Lifetime or message cap exceeded.
    SessionRevokedError  — Explicitly terminated.
    SessionNotActiveError — Operation requires ACTIVE state.
    SessionReorderError  — Message arrived out of order or was replayed.
"""
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, ClassVar

from uxsp.crypto.kdf import derive_key
from uxsp.crypto.symmetric import decrypt, encrypt

# ─────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────


class SessionState(Enum):
    """
    Lifecycle states for a UXSP session.

    PENDING  — Session created but not yet activated (handshake not complete).
    ACTIVE   — Session is ready for encrypt/decrypt calls.
    EXPIRED  — Lifetime or message cap exceeded; must re-handshake.
    REVOKED  — Explicitly terminated via session.revoke(); cannot be reactivated.
    """
    PENDING = auto()
    ACTIVE = auto()
    EXPIRED = auto()
    REVOKED = auto()


# ─────────────────────────────────────────────
# SESSION ERRORS
# ─────────────────────────────────────────────


class SessionError(Exception):
    """Base class for session errors."""

    pass


class SessionExpiredError(SessionError):
    """Session exceeded lifetime or message count."""

    pass


class SessionRevokedError(SessionError):
    """Session was explicitly revoked."""

    pass


class SessionNotActiveError(SessionError):
    """Operation requires ACTIVE session."""

    pass


class SessionReorderError(SessionError):
    """
    Message arrived out of order or was replayed within the session.

    Within a session, messages must arrive in sequence order.
    seq=5 arriving before seq=3 is rejected.
    seq=3 arriving again after seq=3 was already received is rejected.

    This prevents:
        - Within-session replay attacks
        - Message reordering attacks
        - Injection of old session messages

    Catch this specifically to detect active session manipulation.
    """

    pass


# ─────────────────────────────────────────────
# SESSION CONFIG
# ─────────────────────────────────────────────


@dataclass
class SessionConfig:
    """
    Configuration dataclass for Session behaviour.

    Fields:
        max_lifetime_seconds — How many seconds the session stays valid (default 3 600 = 1 h).
        max_messages         — Combined send+receive cap before expiry (default 10 000).
        key_info             — HKDF info bytes used during session key derivation; changing
                               this value makes keys incompatible with other deployments.
        enforce_ordering     — If True (default), messages must arrive in strict seq order.
                               If False, a 128-message sliding window is used instead.
    """
    max_lifetime_seconds: int = 3600
    max_messages: int = 10_000
    key_info: bytes = b"UXSP-session-key-v1"
    enforce_ordering: bool = True

    def __post_init__(self) -> None:
        if self.max_lifetime_seconds <= 0:
            raise ValueError("max_lifetime_seconds must be positive")
        if self.max_messages <= 0:
            raise ValueError("max_messages must be positive")
        if not self.key_info:
            raise ValueError("key_info cannot be empty")


# ─────────────────────────────────────────────
# SESSION
# ─────────────────────────────────────────────


class Session:
    """
    An active, encrypted, sequenced UXSP communication channel.

    What this class does:
        Holds the AES-256-GCM send and receive keys derived from the handshake
        shared secret and provides encrypt() / decrypt() for application data.

        Both keys are derived from the same shared secret but use different
        HKDF info strings (init_to_resp vs resp_to_init) so the two directions
        are cryptographically decoupled.  This means a compromised receive key
        cannot be used to forge sent messages.

    Thread safety:
        All state mutations (sequence numbers, expiry evaluation) are protected
        by a threading.Lock().  Multiple threads may call encrypt() and decrypt()
        concurrently from the same Session object.

    Lifecycle:
        Created by Handshake.respond() or Handshake.complete() in PENDING state,
        immediately activated to ACTIVE.  Transitions to EXPIRED or REVOKED are
        one-way; the session cannot be reactivated after either transition.
    """
    _send_seq: int
    _recv_seq: int
    _WINDOW_SIZE: ClassVar[int] = 128
    _seen_seqs: set[int]
    _max_seen_seq: int
    _recv_count: int

    def __init__(
        self,
        session_id: str,
        local_id: str,
        remote_id: str,
        shared_secret: bytes,
        is_initiator: bool,
        config: SessionConfig | None = None,
    ) -> None:

        self.session_id = session_id
        self.local_id = local_id
        self.remote_id = remote_id
        self._config = config or SessionConfig()
        self._state = SessionState.PENDING
        self._created_at = time.time()
        self._lock = threading.Lock()
        self._send_seq = 0
        self._recv_seq = 0
        self._seen_seqs: set[int] = set()
        self._max_seen_seq = -1
        self._recv_count = 0

        self._send_key = derive_key(
            shared_secret,
            length=32,
            info=self._config.key_info
            + b":enc"
            + (b":init_to_resp" if is_initiator else b":resp_to_init"),
        )
        self._recv_key = derive_key(
            shared_secret,
            length=32,
            info=self._config.key_info
            + b":enc"
            + (b":resp_to_init" if is_initiator else b":init_to_resp"),
        )

    # ─────────────────────────────────────────
    # STATE MANAGEMENT
    # ─────────────────────────────────────────

    def _activate(self) -> None:
        with self._lock:
            if self._state != SessionState.PENDING:
                raise SessionError(f"Cannot activate session in state {self._state.name}")
            self._state = SessionState.ACTIVE

    def _evaluate_expiry_unlocked(self) -> None:
        """Must be called with self._lock already held."""
        if self._state != SessionState.ACTIVE:
            return
        elapsed = time.time() - self._created_at
        if elapsed > self._config.max_lifetime_seconds:
            self._state = SessionState.EXPIRED
            return
        recv = self._recv_seq if self._config.enforce_ordering else self._recv_count
        total = self._send_seq + recv
        if total >= self._config.max_messages:
            self._state = SessionState.EXPIRED

    def _evaluate_expiry(self) -> None:
        with self._lock:
            self._evaluate_expiry_unlocked()

    def _check_active(self) -> None:
        with self._lock:
            self._check_active_unlocked()

    def _check_active_unlocked(self) -> None:
        """Must be called with self._lock already held."""
        self._evaluate_expiry_unlocked()
        if self._state == SessionState.EXPIRED:
            raise SessionExpiredError(
                f"Session {self.session_id[:8]}... expired. Re-establish via Handshake."
            )
        if self._state == SessionState.REVOKED:
            raise SessionRevokedError(f"Session {self.session_id[:8]}... was revoked.")
        if self._state != SessionState.ACTIVE:
            raise SessionNotActiveError(f"Session is {self._state.name}, not ACTIVE.")

    def revoke(self) -> None:
        """Explicitly terminate this session immediately."""
        with self._lock:
            self._state = SessionState.REVOKED

    # ─────────────────────────────────────────
    # ENCRYPT
    # ─────────────────────────────────────────

    def encrypt(self, plaintext: bytes) -> dict[str, Any]:
        """
        Encrypt plaintext and return a dict payload safe to transmit over the session.

        Atomically increments the send sequence number, derives per-message AEAD
        associated data (session_id:seq), and encrypts with AES-256-GCM.

        Returned dict keys: session_id (str), seq (int), ciphertext (hex str), nonce (hex str).
        Raises TypeError if plaintext is not bytes.
        Raises SessionExpiredError / SessionRevokedError / SessionNotActiveError if the
        session is not in ACTIVE state.
        """

        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")

        with self._lock:
            self._check_active_unlocked()
            seq = self._send_seq
            self._send_seq += 1
        ad = f"{self.session_id}:{seq}".encode()

        result = encrypt(plaintext, self._send_key, associated_data=ad)
        self._evaluate_expiry()

        return {
            "session_id": self.session_id,
            "seq": seq,
            "ciphertext": result["ciphertext"].hex(),
            "nonce": result["nonce"].hex(),
        }

    # ─────────────────────────────────────────
    # DECRYPT — with sequence ordering enforced
    # ─────────────────────────────────────────

    def decrypt(self, payload: dict[str, Any]) -> bytes:
        """
        Decrypt a session payload dict produced by the remote peer’s encrypt().

        Validates session_id, seq, ciphertext, and nonce fields, enforces
        sequence ordering (or sliding-window), decrypts with AES-256-GCM, and
        returns plaintext bytes.

        Raises ValueError for malformed payload fields.
        Raises SessionReorderError for out-of-order or replayed sequence numbers.
        Raises SessionError if AES-GCM authentication fails (possible tampering).
        Raises SessionExpiredError / SessionRevokedError / SessionNotActiveError if
        the session is not active.
        """

        if payload.get("session_id") != self.session_id:
            raise ValueError(
                f"Payload session_id mismatch. "
                f"Expected {self.session_id[:8]}..., "
                f"got {str(payload.get('session_id', ''))[:8]}..."
            )

        for field in ("ciphertext", "nonce", "seq"):
            if field not in payload:
                raise ValueError(f"Session payload missing field: '{field}'")

        incoming_seq = payload["seq"]
        if not isinstance(incoming_seq, int) or isinstance(incoming_seq, bool) or incoming_seq < 0:
            raise ValueError("Session payload field 'seq' must be a non-negative integer.")
        if not isinstance(payload["ciphertext"], str) or not isinstance(payload["nonce"], str):
            raise ValueError("Session payload fields 'ciphertext' and 'nonce' must be hex strings.")

        try:
            ciphertext = bytes.fromhex(payload["ciphertext"])
            nonce = bytes.fromhex(payload["nonce"])
        except (TypeError, ValueError) as e:
            raise ValueError(f"Session payload contains invalid hex data: {e}") from e

        with self._lock:
            self._check_active_unlocked()
            if self._config.enforce_ordering:
                if incoming_seq < self._recv_seq:
                    raise SessionReorderError(
                        f"Message seq={incoming_seq} already received or replayed. "
                        f"Expected seq={self._recv_seq}. "
                        f"Within-session replay or reorder attack detected."
                    )
                if incoming_seq > self._recv_seq:
                    raise SessionReorderError(
                        f"Message seq={incoming_seq} arrived out of order. "
                        f"Expected seq={self._recv_seq}. "
                        f"Messages must arrive in sequence order."
                    )
                self._recv_seq += 1

            else:
                window_floor = max(0, self._max_seen_seq - self._WINDOW_SIZE + 1)
                if incoming_seq in self._seen_seqs:
                    raise SessionReorderError(
                        f"Message seq={incoming_seq} already received. "
                        f"Within-session replay attack detected."
                    )
                if self._max_seen_seq >= 0 and incoming_seq < window_floor:
                    raise SessionReorderError(
                        f"Message seq={incoming_seq} is outside the replay-protection "
                        f"window (floor={window_floor}, max={self._max_seen_seq}). "
                        f"Possible delayed replay attack."
                    )
                self._seen_seqs.add(incoming_seq)
                self._recv_count += 1
                if incoming_seq > self._max_seen_seq:
                    self._max_seen_seq = incoming_seq

                if len(self._seen_seqs) > self._WINDOW_SIZE * 2:
                    new_floor = self._max_seen_seq - self._WINDOW_SIZE + 1
                    self._seen_seqs = {n for n in self._seen_seqs if n >= new_floor}

            ad = f"{self.session_id}:{incoming_seq}".encode()
            try:
                plaintext = decrypt(ciphertext, nonce, self._recv_key, associated_data=ad)
            except Exception as e:
                # Rollback while still holding the lock
                if self._config.enforce_ordering:
                    if self._recv_seq == incoming_seq + 1:
                        self._recv_seq = incoming_seq
                else:
                    self._seen_seqs.discard(incoming_seq)
                    if self._recv_count > 0:
                        self._recv_count -= 1
                    if incoming_seq == self._max_seen_seq:
                        self._max_seen_seq = max(self._seen_seqs, default=-1)
                if isinstance(e, ValueError):
                    raise SessionError(
                        f"Session decryption failed: {e}. Payload may be tampered."
                    ) from e
                raise

        self._evaluate_expiry()
        return plaintext

    # ─────────────────────────────────────────
    # PROPERTIES
    # ─────────────────────────────────────────

    @property
    def state(self) -> SessionState:
        with self._lock:
            return self._state

    @property
    def is_active(self) -> bool:
        with self._lock:
            self._evaluate_expiry_unlocked()
            return self._state == SessionState.ACTIVE

    @property
    def message_count(self) -> int:
        """Total number of messages sent and received."""
        with self._lock:
            recv = self._recv_seq if self._config.enforce_ordering else self._recv_count
            return self._send_seq + recv

    @property
    def remaining_messages(self) -> int:
        """
        Return how many more messages (send + receive combined) can be processed
        before the session expires.  Returns 0 if the session is not ACTIVE.
        """
        with self._lock:
            self._evaluate_expiry_unlocked()
            if self._state != SessionState.ACTIVE:
                return 0
            recv = self._recv_seq if self._config.enforce_ordering else self._recv_count
            total = self._send_seq + recv
            return max(0, self._config.max_messages - total)

    @property
    def remaining_seconds(self) -> float:
        with self._lock:
            elapsed = time.time() - self._created_at
        return max(0.0, self._config.max_lifetime_seconds - elapsed)

    @property
    def age_seconds(self) -> float:
        with self._lock:
            return time.time() - self._created_at

    def __repr__(self) -> str:
        with self._lock:
            state_name = self._state.name
            send_seq = self._send_seq
        return (
            f"Session(id={self.session_id[:8]}..., "
            f"state={state_name}, "
            f"sent={send_seq}/{self._config.max_messages}, "
            f"age={self.age_seconds:.0f}s)"
        )
