"""
uxsp.core.handshake — Mutual-Authentication Handshake

What this file does:
    Implements the three-step UXSP handshake protocol that establishes a
    mutually authenticated, forward-secret shared session key between two
    parties (initiator and responder) without either side ever transmitting
    a raw private key.

    Protocol steps:
        1. initiate()  (initiator) — builds a HELLO message containing:
             - A fresh X25519 ephemeral public key and a KEM ciphertext
               computed against the responder’s public keys.
             - A hybrid (Ed25519 + ML-DSA) signature over all fields.
        2. respond()   (responder) — verifies the HELLO signature, performs
             KEM decapsulation to recover the initiator’s half of the shared
             secret, generates its own ECDH + KEM contribution, and sends an
             ACK that includes an HMAC proof-of-possession over the partial
             shared secret (prevents MITM).
        3. complete()  (initiator) — verifies the ACK signature and proof,
             performs its own KEM decapsulation, and derives the final 32-byte
             session key using HKDF over both halves.

    The final key is derived with HKDF binding the session_id, initiator_id,
    and responder_id so the key material is unique even if the same ephemeral
    keys are accidentally reused.

    Replay protection:
        Both HELLO and ACK messages are marked in the provided NonceStore to
        prevent replayed handshakes from re-activating sessions.

Key class:
    Handshake — Stateful object that drives the protocol from either side.

Key errors:
    HandshakeError       — Base for all handshake failures.
    HandshakeAuthError   — Signature or identity check failed.
    HandshakeProofError  — HMAC proof mismatch (possible MITM).
    HandshakeExpiredError — Message timestamp too old or too far in the future.
"""
from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from typing import Any, TypedDict, cast

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.nonce import NonceStore
from uxsp.core.session import Session, SessionConfig
from uxsp.crypto.hybrid import (
    EnvelopeValidationError,
    bind_fields,
    hybrid_recipient_exchange,
    hybrid_sender_exchange,
    hybrid_sign,
    hybrid_verify,
)
from uxsp.crypto.kdf import derive_key

SUPPORTED_VERSIONS = ["1"]


class ExchangeResult(TypedDict):
    ephemeral_pub: bytes
    kem_ciphertext: bytes
    shared_key: bytes


# ─────────────────────────────────────────────
# HANDSHAKE ERRORS
# ─────────────────────────────────────────────


class HandshakeError(Exception):
    """Base class for handshake failures."""

    pass


class HandshakeAuthError(HandshakeError):
    """Signature verification failed during handshake."""

    pass


class HandshakeProofError(HandshakeError):
    """Shared secret proof did not match — possible MITM."""

    pass


class HandshakeExpiredError(HandshakeError):
    """Handshake message is too old — replay or delay attack."""

    pass


# ─────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────


def _make_hello(
    initiator: Identity, responder_card: PublicCard, session_id: str
) -> tuple[dict[str, Any], ExchangeResult]:
    """
    Build the HELLO message for the initiator side of the handshake.

    Performs a hybrid key exchange against the responder’s public keys
    (X25519 ECDH + ML-KEM), signs all fields with the initiator’s hybrid
    keypair, and returns both the JSON-serialisable HELLO dict and the
    exchange result (which contains the initiator’s half of the shared key).
    """
    ts = int(time.time())
    exchange = hybrid_sender_exchange(responder_card.public_keys)

    signable = bind_fields(
        b"UXSP-HELLO",
        ",".join(SUPPORTED_VERSIONS).encode(),
        session_id.encode(),
        initiator.entity_id.encode(),
        responder_card.entity_id.encode(),
        exchange["ephemeral_pub"],
        exchange["kem_ciphertext"],
        str(ts).encode(),
    )

    sigs = hybrid_sign(signable, initiator.keypair)

    hello: dict[str, Any] = {
        "type": "UXSP-HELLO",
        "supported_versions": SUPPORTED_VERSIONS,
        "session_id": session_id,
        "initiator_id": initiator.entity_id,
        "responder_id": responder_card.entity_id,
        "timestamp": ts,
        "ephemeral_pub": exchange["ephemeral_pub"].hex(),
        "kem_ciphertext": exchange["kem_ciphertext"].hex(),
        "classical_sig": sigs["classical_sig"],
        "pqc_sig": sigs["pqc_sig"],
    }
    return hello, cast(ExchangeResult, exchange)


def _verify_hello_signature(
    hello: dict[str, Any], initiator_card: PublicCard, responder: Identity, max_age: int = 30
) -> tuple[bytes, str]:
    """Step 1: Check signature and metadata. Returns the signable bytes and negotiated version."""

    _HELLO_REQUIRED = (
        "type",
        "supported_versions",
        "session_id",
        "initiator_id",
        "responder_id",
        "timestamp",
        "ephemeral_pub",
        "kem_ciphertext",
        "classical_sig",
        "pqc_sig",
    )
    missing = [f for f in _HELLO_REQUIRED if f not in hello]
    if missing:
        raise HandshakeAuthError(
            f"HelloMessage missing required fields: {missing}. "
            "Possible malformed or truncated payload."
        )

    if hello.get("type") != "UXSP-HELLO":
        raise HandshakeAuthError(
            f"Expected UXSP-HELLO message, got '{hello.get('type')}'. "
            f"Possible protocol confusion attack."
        )

    try:
        age = int(time.time()) - int(hello["timestamp"])
    except (ValueError, TypeError):
        raise HandshakeAuthError(
            f"Invalid timestamp format in HelloMessage: '{hello.get('timestamp')}'. "
            "Must be a Unix integer."
        ) from None

    if age < -max_age or age > max_age:
        raise HandshakeExpiredError(f"HelloMessage is {age}s old. Maximum: {max_age}s.")

    if hello.get("initiator_id") != initiator_card.entity_id:
        raise HandshakeAuthError(
            f"HelloMessage initiator_id '{hello.get('initiator_id', '')[:8]}...' "
            f"does not match provided card '{initiator_card.entity_id[:8]}...'. "
            f"Possible identity confusion attack."
        )

    if hello.get("responder_id") != responder.entity_id:
        raise HandshakeAuthError(
            f"HelloMessage intended for '{hello.get('responder_id', '')[:8]}...', "
            f"not for this responder '{responder.entity_id[:8]}...'. "
            f"Possible misdirected or replayed handshake."
        )
    client_versions = hello.get("supported_versions")
    if not isinstance(client_versions, list) or not client_versions:
        raise HandshakeAuthError("HelloMessage missing or invalid 'supported_versions'.")
    
    common = set(SUPPORTED_VERSIONS).intersection(client_versions)
    if not common:
        raise HandshakeAuthError(f"No common protocol version supported. Peer supports: {client_versions}")
    try:
        negotiated_version = max(common, key=int)
    except ValueError:
        negotiated_version = max(common)

    try:
        signable = bind_fields(
            b"UXSP-HELLO",
            ",".join(hello["supported_versions"]).encode(),
            str(hello["session_id"]).encode(),
            str(hello["initiator_id"]).encode(),
            str(hello["responder_id"]).encode(),
            bytes.fromhex(hello["ephemeral_pub"]),
            bytes.fromhex(hello["kem_ciphertext"]),
            str(hello["timestamp"]).encode(),
        )
    except (ValueError, TypeError, AttributeError) as exc:
        raise HandshakeAuthError(
            f"HelloMessage contains malformed or invalid field types: {exc}"
        ) from exc

    sigs = {
        "classical_sig": hello["classical_sig"],
        "pqc_sig": hello["pqc_sig"],
    }
    try:
        signature_ok = hybrid_verify(signable, sigs, initiator_card.public_keys)
    except EnvelopeValidationError as exc:
        raise HandshakeAuthError(f"HelloMessage signature fields are invalid: {exc}") from exc

    if not signature_ok:
        raise HandshakeAuthError(
            "HelloMessage signature invalid. Initiator identity could not be verified."
        )

    return signable, negotiated_version


def _derive_hello_secret(hello: dict[str, Any], responder: Identity) -> bytes:
    """Step 2: Expensive KEM decapsulation."""
    return hybrid_recipient_exchange(
        bytes.fromhex(hello["ephemeral_pub"]),
        bytes.fromhex(hello["kem_ciphertext"]),
        responder.keypair,
    )


def _make_ack(
    responder: Identity,
    session_id: str,
    initiator_id: str,
    shared_secret_A: bytes,
    initiator_card: PublicCard,
    negotiated_version: str,
) -> tuple[dict[str, Any], ExchangeResult]:
    """
    Build the ACK message for the responder side of the handshake.

    Generates the responder’s own ECDH + ML-KEM exchange contribution
    directed at the initiator, computes an HMAC-SHA256 proof-of-possession
    over the initiator’s half of the shared secret to prove the responder
    decapsulated correctly (guarding against MITM), signs all fields, and
    returns the JSON-serialisable ACK dict and the responder’s exchange result.
    """
    ts = int(time.time())

    resp_exchange = hybrid_sender_exchange(initiator_card.public_keys)

    proof = hmac.new(
        shared_secret_A, (session_id + ":responder-proof").encode(), digestmod=hashlib.sha256
    ).hexdigest()

    signable = bind_fields(
        b"UXSP-ACK",
        negotiated_version.encode(),
        session_id.encode(),
        responder.entity_id.encode(),
        initiator_id.encode(),
        proof.encode(),
        resp_exchange["ephemeral_pub"],
        resp_exchange["kem_ciphertext"],
        str(ts).encode(),
    )

    sigs = hybrid_sign(signable, responder.keypair)

    ack = {
        "type": "UXSP-ACK",
        "version": negotiated_version,
        "session_id": session_id,
        "responder_id": responder.entity_id,
        "initiator_id": initiator_id,
        "timestamp": ts,
        "proof": proof,
        "ephemeral_pub": resp_exchange["ephemeral_pub"].hex(),
        "kem_ciphertext": resp_exchange["kem_ciphertext"].hex(),
        "classical_sig": sigs["classical_sig"],
        "pqc_sig": sigs["pqc_sig"],
    }
    return ack, cast(ExchangeResult, resp_exchange)


def _verify_ack_signature(
    ack: dict[str, Any], responder_card: PublicCard, max_age: int = 30
) -> bytes:
    """
    Verify the ACK message’s signature and basic metadata.

    Checks for required fields, validates the timestamp freshness window,
    and verifies the hybrid (Ed25519 + ML-DSA) signature using the
    responder’s public keys.  Returns the canonical signable bytes so the
    caller can use them for additional checks without re-encoding.
    """

    # Guard against KeyError on malformed payloads before any field access.
    _ACK_REQUIRED = (
        "type",
        "version",
        "session_id",
        "responder_id",
        "initiator_id",
        "timestamp",
        "proof",
        "ephemeral_pub",
        "kem_ciphertext",
        "classical_sig",
        "pqc_sig",
    )
    missing = [f for f in _ACK_REQUIRED if f not in ack]
    if missing:
        raise HandshakeAuthError(
            f"AckMessage missing required fields: {missing}. "
            "Possible malformed or truncated payload."
        )

    if ack.get("type") != "UXSP-ACK":
        raise HandshakeAuthError(f"Expected UXSP-ACK message, got '{ack.get('type')}'.")

    try:
        age = int(time.time()) - int(ack["timestamp"])
    except (ValueError, TypeError):
        raise HandshakeAuthError(
            f"Invalid timestamp format in AckMessage: '{ack.get('timestamp')}'. "
            "Must be a Unix integer."
        ) from None

    if age < -max_age or age > max_age:
        raise HandshakeExpiredError(f"AckMessage age {age}s is out of bounds. Maximum: {max_age}s.")
    version = ack.get("version")
    if version not in SUPPORTED_VERSIONS:
        raise HandshakeAuthError(f"Unsupported ack version '{version}'.")

    try:
        signable = bind_fields(
            b"UXSP-ACK",
            str(ack["version"]).encode(),
            str(ack["session_id"]).encode(),
            str(ack["responder_id"]).encode(),
            str(ack["initiator_id"]).encode(),
            str(ack["proof"]).encode(),
            bytes.fromhex(ack["ephemeral_pub"]),
            bytes.fromhex(ack["kem_ciphertext"]),
            str(ack["timestamp"]).encode(),
        )
    except (ValueError, TypeError, AttributeError) as exc:
        raise HandshakeAuthError(
            f"AckMessage contains malformed or invalid field types: {exc}"
        ) from exc

    sigs = {
        "classical_sig": ack["classical_sig"],
        "pqc_sig": ack["pqc_sig"],
    }
    try:
        signature_ok = hybrid_verify(signable, sigs, responder_card.public_keys)
    except EnvelopeValidationError as exc:
        raise HandshakeAuthError(f"AckMessage signature fields are invalid: {exc}") from exc

    if not signature_ok:
        raise HandshakeAuthError(
            "AckMessage signature invalid. Responder identity could not be verified."
        )
    return signable


def _derive_ack_secret(ack: dict[str, Any], shared_secret_A: bytes, initiator: Identity) -> bytes:
    """Step 2: Check proof and perform expensive KEM decapsulation."""

    expected_proof = hmac.new(
        shared_secret_A, (ack["session_id"] + ":responder-proof").encode(), digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(ack["proof"], expected_proof):
        raise HandshakeProofError(
            "Shared secret proof mismatch. Possible man-in-the-middle attack."
        )

    return hybrid_recipient_exchange(
        bytes.fromhex(ack["ephemeral_pub"]), bytes.fromhex(ack["kem_ciphertext"]), initiator.keypair
    )


# ─────────────────────────────────────────────
# PUBLIC API — Handshake
# ─────────────────────────────────────────────


class Handshake:
    """
    Stateful handshake manager for establishing a UXSP session.

    A handshake consists of three steps:
    1. initiate(): Alice generates a HELLO message.
    2. respond(): Bob verifies HELLO and generates an ACK message.
    3. complete(): Alice verifies ACK and activates the session.
    """

    def __init__(self) -> None:
        # all attributes declared here so type checker knows they exist
        self._hello_msg: dict[str, Any] | None = None
        self._ack_msg: dict[str, Any] | None = None
        self._session: Session | None = None
        self._exchange: ExchangeResult | None = None
        self._session_id: str | None = None
        self._config: SessionConfig | None = None
        self._initiator: Identity | None = None
        self._resp_card: PublicCard | None = None

    @classmethod
    def initiate(
        cls, initiator: Identity, responder_card: PublicCard, config: SessionConfig | None = None
    ) -> Handshake:
        """
        Start a new handshake as the initiating party.

        Creates a fresh session_id UUID, builds the HELLO message (ephemeral
        key exchange + signature), and returns a Handshake object whose
        hello_message property is ready to send to the responder.
        """
        hs = cls()
        hs._session_id = str(uuid.uuid4())
        hs._config = config or SessionConfig()
        hs._initiator = initiator
        hs._resp_card = responder_card
        hello, exchange = _make_hello(initiator, responder_card, hs._session_id)
        hs._hello_msg = hello
        hs._exchange = exchange
        return hs

    @classmethod
    def respond(
        cls,
        responder: Identity,
        hello: dict[str, Any],
        initiator_card: PublicCard,
        nonce_store: NonceStore,
        config: SessionConfig | None = None,
    ) -> Handshake:
        """
        Process a HANDSHAKE_HELLO message and produce an ACK as the responder.

        Verifies the HELLO message's timestamp freshness, checks its nonce in
        the nonce_store to prevent handshake replay, verifies the initiator's
        hybrid (Ed25519 + ML-DSA) signature, performs KEM decapsulation to
        recover the initiator's shared secret, generates the responder's own
        exchange contribution, computes an HMAC proof-of-possession, and
        returns a Handshake whose ack_message is ready to send.

        The 'nonce_store' is MANDATORY to prevent handshake replay attacks.
        In production, use a persistent store (Redis / Postgres).

        Raises HandshakeAuthError   if any signature or identity check fails.
        Raises HandshakeExpiredError if the HELLO timestamp is stale or replayed.
        Raises HandshakeError       for any other protocol violation.
        """

        hs = cls()
        hs._config = config or SessionConfig()
        hs._session_id = str(hello.get("session_id", ""))

        try:
            uuid.UUID(hs._session_id)
        except (ValueError, TypeError, AttributeError):
            raise HandshakeAuthError(f"Invalid or malformed session_id: {hs._session_id}") from None

        _signable, negotiated_version = _verify_hello_signature(hello, initiator_card, responder)

        if not nonce_store.mark_used(f"hello:{hello['session_id']}", ttl_seconds=90):
            raise HandshakeExpiredError("Replay attack detected: hello message already processed.")

        shared_secret_A = _derive_hello_secret(hello, responder)

        ack_msg, resp_exchange = _make_ack(
            responder, hello["session_id"], hello["initiator_id"], shared_secret_A, initiator_card, negotiated_version
        )
        hs._ack_msg = ack_msg

        shared_secret_B = resp_exchange["shared_key"]
        final_shared_secret = derive_key(
            ikm=shared_secret_A + shared_secret_B,
            info=(
                b"UXSP-final-session-key:"
                + hello["session_id"].encode()
                + b":"
                + hello["initiator_id"].encode()
                + b":"
                + responder.entity_id.encode()
            ),
            length=32,
        )

        session = Session(
            session_id=hello["session_id"],
            local_id=responder.entity_id,
            remote_id=hello["initiator_id"],
            shared_secret=final_shared_secret,
            is_initiator=False,
            config=hs._config,
        )

        session._activate()
        hs._session = session
        return hs

    def complete(
        self, ack: dict[str, Any], responder_card: PublicCard, nonce_store: NonceStore
    ) -> Session:
        """
        Finalise the handshake as the initiating party.

        Verifies the responder’s ACK signature and HMAC proof, performs the
        initiator’s own KEM decapsulation, derives the final session key with
        HKDF binding both half-secrets, and activates a new Session object.

        Raises HandshakeError if called before initiate().
        Raises HandshakeAuthError / HandshakeProofError on verification failure.
        Raises HandshakeExpiredError if the ACK nonce was already processed.

        Returns the active Session ready for encrypt/decrypt.
        """

        if (
            self._hello_msg is None
            or self._initiator is None
            or self._session_id is None
            or self._exchange is None
        ):
            raise HandshakeError("complete() called before initiate().")

        _signable = _verify_ack_signature(ack, responder_card)

        if ack.get("session_id") != self._session_id:
            raise HandshakeAuthError("AckMessage session_id does not match the pending handshake.")
        if ack.get("initiator_id") != self._initiator.entity_id:
            raise HandshakeAuthError("AckMessage initiator_id does not match this initiator.")
        if ack.get("responder_id") != responder_card.entity_id:
            raise HandshakeAuthError("AckMessage responder_id does not match the responder card.")

        if not nonce_store.mark_used(f"ack:{ack['session_id']}", ttl_seconds=90):
            raise HandshakeExpiredError("Replay attack detected: ack message already processed.")

        if self._resp_card is not None and self._resp_card.entity_id != responder_card.entity_id:
            raise HandshakeAuthError("responder_card does not match the card used in initiate().")

        shared_secret_A = self._exchange["shared_key"]
        shared_secret_B = _derive_ack_secret(ack, shared_secret_A, self._initiator)

        final_shared_secret = derive_key(
            ikm=shared_secret_A + shared_secret_B,
            info=(
                b"UXSP-final-session-key:"
                + self._session_id.encode()
                + b":"
                + self._initiator.entity_id.encode()
                + b":"
                + responder_card.entity_id.encode()
            ),
            length=32,
        )

        session = Session(
            session_id=self._session_id,
            local_id=self._initiator.entity_id,
            remote_id=responder_card.entity_id,
            shared_secret=final_shared_secret,
            is_initiator=True,
            config=self._config or SessionConfig(),
        )

        session._activate()
        self._session = session
        return session

    # ─────────────────────────────────────────
    # PROPERTIES
    # ─────────────────────────────────────────

    @property
    def hello_message(self) -> dict[str, Any]:
        """HelloMessage to send to responder (available after initiate())."""
        if self._hello_msg is None:
            raise HandshakeError("No hello message. Use Handshake.initiate() first.")
        return self._hello_msg

    @property
    def ack_message(self) -> dict[str, Any]:
        """AckMessage to send to initiator (available after respond())."""
        if self._ack_msg is None:
            raise HandshakeError("No ack message. Use Handshake.respond() first.")
        return self._ack_msg

    @property
    def session(self) -> Session:
        """Active session (available after respond() or complete())."""
        if self._session is None:
            raise HandshakeError("Session not yet established. Call respond() or complete() first.")
        return self._session
