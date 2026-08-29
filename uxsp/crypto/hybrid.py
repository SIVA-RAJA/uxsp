"""
uxsp.crypto.hybrid — Hybrid Classical + PQC Cryptography

What this file does:
    Provides the high-level hybrid cryptographic primitives that combine
    X25519 (classical ECDH) with ML-KEM (post-quantum key encapsulation) and
    Ed25519 with ML-DSA (post-quantum digital signatures).

    The hybrid approach means an adversary would need to break BOTH the
    classical and the PQC algorithm to decrypt a sealed message or forge a
    signature.  This provides security against both classical and quantum
    adversaries.

    Key operations:
        seal()       — Encrypt + sign a plaintext for a specific recipient.
        open_seal()  — Verify + decrypt a sealed envelope.
        generate_hybrid_keypair() — Create the four-algorithm keypair.
        extract_public_keys()     — Pull only public keys from a keypair.
        hybrid_sign()             — Sign with Ed25519 + ML-DSA.
        hybrid_verify()           — Verify both classical and PQC signatures.
        bind_fields()             — Length-prefix concatenation for canonical signable bytes.

    The seal/open_seal protocol:
        1. Sender performs hybrid_sender_exchange() to derive a shared key
           and produce ephemeral_pub + kem_ciphertext (the key material).
        2. Sender encrypts with AES-256-GCM (symmetric.encrypt).
        3. Sender signs all fields with hybrid_sign() using Ed25519 + ML-DSA.
        4. Receiver verifies signatures (hybrid_verify) and decrypts
           (hybrid_recipient_exchange + symmetric.decrypt).

    EnvelopeValidationError is the canonical exception for any validation
    failure (wrong version, bad hex, tampered fields, expired timestamp).
"""
from __future__ import annotations

import os
import struct
import time
from typing import Any

from .asymmetric import (
    compute_shared_secret,
    generate_exchange_keypair,
    generate_signing_keypair,
    sign,
    verify,
)
from .kdf import derive_key
from .pqc import (
    decapsulate,
    encapsulate,
    generate_kem_keypair,
    generate_sig_keypair,
    pqc_sign,
    pqc_verify,
)
from .symmetric import decrypt, encrypt

# ═════════════════════════════════════════════════════════════
# ERRORS
# ═════════════════════════════════════════════════════════════


class EnvelopeValidationError(ValueError):
    """
    Raised when an envelope or signature payload contains invalid data
    (e.g. malformed hex, missing fields, unknown version).

    Callers should catch this instead of bare ValueError so that a
    single malformed packet cannot crash an unguarded worker process.
    """

    pass


def _require_open_context(
    envelope: dict[str, Any],
    expected_recipient_id: str | None,
    max_age_seconds: int,
    clock_skew_seconds: int,
    allow_classical_only: bool = False,
) -> dict[str, Any]:
    """
    Validate all required fields, timestamps, and recipient of an envelope dict.

    Returns a dict with decoded (bytes) versions of the hex fields.  Raises
    EnvelopeValidationError for any missing field, type mismatch, timestamp
    out of range, or wrong recipient.
    """
    if envelope.get("version") != "UXSP-1":
        raise EnvelopeValidationError(f"Unknown envelope version: {envelope.get('version')}")

    is_classical_only = envelope.get("pqc_mode") == "none"

    if is_classical_only and not allow_classical_only:
        raise EnvelopeValidationError("Classical-only envelope rejected (allow_classical_only=False).")

    # enforce required fields — no silent defaults
    required_fields = [
        "ciphertext",
        "nonce",
        "sender_id",
        "recipient_id",
        "timestamp",
        "envelope_nonce",
        "ephemeral_pub",
        "classical_sig",
    ]
    if not is_classical_only:
        required_fields.extend(["kem_ciphertext", "pqc_sig"])

    for field in required_fields:
        if field not in envelope:
            raise EnvelopeValidationError(
                f"Envelope missing required field: '{field}'. "
                f"Possible downgrade attack or corrupted envelope."
            )

    try:
        ts = int(envelope["timestamp"])
    except (TypeError, ValueError) as exc:
        raise EnvelopeValidationError(
            f"Envelope timestamp must be a Unix integer, got {envelope['timestamp']!r}."
        ) from exc

    age = time.time() - ts
    if age > max_age_seconds:
        raise EnvelopeValidationError(f"Envelope is {age:.0f}s old. Possible replay attack.")
    if age < -clock_skew_seconds:
        raise EnvelopeValidationError(
            f"Envelope timestamp is {-age:.0f}s in the future. Clock skew too large."
        )

    if expected_recipient_id is not None and envelope.get("recipient_id") != expected_recipient_id:
        raise EnvelopeValidationError(
            f"Envelope recipient_id '{envelope.get('recipient_id')}' "
            f"does not match expected '{expected_recipient_id}'. "
            "Possible misrouted or replayed envelope."
        )

    for field in ("sender_id", "recipient_id", "envelope_nonce"):
        if not isinstance(envelope[field], str) or not envelope[field]:
            raise EnvelopeValidationError(f"Envelope field '{field}' must be a non-empty string.")

    try:
        ct = bytes.fromhex(envelope["ciphertext"])
        nonce = bytes.fromhex(envelope["nonce"])
        ephemeral_pub = bytes.fromhex(envelope["ephemeral_pub"])
        kem_ciphertext = bytes.fromhex(envelope["kem_ciphertext"]) if not is_classical_only else b""
    except (ValueError, TypeError) as exc:
        raise EnvelopeValidationError(
            f"Envelope contains invalid hex data: {exc}. Possible malformed or tampered envelope."
        ) from exc

    return {
        "timestamp": ts,
        "sender_id": envelope["sender_id"],
        "recipient_id": envelope["recipient_id"],
        "envelope_nonce": envelope["envelope_nonce"],
        "classical_sig": envelope["classical_sig"],
        "pqc_sig": envelope.get("pqc_sig", ""),
        "ciphertext": ct,
        "nonce": nonce,
        "ephemeral_pub": ephemeral_pub,
        "kem_ciphertext": kem_ciphertext,
        "is_classical_only": is_classical_only,
    }


def verify_envelope(
    envelope: dict[str, Any],
    sender_public_keys: dict[str, bytes],
    expected_recipient_id: str | None = None,
    expected_sender_id: str | None = None,
    max_age_seconds: int = 300,
    clock_skew_seconds: int = 30,
    allow_classical_only: bool = False,
) -> dict[str, Any]:
    """
    Verify all signatures and metadata on an envelope without decrypting it.

    Validates required fields, timestamp freshness, recipient and sender IDs,
    and both the Ed25519 and ML-DSA signatures.  Returns the validated context
    dict (with binary fields decoded) which can be passed to
    decrypt_verified_envelope().

    Raises EnvelopeValidationError for any failure.
    """

    ctx = _require_open_context(
        envelope,
        expected_recipient_id,
        max_age_seconds,
        clock_skew_seconds,
        allow_classical_only=allow_classical_only,
    )
    if expected_sender_id is not None and ctx["sender_id"] != expected_sender_id:
        raise EnvelopeValidationError(
            f"Envelope sender_id '{ctx['sender_id']}' "
            f"does not match expected '{expected_sender_id}'. "
            "Possible sender identity confusion attack."
        )

    signable = bind_fields(
        b"UXSP-1",
        ctx["ciphertext"],
        ctx["nonce"],
        ctx["sender_id"].encode(),
        ctx["recipient_id"].encode(),
        str(ctx["timestamp"]).encode(),
        ctx["envelope_nonce"].encode(),
        ctx["ephemeral_pub"],
        ctx["kem_ciphertext"],
    )

    sigs = {
        "classical_sig": ctx["classical_sig"],
    }
    if not ctx["is_classical_only"]:
        sigs["pqc_sig"] = ctx["pqc_sig"]

    if not hybrid_verify(signable, sigs, sender_public_keys, allow_classical_only=ctx["is_classical_only"]):
        raise EnvelopeValidationError(
            "Signature verification failed. Envelope tampered or sender identity invalid."
        )

    return ctx


def decrypt_verified_envelope(
    verified_context: dict[str, Any],
    recipient_keypair: dict[str, dict[str, Any]],
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt an envelope context returned by verify_envelope()."""
    shared_key = hybrid_recipient_exchange(
        verified_context["ephemeral_pub"],
        verified_context["kem_ciphertext"],
        recipient_keypair,
        is_classical_only=verified_context.get("is_classical_only", False)
    )

    return decrypt(
        verified_context["ciphertext"],
        verified_context["nonce"],
        shared_key,
        associated_data=associated_data,
    )


# ═════════════════════════════════════════════════════════════
# HYBRID KEY PAIR
# ═════════════════════════════════════════════════════════════


def generate_hybrid_keypair() -> dict[str, Any]:
    """
    Generate a complete four-algorithm hybrid keypair.

    Returns a dict with four sub-dicts: 'exchange' (X25519), 'kem' (ML-KEM),
    'signing' (Ed25519), 'pqc_sig' (ML-DSA).  Each sub-dict contains
    'private_key' and 'public_key' as raw bytes plus an 'algorithm' string
    for the PQC entries.
    """
    return {
        "exchange": generate_exchange_keypair(),
        "kem": generate_kem_keypair(),
        "signing": generate_signing_keypair(),
        "pqc_sig": generate_sig_keypair(),
    }


def extract_public_keys(keypair: dict[str, dict[str, Any]]) -> dict[str, bytes]:
    """
    Extract only the four public keys from a full hybrid keypair.

    Returns a flat dict with keys: 'exchange_pub', 'kem_pub', 'signing_pub',
    'pqc_sig_pub'.  Raises ValueError if any key is missing from the keypair.
    """
    try:
        return {
            "exchange_pub": keypair["exchange"]["public_key"],
            "kem_pub": keypair["kem"]["public_key"],
            "signing_pub": keypair["signing"]["public_key"],
            "pqc_sig_pub": keypair["pqc_sig"]["public_key"],
        }
    except KeyError as exc:
        raise ValueError(f"Malformed keypair, missing key: {exc}") from exc


# ═════════════════════════════════════════════════════════════
# INTERNAL
# ═════════════════════════════════════════════════════════════


def bind_fields(*fields: bytes) -> bytes:
    """Length-prefixed concatenation. Prevents length confusion attacks."""
    result = b""
    for f in fields:
        if not isinstance(f, bytes):
            raise TypeError(f"bind_fields: all fields must be bytes, got {type(f).__name__!r}")
        result += struct.pack(">I", len(f)) + f
    return result


# ═════════════════════════════════════════════════════════════
# HYBRID KEY EXCHANGE
# ═════════════════════════════════════════════════════════════


def hybrid_sender_exchange(recipient_public_keys: dict[str, bytes]) -> dict[str, Any]:
    """
    Perform the sender’s half of the hybrid key exchange.

    Generates an ephemeral X25519 keypair, computes the ECDH shared secret
    against the recipient’s exchange_pub, encapsulates against the recipient’s
    kem_pub (ML-KEM), concatenates both secrets, and runs HKDF to produce a
    final 32-byte shared key.

    Returns a dict with 'shared_key' (bytes), 'ephemeral_pub' (bytes), and
    'kem_ciphertext' (bytes).  The last two must be sent to the recipient.
    """
    ephemeral = generate_exchange_keypair()
    classical_secret = compute_shared_secret(
        ephemeral["private_key"], recipient_public_keys["exchange_pub"]
    )
    kem_result = encapsulate(recipient_public_keys["kem_pub"])
    pqc_secret = kem_result["shared_secret"]
    final_key = derive_key(
        ikm=classical_secret + pqc_secret,
        salt=ephemeral["public_key"],  # Salt with ephemeral public key (Issue 4)
        info=b"UXSP-hybrid-key-exchange-v1",
        length=32,
    )
    return {
        "shared_key": final_key,
        "ephemeral_pub": ephemeral["public_key"],
        "kem_ciphertext": kem_result["ciphertext"],
    }


def hybrid_recipient_exchange(
    ephemeral_pub: bytes,
    kem_ciphertext: bytes,
    my_private_keys: dict[str, dict[str, Any]],
    is_classical_only: bool = False
) -> bytes:
    """
    Perform the recipient’s half of the hybrid key exchange.

    Uses the recipient’s X25519 private key to compute the ECDH shared secret
    against the sender’s ephemeral_pub, decapsulates the kem_ciphertext with
    the recipient’s ML-KEM private key, concatenates both secrets, and runs
    HKDF with the same info string to reproduce the sender’s shared_key.

    Returns the 32-byte shared key matching the one produced by hybrid_sender_exchange().
    """
    try:
        classical_secret = compute_shared_secret(
            my_private_keys["exchange"]["private_key"], ephemeral_pub
        )
        if is_classical_only:
            pqc_secret = b""
        else:
            pqc_secret = decapsulate(kem_ciphertext, my_private_keys["kem"]["private_key"])
    except KeyError as exc:
        raise ValueError(f"my_private_keys missing required key: {exc}") from exc

    return derive_key(
        ikm=classical_secret + pqc_secret,
        salt=ephemeral_pub,
        info=b"UXSP-hybrid-key-exchange-v1",
        length=32,
    )


# ═════════════════════════════════════════════════════════════
# HYBRID SIGNING
# ═════════════════════════════════════════════════════════════


def hybrid_sign(message: bytes, keypair: dict[str, dict[str, Any]]) -> dict[str, str]:
    """
    Sign a message with both Ed25519 and ML-DSA.

    Returns a dict with 'classical_sig' (hex) and 'pqc_sig' (hex).  Both
    signatures cover the exact same message bytes, providing a dual-layer
    authentication that is secure against classical and quantum forgers.

    Raises TypeError if message is not bytes.
    Raises ValueError if the keypair is missing required entries.
    """

    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    try:
        classical_hex = sign(message, keypair["signing"]["private_key"]).hex()
        pqc_hex = pqc_sign(message, keypair["pqc_sig"]["private_key"]).hex()
    except (AttributeError, KeyError) as exc:
        raise ValueError(f"Signing failed — missing key or invalid result: {exc}") from exc
    return {
        "classical_sig": classical_hex,
        "pqc_sig": pqc_hex,
    }


def hybrid_verify(
    message: bytes,
    signatures: dict[str, str],
    sender_public_keys: dict[str, bytes],
    allow_classical_only: bool = False
) -> bool:
    """
    Verify both the Ed25519 and ML-DSA signatures on a message.

    Returns True only when BOTH signatures are valid.  Returns False (short-
    circuits) as soon as the classical signature fails.  Raises
    EnvelopeValidationError if the signature fields contain invalid hex or
    the sender_public_keys dict is missing required entries.
    """
    try:
        classical_sig_bytes = bytes.fromhex(signatures["classical_sig"])
        if not allow_classical_only:
            pqc_sig_bytes = bytes.fromhex(signatures["pqc_sig"])
    except (TypeError, ValueError, KeyError) as exc:
        raise EnvelopeValidationError(f"Signature fields contain invalid hex data: {exc}") from exc

    try:
        signing_pub = sender_public_keys["signing_pub"]
        pqc_sig_pub = sender_public_keys["pqc_sig_pub"]
    except KeyError as exc:
        raise EnvelopeValidationError(f"sender_public_keys missing required key: {exc}") from exc

    classical_ok = verify(message, classical_sig_bytes, signing_pub)
    if not classical_ok:
        return False

    if allow_classical_only:
        import logging
        logging.getLogger("uxsp.crypto").warning("PQC is not active for this envelope (classical-only mode).")
        return True

    return pqc_verify(message, pqc_sig_bytes, pqc_sig_pub)


# ═════════════════════════════════════════════════════════════
# SEAL / OPEN
# ═════════════════════════════════════════════════════════════


def seal(
    plaintext: bytes,
    sender_keypair: dict[str, dict[str, Any]],
    recipient_public_keys: dict[str, bytes],
    sender_id: str,
    recipient_id: str,
    associated_data: bytes = b"",
) -> dict[str, Any]:
    """
    Encrypt and sign plaintext for a specific recipient (sender side).

    Steps:
        1. hybrid_sender_exchange() — derive shared key, produce ephemeral_pub + kem_ciphertext.
        2. symmetric.encrypt()      — AES-256-GCM encrypt plaintext.
        3. bind_fields()            — construct canonical signable bytes.
        4. hybrid_sign()            — sign with Ed25519 + ML-DSA.

    Returns a JSON-serialisable dict representing the sealed envelope.  All
    binary fields are hex-encoded strings.

    Raises ValueError if sender_id or recipient_id is empty.
    Raises TypeError if plaintext is not bytes.
    """

    if not sender_id:
        raise ValueError("sender_id cannot be empty")
    if not recipient_id:
        raise ValueError("recipient_id cannot be empty")
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    exchange = hybrid_sender_exchange(recipient_public_keys)
    shared_key = exchange["shared_key"]

    encrypted = encrypt(plaintext, shared_key, associated_data=associated_data)
    ct = encrypted["ciphertext"]
    nonce = encrypted["nonce"]

    if not isinstance(ct, bytes) or not isinstance(nonce, bytes):
        raise TypeError("encrypt() must return bytes for 'ciphertext' and 'nonce'")

    envelope_nonce = os.urandom(16).hex()
    ts = int(time.time())

    signable = bind_fields(
        b"UXSP-1",
        ct,
        nonce,
        sender_id.encode(),
        recipient_id.encode(),
        str(ts).encode(),
        envelope_nonce.encode(),
        exchange["ephemeral_pub"],
        exchange["kem_ciphertext"],
    )

    sigs = hybrid_sign(signable, sender_keypair)

    return {
        "version": "UXSP-1",
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "timestamp": ts,
        "envelope_nonce": envelope_nonce,
        "ciphertext": ct.hex(),
        "nonce": nonce.hex(),
        "ephemeral_pub": exchange["ephemeral_pub"].hex(),
        "kem_ciphertext": exchange["kem_ciphertext"].hex(),
        "classical_sig": sigs["classical_sig"],
        "pqc_sig": sigs["pqc_sig"],
    }


def open_seal(
    envelope: dict[str, Any],
    recipient_keypair: dict[str, dict[str, Any]],
    sender_public_keys: dict[str, bytes],
    expected_recipient_id: str | None = None,
    expected_sender_id: str | None = None,
    max_age_seconds: int = 300,
    clock_skew_seconds: int = 30,
    allow_classical_only: bool = False,
    associated_data: bytes = b"",
) -> bytes:
    """
    Verify and decrypt a sealed envelope (recipient side).

    Steps:
        1. verify_envelope()          — validate all signatures and metadata.
        2. hybrid_recipient_exchange() — recover the shared key.
        3. symmetric.decrypt()         — AES-256-GCM decrypt.

    Returns the original plaintext bytes on success.
    Raises EnvelopeValidationError for any signature or metadata failure.
    Raises ValueError for decryption failures (tampered ciphertext).
    """

    ctx = verify_envelope(
        envelope,
        sender_public_keys,
        expected_recipient_id=expected_recipient_id,
        expected_sender_id=expected_sender_id,
        max_age_seconds=max_age_seconds,
        clock_skew_seconds=clock_skew_seconds,
        allow_classical_only=allow_classical_only,
    )
    return decrypt_verified_envelope(
        ctx,
        recipient_keypair,
        associated_data=associated_data,
    )
