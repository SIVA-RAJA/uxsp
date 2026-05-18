"""
uxsp.crypto.kdf — Key Derivation Functions

What this file does:
    Provides two categories of key derivation:

    1. HKDF (HMAC-based Key Derivation Function via SHA-256):
           derive_key()         — Derive one symmetric key from secret material.
           derive_multiple_keys() — Derive encryption, integrity, and session-ID
                                    keys from a single shared secret (used by
                                    the handshake to split the shared secret
                                    into independent keys).

    2. Argon2id (password-based key derivation / authentication):
           derive_key_from_password() — Slow, memory-hard derivation of a raw
                                        AES key from a user password.  Used by
                                        Identity.save() / load() to protect the
                                        private key file.
           argon2id_hash()            — Hash a password for storage (returns
                                        Argon2 encoded string).
           argon2id_verify()          — Verify a password against a stored hash.
           argon2id_needs_rehash()    — Check if the stored hash needs upgrading
                                        to current parameters.

    Argon2id parameters are set to OWASP 2024 recommendations:
        time_cost = 3, memory_cost = 65536 (64 MB), parallelism = 4.
"""
from __future__ import annotations

import os

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ─────────────────────────────────────────────
# HKDF — derive key from secret material
# ─────────────────────────────────────────────


def derive_key(ikm: bytes, length: int = 32, salt: bytes | None = None, info: bytes = b"") -> bytes:
    """
    Derive a symmetric key from secret input material using HKDF-SHA256.

    Parameters:
        ikm    — Input key material (e.g. a Diffie-Hellman shared secret).
        length — Length of the derived key in bytes (default 32 = AES-256).
        salt   — Optional cryptographic salt (recommended for domain separation).
        info   — Context string that binds the key to its intended purpose;
                  changing info produces a completely different key from the same ikm.

    Returns the derived key as bytes.  Raises TypeError / ValueError for bad inputs.
    """

    if not isinstance(ikm, bytes):
        raise TypeError("ikm must be bytes")
    if not isinstance(length, int) or length <= 0:
        raise ValueError("length must be a positive integer")
    if salt is not None and not isinstance(salt, bytes):
        raise TypeError("salt must be bytes or None")
    if not isinstance(info, bytes):
        raise TypeError("info must be bytes")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,  # cryptography library accepts None here
        info=info,
    )
    return hkdf.derive(ikm)


def derive_multiple_keys(ikm: bytes, salt: bytes | None = None) -> dict[str, bytes]:
    """
    Derive three independent keys from a shared secret for use in a session.

    Uses different HKDF info strings so the three keys are cryptographically
    independent (knowing one does not help an adversary recover the others):
        'encryption'  — 32 bytes, for AES-256-GCM data encryption.
        'integrity'   — 32 bytes, for HMAC or AEAD tag verification.
        'session_id'  — 16 bytes, used as the session identifier.
    """

    return {
        "encryption": derive_key(ikm, 32, salt=salt, info=b"UXSP-encryption-v1"),
        "integrity": derive_key(ikm, 32, salt=salt, info=b"UXSP-integrity-v1"),
        "session_id": derive_key(ikm, 16, salt=salt, info=b"UXSP-session-id-v1"),
    }


# ─────────────────────────────────────────────
# ARGON2 — key WRAPPING (deriving raw bytes)
# ─────────────────────────────────────────────


def derive_key_from_password(
    password: str,
    salt: bytes | None = None,
    length: int = 32,
    time_cost: int = 3,
    memory_cost: int = 65536,
    parallelism: int = 4,
) -> dict[str, bytes]:
    """
    Derive a raw AES key from a user password using Argon2id.

    Parameters:
        password    — The user’s password (str).
        salt        — Optional salt bytes; a random 16-byte salt is generated
                      if None.  The salt must be stored alongside the ciphertext.
        length      — Length of the derived key in bytes (default 32).
        time_cost   — Number of Argon2 iterations (≥ 1).
        memory_cost — Memory usage in kibibytes (≥ 8; default 64 MB).
        parallelism — Number of parallel threads (≥ 1).

    Returns a dict with 'key' (bytes) and 'salt' (bytes).  Store the salt;
    you need it to re-derive the same key.
    Raises TypeError / ValueError for invalid parameter types or values.
    """

    if not isinstance(password, str):
        raise TypeError("password must be a str")
    if salt is not None and not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")
    if isinstance(length, bool) or not isinstance(length, int) or length <= 0:
        raise ValueError("length must be a positive integer")
    if isinstance(time_cost, bool) or not isinstance(time_cost, int) or time_cost < 1:
        raise ValueError("time_cost must be >= 1")
    if isinstance(memory_cost, bool) or not isinstance(memory_cost, int) or memory_cost < 8:
        raise ValueError("memory_cost must be >= 8")
    if isinstance(parallelism, bool) or not isinstance(parallelism, int) or parallelism < 1:
        raise ValueError("parallelism must be >= 1")

    if salt is None:
        salt = os.urandom(16)
    elif len(salt) < 8:
        raise ValueError("Salt must be at least 8 bytes long.")

    key = hash_secret_raw(
        password.encode("utf-8"),
        salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=length,
        type=Type.ID,
    )
    return {
        "key": key,
        "salt": salt,
    }


# ─────────────────────────────────────────────
# ARGON2ID — password hashing for authentication
# ─────────────────────────────────────────────

# Argon2id parameters — tuned for security vs performance balance
# time_cost     = number of iterations
# memory_cost   = memory in kibibytes (64 MB — resists GPU attacks)
# parallelism   = threads
# These values meet OWASP 2024 recommendations.
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def argon2id_hash(password: str) -> str:
    """
    Hash a password for authentication storage using Argon2id.

    Returns an encoded Argon2 hash string that contains the algorithm
    parameters, salt, and hash — all in one self-contained string.  Store
    this string in your database instead of the raw password.

    To verify a user’s password later, use argon2id_verify().
    Raises TypeError if password is not a str.
    """

    if not isinstance(password, str):
        raise TypeError("password must be a str")

    return _hasher.hash(password)


def argon2id_verify(stored_hash: str, password: str) -> bool:
    """
    Verify a plain-text password against a stored Argon2id hash.

    Returns True if the password matches, False otherwise.  Never raises
    an exception for wrong passwords; only raises TypeError if the arguments
    have the wrong types.
    """

    if not isinstance(stored_hash, str) or not isinstance(password, str):
        raise TypeError("stored_hash and password must be str")

    try:
        _hasher.verify(stored_hash, password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def argon2id_needs_rehash(stored_hash: str) -> bool:
    """
    Return True if the stored Argon2id hash was created with weaker parameters
    than the current configuration.

    Call this after a successful login; if it returns True, re-hash the
    password with argon2id_hash() and update the stored hash so that accounts
    are gradually upgraded when Argon2 parameter recommendations change.
    Raises TypeError if stored_hash is not a str.
    """

    if not isinstance(stored_hash, str):
        raise TypeError("stored_hash must be a str")

    return _hasher.check_needs_rehash(stored_hash)
