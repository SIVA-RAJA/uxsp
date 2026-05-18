"""
uxsp.crypto.symmetric — AES-256-GCM Symmetric Encryption

What this file does:
    Provides AES-256-GCM (Galois/Counter Mode) authenticated encryption.
    AES-GCM is used as the final encryption layer in every UXSP seal() call
    after the shared key has been derived via the hybrid key exchange.

    AES-GCM provides both confidentiality (no one can read the ciphertext
    without the key) and integrity/authenticity (any tampering is detected
    by the AEAD tag).

    Functions:
        generate_symmetric_key() — Create a random 256-bit (32-byte) AES key.
        encrypt(data, key)        — Encrypt bytes; returns {ciphertext, nonce}.
        decrypt(ct, nonce, key)   — Decrypt + verify; returns plaintext bytes.
        encrypt_str(text, key)    — Convenience wrapper: str → hex-encoded result.
        decrypt_str(ct_hex, nonce_hex, key) — Reverse of encrypt_str.

    Constants:
        KEY_SIZE  — 32 bytes (256 bits).
        NONCE_SIZE — 12 bytes (96 bits, as recommended for AES-GCM).
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE: int = 32
NONCE_SIZE: int = 12


def generate_symmetric_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return os.urandom(KEY_SIZE)


def encrypt(data: bytes, key: bytes, associated_data: bytes | None = None) -> dict[str, bytes]:
    """
    Encrypt data with AES-256-GCM using a fresh random nonce.

    Parameters:
        data            — Plaintext bytes to encrypt.
        key             — 32-byte AES-256 key.
        associated_data — Optional bytes authenticated but not encrypted (AEAD).

    Returns a dict with:
        'ciphertext' — Encrypted bytes (includes 16-byte GCM authentication tag).
        'nonce'      — Random 12-byte nonce; must be stored alongside ciphertext.

    Raises TypeError for wrong argument types.  Raises ValueError if key is not 32 bytes.
    """

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes.")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes. Use data.encode() for strings.")
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise TypeError("associated_data must be bytes or None.")

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data)

    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
    }


def decrypt(
    ciphertext: bytes, nonce: bytes, key: bytes, associated_data: bytes | None = None
) -> bytes:
    """
    Decrypt and verify AES-256-GCM ciphertext.

    Parameters:
        ciphertext      — Encrypted bytes (output of encrypt()).
        nonce           — 12-byte nonce (output of encrypt()).
        key             — 32-byte AES-256 key.
        associated_data — Must match what was passed to encrypt(); default None.

    Returns the original plaintext bytes.  Raises ValueError with a clear message
    if the authentication tag does not match (indicating tampering or wrong key).
    Raises TypeError for wrong argument types.
    """

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes.")
    if not isinstance(nonce, bytes):
        raise TypeError("nonce must be bytes.")
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes.")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise TypeError("associated_data must be bytes or None.")

    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as e:
        raise ValueError(
            "Decryption failed: authentication tag invalid. "
            "Data may be tampered or key/nonce mismatch."
        ) from e


def encrypt_str(text: str, key: bytes, associated_data: bytes | None = None) -> dict[str, str]:
    """
    Encrypt a plain-text string and return hex-encoded ciphertext and nonce.

    Convenience wrapper around encrypt() for callers working with strings.
    Returns a dict with 'ciphertext' (hex str) and 'nonce' (hex str).
    Use decrypt_str() to reverse.  Raises TypeError for wrong argument types.
    """

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes.")
    if not isinstance(text, str):
        raise TypeError("text must be str.")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise TypeError("associated_data must be bytes or None.")

    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")

    result = encrypt(text.encode("utf-8"), key, associated_data)
    return {
        "ciphertext": result["ciphertext"].hex(),
        "nonce": result["nonce"].hex(),
    }


def decrypt_str(
    ciphertext_hex: str, nonce_hex: str, key: bytes, associated_data: bytes | None = None
) -> str:
    """
    Decrypt hex-encoded AES-256-GCM ciphertext back to a plain string.

    Convenience wrapper around decrypt() for callers working with strings.
    Raises TypeError for wrong argument types, ValueError if the nonce_hex
    length is wrong or the authentication tag is invalid.
    """

    if not isinstance(key, bytes):
        raise TypeError("key must be bytes.")
    if not isinstance(nonce_hex, str):
        raise TypeError("nonce_hex must be str.")
    if not isinstance(ciphertext_hex, str):
        raise TypeError("ciphertext_hex must be str.")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise TypeError("associated_data must be bytes or None.")

    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(nonce_hex) != NONCE_SIZE * 2:
        raise ValueError(f"Nonce must be {NONCE_SIZE * 2} hex chars, got {len(nonce_hex)}")

    plaintext = decrypt(
        bytes.fromhex(ciphertext_hex), bytes.fromhex(nonce_hex), key, associated_data
    )
    return plaintext.decode("utf-8")
