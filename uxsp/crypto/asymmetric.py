"""
uxsp.crypto.asymmetric — Classical Asymmetric Cryptography

What this file does:
    Provides X25519 key exchange and Ed25519 digital signature operations
    using the 'cryptography' library.  These are the “classical” (non-PQC)
    building blocks that are combined with the post-quantum algorithms in
    hybrid.py to achieve forward secrecy against both classical and quantum
    adversaries.

    X25519 (key exchange):
        generate_exchange_keypair() — Create a new X25519 keypair.
        compute_shared_secret()     — Perform Diffie-Hellman to get a shared secret.

    Ed25519 (signatures):
        generate_signing_keypair() — Create a new Ed25519 keypair.
        sign()     — Sign raw bytes; returns signature bytes.
        verify()   — Verify a signature; returns bool.
        sign_str() — Convenience: sign a str, return hex-encoded signature.
        verify_str() — Convenience: verify a hex-encoded signature against a str.

All key material is handled as raw bytes (no PEM, no DER) to keep the API
uniform with the PQC layer.
"""
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# ═════════════════════════════════════════════════════════════
# X25519 KEY EXCHANGE
# ═════════════════════════════════════════════════════════════


def generate_exchange_keypair() -> dict[str, bytes]:
    """
    Generate a new X25519 keypair for Diffie-Hellman key exchange.

    Returns a dict with keys 'private_key' and 'public_key', both as raw bytes.
    The private key must never be transmitted.  The public key is shared with
    the other party to derive a shared secret via compute_shared_secret().
    """

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return {
        "private_key": private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        "public_key": public_key.public_bytes(Encoding.Raw, PublicFormat.Raw),
    }


def compute_shared_secret(my_private_key_bytes: bytes, their_public_key_bytes: bytes) -> bytes:
    """
    Perform X25519 Diffie-Hellman key agreement.

    Takes the local private key and the remote party’s public key (both as raw
    bytes) and returns a 32-byte shared secret.  The shared secret must be
    passed through HKDF (see kdf.derive_key) before use as an encryption key.

    Raises TypeError if either argument is not bytes.
    """

    if not isinstance(my_private_key_bytes, bytes):
        raise TypeError("my_private_key_bytes must be bytes.")
    if not isinstance(their_public_key_bytes, bytes):
        raise TypeError("their_public_key_bytes must be bytes.")

    my_private = X25519PrivateKey.from_private_bytes(my_private_key_bytes)
    their_public = X25519PublicKey.from_public_bytes(their_public_key_bytes)

    shared_secret = my_private.exchange(their_public)

    return shared_secret


# ═════════════════════════════════════════════════════════════
# Ed25519 DIGITAL SIGNATURES
# ═════════════════════════════════════════════════════════════


def generate_signing_keypair() -> dict[str, bytes]:
    """
    Generate a new Ed25519 keypair for digital signatures.

    Returns a dict with keys 'private_key' and 'public_key', both as raw bytes.
    Use sign() with the private key to produce signatures, and verify() with
    the public key to check them.
    """

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return {
        "private_key": private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        "public_key": public_key.public_bytes(Encoding.Raw, PublicFormat.Raw),
    }


def sign(message: bytes, private_key_bytes: bytes) -> bytes:
    """
    Sign a message with an Ed25519 private key.

    Returns the 64-byte signature as raw bytes.  Raises TypeError if
    either argument is not bytes.
    """

    if not isinstance(message, bytes):
        raise TypeError("message must be bytes. Use message.encode() for strings.")
    if not isinstance(private_key_bytes, bytes):
        raise TypeError("private_key_bytes must be bytes.")

    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(message)


def verify(message: bytes, signature: bytes, public_key_bytes: bytes) -> bool:
    """
    Verify an Ed25519 signature against a message and public key.

    Returns True if the signature is valid, False if invalid (including
    if the key or signature bytes are malformed).  Raises TypeError if
    any argument is not bytes.
    """
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes.")
    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes.")
    if not isinstance(public_key_bytes, bytes):
        raise TypeError("public_key_bytes must be bytes.")

    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        return False


def sign_str(text: str, private_key_bytes: bytes) -> str:
    """Sign a string. Returns hex-encoded signature."""
    if not isinstance(text, str):
        raise TypeError("text must be a str.")
    if not isinstance(private_key_bytes, bytes):
        raise TypeError("private_key_bytes must be bytes.")

    return sign(text.encode("utf-8"), private_key_bytes).hex()


def verify_str(text: str, signature_hex: str, public_key_bytes: bytes) -> bool:
    """
    Verify an Ed25519 signature where the message is a plain string.

    Decodes signature_hex from hex and encodes text as UTF-8, then delegates
    to verify().  Returns False (rather than raising) if signature_hex is not
    valid hex.  Raises TypeError if any argument has the wrong type.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a str.")
    if not isinstance(signature_hex, str):
        raise TypeError("signature_hex must be a str.")
    if not isinstance(public_key_bytes, bytes):
        raise TypeError("public_key_bytes must be bytes.")

    try:
        return verify(text.encode("utf-8"), bytes.fromhex(signature_hex), public_key_bytes)
    except (ValueError, AttributeError):
        return False
