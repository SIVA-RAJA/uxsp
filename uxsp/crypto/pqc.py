"""
uxsp.crypto.pqc — Post-Quantum Cryptography (ML-KEM and ML-DSA)

What this file does:
    Provides NIST PQC-standardised key encapsulation (ML-KEM, formerly Kyber)
    and digital signature (ML-DSA, formerly Dilithium) operations via the
    Open Quantum Safe library (liboqs).

    Algorithm detection:
        At module load, _detect_kem() and _detect_sig() probe the liboqs
        installation for the preferred algorithms (ML-KEM-768 / ML-DSA-65
        with Kyber768 / Dilithium3 as fallbacks).  If liboqs is not installed
        or has no compatible algorithm, all operations raise RuntimeError.

    ML-KEM (Key Encapsulation Mechanism):
        generate_kem_keypair() — Create a public/private KEM keypair.
        encapsulate(pk)        — Derive a shared secret + produce a ciphertext.
        decapsulate(ct, sk)    — Recover the shared secret from a ciphertext.

    ML-DSA (Digital Signature Algorithm):
        generate_sig_keypair() — Create a public/private signing keypair.
        pqc_sign(msg, sk)     — Sign a message; returns signature bytes.
        pqc_verify(msg, sig, pk) — Verify a signature; returns bool.

    Introspection:
        active_algorithms() — Return the algorithm names in use (useful for logging).

    TypedDicts:
        KemKeypair        — {public_key, private_key, algorithm}
        EncapsulateResult — {shared_secret, ciphertext, algorithm}
        SigKeypair        — {public_key, private_key, algorithm}

Requires:
    liboqs C library installed on the system, and 'liboqs-python' package
    installed (pip install liboqs-python).
"""
from __future__ import annotations

import warnings
from typing import TypedDict

try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning, module="oqs")
        import oqs
    _OQS_MECH_ERROR: type[Exception] = getattr(oqs, "MechanismNotEnabledError", RuntimeError)
except ImportError:
    raise ImportError(
        "UXSP requires the 'liboqs' C library and 'liboqs-python' wrapper. "
        "Please install liboqs on your system and run 'pip install liboqs-python'."
    ) from None


class KemKeypair(TypedDict):
    """
    TypedDict representing a ML-KEM (Kyber) key pair.

    Fields:
        public_key  — Bytes to share with the party who will encapsulate to you.
        private_key — Secret bytes required to decapsulate and recover the shared secret.
        algorithm   — Algorithm name string (e.g. 'ML-KEM-768').
    """
    public_key: bytes
    private_key: bytes
    algorithm: str


class EncapsulateResult(TypedDict):
    """
    TypedDict representing the result of a KEM encapsulation operation.

    Fields:
        shared_secret — The derived secret bytes; send this to no one (keep locally).
        ciphertext    — The encrypted form of the shared secret; send this to the other party.
        algorithm     — Algorithm name string used for encapsulation.
    """
    shared_secret: bytes
    ciphertext: bytes
    algorithm: str


class SigKeypair(TypedDict):
    """
    TypedDict representing a ML-DSA (Dilithium) signing key pair.

    Fields:
        public_key  — Bytes distributed to verifiers.
        private_key — Secret bytes used to sign messages.
        algorithm   — Algorithm name string (e.g. 'ML-DSA-65').
    """
    public_key: bytes
    private_key: bytes
    algorithm: str


# ─────────────────────────────────────────────
# ALGORITHM DETECTION — cached at module load
# runs once when Python imports this file
# ─────────────────────────────────────────────


def _detect_kem() -> str:
    """
    Probe liboqs for a supported ML-KEM algorithm.

    Prefers 'ML-KEM-768' (NIST-standardised); falls back to 'Kyber768' if
    available.  Raises RuntimeError if neither is enabled in the liboqs build.
    """
    available = oqs.get_enabled_kem_mechanisms()
    for candidate in ("ML-KEM-768", "Kyber768"):
        if candidate in available:
            return candidate
    raise RuntimeError(f"No supported KEM algorithm found. Available: {available}")


def _detect_sig() -> str:
    """
    Probe liboqs for a supported ML-DSA algorithm.

    Prefers 'ML-DSA-65' (NIST-standardised); falls back to 'Dilithium3' if
    available.  Raises RuntimeError if neither is enabled in the liboqs build.
    """
    available = oqs.get_enabled_sig_mechanisms()
    for candidate in ("ML-DSA-65", "Dilithium3"):
        if candidate in available:
            return candidate
    raise RuntimeError(f"No supported signature algorithm found. Available: {available}")


try:
    _KEM_ALGORITHM: str = _detect_kem()
    _SIG_ALGORITHM: str = _detect_sig()
except RuntimeError as _pqc_err:
    _KEM_ALGORITHM = ""
    _SIG_ALGORITHM = ""
    warnings.warn(
        f"UXSP PQC algorithms unavailable: {_pqc_err}. "
        "PQC operations will raise RuntimeError until liboqs is correctly installed.",
        ImportWarning,
        stacklevel=2,
    )


# ═════════════════════════════════════════════════════════════
# ML-KEM (KYBER) KEY ENCAPSULATION
# ═════════════════════════════════════════════════════════════


def generate_kem_keypair() -> KemKeypair:
    """
    Generate a new ML-KEM (Kyber) keypair.

    Returns a KemKeypair with 'public_key', 'private_key' (both bytes), and
    'algorithm'.  Raises RuntimeError if liboqs is not installed or no
    supported KEM algorithm is available.
    """
    if not _KEM_ALGORITHM:
        raise RuntimeError(
            "No KEM algorithm available. "
            "Check that liboqs is correctly installed: "
            "https://github.com/open-quantum-safe/liboqs"
        )
    with oqs.KeyEncapsulation(_KEM_ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

    return {
        "public_key": public_key,
        "private_key": private_key,
        "algorithm": _KEM_ALGORITHM,
    }


def encapsulate(recipient_public_key: bytes) -> EncapsulateResult:
    """
    Encapsulate a shared secret using the recipient’s ML-KEM public key.

    Returns an EncapsulateResult containing:
        shared_secret — Keep locally; this is the key material.
        ciphertext    — Send to the recipient; they use decapsulate() to recover
                        the same shared_secret.
    Raises TypeError if recipient_public_key is not bytes.
    """
    if not _KEM_ALGORITHM:
        raise RuntimeError("No KEM algorithm available. Check that liboqs is correctly installed.")

    if not isinstance(recipient_public_key, bytes):
        raise TypeError("recipient_public_key must be bytes")

    with oqs.KeyEncapsulation(_KEM_ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(recipient_public_key)

    return {
        "shared_secret": shared_secret,
        "ciphertext": ciphertext,
        "algorithm": _KEM_ALGORITHM,
    }


def decapsulate(ciphertext: bytes, private_key: bytes) -> bytes:
    """
    Recover the shared secret from a KEM ciphertext using the private key.

    Returns the shared secret bytes, which match what the sender’s
    encapsulate() produced.  Raises TypeError if either argument is not bytes.
    """
    if not _KEM_ALGORITHM:
        raise RuntimeError("No KEM algorithm available. Check that liboqs is correctly installed.")

    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    if not isinstance(private_key, bytes):
        raise TypeError("private_key must be bytes")

    with oqs.KeyEncapsulation(_KEM_ALGORITHM, secret_key=private_key) as kem:
        return bytes(kem.decap_secret(ciphertext))


# ═════════════════════════════════════════════════════════════
# ML-DSA (DILITHIUM) DIGITAL SIGNATURES
# ═════════════════════════════════════════════════════════════


def generate_sig_keypair() -> SigKeypair:
    """
    Generate a new ML-DSA (Dilithium) signing keypair.

    Returns a SigKeypair with 'public_key', 'private_key' (both bytes), and
    'algorithm'.  Raises RuntimeError if liboqs is not installed or no
    supported signature algorithm is available.
    """
    if not _SIG_ALGORITHM:
        raise RuntimeError(
            "No signature algorithm available. Check that liboqs is correctly installed."
        )
    with oqs.Signature(_SIG_ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

    return {
        "public_key": public_key,
        "private_key": private_key,
        "algorithm": _SIG_ALGORITHM,
    }


def pqc_sign(message: bytes, private_key: bytes) -> bytes:
    """
    Sign a message using the ML-DSA (Dilithium) private key.

    Returns the signature as bytes.  Raises TypeError if either argument
    is not bytes.
    """
    if not _SIG_ALGORITHM:
        raise RuntimeError(
            "No signature algorithm available. Check that liboqs is correctly installed."
        )
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(private_key, bytes):
        raise TypeError("private_key must be bytes")

    with oqs.Signature(_SIG_ALGORITHM, secret_key=private_key) as signer:
        return bytes(signer.sign(message))


def pqc_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify an ML-DSA (Dilithium) signature against a message and public key.

    Returns True if the signature is valid, False otherwise.  Returns False
    (rather than raising) for malformed inputs where possible.
    Raises TypeError if any argument is not bytes.
    """
    if not _SIG_ALGORITHM:
        raise RuntimeError(
            "No signature algorithm available. Check that liboqs is correctly installed."
        )

    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes")
    if not isinstance(public_key, bytes):
        raise TypeError("public_key must be bytes")

    try:
        with oqs.Signature(_SIG_ALGORITHM) as verifier:
            return bool(verifier.verify(message, signature, public_key))
    except (_OQS_MECH_ERROR, ValueError, TypeError, RuntimeError):
        return False


# ─────────────────────────────────────────────
# INTROSPECTION — useful for debugging
# ─────────────────────────────────────────────


def active_algorithms() -> dict[str, str]:
    """
    Return the ML-KEM and ML-DSA algorithm names currently in use.

    Returns a dict with keys 'kem' and 'sig'.  Values are algorithm name
    strings (e.g. 'ML-KEM-768') or 'unavailable' if liboqs is not properly
    configured.  Useful for logging and debugging.
    """

    return {
        "kem": _KEM_ALGORITHM or "unavailable",
        "sig": _SIG_ALGORITHM or "unavailable",
    }
