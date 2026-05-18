"""
Full-coverage pytest suite for asymmetric.py

Concepts tested
───────────────
X25519  – key generation, shape, shared-secret exchange (symmetry + mismatch)
Ed25519 – key generation, sign/verify round-trip, tampered message/sig/key,
          helper wrappers sign_str / verify_str, every TypeError/ValueError
          guard, and every except branch inside verify / verify_str.
"""

import pytest

from uxsp.crypto.asymmetric import (
    compute_shared_secret,
    generate_exchange_keypair,
    generate_signing_keypair,
    sign,
    sign_str,
    verify,
    verify_str,
)

# ═══════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════

def fresh_exchange():
    return generate_exchange_keypair()

def fresh_signing():
    return generate_signing_keypair()


# ═══════════════════════════════════════════════════════════════
# generate_exchange_keypair
# ═══════════════════════════════════════════════════════════════

class TestGenerateExchangeKeypair:

    def test_returns_dict_with_expected_keys(self):
        kp = fresh_exchange()
        assert set(kp.keys()) == {"private_key", "public_key"}

    def test_both_values_are_bytes(self):
        kp = fresh_exchange()
        assert isinstance(kp["private_key"], bytes)
        assert isinstance(kp["public_key"], bytes)

    def test_raw_key_lengths_are_32_bytes(self):
        # X25519 raw keys are always 32 bytes
        kp = fresh_exchange()
        assert len(kp["private_key"]) == 32
        assert len(kp["public_key"]) == 32

    def test_two_calls_produce_different_keys(self):
        kp1 = fresh_exchange()
        kp2 = fresh_exchange()
        assert kp1["private_key"] != kp2["private_key"]
        assert kp1["public_key"] != kp2["public_key"]


# ═══════════════════════════════════════════════════════════════
# compute_shared_secret
# ═══════════════════════════════════════════════════════════════

class TestComputeSharedSecret:

    def test_shared_secret_is_bytes(self):
        a = fresh_exchange()
        b = fresh_exchange()
        secret = compute_shared_secret(a["private_key"], b["public_key"])
        assert isinstance(secret, bytes)

    def test_shared_secret_is_32_bytes(self):
        a = fresh_exchange()
        b = fresh_exchange()
        secret = compute_shared_secret(a["private_key"], b["public_key"])
        assert len(secret) == 32

    def test_exchange_is_symmetric(self):
        """DH property: A·b == B·a"""
        a = fresh_exchange()
        b = fresh_exchange()
        s_ab = compute_shared_secret(a["private_key"], b["public_key"])
        s_ba = compute_shared_secret(b["private_key"], a["public_key"])
        assert s_ab == s_ba

    def test_different_peer_gives_different_secret(self):
        a = fresh_exchange()
        b = fresh_exchange()
        c = fresh_exchange()
        s_ab = compute_shared_secret(a["private_key"], b["public_key"])
        s_ac = compute_shared_secret(a["private_key"], c["public_key"])
        assert s_ab != s_ac

    def test_raises_type_error_for_non_bytes_private_key(self):
        b = fresh_exchange()
        with pytest.raises(TypeError, match="my_private_key_bytes must be bytes"):
            compute_shared_secret("not bytes", b["public_key"])

    def test_raises_type_error_for_non_bytes_public_key(self):
        a = fresh_exchange()
        with pytest.raises(TypeError, match="their_public_key_bytes must be bytes"):
            compute_shared_secret(a["private_key"], 12345)


# ═══════════════════════════════════════════════════════════════
# generate_signing_keypair
# ═══════════════════════════════════════════════════════════════

class TestGenerateSigningKeypair:

    def test_returns_dict_with_expected_keys(self):
        kp = fresh_signing()
        assert set(kp.keys()) == {"private_key", "public_key"}

    def test_both_values_are_bytes(self):
        kp = fresh_signing()
        assert isinstance(kp["private_key"], bytes)
        assert isinstance(kp["public_key"], bytes)

    def test_raw_key_lengths_are_32_bytes(self):
        # Ed25519 raw private key = 32 bytes, public key = 32 bytes
        kp = fresh_signing()
        assert len(kp["private_key"]) == 32
        assert len(kp["public_key"]) == 32

    def test_two_calls_produce_different_keys(self):
        kp1 = fresh_signing()
        kp2 = fresh_signing()
        assert kp1["private_key"] != kp2["private_key"]


# ═══════════════════════════════════════════════════════════════
# sign
# ═══════════════════════════════════════════════════════════════

class TestSign:

    def test_signature_is_bytes(self):
        kp = fresh_signing()
        sig = sign(b"hello", kp["private_key"])
        assert isinstance(sig, bytes)

    def test_signature_is_64_bytes(self):
        # Ed25519 signatures are always 64 bytes
        kp = fresh_signing()
        sig = sign(b"hello", kp["private_key"])
        assert len(sig) == 64

    def test_same_message_same_key_same_signature(self):
        # Ed25519 is deterministic
        kp = fresh_signing()
        assert sign(b"msg", kp["private_key"]) == sign(b"msg", kp["private_key"])

    def test_different_messages_different_signatures(self):
        kp = fresh_signing()
        assert sign(b"msg1", kp["private_key"]) != sign(b"msg2", kp["private_key"])

    def test_raises_type_error_for_non_bytes_message(self):
        kp = fresh_signing()
        with pytest.raises(TypeError, match="message must be bytes"):
            sign("not bytes", kp["private_key"])

    def test_raises_type_error_for_non_bytes_private_key(self):
        with pytest.raises(TypeError, match="private_key_bytes must be bytes"):
            sign(b"hello", "not bytes")


# ═══════════════════════════════════════════════════════════════
# verify
# ═══════════════════════════════════════════════════════════════

class TestVerify:

    def setup_method(self):
        self.kp = fresh_signing()
        self.message = b"authentic message"
        self.sig = sign(self.message, self.kp["private_key"])

    def test_valid_signature_returns_true(self):
        assert verify(self.message, self.sig, self.kp["public_key"]) is True

    def test_tampered_message_returns_false(self):
        # Exercises the InvalidSignature except branch
        assert verify(b"tampered", self.sig, self.kp["public_key"]) is False

    def test_tampered_signature_returns_false(self):
        # Flip one byte → InvalidSignature
        bad_sig = bytes([self.sig[0] ^ 0xFF]) + self.sig[1:]
        assert verify(self.message, bad_sig, self.kp["public_key"]) is False

    def test_wrong_public_key_returns_false(self):
        other_kp = fresh_signing()
        assert verify(self.message, self.sig, other_kp["public_key"]) is False

    def test_bad_signature_length_returns_false(self):
        # Too short → ValueError inside cryptography
        assert verify(self.message, b"\x00" * 10, self.kp["public_key"]) is False

    def test_bad_public_key_bytes_returns_false(self):
        # Wrong-length public key triggers ValueError
        assert verify(self.message, self.sig, b"\x00" * 10) is False

    def test_raises_type_error_for_non_bytes_message(self):
        with pytest.raises(TypeError, match="message must be bytes"):
            verify("string", self.sig, self.kp["public_key"])

    def test_raises_type_error_for_non_bytes_signature(self):
        with pytest.raises(TypeError, match="signature must be bytes"):
            verify(self.message, "string", self.kp["public_key"])

    def test_raises_type_error_for_non_bytes_public_key(self):
        with pytest.raises(TypeError, match="public_key_bytes must be bytes"):
            verify(self.message, self.sig, "string")

    def test_empty_message_can_be_signed_and_verified(self):
        sig = sign(b"", self.kp["private_key"])
        assert verify(b"", sig, self.kp["public_key"]) is True

    def test_large_message(self):
        large = b"x" * 100_000
        sig = sign(large, self.kp["private_key"])
        assert verify(large, sig, self.kp["public_key"]) is True


# ═══════════════════════════════════════════════════════════════
# sign_str
# ═══════════════════════════════════════════════════════════════

class TestSignStr:

    def setup_method(self):
        self.kp = fresh_signing()

    def test_returns_hex_string(self):
        hex_sig = sign_str("hello", self.kp["private_key"])
        assert isinstance(hex_sig, str)
        # Must be valid hex of length 128 (64 bytes * 2)
        assert len(hex_sig) == 128
        int(hex_sig, 16)  # raises if not valid hex

    def test_consistent_with_sign(self):
        text = "consistency check"
        hex_sig = sign_str(text, self.kp["private_key"])
        raw_sig = sign(text.encode("utf-8"), self.kp["private_key"])
        assert hex_sig == raw_sig.hex()

    def test_raises_type_error_for_non_str_text(self):
        with pytest.raises(TypeError, match="text must be a str"):
            sign_str(b"bytes not str", self.kp["private_key"])

    def test_raises_type_error_for_non_bytes_private_key(self):
        with pytest.raises(TypeError, match="private_key_bytes must be bytes"):
            sign_str("hello", "not bytes")


# ═══════════════════════════════════════════════════════════════
# verify_str
# ═══════════════════════════════════════════════════════════════

class TestVerifyStr:

    def setup_method(self):
        self.kp = fresh_signing()
        self.text = "verify me"
        self.hex_sig = sign_str(self.text, self.kp["private_key"])

    def test_valid_returns_true(self):
        assert verify_str(self.text, self.hex_sig, self.kp["public_key"]) is True

    def test_tampered_text_returns_false(self):
        assert verify_str("different", self.hex_sig, self.kp["public_key"]) is False

    def test_tampered_hex_sig_returns_false(self):
        # Change first two hex chars → different bytes → InvalidSignature
        bad = ("00" if self.hex_sig[:2] != "00" else "01") + self.hex_sig[2:]
        assert verify_str(self.text, bad, self.kp["public_key"]) is False

    def test_invalid_hex_string_returns_false(self):
        # Non-hex string → ValueError in bytes.fromhex → caught, returns False
        assert verify_str(self.text, "not-valid-hex!!", self.kp["public_key"]) is False

    def test_wrong_public_key_returns_false(self):
        other_kp = fresh_signing()
        assert verify_str(self.text, self.hex_sig, other_kp["public_key"]) is False

    def test_raises_type_error_for_non_str_text(self):
        with pytest.raises(TypeError, match="text must be a str"):
            verify_str(b"bytes", self.hex_sig, self.kp["public_key"])

    def test_raises_type_error_for_non_str_signature_hex(self):
        with pytest.raises(TypeError, match="signature_hex must be a str"):
            verify_str(self.text, b"bytes", self.kp["public_key"])

    def test_raises_type_error_for_non_bytes_public_key(self):
        with pytest.raises(TypeError, match="public_key_bytes must be bytes"):
            verify_str(self.text, self.hex_sig, "not bytes")

    def test_unicode_text_round_trip(self):
        text = "こんにちは 🌸"
        hex_sig = sign_str(text, self.kp["private_key"])
        assert verify_str(text, hex_sig, self.kp["public_key"]) is True
