"""
Full-coverage pytest suite for symmetric.py

Covers every line including:
  - generate_symmetric_key
  - encrypt / decrypt (bytes API)
  - encrypt_str / decrypt_str (hex-string API)
  - All TypeError / ValueError guards
  - The InvalidTag → ValueError re-raise path
"""

from __future__ import annotations

import pytest

from uxsp.crypto.symmetric import (
    KEY_SIZE,
    NONCE_SIZE,
    decrypt,
    decrypt_str,
    encrypt,
    encrypt_str,
    generate_symmetric_key,
)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def good_key() -> bytes:
    return generate_symmetric_key()


# ──────────────────────────────────────────────────────────────────────────────
# generate_symmetric_key
# ──────────────────────────────────────────────────────────────────────────────

class TestGenerateSymmetricKey:
    def test_returns_bytes(self):
        assert isinstance(generate_symmetric_key(), bytes)

    def test_correct_length(self):
        assert len(generate_symmetric_key()) == KEY_SIZE

    def test_randomness(self):
        # Two successive keys must not be identical (astronomically unlikely)
        assert generate_symmetric_key() != generate_symmetric_key()


# ──────────────────────────────────────────────────────────────────────────────
# encrypt – type guards
# ──────────────────────────────────────────────────────────────────────────────

class TestEncryptTypeGuards:
    def test_key_not_bytes_raises(self):
        with pytest.raises(TypeError, match="key must be bytes"):
            encrypt(b"data", "not-bytes")  # type: ignore[arg-type]

    def test_data_not_bytes_raises(self):
        with pytest.raises(TypeError, match="data must be bytes"):
            encrypt("a string", good_key())  # type: ignore[arg-type]

    def test_associated_data_not_bytes_raises(self):
        with pytest.raises(TypeError, match="associated_data must be bytes or None"):
            encrypt(b"data", good_key(), associated_data="aad")  # type: ignore[arg-type]

    def test_wrong_key_length_raises(self):
        with pytest.raises(ValueError, match="Key must be"):
            encrypt(b"data", b"short")


# ──────────────────────────────────────────────────────────────────────────────
# encrypt – happy paths
# ──────────────────────────────────────────────────────────────────────────────

class TestEncryptHappyPath:
    def test_returns_dict_with_expected_keys(self):
        result = encrypt(b"hello", good_key())
        assert set(result.keys()) == {"ciphertext", "nonce"}

    def test_nonce_is_correct_length(self):
        result = encrypt(b"hello", good_key())
        assert len(result["nonce"]) == NONCE_SIZE

    def test_ciphertext_is_bytes(self):
        result = encrypt(b"hello", good_key())
        assert isinstance(result["ciphertext"], bytes)

    def test_ciphertext_differs_from_plaintext(self):
        plaintext = b"sensitive data"
        result = encrypt(plaintext, good_key())
        assert result["ciphertext"] != plaintext

    def test_with_associated_data(self):
        result = encrypt(b"data", good_key(), associated_data=b"aad")
        assert "ciphertext" in result and "nonce" in result

    def test_without_associated_data_default_none(self):
        # associated_data defaults to None; must not raise
        result = encrypt(b"data", good_key())
        assert result is not None

    def test_same_plaintext_different_nonces_each_call(self):
        key = good_key()
        r1 = encrypt(b"same", key)
        r2 = encrypt(b"same", key)
        # Random nonce means nonces should differ
        assert r1["nonce"] != r2["nonce"]


# ──────────────────────────────────────────────────────────────────────────────
# decrypt – type guards
# ──────────────────────────────────────────────────────────────────────────────

class TestDecryptTypeGuards:
    def setup_method(self):
        self.key = good_key()
        result = encrypt(b"payload", self.key)
        self.ct = result["ciphertext"]
        self.nonce = result["nonce"]

    def test_key_not_bytes_raises(self):
        with pytest.raises(TypeError, match="key must be bytes"):
            decrypt(self.ct, self.nonce, "bad-key")  # type: ignore[arg-type]

    def test_nonce_not_bytes_raises(self):
        with pytest.raises(TypeError, match="nonce must be bytes"):
            decrypt(self.ct, "bad-nonce", self.key)  # type: ignore[arg-type]

    def test_ciphertext_not_bytes_raises(self):
        with pytest.raises(TypeError, match="ciphertext must be bytes"):
            decrypt("not bytes", self.nonce, self.key)  # type: ignore[arg-type]

    def test_associated_data_not_bytes_raises(self):
        with pytest.raises(TypeError, match="associated_data must be bytes or None"):
            decrypt(self.ct, self.nonce, self.key, associated_data="aad")  # type: ignore[arg-type]

    def test_wrong_key_length_raises(self):
        with pytest.raises(ValueError, match="Key must be"):
            decrypt(self.ct, self.nonce, b"tooshort")

    def test_wrong_nonce_length_raises(self):
        with pytest.raises(ValueError, match="Nonce must be"):
            decrypt(self.ct, b"bad", self.key)


# ──────────────────────────────────────────────────────────────────────────────
# decrypt – happy paths and failure modes
# ──────────────────────────────────────────────────────────────────────────────

class TestDecryptHappyPath:
    def test_round_trip(self):
        key = good_key()
        plaintext = b"round-trip data"
        result = encrypt(plaintext, key)
        assert decrypt(result["ciphertext"], result["nonce"], key) == plaintext

    def test_round_trip_with_associated_data(self):
        key = good_key()
        aad = b"extra header"
        plaintext = b"authenticated payload"
        result = encrypt(plaintext, key, associated_data=aad)
        recovered = decrypt(result["ciphertext"], result["nonce"], key, associated_data=aad)
        assert recovered == plaintext

    def test_wrong_key_raises_invalid_tag(self):
        key = good_key()
        result = encrypt(b"secret", key)
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt(result["ciphertext"], result["nonce"], good_key())  # different key

    def test_tampered_ciphertext_raises(self):
        key = good_key()
        result = encrypt(b"secret", key)
        tampered = bytes([result["ciphertext"][0] ^ 0xFF]) + result["ciphertext"][1:]
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt(tampered, result["nonce"], key)

    def test_wrong_aad_raises(self):
        key = good_key()
        result = encrypt(b"data", key, associated_data=b"correct-aad")
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt(result["ciphertext"], result["nonce"], key, associated_data=b"wrong-aad")

    def test_missing_aad_on_decrypt_raises(self):
        key = good_key()
        result = encrypt(b"data", key, associated_data=b"required")
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt(result["ciphertext"], result["nonce"], key)  # no aad supplied


# ──────────────────────────────────────────────────────────────────────────────
# encrypt_str – type guards
# ──────────────────────────────────────────────────────────────────────────────

class TestEncryptStrTypeGuards:
    def test_key_not_bytes_raises(self):
        with pytest.raises(TypeError, match="key must be bytes"):
            encrypt_str("text", "not-bytes")  # type: ignore[arg-type]

    def test_text_not_str_raises(self):
        with pytest.raises(TypeError, match="text must be str"):
            encrypt_str(b"bytes", good_key())  # type: ignore[arg-type]

    def test_associated_data_not_bytes_raises(self):
        with pytest.raises(TypeError, match="associated_data must be bytes or None"):
            encrypt_str("text", good_key(), associated_data="aad")  # type: ignore[arg-type]

    def test_wrong_key_length_raises(self):
        with pytest.raises(ValueError, match="Key must be"):
            encrypt_str("text", b"short")


# ──────────────────────────────────────────────────────────────────────────────
# encrypt_str – happy paths
# ──────────────────────────────────────────────────────────────────────────────

class TestEncryptStrHappyPath:
    def test_returns_hex_strings(self):
        result = encrypt_str("hello", good_key())
        assert isinstance(result["ciphertext"], str)
        assert isinstance(result["nonce"], str)

    def test_nonce_hex_correct_length(self):
        result = encrypt_str("hello", good_key())
        # Each byte becomes 2 hex chars
        assert len(result["nonce"]) == NONCE_SIZE * 2

    def test_with_associated_data(self):
        result = encrypt_str("text", good_key(), associated_data=b"aad")
        assert "ciphertext" in result

    def test_without_associated_data(self):
        result = encrypt_str("text", good_key())
        assert result is not None


# ──────────────────────────────────────────────────────────────────────────────
# decrypt_str – type guards
# ──────────────────────────────────────────────────────────────────────────────

class TestDecryptStrTypeGuards:
    def setup_method(self):
        self.key = good_key()
        result = encrypt_str("payload", self.key)
        self.ct_hex = result["ciphertext"]
        self.nonce_hex = result["nonce"]

    def test_key_not_bytes_raises(self):
        with pytest.raises(TypeError, match="key must be bytes"):
            decrypt_str(self.ct_hex, self.nonce_hex, "bad")  # type: ignore[arg-type]

    def test_nonce_not_str_raises(self):
        with pytest.raises(TypeError, match="nonce_hex must be str"):
            decrypt_str(self.ct_hex, b"bad", self.key)  # type: ignore[arg-type]

    def test_ciphertext_not_str_raises(self):
        with pytest.raises(TypeError, match="ciphertext_hex must be str"):
            decrypt_str(b"bad", self.nonce_hex, self.key)  # type: ignore[arg-type]

    def test_associated_data_not_bytes_raises(self):
        with pytest.raises(TypeError, match="associated_data must be bytes or None"):
            decrypt_str(self.ct_hex, self.nonce_hex, self.key, associated_data="aad")  # type: ignore[arg-type]

    def test_wrong_key_length_raises(self):
        with pytest.raises(ValueError, match="Key must be"):
            decrypt_str(self.ct_hex, self.nonce_hex, b"short")

    def test_wrong_nonce_hex_length_raises(self):
        with pytest.raises(ValueError, match="Nonce must be"):
            decrypt_str(self.ct_hex, "deadbeef", self.key)  # too short


# ──────────────────────────────────────────────────────────────────────────────
# decrypt_str – happy paths and failure modes
# ──────────────────────────────────────────────────────────────────────────────

class TestDecryptStrHappyPath:
    def test_round_trip(self):
        key = good_key()
        text = "Hello, world! 🌍"
        result = encrypt_str(text, key)
        assert decrypt_str(result["ciphertext"], result["nonce"], key) == text

    def test_round_trip_with_associated_data(self):
        key = good_key()
        aad = b"metadata"
        text = "authenticated message"
        result = encrypt_str(text, key, associated_data=aad)
        assert decrypt_str(result["ciphertext"], result["nonce"], key, associated_data=aad) == text

    def test_empty_string_round_trip(self):
        key = good_key()
        result = encrypt_str("", key)
        assert decrypt_str(result["ciphertext"], result["nonce"], key) == ""

    def test_wrong_key_raises(self):
        key = good_key()
        result = encrypt_str("secret", key)
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_str(result["ciphertext"], result["nonce"], good_key())

    def test_returns_str(self):
        key = good_key()
        result = encrypt_str("data", key)
        recovered = decrypt_str(result["ciphertext"], result["nonce"], key)
        assert isinstance(recovered, str)
