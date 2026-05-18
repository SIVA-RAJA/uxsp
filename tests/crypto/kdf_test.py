"""
Pytest suite for kdf.py
========================
Coverage targets — every executable line, every branch:

  derive_key                 — happy path, all TypeError / ValueError guards
  derive_multiple_keys       — key presence, lengths, domain separation
  derive_key_from_password   — happy path with/without salt, all guards,
                               short-salt rejection, determinism
  argon2id_hash              — produces PHC string, TypeError guard
  argon2id_verify            — correct, wrong password, bad hash, TypeError
  argon2id_needs_rehash      — False for fresh hash, True for downgraded
                               params, TypeError guard
"""

from __future__ import annotations

import os

import pytest

# ── subject under test ──────────────────────────────────────────────────────
from uxsp.crypto.kdf import (
    argon2id_hash,
    argon2id_needs_rehash,
    argon2id_verify,
    derive_key,
    derive_key_from_password,
    derive_multiple_keys,
)

# ════════════════════════════════════════════════════════════════════════════
# helpers
# ════════════════════════════════════════════════════════════════════════════

def fresh_salt(n: int = 16) -> bytes:
    return os.urandom(n)


# ════════════════════════════════════════════════════════════════════════════
# derive_key
# ════════════════════════════════════════════════════════════════════════════

class TestDeriveKey:

    # ── happy paths ─────────────────────────────────────────────────────────

    def test_returns_bytes_of_requested_length(self):
        key = derive_key(b"secret", length=32)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_custom_length(self):
        key = derive_key(b"secret", length=64)
        assert len(key) == 64

    def test_with_salt(self):
        key = derive_key(b"secret", length=32, salt=b"saltsaltsaltsalt")
        assert len(key) == 32

    def test_with_info(self):
        key = derive_key(b"secret", length=32, info=b"context-label")
        assert len(key) == 32

    def test_salt_none_is_accepted(self):
        # salt=None is the default; the cryptography library handles it
        key = derive_key(b"secret", length=16, salt=None)
        assert len(key) == 16

    def test_different_info_produces_different_keys(self):
        salt = b"same-salt-value!"
        k1 = derive_key(b"ikm", salt=salt, info=b"purpose-a")
        k2 = derive_key(b"ikm", salt=salt, info=b"purpose-b")
        assert k1 != k2

    def test_same_inputs_produce_same_key(self):
        ikm  = b"deterministic"
        salt = b"fixed-salt-16byt"
        k1 = derive_key(ikm, length=32, salt=salt, info=b"ctx")
        k2 = derive_key(ikm, length=32, salt=salt, info=b"ctx")
        assert k1 == k2

    # ── TypeError guards ────────────────────────────────────────────────────

    def test_ikm_not_bytes_raises_typeerror(self):
        with pytest.raises(TypeError, match="ikm must be bytes"):
            derive_key("not-bytes")

    def test_salt_not_bytes_raises_typeerror(self):
        with pytest.raises(TypeError, match="salt must be bytes or None"):
            derive_key(b"ikm", salt="bad-salt")

    def test_info_not_bytes_raises_typeerror(self):
        with pytest.raises(TypeError, match="info must be bytes"):
            derive_key(b"ikm", info="not-bytes")

    # ── ValueError guards ───────────────────────────────────────────────────

    def test_length_zero_raises_valueerror(self):
        with pytest.raises(ValueError, match="length must be a positive integer"):
            derive_key(b"ikm", length=0)

    def test_length_negative_raises_valueerror(self):
        with pytest.raises(ValueError, match="length must be a positive integer"):
            derive_key(b"ikm", length=-1)

    def test_length_not_int_raises_valueerror(self):
        with pytest.raises(ValueError, match="length must be a positive integer"):
            derive_key(b"ikm", length=16.0)


# ════════════════════════════════════════════════════════════════════════════
# derive_multiple_keys
# ════════════════════════════════════════════════════════════════════════════

class TestDeriveMultipleKeys:

    def test_returns_expected_keys(self):
        result = derive_multiple_keys(b"master-ikm")
        assert set(result.keys()) == {"encryption", "integrity", "session_id"}

    def test_encryption_key_is_32_bytes(self):
        result = derive_multiple_keys(b"master-ikm")
        assert len(result["encryption"]) == 32

    def test_integrity_key_is_32_bytes(self):
        result = derive_multiple_keys(b"master-ikm")
        assert len(result["integrity"]) == 32

    def test_session_id_is_16_bytes(self):
        result = derive_multiple_keys(b"master-ikm")
        assert len(result["session_id"]) == 16

    def test_keys_are_all_distinct(self):
        result = derive_multiple_keys(b"master-ikm")
        values = list(result.values())
        # All three subkeys must be domain-separated from one another
        assert values[0] != values[1]
        assert values[0] != values[2]
        assert values[1] != values[2]

    def test_with_explicit_salt(self):
        salt   = fresh_salt()
        result = derive_multiple_keys(b"master-ikm", salt=salt)
        assert len(result["encryption"]) == 32

    def test_salt_none_is_accepted(self):
        result = derive_multiple_keys(b"master-ikm", salt=None)
        assert len(result["encryption"]) == 32

    def test_determinism_with_same_salt(self):
        salt = b"fixed-salt-16-by"
        r1 = derive_multiple_keys(b"ikm", salt=salt)
        r2 = derive_multiple_keys(b"ikm", salt=salt)
        assert r1 == r2

    def test_different_salt_different_keys(self):
        r1 = derive_multiple_keys(b"ikm", salt=b"salt-number-one!")
        r2 = derive_multiple_keys(b"ikm", salt=b"salt-number-two!")
        assert r1["encryption"] != r2["encryption"]


# ════════════════════════════════════════════════════════════════════════════
# derive_key_from_password
# ════════════════════════════════════════════════════════════════════════════

class TestDeriveKeyFromPassword:

    # ── happy paths ─────────────────────────────────────────────────────────

    def test_returns_key_and_salt(self):
        result = derive_key_from_password("password123")
        assert "key" in result
        assert "salt" in result

    def test_key_is_default_length(self):
        result = derive_key_from_password("password123")
        assert len(result["key"]) == 32

    def test_salt_is_16_bytes_when_not_provided(self):
        result = derive_key_from_password("password123")
        assert len(result["salt"]) == 16

    def test_custom_length(self):
        result = derive_key_from_password("password123", length=64)
        assert len(result["key"]) == 64

    def test_explicit_salt_is_preserved(self):
        salt   = fresh_salt(16)
        result = derive_key_from_password("password", salt=salt)
        assert result["salt"] == salt

    def test_determinism_with_same_salt(self):
        salt = fresh_salt(16)
        r1 = derive_key_from_password("password", salt=salt)
        r2 = derive_key_from_password("password", salt=salt)
        assert r1["key"] == r2["key"]

    def test_different_passwords_different_keys(self):
        salt = fresh_salt(16)
        r1 = derive_key_from_password("password-A", salt=salt)
        r2 = derive_key_from_password("password-B", salt=salt)
        assert r1["key"] != r2["key"]

    def test_different_salts_different_keys(self):
        r1 = derive_key_from_password("password", salt=fresh_salt(16))
        r2 = derive_key_from_password("password", salt=fresh_salt(16))
        # Astronomically unlikely to collide with random 128-bit salts
        assert r1["key"] != r2["key"]

    def test_random_salt_generated_when_none(self):
        # Each call without a salt must produce a unique salt
        r1 = derive_key_from_password("pw")
        r2 = derive_key_from_password("pw")
        assert r1["salt"] != r2["salt"]

    # ── short-salt rejection ─────────────────────────────────────────────────

    def test_salt_too_short_raises_valueerror(self):
        with pytest.raises(ValueError, match="Salt must be at least 8 bytes"):
            derive_key_from_password("pw", salt=b"short")

    def test_salt_exactly_8_bytes_is_accepted(self):
        result = derive_key_from_password("pw", salt=b"8bytsalt")
        assert len(result["key"]) == 32

    # ── TypeError guards ─────────────────────────────────────────────────────

    def test_password_not_str_raises_typeerror(self):
        with pytest.raises(TypeError, match="password must be a str"):
            derive_key_from_password(b"bytes-not-str")

    def test_salt_not_bytes_raises_typeerror(self):
        with pytest.raises(TypeError, match="salt must be bytes"):
            derive_key_from_password("pw", salt="string-salt")

    # ── ValueError guards — length ────────────────────────────────────────────

    def test_length_zero_raises_valueerror(self):
        with pytest.raises(ValueError, match="length must be a positive integer"):
            derive_key_from_password("pw", length=0)

    def test_length_negative_raises_valueerror(self):
        with pytest.raises(ValueError, match="length must be a positive integer"):
            derive_key_from_password("pw", length=-5)

    def test_length_bool_raises_valueerror(self):
        # bool is a subclass of int; the code explicitly rejects it
        with pytest.raises(ValueError, match="length must be a positive integer"):
            derive_key_from_password("pw", length=True)

    def test_length_float_raises_valueerror(self):
        with pytest.raises(ValueError, match="length must be a positive integer"):
            derive_key_from_password("pw", length=32.0)

    # ── ValueError guards — time_cost ─────────────────────────────────────────

    def test_time_cost_zero_raises_valueerror(self):
        with pytest.raises(ValueError, match="time_cost must be >= 1"):
            derive_key_from_password("pw", time_cost=0)

    def test_time_cost_bool_raises_valueerror(self):
        with pytest.raises(ValueError, match="time_cost must be >= 1"):
            derive_key_from_password("pw", time_cost=True)

    def test_time_cost_float_raises_valueerror(self):
        with pytest.raises(ValueError, match="time_cost must be >= 1"):
            derive_key_from_password("pw", time_cost=1.0)

    # ── ValueError guards — memory_cost ───────────────────────────────────────

    def test_memory_cost_too_low_raises_valueerror(self):
        with pytest.raises(ValueError, match="memory_cost must be >= 8"):
            derive_key_from_password("pw", memory_cost=4)

    def test_memory_cost_bool_raises_valueerror(self):
        with pytest.raises(ValueError, match="memory_cost must be >= 8"):
            derive_key_from_password("pw", memory_cost=True)

    def test_memory_cost_float_raises_valueerror(self):
        with pytest.raises(ValueError, match="memory_cost must be >= 8"):
            derive_key_from_password("pw", memory_cost=65536.0)

    # ── ValueError guards — parallelism ───────────────────────────────────────

    def test_parallelism_zero_raises_valueerror(self):
        with pytest.raises(ValueError, match="parallelism must be >= 1"):
            derive_key_from_password("pw", parallelism=0)

    def test_parallelism_bool_raises_valueerror(self):
        with pytest.raises(ValueError, match="parallelism must be >= 1"):
            derive_key_from_password("pw", parallelism=True)

    def test_parallelism_float_raises_valueerror(self):
        with pytest.raises(ValueError, match="parallelism must be >= 1"):
            derive_key_from_password("pw", parallelism=4.0)

    # ── Argon2id type is used (spot-check via output length) ─────────────────

    def test_custom_params_still_produce_correct_length(self):
        result = derive_key_from_password(
            "pw",
            salt=fresh_salt(16),
            length=24,
            time_cost=1,
            memory_cost=8,
            parallelism=1,
        )
        assert len(result["key"]) == 24


# ════════════════════════════════════════════════════════════════════════════
# argon2id_hash
# ════════════════════════════════════════════════════════════════════════════

class TestArgon2idHash:

    def test_returns_phc_string(self):
        h = argon2id_hash("hunter2")
        assert isinstance(h, str)
        assert h.startswith("$argon2id$")

    def test_two_hashes_of_same_password_differ(self):
        # Argon2 embeds a random salt; two hashes must never be identical
        h1 = argon2id_hash("hunter2")
        h2 = argon2id_hash("hunter2")
        assert h1 != h2

    def test_password_not_str_raises_typeerror(self):
        with pytest.raises(TypeError, match="password must be a str"):
            argon2id_hash(b"bytes")

    def test_password_not_str_int_raises_typeerror(self):
        with pytest.raises(TypeError, match="password must be a str"):
            argon2id_hash(12345)


# ════════════════════════════════════════════════════════════════════════════
# argon2id_verify
# ════════════════════════════════════════════════════════════════════════════

class TestArgon2idVerify:

    def test_correct_password_returns_true(self):
        h = argon2id_hash("correct-horse-battery-staple")
        assert argon2id_verify(h, "correct-horse-battery-staple") is True

    def test_wrong_password_returns_false(self):
        h = argon2id_hash("correct-horse-battery-staple")
        assert argon2id_verify(h, "wrong-password") is False

    def test_empty_password_can_be_hashed_and_verified(self):
        h = argon2id_hash("")
        assert argon2id_verify(h, "") is True
        assert argon2id_verify(h, " ") is False

    def test_invalid_hash_string_returns_false(self):
        # InvalidHashError path — not a valid PHC string at all
        assert argon2id_verify("not-a-valid-hash", "any-password") is False

    def test_truncated_hash_returns_false(self):
        # Another InvalidHashError / VerificationError trigger
        assert argon2id_verify("$argon2id$", "pw") is False

    def test_non_str_stored_hash_raises_typeerror(self):
        with pytest.raises(TypeError):
            argon2id_verify(b"bytes-hash", "pw")

    def test_non_str_password_raises_typeerror(self):
        with pytest.raises(TypeError):
            argon2id_verify("$argon2id$...", b"bytes-pw")

    def test_both_non_str_raises_typeerror(self):
        with pytest.raises(TypeError):
            argon2id_verify(None, None)


# ════════════════════════════════════════════════════════════════════════════
# argon2id_needs_rehash
# ════════════════════════════════════════════════════════════════════════════

class TestArgon2idNeedsRehash:

    def test_fresh_hash_does_not_need_rehash(self):
        h = argon2id_hash("my-password")
        assert argon2id_needs_rehash(h) is False

    def test_hash_with_lower_time_cost_needs_rehash(self):
        # Hash produced with time_cost=1 (below the module's configured t=3)
        from argon2 import PasswordHasher
        weak_hasher = PasswordHasher(
            time_cost=1, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16
        )
        weak_hash = weak_hasher.hash("pw")
        # The module's _hasher (t=3) must flag this as needing rehash
        assert argon2id_needs_rehash(weak_hash) is True

    def test_hash_with_lower_memory_cost_needs_rehash(self):
        from argon2 import PasswordHasher
        weak_hasher = PasswordHasher(
            time_cost=3, memory_cost=8192, parallelism=4, hash_len=32, salt_len=16
        )
        weak_hash = weak_hasher.hash("pw")
        assert argon2id_needs_rehash(weak_hash) is True

    def test_non_str_raises_typeerror(self):
        with pytest.raises(TypeError, match="stored_hash must be a str"):
            argon2id_needs_rehash(b"bytes")

    def test_int_raises_typeerror(self):
        with pytest.raises(TypeError, match="stored_hash must be a str"):
            argon2id_needs_rehash(42)

    def test_none_raises_typeerror(self):
        with pytest.raises(TypeError, match="stored_hash must be a str"):
            argon2id_needs_rehash(None)
