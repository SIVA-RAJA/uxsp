"""
Full-coverage pytest suite for identity.py
===========================================
Strategy
--------
All external uxsp dependencies are mocked at the module boundary so the
tests exercise the real logic in identity.py without requiring the uxsp
package to be installed.  Every branch, every raise, every else-path,
every line in save/load is covered.

Run with:
    pytest test_identity.py -v --tb=short
"""

import json
import os
import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

# ──────────────────────────────────────────────────────────────────
# Helpers that build realistic-looking fake objects / data
# ──────────────────────────────────────────────────────────────────

def _fake_keypair():
    """Return a minimal keypair dict whose values are real bytes."""
    return {
        "exchange": {"private_key": bytes(32), "public_key": bytes(32)},
        "kem":      {"private_key": bytes(32), "public_key": bytes(32)},
        "signing":  {"private_key": bytes(32), "public_key": bytes(32)},
        "pqc_sig":  {"private_key": bytes(32), "public_key": bytes(32)},
    }


def _fake_pub_keys():
    """Public-keys dict as bytes (the shape extract_public_keys returns)."""
    return {
        "exchange_pub": bytes(32),
        "kem_pub":      bytes(32),
        "signing_pub":  bytes(32),
        "pqc_sig_pub":  bytes(32),
    }


def _pub_keys_hex():
    """Hex-string version of the public keys (for JSON payloads)."""
    return {k: v.hex() for k, v in _fake_pub_keys().items()}


# ──────────────────────────────────────────────────────────────────
# Module-level patch context so every test imports mocked modules
# ──────────────────────────────────────────────────────────────────

class _MockEnvelope:
    from_dict = MagicMock()
    def to_dict(self):
        return getattr(self, "_d", {})
MOCK_ENVELOPE_CLS = _MockEnvelope
MOCK_REPLAY_GUARD   = MagicMock()
MOCK_SEAL           = MagicMock(return_value={"sealed": True})
MOCK_VERIFY         = MagicMock(return_value={"verified": True})
MOCK_DECRYPT_VE     = MagicMock(return_value=b"plaintext")
MOCK_EXTRACT_PUB    = MagicMock(return_value=_fake_pub_keys())
MOCK_GEN_KEYPAIR    = MagicMock(return_value=_fake_keypair())
MOCK_SYM_ENCRYPT    = MagicMock(return_value={
    "ciphertext": bytes(16), "nonce": bytes(12)
})
MOCK_SYM_DECRYPT    = MagicMock(return_value=json.dumps({
    "exchange_priv": bytes(32).hex(),
    "kem_priv":      bytes(32).hex(),
    "signing_priv":  bytes(32).hex(),
    "pqc_sig_priv":  bytes(32).hex(),
}).encode())
MOCK_KDF            = MagicMock(return_value={
    "key":  bytes(32),
    "salt": bytes(16),
})


PATCHES = {
    "uxsp.core.envelope.Envelope":             MOCK_ENVELOPE_CLS,
    "uxsp.core.replay.DefaultReplayGuard":     MOCK_REPLAY_GUARD,
    "uxsp.crypto.hybrid.seal":                 MOCK_SEAL,
    "uxsp.crypto.hybrid.verify_envelope":      MOCK_VERIFY,
    "uxsp.crypto.hybrid.decrypt_verified_envelope": MOCK_DECRYPT_VE,
    "uxsp.crypto.hybrid.extract_public_keys":  MOCK_EXTRACT_PUB,
    "uxsp.crypto.hybrid.generate_hybrid_keypair": MOCK_GEN_KEYPAIR,
    "uxsp.crypto.symmetric.encrypt":           MOCK_SYM_ENCRYPT,
    "uxsp.crypto.symmetric.decrypt":           MOCK_SYM_DECRYPT,
}


@pytest.fixture(autouse=True)
def _patch_uxsp(monkeypatch):
    """
    Patch all uxsp symbols before each test.
    """
    monkeypatch.setattr("uxsp.core.identity.Envelope", MOCK_ENVELOPE_CLS)
    monkeypatch.setattr("uxsp.core.identity.DefaultReplayGuard", MOCK_REPLAY_GUARD)
    monkeypatch.setattr("uxsp.core.identity.seal", MOCK_SEAL)
    monkeypatch.setattr("uxsp.core.identity.verify_envelope", MOCK_VERIFY)
    monkeypatch.setattr("uxsp.core.identity.decrypt_verified_envelope", MOCK_DECRYPT_VE)
    monkeypatch.setattr("uxsp.core.identity.extract_public_keys", MOCK_EXTRACT_PUB)
    monkeypatch.setattr("uxsp.core.identity.generate_hybrid_keypair", MOCK_GEN_KEYPAIR)
    monkeypatch.setattr("uxsp.core.identity.encrypt", MOCK_SYM_ENCRYPT)
    monkeypatch.setattr("uxsp.core.identity.decrypt", MOCK_SYM_DECRYPT)

    # For kdf we need to patch the actual module since it's imported dynamically inside methods
    monkeypatch.setattr("uxsp.crypto.kdf.derive_key_from_password", MOCK_KDF)

    # Reset call counts between tests
    for m in (MOCK_SEAL, MOCK_VERIFY, MOCK_DECRYPT_VE, MOCK_EXTRACT_PUB,
              MOCK_GEN_KEYPAIR, MOCK_SYM_ENCRYPT, MOCK_SYM_DECRYPT, MOCK_KDF):
        m.reset_mock()

    # Restore default return values after reset
    MOCK_EXTRACT_PUB.return_value    = _fake_pub_keys()
    MOCK_GEN_KEYPAIR.return_value    = _fake_keypair()
    MOCK_SEAL.return_value           = {"sealed": True}
    MOCK_VERIFY.return_value         = {"verified": True}
    MOCK_DECRYPT_VE.return_value     = b"plaintext"
    MOCK_SYM_ENCRYPT.return_value    = {"ciphertext": bytes(16), "nonce": bytes(12)}
    MOCK_SYM_DECRYPT.return_value    = json.dumps({
        "exchange_priv": bytes(32).hex(),
        "kem_priv":      bytes(32).hex(),
        "signing_priv":  bytes(32).hex(),
        "pqc_sig_priv":  bytes(32).hex(),
    }).encode()
    MOCK_KDF.return_value = {"key": bytes(32), "salt": bytes(16)}

    yield


def _import():
    """Import identity."""
    import uxsp.core.identity as mod
    return mod


# ══════════════════════════════════════════════════════════════════
# 1. validate_role
# ══════════════════════════════════════════════════════════════════

class TestValidateRole:

    def test_returns_uppercased_stripped(self):
        m = _import()
        assert m.validate_role("  admin  ") == "ADMIN"

    def test_non_string_raises(self):
        m = _import()
        with pytest.raises(ValueError, match="Role must be a string"):
            m.validate_role(123)

    def test_empty_after_strip_raises(self):
        m = _import()
        with pytest.raises(ValueError, match="Role cannot be empty"):
            m.validate_role("   ")

    def test_too_long_raises(self):
        m = _import()
        with pytest.raises(ValueError, match="64 characters"):
            m.validate_role("A" * 65)

    def test_exact_64_ok(self):
        m = _import()
        result = m.validate_role("A" * 64)
        assert result == "A" * 64

    def test_internal_whitespace_raises(self):
        m = _import()
        with pytest.raises(ValueError, match="internal whitespace"):
            m.validate_role("AD MIN")

    def test_internal_tab_raises(self):
        m = _import()
        with pytest.raises(ValueError, match="internal whitespace"):
            m.validate_role("AD\tMIN")

    def test_valid_role_with_underscore(self):
        m = _import()
        assert m.validate_role("power_user") == "POWER_USER"


# ══════════════════════════════════════════════════════════════════
# 2. _identity_public_metadata & _identity_associated_data
# ══════════════════════════════════════════════════════════════════

class TestHelperFunctions:

    def _sample_payload(self):
        return {
            "version":     "UXSP-IDENTITY-1",
            "entity_id":   "abc-123",
            "name":        "Alice",
            "role":        "ADMIN",
            "created_at":  "2024-01-01T00:00:00+00:00",
            "public_keys": {"k": "v"},
        }

    def test_public_metadata_returns_subset(self):
        m = _import()
        payload = self._sample_payload()
        result = m._identity_public_metadata(payload)
        assert set(result.keys()) == {
            "version", "entity_id", "name", "role", "created_at", "public_keys"
        }
        assert result["entity_id"] == "abc-123"

    def test_associated_data_is_bytes(self):
        m = _import()
        payload = self._sample_payload()
        ad = m._identity_associated_data(payload)
        assert isinstance(ad, bytes)

    def test_associated_data_is_sorted_compact_json(self):
        """Keys must be sorted and separators compact (no spaces)."""
        m = _import()
        payload = self._sample_payload()
        ad = m._identity_associated_data(payload)
        decoded = json.loads(ad.decode("utf-8"))
        # Round-trip produces same data
        assert decoded["entity_id"] == "abc-123"
        # No spaces around separators
        assert b": " not in ad
        assert b", " not in ad


# ══════════════════════════════════════════════════════════════════
# 3. Identity.__init__
# ══════════════════════════════════════════════════════════════════

class TestIdentityInit:

    def test_explicit_created_at_stored(self):
        m = _import()
        ts = "2020-06-15T12:00:00+00:00"
        ident = m.Identity(
            entity_id="eid", name="Bob", role="USER",
            keypair=_fake_keypair(), created_at=ts
        )
        assert ident.created_at == ts

    def test_missing_created_at_defaults_to_now(self):
        m = _import()
        before = datetime.now(UTC).isoformat()
        ident = m.Identity(
            entity_id="eid", name="Bob", role="USER",
            keypair=_fake_keypair()
        )
        assert ident.created_at >= before

    def test_role_normalised_on_init(self):
        m = _import()
        ident = m.Identity("eid", "Bob", "  user  ", _fake_keypair())
        assert ident.role == "USER"

    def test_extract_public_keys_called(self):
        m = _import()
        kp = _fake_keypair()
        m.Identity("eid", "Bob", "USER", kp)
        MOCK_EXTRACT_PUB.assert_called_once_with(kp)


# ══════════════════════════════════════════════════════════════════
# 4. Identity.create
# ══════════════════════════════════════════════════════════════════

class TestIdentityCreate:

    def test_create_returns_identity(self):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        assert isinstance(ident, m.Identity)
        assert ident.name == "Alice"
        assert ident.role == "ADMIN"

    def test_create_strips_name(self):
        m = _import()
        ident = m.Identity.create("  Alice  ", "ADMIN")
        assert ident.name == "Alice"

    def test_create_empty_name_raises(self):
        m = _import()
        with pytest.raises(ValueError, match="Name cannot be empty"):
            m.Identity.create("", "ADMIN")

    def test_create_whitespace_only_name_raises(self):
        m = _import()
        with pytest.raises(ValueError, match="Name cannot be empty"):
            m.Identity.create("   ", "ADMIN")

    def test_create_generates_keypair(self):
        m = _import()
        m.Identity.create("Alice", "ADMIN")
        MOCK_GEN_KEYPAIR.assert_called_once()

    def test_create_entity_id_is_uuid(self):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        uuid.UUID(ident.entity_id)  # raises if not a valid UUID


# ══════════════════════════════════════════════════════════════════
# 5. Identity.public_card
# ══════════════════════════════════════════════════════════════════

class TestIdentityPublicCard:

    def test_public_card_returns_public_card(self):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        card = ident.public_card()
        assert isinstance(card, m.PublicCard)

    def test_public_card_fields_match(self):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        card = ident.public_card()
        assert card.entity_id  == ident.entity_id
        assert card.name       == ident.name
        assert card.role       == ident.role
        assert card.created_at == ident.created_at


# ══════════════════════════════════════════════════════════════════
# 6. Identity.seal_for
# ══════════════════════════════════════════════════════════════════

class TestIdentitySealFor:

    def test_seal_for_calls_seal(self):
        m = _import()
        sender   = m.Identity.create("Alice", "ADMIN")
        receiver = m.Identity.create("Bob",   "USER")
        r_card   = receiver.public_card()

        MOCK_ENVELOPE_CLS.from_dict.return_value = MagicMock()
        result = sender.seal_for(b"hello", r_card)

        MOCK_SEAL.assert_called_once_with(
            plaintext             = b"hello",
            sender_keypair        = sender.keypair,
            recipient_public_keys = r_card.public_keys,
            sender_id             = sender.entity_id,
            recipient_id          = r_card.entity_id,
        )
        MOCK_ENVELOPE_CLS.from_dict.assert_called_once_with({"sealed": True})
        assert result == MOCK_ENVELOPE_CLS.from_dict.return_value


# ══════════════════════════════════════════════════════════════════
# 7. Identity.open_from
# ══════════════════════════════════════════════════════════════════

class TestIdentityOpenFrom:

    def _make_two(self):
        m = _import()
        sender   = m.Identity.create("Alice", "ADMIN")
        receiver = m.Identity.create("Bob",   "USER")
        return m, sender, receiver

    def _fake_envelope_dict(self, sender_id, recipient_id):
        return {
            "sender_id":    sender_id,
            "recipient_id": recipient_id,
        }

    def test_none_replay_guard_raises_runtime_error(self):
        m, sender, receiver = self._make_two()
        with pytest.raises(RuntimeError, match="CRITICAL SECURITY ERROR"):
            receiver.open_from({}, sender.public_card(), replay_guard=None)

    def test_recipient_id_mismatch_raises(self):
        m, sender, receiver = self._make_two()
        guard = MagicMock()
        env_dict = self._fake_envelope_dict(sender.entity_id, "wrong-id")

        # Pass as plain dict (exercises the `else` branch of isinstance check)
        with pytest.raises(ValueError, match="Recipient ID mismatch"):
            receiver.open_from(env_dict, sender.public_card(), guard)

    def test_sender_id_mismatch_raises(self):
        m, sender, receiver = self._make_two()
        guard = MagicMock()
        env_dict = self._fake_envelope_dict("wrong-sender", receiver.entity_id)
        with pytest.raises(ValueError, match="Sender ID mismatch"):
            receiver.open_from(env_dict, sender.public_card(), guard)

    def test_open_from_envelope_object(self):
        """Branch: envelope is an Envelope instance → .to_dict() is called."""
        m, sender, receiver = self._make_two()
        guard = MagicMock()
        guard.window_seconds = 300
        guard.clock_skew     = 5
        env_dict = self._fake_envelope_dict(sender.entity_id, receiver.entity_id)

        fake_env = MagicMock(spec=MOCK_ENVELOPE_CLS)
        fake_env.to_dict.return_value = env_dict

        result = receiver.open_from(fake_env, sender.public_card(), guard)

        fake_env.to_dict.assert_called_once()
        assert result == b"plaintext"

    def test_open_from_dict_object(self):
        """Branch: envelope is a plain dict → no .to_dict() call."""
        m, sender, receiver = self._make_two()
        guard = MagicMock()
        guard.window_seconds = 300
        guard.clock_skew     = 5

        env_dict = self._fake_envelope_dict(sender.entity_id, receiver.entity_id)
        result = receiver.open_from(env_dict, sender.public_card(), guard)

        MOCK_VERIFY.assert_called_once()
        MOCK_DECRYPT_VE.assert_called_once()
        assert result == b"plaintext"

    def test_open_from_calls_replay_guard_precheck_and_commit(self):
        m, sender, receiver = self._make_two()
        guard = MagicMock()
        guard.window_seconds = 300
        guard.clock_skew     = 5

        env_dict = self._fake_envelope_dict(sender.entity_id, receiver.entity_id)
        receiver.open_from(env_dict, sender.public_card(), guard)

        guard.precheck.assert_called_once_with(env_dict)
        guard.commit.assert_called_once_with(env_dict)

    def test_verify_envelope_called_with_correct_args(self):
        m, sender, receiver = self._make_two()
        guard = MagicMock()
        guard.window_seconds = 60
        guard.clock_skew     = 10

        env_dict = self._fake_envelope_dict(sender.entity_id, receiver.entity_id)
        receiver.open_from(env_dict, sender.public_card(), guard)

        MOCK_VERIFY.assert_called_once_with(
            envelope              = env_dict,
            sender_public_keys    = sender.public_card().public_keys,
            expected_recipient_id = receiver.entity_id,
            expected_sender_id    = sender.entity_id,
            max_age_seconds       = 60,
            clock_skew_seconds    = 10,
        )


# ══════════════════════════════════════════════════════════════════
# 8. Identity.save
# ══════════════════════════════════════════════════════════════════

class TestIdentitySave:

    def test_save_creates_file(self, tmp_path):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        path = str(tmp_path / "alice.id")
        ident.save(path, "password123")
        assert os.path.exists(path)

    def test_save_creates_parent_dirs(self, tmp_path):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        deep = str(tmp_path / "a" / "b" / "c" / "alice.id")
        ident.save(deep, "password123")
        assert os.path.exists(deep)

    def test_save_calls_kdf(self, tmp_path):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        ident.save(str(tmp_path / "alice.id"), "secret")
        MOCK_KDF.assert_called()

    def test_save_calls_encrypt(self, tmp_path):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        ident.save(str(tmp_path / "alice.id"), "secret")
        MOCK_SYM_ENCRYPT.assert_called_once()

    def test_save_json_structure(self, tmp_path):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        path = str(tmp_path / "alice.id")
        ident.save(path, "secret")

        with open(path) as f:
            data = json.load(f)

        assert data["version"]    == "UXSP-IDENTITY-1"
        assert data["entity_id"]  == ident.entity_id
        assert data["name"]       == "Alice"
        assert data["role"]       == "ADMIN"
        assert "public_keys"      in data
        assert "encrypted_private" in data
        assert data["encrypted_private"]["associated_data"] == "public-metadata-v1"

    def test_save_tmp_file_cleaned_on_write_error(self, tmp_path, monkeypatch):
        """
        If os.fdopen / json.dump raises, the temp file should be deleted
        and the exception re-raised  (covers the except BaseException branch).
        """
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        path  = str(tmp_path / "alice.id")


        deleted = []

        def boom(*args, **kwargs):
            raise OSError("disk full")

        def track_unlink(p):
            deleted.append(p)

        monkeypatch.setattr(os, "fdopen",  boom)
        monkeypatch.setattr(os, "unlink",  track_unlink)

        with pytest.raises(OSError, match="disk full"):
            ident.save(path, "secret")

        # temp file should have been removed
        assert len(deleted) == 1


# ══════════════════════════════════════════════════════════════════
# 9. Identity.load  — happy path
# ══════════════════════════════════════════════════════════════════

class TestIdentityLoadHappy:

    def _write_payload(self, path, payload):
        with open(path, "w") as f:
            json.dump(payload, f)

    def _good_payload(self, entity_id=None):
        eid = entity_id or str(uuid.uuid4())
        return {
            "version":    "UXSP-IDENTITY-1",
            "entity_id":  eid,
            "name":       "Alice",
            "role":       "ADMIN",
            "created_at": "2024-01-01T00:00:00+00:00",
            "public_keys": _pub_keys_hex(),
            "encrypted_private": {
                "ciphertext":      bytes(16).hex(),
                "nonce":           bytes(12).hex(),
                "kdf_salt":        bytes(16).hex(),
                "associated_data": "public-metadata-v1",
            },
        }

    def test_load_returns_identity(self, tmp_path):
        m = _import()
        payload = self._good_payload()
        path = str(tmp_path / "alice.id")
        self._write_payload(path, payload)

        ident = m.Identity.load(path, "secret")
        assert isinstance(ident, m.Identity)
        assert ident.entity_id == payload["entity_id"]
        assert ident.name == "Alice"
        assert ident.role == "ADMIN"

    def test_load_uses_associated_data_v1_branch(self, tmp_path):
        """associated_data == 'public-metadata-v1' → _identity_associated_data()."""
        m = _import()
        payload = self._good_payload()
        path = str(tmp_path / "alice.id")
        self._write_payload(path, payload)

        MOCK_SYM_DECRYPT.return_value = json.dumps({
            "exchange_priv": bytes(32).hex(),
            "kem_priv":      bytes(32).hex(),
            "signing_priv":  bytes(32).hex(),
            "pqc_sig_priv":  bytes(32).hex(),
        }).encode()

        m.Identity.load(path, "secret")
        # symmetric decrypt should have been called with associated_data bytes
        _, kwargs = MOCK_SYM_DECRYPT.call_args
        assert isinstance(kwargs.get("associated_data") or
                          MOCK_SYM_DECRYPT.call_args[0][2], bytes)

    def test_load_legacy_associated_data_branch(self, tmp_path):
        """associated_data != 'public-metadata-v1' → entity_id.encode() fallback."""
        m = _import()
        payload = self._good_payload()
        payload["encrypted_private"]["associated_data"] = "legacy"
        path = str(tmp_path / "alice.id")
        self._write_payload(path, payload)

        m.Identity.load(path, "secret")
        MOCK_SYM_DECRYPT.assert_called_once()


# ══════════════════════════════════════════════════════════════════
# 10. Identity.load — error paths
# ══════════════════════════════════════════════════════════════════

class TestIdentityLoadErrors:

    def _write(self, tmp_path, payload):
        path = str(tmp_path / "id.json")
        with open(path, "w") as f:
            json.dump(payload, f)
        return path

    def _base(self):
        return {
            "version":    "UXSP-IDENTITY-1",
            "entity_id":  str(uuid.uuid4()),
            "name":       "Alice",
            "role":       "ADMIN",
            "created_at": "2024-01-01T00:00:00+00:00",
            "public_keys": _pub_keys_hex(),
            "encrypted_private": {
                "ciphertext":      bytes(16).hex(),
                "nonce":           bytes(12).hex(),
                "kdf_salt":        bytes(16).hex(),
                "associated_data": "public-metadata-v1",
            },
        }

    def test_wrong_version_raises(self, tmp_path):
        m = _import()
        p = self._base()
        p["version"] = "UXSP-IDENTITY-99"
        path = self._write(tmp_path, p)
        with pytest.raises(ValueError, match="Unknown identity file version"):
            m.Identity.load(path, "secret")

    def test_missing_kdf_salt_raises(self, tmp_path):
        m = _import()
        p = self._base()
        del p["encrypted_private"]["kdf_salt"]
        path = self._write(tmp_path, p)
        with pytest.raises(ValueError, match="invalid encrypted_private metadata"):
            m.Identity.load(path, "secret")

    def test_invalid_kdf_salt_hex_raises(self, tmp_path):
        m = _import()
        p = self._base()
        p["encrypted_private"]["kdf_salt"] = "ZZZZ"
        path = self._write(tmp_path, p)
        with pytest.raises(ValueError, match="invalid encrypted_private metadata"):
            m.Identity.load(path, "secret")

    def test_missing_ciphertext_raises(self, tmp_path):
        m = _import()
        p = self._base()
        del p["encrypted_private"]["ciphertext"]
        path = self._write(tmp_path, p)
        with pytest.raises(ValueError, match="encrypted_private block is malformed"):
            m.Identity.load(path, "secret")

    def test_invalid_ciphertext_hex_raises(self, tmp_path):
        m = _import()
        p = self._base()
        p["encrypted_private"]["ciphertext"] = "ZZZZ"
        path = self._write(tmp_path, p)
        with pytest.raises(ValueError, match="encrypted_private block is malformed"):
            m.Identity.load(path, "secret")

    def test_missing_nonce_raises(self, tmp_path):
        m = _import()
        p = self._base()
        del p["encrypted_private"]["nonce"]
        path = self._write(tmp_path, p)
        with pytest.raises(ValueError, match="encrypted_private block is malformed"):
            m.Identity.load(path, "secret")

    def test_decrypt_failure_raises(self, tmp_path):
        m = _import()
        p = self._base()
        path = self._write(tmp_path, p)
        MOCK_SYM_DECRYPT.side_effect = ValueError("bad tag")
        with pytest.raises(ValueError, match="Wrong password or corrupted file"):
            m.Identity.load(path, "secret")
        MOCK_SYM_DECRYPT.side_effect = None

    def test_malformed_private_json_raises(self, tmp_path):
        m = _import()
        p = self._base()
        path = self._write(tmp_path, p)
        MOCK_SYM_DECRYPT.return_value = b"not-valid-json!!!"
        with pytest.raises(ValueError, match="private key payload is malformed"):
            m.Identity.load(path, "secret")

    def test_malformed_key_material_raises(self, tmp_path):
        """Missing key inside the priv dict → ValueError about malformed key material."""
        m = _import()
        p = self._base()
        path = self._write(tmp_path, p)
        # Return valid JSON but missing required keys
        MOCK_SYM_DECRYPT.return_value = json.dumps({
            "exchange_priv": bytes(32).hex(),
            # kem_priv / signing_priv / pqc_sig_priv intentionally missing
        }).encode()
        with pytest.raises(ValueError, match="malformed key material"):
            m.Identity.load(path, "secret")

    def test_missing_entity_id_for_legacy_branch_raises(self, tmp_path):
        """associated_data == legacy but entity_id key is absent → KeyError → ValueError."""
        m = _import()
        p = self._base()
        p["encrypted_private"]["associated_data"] = "legacy"
        del p["entity_id"]
        path = self._write(tmp_path, p)
        with pytest.raises(ValueError, match="missing required metadata field"):
            m.Identity.load(path, "secret")


# ══════════════════════════════════════════════════════════════════
# 11. Identity.__repr__ and __eq__
# ══════════════════════════════════════════════════════════════════

class TestIdentityUtils:

    def test_repr_contains_name_and_role(self):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        r = repr(ident)
        assert "Alice" in r
        assert "ADMIN" in r
        assert "..." in r

    def test_eq_same_entity_id(self):
        m = _import()
        a = m.Identity.create("Alice", "ADMIN")
        b = m.Identity(a.entity_id, "Other", "USER", _fake_keypair())
        assert a == b

    def test_eq_different_entity_id(self):
        m = _import()
        a = m.Identity.create("Alice", "ADMIN")
        b = m.Identity.create("Bob",   "USER")
        assert a != b

    def test_eq_non_identity_returns_not_implemented(self):
        m = _import()
        ident = m.Identity.create("Alice", "ADMIN")
        result = ident.__eq__("not an identity")
        assert result is NotImplemented


# ══════════════════════════════════════════════════════════════════
# 12. PublicCard.__init__
# ══════════════════════════════════════════════════════════════════

class TestPublicCardInit:

    def test_role_normalised(self):
        m = _import()
        card = m.PublicCard("eid", "Alice", " admin ", _fake_pub_keys(), "2024-01-01")
        assert card.role == "ADMIN"

    def test_attributes_stored(self):
        m = _import()
        pk = _fake_pub_keys()
        card = m.PublicCard("eid", "Alice", "ADMIN", pk, "2024-01-01")
        assert card.entity_id   == "eid"
        assert card.name        == "Alice"
        assert card.public_keys == pk
        assert card.created_at  == "2024-01-01"


# ══════════════════════════════════════════════════════════════════
# 13. PublicCard.to_dict / to_json
# ══════════════════════════════════════════════════════════════════

class TestPublicCardSerialization:

    def _card(self):
        m = _import()
        return m, m.PublicCard("eid-1234", "Alice", "ADMIN", _fake_pub_keys(), "2024-01-01")

    def test_to_dict_version(self):
        m, card = self._card()
        d = card.to_dict()
        assert d["version"]   == "UXSP-PUBCARD-1"
        assert d["entity_id"] == "eid-1234"
        assert d["name"]      == "Alice"
        assert d["role"]      == "ADMIN"

    def test_to_dict_public_keys_are_hex_strings(self):
        m, card = self._card()
        d = card.to_dict()
        for v in d["public_keys"].values():
            assert isinstance(v, str)
            bytes.fromhex(v)  # must not raise

    def test_to_json_is_string(self):
        m, card = self._card()
        j = card.to_json()
        assert isinstance(j, str)
        parsed = json.loads(j)
        assert parsed["name"] == "Alice"


# ══════════════════════════════════════════════════════════════════
# 14. PublicCard.from_dict / from_json
# ══════════════════════════════════════════════════════════════════

class TestPublicCardDeserialization:

    def _dict(self, version="UXSP-PUBCARD-1"):
        return {
            "version":    version,
            "entity_id":  "eid-5678",
            "name":       "Bob",
            "role":       "USER",
            "created_at": "2024-06-01",
            "public_keys": _pub_keys_hex(),
        }

    def test_from_dict_valid(self):
        m = _import()
        card = m.PublicCard.from_dict(self._dict())
        assert card.entity_id == "eid-5678"
        assert card.name      == "Bob"
        assert card.role      == "USER"

    def test_from_dict_none_version_accepted(self):
        """version == None is treated as legacy and accepted."""
        m = _import()
        d = self._dict()
        d["version"] = None
        card = m.PublicCard.from_dict(d)
        assert card.name == "Bob"

    def test_from_dict_unknown_version_raises(self):
        m = _import()
        d = self._dict(version="UXSP-PUBCARD-99")
        with pytest.raises(ValueError, match="Unknown PublicCard version"):
            m.PublicCard.from_dict(d)

    def test_from_dict_public_keys_are_bytes(self):
        m = _import()
        card = m.PublicCard.from_dict(self._dict())
        for v in card.public_keys.values():
            assert isinstance(v, bytes)

    def test_from_json_roundtrip(self):
        m = _import()
        original = m.PublicCard("eid-abc", "Carol", "MOD", _fake_pub_keys(), "2023-12-31")
        j    = original.to_json()
        copy = m.PublicCard.from_json(j)
        assert copy.entity_id  == original.entity_id
        assert copy.name       == original.name
        assert copy.role       == original.role
        assert copy.created_at == original.created_at


# ══════════════════════════════════════════════════════════════════
# 15. PublicCard.__repr__ and __eq__
# ══════════════════════════════════════════════════════════════════

class TestPublicCardUtils:

    def test_repr_contains_name_and_role(self):
        m = _import()
        card = m.PublicCard("eid-abcdef12", "Bob", "USER", _fake_pub_keys(), "2024")
        r = repr(card)
        assert "Bob"  in r
        assert "USER" in r
        assert "..."  in r

    def test_eq_same_entity_id(self):
        m = _import()
        a = m.PublicCard("same-eid", "Alice", "ADMIN", _fake_pub_keys(), "2024")
        b = m.PublicCard("same-eid", "Other", "USER",  _fake_pub_keys(), "2023")
        assert a == b

    def test_eq_different_entity_id(self):
        m = _import()
        a = m.PublicCard("eid-1", "Alice", "ADMIN", _fake_pub_keys(), "2024")
        b = m.PublicCard("eid-2", "Bob",   "USER",  _fake_pub_keys(), "2024")
        assert a != b

    def test_eq_non_public_card_returns_not_implemented(self):
        m = _import()
        card = m.PublicCard("eid", "Alice", "ADMIN", _fake_pub_keys(), "2024")
        result = card.__eq__("not a card")
        assert result is NotImplemented


# ══════════════════════════════════════════════════════════════════
# 16. save → load round-trip  (integration-style)
# ══════════════════════════════════════════════════════════════════

class TestSaveLoadRoundtrip:
    """
    Exercises save() + load() together so every step of the data pipeline
    is exercised end-to-end with consistent mocks.
    """

    def test_roundtrip_preserves_identity_fields(self, tmp_path):
        m = _import()
        original = m.Identity.create("Diana", "ENGINEER")
        path = str(tmp_path / "diana.id")

        # Restore decrypt to return the private keys that save() wrote
        priv_payload = json.dumps({
            "exchange_priv": original.keypair["exchange"]["private_key"].hex(),
            "kem_priv":      original.keypair["kem"]["private_key"].hex(),
            "signing_priv":  original.keypair["signing"]["private_key"].hex(),
            "pqc_sig_priv":  original.keypair["pqc_sig"]["private_key"].hex(),
        }).encode()
        MOCK_SYM_DECRYPT.return_value = priv_payload

        original.save(path, "strongpassword")
        loaded = m.Identity.load(path, "strongpassword")

        assert loaded.entity_id  == original.entity_id
        assert loaded.name       == original.name
        assert loaded.role       == original.role
        assert loaded.created_at == original.created_at


# ══════════════════════════════════════════════════════════════════
# 17. Key Rotation & Expiry / Revocation Tests
# ══════════════════════════════════════════════════════════════════

class TestKeyRotationAndExpiry:

    def test_identity_rotate_keys(self):
        m = _import()
        ident = m.Identity.create("Eve", "DEVELOPER")
        old_id = ident.entity_id
        old_version = ident.key_version
        assert ident.keys_rotated_at is None

        # Change mock return value for new keypair
        new_keypair = {
            "exchange": {"private_key": b"1" * 32, "public_key": b"1" * 32},
            "kem":      {"private_key": b"1" * 32, "public_key": b"1" * 32},
            "signing":  {"private_key": b"1" * 32, "public_key": b"1" * 32},
            "pqc_sig":  {"private_key": b"1" * 32, "public_key": b"1" * 32},
        }
        MOCK_GEN_KEYPAIR.return_value = new_keypair

        rotated = ident.rotate_keys()
        assert rotated.entity_id == old_id
        assert rotated.key_version == old_version + 1
        assert rotated.keys_rotated_at is not None
        assert rotated.keypair == new_keypair

    def test_public_card_expiration(self):
        m = _import()
        ident = m.Identity.create("Frank", "TESTER")
        
        # Valid card with TTL
        card_ttl = ident.public_card(ttl_seconds=3600)
        assert card_ttl.valid_until is not None
        assert not card_ttl.is_expired()

        # Expired card
        past_str = "2020-01-01T00:00:00+00:00"
        card_expired = ident.public_card(valid_until=past_str)
        assert card_expired.is_expired()
        
        with pytest.raises(m.CardExpiredError, match="expired at"):
            card_expired.verify_validity()

    def test_public_card_revocation(self):
        m = _import()
        card = m.PublicCard("eid-123", "Grace", "USER", _fake_pub_keys(), "2024-01-01")
        assert not card.is_revoked
        card.verify_validity()

        card.revoke(reason="Key compromised")
        assert card.is_revoked
        assert card.revocation_reason == "Key compromised"
        assert card.revoked_at is not None

        with pytest.raises(m.CardRevokedError, match="has been revoked"):
            card.verify_validity()

    def test_seal_and_open_validity_check(self):
        m = _import()
        sender = m.Identity.create("Sender", "USER")
        recipient = m.Identity.create("Recipient", "USER")

        expired_card = recipient.public_card(valid_until="2020-01-01T00:00:00+00:00")
        with pytest.raises(m.CardExpiredError):
            sender.seal_for(b"hello", expired_card)

        revoked_card = sender.public_card()
        revoked_card.revoke("compromised")
        with pytest.raises(m.CardRevokedError):
            recipient.open_from({}, revoked_card, MOCK_REPLAY_GUARD)

    def test_card_serialization_preserves_expiry_and_revocation(self):
        m = _import()
        card = m.PublicCard(
            "eid-999", "Heidi", "ADMIN", _fake_pub_keys(), "2024-01-01",
            valid_until="2030-01-01T00:00:00+00:00",
            is_revoked=True,
            revocation_reason="Old key",
            revoked_at="2025-01-01T00:00:00+00:00",
            key_version=3,
        )
        d = card.to_dict()
        assert d["revoked_at"] == "2025-01-01T00:00:00+00:00"
        restored = m.PublicCard.from_dict(d)
        assert restored.valid_until == "2030-01-01T00:00:00+00:00"
        assert restored.is_revoked is True
        assert restored.revocation_reason == "Old key"
        assert restored.revoked_at == "2025-01-01T00:00:00+00:00"
        assert restored.key_version == 3
        assert restored == card

    def test_expiration_and_revocation_edge_cases(self):
        m = _import()
        card = m.PublicCard("eid-1", "A", "USER", _fake_pub_keys(), "2024-01-01", valid_until="2025-01-01T00:00:00")
        
        # Test now as ISO string
        assert card.is_expired(now="2026-01-01T00:00:00")
        assert not card.is_expired(now="2024-06-01T00:00:00")

        # Test now as datetime naive and tz-aware
        now_dt_tz = datetime(2026, 1, 1, tzinfo=UTC)
        assert card.is_expired(now=now_dt_tz)

        now_dt_naive = datetime(2026, 1, 1)
        assert card.is_expired(now=now_dt_naive)

        # Test revoke with datetime objects
        card.revoke(revoked_at=now_dt_tz)
        assert card.revoked_at == now_dt_tz.isoformat()

        card.revoke(revoked_at=now_dt_naive)
        assert card.revoked_at == now_dt_naive.replace(tzinfo=UTC).isoformat()

        card.revoke(revoked_at="custom-time-string")
        assert card.revoked_at == "custom-time-string"


