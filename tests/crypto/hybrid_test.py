"""
Full-coverage pytest suite for hybrid.py
=========================================
Strategy
--------
hybrid.py imports from five sibling modules (.asymmetric, .kdf, .pqc, .symmetric).
We install lightweight fakes for every symbol before the module is imported so
that tests exercise the *logic inside hybrid.py* – not the crypto primitives.

Every branch, every early-return, every exception path is covered.
Run with:
    pytest test_hybrid.py -v --tb=short
"""

from __future__ import annotations

import importlib
import struct
import sys
import time
import types
from unittest.mock import patch

import pytest

# ─────────────────────────────────────────────────────────────
# Fake crypto primitives
# These are honest implementations that satisfy the contracts
# described by hybrid.py (return types, field names, etc.).
# ─────────────────────────────────────────────────────────────

FAKE_CLASSICAL_SECRET = b"\xaa" * 32
FAKE_PQC_SECRET       = b"\xbb" * 32
FAKE_DERIVED_KEY      = b"\xcc" * 32
FAKE_CLASSICAL_SIG    = b"\xdd" * 64
FAKE_PQC_SIG          = b"\xee" * 64
FAKE_CIPHERTEXT       = b"\xff" * 48
FAKE_NONCE            = b"\x11" * 12
FAKE_KEM_CT           = b"\x22" * 32
FAKE_EPHEMERAL_PUB    = b"\x33" * 32
FAKE_EXCHANGE_PUB     = b"\x44" * 32
FAKE_EXCHANGE_PRIV    = b"\x55" * 32
FAKE_SIGNING_PUB      = b"\x66" * 32
FAKE_SIGNING_PRIV     = b"\x77" * 32
FAKE_KEM_PUB          = b"\x88" * 32
FAKE_KEM_PRIV         = b"\x99" * 32
FAKE_SIG_PUB          = b"\xab" * 32
FAKE_SIG_PRIV         = b"\xcd" * 32
FAKE_PLAINTEXT        = b"hello hybrid world"


def _make_asymmetric_mod():
    mod = types.ModuleType("pkg.asymmetric")

    def generate_exchange_keypair():
        return {"public_key": FAKE_EPHEMERAL_PUB, "private_key": FAKE_EXCHANGE_PRIV}

    def generate_signing_keypair():
        return {"public_key": FAKE_SIGNING_PUB, "private_key": FAKE_SIGNING_PRIV}

    def compute_shared_secret(priv, pub):
        return FAKE_CLASSICAL_SECRET

    def sign(message, private_key):
        return FAKE_CLASSICAL_SIG

    def verify(message, sig, pub):
        return True   # default: valid

    mod.generate_exchange_keypair = generate_exchange_keypair
    mod.generate_signing_keypair  = generate_signing_keypair
    mod.compute_shared_secret     = compute_shared_secret
    mod.sign                      = sign
    mod.verify                    = verify
    return mod


def _make_kdf_mod():
    mod = types.ModuleType("pkg.kdf")
    mod.derive_key = lambda ikm, salt, info, length: FAKE_DERIVED_KEY
    return mod


def _make_pqc_mod():
    mod = types.ModuleType("pkg.pqc")

    def generate_kem_keypair():
        return {"public_key": FAKE_KEM_PUB, "private_key": FAKE_KEM_PRIV}

    def generate_sig_keypair():
        return {"public_key": FAKE_SIG_PUB, "private_key": FAKE_SIG_PRIV}

    def encapsulate(kem_pub):
        return {"shared_secret": FAKE_PQC_SECRET, "ciphertext": FAKE_KEM_CT}

    def decapsulate(ct, priv):
        return FAKE_PQC_SECRET

    def pqc_sign(message, priv):
        return FAKE_PQC_SIG

    def pqc_verify(message, sig, pub):
        return True   # default: valid

    mod.generate_kem_keypair = generate_kem_keypair
    mod.generate_sig_keypair = generate_sig_keypair
    mod.encapsulate          = encapsulate
    mod.decapsulate          = decapsulate
    mod.pqc_sign             = pqc_sign
    mod.pqc_verify           = pqc_verify
    return mod


def _make_symmetric_mod():
    mod = types.ModuleType("pkg.symmetric")

    def encrypt(plaintext, key, associated_data=b""):
        return {"ciphertext": FAKE_CIPHERTEXT, "nonce": FAKE_NONCE}

    def decrypt(ciphertext, nonce, key, associated_data=b""):
        return FAKE_PLAINTEXT

    mod.encrypt = encrypt
    mod.decrypt = decrypt
    return mod


# ─────────────────────────────────────────────────────────────
# Module loader
# We install fakes into sys.modules then import hybrid as a
# top-level module (not a package member) so we don't need a
# real package on disk.
# ─────────────────────────────────────────────────────────────

_ASYM_MOD = _make_asymmetric_mod()
_KDF_MOD  = _make_kdf_mod()
_PQC_MOD  = _make_pqc_mod()
_SYM_MOD  = _make_symmetric_mod()

_FAKE_DEPS = {
    "pkg":               types.ModuleType("pkg"),
    "pkg.asymmetric":    _ASYM_MOD,
    "pkg.kdf":           _KDF_MOD,
    "pkg.pqc":           _PQC_MOD,
    "pkg.symmetric":     _SYM_MOD,
}


def _load_hybrid():
    """
    Load hybrid.py as `pkg.hybrid`, injecting fake sibling modules.
    Returns the freshly-imported module object.
    """
    # Remove any stale copy
    for key in list(sys.modules.keys()):
        if "pkg" in key:
            del sys.modules[key]

    for name, mod in _FAKE_DEPS.items():
        sys.modules[name] = mod

    # Read source
    import pathlib
    src = pathlib.Path("uxsp/crypto/hybrid.py").read_text()

    # Patch relative imports → absolute so exec works
    src = src.replace("from .asymmetric import", "from pkg.asymmetric import")
    src = src.replace("from .kdf import",        "from pkg.kdf import")
    src = src.replace("from .pqc import",        "from pkg.pqc import")
    src = src.replace("from .symmetric import",  "from pkg.symmetric import")

    spec    = importlib.util.spec_from_loader("pkg.hybrid", loader=None)
    module  = types.ModuleType("pkg.hybrid")
    module.__spec__ = spec
    exec(compile(src, "uxsp/crypto/hybrid.py", "exec"), module.__dict__)   # noqa: S102
    sys.modules["pkg.hybrid"] = module
    return module


# Load once for the whole session
hybrid = _load_hybrid()

EnvelopeValidationError = hybrid.EnvelopeValidationError


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _make_keypair():
    """Build a minimal keypair dict matching generate_hybrid_keypair()."""
    return {
        "exchange": {"public_key": FAKE_EXCHANGE_PUB,  "private_key": FAKE_EXCHANGE_PRIV},
        "kem":      {"public_key": FAKE_KEM_PUB,       "private_key": FAKE_KEM_PRIV},
        "signing":  {"public_key": FAKE_SIGNING_PUB,   "private_key": FAKE_SIGNING_PRIV},
        "pqc_sig":  {"public_key": FAKE_SIG_PUB,       "private_key": FAKE_SIG_PRIV},
    }


def _make_public_keys(kp=None):
    kp = kp or _make_keypair()
    return hybrid.extract_public_keys(kp)


def _make_valid_envelope(sender_id="alice", recipient_id="bob",
                         ts=None, associated_data=b"") -> dict:
    """Seal a real envelope using all our fakes."""
    sender_kp    = _make_keypair()
    recipient_kp = _make_keypair()
    recip_pub    = _make_public_keys(recipient_kp)
    return hybrid.seal(
        FAKE_PLAINTEXT, sender_kp, recip_pub,
        sender_id, recipient_id,
        associated_data=associated_data,
    ), sender_kp, recipient_kp


# ═════════════════════════════════════════════════════════════
# bind_fields
# ═════════════════════════════════════════════════════════════

class TestBindFields:
    def test_single_field_format(self):
        data   = b"hello"
        result = hybrid.bind_fields(data)
        length = struct.unpack(">I", result[:4])[0]
        assert length == 5
        assert result[4:] == b"hello"

    def test_multiple_fields_concatenated(self):
        result = hybrid.bind_fields(b"abc", b"de")
        # first field: 4-byte length + 3 bytes; second: 4-byte length + 2 bytes
        assert len(result) == 4 + 3 + 4 + 2

    def test_empty_field_allowed(self):
        result = hybrid.bind_fields(b"")
        assert result == b"\x00\x00\x00\x00"

    def test_non_bytes_raises_type_error(self):
        with pytest.raises(TypeError, match="all fields must be bytes"):
            hybrid.bind_fields(b"ok", "not bytes")

    def test_no_fields_returns_empty(self):
        assert hybrid.bind_fields() == b""


# ═════════════════════════════════════════════════════════════
# generate_hybrid_keypair / extract_public_keys
# ═════════════════════════════════════════════════════════════

class TestKeyPairGeneration:
    def test_generate_returns_four_subkeys(self):
        kp = hybrid.generate_hybrid_keypair()
        assert set(kp.keys()) == {"exchange", "kem", "signing", "pqc_sig"}

    def test_extract_public_keys_happy_path(self):
        kp  = _make_keypair()
        pub = hybrid.extract_public_keys(kp)
        assert pub["exchange_pub"] == FAKE_EXCHANGE_PUB
        assert pub["kem_pub"]      == FAKE_KEM_PUB
        assert pub["signing_pub"]  == FAKE_SIGNING_PUB
        assert pub["pqc_sig_pub"]  == FAKE_SIG_PUB

    def test_extract_public_keys_missing_subkey(self):
        kp = _make_keypair()
        del kp["kem"]
        with pytest.raises(ValueError, match="Malformed keypair"):
            hybrid.extract_public_keys(kp)

    def test_extract_public_keys_missing_inner_key(self):
        kp = _make_keypair()
        del kp["exchange"]["public_key"]
        with pytest.raises(ValueError, match="Malformed keypair"):
            hybrid.extract_public_keys(kp)


# ═════════════════════════════════════════════════════════════
# hybrid_sender_exchange / hybrid_recipient_exchange
# ═════════════════════════════════════════════════════════════

class TestHybridKeyExchange:
    def test_sender_exchange_returns_three_keys(self):
        pub    = _make_public_keys()
        result = hybrid.hybrid_sender_exchange(pub)
        assert "shared_key"     in result
        assert "ephemeral_pub"  in result
        assert "kem_ciphertext" in result
        assert len(result["shared_key"]) == 32

    def test_recipient_exchange_matches_derived_key(self):
        kp  = _make_keypair()
        key = hybrid.hybrid_recipient_exchange(
            FAKE_EPHEMERAL_PUB, FAKE_KEM_CT, kp
        )
        assert key == FAKE_DERIVED_KEY

    def test_recipient_exchange_missing_exchange_key(self):
        kp = _make_keypair()
        del kp["exchange"]
        with pytest.raises(ValueError, match="missing required key"):
            hybrid.hybrid_recipient_exchange(FAKE_EPHEMERAL_PUB, FAKE_KEM_CT, kp)

    def test_recipient_exchange_missing_kem_key(self):
        kp = _make_keypair()
        del kp["kem"]
        with pytest.raises(ValueError, match="missing required key"):
            hybrid.hybrid_recipient_exchange(FAKE_EPHEMERAL_PUB, FAKE_KEM_CT, kp)


# ═════════════════════════════════════════════════════════════
# hybrid_sign / hybrid_verify
# ═════════════════════════════════════════════════════════════

class TestHybridSign:
    def test_sign_returns_hex_strings(self):
        kp   = _make_keypair()
        sigs = hybrid.hybrid_sign(b"msg", kp)
        assert isinstance(sigs["classical_sig"], str)
        assert isinstance(sigs["pqc_sig"],       str)
        # valid hex round-trip
        assert bytes.fromhex(sigs["classical_sig"]) == FAKE_CLASSICAL_SIG
        assert bytes.fromhex(sigs["pqc_sig"])       == FAKE_PQC_SIG

    def test_sign_rejects_non_bytes_message(self):
        with pytest.raises(TypeError, match="message must be bytes"):
            hybrid.hybrid_sign("not bytes", _make_keypair())

    def test_sign_missing_signing_key_raises_value_error(self):
        kp = _make_keypair()
        del kp["signing"]
        with pytest.raises(ValueError, match="Signing failed"):
            hybrid.hybrid_sign(b"msg", kp)

    def test_sign_missing_pqc_sig_key_raises_value_error(self):
        kp = _make_keypair()
        del kp["pqc_sig"]
        with pytest.raises(ValueError, match="Signing failed"):
            hybrid.hybrid_sign(b"msg", kp)

    def test_sign_sign_returns_non_bytes_raises_value_error(self):
        """Cover the AttributeError branch: sign() returns None → .hex() fails."""
        kp = _make_keypair()
        with patch.object(hybrid, "sign", return_value=None):
            with pytest.raises(ValueError, match="Signing failed"):
                hybrid.hybrid_sign(b"msg", kp)


class TestHybridVerify:
    def _valid_sigs(self):
        return {
            "classical_sig": FAKE_CLASSICAL_SIG.hex(),
            "pqc_sig":       FAKE_PQC_SIG.hex(),
        }

    def _sender_pub(self):
        return {
            "signing_pub": FAKE_SIGNING_PUB,
            "pqc_sig_pub": FAKE_SIG_PUB,
        }

    def test_verify_returns_true_when_both_valid(self):
        assert hybrid.hybrid_verify(b"msg", self._valid_sigs(), self._sender_pub()) is True

    def test_verify_returns_false_when_classical_fails(self):
        with patch.object(hybrid, "verify", return_value=False):
            result = hybrid.hybrid_verify(b"msg", self._valid_sigs(), self._sender_pub())
        assert result is False

    def test_verify_pqc_result_propagated(self):
        """When classical passes but pqc_verify returns False, overall is False."""
        with patch.object(hybrid, "pqc_verify", return_value=False):
            result = hybrid.hybrid_verify(b"msg", self._valid_sigs(), self._sender_pub())
        assert result is False

    def test_verify_bad_hex_in_classical_sig(self):
        sigs = {"classical_sig": "ZZZZ", "pqc_sig": FAKE_PQC_SIG.hex()}
        with pytest.raises(EnvelopeValidationError, match="invalid hex"):
            hybrid.hybrid_verify(b"msg", sigs, self._sender_pub())

    def test_verify_missing_classical_sig_key(self):
        sigs = {"pqc_sig": FAKE_PQC_SIG.hex()}  # classical_sig missing
        with pytest.raises(EnvelopeValidationError, match="invalid hex"):
            hybrid.hybrid_verify(b"msg", sigs, self._sender_pub())

    def test_verify_missing_sender_signing_pub(self):
        pub = {"pqc_sig_pub": FAKE_SIG_PUB}  # signing_pub missing
        with pytest.raises(EnvelopeValidationError, match="missing required key"):
            hybrid.hybrid_verify(b"msg", self._valid_sigs(), pub)

    def test_verify_missing_sender_pqc_pub(self):
        pub = {"signing_pub": FAKE_SIGNING_PUB}  # pqc_sig_pub missing
        with pytest.raises(EnvelopeValidationError, match="missing required key"):
            hybrid.hybrid_verify(b"msg", self._valid_sigs(), pub)


# ═════════════════════════════════════════════════════════════
# _require_open_context (tested indirectly through verify_envelope)
# ═════════════════════════════════════════════════════════════

def _base_raw_envelope(ts=None):
    """Minimal structurally-valid raw envelope dict."""
    ts = ts or int(time.time())
    return {
        "version":        "UXSP-1",
        "sender_id":      "alice",
        "recipient_id":   "bob",
        "timestamp":      ts,
        "envelope_nonce": "deadbeef",
        "ciphertext":     FAKE_CIPHERTEXT.hex(),
        "nonce":          FAKE_NONCE.hex(),
        "ephemeral_pub":  FAKE_EPHEMERAL_PUB.hex(),
        "kem_ciphertext": FAKE_KEM_CT.hex(),
        "classical_sig":  FAKE_CLASSICAL_SIG.hex(),
        "pqc_sig":        FAKE_PQC_SIG.hex(),
    }


def _sender_pub_keys():
    return {
        "signing_pub": FAKE_SIGNING_PUB,
        "pqc_sig_pub": FAKE_SIG_PUB,
    }


class TestRequireOpenContext:
    """Tests for _require_open_context via verify_envelope."""

    def test_wrong_version_raises(self):
        env = _base_raw_envelope()
        env["version"] = "UXSP-2"
        with pytest.raises(EnvelopeValidationError, match="Unknown envelope version"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_missing_required_field_raises(self):
        for field in ("ciphertext", "nonce", "sender_id", "recipient_id",
                      "timestamp", "envelope_nonce",
                      "ephemeral_pub", "kem_ciphertext",
                      "classical_sig", "pqc_sig"):
            env = _base_raw_envelope()
            del env[field]
            with pytest.raises(EnvelopeValidationError, match=f"'{field}'"):
                hybrid._require_open_context(env, None, 300, 30)

    def test_non_integer_timestamp_raises(self):
        env = _base_raw_envelope()
        env["timestamp"] = "not-a-number"
        with pytest.raises(EnvelopeValidationError, match="Unix integer"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_none_timestamp_raises(self):
        env = _base_raw_envelope()
        env["timestamp"] = None
        with pytest.raises(EnvelopeValidationError, match="Unix integer"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_too_old_envelope_raises(self):
        env = _base_raw_envelope(ts=int(time.time()) - 9999)
        with pytest.raises(EnvelopeValidationError, match="replay attack"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_too_far_future_raises(self):
        env = _base_raw_envelope(ts=int(time.time()) + 9999)
        with pytest.raises(EnvelopeValidationError, match="Clock skew"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_wrong_recipient_id_raises(self):
        env = _base_raw_envelope()
        with pytest.raises(EnvelopeValidationError, match="recipient_id"):
            hybrid._require_open_context(env, "carol", 300, 30)

    def test_correct_recipient_id_passes(self):
        env = _base_raw_envelope()
        ctx = hybrid._require_open_context(env, "bob", 300, 30)
        assert ctx["recipient_id"] == "bob"

    def test_none_recipient_id_skips_check(self):
        env = _base_raw_envelope()
        ctx = hybrid._require_open_context(env, None, 300, 30)
        assert ctx is not None

    def test_empty_sender_id_raises(self):
        env = _base_raw_envelope()
        env["sender_id"] = ""
        with pytest.raises(EnvelopeValidationError, match="sender_id"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_non_str_recipient_id_raises(self):
        env = _base_raw_envelope()
        env["recipient_id"] = 123
        with pytest.raises(EnvelopeValidationError, match="recipient_id"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_empty_envelope_nonce_raises(self):
        env = _base_raw_envelope()
        env["envelope_nonce"] = ""
        with pytest.raises(EnvelopeValidationError, match="envelope_nonce"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_invalid_hex_ciphertext_raises(self):
        env = _base_raw_envelope()
        env["ciphertext"] = "ZZZZ"
        with pytest.raises(EnvelopeValidationError, match="invalid hex"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_invalid_hex_nonce_raises(self):
        env = _base_raw_envelope()
        env["nonce"] = "ZZZZ"
        with pytest.raises(EnvelopeValidationError, match="invalid hex"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_invalid_hex_ephemeral_pub_raises(self):
        env = _base_raw_envelope()
        env["ephemeral_pub"] = "ZZZZ"
        with pytest.raises(EnvelopeValidationError, match="invalid hex"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_invalid_hex_kem_ciphertext_raises(self):
        env = _base_raw_envelope()
        env["kem_ciphertext"] = "ZZZZ"
        with pytest.raises(EnvelopeValidationError, match="invalid hex"):
            hybrid._require_open_context(env, None, 300, 30)

    def test_happy_path_returns_parsed_dict(self):
        env = _base_raw_envelope()
        ctx = hybrid._require_open_context(env, None, 300, 30)
        assert ctx["ciphertext"]     == FAKE_CIPHERTEXT
        assert ctx["nonce"]          == FAKE_NONCE
        assert ctx["ephemeral_pub"]  == FAKE_EPHEMERAL_PUB
        assert ctx["kem_ciphertext"] == FAKE_KEM_CT


# ═════════════════════════════════════════════════════════════
# verify_envelope
# ═════════════════════════════════════════════════════════════

class TestVerifyEnvelope:
    def test_wrong_sender_id_raises(self):
        env = _base_raw_envelope()
        with pytest.raises(EnvelopeValidationError, match="sender identity confusion"):
            hybrid.verify_envelope(
                env, _sender_pub_keys(),
                expected_sender_id="carol"
            )

    def test_correct_sender_id_passes(self):
        env = _base_raw_envelope()
        ctx = hybrid.verify_envelope(env, _sender_pub_keys(), expected_sender_id="alice")
        assert ctx["sender_id"] == "alice"

    def test_none_sender_id_skips_check(self):
        env = _base_raw_envelope()
        ctx = hybrid.verify_envelope(env, _sender_pub_keys(), expected_sender_id=None)
        assert ctx is not None

    def test_signature_failure_raises(self):
        env = _base_raw_envelope()
        with patch.object(hybrid, "verify", return_value=False):
            with pytest.raises(EnvelopeValidationError, match="Signature verification failed"):
                hybrid.verify_envelope(env, _sender_pub_keys())

    def test_valid_envelope_returns_context(self):
        env = _base_raw_envelope()
        ctx = hybrid.verify_envelope(env, _sender_pub_keys())
        assert "ciphertext" in ctx
        assert "nonce"      in ctx


# ═════════════════════════════════════════════════════════════
# decrypt_verified_envelope
# ═════════════════════════════════════════════════════════════

class TestDecryptVerifiedEnvelope:
    def _make_ctx(self):
        return {
            "ephemeral_pub":  FAKE_EPHEMERAL_PUB,
            "kem_ciphertext": FAKE_KEM_CT,
            "ciphertext":     FAKE_CIPHERTEXT,
            "nonce":          FAKE_NONCE,
        }

    def test_returns_plaintext(self):
        kp  = _make_keypair()
        ctx = self._make_ctx()
        result = hybrid.decrypt_verified_envelope(ctx, kp)
        assert result == FAKE_PLAINTEXT

    def test_associated_data_forwarded(self):
        kp  = _make_keypair()
        ctx = self._make_ctx()
        # decrypt is a fake that ignores associated_data, but we call with it
        # to cover the keyword-arg path.
        result = hybrid.decrypt_verified_envelope(ctx, kp, associated_data=b"aad")
        assert result == FAKE_PLAINTEXT


# ═════════════════════════════════════════════════════════════
# seal
# ═════════════════════════════════════════════════════════════

class TestSeal:
    def test_seal_returns_valid_envelope_structure(self):
        sender_kp  = _make_keypair()
        recip_pub  = _make_public_keys()
        env        = hybrid.seal(FAKE_PLAINTEXT, sender_kp, recip_pub, "alice", "bob")
        assert env["version"]    == "UXSP-1"
        assert env["sender_id"]  == "alice"
        assert env["recipient_id"] == "bob"
        for field in ("ciphertext", "nonce", "ephemeral_pub",
                      "kem_ciphertext", "classical_sig", "pqc_sig"):
            assert field in env

    def test_empty_sender_id_raises(self):
        with pytest.raises(ValueError, match="sender_id cannot be empty"):
            hybrid.seal(FAKE_PLAINTEXT, _make_keypair(), _make_public_keys(), "", "bob")

    def test_empty_recipient_id_raises(self):
        with pytest.raises(ValueError, match="recipient_id cannot be empty"):
            hybrid.seal(FAKE_PLAINTEXT, _make_keypair(), _make_public_keys(), "alice", "")

    def test_non_bytes_plaintext_raises(self):
        with pytest.raises(TypeError, match="plaintext must be bytes"):
            hybrid.seal("not bytes", _make_keypair(), _make_public_keys(), "alice", "bob")

    def test_encrypt_returning_non_bytes_ciphertext_raises(self):
        """Cover the isinstance(ct, bytes) guard."""
        def bad_encrypt(pt, key, associated_data=b""):
            return {"ciphertext": "string", "nonce": FAKE_NONCE}

        with patch.object(hybrid, "encrypt", side_effect=bad_encrypt):
            with pytest.raises(TypeError, match="bytes"):
                hybrid.seal(FAKE_PLAINTEXT, _make_keypair(), _make_public_keys(),
                            "alice", "bob")

    def test_encrypt_returning_non_bytes_nonce_raises(self):
        """Cover the isinstance(nonce, bytes) guard."""
        def bad_encrypt(pt, key, associated_data=b""):
            return {"ciphertext": FAKE_CIPHERTEXT, "nonce": "string"}

        with patch.object(hybrid, "encrypt", side_effect=bad_encrypt):
            with pytest.raises(TypeError, match="bytes"):
                hybrid.seal(FAKE_PLAINTEXT, _make_keypair(), _make_public_keys(),
                            "alice", "bob")

    def test_seal_with_associated_data(self):
        sender_kp = _make_keypair()
        recip_pub = _make_public_keys()
        env = hybrid.seal(FAKE_PLAINTEXT, sender_kp, recip_pub,
                          "alice", "bob", associated_data=b"extra")
        assert env["version"] == "UXSP-1"


# ═════════════════════════════════════════════════════════════
# open_seal (full round-trip)
# ═════════════════════════════════════════════════════════════

class TestOpenSeal:
    def _setup(self):
        sender_kp    = _make_keypair()
        recipient_kp = _make_keypair()
        recip_pub    = _make_public_keys(recipient_kp)
        sender_pub   = _make_public_keys(sender_kp)
        env = hybrid.seal(
            FAKE_PLAINTEXT, sender_kp, recip_pub,
            "alice", "bob"
        )
        return env, recipient_kp, sender_pub

    def test_open_seal_returns_plaintext(self):
        env, recip_kp, sender_pub = self._setup()
        result = hybrid.open_seal(env, recip_kp, sender_pub)
        assert result == FAKE_PLAINTEXT

    def test_open_seal_with_expected_ids(self):
        env, recip_kp, sender_pub = self._setup()
        result = hybrid.open_seal(
            env, recip_kp, sender_pub,
            expected_recipient_id="bob",
            expected_sender_id="alice",
        )
        assert result == FAKE_PLAINTEXT

    def test_open_seal_wrong_recipient_raises(self):
        env, recip_kp, sender_pub = self._setup()
        with pytest.raises(EnvelopeValidationError, match="recipient_id"):
            hybrid.open_seal(
                env, recip_kp, sender_pub,
                expected_recipient_id="carol",
            )

    def test_open_seal_wrong_sender_raises(self):
        env, recip_kp, sender_pub = self._setup()
        with pytest.raises(EnvelopeValidationError, match="sender identity confusion"):
            hybrid.open_seal(
                env, recip_kp, sender_pub,
                expected_sender_id="mallory",
            )

    def test_open_seal_tampered_signature_raises(self):
        env, recip_kp, sender_pub = self._setup()
        env["classical_sig"] = FAKE_CLASSICAL_SIG.hex()  # still valid hex
        with patch.object(hybrid, "verify", return_value=False):
            with pytest.raises(EnvelopeValidationError, match="Signature verification failed"):
                hybrid.open_seal(env, recip_kp, sender_pub)

    def test_open_seal_expired_envelope_raises(self):
        env, recip_kp, sender_pub = self._setup()
        env["timestamp"] = int(time.time()) - 9999
        with pytest.raises(EnvelopeValidationError, match="replay attack"):
            hybrid.open_seal(env, recip_kp, sender_pub, max_age_seconds=300)

    def test_open_seal_with_associated_data(self):
        sender_kp    = _make_keypair()
        recipient_kp = _make_keypair()
        recip_pub    = _make_public_keys(recipient_kp)
        sender_pub   = _make_public_keys(sender_kp)
        aad = b"some-associated-data"
        env = hybrid.seal(FAKE_PLAINTEXT, sender_kp, recip_pub,
                          "alice", "bob", associated_data=aad)
        result = hybrid.open_seal(env, recipient_kp, sender_pub,
                                  associated_data=aad)
        assert result == FAKE_PLAINTEXT

    def test_open_seal_custom_max_age(self):
        """Cover the max_age_seconds / clock_skew_seconds forwarding path."""
        env, recip_kp, sender_pub = self._setup()
        # Should pass with a large window
        result = hybrid.open_seal(env, recip_kp, sender_pub,
                                  max_age_seconds=3600,
                                  clock_skew_seconds=60)
        assert result == FAKE_PLAINTEXT


# ═════════════════════════════════════════════════════════════
# EnvelopeValidationError (class itself)
# ═════════════════════════════════════════════════════════════

class TestEnvelopeValidationError:
    def test_is_value_error(self):
        err = EnvelopeValidationError("test")
        assert isinstance(err, ValueError)

    def test_message_preserved(self):
        err = EnvelopeValidationError("something went wrong")
        assert "something went wrong" in str(err)

    def test_can_be_caught_as_value_error(self):
        with pytest.raises(ValueError):
            raise EnvelopeValidationError("caught as ValueError")
