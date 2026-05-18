"""
Full-coverage pytest suite for signing.py

Strategy
--------
* All external collaborators (Identity, PublicCard, hybrid_sign, hybrid_verify,
  bind_fields, EnvelopeValidationError) are mocked so tests are self-contained.
* Every branch in every method is exercised explicitly.
* Helper factories create lightweight fakes that mirror the real contracts.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import types
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# BUILD FAKE MODULES so `import signing` works without the real uxsp package
# ─────────────────────────────────────────────────────────────────────────────

# --- EnvelopeValidationError (real exception class needed for isinstance) ---
class EnvelopeValidationError(Exception):
    pass


def _make_public_card(entity_id: str = "eid-abc",
                      name: str = "Alice",
                      role: str = "USER",
                      created_at: str = "2024-01-01T00:00:00Z",
                      public_keys: dict | None = None) -> MagicMock:
    """Return a MagicMock that quacks like PublicCard."""
    card = MagicMock()
    card.entity_id  = entity_id
    card.name       = name
    card.role       = role
    card.created_at = created_at
    card.public_keys = public_keys or {
        "exchange_pub": b"xpub",
        "kem_pub":      b"kpub",
        "signing_pub":  b"spub",
        "pqc_sig_pub":  b"ppub",
    }
    card.to_dict.return_value = {
        "entity_id":   entity_id,
        "name":        name,
        "role":        role,
        "created_at":  created_at,
        "public_keys": {k: v.hex() for k, v in card.public_keys.items()},
    }
    return card


def _make_identity(entity_id: str = "anchor-001",
                   name: str = "Root CA",
                   public_card: MagicMock | None = None) -> MagicMock:
    identity = MagicMock()
    identity.entity_id  = entity_id
    identity.name       = name
    identity.created_at = "2024-01-01T00:00:00Z"
    identity.keypair    = MagicMock()
    pc = public_card or _make_public_card(entity_id=entity_id, name=name, role="TRUST-ANCHOR")
    identity.public_card.return_value = pc
    return identity


# Synthetic return value for hybrid_sign
_FAKE_SIGS = {
    "classical_sig": "deadbeef",
    "pqc_sig":       "cafebabe",
}

_FAKE_SIGNABLE = b"signable-bytes"


import uxsp.crypto.hybrid

# Define our own EnvelopeValidationError if it's missing (it shouldn't be)
EnvelopeValidationError = uxsp.crypto.hybrid.EnvelopeValidationError

class _MockHybridModule:
    """A helper object to hold the mock references and automatically patch uxsp.crypto.hybrid."""
    def __init__(self):
        self.bind_fields = MagicMock(return_value=_FAKE_SIGNABLE)
        self.hybrid_sign = MagicMock(return_value=_FAKE_SIGS)
        self.hybrid_verify = MagicMock(return_value=True)
        self.EnvelopeValidationError = EnvelopeValidationError

_HYBRID = _MockHybridModule()

# We patch the functions in the real uxsp.core.signing module directly
_patch_bind_fields = patch("uxsp.core.signing.bind_fields", _HYBRID.bind_fields)
_patch_hybrid_sign = patch("uxsp.core.signing.hybrid_sign", _HYBRID.hybrid_sign)
_patch_hybrid_verify = patch("uxsp.core.signing.hybrid_verify", _HYBRID.hybrid_verify)
_patch_bind_fields.start()
_patch_hybrid_sign.start()
_patch_hybrid_verify.start()


# Now safe to import
from uxsp.core.signing import (
    CardNotYetValidError,
    ExpiredCardError,
    InvalidCardSignatureError,
    PublicAnchor,
    SignedCard,
    SigningError,
    TrustAnchor,
    TrustStore,
    UntrustedCardError,
    _card_signable,
    _lock_exclusive,
    _lock_release,
)

# ─────────────────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

NOW = int(time.time())
PAST  = NOW - 100
FAR_PAST  = NOW - 100_000
FAR_FUTURE = NOW + 100_000


def _public_anchor(anchor_id: str = "anchor-001",
                   name: str = "Root CA",
                   public_keys: dict | None = None) -> PublicAnchor:
    return PublicAnchor(
        anchor_id   = anchor_id,
        name        = name,
        public_keys = public_keys or {"key": b"\x01\x02"},
        created_at  = "2024-01-01T00:00:00Z",
    )


def _signed_card(issuer_id: str = "anchor-001",
                 not_before: int = FAR_PAST,
                 not_after:  int = FAR_FUTURE,
                 card: MagicMock | None = None) -> SignedCard:
    c = card or _make_public_card()
    return SignedCard(
        card          = c,
        cert_id       = str(uuid.uuid4()),
        issuer_id     = issuer_id,
        issuer_name   = "Root CA",
        not_before    = not_before,
        not_after     = not_after,
        classical_sig = bytes.fromhex(_FAKE_SIGS["classical_sig"]),
        pqc_sig       = bytes.fromhex(_FAKE_SIGS["pqc_sig"]),
    )


# ─────────────────────────────────────────────────────────────────────────────
# EXCEPTION HIERARCHY
# ─────────────────────────────────────────────────────────────────────────────

class TestExceptionHierarchy:
    def test_signing_error_is_exception(self):
        assert issubclass(SigningError, Exception)

    def test_untrusted_card_error_is_signing_error(self):
        assert issubclass(UntrustedCardError, SigningError)

    def test_invalid_card_signature_error_is_signing_error(self):
        assert issubclass(InvalidCardSignatureError, SigningError)

    def test_expired_card_error_is_signing_error(self):
        assert issubclass(ExpiredCardError, SigningError)

    def test_card_not_yet_valid_error_is_signing_error(self):
        assert issubclass(CardNotYetValidError, SigningError)

    def test_raise_untrusted_card_error(self):
        with pytest.raises(UntrustedCardError):
            raise UntrustedCardError("bad issuer")

    def test_raise_invalid_card_signature_error(self):
        with pytest.raises(InvalidCardSignatureError):
            raise InvalidCardSignatureError("bad sig")

    def test_raise_expired_card_error(self):
        with pytest.raises(ExpiredCardError):
            raise ExpiredCardError("expired")

    def test_raise_card_not_yet_valid_error(self):
        with pytest.raises(CardNotYetValidError):
            raise CardNotYetValidError("future")


# ─────────────────────────────────────────────────────────────────────────────
# TrustAnchor
# ─────────────────────────────────────────────────────────────────────────────

class TestTrustAnchor:

    def _make_anchor(self, entity_id="anchor-001", name="Root CA"):
        identity = _make_identity(entity_id=entity_id, name=name)
        signing.Identity = MagicMock(return_value=identity)
        with patch("uxsp.core.signing.Identity") as MockId:
            MockId.create.return_value = identity
            TrustAnchor.create(name)
        # rebuild with the identity we control
        return TrustAnchor(identity), identity

    def test_create_calls_identity_create(self):
        identity = _make_identity()
        with patch("uxsp.core.signing.Identity") as MockId:
            MockId.create.return_value = identity
            anchor = TrustAnchor.create("Root CA")
        MockId.create.assert_called_once_with("Root CA", "TRUST-ANCHOR")
        assert isinstance(anchor, TrustAnchor)

    def test_save_delegates_to_identity(self):
        identity = _make_identity()
        anchor = TrustAnchor(identity)
        anchor.save("/some/path", "secret")
        identity.save.assert_called_once_with("/some/path", "secret")

    def test_load_returns_trust_anchor(self):
        identity = _make_identity()
        with patch("uxsp.core.signing.Identity") as MockId:
            MockId.load.return_value = identity
            anchor = TrustAnchor.load("/path/to/file", "pw")
        MockId.load.assert_called_once_with("/path/to/file", "pw")
        assert isinstance(anchor, TrustAnchor)

    def test_public_anchor_returns_correct_object(self):
        identity = _make_identity(entity_id="eid-x", name="CA-X")
        pc = _make_public_card(entity_id="eid-x", name="CA-X")
        pc.public_keys = {"signing_pub": b"\xaa"}
        identity.public_card.return_value = pc
        anchor = TrustAnchor(identity)
        pa = anchor.public_anchor()
        assert isinstance(pa, PublicAnchor)
        assert pa.anchor_id  == "eid-x"
        assert pa.name       == "CA-X"
        assert pa.public_keys == {"signing_pub": b"\xaa"}

    def test_issue_returns_signed_card(self):
        identity = _make_identity()
        anchor = TrustAnchor(identity)
        card = _make_public_card()
        _HYBRID.hybrid_sign.return_value = _FAKE_SIGS
        _HYBRID.bind_fields.return_value = _FAKE_SIGNABLE

        sc = anchor.issue(card, validity_days=30)

        assert isinstance(sc, SignedCard)
        assert sc.issuer_id   == identity.entity_id
        assert sc.issuer_name == identity.name
        assert sc.classical_sig == bytes.fromhex(_FAKE_SIGS["classical_sig"])
        assert sc.pqc_sig       == bytes.fromhex(_FAKE_SIGS["pqc_sig"])

    def test_issue_respects_not_before_override(self):
        identity = _make_identity()
        anchor = TrustAnchor(identity)
        card = _make_public_card()
        nb = NOW - 500
        sc = anchor.issue(card, validity_days=1, not_before=nb)
        assert sc.not_before == nb
        assert sc.not_after  == nb + 86400

    def test_issue_uses_current_time_when_not_before_is_none(self):
        identity = _make_identity()
        anchor = TrustAnchor(identity)
        card = _make_public_card()
        before = int(time.time())
        sc = anchor.issue(card, validity_days=1)
        after = int(time.time())
        assert before <= sc.not_before <= after

    def test_issue_raises_for_zero_validity(self):
        identity = _make_identity()
        anchor = TrustAnchor(identity)
        with pytest.raises(ValueError, match="must be positive"):
            anchor.issue(_make_public_card(), validity_days=0)

    def test_issue_raises_for_negative_validity(self):
        identity = _make_identity()
        anchor = TrustAnchor(identity)
        with pytest.raises(ValueError, match="must be positive"):
            anchor.issue(_make_public_card(), validity_days=-1)

    def test_issue_raises_for_excessive_validity(self):
        identity = _make_identity()
        anchor = TrustAnchor(identity)
        with pytest.raises(ValueError, match="cannot exceed 730"):
            anchor.issue(_make_public_card(), validity_days=731)

    def test_issue_accepts_max_valid_days(self):
        identity = _make_identity()
        anchor = TrustAnchor(identity)
        # 730 is the boundary — should NOT raise
        sc = anchor.issue(_make_public_card(), validity_days=730)
        assert sc.not_after - sc.not_before == 730 * 86400

    def test_entity_id_property(self):
        identity = _make_identity(entity_id="test-id")
        anchor = TrustAnchor(identity)
        assert anchor.entity_id == "test-id"

    def test_name_property(self):
        identity = _make_identity(name="My CA")
        anchor = TrustAnchor(identity)
        assert anchor.name == "My CA"

    def test_repr(self):
        identity = _make_identity(entity_id="abcdefghijk", name="CA")
        anchor = TrustAnchor(identity)
        r = repr(anchor)
        assert "TrustAnchor" in r
        assert "abcdefgh" in r  # first 8 chars
        assert "CA" in r


# ─────────────────────────────────────────────────────────────────────────────
# PublicAnchor
# ─────────────────────────────────────────────────────────────────────────────

class TestPublicAnchor:

    def _anchor(self, **kw) -> PublicAnchor:
        defaults = {
            "anchor_id": "anchor-001",
            "name": "Root CA",
            "public_keys": {"key": b"\x01\x02"},
            "created_at": "2024-01-01T00:00:00Z",
        }
        defaults.update(kw)
        return PublicAnchor(**defaults)

    def test_to_dict_hex_encodes_keys(self):
        anchor = self._anchor(public_keys={"k": b"\xde\xad"})
        d = anchor.to_dict()
        assert d["public_keys"]["k"] == "dead"
        assert d["anchor_id"] == "anchor-001"
        assert d["name"]      == "Root CA"
        assert d["created_at"] == "2024-01-01T00:00:00Z"

    def test_to_json_is_valid_json(self):
        anchor = self._anchor()
        data = json.loads(anchor.to_json())
        assert data["anchor_id"] == "anchor-001"

    def test_from_dict_roundtrip(self):
        anchor = self._anchor(public_keys={"k": b"\xca\xfe"})
        anchor2 = PublicAnchor.from_dict(anchor.to_dict())
        assert anchor2.anchor_id   == anchor.anchor_id
        assert anchor2.name        == anchor.name
        assert anchor2.created_at  == anchor.created_at
        assert anchor2.public_keys == anchor.public_keys

    def test_from_json_roundtrip(self):
        anchor = self._anchor(public_keys={"k": b"\xbe\xef"})
        anchor2 = PublicAnchor.from_json(anchor.to_json())
        assert anchor2.anchor_id == anchor.anchor_id

    def test_repr(self):
        anchor = self._anchor(anchor_id="abcdefghijkl", name="MyCA")
        r = repr(anchor)
        assert "PublicAnchor" in r
        assert "abcdefgh" in r

    def test_eq_same_anchor_id(self):
        a1 = self._anchor(anchor_id="x")
        a2 = self._anchor(anchor_id="x")
        assert a1 == a2

    def test_eq_different_anchor_id(self):
        a1 = self._anchor(anchor_id="x")
        a2 = self._anchor(anchor_id="y")
        assert a1 != a2

    def test_eq_non_anchor_object(self):
        anchor = self._anchor()
        assert anchor != "not_an_anchor"

    def test_hash_consistency(self):
        anchor = self._anchor(anchor_id="abc")
        assert hash(anchor) == hash("abc")

    def test_usable_in_set(self):
        a1 = self._anchor(anchor_id="x")
        a2 = self._anchor(anchor_id="x")
        assert len({a1, a2}) == 1


# ─────────────────────────────────────────────────────────────────────────────
# SignedCard
# ─────────────────────────────────────────────────────────────────────────────

class TestSignedCard:

    def _sc(self, **kw) -> SignedCard:
        defaults = {
            "card": _make_public_card(),
            "cert_id": "cert-1234",
            "issuer_id": "anchor-001",
            "issuer_name": "Root CA",
            "not_before": FAR_PAST,
            "not_after": FAR_FUTURE,
            "classical_sig": b"\xde\xad",
            "pqc_sig": b"\xca\xfe",
        }
        defaults.update(kw)
        return SignedCard(**defaults)

    # --- is_time_valid ---

    def test_is_time_valid_within_window(self):
        sc = self._sc(not_before=NOW - 10, not_after=NOW + 10)
        assert sc.is_time_valid(now=NOW) is True

    def test_is_time_valid_before_window(self):
        sc = self._sc(not_before=NOW + 100, not_after=NOW + 200)
        assert sc.is_time_valid(now=NOW) is False

    def test_is_time_valid_after_window(self):
        sc = self._sc(not_before=NOW - 200, not_after=NOW - 100)
        assert sc.is_time_valid(now=NOW) is False

    def test_is_time_valid_uses_real_time_when_now_is_none(self):
        sc = self._sc(not_before=FAR_PAST, not_after=FAR_FUTURE)
        assert sc.is_time_valid() is True

    def test_is_time_valid_at_boundary_not_before(self):
        sc = self._sc(not_before=NOW, not_after=NOW + 100)
        assert sc.is_time_valid(now=NOW) is True

    def test_is_time_valid_at_boundary_not_after(self):
        sc = self._sc(not_before=NOW - 100, not_after=NOW)
        assert sc.is_time_valid(now=NOW) is True

    # --- check_time_validity ---

    def test_check_time_validity_ok(self):
        sc = self._sc()
        sc.check_time_validity(now=NOW)   # no exception

    def test_check_time_validity_raises_not_yet_valid(self):
        sc = self._sc(not_before=NOW + 1000, not_after=NOW + 2000)
        with pytest.raises(CardNotYetValidError, match="not yet valid"):
            sc.check_time_validity(now=NOW)

    def test_check_time_validity_raises_expired(self):
        sc = self._sc(not_before=FAR_PAST, not_after=NOW - 1)
        with pytest.raises(ExpiredCardError, match="expired"):
            sc.check_time_validity(now=NOW)

    def test_check_time_validity_uses_real_time_when_now_is_none(self):
        sc = self._sc()
        sc.check_time_validity()   # should not raise

    # --- remaining_seconds / remaining_days ---

    def test_remaining_seconds_positive(self):
        sc = self._sc(not_after=int(time.time()) + 3600)
        assert sc.remaining_seconds > 0

    def test_remaining_seconds_zero_when_expired(self):
        sc = self._sc(not_after=int(time.time()) - 100)
        assert sc.remaining_seconds == 0.0

    def test_remaining_days(self):
        sc = self._sc(not_after=int(time.time()) + 86400)
        # should be approximately 1.0
        assert 0.99 < sc.remaining_days < 1.01

    # --- serialisation ---

    def test_to_dict_contains_expected_keys(self):
        sc = self._sc()
        d = sc.to_dict()
        for key in ("cert_id", "issuer_id", "issuer_name",
                    "not_before", "not_after", "classical_sig", "pqc_sig", "card"):
            assert key in d

    def test_to_dict_hex_encodes_sigs(self):
        sc = self._sc(classical_sig=b"\xde\xad", pqc_sig=b"\xca\xfe")
        d = sc.to_dict()
        assert d["classical_sig"] == "dead"
        assert d["pqc_sig"]       == "cafe"

    def test_to_json_no_indent(self):
        sc = self._sc()
        j = sc.to_json()
        assert json.loads(j)["cert_id"] == "cert-1234"

    def test_to_json_with_indent(self):
        sc = self._sc()
        j = sc.to_json(indent=2)
        assert "\n" in j

    def test_from_dict_roundtrip(self):
        original = self._sc(cert_id="cert-xyz")
        d = original.to_dict()
        # PublicCard.from_dict must return a mock — patch it
        with patch("uxsp.core.signing.PublicCard") as MockPC:
            MockPC.from_dict.return_value = original.card
            restored = SignedCard.from_dict(d)
        assert restored.cert_id       == "cert-xyz"
        assert restored.issuer_id     == original.issuer_id
        assert restored.classical_sig == original.classical_sig
        assert restored.pqc_sig       == original.pqc_sig

    def test_from_json_roundtrip(self):
        original = self._sc(cert_id="cert-json")
        j = original.to_json()
        with patch("uxsp.core.signing.PublicCard") as MockPC:
            MockPC.from_dict.return_value = original.card
            restored = SignedCard.from_json(j)
        assert restored.cert_id == "cert-json"

    # --- repr / eq / hash ---

    def test_repr(self):
        sc = self._sc()
        r = repr(sc)
        assert "SignedCard" in r
        assert "Root CA" in r

    def test_eq_same_cert_id(self):
        sc1 = self._sc(cert_id="abc")
        sc2 = self._sc(cert_id="abc")
        assert sc1 == sc2

    def test_eq_different_cert_id(self):
        sc1 = self._sc(cert_id="abc")
        sc2 = self._sc(cert_id="xyz")
        assert sc1 != sc2

    def test_eq_non_signed_card_object(self):
        sc = self._sc()
        assert sc != "not a card"

    def test_hash_consistency(self):
        sc = self._sc(cert_id="cert-hash")
        assert hash(sc) == hash("cert-hash")

    def test_usable_in_set(self):
        sc1 = self._sc(cert_id="same")
        sc2 = self._sc(cert_id="same")
        assert len({sc1, sc2}) == 1


class TestSigningWin32LockBranch:
    """Cover lines 23-32 of signing.py (msvcrt path)."""

    def test_win32_lock_helpers_execute(self, monkeypatch, tmp_path):
        """
        Patch sys.platform to 'win32' and reload signing so the else-branch
        that defines _lock_exclusive / _lock_release via msvcrt runs.
        We then call the helpers through a lightweight file handle mock so
        no actual msvcrt calls are made (they would fail on POSIX).
        """
        # Build a fake msvcrt module
        fake_msvcrt = types.ModuleType("msvcrt")
        fake_msvcrt.LK_LOCK   = 2
        fake_msvcrt.LK_UNLCK  = 0

        lock_calls: list[str] = []

        def _locking(fd, mode, nbytes):
            lock_calls.append(("locking", fd, mode, nbytes))

        fake_msvcrt.locking = _locking

        # Fake file handle
        fh = MagicMock()
        fh.fileno.return_value = 3

        # Reload signing with win32 platform + fake msvcrt
        orig_platform = sys.platform
        orig_msvcrt   = sys.modules.get("msvcrt")
        orig_signing  = sys.modules.pop("uxsp.core.signing", None)

        try:
            sys.platform = "win32"
            sys.modules["msvcrt"] = fake_msvcrt

            import uxsp.core.signing as signing_mod

            # Exercise both helpers
            signing_mod._lock_exclusive(fh)
            signing_mod._lock_release(fh)

            # Verify seek and locking were called
            assert fh.seek.call_count >= 2
            assert len(lock_calls) == 2
            assert lock_calls[0][2] == fake_msvcrt.LK_LOCK
            assert lock_calls[1][2] == fake_msvcrt.LK_UNLCK
        finally:
            sys.platform = orig_platform
            sys.modules.pop("uxsp.core.signing", None)
            if orig_signing is not None:
                sys.modules["uxsp.core.signing"] = orig_signing
            if orig_msvcrt is None:
                sys.modules.pop("msvcrt", None)
            else:
                sys.modules["msvcrt"] = orig_msvcrt
            # Restore the real signing module
            import uxsp.core.signing  # noqa: F401


# ─────────────────────────────────────────────────────────────────────────────
# TrustStore
# ─────────────────────────────────────────────────────────────────────────────

class TestTrustStore:

    def _store_with_anchor(self, anchor_id="anchor-001") -> tuple[TrustStore, PublicAnchor]:
        store = TrustStore()
        pa = _public_anchor(anchor_id=anchor_id)
        store.add(pa)
        return store, pa

    # --- add / remove / has / anchor_ids ---

    def test_add_and_has(self):
        store, pa = self._store_with_anchor()
        assert store.has(pa.anchor_id)

    def test_remove_existing(self):
        store, pa = self._store_with_anchor()
        store.remove(pa.anchor_id)
        assert not store.has(pa.anchor_id)

    def test_remove_nonexistent_does_not_raise(self):
        store = TrustStore()
        store.remove("nonexistent")   # should be silent

    def test_has_returns_false_for_unknown(self):
        store = TrustStore()
        assert not store.has("unknown-id")

    def test_anchor_ids(self):
        store, pa = self._store_with_anchor("id-1")
        assert "id-1" in store.anchor_ids

    def test_len(self):
        store = TrustStore()
        assert len(store) == 0
        store.add(_public_anchor("a"))
        store.add(_public_anchor("b"))
        assert len(store) == 2

    def test_repr(self):
        store, _ = self._store_with_anchor()
        r = repr(store)
        assert "TrustStore" in r

    # --- from_anchors ---

    def test_from_anchors(self):
        a1 = _public_anchor("a1")
        a2 = _public_anchor("a2")
        store = TrustStore.from_anchors(a1, a2)
        assert store.has("a1")
        assert store.has("a2")
        assert len(store) == 2

    # --- verify: UntrustedCardError (unknown issuer) ---

    def test_verify_raises_untrusted_card_error_when_issuer_unknown(self):
        store = TrustStore()
        sc = _signed_card(issuer_id="unknown-anchor")
        with pytest.raises(UntrustedCardError, match="not in the trust store"):
            store.verify(sc)

    # --- verify: entity_id mismatch ---

    def test_verify_raises_when_entity_id_does_not_match(self):
        store, pa = self._store_with_anchor("anchor-001")
        pa.public_keys = {
            "signing_pub": b"sp", "exchange_pub": b"ep",
            "kem_pub": b"kp", "pqc_sig_pub": b"pp",
        }
        card = _make_public_card(entity_id="entity-A")
        sc = _signed_card(issuer_id="anchor-001", card=card)
        with pytest.raises(UntrustedCardError, match="does not match expected"):
            store.verify(sc, expected_entity_id="entity-B")

    # --- verify: time checks delegated ---

    def test_verify_raises_expired_card_error(self):
        store, pa = self._store_with_anchor("anchor-001")
        pa.public_keys = {"k": b"\x01"}
        sc = _signed_card(issuer_id="anchor-001",
                          not_before=FAR_PAST,
                          not_after=NOW - 10)
        with pytest.raises(ExpiredCardError):
            store.verify(sc, now=NOW)

    def test_verify_raises_card_not_yet_valid(self):
        store, pa = self._store_with_anchor("anchor-001")
        pa.public_keys = {"k": b"\x01"}
        sc = _signed_card(issuer_id="anchor-001",
                          not_before=NOW + 1000,
                          not_after=NOW + 2000)
        with pytest.raises(CardNotYetValidError):
            store.verify(sc, now=NOW)

    # --- verify: EnvelopeValidationError -> InvalidCardSignatureError ---

    def test_verify_wraps_envelope_validation_error(self):
        store, pa = self._store_with_anchor("anchor-001")
        pa.public_keys = {"k": b"\x01"}
        sc = _signed_card(issuer_id="anchor-001")
        _HYBRID.bind_fields.return_value = _FAKE_SIGNABLE
        _HYBRID.hybrid_verify.side_effect = EnvelopeValidationError("bad envelope")

        with pytest.raises(InvalidCardSignatureError, match="malformed"):
            store.verify(sc, now=NOW)

        _HYBRID.hybrid_verify.side_effect = None  # reset

    # --- verify: hybrid_verify returns False ---

    def test_verify_raises_when_signature_check_fails(self):
        store, pa = self._store_with_anchor("anchor-001")
        pa.public_keys = {"k": b"\x01"}
        sc = _signed_card(issuer_id="anchor-001")
        _HYBRID.bind_fields.return_value = _FAKE_SIGNABLE
        _HYBRID.hybrid_verify.return_value = False

        with pytest.raises(InvalidCardSignatureError, match="tampered"):
            store.verify(sc, now=NOW)

        _HYBRID.hybrid_verify.return_value = True  # reset

    # --- verify: happy path ---

    def test_verify_happy_path_returns_public_card(self):
        store, pa = self._store_with_anchor("anchor-001")
        pa.public_keys = {"k": b"\x01"}
        card = _make_public_card(entity_id="entity-A")
        sc = _signed_card(issuer_id="anchor-001", card=card)
        _HYBRID.bind_fields.return_value = _FAKE_SIGNABLE
        _HYBRID.hybrid_verify.return_value = True

        result = store.verify(sc, now=NOW)
        assert result is card

    def test_verify_happy_path_with_matching_entity_id(self):
        store, pa = self._store_with_anchor("anchor-001")
        pa.public_keys = {"k": b"\x01"}
        card = _make_public_card(entity_id="entity-A")
        sc = _signed_card(issuer_id="anchor-001", card=card)
        _HYBRID.hybrid_verify.return_value = True

        result = store.verify(sc, now=NOW, expected_entity_id="entity-A")
        assert result is card

    # --- serialisation ---

    def test_to_dict_structure(self):
        store, _ = self._store_with_anchor()
        d = store.to_dict()
        assert "anchors" in d
        assert isinstance(d["anchors"], list)

    def test_to_json_is_valid_json(self):
        store, _ = self._store_with_anchor()
        j = store.to_json()
        data = json.loads(j)
        assert "anchors" in data

    # --- save / load ---

    def test_save_and_load_roundtrip(self):
        store, pa = self._store_with_anchor("anchor-save")
        pa.public_keys = {"signing_pub": b"\xab\xcd"}

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "trust_store.json")
            store.save(path)

            # from_dict is called during load; patch PublicAnchor.from_dict
            with patch("uxsp.core.signing.PublicAnchor") as MockPA:
                MockPA.from_dict.return_value = pa
                TrustStore.load(path)

            MockPA.from_dict.assert_called_once()

    def test_save_creates_parent_dirs(self):
        store = TrustStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "deep", "sub", "ts.json")
            store.save(path)
            assert os.path.exists(path)

    def test_load_raises_for_non_dict_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as f:
            f.write(json.dumps([1, 2, 3]))
            path = f.name
        try:
            with pytest.raises(ValueError, match="must contain a JSON object"):
                TrustStore.load(path)
        finally:
            os.unlink(path)

    def test_load_empty_anchors_list(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                         delete=False) as f:
            f.write(json.dumps({"anchors": []}))
            path = f.name
        try:
            store = TrustStore.load(path)
            assert len(store) == 0
        finally:
            os.unlink(path)

    def test_save_cleans_up_tmp_on_write_error(self):
        """If the atomic write fails, the temp file must be removed."""
        store = TrustStore()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "ts.json")
            with patch("os.replace", side_effect=OSError("disk full")):
                with pytest.raises(OSError, match="disk full"):
                    store.save(path)
            # tmp file should have been cleaned up
            leftovers = list(Path(tmpdir).glob("tmp*"))
            assert len(leftovers) == 0

    # --- thread safety smoke test ---

    def test_concurrent_add_and_remove(self):
        import threading
        store = TrustStore()
        errors = []

        def add_remove():
            try:
                pa = _public_anchor(anchor_id=str(uuid.uuid4()))
                store.add(pa)
                store.remove(pa.anchor_id)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=add_remove) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []


# ─────────────────────────────────────────────────────────────────────────────
# _card_signable
# ─────────────────────────────────────────────────────────────────────────────

class TestCardSignable:

    def test_calls_bind_fields_with_correct_arguments(self):
        card = _make_public_card(
            entity_id  = "eid",
            name       = "Bob",
            role       = "USER",
            created_at = "2024-01-01T00:00:00Z",
            public_keys = {
                "exchange_pub": b"ep",
                "kem_pub":      b"kp",
                "signing_pub":  b"sp",
                "pqc_sig_pub":  b"pp",
            },
        )
        _HYBRID.bind_fields.reset_mock()
        _HYBRID.bind_fields.return_value = b"result"

        result = _card_signable(card, not_before=100, not_after=200, cert_id="cid")

        assert result == b"result"
        _HYBRID.bind_fields.assert_called_once_with(
            b"eid",
            b"Bob",
            b"USER",
            b"2024-01-01T00:00:00Z",
            b"ep",
            b"kp",
            b"sp",
            b"pp",
            b"100",
            b"200",
            b"cid",
        )

    def test_encodes_timestamps_as_strings(self):
        card = _make_public_card()
        _HYBRID.bind_fields.reset_mock()
        _CARD_NB, _CARD_NA = 999, 1234567
        _card_signable(card, not_before=_CARD_NB, not_after=_CARD_NA, cert_id="x")
        args = _HYBRID.bind_fields.call_args[0]
        assert b"999"     in args
        assert b"1234567" in args


# ─────────────────────────────────────────────────────────────────────────────
# Platform-specific lock helpers (covered via TrustStore.save)
# ─────────────────────────────────────────────────────────────────────────────

class TestLockHelpers:
    """
    _lock_exclusive / _lock_release are exercised indirectly by TrustStore.save.
    We add a direct unit test for the non-win32 path.
    """

    @pytest.mark.skipif(sys.platform == "win32", reason="fcntl not available on Windows")
    def test_lock_exclusive_and_release(self):
        with tempfile.NamedTemporaryFile() as f:
            # Should not raise
            _lock_exclusive(f)
            _lock_release(f)

    @pytest.mark.skipif(sys.platform != "win32", reason="msvcrt-specific")
    def test_lock_exclusive_and_release_windows(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            with open(path, "a") as fh:
                _lock_exclusive(fh)
                _lock_release(fh)
        finally:
            os.unlink(path)
