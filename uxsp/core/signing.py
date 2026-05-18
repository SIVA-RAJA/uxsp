"""
uxsp.core.signing — Trust Anchors, Signed Cards, and Trust Stores

What this file does:
    Implements a lightweight X.509-style certificate chain for UXSP identities.
    A TrustAnchor (root CA) signs PublicCards to produce SignedCards, and a
    TrustStore verifies those cards before trusting the sender of an envelope.

    Verification flow:
        1. An authority creates a TrustAnchor and distributes its PublicAnchor.
        2. Entities submit their PublicCard to the authority.
        3. The authority calls TrustAnchor.issue() to produce a SignedCard.
        4. Entities present their SignedCard when establishing sessions.
        5. Receivers call TrustStore.verify(signed_card) to confirm the card was
           signed by a trusted anchor and is within its validity window.

    Signing uses a hybrid scheme (Ed25519 + ML-DSA) so the certificates are
    secure against both classical and quantum adversaries.

    Cross-process file safety:
        TrustStore.save() acquires an exclusive file lock (fcntl on POSIX,
        msvcrt on Windows) before writing so concurrent processes do not
        corrupt the trust store file.

Key classes:
    TrustAnchor  — Root CA with private signing keys.
    PublicAnchor — Distributable public representation of a TrustAnchor.
    SignedCard   — A PublicCard plus issuer signature and validity window.
    TrustStore   — Collection of trusted PublicAnchors used to verify SignedCards.

Key errors:
    SigningError             — Base.
    UntrustedCardError       — Issuer not in TrustStore.
    InvalidCardSignatureError — Signature does not verify.
    ExpiredCardError         — Card past its not_after date.
    CardNotYetValidError     — Card before its not_before date.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

if sys.platform != "win32":
    import fcntl as _fcntl

    def _lock_exclusive(fh: Any) -> None:
        _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX)

    def _lock_release(fh: Any) -> None:
        _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)
else:
    import msvcrt as _msvcrt

    _LOCK_NBYTES = 1

    def _lock_exclusive(fh: Any) -> None:
        fh.seek(0)
        _msvcrt.locking(fh.fileno(), _msvcrt.LK_LOCK, _LOCK_NBYTES)

    def _lock_release(fh: Any) -> None:
        fh.seek(0)
        _msvcrt.locking(fh.fileno(), _msvcrt.LK_UNLCK, _LOCK_NBYTES)


from uxsp.core.identity import Identity, PublicCard
from uxsp.crypto.hybrid import EnvelopeValidationError, bind_fields, hybrid_sign, hybrid_verify

# ─────────────────────────────────────────────
# ERRORS
# ─────────────────────────────────────────────


class SigningError(Exception):
    """Base class for signing errors."""

    pass


class UntrustedCardError(SigningError):
    """
    SignedCard issuer is not in the TrustStore.

    Raise this when you receive a SignedCard whose issuer_id is
    not a trusted anchor. The card must be rejected — do not open
    envelopes from an untrusted sender.
    """

    pass


class InvalidCardSignatureError(SigningError):
    """
    The signature on a SignedCard does not verify against the issuer's
    public keys. Card was tampered or issued by a different anchor.
    """

    pass


class ExpiredCardError(SigningError):
    """
    SignedCard has passed its not_after timestamp.
    Reject and ask the entity to renew their card.
    """

    pass


class CardNotYetValidError(SigningError):
    """
    SignedCard's not_before is in the future.
    Possible clock skew or pre-issued card used too early.
    """

    pass


# ─────────────────────────────────────────────
# TRUST ANCHOR
# ─────────────────────────────────────────────


class TrustAnchor:
    """
    A root Certificate Authority for UXSP identities.

    What this class does:
        Wraps a secret Identity (with the TRUST-ANCHOR role) and provides
        methods to:
          - create()  — Generate a fresh TrustAnchor keypair.
          - save() / load() — Persist / restore the encrypted anchor key file.
          - public_anchor() — Export a PublicAnchor for distribution.
          - issue() — Sign a PublicCard to produce a SignedCard with a
                       configurable validity window (max 730 days).

    Security:
        The private signing keys must be kept on a secure, offline host.
        The PublicAnchor (from public_anchor()) is safe to distribute to all
        parties that need to verify UXSP certificates.
    """
    def __init__(self, identity: Identity) -> None:
        self._identity = identity

    @classmethod
    def create(cls, name: str) -> TrustAnchor:
        """
        Create a new TrustAnchor with a freshly generated hybrid keypair.

        Internally creates an Identity with role='TRUST-ANCHOR' and wraps it.
        Returns a TrustAnchor whose private keys exist only in memory until
        save() is called.
        """

        identity = Identity.create(name, "TRUST-ANCHOR")
        return cls(identity)

    def save(self, path: str, password: str) -> None:
        """Save the TrustAnchor's identity (with encrypted private keys)."""
        self._identity.save(path, password)

    @classmethod
    def load(cls, path: str, password: str) -> TrustAnchor:
        """Load a TrustAnchor from an encrypted identity file."""
        identity = Identity.load(path, password)
        return cls(identity)

    def public_anchor(self) -> PublicAnchor:
        """
        Export the public-facing representation of this TrustAnchor.

        The returned PublicAnchor contains only public keys and can safely be
        distributed to any party that needs to verify UXSP certificates.
        """

        card = self._identity.public_card()
        return PublicAnchor(
            anchor_id=self._identity.entity_id,
            name=self._identity.name,
            public_keys=card.public_keys,
            created_at=self._identity.created_at,
        )

    def issue(
        self, card: PublicCard, validity_days: int = 365, not_before: int | None = None
    ) -> SignedCard:
        """
        Sign a PublicCard and issue a SignedCard with a validity window.

        Computes the canonical signable bytes from the card’s fields plus the
        validity window, signs with the anchor’s Ed25519 and ML-DSA private
        keys, and returns a SignedCard.

        Parameters:
            card          — The PublicCard to certify.
            validity_days — Number of days before the card expires (max 730).
            not_before    — Unix timestamp for the start of validity (default: now).
        """

        if validity_days <= 0:
            raise ValueError("validity_days must be positive")
        if validity_days > 730:
            raise ValueError("validity_days cannot exceed 730 (2 years)")

        nb: int = not_before if not_before is not None else int(time.time())
        na: int = nb + validity_days * 86400
        cid = str(uuid.uuid4())

        signable = _card_signable(card, nb, na, cid)
        sigs = hybrid_sign(signable, self._identity.keypair)

        return SignedCard(
            card=card,
            cert_id=cid,
            issuer_id=self._identity.entity_id,
            issuer_name=self._identity.name,
            not_before=nb,
            not_after=na,
            classical_sig=bytes.fromhex(sigs["classical_sig"]),
            pqc_sig=bytes.fromhex(sigs["pqc_sig"]),
        )

    @property
    def entity_id(self) -> str:
        return self._identity.entity_id

    @property
    def name(self) -> str:
        return self._identity.name

    def __repr__(self) -> str:
        return f"TrustAnchor(id={self.entity_id[:8]}..., name={self.name!r})"


# ─────────────────────────────────────────────
# PUBLIC ANCHOR — safe to distribute
# ─────────────────────────────────────────────


class PublicAnchor:
    """
    The distributable, secret-free representation of a TrustAnchor.

    What this class does:
        Contains the anchor’s anchor_id, name, creation timestamp, and four
        public keys (exchange_pub, kem_pub, signing_pub, pqc_sig_pub).  Used
        by TrustStore to verify the signatures on SignedCards.

        Serialised to/from JSON for storage and distribution.  Two PublicAnchors
        with the same anchor_id are considered equal (equality / hashing).
    """
    def __init__(
        self, anchor_id: str, name: str, public_keys: dict[str, bytes], created_at: str
    ) -> None:
        self.anchor_id = anchor_id
        self.name = name
        self.public_keys = public_keys
        self.created_at = created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_id": self.anchor_id,
            "name": self.name,
            "created_at": self.created_at,
            "public_keys": {k: v.hex() for k, v in self.public_keys.items()},
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PublicAnchor:
        return cls(
            anchor_id=data["anchor_id"],
            name=data["name"],
            created_at=data["created_at"],
            public_keys={k: bytes.fromhex(v) for k, v in data["public_keys"].items()},
        )

    @classmethod
    def from_json(cls, s: str) -> PublicAnchor:
        return cls.from_dict(json.loads(s))

    def __repr__(self) -> str:
        return f"PublicAnchor(id={self.anchor_id[:8]}..., name={self.name!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PublicAnchor):
            return False
        return self.anchor_id == other.anchor_id

    def __hash__(self) -> int:
        return hash(self.anchor_id)


# ─────────────────────────────────────────────
# SIGNED CARD
# ─────────────────────────────────────────────


class SignedCard:
    """
    A PublicCard that has been signed by a TrustAnchor.

    What this class does:
        Combines a PublicCard with certificate metadata (cert_id, issuer_id,
        issuer_name, not_before, not_after) and both a classical (Ed25519) and
        a post-quantum (ML-DSA) signature over all fields.

        Validity checks:
            is_time_valid()       — Returns True if now is within [not_before, not_after].
            check_time_validity() — Raises CardNotYetValidError or ExpiredCardError.

        Note: time validity alone does not mean the card is trustworthy — you
        must also call TrustStore.verify() to confirm the issuer is trusted and
        the signature is correct.

    Serialisation:
        to_dict() / to_json() / from_dict() / from_json() for JSON round-trips.
    """
    def __init__(self,
        card: PublicCard,
        cert_id: str,
        issuer_id: str,
        issuer_name: str,
        not_before: int,
        not_after: int,
        classical_sig: bytes,
        pqc_sig: bytes,
    ) -> None:

        self.card = card
        self.cert_id = cert_id
        self.issuer_id = issuer_id
        self.issuer_name = issuer_name
        self.not_before = not_before
        self.not_after = not_after
        self.classical_sig = classical_sig
        self.pqc_sig = pqc_sig

    # ─────────────────────────────────────────
    # VALIDITY WINDOW (time only, not trust)
    # ─────────────────────────────────────────

    def is_time_valid(self, now: int | None = None) -> bool:
        """Return True if current time is within the validity window."""
        t = now if now is not None else int(time.time())
        return self.not_before <= t <= self.not_after

    def check_time_validity(self, now: int | None = None) -> None:

        t = now if now is not None else int(time.time())
        if t < self.not_before:
            raise CardNotYetValidError(
                f"SignedCard for '{self.card.name}' is not yet valid. "
                f"Valid from {self.not_before}, current time {t}."
            )
        if t > self.not_after:
            raise ExpiredCardError(
                f"SignedCard for '{self.card.name}' expired at "
                f"{self.not_after}. Current time {t}. "
                f"Request a new card from the issuer."
            )

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, float(self.not_after) - time.time())

    @property
    def remaining_days(self) -> float:
        return self.remaining_seconds / 86400

    # ─────────────────────────────────────────
    # SERIALISATION
    # ─────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        return {
            "cert_id": self.cert_id,
            "issuer_id": self.issuer_id,
            "issuer_name": self.issuer_name,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "classical_sig": self.classical_sig.hex(),
            "pqc_sig": self.pqc_sig.hex(),
            "card": self.card.to_dict(),
        }

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedCard:
        card = PublicCard.from_dict(data["card"])
        return cls(
            card=card,
            cert_id=data["cert_id"],
            issuer_id=data["issuer_id"],
            issuer_name=data["issuer_name"],
            not_before=int(data["not_before"]),
            not_after=int(data["not_after"]),
            classical_sig=bytes.fromhex(data["classical_sig"]),
            pqc_sig=bytes.fromhex(data["pqc_sig"]),
        )

    @classmethod
    def from_json(cls, s: str) -> SignedCard:
        return cls.from_dict(json.loads(s))

    def __repr__(self) -> str:
        days = self.remaining_days
        return (
            f"SignedCard(entity={self.card.name!r}, "
            f"issuer={self.issuer_name!r}, "
            f"cert={self.cert_id[:8]}..., "
            f"expires_in={days:.1f}d)"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SignedCard):
            return False
        return self.cert_id == other.cert_id

    def __hash__(self) -> int:
        return hash(self.cert_id)


# ─────────────────────────────────────────────
# TRUST STORE
# ─────────────────────────────────────────────


class TrustStore:
    """
    A thread-safe, in-memory collection of trusted PublicAnchors.

    What this class does:
        Acts as the verifying endpoint for the UXSP certificate chain.  Before
        trusting a peer’s SignedCard, the receiver calls TrustStore.verify()
        which:
          1. Looks up the issuer in the store (raises UntrustedCardError if absent).
          2. Checks the card’s validity window (raises Expired/CardNotYetValidError).
          3. Verifies the hybrid (Ed25519 + ML-DSA) signature against the anchor’s
             public keys (raises InvalidCardSignatureError on failure).
          4. Optionally checks that the card’s entity_id matches an expected value
             to guard against card-substitution attacks.

    Thread safety:
        All reads and writes to the internal anchor dictionary are protected by
        a threading.Lock().

    Persistence:
        save() / load() / from_anchors() for JSON serialisation and convenience
        construction.  save() uses an exclusive file lock to prevent corruption
        from concurrent writers.
    """
    def __init__(self) -> None:
        self._anchors: dict[str, PublicAnchor] = {}
        self._lock = threading.Lock()

    def add(self, anchor: PublicAnchor) -> None:
        """Add a trusted PublicAnchor."""
        with self._lock:
            self._anchors[anchor.anchor_id] = anchor

    def remove(self, anchor_id: str) -> None:
        """Remove an anchor (e.g. it was compromised)."""
        with self._lock:
            self._anchors.pop(anchor_id, None)

    def has(self, anchor_id: str) -> bool:
        """Return True if anchor_id is trusted."""
        with self._lock:
            return anchor_id in self._anchors

    @property
    def anchor_ids(self) -> list[str]:
        with self._lock:
            return list(self._anchors.keys())

    def verify(
        self, signed_card: SignedCard, now: int | None = None, expected_entity_id: str | None = None
    ) -> PublicCard:
        """
        Verify a SignedCard against this trust store.

        Args:
            signed_card        : The card to verify.
            now                : Unix timestamp override (for testing).
            expected_entity_id : If provided, raises UntrustedCardError when
                                 the card's entity_id does not match. Use this
                                 to guard against a valid card for entity A
                                 being accepted when entity B is expected.
        """

        with self._lock:
            anchor = self._anchors.get(signed_card.issuer_id)
            if anchor is None:
                raise UntrustedCardError(
                    f"Card issuer '{signed_card.issuer_id[:8]}...' "
                    f"({signed_card.issuer_name!r}) is not in the trust store. "
                    f"Trusted anchors: {[a[:8] + '...' for a in self._anchors]}"
                )

            anchor_public_keys = dict(anchor.public_keys)

            anchor_name = anchor.name

        if expected_entity_id is not None and signed_card.card.entity_id != expected_entity_id:
            raise UntrustedCardError(
                f"Card entity_id '{signed_card.card.entity_id[:8]}...' "
                f"does not match expected entity "
                f"'{expected_entity_id[:8]}...'. "
                f"Possible card substitution attack."
            )

        signed_card.check_time_validity(now)

        signable = _card_signable(
            signed_card.card,
            signed_card.not_before,
            signed_card.not_after,
            signed_card.cert_id,
        )

        sigs: dict[str, str] = {
            "classical_sig": signed_card.classical_sig.hex(),
            "pqc_sig": signed_card.pqc_sig.hex(),
        }

        try:
            signature_ok = hybrid_verify(signable, sigs, anchor_public_keys)
        except EnvelopeValidationError as exc:
            raise InvalidCardSignatureError(
                f"Signature on card for '{signed_card.card.name}' is malformed: {exc}"
            ) from exc

        if not signature_ok:
            raise InvalidCardSignatureError(
                f"Signature on card for '{signed_card.card.name}' "
                f"(cert {signed_card.cert_id[:8]}...) "
                f"does not verify against anchor "
                f"'{anchor_name}'. Card was tampered."
            )

        return signed_card.card

    # ─────────────────────────────────────────
    # SERIALISATION
    # ─────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {"anchors": [a.to_dict() for a in self._anchors.values()]}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str) -> None:

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        lock_path = Path(str(path) + ".lock")

        with open(lock_path, "a") as lf:
            _lock_exclusive(lf)
            try:
                tmp_fd, tmp_path = tempfile.mkstemp(dir=str(p.parent))
                try:
                    with os.fdopen(tmp_fd, "w") as f:
                        f.write(self.to_json())
                    if sys.platform != "win32":
                        os.chmod(tmp_path, 0o644)
                    os.replace(tmp_path, path)
                except Exception:
                    with contextlib.suppress(OSError):
                        os.unlink(tmp_path)
                    raise
            finally:
                _lock_release(lf)

    @classmethod
    def load(cls, path: str) -> TrustStore:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError(f"TrustStore file '{path}' must contain a JSON object.")
        store = cls()
        for a in data.get("anchors", []):
            store.add(PublicAnchor.from_dict(a))
        return store

    @classmethod
    def from_anchors(cls, *anchors: PublicAnchor) -> TrustStore:
        """Convenience constructor: TrustStore.from_anchors(a1, a2)."""
        store = cls()
        for a in anchors:
            store.add(a)
        return store

    def __len__(self) -> int:
        with self._lock:
            return len(self._anchors)

    def __repr__(self) -> str:
        with self._lock:
            names = [a.name for a in self._anchors.values()]
        return f"TrustStore(anchors={names})"


# ─────────────────────────────────────────────
# INTERNAL — canonical signable bytes for a card
# ─────────────────────────────────────────────


def _card_signable(card: PublicCard, not_before: int, not_after: int, cert_id: str) -> bytes:
    """
    Produce the canonical length-prefixed byte string that is signed by the
    TrustAnchor when issuing a card and verified by TrustStore.verify().

    Binds: entity_id, name, role, created_at, all four public keys,
    not_before, not_after, and cert_id.  Length-prefixes each field to
    prevent length-extension / field-confusion attacks.
    """

    return bind_fields(
        card.entity_id.encode(),
        card.name.encode(),
        card.role.encode(),
        card.created_at.encode(),
        card.public_keys["exchange_pub"],
        card.public_keys["kem_pub"],
        card.public_keys["signing_pub"],
        card.public_keys["pqc_sig_pub"],
        str(not_before).encode(),
        str(not_after).encode(),
        cert_id.encode(),
    )
