"""
uxsp.core.identity — Identity and PublicCard

What this file does:
    Manages cryptographic identities for entities that communicate using UXSP.
    An Identity holds the complete hybrid keypair (classical X25519 exchange,
    ML-KEM for post-quantum key encapsulation, Ed25519 signing, and ML-DSA
    post-quantum signing) together with metadata (entity ID, name, role).

    A PublicCard is the shareable, secret-free projection of an Identity — it
    contains only public keys and metadata.  PublicCards are distributed to
    peers who need to send messages to, or verify messages from, this entity.

    Private keys are never stored in plain text; Identity.save() derives an
    AES-GCM encryption key from the user’s password via Argon2id, binds it to
    the public metadata as associated data, and writes an encrypted file.
    Identity.load() reverses this process.

Key classes:
    Identity    — Full keypair + metadata (keep private; has seal/open methods).
    PublicCard  — Public-only card (safe to share; no private key material).

Key functions:
    validate_role — Normalise and sanity-check a role string.
"""
import contextlib
import json
import os
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from uxsp.core.envelope import Envelope
from uxsp.core.replay import DefaultReplayGuard
from uxsp.crypto.hybrid import (
    decrypt_verified_envelope,
    extract_public_keys,
    generate_hybrid_keypair,
    seal,
    verify_envelope,
)
from uxsp.crypto.symmetric import decrypt, encrypt

# ─────────────────────────────────────────────
# EXCEPTIONS & ROLE VALIDATION
# ─────────────────────────────────────────────


class CardExpiredError(ValueError):
    """Raised when a PublicCard has expired (past its valid_until timestamp)."""
    pass


class CardRevokedError(ValueError):
    """Raised when a PublicCard has been revoked."""
    pass


def validate_role(role: str) -> str:
    """
    Normalise and validate a role string.

    Strips surrounding whitespace, converts to upper-case, and checks that the
    result is non-empty, at most 64 characters, and contains no internal
    whitespace.  Returns the normalised role on success or raises ValueError.
    """

    if not isinstance(role, str):
        raise ValueError("Role must be a string")

    # Strip whitespace from ends first
    role = role.strip().upper()

    if not role:
        raise ValueError("Role cannot be empty")
    if len(role) > 64:
        raise ValueError("Role must be 64 characters or fewer")

    # Check for internal whitespace
    if any(c.isspace() for c in role):
        raise ValueError("Role cannot contain internal whitespace")

    return role


def _identity_public_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    meta = {
        "version": payload["version"],
        "entity_id": payload["entity_id"],
        "name": payload["name"],
        "role": payload["role"],
        "created_at": payload["created_at"],
        "public_keys": payload["public_keys"],
    }
    if "key_version" in payload:
        meta["key_version"] = payload["key_version"]
    if payload.get("keys_rotated_at"):
        meta["keys_rotated_at"] = payload["keys_rotated_at"]
    return meta


def _identity_associated_data(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        _identity_public_metadata(payload),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


# ─────────────────────────────────────────────
# IDENTITY
# ─────────────────────────────────────────────


class Identity:
    """
    Represents a UXSP participant with a full hybrid keypair.

    What this class does:
        Holds the private + public keys for all four algorithms used by UXSP
        (X25519 ECDH, ML-KEM key encapsulation, Ed25519 signing, ML-DSA
        post-quantum signing) together with the entity’s UUID, display name,
        role string, and creation timestamp.

        Provides:
          - create()      — Generate a brand-new identity with a fresh keypair.
          - rotate_keys() — Generate a fresh keypair preserving entity_id.
          - public_card() — Extract the shareable PublicCard (no secrets).
          - seal_for()    — Encrypt + sign a message for a named recipient.
          - open_from()   — Decrypt + verify a message from a named sender.
          - save() / load() — Persist / restore the encrypted key file.

    Do NOT expose the .keypair dict outside trusted code; it contains raw
    private key bytes.
    """
    _VERSION = "UXSP-IDENTITY-1"
    def __init__(
        self,
        entity_id: str,
        name: str,
        role: str,
        keypair: dict[str, Any],
        created_at: str | None = None,
        key_version: int = 1,
        keys_rotated_at: str | None = None,
    ):
        """Internal. Use Identity.create() or Identity.load()."""
        self.entity_id = entity_id
        self.name = name
        self.role = validate_role(role)
        self.keypair = keypair
        self.created_at: str = created_at or datetime.now(UTC).isoformat()
        self.key_version: int = key_version
        self.keys_rotated_at: str | None = keys_rotated_at
        self._pub = extract_public_keys(keypair)

    # ─────────────────────────────────────────
    # CREATION & KEY ROTATION
    # ─────────────────────────────────────────

    @classmethod
    def create(cls, name: str, role: str) -> "Identity":
        """
        Create a brand-new Identity with a freshly generated hybrid keypair.

        Assigns a random UUID as the entity_id and the current UTC time as
        created_at. Raises ValueError if name is empty.
        """
        if not name or not name.strip():
            raise ValueError("Name cannot be empty")

        return cls(
            entity_id=str(uuid.uuid4()),
            name=name.strip(),
            role=role,
            keypair=generate_hybrid_keypair(),
        )

    def rotate_keys(self) -> "Identity":
        """
        Generate a new hybrid keypair while preserving entity_id, name, and role.

        Increments key_version and updates keys_rotated_at timestamp.
        Returns self for fluent chaining.
        """
        self.keypair = generate_hybrid_keypair()
        self._pub = extract_public_keys(self.keypair)
        self.key_version += 1
        self.keys_rotated_at = datetime.now(UTC).isoformat()
        return self

    # ─────────────────────────────────────────
    # PUBLIC CARD
    # ─────────────────────────────────────────

    def public_card(
        self,
        valid_until: str | datetime | None = None,
        ttl_seconds: float | int | None = None,
    ) -> "PublicCard":
        """
        Return a PublicCard containing only public keys and metadata.

        Optionally specify valid_until (ISO timestamp string or datetime) or ttl_seconds
        to issue a card with an expiration date.
        """
        v_until_str: str | None = None
        if valid_until is not None:
            if isinstance(valid_until, datetime):
                dt = valid_until if valid_until.tzinfo is not None else valid_until.replace(tzinfo=UTC)
                v_until_str = dt.isoformat()
            else:
                v_until_str = str(valid_until)
        elif ttl_seconds is not None:
            from datetime import timedelta
            v_until_str = (datetime.now(UTC) + timedelta(seconds=float(ttl_seconds))).isoformat()

        return PublicCard(
            entity_id=self.entity_id,
            name=self.name,
            role=self.role,
            public_keys=self._pub,
            created_at=self.created_at,
            valid_until=v_until_str,
            key_version=self.key_version,
        )

    # ─────────────────────────────────────────
    # SEAL / OPEN
    # ─────────────────────────────────────────

    def seal_for(self, plaintext: bytes, recipient_card: "PublicCard") -> Envelope:
        """
        Encrypt and sign plaintext for the given recipient.

        Verifies that recipient_card is valid (neither expired nor revoked).
        Performs hybrid key exchange (X25519 + ML-KEM) to derive a shared key,
        encrypts plaintext with AES-256-GCM, signs the ciphertext + metadata
        with both Ed25519 and ML-DSA, and returns an Envelope containing all
        wire-level fields.
        """
        if recipient_card.is_revoked:
            raise CardRevokedError(f"Cannot seal for revoked card: {recipient_card.entity_id}")
        recipient_card.verify_validity()

        raw = seal(
            plaintext=plaintext,
            sender_keypair=self.keypair,
            recipient_public_keys=recipient_card.public_keys,
            sender_id=self.entity_id,
            recipient_id=recipient_card.entity_id,
        )
        return Envelope.from_dict(raw)

    def open_from(
        self,
        envelope: Envelope | dict[str, Any],
        sender_card: "PublicCard",
        replay_guard: DefaultReplayGuard | None,
    ) -> bytes:
        """
        Decrypt and authenticate an envelope from sender_card.
        Verifies that sender_card is valid (neither expired nor revoked).
        A ReplayGuard instance is strictly required to prevent replay attacks.
        """
        if sender_card.is_revoked:
            raise CardRevokedError(f"Cannot open from revoked card: {sender_card.entity_id}")
        sender_card.verify_validity()

        if replay_guard is None:
            raise RuntimeError(
                "CRITICAL SECURITY ERROR: open_from() must be called with a "
                "replay_guard. Replay protection is mandatory in UXSP."
            )
        d: dict[str, Any] = envelope.to_dict() if isinstance(envelope, Envelope) else envelope

        if d.get("recipient_id") != self.entity_id:
            raise ValueError("Recipient ID mismatch: envelope not intended for this identity.")
        if d.get("sender_id") != sender_card.entity_id:
            raise ValueError("Sender ID mismatch: envelope sender does not match sender card.")

        replay_guard.precheck(d)

        verified = verify_envelope(
            envelope=d,
            sender_public_keys=sender_card.public_keys,
            expected_recipient_id=self.entity_id,
            expected_sender_id=sender_card.entity_id,
            max_age_seconds=replay_guard.window_seconds,
            clock_skew_seconds=replay_guard.clock_skew,
        )
        replay_guard.commit(d)
        return decrypt_verified_envelope(verified, self.keypair)

    # ─────────────────────────────────────────
    # SAVE / LOAD & ENCRYPTED SERIALIZATION
    # ─────────────────────────────────────────

    def to_encrypted_dict(self, password: str) -> dict[str, Any]:
        """
        Encrypt private keys and serialize this identity to a dictionary.

        Derives an AES-256-GCM key from the password using Argon2id, binds the
        encryption to all public metadata fields as AES-GCM associated data,
        and returns a dictionary containing public metadata and encrypted private key material.
        """
        from uxsp.crypto.kdf import derive_key_from_password

        kdf_result = derive_key_from_password(password)

        private_data = json.dumps(
            {
                "exchange_priv": self.keypair["exchange"]["private_key"].hex(),
                "kem_priv": self.keypair["kem"]["private_key"].hex(),
                "signing_priv": self.keypair["signing"]["private_key"].hex(),
                "pqc_sig_priv": self.keypair["pqc_sig"]["private_key"].hex(),
            }
        ).encode()

        payload = {
            "version": self._VERSION,
            "entity_id": self.entity_id,
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at,
            "key_version": self.key_version,
            "keys_rotated_at": self.keys_rotated_at,
            "public_keys": {
                "exchange_pub": self._pub["exchange_pub"].hex(),
                "kem_pub": self._pub["kem_pub"].hex(),
                "signing_pub": self._pub["signing_pub"].hex(),
                "pqc_sig_pub": self._pub["pqc_sig_pub"].hex(),
            },
        }

        enc = encrypt(
            private_data,
            kdf_result["key"],
            associated_data=_identity_associated_data(payload),
        )
        payload["encrypted_private"] = {
            "ciphertext": enc["ciphertext"].hex(),
            "nonce": enc["nonce"].hex(),
            "kdf_salt": kdf_result["salt"].hex(),
            "associated_data": "public-metadata-v1",
        }
        return payload

    def to_encrypted_json(self, password: str, indent: int | None = None) -> str:
        """Serialize identity to an encrypted JSON string protected by password."""
        return json.dumps(self.to_encrypted_dict(password), indent=indent)

    export_encrypted = to_encrypted_json

    @classmethod
    def from_encrypted_dict(cls, payload: dict[str, Any], password: str) -> "Identity":
        """Reconstruct an Identity from an encrypted dictionary payload and password."""
        if not isinstance(payload, dict):
            raise ValueError("Payload must be a dictionary.")

        if payload.get("version") != cls._VERSION:
            raise ValueError(f"Unknown identity file version: {payload.get('version')}")

        enc_priv = payload.get("encrypted_private")
        if not isinstance(enc_priv, dict):
            raise ValueError("Identity payload missing encrypted_private section.")

        from uxsp.crypto.kdf import derive_key_from_password

        try:
            _salt = bytes.fromhex(enc_priv["kdf_salt"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError("invalid encrypted_private metadata") from e

        kdf_result = derive_key_from_password(password, salt=_salt)

        try:
            if enc_priv.get("associated_data") == "public-metadata-v1":
                associated_data = _identity_associated_data(payload)
            else:
                associated_data = payload["entity_id"].encode()
        except KeyError as e:
            raise ValueError(f"missing required metadata field: {e}") from e

        try:
            ct = bytes.fromhex(enc_priv["ciphertext"])
            nonce = bytes.fromhex(enc_priv["nonce"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError("encrypted_private block is malformed.") from e

        try:
            private_data = decrypt(ct, nonce, kdf_result["key"], associated_data=associated_data)
        except Exception as exc:
            raise ValueError("Wrong password or corrupted file.") from exc

        try:
            priv = json.loads(private_data.decode())
            pub = payload["public_keys"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as e:
            raise ValueError("private key payload is malformed.") from e

        try:
            keypair = {
                "exchange": {
                    "private_key": bytes.fromhex(priv["exchange_priv"]),
                    "public_key": bytes.fromhex(pub["exchange_pub"]),
                },
                "kem": {
                    "private_key": bytes.fromhex(priv["kem_priv"]),
                    "public_key": bytes.fromhex(pub["kem_pub"]),
                },
                "signing": {
                    "private_key": bytes.fromhex(priv["signing_priv"]),
                    "public_key": bytes.fromhex(pub["signing_pub"]),
                },
                "pqc_sig": {
                    "private_key": bytes.fromhex(priv["pqc_sig_priv"]),
                    "public_key": bytes.fromhex(pub["pqc_sig_pub"]),
                },
            }
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError("malformed key material") from e

        return cls(
            entity_id=payload["entity_id"],
            name=payload["name"],
            role=payload["role"],
            keypair=keypair,
            created_at=payload["created_at"],
            key_version=payload.get("key_version", 1),
            keys_rotated_at=payload.get("keys_rotated_at"),
        )

    @classmethod
    def from_encrypted_json(cls, encrypted_json: str | bytes, password: str) -> "Identity":
        """Deserialize an Identity from an encrypted JSON string or bytes."""
        if isinstance(encrypted_json, bytes):
            encrypted_json = encrypted_json.decode("utf-8")
        try:
            data = json.loads(encrypted_json)
        except Exception as e:
            raise ValueError(f"Failed to parse encrypted JSON: {e}") from e
        return cls.from_encrypted_dict(data, password)

    import_encrypted = from_encrypted_json

    def save(self, path: str, password: str) -> None:
        """
        Encrypt and persist this identity to disk.
        Atomic write using temporary file.
        """
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_encrypted_dict(password)

        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(Path(path).parent))
        try:
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_path, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise

    @classmethod
    def load(cls, path: str, password: str) -> "Identity":
        """Load and decrypt an identity from a file previously created by save()."""
        with open(path) as f:
            payload = json.load(f)
        return cls.from_encrypted_dict(payload, password)

    # ─────────────────────────────────────────
    # PASSWORD HASHING HELPERS
    # ─────────────────────────────────────────

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using Argon2id."""
        from uxsp.crypto.kdf import argon2id_hash
        return argon2id_hash(password)

    @staticmethod
    def verify_password(stored_hash: str, password: str) -> bool:
        """Verify a password against an Argon2id PHC string hash."""
        from uxsp.crypto.kdf import argon2id_verify
        return argon2id_verify(stored_hash, password)

    # ─────────────────────────────────────────
    # UTILITIES
    # ─────────────────────────────────────────

    def __repr__(self) -> str:
        return f"Identity(id={self.entity_id[:8]}..., name={self.name!r}, role={self.role}, key_version={self.key_version})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Identity):
            return NotImplemented
        return self.entity_id == other.entity_id


# ─────────────────────────────────────────────
# PUBLIC CARD
# ─────────────────────────────────────────────


class PublicCard:
    """
    The public face of an Identity — contains only public keys and metadata.

    What this class does:
        Holds the four public keys (exchange_pub, kem_pub, signing_pub,
        pqc_sig_pub) plus entity_id, name, role, created_at, expiration
        metadata (valid_until), and revocation status (is_revoked).

        PublicCards are the primary unit exchanged between UXSP participants:
          - Share your PublicCard so others can seal messages to you.
          - Store a peer’s PublicCard so you can verify their envelopes.
          - Pass the card to TrustAnchor.issue() to obtain a SignedCard.

    Serialisation:
        to_dict() / to_json()  — convert public keys to hex strings for JSON.
        from_dict() / from_json() — reconstruct from JSON (hex strings → bytes).
    """
    _VERSION = "UXSP-PUBCARD-1"

    def __init__(
        self,
        entity_id: str,
        name: str,
        role: str,
        public_keys: dict[str, bytes],
        created_at: str,
        valid_until: str | None = None,
        is_revoked: bool = False,
        revocation_reason: str | None = None,
        revoked_at: str | None = None,
        key_version: int = 1,
    ):
        self.entity_id = entity_id
        self.name = name
        self.role = validate_role(role)
        self.public_keys = public_keys
        self.created_at: str = created_at
        self.valid_until: str | None = valid_until
        self.is_revoked: bool = is_revoked
        self.revocation_reason: str | None = revocation_reason
        self.revoked_at: str | None = revoked_at
        self.key_version: int = key_version

    def is_expired(self, now: datetime | str | None = None) -> bool:
        """Check if this PublicCard is past its valid_until timestamp."""
        if not self.valid_until:
            return False

        if now is None:
            now_dt = datetime.now(UTC)
        elif isinstance(now, str):
            now_dt = datetime.fromisoformat(now)
            if now_dt.tzinfo is None:
                now_dt = now_dt.replace(tzinfo=UTC)
        else:
            now_dt = now if now.tzinfo is not None else now.replace(tzinfo=UTC)

        valid_until_dt = datetime.fromisoformat(self.valid_until)
        if valid_until_dt.tzinfo is None:
            valid_until_dt = valid_until_dt.replace(tzinfo=UTC)

        return now_dt > valid_until_dt

    def revoke(
        self,
        reason: str | None = "Key compromised",
        revoked_at: str | datetime | None = None,
    ) -> None:
        """Mark this PublicCard as revoked."""
        self.is_revoked = True
        self.revocation_reason = reason or "Key compromised"
        if revoked_at is None:
            self.revoked_at = datetime.now(UTC).isoformat()
        elif isinstance(revoked_at, datetime):
            dt = revoked_at if revoked_at.tzinfo is not None else revoked_at.replace(tzinfo=UTC)
            self.revoked_at = dt.isoformat()
        else:
            self.revoked_at = str(revoked_at)

    def verify_validity(self, now: datetime | str | None = None) -> None:
        """
        Verify that this PublicCard is valid (neither revoked nor expired).
        Raises CardRevokedError if revoked or CardExpiredError if expired.
        """
        if self.is_revoked:
            reason_msg = f" (reason: {self.revocation_reason})" if self.revocation_reason else ""
            raise CardRevokedError(f"PublicCard for entity '{self.entity_id}' has been revoked{reason_msg}.")
        if self.is_expired(now=now):
            raise CardExpiredError(f"PublicCard for entity '{self.entity_id}' expired at {self.valid_until}.")

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (JSON-safe hex strings)."""
        d = {
            "version": self._VERSION,
            "entity_id": self.entity_id,
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at,
            "public_keys": {k: v.hex() for k, v in self.public_keys.items()},
            "key_version": self.key_version,
            "is_revoked": self.is_revoked,
        }
        if self.valid_until is not None:
            d["valid_until"] = self.valid_until
        if self.revocation_reason is not None:
            d["revocation_reason"] = self.revocation_reason
        if self.revoked_at is not None:
            d["revoked_at"] = self.revoked_at
        return d

    def to_json(self) -> str:
        """Serialise to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PublicCard":
        """Reconstruct a PublicCard from a dict."""

        if data.get("version") not in (cls._VERSION, None):
            raise ValueError(f"Unknown PublicCard version: {data.get('version')}")

        return cls(
            entity_id=data["entity_id"],
            name=data["name"],
            role=data["role"],
            created_at=data["created_at"],
            public_keys={k: bytes.fromhex(v) for k, v in data["public_keys"].items()},
            valid_until=data.get("valid_until"),
            is_revoked=bool(data.get("is_revoked", False)),
            revocation_reason=data.get("revocation_reason"),
            revoked_at=data.get("revoked_at"),
            key_version=int(data.get("key_version", 1)),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "PublicCard":
        """Reconstruct a PublicCard from a JSON string."""
        return cls.from_dict(json.loads(json_str))

    def __repr__(self) -> str:
        status = " (REVOKED)" if self.is_revoked else ""
        return f"PublicCard(id={self.entity_id[:8]}..., name={self.name!r}, role={self.role}, version={self.key_version}){status}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PublicCard):
            return NotImplemented
        return (
            self.entity_id == other.entity_id
            and self.key_version == other.key_version
            and self.is_revoked == other.is_revoked
        )
