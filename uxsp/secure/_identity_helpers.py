from __future__ import annotations

from uxsp.core.identity import Identity, PublicCard
from uxsp.secure._context import _GLOBAL_CONTEXT, get_peer
from uxsp.secure._errors import PeerNotFoundError


def create_identity(name: str, role: str = "CLIENT") -> Identity:
    """Create a brand-new Identity with a freshly generated hybrid keypair."""
    return Identity.create(name=name, role=role)


def rotate_keys(identity: Identity | None = None) -> Identity:
    """
    Generate a new hybrid keypair for an Identity while preserving entity_id.

    If identity is None, rotates the active global context identity and updates registered keys.
    """
    if identity is None:
        ident = _GLOBAL_CONTEXT.get_identity()
        ident.rotate_keys()
        _GLOBAL_CONTEXT.set_identity(ident)
        return ident
    return identity.rotate_keys()


def revoke_peer(peer: str | int | PublicCard | Identity, reason: str = "Key compromised") -> PublicCard:
    """Mark a registered peer's PublicCard as revoked."""
    return _GLOBAL_CONTEXT.revoke_peer(peer, reason=reason)


def verify_peer_validity(peer: str | int | PublicCard | Identity) -> None:
    """Verify that a peer's PublicCard is neither expired nor revoked."""
    try:
        card = get_peer(peer)
    except PeerNotFoundError:
        if isinstance(peer, PublicCard):
            card = peer
        elif isinstance(peer, Identity):
            card = peer.public_card()
        else:
            raise
    card.verify_validity()


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return Identity.hash_password(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify a password against an Argon2id PHC string hash."""
    return Identity.verify_password(stored_hash, password)


def export_identity_encrypted(identity: Identity, password: str) -> str:
    """Export an Identity to an encrypted JSON string protected by password."""
    return identity.to_encrypted_json(password)


def import_identity_encrypted(encrypted_json: str | bytes, password: str) -> Identity:
    """Import an Identity from an encrypted JSON string protected by password."""
    return Identity.from_encrypted_json(encrypted_json, password)
