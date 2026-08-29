"""
UXSP Contrib — Web Framework Integrations for FastAPI, Django, and Flask.

Provides 1-line middleware and decorators for effortless request decryption and
response encryption in web microservices and APIs.

Usage:
    # FastAPI
    from uxsp.contrib.fastapi import UXSPFastAPIMiddleware, protect

    # Django
    from uxsp.contrib.django import UXSPDjangoMiddleware, protect_view

    # Flask
    from uxsp.contrib.flask import UXSPFlaskMiddleware, protect_route

Security Context:
    UXSP natively replaces CSRF protection. Because every incoming request is
    cryptographically authenticated and protected against replay attacks (via nonces
    and timestamps), traditional CSRF tokens are unnecessary when UXSP is enforced.
"""

from __future__ import annotations

from typing import Any
from uxsp.core.identity import PublicCard
from uxsp.secure import _GLOBAL_CONTEXT
from uxsp.storage.keystore import KeyStore

def resolve_peer_card(keystore: KeyStore | None, sender_id: str) -> PublicCard | None:
    """
    Shared utility to resolve a peer's PublicCard.
    Checks the provided keystore first, then falls back to the global context.
    """
    if keystore is not None:
        card = keystore.public_card(sender_id) if hasattr(keystore, "public_card") else keystore.get(sender_id)
        if card is not None:
            return card.card if hasattr(card, "card") else card
    try:
        return _GLOBAL_CONTEXT.get_peer(sender_id)
    except Exception:
        return None

__all__ = ["resolve_peer_card"]
