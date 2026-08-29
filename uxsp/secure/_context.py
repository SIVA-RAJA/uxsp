from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.core.nonce import MemoryNonceStore, NonceStore
from uxsp.core.replay import ReplayGuard
from uxsp.secure._errors import PeerNotFoundError
from uxsp.secure._package import SecurePackage
from uxsp.secure._utils import _normalize_id
from uxsp.storage.keystore import KeyStore, MemoryKeyStore


class SecureContext:
    """
    Manages local identities, peer public keys, replay guards, and defaults
    for the simplified secure workflow.
    """
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._identity: Identity | None = None
        self._keystore: KeyStore = MemoryKeyStore()
        self._noncestore: NonceStore = MemoryNonceStore()
        self._replay_guard: ReplayGuard = ReplayGuard(self._noncestore)
        self._default_output_dir: Path = Path.cwd() / "downloads"
        self._transport_hook: Callable[[SecurePackage], Any] | None = None

    def configure(
        self,
        *,
        identity: Identity | None = None,
        keystore: KeyStore | None = None,
        noncestore: NonceStore | None = None,
        replay_guard: ReplayGuard | None = None,
        default_output_dir: str | Path | None = None,
        transport_hook: Callable[[SecurePackage], Any] | None = None,
    ) -> None:
        """Configure runtime defaults."""
        with self._lock:
            if identity is not None:
                self._identity = identity
                self._keystore.put(identity.public_card())
            if keystore is not None:
                self._keystore = keystore
                if self._identity is not None:
                    self._keystore.put(self._identity.public_card())
            if noncestore is not None:
                self._noncestore = noncestore
                self._replay_guard = ReplayGuard(noncestore)
            if replay_guard is not None:
                self._replay_guard = replay_guard
            if default_output_dir is not None:
                self._default_output_dir = Path(default_output_dir)
            if transport_hook is not None:
                self._transport_hook = transport_hook

    def get_identity(self) -> Identity:
        """Get or create the default identity."""
        with self._lock:
            if self._identity is None:
                self._identity = Identity.create(name="DefaultUser", role="client")
                self._keystore.put(self._identity.public_card())
            return self._identity

    def set_identity(self, identity: Identity) -> None:
        """Set the active local identity."""
        with self._lock:
            self._identity = identity
            self._keystore.put(identity.public_card())

    def register_peer(self, peer_card_or_identity: PublicCard | Identity) -> None:
        """Register a peer's public card."""
        with self._lock:
            if isinstance(peer_card_or_identity, Identity):
                card = peer_card_or_identity.public_card()
            else:
                card = peer_card_or_identity
            self._keystore.put(card)

    def get_peer(self, entity_id: str | int | PublicCard | Identity) -> PublicCard:
        """Retrieve a registered peer's PublicCard."""
        eid = _normalize_id(entity_id)
        with self._lock:
            card = self._keystore.get(eid)
            if card is None:
                raise PeerNotFoundError(
                    f"No public card registered for peer '{eid}'. "
                    f"Register peer using uxsp.secure.register_peer(card) first."
                )
            if isinstance(card, PublicCard):
                return card
            return card.card

    def revoke_peer(self, peer: str | int | PublicCard | Identity, reason: str = "Key compromised") -> PublicCard:
        """Mark a registered peer's PublicCard as revoked."""
        eid = _normalize_id(peer)
        card = self.get_peer(eid)
        card.revoke(reason=reason)
        with self._lock:
            self._keystore.put(card, overwrite=True)
        return card

    def get_replay_guard(self) -> ReplayGuard:
        """Get the active replay guard."""
        with self._lock:
            return self._replay_guard

    def get_default_output_dir(self) -> Path:
        """Get the default download output directory."""
        with self._lock:
            return self._default_output_dir

    def dispatch_package(self, package: SecurePackage) -> Any:
        """Dispatch a package via transport hook if configured."""
        with self._lock:
            hook = self._transport_hook
        if hook is not None:
            return hook(package)
        return package

    def reset(self) -> None:
        """Reset context state to clean defaults (useful in tests)."""
        with self._lock:
            self._identity = None
            self._keystore = MemoryKeyStore()
            self._noncestore = MemoryNonceStore()
            self._replay_guard = ReplayGuard(self._noncestore)
            self._default_output_dir = Path.cwd() / "downloads"
            self._transport_hook = None


_GLOBAL_CONTEXT = SecureContext()


def configure(**kwargs: Any) -> None:
    """Configure global context defaults."""
    _GLOBAL_CONTEXT.configure(**kwargs)


def get_context() -> SecureContext:
    """Return the global secure context."""
    return _GLOBAL_CONTEXT


def set_identity(identity: Identity) -> None:
    """Set the active local identity."""
    _GLOBAL_CONTEXT.set_identity(identity)


def get_identity() -> Identity:
    """Get the active local identity."""
    return _GLOBAL_CONTEXT.get_identity()


def register_peer(peer_card_or_identity: PublicCard | Identity) -> None:
    """Register a peer's public card or identity."""
    _GLOBAL_CONTEXT.register_peer(peer_card_or_identity)


def get_peer(entity_id: str | int | PublicCard | Identity) -> PublicCard:
    """Retrieve a registered peer's PublicCard."""
    return _GLOBAL_CONTEXT.get_peer(entity_id)


def reset_context() -> None:
    """Reset the global context."""
    _GLOBAL_CONTEXT.reset()
