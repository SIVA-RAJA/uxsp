from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from uxsp.core.chunking import create_chunked_transfer, reassemble_chunked_transfer
from uxsp.core.envelope import Envelope
from uxsp.core.identity import Identity, PublicCard
from uxsp.crypto.symmetric import decrypt, encrypt
from uxsp.secure._context import _GLOBAL_CONTEXT
from uxsp.secure._errors import SecureReceiveError, TypeMismatchError
from uxsp.secure._package import SecurePackage
from uxsp.secure._utils import _normalize_id, _safe_is_file
from uxsp.storage.keystore import AsyncKeyStore

# Note: this file implements native async payload dispatching.
# It assumes _GLOBAL_CONTEXT is configured with async stores or we resolve peers asynchronously.

async def async_secure_send_payload(
    receiver_id: str | int | PublicCard | Identity | None = None,
    payload_bytes: bytes = b"",
    data_type: str = "file",
    *,
    sender_identity: Identity | None = None,
    sender: Identity | None = None,
    receiver: str | int | PublicCard | Identity | None = None,
    output_file: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurePackage:
    rec_target = receiver if receiver is not None else receiver_id
    if rec_target is None:
        raise ValueError("Receiver identity or receiver_id must be provided.")

    if isinstance(rec_target, Identity):
        peer_card = rec_target.public_card()
        rec_id = rec_target.entity_id
    elif isinstance(rec_target, PublicCard):
        peer_card = rec_target
        rec_id = rec_target.entity_id
    else:
        rec_id = _normalize_id(rec_target)
        # If the keystore is async, we await it; else we use the sync get_peer
        if isinstance(_GLOBAL_CONTEXT._keystore, AsyncKeyStore):
            peer_card = await _GLOBAL_CONTEXT._keystore.require(rec_id)
        else:
            peer_card = _GLOBAL_CONTEXT.get_peer(rec_id)

    sender_obj = sender or sender_identity or _GLOBAL_CONTEXT.get_identity()
    meta = metadata or {}

    if len(payload_bytes) <= 30 * 1024:
        env = sender_obj.seal_for(payload_bytes, peer_card)
        package = SecurePackage(
            sender_id=sender_obj.entity_id,
            receiver_id=rec_id,
            data_type=data_type,
            is_chunked=False,
            envelope=env.to_dict(),
            metadata=meta,
        )
    else:
        # Large payload chunking - session key approach
        # Note: Best-effort memory zeroing of session key bytearray upon completion.
        session_key = bytearray(os.urandom(32))
        try:
            env = sender_obj.seal_for(bytes(session_key), peer_card)
            chunks = create_chunked_transfer(payload_bytes, chunk_size=16 * 1024)
            sealed_chunks: list[dict[str, Any]] = []
            for seq, chunk_bytes in enumerate(chunks):
                ad = f"{env.envelope_nonce}:{seq}".encode()
                enc_dict = encrypt(chunk_bytes, bytes(session_key), associated_data=ad)
                sealed_chunks.append({
                    "c": enc_dict["ciphertext"].hex(),
                    "n": enc_dict["nonce"].hex(),
                })
        finally:
            for i in range(len(session_key)):
                session_key[i] = 0

        package = SecurePackage(
            sender_id=sender_obj.entity_id,
            receiver_id=rec_id,
            data_type=data_type,
            is_chunked=True,
            envelope=env.to_dict(),
            chunks=sealed_chunks,
            metadata=meta,
        )

    if output_file is not None:
        package.save(output_file)

    # Note: async transport hooks could be awaited here, but for now we dispatch synchronously
    _GLOBAL_CONTEXT.dispatch_package(package)
    return package


def _resolve_package_input(package_input: Any) -> SecurePackage:
    if isinstance(package_input, SecurePackage):
        return package_input
    if isinstance(package_input, dict):
        return SecurePackage.from_dict(package_input)
    if isinstance(package_input, bytes):
        return SecurePackage.from_json(package_input)
    if isinstance(package_input, str):
        trimmed = package_input.strip()
        if trimmed.startswith("{"):
            return SecurePackage.from_json(trimmed)
    if isinstance(package_input, (str, Path)):
        if _safe_is_file(package_input):
            return SecurePackage.from_file(Path(package_input))
        raise SecureReceiveError(f"Package file not found: {package_input}")
    raise SecureReceiveError(f"Cannot resolve package from input of type {type(package_input).__name__}")


class FreshnessOnlyReplayGuard:
    """
    Validates timestamp freshness and clock skew via the underlying guard,
    while skipping nonce deduplication because it was already executed
    atomically via AsyncNonceStore.check_and_mark().
    """

    def __init__(self, guard: Any) -> None:
        self._guard = guard
        self.window_seconds = guard.window_seconds
        self.clock_skew = guard.clock_skew

    def precheck(self, e: Any) -> None:
        self._guard.check_freshness(e)

    def commit(self, e: Any) -> None:
        pass


async def _check_async_replay(guard: Any, nonce: str) -> None:
    from uxsp.core.envelope import EnvelopeExpiredError
    if hasattr(guard._store, "check_and_mark"):
        valid = await guard._store.check_and_mark(nonce, ttl_seconds=guard.window_seconds)
    else:
        valid = await guard._store.mark_used(nonce, ttl_seconds=guard.window_seconds)
    if not valid:
        raise EnvelopeExpiredError("Replay detected (async).")


async def async_secure_receive_payload(
    sender_id: str | int | PublicCard | Identity | None = None,
    package_input: Any = None,
    expected_type: str | None = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> bytes:
    """
    Asynchronously decrypt and authenticate a received SecurePackage or payload input.
    """
    snd_target = sender_card if sender_card is not None else (sender if sender is not None else sender_id)
    if snd_target is None:
        raise ValueError("Sender identity/card or sender_id must be provided.")

    if isinstance(snd_target, Identity):
        peer_card = snd_target.public_card()
        snd_id = snd_target.entity_id
    elif isinstance(snd_target, PublicCard):
        peer_card = snd_target
        snd_id = snd_target.entity_id
    else:
        snd_id = _normalize_id(snd_target)
        if isinstance(_GLOBAL_CONTEXT._keystore, AsyncKeyStore):
            peer_card = await _GLOBAL_CONTEXT._keystore.require(snd_id)
        else:
            peer_card = _GLOBAL_CONTEXT.get_peer(snd_id)

    package = _resolve_package_input(package_input)
    receiver_obj = receiver or receiver_identity or _GLOBAL_CONTEXT.get_identity()
    guard = _GLOBAL_CONTEXT.get_replay_guard()

    if package.sender_id != snd_id:
        raise SecureReceiveError(
            f"Sender ID mismatch: expected '{snd_id}', package has '{package.sender_id}'"
        )
    if package.receiver_id != receiver_obj.entity_id:
        raise SecureReceiveError(
            f"Receiver ID mismatch: intended for '{package.receiver_id}', current identity is '{receiver_obj.entity_id}'"
        )

    if expected_type is not None and package.data_type != expected_type:
        raise TypeMismatchError(
            f"Data type mismatch: expected '{expected_type}', got '{package.data_type}'"
        )

    guard = _GLOBAL_CONTEXT.get_replay_guard()
    from uxsp.storage.noncestore import AsyncNonceStore

    if not package.is_chunked:
        if package.envelope is None:
            raise SecureReceiveError("Package is marked non-chunked but missing envelope.")
        env = Envelope.from_dict(package.envelope)

        # Async Replay Check
        if isinstance(guard._store, AsyncNonceStore):
            await _check_async_replay(guard, env.envelope_nonce)
            payload_bytes = receiver_obj.open_from(env, peer_card, replay_guard=FreshnessOnlyReplayGuard(guard))
        else:
            payload_bytes = receiver_obj.open_from(env, peer_card, replay_guard=guard)

        return payload_bytes
    else:
        if not package.chunks:
            raise SecureReceiveError("Package is marked chunked but contains no chunks.")
        if package.envelope is None:
            raise SecureReceiveError("Package is marked chunked but missing session key envelope.")

        env = Envelope.from_dict(package.envelope)

        # Async Replay Check
        if isinstance(guard._store, AsyncNonceStore):
            await _check_async_replay(guard, env.envelope_nonce)
            session_key_bytes = receiver_obj.open_from(env, peer_card, replay_guard=FreshnessOnlyReplayGuard(guard))
        else:
            session_key_bytes = receiver_obj.open_from(env, peer_card, replay_guard=guard)

        session_key = bytearray(session_key_bytes)
        try:
            raw_chunks: list[bytes] = []
            for seq, c_dict in enumerate(package.chunks):
                ad = f"{env.envelope_nonce}:{seq}".encode()
                ciphertext = bytes.fromhex(c_dict["c"])
                nonce = bytes.fromhex(c_dict["n"])
                c_bytes = decrypt(ciphertext, nonce, bytes(session_key), associated_data=ad)
                raw_chunks.append(c_bytes)

            _, reassembled = reassemble_chunked_transfer(raw_chunks)
            return reassembled
        finally:
            for i in range(len(session_key)):
                session_key[i] = 0
