from __future__ import annotations

from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.secure._package import SecurePackage
from uxsp.secure._engine import _secure_send_payload, _secure_receive_payload, _resolve_package_input

def SendLiveSession(
    receiver_id: str | int | PublicCard | Identity | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[SecurePackage, __import__("uxsp.core.live", fromlist=["LiveSession"]).LiveSession]:
    """
    Negotiate a high-performance AES-GCM LiveSession for WebRTC video or socket streams.
    Returns a tuple: (The encrypted SecurePackage to send, The local LiveSession).
    """
    from uxsp.core.live import LiveSession

    session = LiveSession.generate()
    meta = metadata or {}
    meta["uxsp_live_exchange"] = True
    meta["session_id"] = session.session_id_bytes.hex()

    pkg = _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=session.key,
        data_type="live_session",
        metadata=meta,
    )

    return pkg, session


def ReceiveLiveSession(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: str | dict[str, Any] | SecurePackage | None = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> __import__("uxsp.core.live", fromlist=["LiveSession"]).LiveSession:
    """
    Accept a high-performance AES-GCM LiveSession from a peer.
    Returns the decrypted, ready-to-use LiveSession.
    """
    from uxsp.core.live import LiveSession

    pkg = _resolve_package_input(package)
    key_bytes = _secure_receive_payload(
        sender_id=sender_id,
        package_input=pkg,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        expected_type="live_session",
    )
    meta = pkg.metadata or {}
    session_id_hex = meta.get("session_id")
    session_id = bytes.fromhex(session_id_hex) if session_id_hex else None
    return LiveSession(key=key_bytes, session_id=session_id)


def SendLiveVoiceCall(
    receiver_id: str | int | PublicCard | Identity | None = None,
    *,
    receiver: str | int | PublicCard | Identity | None = None,
    sender: Identity | None = None,
    sender_identity: Identity | None = None,
    codec: str = "opus",
    sample_rate: int = 48000,
    channels: int = 1,
    metadata: dict[str, Any] | None = None,
) -> tuple[SecurePackage, __import__("uxsp.core.live", fromlist=["LiveVoiceSession"]).LiveVoiceSession]:
    """
    Negotiate a high-performance AES-GCM LiveVoiceSession for live voice calling / audio streaming.
    Returns a tuple: (The encrypted SecurePackage to send, The local LiveVoiceSession).
    """
    from uxsp.core.live import LiveVoiceSession

    session = LiveVoiceSession.generate_voice(codec=codec, sample_rate=sample_rate, channels=channels)
    meta = metadata or {}
    meta["uxsp_live_voice_exchange"] = True
    meta["session_id"] = session.session_id_bytes.hex()
    meta["codec"] = codec
    meta["sample_rate"] = sample_rate
    meta["channels"] = channels

    pkg = _secure_send_payload(
        receiver_id=receiver_id,
        receiver=receiver,
        sender=sender,
        sender_identity=sender_identity,
        payload_bytes=session.key,
        data_type="live_voice_session",
        metadata=meta,
    )

    return pkg, session


def ReceiveLiveVoiceCall(
    sender_id: str | int | PublicCard | Identity | None = None,
    package: str | dict[str, Any] | SecurePackage | None = None,
    *,
    sender: str | int | PublicCard | Identity | None = None,
    sender_card: PublicCard | Identity | None = None,
    receiver: Identity | None = None,
    receiver_identity: Identity | None = None,
) -> __import__("uxsp.core.live", fromlist=["LiveVoiceSession"]).LiveVoiceSession:
    """
    Accept a high-performance AES-GCM LiveVoiceSession from a peer for live voice calling.
    Returns the decrypted, ready-to-use LiveVoiceSession.
    """
    from uxsp.core.live import LiveVoiceSession

    pkg = _resolve_package_input(package)
    key_bytes = _secure_receive_payload(
        sender_id=sender_id,
        package_input=pkg,
        sender=sender,
        sender_card=sender_card,
        receiver=receiver,
        receiver_identity=receiver_identity,
        expected_type="live_voice_session",
    )
    meta = pkg.metadata or {}
    session_id_hex = meta.get("session_id")
    session_id = bytes.fromhex(session_id_hex) if session_id_hex else None
    codec = meta.get("codec", "opus")
    sample_rate = meta.get("sample_rate", 48000)
    channels = meta.get("channels", 1)

    return LiveVoiceSession(key=key_bytes, session_id=session_id, codec=codec, sample_rate=sample_rate, channels=channels)


SendLiveVoice = SendLiveVoiceCall
ReceiveLiveVoice = ReceiveLiveVoiceCall
SendVoiceCall = SendLiveVoiceCall
ReceiveVoiceCall = ReceiveLiveVoiceCall
