"""
UXSP Live Streaming Module (`uxsp.core.live`)

High-performance, zero-parsing symmetric encryption for live streaming (WebRTC video frames,
DataChannels, or raw WebSockets). 

This module bypasses the standard JSON `SecurePackage` envelope format to provide millisecond
latency suitable for 60 FPS video calls and real-time CCTV pipelines.
"""

from __future__ import annotations

import os
import struct

from uxsp.crypto.symmetric import KEY_SIZE, NONCE_SIZE, encrypt, decrypt
from uxsp.crypto.kdf import derive_key
from uxsp.core.replay import ReplayError


class LiveSession:
    """
    Manages a blazing-fast AES-GCM symmetric session key for real-time video/audio frames.
    """

    def __init__(self, key: bytes | None = None, session_id: bytes | None = None) -> None:
        """
        Initialize the session. If key is None, a new random 256-bit key is generated.
        """
        if key is None:
            self.key = os.urandom(KEY_SIZE)
        else:
            if len(key) != KEY_SIZE:
                raise ValueError(f"LiveSession key must be {KEY_SIZE} bytes.")
            self.key = bytes(key)
        self.session_id_bytes = session_id if isinstance(session_id, bytes) else (session_id.encode() if session_id else os.urandom(16))
        self._frame_count = 0
        self._last_seq = -1

    def _ratchet_key(self) -> None:
        self.key = derive_key(self.key, info=b"UXSP-live-ratchet", length=32)
        self._frame_count = 0

    @classmethod
    def generate(cls) -> LiveSession:
        """Create a new LiveSession with a fresh cryptographic key."""
        return cls()

    def encrypt_frame(self, frame: bytes | bytearray, metadata: bytes = b"") -> bytes:
        """
        Encrypt a raw binary frame (e.g. video codec output).
        Optionally attaches unencrypted (but mathematically authenticated) metadata.
        
        Format: [2-byte Metadata Length] [Metadata Bytes] [12-byte Nonce] [Ciphertext]
        """
        if len(metadata) > 65535:
            raise ValueError("Metadata too large (max 65535 bytes).")

        ad = self.session_id_bytes + metadata
        enc_dict = encrypt(bytes(frame), self.key, associated_data=ad)
        
        # Combine length + metadata + nonce + ciphertext
        meta_len = struct.pack(">H", len(metadata))
        result = meta_len + metadata + enc_dict["nonce"] + enc_dict["ciphertext"]
        
        self._frame_count += 1
        if self._frame_count >= 65536:
            self._ratchet_key()
            
        return result

    def decrypt_frame(self, encrypted_frame: bytes | bytearray, expected_seq: int | None = None) -> tuple[bytes, bytes]:
        """
        Decrypt a raw binary frame received over the wire.
        Returns a tuple: (decrypted_frame_bytes, unencrypted_metadata_bytes)
        """
        if len(encrypted_frame) < 2:
            raise ValueError("Encrypted frame is too small to contain length header.")
        
        meta_len = struct.unpack(">H", encrypted_frame[:2])[0]
        
        if len(encrypted_frame) < 2 + meta_len + NONCE_SIZE:
            raise ValueError("Encrypted frame is too small to contain metadata and nonce.")
        
        metadata = encrypted_frame[2 : 2 + meta_len]
        nonce = encrypted_frame[2 + meta_len : 2 + meta_len + NONCE_SIZE]
        ciphertext = encrypted_frame[2 + meta_len + NONCE_SIZE :]
        
        ad = self.session_id_bytes + metadata
        decrypted = decrypt(ciphertext, nonce, self.key, associated_data=ad)
        
        if expected_seq is not None:
            if expected_seq <= self._last_seq:
                raise ReplayError("Frame replay detected")
            self._last_seq = expected_seq
            
        self._frame_count += 1
        if self._frame_count >= 65536:
            self._ratchet_key()
            
        return decrypted, metadata

    @classmethod
    def extract_metadata(cls, encrypted_frame: bytes | bytearray) -> bytes:
        """
        Utility for routing servers (SFUs) to inspect the unencrypted metadata 
        attached to a frame without needing the decryption key.
        """
        if len(encrypted_frame) < 2:
            raise ValueError("Malformed frame: too short to contain metadata length.")
        meta_len = struct.unpack(">H", encrypted_frame[:2])[0]
        if len(encrypted_frame) < 2 + meta_len:
            raise ValueError("Malformed frame: too short to contain full metadata.")
        return encrypted_frame[2 : 2 + meta_len]

    def encrypt_voice_frame(
        self,
        frame: bytes | bytearray,
        *,
        codec: str = "opus",
        sample_rate: int = 48000,
        channels: int = 1,
        sequence: int = 0,
        is_muted: bool = False,
        metadata: bytes = b"",
    ) -> bytes:
        """
        Encrypt a live audio/voice frame with authenticated voice metadata.
        """
        import json

        audio_meta = {
            "type": "voice",
            "codec": codec,
            "sample_rate": sample_rate,
            "channels": channels,
            "sequence": sequence,
            "is_muted": is_muted,
        }
        if metadata:
            audio_meta["extra"] = metadata.hex()

        meta_bytes = json.dumps(audio_meta, separators=(",", ":")).encode("utf-8")
        return self.encrypt_frame(frame, metadata=meta_bytes)

    def decrypt_voice_frame(
        self,
        encrypted_frame: bytes | bytearray,
    ) -> tuple[bytes, dict[str, Any]]:
        """
        Decrypt a live voice audio frame and return (decrypted_audio_bytes, audio_metadata_dict).
        """
        import json

        decrypted_frame, meta_bytes = self.decrypt_frame(encrypted_frame)
        try:
            audio_meta = json.loads(meta_bytes.decode("utf-8"))
            if "extra" in audio_meta and isinstance(audio_meta["extra"], str):
                audio_meta["extra_bytes"] = bytes.fromhex(audio_meta["extra"])
        except Exception:
            audio_meta = {"raw_metadata": meta_bytes}
        return decrypted_frame, audio_meta


class LiveVoiceSession(LiveSession):
    """
    Manages an encrypted live voice/audio call session between peers.
    Supports zero-latency audio frame encryption (Opus, PCM, AAC)
    with authenticated audio call metadata (codec, sample rate, sequence, mute state).
    """

    def __init__(
        self,
        key: bytes | None = None,
        session_id: bytes | None = None,
        codec: str = "opus",
        sample_rate: int = 48000,
        channels: int = 1,
    ) -> None:
        super().__init__(key=key, session_id=session_id)
        self.codec = codec
        self.sample_rate = sample_rate
        self.channels = channels
        self.sequence = 0
        self.is_muted = False

    @classmethod
    def generate_voice(
        cls,
        codec: str = "opus",
        sample_rate: int = 48000,
        channels: int = 1,
    ) -> LiveVoiceSession:
        """Create a new LiveVoiceSession with fresh cryptographic key and call settings."""
        return cls(key=None, session_id=None, codec=codec, sample_rate=sample_rate, channels=channels)

    def mute(self) -> None:
        """Mute local audio transmission state."""
        self.is_muted = True

    def unmute(self) -> None:
        """Unmute local audio transmission state."""
        self.is_muted = False

    def next_sequence(self) -> int:
        """Increment and return the next audio packet sequence number."""
        self.sequence += 1
        return self.sequence

    def encrypt_voice_frame(  # type: ignore[override]
        self,
        frame: bytes | bytearray,
        *,
        codec: str | None = None,
        sample_rate: int | None = None,
        channels: int | None = None,
        sequence: int | None = None,
        is_muted: bool | None = None,
        metadata: bytes = b"",
    ) -> bytes:
        """
        Encrypt a live audio frame using current voice session parameters.
        """
        seq = sequence if sequence is not None else self.next_sequence()
        muted = is_muted if is_muted is not None else self.is_muted
        cd = codec or self.codec
        sr = sample_rate or self.sample_rate
        ch = channels or self.channels

        return super().encrypt_voice_frame(
            frame,
            codec=cd,
            sample_rate=sr,
            channels=ch,
            sequence=seq,
            is_muted=muted,
            metadata=metadata,
        )

