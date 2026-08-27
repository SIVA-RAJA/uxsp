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


class LiveSession:
    """
    Manages a blazing-fast AES-GCM symmetric session key for real-time video/audio frames.
    """

    def __init__(self, key: bytes | None = None) -> None:
        """
        Initialize the session. If key is None, a new random 256-bit key is generated.
        """
        if key is None:
            self.key = os.urandom(KEY_SIZE)
        else:
            if len(key) != KEY_SIZE:
                raise ValueError(f"LiveSession key must be {KEY_SIZE} bytes.")
            self.key = bytes(key)

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

        enc_dict = encrypt(bytes(frame), self.key, associated_data=metadata)
        
        # Combine length + metadata + nonce + ciphertext
        meta_len = struct.pack(">H", len(metadata))
        return meta_len + metadata + enc_dict["nonce"] + enc_dict["ciphertext"]

    def decrypt_frame(self, encrypted_frame: bytes | bytearray) -> tuple[bytes, bytes]:
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
        
        decrypted = decrypt(ciphertext, nonce, self.key, associated_data=metadata)
        return decrypted, metadata

    @classmethod
    def extract_metadata(cls, encrypted_frame: bytes | bytearray) -> bytes:
        """
        Utility for routing servers (SFUs) to inspect the unencrypted metadata 
        attached to a frame without needing the decryption key.
        """
        if len(encrypted_frame) < 2:
            return b""
        meta_len = struct.unpack(">H", encrypted_frame[:2])[0]
        if len(encrypted_frame) < 2 + meta_len:
            return b""
        return encrypted_frame[2 : 2 + meta_len]
