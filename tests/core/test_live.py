import pytest

from uxsp.core.live import LiveSession

def test_livesession_generation():
    session = LiveSession.generate()
    assert len(session.key) == 32

    # Restoring from key
    session2 = LiveSession(session.key)
    assert session2.key == session.key

def test_livesession_encryption():
    session = LiveSession.generate()
    frame = b"hello video frame"
    metadata = b'{"vol": 85}'

    encrypted = session.encrypt_frame(frame, metadata)
    
    # Verify we can extract metadata without decryption key
    extracted_meta = LiveSession.extract_metadata(encrypted)
    assert extracted_meta == metadata

    # Decrypt and verify
    decrypted, dec_meta = session.decrypt_frame(encrypted)
    assert decrypted == frame
    assert dec_meta == metadata

def test_livesession_tamper_metadata():
    session = LiveSession.generate()
    frame = b"hello video frame"
    metadata = b'{"vol": 85}'

    encrypted = session.encrypt_frame(frame, metadata)
    
    # Tamper with the metadata length (first 2 bytes)
    tampered_len = bytearray(encrypted)
    tampered_len[1] = tampered_len[1] ^ 0xFF
    with pytest.raises(ValueError, match="(Decryption failed|too small)"):
        session.decrypt_frame(bytes(tampered_len))

    # Tamper with the metadata content
    tampered_meta = bytearray(encrypted)
    tampered_meta[3] = tampered_meta[3] ^ 0xFF
    with pytest.raises(ValueError, match="Decryption failed"):
        session.decrypt_frame(bytes(tampered_meta))

def test_livesession_tamper_ciphertext():
    session = LiveSession.generate()
    frame = b"hello video frame"
    
    encrypted = session.encrypt_frame(frame)
    
    tampered = bytearray(encrypted)
    tampered[-1] = tampered[-1] ^ 0xFF
    
    with pytest.raises(ValueError, match="Decryption failed"):
        session.decrypt_frame(bytes(tampered))


def test_livesession_exceptions():
    # Line 32: bad key size
    with pytest.raises(ValueError, match="LiveSession key must be 32 bytes"):
        LiveSession(key=b"too_short")

    session = LiveSession.generate()

    # Line 48: metadata too large
    huge_metadata = b"A" * 65536
    with pytest.raises(ValueError, match="Metadata too large"):
        session.encrypt_frame(b"frame", huge_metadata)

    # Line 62: encrypted frame too small (no length header)
    with pytest.raises(ValueError, match="too small to contain length header"):
        session.decrypt_frame(b"\x00")

    # Line 83: extract_metadata < 2 bytes
    assert LiveSession.extract_metadata(b"\x00") == b""

    # Line 86: extract_metadata length header larger than buffer
    assert LiveSession.extract_metadata(b"\xff\xff\x00") == b""

