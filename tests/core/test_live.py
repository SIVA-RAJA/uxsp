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

def test_livesession_ratcheting():
    session1 = LiveSession.generate()
    session2 = LiveSession(session1.key, session_id=session1.session_id_bytes)

    session1._frame_count = 65535
    session2._frame_count = 65535

    frame = b"hello ratchet"
    enc = session1.encrypt_frame(frame)
    assert session1._frame_count == 0

    dec, _ = session2.decrypt_frame(enc)
    assert session2._frame_count == 0
    assert dec == frame
    assert session1.key == session2.key

def test_livesession_replay_protection():
    session = LiveSession.generate()
    frame = b"hello replay"
    enc = session.encrypt_frame(frame)

    dec, _ = session.decrypt_frame(enc, expected_seq=5)
    assert dec == frame
    assert session._last_seq == 5

    from uxsp.core.replay import ReplayError
    with pytest.raises(ReplayError, match="Frame replay detected"):
        session.decrypt_frame(enc, expected_seq=5)

    with pytest.raises(ReplayError, match="Frame replay detected"):
        session.decrypt_frame(enc, expected_seq=4)

def test_livesession_session_binding():
    key = b"A" * 32
    session1 = LiveSession(key, session_id=b"session1")
    session2 = LiveSession(key, session_id=b"session2")

    frame = b"hello binding"
    enc = session1.encrypt_frame(frame)

    with pytest.raises(ValueError, match="Decryption failed"):
        session2.decrypt_frame(enc)


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
    with pytest.raises(ValueError, match="too short to contain metadata length"):
        LiveSession.extract_metadata(b"\x00")

    # Line 86: extract_metadata length header larger than buffer
    with pytest.raises(ValueError, match="too short to contain full metadata"):
        LiveSession.extract_metadata(b"\xff\xff\x00")


def test_livevoicesession_voice_frames():
    from uxsp.core.live import LiveVoiceSession

    session = LiveVoiceSession.generate_voice(codec="opus", sample_rate=48000, channels=2)
    assert session.codec == "opus"
    assert session.sample_rate == 48000
    assert session.channels == 2
    assert session.sequence == 0
    assert not session.is_muted

    session.mute()
    assert session.is_muted
    session.unmute()
    assert not session.is_muted

    audio_frame = b"\x01\x02\x03\x04\x05\x06"
    encrypted = session.encrypt_voice_frame(audio_frame, metadata=b"mic1")

    decrypted, meta = session.decrypt_voice_frame(encrypted)
    assert decrypted == audio_frame
    assert meta["type"] == "voice"
    assert meta["codec"] == "opus"
    assert meta["sample_rate"] == 48000
    assert meta["channels"] == 2
    assert meta["sequence"] == 1
    assert meta["is_muted"] is False
    assert meta["extra_bytes"] == b"mic1"

    # Encrypt on base LiveSession as well
    base_session = LiveSession.generate()
    enc_base = base_session.encrypt_voice_frame(audio_frame, codec="pcm", sample_rate=16000, channels=1, sequence=5, is_muted=True)
    dec_base, meta_base = base_session.decrypt_voice_frame(enc_base)
    assert dec_base == audio_frame
    assert meta_base["codec"] == "pcm"
    assert meta_base["sample_rate"] == 16000
    assert meta_base["sequence"] == 5
    assert meta_base["is_muted"] is True

    # Test corrupted json metadata handling in decrypt_voice_frame
    raw_enc = base_session.encrypt_frame(audio_frame, metadata=b"not json")
    dec_raw, meta_raw = base_session.decrypt_voice_frame(raw_enc)
    assert dec_raw == audio_frame
    assert meta_raw == {"raw_metadata": b"not json"}


