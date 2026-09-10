"""
Tests for UXSP Native Async Secure Dispatchers (`uxsp.aio.secure`)
"""

import pytest

import uxsp
import uxsp.aio


@pytest.fixture
def alice_identity():
    return uxsp.create_identity("Alice", role="CLIENT")


@pytest.fixture
def bob_identity():
    return uxsp.create_identity("Bob", role="SERVER")


@pytest.mark.asyncio
async def test_async_send_receive_text(alice_identity, bob_identity):
    pkg = await uxsp.aio.SendText(
        text="Async hello world!",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    assert pkg is not None

    received = await uxsp.aio.ReceiveText(
        package=pkg,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert received == "Async hello world!"


@pytest.mark.asyncio
async def test_async_send_receive_json(alice_identity, bob_identity):
    data = {"order_id": 12345, "status": "APPROVED", "items": ["item1", "item2"]}
    pkg = await uxsp.aio.SendJSON(
        data=data,
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )

    received = await uxsp.aio.ReceiveJSON(
        package=pkg,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert received == data


@pytest.mark.asyncio
async def test_async_send_receive_binary(alice_identity, bob_identity):
    binary_data = b"\x00\x01\x02\x03\x04\xff"
    pkg = await uxsp.aio.SendBinary(
        data=binary_data,
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )

    received = await uxsp.aio.ReceiveBinary(
        package=pkg,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert received == binary_data


@pytest.mark.asyncio
async def test_async_send_receive_html(alice_identity, bob_identity):
    html_data = "<h1>Async Security</h1><p>Quantum safe</p>"
    pkg = await uxsp.aio.SendHTML(
        html_content=html_data,
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )

    received = await uxsp.aio.ReceiveHTML(
        package=pkg,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert received == html_data


@pytest.mark.asyncio
async def test_async_send_receive_location(alice_identity, bob_identity):
    pkg = await uxsp.aio.SendLocation(
        latitude=13.0827,
        longitude=80.2707,
        description="Chennai Central",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )

    received = await uxsp.aio.ReceiveLocation(
        package=pkg,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert received["latitude"] == 13.0827
    assert received["longitude"] == 80.2707
    assert received["description"] == "Chennai Central"


@pytest.mark.asyncio
async def test_async_send_receive_contact(alice_identity, bob_identity):
    contact = {"name": "Siva Raja", "email": "sivaraja5401@gmail.com"}
    pkg = await uxsp.aio.SendContact(
        contact_data=contact,
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )

    received = await uxsp.aio.ReceiveContact(
        package=pkg,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert received == contact


@pytest.mark.asyncio
async def test_async_send_receive_files_and_media(tmp_path, alice_identity, bob_identity):
    # Test SendFile & ReceiveFile
    f = tmp_path / "test.txt"
    f.write_text("File content for async test", encoding="utf-8")

    pkg_file = await uxsp.aio.SendFile(
        file_path_or_bytes=f,
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    out_file = await uxsp.aio.ReceiveFile(
        package=pkg_file,
        download_path=tmp_path / "out.txt",
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert out_file.read_text(encoding="utf-8") == "File content for async test"

    # Test SendVideo & ReceiveVideo
    v = tmp_path / "test.mp4"
    v.write_bytes(b"\x00\x00\x00\x1cftypisom")
    pkg_video = await uxsp.aio.SendVideo(
        video_path_or_bytes=v,
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    out_video = await uxsp.aio.ReceiveVideo(
        package=pkg_video,
        download_path=tmp_path / "out.mp4",
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert out_video.read_bytes() == b"\x00\x00\x00\x1cftypisom"

    # Test SendAudio & ReceiveAudio
    pkg_audio = await uxsp.aio.SendAudio(
        audio_path_or_bytes=b"AUDIOBYTES",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    out_audio = await uxsp.aio.ReceiveAudio(
        package=pkg_audio,
        download_path=tmp_path / "out.mp3",
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert out_audio.read_bytes() == b"AUDIOBYTES"

    # Test SendPhoto & ReceivePhoto (and SendImage / ReceiveImage aliases)
    pkg_photo = await uxsp.aio.SendPhoto(
        photo_path_or_bytes=b"PHOTOBYTES",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    out_photo = await uxsp.aio.ReceivePhoto(
        package=pkg_photo,
        download_path=tmp_path / "out.jpg",
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert out_photo.read_bytes() == b"PHOTOBYTES"

    # Test SendDocument & ReceiveDocument (and SendDoc / ReceiveDoc aliases)
    pkg_doc = await uxsp.aio.SendDoc(
        doc_path_or_bytes=b"DOCBYTES",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    out_doc = await uxsp.aio.ReceiveDoc(
        package=pkg_doc,
        download_path=tmp_path / "out.docx",
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert out_doc.read_bytes() == b"DOCBYTES"

    # Test SendPDF & ReceivePDF
    pkg_pdf = await uxsp.aio.SendPDF(
        pdf_path_or_bytes=b"PDFBYTES",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    out_pdf = await uxsp.aio.ReceivePDF(
        package=pkg_pdf,
        download_path=tmp_path / "out.pdf",
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert out_pdf.read_bytes() == b"PDFBYTES"

    # Test SendArchive & ReceiveArchive (and SendZip / ReceiveZip aliases)
    pkg_zip = await uxsp.aio.SendZip(
        archive_path_or_bytes=b"ZIPBYTES",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    out_zip = await uxsp.aio.ReceiveZip(
        package=pkg_zip,
        download_path=tmp_path / "out.zip",
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert out_zip.read_bytes() == b"ZIPBYTES"

    # Test SendVoice & ReceiveVoice
    pkg_voice = await uxsp.aio.SendVoice(
        voice_path_or_bytes=b"VOICEBYTES",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    out_voice = await uxsp.aio.ReceiveVoice(
        package=pkg_voice,
        download_path=tmp_path / "out.ogg",
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert out_voice.read_bytes() == b"VOICEBYTES"


@pytest.mark.asyncio
async def test_async_universal_send_receive(alice_identity, bob_identity):
    # Test string text via universal Send/Receive
    pkg_text = await uxsp.aio.Send(
        item="Polymorphic async text",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    rec_text = await uxsp.aio.Receive(
        package=pkg_text,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert rec_text == "Polymorphic async text"

    # Test dict JSON via universal Send/Receive
    pkg_json = await uxsp.aio.Send(
        item={"key": "value"},
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    rec_json = await uxsp.aio.Receive(
        package=pkg_json,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert rec_json == {"key": "value"}

    # Test binary bytes via universal Send/Receive
    pkg_bin = await uxsp.aio.Send(
        item=b"binary_payload",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    rec_bin = await uxsp.aio.Receive(
        package=pkg_bin,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert rec_bin == b"binary_payload"

    # Test data_type overrides
    for dt, payload in [
        ("text", "plain text"),
        ("json", {"a": 1}),
        ("binary", b"raw"),
        ("html", "<h1>test</h1>"),
        ("contact", {"name": "Test"}),
    ]:
        pkg_dt = await uxsp.aio.Send(
            item=payload,
            data_type=dt,
            receiver=bob_identity.public_card(),
            sender=alice_identity,
        )
        rec_dt = await uxsp.aio.Receive(
            package=pkg_dt,
            sender=alice_identity.public_card(),
            receiver=bob_identity,
        )
        assert rec_dt is not None

    # Test live session polymorphic
    pkg_live = await uxsp.aio.Send(
        data_type="live_session",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    rec_live = await uxsp.aio.Receive(
        package=pkg_live,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert rec_live is not None

    pkg_live_voice = await uxsp.aio.Send(
        data_type="live_voice_session",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    rec_live_voice = await uxsp.aio.Receive(
        package=pkg_live_voice,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert rec_live_voice is not None

    # Test file path polymorphic
    import tempfile
    from pathlib import Path
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"file content")
        tmp_txt = Path(f.name)
    try:
        pkg_file = await uxsp.aio.Send(
            item=tmp_txt,
            receiver=bob_identity.public_card(),
            sender=alice_identity,
        )
        assert pkg_file is not None
    finally:
        tmp_txt.unlink(missing_ok=True)

    # Test unknown type error
    from uxsp.secure import SecureSendError
    with pytest.raises(SecureSendError, match="Cannot automatically infer data type"):
        await uxsp.aio.Send(
            item=object(),
            receiver=bob_identity.public_card(),
            sender=alice_identity,
        )


@pytest.mark.asyncio
async def test_async_polymorphic_all_types(alice_identity, bob_identity, tmp_path):
    # data_type explicit send & receive
    types_and_payloads = [
        ("video", b"fake_mp4_bytes"),
        ("audio", b"fake_mp3_bytes"),
        ("photo", b"fake_jpg_bytes"),
        ("document", b"fake_doc_bytes"),
        ("pdf", b"fake_pdf_bytes"),
        ("archive", b"fake_zip_bytes"),
        ("voice", b"fake_voice_bytes"),
        ("file", b"fake_file_bytes"),
        ("location", {"latitude": 37.77, "longitude": -122.41}),
        ("contact", {"name": "Charlie", "phone": "555-0199"}),
    ]

    for dt, payload in types_and_payloads:
        pkg = await uxsp.aio.Send(
            item=payload,
            data_type=dt,
            receiver=bob_identity.public_card(),
            sender=alice_identity,
        )
        assert pkg is not None
        rec = await uxsp.aio.Receive(
            package=pkg,
            sender=alice_identity.public_card(),
            receiver=bob_identity,
        )
        assert rec is not None

    # Location variants (tuple and None)
    pkg_tuple = await uxsp.aio.Send(item=(37.77, -122.41), data_type="location", receiver=bob_identity.public_card(), sender=alice_identity)
    assert pkg_tuple is not None
    pkg_none = await uxsp.aio.Send(item=None, data_type="location", receiver=bob_identity.public_card(), sender=alice_identity)
    assert pkg_none is not None

    # Live session via Send/Receive
    pkg_ls = await uxsp.aio.Send(
        data_type="live_session",
        receiver=bob_identity.public_card(),
        sender=alice_identity,
    )
    rec_ls = await uxsp.aio.Receive(
        package=pkg_ls,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert rec_ls is not None

    # Path extension inference
    extensions = [
        (".mp4", b"mp4"),
        (".mp3", b"mp3"),
        (".png", b"png"),
        (".pdf", b"pdf"),
        (".zip", b"zip"),
        (".html", b"<html>test</html>"),
        (".json", b'{"key": "val"}'),
        (".dat", b"dat"),
    ]
    for ext, content in extensions:
        p = tmp_path / f"test{ext}"
        p.write_bytes(content)
        pkg_ext = await uxsp.aio.Send(
            item=p,
            receiver=bob_identity.public_card(),
            sender=alice_identity,
        )
        assert pkg_ext is not None

    # Fallback to async_secure_receive_payload for custom data_type
    from uxsp.aio._engine import async_secure_send_payload
    custom_pkg = await async_secure_send_payload(
        receiver=bob_identity,
        payload_bytes=b"custom_payload",
        sender=alice_identity,
        data_type="custom_type",
    )
    custom_rec = await uxsp.aio.Receive(
        package=custom_pkg,
        sender=alice_identity.public_card(),
        receiver=bob_identity,
    )
    assert custom_rec == b"custom_payload"


@pytest.mark.asyncio
async def test_async_context_helpers(alice_identity, bob_identity):
    from uxsp.aio.secure import (
        get_identity,
        get_peer,
        register_peer,
        reset_context,
        revoke_peer,
        rotate_keys,
        set_identity,
        verify_peer_validity,
    )
    await reset_context()
    await set_identity(alice_identity)
    cur = await get_identity()
    assert cur.entity_id == alice_identity.entity_id

    await register_peer(bob_identity.public_card())
    peer = await get_peer(bob_identity.entity_id)
    assert peer.entity_id == bob_identity.entity_id

    await verify_peer_validity(bob_identity.entity_id)

    revoked = await revoke_peer(bob_identity.entity_id, reason="testing")
    assert revoked.is_revoked is True

    rotated = await rotate_keys(alice_identity)
    assert rotated is not None

    await reset_context()



@pytest.mark.asyncio
async def test_async_live_session(alice_identity, bob_identity):
    # Test SendLiveSession
    pkg, sender_session = await uxsp.aio.SendLiveSession(
        receiver=bob_identity.public_card(),
        sender=alice_identity,
        metadata={"video": "h264"}
    )
    assert sender_session is not None
    assert pkg.metadata["video"] == "h264"

    # Test ReceiveLiveSession
    receiver_session = await uxsp.aio.ReceiveLiveSession(
        sender=alice_identity.public_card(),
        package=pkg,
        receiver=bob_identity
    )
    assert receiver_session is not None

    # Verify the sessions matched keys
    assert sender_session.key == receiver_session.key


@pytest.mark.asyncio
async def test_async_live_voice_call(alice_identity, bob_identity):
    pkg, sender_voice_session = await uxsp.aio.SendLiveVoiceCall(
        receiver=bob_identity.public_card(),
        sender=alice_identity,
        codec="opus",
        sample_rate=48000,
        channels=1,
    )
    assert sender_voice_session is not None
    assert pkg.data_type == "live_voice_session"

    receiver_voice_session = await uxsp.aio.ReceiveLiveVoiceCall(
        sender=alice_identity.public_card(),
        package=pkg,
        receiver=bob_identity,
    )
    assert receiver_voice_session is not None
    assert sender_voice_session.key == receiver_voice_session.key
    assert receiver_voice_session.codec == "opus"

    # Test voice frame roundtrip
    frame = b"opus_audio_frame_data"
    enc = sender_voice_session.encrypt_voice_frame(frame)
    dec, meta = receiver_voice_session.decrypt_voice_frame(enc)
    assert dec == frame
    assert meta["codec"] == "opus"

