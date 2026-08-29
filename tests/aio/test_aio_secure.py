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

