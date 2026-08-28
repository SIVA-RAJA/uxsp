"""
tests.core.test_secure — Comprehensive Tests for uxsp.secure simple Workflow
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

import uxsp
from uxsp.core.identity import Identity
from uxsp.core.replay import ReplayError
from uxsp.core.signing import TrustAnchor
from uxsp.secure import (
    PeerNotFoundError,
    Receive,
    ReceiveArchive,
    ReceiveAudio,
    ReceiveBinary,
    ReceiveContact,
    ReceiveDoc,
    ReceiveDocument,
    ReceiveFile,
    ReceiveHTML,
    ReceiveImage,
    ReceiveJSON,
    ReceiveLocation,
    ReceivePDF,
    ReceivePhoto,
    ReceiveText,
    ReceiveVideo,
    ReceiveVoice,
    ReceiveZip,
    SecureContext,
    SecurePackage,
    SecureReceiveError,
    SecureSendError,
    Send,
    SendArchive,
    SendAudio,
    SendBinary,
    SendContact,
    SendDoc,
    SendDocument,
    SendFile,
    SendHTML,
    SendImage,
    SendJSON,
    SendLocation,
    SendPDF,
    SendPhoto,
    SendText,
    SendVideo,
    SendVoice,
    SendZip,
    TypeMismatchError,
    configure,
    get_context,
    get_identity,
    get_peer,
    register_peer,
    reset_context,
    set_identity,
)


@pytest.fixture(autouse=True)
def setup_and_teardown():
    """Reset global context before and after each test."""
    reset_context()
    yield
    reset_context()


@pytest.fixture
def temp_dir():
    """Provide a clean temporary directory for files."""
    d = tempfile.mkdtemp(prefix="uxsp_test_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def alice_and_bob():
    """Create two identities and register each other as peers."""
    alice = Identity.create(name="Alice", role="client")
    bob = Identity.create(name="Bob", role="server")
    return alice, bob


class TestSecurePackage:
    def test_package_to_and_from_dict(self):
        pkg = SecurePackage(
            sender_id="alice",
            receiver_id="bob",
            data_type="video",
            is_chunked=False,
            envelope={"header": {"v": 1}},
            metadata={"priority": "high"},
        )
        d = pkg.to_dict()
        assert d["sender_id"] == "alice"
        assert d["receiver_id"] == "bob"
        assert d["data_type"] == "video"
        assert d["is_chunked"] is False
        assert d["metadata"] == {"priority": "high"}

        pkg2 = SecurePackage.from_dict(d)
        assert pkg2.sender_id == pkg.sender_id
        assert pkg2.receiver_id == pkg.receiver_id
        assert pkg2.data_type == pkg.data_type
        assert pkg2.is_chunked == pkg.is_chunked
        assert pkg2.metadata == pkg.metadata

    def test_package_json_and_file_roundtrip(self, temp_dir):
        pkg = SecurePackage(
            sender_id="alice",
            receiver_id="bob",
            data_type="text",
            is_chunked=False,
            envelope={"header": {"v": 1}},
        )
        json_str = pkg.to_json()
        pkg_from_json = SecurePackage.from_json(json_str)
        assert pkg_from_json.sender_id == "alice"

        file_path = temp_dir / "pkg.json"
        pkg.save(file_path)
        pkg_from_file = SecurePackage.from_file(file_path)
        assert pkg_from_file.sender_id == "alice"
        assert pkg_from_file.receiver_id == "bob"

    def test_from_dict_invalid_type_raises(self):
        with pytest.raises(SecureReceiveError, match="must be a dictionary"):
            SecurePackage.from_dict("not a dict")  # type: ignore

    def test_from_json_malformed_raises(self):
        with pytest.raises(SecureReceiveError, match="Failed to parse JSON"):
            SecurePackage.from_json("invalid json{{{")

    def test_from_file_missing_raises(self, temp_dir):
        with pytest.raises(SecureReceiveError, match="Package file not found"):
            SecurePackage.from_file(temp_dir / "non_existent.json")


class TestSecureContext:
    def test_default_identity_creation(self):
        ctx = SecureContext()
        ident = ctx.get_identity()
        assert ident is not None
        assert ident.name == "DefaultUser"
        # Subsequent call returns same instance
        assert ctx.get_identity() is ident

    def test_custom_identity_and_peer_registration(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        assert get_identity().entity_id == alice.entity_id

        register_peer(bob.public_card())
        peer = get_peer(bob.entity_id)
        assert peer.entity_id == bob.entity_id

        # Also register via Identity instance
        charlie = Identity.create(name="Charlie", role="client")
        register_peer(charlie)
        assert get_peer(charlie.entity_id).entity_id == charlie.entity_id

    def test_get_peer_unregistered_raises(self):
        with pytest.raises(PeerNotFoundError, match="No public card registered"):
            get_peer("unknown_entity_999")

    def test_configure_and_transport_hook(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        dispatched = []
        configure(transport_hook=lambda p: dispatched.append(p))

        SendText(bob.entity_id, "Hello Hook!")
        assert len(dispatched) == 1
        assert dispatched[0].sender_id == alice.entity_id


class TestSendAndReceiveVideo:
    def test_send_and_receive_video_small(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # Create dummy small video (10 KB)
        sample_video_bytes = b"\x00\x00\x00\x18ftypmp42" + (b"VIDEODATA" * 1000)
        video_path = temp_dir / "sample.mp4"
        video_path.write_bytes(sample_video_bytes)

        # Alice sends video to Bob
        package = SendVideo(bob.entity_id, video_path)
        assert package.is_chunked is False
        assert package.data_type == "video"

        # Bob receives video from Alice
        set_identity(bob)
        register_peer(alice)

        download_path = temp_dir / "received_sample.mp4"
        out_path = ReceiveVideo(alice.entity_id, download_path, package=package)

        assert out_path.exists()
        assert out_path.read_bytes() == sample_video_bytes

    def test_send_and_receive_video_large_chunked(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # Create large video (150 KB > 64 KB envelope limit)
        large_video_bytes = b"\x00\x00\x00\x18ftypmp42" + os.urandom(150 * 1024)
        video_path = temp_dir / "large.mp4"
        video_path.write_bytes(large_video_bytes)

        # Alice sends large video
        package = SendVideo(bob.entity_id, video_path)
        assert package.is_chunked is True
        assert len(package.chunks) > 1

        # Bob receives large video
        set_identity(bob)
        register_peer(alice)

        out_dir = temp_dir / "bob_downloads"
        out_path = ReceiveVideo(alice.entity_id, out_dir, package=package)

        assert out_path.exists()
        assert out_path.read_bytes() == large_video_bytes
        assert out_path.name == "large.mp4"

    def test_send_video_bytes_input(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        raw_vid = b"DUMMY_VIDEO_STREAM_BYTES"
        package = SendVideo(bob.entity_id, raw_vid, filename="stream.mp4")

        set_identity(bob)
        register_peer(alice)

        out_path = ReceiveVideo(alice.entity_id, temp_dir, package=package)
        assert out_path.read_bytes() == raw_vid
        assert out_path.name == "stream.mp4"

    def test_send_video_with_integer_ids(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        # Test integer ID conversion
        set_identity(alice)
        register_peer(bob)

        vid_bytes = b"INT_ID_VIDEO"
        package = SendVideo(bob.entity_id, vid_bytes)

        set_identity(bob)
        register_peer(alice)

        out = ReceiveVideo(alice.entity_id, temp_dir / "int_vid.mp4", package=package)
        assert out.read_bytes() == vid_bytes

    def test_send_video_invalid_input_raises(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        with pytest.raises(SecureSendError, match="must be a file path"):
            SendVideo(bob.entity_id, 12345)  # type: ignore


class Test14DataTypes:
    def test_audio_send_receive(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        audio_data = b"ID3\x03\x00\x00\x00" + os.urandom(80 * 1024)  # chunked
        pkg = SendAudio(bob.entity_id, audio_data, filename="track.mp3")

        set_identity(bob)
        register_peer(alice)
        out = ReceiveAudio(alice.entity_id, temp_dir / "track.mp3", package=pkg)
        assert out.read_bytes() == audio_data

    def test_photo_and_image_send_receive(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        photo_data = b"\xff\xd8\xff\xe0\x00\x10JFIF" + os.urandom(5000)
        pkg = SendPhoto(bob.entity_id, photo_data, filename="profile.jpg")

        set_identity(bob)
        register_peer(alice)
        out = ReceivePhoto(alice.entity_id, temp_dir / "profile.jpg", package=pkg)
        assert out.read_bytes() == photo_data

        # Alias SendImage / ReceiveImage
        set_identity(alice)
        pkg2 = SendImage(bob.entity_id, photo_data, filename="profile2.jpg")
        set_identity(bob)
        out2 = ReceiveImage(alice.entity_id, temp_dir / "profile2.jpg", package=pkg2)
        assert out2.read_bytes() == photo_data

    def test_text_send_receive(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        message = "Post-Quantum Security with UXSP! 🚀🔐"
        pkg = SendText(bob.entity_id, message)

        set_identity(bob)
        register_peer(alice)
        text_out = ReceiveText(alice.entity_id, package=pkg)
        assert text_out == message

        # Test writing to file when download_path is provided
        text_file = temp_dir / "msg.txt"
        # Reset replay guard to test re-decrypting with download_path
        reset_context()
        set_identity(alice)
        register_peer(bob)
        pkg_new = SendText(bob.entity_id, message)
        set_identity(bob)
        register_peer(alice)
        text_out2 = ReceiveText(alice.entity_id, package=pkg_new, download_path=text_file)
        assert text_out2 == message
        assert text_file.read_text(encoding="utf-8") == message

    def test_document_and_doc_send_receive(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        doc_data = b"CONFIDENTIAL DOCUMENT CONTENT"
        pkg = SendDocument(bob.entity_id, doc_data, filename="report.docx")

        set_identity(bob)
        register_peer(alice)
        out = ReceiveDocument(alice.entity_id, temp_dir / "report.docx", package=pkg)
        assert out.read_bytes() == doc_data

        # Alias SendDoc / ReceiveDoc
        set_identity(alice)
        pkg2 = SendDoc(bob.entity_id, doc_data, filename="report2.docx")
        set_identity(bob)
        out2 = ReceiveDoc(alice.entity_id, temp_dir / "report2.docx", package=pkg2)
        assert out2.read_bytes() == doc_data

    def test_pdf_send_receive(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pdf_bytes = b"%PDF-1.7\nSample PDF payload"
        pdf_file = temp_dir / "test.pdf"
        pdf_file.write_bytes(pdf_bytes)

        pkg = SendPDF(bob.entity_id, pdf_file)

        set_identity(bob)
        register_peer(alice)
        out = ReceivePDF(alice.entity_id, temp_dir / "downloaded.pdf", package=pkg)
        assert out.read_bytes() == pdf_bytes

    def test_generic_file_send_receive(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        data = b"Custom generic file data 12345"
        fpath = temp_dir / "custom.dat"
        fpath.write_bytes(data)

        pkg = SendFile(bob.entity_id, fpath)

        set_identity(bob)
        register_peer(alice)
        out = ReceiveFile(alice.entity_id, temp_dir / "received_custom.dat", package=pkg)
        assert out.read_bytes() == data

    @pytest.mark.parametrize("sender_func, data_type", [
        (SendFile, "file"),
        (SendVideo, "video"),
        (SendAudio, "audio"),
        (SendPhoto, "photo"),
        (SendDocument, "document"),
        (SendArchive, "archive"),
        (SendPDF, "pdf"),
        (SendVoice, "voice"),
    ])
    def test_generic_file_large_streaming(self, alice_and_bob, temp_dir, monkeypatch, sender_func, data_type):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # Mock stat().st_size to return > 64MB without creating a massive file
        from pathlib import Path
        original_stat = Path.stat
        class MockStat:
            st_size = 70 * 1024 * 1024
        def mock_stat(self):
            return MockStat()
        monkeypatch.setattr(Path, "stat", mock_stat)
        
        # We also need a dummy file so open() doesn't fail
        dummy_path = temp_dir / "fake_huge.dat"
        dummy_path.write_bytes(b"dummy")

        # It should return a Generator since it delegates to SendStream
        gen = sender_func(bob.entity_id, dummy_path)
        
        import types
        assert isinstance(gen, types.GeneratorType), f"{sender_func.__name__} did not return a generator for > 64MB file"
        
        # Pull one chunk to verify it yields packages
        pkg = next(gen)
        assert pkg.data_type == data_type

    def test_binary_send_receive(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        raw = os.urandom(1024)
        pkg = SendBinary(bob.entity_id, raw)

        set_identity(bob)
        register_peer(alice)
        res_bytes = ReceiveBinary(alice.entity_id, package=pkg)
        assert res_bytes == raw

    def test_json_send_receive(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        data = {"user": "Alice", "balance": 1500.50, "roles": ["admin", "editor"]}
        pkg = SendJSON(bob.entity_id, data)

        set_identity(bob)
        register_peer(alice)
        res_data = ReceiveJSON(alice.entity_id, package=pkg)
        assert res_data == data

    def test_html_send_receive(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        html = "<html><body><h1>Encrypted Portal</h1></body></html>"
        pkg = SendHTML(bob.entity_id, html)

        set_identity(bob)
        register_peer(alice)
        res_html = ReceiveHTML(alice.entity_id, package=pkg)
        assert res_html == html

    def test_archive_and_zip_send_receive(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        zip_bytes = b"PK\x03\x04" + os.urandom(2048)
        pkg = SendArchive(bob.entity_id, zip_bytes, filename="data.zip")

        set_identity(bob)
        register_peer(alice)
        out = ReceiveArchive(alice.entity_id, temp_dir / "data.zip", package=pkg)
        assert out.read_bytes() == zip_bytes

        # Alias SendZip / ReceiveZip
        set_identity(alice)
        pkg2 = SendZip(bob.entity_id, zip_bytes, filename="data2.zip")
        set_identity(bob)
        out2 = ReceiveZip(alice.entity_id, temp_dir / "data2.zip", package=pkg2)
        assert out2.read_bytes() == zip_bytes

    def test_voice_send_receive(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        voice_bytes = b"OggS\x00\x02\x00\x00" + os.urandom(4096)
        pkg = SendVoice(bob.entity_id, voice_bytes, duration_seconds=12.5)
        assert pkg.metadata.get("duration_seconds") == 12.5

        set_identity(bob)
        register_peer(alice)
        out = ReceiveVoice(alice.entity_id, temp_dir / "voice.ogg", package=pkg)
        assert out.read_bytes() == voice_bytes

    def test_location_send_receive(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pkg = SendLocation(
            bob.entity_id,
            latitude=37.7749,
            longitude=-122.4194,
            description="San Francisco HQ",
        )

        set_identity(bob)
        register_peer(alice)
        loc = ReceiveLocation(alice.entity_id, package=pkg)
        assert loc["latitude"] == 37.7749
        assert loc["longitude"] == -122.4194
        assert loc["description"] == "San Francisco HQ"

    def test_contact_send_receive_dict_and_vcard(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # Dict contact
        contact_dict = {"name": "Alice Smith", "phone": "+1-555-0199", "email": "alice@uxsp.dev"}
        pkg_dict = SendContact(bob.entity_id, contact_dict)

        set_identity(bob)
        register_peer(alice)
        res_dict = ReceiveContact(alice.entity_id, package=pkg_dict)
        assert res_dict == contact_dict

        # vCard contact string
        vcard_str = "BEGIN:VCARD\nVERSION:3.0\nFN:Alice Smith\nTEL:+1-555-0199\nEND:VCARD"
        set_identity(alice)
        pkg_vcard = SendContact(bob.entity_id, vcard_str)

        set_identity(bob)
        res_vcard = ReceiveContact(alice.entity_id, package=pkg_vcard)
        assert res_vcard == vcard_str


class TestPolymorphicSendAndReceive:
    def test_polymorphic_file_extensions(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # MP4 -> Video
        mp4_path = temp_dir / "test.mp4"
        mp4_path.write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"12345")
        pkg_mp4 = Send(bob.entity_id, mp4_path)
        assert pkg_mp4.data_type == "video"

        # MP3 -> Audio
        mp3_path = temp_dir / "test.mp3"
        mp3_path.write_bytes(b"ID3\x03\x00\x00\x00" + b"12345")
        pkg_mp3 = Send(bob.entity_id, mp3_path)
        assert pkg_mp3.data_type == "audio"

        # JPG -> Photo
        jpg_path = temp_dir / "test.jpg"
        jpg_path.write_bytes(b"\xff\xd8\xff\xe0" + b"12345")
        pkg_jpg = Send(bob.entity_id, jpg_path)
        assert pkg_jpg.data_type == "photo"

        # PDF -> PDF
        pdf_path = temp_dir / "test.pdf"
        pdf_path.write_bytes(b"%PDF-1.7\n12345")
        pkg_pdf = Send(bob.entity_id, pdf_path)
        assert pkg_pdf.data_type == "pdf"

        # JSON file -> JSON
        json_path = temp_dir / "test.json"
        json_path.write_text('{"key": "value"}', encoding="utf-8")
        pkg_json = Send(bob.entity_id, json_path)
        assert pkg_json.data_type == "json"

        # String -> Text
        pkg_str = Send(bob.entity_id, "Plain text string")
        assert pkg_str.data_type == "text"

        # Dict -> JSON
        pkg_dict = Send(bob.entity_id, {"msg": "hello"})
        assert pkg_dict.data_type == "json"

        # Bytes -> Binary
        pkg_bytes = Send(bob.entity_id, b"\x01\x02\x03\x04")
        assert pkg_bytes.data_type == "binary"

        # Test polymorphic receive on each
        set_identity(bob)
        register_peer(alice)

        assert Receive(alice.entity_id, pkg_str) == "Plain text string"
        assert Receive(alice.entity_id, pkg_dict) == {"msg": "hello"}
        assert Receive(alice.entity_id, pkg_bytes) == b"\x01\x02\x03\x04"
        assert Receive(alice.entity_id, pkg_json) == {"key": "value"}

    def test_polymorphic_with_explicit_data_type(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pkg = Send(bob.entity_id, b"audio_bytes", data_type="audio")
        assert pkg.data_type == "audio"

        set_identity(bob)
        register_peer(alice)
        out = Receive(alice.entity_id, pkg, download_path=temp_dir / "audio.mp3")
        assert out.read_bytes() == b"audio_bytes"


class TestSecurityAndErrorHandling:
    def test_replay_attack_protection(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pkg = SendText(bob.entity_id, "Single use secret token")

        set_identity(bob)
        register_peer(alice)

        # First receive succeeds
        assert ReceiveText(alice.entity_id, package=pkg) == "Single use secret token"

        # Second receive is blocked by ReplayGuard
        with pytest.raises(ReplayError):
            ReceiveText(alice.entity_id, package=pkg)

    def test_sender_id_mismatch_raises(self, alice_and_bob):
        alice, bob = alice_and_bob
        charlie = Identity.create(name="Charlie", role="client")

        set_identity(alice)
        register_peer(bob)
        pkg = SendText(bob.entity_id, "Hello")

        set_identity(bob)
        register_peer(alice)
        register_peer(charlie)

        with pytest.raises(SecureReceiveError, match="Sender ID mismatch"):
            ReceiveText(charlie.entity_id, package=pkg)

    def test_receiver_id_mismatch_raises(self, alice_and_bob):
        alice, bob = alice_and_bob
        charlie = Identity.create(name="Charlie", role="server")

        set_identity(alice)
        register_peer(bob)
        pkg = SendText(bob.entity_id, "Hello Bob")

        set_identity(charlie)
        register_peer(alice)

        with pytest.raises(SecureReceiveError, match="Receiver ID mismatch"):
            ReceiveText(alice.entity_id, package=pkg)

    def test_type_mismatch_raises(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pkg = SendText(bob.entity_id, "Not a video")

        set_identity(bob)
        register_peer(alice)

        with pytest.raises(TypeMismatchError, match="Data type mismatch"):
            ReceiveVideo(alice.entity_id, package=pkg)

    def test_package_file_missing_on_receive_raises(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(bob)
        register_peer(alice)

        with pytest.raises(SecureReceiveError, match="Package file not found"):
            ReceiveText(alice.entity_id, package=temp_dir / "non_existent.json")

    def test_invalid_package_structures(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # Missing envelope in non-chunked
        bad_pkg = SecurePackage(
            sender_id=alice.entity_id,
            receiver_id=bob.entity_id,
            data_type="text",
            is_chunked=False,
            envelope=None,
        )
        set_identity(bob)
        register_peer(alice)
        with pytest.raises(SecureReceiveError, match="missing envelope"):
            ReceiveText(alice.entity_id, package=bad_pkg)

        # Empty chunks in chunked
        bad_pkg2 = SecurePackage(
            sender_id=alice.entity_id,
            receiver_id=bob.entity_id,
            data_type="text",
            is_chunked=True,
            chunks=[],
        )
        with pytest.raises(SecureReceiveError, match="contains no chunks"):
            ReceiveText(alice.entity_id, package=bad_pkg2)

    def test_invalid_sender_receiver_inputs(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # Empty ID
        with pytest.raises(ValueError, match="cannot be empty"):
            SendText("", "hello")

        # Invalid location coords
        with pytest.raises(SecureSendError, match="latitude"):
            SendLocation(bob.entity_id, latitude=100.0, longitude=0.0)
        with pytest.raises(SecureSendError, match="longitude"):
            SendLocation(bob.entity_id, latitude=0.0, longitude=200.0)

        # Invalid contact
        with pytest.raises(SecureSendError, match="contact"):
            SendContact(bob.entity_id, 12345)  # type: ignore

        # Invalid photo file
        with pytest.raises(SecureSendError):
            SendPhoto(bob.entity_id, temp_dir / "does_not_exist.jpg")

        # Invalid audio file
        with pytest.raises(SecureSendError):
            SendAudio(bob.entity_id, temp_dir / "does_not_exist.mp3")

        # Invalid document file
        with pytest.raises(SecureSendError):
            SendDocument(bob.entity_id, temp_dir / "does_not_exist.docx")

        # Invalid PDF file
        with pytest.raises(SecureSendError):
            SendPDF(bob.entity_id, temp_dir / "does_not_exist.pdf")

        # Invalid Archive file
        with pytest.raises(SecureSendError):
            SendArchive(bob.entity_id, temp_dir / "does_not_exist.zip")

        # Invalid Voice file
        with pytest.raises(SecureSendError):
            SendVoice(bob.entity_id, temp_dir / "does_not_exist.ogg")

        # Invalid generic file
        with pytest.raises(SecureSendError):
            SendFile(bob.entity_id, temp_dir / "does_not_exist.bin")


class TestConfigurationAndPolymorphicDispatch:
    def test_configure_options(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        from uxsp.core.replay import ReplayGuard
        from uxsp.storage.keystore import MemoryKeyStore
        from uxsp.storage.noncestore import MemoryNonceStore

        ks = MemoryKeyStore()
        ns = MemoryNonceStore()
        rg = ReplayGuard(ns)
        out_dir = temp_dir / "custom_downloads"

        configure(
            identity=alice,
            keystore=ks,
            noncestore=ns,
            replay_guard=rg,
            default_output_dir=out_dir,
        )

        ctx = get_context()
        assert ctx.get_identity().entity_id == alice.entity_id
        assert ctx.get_default_output_dir() == out_dir
        assert ctx.get_replay_guard() is rg

    def test_polymorphic_all_explicit_types(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # Video
        p_vid = Send(bob.entity_id, b"vid", data_type="video")
        # Audio
        p_aud = Send(bob.entity_id, b"aud", data_type="audio")
        # Photo / Image
        p_img = Send(bob.entity_id, b"img", data_type="photo")
        p_img2 = Send(bob.entity_id, b"img", data_type="image")
        # Text
        p_txt = Send(bob.entity_id, "hello", data_type="text")
        # Document / Doc
        p_doc = Send(bob.entity_id, b"doc", data_type="document")
        p_doc2 = Send(bob.entity_id, b"doc", data_type="doc")
        # PDF
        p_pdf = Send(bob.entity_id, b"%PDF", data_type="pdf")
        # Archive / Zip
        p_zip = Send(bob.entity_id, b"PK", data_type="archive")
        p_zip2 = Send(bob.entity_id, b"PK", data_type="zip")
        # Voice
        p_vox = Send(bob.entity_id, b"voice", data_type="voice")
        # JSON
        p_json = Send(bob.entity_id, {"a": 1}, data_type="json")
        # HTML
        p_html = Send(bob.entity_id, "<b>hi</b>", data_type="html")
        # Contact
        p_cnt = Send(bob.entity_id, {"name": "Test"}, data_type="contact")
        # Binary
        p_bin = Send(bob.entity_id, b"\x00\x01", data_type="binary")
        # File
        p_file = Send(bob.entity_id, b"file", data_type="file")

        assert p_img2.data_type == "photo"
        assert p_doc2.data_type == "document"
        assert p_zip2.data_type == "archive"

        # Test polymorphic receive for all
        set_identity(bob)
        register_peer(alice)

        assert Receive(alice.entity_id, p_txt) == "hello"
        assert Receive(alice.entity_id, p_json) == {"a": 1}
        assert Receive(alice.entity_id, p_html) == "<b>hi</b>"
        assert Receive(alice.entity_id, p_cnt) == {"name": "Test"}
        assert Receive(alice.entity_id, p_bin) == b"\x00\x01"

        out_v = Receive(alice.entity_id, p_vid, download_path=temp_dir / "v.mp4")
        assert out_v.read_bytes() == b"vid"

        out_a = Receive(alice.entity_id, p_aud, download_path=temp_dir / "a.mp3")
        assert out_a.read_bytes() == b"aud"

        out_p = Receive(alice.entity_id, p_img, download_path=temp_dir / "p.jpg")
        assert out_p.read_bytes() == b"img"

        out_d = Receive(alice.entity_id, p_doc, download_path=temp_dir / "d.docx")
        assert out_d.read_bytes() == b"doc"

        out_pdf = Receive(alice.entity_id, p_pdf, download_path=temp_dir / "p.pdf")
        assert out_pdf.read_bytes() == b"%PDF"

        out_z = Receive(alice.entity_id, p_zip, download_path=temp_dir / "z.zip")
        assert out_z.read_bytes() == b"PK"

        out_vox = Receive(alice.entity_id, p_vox, download_path=temp_dir / "v.ogg")
        assert out_vox.read_bytes() == b"voice"

        out_f = Receive(alice.entity_id, p_file, download_path=temp_dir / "f.dat")
        assert out_f.read_bytes() == b"file"

    def test_polymorphic_fallback_unknown_type(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # Send custom data_type
        pkg = uxsp.secure._secure_send_payload(
            bob.entity_id,
            b"custom raw content",
            data_type="custom_type",
        )

        set_identity(bob)
        register_peer(alice)

        out_path = Receive(alice.entity_id, pkg, download_path=temp_dir / "custom.out")
        assert out_path.read_bytes() == b"custom raw content"

    def test_send_output_file(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pkg_path = temp_dir / "exported_package.json"
        SendText(bob.entity_id, "Saved to file", output_file=pkg_path)

        assert pkg_path.exists()
        loaded = SecurePackage.from_file(str(pkg_path))
        assert loaded.sender_id == alice.entity_id

    def test_resolve_package_input_formats(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pkg1 = SendText(bob.entity_id, "Resolve test 1")
        pkg2 = SendText(bob.entity_id, "Resolve test 2")
        pkg3 = SendText(bob.entity_id, "Resolve test 3")

        set_identity(bob)
        register_peer(alice)

        # 1. From dict
        assert ReceiveText(alice.entity_id, package=pkg1.to_dict()) == "Resolve test 1"

        # 2. From JSON string (including long JSON string)
        assert ReceiveText(alice.entity_id, package=pkg2.to_json()) == "Resolve test 2"

        # 3. From file
        pkg_file = temp_dir / "pkg3.json"
        pkg3.to_file(pkg_file)
        assert ReceiveText(alice.entity_id, package=str(pkg_file)) == "Resolve test 3"

        # 4. Invalid input type
        with pytest.raises(SecureReceiveError, match="Cannot resolve package"):
            ReceiveText(alice.entity_id, package=12345)

        # 5. Non-existent string path / string with null byte / very long string not json
        with pytest.raises(SecureReceiveError, match="Package file not found"):
            ReceiveText(alice.entity_id, package="non_existent_file.json")

        with pytest.raises(SecureReceiveError, match="Package file not found"):
            ReceiveText(alice.entity_id, package="bad_path\x00with_null.json")

        with pytest.raises(SecureReceiveError, match="Package file not found"):
            ReceiveText(alice.entity_id, package="X" * 5000)

        # 6. Test _safe_is_file directly
        assert not uxsp.secure._safe_is_file(12345)
        assert not uxsp.secure._safe_is_file("bad_path\x00with_null.json")
        assert not uxsp.secure._safe_is_file("X" * 5000)
        assert uxsp.secure._safe_is_file(pkg_file)

    def test_safe_is_file_exception_handling(self, monkeypatch):
        def mock_is_file(_self):
            raise OSError("Simulated filesystem error")
        monkeypatch.setattr(Path, "is_file", mock_is_file)
        assert not uxsp.secure._safe_is_file("some_file.txt")

    def test_polymorphic_file_extensions_and_invalid(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # File with unknown extension
        custom_file = temp_dir / "data.xyz"
        custom_file.write_bytes(b"xyz-data")
        pkg = Send(bob.entity_id, custom_file)
        assert pkg.data_type == "file"

        # HTML file auto-detection
        html_file = temp_dir / "page.html"
        html_file.write_text("<h1>Test</h1>", encoding="utf-8")
        pkg_html = Send(bob.entity_id, html_file)
        assert pkg_html.data_type == "html"

        # JSON file auto-detection
        json_file = temp_dir / "config.json"
        json_file.write_text('{"key": "value"}', encoding="utf-8")
        pkg_json = Send(bob.entity_id, json_file)
        assert pkg_json.data_type == "json"

        # Unsupported object
        class UnsupportedObj:
            pass

        with pytest.raises(SecureSendError, match="Cannot automatically infer"):
            Send(bob.entity_id, UnsupportedObj())

    def test_default_output_directory(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pkg = SendVideo(bob.entity_id, b"vid data", filename="default_output_video.mp4")

        set_identity(bob)
        register_peer(alice)

        # Receive with download_path=None -> uses default output dir (~/.uxsp/downloads or configured)
        out_file = ReceiveVideo(alice.entity_id, package=pkg)
        assert out_file.exists()
        assert out_file.read_bytes() == b"vid data"

    def test_signed_card_retrieval_and_package_from_bytes(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)

        # Register a SignedCard in context
        anchor = TrustAnchor.create("TestCA")
        signed_card = anchor.issue(bob.public_card())
        register_peer(signed_card)

        # get_peer should return the inner card
        card = get_peer(bob.entity_id)
        assert card.entity_id == bob.entity_id

        # Package from_json with bytes input
        pkg = SendText(bob.entity_id, "hello bytes")
        json_bytes = pkg.to_json().encode("utf-8")
        pkg_from_bytes = SecurePackage.from_json(json_bytes)
        assert pkg_from_bytes.sender_id == alice.entity_id

        set_identity(bob)
        register_peer(alice)
        assert ReceiveText(alice.entity_id, package=json_bytes) == "hello bytes"

    def test_send_invalid_types_and_missing_files(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        non_existent = temp_dir / "non_existent.bin"

        with pytest.raises(SecureSendError, match="File not found"):
            SendVideo(bob.entity_id, non_existent)
        with pytest.raises(SecureSendError, match="audio_path_or_bytes"):
            SendAudio(bob.entity_id, 12345)
        with pytest.raises(SecureSendError, match="photo_path_or_bytes"):
            SendPhoto(bob.entity_id, 12345)
        with pytest.raises(SecureSendError, match="text must be a string"):
            SendText(bob.entity_id, 12345)  # type: ignore
        with pytest.raises(SecureSendError, match="File not found"):
            SendDocument(bob.entity_id, non_existent)
        with pytest.raises(SecureSendError, match="doc_path_or_bytes"):
            SendDocument(bob.entity_id, 12345)
        with pytest.raises(SecureSendError, match="pdf_path_or_bytes"):
            SendPDF(bob.entity_id, 12345)
        with pytest.raises(SecureSendError, match="file_path_or_bytes"):
            SendFile(bob.entity_id, 12345)
        with pytest.raises(SecureSendError, match="data must be bytes"):
            SendBinary(bob.entity_id, "not-bytes")  # type: ignore
        with pytest.raises(SecureSendError, match="JSON-serializable"):
            SendJSON(bob.entity_id, object())
        with pytest.raises(SecureSendError, match="html_content must be a string"):
            SendHTML(bob.entity_id, 12345)  # type: ignore
        with pytest.raises(SecureSendError, match="File not found"):
            SendArchive(bob.entity_id, non_existent)
        with pytest.raises(SecureSendError, match="archive_path_or_bytes"):
            SendArchive(bob.entity_id, 12345)
        with pytest.raises(SecureSendError, match="File not found"):
            SendVoice(bob.entity_id, non_existent)
        with pytest.raises(SecureSendError, match="voice_path_or_bytes"):
            SendVoice(bob.entity_id, 12345)

    def test_file_path_branches_and_receives_with_download_path(self, alice_and_bob, temp_dir):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        # 1. SendDocument from file path
        doc_file = temp_dir / "test_doc.docx"
        doc_file.write_bytes(b"doc binary content")
        pkg_doc = SendDocument(bob.entity_id, doc_file)

        # 2. SendArchive from file path
        zip_file = temp_dir / "test_archive.zip"
        zip_file.write_bytes(b"zip archive content")
        pkg_zip = SendArchive(bob.entity_id, zip_file)

        # 3. SendVoice from file path
        voice_file = temp_dir / "test_voice.ogg"
        voice_file.write_bytes(b"voice ogg content")
        pkg_voice = SendVoice(bob.entity_id, voice_file)

        # 4. Polymorphic Send archive file
        pkg_poly_zip = Send(bob.entity_id, zip_file)
        assert pkg_poly_zip.data_type == "archive"

        # 5. SendBinary / SendJSON / SendHTML / SendLocation
        pkg_bin = SendBinary(bob.entity_id, b"binary raw data")
        pkg_json = SendJSON(bob.entity_id, {"msg": "json data"})
        pkg_html = SendHTML(bob.entity_id, "<div>hello</div>")
        pkg_loc = SendLocation(bob.entity_id, latitude=12.34, longitude=56.78)

        # Switch to Bob
        set_identity(bob)
        register_peer(alice)

        # Receive with download_path
        out_doc = ReceiveDocument(alice.entity_id, download_path=temp_dir / "out_doc.docx", package=pkg_doc)
        assert out_doc.read_bytes() == b"doc binary content"

        out_zip = ReceiveArchive(alice.entity_id, download_path=temp_dir / "out_archive.zip", package=pkg_zip)
        assert out_zip.read_bytes() == b"zip archive content"

        out_voice = ReceiveVoice(alice.entity_id, download_path=temp_dir / "out_voice.ogg", package=pkg_voice)
        assert out_voice.read_bytes() == b"voice ogg content"

        out_bin = ReceiveBinary(alice.entity_id, download_path=temp_dir / "out.bin", package=pkg_bin)
        assert out_bin == b"binary raw data"
        assert (temp_dir / "out.bin").read_bytes() == b"binary raw data"

        out_json = ReceiveJSON(alice.entity_id, download_path=temp_dir / "out.json", package=pkg_json)
        assert out_json == {"msg": "json data"}
        assert json.loads((temp_dir / "out.json").read_text(encoding="utf-8")) == {"msg": "json data"}

        out_html = ReceiveHTML(alice.entity_id, download_path=temp_dir / "out.html", package=pkg_html)
        assert out_html == "<div>hello</div>"
        assert (temp_dir / "out.html").read_text(encoding="utf-8") == "<div>hello</div>"

        # Polymorphic receive location
        loc_res = Receive(alice.entity_id, package=pkg_loc)
        assert loc_res["latitude"] == 12.34

        # Polymorphic receive custom data type with and without download_path
        set_identity(alice)
        register_peer(bob)
        custom_pkg1 = SendText(bob.entity_id, "fallback custom 1")
        custom_pkg1.data_type = "unknown_custom"
        custom_pkg2 = SendText(bob.entity_id, "fallback custom 2")
        custom_pkg2.data_type = "unknown_custom"

        set_identity(bob)
        register_peer(alice)
        res_custom = Receive(alice.entity_id, package=custom_pkg1)
        assert isinstance(res_custom, bytes)
        assert res_custom.decode("utf-8") == "fallback custom 1"

        res_custom_file = Receive(alice.entity_id, package=custom_pkg2, download_path=temp_dir / "custom.out")
        assert res_custom_file.exists()
        assert res_custom_file.read_text(encoding="utf-8") == "fallback custom 2"


class TestDirectObjectPassingAndMemoryHelpers:
    """
    Tests for the streamlined, stateless workflow where Identity and PublicCard objects
    are passed directly into Send* and Receive* functions without global state.
    """

    def test_in_memory_identity_export_import(self):
        alice = uxsp.create_identity("Alice", role="CLIENT")
        assert alice.name == "Alice"
        assert alice.role == "CLIENT"

        # Encrypted serialization
        password = "SuperSecretPassword123!"
        encrypted_json = uxsp.export_identity_encrypted(alice, password)
        assert isinstance(encrypted_json, str)
        assert "UXSP-IDENTITY-1" in encrypted_json

        # Encrypted deserialization
        restored = uxsp.import_identity_encrypted(encrypted_json, password)
        assert restored.entity_id == alice.entity_id
        assert restored.name == "Alice"
        assert restored.role == "CLIENT"

        # Wrong password raises error
        with pytest.raises(ValueError, match="Wrong password"):
            uxsp.import_identity_encrypted(encrypted_json, "WrongPassword")

    def test_password_hashing_helpers(self):
        password = "my_secure_password"
        hashed = uxsp.hash_password(password)
        assert hashed.startswith("$argon2id$")

        assert uxsp.verify_password(hashed, password) is True
        assert uxsp.verify_password(hashed, "wrong_password") is False

    def test_direct_identity_and_card_passing_stateless(self):
        """
        Verify sending and receiving payloads directly by passing Identity and PublicCard objects
        without calling global configure(), set_identity(), or register_peer().
        """
        alice = uxsp.create_identity("Alice", role="CLIENT")
        bob = uxsp.create_identity("Bob", role="SERVER")

        # Alice sends to Bob using Bob's PublicCard directly (or Bob's Identity)
        message = "Direct stateless message test!"
        pkg = SendText(
            receiver=bob.public_card(),
            text=message,
            sender=alice,
        )

        assert pkg.sender_id == alice.entity_id
        assert pkg.receiver_id == bob.entity_id

        # Bob receives message using Alice's PublicCard and Bob's Identity directly
        received_text = ReceiveText(
            sender=alice.public_card(),
            package=pkg,
            receiver=bob,
        )
        assert received_text == message

    def test_direct_object_passing_polymorphic(self):
        alice = uxsp.create_identity("Alice", role="CLIENT")
        bob = uxsp.create_identity("Bob", role="SERVER")

        payload_dict = {"event": "USER_LOGIN", "user_id": 42}

        # Send via polymorphic Send with Identity/PublicCard arguments
        pkg = Send(
            receiver=bob,
            item=payload_dict,
            sender=alice,
        )

        # Receive via polymorphic Receive with Identity/PublicCard arguments
        received_dict = Receive(
            sender=alice,
            package=pkg,
            receiver=bob,
        )
        assert received_dict == payload_dict

    def test_from_encrypted_json_bytes_and_error_branches(self):
        alice = uxsp.create_identity("Alice", role="CLIENT")
        password = "TestPassword123!"
        enc_json_str = alice.to_encrypted_json(password)
        enc_json_bytes = enc_json_str.encode("utf-8")

        # Deserializing from bytes
        restored = Identity.from_encrypted_json(enc_json_bytes, password)
        assert restored.entity_id == alice.entity_id

        # Invalid JSON string
        with pytest.raises(ValueError, match="Failed to parse encrypted JSON"):
            Identity.from_encrypted_json("not valid json{{{", password)

        # Non-dict payload
        with pytest.raises(ValueError, match="Payload must be a dictionary"):
            Identity.from_encrypted_dict("not a dict", password)  # type: ignore

        # Missing encrypted_private section
        with pytest.raises(ValueError, match="Identity payload missing encrypted_private"):
            Identity.from_encrypted_dict({"version": Identity._VERSION}, password)

    def test_normalize_id_and_missing_sender_receiver(self):
        alice = uxsp.create_identity("Alice", role="CLIENT")
        card = alice.public_card()

        # _normalize_id with Identity & PublicCard
        assert uxsp.secure._normalize_id(alice) == alice.entity_id
        assert uxsp.secure._normalize_id(card) == alice.entity_id

        # _secure_send_payload missing receiver
        with pytest.raises(ValueError, match="Receiver identity or receiver_id must be provided"):
            uxsp.secure._secure_send_payload(receiver=None)

        # _secure_receive_payload missing sender
        with pytest.raises(ValueError, match="Sender identity/card or sender_id must be provided"):
            uxsp.secure._secure_receive_payload(sender=None)


class TestHighLevelIdentityLifecycle:

    def test_rotate_keys_and_revoke_peer(self):
        uxsp.secure.reset_context()
        alice = uxsp.create_identity("Alice", role="CLIENT")
        bob = uxsp.create_identity("Bob", role="SERVER")

        uxsp.set_identity(alice)
        uxsp.register_peer(bob)

        # Rotate active identity keys
        rotated_alice = uxsp.rotate_keys()
        assert rotated_alice.entity_id == alice.entity_id
        assert rotated_alice.key_version == 2

        # Rotate explicit identity
        rotated_bob = uxsp.rotate_keys(bob)
        assert rotated_bob.entity_id == bob.entity_id
        assert rotated_bob.key_version == 2

        # Verify peer validity
        uxsp.verify_peer_validity(bob)

        # Unregistered identity/card verify_peer_validity branches
        unregistered = uxsp.create_identity("Unregistered", role="CLIENT")
        uxsp.verify_peer_validity(unregistered)
        uxsp.verify_peer_validity(unregistered.public_card())
        with pytest.raises(uxsp.PeerNotFoundError):
            uxsp.verify_peer_validity("nonexistent_id")

        # Revoke peer
        revoked_card = uxsp.revoke_peer(bob, reason="Security audit")
        assert revoked_card.is_revoked
        assert revoked_card.revocation_reason == "Security audit"

        with pytest.raises(uxsp.CardRevokedError, match="has been revoked"):
            uxsp.verify_peer_validity(bob)

    @pytest.mark.asyncio
    async def test_async_rotate_keys_and_revoke_peer(self):
        import uxsp.aio
        await uxsp.aio.reset_context()
        alice = uxsp.create_identity("Alice", role="CLIENT")
        bob = uxsp.create_identity("Bob", role="SERVER")

        await uxsp.aio.set_identity(alice)
        assert (await uxsp.aio.get_identity()).entity_id == alice.entity_id

        await uxsp.aio.register_peer(bob)
        assert (await uxsp.aio.get_peer(bob)).entity_id == bob.entity_id

        # Async rotate
        rotated = await uxsp.aio.rotate_keys(bob)
        assert rotated.key_version == 2

        # Async verify
        await uxsp.aio.verify_peer_validity(bob)

        # Async revoke
        revoked = await uxsp.aio.revoke_peer(bob, reason="Compromised")
        assert revoked.is_revoked

        with pytest.raises(uxsp.aio.CardRevokedError):
            await uxsp.aio.verify_peer_validity(bob)


class TestLiveVoiceCalling:
    def test_send_and_receive_live_voice_call(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pkg, session_alice = uxsp.SendLiveVoiceCall(bob.entity_id, codec="opus", sample_rate=48000, channels=2)
        assert pkg.data_type == "live_voice_session"
        assert session_alice.codec == "opus"

        set_identity(bob)
        register_peer(alice)
        session_bob = uxsp.ReceiveLiveVoiceCall(alice.entity_id, package=pkg)
        assert session_bob.key == session_alice.key
        assert session_bob.codec == "opus"

        # Exchange an encrypted live audio frame
        audio_frame = b"\x00\xff\x11\x22\x33\x44"
        enc_frame = session_alice.encrypt_voice_frame(audio_frame)
        dec_frame, meta = session_bob.decrypt_voice_frame(enc_frame)
        assert dec_frame == audio_frame
        assert meta["codec"] == "opus"
        assert meta["channels"] == 2

    def test_polymorphic_live_voice_dispatch(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pkg = Send(bob.entity_id, data_type="live_voice_call")
        assert pkg.data_type == "live_voice_session"

        set_identity(bob)
        register_peer(alice)
        session_bob = Receive(alice.entity_id, package=pkg)
        assert isinstance(session_bob, uxsp.LiveVoiceSession)

    def test_polymorphic_live_session_dispatch(self, alice_and_bob):
        alice, bob = alice_and_bob
        set_identity(alice)
        register_peer(bob)

        pkg = Send(bob.entity_id, data_type="live_session")
        assert pkg.data_type == "live_session"

        set_identity(bob)
        register_peer(alice)
        session_bob = Receive(alice.entity_id, package=pkg)
        assert isinstance(session_bob, uxsp.LiveSession)







