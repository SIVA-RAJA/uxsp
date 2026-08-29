"""
Unit tests for Synchronous File Streaming API (SendStream / ReceiveStream) in uxsp.secure
"""
import io
import os

import pytest

from uxsp import Identity, ReceiveStream, SendStream
from uxsp.secure import SecureSendError


@pytest.fixture
def alice_and_bob():
    alice = Identity.create(name="Alice", role="client")
    bob = Identity.create(name="Bob", role="server")
    return alice, bob


def test_send_stream_generator_to_receive_stream(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob
    alice_card = alice.public_card()
    bob_card = bob.public_card()

    # Create dummy 5MB test binary data
    original_data = os.urandom(5 * 1024 * 1024)

    def data_generator():
        chunk_size = 64 * 1024
        for i in range(0, len(original_data), chunk_size):
            yield original_data[i : i + chunk_size]

    # SendStream yields a generator of SecurePackage objects
    packages_gen = SendStream(
        stream_or_path=data_generator(),
        sender=alice,
        receiver=bob_card,
        filename="large_asset.bin",
        chunk_size=64 * 1024,
    )

    out_file = tmp_path / "decrypted.bin"
    res_path = ReceiveStream(
        packages_or_stream=packages_gen,
        output_file=out_file,
        sender=alice_card,
        receiver=bob,
    )

    assert res_path == out_file
    assert out_file.read_bytes() == original_data


def test_send_stream_file_path_to_output_destination(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob

    # Create large file on disk
    src_file = tmp_path / "source_10mb.dat"
    original_data = b"STREAMING_TEST_PATTERN_" * 200000  # ~4.4 MB
    src_file.write_bytes(original_data)

    pkg_file = tmp_path / "packages.jsonl"
    written_pkg_path = SendStream(
        stream_or_path=src_file,
        output_destination=pkg_file,
        sender=alice,
        receiver=bob.public_card(),
        chunk_size=32 * 1024,
    )

    assert written_pkg_path == pkg_file
    assert pkg_file.is_file()

    # ReceiveStream from package JSON lines file directly
    out_file = tmp_path / "restored.dat"
    res_path = ReceiveStream(
        packages_or_stream=pkg_file,
        output_file=out_file,
        sender=alice.public_card(),
        receiver=bob,
    )

    assert res_path == out_file
    assert out_file.read_bytes() == original_data


def test_send_stream_file_descriptor_and_receive_fd(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob
    original_data = b"BINARY_FD_DATA_" * 50000

    src_fd = io.BytesIO(original_data)
    out_pkg_fd = io.StringIO()

    SendStream(
        stream_or_path=src_fd,
        output_destination=out_pkg_fd,
        sender=alice,
        receiver=bob.public_card(),
        chunk_size=16 * 1024,
    )

    # Reset package buffer position
    out_pkg_fd.seek(0)

    out_data_fd = io.BytesIO()
    bytes_written = ReceiveStream(
        packages_or_stream=out_pkg_fd,
        output_file=out_data_fd,
        sender=alice.public_card(),
        receiver=bob,
    )

    assert bytes_written == len(original_data)
    assert out_data_fd.getvalue() == original_data


def test_empty_stream_handling(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob

    # Stream yielding empty bytes
    packages_gen = SendStream(
        stream_or_path=[],
        sender=alice,
        receiver=bob.public_card(),
    )

    out_file = tmp_path / "empty.bin"
    ReceiveStream(
        packages_or_stream=packages_gen,
        output_file=out_file,
        sender=alice.public_card(),
        receiver=bob,
    )

    assert out_file.read_bytes() == b""


def test_send_stream_invalid_source_and_destination(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob

    with pytest.raises(SecureSendError, match="File not found"):
        gen = SendStream(stream_or_path=tmp_path / "non_existent.bin", sender=alice, receiver=bob.public_card())
        next(gen)

    with pytest.raises(SecureSendError, match="Source must be"):
        gen = SendStream(stream_or_path=12345, sender=alice, receiver=bob.public_card())
        next(gen)

    with pytest.raises(SecureSendError, match="output_destination must be"):
        SendStream(stream_or_path=[b"data"], output_destination=999, sender=alice, receiver=bob.public_card())


def test_receive_stream_invalid_inputs(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob

    with pytest.raises(ValueError, match="output_file must be"):
        ReceiveStream(packages_or_stream=[], output_file=12345, sender=alice.public_card(), receiver=bob)

    with pytest.raises(ValueError, match="packages_or_stream must be"):
        ReceiveStream(packages_or_stream=12345, output_file=tmp_path / "out.bin", sender=alice.public_card(), receiver=bob)


def test_stream_bytes_and_json_string_packages(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob
    data = b"JSON_STRING_PACKAGES_DATA"

    # ReceiveStream from iterable of JSON str
    bin_out_fd1 = io.BytesIO()
    SendStream(stream_or_path=[data], output_destination=bin_out_fd1, sender=alice, receiver=bob.public_card())
    json_str_line = bin_out_fd1.getvalue().decode("utf-8")

    out_file_str = tmp_path / "out_str.bin"
    ReceiveStream(packages_or_stream=[json_str_line], output_file=out_file_str, sender=alice.public_card(), receiver=bob)
    assert out_file_str.read_bytes() == data

    # ReceiveStream from iterable of JSON bytes
    bin_out_fd2 = io.BytesIO()
    SendStream(stream_or_path=[data], output_destination=bin_out_fd2, sender=alice, receiver=bob.public_card())
    json_bytes_line = bin_out_fd2.getvalue()

    out_file_bytes = tmp_path / "out_bytes.bin"
    ReceiveStream(packages_or_stream=[json_bytes_line], output_file=out_file_bytes, sender=alice.public_card(), receiver=bob)
    assert out_file_bytes.read_bytes() == data

    # ReceiveStream from binary file descriptor (rb mode)
    bin_out_fd3 = io.BytesIO()
    SendStream(stream_or_path=[data], output_destination=bin_out_fd3, sender=alice, receiver=bob.public_card())
    rb_fd = io.BytesIO(bin_out_fd3.getvalue())

    out_file_rb = tmp_path / "out_rb.bin"
    ReceiveStream(packages_or_stream=rb_fd, output_file=out_file_rb, sender=alice.public_card(), receiver=bob)
    assert out_file_rb.read_bytes() == data

def test_chunked_stream_transfer_exceptions_and_empty(tmp_path):
    from uxsp.core.chunking import ChunkValidationError, UXSPChunk, create_chunked_stream_transfer

    with pytest.raises(ChunkValidationError, match="chunk_size must be positive"):
        next(create_chunked_stream_transfer(tmp_path / "dummy.txt", chunk_size=0))

    with pytest.raises(ChunkValidationError, match="File not found"):
        next(create_chunked_stream_transfer(tmp_path / "non_existent_stream.bin"))

    # Test 0-byte file (lines 393-408)
    empty_file = tmp_path / "empty_stream.dat"
    empty_file.touch()

    gen = create_chunked_stream_transfer(empty_file)
    chunk1 = next(gen)

    parsed = UXSPChunk.from_bytes(chunk1)
    assert parsed.total_chunks == 1
    assert parsed.chunk_index == 0
    assert parsed.body == b""

    with pytest.raises(StopIteration):
        next(gen)

    # Test file with data (lines 381, 387, 410-428)
    data_file = tmp_path / "data_stream.dat"
    data_file.write_bytes(b"hello world")

    gen2 = create_chunked_stream_transfer(data_file, chunk_size=5)

    # Chunk 1: "hello"
    c1 = UXSPChunk.from_bytes(next(gen2))
    assert c1.total_chunks == 3
    assert c1.chunk_index == 0
    assert c1.body == b"hello"

    # Chunk 2: " worl"
    c2 = UXSPChunk.from_bytes(next(gen2))
    assert c2.chunk_index == 1
    assert c2.body == b" worl"

    # Chunk 3: "d"
    c3 = UXSPChunk.from_bytes(next(gen2))
    assert c3.chunk_index == 2
    assert c3.body == b"d"

    with pytest.raises(StopIteration):
        next(gen2)

