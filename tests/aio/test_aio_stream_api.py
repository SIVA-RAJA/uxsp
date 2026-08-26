"""
Unit tests for Asynchronous File Streaming API (uxsp.aio.SendStream / uxsp.aio.ReceiveStream)
"""
import io
import os

import pytest

from uxsp import Identity
from uxsp.aio import ReceiveStream, SendStream


@pytest.fixture
def alice_and_bob():
    alice = Identity.create(name="Alice", role="client")
    bob = Identity.create(name="Bob", role="server")
    return alice, bob


@pytest.mark.asyncio
async def test_aio_send_stream_generator_to_receive_stream(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob
    original_data = os.urandom(3 * 1024 * 1024)

    async def async_data_generator():
        chunk_size = 32 * 1024
        for i in range(0, len(original_data), chunk_size):
            yield original_data[i : i + chunk_size]

    # SendStream returns an AsyncIterator of SecurePackage objects
    packages_gen = await SendStream(
        stream_or_path=async_data_generator(),
        sender=alice,
        receiver=bob.public_card(),
        filename="async_large.bin",
        chunk_size=32 * 1024,
    )

    out_file = tmp_path / "async_decrypted.bin"
    res_path = await ReceiveStream(
        packages_or_stream=packages_gen,
        output_file=out_file,
        sender=alice.public_card(),
        receiver=bob,
    )

    assert res_path == out_file
    assert out_file.read_bytes() == original_data


@pytest.mark.asyncio
async def test_aio_send_stream_file_path_to_destination(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob

    src_file = tmp_path / "async_src.dat"
    original_data = b"ASYNC_STREAMING_PATTERN_" * 150000
    src_file.write_bytes(original_data)

    pkg_file = tmp_path / "async_packages.jsonl"
    written_pkg_path = await SendStream(
        stream_or_path=src_file,
        output_destination=pkg_file,
        sender=alice,
        receiver=bob.public_card(),
        chunk_size=64 * 1024,
    )

    assert written_pkg_path == pkg_file
    assert pkg_file.is_file()

    out_file = tmp_path / "async_restored.dat"
    res_path = await ReceiveStream(
        packages_or_stream=pkg_file,
        output_file=out_file,
        sender=alice.public_card(),
        receiver=bob,
    )

    assert res_path == out_file
    assert out_file.read_bytes() == original_data


@pytest.mark.asyncio
async def test_aio_send_stream_descriptor_and_receive_fd(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob
    original_data = b"ASYNC_FD_PATTERN_" * 30000

    src_fd = io.BytesIO(original_data)
    out_pkg_fd = io.StringIO()

    await SendStream(
        stream_or_path=src_fd,
        output_destination=out_pkg_fd,
        sender=alice,
        receiver=bob.public_card(),
        chunk_size=16 * 1024,
    )

    out_pkg_fd.seek(0)

    out_data_fd = io.BytesIO()
    bytes_written = await ReceiveStream(
        packages_or_stream=out_pkg_fd,
        output_file=out_data_fd,
        sender=alice.public_card(),
        receiver=bob,
    )

    assert bytes_written == len(original_data)
    assert out_data_fd.getvalue() == original_data


@pytest.mark.asyncio
async def test_aio_empty_stream_handling(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob

    packages_gen = await SendStream(
        stream_or_path=[],
        sender=alice,
        receiver=bob.public_card(),
    )

    out_file = tmp_path / "async_empty.bin"
    await ReceiveStream(
        packages_or_stream=packages_gen,
        output_file=out_file,
        sender=alice.public_card(),
        receiver=bob,
    )

    assert out_file.read_bytes() == b""


@pytest.mark.asyncio
async def test_aio_stream_invalid_types(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob

    with pytest.raises(TypeError, match="File not found"):
        gen = await SendStream(stream_or_path=tmp_path / "missing.bin", sender=alice, receiver=bob.public_card())
        async for _ in gen:
            pass

    with pytest.raises(TypeError, match="Source must be"):
        gen = await SendStream(stream_or_path=99999, sender=alice, receiver=bob.public_card())
        async for _ in gen:
            pass

    with pytest.raises(TypeError, match="output_destination must be"):
        await SendStream(stream_or_path=[b"data"], output_destination=123, sender=alice, receiver=bob.public_card())

    with pytest.raises(TypeError, match="output_file must be"):
        await ReceiveStream(packages_or_stream=[], output_file=888, sender=alice.public_card(), receiver=bob)

    with pytest.raises(TypeError, match="packages_or_stream must be"):
        await ReceiveStream(packages_or_stream=888, output_file=tmp_path / "out.bin", sender=alice.public_card(), receiver=bob)


@pytest.mark.asyncio
async def test_aio_stream_bytes_and_json_string_packages(tmp_path, alice_and_bob):
    alice, bob = alice_and_bob
    data = b"ASYNC_JSON_STRING_PACKAGES_DATA"

    # Async ReceiveStream from sync iterable of JSON str
    bin_out_fd1 = io.BytesIO()
    await SendStream(stream_or_path=[data], output_destination=bin_out_fd1, sender=alice, receiver=bob.public_card())
    json_str_line = bin_out_fd1.getvalue().decode("utf-8")

    out_file_str = tmp_path / "aio_out_str.bin"
    await ReceiveStream(packages_or_stream=[json_str_line], output_file=out_file_str, sender=alice.public_card(), receiver=bob)
    assert out_file_str.read_bytes() == data

    # Async ReceiveStream from async iterable of JSON bytes
    bin_out_fd2 = io.BytesIO()
    await SendStream(stream_or_path=[data], output_destination=bin_out_fd2, sender=alice, receiver=bob.public_card())
    json_bytes_line = bin_out_fd2.getvalue()

    async def async_json_bytes_gen():
        yield json_bytes_line

    out_file_bytes = tmp_path / "aio_out_bytes.bin"
    await ReceiveStream(packages_or_stream=async_json_bytes_gen(), output_file=out_file_bytes, sender=alice.public_card(), receiver=bob)
    assert out_file_bytes.read_bytes() == data

    # Async ReceiveStream from binary file descriptor (rb mode)
    bin_out_fd3 = io.BytesIO()
    await SendStream(stream_or_path=[data], output_destination=bin_out_fd3, sender=alice, receiver=bob.public_card())
    rb_fd = io.BytesIO(bin_out_fd3.getvalue())

    out_file_rb = tmp_path / "aio_out_rb.bin"
    await ReceiveStream(packages_or_stream=rb_fd, output_file=out_file_rb, sender=alice.public_card(), receiver=bob)
    assert out_file_rb.read_bytes() == data

    # Async ReceiveStream from list of SecurePackage objects directly
    pkg_list = []
    async for pkg in await SendStream(stream_or_path=[data], sender=alice, receiver=bob.public_card()):
        pkg_list.append(pkg)

    out_file_pkg = tmp_path / "aio_out_pkg.bin"
    await ReceiveStream(packages_or_stream=pkg_list, output_file=out_file_pkg, sender=alice.public_card(), receiver=bob)
    assert out_file_pkg.read_bytes() == data
