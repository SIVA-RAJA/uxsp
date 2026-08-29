from __future__ import annotations

import pytest
from pathlib import Path

from uxsp.aio._types import async_send_file_type
from uxsp.secure._errors import SecureSendError

@pytest.mark.asyncio
async def test_async_types_edge_cases(tmp_path):
    # Line 32
    with pytest.raises(SecureSendError, match="File not found"):
        await async_send_file_type(
            receiver_id="test",
            file_path_or_bytes="nonexistent.txt",
            data_type="file",
            default_filename="x",
            default_content_type="text/plain",
        )
        
    # Line 35-37: > 64MB file returns SendStream generator
    large_file = tmp_path / "large.bin"
    with open(large_file, "wb") as f:
        f.truncate(65 * 1024 * 1024)
        
    res = await async_send_file_type(
        receiver_id="test",
        file_path_or_bytes=large_file,
        data_type="file",
        default_filename="x",
        default_content_type="application/octet-stream",
    )
    import types
    assert isinstance(res, types.GeneratorType)
    
    # Line 53-56: Invalid type
    with pytest.raises(SecureSendError, match="file_path_or_bytes must be a file path or bytes"):
        await async_send_file_type(
            receiver_id="test",
            file_path_or_bytes=123,
            data_type="file",
            default_filename="x",
            default_content_type="text/plain",
        )
        
    with pytest.raises(SecureSendError, match="doc_path_or_bytes must be a file path or bytes"):
        await async_send_file_type(
            receiver_id="test",
            file_path_or_bytes=123,
            data_type="document",
            default_filename="x",
            default_content_type="text/plain",
        )
