from unittest.mock import patch
import pytest
from uxsp.crypto import hybrid

def test_bind_fields_python_fallback():
    with patch("uxsp.crypto.hybrid._HAS_RUST_CORE", False):
        res = hybrid.bind_fields(b"hello", b"world")
        assert len(res) == 4 + 5 + 4 + 5

def test_bind_fields_rust_exception_fallback():
    class DummyNative:
        @staticmethod
        def bind_fields_native(fields):
            raise RuntimeError("Mock error")

    with patch("uxsp.crypto.hybrid._HAS_RUST_CORE", True):
        with patch("uxsp.crypto.hybrid.uxsp_core_native", DummyNative):
            res = hybrid.bind_fields(b"hello", b"world")
            assert len(res) == 4 + 5 + 4 + 5
