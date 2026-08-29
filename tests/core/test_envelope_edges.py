from __future__ import annotations

import pytest

from uxsp.core.envelope import Envelope

def test_envelope_size_bytes_cache_setattr():
    env = Envelope.from_dict({
        "version": "UXSP-1",
        "timestamp": 1234567890,
        "sender_id": "sender",
        "recipient_id": "rec",
        "envelope_nonce": "n123",
        "ciphertext": "abc",
        "nonce": "n456",
        "ephemeral_pub": "pub123",
        "kem_ciphertext": "kem123",
        "classical_sig": "sig123",
        "pqc_sig": "pqc123"
    })
    # This should hit the False branch of `if name != "_size_bytes_cache":`
    env._size_bytes_cache = 100
    assert env._size_bytes_cache == 100
    
    # Hit line 202 by setting an attribute other than _size_bytes_cache
    with pytest.raises(AttributeError):
        env.custom_attr = 42
    assert env._size_bytes_cache is None
    
    with pytest.raises(AttributeError, match="immutable"):
        env.version = "UXSP-2"
