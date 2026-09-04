"""
Tests for UXSP HTTP transport negotiation headers (Sec-UXSP-Support, Sec-UXSP-Selected).
"""

import pytest

from uxsp.transport.http import (
    DEFAULT_UXSP_SELECTED,
    DEFAULT_UXSP_SUPPORT,
    HEADER_SEC_UXSP_SELECTED,
    HEADER_SEC_UXSP_SUPPORT,
    UXSPHTTPRequest,
    UXSPHTTPResponse,
    negotiate_protocol,
)
from uxsp.core.envelope import Envelope

def test_negotiate_protocol_valid():
    assert negotiate_protocol("v1.2, ml-kem-768") == "v1.2"
    assert negotiate_protocol("ml-kem-768") == "v1.2"
    assert negotiate_protocol("v1.0") == "v1.0"
    assert negotiate_protocol(None) is None
    assert negotiate_protocol("") is None
    assert negotiate_protocol("unknown-alg") == DEFAULT_UXSP_SELECTED

def test_http_request_build_includes_negotiation_header():
    dummy_envelope = {
        "sender_id": "sender_123",
        "recipient_id": "recipient_456",
        "timestamp": 1234567890,
        "envelope_nonce": "nonce_abc",
    }
    req = UXSPHTTPRequest.build(dummy_envelope, sec_support="v1.2, ml-kem-768")
    assert req["headers"][HEADER_SEC_UXSP_SUPPORT] == "v1.2, ml-kem-768"
    assert req["headers"]["X-UXSP-Sender"] == "sender_123"

def test_http_response_build_includes_selected_header():
    dummy_envelope = {
        "sender_id": "sender_123",
        "recipient_id": "recipient_456",
        "timestamp": 1234567890,
        "envelope_nonce": "nonce_abc",
    }
    resp = UXSPHTTPResponse.build(dummy_envelope, sec_selected="v1.2")
    assert resp["headers"][HEADER_SEC_UXSP_SELECTED] == "v1.2"
