"""
UXSP Dynamic Application Security Testing (DAST) Suite

Dynamic security tests verifying the resilience of running UXSP servers
against active web and network attacks:
- Cryptographic replay attacks & duplicate nonces
- Ciphertext, auth tag, and header tampering
- Malformed payloads and fuzzing inputs
- Protocol negotiation bypass and version manipulation
- Denial of Service (DoS) oversized payload enforcement
- HTTP method confusion and path traversal probes
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

import uxsp
from scripts.dast_server import (
    DAST_KEYSTORE,
    SERVER_IDENTITY,
    TEST_CLIENT_IDENTITY,
    create_dast_app,
)
from uxsp.secure import Send


@pytest.fixture(autouse=True)
def setup_dast_peers() -> None:
    """Ensure DAST identities and keys are consistently registered across all test runs."""
    DAST_KEYSTORE.put(TEST_CLIENT_IDENTITY.public_card())
    DAST_KEYSTORE.put(SERVER_IDENTITY.public_card())
    uxsp.secure.register_peer(TEST_CLIENT_IDENTITY.public_card())
    uxsp.secure.register_peer(SERVER_IDENTITY.public_card())


@pytest.fixture()
def hybrid_client() -> TestClient:
    """Test client bound to hybrid mode server (fallback enabled)."""
    app = create_dast_app(strict=False)
    return TestClient(app)


@pytest.fixture()
def strict_client() -> TestClient:
    """Test client bound to strict mode server (fallback disabled)."""
    app = create_dast_app(strict=True)
    return TestClient(app)


# ── 1. Replay Attack Detection ───────────────────────────────────────────────
def test_dast_replay_attack_prevention(hybrid_client: TestClient) -> None:
    """
    DAST Replay Attack:
    Send a valid UXSP sealed package, then immediately re-transmit the exact
    same package. The server's NonceStore must detect the replay and reject it.
    """
    req_payload = {"action": "transfer_funds", "amount": 1000}
    pkg = Send(
        receiver=SERVER_IDENTITY.public_card(),
        item=req_payload,
        sender=TEST_CLIENT_IDENTITY,
    )
    raw_json = pkg.to_json()

    # First transmission: Must succeed
    resp1 = hybrid_client.post(
        "/api/secure/echo",
        content=raw_json,
        headers={"Content-Type": "application/json", "X-UXSP-Package": "1"},
    )
    assert resp1.status_code == 200, f"Expected 200, got {resp1.status_code}: {resp1.text}"

    # Replay attack: Exact same payload re-sent
    resp2 = hybrid_client.post(
        "/api/secure/echo",
        content=raw_json,
        headers={"Content-Type": "application/json", "X-UXSP-Package": "1"},
    )
    # The server MUST reject replay attacks with 400
    assert resp2.status_code == 400, f"Expected replay rejection (400), got {resp2.status_code}"


# ── 2. Ciphertext & Auth Tag Tampering Fuzzing ──────────────────────────────
def test_dast_ciphertext_tampering_fuzzing(hybrid_client: TestClient) -> None:
    """
    DAST Tampering:
    Modify bits in the encrypted ciphertext or authentication tag inside envelope.
    The server must cleanly reject with HTTP 400 without 500 crashes or stack traces.
    """
    req_payload = {"sensitive_command": "execute_pqc_job"}
    pkg = Send(
        receiver=SERVER_IDENTITY.public_card(),
        item=req_payload,
        sender=TEST_CLIENT_IDENTITY,
    )
    pkg_dict = pkg.to_dict()

    # Tamper with the ciphertext inside the envelope
    assert "envelope" in pkg_dict
    original_ct = pkg_dict["envelope"]["ciphertext"]
    assert len(original_ct) > 5
    tampered_ct = original_ct[:3] + ("A" if original_ct[3] != "A" else "B") + original_ct[4:]
    pkg_dict["envelope"]["ciphertext"] = tampered_ct

    tampered_json = json.dumps(pkg_dict)

    resp = hybrid_client.post(
        "/api/secure/echo",
        content=tampered_json,
        headers={"Content-Type": "application/json", "X-UXSP-Package": "1"},
    )
    # Must reject with HTTP 400
    assert resp.status_code == 400, f"Expected 400 on tampered ciphertext, got {resp.status_code}"
    assert "Traceback" not in resp.text


# ── 3. Malformed JSON & Fuzzing Payloads ─────────────────────────────────────
@pytest.mark.parametrize(
    "fuzzed_payload",
    [
        "{{malformed_json",
        "",
        "null",
        "[]",
        "0",
        '{"v": "1.3", "recipient": "bogus"}',
        '{"v": "1.3", "recipient": 12345, "sender": false}',
        "A" * 5000,
        b"\x00\xff\xfe\xfd\x80\x90",
    ],
)
def test_dast_fuzzed_request_resilience(hybrid_client: TestClient, fuzzed_payload: Any) -> None:
    """
    DAST Fuzzing:
    Send arbitrary malformed bodies with the X-UXSP-Package header.
    The server must cleanly reject with 400 and never crash with HTTP 500.
    """
    resp = hybrid_client.post(
        "/api/secure/echo",
        content=fuzzed_payload if isinstance(fuzzed_payload, (str, bytes)) else json.dumps(fuzzed_payload),
        headers={"Content-Type": "application/json", "X-UXSP-Package": "1"},
    )
    assert resp.status_code != 500, f"Server returned 500 on input: {fuzzed_payload!r}"
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"


# ── 4. Protocol Downgrade & Negotiation Manipulation ─────────────────────────
def test_dast_strict_mode_rejects_unencrypted_requests(strict_client: TestClient) -> None:
    """
    DAST Protocol Enforcement:
    In strict mode, any attempt to bypass UXSP encryption and send plaintext
    must be rejected with HTTP 400.
    """
    resp = strict_client.post(
        "/api/secure/echo",
        json={"message": "Unencrypted attacker probe"},
    )
    assert resp.status_code == 400, f"Strict mode accepted unencrypted request: {resp.status_code}"


def test_dast_negotiation_header_tampering(hybrid_client: TestClient) -> None:
    """
    DAST Negotiation:
    Probe with malicious/bogus protocol negotiation headers.
    """
    # Bogus UXSP version: fallback to standard HTTP gracefully
    resp = hybrid_client.get(
        "/api/public/status",
        headers={"X-UXSP-Version": "999.999.999", "X-UXSP-Accept": "application/x-bogus"},
    )
    assert resp.status_code == 200

    # Header with unknown sender identity sending non-package body
    resp2 = hybrid_client.post(
        "/api/secure/echo",
        content='{"test": 1}',
        headers={
            "X-UXSP-Package": "1",
            "X-UXSP-Sender": "unknown-nonexistent-sender-id",
        },
    )
    assert resp2.status_code == 400


# ── 5. Denial of Service (Payload Size Ceiling) ──────────────────────────────
def test_dast_payload_too_large_rejection(hybrid_client: TestClient) -> None:
    """
    DAST DoS Protection:
    Send a payload exceeding max_request_size (2 MiB).
    Server must respond with HTTP 413 Payload Too Large.
    """
    oversized_data = "X" * (3 * 1024 * 1024)  # 3 MiB
    resp = hybrid_client.post(
        "/api/secure/echo",
        content=oversized_data,
        headers={"Content-Type": "application/json", "X-UXSP-Package": "1"},
    )
    assert resp.status_code == 413, f"Expected HTTP 413 on oversized payload, got {resp.status_code}"


# ── 6. Path Traversal & Security Probing ─────────────────────────────────────
@pytest.mark.parametrize(
    "probe_path",
    [
        "/api/public/health/../../etc/passwd",
        "/docs/../../../../etc/shadow",
        "/openapi.json%00.html",
        "//api//public//health",
        "/api/public/health?param=<script>alert(1)</script>",
        "/api/public/health?param=1' OR '1'='1",
    ],
)
def test_dast_path_traversal_and_injection_probes(hybrid_client: TestClient, probe_path: str) -> None:
    """
    DAST Path Traversal & Injection:
    Verify that URI traversal and standard injection probes do not leak files or cause crashes.
    """
    resp = hybrid_client.get(probe_path)
    assert resp.status_code in (200, 404, 400), f"Unexpected status {resp.status_code} for path {probe_path}"
    assert "root:x:0:0:" not in resp.text
    assert "Traceback" not in resp.text


# ── 7. HTTP Method Fuzzing ──────────────────────────────────────────────────
@pytest.mark.parametrize("method", ["TRACE", "OPTIONS", "HEAD", "PATCH"])
def test_dast_http_method_handling(hybrid_client: TestClient, method: str) -> None:
    """
    DAST HTTP Method Verification:
    Verify that unexpected or unhandled HTTP methods are handled cleanly.
    """
    resp = hybrid_client.request(method, "/api/public/health")
    assert resp.status_code in (200, 405), f"Method {method} returned unexpected code {resp.status_code}"
    # TRACE method should never reflect request headers back (XST prevention)
    if method == "TRACE":
        assert resp.status_code == 405
