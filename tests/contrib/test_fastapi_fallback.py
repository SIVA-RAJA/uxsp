"""
Tests for FastAPI middleware automatic protocol fallback and upgrade.
"""

import json
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import uxsp
from uxsp.contrib.fastapi import UXSPFastAPIMiddleware
from uxsp.core.identity import Identity
from uxsp.transport.http import HEADER_SEC_UXSP_SELECTED, HEADER_SEC_UXSP_SUPPORT

@pytest.fixture()
def server_id():
    return Identity.create("FastAPI Hybrid Server", role="SERVER")

@pytest.fixture()
def client_id():
    return Identity.create("FastAPI Hybrid Client", role="CLIENT")

def test_fastapi_fallback_plain_https_json_request(server_id):
    """
    Standard plain HTTPS/JSON request should pass through unencrypted seamlessly without errors.
    """
    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware, identity=server_id, fallback=True)

    @app.post("/api/login")
    async def login_endpoint(request: Request):
        body = await request.json()
        return {"status": "authenticated", "user": body.get("username")}

    test_client = TestClient(app)

    # Standard HTTPS plaintext JSON request from non-UXSP client
    response = test_client.post("/api/login", json={"username": "alice", "password": "secretpassword"})
    assert response.status_code == 200
    assert response.json() == {"status": "authenticated", "user": "alice"}
    # No Sec-UXSP-Selected if client didn't send Sec-UXSP-Support
    assert HEADER_SEC_UXSP_SELECTED not in response.headers

def test_fastapi_fallback_auto_negotiation_upgrade_header(server_id):
    """
    Plain HTTPS request with Sec-UXSP-Support header should pass through plaintext
    and return Sec-UXSP-Selected in response to notify client of UXSP support.
    """
    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware, identity=server_id, mode="hybrid")

    @app.post("/api/data")
    async def data_endpoint(request: Request):
        data = await request.json()
        return {"received": data}

    test_client = TestClient(app)

    # Client probes with Sec-UXSP-Support header
    headers = {HEADER_SEC_UXSP_SUPPORT: "v1.2, ml-kem-768"}
    response = test_client.post("/api/data", json={"items": [1, 2, 3]}, headers=headers)

    assert response.status_code == 200
    assert response.json() == {"received": {"items": [1, 2, 3]}}
    assert response.headers.get(HEADER_SEC_UXSP_SELECTED) == "v1.2"

def test_fastapi_fallback_encrypted_uxsp_request(server_id, client_id):
    """
    When client sends UXSP encrypted package, server decrypts using PQC and returns encrypted response with Sec-UXSP-Selected.
    """
    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware, identity=server_id, fallback=True)
    uxsp.secure.register_peer(client_id.public_card())

    @app.post("/api/secure")
    async def secure_endpoint(request: Request):
        payload = request.state.uxsp_payload
        return {"secret_reply": payload.get("data") * 2}

    test_client = TestClient(app)

    pkg = uxsp.secure.Send(
        receiver=server_id.public_card(),
        item={"data": 21},
        sender=client_id,
    )

    headers = {
        "Content-Type": "application/json",
        "X-UXSP-Package": "1",
        HEADER_SEC_UXSP_SUPPORT: "v1.2, ml-kem-768",
    }
    response = test_client.post("/api/secure", content=pkg.to_json(), headers=headers)

    assert response.status_code == 200
    assert response.headers.get(HEADER_SEC_UXSP_SELECTED) == "v1.2"
    assert response.headers.get("X-UXSP-Package") == "1"

    resp_pkg = uxsp.secure.SecurePackage.from_dict(response.json())
    decrypted = uxsp.secure.Receive(
        sender=server_id.public_card(),
        package=resp_pkg,
        receiver=client_id,
    )
    res_dict = json.loads(decrypted.decode("utf-8")) if isinstance(decrypted, bytes) else decrypted
    assert res_dict == {"secret_reply": 42}

def test_fastapi_strict_mode_rejects_plain_https(server_id):
    """
    Strict mode (fallback=False or mode="strict") rejects non-UXSP requests with 400.
    """
    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware, identity=server_id, mode="strict")

    @app.post("/api/strict")
    async def strict_endpoint():
        return {"ok": True}

    test_client = TestClient(app)

    response = test_client.post("/api/strict", json={"plain": "data"})
    assert response.status_code == 400
    assert "UXSP Encryption Required" in response.json()["error"]
