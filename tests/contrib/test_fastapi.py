"""
Tests for uxsp.contrib.fastapi (UXSPFastAPIMiddleware & @protect decorator).
"""

from __future__ import annotations

import json
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response
from fastapi.testclient import TestClient
import pytest

import uxsp
from uxsp.contrib.fastapi import UXSPFastAPIMiddleware, protect, protect_route
from uxsp.core.identity import Identity
from uxsp.storage.keystore import MemoryKeyStore


@pytest.fixture()
def server_identity():
    return Identity.create("FastAPI Server", role="SERVER")


@pytest.fixture()
def client_identity():
    return Identity.create("FastAPI Client", role="CLIENT")


def test_fastapi_middleware_happy_path(server_identity, client_identity):
    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware, identity=server_identity)

    uxsp.secure.register_peer(client_identity.public_card())

    @app.post("/api/echo")
    async def echo_endpoint(request: Request):
        payload = request.state.uxsp_payload
        return {"echo": payload, "status": "ok"}

    test_client = TestClient(app)

    req_data = {"message": "Hello FastAPI from client!"}
    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item=req_data,
        sender=client_identity,
    )

    response = test_client.post(
        "/api/echo",
        content=pkg.to_json(),
        headers={"Content-Type": "application/json", "X-UXSP-Package": "1"},
    )

    assert response.status_code == 200
    assert response.headers.get("X-UXSP-Package") == "1"
    assert response.headers.get("X-UXSP-Sender") == server_identity.entity_id

    resp_pkg = uxsp.secure.SecurePackage.from_dict(response.json())
    decrypted_resp = uxsp.secure.Receive(
        sender=server_identity.public_card(),
        package=resp_pkg,
        receiver=client_identity,
    )

    resp_dict = json.loads(decrypted_resp.decode("utf-8")) if isinstance(decrypted_resp, bytes) else decrypted_resp
    assert resp_dict == {"echo": req_data, "status": "ok"}


def test_fastapi_middleware_keystore_and_text_response(server_identity, client_identity):
    keystore = MemoryKeyStore()
    keystore.put(client_identity.public_card())

    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware, identity=lambda: server_identity, keystore=keystore)

    @app.post("/api/text")
    async def text_endpoint(request: Request):
        return PlainTextResponse("PlainTextResult")

    test_client = TestClient(app)

    # Test sending text payload (not JSON)
    pkg = uxsp.secure.SendText(
        receiver=server_identity.public_card(),
        text="Hello String Payload",
        sender=client_identity,
    )

    response = test_client.post(
        "/api/text",
        content=pkg.to_json(),
        headers={"X-UXSP-Package": "1"},
    )

    assert response.status_code == 200
    assert response.headers.get("X-UXSP-Package") == "1"


def test_fastapi_middleware_global_context_fallback(server_identity, client_identity):
    uxsp.secure.set_identity(server_identity)
    uxsp.secure.register_peer(client_identity.public_card())

    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware)

    @app.post("/api/global")
    async def global_endpoint(request: Request):
        return {"data": request.state.uxsp_payload}

    test_client = TestClient(app)

    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item={"g": 1},
        sender=client_identity,
    )

    response = test_client.post("/api/global", content=pkg.to_json())
    assert response.status_code == 200


def test_fastapi_middleware_require_encryption(server_identity):
    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware, identity=server_identity, require_encryption=True)

    @app.post("/api/unencrypted")
    async def unencrypted_endpoint():
        return {"data": "plain"}

    test_client = TestClient(app)

    response = test_client.post("/api/unencrypted", json={"data": "plain"})
    assert response.status_code == 400
    assert "Encryption Required" in response.json()["error"]


def test_fastapi_middleware_excluded_path(server_identity):
    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware, identity=server_identity, require_encryption=True, exclude_paths=["/public"])

    @app.get("/public/health")
    async def health_check():
        return {"status": "healthy"}

    test_client = TestClient(app)

    response = test_client.get("/public/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_fastapi_protect_decorator(server_identity, client_identity):
    app = FastAPI()
    uxsp.secure.register_peer(client_identity.public_card())

    @app.post("/api/protected")
    @protect(server_identity=server_identity)
    async def protected_endpoint(request: Request):
        return {"protected_data": request.state.uxsp_payload}

    @app.post("/api/protected_pos")
    @protect_route(server_identity=server_identity)
    async def protected_pos_endpoint(req: Request):
        return {"ok": True}

    @app.post("/api/no_req")
    @protect()
    async def no_req_endpoint():
        return {"ok": True}

    app.add_middleware(UXSPFastAPIMiddleware, identity=server_identity)
    test_client = TestClient(app)

    req_data = {"secret": "TopSecretValue"}
    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item=req_data,
        sender=client_identity,
    )

    response = test_client.post(
        "/api/protected",
        content=pkg.to_json(),
        headers={"X-UXSP-Package": "1"},
    )
    assert response.status_code == 200

    pkg2 = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item=req_data,
        sender=client_identity,
    )

    response_pos = test_client.post(
        "/api/protected_pos",
        content=pkg2.to_json(),
        headers={"X-UXSP-Package": "1"},
    )
    assert response_pos.status_code == 200

    response_no = test_client.post("/api/no_req", json={"a": 1})
    assert response_no.status_code == 200


def test_fastapi_protect_decorator_direct_invocation():
    # Directly invoke decorated function without Request
    @protect()
    async def dummy_fn(x: int):
        return x + 1

    import asyncio
    res = asyncio.run(dummy_fn(5))
    assert res == 6

    # Directly invoke decorated function with Request as positional arg
    @protect()
    async def dummy_fn_req(req: Request):
        return getattr(req.state, "uxsp_force_encrypt", False)

    scope = {"type": "http", "method": "POST", "path": "/"}
    req = Request(scope)
    assert asyncio.run(dummy_fn_req(req)) is True


def test_fastapi_bytes_payload_and_require_enc(server_identity, client_identity):
    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware, identity=server_identity, require_encryption=True)
    uxsp.secure.register_peer(client_identity.public_card())

    @app.post("/api/bytes")
    async def bytes_endpoint(request: Request):
        return Response(content=f"Received: {request.state.uxsp_payload}".encode("utf-8"), media_type="text/plain")

    test_client = TestClient(app)

    # Test require_encryption error response (line 166)
    res_no_pkg = test_client.post("/api/bytes", content=b"plain text", headers={"Content-Type": "text/plain"})
    assert res_no_pkg.status_code == 400
    assert "Encryption Required" in res_no_pkg.json()["error"]

    # Test SendBinary (raw binary bytes payload: lines 143-146 & 160-163)
    pkg = uxsp.secure.SendBinary(
        receiver=server_identity.public_card(),
        data=b"\x00\x01\x02\x03\xff",
        sender=client_identity,
    )
    res_bytes = test_client.post("/api/bytes", content=pkg.to_json(), headers={"X-UXSP-Package": "1"})
    assert res_bytes.status_code == 200
    assert res_bytes.headers.get("X-UXSP-Package") == "1"


def test_fastapi_middleware_malformed_package_and_invalid_body(server_identity):
    app = FastAPI()
    app.add_middleware(UXSPFastAPIMiddleware, identity=server_identity)

    @app.post("/api/echo")
    async def echo_endpoint():
        return {"ok": True}

    test_client = TestClient(app)

    # Invalid json body test
    res_bad_json = test_client.post("/api/echo", content=b"not json", headers={"X-UXSP-Package": "1"})
    assert res_bad_json.status_code == 200

    fake_pkg = {
        "sender_id": "fake_id",
        "receiver_id": server_identity.entity_id,
        "data_type": "json",
        "is_chunked": False,
        "envelope": {"magic": "UXSP-INVALID", "ciphertext": "bad"},
    }

    response = test_client.post("/api/echo", json=fake_pkg)
    assert response.status_code == 400
    assert "Decryption Failed" in response.json()["error"]
