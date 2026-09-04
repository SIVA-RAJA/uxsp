"""
Tests for Flask middleware automatic protocol fallback and upgrade.
"""

import json
import pytest

flask = pytest.importorskip("flask")
from flask import Flask, jsonify, request, g

import uxsp
from uxsp.contrib.flask import UXSPFlaskMiddleware
from uxsp.core.identity import Identity
from uxsp.transport.http import HEADER_SEC_UXSP_SELECTED, HEADER_SEC_UXSP_SUPPORT

@pytest.fixture()
def server_id():
    return Identity.create("Flask Hybrid Server", role="SERVER")

@pytest.fixture()
def client_id():
    return Identity.create("Flask Hybrid Client", role="CLIENT")

def test_flask_fallback_plain_https_json_request(server_id):
    app = Flask(__name__)
    UXSPFlaskMiddleware(app, identity=server_id, fallback=True)

    @app.route("/api/login", methods=["POST"])
    def login_endpoint():
        data = request.get_json()
        return jsonify({"status": "authenticated", "user": data.get("username")})

    client = app.test_client()

    res = client.post("/api/login", json={"username": "bob", "password": "password123"})
    assert res.status_code == 200
    assert res.get_json() == {"status": "authenticated", "user": "bob"}
    assert HEADER_SEC_UXSP_SELECTED not in res.headers

def test_flask_fallback_auto_negotiation_upgrade_header(server_id):
    app = Flask(__name__)
    UXSPFlaskMiddleware(app, identity=server_id, mode="hybrid")

    @app.route("/api/ping", methods=["POST"])
    def ping_endpoint():
        return jsonify({"pong": True})

    client = app.test_client()

    headers = {HEADER_SEC_UXSP_SUPPORT: "v1.2, ml-kem-768"}
    res = client.post("/api/ping", json={"test": 1}, headers=headers)
    assert res.status_code == 200
    assert res.get_json() == {"pong": True}
    assert res.headers.get(HEADER_SEC_UXSP_SELECTED) == "v1.2"

def test_flask_fallback_encrypted_uxsp_request(server_id, client_id):
    app = Flask(__name__)
    UXSPFlaskMiddleware(app, identity=server_id, fallback=True)
    uxsp.secure.register_peer(client_id.public_card())

    @app.route("/api/secure", methods=["POST"])
    def secure_endpoint():
        payload = g.uxsp_payload
        return jsonify({"echo": payload})

    client = app.test_client()

    pkg = uxsp.secure.Send(
        receiver=server_id.public_card(),
        item={"hello": "flask"},
        sender=client_id,
    )

    headers = {
        "Content-Type": "application/json",
        "X-UXSP-Package": "1",
        HEADER_SEC_UXSP_SUPPORT: "v1.2, ml-kem-768",
    }
    res = client.post("/api/secure", data=pkg.to_json(), headers=headers)
    assert res.status_code == 200
    assert res.headers.get(HEADER_SEC_UXSP_SELECTED) == "v1.2"
    assert res.headers.get("X-UXSP-Package") == "1"

    resp_pkg = uxsp.secure.SecurePackage.from_dict(res.get_json())
    decrypted = uxsp.secure.Receive(
        sender=server_id.public_card(),
        package=resp_pkg,
        receiver=client_id,
    )
    res_dict = json.loads(decrypted.decode("utf-8")) if isinstance(decrypted, bytes) else decrypted
    assert res_dict == {"echo": {"hello": "flask"}}

def test_flask_strict_mode_rejects_plain_https(server_id):
    app = Flask(__name__)
    UXSPFlaskMiddleware(app, identity=server_id, mode="strict")

    @app.route("/api/strict", methods=["POST"])
    def strict_endpoint():
        return jsonify({"ok": True})

    client = app.test_client()

    res = client.post("/api/strict", json={"plain": "data"})
    assert res.status_code == 400
    assert "UXSP Encryption Required" in res.get_json()["error"]

def test_flask_streaming_response_negotiation(server_id, client_id):
    app = Flask(__name__)
    UXSPFlaskMiddleware(app, identity=server_id, fallback=True)
    uxsp.secure.register_peer(client_id.public_card())

    @app.route("/api/stream", methods=["POST"])
    def stream_endpoint():
        def generate():
            yield b"chunk_1"
            yield b"chunk_2"
        from flask import Response
        return Response(generate(), content_type="text/plain")

    client = app.test_client()

    pkg = uxsp.secure.Send(
        receiver=server_id.public_card(),
        item={"hello": "stream"},
        sender=client_id,
    )

    headers = {
        "Content-Type": "application/json",
        "X-UXSP-Package": "1",
        HEADER_SEC_UXSP_SUPPORT: "v1.2, ml-kem-768",
    }
    res = client.post("/api/stream", data=pkg.to_json(), headers=headers)
    assert res.status_code == 200
    assert res.headers.get(HEADER_SEC_UXSP_SELECTED) == "v1.2"
    assert res.headers.get("X-UXSP-Package") == "1"

