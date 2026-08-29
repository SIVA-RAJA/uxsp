"""
Tests for uxsp.contrib.flask (UXSPFlaskMiddleware & @protect_route decorator).
"""

from __future__ import annotations

import json

import pytest

flask = pytest.importorskip("flask")

from flask import Flask, g, jsonify

import uxsp
from uxsp.contrib.flask import UXSPFlaskMiddleware, protect, protect_route
from uxsp.core.identity import Identity
from uxsp.storage.keystore import MemoryKeyStore


@pytest.fixture()
def server_identity():
    return Identity.create("Flask Server", role="SERVER")


@pytest.fixture()
def client_identity():
    return Identity.create("Flask Client", role="CLIENT")


def test_flask_middleware_happy_path(server_identity, client_identity):
    app = Flask("test_flask_app")
    UXSPFlaskMiddleware(app, identity=server_identity)
    uxsp.secure.register_peer(client_identity.public_card())

    @app.route("/api/echo", methods=["POST"])
    def echo_endpoint():
        payload = g.uxsp_payload
        return jsonify({"echo": payload, "status": "ok"})

    test_client = app.test_client()

    req_data = {"flask_msg": "Hello Flask from client!"}
    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item=req_data,
        sender=client_identity,
    )

    response = test_client.post(
        "/api/echo",
        data=pkg.to_json(),
        content_type="application/json",
        headers={"X-UXSP-Package": "1"},
    )

    assert response.status_code == 200
    assert response.headers.get("X-UXSP-Package") == "1"
    assert response.headers.get("X-UXSP-Sender") == server_identity.entity_id

    resp_pkg = uxsp.secure.SecurePackage.from_dict(response.get_json())
    decrypted_resp = uxsp.secure.Receive(
        sender=server_identity.public_card(),
        package=resp_pkg,
        receiver=client_identity,
    )

    resp_dict = json.loads(decrypted_resp.decode("utf-8")) if isinstance(decrypted_resp, bytes) else decrypted_resp
    assert resp_dict == {"echo": req_data, "status": "ok"}


def test_flask_middleware_keystore_and_text_response(server_identity, client_identity):
    keystore = MemoryKeyStore()
    keystore.put(client_identity.public_card())

    app = Flask("test_flask_keystore")
    ext = UXSPFlaskMiddleware(identity=lambda: server_identity, keystore=keystore)
    ext.init_app(app)

    @app.route("/api/text", methods=["POST"])
    def text_endpoint():
        return f"TextResult: {g.uxsp_payload}"

    test_client = app.test_client()

    pkg = uxsp.secure.SendText(
        receiver=server_identity.public_card(),
        text="String Payload",
        sender=client_identity,
    )

    response = test_client.post("/api/text", data=pkg.to_json(), content_type="application/json", headers={"X-UXSP-Package": "1"})
    assert response.status_code == 200
    assert response.headers.get("X-UXSP-Package") == "1"


def test_flask_middleware_global_context_fallback(server_identity, client_identity):
    uxsp.secure.set_identity(server_identity)
    uxsp.secure.register_peer(client_identity.public_card())

    app = Flask("test_flask_global")
    UXSPFlaskMiddleware(app)

    @app.route("/api/global", methods=["POST"])
    def global_endpoint():
        return jsonify({"ok": True})

    test_client = app.test_client()
    pkg = uxsp.secure.Send(receiver=server_identity.public_card(), item="msg", sender=client_identity)

    response = test_client.post("/api/global", data=pkg.to_json(), content_type="application/json")
    assert response.status_code == 200


def test_flask_middleware_require_encryption(server_identity):
    app = Flask("test_flask_require_enc")
    UXSPFlaskMiddleware(app, identity=server_identity, require_encryption=True)

    @app.route("/api/unencrypted", methods=["POST"])
    def unencrypted_endpoint():
        return jsonify({"status": "plain"})

    test_client = app.test_client()
    response = test_client.post("/api/unencrypted", json={"data": "plain"})

    assert response.status_code == 400
    assert "Encryption Required" in response.get_json()["error"]


def test_flask_middleware_excluded_path(server_identity):
    app = Flask("test_flask_excluded")
    UXSPFlaskMiddleware(app, identity=server_identity, require_encryption=True, exclude_paths=["/static"])

    @app.route("/static/style.css")
    def static_style():
        return "body { color: red; }"

    test_client = app.test_client()
    response = test_client.get("/static/style.css")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "body { color: red; }"


def test_flask_protect_route_decorator(server_identity, client_identity):
    app = Flask("test_flask_protect")
    UXSPFlaskMiddleware(app, identity=server_identity)
    uxsp.secure.register_peer(client_identity.public_card())

    @app.route("/api/protected", methods=["POST"])
    @protect_route(server_identity=server_identity)
    def protected_endpoint():
        return jsonify({"received": g.uxsp_payload})

    @app.route("/api/alias", methods=["POST"])
    @protect()
    def alias_endpoint():
        return jsonify({"ok": True})

    test_client = app.test_client()
    req_data = {"secret": "FlaskSecretValue"}
    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item=req_data,
        sender=client_identity,
    )

    response = test_client.post(
        "/api/protected",
        data=pkg.to_json(),
        content_type="application/json",
        headers={"X-UXSP-Package": "1"},
    )

    assert response.status_code == 200
    assert response.headers.get("X-UXSP-Package") == "1"

    pkg2 = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item=req_data,
        sender=client_identity,
    )

    res_alias = test_client.post(
        "/api/alias",
        data=pkg2.to_json(),
        content_type="application/json",
        headers={"X-UXSP-Package": "1"},
    )
    assert res_alias.status_code == 200


def test_flask_bytes_payload(server_identity, client_identity):
    app = Flask("test_flask_bytes")
    UXSPFlaskMiddleware(app, identity=server_identity)
    uxsp.secure.register_peer(client_identity.public_card())

    @app.route("/api/bytes", methods=["POST"])
    def bytes_endpoint():
        return f"Received: {g.uxsp_payload}"

    test_client = app.test_client()

    # Test SendBinary (raw binary bytes payload: lines 140-143)
    pkg = uxsp.secure.SendBinary(
        receiver=server_identity.public_card(),
        data=b"\x00\x01\x02\x03\xff",
        sender=client_identity,
    )
    res_bytes = test_client.post("/api/bytes", data=pkg.to_json(), content_type="application/json", headers={"X-UXSP-Package": "1"})
    assert res_bytes.status_code == 200
    assert res_bytes.headers.get("X-UXSP-Package") == "1"


def test_flask_middleware_malformed_package(server_identity):
    app = Flask("test_flask_malformed")
    UXSPFlaskMiddleware(app, identity=server_identity)

    @app.route("/api/echo", methods=["POST"])
    def echo_endpoint():
        return jsonify({"ok": True})

    test_client = app.test_client()

    # Invalid json body test
    res_bad_json = test_client.post("/api/echo", data="{not json}", content_type="text/plain", headers={"X-UXSP-Package": "1"})
    assert res_bad_json.status_code == 200

    fake_pkg = {
        "sender_id": "fake_id",
        "receiver_id": server_identity.entity_id,
        "data_type": "json",
        "is_chunked": False,
        "envelope": {"magic": "UXSP-INVALID", "ciphertext": "bad"},
    }

    response = test_client.post("/api/echo", json=fake_pkg, headers={"X-UXSP-Package": "1"})
    assert response.status_code == 400
    assert "Decryption Failed" in response.get_json()["error"]


def test_flask_streaming_response(server_identity, client_identity):
    from flask import Response
    app = Flask("test_flask_streaming")
    UXSPFlaskMiddleware(app, identity=server_identity)
    uxsp.secure.register_peer(client_identity.public_card())

    @app.route("/api/stream", methods=["POST"])
    @protect(server_identity=server_identity)
    def stream_endpoint():
        def generate():
            yield b"chunk1"
            yield b"chunk2"
        return Response(generate(), mimetype="application/octet-stream", headers={"X-Custom-Header": "custom"})

    test_client = app.test_client()
    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item={"hello": "stream"},
        sender=client_identity,
    )

    response = test_client.post(
        "/api/stream",
        data=pkg.to_json(),
        content_type="application/json",
        headers={"X-UXSP-Package": "1"}
    )
    assert response.status_code == 200

    # Process stream
    lines = response.get_data().split(b"\n")
    valid_chunks = [L for L in lines if L.strip()]
    assert len(valid_chunks) == 2

    import json
    chunk_pkg = uxsp.secure.SecurePackage.from_dict(json.loads(valid_chunks[0].decode("utf-8")))
    dec = uxsp.secure.Receive(sender=server_identity.public_card(), package=chunk_pkg, receiver=client_identity)
    assert dec == b"chunk1"


def test_flask_max_response_size(server_identity, client_identity):
    from flask import Response
    app = Flask("test_flask_max_size")
    app.testing = True
    UXSPFlaskMiddleware(app, identity=server_identity, max_response_size=5)
    uxsp.secure.register_peer(client_identity.public_card())

    @app.route("/api/big", methods=["POST"])
    @protect(server_identity=server_identity)
    def big_endpoint():
        return Response(b"too_big_response")

    test_client = app.test_client()
    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item="hi",
        sender=client_identity,
    )

    with pytest.raises(ValueError, match="exceeds max_response_size"):
        test_client.post(
            "/api/big",
            data=pkg.to_json(),
            content_type="application/json",
            headers={"X-UXSP-Package": "1"}
        )


def test_flask_protect_missing_middleware(server_identity):
    app = Flask("test_flask_missing_mw")
    app.testing = True

    @app.route("/api/broken", methods=["POST"])
    @protect(server_identity=server_identity)
    def broken_endpoint():
        return jsonify({"ok": True})

    test_client = app.test_client()

    with pytest.raises(RuntimeError, match="@protect_route decorator requires UXSPFlaskMiddleware"):
        test_client.post("/api/broken", json={"hello": "world"})
