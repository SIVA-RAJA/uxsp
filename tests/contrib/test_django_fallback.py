"""
Tests for Django middleware automatic protocol fallback and upgrade.
"""

import json
import pytest

django = pytest.importorskip("django")
from django.conf import settings

if not settings.configured:
    settings.configure(
        SECRET_KEY="test-key",
        ALLOWED_HOSTS=["*"],
        MIDDLEWARE=[
            "uxsp.contrib.django.UXSPDjangoMiddleware",
        ],
        ROOT_URLCONF=__name__,
    )

import django
django.setup()

from django.http import JsonResponse
from django.test import RequestFactory, override_settings

import uxsp
from uxsp.contrib.django import UXSPDjangoMiddleware
from uxsp.core.identity import Identity
from uxsp.transport.http import HEADER_SEC_UXSP_SELECTED, HEADER_SEC_UXSP_SUPPORT

@pytest.fixture()
def server_id():
    return Identity.create("Django Hybrid Server", role="SERVER")

@pytest.fixture()
def client_id():
    return Identity.create("Django Hybrid Client", role="CLIENT")

def test_django_fallback_plain_https_json_request(server_id):
    def dummy_view(request):
        data = json.loads(request.body.decode("utf-8"))
        return JsonResponse({"status": "ok", "user": data.get("user")})

    middleware = UXSPDjangoMiddleware(dummy_view)
    middleware.identity = server_id
    middleware.fallback = True
    middleware.require_encryption = False

    rf = RequestFactory()
    req = rf.post("/api/login", data=json.dumps({"user": "charlie"}), content_type="application/json")

    resp = middleware(req)
    assert resp.status_code == 200
    assert json.loads(resp.content.decode("utf-8")) == {"status": "ok", "user": "charlie"}
    assert HEADER_SEC_UXSP_SELECTED not in resp

def test_django_fallback_auto_negotiation_upgrade_header(server_id):
    def dummy_view(request):
        return JsonResponse({"ok": True})

    middleware = UXSPDjangoMiddleware(dummy_view)
    middleware.identity = server_id
    middleware.fallback = True
    middleware.require_encryption = False

    rf = RequestFactory()
    req = rf.post("/api/ping", data=json.dumps({"ping": 1}), content_type="application/json", HTTP_SEC_UXSP_SUPPORT="v1.2, ml-kem-768")

    resp = middleware(req)
    assert resp.status_code == 200
    assert resp[HEADER_SEC_UXSP_SELECTED] == "v1.2"

def test_django_fallback_encrypted_uxsp_request(server_id, client_id):
    uxsp.secure.register_peer(client_id.public_card())

    def dummy_view(request):
        payload = request.uxsp_payload
        return JsonResponse({"result": payload.get("num") * 10})

    middleware = UXSPDjangoMiddleware(dummy_view)
    middleware.identity = server_id

    pkg = uxsp.secure.Send(
        receiver=server_id.public_card(),
        item={"num": 5},
        sender=client_id,
    )

    rf = RequestFactory()
    req = rf.post(
        "/api/calc",
        data=pkg.to_json(),
        content_type="application/json",
        HTTP_X_UXSP_PACKAGE="1",
        HTTP_SEC_UXSP_SUPPORT="v1.2, ml-kem-768",
    )

    resp = middleware(req)
    assert resp.status_code == 200
    assert resp[HEADER_SEC_UXSP_SELECTED] == "v1.2"
    assert resp["X-UXSP-Package"] == "1"

    resp_pkg = uxsp.secure.SecurePackage.from_dict(json.loads(resp.content.decode("utf-8")))
    decrypted = uxsp.secure.Receive(
        sender=server_id.public_card(),
        package=resp_pkg,
        receiver=client_id,
    )
    res_dict = json.loads(decrypted.decode("utf-8")) if isinstance(decrypted, bytes) else decrypted
    assert res_dict == {"result": 50}

def test_django_strict_mode_rejects_plain_https(server_id):
    def dummy_view(request):
        return JsonResponse({"ok": True})

    middleware = UXSPDjangoMiddleware(dummy_view)
    middleware.identity = server_id
    middleware.fallback = False
    middleware.require_encryption = True

    rf = RequestFactory()
    req = rf.post("/api/strict", data=json.dumps({"plain": 1}), content_type="application/json")

    resp = middleware(req)
    assert resp.status_code == 400
    assert "UXSP Encryption Required" in json.loads(resp.content.decode("utf-8"))["error"]

def test_django_settings_require_encryption(server_id):
    with override_settings(UXSP_REQUIRE_ENCRYPTION=True, UXSP_SERVER_IDENTITY=server_id):
        def dummy_view(request):
            return JsonResponse({"ok": True})

        middleware = UXSPDjangoMiddleware(dummy_view)
        assert middleware.fallback is False
        assert middleware.mode == "strict"
        assert middleware.require_encryption is True

def test_django_streaming_response_negotiation(server_id, client_id):
    from django.http import StreamingHttpResponse
    uxsp.secure.register_peer(client_id.public_card())

    def streaming_view(request):
        def generate():
            yield b"data_chunk_1"
            yield b"data_chunk_2"
        return StreamingHttpResponse(generate(), content_type="application/octet-stream")

    middleware = UXSPDjangoMiddleware(streaming_view)
    middleware.identity = server_id

    pkg = uxsp.secure.Send(
        receiver=server_id.public_card(),
        item={"stream": True},
        sender=client_id,
    )

    rf = RequestFactory()
    req = rf.post(
        "/api/stream",
        data=pkg.to_json(),
        content_type="application/json",
        HTTP_X_UXSP_PACKAGE="1",
        HTTP_SEC_UXSP_SUPPORT="v1.2, ml-kem-768",
    )

    resp = middleware(req)
    assert resp.status_code == 200
    assert resp[HEADER_SEC_UXSP_SELECTED] == "v1.2"
    assert resp["X-UXSP-Package"] == "1"

