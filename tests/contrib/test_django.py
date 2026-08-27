"""
Tests for uxsp.contrib.django (UXSPDjangoMiddleware & @protect_view decorator).
"""

from __future__ import annotations

import json

import pytest

django = pytest.importorskip("django")

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.test import RequestFactory

import uxsp
from uxsp.contrib.django import UXSPDjangoMiddleware, protect, protect_view
from uxsp.core.identity import Identity
from uxsp.storage.keystore import MemoryKeyStore

if not settings.configured:
    settings.configure(
        SECRET_KEY="uxsp-django-test-secret-key",
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF=__name__,
        MIDDLEWARE=[],
    )

django.setup()


@pytest.fixture()
def server_identity():
    return Identity.create("Django Server", role="SERVER")


@pytest.fixture()
def client_identity():
    return Identity.create("Django Client", role="CLIENT")


def test_django_middleware_happy_path(server_identity, client_identity):
    uxsp.secure.register_peer(client_identity.public_card())

    def view_func(request):
        payload = request.uxsp_payload
        return JsonResponse({"echo": payload, "status": "ok"})

    middleware = UXSPDjangoMiddleware(view_func)
    middleware.identity = server_identity

    factory = RequestFactory()

    req_data = {"django_message": "Hello Django from client!"}
    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item=req_data,
        sender=client_identity,
    )

    request = factory.post(
        "/api/echo",
        data=pkg.to_json(),
        content_type="application/json",
        HTTP_X_UXSP_PACKAGE="1",
        HTTP_X_UXSP_SENDER=client_identity.entity_id,
    )

    response = middleware(request)

    assert response.status_code == 200
    assert response["X-UXSP-Package"] == "1"
    assert response["X-UXSP-Sender"] == server_identity.entity_id

    resp_pkg = uxsp.secure.SecurePackage.from_dict(json.loads(response.content.decode("utf-8")))
    decrypted_resp = uxsp.secure.Receive(
        sender=server_identity.public_card(),
        package=resp_pkg,
        receiver=client_identity,
    )

    resp_dict = json.loads(decrypted_resp.decode("utf-8")) if isinstance(decrypted_resp, bytes) else decrypted_resp
    assert resp_dict == {"echo": req_data, "status": "ok"}


def test_django_middleware_keystore_and_text_response(server_identity, client_identity):
    keystore = MemoryKeyStore()
    keystore.put(client_identity.public_card())

    def view_func(request):
        return HttpResponse("TextResponse")

    middleware = UXSPDjangoMiddleware(view_func)
    middleware.identity = server_identity
    middleware.keystore = keystore

    factory = RequestFactory()
    pkg = uxsp.secure.SendText(
        receiver=server_identity.public_card(),
        text="String Payload",
        sender=client_identity,
    )

    request = factory.post("/api/text", data=pkg.to_json(), content_type="application/json")
    response = middleware(request)
    assert response.status_code == 200
    assert response["X-UXSP-Package"] == "1"


def test_django_middleware_global_context_fallback(server_identity, client_identity):
    uxsp.secure.set_identity(server_identity)
    uxsp.secure.register_peer(client_identity.public_card())

    def view_func(request):
        return JsonResponse({"ok": True})

    middleware = UXSPDjangoMiddleware(view_func)
    factory = RequestFactory()
    pkg = uxsp.secure.Send(receiver=server_identity.public_card(), item="msg", sender=client_identity)

    request = factory.post("/api/global", data=pkg.to_json(), content_type="application/json")
    response = middleware(request)
    assert response.status_code == 200


def test_django_middleware_require_encryption(server_identity):
    def view_func(request):
        return JsonResponse({"status": "ok"})

    middleware = UXSPDjangoMiddleware(view_func)
    middleware.identity = server_identity
    middleware.require_encryption = True

    factory = RequestFactory()
    request = factory.post("/api/unencrypted", data=json.dumps({"plain": "text"}), content_type="application/json")

    response = middleware(request)
    assert response.status_code == 400
    assert "Encryption Required" in json.loads(response.content.decode("utf-8"))["error"]


def test_django_middleware_excluded_path(server_identity):
    def view_func(request):
        return JsonResponse({"status": "admin_ok"})

    middleware = UXSPDjangoMiddleware(view_func)
    middleware.identity = server_identity
    middleware.require_encryption = True
    middleware.exclude_paths = ["/admin/"]

    factory = RequestFactory()
    request = factory.get("/admin/dashboard")

    response = middleware(request)
    assert response.status_code == 200
    assert json.loads(response.content.decode("utf-8")) == {"status": "admin_ok"}


def test_django_protect_view_decorator(server_identity, client_identity):
    uxsp.secure.register_peer(client_identity.public_card())

    @protect_view(server_identity=server_identity)
    def protected_view(request):
        return JsonResponse({"data": request.uxsp_payload})

    @protect()
    def protect_alias_view(request):
        return JsonResponse({"data": request.uxsp_payload})

    factory = RequestFactory()
    req_data = {"secret": "DjangoSecret"}
    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item=req_data,
        sender=client_identity,
    )

    middleware = UXSPDjangoMiddleware(protected_view)
    middleware.identity = server_identity

    request = factory.post(
        "/api/protected",
        data=pkg.to_json(),
        content_type="application/json",
        HTTP_X_UXSP_PACKAGE="1",
    )

    response = middleware(request)
    assert response.status_code == 200

    middleware_alias = UXSPDjangoMiddleware(protect_alias_view)
    middleware_alias.identity = server_identity
    pkg2 = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item=req_data,
        sender=client_identity,
    )

    req2 = factory.post(
        "/api/alias",
        data=pkg2.to_json(),
        content_type="application/json",
        HTTP_X_UXSP_PACKAGE="1",
    )
    res2 = middleware_alias(req2)
    assert res2.status_code == 200


def test_django_bytes_payload_and_require_enc(server_identity, client_identity):
    uxsp.secure.register_peer(client_identity.public_card())

    def view_func(request):
        return HttpResponse(f"Received: {request.uxsp_payload}")

    middleware = UXSPDjangoMiddleware(view_func)
    middleware.identity = server_identity
    middleware.require_encryption = True

    factory = RequestFactory()

    # Test require_encryption error response (lines 144-147)
    request_no_pkg = factory.post("/api/bytes", data="plain text", content_type="text/plain")
    res_no_pkg = middleware(request_no_pkg)
    assert res_no_pkg.status_code == 400
    assert "Encryption Required" in json.loads(res_no_pkg.content.decode("utf-8"))["error"]

    # Test SendBinary (raw binary bytes payload: lines 127-130)
    pkg = uxsp.secure.SendBinary(
        receiver=server_identity.public_card(),
        data=b"\x00\x01\x02\x03\xff",
        sender=client_identity,
    )
    request_bytes = factory.post("/api/bytes", data=pkg.to_json(), content_type="application/json", HTTP_X_UXSP_PACKAGE="1")
    res_bytes = middleware(request_bytes)
    assert res_bytes.status_code == 200
    assert res_bytes["X-UXSP-Package"] == "1"


def test_django_middleware_malformed_package(server_identity):
    def view_func(request):
        return JsonResponse({"ok": True})

    middleware = UXSPDjangoMiddleware(view_func)
    middleware.identity = server_identity

    factory = RequestFactory()

    # Invalid json body test
    req_bad_json = factory.post("/api/echo", data="not json", content_type="text/plain", HTTP_X_UXSP_PACKAGE="1")
    res_bad_json = middleware(req_bad_json)
    assert res_bad_json.status_code == 200

    fake_pkg = {
        "sender_id": "fake_id",
        "receiver_id": server_identity.entity_id,
        "data_type": "json",
        "is_chunked": False,
        "envelope": {"magic": "UXSP-INVALID", "ciphertext": "bad"},
    }

    request = factory.post(
        "/api/echo",
        data=json.dumps(fake_pkg),
        content_type="application/json",
    )

    response = middleware(request)
    assert response.status_code == 400
    assert "Decryption Failed" in json.loads(response.content.decode("utf-8"))["error"]


def test_django_streaming_response(server_identity, client_identity):
    from django.http import StreamingHttpResponse
    uxsp.secure.register_peer(client_identity.public_card())

    def view_func(request):
        def generate():
            yield b"chunk1"
            yield b"chunk2"
        return StreamingHttpResponse(generate(), content_type="application/octet-stream")

    middleware = UXSPDjangoMiddleware(view_func)
    middleware.identity = server_identity

    factory = RequestFactory()
    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item={"hello": "stream"},
        sender=client_identity,
    )

    request = factory.post(
        "/api/stream",
        data=pkg.to_json(),
        content_type="application/json",
        HTTP_X_UXSP_PACKAGE="1",
        HTTP_X_UXSP_SENDER=client_identity.entity_id,
    )

    response = middleware(request)
    assert response.status_code == 200
    
    # Process stream
    lines = list(response.streaming_content)
    valid_chunks = [L for L in lines if L.strip()]
    assert len(valid_chunks) == 2
    
    import json
    chunk_pkg = uxsp.secure.SecurePackage.from_dict(json.loads(valid_chunks[0].decode("utf-8")))
    dec = uxsp.secure.Receive(sender=server_identity.public_card(), package=chunk_pkg, receiver=client_identity)
    assert dec == b"chunk1"


def test_django_max_response_size(server_identity, client_identity):
    uxsp.secure.register_peer(client_identity.public_card())

    def view_func(request):
        return HttpResponse(b"too_big_response")

    middleware = UXSPDjangoMiddleware(view_func)
    middleware.identity = server_identity
    middleware.max_response_size = 5

    factory = RequestFactory()
    pkg = uxsp.secure.Send(
        receiver=server_identity.public_card(),
        item="hi",
        sender=client_identity,
    )

    request = factory.post(
        "/api/big",
        data=pkg.to_json(),
        content_type="application/json",
        HTTP_X_UXSP_PACKAGE="1",
        HTTP_X_UXSP_SENDER=client_identity.entity_id,
    )

    with pytest.raises(ValueError, match="exceeds max_response_size"):
        middleware(request)


def test_django_protect_missing_middleware(server_identity):
    @protect_view(server_identity=server_identity)
    def broken_view(request):
        return JsonResponse({"ok": True})

    factory = RequestFactory()
    request = factory.post("/api/broken", data={"hello": "world"}, content_type="application/json")

    with pytest.raises(RuntimeError, match="@protect_view decorator requires UXSPDjangoMiddleware"):
        broken_view(request)
