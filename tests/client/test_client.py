"""
Comprehensive Test Suite for UXSP Client-Side Protocol Fallback & Transport
"""
from __future__ import annotations

import json
import time
from typing import Any

import fakeredis
import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

import uxsp.aio as aio
from uxsp.client import (
    AsyncUXSPClient,
    HostCapability,
    InMemoryHostCapabilityCache,
    ProtocolFallbackError,
    RedisHostCapabilityCache,
    UXSPClient,
    UXSPClientError,
    UXSPPeerResolutionError,
    UXSPResponse,
    normalize_host_key,
)
from uxsp.contrib.fastapi import UXSPFastAPIMiddleware
from uxsp.core.identity import Identity
from uxsp.secure import SecurePackage
from uxsp.transport.http import (
    HEADER_SEC_UXSP_SELECTED,
    HEADER_SEC_UXSP_SUPPORT,
)

try:
    import httpx
except ImportError:
    try:
        import httpx2 as httpx
    except ImportError:
        httpx = None


# ─────────────────────────────────────────────
# 1. HOST KEY & CAPABILITY TESTS
# ─────────────────────────────────────────────


def test_normalize_host_key():
    assert normalize_host_key("https://api.google.com/v1/resource") == "api.google.com:443"
    assert normalize_host_key("http://insecure.test:8080/foo") == "insecure.test:8080"
    assert normalize_host_key("api.stripe.com") == "api.stripe.com:443"
    assert normalize_host_key("http://localhost") == "localhost:80"
    assert normalize_host_key("wss://gateway.uxsp.io:9000/ws") == "gateway.uxsp.io:9000"


def test_host_capability_dataclass():
    cap = HostCapability(
        host="api.test:443",
        supports_uxsp=True,
        selected_version="v1.2",
        peer_id="peer_xyz",
        ttl=10.0,
    )
    assert not cap.is_expired()
    d = cap.to_dict()
    assert d["supports_uxsp"] is True
    assert d["selected_version"] == "v1.2"

    cap_restored = HostCapability.from_dict(d)
    assert cap_restored.host == "api.test:443"
    assert cap_restored.peer_id == "peer_xyz"

    # Expired check
    cap_expired = HostCapability(
        host="api.test:443",
        supports_uxsp=False,
        cached_at=time.time() - 20.0,
        ttl=10.0,
    )
    assert cap_expired.is_expired()


# ─────────────────────────────────────────────
# 2. CACHE BACKEND TESTS
# ─────────────────────────────────────────────


def test_in_memory_host_capability_cache():
    cache = InMemoryHostCapabilityCache(default_ttl=5.0)
    key = "api.google.com:443"
    assert cache.get(key) is None

    cap = HostCapability(host=key, supports_uxsp=False, ttl=5.0)
    cache.set(key, cap)
    assert cache.get(key) is not None
    assert cache.get(key).supports_uxsp is False

    # Simulate expiration
    cap.cached_at = time.time() - 10.0
    assert cache.get(key) is None

    # Clear
    cache.set(key, HostCapability(host=key, supports_uxsp=True))
    cache.clear()
    assert cache.get(key) is None


@pytest.mark.asyncio
async def test_in_memory_cache_async_methods():
    cache = InMemoryHostCapabilityCache(default_ttl=5.0)
    key = "api.uxsp.test:443"
    cap = HostCapability(host=key, supports_uxsp=True)
    await cache.aset(key, cap)
    retrieved = await cache.aget(key)
    assert retrieved is not None
    assert retrieved.supports_uxsp is True
    await cache.aclear()
    assert await cache.aget(key) is None


def test_redis_host_capability_cache_sync():
    r = fakeredis.FakeRedis()
    cache = RedisHostCapabilityCache(r, prefix="test_uxsp:")
    key = "redis.test:443"

    assert cache.get(key) is None
    cap = HostCapability(host=key, supports_uxsp=True, selected_version="v1.2")
    cache.set(key, cap)

    retrieved = cache.get(key)
    assert retrieved is not None
    assert retrieved.supports_uxsp is True
    assert retrieved.selected_version == "v1.2"

    cache.clear()
    assert cache.get(key) is None


@pytest.mark.asyncio
async def test_redis_host_capability_cache_async():
    r = fakeredis.FakeAsyncRedis()
    cache = RedisHostCapabilityCache(r, prefix="test_uxsp_async:")
    key = "async.redis.test:443"

    assert await cache.aget(key) is None
    cap = HostCapability(host=key, supports_uxsp=False)
    await cache.aset(key, cap)

    retrieved = await cache.aget(key)
    assert retrieved is not None
    assert retrieved.supports_uxsp is False

    await cache.aclear()
    assert await cache.aget(key) is None


# ─────────────────────────────────────────────
# 3. RESPONSE OBJECT TESTS
# ─────────────────────────────────────────────


def test_uxsp_response_plain():
    body = json.dumps({"status": "ok", "message": "hello"}).encode("utf-8")
    resp = UXSPResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        content=body,
        url="https://api.google.com/test",
        is_uxsp=False,
    )
    assert resp.text == body.decode("utf-8")
    assert resp.json() == {"status": "ok", "message": "hello"}
    resp.raise_for_status()

    # Error response
    err_resp = UXSPResponse(
        status_code=404,
        headers={},
        content=b"Not Found",
        url="https://api.google.com/missing",
    )
    with pytest.raises(UXSPClientError) as exc_info:
        err_resp.raise_for_status()
    assert "404" in str(exc_info.value)


def test_uxsp_response_encrypted():
    resp = UXSPResponse(
        status_code=200,
        headers={"x-uxsp-package": "1"},
        content=b'{"mock": "package"}',
        url="https://api.uxsp.internal/secure",
        is_uxsp=True,
        data={"secret": 42},
    )
    assert resp.is_uxsp is True
    assert resp.json() == {"secret": 42}


# ─────────────────────────────────────────────
# 4. SYNCHRONOUS CLIENT TESTS (MOCK TRANSPORT)
# ─────────────────────────────────────────────


def test_sync_client_external_https_discovery():
    """
    Test 1: Calling a regular external HTTPS server (e.g. Google/Stripe).
    Initial request sends Sec-UXSP-Support probe.
    Server ignores it and replies plain HTTP.
    Client caches supports_uxsp=False.
    Subsequent request uses plain HTTPS directly without probe.
    """
    requests_log: list[dict[str, Any]] = []

    def mock_request(method, url, headers, content, timeout):
        requests_log.append({"url": url, "headers": headers, "content": content})
        return 200, {"Content-Type": "application/json"}, b'{"google": "ok"}'

    client = UXSPClient(cache=InMemoryHostCapabilityCache())
    client._raw_send = mock_request

    # First request: unknown host -> probe sent
    resp1 = client.fetch("https://api.google.com/search", data={"q": "crypto"})
    assert resp1.status_code == 200
    assert resp1.is_uxsp is False
    assert resp1.json() == {"google": "ok"}
    assert HEADER_SEC_UXSP_SUPPORT in requests_log[0]["headers"]

    # Verify cache recorded supports_uxsp=False
    cap = client.cache.get("api.google.com:443")
    assert cap is not None
    assert cap.supports_uxsp is False

    # Second request: known plain HTTPS host -> probe header omitted
    resp2 = client.fetch("https://api.google.com/search?q=uxsp")
    assert resp2.status_code == 200
    assert resp2.is_uxsp is False
    assert HEADER_SEC_UXSP_SUPPORT not in requests_log[1]["headers"]


def test_sync_client_uxsp_server_discovery_and_encryption():
    """
    Test 2: Calling a UXSP server with fallback.
    Initial request sends probe -> server responds Sec-UXSP-Selected: v1.2.
    Client caches supports_uxsp=True.
    When peer card is registered, client automatically encrypts future requests.
    """
    alice = Identity.create(name="AliceClient", role="CLIENT")
    bob = Identity.create(name="BobServer", role="SERVER")
    bob_card = bob.public_card()

    cache = InMemoryHostCapabilityCache()
    client = UXSPClient(identity=alice, cache=cache)
    requests_log: list[dict[str, Any]] = []

    def mock_server(method, url, headers, content, timeout):
        requests_log.append({"headers": headers, "content": content})
        content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
        # If client sent plain probe:
        if HEADER_SEC_UXSP_SUPPORT in headers and "application/uxsp+json" not in content_type:
            return (
                200,
                {
                    "Content-Type": "application/json",
                    HEADER_SEC_UXSP_SELECTED: "v1.2",
                    "X-UXSP-Sender": bob.entity_id,
                },
                b'{"server": "uxsp_ready"}',
            )

        # If client sent UXSP package:
        if "application/uxsp+json" in content_type:
            pkg = SecurePackage.from_json(content.decode("utf-8"))
            from uxsp.secure import Receive, Send

            item = Receive(pkg, sender=alice.public_card(), receiver=bob)
            assert item == {"msg": "secret request"}
            # Reply with encrypted response
            reply_pkg = Send(receiver=alice.public_card(), item={"status": "granted"}, sender=bob)
            return (
                200,
                {
                    "Content-Type": "application/uxsp+json",
                    "X-UXSP-Package": "1",
                    "X-UXSP-Sender": bob.entity_id,
                    HEADER_SEC_UXSP_SELECTED: "v1.2",
                },
                reply_pkg.to_json().encode("utf-8"),
            )

        return 400, {}, b"Unknown request format"

    client._raw_send = mock_server

    # Request 1: Probe
    resp1 = client.fetch("https://api.myinfra.org/v1/auth", json_data={"hello": "world"})
    assert resp1.status_code == 200
    assert resp1.is_uxsp is False
    cap = cache.get("api.myinfra.org:443")
    assert cap is not None
    assert cap.supports_uxsp is True
    assert cap.selected_version == "v1.2"

    # Register Bob's public card
    client.register_peer("api.myinfra.org:443", bob_card)

    # Request 2: Now encrypted with UXSP!
    resp2 = client.fetch("https://api.myinfra.org/v1/auth", json_data={"msg": "secret request"})
    assert resp2.status_code == 200
    assert resp2.is_uxsp is True
    assert resp2.json() == {"status": "granted"}


def test_sync_client_force_uxsp_errors():
    cache = InMemoryHostCapabilityCache()
    client = UXSPClient(cache=cache)

    # 1. Force UXSP when host is known non-UXSP -> ProtocolFallbackError
    cache.set("google.com:443", HostCapability(host="google.com:443", supports_uxsp=False))
    with pytest.raises(ProtocolFallbackError):
        client.fetch("https://google.com", force_uxsp=True)

    # 2. Force UXSP without peer card -> UXSPPeerResolutionError
    with pytest.raises(UXSPPeerResolutionError):
        client.fetch("https://unknown.com", force_uxsp=True)


def test_sync_client_methods_and_convenience():
    called = []

    def mock_send(method, url, headers, content, timeout):
        called.append((method, url))
        return 200, {}, b"ok"

    client = UXSPClient()
    client._raw_send = mock_send

    client.get("https://test.local/get")
    client.post("https://test.local/post", json_data={"a": 1})
    client.put("https://test.local/put", data="raw")
    client.delete("https://test.local/del")
    client.patch("https://test.local/patch")

    assert called == [
        ("GET", "https://test.local/get"),
        ("POST", "https://test.local/post"),
        ("PUT", "https://test.local/put"),
        ("DELETE", "https://test.local/del"),
        ("PATCH", "https://test.local/patch"),
    ]

    with client:
        pass  # test __enter__ and __exit__


# ─────────────────────────────────────────────
# 5. ASYNCHRONOUS CLIENT TESTS
# ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_client_discovery_and_encryption():
    alice = await aio.create_identity("AsyncAlice")
    bob = await aio.create_identity("AsyncBob")
    bob_card = bob.public_card()

    cache = InMemoryHostCapabilityCache()
    client = AsyncUXSPClient(identity=alice, cache=cache)

    async def mock_async_server(method, url, headers, content, timeout):
        content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
        if "application/uxsp+json" in content_type:
            pkg = SecurePackage.from_json(content.decode("utf-8"))
            item = await aio.Receive(pkg, sender=alice.public_card(), receiver=bob)
            assert item == {"vault_key": "top_secret"}
            reply_pkg = await aio.Send(
                receiver=alice.public_card(), item={"access": "granted"}, sender=bob
            )
            return (
                200,
                {
                    "Content-Type": "application/uxsp+json",
                    "X-UXSP-Package": "1",
                    "X-UXSP-Sender": bob.entity_id,
                    HEADER_SEC_UXSP_SELECTED: "v1.2",
                },
                reply_pkg.to_json().encode("utf-8"),
            )

        # Plain response with UXSP support
        return (
            200,
            {
                "Content-Type": "application/json",
                HEADER_SEC_UXSP_SELECTED: "v1.2",
                "X-UXSP-Sender": bob.entity_id,
            },
            b'{"status": "ok"}',
        )

    client._raw_send = mock_async_server

    # Request 1: Probe
    resp1 = await client.fetch("https://async.server.test/api", json_data={"hello": "async"})
    assert resp1.status_code == 200
    assert resp1.is_uxsp is False

    cap = await cache.aget("async.server.test:443")
    assert cap is not None
    assert cap.supports_uxsp is True

    # Register Bob's card
    client.register_peer("async.server.test:443", bob_card)

    # Request 2: UXSP Encrypted
    resp2 = await client.fetch(
        "https://async.server.test/api", json_data={"vault_key": "top_secret"}
    )
    assert resp2.status_code == 200
    assert resp2.is_uxsp is True
    assert resp2.json() == {"access": "granted"}

    await client.aclose()


@pytest.mark.asyncio
async def test_async_client_convenience_methods():
    called = []

    async def mock_send(method, url, headers, content, timeout):
        called.append((method, url))
        return 200, {}, b"async_ok"

    client = AsyncUXSPClient()
    client._raw_send = mock_send

    await client.get("https://async.test/get")
    await client.post("https://async.test/post", json_data={"a": 1})
    await client.put("https://async.test/put")
    await client.delete("https://async.test/del")
    await client.patch("https://async.test/patch")

    assert called == [
        ("GET", "https://async.test/get"),
        ("POST", "https://async.test/post"),
        ("PUT", "https://async.test/put"),
        ("DELETE", "https://async.test/del"),
        ("PATCH", "https://async.test/patch"),
    ]

    async with client:
        pass


@pytest.mark.asyncio
async def test_async_client_force_uxsp_errors():
    cache = InMemoryHostCapabilityCache()
    client = AsyncUXSPClient(cache=cache)

    await cache.aset("non_uxsp.com:443", HostCapability(host="non_uxsp.com:443", supports_uxsp=False))
    with pytest.raises(ProtocolFallbackError):
        await client.fetch("https://non_uxsp.com", force_uxsp=True)

    with pytest.raises(UXSPPeerResolutionError):
        await client.fetch("https://unknown.com", force_uxsp=True)


# ─────────────────────────────────────────────
# 6. FASTAPI ASGI INTEGRATION TEST
# ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fastapi_middleware_automatic_fallback_and_uxsp():
    from starlette.applications import Starlette
    from starlette.routing import Route

    server_ident = await aio.create_identity("ServerAPI")
    client_ident = await aio.create_identity("ClientApp")

    async def endpoint(request: Request):
        # Read decrypted state or plain json
        body = getattr(request.state, "uxsp_payload", None)
        if body is None:
            raw = await request.body()
            body = json.loads(raw.decode()) if raw else {}
        return JSONResponse({"echo": body, "secure": bool(request.state.uxsp_encrypted)})

    from uxsp.secure import register_peer

    register_peer(client_ident.public_card())

    app = Starlette(routes=[Route("/process", endpoint, methods=["POST", "GET"])])
    app.add_middleware(
        UXSPFastAPIMiddleware,
        identity=server_ident,
        fallback=True,
    )

    # Use httpx.ASGITransport
    transport = httpx.ASGITransport(app=app)
    custom_http = httpx.AsyncClient(transport=transport, base_url="https://testserver")

    cache = InMemoryHostCapabilityCache()
    uxsp_client = AsyncUXSPClient(
        identity=client_ident,
        cache=cache,
        http_client=custom_http,
    )
    uxsp_client.register_peer("testserver:443", server_ident.public_card())

    # 1. Plain request with probe to start:
    resp1 = await uxsp_client.fetch("https://testserver/process", json_data={"hello": "server"})
    # Since testserver was unknown, probe sent -> server replies with Sec-UXSP-Selected!
    assert resp1.status_code == 200
    assert resp1.json()["echo"] == {"hello": "server"}
    assert resp1.json()["secure"] is False  # first was plain fallback

    # Check cache was updated with supports_uxsp=True
    cap = await cache.aget("testserver:443")
    assert cap is not None
    assert cap.supports_uxsp is True

    # 2. Next request automatically sends UXSP encrypted package!
    resp2 = await uxsp_client.fetch("https://testserver/process", json_data={"secret": "agent_data"})
    assert resp2.status_code == 200
    assert resp2.is_uxsp is True
    assert resp2.json()["echo"] == {"secret": "agent_data"}
    assert resp2.json()["secure"] is True

    await custom_http.aclose()


# ─────────────────────────────────────────────
# 7. COVERAGE & EDGE CASE TESTS
# ─────────────────────────────────────────────


def test_convenience_functions_sync():
    import uxsp.client as c
    from uxsp.client._sync_client import _DEFAULT_CLIENT

    def mock_send(method, url, headers, content, timeout):
        return 200, {}, b'{"res": "ok"}'

    _DEFAULT_CLIENT._raw_send = mock_send
    assert c.fetch("https://example.com").status_code == 200
    assert c.request("GET", "https://example.com").status_code == 200
    assert c.get("https://example.com").status_code == 200
    assert c.post("https://example.com", json_data={"x": 1}).status_code == 200
    assert c.put("https://example.com").status_code == 200
    assert c.delete("https://example.com").status_code == 200
    assert c.patch("https://example.com").status_code == 200


@pytest.mark.asyncio
async def test_convenience_functions_async():
    import uxsp.aio.client as ac

    async def mock_async_send(method, url, headers, content, timeout):
        return 200, {}, b'{"res": "ok"}'

    from uxsp.client._async_client import _DEFAULT_ASYNC_CLIENT

    _DEFAULT_ASYNC_CLIENT._raw_send = mock_async_send
    assert (await ac.fetch("https://example.com")).status_code == 200
    assert (await ac.request("GET", "https://example.com")).status_code == 200
    assert (await ac.get("https://example.com")).status_code == 200
    assert (await ac.post("https://example.com", json_data={"x": 1})).status_code == 200
    assert (await ac.put("https://example.com")).status_code == 200
    assert (await ac.delete("https://example.com")).status_code == 200
    assert (await ac.patch("https://example.com")).status_code == 200


def test_resolve_peer_card_variants():
    ident = Identity.create("TestUser", "CLIENT")
    card = ident.public_card()

    from uxsp.storage.keystore import MemoryKeyStore

    ks = MemoryKeyStore()
    ks.put(card)

    client = UXSPClient(identity=ident, keystore=ks)

    # 1. Identity instance passed as peer_card
    resolved = client._resolve_peer_card("host:443", peer_card=ident)
    assert resolved.entity_id == card.entity_id

    # 2. peer_id resolved via keystore
    resolved2 = client._resolve_peer_card("host:443", peer_id=card.entity_id)
    assert resolved2.entity_id == card.entity_id

    # 3. peer_id resolved via peer_registry
    client.peer_registry["custom_peer"] = card
    resolved3 = client._resolve_peer_card("host:443", peer_id="custom_peer")
    assert resolved3.entity_id == card.entity_id

    # 4. cap.peer_id resolved via keystore
    cap = HostCapability(host="host:443", supports_uxsp=True, peer_id=card.entity_id)
    resolved4 = client._resolve_peer_card("host:443", cap=cap)
    assert resolved4.entity_id == card.entity_id

    # 5. cap.peer_id in peer_registry
    cap5 = HostCapability(host="host:443", supports_uxsp=True, peer_id="custom_peer")
    resolved5 = client._resolve_peer_card("host:443", cap=cap5)
    assert resolved5.entity_id == card.entity_id


@pytest.mark.asyncio
async def test_async_resolve_peer_card_variants():
    ident = await aio.create_identity("AsyncUser")
    card = ident.public_card()

    from uxsp.storage.keystore import MemoryKeyStore

    ks = MemoryKeyStore()
    ks.put(card)

    client = AsyncUXSPClient(identity=ident, keystore=ks)

    # 1. Identity instance as peer_card
    resolved = await client._resolve_peer_card("host:443", peer_card=ident)
    assert resolved.entity_id == card.entity_id

    # 2. peer_id via keystore
    resolved2 = await client._resolve_peer_card("host:443", peer_id=card.entity_id)
    assert resolved2.entity_id == card.entity_id

    # 3. peer_id via peer_registry
    client.peer_registry["async_custom"] = card
    resolved3 = await client._resolve_peer_card("host:443", peer_id="async_custom")
    assert resolved3.entity_id == card.entity_id

    # 4. cap.peer_id via keystore
    cap = HostCapability(host="host:443", supports_uxsp=True, peer_id=card.entity_id)
    resolved4 = await client._resolve_peer_card("host:443", cap=cap)
    assert resolved4.entity_id == card.entity_id

    # 5. cap.peer_id via peer_registry
    cap5 = HostCapability(host="host:443", supports_uxsp=True, peer_id="async_custom")
    resolved5 = await client._resolve_peer_card("host:443", cap=cap5)
    assert resolved5.entity_id == card.entity_id


def test_active_identity_fallbacks(monkeypatch):
    import uxsp.secure as sec

    monkeypatch.setattr(sec.get_context(), "get_identity", lambda: None)
    client = UXSPClient(identity=None)
    with pytest.raises(UXSPClientError):
        client._get_active_identity()

    user = Identity.create("ConfiguredUser", "CLIENT")
    monkeypatch.undo()
    sec.configure(identity=user)
    assert client._get_active_identity().entity_id == user.entity_id
    sec.reset_context()


@pytest.mark.asyncio
async def test_async_active_identity_fallbacks(monkeypatch):
    from uxsp.aio import secure as asec

    async def mock_none_ident():
        return None

    monkeypatch.setattr(asec, "get_identity", mock_none_ident)
    client = AsyncUXSPClient(identity=None)
    with pytest.raises(UXSPClientError):
        await client._get_active_identity()

    user = await aio.create_identity("AsyncConfiguredUser")
    monkeypatch.undo()
    await aio.configure(identity=user)
    active = await client._get_active_identity()
    assert active.entity_id == user.entity_id
    await aio.reset_context()


def test_response_json_edge_cases():
    # String but not JSON
    r1 = UXSPResponse(200, {}, b"", "http://x", is_uxsp=True, data="plain string not json")
    assert r1.json() == "plain string not json"

    # Non-string data (e.g. integer or bool)
    r2 = UXSPResponse(200, {}, b"", "http://x", is_uxsp=True, data=12345)
    assert r2.json() == 12345


def test_send_plain_content_types():
    def mock_send(method, url, headers, content, timeout):
        return 200, headers, content

    client = UXSPClient()
    client._raw_send = mock_send

    # Bytes
    resp1 = client._send_plain("POST", "http://x", data=b"bytes_data", json_data=None, headers={}, timeout=5)
    assert resp1.content == b"bytes_data"

    # String
    resp2 = client._send_plain("POST", "http://x", data="string_data", json_data=None, headers={}, timeout=5)
    assert resp2.content == b"string_data"

    # Dict (form urlencoded)
    resp3 = client._send_plain("POST", "http://x", data={"k": "v"}, json_data=None, headers={}, timeout=5)
    assert b"k=v" in resp3.content
    assert resp3.headers["Content-Type"] == "application/x-www-form-urlencoded"


@pytest.mark.asyncio
async def test_async_send_plain_content_types():
    async def mock_async_send(method, url, headers, content, timeout):
        return 200, headers, content

    client = AsyncUXSPClient()
    client._raw_send = mock_async_send

    # Bytes
    resp1 = await client._send_plain("POST", "http://x", data=b"bytes_data", json_data=None, headers={}, timeout=5)
    assert resp1.content == b"bytes_data"

    # String
    resp2 = await client._send_plain("POST", "http://x", data="string_data", json_data=None, headers={}, timeout=5)
    assert resp2.content == b"string_data"

    # Dict (form urlencoded)
    resp3 = await client._send_plain("POST", "http://x", data={"k": "v"}, json_data=None, headers={}, timeout=5)
    assert b"k=v" in resp3.content
    assert resp3.headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_decryption_failure_handling():
    alice = Identity.create("Alice", "CLIENT")
    bob = Identity.create("Bob", "SERVER")

    def bad_uxsp_server(method, url, headers, content, timeout):
        return 200, {"Content-Type": "application/uxsp+json", "X-UXSP-Package": "1"}, b"invalid corrupted json"

    client_strict = UXSPClient(identity=alice, allow_fallback=False)
    client_strict._raw_send = bad_uxsp_server
    client_strict.register_peer("corrupt.test:443", bob.public_card())
    client_strict.cache.set("corrupt.test:443", HostCapability("corrupt.test:443", supports_uxsp=True))

    with pytest.raises(UXSPClientError):
        client_strict.fetch("https://corrupt.test/api", json_data={"a": 1})

    client_lenient = UXSPClient(identity=alice, allow_fallback=True)
    client_lenient._raw_send = bad_uxsp_server
    client_lenient.register_peer("corrupt.test:443", bob.public_card())
    client_lenient.cache.set("corrupt.test:443", HostCapability("corrupt.test:443", supports_uxsp=True))

    resp = client_lenient.fetch("https://corrupt.test/api", json_data={"a": 1})
    assert resp.is_uxsp is False


@pytest.mark.asyncio
async def test_async_decryption_failure_handling():
    alice = await aio.create_identity("AsyncAlice")
    bob = await aio.create_identity("AsyncBob")

    async def bad_async_server(method, url, headers, content, timeout):
        return 200, {"Content-Type": "application/uxsp+json", "X-UXSP-Package": "1"}, b"corrupt bytes"

    client_strict = AsyncUXSPClient(identity=alice, allow_fallback=False)
    client_strict._raw_send = bad_async_server
    client_strict.register_peer("corrupt.async:443", bob.public_card())
    await client_strict.cache.aset("corrupt.async:443", HostCapability("corrupt.async:443", supports_uxsp=True))

    with pytest.raises(UXSPClientError):
        await client_strict.fetch("https://corrupt.async/api", json_data={"a": 1})

    client_lenient = AsyncUXSPClient(identity=alice, allow_fallback=True)
    client_lenient._raw_send = bad_async_server
    client_lenient.register_peer("corrupt.async:443", bob.public_card())
    await client_lenient.cache.aset("corrupt.async:443", HostCapability("corrupt.async:443", supports_uxsp=True))

    resp = await client_lenient.fetch("https://corrupt.async/api", json_data={"a": 1})
    assert resp.is_uxsp is False


def test_redis_cache_sync_call_on_async_client_errors():
    r = fakeredis.FakeAsyncRedis()
    cache = RedisHostCapabilityCache(r)

    with pytest.raises(RuntimeError):
        cache.get("host:443")

    with pytest.raises(RuntimeError):
        cache.set("host:443", HostCapability("host:443", supports_uxsp=True))

    with pytest.raises(RuntimeError):
        cache.clear()


def test_urllib_fallback_branches(monkeypatch):
    import urllib.error
    import urllib.request
    from io import BytesIO
    from unittest.mock import MagicMock

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.read.return_value = b"urllib_success"
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = None

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: mock_resp)

    client = UXSPClient(http_client=None)
    client._http_client = None
    status, hdrs, body = client._raw_send("GET", "http://urllib.test", {}, None, 5.0)
    assert status == 200
    assert body == b"urllib_success"

    def mock_err(req, timeout):
        err = urllib.error.HTTPError(
            "http://urllib.test", 404, "Not Found", {"Server": "Mock"}, BytesIO(b"urllib_404")
        )
        raise err

    monkeypatch.setattr(urllib.request, "urlopen", mock_err)
    status2, hdrs2, body2 = client._raw_send("GET", "http://urllib.test", {}, None, 5.0)
    assert status2 == 404
    assert body2 == b"urllib_404"


@pytest.mark.asyncio
async def test_async_urllib_fallback_branches(monkeypatch):
    import urllib.error
    import urllib.request
    from io import BytesIO
    from unittest.mock import MagicMock

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = {"Content-Type": "text/plain"}
    mock_resp.read.return_value = b"async_urllib_success"
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = None

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: mock_resp)

    client = AsyncUXSPClient(http_client=None)
    client._http_client = None
    status, hdrs, body = await client._raw_send("GET", "http://urllib.test", {}, None, 5.0)
    assert status == 200
    assert body == b"async_urllib_success"

    def mock_err(req, timeout):
        err = urllib.error.HTTPError(
            "http://urllib.test", 500, "Internal Server Error", {"Server": "Mock"}, BytesIO(b"urllib_500")
        )
        raise err

    monkeypatch.setattr(urllib.request, "urlopen", mock_err)
    status2, hdrs2, body2 = await client._raw_send("GET", "http://urllib.test", {}, None, 5.0)
    assert status2 == 500
    assert body2 == b"urllib_500"


@pytest.mark.asyncio
async def test_cache_base_class_abstract_and_awaitables():
    from uxsp.client._cache import HostCapabilityCache

    class DummyCache(HostCapabilityCache):
        def get(self, host_key):
            super().get(host_key)

        def set(self, host_key, capability):
            super().set(host_key, capability)

        def clear(self):
            super().clear()

    dummy = DummyCache()
    with pytest.raises(NotImplementedError):
        dummy.get("x")
    with pytest.raises(NotImplementedError):
        dummy.set("x", HostCapability("x", True))
    with pytest.raises(NotImplementedError):
        dummy.clear()

    # Test awaitable delegation in base class
    class AwaitableCache(HostCapabilityCache):
        def __init__(self):
            self.store = {}

        def get(self, host_key):
            async def _coro():
                return self.store.get(host_key)
            return _coro()

        def set(self, host_key, capability):
            async def _coro():
                self.store[host_key] = capability
            return _coro()

        def clear(self):
            async def _coro():
                self.store.clear()
            return _coro()

    aw = AwaitableCache()
    await aw.aset("k", HostCapability("k", True))
    res = await aw.aget("k")
    assert res.supports_uxsp is True
    await aw.aclear()
    assert await aw.aget("k") is None


@pytest.mark.asyncio
async def test_redis_cache_bytes_decode():
    class MockBytesRedis:
        def __init__(self):
            self.data = {}

        async def get(self, key):
            val = self.data.get(key)
            return val.encode("utf-8") if isinstance(val, str) else val

        async def set(self, key, val, ex=None):
            self.data[key] = val

    cache = RedisHostCapabilityCache(MockBytesRedis())
    await cache.aset("host:443", HostCapability("host:443", True, selected_version="v1.2"))
    ret = await cache.aget("host:443")
    assert ret is not None
    assert ret.selected_version == "v1.2"


def test_sync_client_close_and_fallback_on_error(monkeypatch):
    client = UXSPClient()
    assert client._owns_client is True
    client.close()
    assert client._http_client is None

    # Test fallback when _send_uxsp raises Exception
    alice = Identity.create("Alice", "CLIENT")
    bob = Identity.create("Bob", "SERVER")
    c2 = UXSPClient(identity=alice, allow_fallback=True)
    c2.register_peer("host:443", bob.public_card())
    c2.cache.set("host:443", HostCapability("host:443", supports_uxsp=True))

    def mock_raise(*args, **kwargs):
        raise Exception("simulated failure in _send_uxsp")

    monkeypatch.setattr(c2, "_send_uxsp", mock_raise)
    monkeypatch.setattr(c2, "_send_plain", lambda *args, **kwargs: UXSPResponse(200, {}, b"fallback", "http://x"))

    resp = c2.fetch("https://host/api", json_data={"a": 1})
    assert resp.content == b"fallback"


@pytest.mark.asyncio
async def test_async_client_aclose_and_fallback_on_error(monkeypatch):
    client = AsyncUXSPClient()
    assert client._owns_client is True
    await client.aclose()
    assert client._http_client is None

    # Test fallback when async _send_uxsp raises Exception
    alice = await aio.create_identity("AsyncAlice")
    bob = await aio.create_identity("AsyncBob")
    c2 = AsyncUXSPClient(identity=alice, allow_fallback=True)
    c2.register_peer("host:443", bob.public_card())
    await c2.cache.aset("host:443", HostCapability("host:443", supports_uxsp=True))

    async def mock_raise(*args, **kwargs):
        raise Exception("simulated async failure in _send_uxsp")

    async def mock_plain(*args, **kwargs):
        return UXSPResponse(200, {}, b"async_fallback", "http://x")

    monkeypatch.setattr(c2, "_send_uxsp", mock_raise)
    monkeypatch.setattr(c2, "_send_plain", mock_plain)

    resp = await c2.fetch("https://host/api", json_data={"a": 1})
    assert resp.content == b"async_fallback"


@pytest.mark.asyncio
async def test_async_lookup_keystore_with_async_keystore():
    from uxsp.storage.keystore import AsyncKeyStore

    class DummyAsyncKeyStore(AsyncKeyStore):
        def __init__(self):
            self.cards = {}
        async def put(self, card, overwrite=True):
            self.cards[card.entity_id] = card
        async def get(self, entity_id):
            return self.cards.get(entity_id)
        async def delete(self, entity_id):
            return True
        async def list_ids(self):
            return list(self.cards.keys())

    ks = DummyAsyncKeyStore()
    ident = await aio.create_identity("KeyUser")
    card = ident.public_card()
    await ks.put(card)

    client = AsyncUXSPClient(keystore=ks)
    found = await client._lookup_keystore(ident.entity_id)
    assert found is not None
    assert found.entity_id == ident.entity_id

    missing = await client._lookup_keystore("missing_id")
    assert missing is None


def test_raw_send_httpx_branch():
    def handler(request):
        return httpx.Response(200, headers={"Content-Type": "application/json"}, text="httpx_ok")

    transport = httpx.MockTransport(handler)
    http_c = httpx.Client(transport=transport)
    client = UXSPClient(http_client=http_c)

    status, hdrs, body = client._raw_send("GET", "https://mock.test/url", {}, None, 5.0)
    assert status == 200
    assert body == b"httpx_ok"
    http_c.close()


def test_sync_client_force_uxsp_send_failure(monkeypatch):
    alice = Identity.create("Alice", "CLIENT")
    bob = Identity.create("Bob", "SERVER")
    c = UXSPClient(identity=alice, force_uxsp=True)
    c.register_peer("host:443", bob.public_card())
    c.cache.set("host:443", HostCapability("host:443", supports_uxsp=True))

    def mock_raise(*args, **kwargs):
        raise ValueError("simulated network error")

    monkeypatch.setattr(c, "_send_uxsp", mock_raise)
    with pytest.raises(ProtocolFallbackError) as exc_info:
        c.fetch("https://host/api", peer_card=bob.public_card())
    assert "simulated network error" in str(exc_info.value)


@pytest.mark.asyncio
async def test_async_client_force_uxsp_send_failure(monkeypatch):
    alice = await aio.create_identity("AsyncAlice")
    bob = await aio.create_identity("AsyncBob")
    c = AsyncUXSPClient(identity=alice, force_uxsp=True)
    c.register_peer("host:443", bob.public_card())
    await c.cache.aset("host:443", HostCapability("host:443", supports_uxsp=True))

    async def mock_raise(*args, **kwargs):
        raise ValueError("simulated async network error")

    monkeypatch.setattr(c, "_send_uxsp", mock_raise)
    with pytest.raises(ProtocolFallbackError) as exc_info:
        await c.fetch("https://host/api", peer_card=bob.public_card())
    assert "simulated async network error" in str(exc_info.value)


@pytest.mark.asyncio
async def test_async_lookup_keystore_global_fallback():
    client = AsyncUXSPClient(keystore=None)
    ident = await aio.create_identity("GlobalUser")
    await aio.register_peer(ident.public_card())

    found = await client._lookup_keystore(ident.entity_id)
    assert found is not None
    assert found.entity_id == ident.entity_id


@pytest.mark.asyncio
async def test_async_lookup_keystore_exception(monkeypatch):
    client = AsyncUXSPClient(keystore=None)
    import uxsp.aio.secure as aio_sec

    async def mock_fail(entity_id):
        raise RuntimeError("boom")

    monkeypatch.setattr(aio_sec, "get_peer", mock_fail)
    found = await client._lookup_keystore("some_id")
    assert found is None


def test_sync_client_no_httpx(monkeypatch):
    import builtins
    import importlib
    import sys

    orig_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in ("httpx", "httpx2"):
            raise ImportError("no httpx")
        return orig_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    sys.modules.pop("uxsp.client._sync_client", None)
    sync_mod = importlib.import_module("uxsp.client._sync_client")
    try:
        assert sync_mod.httpx is None
        c = sync_mod.UXSPClient()
        assert c._http_client is None
        assert c._owns_client is False
    finally:
        monkeypatch.undo()
        sys.modules.pop("uxsp.client._sync_client", None)
        importlib.import_module("uxsp.client._sync_client")


def test_async_client_no_httpx(monkeypatch):
    import builtins
    import importlib
    import sys

    orig_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in ("httpx", "httpx2"):
            raise ImportError("no httpx")
        return orig_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    sys.modules.pop("uxsp.client._async_client", None)
    async_mod = importlib.import_module("uxsp.client._async_client")
    try:
        assert async_mod.httpx is None
        c = async_mod.AsyncUXSPClient()
        assert c._http_client is None
        assert c._owns_client is False
    finally:
        monkeypatch.undo()
        sys.modules.pop("uxsp.client._async_client", None)
        importlib.import_module("uxsp.client._async_client")




