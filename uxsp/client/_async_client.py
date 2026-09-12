"""
uxsp.client._async_client — Asynchronous Smart Client with Automatic Protocol Switching
"""
from __future__ import annotations

import asyncio
import inspect
import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

from uxsp.client._cache import (
    HostCapability,
    HostCapabilityCache,
    get_default_capability_cache,
    normalize_host_key,
)
from uxsp.client._errors import ProtocolFallbackError, UXSPClientError, UXSPPeerResolutionError
from uxsp.client._response import UXSPResponse
from uxsp.core.identity import Identity, PublicCard
from uxsp.secure._package import SecurePackage
from uxsp.transport.http import (
    DEFAULT_UXSP_SUPPORT,
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


class AsyncUXSPClient:
    """
    Asynchronous UXSP Smart Client with automatic protocol discovery,
    caching, non-blocking crypto, and fallback to plain HTTPS.
    """

    def __init__(
        self,
        *,
        identity: Identity | None = None,
        keystore: Any = None,
        cache: HostCapabilityCache | None = None,
        timeout: float = 30.0,
        allow_fallback: bool = True,
        force_uxsp: bool = False,
        peer_registry: dict[str, PublicCard] | None = None,
        http_client: Any = None,
    ) -> None:
        self.identity = identity
        self.keystore = keystore
        self.cache = cache or get_default_capability_cache()
        self.timeout = timeout
        self.allow_fallback = allow_fallback
        self.force_uxsp = force_uxsp
        self.peer_registry: dict[str, PublicCard] = dict(peer_registry or {})

        if http_client is not None:
            self._http_client = http_client
            self._owns_client = False
        elif httpx is not None:
            self._http_client = httpx.AsyncClient(timeout=timeout, follow_redirects=True)
            self._owns_client = True
        else:
            self._http_client = None
            self._owns_client = False

    async def __aenter__(self) -> AsyncUXSPClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close underlying async HTTP client session."""
        if self._owns_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    def register_peer(self, host_or_id: str, card: PublicCard) -> None:
        """Register a PublicCard for a host key or entity ID."""
        self.peer_registry[host_or_id.lower()] = card

    async def _get_active_identity(self) -> Identity:
        if self.identity is not None:
            return self.identity
        from uxsp.aio.secure import get_identity

        ident = await get_identity()
        if ident is not None:
            return ident
        raise UXSPClientError(
            "No client identity configured. Pass `identity` to AsyncUXSPClient or configure context."
        )

    async def _resolve_peer_card(
        self,
        host_key: str,
        peer_id: str | None = None,
        peer_card: PublicCard | Identity | None = None,
        cap: HostCapability | None = None,
    ) -> PublicCard | None:
        if isinstance(peer_card, PublicCard):
            return peer_card
        if isinstance(peer_card, Identity):
            return peer_card.public_card()

        # Check explicit peer_id
        if peer_id:
            if peer_id in self.peer_registry:
                return self.peer_registry[peer_id]
            card = await self._lookup_keystore(peer_id)
            if card is not None:
                return card

        # Check host_key in peer_registry
        if host_key in self.peer_registry:
            return self.peer_registry[host_key]

        # Check cached cap.peer_id
        if cap and cap.peer_id:
            if cap.peer_id in self.peer_registry:
                return self.peer_registry[cap.peer_id]
            card = await self._lookup_keystore(cap.peer_id)
            if card is not None:
                return card

        return None

    async def _lookup_keystore(self, entity_id: str) -> PublicCard | None:
        ks = self.keystore
        if ks is not None:
            res = ks.get(entity_id)
            if inspect.isawaitable(res):
                res = await res
            if res is not None:
                res_card = res.card if hasattr(res, "card") else res
                if isinstance(res_card, PublicCard):
                    return res_card
            return None

        try:
            from uxsp.aio.secure import get_peer

            return await get_peer(entity_id)
        except Exception:
            return None

    async def _raw_send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        content: bytes | None,
        timeout: float,
    ) -> tuple[int, dict[str, str], bytes]:
        if self._http_client is not None:
            resp = await self._http_client.request(
                method=method,
                url=url,
                headers=headers,
                content=content,
                timeout=timeout,
            )
            resp_headers = dict(resp.headers.items())
            return resp.status_code, resp_headers, resp.content

        # Fallback to urllib.request in worker thread
        def _sync_urllib() -> tuple[int, dict[str, str], bytes]:
            req = urllib.request.Request(url, data=content, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    status = response.status
                    r_headers = dict(response.headers.items())
                    body = response.read()
                    return status, r_headers, body
            except urllib.error.HTTPError as e:
                err_headers = dict(e.headers.items()) if e.headers else {}
                err_body = e.read() if hasattr(e, "read") else b""
                return e.code, err_headers, err_body

        return await asyncio.to_thread(_sync_urllib)

    async def fetch(
        self,
        url: str,
        *,
        data: Any = None,
        json: Any = None,
        json_data: Any = None,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        peer_id: str | None = None,
        peer_card: PublicCard | Identity | None = None,
        allow_fallback: bool | None = None,
        force_uxsp: bool | None = None,
        timeout: float | None = None,
    ) -> UXSPResponse:
        """
        Asynchronously fetch URL with automatic protocol discovery, caching, and fallback.
        """
        actual_json = json if json is not None else json_data
        allow_fb = self.allow_fallback if allow_fallback is None else allow_fallback
        force_u = self.force_uxsp if force_uxsp is None else force_uxsp
        t_out = self.timeout if timeout is None else timeout
        hdrs = dict(headers or {})

        host_key = normalize_host_key(url)
        cap = await self.cache.aget(host_key)

        if force_u and cap is not None and not cap.supports_uxsp:
            raise ProtocolFallbackError(
                f"Host '{host_key}' is known to not support UXSP and force_uxsp=True."
            )

        resolved_card = await self._resolve_peer_card(host_key, peer_id, peer_card, cap)

        # ── Case 1: Host is known HTTPS-only ──────────────────────────────────
        if cap is not None and not cap.supports_uxsp:
            return await self._send_plain(
                method, url, data=data, json_data=actual_json, headers=hdrs, timeout=t_out
            )

        # ── Case 2: Host supports UXSP and recipient card is resolved ────────
        should_send_uxsp = (cap is not None and cap.supports_uxsp) or force_u
        if should_send_uxsp:
            if resolved_card is None:
                raise UXSPPeerResolutionError(
                    f"Host '{host_key}' requires UXSP, but no PublicCard could be resolved."
                )
            try:
                return await self._send_uxsp(
                    method,
                    url,
                    data=data,
                    json_data=actual_json,
                    headers=hdrs,
                    recipient_card=resolved_card,
                    timeout=t_out,
                    host_key=host_key,
                )
            except Exception as exc:
                if not allow_fb:
                    raise
                if force_u:
                    raise ProtocolFallbackError(
                        f"UXSP request to '{host_key}' failed and force_uxsp is enabled: {exc}"
                    ) from exc
                # Fallback to plain HTTPS
                resp = await self._send_plain(
                    method, url, data=data, json_data=actual_json, headers=hdrs, timeout=t_out
                )
                return resp

        # ── Case 3: Unknown host capability / probe request ──────────────────
        probe_headers = dict(hdrs)
        probe_headers[HEADER_SEC_UXSP_SUPPORT] = DEFAULT_UXSP_SUPPORT

        resp = await self._send_plain(
            method,
            url,
            data=data,
            json_data=actual_json,
            headers=probe_headers,
            timeout=t_out,
        )

        norm_resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        selected = norm_resp_headers.get(HEADER_SEC_UXSP_SELECTED.lower())
        server_sender = (
            norm_resp_headers.get("x-uxsp-sender") or norm_resp_headers.get("x-uxsp-sender")
        )

        if selected:
            new_cap = HostCapability(
                host=host_key,
                supports_uxsp=True,
                selected_version=selected,
                peer_id=server_sender,
            )
            await self.cache.aset(host_key, new_cap)
        else:
            new_cap = HostCapability(
                host=host_key,
                supports_uxsp=False,
            )
            await self.cache.aset(host_key, new_cap)

        return resp

    async def _send_plain(
        self,
        method: str,
        url: str,
        *,
        data: Any,
        json_data: Any,
        headers: dict[str, str],
        timeout: float,
    ) -> UXSPResponse:
        content: bytes | None = None
        hdrs = dict(headers)

        if json_data is not None:
            content = json.dumps(json_data).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        elif isinstance(data, (bytes, bytearray)):
            content = bytes(data)
        elif isinstance(data, str):
            content = data.encode("utf-8")
        elif isinstance(data, dict):
            content = urlencode(data).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")

        status, resp_headers, body = await self._raw_send(method, url, hdrs, content, timeout)
        return UXSPResponse(
            status_code=status,
            headers=resp_headers,
            content=body,
            url=url,
            is_uxsp=False,
        )

    async def _send_uxsp(
        self,
        method: str,
        url: str,
        *,
        data: Any,
        json_data: Any,
        headers: dict[str, str],
        recipient_card: PublicCard,
        timeout: float,
        host_key: str,
    ) -> UXSPResponse:
        sender_ident = await self._get_active_identity()
        payload_item = json_data if json_data is not None else (data if data is not None else "")
        from uxsp.aio.secure import Receive, Send

        # Asynchronously encrypt payload into SecurePackage
        pkg: SecurePackage = await Send(
            receiver=recipient_card,
            item=payload_item,
            sender=sender_ident,
        )

        content = pkg.to_json().encode("utf-8")
        hdrs = dict(headers)
        hdrs["Content-Type"] = "application/uxsp+json"
        hdrs["X-UXSP-Package"] = "1"
        hdrs["X-UXSP-Sender"] = sender_ident.entity_id
        hdrs["X-UXSP-Recipient"] = recipient_card.entity_id
        hdrs["X-UXSP-Version"] = "1"
        hdrs[HEADER_SEC_UXSP_SUPPORT] = DEFAULT_UXSP_SUPPORT

        req_method = "POST" if method.upper() == "GET" and content else method.upper()
        status, resp_headers, body = await self._raw_send(req_method, url, hdrs, content, timeout)

        norm_resp_headers = {k.lower(): v for k, v in resp_headers.items()}
        selected = norm_resp_headers.get(HEADER_SEC_UXSP_SELECTED.lower())

        await self.cache.aset(
            host_key,
            HostCapability(
                host=host_key,
                supports_uxsp=True,
                selected_version=selected or "v1.2",
                peer_id=recipient_card.entity_id,
            ),
        )

        is_uxsp_response = (
            "application/uxsp+json" in norm_resp_headers.get("content-type", "")
            or bool(norm_resp_headers.get("x-uxsp-package"))
        )

        if is_uxsp_response:
            try:
                raw_text = body.decode("utf-8").strip()
                pkg_resp = SecurePackage.from_json(raw_text)
                decrypted_data = await Receive(package=pkg_resp, sender=recipient_card, receiver=sender_ident)
                return UXSPResponse(
                    status_code=status,
                    headers=resp_headers,
                    content=body,
                    url=url,
                    is_uxsp=True,
                    package=pkg_resp,
                    data=decrypted_data,
                )
            except Exception as e:
                if not self.allow_fallback:
                    raise UXSPClientError(f"Failed to decrypt UXSP response: {e}") from e

        return UXSPResponse(
            status_code=status,
            headers=resp_headers,
            content=body,
            url=url,
            is_uxsp=False,
            data=None,
        )

    async def request(self, method: str, url: str, **kwargs: Any) -> UXSPResponse:
        return await self.fetch(url, method=method, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> UXSPResponse:
        return await self.fetch(url, method="GET", **kwargs)

    async def post(self, url: str, **kwargs: Any) -> UXSPResponse:
        return await self.fetch(url, method="POST", **kwargs)

    async def put(self, url: str, **kwargs: Any) -> UXSPResponse:
        return await self.fetch(url, method="PUT", **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> UXSPResponse:
        return await self.fetch(url, method="DELETE", **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> UXSPResponse:
        return await self.fetch(url, method="PATCH", **kwargs)


_DEFAULT_ASYNC_CLIENT = AsyncUXSPClient()


async def fetch(url: str, **kwargs: Any) -> UXSPResponse:
    """Convenience function: async smart fetch with default async client."""
    return await _DEFAULT_ASYNC_CLIENT.fetch(url, **kwargs)


async def request(method: str, url: str, **kwargs: Any) -> UXSPResponse:
    """Convenience function: async smart request with default async client."""
    return await _DEFAULT_ASYNC_CLIENT.request(method, url, **kwargs)


async def get(url: str, **kwargs: Any) -> UXSPResponse:
    return await _DEFAULT_ASYNC_CLIENT.get(url, **kwargs)


async def post(url: str, **kwargs: Any) -> UXSPResponse:
    return await _DEFAULT_ASYNC_CLIENT.post(url, **kwargs)


async def put(url: str, **kwargs: Any) -> UXSPResponse:
    return await _DEFAULT_ASYNC_CLIENT.put(url, **kwargs)


async def delete(url: str, **kwargs: Any) -> UXSPResponse:
    return await _DEFAULT_ASYNC_CLIENT.delete(url, **kwargs)


async def patch(url: str, **kwargs: Any) -> UXSPResponse:
    return await _DEFAULT_ASYNC_CLIENT.patch(url, **kwargs)
