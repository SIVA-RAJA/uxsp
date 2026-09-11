"""
uxsp.client._sync_client — Synchronous Smart Client with Automatic Protocol Switching
"""
from __future__ import annotations

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
from uxsp.secure._context import get_context
from uxsp.secure._dispatch import Receive, Send
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


class UXSPClient:
    """
    Synchronous UXSP Smart Client with automatic protocol discovery,
    caching, and fallback to plain HTTPS for non-UXSP endpoints.
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
            self._http_client = httpx.Client(timeout=timeout, follow_redirects=True)
            self._owns_client = True
        else:
            self._http_client = None
            self._owns_client = False

    def __enter__(self) -> UXSPClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close underlying HTTP client session."""
        if self._owns_client and self._http_client is not None:
            self._http_client.close()
            self._http_client = None

    def register_peer(self, host_or_id: str, card: PublicCard) -> None:
        """Register a PublicCard for a host key or entity ID."""
        self.peer_registry[host_or_id.lower()] = card

    def _get_active_identity(self) -> Identity:
        if self.identity is not None:
            return self.identity
        ctx = get_context()
        ident = ctx.get_identity()
        if ident is not None:
            return ident
        raise UXSPClientError(
            "No client identity configured. Pass `identity` to UXSPClient or configure global context."
        )

    def _resolve_peer_card(
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
            ks = self.keystore or getattr(get_context(), "_keystore", None)
            if ks is not None:
                card = ks.get(peer_id)
                if card is not None:
                    return card.card if hasattr(card, "card") else card

        # Check host_key in peer_registry
        if host_key in self.peer_registry:
            return self.peer_registry[host_key]

        # Check cached cap.peer_id
        if cap and cap.peer_id:
            if cap.peer_id in self.peer_registry:
                return self.peer_registry[cap.peer_id]
            ks = self.keystore or getattr(get_context(), "_keystore", None)
            if ks is not None:
                card = ks.get(cap.peer_id)
                if card is not None:
                    return card.card if hasattr(card, "card") else card

        return None

    def _raw_send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        content: bytes | None,
        timeout: float,
    ) -> tuple[int, dict[str, str], bytes]:
        """Execute low-level HTTP request using httpx or urllib."""
        if self._http_client is not None:
            resp = self._http_client.request(
                method=method,
                url=url,
                headers=headers,
                content=content,
                timeout=timeout,
            )
            resp_headers = dict(resp.headers.items())
            return resp.status_code, resp_headers, resp.content

        # Fallback to urllib.request
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

    def fetch(
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
        Smart fetch with automatic protocol probing, caching, and fallback.
        """
        actual_json = json if json is not None else json_data
        allow_fb = self.allow_fallback if allow_fallback is None else allow_fallback
        force_u = self.force_uxsp if force_uxsp is None else force_uxsp
        t_out = self.timeout if timeout is None else timeout
        hdrs = dict(headers or {})

        host_key = normalize_host_key(url)
        cap = self.cache.get(host_key)

        if force_u and cap is not None and not cap.supports_uxsp:
            raise ProtocolFallbackError(
                f"Host '{host_key}' is known to not support UXSP and force_uxsp=True."
            )

        resolved_card = self._resolve_peer_card(host_key, peer_id, peer_card, cap)

        # ── Case 1: Host is known HTTPS-only ──────────────────────────────────
        if cap is not None and not cap.supports_uxsp:
            return self._send_plain(
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
                return self._send_uxsp(
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
                # Automatic fallback to plain HTTPS
                resp = self._send_plain(
                    method, url, data=data, json_data=actual_json, headers=hdrs, timeout=t_out
                )
                return resp

        # ── Case 3: Unknown host capability / probe request ──────────────────
        # Send initial request with Sec-UXSP-Support probe header
        probe_headers = dict(hdrs)
        probe_headers[HEADER_SEC_UXSP_SUPPORT] = DEFAULT_UXSP_SUPPORT

        resp = self._send_plain(
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
            # Server responded that it supports UXSP!
            new_cap = HostCapability(
                host=host_key,
                supports_uxsp=True,
                selected_version=selected,
                peer_id=server_sender,
            )
            self.cache.set(host_key, new_cap)
        else:
            # Server is standard HTTPS without UXSP support
            new_cap = HostCapability(
                host=host_key,
                supports_uxsp=False,
            )
            self.cache.set(host_key, new_cap)

        return resp

    def _send_plain(
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

        status, resp_headers, body = self._raw_send(method, url, hdrs, content, timeout)
        return UXSPResponse(
            status_code=status,
            headers=resp_headers,
            content=body,
            url=url,
            is_uxsp=False,
        )

    def _send_uxsp(
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
        sender_ident = self._get_active_identity()
        payload_item = json_data if json_data is not None else (data if data is not None else "")

        # Encrypt payload into SecurePackage
        pkg: SecurePackage = Send(
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

        # Adjust HTTP method for body if GET
        req_method = "POST" if method.upper() == "GET" and content else method.upper()
        status, resp_headers, body = self._raw_send(req_method, url, hdrs, content, timeout)

        norm_resp_headers = {k.lower(): v for k, v in resp_headers.items()}
        selected = norm_resp_headers.get(HEADER_SEC_UXSP_SELECTED.lower())

        # Update cache capability
        self.cache.set(
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
                decrypted_data = Receive(pkg_resp, sender=recipient_card, receiver=sender_ident)
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

    def request(self, method: str, url: str, **kwargs: Any) -> UXSPResponse:
        return self.fetch(url, method=method, **kwargs)

    def get(self, url: str, **kwargs: Any) -> UXSPResponse:
        return self.fetch(url, method="GET", **kwargs)

    def post(self, url: str, **kwargs: Any) -> UXSPResponse:
        return self.fetch(url, method="POST", **kwargs)

    def put(self, url: str, **kwargs: Any) -> UXSPResponse:
        return self.fetch(url, method="PUT", **kwargs)

    def delete(self, url: str, **kwargs: Any) -> UXSPResponse:
        return self.fetch(url, method="DELETE", **kwargs)

    def patch(self, url: str, **kwargs: Any) -> UXSPResponse:
        return self.fetch(url, method="PATCH", **kwargs)


_DEFAULT_CLIENT = UXSPClient()


def fetch(url: str, **kwargs: Any) -> UXSPResponse:
    """Convenience function: smart fetch with default client."""
    return _DEFAULT_CLIENT.fetch(url, **kwargs)


def request(method: str, url: str, **kwargs: Any) -> UXSPResponse:
    """Convenience function: smart request with default client."""
    return _DEFAULT_CLIENT.request(method, url, **kwargs)


def get(url: str, **kwargs: Any) -> UXSPResponse:
    return _DEFAULT_CLIENT.get(url, **kwargs)


def post(url: str, **kwargs: Any) -> UXSPResponse:
    return _DEFAULT_CLIENT.post(url, **kwargs)


def put(url: str, **kwargs: Any) -> UXSPResponse:
    return _DEFAULT_CLIENT.put(url, **kwargs)


def delete(url: str, **kwargs: Any) -> UXSPResponse:
    return _DEFAULT_CLIENT.delete(url, **kwargs)


def patch(url: str, **kwargs: Any) -> UXSPResponse:
    return _DEFAULT_CLIENT.patch(url, **kwargs)
