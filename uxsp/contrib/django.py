"""
UXSP Django Framework Integration

Provides 1-line middleware and view decorators for Django applications.

Features:
    - UXSPDjangoMiddleware: Automatic Django request decryption & response encryption.
    - @protect_view / @protect: View-level decorator for targeted endpoint protection.
    - Configurable settings via Django settings.py (UXSP_SERVER_IDENTITY, UXSP_REQUIRE_ENCRYPTION).

Example:
    # in settings.py
    MIDDLEWARE = [
        ...
        'uxsp.contrib.django.UXSPDjangoMiddleware',
    ]

    # in views.py
    from django.http import JsonResponse
    from uxsp.contrib.django import protect_view

    @protect_view()
    def my_api_view(request):
        data = request.uxsp_payload
        return JsonResponse({"status": "ok", "received": data})
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable, Sequence
from typing import Any

from uxsp.core.identity import Identity, PublicCard
from uxsp.secure import (
    _GLOBAL_CONTEXT,
    Receive,
    SecurePackage,
    Send,
)
from uxsp.storage.keystore import KeyStore
from uxsp.contrib import resolve_peer_card

try:
    from django.conf import settings
    from django.http import HttpRequest, HttpResponse, JsonResponse
except ImportError as err:  # pragma: no cover
    raise ImportError(
        "Django is required to use uxsp.contrib.django. "
        "Install it via 'pip install uxsp[django]'"
    ) from err


logger = logging.getLogger(__name__)

class UXSPDjangoMiddleware:
    """
    Django middleware for automatic request decryption and response encryption.

    Reads configuration options from Django settings if available:
        - UXSP_SERVER_IDENTITY: Server Identity instance.
        - UXSP_KEYSTORE: KeyStore instance.
        - UXSP_REQUIRE_ENCRYPTION: bool (default: False).
        - UXSP_EXCLUDE_PATHS: list of path prefixes to exclude (default: ["/admin/", "/static/"]).
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self.max_response_size: int = getattr(settings, "UXSP_MAX_RESPONSE_SIZE", 16 * 1024 * 1024)
        self.identity: Identity | None = getattr(settings, "UXSP_SERVER_IDENTITY", None)
        self.keystore: KeyStore | None = getattr(settings, "UXSP_KEYSTORE", None)
        self.require_encryption: bool = getattr(settings, "UXSP_REQUIRE_ENCRYPTION", False)
        self.exclude_paths: Sequence[str] = getattr(settings, "UXSP_EXCLUDE_PATHS", ["/admin/", "/static/"])

    def _get_identity(self) -> Identity:
        if isinstance(self.identity, Identity):
            return self.identity
        return _GLOBAL_CONTEXT.get_identity()



    def __call__(self, request: HttpRequest) -> HttpResponse:
        path = request.path
        if any(path.startswith(exc) for exc in self.exclude_paths):
            return self.get_response(request)

        # Initialize UXSP request attributes
        request.uxsp_encrypted = False
        request.uxsp_payload = None
        request.uxsp_sender_id = None
        request.uxsp_sender_card = None

        header_pkg = request.META.get("HTTP_X_UXSP_PACKAGE")
        header_sender = request.META.get("HTTP_X_UXSP_SENDER")
        content_type = request.META.get("CONTENT_TYPE", "")

        body_bytes = request.body
        is_uxsp_request = False
        package: SecurePackage | None = None

        if header_pkg or header_sender or "application/uxsp+json" in content_type:
            if body_bytes and body_bytes.strip().startswith(b"{"):
                try:
                    data_dict = json.loads(body_bytes.decode("utf-8"))
                    if isinstance(data_dict, dict) and "sender_id" in data_dict and ("envelope" in data_dict or "chunks" in data_dict):
                        package = SecurePackage.from_dict(data_dict)
                        is_uxsp_request = True
                except Exception:
                    pass

        server_identity = self._get_identity()

        if is_uxsp_request and package is not None:
            sender_id = package.sender_id
            sender_card = resolve_peer_card(self.keystore, sender_id)

            try:
                received_item = Receive(
                    sender=sender_card or sender_id,
                    package=package,
                    receiver=server_identity,
                )

                if isinstance(received_item, bytes):
                    try:
                        parsed_payload = json.loads(received_item.decode("utf-8"))
                    except Exception:
                        parsed_payload = received_item
                else:
                    parsed_payload = received_item

                request.uxsp_encrypted = True
                request.uxsp_payload = parsed_payload
                request.uxsp_sender_id = sender_id
                request.uxsp_sender_card = sender_card or resolve_peer_card(self.keystore, sender_id)

                if isinstance(parsed_payload, (dict, list)):
                    request._body = json.dumps(parsed_payload).encode("utf-8")
                elif isinstance(parsed_payload, bytes):
                    request._body = parsed_payload
                else:
                    request._body = str(parsed_payload).encode("utf-8")
            except Exception as e:
                logger.error("UXSP decryption failed: %s", e, exc_info=True)
                return JsonResponse(
                    {"error": "UXSP Decryption Failed"},
                    status=400,
                )
        elif self.require_encryption:
            return JsonResponse(
                {"error": "UXSP Encryption Required", "detail": "Missing valid SecurePackage body."},
                status=400,
            )

        response = self.get_response(request)

        should_encrypt = getattr(request, "uxsp_encrypted", False) or getattr(request, "uxsp_force_encrypt", False)
        sender_card = getattr(request, "uxsp_sender_card", None)

        if should_encrypt and sender_card is not None:
            from django.http import StreamingHttpResponse
            if getattr(response, "streaming", False):
                def encrypt_stream():
                    for chunk in response.streaming_content:
                        if not chunk: continue
                        out_pkg = Send(
                            receiver=sender_card,
                            item=chunk,
                            sender=server_identity,
                            data_type="binary"
                        )
                        yield out_pkg.to_json().encode("utf-8") + b"\n"
                
                encrypted_response = StreamingHttpResponse(
                    encrypt_stream(),
                    status=response.status_code,
                    content_type="application/x-ndjson"
                )
                for k, v in response.items():
                    if k.lower() not in ("content-length", "content-type"):
                        encrypted_response[k] = v
                encrypted_response["X-UXSP-Package"] = "1"
                encrypted_response["X-UXSP-Sender"] = server_identity.entity_id
                encrypted_response["X-UXSP-Recipient"] = getattr(request, "uxsp_sender_id", "") or ""
                encrypted_response["X-UXSP-Version"] = "1"
                return encrypted_response

            content = response.content
            if len(content) > self.max_response_size:
                raise ValueError(f"Response exceeds max_response_size of {self.max_response_size} bytes. Use StreamingHttpResponse.")
            try:
                resp_obj = json.loads(content.decode("utf-8"))
            except Exception:
                resp_obj = content.decode("utf-8", errors="replace")

            out_pkg = Send(
                receiver=sender_card,
                item=resp_obj,
                sender=server_identity,
            )

            encrypted_response = JsonResponse(out_pkg.to_dict(), status=response.status_code)
            encrypted_response["X-UXSP-Package"] = "1"
            encrypted_response["X-UXSP-Sender"] = server_identity.entity_id
            encrypted_response["X-UXSP-Recipient"] = getattr(request, "uxsp_sender_id", "") or ""
            encrypted_response["X-UXSP-Version"] = "1"
            return encrypted_response

        return response


def protect_view(
    server_identity: Identity | Callable[[], Identity] | None = None,
) -> Callable[[Callable[..., HttpResponse]], Callable[..., HttpResponse]]:
    """
    View decorator for Django view functions requiring UXSP protection.

    Usage:
        @protect_view()
        def my_view(request):
            data = request.uxsp_payload
            return JsonResponse({"received": data})
    """

    def decorator(view_func: Callable[..., HttpResponse]) -> Callable[..., HttpResponse]:
        @functools.wraps(view_func)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            if not hasattr(request, "uxsp_encrypted"):
                raise RuntimeError("@protect_view decorator requires UXSPDjangoMiddleware to be installed.")
            request.uxsp_force_encrypt = True
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


protect = protect_view
