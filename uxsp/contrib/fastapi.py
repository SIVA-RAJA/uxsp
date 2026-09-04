"""
UXSP FastAPI & Starlette Integration

Provides 1-line middleware and decorators for FastAPI applications.

Features:
    - UXSPFastAPIMiddleware / UXSPMiddleware: Automatic request decryption & response encryption.
    - @protect / @protect_route: Route-level endpoint decorator for targeted protection.
    - Automatic header management (X-UXSP-Package, X-UXSP-Sender, X-UXSP-Recipient).

Example:
    from fastapi import FastAPI, Request
    from uxsp.contrib.fastapi import UXSPMiddleware, protect
    from uxsp import Identity

    server_id = Identity.create("API Server", role="SERVER")
    app = FastAPI()
    app.add_middleware(UXSPMiddleware, identity=server_id)

    @app.post("/secure-endpoint")

    async def secure_endpoint(request: Request):
        payload = request.state.uxsp_payload
        return {"status": "success", "received": payload}
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable, Sequence
from typing import Any

from uxsp.contrib import resolve_peer_card
from uxsp.core.identity import Identity, PublicCard
from uxsp.secure import (
    Receive,
    SecurePackage,
    Send,
)
from uxsp.secure._context import _GLOBAL_CONTEXT
from uxsp.storage.keystore import KeyStore

try:
    from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
except ImportError as err:  # pragma: no cover
    raise ImportError(
        "FastAPI and Starlette are required to use uxsp.contrib.fastapi. "
        "Install them via 'pip install uxsp[fastapi]'"
    ) from err


from uxsp.transport.http import (
    DEFAULT_UXSP_SELECTED,
    HEADER_SEC_UXSP_SELECTED,
    HEADER_SEC_UXSP_SUPPORT,
    negotiate_protocol,
)

logger = logging.getLogger(__name__)

class UXSPFastAPIMiddleware(BaseHTTPMiddleware):
    """
    FastAPI / Starlette middleware for automatic request decryption, response encryption,
    and Seamless Protocol Negotiation (Automatic Fallback & Upgrade).

    Args:
        app: Starlette / FastAPI application instance.
        identity: Server Identity object or a callable returning an Identity.
        keystore: Optional BaseKeyStore to resolve peer PublicCards by entity_id.
        fallback: If True (default), allows plain HTTPS/JSON requests to pass through unencrypted.
        mode: Operation mode ("hybrid" default, or "strict" to mandate encryption).
        require_encryption: Legacy setting. If True, sets mode="strict" (fallback=False).
        exclude_paths: List of path prefixes to bypass UXSP processing (e.g. ["/docs", "/openapi.json"]).
    """

    def __init__(
        self,
        app: Any,
        identity: Identity | Callable[[], Identity] | None = None,
        keystore: KeyStore | None = None,
        fallback: bool = True,
        mode: str = "hybrid",
        require_encryption: bool | None = None,
        exclude_paths: Sequence[str] | None = None,
        max_response_size: int = 16 * 1024 * 1024,
    ) -> None:
        super().__init__(app)
        self.identity = identity
        self.keystore = keystore

        if require_encryption is not None:
            self.fallback = not require_encryption
            self.mode = "strict" if require_encryption else mode
        else:
            self.fallback = fallback
            self.mode = mode.lower() if mode else "hybrid"

        self.require_encryption = not self.fallback or self.mode == "strict"
        self.exclude_paths = list(exclude_paths) if exclude_paths else ["/docs", "/openapi.json", "/redoc"]
        self.max_response_size = max_response_size

    def _get_identity(self) -> Identity:
        if callable(self.identity):
            return self.identity()
        if isinstance(self.identity, Identity):
            return self.identity
        return _GLOBAL_CONTEXT.get_identity()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 1. Skip excluded paths
        path = request.url.path
        if any(path.startswith(exc) for exc in self.exclude_paths):
            return await call_next(request)

        # Initialize state flags
        request.state.uxsp_encrypted = False
        request.state.uxsp_payload = None
        request.state.uxsp_sender_id = None
        request.state.uxsp_sender_card = None
        request.state.uxsp_negotiated = None

        sec_support = request.headers.get(HEADER_SEC_UXSP_SUPPORT) or request.headers.get("sec-uxsp-support")
        if sec_support:
            request.state.uxsp_negotiated = negotiate_protocol(sec_support) or DEFAULT_UXSP_SELECTED

        header_pkg = request.headers.get("X-UXSP-Package")
        header_sender = request.headers.get("X-UXSP-Sender")
        content_type = request.headers.get("Content-Type", "")

        # Read body bytes
        body_bytes = await request.body()

        is_uxsp_request = False
        package: SecurePackage | None = None

        if (header_pkg or header_sender or "application/uxsp+json" in content_type) and (body_bytes and body_bytes.strip().startswith(b"{")):
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
                # Decrypt incoming package
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

                request.state.uxsp_encrypted = True
                request.state.uxsp_payload = parsed_payload
                request.state.uxsp_sender_id = sender_id
                request.state.uxsp_sender_card = sender_card or resolve_peer_card(self.keystore, sender_id)

                # Mutate request body so endpoint can read decrypted json
                if isinstance(parsed_payload, (dict, list)):
                    decrypted_bytes = json.dumps(parsed_payload).encode("utf-8")
                elif isinstance(parsed_payload, bytes):
                    decrypted_bytes = parsed_payload
                else:
                    decrypted_bytes = str(parsed_payload).encode("utf-8")

                original_receive = request.scope.get("receive") or getattr(request, "_receive", None)
                _receive_state = {"consumed": False}
                request.state.is_done = False

                async def receive_override() -> dict[str, Any]:
                    if getattr(request.state, "is_done", False):
                        if original_receive is not None:
                            return await original_receive()  # type: ignore[no-any-return]
                        return {"type": "http.disconnect"}

                    if not _receive_state["consumed"]:
                        _receive_state["consumed"] = True
                        return {"type": "http.request", "body": decrypted_bytes, "more_body": False}
                    if original_receive is not None:
                        return await original_receive()  # type: ignore[no-any-return]
                    return {"type": "http.disconnect"}

                request._receive = receive_override  # noqa: B010
                request.scope["receive"] = receive_override
            except Exception as e:
                logger.error("UXSP decryption failed: %s", e, exc_info=True)
                return JSONResponse(
                    status_code=400,
                    content={"error": "UXSP Decryption Failed"},
                )
        elif self.require_encryption:
            return JSONResponse(
                status_code=400,
                content={"error": "UXSP Encryption Required", "detail": "Missing X-UXSP-Package or valid SecurePackage body."},
            )

        # Call endpoint handler
        response = await call_next(request)
        request.state.is_done = True

        # Attach Sec-UXSP-Selected if protocol was negotiated or default
        selected = request.state.uxsp_negotiated or (DEFAULT_UXSP_SELECTED if sec_support else None)

        # Encrypt outgoing response if request was encrypted or force encrypt set
        should_encrypt = request.state.uxsp_encrypted or getattr(request.state, "uxsp_force_encrypt", False)
        if should_encrypt and request.state.uxsp_sender_card is not None:
            resp_body = getattr(response, "body", None)
            body_iter = getattr(response, "body_iterator", None)

            if resp_body is None and body_iter is not None:
                from starlette.responses import StreamingResponse

                async def encrypt_stream():  # type: ignore[no-untyped-def]
                    async for chunk in body_iter:
                        if not chunk:
                            continue  # pragma: no cover
                        out_pkg = Send(
                            receiver=request.state.uxsp_sender_card,
                            item=chunk,
                            sender=server_identity,
                            data_type="binary"
                        )
                        yield out_pkg.to_json() + "\n"

                encrypted_response = StreamingResponse(
                    encrypt_stream(),  # type: ignore[no-untyped-call]
                    status_code=response.status_code,
                    media_type="application/x-ndjson"
                )
                for k, v in response.headers.items():
                    if k.lower() not in ("content-length", "content-type"):
                        encrypted_response.headers[k] = v
                encrypted_response.headers["X-UXSP-Package"] = "1"
                encrypted_response.headers["X-UXSP-Sender"] = server_identity.entity_id
                encrypted_response.headers["X-UXSP-Recipient"] = request.state.uxsp_sender_id or ""
                encrypted_response.headers["X-UXSP-Version"] = "1"
                if selected:
                    encrypted_response.headers[HEADER_SEC_UXSP_SELECTED] = selected
                return encrypted_response

            if resp_body:
                if len(resp_body) > self.max_response_size:
                    raise ValueError(f"Response exceeds max_response_size of {self.max_response_size} bytes. Use StreamingResponse instead.")

                try:
                    resp_obj = json.loads(resp_body.decode("utf-8"))
                except Exception:
                    resp_obj = resp_body.decode("utf-8", errors="replace")

                out_pkg = Send(
                    receiver=request.state.uxsp_sender_card,
                    item=resp_obj,
                    sender=server_identity,
                )

                encrypted_response = JSONResponse(
                    content=out_pkg.to_dict(),
                    status_code=response.status_code,
                    headers=dict(response.headers),
                )
                encrypted_response.headers["X-UXSP-Package"] = "1"
                encrypted_response.headers["X-UXSP-Sender"] = server_identity.entity_id
                encrypted_response.headers["X-UXSP-Recipient"] = request.state.uxsp_sender_id or ""
                encrypted_response.headers["X-UXSP-Version"] = "1"
                if selected:
                    encrypted_response.headers[HEADER_SEC_UXSP_SELECTED] = selected
                return encrypted_response

        # For unencrypted fallback response, attach Sec-UXSP-Selected header if client sent Sec-UXSP-Support
        if selected:
            response.headers[HEADER_SEC_UXSP_SELECTED] = selected

        return response



UXSPMiddleware = UXSPFastAPIMiddleware


def protect(
    server_identity: Identity | Callable[[], Identity] | None = None,
    peer_card: PublicCard | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Route decorator for FastAPI / Starlette endpoints requiring UXSP protection.

    Usage:
        @app.post("/secure-data")
        @protect(server_identity=server_id)
        async def secure_endpoint(request: Request):
            data = request.state.uxsp_payload
            return {"received": data}
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Locate Request object in args or kwargs
            request: Request | None = kwargs.get("request")
            if request is None:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is not None:
                if not hasattr(request.state, "uxsp_encrypted"):
                    raise RuntimeError("@protect decorator requires UXSPMiddleware to be installed.")
                request.state.uxsp_force_encrypt = True

            return await func(*args, **kwargs)

        return wrapper

    return decorator


protect_route = protect
