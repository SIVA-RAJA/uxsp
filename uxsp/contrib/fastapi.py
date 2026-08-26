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

try:
    from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
except ImportError as err:  # pragma: no cover
    raise ImportError(
        "FastAPI and Starlette are required to use uxsp.contrib.fastapi. "
        "Install them via 'pip install uxsp[fastapi]'"
    ) from err


class UXSPFastAPIMiddleware(BaseHTTPMiddleware):
    """
    FastAPI / Starlette middleware for automatic request decryption and response encryption.

    Args:
        app: Starlette / FastAPI application instance.
        identity: Server Identity object or a callable returning an Identity.
        keystore: Optional BaseKeyStore to resolve peer PublicCards by entity_id.
        require_encryption: If True, all non-excluded routes mandate encrypted UXSP requests.
        exclude_paths: List of path prefixes to bypass UXSP processing (e.g. ["/docs", "/openapi.json"]).
    """

    def __init__(
        self,
        app: Any,
        identity: Identity | Callable[[], Identity] | None = None,
        keystore: KeyStore | None = None,
        require_encryption: bool = False,
        exclude_paths: Sequence[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.identity = identity
        self.keystore = keystore
        self.require_encryption = require_encryption
        self.exclude_paths = list(exclude_paths) if exclude_paths else ["/docs", "/openapi.json", "/redoc"]

    def _get_identity(self) -> Identity:
        if callable(self.identity):
            return self.identity()
        if isinstance(self.identity, Identity):
            return self.identity
        return _GLOBAL_CONTEXT.get_identity()

    def _resolve_peer_card(self, sender_id: str) -> PublicCard | None:
        if self.keystore is not None:
            card = self.keystore.public_card(sender_id) if hasattr(self.keystore, "public_card") else self.keystore.get(sender_id)
            if card is not None:
                return card.card if hasattr(card, "card") else card
        try:
            return _GLOBAL_CONTEXT.get_peer(sender_id)
        except Exception:
            return None

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

        header_pkg = request.headers.get("X-UXSP-Package")
        header_sender = request.headers.get("X-UXSP-Sender")

        # Read body bytes
        body_bytes = await request.body()

        is_uxsp_request = False
        package: SecurePackage | None = None

        if header_pkg or header_sender or (body_bytes and body_bytes.strip().startswith(b"{")):
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
            sender_card = self._resolve_peer_card(sender_id)

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
                request.state.uxsp_sender_card = sender_card or self._resolve_peer_card(sender_id)

                # Mutate request body so endpoint can read decrypted json
                if isinstance(parsed_payload, (dict, list)):
                    decrypted_bytes = json.dumps(parsed_payload).encode("utf-8")
                elif isinstance(parsed_payload, bytes):
                    decrypted_bytes = parsed_payload
                else:
                    decrypted_bytes = str(parsed_payload).encode("utf-8")

                async def receive_override() -> dict[str, Any]:
                    return {"type": "http.request", "body": decrypted_bytes, "more_body": False}

                request._receive = receive_override  # type: ignore[assignment]
                request.scope["receive"] = receive_override
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={"error": "UXSP Decryption Failed", "detail": str(e)},
                )
        elif self.require_encryption:
            return JSONResponse(
                status_code=400,
                content={"error": "UXSP Encryption Required", "detail": "Missing X-UXSP-Package or valid SecurePackage body."},
            )

        # Call endpoint handler
        response = await call_next(request)

        # Encrypt outgoing response if request was encrypted or require_encryption is set
        should_encrypt = request.state.uxsp_encrypted or getattr(request.state, "uxsp_force_encrypt", False)
        if should_encrypt and request.state.uxsp_sender_card is not None:
            # Consume response body
            resp_body = getattr(response, "body", None)
            if resp_body is None and hasattr(response, "body_iterator"):
                chunks = []
                async for chunk in response.body_iterator:  # type: ignore[union-attr]
                    chunks.append(chunk)
                resp_body = b"".join(chunks)

            if resp_body:
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
                return encrypted_response

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
                request.state.uxsp_force_encrypt = True

            return await func(*args, **kwargs)

        return wrapper

    return decorator


protect_route = protect
