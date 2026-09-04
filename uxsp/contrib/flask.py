"""
UXSP Flask Framework Integration

Provides 1-line middleware extensions and route decorators for Flask applications.

Features:
    - UXSPFlaskMiddleware: Automatic Flask request decryption & response encryption.
    - @protect_route / @protect: Route-level decorator for targeted endpoint protection.
    - Uses Flask application context (flask.g.uxsp_payload, flask.g.uxsp_sender_id).

Example:
    from flask import Flask, jsonify, g
    from uxsp.contrib.flask import UXSPFlaskMiddleware, protect_route
    from uxsp import Identity

    server_id = Identity.create("API Server", role="SERVER")
    app = Flask(__name__)
    uxsp_ext = UXSPFlaskMiddleware(app, identity=server_id)

    @app.route("/secure-endpoint", methods=["POST"])

    def secure_endpoint():
        data = g.uxsp_payload
        return jsonify({"status": "success", "received": data})
"""

from __future__ import annotations

import functools
import json
import logging
from collections.abc import Callable, Sequence
from typing import Any

from uxsp.contrib import resolve_peer_card
from uxsp.core.identity import Identity
from uxsp.secure import (
    Receive,
    SecurePackage,
    Send,
)
from uxsp.secure._context import _GLOBAL_CONTEXT
from uxsp.storage.keystore import KeyStore

try:
    from flask import Flask, Response, g, jsonify, request
except ImportError as err:  # pragma: no cover
    raise ImportError(
        "Flask is required to use uxsp.contrib.flask. "
        "Install it via 'pip install uxsp[flask]'"
    ) from err


from uxsp.transport.http import (
    DEFAULT_UXSP_SELECTED,
    HEADER_SEC_UXSP_SELECTED,
    HEADER_SEC_UXSP_SUPPORT,
    negotiate_protocol,
)

logger = logging.getLogger(__name__)

class UXSPFlaskMiddleware:
    """
    Flask extension for automatic request decryption, response encryption,
    and Seamless Protocol Negotiation (Automatic Fallback & Upgrade).

    Args:
        app: Flask application instance.
        identity: Server Identity instance or callable returning an Identity.
        keystore: Optional BaseKeyStore instance.
        fallback: If True (default), allows plain HTTPS/JSON requests to pass through unencrypted.
        mode: Operation mode ("hybrid" default, or "strict" to mandate encryption).
        require_encryption: Legacy setting. If True, sets mode="strict" (fallback=False).
        exclude_paths: List of route path prefixes to bypass (e.g. ["/static"]).
    """

    def __init__(
        self,
        app: Flask | None = None,
        identity: Identity | Callable[[], Identity] | None = None,
        keystore: KeyStore | None = None,
        fallback: bool = True,
        mode: str = "hybrid",
        require_encryption: bool | None = None,
        exclude_paths: Sequence[str] | None = None,
        max_response_size: int = 16 * 1024 * 1024,
    ) -> None:
        self.identity = identity
        self.keystore = keystore

        if require_encryption is not None:
            self.fallback = not require_encryption
            self.mode = "strict" if require_encryption else mode
        else:
            self.fallback = fallback
            self.mode = mode.lower() if mode else "hybrid"

        self.require_encryption = not self.fallback or self.mode == "strict"
        self.exclude_paths = list(exclude_paths) if exclude_paths else ["/static"]
        self.max_response_size = max_response_size

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        app.before_request(self._before_request)
        app.after_request(self._after_request)

    def _get_identity(self) -> Identity:
        if callable(self.identity):
            return self.identity()
        if isinstance(self.identity, Identity):
            return self.identity
        return _GLOBAL_CONTEXT.get_identity()

    def _before_request(self) -> Response | tuple[Response, int] | None:
        path = request.path
        if any(path.startswith(exc) for exc in self.exclude_paths):
            return None

        g.uxsp_encrypted = False
        g.uxsp_payload = None
        g.uxsp_sender_id = None
        g.uxsp_sender_card = None
        g.uxsp_negotiated = None

        sec_support = request.headers.get(HEADER_SEC_UXSP_SUPPORT) or request.headers.get("sec-uxsp-support")
        if sec_support:
            g.uxsp_negotiated = negotiate_protocol(sec_support) or DEFAULT_UXSP_SELECTED

        header_pkg = request.headers.get("X-UXSP-Package")
        header_sender = request.headers.get("X-UXSP-Sender")
        content_type = request.headers.get("Content-Type", "")

        body_bytes = request.get_data()
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

                g.uxsp_encrypted = True
                g.uxsp_payload = parsed_payload
                g.uxsp_sender_id = sender_id
                g.uxsp_sender_card = sender_card or resolve_peer_card(self.keystore, sender_id)
            except Exception as e:
                logger.error("UXSP decryption failed: %s", e, exc_info=True)
                return jsonify({"error": "UXSP Decryption Failed"}), 400
        elif self.require_encryption:
            return jsonify({"error": "UXSP Encryption Required", "detail": "Missing valid SecurePackage body."}), 400

        return None

    def _after_request(self, response: Response) -> Response:
        should_encrypt = getattr(g, "uxsp_encrypted", False) or getattr(g, "uxsp_force_encrypt", False)
        sender_card = getattr(g, "uxsp_sender_card", None)
        server_identity = self._get_identity()

        selected = getattr(g, "uxsp_negotiated", None) or (
            DEFAULT_UXSP_SELECTED if request.headers.get(HEADER_SEC_UXSP_SUPPORT) or request.headers.get("sec-uxsp-support") else None
        )

        if should_encrypt and sender_card is not None:
            if response.is_streamed:
                def encrypt_stream():  # type: ignore[no-untyped-def]
                    for chunk in response.iter_encoded():
                        if not chunk:
                            continue  # pragma: no cover
                        out_pkg = Send(
                            receiver=sender_card,
                            item=chunk,
                            sender=server_identity,
                            data_type="binary"
                        )
                        yield out_pkg.to_json().encode("utf-8") + b"\n"

                from flask import Response as FlaskResponse
                encrypted_response = FlaskResponse(
                    encrypt_stream(),  # type: ignore[no-untyped-call]
                    status=response.status_code,
                    content_type="application/x-ndjson"
                )
                for k, v in response.headers.items():
                    if k.lower() not in ("content-length", "content-type"):
                        encrypted_response.headers[k] = v
                encrypted_response.headers["X-UXSP-Package"] = "1"
                encrypted_response.headers["X-UXSP-Sender"] = server_identity.entity_id
                encrypted_response.headers["X-UXSP-Recipient"] = getattr(g, "uxsp_sender_id", "") or ""
                encrypted_response.headers["X-UXSP-Version"] = "1"
                if selected:
                    encrypted_response.headers[HEADER_SEC_UXSP_SELECTED] = selected
                return encrypted_response

            content = response.get_data()
            if len(content) > self.max_response_size:
                raise ValueError(f"Response exceeds max_response_size of {self.max_response_size} bytes. Use streaming response.")

            try:
                resp_obj = json.loads(content.decode("utf-8"))
            except Exception:
                resp_obj = content.decode("utf-8", errors="replace")

            out_pkg = Send(
                receiver=sender_card,
                item=resp_obj,
                sender=server_identity,
            )

            encrypted_data = out_pkg.to_json()
            response.set_data(encrypted_data)
            response.content_type = "application/json"
            response.headers["X-UXSP-Package"] = "1"
            response.headers["X-UXSP-Sender"] = server_identity.entity_id
            response.headers["X-UXSP-Recipient"] = getattr(g, "uxsp_sender_id", "") or ""
            response.headers["X-UXSP-Version"] = "1"
            if selected:
                response.headers[HEADER_SEC_UXSP_SELECTED] = selected

            return response

        # Attach Sec-UXSP-Selected for unencrypted fallback response if Sec-UXSP-Support was sent
        if selected:
            response.headers[HEADER_SEC_UXSP_SELECTED] = selected

        return response



def protect_route(
    server_identity: Identity | Callable[[], Identity] | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Route decorator for Flask view functions requiring UXSP protection.

    Usage:
        @app.route("/secure-data", methods=["POST"])
        @protect_route()
        def secure_endpoint():
            data = g.uxsp_payload
            return jsonify({"received": data})
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not hasattr(g, "uxsp_encrypted"):
                raise RuntimeError("@protect_route decorator requires UXSPFlaskMiddleware to be installed.")
            g.uxsp_force_encrypt = True
            return func(*args, **kwargs)

        return wrapper

    return decorator


protect = protect_route
