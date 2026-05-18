"""
uxsp.transport.http — HTTP Transport Layer for UXSP Envelopes

What this file does:
    Provides helpers for sending and receiving UXSP-sealed envelopes over HTTP.
    Both the sender (UXSPHTTPRequest.build) and the receiver
    (UXSPHTTPRequest.parse) side are covered, and a matching pair is provided
    for HTTP responses (UXSPHTTPResponse).

    Wire format:
        The sealed envelope is JSON-encoded and placed in the HTTP body with
        Content-Type: application/uxsp+json.  Key metadata (sender, recipient,
        timestamp, nonce) are duplicated in custom HTTP headers so that API
        gateways and load balancers can route or log requests without parsing
        the JSON body.  parse() cross-validates headers against body fields to
        detect tampering or misrouting.

    Custom headers:
        X-UXSP-Version   — Protocol version string (must equal '1').
        X-UXSP-Sender    — Sender entity ID.
        X-UXSP-Recipient — Recipient entity ID.
        X-UXSP-Timestamp — Unix timestamp from the envelope.
        X-UXSP-Nonce     — envelope_nonce from the envelope.

Key classes:
    UXSPHTTPRequest  — Build and parse incoming HTTP requests.
    UXSPHTTPResponse — Build and parse outgoing HTTP responses.

Key errors:
    UXSPHTTPError           — Base.
    MissingUXSPHeaderError  — A required header is absent.
    WrongRecipientError     — Envelope addressed to a different recipient.
    UXSPVersionMismatchError — Client/server version incompatible.
"""
from __future__ import annotations

import json
from typing import Any

from uxsp.core.envelope import Envelope, EnvelopeTooLargeError

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

UXSP_VERSION = "1"
HEADER_VERSION = "X-UXSP-Version"
HEADER_SENDER = "X-UXSP-Sender"
HEADER_RECIPIENT = "X-UXSP-Recipient"
HEADER_TIMESTAMP = "X-UXSP-Timestamp"
HEADER_NONCE = "X-UXSP-Nonce"
UXSP_CONTENT_TYPE = "application/uxsp+json"


# ─────────────────────────────────────────────
# ERRORS
# ─────────────────────────────────────────────


class UXSPHTTPError(Exception):
    """Base class for HTTP transport errors."""

    pass


class MissingUXSPHeaderError(UXSPHTTPError):
    """A required UXSP header is missing from the request."""

    pass


class WrongRecipientError(UXSPHTTPError):
    """
    The envelope is addressed to a different recipient.
    Reject immediately — do not attempt decryption.
    """

    pass


class UXSPVersionMismatchError(UXSPHTTPError):
    """Client and server UXSP versions are incompatible."""

    pass


# ─────────────────────────────────────────────
# HTTP REQUEST BUILDER — sender side
# ─────────────────────────────────────────────


class UXSPHTTPRequest:
    """
    Helper for building and parsing UXSP envelopes as HTTP requests.

    What this class does:
        build()  — Accepts an Envelope or dict and returns a dict containing
                   'headers', 'body' (JSON string), and 'content_type', ready
                   to be passed to your HTTP client library.
        parse()  — Accepts raw HTTP headers and body (bytes or str), validates
                   the UXSP headers (version, sender, recipient, nonce, timestamp),
                   enforces the size limit, parses the JSON body into an Envelope,
                   and cross-validates header fields against body fields.

    Typical usage (sender side):
        req = UXSPHTTPRequest.build(envelope)
        response = requests.post(url, data=req['body'], headers=req['headers'],
                                 content_type=req['content_type'])

    Typical usage (receiver side / server handler):
        envelope = UXSPHTTPRequest.parse(request.headers, request.body, my_id=my_entity_id)
    """
    @staticmethod
    def build(envelope: dict[str, Any] | Envelope) -> dict[str, Any]:
        return UXSPHTTPRequest._build_envelope_response(envelope)

    @staticmethod
    def _build_envelope_response(envelope: dict[str, Any] | Envelope) -> dict[str, Any]:

        d: dict[str, Any] = envelope.to_dict() if isinstance(envelope, Envelope) else envelope

        headers = {
            HEADER_VERSION: UXSP_VERSION,
            HEADER_NONCE: str(d.get("envelope_nonce", "")),
            HEADER_TIMESTAMP: str(d.get("timestamp", "")),
            HEADER_SENDER: str(d.get("sender_id", "")),
            HEADER_RECIPIENT: str(d.get("recipient_id", "")),
        }
        return {
            "headers": headers,
            "body": json.dumps(d),
            "content_type": UXSP_CONTENT_TYPE,
        }

    @staticmethod
    def parse(
        headers: dict[str, str],
        body: bytes | str,
        my_id: str | None = None,
        max_bytes: int | None = None,
    ) -> Envelope:
        # normalise header keys — HTTP headers are case-insensitive
        norm = {k.lower(): v for k, v in headers.items()}

        def get_header(name: str) -> str:
            val = norm.get(name.lower())
            if val is None:
                raise MissingUXSPHeaderError(
                    f"Required UXSP header missing: '{name}'. Is this a UXSP request?"
                )
            return val

        # version check
        version = get_header(HEADER_VERSION)
        if version != UXSP_VERSION:
            raise UXSPVersionMismatchError(
                f"UXSP version mismatch. Server: {UXSP_VERSION}, Client: {version}."
            )

        # required headers
        sender_id = get_header(HEADER_SENDER)
        recipient_id = get_header(HEADER_RECIPIENT)
        timestamp = get_header(HEADER_TIMESTAMP)
        envelope_nonce = get_header(HEADER_NONCE)

        if my_id is not None and recipient_id != my_id:
            raise WrongRecipientError(
                f"Envelope addressed to '{recipient_id[:8]}...', "
                f"not to this entity '{my_id[:8]}...'. "
                f"Possible misrouted or replayed request."
            )

        limit = max_bytes if max_bytes is not None else Envelope.MAX_BYTES
        if isinstance(body, bytes):
            if len(body) > limit:
                raise EnvelopeTooLargeError(
                    f"Request body is {len(body)} bytes, maximum allowed is {limit} bytes."
                )
            try:
                body_str = body.decode("utf-8")
            except UnicodeDecodeError as e:
                raise UXSPHTTPError("Request body must be valid UTF-8 JSON.") from e
        elif isinstance(body, str):
            # Exact check: encode to measure actual UTF-8 bytes
            body_bytes = body.encode("utf-8")
            if len(body_bytes) > limit:
                raise EnvelopeTooLargeError(
                    f"Request body (UTF-8) is {len(body_bytes)} bytes, "
                    f"maximum allowed is {limit} bytes."
                )
            body_str = body
        else:
            raise UXSPHTTPError(f"Unexpected body type: {type(body)}")

        try:
            envelope_dict = json.loads(body_str)
        except json.JSONDecodeError as e:
            raise UXSPHTTPError(f"Invalid JSON: {e}") from e
        if not isinstance(envelope_dict, dict):
            raise UXSPHTTPError("JSON payload must be an object/dictionary.")

        parsed = Envelope.from_dict(envelope_dict)
        _assert_headers_match_envelope(
            parsed,
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=timestamp,
            envelope_nonce=envelope_nonce,
        )
        return parsed


# ─────────────────────────────────────────────
# HTTP RESPONSE BUILDER — receiver side
# ─────────────────────────────────────────────


class UXSPHTTPResponse:
    """
    Helper for building and parsing UXSP envelopes as HTTP responses.

    What this class does:
        Mirrors UXSPHTTPRequest for the response side of a request–response
        exchange.  build() produces the same header+body format as
        UXSPHTTPRequest.build().  parse() validates the response headers and
        body, cross-checking all UXSP header values against the JSON body.

    Typical usage (receiver / client side):
        envelope = UXSPHTTPResponse.parse(response.headers, response.content,
                                          my_id=my_entity_id)
    """
    @staticmethod
    def build(envelope: dict[str, Any] | Envelope) -> dict[str, Any]:

        return UXSPHTTPRequest._build_envelope_response(envelope)

    @staticmethod
    def parse(
        headers: dict[str, str],
        body: bytes | str,
        my_id: str | None = None,
        max_bytes: int | None = None,
    ) -> Envelope:
        norm = {k.lower(): v for k, v in headers.items()}

        def get_header(name: str) -> str:
            val = norm.get(name.lower())
            if val is None:
                raise MissingUXSPHeaderError(
                    f"Required UXSP header missing: '{name}'. Is this a UXSP response?"
                )
            return val

        version = get_header(HEADER_VERSION)
        if version != UXSP_VERSION:
            raise UXSPVersionMismatchError(
                f"Response UXSP version mismatch: got {version}, expected {UXSP_VERSION}."
            )

        sender_id = get_header(HEADER_SENDER)
        recipient_id = get_header(HEADER_RECIPIENT)
        timestamp = get_header(HEADER_TIMESTAMP)
        envelope_nonce = get_header(HEADER_NONCE)
        limit = max_bytes if max_bytes is not None else Envelope.MAX_BYTES
        if isinstance(body, bytes):
            if len(body) > limit:
                raise EnvelopeTooLargeError(f"Response body is {len(body)} bytes, max {limit}.")
            try:
                body_str = body.decode("utf-8")
            except UnicodeDecodeError as e:
                raise UXSPHTTPError("Response body must be valid UTF-8 JSON.") from e
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8")
            if len(body_bytes) > limit:
                raise EnvelopeTooLargeError(
                    f"Response body (UTF-8) is {len(body_bytes)} bytes, max {limit}."
                )
            body_str = body
        else:
            raise UXSPHTTPError(f"Unexpected body type: {type(body)}")

        try:
            data = json.loads(body_str)
        except json.JSONDecodeError as e:
            raise UXSPHTTPError(f"Invalid JSON: {e}") from e

        if not isinstance(data, dict):
            raise UXSPHTTPError("JSON payload must be an object/dictionary.")

        parsed = Envelope.from_dict(data)
        _assert_headers_match_envelope(
            parsed,
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=timestamp,
            envelope_nonce=envelope_nonce,
        )
        return parsed


def _assert_headers_match_envelope(
    envelope: Envelope, *, sender_id: str, recipient_id: str, timestamp: str, envelope_nonce: str
) -> None:
    """
    Verify that the UXSP HTTP headers match the corresponding fields in the envelope body.

    This cross-validation guards against tampering where an adversary replaces
    a header value without updating the envelope body (or vice versa).  Raises
    UXSPHTTPError if any field does not match.
    """
    if envelope.sender_id != sender_id:
        raise UXSPHTTPError("UXSP sender header does not match envelope sender_id.")
    if envelope.recipient_id != recipient_id:
        raise UXSPHTTPError("UXSP recipient header does not match envelope recipient_id.")
    if str(envelope.timestamp) != timestamp:
        raise UXSPHTTPError("UXSP timestamp header does not match envelope timestamp.")
    if envelope.envelope_nonce != envelope_nonce:
        raise UXSPHTTPError("UXSP nonce header does not match envelope envelope_nonce.")
