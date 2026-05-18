"""
Full-coverage pytest suite for uxsp/transport/http.py

Mocking strategy
----------------
- `Envelope` is imported inside the module under test, so we patch it at the
  module level: `uxsp.transport.http.Envelope`  (adjust the dotted path to
  match your actual package layout, e.g. `uxsp.core.http.Envelope`).
- `EnvelopeTooLargeError` is also patched so tests stay independent of the
  real Envelope implementation.

Run with:
    pytest test_http.py -v --tb=short
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

# We also need EnvelopeTooLargeError for isinstance checks in the module
from uxsp.core.envelope import EnvelopeTooLargeError  # real import for the exception class

# ── import the module under test ──────────────────────────────────────────────
# Adjust this import to your real package path:
from uxsp.transport.http import (  # noqa: F401  (replace `http` with your real module path)
    HEADER_NONCE,
    HEADER_RECIPIENT,
    HEADER_SENDER,
    HEADER_TIMESTAMP,
    HEADER_VERSION,
    UXSP_CONTENT_TYPE,
    UXSP_VERSION,
    MissingUXSPHeaderError,
    UXSPHTTPError,
    UXSPHTTPRequest,
    UXSPHTTPResponse,
    UXSPVersionMismatchError,
    WrongRecipientError,
    _assert_headers_match_envelope,
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

SENDER    = "sender-abc-123"
RECIPIENT = "recipient-xyz-789"
TIMESTAMP = "1700000000"
NONCE     = "nonce-abc"


def make_envelope_dict() -> dict:
    """Minimal dict that matches what the module expects."""
    return {
        "sender_id":      SENDER,
        "recipient_id":   RECIPIENT,
        "timestamp":      TIMESTAMP,
        "envelope_nonce": NONCE,
        "payload":        "encrypted-blob",
    }


def make_valid_headers(
    version:   str = UXSP_VERSION,
    sender:    str = SENDER,
    recipient: str = RECIPIENT,
    timestamp: str = TIMESTAMP,
    nonce:     str = NONCE,
) -> dict[str, str]:
    return {
        HEADER_VERSION:   version,
        HEADER_SENDER:    sender,
        HEADER_RECIPIENT: recipient,
        HEADER_TIMESTAMP: timestamp,
        HEADER_NONCE:     nonce,
    }


def make_mock_envelope(
    sender_id:      str = SENDER,
    recipient_id:   str = RECIPIENT,
    timestamp:      str = TIMESTAMP,
    envelope_nonce: str = NONCE,
) -> MagicMock:
    """Return a mock that behaves like an Envelope instance."""
    env = MagicMock()
    from uxsp.core.envelope import Envelope
    env.__class__ = Envelope
    env.sender_id      = sender_id
    env.recipient_id   = recipient_id
    env.timestamp      = timestamp
    env.envelope_nonce = envelope_nonce
    env.to_dict.return_value = make_envelope_dict()
    return env


# ─────────────────────────────────────────────────────────────────────────────
# EXCEPTION HIERARCHY SMOKE TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestExceptionHierarchy:
    def test_missing_header_is_uxsp_http_error(self):
        err = MissingUXSPHeaderError("x")
        assert isinstance(err, UXSPHTTPError)

    def test_wrong_recipient_is_uxsp_http_error(self):
        err = WrongRecipientError("x")
        assert isinstance(err, UXSPHTTPError)

    def test_version_mismatch_is_uxsp_http_error(self):
        err = UXSPVersionMismatchError("x")
        assert isinstance(err, UXSPHTTPError)


# ─────────────────────────────────────────────────────────────────────────────
# UXSPHTTPRequest.build()
# ─────────────────────────────────────────────────────────────────────────────

class TestUXSPHTTPRequestBuild:
    """Covers _build_envelope_response via both build() code-paths."""

    def test_build_from_envelope_instance(self):
        mock_env = make_mock_envelope()
        result = UXSPHTTPRequest.build(mock_env)

        mock_env.to_dict.assert_called_once()
        assert result["content_type"] == UXSP_CONTENT_TYPE
        assert result["headers"][HEADER_VERSION]   == UXSP_VERSION
        assert result["headers"][HEADER_SENDER]    == SENDER
        assert result["headers"][HEADER_RECIPIENT] == RECIPIENT
        assert result["headers"][HEADER_TIMESTAMP] == TIMESTAMP
        assert result["headers"][HEADER_NONCE]     == NONCE
        # body must be valid JSON containing the envelope dict
        body = json.loads(result["body"])
        assert body["sender_id"] == SENDER

    def test_build_from_plain_dict(self):
        d = make_envelope_dict()
        result = UXSPHTTPRequest.build(d)

        assert result["content_type"] == UXSP_CONTENT_TYPE
        assert result["headers"][HEADER_SENDER] == SENDER
        body = json.loads(result["body"])
        assert body["recipient_id"] == RECIPIENT

    def test_build_missing_optional_fields_default_to_empty_string(self):
        """to_dict returns a minimal dict — missing keys become empty strings."""
        result = UXSPHTTPRequest.build({})
        assert result["headers"][HEADER_NONCE]     == ""
        assert result["headers"][HEADER_TIMESTAMP] == ""
        assert result["headers"][HEADER_SENDER]    == ""
        assert result["headers"][HEADER_RECIPIENT] == ""


# ─────────────────────────────────────────────────────────────────────────────
# UXSPHTTPRequest.parse() — happy path
# ─────────────────────────────────────────────────────────────────────────────

class TestUXSPHTTPRequestParseHappyPath:
    """parse() returns an Envelope on valid input."""

    def _parse(self, body, *, my_id=None, max_bytes=None, headers=None):
        h = headers or make_valid_headers()
        with patch("uxsp.transport.http.Envelope") as MockEnv:
            mock_env = make_mock_envelope()
            MockEnv.from_dict.return_value = mock_env
            MockEnv.MAX_BYTES = 10_000_000
            result = UXSPHTTPRequest.parse(h, body, my_id=my_id, max_bytes=max_bytes)
        return result, mock_env

    def test_parse_bytes_body(self):
        body = json.dumps(make_envelope_dict()).encode()
        result, mock_env = self._parse(body)
        assert result is mock_env

    def test_parse_str_body(self):
        body = json.dumps(make_envelope_dict())
        result, mock_env = self._parse(body)
        assert result is mock_env

    def test_parse_with_my_id_matching_recipient(self):
        body = json.dumps(make_envelope_dict())
        result, mock_env = self._parse(body, my_id=RECIPIENT)
        assert result is mock_env

    def test_parse_headers_are_case_insensitive(self):
        """HTTP headers must be normalised before lookup."""
        body = json.dumps(make_envelope_dict())
        mixed_case_headers = {k.upper(): v for k, v in make_valid_headers().items()}
        result, mock_env = self._parse(body, headers=mixed_case_headers)
        assert result is mock_env

    def test_parse_respects_custom_max_bytes(self):
        body = json.dumps(make_envelope_dict())
        # max_bytes larger than body — should pass
        result, mock_env = self._parse(body, max_bytes=10_000_000)
        assert result is mock_env


# ─────────────────────────────────────────────────────────────────────────────
# UXSPHTTPRequest.parse() — error paths
# ─────────────────────────────────────────────────────────────────────────────

class TestUXSPHTTPRequestParseErrors:

    def _parse(self, headers, body, my_id=None, max_bytes=None):
        with patch("uxsp.transport.http.Envelope") as MockEnv:
            MockEnv.MAX_BYTES = 10_000_000
            mock_env = make_mock_envelope()
            MockEnv.from_dict.return_value = mock_env
            return UXSPHTTPRequest.parse(headers, body, my_id=my_id, max_bytes=max_bytes)

    # ── missing header ────────────────────────────────────────────────────────

    @pytest.mark.parametrize("drop_header", [
        HEADER_VERSION,
        HEADER_SENDER,
        HEADER_RECIPIENT,
        HEADER_TIMESTAMP,
        HEADER_NONCE,
    ])
    def test_missing_required_header_raises(self, drop_header):
        h = make_valid_headers()
        del h[drop_header]
        with pytest.raises(MissingUXSPHeaderError, match=drop_header):
            self._parse(h, json.dumps(make_envelope_dict()))

    # ── version mismatch ─────────────────────────────────────────────────────

    def test_version_mismatch_raises(self):
        h = make_valid_headers(version="99")
        with pytest.raises(UXSPVersionMismatchError):
            self._parse(h, json.dumps(make_envelope_dict()))

    # ── wrong recipient ───────────────────────────────────────────────────────

    def test_wrong_recipient_raises(self):
        h = make_valid_headers()
        with pytest.raises(WrongRecipientError):
            self._parse(h, json.dumps(make_envelope_dict()), my_id="someone-else")

    def test_correct_recipient_does_not_raise(self):
        h = make_valid_headers()
        # should NOT raise
        self._parse(h, json.dumps(make_envelope_dict()), my_id=RECIPIENT)

    def test_my_id_none_skips_recipient_check(self):
        h = make_valid_headers()
        self._parse(h, json.dumps(make_envelope_dict()), my_id=None)

    # ── body too large (bytes) ────────────────────────────────────────────────

    def test_bytes_body_too_large_raises(self):
        body = json.dumps(make_envelope_dict()).encode()
        with pytest.raises(EnvelopeTooLargeError):
            self._parse(make_valid_headers(), body, max_bytes=1)

    # ── body too large (str) ─────────────────────────────────────────────────

    def test_str_body_too_large_raises(self):
        body = json.dumps(make_envelope_dict())
        with pytest.raises(EnvelopeTooLargeError):
            self._parse(make_valid_headers(), body, max_bytes=1)

    # ── invalid UTF-8 bytes ───────────────────────────────────────────────────

    def test_invalid_utf8_bytes_raises(self):
        bad_bytes = b"\xff\xfe"
        with pytest.raises(UXSPHTTPError, match="UTF-8"):
            self._parse(make_valid_headers(), bad_bytes, max_bytes=10_000_000)

    # ── invalid JSON ─────────────────────────────────────────────────────────

    def test_invalid_json_bytes_raises(self):
        with pytest.raises(UXSPHTTPError, match="Invalid JSON"):
            self._parse(make_valid_headers(), b"not-json", max_bytes=10_000_000)

    def test_invalid_json_str_raises(self):
        with pytest.raises(UXSPHTTPError, match="Invalid JSON"):
            self._parse(make_valid_headers(), "not-json")

    # ── JSON not a dict ───────────────────────────────────────────────────────

    def test_json_array_raises(self):
        with pytest.raises(UXSPHTTPError, match="object/dictionary"):
            self._parse(make_valid_headers(), json.dumps([1, 2, 3]))

    # ── unexpected body type ─────────────────────────────────────────────────

    def test_unexpected_body_type_raises(self):
        with pytest.raises(UXSPHTTPError, match="Unexpected body type"):
            self._parse(make_valid_headers(), 12345)

    # ── header / envelope field mismatches ───────────────────────────────────

    def test_sender_mismatch_raises(self):
        h = make_valid_headers(sender="wrong-sender")
        with pytest.raises(UXSPHTTPError, match="sender"):
            self._parse(h, json.dumps(make_envelope_dict()))

    def test_recipient_mismatch_raises(self):
        h = make_valid_headers(recipient="wrong-recipient")
        with pytest.raises(UXSPHTTPError, match="recipient"):
            self._parse(h, json.dumps(make_envelope_dict()))

    def test_timestamp_mismatch_raises(self):
        h = make_valid_headers(timestamp="9999999999")
        with pytest.raises(UXSPHTTPError, match="timestamp"):
            self._parse(h, json.dumps(make_envelope_dict()))

    def test_nonce_mismatch_raises(self):
        h = make_valid_headers(nonce="bad-nonce")
        with pytest.raises(UXSPHTTPError, match="nonce"):
            self._parse(h, json.dumps(make_envelope_dict()))


# ─────────────────────────────────────────────────────────────────────────────
# UXSPHTTPResponse.build()
# ─────────────────────────────────────────────────────────────────────────────

class TestUXSPHTTPResponseBuild:
    """build() delegates to UXSPHTTPRequest._build_envelope_response."""

    def test_build_from_envelope(self):
        mock_env = make_mock_envelope()
        result = UXSPHTTPResponse.build(mock_env)
        assert result["content_type"] == UXSP_CONTENT_TYPE
        assert result["headers"][HEADER_SENDER] == SENDER

    def test_build_from_dict(self):
        result = UXSPHTTPResponse.build(make_envelope_dict())
        assert result["headers"][HEADER_RECIPIENT] == RECIPIENT


# ─────────────────────────────────────────────────────────────────────────────
# UXSPHTTPResponse.parse() — happy path
# ─────────────────────────────────────────────────────────────────────────────

class TestUXSPHTTPResponseParseHappyPath:

    def _parse(self, body, *, my_id=None, max_bytes=None, headers=None):
        h = headers or make_valid_headers()
        with patch("uxsp.transport.http.Envelope") as MockEnv:
            mock_env = make_mock_envelope()
            MockEnv.from_dict.return_value = mock_env
            MockEnv.MAX_BYTES = 10_000_000
            return UXSPHTTPResponse.parse(h, body, my_id=my_id, max_bytes=max_bytes)

    def test_parse_bytes_body(self):
        body = json.dumps(make_envelope_dict()).encode()
        result = self._parse(body)
        assert result is not None

    def test_parse_str_body(self):
        result = self._parse(json.dumps(make_envelope_dict()))
        assert result is not None

    def test_parse_with_matching_my_id(self):
        result = self._parse(json.dumps(make_envelope_dict()), my_id=RECIPIENT)
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# UXSPHTTPResponse.parse() — error paths
# ─────────────────────────────────────────────────────────────────────────────

class TestUXSPHTTPResponseParseErrors:

    def _parse(self, headers, body, my_id=None, max_bytes=None):
        with patch("uxsp.transport.http.Envelope") as MockEnv:
            MockEnv.MAX_BYTES = 10_000_000
            mock_env = make_mock_envelope()
            MockEnv.from_dict.return_value = mock_env
            return UXSPHTTPResponse.parse(headers, body, my_id=my_id, max_bytes=max_bytes)

    @pytest.mark.parametrize("drop_header", [
        HEADER_VERSION,
        HEADER_SENDER,
        HEADER_RECIPIENT,
        HEADER_TIMESTAMP,
        HEADER_NONCE,
    ])
    def test_missing_header_raises(self, drop_header):
        h = make_valid_headers()
        del h[drop_header]
        with pytest.raises(MissingUXSPHeaderError, match=drop_header):
            self._parse(h, json.dumps(make_envelope_dict()))

    def test_version_mismatch_raises(self):
        h = make_valid_headers(version="0")
        with pytest.raises(UXSPVersionMismatchError):
            self._parse(h, json.dumps(make_envelope_dict()))

    def test_bytes_body_too_large_raises(self):
        body = json.dumps(make_envelope_dict()).encode()
        with pytest.raises(EnvelopeTooLargeError):
            self._parse(make_valid_headers(), body, max_bytes=1)

    def test_str_body_too_large_raises(self):
        body = json.dumps(make_envelope_dict())
        with pytest.raises(EnvelopeTooLargeError):
            self._parse(make_valid_headers(), body, max_bytes=1)

    def test_invalid_utf8_raises(self):
        with pytest.raises(UXSPHTTPError, match="UTF-8"):
            self._parse(make_valid_headers(), b"\xff\xfe", max_bytes=10_000_000)

    def test_invalid_json_raises(self):
        with pytest.raises(UXSPHTTPError, match="Invalid JSON"):
            self._parse(make_valid_headers(), b"oops", max_bytes=10_000_000)

    def test_json_not_dict_raises(self):
        with pytest.raises(UXSPHTTPError, match="object/dictionary"):
            self._parse(make_valid_headers(), json.dumps([]))

    def test_unexpected_body_type_raises(self):
        with pytest.raises(UXSPHTTPError, match="Unexpected body type"):
            self._parse(make_valid_headers(), object())

    def test_sender_mismatch_raises(self):
        h = make_valid_headers(sender="impostor")
        with pytest.raises(UXSPHTTPError, match="sender"):
            self._parse(h, json.dumps(make_envelope_dict()))

    def test_recipient_mismatch_raises(self):
        h = make_valid_headers(recipient="impostor")
        with pytest.raises(UXSPHTTPError, match="recipient"):
            self._parse(h, json.dumps(make_envelope_dict()))

    def test_timestamp_mismatch_raises(self):
        h = make_valid_headers(timestamp="0")
        with pytest.raises(UXSPHTTPError, match="timestamp"):
            self._parse(h, json.dumps(make_envelope_dict()))

    def test_nonce_mismatch_raises(self):
        h = make_valid_headers(nonce="wrong")
        with pytest.raises(UXSPHTTPError, match="nonce"):
            self._parse(h, json.dumps(make_envelope_dict()))

    def test_default_max_bytes_used_when_none(self):
        """When max_bytes is None the module uses Envelope.MAX_BYTES — verify path taken."""
        body = json.dumps(make_envelope_dict()).encode()
        # Should succeed because mock MAX_BYTES is large
        result = self._parse(make_valid_headers(), body, max_bytes=None)
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# _assert_headers_match_envelope() — standalone coverage
# ─────────────────────────────────────────────────────────────────────────────

class TestAssertHeadersMatchEnvelope:
    """Direct unit tests to guarantee every branch of the helper is exercised."""

    def _env(self, **overrides):
        defaults = {
            "sender_id": SENDER,
            "recipient_id": RECIPIENT,
            "timestamp": TIMESTAMP,
            "envelope_nonce": NONCE,
        }
        defaults.update(overrides)
        return make_mock_envelope(**defaults)

    def test_all_match_no_raise(self):
        _assert_headers_match_envelope(
            self._env(),
            sender_id=SENDER, recipient_id=RECIPIENT,
            timestamp=TIMESTAMP, envelope_nonce=NONCE,
        )

    def test_sender_mismatch(self):
        with pytest.raises(UXSPHTTPError, match="sender"):
            _assert_headers_match_envelope(
                self._env(sender_id="X"),
                sender_id=SENDER, recipient_id=RECIPIENT,
                timestamp=TIMESTAMP, envelope_nonce=NONCE,
            )

    def test_recipient_mismatch(self):
        with pytest.raises(UXSPHTTPError, match="recipient"):
            _assert_headers_match_envelope(
                self._env(recipient_id="X"),
                sender_id=SENDER, recipient_id=RECIPIENT,
                timestamp=TIMESTAMP, envelope_nonce=NONCE,
            )

    def test_timestamp_mismatch(self):
        with pytest.raises(UXSPHTTPError, match="timestamp"):
            _assert_headers_match_envelope(
                self._env(timestamp="0"),
                sender_id=SENDER, recipient_id=RECIPIENT,
                timestamp=TIMESTAMP, envelope_nonce=NONCE,
            )

    def test_nonce_mismatch(self):
        with pytest.raises(UXSPHTTPError, match="nonce"):
            _assert_headers_match_envelope(
                self._env(envelope_nonce="bad"),
                sender_id=SENDER, recipient_id=RECIPIENT,
                timestamp=TIMESTAMP, envelope_nonce=NONCE,
            )
