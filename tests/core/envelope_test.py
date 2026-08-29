"""
pytest suite for envelope.py
Coverage target: every executable line, every branch, every edge case.
Run: pytest test_envelope.py -v
"""

from __future__ import annotations

import json
import time
from unittest.mock import patch

import pytest

from uxsp.core.envelope import (
    _DEFAULT_MAX_BYTES,
    _REQUIRED_FIELDS,
    UXSP_VERSION,
    Envelope,
    EnvelopeError,
    EnvelopeExpiredError,
    EnvelopeTooLargeError,
    EnvelopeValidationError,
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _valid_dict(**overrides) -> dict:
    """Minimal valid envelope dict, with optional field overrides."""
    base = {
        "version":        UXSP_VERSION,
        "sender_id":      "alice",
        "recipient_id":   "bob",
        "timestamp":      int(time.time()),
        "envelope_nonce": "nonce-abc123",
        "ciphertext":     "ct_payload",
        "nonce":          "nonce_val",
        "ephemeral_pub":  "epk_val",
        "kem_ciphertext": "kem_val",
        "classical_sig":  "csig_val",
        "pqc_sig":        "pqcsig_val",
    }
    base.update(overrides)
    return base


def _make_envelope(**overrides) -> Envelope:
    """Build Envelope directly via constructor."""
    d = _valid_dict(**overrides)
    return Envelope(
        version=d["version"],
        sender_id=d["sender_id"],
        recipient_id=d["recipient_id"],
        timestamp=d["timestamp"],
        envelope_nonce=d["envelope_nonce"],
        ciphertext=d["ciphertext"],
        nonce=d["nonce"],
        ephemeral_pub=d["ephemeral_pub"],
        kem_ciphertext=d["kem_ciphertext"],
        classical_sig=d["classical_sig"],
        pqc_sig=d["pqc_sig"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS AND MODULE-LEVEL ATTRIBUTES
# ─────────────────────────────────────────────────────────────────────────────

class TestModuleConstants:
    """Lines 11–28: module-level constants are correct."""

    def test_uxsp_version_value(self):
        assert UXSP_VERSION == "UXSP-1"

    def test_default_max_bytes(self):
        assert _DEFAULT_MAX_BYTES == 64 * 1024

    def test_required_fields_is_frozenset(self):
        assert isinstance(_REQUIRED_FIELDS, frozenset)

    def test_required_fields_contents(self):
        expected = {
            "version", "sender_id", "recipient_id", "timestamp",
            "envelope_nonce", "ciphertext", "nonce", "ephemeral_pub",
            "kem_ciphertext", "classical_sig", "pqc_sig",
        }
        assert expected == _REQUIRED_FIELDS


# ─────────────────────────────────────────────────────────────────────────────
# EXCEPTION HIERARCHY
# ─────────────────────────────────────────────────────────────────────────────

class TestExceptionHierarchy:
    """Lines 35–56: all custom exceptions inherit correctly."""

    def test_envelope_error_is_exception(self):
        assert issubclass(EnvelopeError, Exception)

    def test_validation_error_inherits_envelope_error(self):
        assert issubclass(EnvelopeValidationError, EnvelopeError)

    def test_too_large_error_inherits_envelope_error(self):
        assert issubclass(EnvelopeTooLargeError, EnvelopeError)

    def test_expired_error_inherits_envelope_error(self):
        assert issubclass(EnvelopeExpiredError, EnvelopeError)

    def test_can_raise_and_catch_as_base(self):
        with pytest.raises(EnvelopeError):
            raise EnvelopeValidationError("test")

    def test_can_raise_too_large_as_base(self):
        with pytest.raises(EnvelopeError):
            raise EnvelopeTooLargeError("big")

    def test_can_raise_expired_as_base(self):
        with pytest.raises(EnvelopeError):
            raise EnvelopeExpiredError("old")


# ─────────────────────────────────────────────────────────────────────────────
# ENVELOPE.__init__  (Lines 83–98)
# ─────────────────────────────────────────────────────────────────────────────

class TestEnvelopeInit:
    """__init__ stores every field and initialises _size_bytes_cache to None."""

    def test_all_fields_stored_correctly(self):
        now = int(time.time())
        e = Envelope(
            version="UXSP-1", sender_id="alice", recipient_id="bob",
            timestamp=now, envelope_nonce="en", ciphertext="ct",
            nonce="n", ephemeral_pub="ep", kem_ciphertext="kc",
            classical_sig="cs", pqc_sig="ps",
        )
        assert e.version == "UXSP-1"
        assert e.sender_id == "alice"
        assert e.recipient_id == "bob"
        assert e.timestamp == now
        assert e.envelope_nonce == "en"
        assert e.ciphertext == "ct"
        assert e.nonce == "n"
        assert e.ephemeral_pub == "ep"
        assert e.kem_ciphertext == "kc"
        assert e.classical_sig == "cs"
        assert e.pqc_sig == "ps"

    def test_size_bytes_cache_is_none_initially(self):
        e = _make_envelope()
        assert e._size_bytes_cache is None

    def test_class_max_bytes(self):
        # ClassVar is set at class level
        assert Envelope.MAX_BYTES == _DEFAULT_MAX_BYTES

    def test_has_slots_no_dict(self):
        """Verifies that Envelope uses __slots__ and has no __dict__."""
        e = _make_envelope()
        assert not hasattr(e, "__dict__")


# ─────────────────────────────────────────────────────────────────────────────
# ENVELOPE.__setattr__  (Lines 110–115)
# ─────────────────────────────────────────────────────────────────────────────

class TestSetAttr:
    """Immutability guard and cache-clearing logic."""

    # Branch 1: immutable field → raise AttributeError
    @pytest.mark.parametrize("field", [
        "version", "sender_id", "recipient_id", "timestamp",
        "envelope_nonce", "ciphertext", "nonce", "ephemeral_pub",
        "kem_ciphertext", "classical_sig", "pqc_sig",
    ])
    def test_immutable_fields_raise(self, field):
        e = _make_envelope()
        with pytest.raises(AttributeError, match=f"'{field}' is immutable"):
            setattr(e, field, "bad")

    # Branch 2: name == "_size_bytes_cache" → skip cache-clear, just set
    def test_setting_size_bytes_cache_directly_does_not_self_clear(self):
        e = _make_envelope()
        # Setting _size_bytes_cache should NOT clear itself first
        object.__setattr__(e, "_size_bytes_cache", 42)   # prime it
        # Now assign via __setattr__ (not bypassing it)
        e._size_bytes_cache = 99   # name == "_size_bytes_cache" branch
        assert e._size_bytes_cache == 99




# ─────────────────────────────────────────────────────────────────────────────
# ENVELOPE.from_dict  (Lines 118–172)
# ─────────────────────────────────────────────────────────────────────────────

class TestFromDict:
    """Every branch inside from_dict."""

    # ── Happy path ────────────────────────────────────────────────────────────

    def test_valid_dict_returns_envelope(self):
        e = Envelope.from_dict(_valid_dict())
        assert isinstance(e, Envelope)
        assert e.sender_id == "alice"

    def test_timestamp_as_int_accepted(self):
        e = Envelope.from_dict(_valid_dict(timestamp=1_000_000_000))
        assert e.timestamp == 1_000_000_000

    def test_timestamp_as_string_int_coerced(self):
        # str-that-is-int → int() converts it (lines 153-154)
        e = Envelope.from_dict(_valid_dict(timestamp="1000000000"))
        assert e.timestamp == 1_000_000_000
        assert isinstance(e.timestamp, int)

    def test_uses_cls_max_bytes_when_max_bytes_is_none(self):
        # max_bytes=None → uses Envelope.MAX_BYTES (line 146)
        e = Envelope.from_dict(_valid_dict())
        assert e.version == UXSP_VERSION

    def test_uses_provided_max_bytes_when_given(self):
        # max_bytes is not None → uses the given value (line 146 else-branch)
        large_limit = 999_999
        e = Envelope.from_dict(_valid_dict(), max_bytes=large_limit)
        assert isinstance(e, Envelope)

    # ── Missing fields ────────────────────────────────────────────────────────

    def test_missing_single_field_raises_validation(self):
        d = _valid_dict()
        del d["pqc_sig"]
        with pytest.raises(EnvelopeValidationError, match="missing required fields"):
            Envelope.from_dict(d)

    def test_missing_multiple_fields_listed_in_message(self):
        d = _valid_dict()
        del d["sender_id"]
        del d["classical_sig"]
        with pytest.raises(EnvelopeValidationError) as exc_info:
            Envelope.from_dict(d)
        msg = str(exc_info.value)
        assert "classical_sig" in msg
        assert "sender_id" in msg

    def test_empty_dict_raises_validation(self):
        with pytest.raises(EnvelopeValidationError):
            Envelope.from_dict({})

    # ── Non-string string fields ──────────────────────────────────────────────

    @pytest.mark.parametrize("field", [
        "version", "sender_id", "recipient_id", "envelope_nonce",
        "ciphertext", "nonce", "ephemeral_pub", "kem_ciphertext",
        "classical_sig", "pqc_sig",
    ])
    def test_non_string_field_raises_validation(self, field):
        d = _valid_dict()
        d[field] = 12345   # int instead of str
        with pytest.raises(EnvelopeValidationError, match=f"'{field}' must be a string"):
            Envelope.from_dict(d)

    def test_non_string_field_error_mentions_type(self):
        d = _valid_dict(version=True)
        with pytest.raises(EnvelopeValidationError, match="bool"):
            Envelope.from_dict(d)

    # ── Wrong version ─────────────────────────────────────────────────────────

    def test_wrong_version_raises_validation(self):
        d = _valid_dict(version="UXSP-99")
        with pytest.raises(EnvelopeValidationError, match="Unknown envelope version"):
            Envelope.from_dict(d)

    def test_wrong_version_message_shows_expected(self):
        d = _valid_dict(version="BAD-VER")
        with pytest.raises(EnvelopeValidationError, match=UXSP_VERSION):
            Envelope.from_dict(d)

    # ── Size limit ────────────────────────────────────────────────────────────

    def test_oversized_dict_raises_too_large(self):
        d = _valid_dict(ciphertext="x" * 70_000)
        with pytest.raises(EnvelopeTooLargeError, match="exceeds limit"):
            Envelope.from_dict(d)

    def test_oversized_with_custom_limit_raises_too_large(self):
        d = _valid_dict()
        with pytest.raises(EnvelopeTooLargeError):
            Envelope.from_dict(d, max_bytes=10)

    def test_exact_size_limit_passes(self):
        d = _valid_dict()
        serialised_len = len(json.dumps(d, separators=(",", ":")))
        # exactly at limit → passes (check is strictly >)
        e = Envelope.from_dict(d, max_bytes=serialised_len)
        assert isinstance(e, Envelope)

    # ── Bad timestamp ─────────────────────────────────────────────────────────

    def test_string_timestamp_raises_validation(self):
        # "abc" cannot be int-cast → ValueError → EnvelopeValidationError
        d = _valid_dict(timestamp="not-a-number")
        with pytest.raises(EnvelopeValidationError, match="Invalid timestamp value"):
            Envelope.from_dict(d)

    def test_none_timestamp_raises_validation(self):
        # None → TypeError inside int() → EnvelopeValidationError
        d = _valid_dict(timestamp=None)
        with pytest.raises(EnvelopeValidationError, match="Invalid timestamp value"):
            Envelope.from_dict(d)

    def test_timestamp_error_chained_from_original(self):
        d = _valid_dict(timestamp="bad")
        with pytest.raises(EnvelopeValidationError) as exc_info:
            Envelope.from_dict(d)
        # __cause__ must be the ValueError (chained via `from e`)
        assert exc_info.value.__cause__ is not None


# ─────────────────────────────────────────────────────────────────────────────
# ENVELOPE.from_json  (Lines 178–203)
# ─────────────────────────────────────────────────────────────────────────────

class TestFromJson:
    """Every branch inside from_json."""

    def _valid_json(self, **overrides) -> str:
        return json.dumps(_valid_dict(**overrides))

    # ── Happy path ────────────────────────────────────────────────────────────

    def test_valid_json_returns_envelope(self):
        e = Envelope.from_json(self._valid_json())
        assert isinstance(e, Envelope)

    def test_passes_limit_to_from_dict(self):
        """max_bytes flows through to from_dict (line 203)."""
        e = Envelope.from_json(self._valid_json(), max_bytes=999_999)
        assert isinstance(e, Envelope)

    def test_uses_class_max_bytes_when_none(self):
        """max_bytes=None → cls.MAX_BYTES used on line 181."""
        e = Envelope.from_json(self._valid_json())
        assert e.sender_id == "alice"

    # ── Branch: char-count exceeds limit (line 183-186) ──────────────────────

    def test_char_count_exceeds_limit_raises_too_large(self):
        js = self._valid_json()
        with pytest.raises(EnvelopeTooLargeError, match="preliminary character count"):
            Envelope.from_json(js, max_bytes=5)

    # ── Branch: byte-count exceeds limit after char check passes (lines 190-193)

    def test_byte_count_exceeds_limit_raises_too_large(self):
        """
        Trigger: string with literal multibyte UTF-8 chars (via ensure_ascii=False)
        so that len(json_str) <= limit < len(raw).
        """
        d = _valid_dict()
        # inject literal € (3 bytes each) into a field via ensure_ascii=False
        d["recipient_id"] = "bob" + "€" * 30
        js = json.dumps(d, ensure_ascii=False)   # literal chars, not \uXXXX
        char_len = len(js)
        byte_len = len(js.encode("utf-8"))
        assert byte_len > char_len               # ensure the scenario is real
        # limit == char_len: char check passes (equal, not >), byte check fires
        with pytest.raises(EnvelopeTooLargeError, match=r"\d+ bytes, maximum allowed"):
            Envelope.from_json(js, max_bytes=char_len)

    # ── Branch: invalid JSON (lines 195-198) ─────────────────────────────────

    def test_invalid_json_raises_validation(self):
        with pytest.raises(EnvelopeValidationError, match="Invalid JSON payload"):
            Envelope.from_json("{not valid json}")

    def test_invalid_json_cause_is_suppressed(self):
        """from None suppresses the JSONDecodeError chain."""
        with pytest.raises(EnvelopeValidationError) as exc_info:
            Envelope.from_json("{bad}")
        assert exc_info.value.__cause__ is None

    # ── Branch: JSON is not a dict (lines 200-201) ───────────────────────────

    def test_json_list_raises_validation(self):
        with pytest.raises(EnvelopeValidationError, match="must be an object/dictionary"):
            Envelope.from_json("[1, 2, 3]")

    def test_json_string_raises_validation(self):
        with pytest.raises(EnvelopeValidationError, match="must be an object/dictionary"):
            Envelope.from_json('"just a string"')

    def test_json_number_raises_validation(self):
        with pytest.raises(EnvelopeValidationError, match="must be an object/dictionary"):
            Envelope.from_json("42")


# ─────────────────────────────────────────────────────────────────────────────
# ENVELOPE.from_bytes  (Lines 205–213)
# ─────────────────────────────────────────────────────────────────────────────

class TestFromBytes:
    """Every branch inside from_bytes."""

    def test_valid_bytes_returns_envelope(self):
        js = json.dumps(_valid_dict()).encode("utf-8")
        e = Envelope.from_bytes(js)
        assert isinstance(e, Envelope)

    def test_max_bytes_passed_through(self):
        js = json.dumps(_valid_dict()).encode("utf-8")
        e = Envelope.from_bytes(js, max_bytes=999_999)
        assert isinstance(e, Envelope)

    def test_invalid_utf8_raises_validation(self):
        """UnicodeDecodeError → EnvelopeValidationError (line 211-212)."""
        with pytest.raises(EnvelopeValidationError, match="valid UTF-8"):
            Envelope.from_bytes(b"\xff\xfe\xfd")

    def test_invalid_utf8_chained_from_unicode_decode_error(self):
        with pytest.raises(EnvelopeValidationError) as exc_info:
            Envelope.from_bytes(b"\xff\xfe")
        assert isinstance(exc_info.value.__cause__, UnicodeDecodeError)

    def test_oversized_bytes_raises_too_large(self):
        js = json.dumps(_valid_dict()).encode("utf-8")
        with pytest.raises(EnvelopeTooLargeError):
            Envelope.from_bytes(js, max_bytes=5)


# ─────────────────────────────────────────────────────────────────────────────
# TO_DICT / TO_JSON / TO_BYTES  (Lines 219–245)
# ─────────────────────────────────────────────────────────────────────────────

class TestSerialisation:

    def test_to_dict_returns_all_fields(self):
        e = _make_envelope()
        d = e.to_dict()
        assert set(d.keys()) == {
            "version", "sender_id", "recipient_id", "timestamp",
            "envelope_nonce", "ciphertext", "nonce", "ephemeral_pub",
            "kem_ciphertext", "classical_sig", "pqc_sig",
        }

    def test_to_dict_values_match(self):
        now = int(time.time())
        e = _make_envelope(timestamp=now, sender_id="alice", recipient_id="bob")
        d = e.to_dict()
        assert d["sender_id"] == "alice"
        assert d["recipient_id"] == "bob"
        assert d["timestamp"] == now

    def test_to_json_is_valid_json(self):
        e = _make_envelope()
        parsed = json.loads(e.to_json())
        assert parsed["version"] == UXSP_VERSION

    def test_to_json_no_indent(self):
        e = _make_envelope()
        js = e.to_json()            # indent=None default
        assert "\n" not in js       # compact output

    def test_to_json_with_indent(self):
        e = _make_envelope()
        js = e.to_json(indent=2)
        assert "\n" in js           # pretty-printed

    def test_to_bytes_returns_utf8_bytes(self):
        e = _make_envelope()
        raw = e.to_bytes()
        assert isinstance(raw, bytes)
        assert json.loads(raw)["version"] == UXSP_VERSION

    def test_to_bytes_sets_size_cache(self):
        """to_bytes updates _size_bytes_cache (line 244)."""
        e = _make_envelope()
        assert e._size_bytes_cache is None
        raw = e.to_bytes()
        assert e._size_bytes_cache == len(raw)

    def test_roundtrip_from_dict(self):
        original = _valid_dict()
        e = Envelope.from_dict(original)
        d = e.to_dict()
        assert d == {k: original[k] for k in d}

    def test_roundtrip_from_json(self):
        js = json.dumps(_valid_dict())
        e = Envelope.from_json(js)
        assert json.loads(e.to_json())["sender_id"] == "alice"

    def test_roundtrip_from_bytes(self):
        raw = json.dumps(_valid_dict()).encode("utf-8")
        e = Envelope.from_bytes(raw)
        assert e.to_bytes() == e.to_json().encode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# AGE / FRESHNESS  (Lines 251–278)
# ─────────────────────────────────────────────────────────────────────────────

class TestFreshness:

    # ── age_seconds ───────────────────────────────────────────────────────────

    def test_age_seconds_recent_envelope(self):
        e = _make_envelope(timestamp=int(time.time()))
        age = e.age_seconds()
        assert 0 <= age < 5      # should be almost zero

    def test_age_seconds_old_envelope(self):
        old_ts = int(time.time()) - 1000
        e = _make_envelope(timestamp=old_ts)
        assert e.age_seconds() > 999

    def test_age_seconds_future_envelope(self):
        """Future timestamp yields negative age (clock-skew scenario)."""
        future_ts = int(time.time()) + 30
        e = _make_envelope(timestamp=future_ts)
        assert e.age_seconds() < 0

    # ── is_fresh ──────────────────────────────────────────────────────────────

    def test_is_fresh_returns_true_for_new_envelope(self):
        e = _make_envelope()
        assert e.is_fresh() is True

    def test_is_fresh_returns_false_for_old_envelope(self):
        e = _make_envelope(timestamp=int(time.time()) - 9999)
        assert e.is_fresh() is False

    def test_is_fresh_future_within_skew_is_true(self):
        """Slightly future timestamp within clock_skew is accepted."""
        e = _make_envelope(timestamp=int(time.time()) + 20)
        assert e.is_fresh(clock_skew=30.0) is True

    def test_is_fresh_future_beyond_skew_is_false(self):
        e = _make_envelope(timestamp=int(time.time()) + 60)
        assert e.is_fresh(clock_skew=30.0) is False

    def test_is_fresh_negative_max_age_raises(self):
        e = _make_envelope()
        with pytest.raises(ValueError, match="non-negative"):
            e.is_fresh(max_age_seconds=-1.0)

    def test_is_fresh_negative_clock_skew_raises(self):
        e = _make_envelope()
        with pytest.raises(ValueError, match="non-negative"):
            e.is_fresh(clock_skew=-1.0)

    # ── assert_fresh ──────────────────────────────────────────────────────────

    def test_assert_fresh_passes_for_new_envelope(self):
        e = _make_envelope()
        e.assert_fresh()   # must not raise

    def test_assert_fresh_raises_for_old_envelope(self):
        e = _make_envelope(timestamp=int(time.time()) - 9999)
        with pytest.raises(EnvelopeExpiredError):
            e.assert_fresh()

    def test_assert_fresh_error_message_shows_age(self):
        e = _make_envelope(timestamp=int(time.time()) - 9999)
        with pytest.raises(EnvelopeExpiredError, match=r"\d+\.\d+s old"):
            e.assert_fresh()

    def test_assert_fresh_negative_max_age_raises_value_error(self):
        e = _make_envelope()
        with pytest.raises(ValueError, match="non-negative"):
            e.assert_fresh(max_age_seconds=-1.0)

    def test_assert_fresh_negative_clock_skew_raises_value_error(self):
        e = _make_envelope()
        with pytest.raises(ValueError, match="non-negative"):
            e.assert_fresh(clock_skew=-1.0)

    def test_assert_fresh_uses_single_age_capture(self):
        """
        The method captures age once and uses it in both the check and error
        message. Mock time.time to a stable value and verify consistency.
        """
        frozen_now = 1_700_000_000.0
        old_ts = int(frozen_now) - 9999
        e = _make_envelope(timestamp=old_ts)
        with patch("uxsp.core.envelope.time.time", return_value=frozen_now):
            with pytest.raises(EnvelopeExpiredError, match="9999"):
                e.assert_fresh()

    # ── addressed_to / sent_by ────────────────────────────────────────────────

    def test_addressed_to_correct_entity(self):
        e = _make_envelope(recipient_id="bob")
        assert e.addressed_to("bob") is True

    def test_addressed_to_wrong_entity(self):
        e = _make_envelope(recipient_id="bob")
        assert e.addressed_to("charlie") is False

    def test_sent_by_correct_entity(self):
        e = _make_envelope(sender_id="alice")
        assert e.sent_by("alice") is True

    def test_sent_by_wrong_entity(self):
        e = _make_envelope(sender_id="alice")
        assert e.sent_by("eve") is False


# ─────────────────────────────────────────────────────────────────────────────
# SIZE_BYTES PROPERTY  (Lines 280–286)
# ─────────────────────────────────────────────────────────────────────────────

class TestSizeBytesProperty:

    def test_size_bytes_computed_on_first_access(self):
        e = _make_envelope()
        assert e._size_bytes_cache is None
        sz = e.size_bytes
        assert sz > 0

    def test_size_bytes_cached_on_second_access(self):
        """Second access returns cached value without recomputing."""
        e = _make_envelope()
        # poison the to_json path so recomputation would differ — if cache is
        # used it never calls to_json again
        object.__setattr__(e, "_size_bytes_cache", 99999)
        sz2 = e.size_bytes
        assert sz2 == 99999

    def test_size_bytes_matches_actual_byte_len(self):
        e = _make_envelope()
        expected = len(e.to_json().encode("utf-8"))
        assert e.size_bytes == expected

    def test_size_bytes_populated_by_to_bytes(self):
        e = _make_envelope()
        raw = e.to_bytes()
        assert e._size_bytes_cache == len(raw)
        assert e.size_bytes == len(raw)   # now hits cached branch


# ─────────────────────────────────────────────────────────────────────────────
# _SAFE_PREFIX  (Lines 292–296)
# ─────────────────────────────────────────────────────────────────────────────

class TestSafePrefix:

    def test_non_string_returns_invalid(self):
        assert Envelope._safe_prefix(12345) == "<invalid>"

    def test_none_returns_invalid(self):
        assert Envelope._safe_prefix(None) == "<invalid>"

    def test_empty_string_returns_invalid(self):
        # len(val) == 0 → <invalid>
        assert Envelope._safe_prefix("") == "<invalid>"

    def test_short_string_no_ellipsis(self):
        # len("hi") <= 8 → no "..."
        assert Envelope._safe_prefix("hi") == "hi"

    def test_exactly_n_chars_no_ellipsis(self):
        assert Envelope._safe_prefix("12345678") == "12345678"

    def test_longer_string_gets_ellipsis(self):
        assert Envelope._safe_prefix("hello world") == "hello wo..."

    def test_custom_n(self):
        assert Envelope._safe_prefix("abcdef", n=3) == "abc..."

    def test_custom_n_exact_length(self):
        assert Envelope._safe_prefix("abc", n=3) == "abc"


# ─────────────────────────────────────────────────────────────────────────────
# __repr__  (Lines 298–306)
# ─────────────────────────────────────────────────────────────────────────────

class TestRepr:

    def test_repr_contains_from(self):
        e = _make_envelope(sender_id="alice")
        r = repr(e)
        assert "from=" in r

    def test_repr_contains_to(self):
        e = _make_envelope(recipient_id="bob")
        r = repr(e)
        assert "to=" in r

    def test_repr_contains_ts(self):
        e = _make_envelope()
        r = repr(e)
        assert "ts=" in r

    def test_repr_contains_nonce(self):
        e = _make_envelope()
        r = repr(e)
        assert "nonce=" in r

    def test_repr_contains_size(self):
        e = _make_envelope()
        r = repr(e)
        assert "size=" in r
        assert "B)" in r

    def test_repr_triggers_size_bytes_computation(self):
        e = _make_envelope()
        assert e._size_bytes_cache is None
        repr(e)
        assert e._size_bytes_cache is not None


# ─────────────────────────────────────────────────────────────────────────────
# __eq__  (Lines 308–316)
# ─────────────────────────────────────────────────────────────────────────────

class TestEquality:

    def test_equal_envelopes(self):
        d = _valid_dict()
        e1 = Envelope.from_dict(d)
        e2 = Envelope.from_dict(d)
        assert e1 == e2

    def test_not_equal_different_nonce(self):
        e1 = _make_envelope(envelope_nonce="nonce-A")
        e2 = _make_envelope(envelope_nonce="nonce-B")
        assert e1 != e2

    def test_not_equal_different_sender(self):
        e1 = _make_envelope(sender_id="alice", envelope_nonce="X")
        e2 = _make_envelope(sender_id="eve",   envelope_nonce="X")
        assert e1 != e2

    def test_not_equal_different_recipient(self):
        e1 = _make_envelope(recipient_id="bob",     envelope_nonce="X")
        e2 = _make_envelope(recipient_id="charlie", envelope_nonce="X")
        assert e1 != e2

    def test_not_equal_different_ciphertext(self):
        e1 = _make_envelope(ciphertext="ct1", envelope_nonce="X")
        e2 = _make_envelope(ciphertext="ct2", envelope_nonce="X")
        assert e1 != e2

    def test_not_equal_to_non_envelope(self):
        """isinstance check: returns False for non-Envelope objects."""
        e = _make_envelope()
        assert e != "not an envelope"
        assert e != 42
        assert e != None    # noqa: E711


# ─────────────────────────────────────────────────────────────────────────────
# __hash__  (Lines 318–319)
# ─────────────────────────────────────────────────────────────────────────────

class TestHash:

    def test_hash_is_int(self):
        e = _make_envelope()
        assert isinstance(hash(e), int)

    def test_equal_envelopes_same_hash(self):
        d = _valid_dict()
        e1 = Envelope.from_dict(d)
        e2 = Envelope.from_dict(d)
        assert hash(e1) == hash(e2)

    def test_envelope_usable_in_set(self):
        e1 = _make_envelope(envelope_nonce="n1")
        e2 = _make_envelope(envelope_nonce="n2")
        s = {e1, e2}
        assert len(s) == 2

    def test_envelope_usable_as_dict_key(self):
        e = _make_envelope()
        d = {e: "value"}
        assert d[e] == "value"

    def test_duplicate_envelopes_deduplicated_in_set(self):
        d = _valid_dict()
        e1 = Envelope.from_dict(d)
        e2 = Envelope.from_dict(d)
        assert len({e1, e2}) == 1


# ─────────────────────────────────────────────────────────────────────────────
# IMMUTABLE_FIELDS class-level frozenset  (Lines 104–108)
# ─────────────────────────────────────────────────────────────────────────────

class TestImmutableFieldsSet:

    def test_immutable_fields_is_frozenset(self):
        assert isinstance(Envelope._IMMUTABLE_FIELDS, frozenset)

    def test_immutable_fields_contains_all_envelope_fields(self):
        expected = {
            "version", "sender_id", "recipient_id", "timestamp",
            "envelope_nonce", "ciphertext", "nonce", "ephemeral_pub",
            "kem_ciphertext", "classical_sig", "pqc_sig",
        }
        assert expected == Envelope._IMMUTABLE_FIELDS
