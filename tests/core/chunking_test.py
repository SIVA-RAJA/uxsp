"""
Pytest suite for chunking.py — 100 % line + branch coverage.

Every test is named after the exact concept / branch it exercises so
failures are self-documenting.  No test is written merely to satisfy the
code; each verifies the *behaviour* the code is supposed to implement.

Run:
    pip install pytest
    pytest test_chunking.py -v --tb=short
"""

from __future__ import annotations

import hashlib
import json
import sys
import uuid

import pytest

# ── module under test ──────────────────────────────────────────────────────
from uxsp.core.chunking import (
    _HEADER_LEN_BYTES,
    _MAGIC,
    _MAX_HEADER_LEN,
    ChunkFormatError,
    ChunkValidationError,
    UXSPChunk,
    _require_non_negative_int,
    _sha256_hex,
    _validate_sha256_hex,
    create_chunked_text,
    create_chunked_transfer,
    decode_chunked_text,
    reassemble_chunked_transfer,
)

# ══════════════════════════════════════════════════════════════════════════════
# Helpers shared across tests
# ══════════════════════════════════════════════════════════════════════════════

_VALID_HEX64 = "a" * 64          # valid 64-char hex string
_VALID_HEX64_UPPER = "A" * 64    # uppercase variant — must be normalised to lower


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_valid_chunk(
    body: bytes = b"hello",
    kind: str = "binary",
    chunk_index: int = 0,
    total_chunks: int = 1,
    filename: str | None = None,
    content_type: str = "application/octet-stream",
    encoding: str | None = None,
) -> UXSPChunk:
    """Build a minimal, always-valid UXSPChunk."""
    file_hash = _sha256(body)
    chunk_hash = _sha256(body)
    return UXSPChunk(
        transfer_id=uuid.uuid4().hex,
        chunk_index=chunk_index,
        total_chunks=total_chunks,
        file_hash_sha256=file_hash,
        chunk_hash_sha256=chunk_hash,
        kind=kind,          # type: ignore[arg-type]
        body=body,
        filename=filename,
        content_type=content_type,
        encoding=encoding,
    )


def _tamper_header(packed: bytes, **overrides) -> bytes:
    """
    Unpack a serialised chunk, apply *overrides* to the JSON header dict,
    repack with the original body.  The chunk hash is intentionally NOT
    recomputed so callers can test hash-mismatch paths; pass
    recompute_chunk_hash=True to get a structurally valid tampered chunk.
    """
    recompute = overrides.pop("recompute_chunk_hash", False)
    magic_len = len(_MAGIC)
    header_len = int.from_bytes(packed[magic_len : magic_len + _HEADER_LEN_BYTES], "big")
    header_start = magic_len + _HEADER_LEN_BYTES
    header_end = header_start + header_len
    header = json.loads(packed[header_start:header_end])
    body = packed[header_end:]

    header.update(overrides)
    if recompute:
        header["chunk_hash_sha256"] = _sha256(body)

    new_header_raw = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode()
    new_header_len = len(new_header_raw)
    return (
        _MAGIC
        + new_header_len.to_bytes(_HEADER_LEN_BYTES, "big")
        + new_header_raw
        + body
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. _sha256_hex  (line 50-51)
# ══════════════════════════════════════════════════════════════════════════════

class TestSha256Hex:
    def test_bytes_input(self):
        assert _sha256_hex(b"abc") == hashlib.sha256(b"abc").hexdigest()

    def test_bytearray_input(self):
        # line 51: bytearray must also be accepted
        assert _sha256_hex(bytearray(b"abc")) == hashlib.sha256(b"abc").hexdigest()

    def test_empty_bytes(self):
        assert _sha256_hex(b"") == hashlib.sha256(b"").hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# 2. _validate_sha256_hex  (lines 54-68)
# ══════════════════════════════════════════════════════════════════════════════

class TestValidateSha256Hex:
    # line 60-61: non-string input
    def test_non_string_raises(self):
        with pytest.raises(ChunkValidationError, match="must be a string"):
            _validate_sha256_hex(12345, "fld")

    def test_none_raises(self):
        with pytest.raises(ChunkValidationError, match="must be a string"):
            _validate_sha256_hex(None, "fld")

    # line 62-63: wrong length
    def test_too_short_raises(self):
        with pytest.raises(ChunkValidationError, match="64-char"):
            _validate_sha256_hex("abc", "fld")

    def test_too_long_raises(self):
        with pytest.raises(ChunkValidationError, match="64-char"):
            _validate_sha256_hex("a" * 65, "fld")

    # line 64-67: invalid hex chars (bytes.fromhex raises ValueError)
    def test_invalid_hex_chars_raises(self):
        with pytest.raises(ChunkValidationError, match="valid hex"):
            _validate_sha256_hex("g" * 64, "fld")   # 'g' is not hex

    # line 68: returns lowercased value
    def test_returns_lowercase(self):
        result = _validate_sha256_hex("A" * 64, "fld")
        assert result == "a" * 64

    def test_valid_lowercase_passthrough(self):
        val = "deadbeef" * 8   # 64 chars, valid hex
        assert _validate_sha256_hex(val, "fld") == val


# ══════════════════════════════════════════════════════════════════════════════
# 3. _require_non_negative_int  (lines 70-77)
# ══════════════════════════════════════════════════════════════════════════════

class TestRequireNonNegativeInt:
    # line 73-74: bool is rejected (bool is subclass of int, must be caught first)
    def test_true_raises(self):
        with pytest.raises(ChunkValidationError, match="must be an int"):
            _require_non_negative_int(True, "fld")

    def test_false_raises(self):
        with pytest.raises(ChunkValidationError, match="must be an int"):
            _require_non_negative_int(False, "fld")

    # line 73-74: non-int type
    def test_string_raises(self):
        with pytest.raises(ChunkValidationError, match="must be an int"):
            _require_non_negative_int("3", "fld")

    def test_none_raises(self):
        with pytest.raises(ChunkValidationError, match="must be an int"):
            _require_non_negative_int(None, "fld")

    def test_float_raises(self):
        with pytest.raises(ChunkValidationError, match="must be an int"):
            _require_non_negative_int(1.0, "fld")

    # line 75-76: negative int
    def test_negative_raises(self):
        with pytest.raises(ChunkValidationError, match="non-negative"):
            _require_non_negative_int(-1, "fld")

    # line 77: valid return
    def test_zero_is_valid(self):
        assert _require_non_negative_int(0, "fld") == 0

    def test_positive_is_valid(self):
        assert _require_non_negative_int(42, "fld") == 42


# ══════════════════════════════════════════════════════════════════════════════
# 4. UXSPChunk.__post_init__  (lines 109-113)
# ══════════════════════════════════════════════════════════════════════════════

class TestUXSPChunkPostInit:
    def test_valid_chunk_created(self):
        c = _make_valid_chunk()
        assert len(c.file_hash_sha256) == 64
        assert len(c.chunk_hash_sha256) == 64

    # __post_init__ normalises uppercase hex to lowercase (line 113)
    def test_uppercase_hash_normalised(self):
        body = b"data"
        h = _sha256(body).upper()
        c = UXSPChunk(
            transfer_id="tid",
            chunk_index=0,
            total_chunks=1,
            file_hash_sha256=h,
            chunk_hash_sha256=h,
            kind="binary",
            body=body,
        )
        assert c.file_hash_sha256 == h.lower()
        assert c.chunk_hash_sha256 == h.lower()

    # __post_init__ raises ChunkValidationError for invalid hash (via _validate_sha256_hex)
    def test_invalid_file_hash_raises(self):
        with pytest.raises(ChunkValidationError):
            UXSPChunk(
                transfer_id="tid",
                chunk_index=0,
                total_chunks=1,
                file_hash_sha256="not-a-hash",
                chunk_hash_sha256=_sha256(b"x"),
                kind="binary",
                body=b"x",
            )

    def test_invalid_chunk_hash_raises(self):
        h = _sha256(b"x")
        with pytest.raises(ChunkValidationError):
            UXSPChunk(
                transfer_id="tid",
                chunk_index=0,
                total_chunks=1,
                file_hash_sha256=h,
                chunk_hash_sha256="ZZZZ",   # invalid
                kind="binary",
                body=b"x",
            )

    # non-string hash triggers the isinstance check inside _validate_sha256_hex
    def test_none_hash_raises(self):
        with pytest.raises(ChunkValidationError, match="must be a string"):
            UXSPChunk(
                transfer_id="tid",
                chunk_index=0,
                total_chunks=1,
                file_hash_sha256=None,      # type: ignore[arg-type]
                chunk_hash_sha256=_sha256(b"x"),
                kind="binary",
                body=b"x",
            )


class TestChunkingTypingExtensions:
    """Cover line 14 of chunking.py (Python < 3.11 fallback)."""

    def test_self_import_from_typing_extensions(self, monkeypatch):
        """
        Simulate Python 3.10 by temporarily replacing sys.version_info so
        the ``else`` branch (typing_extensions.Self) is taken.
        """
        # sys.version_info is not a namedtuple — patch with a simple tuple
        # whose first two elements compare as (3, 10) < (3, 11).
        fake_ver = (3, 10, 0, "final", 0)
        monkeypatch.setattr(sys, "version_info", fake_ver)

        # Remove cached module so it re-evaluates the if/else
        orig = sys.modules.pop("uxsp.core.chunking", None)
        try:
            import uxsp.core.chunking as chunking_mod
            # Self should be importable (typing_extensions provides it)
            assert hasattr(chunking_mod, "UXSPChunk")
        finally:
            sys.modules.pop("uxsp.core.chunking", None)
            if orig is not None:
                sys.modules["uxsp.core.chunking"] = orig
            else:
                import uxsp.core.chunking  # noqa: F401  restore


# ══════════════════════════════════════════════════════════════════════════════
# 5. UXSPChunk.to_bytes  (lines 119-143)
# ══════════════════════════════════════════════════════════════════════════════

class TestToBytes:
    def test_starts_with_magic(self):
        packed = _make_valid_chunk().to_bytes()
        assert packed.startswith(_MAGIC)

    def test_header_len_field_matches_actual_header(self):
        packed = _make_valid_chunk().to_bytes()
        magic_len = len(_MAGIC)
        stored_len = int.from_bytes(packed[magic_len : magic_len + _HEADER_LEN_BYTES], "big")
        header_start = magic_len + _HEADER_LEN_BYTES
        actual_header = packed[header_start : header_start + stored_len]
        header = json.loads(actual_header)
        assert isinstance(header, dict)

    def test_body_appended_correctly(self):
        body = b"payload-data"
        packed = _make_valid_chunk(body=body).to_bytes()
        assert packed.endswith(body)

    def test_optional_fields_in_header(self):
        c = _make_valid_chunk(filename="test.txt", encoding="utf-8")
        packed = c.to_bytes()
        magic_len = len(_MAGIC)
        h_len = int.from_bytes(packed[magic_len : magic_len + _HEADER_LEN_BYTES], "big")
        h_start = magic_len + _HEADER_LEN_BYTES
        header = json.loads(packed[h_start : h_start + h_len])
        assert header["filename"] == "test.txt"
        assert header["encoding"] == "utf-8"

    # line 134-137: header too large
    def test_oversized_header_raises(self):
        c = _make_valid_chunk()
        # We need to force to_bytes to produce a header > 64 KiB.
        # Easiest: patch content_type with huge string via object.__setattr__
        # since the dataclass is frozen.
        huge_ct = "x" * (_MAX_HEADER_LEN + 1)
        object.__setattr__(c, "content_type", huge_ct)
        with pytest.raises(ChunkValidationError, match="exceeds maximum"):
            c.to_bytes()


# ══════════════════════════════════════════════════════════════════════════════
# 6. UXSPChunk.from_bytes — format guards  (lines 149-178)
# ══════════════════════════════════════════════════════════════════════════════

class TestFromBytesFormatGuards:
    # line 152-153: non-bytes input
    def test_non_bytes_raises(self):
        with pytest.raises(ChunkFormatError, match="bytes or bytearray"):
            UXSPChunk.from_bytes("string")  # type: ignore[arg-type]

    def test_int_raises(self):
        with pytest.raises(ChunkFormatError):
            UXSPChunk.from_bytes(42)        # type: ignore[arg-type]

    # line 154: bytearray is accepted
    def test_bytearray_accepted(self):
        packed = bytearray(_make_valid_chunk().to_bytes())
        c = UXSPChunk.from_bytes(packed)
        assert isinstance(c, UXSPChunk)

    # line 157-158: too short
    def test_too_short_raises(self):
        with pytest.raises(ChunkFormatError, match="too short"):
            UXSPChunk.from_bytes(b"tiny")

    # line 159-160: bad magic
    def test_bad_magic_raises(self):
        bad = b"BADMAGIC____" + b"\x00" * _HEADER_LEN_BYTES + b"{}"
        with pytest.raises(ChunkFormatError, match="magic"):
            UXSPChunk.from_bytes(bad)

    # line 164-167: declared header_len > _MAX_HEADER_LEN
    def test_declared_header_len_too_large_raises(self):
        # Build a packet where the 4-byte length field claims > 64 KiB
        oversized_len = (_MAX_HEADER_LEN + 1).to_bytes(_HEADER_LEN_BYTES, "big")
        raw = _MAGIC + oversized_len + b"x" * 10
        with pytest.raises(ChunkFormatError, match="exceeds maximum"):
            UXSPChunk.from_bytes(raw)

    # line 170-171: declared header_len extends beyond buffer
    def test_header_len_exceeds_buffer_raises(self):
        # claim header is 100 bytes but only provide 10 bytes of header data
        raw = _MAGIC + (100).to_bytes(_HEADER_LEN_BYTES, "big") + b"x" * 10
        with pytest.raises(ChunkFormatError, match="exceeds packed size"):
            UXSPChunk.from_bytes(raw)

    # line 173-176: invalid UTF-8 / invalid JSON in header
    def test_invalid_utf8_header_raises(self):
        invalid_utf8 = b"\xff\xfe"
        raw = _MAGIC + len(invalid_utf8).to_bytes(_HEADER_LEN_BYTES, "big") + invalid_utf8
        with pytest.raises(ChunkFormatError, match="encoding"):
            UXSPChunk.from_bytes(raw)

    def test_valid_utf8_but_invalid_json_raises(self):
        bad_json = b"not json at all"
        raw = _MAGIC + len(bad_json).to_bytes(_HEADER_LEN_BYTES, "big") + bad_json
        with pytest.raises(ChunkFormatError, match="encoding"):
            UXSPChunk.from_bytes(raw)

    # line 177-178: JSON root is not a dict (e.g. a JSON array)
    def test_json_array_header_raises(self):
        arr = json.dumps([1, 2, 3]).encode()
        raw = _MAGIC + len(arr).to_bytes(_HEADER_LEN_BYTES, "big") + arr
        with pytest.raises(ChunkFormatError, match="JSON object"):
            UXSPChunk.from_bytes(raw)


# ══════════════════════════════════════════════════════════════════════════════
# 7. UXSPChunk.from_bytes — validation guards  (lines 180-237)
# ══════════════════════════════════════════════════════════════════════════════

class TestFromBytesValidationGuards:
    """Each test tampers with exactly one header field via _tamper_header."""

    def _valid_packed(self, **kwargs) -> bytes:
        return _make_valid_chunk(**kwargs).to_bytes()

    # ── body_len ──────────────────────────────────────────────────────────
    # line 182: _require_non_negative_int called for body_len — bool rejected
    def test_body_len_bool_raises(self):
        packed = _tamper_header(self._valid_packed(), body_len=True, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="must be an int"):
            UXSPChunk.from_bytes(packed)

    # line 183-184: body_len doesn't match actual body length
    def test_body_len_mismatch_raises(self):
        packed = _tamper_header(self._valid_packed(), body_len=9999, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="body length mismatch"):
            UXSPChunk.from_bytes(packed)

    # line 182: negative body_len
    def test_body_len_negative_raises(self):
        packed = _tamper_header(self._valid_packed(), body_len=-1, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="non-negative"):
            UXSPChunk.from_bytes(packed)

    # ── kind ──────────────────────────────────────────────────────────────
    # line 186-188: unknown kind
    def test_invalid_kind_raises(self):
        packed = _tamper_header(self._valid_packed(), kind="unknown", recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="Invalid chunk kind"):
            UXSPChunk.from_bytes(packed)

    def test_kind_none_raises(self):
        packed = _tamper_header(self._valid_packed(), kind=None, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="Invalid chunk kind"):
            UXSPChunk.from_bytes(packed)

    # valid kinds all accepted
    @pytest.mark.parametrize("kind", ["file", "binary", "text"])
    def test_valid_kinds_accepted(self, kind):
        body = b"data"
        fh = _sha256(body)
        c = UXSPChunk(
            transfer_id="tid", chunk_index=0, total_chunks=1,
            file_hash_sha256=fh, chunk_hash_sha256=fh,
            kind=kind, body=body,  # type: ignore[arg-type]
        )
        packed = c.to_bytes()
        result = UXSPChunk.from_bytes(packed)
        assert result.kind == kind

    # ── filename ──────────────────────────────────────────────────────────
    # line 191-193: filename present but not a string
    def test_filename_non_string_raises(self):
        packed = _tamper_header(self._valid_packed(), filename=42, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="filename must be string"):
            UXSPChunk.from_bytes(packed)

    # filename=None is allowed (line 191: `if filename is not None` skips check)
    def test_filename_none_accepted(self):
        packed = _tamper_header(self._valid_packed(), filename=None, recompute_chunk_hash=True)
        c = UXSPChunk.from_bytes(packed)
        assert c.filename is None

    # filename as valid string
    def test_filename_string_accepted(self):
        packed = _tamper_header(self._valid_packed(), filename="f.bin", recompute_chunk_hash=True)
        c = UXSPChunk.from_bytes(packed)
        assert c.filename == "f.bin"

    # ── content_type ──────────────────────────────────────────────────────
    # line 195-197: missing content_type
    def test_content_type_missing_raises(self):
        # Remove content_type entirely from header
        base = self._valid_packed()
        magic_len = len(_MAGIC)
        h_len = int.from_bytes(base[magic_len : magic_len + _HEADER_LEN_BYTES], "big")
        h_start = magic_len + _HEADER_LEN_BYTES
        header = json.loads(base[h_start : h_start + h_len])
        body = base[h_start + h_len :]
        del header["content_type"]
        header["chunk_hash_sha256"] = _sha256(body)
        new_h = json.dumps(header, separators=(",", ":")).encode()
        packed = _MAGIC + len(new_h).to_bytes(_HEADER_LEN_BYTES, "big") + new_h + body
        with pytest.raises(ChunkValidationError, match="content_type"):
            UXSPChunk.from_bytes(packed)

    def test_content_type_empty_raises(self):
        packed = _tamper_header(self._valid_packed(), content_type="", recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="content_type"):
            UXSPChunk.from_bytes(packed)

    def test_content_type_non_string_raises(self):
        packed = _tamper_header(self._valid_packed(), content_type=123, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="content_type"):
            UXSPChunk.from_bytes(packed)

    # ── encoding ──────────────────────────────────────────────────────────
    # line 199-201: encoding present but not a string
    def test_encoding_non_string_raises(self):
        packed = _tamper_header(self._valid_packed(), encoding=99, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="encoding must be string"):
            UXSPChunk.from_bytes(packed)

    # line 203-204: encoding is empty string
    def test_encoding_empty_string_raises(self):
        packed = _tamper_header(self._valid_packed(), encoding="", recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="non-empty when present"):
            UXSPChunk.from_bytes(packed)

    # encoding=None: line 200 condition False, line 203 condition False — both skipped
    def test_encoding_none_accepted(self):
        packed = _tamper_header(self._valid_packed(), encoding=None, recompute_chunk_hash=True)
        c = UXSPChunk.from_bytes(packed)
        assert c.encoding is None

    # ── transfer_id ───────────────────────────────────────────────────────
    # line 206-208: empty transfer_id
    def test_transfer_id_empty_raises(self):
        packed = _tamper_header(self._valid_packed(), transfer_id="", recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="transfer_id"):
            UXSPChunk.from_bytes(packed)

    def test_transfer_id_non_string_raises(self):
        packed = _tamper_header(self._valid_packed(), transfer_id=None, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="transfer_id"):
            UXSPChunk.from_bytes(packed)

    # ── chunk_index ───────────────────────────────────────────────────────
    # line 210: bool chunk_index rejected
    def test_chunk_index_bool_raises(self):
        packed = _tamper_header(self._valid_packed(), chunk_index=False, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="must be an int"):
            UXSPChunk.from_bytes(packed)

    def test_chunk_index_negative_raises(self):
        # chunk_index negative: _require_non_negative_int raises
        packed = _tamper_header(self._valid_packed(), chunk_index=-1, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="non-negative"):
            UXSPChunk.from_bytes(packed)

    # ── total_chunks ──────────────────────────────────────────────────────
    # line 211-213: total_chunks = 0
    def test_total_chunks_zero_raises(self):
        packed = _tamper_header(self._valid_packed(), total_chunks=0, chunk_index=0,
                                recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="positive int"):
            UXSPChunk.from_bytes(packed)

    def test_total_chunks_bool_raises(self):
        packed = _tamper_header(self._valid_packed(), total_chunks=True, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="must be an int"):
            UXSPChunk.from_bytes(packed)

    # ── chunk_index >= total_chunks ───────────────────────────────────────
    # line 215-218
    def test_chunk_index_equals_total_raises(self):
        packed = _tamper_header(self._valid_packed(), chunk_index=1, total_chunks=1,
                                recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="cannot be >="):
            UXSPChunk.from_bytes(packed)

    def test_chunk_index_greater_than_total_raises(self):
        packed = _tamper_header(self._valid_packed(), chunk_index=5, total_chunks=3,
                                recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="cannot be >="):
            UXSPChunk.from_bytes(packed)

    # ── file_hash / chunk_hash ────────────────────────────────────────────
    # line 220-221: invalid file_hash_sha256
    def test_invalid_file_hash_raises(self):
        packed = _tamper_header(self._valid_packed(), file_hash_sha256="ZZ" * 32,
                                recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="valid hex"):
            UXSPChunk.from_bytes(packed)

    def test_file_hash_wrong_length_raises(self):
        packed = _tamper_header(self._valid_packed(), file_hash_sha256="ab" * 10,
                                recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="64-char"):
            UXSPChunk.from_bytes(packed)

    # line 223-224: body hash mismatch (chunk_hash doesn't match body)
    def test_body_hash_mismatch_raises(self):
        # Provide a syntactically valid but wrong chunk_hash_sha256
        wrong_hash = "deadbeef" * 8   # valid hex64 but wrong
        packed = _tamper_header(
            self._valid_packed(),
            chunk_hash_sha256=wrong_hash,
            file_hash_sha256=wrong_hash,    # keep file_hash valid hex too
            # do NOT recompute — we want the mismatch
        )
        with pytest.raises(ChunkValidationError, match="hash mismatch"):
            UXSPChunk.from_bytes(packed)

    # ── happy path roundtrip ──────────────────────────────────────────────
    def test_roundtrip_all_fields(self):
        body = b"roundtrip test body"
        h = _sha256(body)
        c = UXSPChunk(
            transfer_id="myid",
            chunk_index=0,
            total_chunks=1,
            file_hash_sha256=h,
            chunk_hash_sha256=h,
            kind="file",
            body=body,
            filename="f.dat",
            content_type="application/octet-stream",
            encoding="utf-8",
        )
        recovered = UXSPChunk.from_bytes(c.to_bytes())
        assert recovered.transfer_id == "myid"
        assert recovered.body == body
        assert recovered.filename == "f.dat"
        assert recovered.encoding == "utf-8"
        assert recovered.kind == "file"


# ══════════════════════════════════════════════════════════════════════════════
# 8. create_chunked_transfer  (lines 245-297)
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateChunkedTransfer:
    # line 264-265: non-bytes data
    def test_non_bytes_raises(self):
        with pytest.raises(ChunkValidationError, match="bytes or bytearray"):
            create_chunked_transfer("string")  # type: ignore[arg-type]

    def test_list_raises(self):
        with pytest.raises(ChunkValidationError):
            create_chunked_transfer([1, 2, 3])  # type: ignore[arg-type]

    # line 266-267: chunk_size <= 0
    def test_zero_chunk_size_raises(self):
        with pytest.raises(ChunkValidationError, match="chunk_size must be positive"):
            create_chunked_transfer(b"data", chunk_size=0)

    def test_negative_chunk_size_raises(self):
        with pytest.raises(ChunkValidationError, match="chunk_size must be positive"):
            create_chunked_transfer(b"data", chunk_size=-1)

    # line 274-275: empty data → exactly one chunk with empty body
    def test_empty_data_produces_one_chunk(self):
        result = create_chunked_transfer(b"")
        assert len(result) == 1
        c = UXSPChunk.from_bytes(result[0])
        assert c.body == b""
        assert c.chunk_index == 0
        assert c.total_chunks == 1

    # line 276-277: non-empty data → correct chunk count
    def test_single_chunk_for_small_data(self):
        result = create_chunked_transfer(b"hello", chunk_size=1024)
        assert len(result) == 1

    def test_multiple_chunks_for_large_data(self):
        data = b"x" * 100
        result = create_chunked_transfer(data, chunk_size=30)
        # ceil(100/30) = 4 chunks
        assert len(result) == 4

    def test_exact_multiple_chunk_size(self):
        data = b"a" * 60
        result = create_chunked_transfer(data, chunk_size=20)
        assert len(result) == 3

    # bytearray input accepted (line 264 isinstance check)
    def test_bytearray_accepted(self):
        result = create_chunked_transfer(bytearray(b"abc"))
        assert len(result) == 1

    # all optional params flow through
    def test_optional_params_flow_into_chunks(self):
        result = create_chunked_transfer(
            b"payload",
            kind="file",
            filename="test.bin",
            content_type="application/pdf",
            encoding="utf-8",
        )
        c = UXSPChunk.from_bytes(result[0])
        assert c.kind == "file"
        assert c.filename == "test.bin"
        assert c.content_type == "application/pdf"
        assert c.encoding == "utf-8"

    # transfer_id is consistent across all chunks
    def test_transfer_id_consistent_across_chunks(self):
        data = b"y" * 200
        result = create_chunked_transfer(data, chunk_size=50)
        ids = {UXSPChunk.from_bytes(p).transfer_id for p in result}
        assert len(ids) == 1   # all same

    # file_hash is consistent across chunks
    def test_file_hash_consistent_across_chunks(self):
        data = b"z" * 200
        result = create_chunked_transfer(data, chunk_size=50)
        hashes = {UXSPChunk.from_bytes(p).file_hash_sha256 for p in result}
        assert len(hashes) == 1
        assert list(hashes)[0] == _sha256(data)

    # each chunk has a correct per-chunk hash
    def test_per_chunk_hash_is_correct(self):
        data = b"a" * 100
        result = create_chunked_transfer(data, chunk_size=40)
        for packed in result:
            c = UXSPChunk.from_bytes(packed)
            assert c.chunk_hash_sha256 == _sha256(c.body)

    # chunk_index and total_chunks are correct
    def test_chunk_indices_are_sequential(self):
        data = b"m" * 90
        result = create_chunked_transfer(data, chunk_size=30)
        chunks = [UXSPChunk.from_bytes(p) for p in result]
        assert [c.chunk_index for c in chunks] == [0, 1, 2]
        assert all(c.total_chunks == 3 for c in chunks)


# ══════════════════════════════════════════════════════════════════════════════
# 9. reassemble_chunked_transfer  (lines 300-362)
# ══════════════════════════════════════════════════════════════════════════════

class TestReassembleChunkedTransfer:
    # line 309-310: empty list
    def test_empty_list_raises(self):
        with pytest.raises(ChunkValidationError, match="No chunks"):
            reassemble_chunked_transfer([])

    # happy path: single chunk
    def test_single_chunk_roundtrip(self):
        data = b"single"
        packed = create_chunked_transfer(data)
        meta, assembled = reassemble_chunked_transfer(packed)
        assert assembled == data
        assert meta["kind"] == "binary"

    # happy path: multiple chunks, fed in reverse order (out-of-order reassembly)
    def test_out_of_order_chunks_reassembled(self):
        data = b"abc" * 50   # 150 bytes
        packed = create_chunked_transfer(data, chunk_size=50)
        shuffled = list(reversed(packed))
        meta, assembled = reassemble_chunked_transfer(shuffled)
        assert assembled == data

    # line 325-326: transfer_id mismatch
    def test_transfer_id_mismatch_raises(self):
        p1 = create_chunked_transfer(b"a" * 50, chunk_size=25)
        p2 = create_chunked_transfer(b"b" * 50, chunk_size=25)
        # Mix first chunk of p1 with first chunk of p2 (different transfer_ids)
        mixed = [p1[0], p2[0]]
        with pytest.raises(ChunkValidationError, match="transfer_id mismatch"):
            reassemble_chunked_transfer(mixed)

    # line 327-328: total_chunks mismatch — forge a chunk with different total_chunks
    def test_total_chunks_mismatch_raises(self):
        data = b"x" * 60
        packed = create_chunked_transfer(data, chunk_size=30)  # 2 chunks, total=2
        forged = _tamper_header(packed[1], total_chunks=99, recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="total_chunks mismatch"):
            reassemble_chunked_transfer([packed[0], forged])

    # line 329-330: file_hash_sha256 mismatch
    def test_file_hash_mismatch_raises(self):
        data = b"x" * 60
        packed = create_chunked_transfer(data, chunk_size=30)
        forged = _tamper_header(packed[1], file_hash_sha256="ab" * 32,
                                recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="file_hash_sha256 mismatch"):
            reassemble_chunked_transfer([packed[0], forged])

    # line 331-337: kind mismatch
    def test_kind_mismatch_raises(self):
        data = b"x" * 60
        packed = create_chunked_transfer(data, chunk_size=30)
        forged = _tamper_header(packed[1], kind="file", recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="metadata mismatch"):
            reassemble_chunked_transfer([packed[0], forged])

    # content_type mismatch (same line 331-337 compound condition)
    def test_content_type_mismatch_raises(self):
        data = b"x" * 60
        packed = create_chunked_transfer(data, chunk_size=30)
        forged = _tamper_header(packed[1], content_type="text/html", recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="metadata mismatch"):
            reassemble_chunked_transfer([packed[0], forged])

    # filename mismatch (same compound condition)
    def test_filename_mismatch_raises(self):
        data = b"x" * 60
        packed = create_chunked_transfer(data, chunk_size=30, filename="a.bin")
        forged = _tamper_header(packed[1], filename="b.bin", recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="metadata mismatch"):
            reassemble_chunked_transfer([packed[0], forged])

    # encoding mismatch (same compound condition)
    def test_encoding_mismatch_raises(self):
        data = b"x" * 60
        packed = create_chunked_transfer(data, chunk_size=30, encoding="utf-8")
        forged = _tamper_header(packed[1], encoding="latin-1", recompute_chunk_hash=True)
        with pytest.raises(ChunkValidationError, match="metadata mismatch"):
            reassemble_chunked_transfer([packed[0], forged])

    # line 340-341: duplicate chunk_index
    def test_duplicate_chunk_index_raises(self):
        data = b"x" * 60
        packed = create_chunked_transfer(data, chunk_size=30)  # 2 chunks: idx 0, idx 1
        # Send chunk 0 twice
        with pytest.raises(ChunkValidationError, match="Duplicate chunk_index"):
            reassemble_chunked_transfer([packed[0], packed[0]])

    # line 342-345: wrong number of chunks (missing one)
    def test_missing_chunk_raises(self):
        data = b"x" * 90
        packed = create_chunked_transfer(data, chunk_size=30)  # 3 chunks
        with pytest.raises(ChunkValidationError, match="Chunk count mismatch"):
            reassemble_chunked_transfer(packed[:2])   # only 2 of 3

    # line 350-351: file hash mismatch after assembly
    def test_assembled_hash_mismatch_raises(self):
        data = b"x" * 60
        create_chunked_transfer(data, chunk_size=30)
        # Corrupt chunk 1's body after it passes from_bytes (impossible via normal API);
        # instead forge a chunk whose body is different but chunk_hash matches body,
        # while file_hash is forged to match.
        # Easiest: use two separate independent transfers and steal a chunk.
        # p2[0] has a different file_hash, so file_hash_mismatch fires — not what we want.
        # To hit the ASSEMBLED hash check we need chunks that individually pass
        # per-chunk validation but whose concatenated hash != file_hash.
        # We construct that manually.
        body_a = b"A" * 30
        body_b = b"B" * 30
        fake_file_hash = "ff" * 32   # wrong assembled hash, but valid hex64

        chunk_a = UXSPChunk(
            transfer_id="tid",
            chunk_index=0,
            total_chunks=2,
            file_hash_sha256=fake_file_hash,
            chunk_hash_sha256=_sha256(body_a),
            kind="binary",
            body=body_a,
        )
        chunk_b = UXSPChunk(
            transfer_id="tid",
            chunk_index=1,
            total_chunks=2,
            file_hash_sha256=fake_file_hash,
            chunk_hash_sha256=_sha256(body_b),
            kind="binary",
            body=body_b,
        )
        with pytest.raises(ChunkValidationError, match="Reassembled file hash mismatch"):
            reassemble_chunked_transfer([chunk_a.to_bytes(), chunk_b.to_bytes()])

    # line 353-362: returned meta dict keys
    def test_meta_dict_keys(self):
        data = b"meta test"
        packed = create_chunked_transfer(data, kind="file", filename="f.bin",
                                         content_type="application/pdf", encoding="utf-8")
        meta, assembled = reassemble_chunked_transfer(packed)
        assert assembled == data
        assert set(meta.keys()) == {
            "transfer_id", "total_chunks", "kind", "filename",
            "content_type", "encoding", "file_hash_sha256"
        }
        assert meta["kind"] == "file"
        assert meta["filename"] == "f.bin"
        assert meta["content_type"] == "application/pdf"
        assert meta["encoding"] == "utf-8"

    # empty data roundtrip
    def test_empty_data_roundtrip(self):
        packed = create_chunked_transfer(b"")
        meta, assembled = reassemble_chunked_transfer(packed)
        assert assembled == b""


# ══════════════════════════════════════════════════════════════════════════════
# 10. create_chunked_text  (lines 370-392)
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateChunkedText:
    # line 377-378: non-string text
    def test_non_string_raises(self):
        with pytest.raises(ChunkValidationError, match="must be a str"):
            create_chunked_text(b"bytes")  # type: ignore[arg-type]

    def test_int_raises(self):
        with pytest.raises(ChunkValidationError, match="must be a str"):
            create_chunked_text(123)  # type: ignore[arg-type]

    # line 379-380: empty encoding string
    def test_empty_encoding_raises(self):
        with pytest.raises(ChunkValidationError, match="non-empty string"):
            create_chunked_text("hello", encoding="")

    # line 381-384: invalid encoding name → LookupError → ChunkValidationError
    def test_invalid_encoding_raises(self):
        with pytest.raises(ChunkValidationError, match="Invalid encoding"):
            create_chunked_text("hello", encoding="not-a-real-encoding")

    # line 385-392: happy path
    def test_basic_text_chunked(self):
        result = create_chunked_text("Hello, World!")
        assert len(result) == 1
        c = UXSPChunk.from_bytes(result[0])
        assert c.kind == "text"
        assert c.content_type == "text/plain"
        assert c.encoding == "utf-8"
        assert c.filename is None

    def test_latin1_encoding(self):
        result = create_chunked_text("café", encoding="latin-1")
        c = UXSPChunk.from_bytes(result[0])
        assert c.encoding == "latin-1"
        assert c.body == "café".encode("latin-1")

    def test_small_chunk_size_produces_multiple_chunks(self):
        text = "a" * 100
        result = create_chunked_text(text, chunk_size=10)
        assert len(result) == 10

    def test_empty_text_produces_one_chunk(self):
        result = create_chunked_text("")
        assert len(result) == 1
        c = UXSPChunk.from_bytes(result[0])
        assert c.body == b""


# ══════════════════════════════════════════════════════════════════════════════
# 11. decode_chunked_text  (lines 395-404)
# ══════════════════════════════════════════════════════════════════════════════

class TestDecodeChunkedText:
    # line 398-399: not a text transfer
    def test_non_text_kind_raises(self):
        packed = create_chunked_transfer(b"data", kind="binary")
        with pytest.raises(ChunkValidationError, match="Not a text"):
            decode_chunked_text(packed)

    def test_file_kind_raises(self):
        packed = create_chunked_transfer(b"data", kind="file")
        with pytest.raises(ChunkValidationError, match="Not a text"):
            decode_chunked_text(packed)

    # line 400: enc = meta.get("encoding") or "utf-8"
    # When encoding is None (which shouldn't happen in normal flow but
    # the code uses `.get("encoding") or "utf-8"` defensively), fallback to utf-8
    def test_encoding_none_falls_back_to_utf8(self):
        # Build a text transfer but strip encoding out of meta by creating
        # chunk directly with encoding=None, kind="text"
        body = b"hello"
        h = _sha256(body)
        c = UXSPChunk(
            transfer_id="tid", chunk_index=0, total_chunks=1,
            file_hash_sha256=h, chunk_hash_sha256=h,
            kind="text", body=body,
            content_type="text/plain", encoding=None,
        )
        result = decode_chunked_text([c.to_bytes()])
        assert result == "hello"

    # line 401-402: happy path decode
    def test_basic_decode(self):
        text = "Hello, 世界"
        packed = create_chunked_text(text, encoding="utf-8")
        assert decode_chunked_text(packed) == text

    def test_latin1_decode(self):
        text = "café"
        packed = create_chunked_text(text, encoding="latin-1")
        assert decode_chunked_text(packed) == text

    # line 403-404: UnicodeDecodeError path
    # Construct a "text" chunk with body that is NOT valid utf-8
    def test_bad_bytes_for_encoding_raises(self):
        body = b"\xff\xfe"   # invalid UTF-8
        h = _sha256(body)
        c = UXSPChunk(
            transfer_id="tid", chunk_index=0, total_chunks=1,
            file_hash_sha256=h, chunk_hash_sha256=h,
            kind="text", body=body,
            content_type="text/plain", encoding="utf-8",
        )
        with pytest.raises(ChunkValidationError, match="Failed to decode"):
            decode_chunked_text([c.to_bytes()])

    # multiple chunk text roundtrip
    def test_multi_chunk_text_roundtrip(self):
        text = "abc" * 5000   # 15000 chars
        packed = create_chunked_text(text, chunk_size=1000)
        assert len(packed) > 1
        assert decode_chunked_text(packed) == text


# ══════════════════════════════════════════════════════════════════════════════
# 12. Exception hierarchy  (lines 33-42)
# ══════════════════════════════════════════════════════════════════════════════

class TestExceptionHierarchy:
    def test_chunk_format_error_is_chunking_error(self):
        from uxsp.core.chunking import ChunkingError
        assert issubclass(ChunkFormatError, ChunkingError)

    def test_chunk_validation_error_is_chunking_error(self):
        from uxsp.core.chunking import ChunkingError
        assert issubclass(ChunkValidationError, ChunkingError)

    def test_chunking_error_is_exception(self):
        from uxsp.core.chunking import ChunkingError
        assert issubclass(ChunkingError, Exception)


# ══════════════════════════════════════════════════════════════════════════════
# 13. Module-level constants  (lines 20-25)
# ══════════════════════════════════════════════════════════════════════════════

class TestModuleConstants:
    def test_valid_kinds_frozenset(self):
        from uxsp.core.chunking import _VALID_KINDS
        assert frozenset({"file", "binary", "text"}) == _VALID_KINDS

    def test_magic_bytes(self):
        assert _MAGIC == b"UXSP-CHUNK-1"

    def test_header_len_bytes(self):
        assert _HEADER_LEN_BYTES == 4

    def test_max_header_len(self):
        assert _MAX_HEADER_LEN == 64 * 1024
