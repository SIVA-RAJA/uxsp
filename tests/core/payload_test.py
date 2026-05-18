"""
Comprehensive pytest suite for payload.py
Covers every line / branch of the module.
"""
from __future__ import annotations

import json

import pytest

from uxsp.core.payload import (
    _HEADER_LEN_BYTES,
    _MAGIC,
    PayloadError,
    PayloadFormatError,
    PayloadValidationError,
    UXSPPayload,
    pack_binary,
    pack_file,
    pack_text,
    unpack_text,
    unpack_to_file,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _raw_payload(
    kind="text",
    body=b"hello",
    filename=None,
    content_type="text/plain",
    encoding="utf-8",
    body_len_override=None,
) -> bytes:
    """Build a raw payload bytes manually so we can inject corruption."""
    header: dict = {
        "kind": kind,
        "filename": filename,
        "content_type": content_type,
        "encoding": encoding,
        "body_len": body_len_override if body_len_override is not None else len(body),
    }
    header_raw = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode()
    return _MAGIC + len(header_raw).to_bytes(_HEADER_LEN_BYTES, "big") + header_raw + body


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    def test_payload_error_is_base(self):
        assert issubclass(PayloadFormatError, PayloadError)
        assert issubclass(PayloadValidationError, PayloadError)

    def test_payload_error_instantiable(self):
        e = PayloadError("base")
        assert str(e) == "base"


# ---------------------------------------------------------------------------
# UXSPPayload dataclass
# ---------------------------------------------------------------------------

class TestUXSPPayloadDataclass:
    def test_default_content_type(self):
        p = UXSPPayload(kind="binary", body=b"\x00")
        assert p.content_type == "application/octet-stream"
        assert p.filename is None
        assert p.encoding is None

    def test_frozen(self):
        p = UXSPPayload(kind="text", body=b"x")
        with pytest.raises((AttributeError, TypeError)):
            p.kind = "binary"  # type: ignore[misc]

    def test_round_trip(self):
        original = UXSPPayload(
            kind="file",
            body=b"data",
            filename="report.pdf",
            content_type="application/pdf",
            encoding=None,
        )
        restored = UXSPPayload.from_bytes(original.to_bytes())
        assert restored == original


# ---------------------------------------------------------------------------
# UXSPPayload.to_bytes
# ---------------------------------------------------------------------------

class TestToBytes:
    def test_magic_prefix(self):
        raw = UXSPPayload(kind="text", body=b"x").to_bytes()
        assert raw.startswith(_MAGIC)

    def test_header_len_field(self):
        raw = UXSPPayload(kind="text", body=b"x").to_bytes()
        idx = len(_MAGIC)
        header_len = int.from_bytes(raw[idx : idx + _HEADER_LEN_BYTES], "big")
        header_end = idx + _HEADER_LEN_BYTES + header_len
        header = json.loads(raw[idx + _HEADER_LEN_BYTES : header_end])
        assert header["kind"] == "text"
        assert header["body_len"] == 1

    def test_body_appended(self):
        body = b"PAYLOAD"
        raw = UXSPPayload(kind="binary", body=body).to_bytes()
        assert raw.endswith(body)

    def test_header_too_large_raises(self, monkeypatch):
        """Force header_len > 0xFFFFFFFF to hit the overflow guard."""
        p = UXSPPayload(kind="text", body=b"x")

        class FakeBytes:
            def __len__(self):
                return 0xFFFFFFFF + 1

        class FakeString:
            def encode(self, *args, **kwargs):
                return FakeBytes()

        def big_dumps(*args, **kwargs):
            return FakeString()

        monkeypatch.setattr("uxsp.core.payload.json.dumps", big_dumps)
        with pytest.raises(PayloadValidationError, match="header too large"):
            p.to_bytes()


# ---------------------------------------------------------------------------
# UXSPPayload.from_bytes — format errors
# ---------------------------------------------------------------------------

class TestFromBytesFormatErrors:
    def test_not_bytes_raises(self):
        with pytest.raises(PayloadFormatError, match="must be bytes"):
            UXSPPayload.from_bytes("not bytes")  # type: ignore[arg-type]

    def test_too_short_raises(self):
        with pytest.raises(PayloadFormatError, match="too short"):
            UXSPPayload.from_bytes(b"\x00")

    def test_wrong_magic_raises(self):
        bad = b"WRONG-MAGIC-XXXX" + b"\x00" * 20
        with pytest.raises(PayloadFormatError, match="magic"):
            UXSPPayload.from_bytes(bad)

    def test_header_len_exceeds_buffer(self):
        # Claim a header of 9999 bytes but provide no actual header bytes.
        raw = _MAGIC + (9999).to_bytes(_HEADER_LEN_BYTES, "big")
        with pytest.raises(PayloadFormatError, match="exceeds payload size"):
            UXSPPayload.from_bytes(raw)

    def test_bad_utf8_header(self):
        header_bytes = b"\xff\xfe"  # invalid UTF-8
        raw = _MAGIC + len(header_bytes).to_bytes(_HEADER_LEN_BYTES, "big") + header_bytes
        with pytest.raises(PayloadFormatError, match="encoding"):
            UXSPPayload.from_bytes(raw)

    def test_header_not_json_object(self):
        # Valid JSON but not a dict (e.g. a list)
        header_bytes = b"[1,2,3]"
        raw = _MAGIC + len(header_bytes).to_bytes(_HEADER_LEN_BYTES, "big") + header_bytes
        with pytest.raises(PayloadFormatError, match="JSON object"):
            UXSPPayload.from_bytes(raw)

    def test_invalid_json_header(self):
        header_bytes = b"not-json!!!"
        raw = _MAGIC + len(header_bytes).to_bytes(_HEADER_LEN_BYTES, "big") + header_bytes
        with pytest.raises(PayloadFormatError, match="encoding"):
            UXSPPayload.from_bytes(raw)


# ---------------------------------------------------------------------------
# UXSPPayload.from_bytes — validation errors
# ---------------------------------------------------------------------------

class TestFromBytesValidationErrors:
    def test_body_len_missing(self):
        raw = _raw_payload()
        # Patch header to remove body_len
        UXSPPayload.from_bytes(raw)
        # Re-build manually without body_len
        header = {"kind": "text", "filename": None, "content_type": "text/plain", "encoding": "utf-8"}
        hb = json.dumps(header).encode()
        bad = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + b"hello"
        with pytest.raises(PayloadValidationError, match="body_len"):
            UXSPPayload.from_bytes(bad)

    def test_body_len_bool(self):
        """bool is a subclass of int, must be rejected."""
        header = {
            "kind": "text", "filename": None,
            "content_type": "text/plain", "encoding": "utf-8", "body_len": True,
        }
        hb = json.dumps(header).encode()
        raw = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + b"x"
        with pytest.raises(PayloadValidationError, match="body_len"):
            UXSPPayload.from_bytes(raw)

    def test_body_len_negative(self):
        header = {
            "kind": "text", "filename": None,
            "content_type": "text/plain", "encoding": "utf-8", "body_len": -1,
        }
        hb = json.dumps(header).encode()
        raw = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + b""
        with pytest.raises(PayloadValidationError, match="body_len"):
            UXSPPayload.from_bytes(raw)

    def test_body_len_mismatch(self):
        raw = _raw_payload(body=b"hello", body_len_override=99)
        with pytest.raises(PayloadValidationError, match="length mismatch"):
            UXSPPayload.from_bytes(raw)

    def test_invalid_kind(self):
        raw = _raw_payload(kind="image")
        with pytest.raises(PayloadValidationError, match="kind"):
            UXSPPayload.from_bytes(raw)

    def test_filename_not_string(self):
        header = {
            "kind": "file", "filename": 42,
            "content_type": "application/octet-stream", "encoding": None,
            "body_len": 3,
        }
        hb = json.dumps(header).encode()
        raw = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + b"abc"
        with pytest.raises(PayloadValidationError, match="filename"):
            UXSPPayload.from_bytes(raw)

    def test_content_type_empty(self):
        header = {
            "kind": "text", "filename": None,
            "content_type": "", "encoding": "utf-8", "body_len": 1,
        }
        hb = json.dumps(header).encode()
        raw = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + b"x"
        with pytest.raises(PayloadValidationError, match="content_type"):
            UXSPPayload.from_bytes(raw)

    def test_content_type_not_string(self):
        header = {
            "kind": "text", "filename": None,
            "content_type": 123, "encoding": "utf-8", "body_len": 1,
        }
        hb = json.dumps(header).encode()
        raw = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + b"x"
        with pytest.raises(PayloadValidationError, match="content_type"):
            UXSPPayload.from_bytes(raw)

    def test_encoding_empty_string(self):
        """encoding present but empty string must raise."""
        header = {
            "kind": "text", "filename": None,
            "content_type": "text/plain", "encoding": "", "body_len": 1,
        }
        hb = json.dumps(header).encode()
        raw = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + b"x"
        with pytest.raises(PayloadValidationError, match="encoding"):
            UXSPPayload.from_bytes(raw)

    def test_encoding_not_string(self):
        header = {
            "kind": "text", "filename": None,
            "content_type": "text/plain", "encoding": 99, "body_len": 1,
        }
        hb = json.dumps(header).encode()
        raw = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + b"x"
        with pytest.raises(PayloadValidationError, match="encoding"):
            UXSPPayload.from_bytes(raw)

    def test_encoding_null_is_valid(self):
        """None/null encoding is allowed for file/binary payloads."""
        raw = _raw_payload(kind="binary", encoding=None, body=b"\xde\xad")
        p = UXSPPayload.from_bytes(raw)
        assert p.encoding is None

    def test_filename_null_is_valid(self):
        raw = _raw_payload(kind="text", filename=None)
        p = UXSPPayload.from_bytes(raw)
        assert p.filename is None

    def test_bytearray_accepted(self):
        raw = _raw_payload()
        p = UXSPPayload.from_bytes(bytearray(raw))
        assert p.kind == "text"


# ---------------------------------------------------------------------------
# pack_text / unpack_text
# ---------------------------------------------------------------------------

class TestPackUnpackText:
    def test_round_trip_utf8(self):
        msg = "Hello, 世界!"
        assert unpack_text(pack_text(msg)) == msg

    def test_round_trip_latin1(self):
        msg = "caf\xe9"
        assert unpack_text(pack_text(msg, encoding="latin-1")) == msg

    def test_pack_text_not_string_raises(self):
        with pytest.raises(PayloadValidationError, match="must be a string"):
            pack_text(123)  # type: ignore[arg-type]

    def test_pack_text_empty_encoding_raises(self):
        with pytest.raises(PayloadValidationError, match="non-empty"):
            pack_text("hi", encoding="")

    def test_pack_text_unknown_encoding_raises(self):
        with pytest.raises(PayloadValidationError, match="Unknown encoding"):
            pack_text("hi", encoding="no-such-codec-xyz")

    def test_unpack_text_wrong_kind_raises(self):
        raw = _raw_payload(kind="binary", body=b"\x00", encoding=None)
        with pytest.raises(PayloadValidationError, match="Expected text payload"):
            unpack_text(raw)

    def test_unpack_text_missing_encoding_raises(self):
        raw = _raw_payload(kind="text", encoding=None, body=b"hi")
        with pytest.raises(PayloadValidationError, match="missing encoding"):
            unpack_text(raw)

    def test_unpack_text_bad_bytes_for_encoding(self):
        # Pack latin-1 bytes but claim ascii — decode will fail
        body = "café".encode("latin-1")          # b'\x63\x61\x66\xe9'
        header = {
            "kind": "text", "filename": None,
            "content_type": "text/plain", "encoding": "ascii", "body_len": len(body),
        }
        hb = json.dumps(header).encode()
        raw = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + body
        with pytest.raises(PayloadValidationError, match="not valid ascii"):
            unpack_text(raw)

    def test_pack_text_empty_string(self):
        assert unpack_text(pack_text("")) == ""


# ---------------------------------------------------------------------------
# pack_file / unpack_to_file
# ---------------------------------------------------------------------------

class TestPackFile:
    def test_pack_and_unpack_round_trip(self, tmp_path):
        src = tmp_path / "hello.txt"
        src.write_text("hello world")
        raw = pack_file(src)
        out = unpack_to_file(raw, tmp_path / "out")
        assert out.read_text() == "hello world"
        assert out.name == "hello.txt"

    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(PayloadValidationError, match="does not exist"):
            pack_file(tmp_path / "ghost.bin")

    def test_path_is_directory_raises(self, tmp_path):
        with pytest.raises(PayloadValidationError, match="does not exist"):
            pack_file(tmp_path)  # directory, not file

    def test_file_too_large_raises(self, tmp_path):
        big = tmp_path / "big.bin"
        big.write_bytes(b"\x00")
        with pytest.raises(PayloadValidationError, match="exceeds limit"):
            pack_file(big, max_bytes=0)

    def test_content_type_explicit(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x01\x02")
        raw = pack_file(f, content_type="image/png")
        p = UXSPPayload.from_bytes(raw)
        assert p.content_type == "image/png"

    def test_content_type_guessed_from_extension(self, tmp_path):
        f = tmp_path / "page.html"
        f.write_text("<html/>")
        raw = pack_file(f)
        p = UXSPPayload.from_bytes(raw)
        assert "html" in p.content_type

    def test_content_type_fallback_octet(self, tmp_path):
        f = tmp_path / "weirdext.zzzzz"
        f.write_bytes(b"x")
        raw = pack_file(f)
        p = UXSPPayload.from_bytes(raw)
        assert p.content_type == "application/octet-stream"

    def test_content_type_empty_string_raises(self, tmp_path):
        f = tmp_path / "x.bin"
        f.write_bytes(b"x")
        with pytest.raises(PayloadValidationError, match="non-empty"):
            pack_file(f, content_type="")

    def test_string_path_accepted(self, tmp_path):
        f = tmp_path / "s.txt"
        f.write_text("str path")
        raw = pack_file(str(f))
        p = UXSPPayload.from_bytes(raw)
        assert p.filename == "s.txt"


class TestUnpackToFile:
    def test_unpack_file_kind(self, tmp_path):
        src = tmp_path / "img.png"
        src.write_bytes(b"\x89PNG")
        raw = pack_file(src)
        out = unpack_to_file(raw, tmp_path / "dest")
        assert out.read_bytes() == b"\x89PNG"

    def test_unpack_binary_kind(self, tmp_path):
        raw = pack_binary(b"\xca\xfe", filename="blob.bin")
        out = unpack_to_file(raw, tmp_path)
        assert out.name == "blob.bin"
        assert out.read_bytes() == b"\xca\xfe"

    def test_wrong_kind_raises(self, tmp_path):
        raw = pack_text("hi")
        with pytest.raises(PayloadValidationError, match="Expected file/binary"):
            unpack_to_file(raw, tmp_path)

    def test_no_filename_uses_default(self, tmp_path):
        raw = pack_binary(b"\x00", filename=None)
        out = unpack_to_file(raw, tmp_path)
        assert out.name == "uxsp_payload.bin"

    def test_filename_with_path_traversal_stripped(self, tmp_path):
        """Path.name strips directory components — traversal must be impossible."""
        raw = pack_binary(b"x", filename="../../etc/passwd")
        out = unpack_to_file(raw, tmp_path)
        # Only the basename survives
        assert out.name == "passwd"
        assert out.parent == tmp_path

    def test_output_dir_created(self, tmp_path):
        raw = pack_binary(b"z", filename="z.bin")
        deep = tmp_path / "a" / "b" / "c"
        unpack_to_file(raw, deep)
        assert deep.exists()

    def test_dot_filename_uses_default(self, tmp_path):
        """A filename that reduces to '.' after Path.name should use the fallback."""
        # We manually build a payload with filename='.'
        header = {
            "kind": "binary", "filename": ".",
            "content_type": "application/octet-stream", "encoding": None, "body_len": 1,
        }
        hb = json.dumps(header).encode()
        raw = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + b"x"
        out = unpack_to_file(raw, tmp_path)
        assert out.name == "uxsp_payload.bin"

    def test_dotdot_filename_uses_default(self, tmp_path):
        header = {
            "kind": "binary", "filename": "..",
            "content_type": "application/octet-stream", "encoding": None, "body_len": 1,
        }
        hb = json.dumps(header).encode()
        raw = _MAGIC + len(hb).to_bytes(_HEADER_LEN_BYTES, "big") + hb + b"x"
        out = unpack_to_file(raw, tmp_path)
        assert out.name == "uxsp_payload.bin"


# ---------------------------------------------------------------------------
# pack_binary
# ---------------------------------------------------------------------------

class TestPackBinary:
    def test_round_trip(self):
        data = bytes(range(256))
        raw = pack_binary(data, filename="dump.bin", content_type="application/octet-stream")
        p = UXSPPayload.from_bytes(raw)
        assert p.body == data
        assert p.filename == "dump.bin"
        assert p.kind == "binary"

    def test_bytearray_accepted(self):
        raw = pack_binary(bytearray(b"\x01\x02\x03"))
        p = UXSPPayload.from_bytes(raw)
        assert p.body == b"\x01\x02\x03"

    def test_not_bytes_raises(self):
        with pytest.raises(PayloadValidationError, match="must be bytes"):
            pack_binary("string data")  # type: ignore[arg-type]

    def test_empty_content_type_raises(self):
        with pytest.raises(PayloadValidationError, match="non-empty"):
            pack_binary(b"x", content_type="")

    def test_empty_filename_raises(self):
        with pytest.raises(PayloadValidationError, match="non-empty string or None"):
            pack_binary(b"x", filename="")

    def test_none_filename_allowed(self):
        raw = pack_binary(b"x", filename=None)
        p = UXSPPayload.from_bytes(raw)
        assert p.filename is None

    def test_empty_bytes(self):
        raw = pack_binary(b"")
        p = UXSPPayload.from_bytes(raw)
        assert p.body == b""

    def test_custom_content_type(self):
        raw = pack_binary(b"\x00", content_type="image/jpeg")
        p = UXSPPayload.from_bytes(raw)
        assert p.content_type == "image/jpeg"


# ---------------------------------------------------------------------------
# All three valid 'kind' values accepted by from_bytes
# ---------------------------------------------------------------------------

class TestAllKinds:
    @pytest.mark.parametrize("kind", ["text", "file", "binary"])
    def test_kind_accepted(self, kind):
        body = b"data"
        raw = _raw_payload(kind=kind, body=body, encoding=None if kind != "text" else "utf-8")
        p = UXSPPayload.from_bytes(raw)
        assert p.kind == kind
