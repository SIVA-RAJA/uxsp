"""
Unit tests for uxsp.schema module and JSON Schema specifications.
"""

import pytest

import uxsp
import uxsp.schema as schema


def test_get_schemas():
    env_schema = schema.get_envelope_schema()
    assert env_schema["title"] == "UXSPEnvelope"
    assert env_schema["properties"]["version"]["enum"] == ["UXSP-1"]

    pkg_schema = schema.get_package_schema()
    assert pkg_schema["title"] == "SecurePackage"

    card_schema = schema.get_public_card_schema()
    assert card_schema["title"] == "PublicCard"


def test_validate_envelope():
    alice = uxsp.create_identity("Alice")
    bob = uxsp.create_identity("Bob")

    pkg = uxsp.secure.SendText("Hello Schema", receiver=bob, sender=alice)
    env_dict = pkg.envelope

    schema.validate_envelope(env_dict)

    # Invalid payload type
    with pytest.raises(schema.SchemaValidationError, match="must be a dictionary"):
        schema.validate_envelope("not a dict")  # type: ignore

    # Invalid version
    bad_env = dict(env_dict)
    bad_env["version"] = "INVALID"
    with pytest.raises(schema.SchemaValidationError, match="Invalid envelope version"):
        schema.validate_envelope(bad_env)

    # Missing field
    missing_env = dict(env_dict)
    del missing_env["ciphertext"]
    with pytest.raises(schema.SchemaValidationError, match="missing required fields"):
        schema.validate_envelope(missing_env)

    # Non-string field
    bad_type_env = dict(env_dict)
    bad_type_env["sender_id"] = 12345
    with pytest.raises(schema.SchemaValidationError, match="must be a string"):
        schema.validate_envelope(bad_type_env)

    # Non-int timestamp
    bad_ts_env = dict(env_dict)
    bad_ts_env["timestamp"] = "12345"
    with pytest.raises(schema.SchemaValidationError, match="must be an integer"):
        schema.validate_envelope(bad_ts_env)


def test_validate_package():
    alice = uxsp.create_identity("Alice")
    bob = uxsp.create_identity("Bob")

    pkg = uxsp.secure.SendText("Hello Package Schema", receiver=bob, sender=alice)
    pkg_dict = pkg.to_dict()

    schema.validate_package(pkg_dict)

    # Invalid payload type
    with pytest.raises(schema.SchemaValidationError, match="must be a dictionary"):
        schema.validate_package(12345)  # type: ignore

    # Missing required fields
    with pytest.raises(schema.SchemaValidationError, match="missing required fields"):
        schema.validate_package({"uxsp_package_version": "1.0"})

    # Invalid package version
    bad_pkg = dict(pkg_dict)
    bad_pkg["uxsp_package_version"] = "2.0"
    with pytest.raises(schema.SchemaValidationError, match="Invalid package version"):
        schema.validate_package(bad_pkg)

    # Non-boolean is_chunked
    bad_chunk_pkg = dict(pkg_dict)
    bad_chunk_pkg["is_chunked"] = "true"
    with pytest.raises(schema.SchemaValidationError, match="must be a boolean"):
        schema.validate_package(bad_chunk_pkg)

    # Invalid chunk in chunks array
    bad_chunks_pkg = dict(pkg_dict)
    bad_chunks_pkg["is_chunked"] = True
    bad_chunks_pkg["chunks"] = ["invalid_chunk_envelope"]
    with pytest.raises(schema.SchemaValidationError, match="Invalid envelope at chunk index 0"):
        schema.validate_package(bad_chunks_pkg)


def test_validate_public_card():
    alice = uxsp.create_identity("Alice")
    card_dict = alice.public_card().to_dict()

    schema.validate_public_card(card_dict)

    # Invalid payload type
    with pytest.raises(schema.SchemaValidationError, match="must be a dictionary"):
        schema.validate_public_card(["not a dict"])  # type: ignore

    # Missing required fields
    with pytest.raises(schema.SchemaValidationError, match="missing required fields"):
        schema.validate_public_card({"version": "UXSP-PUBCARD-1"})

    # Invalid card version
    bad_card = dict(card_dict)
    bad_card["version"] = "BAD-IDENTITY"
    with pytest.raises(schema.SchemaValidationError, match="Invalid PublicCard version"):
        schema.validate_public_card(bad_card)

    # Non-dict public_keys
    bad_pk_card = dict(card_dict)
    bad_pk_card["public_keys"] = "not_a_dict"
    with pytest.raises(schema.SchemaValidationError, match="public_keys' must be a dictionary"):
        schema.validate_public_card(bad_pk_card)

    # Missing public key fields
    missing_pk_card = dict(card_dict)
    missing_pk_card["public_keys"] = {"exchange_pub": "abc"}
    with pytest.raises(schema.SchemaValidationError, match="missing public key fields"):
        schema.validate_public_card(missing_pk_card)
