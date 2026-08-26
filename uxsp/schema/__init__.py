"""
UXSP JSON Schema Module (`uxsp.schema`)

Provides JSON Schema definitions and runtime validation helpers for:
- UXSP-1 Sealed Envelopes
- UXSP SecurePackages
- UXSP PublicCards
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

_SCHEMA_DIR = Path(__file__).parent


class SchemaValidationError(ValueError):
    """Raised when a dictionary fails JSON Schema validation."""

    pass


def get_envelope_schema() -> dict[str, Any]:
    """Return the JSON Schema dictionary for UXSP-1 Envelopes."""
    path = _SCHEMA_DIR / "envelope_schema.json"
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def get_package_schema() -> dict[str, Any]:
    """Return the JSON Schema dictionary for SecurePackages."""
    path = _SCHEMA_DIR / "package_schema.json"
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def get_public_card_schema() -> dict[str, Any]:
    """Return the JSON Schema dictionary for PublicCards."""
    path = _SCHEMA_DIR / "public_card_schema.json"
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def validate_envelope(data: dict[str, Any]) -> None:
    """
    Validate a dictionary against the UXSP-1 Envelope JSON Schema.
    Raises SchemaValidationError if invalid.
    """
    if not isinstance(data, dict):
        raise SchemaValidationError("Envelope payload must be a dictionary.")

    required = (
        "version",
        "sender_id",
        "recipient_id",
        "timestamp",
        "envelope_nonce",
        "ciphertext",
        "nonce",
        "ephemeral_pub",
        "kem_ciphertext",
        "classical_sig",
        "pqc_sig",
    )
    missing = [f for f in required if f not in data]
    if missing:
        raise SchemaValidationError(f"Envelope missing required fields: {', '.join(missing)}")

    if data.get("version") != "UXSP-1":
        raise SchemaValidationError(f"Invalid envelope version '{data.get('version')}'. Expected 'UXSP-1'.")

    string_fields = [
        "sender_id",
        "recipient_id",
        "envelope_nonce",
        "ciphertext",
        "nonce",
        "ephemeral_pub",
        "kem_ciphertext",
        "classical_sig",
        "pqc_sig",
    ]
    for sf in string_fields:
        if not isinstance(data[sf], str):
            raise SchemaValidationError(f"Envelope field '{sf}' must be a string, got {type(data[sf]).__name__}.")

    if not isinstance(data["timestamp"], int):
        raise SchemaValidationError(f"Envelope field 'timestamp' must be an integer, got {type(data['timestamp']).__name__}.")


def validate_package(data: dict[str, Any]) -> None:
    """
    Validate a dictionary against the UXSP SecurePackage JSON Schema.
    Raises SchemaValidationError if invalid.
    """
    if not isinstance(data, dict):
        raise SchemaValidationError("SecurePackage payload must be a dictionary.")

    required = ("uxsp_package_version", "sender_id", "receiver_id", "data_type", "is_chunked")
    missing = [f for f in required if f not in data]
    if missing:
        raise SchemaValidationError(f"SecurePackage missing required fields: {', '.join(missing)}")

    if data.get("uxsp_package_version") != "1.0":
        raise SchemaValidationError(f"Invalid package version '{data.get('uxsp_package_version')}'. Expected '1.0'.")

    if not isinstance(data["is_chunked"], bool):
        raise SchemaValidationError("SecurePackage field 'is_chunked' must be a boolean.")

    if data.get("envelope") is not None:
        validate_envelope(data["envelope"])

    if isinstance(data.get("chunks"), list):
        for idx, chunk in enumerate(data["chunks"]):
            try:
                validate_envelope(chunk)
            except SchemaValidationError as e:
                raise SchemaValidationError(f"Invalid envelope at chunk index {idx}: {e}") from e


def validate_public_card(data: dict[str, Any]) -> None:
    """
    Validate a dictionary against the UXSP PublicCard JSON Schema.
    Raises SchemaValidationError if invalid.
    """
    if not isinstance(data, dict):
        raise SchemaValidationError("PublicCard payload must be a dictionary.")

    required = ("version", "entity_id", "name", "role", "created_at", "public_keys")
    missing = [f for f in required if f not in data]
    if missing:
        raise SchemaValidationError(f"PublicCard missing required fields: {', '.join(missing)}")

    if data.get("version") != "UXSP-PUBCARD-1":
        raise SchemaValidationError(f"Invalid PublicCard version '{data.get('version')}'. Expected 'UXSP-PUBCARD-1'.")

    pk = data.get("public_keys")
    if not isinstance(pk, dict):
        raise SchemaValidationError("PublicCard 'public_keys' must be a dictionary.")

    pk_required = ("exchange_pub", "kem_pub", "signing_pub", "pqc_sig_pub")
    pk_missing = [f for f in pk_required if f not in pk]
    if pk_missing:
        raise SchemaValidationError(f"PublicCard missing public key fields: {', '.join(pk_missing)}")


__all__ = [
    "get_envelope_schema",
    "get_package_schema",
    "get_public_card_schema",
    "validate_envelope",
    "validate_package",
    "validate_public_card",
    "SchemaValidationError",
]
