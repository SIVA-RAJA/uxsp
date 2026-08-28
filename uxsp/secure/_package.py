from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from uxsp.secure._errors import SecureReceiveError
from uxsp.secure._utils import _safe_is_file

@dataclass
class SecurePackage:
    """
    Standard container for encrypted UXSP packages (single envelope or chunked).

    Can be serialized directly to JSON, saved to a file, transmitted over HTTP/WS,
    or passed into Receive* functions.
    """
    sender_id: str
    receiver_id: str
    data_type: str
    is_chunked: bool
    envelope: dict[str, Any] | None = None
    chunks: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert package to a dictionary."""
        return {
            "uxsp_package_version": "1.0",
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "data_type": self.data_type,
            "is_chunked": self.is_chunked,
            "envelope": self.envelope,
            "chunks": self.chunks,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int | None = None) -> str:
        """Serialize package to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, file_path: str | Path) -> Path:
        """Save package to a JSON file."""
        p = Path(file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json(indent=2), encoding="utf-8")
        return p

    to_file = save

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurePackage:
        """Construct package from a dictionary."""
        if not isinstance(data, dict):
            raise SecureReceiveError("Package data must be a dictionary.")
        return cls(
            sender_id=str(data.get("sender_id", "")),
            receiver_id=str(data.get("receiver_id", "")),
            data_type=str(data.get("data_type", "file")),
            is_chunked=bool(data.get("is_chunked", False)),
            envelope=data.get("envelope"),
            chunks=data.get("chunks", []),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_json(cls, json_str: str | bytes) -> SecurePackage:
        """Deserialize package from a JSON string or bytes."""
        try:
            if isinstance(json_str, bytes):
                json_str = json_str.decode("utf-8")
            data = json.loads(json_str)
            return cls.from_dict(data)
        except Exception as exc:
            raise SecureReceiveError(f"Failed to parse JSON package: {exc}") from exc

    @classmethod
    def from_file(cls, file_path: str | Path) -> SecurePackage:
        """Load package from a JSON file."""
        if not _safe_is_file(file_path):
            raise SecureReceiveError(f"Package file not found: {file_path}")
        p = Path(file_path)
        return cls.from_json(p.read_text(encoding="utf-8"))
