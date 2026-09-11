"""
uxsp.client._response — Response Representation for UXSP Client
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from uxsp.client._errors import UXSPClientError
from uxsp.secure._package import SecurePackage


@dataclass
class UXSPResponse:
    """
    Unified HTTP response object returned by UXSP client calls.
    Represents either a UXSP-decrypted response or a standard HTTPS response.
    """

    status_code: int
    headers: dict[str, str]
    content: bytes
    url: str
    is_uxsp: bool = False
    package: SecurePackage | None = None
    data: Any = None

    @property
    def text(self) -> str:
        """Decode raw response content as UTF-8 string."""
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        """
        Parse response payload as JSON.
        If the response was UXSP-encrypted, returns the decrypted payload or
        JSON-decoded decrypted data. Otherwise parses the raw HTTP content as JSON.
        """
        if self.is_uxsp and self.data is not None:
            if isinstance(self.data, (dict, list)):
                return self.data
            if isinstance(self.data, (str, bytes)):
                try:
                    return json.loads(self.data)
                except Exception:
                    return self.data
            return self.data
        return json.loads(self.text)

    def raise_for_status(self) -> None:
        """Raise UXSPClientError if HTTP status code indicates an error (4xx or 5xx)."""
        if 400 <= self.status_code < 600:
            raise UXSPClientError(
                f"HTTP {self.status_code} Error for {self.url}: {self.text[:300]}"
            )
