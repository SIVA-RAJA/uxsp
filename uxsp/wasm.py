"""
UXSP WebAssembly & Pyodide Integration Layer (`uxsp.wasm`)

Enables UXSP cryptographic functions and package handlers to run inside
browser WebAssembly / Pyodide environments and Web Workers.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import uxsp.schema as schema
import uxsp.secure as secure
from uxsp.core.identity import Identity, PublicCard


def is_wasm_environment() -> bool:
    """Return True if running inside a WebAssembly or Pyodide Python environment."""
    return (
        sys.platform in ("emscripten", "wasi")
        or "pyodide" in sys.modules
        or hasattr(sys, "_emscripten_info")
    )


class PyodideUXSPBridge:
    """
    Bridge wrapper for Pyodide/WASM browser applications.

    Exposes simple JSON-in / JSON-out methods for browser client encryption
    and decryption.
    """

    def __init__(self, name: str = "BrowserClient", role: str = "CLIENT") -> None:
        self.identity = Identity.create(name=name, role=role)
        secure.set_identity(self.identity)

    def get_public_card_json(self) -> str:
        """Return browser client's PublicCard as a JSON string."""
        return self.identity.public_card().to_json()

    def seal_text(self, text: str, recipient_card_json: str) -> str:
        """
        Seal a text payload for a recipient specified by recipient_card_json.
        Returns a SecurePackage JSON string ready for backend POST requests.
        """
        recipient_card_dict = json.loads(recipient_card_json)
        card = PublicCard.from_dict(recipient_card_dict)

        pkg = secure.SendText(
            receiver=card,
            text=text,
            sender=self.identity,
        )
        return pkg.to_json()

    def open_text(self, package_json: str, sender_card_json: str | None = None) -> str:
        """
        Open and decrypt a received text package JSON string.
        Returns the plaintext string.
        """
        pkg_dict = json.loads(package_json)
        pkg = secure.SecurePackage.from_dict(pkg_dict)

        sender: Any = None
        if sender_card_json:
            sender = PublicCard.from_dict(json.loads(sender_card_json))

        return secure.ReceiveText(
            package=pkg,
            sender=sender,
            receiver=self.identity,
        )

    def rotate_keys(self) -> str:
        """Rotate keys for the local browser identity and return updated card JSON."""
        self.identity = self.identity.rotate_keys()
        secure.set_identity(self.identity)
        return self.identity.public_card().to_json()

    @staticmethod
    def validate_package(package_json: str) -> bool:
        """Validate package JSON against the UXSP JSON Schema."""
        try:
            pkg_dict = json.loads(package_json)
            schema.validate_package(pkg_dict)
            return True
        except Exception:
            return False


__all__ = ["is_wasm_environment", "PyodideUXSPBridge"]
