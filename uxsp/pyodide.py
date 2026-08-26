"""
UXSP Pyodide Helper (`uxsp.pyodide`)

Exposes JavaScript global binding functions for browser runtimes using Pyodide.
"""

from __future__ import annotations

import json
from typing import Any

from uxsp.wasm import PyodideUXSPBridge


_BRIDGE_INSTANCE: PyodideUXSPBridge | None = None


def get_bridge(name: str = "BrowserClient", role: str = "CLIENT") -> PyodideUXSPBridge:
    """Return singleton Pyodide bridge instance."""
    global _BRIDGE_INSTANCE
    if _BRIDGE_INSTANCE is None:
        _BRIDGE_INSTANCE = PyodideUXSPBridge(name=name, role=role)
    return _BRIDGE_INSTANCE


def js_seal_text(text: str, recipient_card_json: str) -> str:
    """JS binding for sealing text."""
    bridge = get_bridge()
    return bridge.seal_text(text, recipient_card_json)


def js_open_text(package_json: str, sender_card_json: str | None = None) -> str:
    """JS binding for opening text packages."""
    bridge = get_bridge()
    return bridge.open_text(package_json, sender_card_json)


def js_validate_package(package_json: str) -> bool:
    """JS binding for package validation."""
    return PyodideUXSPBridge.validate_package(package_json)


def export_pyodide_globals() -> dict[str, Any]:
    """
    Return dictionary of JavaScript global export functions for Pyodide window object.
    """
    return {
        "uxspSealText": js_seal_text,
        "uxspOpenText": js_open_text,
        "uxspValidatePackage": js_validate_package,
    }


__all__ = [
    "get_bridge",
    "js_seal_text",
    "js_open_text",
    "js_validate_package",
    "export_pyodide_globals",
]
