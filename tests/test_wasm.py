"""
Unit tests for uxsp.wasm and uxsp.pyodide modules.
"""

import json

import pytest

import uxsp
from uxsp.pyodide import export_pyodide_globals, js_open_text, js_seal_text, js_validate_package
from uxsp.wasm import PyodideUXSPBridge, is_wasm_environment


def test_wasm_environment_check():
    # In standard pytest Python environment, returns False
    assert is_wasm_environment() is False


def test_pyodide_bridge_seal_and_open():
    bridge_alice = PyodideUXSPBridge(name="Alice", role="CLIENT")
    bridge_bob = PyodideUXSPBridge(name="Bob", role="SERVER")

    alice_card_json = bridge_alice.get_public_card_json()
    bob_card_json = bridge_bob.get_public_card_json()

    # Seal text from Alice to Bob
    package_json = bridge_alice.seal_text("Hello Pyodide WASM", recipient_card_json=bob_card_json)
    assert isinstance(package_json, str)
    assert PyodideUXSPBridge.validate_package(package_json) is True

    # Open text on Bob's bridge
    decrypted = bridge_bob.open_text(package_json, sender_card_json=alice_card_json)
    assert decrypted == "Hello Pyodide WASM"


def test_pyodide_bridge_invalid_package_validation():
    # Covers lines 90-91 in uxsp/wasm.py
    assert PyodideUXSPBridge.validate_package("invalid json string") is False
    assert PyodideUXSPBridge.validate_package("{}") is False


def test_pyodide_bridge_key_rotation():
    bridge = PyodideUXSPBridge(name="Carol")
    old_card_json = bridge.get_public_card_json()

    new_card_json = bridge.rotate_keys()
    assert new_card_json != old_card_json
    new_card_dict = json.loads(new_card_json)
    assert new_card_dict["key_version"] == 2


def test_pyodide_js_global_bindings():
    sender_bridge = PyodideUXSPBridge(name="SenderBridge", role="CLIENT")
    sender_card_json = sender_bridge.get_public_card_json()

    # get_bridge() is the default singleton receiver
    recipient_bridge = uxsp.pyodide.get_bridge()
    recipient_card_json = recipient_bridge.get_public_card_json()

    # Test js_seal_text
    pkg_json = js_seal_text("Secret Message", recipient_card_json)
    assert js_validate_package(pkg_json) is True

    # Seal from sender_bridge for default singleton bridge (js_open_text)
    pkg_for_default = sender_bridge.seal_text("Via JS Open Text", recipient_card_json)
    decrypted_via_js = js_open_text(pkg_for_default, sender_card_json)
    assert decrypted_via_js == "Via JS Open Text"

    globals_dict = export_pyodide_globals()
    assert "uxspSealText" in globals_dict
    assert "uxspOpenText" in globals_dict
    assert "uxspValidatePackage" in globals_dict

    # Invoke exported global function directly (covers line 47 in uxsp/pyodide.py)
    assert globals_dict["uxspValidatePackage"](pkg_json) is True
