"""
Tests for uxsp curl / uxsp fetch CLI functionality.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from uxsp.cli import main
from uxsp.client import UXSPResponse
from uxsp.core.identity import Identity


class TestClientCLI:
    def test_cli_curl_basic_plain(self, monkeypatch, capsys):
        mock_response = UXSPResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            content=b'{"status": "ok"}',
            url="https://api.example.com/status",
            is_uxsp=False,
        )

        with patch("uxsp.client.UXSPClient.request", return_value=mock_response) as mock_req:
            monkeypatch.setattr("sys.argv", ["uxsp", "curl", "https://api.example.com/status"])
            main()

            mock_req.assert_called_once()
            args, kwargs = mock_req.call_args
            assert kwargs["method"] == "GET"
            assert kwargs["url"] == "https://api.example.com/status"

            captured = capsys.readouterr()
            assert '{"status": "ok"}' in captured.out

    def test_cli_fetch_verbose_and_headers(self, monkeypatch, capsys):
        mock_response = UXSPResponse(
            status_code=200,
            headers={"content-type": "text/plain", "sec-uxsp-selected": "v1.2"},
            content=b"hello secret world",
            url="https://api.example.com/secret",
            is_uxsp=True,
            package=MagicMock(sender_id="sender_bob"),
        )

        with patch("uxsp.client.UXSPClient.request", return_value=mock_response):
            monkeypatch.setattr(
                "sys.argv",
                [
                    "uxsp",
                    "fetch",
                    "https://api.example.com/secret",
                    "-X",
                    "POST",
                    "-d",
                    '{"query": 123}',
                    "-H",
                    "Authorization: Bearer token123",
                    "-H",
                    "X-Custom: Val",
                    "-v",
                    "-i",
                ],
            )
            main()

            captured = capsys.readouterr()
            # Verbose info is written to stderr
            assert "Connecting to api.example.com" in captured.err
            assert "Negotiating UXSP" in captured.err
            assert "Protocol: UXSP Encrypted" in captured.err
            assert "sender_bob" in captured.err
            # Include headers in stdout
            assert "HTTP/1.1 200" in captured.out
            assert "content-type: text/plain" in captured.out
            assert "hello secret world" in captured.out

    def test_cli_curl_file_output(self, monkeypatch, tmp_path):
        out_file = tmp_path / "downloaded.dat"
        mock_response = UXSPResponse(
            status_code=200,
            headers={},
            content=b"\x00\x01\x02\x03\x04",
            url="https://api.example.com/binary",
            is_uxsp=False,
        )

        with patch("uxsp.client.UXSPClient.request", return_value=mock_response):
            monkeypatch.setattr(
                "sys.argv",
                ["uxsp", "curl", "https://api.example.com/binary", "-o", str(out_file), "-v"],
            )
            main()

            assert out_file.exists()
            assert out_file.read_bytes() == b"\x00\x01\x02\x03\x04"

    def test_cli_curl_with_sender_key_and_peer_card(self, monkeypatch, tmp_path):
        sender = Identity.create("Alice", "CLIENT")
        sender_file = tmp_path / "alice.uxsp"
        sender.save(sender_file, "pwd123")

        bob = Identity.create("Bob", "SERVER")
        bob_card = bob.public_card()
        bob_card_file = tmp_path / "bob.card.json"
        bob_card_file.write_text(bob_card.to_json(), encoding="utf-8")

        data_file = tmp_path / "payload.txt"
        data_file.write_text("file body", encoding="utf-8")

        mock_response = UXSPResponse(
            status_code=200,
            headers={},
            content=b"done",
            url="https://api.example.com/upload",
            is_uxsp=False,
        )

        with patch("uxsp.client.UXSPClient.request", return_value=mock_response) as mock_req:
            monkeypatch.setenv("UXSP_PASSWORD", "pwd123")
            monkeypatch.setattr(
                "sys.argv",
                [
                    "uxsp",
                    "curl",
                    "https://api.example.com/upload",
                    "-d",
                    f"@{data_file}",
                    "--sender",
                    str(sender_file),
                    "--peer",
                    str(bob_card_file),
                    "--uxsp-only",
                ],
            )
            main()

            mock_req.assert_called_once()
            _, kwargs = mock_req.call_args
            assert kwargs["data"] == b"file body"
            assert kwargs["peer"].entity_id == bob_card.entity_id

    def test_cli_curl_error_handling(self, monkeypatch, capsys):
        with patch("uxsp.client.UXSPClient.request", side_effect=RuntimeError("Network down")):
            monkeypatch.setattr("sys.argv", ["uxsp", "curl", "https://api.example.com/fail"])
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1
            captured = capsys.readouterr()
            assert "Request failed: Network down" in captured.err
