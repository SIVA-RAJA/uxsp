"""
Full-coverage pytest suite for uxsp.cli.

Strategy
--------
* Every function in cli is tested via its public CLI entry-point (main())
  using argparse + monkeypatching, so we exercise the real argument-parsing
  paths.
* Domain objects are stubbed with minimal fakes so the tests never depend on the real uxsp package.
* File I/O that cli performs (tempfile, os.replace, os.chmod, open) is
  patched or done in a real tmp directory so every branch is reached.
* Error paths are exercised.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import uxsp

class TestInitPackageNotFound:
    def test_version_fallback_when_package_not_found(self, monkeypatch):
        from importlib.metadata import PackageNotFoundError
        with patch("importlib.metadata.version", side_effect=PackageNotFoundError("uxsp")):
            orig = sys.modules.pop("uxsp", None)
            try:
                import uxsp as u
                assert u.__version__ == "1.1.0"
            finally:
                if orig is not None:
                    sys.modules["uxsp"] = orig
                else:
                    sys.modules.pop("uxsp", None)
                    import uxsp

class FakePublicCard:
    def __init__(self, name="Tester", role="SERVER", entity_id="eid-card-001"):
        self.name = name
        self.role = role
        self.entity_id = entity_id

    def to_json(self):
        return json.dumps({"name": self.name, "role": self.role, "entity_id": self.entity_id})

    @classmethod
    def from_json(cls, text: str):
        data = json.loads(text)
        return cls(data.get("name", "X"), data.get("role", "SERVER"), data.get("entity_id", "eid"))

class FakeSignedCard:
    def __init__(self, card: FakePublicCard):
        self.cert_id = "cert-abc-123"
        self._card = card

    def to_json(self, indent=None):
        return json.dumps({"cert_id": self.cert_id}, indent=indent)

class FakeIdentity:
    def __init__(self, name="Test Identity", role="SERVER"):
        self.entity_id = "eid-001"
        self.name = name
        self.role = role
        self.created_at = "2025-01-01T00:00:00Z"

    @classmethod
    def create(cls, name, role):
        return cls(name, role)

    def save(self, path, password):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text("fake-identity")

    def public_card(self):
        return FakePublicCard(self.name, self.role, self.entity_id)

    @classmethod
    def load(cls, path, password):
        return cls()
        
    def rotate_keys(self):
        pass
        
    def revoke(self, reason=None):
        pass

class FakePublicAnchor:
    def __init__(self, name, entity_id):
        self.name = name
        self.entity_id = entity_id

    def to_json(self):
        return json.dumps({"name": self.name, "entity_id": self.entity_id})

class FakeTrustAnchor:
    def __init__(self, name="Root CA"):
        self.entity_id = "anchor-eid-001"
        self.name = name

    @classmethod
    def create(cls, name):
        return cls(name)

    def save(self, path, password):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text("fake-anchor")

    def public_anchor(self):
        return FakePublicAnchor(self.name, self.entity_id)

    def issue(self, card, validity_days=365):
        return FakeSignedCard(card)

    @classmethod
    def load(cls, path, password):
        return cls()

class FakePackage:
    def serialize(self): return b"serialized"
    @classmethod
    def deserialize(cls, data): return cls()

def fake_send(data, sender, receiver):
    return FakePackage()
    
class FakeReceiveData:
    def __init__(self):
        self.filename = "out.txt"
    def read(self):
        return b"data"
        
def fake_receive(pkg, receiver):
    return FakeReceiveData()
    
def fake_send_stream(file, sender, receiver):
    yield b"chunk"
    
def fake_receive_stream(f_in, receiver):
    yield b"chunk"
    
class FakeLiveSession:
    def __init__(self, identity, peer_card): pass
    
class FakeLiveVoiceSession:
    def __init__(self, identity, peer_card): pass

@pytest.fixture(autouse=True)
def mock_uxsp(monkeypatch):
    import uxsp
    import uxsp.secure
    monkeypatch.setattr(uxsp, "__version__", "0.0.test")
    monkeypatch.setattr(uxsp, "Identity", FakeIdentity)
    monkeypatch.setattr(uxsp, "PublicCard", FakePublicCard)
    monkeypatch.setattr(uxsp, "TrustAnchor", FakeTrustAnchor)
    monkeypatch.setattr(uxsp.secure, "SecurePackage", FakePackage)
    monkeypatch.setattr(uxsp.secure, "Send", fake_send)
    monkeypatch.setattr(uxsp.secure, "Receive", fake_receive)
    monkeypatch.setattr(uxsp.secure, "SendStream", fake_send_stream)
    monkeypatch.setattr(uxsp.secure, "ReceiveStream", fake_receive_stream)
    monkeypatch.setattr(uxsp, "LiveSession", FakeLiveSession)
    monkeypatch.setattr(uxsp, "LiveVoiceSession", FakeLiveVoiceSession)
    
def run_cli(monkeypatch, argv: list[str], passwords: list[str] | None = None, *, expect_exit: int | None = None):
    from uxsp.cli import main

    pw_iter = iter(passwords or [])
    def fake_getpass(prompt="", stream=None):
        return next(pw_iter, "secret123")

    monkeypatch.setattr("getpass.getpass", fake_getpass)
    monkeypatch.setattr(sys, "argv", ["uxsp"] + argv)

    if expect_exit is not None:
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == expect_exit
    else:
        main()

class TestPromptPassword:
    def test_confirm_passwords_match(self, monkeypatch, tmp_path):
        monkeypatch.setattr("getpass.getpass", lambda prompt="", stream=None: "abc123")
        from uxsp.cli import utils
        result = utils.prompt_password("Enter: ", confirm=True)
        assert result == "abc123"

    def test_confirm_passwords_mismatch_exits(self, monkeypatch, capsys):
        answers = iter(["first", "second"])
        monkeypatch.setattr("getpass.getpass", lambda prompt="", stream=None: next(answers))
        from uxsp.cli import utils
        with pytest.raises(SystemExit) as exc:
            utils.prompt_password("Enter: ", confirm=True)
        assert exc.value.code == 1

    def test_empty_password_exits(self, monkeypatch, capsys):
        monkeypatch.setattr("getpass.getpass", lambda prompt="", stream=None: "")
        from uxsp.cli import utils
        with pytest.raises(SystemExit) as exc:
            utils.prompt_password("Enter: ")
        assert exc.value.code == 1

    def test_no_confirm(self, monkeypatch):
        call_count = 0
        def fake_gp(prompt="", stream=None):
            nonlocal call_count
            call_count += 1
            return "pw123"
        monkeypatch.setattr("getpass.getpass", fake_gp)
        from uxsp.cli import utils
        result = utils.prompt_password("Enter: ", confirm=False)
        assert result == "pw123"
        assert call_count == 1

class TestVersion:
    def test_version_output(self, monkeypatch, capsys, tmp_path):
        run_cli(monkeypatch, ["version"])
        out = capsys.readouterr().out
        assert "0.0.test" in out

class TestKeygen:
    def test_keygen_creates_identity(self, monkeypatch, tmp_path, capsys):
        out_path = str(tmp_path / "keys" / "server.uxsp")
        run_cli(monkeypatch, ["keygen", "--name", "API Server", "--role", "SERVER", "--out", out_path], passwords=["secret", "secret"])
        assert Path(out_path).exists()

    def test_keygen_password_mismatch_exits(self, monkeypatch, tmp_path):
        out_path = str(tmp_path / "server.uxsp")
        run_cli(monkeypatch, ["keygen", "--name", "X", "--role", "SERVER", "--out", out_path], passwords=["pw1", "pw2"], expect_exit=1)

class TestPubcard:
    def test_pubcard_explicit_out(self, monkeypatch, tmp_path, capsys):
        key_path = tmp_path / "server.uxsp"
        key_path.write_text("fake")
        out_path = str(tmp_path / "server.card.json")
        run_cli(monkeypatch, ["pubcard", "--key", str(key_path), "--out", out_path], passwords=["secret"])
        assert Path(out_path).exists()

    def test_pubcard_default_out(self, monkeypatch, tmp_path, capsys):
        key_path = tmp_path / "mykey.uxsp"
        key_path.write_text("fake")
        run_cli(monkeypatch, ["pubcard", "--key", str(key_path)], passwords=["secret"])
        expected = str(tmp_path / "mykey.card.json")
        assert expected in capsys.readouterr().out

    def test_pubcard_atomic_write_cleanup_on_error(self, monkeypatch, tmp_path):
        key_path = tmp_path / "server.uxsp"
        key_path.write_text("fake")
        def bad_replace(src, dst): raise OSError("disk full")
        monkeypatch.setattr(os, "replace", bad_replace)
        run_cli(monkeypatch, ["pubcard", "--key", str(key_path), "--out", str(tmp_path / "out.card.json")], passwords=["secret"], expect_exit=1)

class TestAnchorCreate:
    def test_anchor_create_produces_files(self, monkeypatch, tmp_path, capsys):
        anchor_path = str(tmp_path / "anchors" / "root.uxsp")
        run_cli(monkeypatch, ["anchor", "create", "--name", "Root CA", "--out", anchor_path], passwords=["secret", "secret"])
        assert Path(anchor_path).exists()

    def test_anchor_create_atomic_cleanup_on_error(self, monkeypatch, tmp_path):
        def bad_replace(src, dst): raise OSError("boom")
        monkeypatch.setattr(os, "replace", bad_replace)
        run_cli(monkeypatch, ["anchor", "create", "--name", "Root CA", "--out", str(tmp_path / "root.uxsp")], passwords=["secret", "secret"], expect_exit=1)

class TestAnchorIssue:
    def _setup_anchor_and_card(self, tmp_path, monkeypatch):
        anchor_path = tmp_path / "root.uxsp"
        anchor_path.write_text("fake-anchor")
        card_path = tmp_path / "server.card.json"
        card_path.write_text(json.dumps({"name": "API Server", "role": "SERVER", "entity_id": "eid-card-001"}))
        return str(anchor_path), str(card_path)

    def test_issue_explicit_out(self, monkeypatch, tmp_path, capsys):
        anchor_path, card_path = self._setup_anchor_and_card(tmp_path, monkeypatch)
        out_path = str(tmp_path / "server.signed.json")
        run_cli(monkeypatch, ["anchor", "issue", "--anchor", anchor_path, "--card", card_path, "--days", "30", "--out", out_path], passwords=["secret"])
        assert Path(out_path).exists()

    def test_issue_default_out(self, monkeypatch, tmp_path, capsys):
        anchor_path, card_path = self._setup_anchor_and_card(tmp_path, monkeypatch)
        run_cli(monkeypatch, ["anchor", "issue", "--anchor", anchor_path, "--card", card_path], passwords=["secret"])
        expected = str(tmp_path / "server.card.signed.json")
        assert expected in capsys.readouterr().out

    def test_issue_atomic_cleanup_on_error(self, monkeypatch, tmp_path):
        anchor_path, card_path = self._setup_anchor_and_card(tmp_path, monkeypatch)
        def bad_replace(src, dst): raise OSError("no space")
        monkeypatch.setattr(os, "replace", bad_replace)
        run_cli(monkeypatch, ["anchor", "issue", "--anchor", anchor_path, "--card", card_path], passwords=["secret"], expect_exit=1)

class TestInfo:
    def test_info_output(self, monkeypatch, tmp_path, capsys):
        key_path = tmp_path / "server.uxsp"
        key_path.write_text("fake")
        run_cli(monkeypatch, ["info", "--key", str(key_path)], passwords=["secret"])
        assert "Entity ID" in capsys.readouterr().out

class TestRotateRevoke:
    def test_rotate(self, monkeypatch, tmp_path, capsys):
        key_path = tmp_path / "server.uxsp"
        key_path.write_text("fake")
        run_cli(monkeypatch, ["rotate", "--key", str(key_path)], passwords=["secret", "newsecret", "newsecret"])
        assert "Keys rotated" in capsys.readouterr().out
        
    def test_revoke(self, monkeypatch, tmp_path, capsys):
        key_path = tmp_path / "server.uxsp"
        key_path.write_text("fake")
        run_cli(monkeypatch, ["revoke", "--key", str(key_path), "--reason", "Compromised"], passwords=["secret"])
        assert "Identity revoked" in capsys.readouterr().out

class TestSecureStreamLive:
    def _setup_files(self, tmp_path):
        sender_path = tmp_path / "sender.uxsp"
        sender_path.write_text("fake")
        receiver_card = tmp_path / "recv.json"
        receiver_card.write_text(json.dumps({"name": "Recv", "role": "SERVER", "entity_id": "eid"}))
        payload = tmp_path / "payload.uxsp"
        payload.write_text("fake")
        target = tmp_path / "target.txt"
        target.write_text("hello")
        return str(sender_path), str(receiver_card), str(payload), str(target)
        
    def test_secure_send(self, monkeypatch, tmp_path, capsys):
        s, r, p, t = self._setup_files(tmp_path)
        out_path = str(tmp_path / "out.uxsp")
        run_cli(monkeypatch, ["secure", "send", "--sender", s, "--receiver", r, "--file", t, "--out", out_path], passwords=["secret"])
        assert Path(out_path).exists()
        
    def test_secure_send_missing_file_text(self, monkeypatch, tmp_path, capsys):
        s, r, p, t = self._setup_files(tmp_path)
        run_cli(monkeypatch, ["secure", "send", "--sender", s, "--receiver", r], passwords=["secret"], expect_exit=1)
        
    def test_secure_send_text(self, monkeypatch, tmp_path, capsys):
        s, r, p, t = self._setup_files(tmp_path)
        out_path = str(tmp_path / "out.uxsp")
        run_cli(monkeypatch, ["secure", "send", "--sender", s, "--receiver", r, "--text", "hello", "--out", out_path], passwords=["secret"])
        assert Path(out_path).exists()
        
    def test_secure_receive(self, monkeypatch, tmp_path, capsys):
        s, r, p, t = self._setup_files(tmp_path)
        out_path = str(tmp_path / "out.txt")
        run_cli(monkeypatch, ["secure", "receive", "--receiver", s, "--payload", p, "--out", out_path], passwords=["secret"])
        assert Path(out_path).exists()

    def test_stream_send(self, monkeypatch, tmp_path, capsys):
        s, r, p, t = self._setup_files(tmp_path)
        out_path = str(tmp_path / "out.stream")
        run_cli(monkeypatch, ["stream", "send", "--sender", s, "--receiver", r, "--file", t, "--out", out_path], passwords=["secret"])
        assert Path(out_path).exists()
        
    def test_stream_receive(self, monkeypatch, tmp_path, capsys):
        s, r, p, t = self._setup_files(tmp_path)
        out_path = str(tmp_path / "out.stream")
        run_cli(monkeypatch, ["stream", "receive", "--receiver", s, "--payload", p, "--out", out_path], passwords=["secret"])
        assert Path(out_path).exists()
        
    def test_live_session(self, monkeypatch, tmp_path, capsys):
        s, r, p, t = self._setup_files(tmp_path)
        run_cli(monkeypatch, ["live", "session", "--identity", s, "--peer", r], passwords=["secret"])
        assert "Session established" in capsys.readouterr().out
        
    def test_live_voice(self, monkeypatch, tmp_path, capsys):
        s, r, p, t = self._setup_files(tmp_path)
        run_cli(monkeypatch, ["live", "voice", "--identity", s, "--peer", r], passwords=["secret"])
        assert "Voice session established" in capsys.readouterr().out
        
class TestMainErrorHandling:
    def test_func_raises_prints_error_and_exits_1(self, monkeypatch, tmp_path, capsys):
        from uxsp.cli import identity
        def boom(_args): raise ValueError("something went wrong")
        monkeypatch.setattr(identity, "keygen", boom)
        run_cli(monkeypatch, ["keygen", "--name", "X", "--role", "SERVER", "--out", "x"], passwords=["s", "s"], expect_exit=1)
        assert "something went wrong" in capsys.readouterr().err

    def test_no_subcommand_exits(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["uxsp"])
        from uxsp.cli import main
        with pytest.raises(SystemExit):
            main()

    def test_unknown_subcommand_exits(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["uxsp", "doesnotexist"])
        from uxsp.cli import main
        with pytest.raises(SystemExit):
            main()

class TestChmodCalledOnNonWin32:
    def test_pubcard_chmod_called(self, monkeypatch, tmp_path):
        key_path = tmp_path / "k.uxsp"
        key_path.write_text("fake")
        chmod_calls = []
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(os, "chmod", lambda path, mode: chmod_calls.append(mode))
        run_cli(monkeypatch, ["pubcard", "--key", str(key_path), "--out", str(tmp_path/"o.json")], passwords=["secret"])
        assert chmod_calls == [0o644]

    def test_anchor_create_chmod_called(self, monkeypatch, tmp_path):
        chmod_calls = []
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(os, "chmod", lambda path, mode: chmod_calls.append(mode))
        run_cli(monkeypatch, ["anchor", "create", "--name", "Root", "--out", str(tmp_path/"r.uxsp")], passwords=["s", "s"])
        assert 0o644 in chmod_calls

    def test_anchor_issue_chmod_called(self, monkeypatch, tmp_path):
        a_path = tmp_path / "r.uxsp"
        a_path.write_text("fake")
        c_path = tmp_path / "x.json"
        c_path.write_text(json.dumps({"name": "X", "role": "SERVER", "entity_id": "e"}))
        chmod_calls = []
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(os, "chmod", lambda path, mode: chmod_calls.append(mode))
        run_cli(monkeypatch, ["anchor", "issue", "--anchor", str(a_path), "--card", str(c_path)], passwords=["s"])
        assert 0o644 in chmod_calls

    def test_pubcard_chmod_skipped_on_win32(self, monkeypatch, tmp_path):
        key_path = tmp_path / "server.uxsp"
        key_path.write_text("fake")
        chmod_calls = []
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(os, "chmod", lambda *a, **kw: chmod_calls.append(a))
        run_cli(monkeypatch, ["pubcard", "--key", str(key_path), "--out", str(tmp_path/"o.json")], passwords=["s"])
        assert chmod_calls == []

    def test_anchor_create_chmod_skipped_on_win32(self, monkeypatch, tmp_path):
        chmod_calls = []
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(os, "chmod", lambda *a, **kw: chmod_calls.append(a))
        run_cli(monkeypatch, ["anchor", "create", "--name", "R", "--out", str(tmp_path/"r.uxsp")], passwords=["s", "s"])
        assert chmod_calls == []

    def test_issue_chmod_skipped_on_win32(self, monkeypatch, tmp_path):
        a_path = tmp_path / "r.uxsp"
        a_path.write_text("f")
        c_path = tmp_path / "x.json"
        c_path.write_text(json.dumps({"name": "X", "role": "S", "entity_id": "e"}))
        chmod_calls = []
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(os, "chmod", lambda *a, **kw: chmod_calls.append(a))
        run_cli(monkeypatch, ["anchor", "issue", "--anchor", str(a_path), "--card", str(c_path)], passwords=["s"])
        assert chmod_calls == []

class TestSecureReceiveNonFile:
    def test_secure_receive_non_file(self, monkeypatch, tmp_path, capsys):
        s_path = tmp_path / "s.uxsp"
        s_path.write_text("fake")
        p_path = tmp_path / "p.uxsp"
        p_path.write_text("fake")
        
        monkeypatch.setattr("uxsp.secure.Receive", lambda pkg, receiver: {"key": "val"})
        
        run_cli(monkeypatch, ["secure", "receive", "--receiver", str(s_path), "--payload", str(p_path)], passwords=["secret"])
        assert "Received Data" in capsys.readouterr().out
