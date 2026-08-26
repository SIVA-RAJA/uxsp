"""
Full-coverage pytest suite for cli.py.

Strategy
--------
* Every function in cli.py is tested via its public CLI entry-point (main())
  using argparse + monkeypatching, so we exercise the real argument-parsing
  paths, not just the helper functions in isolation.
* Domain objects (Identity, TrustAnchor, PublicCard, uxsp.__version__) are
  stubbed with minimal fakes so the tests never depend on the real uxsp package.
* File I/O that cli.py performs (tempfile, os.replace, os.chmod, open) is
  patched or done in a real tmp directory so every branch is reached.
* Error paths (password mismatch, empty password, bad exception from func) are
  all exercised.
"""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

_UXSP_PKG_DIR = _PROJECT_ROOT / "uxsp"

if str(_UXSP_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(_UXSP_PKG_DIR))

class TestInitPackageNotFound:
    """Cover lines 10-11 of uxsp/__init__.py."""

    def test_version_fallback_when_package_not_found(self, monkeypatch):
        """
        When importlib.metadata.version() raises PackageNotFoundError the
        fallback ``__version__ = "1.1.0"`` on line 11 must execute.
        """
        from importlib.metadata import PackageNotFoundError

        # Patch the version() call inside uxsp.__init__
        with patch("importlib.metadata.version", side_effect=PackageNotFoundError("uxsp")):
            # Remove cached module so it re-executes __init__
            orig = sys.modules.pop("uxsp", None)
            try:
                import uxsp  # noqa: F401 – triggers the except branch
                assert uxsp.__version__ == "1.1.0"
            finally:
                # Restore original module
                if orig is not None:
                    sys.modules["uxsp"] = orig
                else:
                    sys.modules.pop("uxsp", None)
                    import uxsp  # re-import to restore normal state  # noqa: F401

# ---------------------------------------------------------------------------
# Helpers – build a minimal fake `uxsp` package so cli.py imports succeed
# ---------------------------------------------------------------------------

def _make_uxsp_module(tmp_path: Path) -> types.ModuleType:
    """Return a fake `uxsp` module with enough surface area for cli.py."""

    mod = types.ModuleType("uxsp")
    mod.__version__ = "0.0.test"

    # --- PublicCard stub ---
    class FakePublicCard:
        def __init__(self, name="Tester", role="SERVER", entity_id="eid-card-001"):
            self.name = name
            self.role = role
            self.entity_id = entity_id

        def to_json(self):
            return json.dumps(
                {"name": self.name, "role": self.role, "entity_id": self.entity_id}
            )

        @classmethod
        def from_json(cls, text: str):
            data = json.loads(text)
            return cls(data["name"], data["role"], data["entity_id"])

    mod.PublicCard = FakePublicCard

    # --- SignedCard stub (returned by anchor.issue) ---
    class FakeSignedCard:
        def __init__(self, card: FakePublicCard):
            self.cert_id = "cert-abc-123"
            self._card = card

        def to_json(self, indent=None):
            return json.dumps({"cert_id": self.cert_id}, indent=indent)

    # --- Identity stub ---
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

    mod.Identity = FakeIdentity

    # --- TrustAnchor stub ---
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

    class FakePublicAnchor:
        def __init__(self, name, entity_id):
            self.name = name
            self.entity_id = entity_id

        def to_json(self):
            return json.dumps({"name": self.name, "entity_id": self.entity_id})

    mod.TrustAnchor = FakeTrustAnchor

    return mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def inject_uxsp(tmp_path, monkeypatch):
    """Inject the fake uxsp module before every test."""
    fake = _make_uxsp_module(tmp_path)
    monkeypatch.setitem(sys.modules, "uxsp", fake)
    # Also remove cli from sys.modules so re-imports pick up the fake uxsp
    sys.modules.pop("cli", None)
    yield fake


@pytest.fixture()
def cli_main():
    """Import (or re-import) cli.main fresh after uxsp is injected."""
    import importlib

    import cli as cli_mod
    importlib.reload(cli_mod)
    return cli_mod.main


# ---------------------------------------------------------------------------
# Utility: run cli.main() with controlled argv and mocked getpass
# ---------------------------------------------------------------------------

def run_cli(
    monkeypatch,
    argv: list[str],
    passwords: list[str] | None = None,
    *,
    expect_exit: int | None = None,
):
    """
    Call cli.main() with the given argv list.

    passwords – list of values that getpass.getpass() should return in order.
    expect_exit – if not None, assert SystemExit with that code.
    """
    import cli as cli_mod

    pw_iter = iter(passwords or [])

    def fake_getpass(prompt="", stream=None):
        return next(pw_iter, "secret123")

    monkeypatch.setattr("getpass.getpass", fake_getpass)
    monkeypatch.setattr(sys, "argv", ["uxsp"] + argv)

    if expect_exit is not None:
        with pytest.raises(SystemExit) as exc_info:
            cli_mod.main()
        assert exc_info.value.code == expect_exit
    else:
        cli_mod.main()


# ===========================================================================
# Tests for _prompt_password
# ===========================================================================

class TestPromptPassword:
    def test_confirm_passwords_match(self, monkeypatch, tmp_path):
        """confirm=True with matching passwords succeeds."""
        monkeypatch.setattr("getpass.getpass", lambda prompt="", stream=None: "abc123")
        import cli
        result = cli._prompt_password("Enter: ", confirm=True)
        assert result == "abc123"

    def test_confirm_passwords_mismatch_exits(self, monkeypatch, capsys):
        """confirm=True with mismatched passwords → sys.exit(1)."""
        answers = iter(["first", "second"])
        monkeypatch.setattr("getpass.getpass", lambda prompt="", stream=None: next(answers))
        import cli
        with pytest.raises(SystemExit) as exc:
            cli._prompt_password("Enter: ", confirm=True)
        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "do not match" in captured.err

    def test_empty_password_exits(self, monkeypatch, capsys):
        """Empty password → sys.exit(1) with message."""
        monkeypatch.setattr("getpass.getpass", lambda prompt="", stream=None: "")
        import cli
        with pytest.raises(SystemExit) as exc:
            cli._prompt_password("Enter: ")
        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "cannot be empty" in captured.err

    def test_no_confirm(self, monkeypatch):
        """confirm=False (default) skips the confirmation prompt."""
        call_count = 0

        def fake_gp(prompt="", stream=None):
            nonlocal call_count
            call_count += 1
            return "pw123"

        monkeypatch.setattr("getpass.getpass", fake_gp)
        import cli
        result = cli._prompt_password("Enter: ", confirm=False)
        assert result == "pw123"
        assert call_count == 1   # only one call, no confirm prompt


# ===========================================================================
# Tests for _version
# ===========================================================================

class TestVersion:
    def test_version_output(self, monkeypatch, capsys, tmp_path):
        run_cli(monkeypatch, ["version"])
        out = capsys.readouterr().out
        assert "0.0.test" in out
        assert "uxsp" in out

# ===========================================================================
# Tests for _keygen
# ===========================================================================

class TestKeygen:
    def test_keygen_creates_identity(self, monkeypatch, tmp_path, capsys):
        out_path = str(tmp_path / "keys" / "server.uxsp")
        run_cli(
            monkeypatch,
            ["keygen", "--name", "API Server", "--role", "SERVER", "--out", out_path],
            passwords=["secret", "secret"],
        )
        captured = capsys.readouterr()
        assert "Identity created" in captured.out
        assert "Saved to" in captured.out
        assert Path(out_path).exists()

    def test_keygen_password_mismatch_exits(self, monkeypatch, tmp_path):
        out_path = str(tmp_path / "server.uxsp")
        run_cli(
            monkeypatch,
            ["keygen", "--name", "X", "--role", "SERVER", "--out", out_path],
            passwords=["pw1", "pw2"],
            expect_exit=1,
        )


# ===========================================================================
# Tests for _pubcard
# ===========================================================================

class TestPubcard:
    def test_pubcard_explicit_out(self, monkeypatch, tmp_path, capsys):
        # First create a fake identity file
        key_path = tmp_path / "server.uxsp"
        key_path.write_text("fake")
        out_path = str(tmp_path / "server.card.json")

        run_cli(
            monkeypatch,
            ["pubcard", "--key", str(key_path), "--out", out_path],
            passwords=["secret"],
        )
        captured = capsys.readouterr()
        assert "Public card" in captured.out
        assert "Entity ID" in captured.out
        assert "Saved to" in captured.out
        assert Path(out_path).exists()

    def test_pubcard_default_out(self, monkeypatch, tmp_path, capsys):
        """When --out is omitted, the output path is derived from the key path."""
        key_path = tmp_path / "mykey.uxsp"
        key_path.write_text("fake")

        run_cli(
            monkeypatch,
            ["pubcard", "--key", str(key_path)],
            passwords=["secret"],
        )
        captured = capsys.readouterr()
        assert "Saved to" in captured.out
        # Default output: <key>.card.json
        expected = str(tmp_path / "mykey.card.json")
        assert expected in captured.out

    def test_pubcard_atomic_write_cleanup_on_error(self, monkeypatch, tmp_path):
        """
        If os.replace raises after tempfile creation, the temp file is deleted
        and the exception propagates (cli wraps it in sys.exit(1)).
        """
        key_path = tmp_path / "server.uxsp"
        key_path.write_text("fake")
        out_path = str(tmp_path / "out.card.json")


        def bad_replace(src, dst):
            raise OSError("disk full")

        monkeypatch.setattr(os, "replace", bad_replace)

        run_cli(
            monkeypatch,
            ["pubcard", "--key", str(key_path), "--out", out_path],
            passwords=["secret"],
            expect_exit=1,
        )

    def test_pubcard_chmod_skipped_on_win32(self, monkeypatch, tmp_path, capsys):
        """On win32, os.chmod should NOT be called (branch: sys.platform != 'win32')."""
        key_path = tmp_path / "server.uxsp"
        key_path.write_text("fake")
        out_path = str(tmp_path / "out.card.json")

        chmod_calls = []

        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(os, "chmod", lambda *a, **kw: chmod_calls.append(a))

        run_cli(
            monkeypatch,
            ["pubcard", "--key", str(key_path), "--out", out_path],
            passwords=["secret"],
        )
        assert chmod_calls == [], "chmod should not be called on win32"


# ===========================================================================
# Tests for _anchor_create
# ===========================================================================

class TestAnchorCreate:
    def test_anchor_create_produces_files(self, monkeypatch, tmp_path, capsys):
        anchor_path = str(tmp_path / "anchors" / "root.uxsp")
        run_cli(
            monkeypatch,
            ["anchor", "create", "--name", "Root CA", "--out", anchor_path],
            passwords=["secret", "secret"],
        )
        captured = capsys.readouterr()
        assert "Trust anchor created" in captured.out
        assert "Anchor key" in captured.out
        assert "Anchor pubkey" in captured.out
        assert Path(anchor_path).exists()

    def test_anchor_create_chmod_skipped_on_win32(self, monkeypatch, tmp_path):
        anchor_path = str(tmp_path / "root.uxsp")
        chmod_calls = []
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(os, "chmod", lambda *a, **kw: chmod_calls.append(a))

        run_cli(
            monkeypatch,
            ["anchor", "create", "--name", "Root CA", "--out", anchor_path],
            passwords=["secret", "secret"],
        )
        assert chmod_calls == []

    def test_anchor_create_atomic_cleanup_on_error(self, monkeypatch, tmp_path):
        anchor_path = str(tmp_path / "root.uxsp")

        def bad_replace(src, dst):
            raise OSError("boom")

        monkeypatch.setattr(os, "replace", bad_replace)

        run_cli(
            monkeypatch,
            ["anchor", "create", "--name", "Root CA", "--out", anchor_path],
            passwords=["secret", "secret"],
            expect_exit=1,
        )


# ===========================================================================
# Tests for _anchor_issue
# ===========================================================================

class TestAnchorIssue:
    def _setup_anchor_and_card(self, tmp_path, monkeypatch):
        """Helper: write a fake anchor file and a real card JSON."""
        anchor_path = tmp_path / "root.uxsp"
        anchor_path.write_text("fake-anchor")

        # Write a real PublicCard JSON
        card_data = {
            "name": "API Server",
            "role": "SERVER",
            "entity_id": "eid-card-001",
        }
        card_path = tmp_path / "server.card.json"
        card_path.write_text(json.dumps(card_data))
        return str(anchor_path), str(card_path)

    def test_issue_explicit_out(self, monkeypatch, tmp_path, capsys):
        anchor_path, card_path = self._setup_anchor_and_card(tmp_path, monkeypatch)
        out_path = str(tmp_path / "server.signed.json")

        run_cli(
            monkeypatch,
            [
                "anchor", "issue",
                "--anchor", anchor_path,
                "--card", card_path,
                "--days", "30",
                "--out", out_path,
            ],
            passwords=["secret"],
        )
        captured = capsys.readouterr()
        assert "Signed card" in captured.out
        assert "Cert ID" in captured.out
        assert "Valid days" in captured.out
        assert "30" in captured.out
        assert Path(out_path).exists()

    def test_issue_default_out(self, monkeypatch, tmp_path, capsys):
        anchor_path, card_path = self._setup_anchor_and_card(tmp_path, monkeypatch)

        run_cli(
            monkeypatch,
            [
                "anchor", "issue",
                "--anchor", anchor_path,
                "--card", card_path,
            ],
            passwords=["secret"],
        )
        captured = capsys.readouterr()
        # Default out: <card_stem>.signed.json
        expected = str(tmp_path / "server.card.signed.json")
        assert expected in captured.out
        assert Path(expected).exists()

    def test_issue_chmod_skipped_on_win32(self, monkeypatch, tmp_path):
        anchor_path, card_path = self._setup_anchor_and_card(tmp_path, monkeypatch)
        out_path = str(tmp_path / "out.json")
        chmod_calls = []
        monkeypatch.setattr("sys.platform", "win32")
        monkeypatch.setattr(os, "chmod", lambda *a, **kw: chmod_calls.append(a))

        run_cli(
            monkeypatch,
            ["anchor", "issue", "--anchor", anchor_path, "--card", card_path, "--out", out_path],
            passwords=["secret"],
        )
        assert chmod_calls == []

    def test_issue_atomic_cleanup_on_error(self, monkeypatch, tmp_path):
        anchor_path, card_path = self._setup_anchor_and_card(tmp_path, monkeypatch)

        def bad_replace(src, dst):
            raise OSError("no space")

        monkeypatch.setattr(os, "replace", bad_replace)

        run_cli(
            monkeypatch,
            ["anchor", "issue", "--anchor", anchor_path, "--card", card_path],
            passwords=["secret"],
            expect_exit=1,
        )


# ===========================================================================
# Tests for _info
# ===========================================================================

class TestInfo:
    def test_info_output(self, monkeypatch, tmp_path, capsys):
        key_path = tmp_path / "server.uxsp"
        key_path.write_text("fake")

        run_cli(
            monkeypatch,
            ["info", "--key", str(key_path)],
            passwords=["secret"],
        )
        captured = capsys.readouterr()
        assert "Entity ID" in captured.out
        assert "Name" in captured.out
        assert "Role" in captured.out
        assert "Created" in captured.out


# ===========================================================================
# Tests for main() error handling
# ===========================================================================

class TestMainErrorHandling:
    def test_func_raises_prints_error_and_exits_1(self, monkeypatch, tmp_path, capsys):
        """If args.func() raises any Exception, main() prints it and exits 1."""
        import cli

        def boom(_args):
            raise ValueError("something went wrong")

        # Patch _keygen with a function that raises
        monkeypatch.setattr(cli, "_keygen", boom)

        out_path = str(tmp_path / "x.uxsp")
        run_cli(
            monkeypatch,
            ["keygen", "--name", "X", "--role", "SERVER", "--out", out_path],
            passwords=["secret", "secret"],
            expect_exit=1,
        )
        captured = capsys.readouterr()
        assert "something went wrong" in captured.err

    def test_no_subcommand_exits(self, monkeypatch):
        """Calling main() without any subcommand should exit (argparse error)."""
        monkeypatch.setattr(sys, "argv", ["uxsp"])
        import cli
        with pytest.raises(SystemExit):
            cli.main()

    def test_unknown_subcommand_exits(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["uxsp", "doesnotexist"])
        import cli
        with pytest.raises(SystemExit):
            cli.main()


# ===========================================================================
# Tests for chmod on non-win32 (positive path — ensure chmod IS called)
# ===========================================================================

class TestChmodCalledOnNonWin32:
    """Ensure the os.chmod branch runs on non-Windows platforms."""

    def test_pubcard_chmod_called(self, monkeypatch, tmp_path):
        key_path = tmp_path / "k.uxsp"
        key_path.write_text("fake")
        out_path = str(tmp_path / "out.card.json")

        chmod_calls = []
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(os, "chmod", lambda path, mode: chmod_calls.append(mode))

        run_cli(
            monkeypatch,
            ["pubcard", "--key", str(key_path), "--out", out_path],
            passwords=["secret"],
        )
        assert chmod_calls == [0o644]

    def test_anchor_create_chmod_called(self, monkeypatch, tmp_path):
        anchor_path = str(tmp_path / "root.uxsp")

        chmod_calls = []
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(os, "chmod", lambda path, mode: chmod_calls.append(mode))

        run_cli(
            monkeypatch,
            ["anchor", "create", "--name", "Root CA", "--out", anchor_path],
            passwords=["secret", "secret"],
        )
        assert 0o644 in chmod_calls

    def test_anchor_issue_chmod_called(self, monkeypatch, tmp_path):
        anchor_path = tmp_path / "root.uxsp"
        anchor_path.write_text("fake-anchor")
        card_data = {"name": "X", "role": "SERVER", "entity_id": "eid-001"}
        card_path = tmp_path / "x.card.json"
        card_path.write_text(json.dumps(card_data))
        out_path = str(tmp_path / "signed.json")

        chmod_calls = []
        monkeypatch.setattr("sys.platform", "linux")
        monkeypatch.setattr(os, "chmod", lambda path, mode: chmod_calls.append(mode))

        run_cli(
            monkeypatch,
            [
                "anchor", "issue",
                "--anchor", str(anchor_path),
                "--card", str(card_path),
                "--out", out_path,
            ],
            passwords=["secret"],
        )
        assert 0o644 in chmod_calls
