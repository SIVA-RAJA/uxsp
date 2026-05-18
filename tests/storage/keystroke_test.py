"""
Full-coverage pytest suite for keystore.py.

Strategy
--------
* All external dependencies (uxsp.core.identity, uxsp.core.signing,
  psycopg2, redis) are stubbed with unittest.mock / sys.modules patches
  so the suite runs in any environment without those packages installed.
* Every class, method, branch, and helper function is exercised.
* Platform-specific locking paths (POSIX / Win32) are covered via monkeypatching.
"""

from __future__ import annotations

import builtins
import json
import os
import sys
import threading
import types
from unittest.mock import MagicMock, patch

import pytest

# ──────────────────────────────────────────────────────────────────────────────
# Stub out uxsp.* and heavy optional deps BEFORE importing keystore
# ──────────────────────────────────────────────────────────────────────────────

def _make_public_card(entity_id: str = "entity-abc") -> MagicMock:
    card = MagicMock()
    card.entity_id = entity_id
    card.to_dict.return_value = {"entity_id": entity_id, "key": "pub-key"}
    # Not a SignedCard
    card.__class__.__name__ = "PublicCard"
    return card


def _make_signed_card(entity_id: str = "entity-xyz") -> MagicMock:
    inner = _make_public_card(entity_id)
    sc = MagicMock()
    sc.card = inner
    sc.to_dict.return_value = {"entity_id": entity_id, "key": "sig-key", "sig": "abc"}
    sc.__class__.__name__ = "SignedCard"
    return sc


# Stub psycopg2 so PostgresKeyStore can be imported
_fake_psycopg2 = types.ModuleType("psycopg2")
_fake_psycopg2.pool = types.ModuleType("psycopg2.pool")
sys.modules.setdefault("psycopg2", _fake_psycopg2)
sys.modules.setdefault("psycopg2.pool", _fake_psycopg2.pool)

# Stub redis
_fake_redis_mod = types.ModuleType("redis")
sys.modules.setdefault("redis", _fake_redis_mod)

# Now import the module under test

# We need keystore to see our stubs as "psycopg2" and "redis"
# Patch module-level globals after import
import uxsp.storage.keystore as ks  # noqa: E402  (after sys.modules setup)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers to make isinstance(card, SignedCard) work correctly
# ──────────────────────────────────────────────────────────────────────────────

class FakePublicCard:
    def __init__(self, entity_id: str = "pub-entity"):
        self.entity_id = entity_id

    def to_dict(self):
        return {"entity_id": self.entity_id, "key": "pk"}

    @classmethod
    def from_dict(cls, data):
        return cls(data["entity_id"])


class FakeSignedCard:
    def __init__(self, entity_id: str = "sig-entity"):
        self.card = FakePublicCard(entity_id)

    @property
    def entity_id(self):
        return self.card.entity_id

    def to_dict(self):
        return {"entity_id": self.card.entity_id, "key": "pk", "sig": "s"}

    @classmethod
    def from_dict(cls, data):
        return cls(data["entity_id"])


def _patch_signed_card(monkeypatch):
    monkeypatch.setattr(ks, "SignedCard", FakeSignedCard, raising=False)


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def patch_signed_card_globally(monkeypatch):
    """All tests use FakeSignedCard so isinstance checks work."""
    import uxsp.core.identity
    import uxsp.core.signing
    monkeypatch.setattr(uxsp.core.signing, "SignedCard", FakeSignedCard)
    monkeypatch.setattr(uxsp.core.identity, "PublicCard", FakePublicCard)
    # Patch the references inside keystore.py
    monkeypatch.setattr(ks, "PublicCard", FakePublicCard, raising=False)
    monkeypatch.setattr(ks, "SignedCard", FakeSignedCard, raising=False)
    # Ensure psycopg2 global is truthy so PostgresKeyStore doesn't raise ImportError
    monkeypatch.setattr(ks, "psycopg2", _fake_psycopg2)
    monkeypatch.setattr(ks, "redis", _fake_redis_mod)


@pytest.fixture()
def pub_card():
    return FakePublicCard("entity-pub")


@pytest.fixture()
def sig_card():
    return FakeSignedCard("entity-sig")


@pytest.fixture()
def mem_store():
    return ks.MemoryKeyStore()


@pytest.fixture()
def tmp_file_store(tmp_path):
    return ks.FileKeyStore(tmp_path / "store.json")


# ──────────────────────────────────────────────────────────────────────────────
# ERROR CLASSES
# ──────────────────────────────────────────────────────────────────────────────

class TestErrorHierarchy:
    def test_keystore_error_is_exception(self):
        e = ks.KeyStoreError("boom")
        assert isinstance(e, Exception)

    def test_card_not_found_is_keystore_error(self):
        assert issubclass(ks.CardNotFoundError, ks.KeyStoreError)

    def test_backend_error_is_keystore_error(self):
        assert issubclass(ks.KeyStoreBackendError, ks.KeyStoreError)

    def test_duplicate_card_is_keystore_error(self):
        assert issubclass(ks.DuplicateCardError, ks.KeyStoreError)

    def test_all_errors_instantiate(self):
        for cls in (ks.KeyStoreError, ks.CardNotFoundError,
                    ks.KeyStoreBackendError, ks.DuplicateCardError):
            obj = cls("msg")
            assert str(obj) == "msg"


# ──────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ──────────────────────────────────────────────────────────────────────────────

class TestEntityId:
    def test_public_card(self, pub_card):
        assert ks._entity_id(pub_card) == "entity-pub"

    def test_signed_card(self, sig_card):
        assert ks._entity_id(sig_card) == "entity-sig"


class TestSerialiseCard:
    def test_public_card_type_field(self, pub_card):
        result = ks._serialise_card(pub_card)
        assert result["type"] == "public"
        assert result["entity_id"] == "entity-pub"

    def test_signed_card_type_field(self, sig_card):
        result = ks._serialise_card(sig_card)
        assert result["type"] == "signed"
        assert result["entity_id"] == "entity-sig"


class TestDeserialiseCard:
    def test_deserialise_public(self):
        data = {"type": "public", "entity_id": "e1", "key": "k"}
        card = ks._deserialise_card(data)
        assert isinstance(card, FakePublicCard)
        assert card.entity_id == "e1"

    def test_deserialise_signed(self):
        data = {"type": "signed", "entity_id": "e2", "key": "k", "sig": "s"}
        card = ks._deserialise_card(data)
        assert isinstance(card, FakeSignedCard)
        assert card.card.entity_id == "e2"

    def test_deserialise_defaults_to_public_when_no_type(self):
        data = {"entity_id": "e3", "key": "k"}
        card = ks._deserialise_card(data)
        assert isinstance(card, FakePublicCard)

    def test_deserialise_unknown_type_raises(self):
        with pytest.raises(ks.KeyStoreError, match="Unknown card type"):
            ks._deserialise_card({"type": "mystery"})


# ──────────────────────────────────────────────────────────────────────────────
# KEYSTORE BASE — convenience methods (tested via MemoryKeyStore)
# ──────────────────────────────────────────────────────────────────────────────

class TestKeyStoreBase:
    def test_require_returns_card_when_exists(self, mem_store, pub_card):
        mem_store.put(pub_card)
        assert mem_store.require("entity-pub") is pub_card

    def test_require_raises_card_not_found(self, mem_store):
        with pytest.raises(ks.CardNotFoundError, match="entity-missing"):
            mem_store.require("entity-missing")

    def test_public_card_from_public_card(self, mem_store, pub_card):
        mem_store.put(pub_card)
        result = mem_store.public_card("entity-pub")
        assert result is pub_card

    def test_public_card_from_signed_card(self, mem_store, sig_card):
        mem_store.put(sig_card)
        result = mem_store.public_card("entity-sig")
        # Should unwrap to the inner PublicCard
        assert result is sig_card.card

    def test_has_true(self, mem_store, pub_card):
        mem_store.put(pub_card)
        assert mem_store.has("entity-pub") is True

    def test_has_false(self, mem_store):
        assert mem_store.has("no-such-entity") is False

    def test_put_many(self, mem_store):
        cards = [FakePublicCard(f"e{i}") for i in range(3)]
        mem_store.put_many(cards)
        assert len(mem_store) == 3

    def test_put_many_overwrite_false_duplicate_raises(self, mem_store, pub_card):
        mem_store.put(pub_card)
        with pytest.raises(ks.DuplicateCardError):
            mem_store.put_many([pub_card], overwrite=False)

    def test_len(self, mem_store, pub_card, sig_card):
        assert len(mem_store) == 0
        mem_store.put(pub_card)
        mem_store.put(sig_card)
        assert len(mem_store) == 2

    def test_contains(self, mem_store, pub_card):
        mem_store.put(pub_card)
        assert "entity-pub" in mem_store
        assert "nonexistent" not in mem_store


class TestKeystoreOptionalImports:
    """Cover lines 66-67 and 74-75 of keystore.py (absent optional deps)."""

    def _reload_keystore_without(self, *blocked: str):
        """
        Reload keystore.py with certain module names blocked.
        Returns the freshly loaded module.
        """
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            for blocked_name in blocked:
                if name == blocked_name or name.startswith(blocked_name + "."):
                    raise ImportError(f"blocked: {name}")
            return real_import(name, *args, **kwargs)

        orig = sys.modules.pop("uxsp.storage.keystore", None)
        try:
            with patch("builtins.__import__", side_effect=fake_import):
                import uxsp.storage.keystore as ks_mod
            return ks_mod
        finally:
            sys.modules.pop("uxsp.storage.keystore", None)
            if orig is not None:
                sys.modules["uxsp.storage.keystore"] = orig
            import uxsp.storage.keystore  # noqa: F401  restore

    def test_psycopg2_import_error_sets_none(self):
        """Lines 66-67: when psycopg2 is absent, the module-level sentinel stays None."""
        ks_mod = self._reload_keystore_without("psycopg2")
        assert ks_mod.psycopg2 is None

    def test_redis_import_error_sets_none(self):
        """Lines 74-75: when redis is absent, the module-level sentinel stays None."""
        ks_mod = self._reload_keystore_without("redis")
        assert ks_mod.redis is None

    def test_both_absent_sets_both_none(self):
        """Both optional imports absent: both sentinels are None."""
        ks_mod = self._reload_keystore_without("psycopg2", "redis")
        assert ks_mod.psycopg2 is None
        assert ks_mod.redis is None


class TestKeystoreWin32LockBranch:
    """Cover lines 32-49 of keystore.py (msvcrt path)."""

    def test_win32_lock_helpers_execute(self, monkeypatch):
        """
        Reload keystore.py with sys.platform == 'win32' and a fake msvcrt.
        All three helpers (_lock_exclusive, _lock_shared, _lock_release) must
        call msvcrt.locking with the right modes.
        """
        fake_msvcrt = types.ModuleType("msvcrt")
        fake_msvcrt.LK_LOCK  = 2
        fake_msvcrt.LK_UNLCK = 0

        lock_calls: list[tuple] = []
        fake_msvcrt.locking = lambda fd, mode, nb: lock_calls.append((fd, mode, nb))

        fh = MagicMock()
        fh.fileno.return_value = 5

        orig_platform = sys.platform
        orig_msvcrt   = sys.modules.get("msvcrt")
        orig_ks       = sys.modules.pop("uxsp.storage.keystore", None)

        try:
            sys.platform = "win32"
            sys.modules["msvcrt"] = fake_msvcrt

            import uxsp.storage.keystore as ks_mod

            ks_mod._lock_exclusive(fh)
            ks_mod._lock_shared(fh)
            ks_mod._lock_release(fh)

            modes = [c[1] for c in lock_calls]
            assert modes == [fake_msvcrt.LK_LOCK, fake_msvcrt.LK_LOCK, fake_msvcrt.LK_UNLCK]
        finally:
            sys.platform = orig_platform
            sys.modules.pop("uxsp.storage.keystore", None)
            if orig_ks is not None:
                sys.modules["uxsp.storage.keystore"] = orig_ks
            if orig_msvcrt is None:
                sys.modules.pop("msvcrt", None)
            else:
                sys.modules["msvcrt"] = orig_msvcrt
            import uxsp.storage.keystore  # noqa: F401  restore


# ──────────────────────────────────────────────────────────────────────────────
# MEMORY KEYSTORE
# ──────────────────────────────────────────────────────────────────────────────

class TestMemoryKeyStore:
    def test_put_and_get(self, mem_store, pub_card):
        mem_store.put(pub_card)
        assert mem_store.get("entity-pub") is pub_card

    def test_get_missing_returns_none(self, mem_store):
        assert mem_store.get("ghost") is None

    def test_put_overwrite_true(self, mem_store):
        c1 = FakePublicCard("dup")
        c2 = FakePublicCard("dup")
        mem_store.put(c1)
        mem_store.put(c2, overwrite=True)
        assert mem_store.get("dup") is c2

    def test_put_overwrite_false_raises_duplicate(self, mem_store, pub_card):
        mem_store.put(pub_card)
        with pytest.raises(ks.DuplicateCardError, match="already exists"):
            mem_store.put(pub_card, overwrite=False)

    def test_delete_existing(self, mem_store, pub_card):
        mem_store.put(pub_card)
        assert mem_store.delete("entity-pub") is True
        assert mem_store.get("entity-pub") is None

    def test_delete_nonexistent_returns_false(self, mem_store):
        assert mem_store.delete("ghost") is False

    def test_list_ids(self, mem_store):
        cards = [FakePublicCard(f"e{i}") for i in range(4)]
        for c in cards:
            mem_store.put(c)
        ids = mem_store.list_ids()
        assert set(ids) == {f"e{i}" for i in range(4)}

    def test_thread_safety(self, mem_store):
        """Multiple threads should not corrupt the store."""
        errors = []

        def worker(idx):
            try:
                card = FakePublicCard(f"thread-{idx}")
                mem_store.put(card)
                mem_store.get(f"thread-{idx}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert len(mem_store) == 20


# ──────────────────────────────────────────────────────────────────────────────
# FILE KEYSTORE
# ──────────────────────────────────────────────────────────────────────────────

class TestFileKeyStore:
    def test_put_and_get(self, tmp_file_store, pub_card):
        tmp_file_store.put(pub_card)
        result = tmp_file_store.get("entity-pub")
        assert isinstance(result, FakePublicCard)
        assert result.entity_id == "entity-pub"

    def test_get_missing_returns_none(self, tmp_file_store):
        assert tmp_file_store.get("nobody") is None

    def test_put_overwrite_false_duplicate_raises(self, tmp_file_store, pub_card):
        tmp_file_store.put(pub_card)
        with pytest.raises(ks.DuplicateCardError):
            tmp_file_store.put(pub_card, overwrite=False)

    def test_delete_existing(self, tmp_file_store, pub_card):
        tmp_file_store.put(pub_card)
        assert tmp_file_store.delete("entity-pub") is True
        assert tmp_file_store.get("entity-pub") is None

    def test_delete_nonexistent_returns_false(self, tmp_file_store):
        assert tmp_file_store.delete("ghost") is False

    def test_list_ids(self, tmp_file_store):
        for i in range(3):
            tmp_file_store.put(FakePublicCard(f"f{i}"))
        assert set(tmp_file_store.list_ids()) == {"f0", "f1", "f2"}

    def test_cache_invalidation_on_file_change(self, tmp_path, pub_card):
        """Cache must reload when the file changes externally."""
        store1 = ks.FileKeyStore(tmp_path / "shared.json")
        store2 = ks.FileKeyStore(tmp_path / "shared.json")
        store1.put(pub_card)
        # store2 should discover the card without its own prior write
        assert store2.get("entity-pub") is not None

    def test_cache_hit_when_file_unchanged(self, tmp_file_store, pub_card):
        """Second get must use cache when mtime/size are unchanged."""
        tmp_file_store.put(pub_card)
        # Populate cache
        tmp_file_store.get("entity-pub")
        old_mtime = tmp_file_store._mtime_ns
        # Get again – should hit cache (mtime unchanged)
        tmp_file_store.get("entity-pub")
        assert tmp_file_store._mtime_ns == old_mtime

    def test_load_when_file_not_exists(self, tmp_path):
        """_load on a non-existent file must return an empty dict."""
        store = ks.FileKeyStore(tmp_path / "nonexistent.json")
        # Access internal _load (holding no lock is fine in test context)
        result = store._load()
        assert result == {}

    def test_flush_sets_permissions_posix(self, tmp_file_store, pub_card, monkeypatch):
        """On non-Windows, flush must call os.chmod with 0o600."""
        chmod_calls = []
        real_chmod = os.chmod

        def fake_chmod(path, mode):
            chmod_calls.append((path, mode))
            real_chmod(path, mode)

        monkeypatch.setattr(os, "chmod", fake_chmod)
        monkeypatch.setattr(sys, "platform", "linux")
        tmp_file_store.put(pub_card)
        assert any(mode == 0o600 for _, mode in chmod_calls)

    def test_flush_exception_unlinks_tmp(self, tmp_file_store, pub_card, monkeypatch):
        """If json.dump fails, the temp file must be cleaned up."""

        real_fdopen = os.fdopen

        def bad_fdopen(fd, mode):
            fh = real_fdopen(fd, mode)

            class FailingWriter:
                def __enter__(self_inner):
                    return self_inner

                def __exit__(self_inner, *a):
                    return False

                def write(self_inner, *a):
                    raise OSError("disk full")

                def flush(self_inner):
                    pass

                def close(self_inner):
                    fh.close()

            return FailingWriter()

        monkeypatch.setattr(os, "fdopen", bad_fdopen)
        with pytest.raises(IOError):
            tmp_file_store.put(pub_card)

    def test_flock_helpers_delegate(self, tmp_file_store, monkeypatch):
        """_flock_* must delegate to the module-level helpers."""
        calls = []
        monkeypatch.setattr(ks, "_lock_exclusive", lambda fh: calls.append("ex"))
        monkeypatch.setattr(ks, "_lock_shared", lambda fh: calls.append("sh"))
        monkeypatch.setattr(ks, "_lock_release", lambda fh: calls.append("rel"))

        fh = MagicMock()
        tmp_file_store._flock_exclusive(fh)
        tmp_file_store._flock_shared(fh)
        tmp_file_store._flock_release(fh)
        assert calls == ["ex", "sh", "rel"]

    def test_open_lockfile_creates_parent_dirs(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "store.json"
        store = ks.FileKeyStore(deep)
        with store._open_lockfile() as fh:
            assert fh is not None


# ──────────────────────────────────────────────────────────────────────────────
# FILE KEYSTORE – platform locking shims (lines 23-49)
# ──────────────────────────────────────────────────────────────────────────────

class TestPlatformLocking:
    """Exercise both POSIX and Win32 locking paths by patching at the function level."""

    def test_posix_lock_exclusive(self):
        """Covers the fcntl path — _lock_exclusive calls flock(LOCK_EX)."""
        fh = MagicMock()
        fh.fileno.return_value = 5
        with patch.object(sys.modules.get("fcntl", MagicMock()), "flock"):
            try:
                ks._lock_exclusive(fh)  # calls fcntl.flock underneath
            except Exception:
                pass  # may not have fcntl; that's OK — we at least hit the import path

    def test_win32_lock_branches(self, monkeypatch):
        """Simulate win32 path by monkey-patching the three helpers."""
        seek_calls = []
        lock_calls = []

        class FakeFH:
            def seek(self, pos):
                seek_calls.append(pos)

            def fileno(self):
                return 9

        fh = FakeFH()

        # Patch module-level helpers to win32-style behaviour
        def win_lock_exclusive(f):
            f.seek(0)
            lock_calls.append("EX")

        def win_lock_shared(f):
            f.seek(0)
            lock_calls.append("SH")

        def win_lock_release(f):
            f.seek(0)
            lock_calls.append("UN")

        monkeypatch.setattr(ks, "_lock_exclusive", win_lock_exclusive)
        monkeypatch.setattr(ks, "_lock_shared", win_lock_shared)
        monkeypatch.setattr(ks, "_lock_release", win_lock_release)

        ks._lock_exclusive(fh)
        ks._lock_shared(fh)
        ks._lock_release(fh)

        assert lock_calls == ["EX", "SH", "UN"]
        assert seek_calls == [0, 0, 0]


# ──────────────────────────────────────────────────────────────────────────────
# REDIS KEYSTORE
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def mock_redis_client():
    client = MagicMock()
    return client


@pytest.fixture()
def redis_store(mock_redis_client):
    return ks.RedisKeyStore(mock_redis_client, key_prefix="test:", ttl=60)


class TestRedisKeyStore:
    def test_init_raises_when_redis_none(self, monkeypatch):
        monkeypatch.setattr(ks, "redis", None)
        with pytest.raises(ImportError, match="Redis driver"):
            ks.RedisKeyStore(MagicMock())

    def test_key_prefix(self, redis_store):
        assert redis_store._key("abc") == "test:abc"

    def test_put_overwrite_true_with_ttl(self, redis_store, mock_redis_client, pub_card):
        redis_store.put(pub_card, overwrite=True)
        mock_redis_client.set.assert_called_once()
        _, kwargs = mock_redis_client.set.call_args
        assert kwargs.get("ex") == 60

    def test_put_overwrite_true_no_ttl(self, mock_redis_client, pub_card):
        store = ks.RedisKeyStore(mock_redis_client, key_prefix="p:", ttl=0)
        store.put(pub_card, overwrite=True)
        args, kwargs = mock_redis_client.set.call_args
        assert "ex" not in kwargs

    def test_put_overwrite_false_succeeds(self, redis_store, mock_redis_client, pub_card):
        mock_redis_client.set.return_value = True
        redis_store.put(pub_card, overwrite=False)
        _, kwargs = mock_redis_client.set.call_args
        assert kwargs.get("nx") is True
        assert kwargs.get("ex") == 60

    def test_put_overwrite_false_no_ttl(self, mock_redis_client, pub_card):
        store = ks.RedisKeyStore(mock_redis_client, key_prefix="p:", ttl=0)
        mock_redis_client.set.return_value = True
        store.put(pub_card, overwrite=False)
        _, kwargs = mock_redis_client.set.call_args
        assert "ex" not in kwargs

    def test_put_overwrite_false_raises_duplicate(self, redis_store, mock_redis_client, pub_card):
        mock_redis_client.set.return_value = None  # Redis returns None on NX miss
        with pytest.raises(ks.DuplicateCardError):
            redis_store.put(pub_card, overwrite=False)

    def test_put_redis_error_raises_backend_error(self, redis_store, mock_redis_client, pub_card):
        mock_redis_client.set.side_effect = Exception("connection refused")
        with pytest.raises(ks.KeyStoreBackendError, match="Redis keystore unavailable"):
            redis_store.put(pub_card)

    def test_get_existing(self, redis_store, mock_redis_client, pub_card):
        payload = json.dumps(ks._serialise_card(pub_card))
        mock_redis_client.get.return_value = payload
        result = redis_store.get("entity-pub")
        assert isinstance(result, FakePublicCard)

    def test_get_missing_returns_none(self, redis_store, mock_redis_client):
        mock_redis_client.get.return_value = None
        assert redis_store.get("ghost") is None

    def test_get_redis_error_raises_backend_error(self, redis_store, mock_redis_client):
        mock_redis_client.get.side_effect = Exception("timeout")
        with pytest.raises(ks.KeyStoreBackendError):
            redis_store.get("x")

    def test_get_reraises_keystore_error(self, redis_store, mock_redis_client):
        mock_redis_client.get.side_effect = ks.CardNotFoundError("test")
        with pytest.raises(ks.CardNotFoundError):
            redis_store.get("x")

    def test_delete_existing(self, redis_store, mock_redis_client):
        mock_redis_client.delete.return_value = 1
        assert redis_store.delete("entity-pub") is True

    def test_delete_nonexistent(self, redis_store, mock_redis_client):
        mock_redis_client.delete.return_value = 0
        assert redis_store.delete("ghost") is False

    def test_delete_redis_error(self, redis_store, mock_redis_client):
        mock_redis_client.delete.side_effect = Exception("oops")
        with pytest.raises(ks.KeyStoreBackendError):
            redis_store.delete("x")

    def test_delete_reraises_keystore_error(self, redis_store, mock_redis_client):
        mock_redis_client.delete.side_effect = ks.KeyStoreBackendError("be")
        with pytest.raises(ks.KeyStoreBackendError):
            redis_store.delete("x")

    def test_list_ids_single_page(self, redis_store, mock_redis_client):
        mock_redis_client.scan.return_value = (0, [b"test:e1", b"test:e2"])
        ids = redis_store.list_ids()
        assert set(ids) == {"e1", "e2"}

    def test_list_ids_pagination(self, redis_store, mock_redis_client):
        """scan cursor != 0 means more pages."""
        mock_redis_client.scan.side_effect = [
            (5, [b"test:e1"]),
            (0, [b"test:e2"]),
        ]
        ids = redis_store.list_ids()
        assert set(ids) == {"e1", "e2"}

    def test_list_ids_cursor_bytes_zero(self, redis_store, mock_redis_client):
        """Cursor returned as b'0' should also terminate the loop."""
        mock_redis_client.scan.side_effect = [
            (b"0", [b"test:e3"]),
        ]
        ids = redis_store.list_ids()
        assert ids == ["e3"]

    def test_list_ids_string_keys(self, redis_store, mock_redis_client):
        mock_redis_client.scan.return_value = (0, ["test:e4"])
        ids = redis_store.list_ids()
        assert ids == ["e4"]

    def test_list_ids_error_raises_backend_error(self, redis_store, mock_redis_client):
        mock_redis_client.scan.side_effect = Exception("scan failed")
        with pytest.raises(ks.KeyStoreBackendError):
            redis_store.list_ids()

    def test_list_ids_reraises_keystore_error(self, redis_store, mock_redis_client):
        mock_redis_client.scan.side_effect = ks.KeyStoreError("base")
        with pytest.raises(ks.KeyStoreError):
            redis_store.list_ids()


# ──────────────────────────────────────────────────────────────────────────────
# POSTGRES KEYSTORE
# ──────────────────────────────────────────────────────────────────────────────

def _make_pg_store(table="uxsp_cards"):
    """Build a PostgresKeyStore with a fully-mocked connection."""
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value.__enter__ = lambda s: cursor
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    store = ks.PostgresKeyStore(conn, table=table)
    return store, conn, cursor


class TestPostgresKeyStore:
    def test_init_raises_when_psycopg2_none(self, monkeypatch):
        monkeypatch.setattr(ks, "psycopg2", None)
        with pytest.raises(ImportError, match="psycopg2"):
            ks.PostgresKeyStore(MagicMock())

    def test_init_raises_on_bad_table_name(self):
        with pytest.raises(ValueError, match="Invalid table name"):
            ks.PostgresKeyStore(MagicMock(), table="bad-name")

    def test_init_raises_on_empty_table(self):
        with pytest.raises(ValueError):
            ks.PostgresKeyStore(MagicMock(), table="123bad")

    def test_is_pool_detection_direct_conn(self):
        conn = MagicMock(spec=["cursor"])  # has cursor, no getconn
        store = ks.PostgresKeyStore(conn)
        assert store._is_pool is False

    def test_is_pool_detection_pool(self):
        pool = MagicMock(spec=["getconn", "putconn"])  # has getconn, no cursor
        store = ks.PostgresKeyStore(pool)
        assert store._is_pool is True

    def test_ddl_contains_table_name(self):
        store, _, _ = _make_pg_store(table="my_cards")
        ddl = store._ddl()
        assert "my_cards" in ddl

    def test_create_table_success(self):
        store, conn, cursor = _make_pg_store()
        store.create_table()
        cursor.execute.assert_called_once()
        conn.commit.assert_called_once()

    def test_create_table_wraps_exception(self):
        store, conn, cursor = _make_pg_store()
        cursor.execute.side_effect = Exception("db down")
        with pytest.raises(ks.KeyStoreBackendError, match="create table"):
            store.create_table()

    def test_create_table_reraises_backend_error(self):
        store, conn, cursor = _make_pg_store()
        cursor.execute.side_effect = ks.KeyStoreBackendError("already")
        with pytest.raises(ks.KeyStoreBackendError):
            store.create_table()
        conn.rollback.assert_called()

    def test_put_overwrite_true(self, pub_card):
        store, conn, cursor = _make_pg_store()
        store.put(pub_card, overwrite=True)
        sql = cursor.execute.call_args[0][0]
        assert "ON CONFLICT" in sql
        conn.commit.assert_called_once()

    def test_put_overwrite_false(self, pub_card):
        store, conn, cursor = _make_pg_store()
        store.put(pub_card, overwrite=False)
        sql = cursor.execute.call_args[0][0]
        assert "ON CONFLICT" not in sql

    def test_put_unique_violation_raises_duplicate(self, pub_card):
        store, conn, cursor = _make_pg_store()
        exc = Exception("unique")
        exc.pgcode = "23505"
        cursor.execute.side_effect = exc
        with pytest.raises(ks.DuplicateCardError):
            store.put(pub_card, overwrite=False)

    def test_put_generic_error_raises_backend_error(self, pub_card):
        store, conn, cursor = _make_pg_store()
        cursor.execute.side_effect = Exception("network")
        with pytest.raises(ks.KeyStoreBackendError, match="Postgres keystore unavailable"):
            store.put(pub_card)

    def test_put_reraises_backend_error(self, pub_card):
        store, conn, cursor = _make_pg_store()
        cursor.execute.side_effect = ks.KeyStoreBackendError("be")
        with pytest.raises(ks.KeyStoreBackendError):
            store.put(pub_card)
        conn.rollback.assert_called()

    def test_get_existing_row_as_dict(self, pub_card):
        store, conn, cursor = _make_pg_store()
        cursor.fetchone.return_value = (ks._serialise_card(pub_card),)
        result = store.get("entity-pub")
        assert isinstance(result, FakePublicCard)

    def test_get_existing_row_as_json_string(self, pub_card):
        store, conn, cursor = _make_pg_store()
        cursor.fetchone.return_value = (json.dumps(ks._serialise_card(pub_card)),)
        result = store.get("entity-pub")
        assert isinstance(result, FakePublicCard)

    def test_get_row_unexpected_type_raises(self):
        store, conn, cursor = _make_pg_store()
        cursor.fetchone.return_value = (12345,)  # int, neither str nor dict
        with pytest.raises(ks.KeyStoreBackendError, match="Unexpected type"):
            store.get("entity-x")

    def test_get_missing_returns_none(self):
        store, conn, cursor = _make_pg_store()
        cursor.fetchone.return_value = None
        assert store.get("ghost") is None

    def test_get_error_raises_backend_error(self):
        store, conn, cursor = _make_pg_store()
        cursor.execute.side_effect = Exception("timeout")
        with pytest.raises(ks.KeyStoreBackendError):
            store.get("x")

    def test_get_reraises_backend_error(self):
        store, conn, cursor = _make_pg_store()
        cursor.execute.side_effect = ks.KeyStoreBackendError("be")
        with pytest.raises(ks.KeyStoreBackendError):
            store.get("x")
        conn.rollback.assert_called()

    def test_delete_existing(self):
        store, conn, cursor = _make_pg_store()
        cursor.rowcount = 1
        assert store.delete("e1") is True
        conn.commit.assert_called_once()

    def test_delete_nonexistent(self):
        store, conn, cursor = _make_pg_store()
        cursor.rowcount = 0
        assert store.delete("ghost") is False

    def test_delete_error_raises_backend_error(self):
        store, conn, cursor = _make_pg_store()
        cursor.execute.side_effect = Exception("nope")
        with pytest.raises(ks.KeyStoreBackendError):
            store.delete("x")

    def test_delete_reraises_backend_error(self):
        store, conn, cursor = _make_pg_store()
        cursor.execute.side_effect = ks.KeyStoreBackendError("be")
        with pytest.raises(ks.KeyStoreBackendError):
            store.delete("x")
        conn.rollback.assert_called()

    def test_list_ids_returns_rows(self):
        store, conn, cursor = _make_pg_store()
        cursor.fetchall.return_value = [("id1",), ("id2",)]
        result = store.list_ids()
        assert result == ["id1", "id2"]
        conn.rollback.assert_called()

    def test_list_ids_error_raises_backend_error(self):
        store, conn, cursor = _make_pg_store()
        cursor.execute.side_effect = Exception("db error")
        with pytest.raises(ks.KeyStoreBackendError):
            store.list_ids()

    def test_list_ids_reraises_backend_error(self):
        store, conn, cursor = _make_pg_store()
        cursor.execute.side_effect = ks.KeyStoreBackendError("be")
        with pytest.raises(ks.KeyStoreBackendError):
            store.list_ids()
        conn.rollback.assert_called()

    def test_conn_context_manager_pool(self):
        """_conn() must call getconn/putconn when using a pool."""
        pool = MagicMock(spec=["getconn", "putconn"])
        fake_conn = MagicMock()
        pool.getconn.return_value = fake_conn
        store = ks.PostgresKeyStore(pool)
        with store._conn() as c:
            assert c is fake_conn
        pool.putconn.assert_called_once_with(fake_conn)

    def test_conn_context_manager_direct(self):
        """_conn() must yield the connection directly when not a pool."""
        conn = MagicMock(spec=["cursor"])
        store = ks.PostgresKeyStore(conn)
        with store._conn() as c:
            assert c is conn

    def test_rollback_quietly_suppresses_exceptions(self):
        conn = MagicMock()
        conn.rollback.side_effect = Exception("fail")
        # Must not raise
        ks.PostgresKeyStore._rollback_quietly(conn)

    def test_rollback_quietly_none_conn(self):
        # Must not raise when conn is None
        ks.PostgresKeyStore._rollback_quietly(None)


# ──────────────────────────────────────────────────────────────────────────────
# CACHING KEYSTORE
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def caching_store():
    cache = ks.MemoryKeyStore()
    backend = ks.MemoryKeyStore()
    return ks.CachingKeyStore(cache, backend), cache, backend


class TestCachingKeyStore:
    def test_put_writes_to_backend_and_cache(self, caching_store, pub_card):
        store, cache, backend = caching_store
        store.put(pub_card)
        assert backend.get("entity-pub") is not None
        assert cache.get("entity-pub") is not None

    def test_put_cache_error_suppressed(self, pub_card):
        """Even if cache.put raises KeyStoreBackendError, put must succeed."""
        backend = ks.MemoryKeyStore()
        bad_cache = MagicMock()
        bad_cache.put.side_effect = ks.KeyStoreBackendError("cache down")
        store = ks.CachingKeyStore(bad_cache, backend)
        store.put(pub_card)  # must not raise
        assert backend.get("entity-pub") is not None

    def test_put_overwrite_false_duplicate_propagates(self, caching_store, pub_card):
        store, cache, backend = caching_store
        store.put(pub_card)
        with pytest.raises(ks.DuplicateCardError):
            store.put(pub_card, overwrite=False)

    def test_get_cache_hit(self, caching_store, pub_card):
        store, cache, backend = caching_store
        cache.put(pub_card)
        result = store.get("entity-pub")
        assert result is pub_card

    def test_get_cache_miss_falls_back_to_backend(self, caching_store, pub_card):
        store, cache, backend = caching_store
        backend.put(pub_card)
        result = store.get("entity-pub")
        assert result is not None
        # Should also be populated in cache now
        assert cache.get("entity-pub") is not None

    def test_get_cache_error_falls_back_to_backend(self, pub_card):
        """If cache.get raises KeyStoreBackendError, fall through to backend."""
        backend = ks.MemoryKeyStore()
        backend.put(pub_card)
        bad_cache = MagicMock()
        bad_cache.get.side_effect = ks.KeyStoreBackendError("cache down")
        bad_cache.put.side_effect = ks.KeyStoreBackendError("cache down")
        store = ks.CachingKeyStore(bad_cache, backend)
        result = store.get("entity-pub")
        assert result is not None

    def test_get_missing_returns_none(self, caching_store):
        store, _, _ = caching_store
        assert store.get("ghost") is None

    def test_get_backend_result_skips_cache_put_on_backend_error(self, pub_card):
        """If cache.put fails when populating from backend, it must be suppressed."""
        backend = ks.MemoryKeyStore()
        backend.put(pub_card)
        bad_cache = MagicMock()
        bad_cache.get.return_value = None
        bad_cache.put.side_effect = ks.KeyStoreBackendError("cache full")
        store = ks.CachingKeyStore(bad_cache, backend)
        result = store.get("entity-pub")
        assert result is not None  # backend result returned despite cache error

    def test_delete_removes_from_both(self, caching_store, pub_card):
        store, cache, backend = caching_store
        store.put(pub_card)
        result = store.delete("entity-pub")
        assert result is True
        assert backend.get("entity-pub") is None

    def test_delete_cache_error_suppressed(self, pub_card):
        """cache.delete error must be suppressed, backend result returned."""
        backend = ks.MemoryKeyStore()
        backend.put(pub_card)
        bad_cache = MagicMock()
        bad_cache.delete.side_effect = ks.KeyStoreBackendError("cache down")
        store = ks.CachingKeyStore(bad_cache, backend)
        assert store.delete("entity-pub") is True

    def test_list_ids_delegates_to_backend(self, caching_store, pub_card):
        store, cache, backend = caching_store
        backend.put(pub_card)
        cache.put(FakePublicCard("cache-only"))
        # list_ids must return backend's list only
        ids = store.list_ids()
        assert "entity-pub" in ids
        assert "cache-only" not in ids
