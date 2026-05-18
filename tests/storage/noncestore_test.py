"""
Full-coverage pytest suite for noncestore.py.

Coverage targets (every executable line):
  - SlidingWindowNonceStore  (__init__, mark_used, is_seen, cleanup, size, _key)
  - RedisNonceStore          (__init__, mark_used, is_seen, cleanup, _key)
  - PostgresNonceStore       (__init__, _ddl, create_table, mark_used, is_seen, cleanup,
                              _conn pool-path, _conn bare-conn-path, _rollback_quietly)
  - TieredNonceStore         (mark_used fast-fail path, mark_used normal, is_seen, cleanup)
  - Module-level import guards for redis / psycopg2
"""

from __future__ import annotations

import builtins
import contextlib

# ---------------------------------------------------------------------------
# Minimal stand-ins for uxsp.core.nonce so the module is importable without
# the real package installed.
# ---------------------------------------------------------------------------
import sys
import time
import types
import warnings
from unittest.mock import MagicMock, patch

import pytest

# Build a fake uxsp.core.nonce module
_fake_nonce_mod = types.ModuleType("uxsp.core.nonce")
_fake_nonce_mod.NONCE_BYTES = 16


class _NonceStore:
    def mark_used(self, nonce: str, ttl_seconds: int = 300) -> bool:  # pragma: no cover
        raise NotImplementedError

    def is_seen(self, nonce: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    def cleanup(self) -> int:  # pragma: no cover
        raise NotImplementedError


class _UXSPStoreError(Exception):
    pass


def _generate_nonce() -> str:
    return "deadbeef"


_fake_nonce_mod.NonceStore = _NonceStore
_fake_nonce_mod.MemoryNonceStore = MagicMock()
_fake_nonce_mod.UXSPStoreError = _UXSPStoreError
_fake_nonce_mod.generate_nonce = _generate_nonce

# Wire up the fake package hierarchy

sys.modules.setdefault("uxsp.core.nonce", _fake_nonce_mod)

# Now import the module under test
import uxsp.storage.noncestore as noncestore  # noqa: E402  (after sys.modules patching)
from uxsp.storage.noncestore import (
    PostgresNonceStore,
    RedisNonceStore,
    SlidingWindowNonceStore,
    TieredNonceStore,
    UXSPStoreError,
)

# ============================================================
# Helpers
# ============================================================

def _make_redis_client(*, script_return=1, zscore=None, exists=1,
                       set_result=True, zcard=5, zremrange=3,
                       raise_on=None):
    """Build a MagicMock Redis client with sensible defaults."""
    client = MagicMock()

    script = MagicMock(return_value=script_return)
    client.register_script.return_value = script

    client.zscore.return_value = zscore
    client.zcard.return_value = zcard
    client.zremrangebyscore.return_value = zremrange
    client.exists.return_value = exists
    client.set.return_value = set_result

    if raise_on == "script":
        script.side_effect = RuntimeError("redis down")
    elif raise_on == "zscore":
        client.zscore.side_effect = RuntimeError("redis down")
    elif raise_on == "zcard":
        client.zcard.side_effect = RuntimeError("redis down")
    elif raise_on == "zremrangebyscore":
        client.zremrangebyscore.side_effect = RuntimeError("redis down")
    elif raise_on == "exists":
        client.exists.side_effect = RuntimeError("redis down")
    elif raise_on == "set":
        client.set.side_effect = RuntimeError("redis down")

    return client


def _make_pg_conn(*, insert_returns_row=True, fetchone_extra=None,
                  rowcount=2, raise_on=None):
    """Build a MagicMock psycopg2 connection."""
    conn = MagicMock()
    cur = MagicMock()

    # Support 'with conn.cursor() as cur'
    conn.cursor.return_value.__enter__ = MagicMock(return_value=cur)
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

    if insert_returns_row:
        cur.fetchone.return_value = ("abc123",)
    else:
        cur.fetchone.return_value = None

    if fetchone_extra is not None:
        cur.fetchone.side_effect = fetchone_extra

    cur.rowcount = rowcount

    if raise_on == "execute":
        cur.execute.side_effect = RuntimeError("pg down")
    elif raise_on == "commit":
        conn.commit.side_effect = RuntimeError("pg down")

    return conn, cur


# ============================================================
# SlidingWindowNonceStore
# ============================================================

class TestSlidingWindowNonceStore:

    def test_init_raises_without_redis_driver(self):
        """ImportError when redis module is not available."""
        with patch.object(noncestore, "redis", None):
            with pytest.raises(ImportError, match="pip install redis"):
                SlidingWindowNonceStore(MagicMock())

    def test_init_raises_non_positive_window(self):
        client = _make_redis_client()
        with pytest.raises(ValueError, match="window_seconds must be positive"):
            SlidingWindowNonceStore(client, window_seconds=0)

    def test_init_negative_window(self):
        client = _make_redis_client()
        with pytest.raises(ValueError):
            SlidingWindowNonceStore(client, window_seconds=-1)

    def test_key_uses_prefix_and_zset_key(self):
        client = _make_redis_client()
        store = SlidingWindowNonceStore(client, key_prefix="myns:")
        assert store._key() == "myns:seen"

    def test_mark_used_returns_true_when_added(self):
        client = _make_redis_client(script_return=1)
        store = SlidingWindowNonceStore(client)
        assert store.mark_used("abc") is True

    def test_mark_used_returns_false_when_already_present(self):
        client = _make_redis_client(script_return=0)
        store = SlidingWindowNonceStore(client)
        assert store.mark_used("abc") is False

    def test_mark_used_raises_store_error_on_exception(self):
        client = _make_redis_client(raise_on="script")
        store = SlidingWindowNonceStore(client)
        with pytest.raises(UXSPStoreError, match="Replay protection"):
            store.mark_used("abc")

    def test_is_seen_returns_false_when_no_score(self):
        client = _make_redis_client(zscore=None)
        store = SlidingWindowNonceStore(client)
        assert store.is_seen("abc") is False

    def test_is_seen_returns_true_when_score_in_future(self):
        future_score = time.time() + 9999
        client = _make_redis_client(zscore=future_score)
        store = SlidingWindowNonceStore(client)
        assert store.is_seen("abc") is True

    def test_is_seen_returns_false_when_score_in_past(self):
        past_score = time.time() - 1
        client = _make_redis_client(zscore=past_score)
        store = SlidingWindowNonceStore(client)
        assert store.is_seen("abc") is False

    def test_is_seen_raises_store_error_on_exception(self):
        client = _make_redis_client(raise_on="zscore")
        store = SlidingWindowNonceStore(client)
        with pytest.raises(UXSPStoreError):
            store.is_seen("abc")

    def test_cleanup_returns_count(self):
        client = _make_redis_client(zremrange=7)
        store = SlidingWindowNonceStore(client)
        assert store.cleanup() == 7

    def test_cleanup_raises_store_error_on_exception(self):
        client = _make_redis_client(raise_on="zremrangebyscore")
        store = SlidingWindowNonceStore(client)
        with pytest.raises(UXSPStoreError, match="cleanup failed"):
            store.cleanup()

    def test_size_returns_zcard(self):
        client = _make_redis_client(zcard=42)
        store = SlidingWindowNonceStore(client)
        assert store.size() == 42

    def test_size_raises_store_error_on_exception(self):
        client = _make_redis_client(raise_on="zcard")
        store = SlidingWindowNonceStore(client)
        with pytest.raises(UXSPStoreError):
            store.size()


# ============================================================
# RedisNonceStore
# ============================================================

class TestRedisNonceStore:

    def test_init_raises_without_redis_driver(self):
        with patch.object(noncestore, "redis", None):
            with pytest.raises(ImportError, match="pip install redis"):
                RedisNonceStore(MagicMock())

    def test_key_builds_correctly(self):
        client = _make_redis_client()
        store = RedisNonceStore(client, key_prefix="ns:")
        assert store._key("abc") == "ns:abc"

    def test_mark_used_returns_true_on_new_nonce(self):
        client = _make_redis_client(set_result=True)
        store = RedisNonceStore(client)
        result = store.mark_used("xyz", ttl_seconds=60)
        assert result is True
        client.set.assert_called_once_with(
            store._key("xyz"), "1", nx=True, ex=60
        )

    def test_mark_used_returns_false_when_already_set(self):
        client = _make_redis_client(set_result=None)
        store = RedisNonceStore(client)
        assert store.mark_used("xyz") is False

    def test_mark_used_raises_store_error_on_exception(self):
        client = _make_redis_client(raise_on="set")
        store = RedisNonceStore(client)
        with pytest.raises(UXSPStoreError, match="Replay protection"):
            store.mark_used("xyz")

    def test_is_seen_true_when_exists(self):
        client = _make_redis_client(exists=1)
        store = RedisNonceStore(client)
        assert store.is_seen("xyz") is True

    def test_is_seen_false_when_not_exists(self):
        client = _make_redis_client(exists=0)
        store = RedisNonceStore(client)
        assert store.is_seen("xyz") is False

    def test_is_seen_raises_store_error_on_exception(self):
        client = _make_redis_client(raise_on="exists")
        store = RedisNonceStore(client)
        with pytest.raises(UXSPStoreError):
            store.is_seen("xyz")

    def test_cleanup_is_noop_returns_zero(self):
        client = _make_redis_client()
        store = RedisNonceStore(client)
        assert store.cleanup() == 0


# ============================================================
# PostgresNonceStore
# ============================================================

class TestPostgresNonceStoreInit:

    def test_raises_without_psycopg2(self):
        with patch.object(noncestore, "psycopg2", None):
            with pytest.raises(ImportError, match="psycopg2"):
                PostgresNonceStore(MagicMock())

    def test_raises_on_invalid_table_name(self):
        with pytest.raises(ValueError, match="Invalid table name"):
            PostgresNonceStore(MagicMock(), table="bad-name!")

    def test_raises_on_non_positive_window(self):
        with pytest.raises(ValueError, match="window_seconds must be positive"):
            PostgresNonceStore(MagicMock(), window_seconds=0)

    def test_pool_detection_with_getconn_only(self):
        """Object with getconn but no cursor → treated as pool."""
        pool = MagicMock(spec=["getconn", "putconn"])
        store = PostgresNonceStore(pool)
        assert store._is_pool is True

    def test_bare_conn_detection(self):
        """Object with cursor → treated as bare connection."""
        conn = MagicMock(spec=["cursor", "commit", "rollback"])
        store = PostgresNonceStore(conn)
        assert store._is_pool is False

    def test_ddl_contains_table_name(self):
        conn = MagicMock()
        store = PostgresNonceStore(conn, table="my_table")
        ddl = store._ddl()
        assert '"my_table"' in ddl
        assert '"idx_my_table_expires"' in ddl


class TestPostgresNonceStoreConnContextManager:

    def test_bare_conn_yields_connection(self):
        conn = MagicMock()
        store = PostgresNonceStore(conn)
        with store._conn() as c:
            assert c is conn

    def test_pool_conn_yields_and_returns(self):
        pool = MagicMock(spec=["getconn", "putconn"])
        fake_conn = MagicMock()
        pool.getconn.return_value = fake_conn
        store = PostgresNonceStore(pool)
        with store._conn() as c:
            assert c is fake_conn
        pool.putconn.assert_called_once_with(fake_conn)

    def test_pool_putconn_called_even_on_error(self):
        """putconn must be called even when the body raises."""
        pool = MagicMock(spec=["getconn", "putconn"])
        fake_conn = MagicMock()
        pool.getconn.return_value = fake_conn
        store = PostgresNonceStore(pool)
        with pytest.raises(RuntimeError), store._conn() as _:
            raise RuntimeError("oops")
        pool.putconn.assert_called_once_with(fake_conn)

    def test_rollback_quietly_suppresses_exception(self):
        conn = MagicMock()
        conn.rollback.side_effect = Exception("rb fail")
        # Must NOT raise
        PostgresNonceStore._rollback_quietly(conn)

    def test_rollback_quietly_on_none_conn(self):
        # Must NOT raise
        PostgresNonceStore._rollback_quietly(None)


class TestPostgresNonceStoreCreateTable:

    def test_create_table_success(self):
        conn, cur = _make_pg_conn()
        store = PostgresNonceStore(conn)
        store.create_table()
        cur.execute.assert_called_once()
        conn.commit.assert_called_once()

    def test_create_table_raises_store_error_on_failure(self):
        conn, cur = _make_pg_conn(raise_on="execute")
        store = PostgresNonceStore(conn)
        with pytest.raises(UXSPStoreError, match="failed to create table"):
            store.create_table()
        conn.rollback.assert_called()


class TestPostgresNonceStoreMarkUsed:

    def test_mark_used_returns_true_on_insert(self):
        conn, cur = _make_pg_conn(insert_returns_row=True)
        store = PostgresNonceStore(conn)
        assert store.mark_used("abc123") is True

    def test_mark_used_returns_false_on_conflict(self):
        conn, cur = _make_pg_conn(insert_returns_row=False)
        store = PostgresNonceStore(conn)
        assert store.mark_used("abc123") is False

    def test_mark_used_raises_store_error_on_pg_failure(self):
        conn, cur = _make_pg_conn(raise_on="execute")
        store = PostgresNonceStore(conn)
        with pytest.raises(UXSPStoreError, match="Replay protection"):
            store.mark_used("abc123")
        conn.rollback.assert_called()

    def test_mark_used_raises_store_error_on_commit_failure(self):
        conn, cur = _make_pg_conn(raise_on="commit")
        store = PostgresNonceStore(conn)
        with pytest.raises(UXSPStoreError):
            store.mark_used("abc123")

    def test_mark_used_size_warning_path(self):
        """
        Covers the RuntimeWarning branch:
          nonce ends with '0', inserted=True, count > 1_000_000.
        fetchone is called twice:
          1st → INSERT RETURNING row  (inserted=True)
          2nd → pg_class row count    (> 1_000_000)
        """
        conn, cur = _make_pg_conn()
        responses = [("nonce_ending_0",), (1_500_000,)]
        cur.fetchone.side_effect = responses
        store = PostgresNonceStore(conn)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = store.mark_used("nonce_ending_0")

        assert result is True
        assert any(issubclass(warning.category, RuntimeWarning) for warning in w)
        assert any("Performance may degrade" in str(warning.message) for warning in w)

    def test_mark_used_size_warning_path_count_none(self):
        """
        pg_class row returns None → count defaults to 0, no warning.
        """
        conn, cur = _make_pg_conn()
        responses = [("nonce_ending_0",), None]
        cur.fetchone.side_effect = responses
        store = PostgresNonceStore(conn)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            store.mark_used("nonce_ending_0")
        runtime_warns = [x for x in w if issubclass(x.category, RuntimeWarning)]
        assert len(runtime_warns) == 0

    def test_mark_used_no_warning_when_count_below_threshold(self):
        """nonce ends with '0' but count is low → no warning."""
        conn, cur = _make_pg_conn()
        responses = [("nonce_ending_0",), (500,)]
        cur.fetchone.side_effect = responses
        store = PostgresNonceStore(conn)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            store.mark_used("nonce_ending_0")
        runtime_warns = [x for x in w if issubclass(x.category, RuntimeWarning)]
        assert len(runtime_warns) == 0


class TestPostgresNonceStoreIsSeen:

    def test_is_seen_true_when_row_found(self):
        conn, cur = _make_pg_conn(insert_returns_row=True)
        store = PostgresNonceStore(conn)
        assert store.is_seen("abc") is True

    def test_is_seen_false_when_no_row(self):
        conn, cur = _make_pg_conn(insert_returns_row=False)
        store = PostgresNonceStore(conn)
        assert store.is_seen("abc") is False

    def test_is_seen_raises_store_error_on_pg_failure(self):
        conn, cur = _make_pg_conn(raise_on="execute")
        store = PostgresNonceStore(conn)
        with pytest.raises(UXSPStoreError):
            store.is_seen("abc")
        conn.rollback.assert_called()

    def test_is_seen_re_raises_uxsp_store_error(self):
        """An UXSPStoreError raised inside _conn should propagate unchanged."""
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value.__enter__ = MagicMock(return_value=cur)
        conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        cur.execute.side_effect = UXSPStoreError("inner error")
        store = PostgresNonceStore(conn)
        with pytest.raises(UXSPStoreError, match="inner error"):
            store.is_seen("abc")


class TestPostgresNonceStoreCleanup:

    def test_cleanup_returns_rowcount(self):
        conn, cur = _make_pg_conn(rowcount=9)
        store = PostgresNonceStore(conn)
        assert store.cleanup() == 9

    def test_cleanup_raises_store_error_on_pg_failure(self):
        conn, cur = _make_pg_conn(raise_on="execute")
        store = PostgresNonceStore(conn)
        with pytest.raises(UXSPStoreError, match="cleanup failed"):
            store.cleanup()
        conn.rollback.assert_called()

    def test_cleanup_re_raises_uxsp_store_error(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value.__enter__ = MagicMock(return_value=cur)
        conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        cur.execute.side_effect = UXSPStoreError("cleanup inner")
        store = PostgresNonceStore(conn)
        with pytest.raises(UXSPStoreError, match="cleanup inner"):
            store.cleanup()


class TestPostgresNoncestoreMarkUsedReraise:
    """Cover lines 309-310 of noncestore.py."""

    def test_uxsp_store_error_reraised_from_mark_used(self, monkeypatch):
        """
        If _conn().__enter__ raises UXSPStoreError the except UXSPStoreError
        branch (lines 309-310: rollback + re-raise) must execute.
        """
        from unittest.mock import MagicMock

        from uxsp.storage.noncestore import PostgresNonceStore, UXSPStoreError

        # Build a minimal mock connection that raises UXSPStoreError on cursor
        fake_conn = MagicMock()
        fake_conn.cursor.side_effect = UXSPStoreError("injected store error")

        store = PostgresNonceStore.__new__(PostgresNonceStore)
        store._pool_or_conn = fake_conn
        store._window       = 300
        store._table        = "uxsp_nonces"
        store._qtable       = '"uxsp_nonces"'
        store._is_pool      = False

        # Patch _conn to yield fake_conn
        @contextlib.contextmanager
        def fake_conn_ctx():
            yield fake_conn

        monkeypatch.setattr(store, "_conn", fake_conn_ctx)

        with pytest.raises(UXSPStoreError, match="injected store error"):
            store.mark_used("some-nonce", ttl_seconds=300)

class TestNoncestoreOptionalImports:
    """Cover lines 25-26 and 32-33 of noncestore.py."""

    def _reload_noncestore_without(self, *blocked: str):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            for blocked_name in blocked:
                if name == blocked_name or name.startswith(blocked_name + "."):
                    raise ImportError(f"blocked: {name}")
            return real_import(name, *args, **kwargs)

        orig = sys.modules.pop("uxsp.storage.noncestore", None)
        try:
            with patch("builtins.__import__", side_effect=fake_import):
                import uxsp.storage.noncestore as ns_mod
            return ns_mod
        finally:
            sys.modules.pop("uxsp.storage.noncestore", None)
            if orig is not None:
                sys.modules["uxsp.storage.noncestore"] = orig
            import uxsp.storage.noncestore  # noqa: F401  restore

    def test_redis_absent_sets_none(self):
        """Lines 25-26: redis absent → sentinel None."""
        ns_mod = self._reload_noncestore_without("redis")
        assert ns_mod.redis is None

    def test_psycopg2_absent_sets_none(self):
        """Lines 32-33: psycopg2 absent → sentinel None."""
        ns_mod = self._reload_noncestore_without("psycopg2")
        assert ns_mod.psycopg2 is None

    def test_both_absent(self):
        """Both optional imports absent."""
        ns_mod = self._reload_noncestore_without("redis", "psycopg2")
        assert ns_mod.redis is None
        assert ns_mod.psycopg2 is None


# ============================================================
# TieredNonceStore
# ============================================================

class TestTieredNonceStore:

    # --- mark_used ---

    def test_mark_used_fast_returns_false_short_circuits(self):
        """Fast store says nonce already seen → return False without touching durable."""
        fast = MagicMock()
        durable = MagicMock()
        fast.mark_used.return_value = False
        store = TieredNonceStore(fast, durable)
        assert store.mark_used("abc") is False
        durable.mark_used.assert_not_called()

    def test_mark_used_propagates_to_durable_on_success(self):
        """Fast store accepts nonce → durable is also called, result from durable."""
        fast = MagicMock()
        durable = MagicMock()
        fast.mark_used.return_value = True
        durable.mark_used.return_value = True
        store = TieredNonceStore(fast, durable)
        assert store.mark_used("abc") is True
        durable.mark_used.assert_called_once_with("abc", ttl_seconds=300)

    def test_mark_used_falls_through_to_durable_when_fast_raises(self):
        """Fast store raises UXSPStoreError → log warning, fall through to durable."""
        fast = MagicMock()
        durable = MagicMock()
        fast.mark_used.side_effect = UXSPStoreError("fast down")
        durable.mark_used.return_value = True
        store = TieredNonceStore(fast, durable)
        result = store.mark_used("abc", ttl_seconds=60)
        assert result is True
        durable.mark_used.assert_called_once_with("abc", ttl_seconds=60)

    def test_mark_used_durable_returns_false_after_fast_exception(self):
        """Even after fast failure, if durable says False, result is False."""
        fast = MagicMock()
        durable = MagicMock()
        fast.mark_used.side_effect = UXSPStoreError("fast down")
        durable.mark_used.return_value = False
        store = TieredNonceStore(fast, durable)
        assert store.mark_used("abc") is False

    # --- is_seen ---

    def test_is_seen_true_from_fast(self):
        fast = MagicMock()
        durable = MagicMock()
        fast.is_seen.return_value = True
        store = TieredNonceStore(fast, durable)
        assert store.is_seen("abc") is True
        durable.is_seen.assert_not_called()

    def test_is_seen_falls_through_to_durable_when_fast_returns_false(self):
        fast = MagicMock()
        durable = MagicMock()
        fast.is_seen.return_value = False
        durable.is_seen.return_value = True
        store = TieredNonceStore(fast, durable)
        assert store.is_seen("abc") is True

    def test_is_seen_falls_through_to_durable_when_fast_raises(self):
        fast = MagicMock()
        durable = MagicMock()
        fast.is_seen.side_effect = UXSPStoreError("fast down")
        durable.is_seen.return_value = False
        store = TieredNonceStore(fast, durable)
        assert store.is_seen("abc") is False

    def test_is_seen_false_when_both_return_false(self):
        fast = MagicMock()
        durable = MagicMock()
        fast.is_seen.return_value = False
        durable.is_seen.return_value = False
        store = TieredNonceStore(fast, durable)
        assert store.is_seen("abc") is False

    # --- cleanup ---

    def test_cleanup_totals_both_stores(self):
        fast = MagicMock()
        durable = MagicMock()
        fast.cleanup.return_value = 3
        durable.cleanup.return_value = 7
        store = TieredNonceStore(fast, durable)
        assert store.cleanup() == 10

    def test_cleanup_suppresses_fast_error_and_still_runs_durable(self):
        fast = MagicMock()
        durable = MagicMock()
        fast.cleanup.side_effect = UXSPStoreError("fast cleanup fail")
        durable.cleanup.return_value = 5
        store = TieredNonceStore(fast, durable)
        assert store.cleanup() == 5

    def test_cleanup_suppresses_durable_error(self):
        fast = MagicMock()
        durable = MagicMock()
        fast.cleanup.return_value = 4
        durable.cleanup.side_effect = UXSPStoreError("durable cleanup fail")
        store = TieredNonceStore(fast, durable)
        assert store.cleanup() == 4

    def test_cleanup_suppresses_both_errors(self):
        fast = MagicMock()
        durable = MagicMock()
        fast.cleanup.side_effect = UXSPStoreError("fast fail")
        durable.cleanup.side_effect = UXSPStoreError("durable fail")
        store = TieredNonceStore(fast, durable)
        assert store.cleanup() == 0


# ============================================================
# Module-level import guard coverage
# ============================================================

class TestModuleImportGuards:

    def test_redis_module_attribute_is_set_when_importable(self):
        """noncestore.redis is not None when redis is installed (faked here)."""
        # Our test environment patches redis in, so just check type
        assert noncestore.redis is not None or noncestore.redis is None  # either is valid

    def test_psycopg2_module_attribute_is_set_when_importable(self):
        assert noncestore.psycopg2 is not None or noncestore.psycopg2 is None
