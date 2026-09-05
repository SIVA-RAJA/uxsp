"""
uxsp.storage.noncestore — Production Nonce Store Backends

What this file does:
    Provides heavier-weight, multi-process-safe nonce store implementations for
    production deployments where nonces must survive across process restarts
    (Postgres) or be shared across multiple servers (Redis).

    All classes implement the NonceStore interface from uxsp.core.nonce and are
    therefore drop-in replacements for the lightweight MemoryNonceStore.

    This module also re-exports the core abstractions (NonceStore, MemoryNonceStore,
    UXSPStoreError, generate_nonce, NONCE_BYTES) so callers can import everything
    they need from a single location.

Available backends:
    SlidingWindowNonceStore — Redis sorted-set with per-nonce expiry scores.
    RedisNonceStore         — Redis string keys with native TTL expiry.
    PostgresNonceStore      — PostgreSQL table with expires_at column.
    TieredNonceStore        — Redis L1 + Postgres L2 (recommended production).

    AsyncNonceStore         — Async ABC for async nonce stores.
    AsyncRedisNonceStore    — Native async Redis backend.

Also re-exported from uxsp.core.nonce:
    NonceStore, MemoryNonceStore, UXSPStoreError, generate_nonce, NONCE_BYTES.
"""
from __future__ import annotations

import contextlib
import logging
import re
import time
import warnings
from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import UTC
from datetime import datetime as _dt
from datetime import timedelta as _td
from typing import Any

# Re-export core abstractions so callers can import from one place
from uxsp.core.nonce import (  # noqa: F401  (re-export)
    NONCE_BYTES,
    MemoryNonceStore,
    NonceStore,
    UXSPStoreError,
    generate_nonce,
)

redis: Any = None
try:
    import redis as _redis

    redis = _redis
except ImportError:
    pass

psycopg2: Any = None
try:
    import psycopg2 as _psycopg2

    psycopg2 = _psycopg2
except ImportError:
    pass


_logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# SLIDING WINDOW NONCE STORE — Redis sorted set
# ─────────────────────────────────────────────


class SlidingWindowNonceStore(NonceStore):
    """
    Redis-backed nonce store using a sorted set with per-nonce expiry scores.

    What this class does:
        Stores each nonce in a Redis ZSET where the score is the Unix expiry
        time.  A Lua script atomically prunes expired nonces, then adds the new
        nonce with NX (only-if-not-present) semantics.  This makes mark_used()
        both atomic and O(log N).

        cleanup() removes expired nonces on demand; Redis also garbage-collects
        the ZSET automatically after a generous grace period (window + 1 hour).

    Use this when you need accurate sliding-window semantics (nonces expire at
    the exact TTL from when they were first seen, not at a fixed window boundary).
    """
    _ZSET_KEY = "seen"
    def __init__(
        self, redis_client: Any, window_seconds: int = 300, key_prefix: str = "uxsp:nonce:sw:"
    ) -> None:

        if redis is None:
            raise ImportError("Redis driver not found. Please install it with: pip install redis")

        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._redis = redis_client
        self._window = window_seconds
        self._prefix = key_prefix

        self._mark_used_script = self._redis.register_script("""
            local key    = KEYS[1]
            local now    = tonumber(ARGV[1])
            local expiry = tonumber(ARGV[2])
            local nonce  = ARGV[3]
            local window = tonumber(ARGV[4])

            redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
            local added = redis.call('ZADD', key, 'NX', expiry, nonce)
            if added == 1 then
                redis.call('EXPIRE', key, window + 3600)
            end
            return added
        """)

    def _key(self) -> str:
        return f"{self._prefix}{self._ZSET_KEY}"

    def mark_used(self, nonce: str, ttl_seconds: int = 300) -> bool:
        """
        Mark nonce as used within a sliding window.
        Uses expiry time as the score in the sorted set.
        """
        try:
            now = time.time()
            expiry = now + ttl_seconds
            rkey = self._key()

            added = self._mark_used_script(keys=[rkey], args=[now, expiry, nonce, ttl_seconds])
            return bool(added)

        except Exception as e:
            raise UXSPStoreError(
                f"SlidingWindowNonceStore unavailable (Redis): {e}. "
                f"Replay protection cannot be guaranteed. "
                f"Reject this envelope."
            ) from e

    def is_seen(self, nonce: str) -> bool:
        try:
            score = self._redis.zscore(self._key(), nonce)
            if score is None:
                return False

            return bool(score > time.time())
        except Exception as e:
            raise UXSPStoreError(f"SlidingWindowNonceStore unavailable (Redis): {e}.") from e

    def cleanup(self) -> int:
        try:
            return int(self._redis.zremrangebyscore(self._key(), 0, time.time()))
        except Exception as e:
            raise UXSPStoreError(f"SlidingWindowNonceStore cleanup failed: {e}.") from e

    def size(self) -> int:
        """Current number of nonces in the window."""
        try:
            return int(self._redis.zcard(self._key()))
        except Exception as e:
            raise UXSPStoreError(f"SlidingWindowNonceStore unavailable: {e}.") from e


# ─────────────────────────────────────────────
# REDIS STORE — production
# ─────────────────────────────────────────────


class RedisNonceStore(NonceStore):
    """
    Redis-backed nonce store using one string key per nonce with native TTL.

    What this class does:
        Uses SET nx ex (set-if-not-exists with expiry) to atomically mark a
        nonce as used.  Redis handles expiry automatically so cleanup() is a
        no-op.  This is the simplest Redis-based nonce store and suitable for
        most production deployments.

    Use SlidingWindowNonceStore instead if you need more accurate timing or
    want to inspect/count nonces in the window.
    """
    def __init__(self, redis_client: Any, key_prefix: str = "uxsp:nonce:") -> None:
        if redis is None:
            raise ImportError("Redis driver not found. Please install it with: pip install redis")

        self._redis = redis_client
        self._prefix = key_prefix

    def _key(self, nonce: str) -> str:
        return f"{self._prefix}{nonce}"

    def mark_used(self, nonce: str, ttl_seconds: int = 300) -> bool:

        try:
            result = self._redis.set(self._key(nonce), "1", nx=True, ex=ttl_seconds)
            return result is True
        except Exception as e:
            raise UXSPStoreError(
                f"Nonce store unavailable (Redis): {e}. "
                f"Replay protection cannot be guaranteed. "
                f"Reject this envelope."
            ) from e

    def is_seen(self, nonce: str) -> bool:
        """
        Raises UXSPStoreError if Redis is unreachable.
        """
        try:
            return bool(self._redis.exists(self._key(nonce)) > 0)
        except Exception as e:
            raise UXSPStoreError(f"Nonce store unavailable (Redis): {e}.") from e

    def cleanup(self) -> int:
        """Redis handles expiry automatically. No-op."""
        return 0


class AsyncNonceStore(ABC):
    """
    Abstract base class for all async UXSP nonce stores.
    """
    @abstractmethod
    async def mark_used(self, nonce: str, ttl_seconds: int = 300) -> bool: ...

    @abstractmethod
    async def is_seen(self, nonce: str) -> bool: ...

    @abstractmethod
    async def cleanup(self) -> int: ...


class AsyncRedisNonceStore(AsyncNonceStore):
    """
    Native Async Redis backend for AsyncNonceStore.
    """
    def __init__(self, async_redis_client: Any, key_prefix: str = "uxsp:nonce:") -> None:
        self._redis = async_redis_client
        self._prefix = key_prefix

    def _key(self, nonce: str) -> str:
        return f"{self._prefix}{nonce}"

    async def mark_used(self, nonce: str, ttl_seconds: int = 300) -> bool:
        try:
            result = await self._redis.set(self._key(nonce), "1", nx=True, ex=ttl_seconds)
            return result is True
        except Exception as e:
            raise UXSPStoreError(
                f"Async Nonce store unavailable (Redis): {e}. "
                f"Replay protection cannot be guaranteed. "
                f"Reject this envelope."
            ) from e

    async def is_seen(self, nonce: str) -> bool:
        try:
            return bool(await self._redis.exists(self._key(nonce)) > 0)
        except Exception as e:
            raise UXSPStoreError(f"Async Nonce store unavailable (Redis): {e}.") from e

    async def cleanup(self) -> int:
        return 0


# ─────────────────────────────────────────────
# POSTGRES NONCE STORE — durable audit log
# ─────────────────────────────────────────────


class PostgresNonceStore(NonceStore):
    """
    Durable nonce store backed by a PostgreSQL table.

    What this class does:
        Stores nonces in an 'uxsp_nonces' table with an expires_at column.
        mark_used() uses INSERT ... ON CONFLICT DO NOTHING ... RETURNING to
        atomically check-and-insert in a single round-trip.  is_seen() checks
        for a non-expired nonce.  cleanup() deletes expired rows.

        When the table exceeds 1 000 000 rows and a new nonce is inserted,
        emits a RuntimeWarning advising that cleanup() should be scheduled.

    Required: psycopg2 or psycopg2-binary installed.
    Accepts either a raw psycopg2 connection or a connection pool.

    Use as the durable L2 in a TieredNonceStore paired with RedisNonceStore.
    """
    DDL = """
    CREATE TABLE IF NOT EXISTS uxsp_nonces (
        nonce      TEXT        PRIMARY KEY,
        seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_uxsp_nonces_expires
        ON uxsp_nonces (expires_at);
    """

    def __init__(
        self, conn_or_pool: Any, window_seconds: int = 300, table: str = "uxsp_nonces"
    ) -> None:

        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", table):
            raise ValueError(
                f"Invalid table name '{table}'. "
                f"Must be a valid SQL identifier (letters, digits, underscores)."
            )

        if psycopg2 is None:
            raise ImportError(
                "Postgres driver (psycopg2) not found. Please install it with: pip install psycopg2-binary"
            )

        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._pool_or_conn = conn_or_pool
        self._window = window_seconds
        self._table = table
        self._qtable = f'"{table}"'
        self._is_pool = hasattr(conn_or_pool, "getconn") and not hasattr(conn_or_pool, "cursor")

    def _ddl(self) -> str:
        idx_name = f'"idx_{self._table}_expires"'
        return f"""
        CREATE TABLE IF NOT EXISTS {self._qtable} (
            nonce      TEXT        PRIMARY KEY,
            seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
            expires_at TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX IF NOT EXISTS {idx_name}
            ON {self._qtable} (expires_at);
        """

    @staticmethod
    def _rollback_quietly(conn: Any | None) -> None:
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.rollback()

    @contextlib.contextmanager
    def _conn(self) -> Iterator[Any]:
        """Context manager that yields a connection from the pool or the bare conn."""
        if self._is_pool:
            c = None
            try:
                c = self._pool_or_conn.getconn()
                yield c
            finally:
                if c is not None:
                    self._pool_or_conn.putconn(c)
        else:
            yield self._pool_or_conn

    def create_table(self) -> None:
        """Create the nonce table if it does not exist."""
        conn: Any | None = None
        try:
            with self._conn() as active_conn:
                conn = active_conn
                with active_conn.cursor() as cur:
                    cur.execute(self._ddl())
                    active_conn.commit()
        except Exception as e:
            self._rollback_quietly(conn)
            raise UXSPStoreError(f"PostgresNonceStore: failed to create table: {e}") from e

    def mark_used(self, nonce: str, ttl_seconds: int = 300) -> bool:

        expires = _dt.now(UTC) + _td(seconds=ttl_seconds)
        conn: Any | None = None
        try:
            with self._conn() as active_conn:
                conn = active_conn
                with active_conn.cursor() as cur:
                    cur.execute(
                        f"""
                            INSERT INTO {self._qtable} (nonce, expires_at)
                            VALUES (%s, %s)
                            ON CONFLICT (nonce) DO NOTHING
                            RETURNING nonce
                            """,
                        (nonce, expires),
                    )
                    inserted = bool(cur.fetchone() is not None)

                    if inserted and nonce.endswith("0"):
                        cur.execute(
                            "SELECT reltuples FROM pg_class WHERE relname = %s", (self._table,)
                        )
                        row = cur.fetchone()
                        count = int(row[0]) if row is not None else 0
                        if count > 1_000_000:
                            warnings.warn(
                                f"PostgresNonceStore table '{self._table}' has {count} rows. "
                                f"Performance may degrade. Please ensure cleanup() is scheduled.",
                                RuntimeWarning,
                                stacklevel=3,
                            )
                    active_conn.commit()
            return inserted
        except UXSPStoreError:
            self._rollback_quietly(conn)
            raise
        except Exception as e:
            self._rollback_quietly(conn)
            raise UXSPStoreError(
                f"PostgresNonceStore unavailable: {e}. Replay protection cannot be guaranteed."
            ) from e

    def is_seen(self, nonce: str) -> bool:
        conn: Any | None = None
        try:
            with self._conn() as active_conn:
                conn = active_conn
                with active_conn.cursor() as cur:
                    cur.execute(
                        f"""
                                SELECT 1 FROM {self._qtable}
                                WHERE nonce = %s AND expires_at > %s
                                """,
                        (nonce, _dt.now(UTC)),
                    )
                    seen = cur.fetchone() is not None
            return seen

        except UXSPStoreError:
            self._rollback_quietly(conn)
            raise
        except Exception as e:
            self._rollback_quietly(conn)
            raise UXSPStoreError(f"PostgresNonceStore unavailable: {e}.") from e

    def cleanup(self) -> int:
        conn: Any | None = None
        try:
            with self._conn() as active_conn:
                conn = active_conn
                with active_conn.cursor() as cur:
                    cur.execute(
                        f"DELETE FROM {self._qtable} WHERE expires_at < %s", (_dt.now(UTC),)
                    )
                    removed = cur.rowcount
                    active_conn.commit()
            return int(removed)
        except UXSPStoreError:
            self._rollback_quietly(conn)
            raise
        except Exception as e:
            if conn is not None:
                self._rollback_quietly(conn)
            raise UXSPStoreError(f"PostgresNonceStore cleanup failed: {e}.") from e


# ─────────────────────────────────────────────
# TIERED NONCE STORE — Redis L1 + Postgres L2
# ─────────────────────────────────────────────


class TieredNonceStore(NonceStore):
    """
    Two-tier nonce store with a fast L1 (Redis) and a durable L2 (Postgres).

    What this class does:
        mark_used() — tries the fast store first; if it returns False (nonce
                       already seen), replay is rejected immediately.  If the
                       fast store is unavailable, falls through to the durable
                       store with a warning log.
        is_seen()   — checks the fast store first; on a miss or error, checks
                       the durable store.
        cleanup()   — runs cleanup on both stores and returns the total count
                       of nonces removed.  Errors in either store are suppressed.

    This is the recommended production configuration: Redis provides
    sub-millisecond performance while Postgres provides durability in case
    Redis fails or is restarted.
    """
    def __init__(self, fast: NonceStore, durable: NonceStore) -> None:
        self._fast = fast
        self._durable = durable

    def mark_used(self, nonce: str, ttl_seconds: int = 300) -> bool:

        try:
            if not self._fast.mark_used(nonce, ttl_seconds=ttl_seconds):
                return False
        except UXSPStoreError as e:
            _logger.warning("Fast nonce store unavailable, falling through to durable: %s", e)

        result = self._durable.mark_used(nonce, ttl_seconds=ttl_seconds)
        if result:
            with contextlib.suppress(UXSPStoreError):
                self._fast.mark_used(nonce, ttl_seconds=ttl_seconds)
        return result

    def is_seen(self, nonce: str) -> bool:
        """Check fast store first, fall back to durable."""
        try:
            if self._fast.is_seen(nonce):
                return True
        except UXSPStoreError:
            pass
        return self._durable.is_seen(nonce)

    def cleanup(self) -> int:
        """Clean up both stores. Returns total removed."""
        total = 0
        with contextlib.suppress(UXSPStoreError):
            total += self._fast.cleanup()
        with contextlib.suppress(UXSPStoreError):
            total += self._durable.cleanup()
        return total
