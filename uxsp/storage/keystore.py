"""
uxsp.storage.keystore — PublicCard / SignedCard Storage Backends

What this file does:
    Provides pluggable key stores that persist PublicCards and SignedCards so
    that an application can look up a peer’s public keys at runtime without
    requiring the peer to be online.

    All backends implement the KeyStore abstract interface, which provides:
        put(card)          — Store or update a card.
        get(entity_id)     — Retrieve a card by entity ID (None if absent).
        require(entity_id) — Like get() but raises CardNotFoundError if absent.
        delete(entity_id)  — Remove a card.
        list_ids()         — Return all known entity IDs.
        has(entity_id)     — Membership test.
        public_card(entity_id) — Unwrap a SignedCard to its inner PublicCard.

    Available backends:
        MemoryKeyStore    — Thread-safe in-process dict (dev/testing).
        FileKeyStore      — Single JSON file with cross-process exclusive locking.
        RedisKeyStore     — Redis strings with optional TTL (fast cache).
        PostgresKeyStore  — PostgreSQL JSONB table (durable source of truth).
        CachingKeyStore   — Redis in front of Postgres (recommended production).

    Errors:
        KeyStoreError         — Base.
        CardNotFoundError     — No card for the requested entity_id.
        KeyStoreBackendError  — Backend unavailable (treat as security event).
        DuplicateCardError    — Card already exists and overwrite=False.

Portable file locking:
    Uses fcntl on POSIX and msvcrt on Windows so all backends have the same
    thread- and process-safe semantics regardless of operating system.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import tempfile
import threading
from abc import ABC, abstractmethod
from collections.abc import Generator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import IO, Any

# ── Portable file-locking shim ────────────────────────────────────────────────
# fcntl is POSIX-only; on Windows we fall back to msvcrt.locking.
# Both expose exclusive/shared locking over file descriptors so the rest of
# the code can call the same helpers regardless of platform.
if sys.platform != "win32":
    import fcntl as _fcntl

    def _lock_exclusive(fh: Any) -> None:
        _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX)

    def _lock_shared(fh: Any) -> None:
        _fcntl.flock(fh.fileno(), _fcntl.LOCK_SH)

    def _lock_release(fh: Any) -> None:
        _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)
else:
    import msvcrt as _msvcrt

    # msvcrt.locking() works on a byte-range, not the whole file.
    # We lock one byte at position 0, which is sufficient as a mutex.
    _LOCK_NBYTES = 1

    def _lock_exclusive(fh: Any) -> None:
        fh.seek(0)
        _msvcrt.locking(fh.fileno(), _msvcrt.LK_LOCK, _LOCK_NBYTES)

    def _lock_shared(fh: Any) -> None:
        # msvcrt has no shared-lock mode; use exclusive for reads too.
        fh.seek(0)
        _msvcrt.locking(fh.fileno(), _msvcrt.LK_LOCK, _LOCK_NBYTES)

    def _lock_release(fh: Any) -> None:
        fh.seek(0)
        _msvcrt.locking(fh.fileno(), _msvcrt.LK_UNLCK, _LOCK_NBYTES)
# ─────────────────────────────────────────────────────────────────────────────

from uxsp.core.identity import PublicCard
from uxsp.core.signing import SignedCard

CardType = PublicCard | SignedCard

psycopg2: Any = None
psycopg2_pool: Any = None
try:
    import psycopg2 as _psycopg2
    from psycopg2 import pool as _psycopg2_pool

    psycopg2 = _psycopg2
    psycopg2_pool = _psycopg2_pool
except ImportError:
    pass

redis: Any = None
try:
    import redis as _redis

    redis = _redis
except ImportError:
    pass


# ─────────────────────────────────────────────
# ERRORS
# ─────────────────────────────────────────────


class KeyStoreError(Exception):
    """Base class for keystore errors."""

    pass


class CardNotFoundError(KeyStoreError):
    """
    No card found for the requested entity_id.
    The entity is unknown or has not registered.
    """

    pass


class KeyStoreBackendError(KeyStoreError):
    """
    Backend (Redis / Postgres) is unavailable.
    Treat as a security event — reject the envelope.
    """

    pass


class DuplicateCardError(KeyStoreError):
    """
    A card already exists for this entity_id and overwrite=False.
    """

    pass


# ─────────────────────────────────────────────
# ABSTRACT BASE
# ─────────────────────────────────────────────


class KeyStore(ABC):
    """
    Abstract base class for all UXSP key stores.

    What this class does:
        Defines the minimum interface that every card storage backend must
        implement.  Concrete subclasses only need to override the four abstract
        methods (put, get, delete, list_ids); the remaining methods are
        implemented here as thin wrappers.

    Usage note:
        Always inject a KeyStore via dependency injection rather than
        hard-coding a specific backend, so you can swap MemoryKeyStore for
        a production backend without touching application logic.
    """
    @abstractmethod
    def put(self, card: CardType, overwrite: bool = True) -> None: ...
    @abstractmethod
    def get(self, entity_id: str) -> CardType | None: ...

    @abstractmethod
    def delete(self, entity_id: str) -> bool: ...

    @abstractmethod
    def list_ids(self) -> list[str]: ...

    # ── convenience wrappers ────────────────────────────────────────

    def require(self, entity_id: str) -> CardType:

        card = self.get(entity_id)
        if card is None:
            raise CardNotFoundError(
                f"No card found for entity '{entity_id}'. "
                f"The entity may not have registered, or the card "
                f"may have been revoked."
            )
        return card

    def public_card(self, entity_id: str) -> PublicCard:

        card = self.require(entity_id)
        if isinstance(card, SignedCard):
            return card.card
        return card

    def has(self, entity_id: str) -> bool:
        """Return True if a card exists for entity_id."""
        return self.get(entity_id) is not None

    def put_many(self, cards: list[CardType], overwrite: bool = True) -> None:
        """Store multiple cards in one call."""
        for card in cards:
            self.put(card, overwrite=overwrite)

    def __len__(self) -> int:
        return len(self.list_ids())

    def __contains__(self, entity_id: str) -> bool:
        return self.has(entity_id)


# ─────────────────────────────────────────────
# MEMORY KEYSTORE — dev / testing
# ─────────────────────────────────────────────


class MemoryKeyStore(KeyStore):
    """
    Thread-safe in-process key store backed by a plain dict.

    What this class does:
        Stores cards in memory for the lifetime of the process.  All operations
        are protected by a threading.Lock() so multiple threads can safely call
        put() and get() concurrently.

    Use only for development, unit tests, or single-process deployments where
    persistence is not required.  State is lost when the process exits.
    """
    def __init__(self) -> None:
        self._store: dict[str, CardType] = {}
        self._lock = threading.Lock()

    def put(self, card: CardType, overwrite: bool = True) -> None:
        eid = _entity_id(card)
        with self._lock:
            if not overwrite and eid in self._store:
                raise DuplicateCardError(
                    f"Card for '{eid[:8]}...' already exists and overwrite=False."
                )
            self._store[eid] = card

    def get(self, entity_id: str) -> CardType | None:
        with self._lock:
            return self._store.get(entity_id)

    def delete(self, entity_id: str) -> bool:
        with self._lock:
            if entity_id in self._store:
                del self._store[entity_id]
                return True
            return False

    def list_ids(self) -> list[str]:
        with self._lock:
            return list(self._store.keys())


# ─────────────────────────────────────────────
# FILE KEYSTORE — single-node persistence
# ─────────────────────────────────────────────


class FileKeyStore(KeyStore):
    """
    Single-file, cross-process-safe JSON key store.

    What this class does:
        Persists cards as a JSON object (entity_id → serialised card) in a
        single file.  Concurrent readers are handled with shared locks;
        writes acquire an exclusive lock and use a temp-file-then-rename pattern
        to prevent corruption from crashes or concurrent writes.

        An in-memory cache keyed on (mtime_ns, size) avoids redundant disk reads
        when no other process has modified the file.

    Suitable for single-node deployments.  For multi-node use, prefer
    RedisKeyStore or PostgresKeyStore.
    """
    def __init__(self, path: str | Path) -> None:
        self._mtime_ns: int = 0
        self._size: int = 0
        self._path = Path(path)
        self._lock_path = Path(str(path) + ".lock")
        self._lock = threading.Lock()  # intra-process
        self._cache: dict[str, CardType] | None = None

    # ── cross-process locking helpers ────────────────────────────────────────

    def _open_lockfile(self) -> IO[str]:
        """Open (or create) the lock-file and return its file descriptor."""
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        return open(self._lock_path, "a")

    def _flock_exclusive(self, fh: IO[str]) -> None:
        """Acquire an exclusive lock; blocks until no other process holds any lock."""
        _lock_exclusive(fh)

    def _flock_shared(self, fh: IO[str]) -> None:
        """Acquire a shared lock; blocks only while an exclusive lock is held."""
        _lock_shared(fh)

    def _flock_release(self, fh: IO[str]) -> None:
        _lock_release(fh)

    # ── internal read / write (caller holds both thread-lock and flock) ──────

    def _load(self) -> dict[str, CardType]:
        """Read the data file into cache (called while locks are held)."""
        if not self._path.exists():
            self._cache = {}
            self._mtime_ns = 0
            self._size = 0
            return self._cache

        stat = self._path.stat()
        current_mtime_ns = stat.st_mtime_ns
        current_size = stat.st_size

        if (
            self._cache is not None
            and current_mtime_ns == self._mtime_ns
            and current_size == self._size
        ):
            return self._cache

        with open(self._path) as f:
            raw: dict[str, Any] = json.load(f)

        self._cache = {eid: _deserialise_card(entry) for eid, entry in raw.items()}
        self._mtime_ns = current_mtime_ns
        self._size = current_size
        return self._cache

    def _flush(self, store: dict[str, CardType]) -> None:
        """Write store atomically (called while exclusive locks are held)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        raw = {eid: _serialise_card(card) for eid, card in store.items()}
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(self._path.parent))
        try:
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(raw, f, indent=2)
            if sys.platform != "win32":
                os.chmod(tmp_path, 0o600)
            Path(tmp_path).replace(self._path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise
        stat_info = self._path.stat()
        self._mtime_ns = stat_info.st_mtime_ns
        self._size = stat_info.st_size
        self._cache = store

    # ── public API ────────────────────────────────────────────────────────────

    def put(self, card: CardType, overwrite: bool = True) -> None:
        eid = _entity_id(card)
        with self._lock, self._open_lockfile() as lf:
            locked = False
            try:
                self._flock_exclusive(lf)
                locked = True
                store = self._load()
                if not overwrite and eid in store:
                    raise DuplicateCardError(
                        f"Card for '{eid[:8]}...' already exists and overwrite=False."
                    )
                store[eid] = card
                self._flush(store)
            finally:
                if locked:
                    self._flock_release(lf)

    def get(self, entity_id: str) -> CardType | None:
        with self._lock, self._open_lockfile() as lf:
            locked = False
            try:
                self._flock_shared(lf)
                locked = True
                return self._load().get(entity_id)
            finally:
                if locked:
                    self._flock_release(lf)

    def delete(self, entity_id: str) -> bool:
        with self._lock, self._open_lockfile() as lf:
            locked = False
            try:
                self._flock_exclusive(lf)
                locked = True
                store = self._load()
                if entity_id not in store:
                    return False
                del store[entity_id]
                self._flush(store)
                return True
            finally:
                if locked:
                    self._flock_release(lf)

    def list_ids(self) -> list[str]:
        with self._lock, self._open_lockfile() as lf:
            locked = False
            try:
                self._flock_shared(lf)
                locked = True
                return list(self._load().keys())
            finally:
                if locked:
                    self._flock_release(lf)


# ─────────────────────────────────────────────
# REDIS KEYSTORE — fast distributed cache
# ─────────────────────────────────────────────


class RedisKeyStore(KeyStore):
    """
    Key store backed by Redis string keys with optional TTL.

    What this class does:
        Stores each card as a JSON string under a namespaced Redis key
        (key_prefix + entity_id).  If ttl > 0, cards expire automatically
        after ttl seconds; set ttl=0 for persistent storage.

        All Redis errors are wrapped in KeyStoreBackendError so callers do not
        need to catch redis.exceptions directly.

    Best used as the fast-cache layer in a CachingKeyStore in front of a
    PostgresKeyStore for durable production storage.
    """
    def __init__(self, redis_client: Any, key_prefix: str = "uxsp:cards:", ttl: int = 3600) -> None:
        if redis is None:
            raise ImportError("Redis driver not found. Please install it with: pip install redis")
        self._redis = redis_client
        self._prefix = key_prefix
        self._ttl = ttl

    def _key(self, entity_id: str) -> str:
        return f"{self._prefix}{entity_id}"

    def put(self, card: CardType, overwrite: bool = True) -> None:
        eid = _entity_id(card)
        rkey = self._key(eid)
        try:
            raw = json.dumps(_serialise_card(card))
            if not overwrite:
                kwargs: dict[str, Any] = {"nx": True}
                if self._ttl > 0:
                    kwargs["ex"] = self._ttl
                result = self._redis.set(rkey, raw, **kwargs)
                if not result:
                    raise DuplicateCardError(
                        f"Card for '{eid[:8]}...' already exists and overwrite=False."
                    )
            else:
                if self._ttl > 0:
                    self._redis.set(rkey, raw, ex=self._ttl)
                else:
                    self._redis.set(rkey, raw)
        except DuplicateCardError:
            raise
        except Exception as e:
            raise KeyStoreBackendError(f"Redis keystore unavailable: {e}") from e

    def get(self, entity_id: str) -> CardType | None:
        try:
            raw = self._redis.get(self._key(entity_id))
            if raw is None:
                return None
            return _deserialise_card(json.loads(raw))
        except KeyStoreError:
            raise
        except Exception as e:
            raise KeyStoreBackendError(f"Redis keystore unavailable: {e}") from e

    def delete(self, entity_id: str) -> bool:
        try:
            return bool(self._redis.delete(self._key(entity_id)))
        except KeyStoreError:
            raise
        except Exception as e:
            raise KeyStoreBackendError(f"Redis keystore unavailable: {e}") from e

    def list_ids(self) -> list[str]:
        try:
            prefix = self._prefix
            keys: list[str | bytes] = []
            cursor: int | bytes = 0
            while True:
                cursor, batch = self._redis.scan(cursor, match=f"{prefix}*", count=100)
                keys.extend(batch)
                if cursor == 0 or cursor == b"0":
                    break
            return [(k.decode() if isinstance(k, bytes) else k).removeprefix(prefix) for k in keys]
        except KeyStoreError:
            raise
        except Exception as e:
            raise KeyStoreBackendError(f"Redis keystore unavailable: {e}") from e


# ─────────────────────────────────────────────
# POSTGRES KEYSTORE — durable source of truth
# ─────────────────────────────────────────────


class PostgresKeyStore(KeyStore):
    """
    Key store backed by a PostgreSQL table (JSONB column).

    What this class does:
        Persists cards in a 'uxsp_cards' table (configurable) with columns:
        entity_id (PRIMARY KEY), card_type, card_json (JSONB), created_at,
        updated_at.  Accepts either a raw psycopg2 connection or a
        psycopg2-compatible connection pool.

        create_table() must be called once per deployment to ensure the table
        and index exist before any put() or get() calls.

    This is the recommended durable backend for production.  Pair it with
    a RedisKeyStore via CachingKeyStore for best performance.
    """
    def __init__(self, conn_or_pool: Any, table: str = "uxsp_cards") -> None:
        if psycopg2 is None:
            raise ImportError(
                "Postgres driver (psycopg2) not found. "
                "Please install it with: pip install psycopg2-binary"
            )
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", table):
            raise ValueError(
                f"Invalid table name '{table}'. "
                f"Must be a valid SQL identifier (letters, digits, underscores)."
            )
        self._pool_or_conn = conn_or_pool
        self._table = table
        self._qtable = f'"{table}"'
        self._is_pool = hasattr(conn_or_pool, "getconn") and not hasattr(conn_or_pool, "cursor")

    def _ddl(self) -> str:
        idx_name = f'"idx_{self._table}_updated"'
        return f"""
        CREATE TABLE IF NOT EXISTS {self._qtable} (
            entity_id   TEXT        PRIMARY KEY,
            card_type   TEXT        NOT NULL,
            card_json   JSONB       NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        CREATE INDEX IF NOT EXISTS {idx_name}
            ON {self._qtable} (updated_at);
        """

    @staticmethod
    def _rollback_quietly(conn: Any | None) -> None:
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.rollback()

    def _conn(self) -> AbstractContextManager[Any]:

        @contextmanager
        def _ctx() -> Generator[Any, None, None]:
            if self._is_pool:
                c = self._pool_or_conn.getconn()
                try:
                    yield c
                finally:
                    self._pool_or_conn.putconn(c)
            else:
                yield self._pool_or_conn

        return _ctx()

    def create_table(self) -> None:
        """Create the uxsp_cards table if it does not exist."""
        conn: Any | None = None
        try:
            with self._conn() as active_conn:
                conn = active_conn
                with active_conn.cursor() as cur:
                    cur.execute(self._ddl())
                    active_conn.commit()
        except KeyStoreBackendError:
            self._rollback_quietly(conn)
            raise
        except Exception as e:
            self._rollback_quietly(conn)
            raise KeyStoreBackendError(f"Postgres keystore: failed to create table: {e}") from e

    def put(self, card: CardType, overwrite: bool = True) -> None:
        eid = _entity_id(card)
        serial = _serialise_card(card)
        ctype = serial["type"]
        card_json = json.dumps(serial)
        conn: Any | None = None
        try:
            with self._conn() as active_conn:
                conn = active_conn
                with active_conn.cursor() as cur:
                    if overwrite:
                        cur.execute(
                            f"""
                                INSERT INTO {self._qtable} (entity_id, card_type, card_json)
                                VALUES (%s, %s, %s::jsonb)
                                ON CONFLICT (entity_id) DO UPDATE
                                    SET card_type  = EXCLUDED.card_type,
                                        card_json  = EXCLUDED.card_json,
                                        updated_at = now()
                                """,
                            (eid, ctype, card_json),
                        )
                    else:
                        cur.execute(
                            f"""
                                INSERT INTO {self._qtable} (entity_id, card_type, card_json)
                                VALUES (%s, %s, %s::jsonb)
                                """,
                            (eid, ctype, card_json),
                        )
                    active_conn.commit()
        except KeyStoreBackendError:
            self._rollback_quietly(conn)
            raise
        except Exception as e:
            self._rollback_quietly(conn)
            # pgcode "23505" is the SQL standard UNIQUE VIOLATION code used by
            # psycopg2.  Checking pgcode is more reliable than string-matching
            # the error message, which may vary by Postgres version and locale.
            if getattr(e, "pgcode", None) == "23505":
                raise DuplicateCardError(
                    f"Card for '{eid[:8]}...' already exists and overwrite=False."
                ) from e
            raise KeyStoreBackendError(f"Postgres keystore unavailable: {e}") from e

    def get(self, entity_id: str) -> CardType | None:
        conn: Any | None = None
        try:
            with self._conn() as active_conn:
                conn = active_conn
                with active_conn.cursor() as cur:
                    cur.execute(
                        f"SELECT card_json FROM {self._qtable} WHERE entity_id = %s", (entity_id,)
                    )
                    row = cur.fetchone()
                active_conn.rollback()
            if row is None:
                return None
            raw = row[0]
            if isinstance(raw, str):
                raw = json.loads(raw)
            elif not isinstance(raw, dict):
                raise KeyStoreBackendError(
                    f"Unexpected type from Postgres JSONB column: {type(raw)}"
                )
            return _deserialise_card(raw)

        except KeyStoreBackendError:
            self._rollback_quietly(conn)
            raise
        except Exception as e:
            self._rollback_quietly(conn)
            raise KeyStoreBackendError(f"Postgres keystore unavailable: {e}") from e

    def delete(self, entity_id: str) -> bool:
        conn: Any | None = None
        try:
            with self._conn() as active_conn:
                conn = active_conn
                with active_conn.cursor() as cur:
                    cur.execute(f"DELETE FROM {self._qtable} WHERE entity_id = %s", (entity_id,))
                    deleted = bool(cur.rowcount > 0)
                    active_conn.commit()
            return deleted
        except KeyStoreBackendError:
            self._rollback_quietly(conn)
            raise
        except Exception as e:
            self._rollback_quietly(conn)
            raise KeyStoreBackendError(f"Postgres keystore unavailable: {e}") from e

    def list_ids(self) -> list[str]:
        conn: Any | None = None
        try:
            with self._conn() as active_conn:
                conn = active_conn
                with active_conn.cursor() as cur:
                    cur.execute(f"SELECT entity_id FROM {self._qtable} ORDER BY created_at")
                    rows = [row[0] for row in cur.fetchall()]
                active_conn.rollback()
            return rows
        except KeyStoreBackendError:
            self._rollback_quietly(conn)
            raise
        except Exception as e:
            self._rollback_quietly(conn)
            raise KeyStoreBackendError(f"Postgres keystore unavailable: {e}") from e


# ─────────────────────────────────────────────
# CACHING KEYSTORE — Redis in front of Postgres
# ─────────────────────────────────────────────


class CachingKeyStore(KeyStore):
    """
    Two-tier key store with a fast cache (Redis) in front of a durable backend (Postgres).

    What this class does:
        On put()   — writes to the backend first, then populates the cache.
        On get()   — checks the cache first; on cache miss or error, reads from
                      the backend and back-fills the cache.
        On delete() — removes from the backend, then evicts from the cache.
        list_ids() — always delegates to the backend (source of truth).

    Cache errors are silently suppressed (fail-open for reads, fail-safe for
    writes): a Redis outage degrades to reading from Postgres, not a crash.
    """
    def __init__(self, cache: KeyStore, backend: KeyStore) -> None:
        self._cache = cache
        self._backend = backend

    def put(self, card: CardType, overwrite: bool = True) -> None:
        self._backend.put(card, overwrite=overwrite)
        with contextlib.suppress(KeyStoreBackendError):
            self._cache.put(card, overwrite=True)

    def get(self, entity_id: str) -> CardType | None:
        try:
            card = self._cache.get(entity_id)
            if card is not None:
                return card
        except KeyStoreBackendError:
            pass
        card = self._backend.get(entity_id)
        if card is not None:
            with contextlib.suppress(KeyStoreBackendError):
                self._cache.put(card, overwrite=True)
        return card

    def delete(self, entity_id: str) -> bool:
        result = self._backend.delete(entity_id)
        with contextlib.suppress(KeyStoreBackendError):
            self._cache.delete(entity_id)
        return result

    def list_ids(self) -> list[str]:
        return self._backend.list_ids()


# ─────────────────────────────────────────────
# INTERNAL HELPERS — card serialisation
# ─────────────────────────────────────────────


def _entity_id(card: CardType) -> str:
    """Extract entity_id regardless of card type."""
    if isinstance(card, SignedCard):
        return card.card.entity_id
    return card.entity_id


def _serialise_card(card: CardType) -> dict[str, Any]:
    """Serialise a PublicCard or SignedCard to a JSON-safe dict."""
    if isinstance(card, SignedCard):
        return {"type": "signed", **card.to_dict()}
    return {"type": "public", **card.to_dict()}


def _deserialise_card(data: dict[str, Any]) -> CardType:
    ctype = data.get("type", "public")
    if ctype == "signed":
        return SignedCard.from_dict(data)
    if ctype == "public":
        return PublicCard.from_dict(data)
    raise KeyStoreError(f"Unknown card type '{ctype}' in serialised data.")
