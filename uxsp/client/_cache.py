"""
uxsp.client._cache — Host Capability Caching for UXSP Protocol Negotiation
"""
from __future__ import annotations

import inspect
import json
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlsplit


def normalize_host_key(url: str) -> str:
    """
    Extract and normalize a host key (hostname:port) from a URL or host string.
    Defaults to port 443 for https/wss, 80 for http/ws.
    """
    if not url.startswith(("http://", "https://", "ws://", "wss://")):
        # If passed without scheme, prepend https:// to parse properly
        url = f"https://{url}"
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme in ("https", "wss") else 80
    return f"{hostname}:{port}"


@dataclass
class HostCapability:
    """Represents protocol capability information discovered for a remote host."""

    host: str
    supports_uxsp: bool
    selected_version: str | None = None
    peer_id: str | None = None
    cached_at: float = field(default_factory=time.time)
    ttl: float = 3600.0

    def is_expired(self) -> bool:
        """Check if this capability entry has expired."""
        return (time.time() - self.cached_at) > self.ttl

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HostCapability:
        return cls(
            host=str(data["host"]),
            supports_uxsp=bool(data["supports_uxsp"]),
            selected_version=data.get("selected_version"),
            peer_id=data.get("peer_id"),
            cached_at=float(data.get("cached_at", time.time())),
            ttl=float(data.get("ttl", 3600.0)),
        )


class HostCapabilityCache(ABC):
    """Abstract base class for host capability caches."""

    @abstractmethod
    def get(self, host_key: str) -> HostCapability | None:
        """Retrieve capability for host_key synchronously."""
        raise NotImplementedError

    @abstractmethod
    def set(self, host_key: str, capability: HostCapability) -> None:
        """Store capability for host_key synchronously."""
        raise NotImplementedError

    @abstractmethod
    def clear(self) -> None:
        """Clear all cached host capabilities synchronously."""
        raise NotImplementedError

    async def aget(self, host_key: str) -> HostCapability | None:
        """Retrieve capability for host_key asynchronously."""
        res = self.get(host_key)
        if inspect.isawaitable(res):
            return await res  # type: ignore[no-any-return]
        return res

    async def aset(self, host_key: str, capability: HostCapability) -> None:
        """Store capability for host_key asynchronously."""
        res = self.set(host_key, capability)
        if inspect.isawaitable(res):
            await res

    async def aclear(self) -> None:
        """Clear all cached host capabilities asynchronously."""
        res = self.clear()
        if inspect.isawaitable(res):
            await res


class InMemoryHostCapabilityCache(HostCapabilityCache):
    """Thread-safe and async-safe in-memory cache for host capabilities."""

    def __init__(self, default_ttl: float = 3600.0) -> None:
        self.default_ttl = default_ttl
        self._entries: dict[str, HostCapability] = {}
        self._lock = threading.Lock()

    def get(self, host_key: str) -> HostCapability | None:
        with self._lock:
            entry = self._entries.get(host_key)
            if entry is None:
                return None
            if entry.is_expired():
                del self._entries[host_key]
                return None
            return entry

    def set(self, host_key: str, capability: HostCapability) -> None:
        with self._lock:
            self._entries[host_key] = capability

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


class RedisHostCapabilityCache(HostCapabilityCache):
    """
    Redis-backed host capability cache supporting both sync and async Redis clients.
    """

    def __init__(
        self,
        redis_client: Any,
        prefix: str = "uxsp:host_cap:",
        default_ttl: float = 3600.0,
    ) -> None:
        self.client = redis_client
        self.prefix = prefix
        self.default_ttl = default_ttl

    def _key(self, host_key: str) -> str:
        return f"{self.prefix}{host_key}"

    def get(self, host_key: str) -> HostCapability | None:
        key = self._key(host_key)
        raw = self.client.get(key)
        if inspect.isawaitable(raw):
            if inspect.iscoroutine(raw):
                raw.close()
            raise RuntimeError(
                "Redis client is asynchronous. Call 'await cache.aget()' instead of 'cache.get()'."
            )
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        data = json.loads(raw)
        return HostCapability.from_dict(data)

    def set(self, host_key: str, capability: HostCapability) -> None:
        key = self._key(host_key)
        val = json.dumps(capability.to_dict())
        res = self.client.set(key, val, ex=int(capability.ttl))
        if inspect.isawaitable(res):
            if inspect.iscoroutine(res):
                res.close()
            raise RuntimeError(
                "Redis client is asynchronous. Call 'await cache.aset()' instead of 'cache.set()'."
            )

    def clear(self) -> None:
        keys = self.client.keys(f"{self.prefix}*")
        if inspect.isawaitable(keys):
            if inspect.iscoroutine(keys):
                keys.close()
            raise RuntimeError(
                "Redis client is asynchronous. Call 'await cache.aclear()' instead of 'cache.clear()'."
            )
        if keys:
            self.client.delete(*keys)

    async def aget(self, host_key: str) -> HostCapability | None:
        key = self._key(host_key)
        raw = self.client.get(key)
        if inspect.isawaitable(raw):
            raw = await raw
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        data = json.loads(raw)
        return HostCapability.from_dict(data)

    async def aset(self, host_key: str, capability: HostCapability) -> None:
        key = self._key(host_key)
        val = json.dumps(capability.to_dict())
        res = self.client.set(key, val, ex=int(capability.ttl))
        if inspect.isawaitable(res):
            await res

    async def aclear(self) -> None:
        keys = self.client.keys(f"{self.prefix}*")
        if inspect.isawaitable(keys):
            keys = await keys
        if keys:
            res = self.client.delete(*keys)
            if inspect.isawaitable(res):
                await res


_GLOBAL_CAPABILITY_CACHE = InMemoryHostCapabilityCache()


def get_default_capability_cache() -> HostCapabilityCache:
    """Return the global default host capability cache."""
    return _GLOBAL_CAPABILITY_CACHE
