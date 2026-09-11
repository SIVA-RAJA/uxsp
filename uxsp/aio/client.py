"""
uxsp.aio.client — Async Smart Client with Automatic Protocol Switching (UXSP ↔ HTTPS)
"""
from __future__ import annotations

from uxsp.client._async_client import (
    AsyncUXSPClient,
    delete,
    fetch,
    get,
    patch,
    post,
    put,
    request,
)
from uxsp.client._cache import (
    HostCapability,
    HostCapabilityCache,
    InMemoryHostCapabilityCache,
    RedisHostCapabilityCache,
    get_default_capability_cache,
    normalize_host_key,
)
from uxsp.client._errors import (
    ProtocolFallbackError,
    UXSPClientError,
    UXSPPeerResolutionError,
)
from uxsp.client._response import UXSPResponse

# Client alias for async module
Client = AsyncUXSPClient

__all__ = [
    "AsyncUXSPClient",
    "Client",
    "UXSPResponse",
    "UXSPClientError",
    "ProtocolFallbackError",
    "UXSPPeerResolutionError",
    "HostCapability",
    "HostCapabilityCache",
    "InMemoryHostCapabilityCache",
    "RedisHostCapabilityCache",
    "normalize_host_key",
    "get_default_capability_cache",
    "fetch",
    "request",
    "get",
    "post",
    "put",
    "delete",
    "patch",
]
