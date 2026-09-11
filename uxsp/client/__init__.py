"""
uxsp.client — Smart Client with Automatic Protocol Switching (UXSP ↔ HTTPS)
"""
from __future__ import annotations

from uxsp.client._async_client import (
    AsyncUXSPClient,
)
from uxsp.client._async_client import (
    delete as adelete,
)
from uxsp.client._async_client import (
    fetch as afetch,
)
from uxsp.client._async_client import (
    get as aget,
)
from uxsp.client._async_client import (
    patch as apatch,
)
from uxsp.client._async_client import (
    post as apost,
)
from uxsp.client._async_client import (
    put as aput,
)
from uxsp.client._async_client import (
    request as arequest,
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
from uxsp.client._sync_client import (
    UXSPClient,
    delete,
    fetch,
    get,
    patch,
    post,
    put,
    request,
)

# Alias for standard Client naming
Client = UXSPClient

__all__ = [
    "UXSPClient",
    "Client",
    "AsyncUXSPClient",
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
    "afetch",
    "arequest",
    "aget",
    "apost",
    "aput",
    "adelete",
    "apatch",
]
