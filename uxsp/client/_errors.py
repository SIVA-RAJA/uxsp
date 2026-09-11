"""
uxsp.client._errors — Exceptions for the UXSP HTTP Client Layer
"""
from __future__ import annotations


class UXSPClientError(Exception):
    """Base exception for all UXSP client-side transport operations."""

    pass


class ProtocolFallbackError(UXSPClientError):
    """
    Raised when UXSP protocol is required or forced, but the target host
    does not support UXSP or rejected the protocol negotiation.
    """

    pass


class UXSPPeerResolutionError(UXSPClientError):
    """
    Raised when UXSP encryption is required but no recipient PublicCard or
    peer entity could be resolved for the target endpoint.
    """

    pass
