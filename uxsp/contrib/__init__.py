"""
UXSP Contrib — Web Framework Integrations for FastAPI, Django, and Flask.

Provides 1-line middleware and decorators for effortless request decryption and
response encryption in web microservices and APIs.

Usage:
    # FastAPI
    from uxsp.contrib.fastapi import UXSPFastAPIMiddleware, protect

    # Django
    from uxsp.contrib.django import UXSPDjangoMiddleware, protect_view

    # Flask
    from uxsp.contrib.flask import UXSPFlaskMiddleware, protect_route
"""

from __future__ import annotations

__all__ = []
