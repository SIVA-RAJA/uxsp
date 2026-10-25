"""
UXSP DAST Reference Target Server

A high-performance FastAPI server instrumented with UXSPFastAPIMiddleware,
used as a live target for Dynamic Application Security Testing (DAST):
- OWASP ZAP (API and Baseline scanning)
- Schemathesis (property-based OpenAPI dynamic fuzzing)
- Custom protocol fuzzer & dynamic attack suites (replay attacks, tampering,
  negotiation manipulation, DoS limits, header injections)
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

import uxsp
from uxsp.contrib.fastapi import UXSPFastAPIMiddleware
from uxsp.core.identity import Identity
from uxsp.storage.keystore import MemoryKeyStore

# ── Identity Setup ────────────────────────────────────────────────────────────
# Predictable identities for DAST fuzzing and verified security testing.
SERVER_IDENTITY = Identity.create("UXSP DAST Server", role="SERVER")
TEST_CLIENT_IDENTITY = Identity.create("UXSP DAST Client", role="CLIENT")

# Dedicated keystore for DAST server to ensure isolation from global context resets
DAST_KEYSTORE = MemoryKeyStore()
DAST_KEYSTORE.put(TEST_CLIENT_IDENTITY.public_card())
DAST_KEYSTORE.put(SERVER_IDENTITY.public_card())

# Register peers globally as well
uxsp.secure.register_peer(TEST_CLIENT_IDENTITY.public_card())
uxsp.secure.register_peer(SERVER_IDENTITY.public_card())


# ── Pydantic Request / Response Models ───────────────────────────────────────
class HealthResponse(BaseModel):
    status: str = Field(..., examples=["healthy"])
    service: str = Field(..., examples=["uxsp-dast-target"])
    version: str = Field(..., examples=["1.3.2"])


class PublicEchoRequest(BaseModel):
    message: str = Field(..., examples=["Hello Plaintext Fallback"])


class PublicEchoResponse(BaseModel):
    echo: Any
    fallback: bool = True


class SecureDataResponse(BaseModel):
    account_id: str
    balance: float
    clearance: str


def create_dast_app(strict: bool = False) -> FastAPI:
    """Create and configure the FastAPI application for DAST scanning."""
    # Ensure peers are registered in global context and keystore
    DAST_KEYSTORE.put(TEST_CLIENT_IDENTITY.public_card())
    DAST_KEYSTORE.put(SERVER_IDENTITY.public_card())
    uxsp.secure.register_peer(TEST_CLIENT_IDENTITY.public_card())
    uxsp.secure.register_peer(SERVER_IDENTITY.public_card())

    app = FastAPI(
        title="UXSP DAST Reference Target Server",
        description="Live target server for Dynamic Application Security Testing (DAST) of UXSP protocol & middlewares.",
        version="1.3.2",
        openapi_url="/openapi.json",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Attach UXSP Middleware with dedicated keystore
    app.add_middleware(
        UXSPFastAPIMiddleware,
        identity=SERVER_IDENTITY,
        keystore=DAST_KEYSTORE,
        fallback=not strict,
        mode="strict" if strict else "hybrid",
        exclude_paths=["/docs", "/openapi.json", "/redoc", "/api/public/health"],
        max_request_size=2 * 1024 * 1024,  # 2 MiB request payload ceiling
    )

    # ── Public Endpoints ──────────────────────────────────────────────────────
    @app.get("/api/public/health", response_model=HealthResponse, tags=["Public"])
    async def health_check() -> dict[str, str]:
        """Unprotected health check endpoint for liveness probes and baseline crawling."""
        return {
            "status": "healthy",
            "service": "uxsp-dast-target",
            "version": "1.3.2",
        }

    @app.get("/api/public/status", tags=["Public"])
    async def server_status() -> dict[str, Any]:
        """Public status endpoint returning supported cryptographic capabilities."""
        return {
            "status": "online",
            "mode": "strict" if strict else "hybrid",
            "uxsp_supported": True,
            "classical_kex": "X25519",
            "quantum_kex": "ML-KEM-768",
            "symmetric_cipher": "AES-256-GCM",
        }

    @app.post("/api/public/echo", response_model=PublicEchoResponse, tags=["Public"])
    async def public_echo(req: PublicEchoRequest) -> dict[str, Any]:
        """Public unencrypted fallback endpoint for negotiation and fallback testing."""
        return {"echo": req.message, "fallback": True}

    @app.get("/api/public/identity", tags=["Public"])
    async def server_identity_card() -> dict[str, Any]:
        """Public endpoint exposing the server's public card for clients."""
        return SERVER_IDENTITY.public_card().to_dict()

    # ── Secure UXSP-Protected Endpoints ───────────────────────────────────────
    @app.post("/api/secure/echo", tags=["Secure"])
    async def secure_echo(request: Request) -> dict[str, Any]:
        """
        Secure endpoint processed by UXSPFastAPIMiddleware.
        Receives an encrypted UXSP package, transparently decrypts the payload,
        and automatically encrypts the response back to the client.
        """
        if getattr(request.state, "uxsp_encrypted", False) and hasattr(request.state, "uxsp_payload"):
            payload = request.state.uxsp_payload
            return {"echo": payload, "secure": True}

        # Reject requests that lacked valid UXSP encryption
        raise HTTPException(status_code=400, detail="UXSP encryption required for /api/secure/echo")

    @app.get("/api/secure/data", response_model=SecureDataResponse, tags=["Secure"])
    async def secure_data(request: Request) -> dict[str, Any]:
        """Protected confidential data endpoint. Requires authenticated UXSP envelope."""
        is_uxsp = getattr(request.state, "uxsp_encrypted", False)
        if not is_uxsp and strict:
            raise HTTPException(status_code=400, detail="UXSP encryption required for this resource")

        return {
            "account_id": "acc_quantum_safe_8892",
            "balance": 154200.50,
            "clearance": "TOP-SECRET//UXSP-PQC",
        }

    return app


app = create_dast_app()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run UXSP DAST Target Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    parser.add_argument("--strict", action="store_true", help="Enforce strict UXSP mode (no plaintext fallback)")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        sys.stderr.write("Error: uvicorn is required to run the DAST server. Install via 'pip install uvicorn'.\n")
        sys.exit(1)

    server_app = create_dast_app(strict=args.strict)
    print(f"[*] Starting UXSP DAST Target Server on http://{args.host}:{args.port}")
    print(f"[*] Mode: {'STRICT' if args.strict else 'HYBRID (Fallback enabled)'}")
    print(f"[*] OpenAPI Schema available at: http://{args.host}:{args.port}/openapi.json")
    print(f"[*] Healthcheck available at: http://{args.host}:{args.port}/api/public/health")

    uvicorn.run(server_app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
