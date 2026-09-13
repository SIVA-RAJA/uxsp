# UXSP: Universal Exchange Security Protocol

[![PyPI version](https://img.shields.io/pypi/v/uxsp.svg?color=blue)](https://pypi.org/project/uxsp/)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/uxsp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Coverage: 100%](https://img.shields.io/badge/Coverage-100%25-brightgreen)](https://github.com/SIVA-RAJA/uxsp)
[![NIST FIPS 203 & 204](https://img.shields.io/badge/NIST-ML--KEM--768%20%7C%20ML--DSA--65-blueviolet)](https://csrc.nist.gov/)

**Universal Exchange Security Protocol (UXSP)** is a production-grade, hybrid post-quantum cryptographic security framework for Python. It provides military-grade message sealing, progressive zero-trust HTTP client networking, seamless framework middlewares, and multi-gigabyte file streaming—all distilled into **intuitive 1-line Python functions**.

---

## Why UXSP?

Imagine you want to send a secret letter to your friend:
1. **Classical locks today (RSA & ECC)**: Think of traditional security like a padlock. An ordinary burglar cannot open it. But mathematicians know that a giant **Quantum Computer** (arriving in the near future) will act like a magic key that instantly pops open all classical padlocks!
2. **"Harvest Now, Decrypt Later" (HNDL)**: Bad actors are recording encrypted internet traffic today. Even if they can't open it now, they will save it on disk and decrypt it once a quantum computer is built.
3. **The UXSP Solution (Double-Locked Safe)**: UXSP puts your message inside a safe with **TWO independent locks**:
   - Lock 1: A battle-tested classical lock (**X25519** & **Ed25519**).
   - Lock 2: A quantum-proof mathematical puzzle approved by NIST (**ML-KEM-768** / CRYSTALS-Kyber & **ML-DSA-65** / CRYSTALS-Dilithium).

An attacker must break **BOTH** locks to read your message or forge your identity. If either lock holds, your message remains 100% secure!

---

## ⚡ Key Features at a Glance

- **1-Line Polymorphic Cryptography**: 14 built-in polymorphic data types (`Text`, `File`, `JSON`, `Binary`, `PDF`, `Document`, `Voice`, `Video`, `Photo`, `Location`, `Contact`, `HTML`, `Archive`, `LiveVoiceCall`).
- **Autonomous Protocol-Switching HTTP Client (`UXSPClient` / `AsyncUXSPClient`)**: Talks to UXSP servers with automatic post-quantum encryption; automatically and transparently falls back to standard plaintext HTTP when talking to legacy servers.
- **Framework Middlewares**: 1-line middlewares and route decorators for **FastAPI**, **Django**, and **Flask** with opportunistic negotiation headers.
- **Ultra-Low-Memory Streaming**: Stream 100GB+ files chunk-by-chunk with $O(\text{chunk\_size})$ RAM usage.
- **Distributed Replay Protection**: Nonce tracking and sliding-window sequencing backed by Memory, **Redis**, or **PostgreSQL**.
- **WebRTC & Live Media**: Real-time voice and video session keys with directional ratchets and monotonic frame counters.
- **Verified Quality**: **100% test coverage** (7,084 / 7,084 statements) and **zero `mypy` strict errors**.

---

## 📦 Installation

```bash
# Base package (cryptography, liboqs-python, argon2-cffi)
pip install uxsp
```

UXSP is highly modular. You only need to install the dependencies required for your specific framework and storage needs.

| Installation Command | Included Components & Dependencies |
| :--- | :--- |
| `pip install uxsp` | Base uxsp.secure (cryptography, liboqs-python, argon2-cffi) |
| `pip install uxsp[aio]` | uxsp.secure + uxsp.aio (Asynchronous capabilities) |
| `pip install uxsp[django]` | uxsp.secure + Django Integrations |
| `pip install uxsp[flask]` | uxsp.secure + Flask Integrations |
| `pip install uxsp[fastapi]` | uxsp.secure + FastAPI, Starlette, HTTPX2 Integrations |
| `pip install uxsp[postgres]` | uxsp.secure + Postgres (psycopg2-binary) |
| `pip install uxsp[redis]` | uxsp.secure + Redis (redis) |
| `pip install "uxsp[aio, django]"` | uxsp.secure + uxsp.aio + Django |
| `pip install "uxsp[aio, postgres]"` | uxsp.secure + uxsp.aio + Postgres |
| `pip install "uxsp[aio, redis]"` | uxsp.secure + uxsp.aio + Redis |
| `pip install "uxsp[aio, django, postgres]"` | uxsp.secure + uxsp.aio + Django + Postgres |
| `pip install "uxsp[aio, django, redis]"` | uxsp.secure + uxsp.aio + Django + Redis |
| `pip install uxsp[all-django]` | uxsp.secure + uxsp.aio + Django + Postgres + Redis |
| `pip install uxsp[all-flask]` | uxsp.secure + uxsp.aio + Flask + Postgres + Redis |
| `pip install uxsp[all-fastapi]` | uxsp.secure + uxsp.aio + FastAPI + Postgres + Redis |
| `pip install uxsp[all]` | Complete stack with all web frameworks and storage backends |

### System Prerequisites (`liboqs`)

UXSP utilizes `liboqs` for C-native Post-Quantum Cryptography acceleration. You must install the required build tools for your platform:

- **Ubuntu / Debian / Mint**:
  ```bash
  sudo apt update && sudo apt install -y build-essential cmake ninja-build libssl-dev git
  ```
- **Fedora / RHEL / CentOS**:
  ```bash
  sudo dnf groupinstall -y "Development Tools" && sudo dnf install -y cmake ninja-build openssl-devel git
  ```
- **macOS**:
  ```bash
  brew install cmake ninja openssl@3
  ```
- **Windows**:
  Requires Visual Studio Build Tools (C++), CMake, and Git. (Note: Windows support is experimental and falls back to `msvcrt` for certain operations).

> [!NOTE]
> **Automatic Pure-Python Fallback**: If `liboqs` fails to compile on your system, UXSP will automatically fall back to its built-in pure Python Post-Quantum Cryptography implementations, ensuring it always runs!

---

## 🚀 5-Minute Developer Quickstart

### 1. Identity Creation & Peer Cards

In UXSP, every user or service has an `Identity` (private keys) and a shareable `PublicCard` (public keys):

```python
from uxsp import Identity

# Create Alice and Bob identities
alice = Identity.create(name="Alice", role="client")
bob = Identity.create(name="Bob", role="server")

# Bob shares his PublicCard with Alice (via QR code, API, or DB)
bob_card = bob.public_card()

# Alice saves her private key encrypted with password
alice.save("alice.card", password="StrongPassword123!")

# Load later:
# alice = Identity.load("alice.card", password="StrongPassword123!")
```

---

### 2. High-Level 1-Line Encryption (`SendText` / `ReceiveText`)

No cipher configuration or manual IV management needed:

```python
import uxsp

# Alice seals a message for Bob
package = uxsp.SendText(
    text="Meeting at 10 PM. Don't be late!",
    receiver=bob_card,
    sender=alice
)

# Alice transmits package (JSON string or dict over HTTP, WebSocket, Queue)
raw_json = package.to_json()

# Bob receives and decrypts in 1 line
received_text = uxsp.ReceiveText(
    package=raw_json,
    sender=alice.public_card(),
    receiver=bob
)

print(received_text)
# Output: "Meeting at 10 PM. Don't be late!"
```

---

### 3. Autonomous HTTP Client with Automatic Fallback (`UXSPClient`)

When modernizing a microservices architecture, you can't migrate every service to UXSP overnight. The `UXSPClient` solves this by **probing endpoints automatically**:
- If the server supports UXSP $\to$ automatically encrypts request and decrypts response.
- If the server is standard HTTP/REST $\to$ automatically falls back to unencrypted HTTP.

```python
from uxsp.client import UXSPClient
from uxsp import Identity

client_ident = Identity.create(name="ApiClient")

# Create the autonomous client
with UXSPClient(identity=client_ident, allow_fallback=True) as client:
    # 1. Sending to a UXSP-enabled server:
    # Probes headers, detects UXSP capability, encrypts payload into SecurePackage!
    resp = client.post("https://api.example.com/secure-data", json={"account": 42})
    print(resp.is_uxsp)  # True
    print(resp.data)     # Decrypted Python dictionary

    # 2. Sending to a legacy/standard public server:
    # Server doesn't support UXSP -> client seamlessly falls back to standard HTTP!
    legacy_resp = client.get("https://httpbin.org/get")
    print(legacy_resp.is_uxsp)  # False
    print(legacy_resp.json())   # Standard JSON response
print("Decrypted payload:", verified_data)
```

---

### 3. Asynchronous Operations (`uxsp.aio`)

Full async/await API designed for high-concurrency event loops:

```python
import asyncio
import uxsp.aio as axsp
from uxsp import Identity

async def main():
    alice = Identity.create(name="Alice")
    bob = Identity.create(name="Bob")

    # Async encryption
    pkg = await axsp.SendText("Quantum-safe greetings!", receiver=bob.public_card(), sender=alice)

    # Async decryption
    msg = await axsp.ReceiveText(pkg, sender=alice.public_card(), receiver=bob)
    print("Async decrypted:", msg)

asyncio.run(main())
```

---

### 4. Quantum-Safe HTTP Client (`UXSPClient` & `AsyncUXSPClient`)

Autonomous HTTP clients with server card auto-discovery, persistent session caching, and opportunistic fallback:

```python
from uxsp import UXSPClient, Identity

alice = Identity.create(name="Alice", role="client")

# Creates client with automatic server discovery (hits /.well-known/uxsp-card)
client = UXSPClient(
    identity=alice,
    base_url="https://api.example.com",
    allow_unencrypted=True  # Opportunistic: falls back to regular HTTPS if server lacks UXSP
)

# Payload is automatically encrypted, signed, and transmitted:
# Server response is automatically decrypted and verified:
response = client.post("/v1/transactions", json={"amount": 1000, "currency": "USD"})
print(response.json())
```

---

### 5. Multi-Gigabyte Streaming (`SendStream` / `ReceiveStream`)

Stream huge multi-gigabyte ISOs, backups, or videos in constant memory buffers (64 KB):

```python
import uxsp

# Encrypt huge file in fixed 64KB chunks
uxsp.SendStream(
    stream_or_path="database_backup.tar.gz",
    receiver=bob_card,
    sender=alice,
    output_destination="encrypted_backup.uxsp"
)

# Decrypt chunk-by-chunk directly to disk
uxsp.ReceiveStream(
    stream_or_path="encrypted_backup.uxsp",
    sender=alice.public_card(),
    receiver=bob,
    output_destination="restored_backup.tar.gz"
)
```

---

### 6. 1-Line Web Framework Middlewares

#### Django

The order of `MIDDLEWARE` in Django is **critical**. You must place `UXSPDjangoMiddleware` **AFTER** standard Security/Session middlewares, but **BEFORE** `CsrfViewMiddleware`.

**Why?** Because UXSP inherently replaces the need for CSRF! By placing it before `CsrfViewMiddleware`, UXSP decrypts the request and cryptographically verifies the sender's signature (which acts as the ultimate CSRF protection) before Django's CSRF checker gets angry about missing tokens.

```python
# settings.py

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    
    # PUT UXSP HERE!
    'uxsp.contrib.django.UXSPDjangoMiddleware',
    
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# UXSP Configuration
UXSP_IDENTITY_FILE = "/var/secrets/django_server.card"
UXSP_PASSWORD = "ServerSecretPassword!"
UXSP_ALLOW_UNENCRYPTED = True  # True allows standard unencrypted clients; False enforces UXSP
UXSP_EXCLUDE_PATHS = ["/admin/", "/static/"]  # Paths that bypass decryption
```

#### FastAPI

In FastAPI (Starlette), middleware executes in **reverse order** of addition (the last added middleware is the outer layer). Add `UXSPFastAPIMiddleware` closest to your application routes so it decrypts the raw byte stream into `request.state.uxsp_payload` before dependency injection and route handlers run.

Always exclude API docs endpoints (`/docs`, `/redoc`, `/openapi.json`) so developers can view Swagger UI in normal web browsers without encryption:

```python
from fastapi import FastAPI, Request
from uxsp.contrib.fastapi import UXSPFastAPIMiddleware, protect
from uxsp import Identity

app = FastAPI()
server_ident = Identity.create(name="FastAPIServer", role="server")

# Protect all routes with automatic protocol negotiation
app.add_middleware(
    UXSPFastAPIMiddleware,
    identity=server_ident,
    allow_unencrypted=True,  # Enables opportunistic fallback for standard HTTP clients
    exclude_paths=["/docs", "/redoc", "/openapi.json"]  # Keep Swagger UI accessible!
)

# Opportunistic route: decrypted if UXSP client, plain JSON if regular client
@app.post("/api/data")
async def handle_data(data: dict):
    return {"status": "ok", "echo": data}

# Strictly quantum-protected route: rejects unencrypted requests with 400 Bad Request
@app.post("/api/transfer")
@protect()
async def secure_transfer(request: Request):
    payload = request.state.uxsp_payload
    return {"status": "success", "processed": payload}
```

#### Flask

In Flask, `UXSPFlaskMiddleware` wraps your WSGI app. It transparently intercepts `wsgi.input`, decrypts the ciphertext payload, and rewrites the WSGI environment so standard `request.get_json()` and `request.data` work seamlessly without changing route logic:

```python
from flask import Flask, request, jsonify
from uxsp.contrib.flask import UXSPFlaskMiddleware, protect_route
from uxsp import Identity

app = Flask(__name__)
server_ident = Identity.create(name="FlaskServer", role="server")

# Wrap WSGI app closest to application logic
app.wsgi_app = UXSPFlaskMiddleware(
    app.wsgi_app,
    identity=server_ident,
    allow_unencrypted=True,
    exclude_paths=["/static/"]
)

@app.route("/api/secure", methods=["POST"])
@protect_route()  # Rejects unencrypted requests before route runs
def secure_route():
    # request.json is automatically decrypted and authenticated!
    return jsonify({"status": "received", "data": request.json})
```

---

## 🏛️ Project Architecture & Cryptographic Specs

```
┌─────────────────────────────────────────────────────────────┐
│                      UXSP Application                       │
│  FastAPI / Django / Flask / UXSPClient / CLI / Stream / Live│
├─────────────────────────────────────────────────────────────┤
│                 Polymorphic Dispatch Layer                  │
│       Send* / Receive* (14 Data Types: Text, File, JSON...) │
├─────────────────────────────────────────────────────────────┤
│                   Session & State Machine                   │
│      3-Step Mutual Handshake, Sequence Numbers, Sliding AD  │
├─────────────────────────────────────────────────────────────┤
│                   Replay Protection Layer                   │
│           Timestamp Freshness Window (300s) + NonceStore    │
│              (Memory, Redis, PostgreSQL TTL backends)       │
├─────────────────────────────────────────────────────────────┤
│                  Hybrid Cryptographic Core                  │
│   Classical: X25519 (ECDH)       + Ed25519 (Signatures)     │
│   Quantum:   ML-KEM-768 (KEM)    + ML-DSA-65 (Signatures)   │
│   Symmetric: AES-256-GCM (AEAD)  + HKDF-SHA256 (KDF)        │
└─────────────────────────────────────────────────────────────┘
```

---

## 📚 Complete Documentation & Resources

- 📖 **[Developer Tutorials Hub](https://github.com/SIVA-RAJA/uxsp/tree/main/tutorial)**: Hands-on walkthroughs for APIs, streaming, WebRTC, CLI, and frameworks.
- 🌐 **[End-to-End Fullstack Integration Guide](https://github.com/SIVA-RAJA/uxsp/blob/main/tutorial/fullstack_integration.md)**: Connect React/Next.js/JS frontend with FastAPI/Django/Flask with post-quantum security.
- 📜 **[Formal Protocol Specification](https://github.com/SIVA-RAJA/uxsp/blob/main/docs/protocol_specification.md)**: RFC 2119 mathematical proofs, threat models, and state machines.
- ⚡ **[Exact Wire Format Specification](https://github.com/SIVA-RAJA/uxsp/blob/main/docs/wire_format.md)**: Bit-by-bit binary encoding and annotated hex test vectors.
- 🌐 **[JavaScript / TypeScript Browser SDK (`@siva_raja/uxsp`)](https://www.npmjs.com/package/@siva_raja/uxsp)**: Browser and Node.js SDK.
- 💬 **[GitHub Discussions & Issues](https://github.com/SIVA-RAJA/uxsp/issues)**: Bug reports and feature proposals.

---

## 🛡️ Security & Vulnerability Reporting

Please report suspected security vulnerabilities privately to **sivaraja5401@gmail.com** with subject `[UXSP SECURITY]`. Review our [Security Policy](https://github.com/SIVA-RAJA/uxsp/blob/main/SECURITY.md) for vulnerability handling timelines.

---

## 📄 License

MIT License — Copyright (c) 2026 SIVA RAJA S.

_UXSP v1.3.0_
