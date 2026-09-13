# UXSP — Universal Exchange Security Protocol

[![Version: 1.3.0](https://img.shields.io/badge/Version-1.3.0-orange)](https://github.com/SIVA-RAJA/uxsp)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)](https://pypi.org/project/uxsp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](https://opensource.org/licenses/MIT)
[![Coverage: 100%](https://img.shields.io/badge/Coverage-100%25-brightgreen)](https://github.com/SIVA-RAJA/uxsp)
[![Type Checking: mypy strict](https://img.shields.io/badge/mypy-strict%20(0%20errors)-blue)](https://mypy.readthedocs.io/)
[![NIST FIPS 203 & 204](https://img.shields.io/badge/NIST-ML--KEM--768%20%7C%20ML--DSA--65-blueviolet)](https://csrc.nist.gov/)

**UXSP (Universal Exchange Security Protocol)** is an enterprise-grade, hybrid post-quantum security framework. It provides application-layer zero-trust encryption, progressive protocol negotiation with automatic fallback, multi-gigabyte streaming in constant memory, and framework middlewares—all designed to protect APIs, data pipelines, messaging, and live media against classical eavesdroppers and future quantum supercomputers.

---

## How UXSP Works

Imagine you want to send a secret drawing to your friend Bob across a playground full of snoopy kids:

```
  Alice's Drawing                        Locked Safe                         Bob Reads Drawing
┌─────────────────┐             ┌───────────────────────────┐             ┌─────────────────┐
│                 │             │  [Lock 1: Classical]      │             │                 │
│   "Top Secret   │ ──(Sealed)─▶│   X25519 + Ed25519        │──(Opened)──▶│   "Top Secret   │
│    Playground   │             │  [Lock 2: Quantum-Proof]  │             │    Playground   │
│     Plan!"      │             │   ML-KEM-768 + ML-DSA-65  │             │     Plan!"      │
└─────────────────┘             └───────────────────────────┘             └─────────────────┘
```

1. **The Classical Lock (Today's Security)**: Standard internet encryption (like RSA and ECC) is like a good metal padlock. Normal computers today cannot pick it.
2. **The Quantum Monster (Tomorrow's Threat)**: Mathematicians have proven that future **Quantum Computers** will be able to pick all classical locks instantly! Even worse, bad actors are collecting encrypted internet traffic *right now* ("Harvest Now, Decrypt Later") to unlock it once their quantum computers are ready.
3. **The UXSP Double Safe**: UXSP puts your message inside a safe with **TWO different locks**:
   - **Lock 1**: Modern classical cryptography (**X25519** ECDH and **Ed25519** digital signatures).
   - **Lock 2**: Quantum-proof lattice mathematics standardized by NIST (**ML-KEM-768** / CRYSTALS-Kyber and **ML-DSA-65** / CRYSTALS-Dilithium).
4. **Unbreakable Guarantee**: An attacker must break **BOTH** locks at the same time to read your message or impersonate the sender. If either lock remains intact, your data is 100% safe!

---

## ⚡ Key Highlights in v1.3.0

- 🔄 **Autonomous Protocol-Switching HTTP Client (`uxsp.client`)**:
  - `UXSPClient` (sync) and `AsyncUXSPClient` (async) automatically probe remote servers using negotiation headers (`X-UXSP-Accept`, `X-UXSP-Version`, `X-UXSP-Identity`).
  - **Automatic Encryption**: If the server speaks UXSP, the client automatically seals the request and decrypts the response.
  - **Automatic Plaintext Fallback**: If the server is standard HTTP/REST (like Stripe, GitHub, or legacy microservices), the client seamlessly communicates in standard plaintext HTTP without errors.
  - **Zero-Trust Enforcement**: Set `allow_fallback=False` / `force_uxsp=True` to immediately reject any unencrypted endpoints.
  - **Pluggable Capability Caching**: Cache server capabilities in Memory, Redis, or PostgreSQL to avoid per-request discovery round-trips.
- 🛡️ **1-Line Polymorphic Cryptography (`uxsp.secure`)**:
  - Direct 1-line operations across **14 polymorphic data types**: `Text`, `File`, `JSON`, `Binary`, `PDF`, `Document`, `Voice`, `Video`, `Photo`, `Location`, `Contact`, `HTML`, `Archive`, and `LiveVoiceCall`.
- 🌐 **Web Framework Middlewares (`uxsp.contrib`)**:
  - Drop-in middlewares and route decorators (`@protect`, `@protect_route`) for **FastAPI**, **Django**, and **Flask** with opportunistic negotiation headers.
- 📦 **Ultra-Low Memory Streaming (`SendStream` / `ReceiveStream`)**:
  - Encrypt and transfer 100GB+ files chunk-by-chunk in fixed $O(\text{chunk\_size})$ RAM footprint without event loop blocking.
- ⏱️ **Durable Replay Protection (`NonceStore`)**:
  - Sliding-window sequencing, timestamp bounds ($\le 300\text{s}$ freshness), and TTL noncestores backed by Memory, **Redis**, or **PostgreSQL**.
- 🎥 **Live Media & WebRTC (`LiveSession` / `LiveVoiceSession`)**:
  - High-performance real-time video, voice calls, and CCTV feed protection with ratcheting directional session keys.
- 💻 **Cross-Platform CLI (`uxsp`)**:
  - Terminal utility for key management, identity generation, sealing/opening envelopes, and `uxsp curl` for probing and querying remote endpoints.
- 📜 **Formal Standards & Exact Wire Format (`docs/`)**:
  - Complete RFC 2119 mathematical specifications (`docs/protocol_specification.md`) and bit-level binary wire format manuals with hex vectors (`docs/wire_format.md`).
- 💎 **100% Strict Type Safety & Test Coverage**:
  - Verified `mypy` strict mode (`strict = true`) across all 78 source files with **0 errors**.
  - Verified **100% test coverage** (7,084 / 7,084 statements) across 1,758 tests with **0 warnings**.

---

## 🏛️ System Architecture

```mermaid
graph TD
    subgraph "Application Layer"
        APP[Web App / Microservice / CLI]
        CLIENT[UXSPClient / AsyncUXSPClient]
        MW[FastAPI / Django / Flask Middleware]
    end

    subgraph "Protocol Switching & Negotiation"
        PROBE{Server Supports UXSP?}
        PROBE -->|Yes| UXSP_PATH[Seal into SecurePackage]
        PROBE -->|No (Fallback)| PLAIN_PATH[Standard HTTP / REST]
        CACHE[(HostCapabilityCache\nMemory / Redis / DB)]
        CLIENT <--> CACHE
    end

    subgraph "UXSP Secure Core"
        DISPATCH[Polymorphic Dispatcher\n14 Data Types]
        STATE[Session State Machine\nMonotonic Seq + Sliding AD]
        REPLAY[ReplayGuard + NonceStore\nTimestamp Window + TTL]
        CRYPTO[Hybrid Cryptographic Engine\nX25519 + ML-KEM-768\nEd25519 + ML-DSA-65\nAES-256-GCM + HKDF]
    end

    APP --> CLIENT
    APP --> MW
    CLIENT --> PROBE
    UXSP_PATH --> DISPATCH
    DISPATCH --> STATE
    STATE --> REPLAY
    REPLAY --> CRYPTO
```

---

## ⚙️ Installation

```bash
# Base package
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

* **Ubuntu / Debian / Mint**:
  ```bash
  sudo apt update && sudo apt install -y build-essential cmake ninja-build libssl-dev git
  ```
* **Fedora / RHEL / CentOS**:
  ```bash
  sudo dnf groupinstall -y "Development Tools" && sudo dnf install -y cmake ninja-build openssl-devel git
  ```
* **macOS**:
  ```bash
  brew install cmake ninja openssl@3
  ```
* **Windows**:
  Requires Visual Studio Build Tools (C++), CMake, and Git. (Note: Windows support is experimental and falls back to `msvcrt` for certain operations).

> [!NOTE]
> **Automatic Pure-Python Fallback**: If `liboqs` fails to compile on your system, UXSP will automatically fall back to its built-in pure Python Post-Quantum Cryptography implementations, ensuring it always runs!

---

## 📚 Complete Documentation Directory

### 📜 Formal Engineering Standards (`docs/`)
For cryptographers, security auditors, and engineers implementing UXSP in other languages (Rust, Go, C/C++, Swift, Zig):
- **[Documentation Index (`docs/index.md`)](./docs/index.md)**: Standards portal and architecture map.
- **[Formal Protocol Specification (`docs/protocol_specification.md`)](./docs/protocol_specification.md)**: RFC 2119 specification, threat models, canonical serialization, trust anchor hierarchy, and error codes (`0x0001` - `0x0015`).
- **[Exact Wire Format & Byte-Level Encoding (`docs/wire_format.md`)](./docs/wire_format.md)**: Bit-by-bit framing, binary header offsets (`0x00` - `0x3A`), variable records, and annotated hex dumps.

### 📖 Developer Tutorials & Framework Guides (`tutorial/`)
For software engineers building applications with UXSP:
- **[Tutorials Portal (`tutorial/index.md`)](./tutorial/index.md)**: Navigation hub for all practical tutorials.
- **[End-to-End Fullstack Integration (`tutorial/fullstack_integration.md`)](./tutorial/fullstack_integration.md)**: Complete React/Next.js/JS frontend + FastAPI/Django/Flask backend setup with zero-trust encryption.
- **[Autonomous HTTP Client & Protocol Switching (`tutorial/client.md`)](./tutorial/client.md)**: In-depth guide on `UXSPClient`, fallback mechanisms, and capability caching.
- **[High-Level APIs (`tutorial/high_level_api.md`)](./tutorial/high_level_api.md)**: 1-line cryptographic operations across 14 polymorphic data types.
- **[Low-Level APIs (`tutorial/low_level_api.md`)](./tutorial/low_level_api.md)**: Envelope, Identity, Session primitives, and key derivation.
- **[Asynchronous Engine (`tutorial/async_api.md`)](./tutorial/async_api.md)**: High-throughput async pipelines (`uxsp.aio`).
- **[Streaming & Live Media (`tutorial/streaming_and_media.md`)](./tutorial/streaming_and_media.md)**: Streaming files, voice calls, and CCTV feeds.
- **[WebRTC Integration (`tutorial/webrtc_integration.md`)](./tutorial/webrtc_integration.md)**: Real-time secure video calls.
- **[Web Framework Middlewares (`tutorial/frameworks/`)](./tutorial/frameworks/fastapi.md)**: Setup guides for FastAPI, Django, and Flask.
- **[Replay Protection (`tutorial/noncestore.md`)](./tutorial/noncestore.md)**: Persistent NonceStores (Memory, Redis, Postgres).
- **[CLI Reference (`tutorial/cli.md`)](./tutorial/cli.md)**: Command-line identity management and `uxsp curl`.
- **[Browser SDK (`tutorial/web_frontend.md`)](./tutorial/web_frontend.md)**: Client-side encryption with `@siva_raja/uxsp`.

---

## 🛡️ Security Policy

We take security seriously. Please report any potential vulnerabilities privately to **sivaraja5401@gmail.com** with subject `[UXSP SECURITY]`. See **[SECURITY.md](./SECURITY.md)** for our coordinated vulnerability disclosure policy.

---

## 📄 License

UXSP is licensed under the **[MIT License](./LICENSE)**.

_UXSP v1.3.0_

_Maintained by SIVA RAJA S_
