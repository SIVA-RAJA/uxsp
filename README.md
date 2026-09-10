# UXSP — Universal Exchange Security Protocol

[![Version: 1.2.0](https://img.shields.io/badge/Version-1.2.0-orange)]()
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green)]()
[![Coverage: 100%](https://img.shields.io/badge/Coverage-100%25-brightgreen)]()

**UXSP (Universal Exchange Security Protocol)** is an enterprise-grade, hybrid post-quantum security framework. It is designed from the ground up to protect your web APIs, file streams, messaging layers, and live media against classical eavesdroppers and the upcoming threat of quantum computers.

---

## 💡 What is UXSP?

In standard web applications, data sent over the internet relies on traditional encryption (like RSA or ECC). However, upcoming quantum computers will soon be powerful enough to break this traditional encryption, exposing sensitive user records, financial transactions, and private messages.

**UXSP solves this problem today by providing "Hybrid Post-Quantum Security":**
1. **Double-Layer Armor**: It combines trusted classical encryption (AES-256-GCM + X25519/Ed25519) with modern NIST-standardized Post-Quantum Cryptography algorithms (**ML-KEM** FIPS 203 and **ML-DSA** FIPS 204).
2. **Zero-Complexity for Developers**: Instead of writing hundreds of lines of complex cryptographic setup, UXSP provides beautiful, high-level APIs that allow developers to secure entire applications, web endpoints, multi-gigabyte file transfers, and even WebRTC video streams with **just 1 line of code**.

---

## ✨ Features Overview

UXSP comes packed with capabilities to handle any data transfer scenario securely:

- **Send Any Format**: Whether you are sending plain text, structured JSON, raw binary, large files, documents (PDF, Word), images, photos, audio, voice memos, archives (Zip), locations, or contacts, UXSP provides dedicated classes for all data types. It automatically serializes, chunks, encrypts, and packages the data.
- **Live Video Calls**: Negotiate high-performance AES-GCM secure WebRTC sessions for real-time video calls with a single line of code.
- **Live Voice Calls**: Establish encrypted audio streams with configurable codecs and sample rates for highly secure voice communication.
- **Live CCTV Integration**: Securely connect and stream data from live CCTV cameras, protecting sensitive monitoring feeds from interception.
- **Web Framework Middlewares**: Drop-in middlewares for **FastAPI**, **Django**, and **Flask**. They automatically decrypt incoming requests, verify identities, and encrypt outbound responses, replacing the need for traditional CSRF tokens.
- **Durable Replay Protection (NonceStores)**: Out-of-the-box support for Memory, Redis, and Postgres-backed NonceStores (both synchronous and asynchronous) to ensure intercepted messages can never be replayed by an attacker.
- **Frontend Interoperability**: A companion NPM package allows your web frontend to encrypt data directly in the browser before it even hits the network.

*(For detailed implementations, tutorials, and code examples of these features, please refer to the `docs/` directory).*

---

## ⚙️ Installation & Setup

UXSP is highly modular. You only need to install the dependencies required for your specific framework and storage needs.

| Installation Command | Included Components & Dependencies |
| :--- | :--- |
| `pip install uxsp` | Base `uxsp.secure` (cryptography, liboqs-python, argon2-cffi) |
| `pip install uxsp[aio]` | `uxsp.secure` + `uxsp.aio` (Asynchronous capabilities) |
| `pip install uxsp[django]` | `uxsp.secure` + Django Integrations |
| `pip install uxsp[flask]` | `uxsp.secure` + Flask Integrations |
| `pip install uxsp[fastapi]` | `uxsp.secure` + FastAPI, Starlette, HTTPX Integrations |
| `pip install uxsp[postgres]` | `uxsp.secure` + Postgres (`psycopg2-binary`) |
| `pip install uxsp[redis]` | `uxsp.secure` + Redis (`redis`) |
| `pip install uxsp[aio, django]` | `uxsp.secure` + `uxsp.aio` + Django |
| `pip install uxsp[aio, postgres]` | `uxsp.secure` + `uxsp.aio` + Postgres |
| `pip install uxsp[aio, redis]` | `uxsp.secure` + `uxsp.aio` + Redis |
| `pip install uxsp[aio, django, postgres]` | `uxsp.secure` + `uxsp.aio` + Django + Postgres |
| `pip install uxsp[aio, django, redis]` | `uxsp.secure` + `uxsp.aio` + Django + Redis |
| `pip install uxsp[all-django]` | `uxsp.secure` + `uxsp.aio` + Django + Postgres + Redis |
| `pip install uxsp[all-flask]` | `uxsp.secure` + `uxsp.aio` + Flask + Postgres + Redis |
| `pip install uxsp[all-fastapi]` | `uxsp.secure` + `uxsp.aio` + FastAPI + Postgres + Redis |
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
  Requires Visual Studio Build Tools (C++), CMake, and Git. *(Note: Windows support is experimental and falls back to msvcrt for certain operations).*

*(If `liboqs` fails to compile on your system, UXSP will automatically fall back to its built-in pure Python Post-Quantum Cryptography implementations, ensuring it always runs).*

---

## 🚀 Documentation & Specifications

UXSP provides both formal protocol engineering specifications and hands-on developer tutorials:

### 📜 Formal Protocol Specifications (`docs/`)
For security auditors, cryptographers, and engineers implementing UXSP in other languages (Rust, Go, C/C++, Zig, Swift):
- **[Formal Protocol Specification (`docs/protocol_specification.md`)](./docs/protocol_specification.md)**: Security proofs, IND-CCA2 threat model, canonical serialization, handshake state machine, session lifecycle, and error code registry.
- **[Exact Wire Format & Byte-Level Encoding (`docs/wire_format.md`)](./docs/wire_format.md)**: Exact bit-level framing, byte offsets, `UXSP/1` binary layout, JSON wire schema, and annotated hex dumps.
- **[Documentation Index (`docs/index.md`)](./docs/index.md)**: Protocol specifications overview and architecture portal.

### 📖 Developer Tutorials & Framework Guides (`tutorial/`)
For application developers building software with UXSP:
- **[Tutorials Portal (`tutorial/index.md`)](./tutorial/index.md)**: Step-by-step guides for all features.
- **[High-Level APIs (`tutorial/high_level_api.md`)](./tutorial/high_level_api.md)**: 1-line cryptographic operations across 14 polymorphic data types.
- **[Low-Level APIs (`tutorial/low_level_api.md`)](./tutorial/low_level_api.md)**: Custom cryptographic workflows and key management.
- **[Asynchronous Engine (`tutorial/async_api.md`)](./tutorial/async_api.md)**: High-throughput async I/O pipelines.
- **[Live Media & WebRTC (`tutorial/streaming_and_media.md`)](./tutorial/streaming_and_media.md)**: Encrypted real-time video, voice calls, and CCTV feeds.
- **[Web Framework Middlewares (`tutorial/frameworks/`)](./tutorial/frameworks/fastapi.md)**: Drop-in protection for **FastAPI**, **Django**, and **Flask**.
- **[Replay Protection (`tutorial/noncestore.md`)](./tutorial/noncestore.md)**: Durable NonceStores (Memory, Redis, Postgres).
- **[CLI Tooling (`tutorial/cli.md`)](./tutorial/cli.md)**: Command-line identity and card management.
- **[Frontend Integration (`tutorial/web_frontend.md`)](./tutorial/web_frontend.md)**: Browser TypeScript/JavaScript SDK.

---

## 📄 License & Security

UXSP is released under the **[MIT License](./LICENSE)**. 
For security disclosures, vulnerability reporting, and threat models, please consult **[SECURITY.md](./SECURITY.md)**.

_UXSP v1.2.0_
_Maintained by SIVA RAJA S_