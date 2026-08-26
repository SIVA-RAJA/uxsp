# UXSP — Universal Exchange Security Protocol

[![Version: 1.1.0](https://img.shields.io/badge/Version-1.1.0-orange)]()
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green)]()
[![Coverage: 100%](https://img.shields.io/badge/Coverage-100%25-brightgreen)]()

**UXSP (Universal Exchange Security Protocol)** is an enterprise-grade, hybrid post-quantum security framework designed to protect data, web APIs, and file streams against both classical eavesdroppers and future quantum computer threats.

---

## 💡 What is UXSP? 

In standard web applications, data sent over the internet relies on traditional encryption (like standard RSA or ECC). However, upcoming quantum computers will soon be powerful enough to break traditional encryption, exposing sensitive user records, financial transactions, and private messages.

**UXSP solves this problem today by providing "Hybrid Post-Quantum Security":**
1. **Double-Layer Armor**: It combines trusted classical encryption (AES-256-GCM + X25519/Ed25519) with modern NIST-standardized Post-Quantum Cryptography algorithms (**ML-KEM** FIPS 203 and **ML-DSA** FIPS 204).
2. **Zero-Complexity for Developers**: Instead of writing hundreds of lines of complex cryptographic setup, UXSP allows developers to secure entire applications, web endpoints, and multi-gigabyte file transfers with **just 1 line of code**.

---

## ✨ Key Capabilities

- 🛡️ **Hybrid Post-Quantum Cryptography**: NIST FIPS 203 (ML-KEM) + FIPS 204 (ML-DSA) combined with classical X25519, Ed25519, and AES-256-GCM.
- ⚡ **Developer-First 1-Line API (`uxsp.secure`)**: Send and receive strings, JSON, files, and multi-gigabyte streams effortlessly. Includes enterprise key lifecycle management (rotation, expiration, revocation).
- 🚀 **Native Async Engine (`uxsp.aio`)**: Non-blocking asynchronous dispatchers and async streaming built for high-throughput ASGI services and WebSockets.
- 🌐 **1-Line Web Framework Integrations**: Automatic middleware and endpoint protection for **FastAPI**, **Django**, and **Flask**.
- 🖥️ **Web & Frontend Interoperability**: Draft-07 JSON Schema wire formats, standalone TypeScript SDK (`uxsp-js`), and Pyodide/WASM browser worker bridges.
- 🎯 **100% Verified Test Coverage**: Every line, branch, and module in UXSP is backed by automated test suites.

---

## ⚙️ Installation & Initial Setup

### 1. Basic Installation
Install the core UXSP package via `pip` (Installs `uxsp.secure` and `uxsp.aio` capabilities natively, with zero bloated external dependencies):

```bash
pip install uxsp

# The following conceptual combinations are natively supported:
pip install uxsp --no-aio       # Conceptual: Install only uxsp.secure features (note: pip syntax doesn't allow --no-flags, but aio uses built-in asyncio anyway!)
pip install uxsp                # Conceptual: Install uxsp.aio and uxsp.secure
```

### 2. Framework & Storage Extras (Modular Installation)
UXSP allows you to strictly install only the dependencies required for your specific web framework or database:

```bash
pip install uxsp[django]           # Install Django integrations and required deps
pip install uxsp[flask]            # Install Flask integrations and required deps
pip install uxsp[fastapi]          # Install FastAPI integrations and required deps
pip install uxsp[postgres]         # Install Postgres durability and required deps
pip install uxsp[postgres, redis]  # Install Postgres & Redis required deps
pip install uxsp[all]              # Install all framework & storage integrations
```

### 3. System Prerequisites (`liboqs`)
UXSP utilizes `liboqs` for C-native Post-Quantum Cryptography acceleration. 

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

*(If `liboqs` is not pre-installed on your system, UXSP automatically falls back to built-in pure Python PQC implementations.)*

---

## 📚 Complete Developer Documentation (`docs/`)

This README serves purely as an introduction to the project. For all code examples, step-by-step tutorials, and API references, please navigate to the **[`docs/`](./docs/)** directory. 

We have prepared comprehensive, easy-to-follow tutorials for every feature in the library:

- 📖 **[Developer Docs Overview](./docs/index.md)** — Master table of contents for all guides.
- 🔐 **[Synchronous High-Level API (`uxsp.secure`)](./docs/high_level_api.md)** — Guide for 14 polymorphic data types, stateless identity passing, multi-gigabyte streaming, and key lifecycle.
- ⚡ **[Asynchronous Engine (`uxsp.aio`)](./docs/async_api.md)** — Non-blocking async dispatchers & async streaming for ASGI servers and WebSockets.
- ⚙️ **[Low-Level Cryptographic APIs (`uxsp.core` & `uxsp.crypto`)](./docs/low_level_api.md)** — Dive deep into manual Post-Quantum hybrid encryption, handshakes, and chunking.
- 🚀 **[FastAPI Protection Guide](./docs/frameworks/fastapi.md)** — 1-Line `UXSPFastAPIMiddleware` and `@protect` decorators.
- 🐍 **[Django Protection Guide](./docs/frameworks/django.md)** — `UXSPDjangoMiddleware` and `@protect_django` view protection.
- 🧪 **[Flask Protection Guide](./docs/frameworks/flask.md)** — `UXSPFlaskMiddleware` and route protection.
- 🌐 **[Web & Frontend Interoperability Guide (For JS/TS Developers)](./docs/web_frontend.md)** — Using `@siva_raja/uxsp` TypeScript SDK, JSON Schemas, and Pyodide/WASM in browser workers.

---

## 📄 License & Security

UXSP is released under the **[MIT License](./LICENSE)**. For security disclosures, vulnerability reporting, and threat models, please consult **[SECURITY.md](./SECURITY.md)**.


_UXSP v1.1.0_ 

_Maintained by SIVA RAJA S_