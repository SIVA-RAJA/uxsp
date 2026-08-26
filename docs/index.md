# UXSP Developer Documentation Index

Welcome to the official developer documentation for the **Universal Exchange Security Protocol (UXSP v1.1.0)**.

---

## 📚 Guides & Tutorials

### 1. High-Level Developer APIs
- 🔐 **[Synchronous High-Level API (`uxsp.secure`)](./high_level_api.md)**  
  Learn how to use `Send`, `Receive`, `SendText`, `SendJSON`, `SendFile`, and 14 polymorphic data types with stateless identity passing, in-memory key serialization, key lifecycle management, and multi-gigabyte file streaming.
- ⚡ **[Native Asynchronous Engine (`uxsp.aio`)](./async_api.md)**  
  Explore non-blocking async dispatchers (`aio.SendText`, `aio.Receive`, `aio.SendStream`) designed for high-concurrency ASGI applications and WebSockets.
- ⚙️ **[Low-Level Cryptographic APIs](./low_level_api.md)**  
  Dive deep into manual hybrid cryptography (`uxsp.crypto`), session handshakes (`uxsp.core.session`), file chunking, and Nonce storage.

---

### 2. Web Framework Protection
- 🚀 **[FastAPI Integration Guide](./frameworks/fastapi.md)**  
  Protect FastAPI applications with `UXSPFastAPIMiddleware` and `@protect` decorators for automatic request decryption and response encryption.
- 🐍 **[Django Integration Guide](./frameworks/django.md)**  
  Secure Django endpoints using `UXSPDjangoMiddleware` and `@protect_django` view decorators.
- 🧪 **[Flask Integration Guide](./frameworks/flask.md)**  
  Integrate 1-line protection into WSGI Flask applications using `UXSPFlaskMiddleware` and `@protect_flask`.

---

### 3. Enterprise Features & Web Integration
- 🌐 **[Web & Frontend Interoperability Guide (For JS/TS Developers)](./web_frontend.md)**  
  Connect browser applications to Python backends using the `uxsp-js` TypeScript SDK, Draft-07 JSON Schemas, and the Pyodide/WASM browser bridge.
