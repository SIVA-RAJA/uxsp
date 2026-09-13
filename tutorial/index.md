# UXSP Developer Tutorials & Guides

Welcome to the official developer tutorials and implementation guides for the **Universal Exchange Security Protocol (UXSP v1.3.0)**.

> 🏛️ **Looking for the Formal Protocol Specification or Exact Wire Format?**  
> If you are building a custom client in another language (Rust, Go, C++, Zig, Swift), auditing the cryptography, or studying the low-level byte format, see the authoritative formal documentation in **[`docs/`](../docs/index.md)**:
> - **[Formal Protocol Specification](../docs/protocol_specification.md)**
> - **[Exact Wire Format & Byte-Level Encoding](../docs/wire_format.md)**

This tutorial directory is written for developers of all skill levels who want to build applications using UXSP. You do not need to be a cryptography expert or understand complex networking to secure your applications with UXSP. If you can read standard Python code, you can use UXSP!

---

## 📖 Recommended Reading Path

1. 🌟 **New to UXSP?** Start with **[High-Level APIs](./high_level_api.md)** to learn how to seal and open 14 different data types in 1 line of Python.
2. 🌐 **Connecting Frontend to Backend?** Read **[End-to-End Fullstack Integration](./fullstack_integration.md)** to see React/Next.js and FastAPI/Django/Flask connected with zero-trust encryption.
3. 🔄 **Building Web Clients / Microservices?** Read **[Autonomous HTTP Client & Protocol Switching](./client.md)** to see how `UXSPClient` talks to both secure UXSP servers and legacy unencrypted endpoints automatically.
4. 🚀 **Running Web Frameworks?** Jump to the middleware guides for **[FastAPI](./frameworks/fastapi.md)**, **[Django](./frameworks/django.md)**, or **[Flask](./frameworks/flask.md)**.
5. 📹 **Media & Streaming?** Explore **[Live Media & WebRTC](./streaming_and_media.md)**.

---

## 📚 Table of Contents

### 1. The Core APIs
- 🔐 **[High-Level APIs (`uxsp.secure` & `uxsp.aio`)](./high_level_api.md)**
  - Securely send and receive Text, JSON, Files, Images, Videos, Audio, and more with a single line of code.
  - Learn how to manage Identities, when to use the Asynchronous (`aio`) API for high performance, and how to rotate your security keys.
- 🔄 **[Autonomous HTTP Client (`uxsp.client`)](./client.md)** *(New in v1.3.0)*
  - Master progressive zero-trust adoption with `UXSPClient` and `AsyncUXSPClient`.
  - Learn how automatic protocol negotiation probes endpoints, encrypts UXSP traffic, and seamlessly falls back to standard HTTP for legacy services.
  - Configure Redis and Database capability caching to eliminate redundant discovery round-trips.
- ⚡ **[Asynchronous API Guide (`uxsp.aio`)](./async_api.md)**
  - High-throughput asynchronous dispatchers, event loops, streaming pipes, and concurrent envelope processing.
- ⚙️ **[Low-Level APIs (Core Concepts)](./low_level_api.md)**
  - Advanced cryptographic concepts: manual envelope configuration, key encapsulation mechanisms (KEM), session ratchets, and trust anchors.

### 2. Fullstack & Web Framework Integrations
- 🌐 **[End-to-End Fullstack Integration (Frontend + Backend)](./fullstack_integration.md)** *(Recommended)*
  - Complete walkthrough connecting React/Next.js/JS frontend (`@siva_raja/uxsp`) with Python backend (FastAPI/Django/Flask).
  - Inspect network traffic, handle CORS, manage client identities, and configure automatic fallback.
- 🚀 **[FastAPI Integration Guide](./frameworks/fastapi.md)**
  - Secure FastAPI applications and endpoints automatically with `UXSPFastAPIMiddleware` and `@protect_route`.
- 🐍 **[Django Integration Guide](./frameworks/django.md)**
  - Protect Django views using `UXSPDjangoMiddleware` and view decorators with seamless CSRF coexistence.
- 🧪 **[Flask Integration Guide](./frameworks/flask.md)**
  - Add drop-in WSGI protection for your Flask routes.

### 3. Live Media & Streaming
- 🎥 **[Live Media & WebRTC (Video, Voice, CCTV)](./streaming_and_media.md)**
  - Establish real-time, encrypted Video and Voice calls.
  - Integrate and secure live CCTV camera feeds using `SendLiveSession` and `SendLiveVoiceCall`.
- 📡 **[WebRTC Integration Deep-Dive](./webrtc_integration.md)**
  - Peer-to-peer session exchange, DTLS-SRTP keying coordination, and secure signaling channels.

### 4. Advanced Security Features & Infrastructure
- 🛡️ **[Replay Protection (NonceStores)](./noncestore.md)**
  - Understand how UXSP prevents attackers from reusing old, intercepted messages (Replay Attacks).
  - Integrate `MemoryNonceStore`, `RedisNonceStore`, `PostgresNonceStore` and their `Async` counterparts.
- 💻 **[The UXSP CLI Tool](./cli.md)**
  - Command Line Interface for generating keys, managing identities, and querying endpoints with `uxsp curl`.
- 🌐 **[Frontend Integration (NPM Package)](./web_frontend.md)**
  - Use `@siva_raja/uxsp` in React, Vue, Svelte, or Next.js so data is encrypted directly inside the user's browser with `uxspFetch`.

---

> **Tip:** Start with the **[High-Level APIs](./high_level_api.md)** to see how incredibly simple UXSP is to use!
