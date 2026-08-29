# UXSP Developer Documentation

Welcome to the official developer documentation for the **Universal Exchange Security Protocol (UXSP v1.2.0)**.

This documentation is written for developers of all skill levels. You do not need to be a cryptography expert or understand complex networking to secure your applications with UXSP. If you can read standard Python code, you can use UXSP!

## 📖 How to Read These Docs

If you are new to UXSP, we recommend reading through the **High-Level APIs** first. It covers how to quickly encrypt and decrypt data using the simple `Send` and `Receive` tools.

Once you understand the basics, you can move on to specific topics like protecting your Web Framework (Django, FastAPI, Flask) or exploring live video streaming.

---

## 📚 Table of Contents

### 1. The Core APIs
- 🔐 **[High-Level APIs (`uxsp.secure` & `uxsp.aio`)](./high_level_api.md)**
  - Discover how to securely send and receive Text, JSON, Files, Images, Videos, Audio, and more with just a single line of code.
  - Learn how to manage Identities, when to use the Asynchronous (`aio`) API for high performance, and how to rotate your security keys.
- ⚙️ **[Low-Level APIs (Core Concepts)](./low_level_api.md)**
  - Dive into the advanced concepts. Learn how manual configuration works, how the core cryptography operates, and how to connect low-level tools with high-level ones.

### 2. Live Media & Streaming
- 🎥 **[Live Media & WebRTC (Video, Voice, CCTV) ](./streaming_and_media.md)**
  - Learn how to establish real-time, encrypted Video and Voice calls.
  - Discover how to integrate and secure live CCTV camera feeds using `SendLiveSession` and `SendLiveVoiceCall`.

### 3. Web Framework Middlewares
- 🐍 **[Django Integration Guide](./frameworks/django.md)**
  - Protect Django views using `UXSPDjangoMiddleware` and `@protect`. Learn why ordering matters and exactly where to put them.
- 🚀 **[FastAPI Integration Guide](./frameworks/fastapi.md)**
  - Secure FastAPI applications and endpoints automatically.
- 🧪 **[Flask Integration Guide](./frameworks/flask.md)**
  - Add drop-in WSGI protection for your Flask routes.

### 4. Advanced Security Features
- 🛡️ **[Replay Protection (NonceStores)](./noncestore.md)**
  - Understand how UXSP prevents attackers from reusing old, intercepted messages (Replay Attacks).
  - Learn how to integrate `MemoryNonceStore`, `RedisNonceStore`, `PostgresNonceStore` and their `Async` counterparts into your apps.
- 💻 **[The UXSP CLI Tool](./cli.md)**
  - Learn how to use the built-in Command Line Interface for generating keys, managing identities, and diagnosing issues during development and production.
- 🌐 **[Frontend Integration (NPM Package)](./web_frontend.md)**
  - Learn how to use the `@siva_raja/uxsp` package in your JavaScript/TypeScript frontend so that data is encrypted *before* it ever leaves the user's browser.

---

> **Tip:** Start with the **[High-Level APIs](./high_level_api.md)** to see how incredibly simple UXSP is to use!
