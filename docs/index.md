# UXSP Documentation & Protocol Specification

Welcome to the official documentation and standards portal for the **Universal Exchange Security Protocol (UXSP)**.

UXSP is an enterprise-grade, hybrid post-quantum cryptographic security protocol designed to deliver end-to-end confidentiality, authenticity, forward secrecy, and replay resistance across heterogenous transport networks (HTTP/HTTPS, WebSockets, WebRTC, binary sockets, and offline storage).

---

## 🏛️ Authoritative Protocol Specifications

For security architects, cryptographers, compliance auditors, and engineers implementing UXSP clients in other languages (such as **Rust, Go, C/C++, Zig, Swift, Java, C#**), refer to the authoritative formal engineering specifications:

| Specification Document | Summary | RFC Status |
| :--- | :--- | :--- |
| 📜 **[Formal Protocol Specification](./protocol_specification.md)** | Formal cryptographic protocol specification, security proofs, IND-CCA2 / EUF-CMA threat model, canonical serialization rules, algorithm suites, identity management, Nonce/timestamp freshness semantics, sequence ordering, 3-step mutual handshake state machine, session lifecycle, version negotiation, and formal error taxonomy. | Standard |
| ⚡ **[Exact Wire Format & Byte-Level Encoding](./wire_format.md)** | Exact byte-level framing, binary layouts, `UXSP/1` magic bytes, header fields, offsets, lengths, bitmasks, big-endian encoding, internal payload framing (`UXSP-PAYLOAD-1`, `UXSP-CHUNK-1`), JSON wire envelope schemas, and complete annotated hex test vectors. | Standard |

---

## 🛠️ Developer Tutorials & Practical Guides

If you are an application developer building software with the Python or JavaScript/TypeScript SDKs, explore our comprehensive developer tutorials in the **[`tutorial/`](../tutorial/index.md)** directory:

- 🚀 **[High-Level Quickstart (`Send` & `Receive`)](../tutorial/high_level_api.md)**: 1-line cryptographic operations across 14 polymorphic data types.
- ⚙️ **[Low-Level Primitives](../tutorial/low_level_api.md)**: Direct usage of `Envelope`, `Identity`, and `Session`.
- ⚡ **[Asynchronous Engine (`uxsp.aio`)](../tutorial/async_api.md)**: High-throughput async I/O pipelines.
- 🎥 **[Live Media & WebRTC Streaming](../tutorial/streaming_and_media.md)**: Real-time encrypted video, voice, and CCTV feeds.
- 🐍 **[Web Framework Integrations](../tutorial/frameworks/fastapi.md)**: Drop-in protection for **FastAPI**, **Django**, and **Flask**.
- 🛡️ **[Replay Guard & NonceStores](../tutorial/noncestore.md)**: Memory, Redis, and Postgres durable replay guards.
- 💻 **[Command-Line Interface (CLI)](../tutorial/cli.md)**: Keys, cards, trust anchors, and envelope diagnostics.
- 🌐 **[Browser & Frontend SDK](../tutorial/web_frontend.md)**: JavaScript/TypeScript client library.

---

## 🔬 Protocol Architecture Summary

```mermaid
graph TD
    subgraph Identity & Trust Anchor Layer
        TA[Trust Anchor / Root CA] -->|Signs| SC[Signed PublicCard]
        PC[PublicCard: X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65]
    end

    subgraph Transport & Wire Envelopes
        ENV[UXSP Sealed Envelope]
        ENV -->|Binary Wire Format| BIN[UXSP/1 Binary Frame 0x55 0x58 0x53 0x50]
        ENV -->|JSON Wire Format| JSN[application/uxsp+json Payload]
    end

    subgraph Cryptographic Core
        KEM[ML-KEM-768 FIPS 203] + ECDH[X25519 Curve25519] --> HKDF[HKDF-SHA256 Master Key]
        SIG[ML-DSA-65 FIPS 204] + EDS[Ed25519] --> DUAL[Dual-Layer Authentication]
        HKDF --> AES[AES-256-GCM AEAD Encryption]
    end

    subgraph State Machines & Guards
        HS[3-Step Handshake: HELLO -> ACK -> COMPLETE]
        SESS[Session Manager: Directional Keys + Monotonic Seq]
        NS[NonceStore: Redis / Postgres / Memory Replay Guard]
    end

    PC --> ENV
    BIN --> AES
    JSN --> AES
    DUAL --> ENV
    HS --> SESS
    SESS --> NS
```

---

## 📌 Document Versioning & Standards Compliance

- **Current Protocol Version**: `UXSP-1` (`UXSP/1.2`)
- **NIST Post-Quantum Standards**:
  - **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM-768)
  - **FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA-65)
- **Classical Baselines**:
  - **RFC 7748**: Elliptic Curves for Security (X25519 ECDH)
  - **RFC 8032**: Edwards-Curve Digital Signature Algorithm (Ed25519)
  - **NIST SP 800-38D**: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (AES-256-GCM)
  - **RFC 5869**: HMAC-based Extract-and-Expand Key Derivation Function (HKDF-SHA256)
  - **RFC 9106**: Argon2 Password Hashing Function (Argon2id)
