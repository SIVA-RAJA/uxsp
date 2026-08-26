# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-08-26

### Milestone: Enterprise Web Framework Integrations, Native Async Engine & Web Interoperability

UXSP 1.1.0 is a major feature release delivering seamless 1-line web framework integrations (FastAPI, Django, Flask), high-throughput asynchronous execution (`uxsp.aio`), memory-efficient multi-gigabyte file streaming, enterprise key lifecycle management (rotation, expiration, revocation), Draft-07 JSON Schema wire specifications, a browser TypeScript SDK (`uxsp-js`), and a WASM/Pyodide browser bridge—all supported by verified **100% test coverage** across 4,617 executable statements.

### Added

- **Web Framework Integrations (`uxsp.contrib`)**:
  - `pip install uxsp[fastapi]`, `pip install uxsp[django]`, `pip install uxsp[flask]`, `pip install uxsp[all]` optional installation extras.
  - `UXSPFastAPIMiddleware` & `@protect` / `@protect_route` endpoint decorators for automatic request decryption and response encryption in FastAPI applications.
  - `UXSPDjangoMiddleware` & `@protect_django` view decorators for Django applications with automatic header resolution (`X-UXSP-Package`, `X-UXSP-Sender`).
  - `UXSPFlaskMiddleware` & `@protect_flask` decorators for Flask web services.
- **Native Asynchronous Engine (`uxsp.aio`)**:
  - High-throughput non-blocking asynchronous dispatchers: `await uxsp.aio.SendText()`, `await uxsp.aio.Receive()`, `await uxsp.aio.SendFile()`, `await uxsp.aio.ReceiveFile()`, and `await uxsp.aio.SendStream()`.
  - Non-blocking async chunked streaming for ASGI servers and WebSocket streams handling thousands of concurrent client connections.
- **File Streaming API (`SendStream` / `ReceiveStream`)**:
  - Multi-gigabyte (10GB+) file transfer support with fixed low memory footprint ($O(\text{chunk\_size})$).
  - Stream chunks directly from file descriptors, path objects, or Python generators directly to disk or output streams.
- **Enterprise Key Lifecycle Management (`uxsp.core.identity`)**:
  - `Identity.rotate_keys()` for generating new hybrid post-quantum keypairs while preserving identity ID and recording key rotation timestamps.
  - `PublicCard` expiration timestamps (`valid_until` ISO strings or `datetime` objects, `ttl_seconds`) and validity verification (`verify_validity()`).
  - Public card revocation tracking (`revoke(reason)`) throwing `CardRevokedError` and `CardExpiredError` on decryption attempts.
- **Web / Frontend Interoperability (`uxsp.schema`, `sdks/js/`, `uxsp.wasm`)**:
  - Draft-07 JSON Schema specifications (`envelope_schema.json`, `package_schema.json`, `public_card_schema.json`) and `uxsp.schema` runtime validator functions.
  - Standalone TypeScript/JavaScript SDK (`uxsp-js` v1.1.0) providing `UXSPClient`, full TypeScript interfaces, and native schema validation for browser applications.
  - Pyodide / WebAssembly compatibility layer (`uxsp.wasm` & `uxsp.pyodide`) enabling UXSP cryptographic execution inside browser Web Workers and Pyodide runtimes.

### Changed

- **Version Bump**: Upgraded package version to `1.1.0`.
- **Test Coverage**: Achieved verified **100% test coverage** (4,617 / 4,617 statements) across 1,533 unit tests.

## [1.0.1] - 2026-08-25

### Milestone: High-Level API Simplification & In-Memory Identity Serialization

UXSP 1.0.1 introduces a major developer workflow enhancement by removing global state requirements and manual temp-file plumbing. High-level functions now support direct object passing (`Identity` and `PublicCard`), and `Identity` supports in-memory encrypted serialization for database/session storage in web backends.

### Added

- **In-Memory Identity Serialization (`uxsp.core.identity`)**:
  - `to_encrypted_json(password)` & `from_encrypted_json(encrypted_json, password)` for serializing/restoring encrypted identity payloads directly in memory (strings or bytes) without disk temporary files.
  - `to_encrypted_dict(password)` & `from_encrypted_dict(payload, password)` dict-based serialization helpers.
  - Top-level aliases `export_encrypted` and `import_encrypted`.
  - Password hashing & verification static methods on `Identity`: `hash_password(password)` and `verify_password(stored_hash, password)`.
- **Stateless Direct Object Passing (`uxsp.secure`)**:
  - Refactored `_secure_send_payload` and `_secure_receive_payload` to accept `Identity` or `PublicCard` objects directly for `sender` and `receiver`.
  - Updated all specialized and polymorphic send/receive handlers (`SendText`, `ReceiveText`, `SendFile`, `ReceiveFile`, `SendJSON`, `ReceiveJSON`, `Send`, `Receive`, etc.) to pass `sender` and `receiver` parameters directly, bypassing global `configure()` or `set_identity()` state for thread-safe multi-user application backends.
- **Top-Level Package Helper Exports**:
  - Exported `create_identity`, `export_identity_encrypted`, `import_identity_encrypted`, `hash_password`, and `verify_password` directly in `uxsp`.

### Changed

- **Application Integration**: Refactored `TharavuXchange` service layer (`uxsp_service.py`) to use the new simplified, stateless APIs and in-memory identity serialization.
- **Test Coverage**: Achieved verified **100% statement coverage** (3,663 / 3,663 lines) across the entire library with 1,466 passing tests.

## [1.0.0] - 2026-08-14

### Milestone: Stable Production Release & Developer API

UXSP 1.0.0 marks the official stable production release of the Universal Exchange Security Protocol, featuring the brand-new **Developer API (`uxsp.secure`)**, end-to-end post-quantum cryptographic security, and verified **100% test coverage** across all 3,590 executable statements.

### Added

- **Developer Workflow (`uxsp.secure`)**:
  - Implemented high-level `Send*` and `Receive*` functional interfaces that drastically reduce developer boilerplate from 30+ lines to 1-2 intuitive lines of Python.
  - Full polymorphic and strongly typed support for **14 data types**:
    - `SendVideo` / `ReceiveVideo` (video files & streams)
    - `SendAudio` / `ReceiveAudio` (audio files & tracks)
    - `SendPhoto` / `ReceivePhoto` (or `SendImage` / `ReceiveImage`)
    - `SendText` / `ReceiveText` (UTF-8 messages)
    - `SendDocument` / `ReceiveDocument` (or `SendDoc` / `ReceiveDoc`)
    - `SendPDF` / `ReceivePDF` (PDF documents)
    - `SendFile` / `ReceiveFile` (arbitrary file transfer)
    - `SendBinary` / `ReceiveBinary` (raw bytes payload)
    - `SendJSON` / `ReceiveJSON` (Python dicts/lists JSON serialization)
    - `SendHTML` / `ReceiveHTML` (rich formatted markup)
    - `SendArchive` / `ReceiveArchive` (or `SendZip` / `ReceiveZip`)
    - `SendVoice` / `ReceiveVoice` (voice memos and clips)
    - `SendLocation` / `ReceiveLocation` (GPS coordinates & location metadata)
    - `SendContact` / `ReceiveContact` (contact cards & address book entries)
  - Universal polymorphic dispatchers `uxsp.secure.Send` and `uxsp.secure.Receive` that auto-detect payloads and file extensions automatically.
  - Context configuration helper `configure(...)` and `get_context()` for customizing identity, key store, nonce store, replay guard, and default download directories.
  - File-based container encapsulation with `SecurePackage` for transport over JSON, REST APIs, message queues, and disk.
- **Top-Level Module Exports**:
  - Direct access to `uxsp.secure.*` and top-level convenient aliases in `uxsp`.

### Changed

- **Production Status**: Promoted development status classifier from `Beta` to `Development Status :: 5 - Production/Stable`.
- **Test Suite**: Expanded tests to 1,459 automated regression tests with 100% statement and branch coverage.
- **Documentation**: Overhauled `README.md` and `SECURITY.md` for v1.0.0 with developer-friendly quickstart guides and comprehensive protocol reference.

## [0.1.2] - 2026-05-19

### Changed

- Bumped package version to 0.1.2

## [0.1.1] - 2026-05-18

This release introduces major feature expansions for handling structured application payloads and large files (including documents, videos, photos, images, and other media), refactors replay protection to support dependency injection and two-stage validation, and fully restructures the test suite to reach a verified **100% test coverage** benchmark.

### Added

- **Structured Messaging (`uxsp.core.payload`)**:
  - Added the `UXSPPayload` container class to safely pack structured application messages.
  - Support for `TEXT` (UTF-8 strings), `BINARY` (raw bytes), and `FILE` (payload body with a preserved filename and content type, allowing users to send files, photos, videos, documents, and other media) payload kinds.
  - Provided high-level convenience packing and unpacking APIs: `pack_text`, `unpack_text`, `pack_file` (with automatic MIME type and filename detection for photos, videos, and other files), `unpack_to_file`, and `pack_binary`.
  - Added binary serialization and format validation with a secure `UXSP-PAYLOAD-1` magic header and length-prefixed JSON metadata.
- **Large-Payload Chunking (`uxsp.core.chunking`)**:
  - Added the `UXSPChunk` frozen dataclass for splitting large payloads exceeding standard Envelope size limits (default 64 KiB)—such as high-resolution photos, large videos, or documents—into individually encrypted and signed chunks.
  - Implemented `create_chunked_transfer` and `reassemble_chunked_transfer` to fragment and safely reconstruct arbitrary binary data.
  - Created convenience text-chunking wrappers `create_chunked_text` and `decode_chunked_text`.
  - Enforced strong integrity checks by requiring every chunk to carry both its individual SHA-256 hash and the final reassembled file's SHA-256 hash, verifying all pieces upon reassembly.
- **Modular Test Suite & 100% Coverage**:
  - Deconstructed the monolithic `tests/test.py` from v0.1.0 into a clean, modular hierarchy under `tests/`.
  - Created distinct, focused test scripts: `tests/cli_test.py`, `tests/core/*_test.py`, `tests/crypto/*_test.py`, `tests/storage/*_test.py`, and `tests/transport/*_test.py`.
  - Achieved a strict **100% statement and branch coverage** across all source files.
- **Static Typing Configurations**:
  - Added a dedicated [tool.pyright] configuration section to `pyproject.toml` to support Pyright standard-mode typing validation alongside Mypy.

### Changed

- **Replay Protection Refactoring (`uxsp.core.replay`)**:
  - Introduced the structural protocol `DefaultReplayGuard` to support dependency injection. Developers can now implement custom replay guards (e.g., distributed guards, memory-optimized databases) seamlessly.
  - Enhanced `ReplayGuard` with advanced stages for two-step protocols:
    - `check_freshness` — Verifies only the timestamp window (cheap, non-blocking check).
    - `precheck` — Diagnostics-level seen check prior to running computationally expensive cryptographic operations.
    - `commit` — Atomic verification and registration to prevent race conditions during concurrent decrypts.
    - `check_and_commit` / `check_and_open` — Robust one-shot APIs.
- **Flexible Dependency Bounds (`pyproject.toml`)**:
  - Converted core dependencies (`cryptography`, `liboqs-python`, `argon2-cffi`) from exact version pins (`==`) to safe minimum lower bounds (`>=`). This eliminates dependency conflicts for packages consuming UXSP as a library.
  - Converted optional dependencies (`redis`, `psycopg2-binary`) to lower bounds (`>= 4.0.0` and `>= 2.9.0` respectively).
- **Metadata and Discoverability**:
  - Updated python version requirements in MyPy and Pyright to `"3.11"` to match core specifications.
  - Registered `Documentation`, `Bug Tracker`, and `Changelog` links in package metadata.
  - Verified and adjusted Windows experimental classifiers for `msvcrt` fallback compatibility.

---

## [0.1.0] - 2026-05-01

### Added

- **Initial Public Beta Release** of the Universal Exchange Security Protocol (UXSP).
- **Hybrid Post-Quantum Cryptography**:
  - Quantum-resistant asymmetric key exchange using **ML-KEM-768** mixed with classical **X25519** ECDH via HKDF-SHA256.
  - Dual signature identity verification utilizing **ML-DSA-65** coupled with classical **Ed25519**.
- **Secure Transport Layers**:
  - Length-prefixed framing and session lifecycle state-machine for stateful WebSockets.
  - High-performance, stateless header-bound envelope handling for HTTP.
- **Storage Infrastructure**:
  - cross-process File and Memory key stores.
  - Memory, Redis, and PostgreSQL nonce storage backends enforcing atomic fail-closed replay protection.
- **Enterprise Controls**:
  - Per-entity rate limiting and token-bucket sliding windows to guard expensive PQC operations.
  - Sequence-number-enforced ordering to prevent out-of-order session injection attacks.
