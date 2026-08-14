# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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
