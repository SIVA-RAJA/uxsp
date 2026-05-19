# UXSP — Universal Exchange Security Protocol

[![Security: Hybrid PQC](https://img.shields.io/badge/Security-Hybrid%20PQC-blueviolet)](https://openquantumsafe.org/)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: passed](https://img.shields.io/badge/Tests-all%20passed-brightgreen)]()
[![Version: 0.1.2](https://img.shields.io/badge/Version-0.1.2-orange)]()

**UXSP** is an enterprise-grade, **hybrid post-quantum secure messaging protocol** for Python. It is designed to safeguard communications against both classical and quantum adversaries—specifically targeting the **"harvest now, decrypt later" (HNDL)** attack vector, where adversaries capture and store encrypted communications today with the intent to decrypt them once cryptographically relevant quantum computers (CRQCs) become available.

To guarantee survival in a post-quantum world, every UXSP transaction is wrapped in **two independent, parallel cryptographic layers**:
1. **A Classical Layer** (using battle-tested X25519 ECDH for key exchange and Ed25519 for signatures).
2. **A Post-Quantum Layer** (using NIST-standardized ML-KEM-768 for key encapsulation and ML-DSA-65 for digital signatures).

Both cryptographic layers must be compromised simultaneously to break the security of the protocol. If either layer remains secure, the entire payload remains fully protected.

---

## Contents

- [How it Works](#how-it-works)
- [Operating System Compatibility](#operating-system-compatibility)
- [Prerequisites: Building `liboqs` for All Platforms](#prerequisites-building-liboqs-for-all-platforms)
  - [Compiling `liboqs` on Linux](#1-compiling-liboqs-on-linux)
  - [Compiling `liboqs` on macOS](#2-compiling-liboqs-on-macos)
  - [Compiling `liboqs` on Windows](#3-compiling-liboqs-on-windows)
  - [Configuring the Dynamic Library Path](#4-configuring-the-dynamic-library-path)
  - [Verifying the Setup](#5-verifying-the-setup)
- [Installation](#installation)
- [Comprehensive API Guide & Code Examples](#comprehensive-api-guide--code-examples)
  - [Level 1: Identity & Key Management](#level-1-identity--key-management)
  - [Level 2: One-Shot Sealed Envelopes (Stateless Encrypted Messages)](#level-2-one-shot-sealed-envelopes-stateless-encrypted-messages)
  - [Level 3: Full-Duplex Authenticated Handshake & Sessions](#level-3-full-duplex-authenticated-handshake--sessions)
  - [Level 4: Advanced Payload Packing (Text, Files, & Large Chunking)](#level-4-advanced-payload-packing-text-files--large-chunking)
  - [Level 5: Trust Anchors & Signed Cards (PKI & CA Chain)](#level-5-trust-anchors--signed-cards-pki--ca-chain)
  - [Level 6: Production Storage Backends (KeyStore & NonceStore)](#level-6-production-storage-backends-keystore--noncestore)
  - [Level 7: Rate Limiting & Guarded Endpoints](#level-7-rate-limiting--guarded-endpoints)
  - [Level 8: HTTP & WebSocket Transport Layers](#level-8-http--websocket-transport-layers)
- [Command-Line Interface (CLI) Guide](#command-line-interface-cli-guide)
- [Cryptographic Specifications](#cryptographic-specifications)
- [Security Guarantees & Threat Model](#security-guarantees--threat-model)
- [Production Deployment Checklist](#production-deployment-checklist)
- [Running the Test Suite](#running-the-test-suite)
- [Contributing & Security Policy](#contributing--security-policy)
- [License](#license)

---

## How it Works

UXSP supports two primary interaction patterns:
1. **Stateless One-Shot Messages (Sealed Envelopes):** For APIs, task queues, or asynchronous messaging where stateful sessions are unnecessary. The sender "seals" the message for the recipient, and the recipient opens it securely with replay protection.
2. **Stateful Full-Duplex Sessions (Handshake):** For persistent sockets, long-lived pipelines, or interactive systems.

```
 Alice (Initiator)                                            Bob (Responder)
       │                                                             │
       │─────── Handshake.initiate() ───────────────────────────────▶│
       │        HELLO Message (signed, KEM encapsulation)            │
       │                                                             │
       │◀────── Handshake.respond() ─────────────────────────────────│
       │        ACK Message (signed, KEM, HMAC proof of shared key)  │
       │                                                             │
       │─────── Handshake.complete() ───────────────────────────────▶│
       │        COMPLETE Message (session active on both sides)      │
       │                                                             │
       │═════════════════════════════════════════════════════════════│
       │            Active Double-Channel Session Encrypted          │
       │            via AES-256-GCM, sequence-locked, replay-safe    │
       │═════════════════════════════════════════════════════════════│
```

---

## Operating System Compatibility

UXSP is a pure-Python library designed to run on all platforms where Python 3.11+ is supported. However, its core post-quantum cryptographic operations rely on **`liboqs`**, a highly optimized C library from the Open Quantum Safe project.

| Operating System | Support Level | Compilation Toolchain | Linking Strategy |
|---|---|---|---|
| **Linux** (Debian/Ubuntu, CentOS/Fedora, Alpine) | **Production-grade (Primary)** | `gcc` / `clang`, CMake, Ninja | `ldconfig` & `/usr/local/lib/liboqs.so` |
| **macOS** (Apple Silicon M1/M2/M3 & Intel) | **Production-grade (Primary)** | Xcode Command Line Tools, Homebrew, CMake, Ninja | `DYLD_LIBRARY_PATH` & `liboqs.dylib` |
| **Windows** (10, 11, Server) | **Supported (Stable)** | MSVC (Visual Studio) or MinGW-w64 (MSYS2), CMake | `%PATH%` DLL path or `LIBOQS_INSTALL_PATH` |

---

## Prerequisites: Building `liboqs` for All Platforms

Because `liboqs` package distribution varies, building from source is the **only guaranteed method** to secure the latest performance optimizations and security fixes. Follow the exact guide below for your operating system.

### 1. Compiling `liboqs` on Linux

#### Ubuntu / Debian / Mint
Install dependencies and build tools:
```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build libssl-dev git
```

#### Fedora / RHEL / CentOS / Rocky Linux
Install dependencies:
```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y cmake ninja-build openssl-devel git
```

#### Clone and Build
Run the following build sequence:
```bash
# Clone the repository (depth=1 fetches only the latest commit to save time)
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Configure the build directory as a dynamic library with OpenSSL acceleration
cmake -S . -B build -GNinja \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_USE_OPENSSL=ON

# Compile the library using all CPU cores
cmake --build build --parallel $(nproc)

# Install to standard path (/usr/local/lib and /usr/local/include)
sudo cmake --install build

# Refresh the system's dynamic linker cache
sudo ldconfig
```

---

### 2. Compiling `liboqs` on macOS

This applies to both **Apple Silicon (M1/M2/M3)** and **Intel** Macs.

1. Install **Homebrew** if you haven't already: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
2. Install build prerequisites:
   ```bash
   brew install cmake ninja openssl@3 git
   ```
3. Clone and build the library:
   ```bash
   git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
   cd liboqs

   # Explicitly link against Homebrew's OpenSSL headers and libraries
   OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)

   cmake -S . -B build -GNinja \
     -DBUILD_SHARED_LIBS=ON \
     -DOQS_BUILD_ONLY_LIB=ON \
     -DOQS_USE_OPENSSL=ON \
     -DOPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR

   cmake --build build --parallel $(sysctl -n hw.ncpu)
   sudo cmake --install build
   ```

---

### 3. Compiling `liboqs` on Windows

You have two primary compiler choices. MSVC is recommended for native deployments; MSYS2 is ideal if you prefer a Unix-like toolchain.

#### Option A: Native Visual Studio (MSVC) — Recommended
1. Install [Visual Studio (2019 or newer)](https://visualstudio.microsoft.com/) and check the workload **"Desktop development with C++"**. Ensure **CMake Tools for Windows** is included.
2. Open the **Developer PowerShell for VS** (search in the Start Menu) and run:
   ```powershell
   git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
   cd liboqs

   # Configure MSVC build (export all symbols is critical for Windows DLL generation)
   cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE

   # Build the release configuration
   cmake --build build --config Release --parallel $env:NUMBER_OF_PROCESSORS

   # Install the built DLL and headers (Run this terminal as Administrator)
   cmake --install build --config Release
   ```
   By default, this will install the library to `C:\Program Files (x86)\liboqs\bin\oqs.dll`.

#### Option B: MSYS2 / MinGW-w64
1. Download and install [MSYS2](https://www.msys2.org/).
2. Open the **MSYS2 MinGW64** shell and update packages:
   ```bash
   pacman -Syu
   pacman -S git mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja mingw-w64-x86_64-toolchain mingw-w64-x86_64-openssl
   ```
3. Build using Ninja:
   ```bash
   git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
   cd liboqs
   cmake -S . -B build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=ON
   cmake --build build
   # Install to MinGW usr path
   cmake --install build
   ```

---

### 4. Configuring the Dynamic Library Path

Once compiled, the underlying python binding (`liboqs-python`) needs to locate your shared library file (`.so`, `.dylib`, or `.dll`). If you get an `ImportError` or `Library not found`, configure the path variables:

*   **Linux:** Run `sudo ldconfig`. If installed in a non-standard path (e.g. `/opt/liboqs/lib`), prepend it:
    ```bash
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/liboqs/lib
    ```
*   **macOS:** Homebrew installs are typically registered automatically, but if needed, define the dynamic library path:
    ```bash
    export DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH:/usr/local/lib
    ```
*   **Windows:** Add the binary path containing your `oqs.dll` (e.g. `C:\Program Files (x86)\liboqs\bin`) to your Windows User or System Environment `PATH` variable.
*   **Universal Bypass (Environment Variable):** `liboqs-python` supports direct paths. You can point the loader directly to the compiled library file:
    ```bash
    export LIBOQS_INSTALL_PATH="/usr/local/lib/liboqs.so"           # Linux
    export LIBOQS_INSTALL_PATH="/usr/local/lib/liboqs.dylib"        # macOS
    set LIBOQS_INSTALL_PATH="C:\Program Files (x86)\liboqs\bin\oqs.dll" # Windows Command Prompt
    ```

---

### 5. Verifying the Setup

Verify that Python can import the library and resolve the NIST Post-Quantum algorithm targets:

```bash
python -c "import oqs; print('oqs version:', oqs.oqs_version()); kem = oqs.KeyEncapsulation('ML-KEM-768'); sig = oqs.Signature('ML-DSA-65'); print('liboqs and wrappers: OK')"
```

If it prints **`liboqs and wrappers: OK`**, you are ready to use UXSP!

---

## Installation

Install the Python package from PyPI. Choose the correct installation variant (core or extras) depending on your storage backend needs.

```bash
# 1. Base Installation — For single-process use (MemoryNonceStore / FileKeyStore)
pip install uxsp

# 2. Redis Integration — For distributed replay protection and rate limiting across clusters
pip install "uxsp[redis]"

# 3. Postgres Integration — For durable relational key storage and nonce audit logs
pip install "uxsp[postgres]"

# 4. Full Production Stack — Includes everything (Redis + Postgres)
pip install "uxsp[redis,postgres]"

# 5. Developer Tools — For running unit tests, coverage, type checkers, and linters
pip install "uxsp[dev]"
```

---

## Comprehensive API Guide & Code Examples

This section walks through the complete API from basic setups (key pairs and identities) to advanced enterprise configurations (tiered storage, WebSocket transports, and rate-limiting).

### Level 1: Identity & Key Management

An `Identity` encapsulates the complete private-public hybrid key pair (X25519, Ed25519, ML-KEM-768, and ML-DSA-65). A `PublicCard` represents the shareable, public half.

```python
from uxsp import Identity, PublicCard

# ─────────────────────────────────────────────────────────────────────────────
# 1. Creating Identities
# ─────────────────────────────────────────────────────────────────────────────
# Roles are free-form strings ("USER", "SERVER", "ADMIN", "GATEWAY", etc.)
# which are bound into all payload signatures to prevent role-spoofing.
alice = Identity.create(name="Alice", role="USER")
bob = Identity.create(name="API Gateway", role="SERVER")

print(f"Alice Entity ID : {alice.entity_id}")
print(f"Alice Display Name : {alice.name}")
print(f"Alice Role : {alice.role}")

# ─────────────────────────────────────────────────────────────────────────────
# 2. Key Export & Storage (Encrypted at rest via Argon2id)
# ─────────────────────────────────────────────────────────────────────────────
# Save private keys encrypted with AES-256-GCM. The key derivation uses Argon2id
# with robust memory constraints (64 MB, time cost=3, parallel lanes=4).
alice.save("alice.uxsp", password="correct-horse-battery-staple")

# Load the identity back
alice_loaded = Identity.load("alice.uxsp", password="correct-horse-battery-staple")

# ─────────────────────────────────────────────────────────────────────────────
# 3. Extracting and Sharing Public Cards
# ─────────────────────────────────────────────────────────────────────────────
# Public cards do NOT contain private keys and are safe to publish or transmit.
alice_card = alice.public_card()

# Export card to a portable JSON string
card_json = alice_card.to_json()

# Import card from a JSON string
received_card = PublicCard.from_json(card_json)
```

---

### Level 2: One-Shot Sealed Envelopes (Stateless Encrypted Messages)

Sealed envelopes (`Envelope`) allow sending secure, encrypted payloads in a single round-trip without establishing a stateful session. **A `ReplayGuard` is mandatory when opening envelopes to prevent replay attacks.**

```python
from uxsp import Identity, ReplayGuard, MemoryNonceStore, DuplicateNonceError, StaleEnvelopeError

# Setup peers
alice = Identity.create("Alice", "USER")
bob = Identity.create("Bob", "USER")
bob_card = bob.public_card()

# ─────────────────────────────────────────────────────────────────────────────
# Alice Seals a Message for Bob
# ─────────────────────────────────────────────────────────────────────────────
payload = b"Top secret operational data."
envelope = alice.seal_for(payload, bob_card)

# The envelope can be converted to/from JSON objects for REST API payloads
envelope_dict = envelope.to_dict()
print("Envelope Nonce:", envelope.envelope_nonce)
print("Timestamp :", envelope.timestamp)

# ─────────────────────────────────────────────────────────────────────────────
# Bob Opens the Envelope
# ─────────────────────────────────────────────────────────────────────────────
# Setup the ReplayGuard. We configure a validity window of 300 seconds (5 min)
# and a clock-skew allowance of 29 seconds.
store = MemoryNonceStore() # Note: Use Redis/Postgres in production!
guard = ReplayGuard(store=store, window_seconds=300, clock_skew=29)

try:
    # Bob decrypts the envelope, verifies both Alice's classical and post-quantum
    # signatures, and validates the nonce and timestamp.
    decrypted_payload = bob.open_from(envelope, alice.public_card(), replay_guard=guard)
    print("Decrypted message:", decrypted_payload.decode("utf-8"))
except StaleEnvelopeError:
    print("Security Alert: The envelope timestamp falls outside the 5-minute window.")
except DuplicateNonceError:
    print("Security Alert: Replay attack detected! This envelope nonce has already been used.")
```

---

### Level 3: Full-Duplex Authenticated Handshake & Sessions

For interactive sockets or microservices pipelines, use a 3-step stateful handshake to derive an ephemeral, forward-secret session key.

```python
from uxsp import Identity, Handshake, MemoryNonceStore, SessionConfig, SessionReorderError

# Configure session parameters
session_cfg = SessionConfig(
    max_lifetime_seconds=3600,   # Session expires after 1 hour
    max_messages=10_000,         # Session key rotates after 10k messages
    enforce_ordering=True        # Strict out-of-order rejection (sequence check)
)

alice = Identity.create("Alice", "USER")
bob = Identity.create("Bob", "SERVER")
bob_card = bob.public_card()

# Global nonce tracking store for handshake replay protection
ns = MemoryNonceStore()

# ─────────────────────────────────────────────────────────────────────────────
# 1. Step 1 (Alice Initiates Handshake)
# ─────────────────────────────────────────────────────────────────────────────
alice_hs = Handshake.initiate(alice, bob_card, config=session_cfg)
hello_payload = alice_hs.hello_message  # Send this to Bob

# ─────────────────────────────────────────────────────────────────────────────
# 2. Step 2 (Bob Responds to Handshake)
# ─────────────────────────────────────────────────────────────────────────────
# Bob verifies Alice's signature, checks for replays using the nonce store,
# runs his KEM decapsulation, and generates an ACK with an HMAC proof of shared secret.
bob_hs = Handshake.respond(bob, hello_payload, alice.public_card(), nonce_store=ns, config=session_cfg)
ack_payload = bob_hs.ack_message  # Send this back to Alice

# Bob's stateful session is immediately active
bob_session = bob_hs.session

# ─────────────────────────────────────────────────────────────────────────────
# 3. Step 3 (Alice Completes Handshake)
# ─────────────────────────────────────────────────────────────────────────────
# Alice verifies the ACK proof to confirm Bob has the matching shared secret,
# preventing man-in-the-middle (MITM) attacks.
alice_session = alice_hs.complete(ack_payload, bob.public_card(), nonce_store=ns)

# Both sessions are now fully established and secure!
assert alice_session.is_active and bob_session.is_active

# ─────────────────────────────────────────────────────────────────────────────
# 4. Message Encrypt / Decrypt with Sequence Protection
# ─────────────────────────────────────────────────────────────────────────────
# UXSP establishes INDEPENDENT channel keys for each direction (Alice->Bob, Bob->Alice).
enc_message = alice_session.encrypt(b"Hello Server")
plain_message = bob_session.decrypt(enc_message)
print("Bob received:", plain_message.decode())

# Strict sequence-ordered checks reject replayed or dropped messages
try:
    # Attempting to replay the exact same message bytes inside the session
    bob_session.decrypt(enc_message)
except SessionReorderError:
    print("Session replay blocked. Sequence number was duplicate or out-of-order.")
```

---

### Level 4: Advanced Payload Packing (Text, Files, & Large Chunking)

UXSP handles arbitrary binary payloads. Since standard envelopes are optimized for small control signals (default maximum limit of 64 KiB to prevent DoS), larger files are transferred using the **chunking engine**.

#### 1. Packaging Structured Payloads (Metadata Bundling)
```python
from uxsp import pack_text, unpack_text, pack_file, unpack_to_file

# Pack/Unpack text with character encoding metadata
packaged_text = pack_text("Sample string data", encoding="utf-8")
assert unpack_text(packaged_text) == "Sample string data"

# Pack a physical file with its filename and mime-type
packaged_file = pack_file("test_photo.jpg", content_type="image/jpeg")

# Encrypt, send, decrypt, and save back to disk securely:
# unpack_to_file extracts the original filename and writes it inside the target folder
saved_file_path = unpack_to_file(packaged_file, target_directory="./received_downloads")
```

#### 2. Segmenting Large Files (Chunked Transfers)
```python
from uxsp import create_chunked_transfer, reassemble_chunked_transfer

# Load a large file (e.g. a 5 MB PDF or video)
large_file_data = b"Imagine a very large binary stream exceeding 64 KiB..." * 2000

# Segment the stream into individually validated 32 KiB chunks.
# Each chunk is populated with:
# - unique transfer ID
# - chunk sequence index
# - SHA-256 hash of the specific chunk body
# - SHA-256 hash of the complete assembled file
packed_chunks = create_chunked_transfer(
    large_file_data,
    chunk_size=32 * 1024,
    kind="binary",
    filename="large_document.pdf",
    content_type="application/pdf"
)

# 1. Alice encrypts every chunk independently
encrypted_chunks = [alice_session.encrypt(chunk) for chunk in packed_chunks]

# 2. Bob decrypts every chunk independently
decrypted_chunks = [bob_session.decrypt(enc_chunk) for enc_chunk in encrypted_chunks]

# 3. Reassemble the stream. The engine validates every chunk hash, sorts the sequence
# to prevent drop/injection attacks, and cross-checks the total file SHA-256 hash.
metadata, original_data = reassemble_chunked_transfer(decrypted_chunks)

print("Reassembly successful!")
print(f"File Name: {metadata['filename']} | Hash: {metadata['file_hash_sha256']}")
assert original_data == large_file_data
```

---

### Level 5: Trust Anchors & Signed Cards (PKI & CA Chain)

To prevent spoofing or key-replacement attacks, deploy the UXSP Public Key Infrastructure. A `TrustAnchor` acts as an offline Certificate Authority (CA) that signs peer public keys (`SignedCard`), establishing validity limits.

```python
from uxsp import TrustAnchor, TrustStore, Identity, UntrustedCardError, ExpiredCardError

# ─────────────────────────────────────────────────────────────────────────────
# 1. Setup the Root Certificate Authority (Trust Anchor)
# ─────────────────────────────────────────────────────────────────────────────
anchor = TrustAnchor.create(name="Global Corporate CA")
# Protect root CA keys on disk
anchor.save("root_ca.uxsp", password="ultra-secure-ca-password")

# Export only the public anchor key to distribute to all clients
public_anchor = anchor.public_anchor()

# ─────────────────────────────────────────────────────────────────────────────
# 2. Issue a Signed Card for a Peer
# ─────────────────────────────────────────────────────────────────────────────
alice = Identity.create("Alice", "USER")

# CA issues a signed certificate valid for 365 days
signed_alice_card = anchor.issue(alice.public_card(), validity_days=365)
signed_card_json = signed_alice_card.to_json()

# ─────────────────────────────────────────────────────────────────────────────
# 3. Verify Cards at Runtime Using the Trust Store
# ─────────────────────────────────────────────────────────────────────────────
# Initialize a TrustStore seeded with our public anchor
store = TrustStore.from_anchors(public_anchor)

try:
    # Verifier parses and validates the signed card.
    # The engine verifies: issuer trust chain -> expiry dates -> dual signatures.
    verified_card = store.verify(signed_alice_card)
    print(f"Verified identity: {verified_card.name} | Role: {verified_card.role}")
    
    # Optional: Pin the card to ensure it matches the expected Entity ID
    store.verify(signed_alice_card, expected_entity_id=alice.entity_id)

except UntrustedCardError:
    print("Verification Failure: Card signature does not match any trusted root CA.")
except ExpiredCardError:
    print("Verification Failure: The peer card has expired or is not yet valid.")
```

---

### Level 6: Production Storage Backends (KeyStore & NonceStore)

For production workloads, avoid standard memory stores. If a process restarts, memory-based nonces are lost, creating a vulnerability window for replay attacks. UXSP provides full Redis and Postgres backends.

#### Plug-and-Play Key Storage
`KeyStore` manages peer `PublicCard`s or `SignedCard`s.

| Class | Type | Persistent? | Exclusive Locking? | Best For |
|---|---|---|---|---|
| `MemoryKeyStore` | Memory | ❌ No | Thread-safe in-process | Local development / unit tests |
| `FileKeyStore` | File | ✅ Yes | `fcntl` / `msvcrt` cross-process | Single-instance system daemons |
| `RedisKeyStore` | Redis | ✅ Yes | Optional TTL expiry | Fast distributed lookup cache |
| `PostgresKeyStore` | SQL | ✅ Yes | ACID Transactional | Central authority / source-of-truth |
| `CachingKeyStore` | Hybrid | ✅ Yes | Two-tier Cache | Production (Redis cache + Postgres DB) |

```python
# PostgreSQL key store setup
import psycopg2
from uxsp import PostgresKeyStore

conn = psycopg2.connect("host=db.internal dbname=uxsp user=postgres password=secret")
key_store = PostgresKeyStore(conn, table="corporate_keys")
key_store.create_table()  # Run once to initialize the JSONB schema

# Tiered caching (Redis cache + Postgres primary)
import redis
from uxsp import RedisKeyStore, CachingKeyStore

r_client = redis.Redis(host="cache.internal", port=6379)
redis_cache = RedisKeyStore(r_client, key_prefix="keys:cache:", ttl=3600)

production_keystore = CachingKeyStore(cache=redis_cache, backend=key_store)
```

#### Production Nonce Storage
`NonceStore` tracks used nonces. **All production stores utilize a fail-closed strategy**: if the store is saturated or disconnected, it rejects messages rather than risking a silent security fallback.

```python
import redis
import psycopg2
from uxsp import RedisNonceStore, SlidingWindowNonceStore, PostgresNonceStore, TieredNonceStore

# 1. Native Redis Nonce Store (Native String Key + TTL expiry)
r_client = redis.Redis(host="localhost", port=6379, db=0)
redis_ns = RedisNonceStore(r_client, key_prefix="uxsp:nonce:l1:")

# 2. Redis Sliding Window Nonce Store (Sorted set with per-nonce micro-time pruning)
sliding_ns = SlidingWindowNonceStore(r_client, window_seconds=300, key_prefix="uxsp:nonce:sw:")

# 3. PostgreSQL Nonce Store (Durable audit log table with auto indexing)
pg_conn = psycopg2.connect("dbname=security_db user=postgres")
postgres_ns = PostgresNonceStore(pg_conn, window_seconds=300, table="replay_audit_log")
postgres_ns.create_table()  # Creates table and indexes automatically

# 4. Tiered Nonce Store (Redis L1 Speed + Postgres L2 Durability)
# Recommended: Read/writes are handled at sub-millisecond speeds via Redis. If Redis
# goes offline, it automatically falls back to Postgres without throwing errors.
prod_nonce_store = TieredNonceStore(fast=redis_ns, durable=postgres_ns)
```

---

### Level 7: Rate Limiting & Guarded Endpoints

Prevent denial-of-service (DoS) and brute-force handshake floods using token bucket or sliding-window rate limiters.

```python
import redis
from uxsp import (
    RateLimiter, SlidingRateLimiter, RedisSlidingRateLimiter,
    GuardedHandshake, Identity, MemoryNonceStore, RateLimitExceededError
)

# ─────────────────────────────────────────────────────────────────────────────
# 1. Rate Limiter Backends
# ─────────────────────────────────────────────────────────────────────────────
# Memory Fixed-Window
limiter = RateLimiter(max_requests=10, window_seconds=60)

# Memory Sliding-Window (Prunes fractional millisecond timestamps to prevent bursts)
limiter = SlidingRateLimiter(max_requests=10, window_seconds=60)

# Production Distributed Sliding-Window (backed by Redis Sorted Sets)
r_client = redis.Redis()
redis_limiter = RedisSlidingRateLimiter(r_client, max_requests=100, window_seconds=60, key_prefix="ratelimit:")

# ─────────────────────────────────────────────────────────────────────────────
# 2. Protecting a Handshake Receiver via GuardedHandshake
# ─────────────────────────────────────────────────────────────────────────────
bob = Identity.create("Bob", "SERVER")
ns = MemoryNonceStore()

# Wrap Bob's identity inside a handshake guard
protected_endpoint = GuardedHandshake(
    limiter=redis_limiter,
    responder=bob,
    nonce_store=ns
)

try:
    # Replaces Bob's standard Handshake.respond() call.
    # The guard checks the client IP/identity, increments the rate limit, and blocks
    # before attempting expensive cryptographic calculations.
    bob_hs = protected_endpoint.respond(hello_payload, alice.public_card())
except RateLimitExceededError as e:
    print(f"Too many requests! Access blocked. Try again in {e.retry_after:.1f} seconds.")
```

---

### Level 8: HTTP & WebSocket Transport Layers

UXSP includes complete, production-ready wire frame formatters for standard request/response protocols.

#### 1. HTTP Transport Layer (`uxsp.transport.http`)
Binds envelopes to HTTP request payloads and registers key fields in custom headers so that API gateways, reverse proxies, and load balancers can log and route traffic without having to parse the JSON request body.

```python
import requests
from uxsp.transport.http import UXSPHTTPRequest, UXSPHTTPResponse, MissingUXSPHeaderError

# SENDER SIDE (Alice -> Bob)
# Alice seals her envelope, then passes it to the HTTP builder
envelope = alice.seal_for(b"Private HTTP request payload", bob.public_card())
http_req = UXSPHTTPRequest.build(envelope)

# Binds the payload to an HTTP client call:
# http_req['headers'] contains custom headers:
# - X-UXSP-Version (always '1')
# - X-UXSP-Sender (Alice's Entity ID)
# - X-UXSP-Recipient (Bob's Entity ID)
# - X-UXSP-Timestamp (Unix timestamp)
# - X-UXSP-Nonce (Unique envelope nonce)
response = requests.post(
    "https://api.bob.com/v1/secure-endpoint",
    data=http_req['body'],
    headers=http_req['headers']
)

# RECEIVER SIDE (Bob's Web Server Framework)
# Bob intercepts the headers and raw body:
try:
    # 1. Parse and cross-validate custom headers against JSON fields to prevent tampering.
    # 2. Enforce explicit size limits before processing.
    received_envelope = UXSPHTTPRequest.parse(
        headers=request.headers,
        body=request.get_data(),
        my_id=bob.entity_id,
        max_bytes=65536
    )
    
    # Decrypt and process
    guard = ReplayGuard(store=postgres_ns)
    plaintext = bob.open_from(received_envelope, alice.public_card(), replay_guard=guard)
    
except MissingUXSPHeaderError:
    print("Rejected. Missing custom UXSP routing headers.")
```

#### 2. WebSocket Transport Layer (`uxsp.transport.websocket`)
Wraps the stateful handshake and full-duplex active session into an atomic frame-based messaging system.

```python
from uxsp import UXSPWebSocket, UXSPFrame, FrameType, RateLimiter
from uxsp.core.nonce import MemoryNonceStore

alice = Identity.create("Alice", "USER")
bob = Identity.create("Bob", "SERVER")
ns = MemoryNonceStore()

# Initialize managers
ws_initiator = UXSPWebSocket.as_initiator(alice, bob.public_card(), nonce_store=ns)

# Responder MUST be assigned a rate limiter to prevent handshake CPU exhaustion attacks
limiter = RateLimiter(max_requests=20, window_seconds=60)
ws_responder = UXSPWebSocket.as_responder(bob, limiter=limiter, nonce_store=ns)

# ─────────────────────────────────────────────────────────────────────────────
# Handshake Phase (Frame exchange over socket)
# ─────────────────────────────────────────────────────────────────────────────
# 1. Initiator builds Hello Frame
hello_frame = ws_initiator.start_handshake()

# 2. Responder processes Hello Frame and returns ACK Frame
ack_frame = ws_responder.handle_hello(hello_frame, alice.public_card())

# 3. Initiator processes ACK Frame and completes local handshake
complete_frame = ws_initiator.complete_handshake(ack_frame)

# 4. Responder confirms completion
ws_responder.handle_complete(complete_frame)

assert ws_initiator.is_ready and ws_responder.is_ready

# ─────────────────────────────────────────────────────────────────────────────
# Data Exchange Phase
# ─────────────────────────────────────────────────────────────────────────────
# Encode messages to frame JSON to send over standard websocket text transport
encoded_frame = ws_initiator.encode(b"WebSocket payload message")
socket_payload = encoded_frame.to_json()

# Receive side decodes
received_frame = UXSPFrame.from_json(socket_payload)
plaintext = ws_responder.decode(received_frame)
print("Decrypted over WS:", plaintext.decode())

# ─────────────────────────────────────────────────────────────────────────────
# Keepalive (Ping / Pong)
# ─────────────────────────────────────────────────────────────────────────────
ping = ws_initiator.ping()
pong = ws_responder.pong(ping)

# ─────────────────────────────────────────────────────────────────────────────
# Graceful Authenticated Close
# ─────────────────────────────────────────────────────────────────────────────
# Builds an encrypted close payload and revokes session keys on the initiator
close_frame = ws_initiator.close(reason="Session finished")

# Receiver decrypts and verifies the close frame, then tears down the session
close_reason = ws_responder.handle_close(close_frame)
print("Session closed. Reason:", close_reason)
```

---

## Command-Line Interface (CLI) Guide

UXSP includes a complete Command-Line Interface (`uxsp`) which matches the Python API. This makes it easy to generate keys, export public cards, and manage trust authorities in bash scripts, CI/CD pipelines, or deployment setups.

```bash
# Display general help and subcommands
uxsp --help

# ─────────────────────────────────────────────────────────────────────────────
# 1. Key Generation (keygen)
# ─────────────────────────────────────────────────────────────────────────────
# Generates a new hybrid private keypair and prompts for a secure password.
# Private keys are encrypted on disk via Argon2id.
uxsp keygen \
  --name "Alice Smith" \
  --role "USER" \
  --out ./keys/alice.uxsp

# ─────────────────────────────────────────────────────────────────────────────
# 2. Exporting Public Cards (pubcard)
# ─────────────────────────────────────────────────────────────────────────────
# Extracts the non-sensitive public card required by other peers to contact you.
# Prompts for the identity password.
uxsp pubcard \
  --key ./keys/alice.uxsp \
  --out ./cards/alice_card.json

# ─────────────────────────────────────────────────────────────────────────────
# 3. Create a Root Trust Anchor (CA Authority)
# ─────────────────────────────────────────────────────────────────────────────
# Generates a Root Certificate Authority keypair.
# Outputs:
# - An encrypted private anchor file (root.uxsp)
# - A public anchor certificate (root.pub.json) to distribute to clients.
uxsp anchor create \
  --name "Internal Corporate CA" \
  --out ./keys/root.uxsp

# ─────────────────────────────────────────────────────────────────────────────
# 4. Issuing signed certificates (anchor issue)
# ─────────────────────────────────────────────────────────────────────────────
# Sign a user's PublicCard with the root CA key to create a SignedCard.
# Prompts for the Root Anchor password.
uxsp anchor issue \
  --anchor ./keys/root.uxsp \
  --card ./cards/alice_card.json \
  --days 365 \
  --out ./cards/alice_signed_card.json

# ─────────────────────────────────────────────────────────────────────────────
# 5. Inspect Identity File Metadata (info)
# ─────────────────────────────────────────────────────────────────────────────
# Decrypts the identity file header and prints metadata. No private keys are exposed.
uxsp info --key ./keys/alice.uxsp
```

---

## Cryptographic Specifications

UXSP implements a rigid hybrid cryptographic architecture designed in accordance with recommendations from national cybersecurity agencies (such as ANSSI and BSI) for early post-quantum transitions.

| Layer | Functional Component | Primary Cryptographic Primitives | Implemented Via |
|---|---|---|---|
| **Classical Asymmetric** | Key Exchange / Signature | **X25519** (ECDH) & **Ed25519** | `cryptography` (BoringSSL backend) |
| **Post-Quantum Asymmetric** | Key Exchange / Signature | **ML-KEM-768** & **ML-DSA-65** | `liboqs` (NIST FIPS 203 & FIPS 204) |
| **Symmetric Encryption** | Payload Cipher | **AES-256-GCM** (with authenticated tags) | `cryptography` (BoringSSL backend) |
| **Key Derivation Engine** | Key Mixing & domain separation | **HKDF-SHA256** | `cryptography` |
| **Password Derivation** | Rest-encryption KDF | **Argon2id** (Memory=64MB, Iterations=3, Parallelism=4) | `argon2-cffi` |
| **Integrity Hashing** | Checksum verification | **SHA-256** | Python Standard Library (`hashlib`) |

### Length-Prefixed Field Binding
To prevent **length-confusion attacks** (where concatenating variable-length fields like `A || B` could lead to identical signatures as `AB || ""`), UXSP processes all signable payloads through a deterministic field binding compiler (`bind_fields`). Every field is prefixed with its actual length in bytes before serialization, ensuring strict domain separation.

---

## Security Guarantees & Threat Model

UXSP is engineered to defend against specific adversary capabilities.

| Adversary Action / Threat | UXSP Countermeasure | Mitigation Level |
|---|---|---|
| **Eavesdropping on Network Traffic** | Payloads are encrypted with **AES-256-GCM** using unique, cryptographically random per-message nonces. | **Total Defense** |
| **Harvest Now, Decrypt Later (HNDL)** | Intercepted ciphertexts are protected by **ML-KEM-768**. The session key cannot be computed even if X25519 is broken in the future by a Shor's algorithm quantum attack. | **Total Defense** |
| **Stateless Message Replay** | **`ReplayGuard`** checks every envelope timestamp against a 5-minute rolling window and checks the nonce against a persistent database. | **Total Defense** (Requires Redis or Postgres) |
| **Handshake Message Replay** | Stateful `Handshake` tracks hello and ack transaction session UUIDs in a mandatory `NonceStore` prior to executing any CPU-heavy KEM math. | **Total Defense** |
| **Man-in-the-Middle (MITM)** | The responder includes an **HMAC-SHA256 proof** of the shared secret in the ACK. The session is never activated on the client unless the proof matches. | **Total Defense** |
| **Signature Forgery** | Payloads are protected by dual signatures (**Ed25519 + ML-DSA-65**). A forged signature requires compromising both math assumptions. | **Total Defense** |
| **Session Message Reordering** | Every session packet contains a strictly incremented sequence number. Out-of-order, dropped, or duplicated index sequences raise a hard error. | **Total Defense** |
| **DoS via Oversized Frames** | UXSP restricts stateless envelope frames to 64 KiB and WebSocket frames to 1 MiB. **The limits are evaluated and enforced before any decryption or signature validation is attempted.** | **Total Defense** |
| **Key-Replacement / Spoofing** | Use `TrustStore` to register corporate public anchors. Cards are verified against anchors before establishing contacts. | **Total Defense** |

### Out of Scope (What UXSP Does NOT Protect Against)
*   **Compromised Endpoints:** If an attacker has compromised the host process memory, filesystem, or operating system kernel of either Alice or Bob, they can read the decrypted secrets directly.
*   **Weak Passwords on Private Keys:** `Identity.save()` uses Argon2id, but a weak password makes the identity file vulnerable to brute-force decryption if stolen from disk.
*   **Physical side channels:** High-precision physical emissions (power fluctuations, electromagnetic signals) are not mitigated beyond standard compiler/hardware defenses inside libraries like OpenSSL or liboqs.

---

## Production Deployment Checklist

Before deploying UXSP in a production environment, complete the following audit checklist:

- [ ] **Configure a Persistent Nonce Store:** Replace `MemoryNonceStore` with a `RedisNonceStore`, `PostgresNonceStore`, or a `TieredNonceStore`. Standard memory stores are volatile and will allow replay attacks if the host application restarts.
- [ ] **Deploy Rate Limiters:** Ensure all `UXSPWebSocket` responder sockets and API handlers are wrapped in a `RateLimiter` or `RedisSlidingRateLimiter` to prevent CPU exhaustion from malicious handshake spam.
- [ ] **Enforce Strong Password Policies:** Ensure users encrypt their local `.uxsp` files with high-entropy passphrases.
- [ ] **Utilize the TrustStore Public Key Infrastructure:** Do not accept raw, unsigned `PublicCard` payloads in production. Require peers to register using a `SignedCard` issued by your private `TrustAnchor`.
- [ ] **Define Explicit Session Lifetimes:** Set appropriate limits on session durations and message counts in `SessionConfig` to force key rotation.
- [ ] **Handle Upstream Dependencies:** Keep `cryptography`, `argon2-cffi`, and `liboqs` updated to ensure security fixes are applied.

---

## Running the Test Suite

UXSP includes a comprehensive test suite covering cryptographic correctness, performance thresholds under high load, state synchronization, and transport integrity.

1. Ensure the developer dependencies are installed:
   ```bash
   pip install "uxsp[dev]"
   ```
2. Run the test runner:
   ```bash
   pytest tests/
   ```
3. Generate a detailed code coverage report:
   ```bash
   pytest tests/ --cov=uxsp --cov-report=term-missing
   ```

---

## Contributing & Security Policy

### Submitting Bug Reports
*   For standard bugs, crash traces, library compatibility issues, or documentation requests, please open a public GitHub issue.
*   Contributions are welcome! Please make sure to write unit tests for any new features or bug fixes.

### Security Vulnerabilities
If you discover a security vulnerability (such as a signature verification bypass, replay protection bypass, or cryptographic weakness), **do not open a public issue**. Report the vulnerability privately:

*   **Email:** [sivaraja5401@gmail.com](mailto:sivaraja5401@gmail.com)
*   **Subject Line:** `[UXSP SECURITY] <Brief summary of the issue>`

Please read the full threat disclosure timelines and severity standards in [SECURITY.md](SECURITY.md). We coordinate fixes and publish updates before making security details public.

---

## License

UXSP is open-source software licensed under the terms of the **MIT License**. For details, see [LICENSE](LICENSE).

---

*UXSP v0.1.2 · Python 3.11+ · Maintained by SIVA RAJA S*