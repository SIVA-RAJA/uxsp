# UXSP — Universal Exchange Security Protocol

[![Security: Hybrid PQC](https://img.shields.io/badge/Security-Hybrid%20PQC-blueviolet)](https://openquantumsafe.org/)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 1466 passed](https://img.shields.io/badge/Tests-1466%20passed-brightgreen)]()
[![Coverage: 100%](https://img.shields.io/badge/Coverage-100%25-brightgreen)]()
[![Version: 1.0.1](https://img.shields.io/badge/Version-1.0.1-orange)]()

**UXSP** is an enterprise-grade, **hybrid post-quantum secure messaging protocol** for Python. It is designed to protect data against both classical supercomputers and future quantum adversaries—specifically defeating the **"harvest now, decrypt later" (HNDL)** attack vector, where attackers capture encrypted traffic today to decrypt it once cryptographically relevant quantum computers (CRQCs) become viable.

Every UXSP communication is protected by **two independent cryptographic layers**:
1. **Classical Layer**: X25519 ECDH (Key Exchange) + Ed25519 (Digital Signatures).
2. **Post-Quantum Layer**: NIST FIPS 203 ML-KEM-768 (Key Encapsulation) + NIST FIPS 204 ML-DSA-65 (Digital Signatures).

Both layers must be broken simultaneously for an adversary to compromise the system. If either layer remains secure, your data remains impenetrable.

---

## Table of Contents

- [Quickstart: The Developer API (`uxsp.secure`)](#quickstart-the-developer-api-uxspsecure)
  - [1. Sender Side](#1-sender-side)
  - [2. Receiver Side](#2-receiver-side)
  - [3. Stateless Direct Object Passing (Web & Multi-Tenant Support)](#3-stateless-direct-object-passing-web--multi-tenant-support)
  - [4. In-Memory Identity Serialization & Password Helpers](#4-in-memory-identity-serialization--password-helpers)
  - [5. Supported 14 Data Types](#5-supported-14-data-types)
  - [6. Universal Polymorphic Dispatch (`Send` & `Receive`)](#6-universal-polymorphic-dispatch-send--receive)
  - [7. Exporting to Disk or Custom Transports (`SecurePackage`)](#7-exporting-to-disk-or-custom-transports-securepackage)
  - [8. Global Context Configuration](#8-global-context-configuration)
- [How it Works](#how-it-works)
- [Operating System Compatibility](#operating-system-compatibility)
- [Prerequisites: Building `liboqs` for All Platforms](#prerequisites-building-liboqs-for-all-platforms)
  - [1. Compiling `liboqs` on Linux](#1-compiling-liboqs-on-linux)
  - [2. Compiling `liboqs` on macOS](#2-compiling-liboqs-on-macos)
  - [3. Compiling `liboqs` on Windows](#3-compiling-liboqs-on-windows)
  - [4. Configuring Dynamic Library Paths](#4-configuring-dynamic-library-paths)
  - [5. Verifying the Setup](#5-verifying-the-setup)
- [Installation](#installation)
- [Comprehensive Low-Level API Guide](#comprehensive-low-level-api-guide)
  - [Level 1: Identity & Key Management](#level-1-identity--key-management)
  - [Level 2: One-Shot Sealed Envelopes](#level-2-one-shot-sealed-envelopes)
  - [Level 3: Full-Duplex Authenticated Handshake & Sessions](#level-3-full-duplex-authenticated-handshake--sessions)
  - [Level 4: Advanced Payload Packing & Chunking](#level-4-advanced-payload-packing--chunking)
  - [Level 5: Trust Anchors & PKI Verification](#level-5-trust-anchors--pki-verification)
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

## Quickstart: The Developer API (`uxsp.secure`)

UXSP v1.0.1 introduces a **stateless, developer-first workflow**. You do not need to configure handshakes, cryptographic sessions, or nonce databases manually for standard operations. **Everything can be sent and received in 1-2 lines of Python.**

### 1. Sender Side
To send an encrypted and quantum-signed asset to a receiver, provide the receiver's Unique ID (`entity_id` / UID) and the asset to send:

```python
import uxsp
from uxsp.secure import SendVideo, SendPhoto, SendText, SendFile, SendLocation

# Send a video file
package = SendVideo("receiver_uid_123", "/path/to/video.mp4")

# Send a photo / image
package = SendPhoto("receiver_uid_123", "/path/to/avatar.png")

# Send a text message
package = SendText("receiver_uid_123", "Hello, quantum world!")

# Send any arbitrary file
package = SendFile("receiver_uid_123", "/path/to/spreadsheet.xlsx")

# Send GPS coordinates
package = SendLocation("receiver_uid_123", latitude=37.7749, longitude=-122.4194)
```

### 2. Receiver Side
To receive and decrypt data, provide the sender's Unique ID and an optional download path:

```python
import uxsp
from uxsp.secure import ReceiveVideo, ReceivePhoto, ReceiveText, ReceiveFile, ReceiveLocation

# Receive and save video to a specific path (returns a Path object)
video_path = ReceiveVideo("sender_uid_123", download_path="/path/to/saved_video.mp4")
print(f"Video downloaded to: {video_path}")

# Receive and save a photo
photo_path = ReceivePhoto("sender_uid_123", download_path="/path/to/saved_photo.png")

# Receive text message (returns a string)
message = ReceiveText("sender_uid_123")
print(f"Decrypted text: {message}")

# Receive GPS coordinates (returns a dictionary)
location = ReceiveLocation("sender_uid_123")
print(f"Received coordinates: {location['latitude']}, {location['longitude']}")
```

---

### 3. Stateless Direct Object Passing (Web & Multi-Tenant Support)

In web frameworks (FastAPI, Flask, Django) or multi-tenant microservices, you may want to pass `Identity` and `PublicCard` instances directly without relying on global context state:

```python
import uxsp
from uxsp.secure import SendText, ReceiveText

# 1. Create or load identities directly in memory
alice = uxsp.create_identity("Alice", role="CLIENT")
bob = uxsp.create_identity("Bob", role="SERVER")

# 2. Alice sends to Bob passing Bob's PublicCard and Alice's Identity directly
package = SendText(
    text="Hello directly from Alice!",
    receiver=bob.public_card(),
    sender=alice
)

# 3. Bob receives passing Alice's PublicCard and Bob's Identity directly
message = ReceiveText(
    package=package,
    sender=alice.public_card(),
    receiver=bob
)
print("Decrypted stateless message:", message)
```

---

### 4. In-Memory Identity Serialization & Password Helpers

UXSP provides zero-disk-I/O encrypted serialization for storing user identities in web databases (PostgreSQL, MongoDB, Redis, session cookies):

```python
import uxsp

# 1. Create a user identity
alice = uxsp.create_identity("Alice", role="CLIENT")
user_password = "UserMasterPassword123!"

# 2. Export identity to an encrypted JSON string (Argon2id + AES-256-GCM)
encrypted_str = uxsp.export_identity_encrypted(alice, user_password)

# 3. Save `encrypted_str` in database column (e.g. TEXT / JSON)
# ...

# 4. Restore identity in memory from encrypted JSON string
restored_alice = uxsp.import_identity_encrypted(encrypted_str, user_password)
assert restored_alice.entity_id == alice.entity_id

# 5. Password Hashing & Verification helpers (Argon2id)
hashed_password = uxsp.hash_password(user_password)
is_valid = uxsp.verify_password(hashed_password, user_password) # True
```

---

### 5. Supported 14 Data Types

UXSP supports 14 dedicated data types with typed helpers and automatic MIME detection:

| Data Type | Sender Helper | Receiver Helper | Accepted Input | Decrypted Return Value |
|---|---|---|---|---|
| **Video** | `SendVideo(uid, data)` | `ReceiveVideo(uid, download_path=None)` | File path (`str`/`Path`) or `bytes` | `pathlib.Path` (saved file) |
| **Audio** | `SendAudio(uid, data)` | `ReceiveAudio(uid, download_path=None)` | File path (`str`/`Path`) or `bytes` | `pathlib.Path` (saved file) |
| **Photo / Image** | `SendPhoto(uid, data)` / `SendImage(...)` | `ReceivePhoto(uid, ...)` / `ReceiveImage(...)` | File path (`str`/`Path`) or `bytes` | `pathlib.Path` (saved file) |
| **Text** | `SendText(uid, text)` | `ReceiveText(uid)` | `str` | `str` (UTF-8) |
| **Document** | `SendDocument(uid, data)` / `SendDoc(...)` | `ReceiveDocument(uid, ...)` / `ReceiveDoc(...)` | File path (`str`/`Path`) or `bytes` | `pathlib.Path` (saved file) |
| **PDF** | `SendPDF(uid, data)` | `ReceivePDF(uid, download_path=None)` | File path (`str`/`Path`) or `bytes` | `pathlib.Path` (saved file) |
| **File** | `SendFile(uid, data)` | `ReceiveFile(uid, download_path=None)` | File path (`str`/`Path`) or `bytes` | `pathlib.Path` (saved file) |
| **Binary** | `SendBinary(uid, data)` | `ReceiveBinary(uid, download_path=None)` | `bytes` | `bytes` (raw body) |
| **JSON** | `SendJSON(uid, data)` | `ReceiveJSON(uid, download_path=None)` | `dict` or `list` | `dict` or `list` |
| **HTML** | `SendHTML(uid, html)` | `ReceiveHTML(uid, download_path=None)` | `str` (HTML markup) | `str` |
| **Archive** | `SendArchive(uid, data)` / `SendZip(...)` | `ReceiveArchive(uid, ...)` / `ReceiveZip(...)` | File path (`str`/`Path`) or `bytes` | `pathlib.Path` (saved file) |
| **Voice** | `SendVoice(uid, data)` | `ReceiveVoice(uid, download_path=None)` | File path (`str`/`Path`) or `bytes` | `pathlib.Path` (saved file) |
| **Location** | `SendLocation(uid, lat, lon)` | `ReceiveLocation(uid)` | `float`, `float` | `dict` with `latitude`, `longitude` |
| **Contact** | `SendContact(uid, contact)` | `ReceiveContact(uid)` | `dict` or `str` (vCard / JSON) | `dict` or `str` |

---

### 6. Universal Polymorphic Dispatch (`Send` & `Receive`)

If you prefer a single function for all data types, use the universal `Send` and `Receive` dispatchers. They automatically detect the payload type from file extensions or data structures:

```python
from uxsp.secure import Send, Receive

# 1. Send automatically detects video from .mp4
pkg1 = Send("bob_uid", "my_clip.mp4")

# 2. Send automatically detects text from str
pkg2 = Send("bob_uid", "Hello Alice!")

# 3. Send automatically detects JSON from dict
pkg3 = Send("bob_uid", {"order_id": 9841, "status": "approved"})

# 4. Receive automatically unpacks according to the embedded type
content = Receive("alice_uid", package=pkg3)
# content is automatically returned as a dict: {'order_id': 9841, 'status': 'approved'}
```

---

### 7. Exporting to Disk or Custom Transports (`SecurePackage`)

Every `Send*` method returns a `SecurePackage` object containing the encrypted hybrid envelope, metadata, and data type. You can save packages directly to files, transmit them over REST APIs, or pass them via message queues (RabbitMQ, Kafka, SQS):

```python
from uxsp.secure import SendText, ReceiveText, SecurePackage

# 1. Save package directly to a JSON file on disk
SendText("bob_uid", "Highly classified memo", output_file="memo.pkg.json")

# 2. Bob reads from the file on disk
memo = ReceiveText("alice_uid", package="memo.pkg.json")
print("Decrypted from disk:", memo)

# 3. Serialize to JSON string for REST APIs
package = SendText("bob_uid", "Secret payload")
json_str = package.to_json()

# 4. Deserialize on recipient server
loaded_package = SecurePackage.from_json(json_str)
result = ReceiveText("alice_uid", package=loaded_package)
```

---

### 8. Global Context Configuration

By default, `uxsp.secure` automatically creates a default ephemeral identity and in-memory stores for zero-setup convenience. In production, configure persistent storage, custom identities, and default download directories:

```python
from uxsp.secure import configure, set_identity, register_peer
from uxsp import Identity, FileKeyStore, RedisNonceStore, ReplayGuard

# Load your production identity
my_identity = Identity.load("/secure/keys/server.uxsp", password="my-master-password")

# Configure custom components
configure(
    identity=my_identity,
    default_output_dir="/var/data/downloads",
    noncestore=RedisNonceStore.from_url("redis://localhost:6379/0"),
    replay_guard=ReplayGuard(window_seconds=300)
)

# Register trusted peers
peer_card = Identity.load("/keys/client.uxsp", "password").public_card()
register_peer(peer_card)
```

---

## How it Works

Underneath the API, UXSP operates on a dual-layer cryptographic architecture supporting both stateless one-shot messages and stateful full-duplex sessions:

```
 Alice (Initiator)                                            Bob (Responder)
       │                                                             │
       │─────── Handshake.initiate() ───────────────────────────────▶│
       │        HELLO Message (signed, ML-KEM-768 encapsulation)     │
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

UXSP is pure Python with C-level acceleration provided by **`liboqs`** (Open Quantum Safe).

| Operating System | Support Level | Compilation Toolchain | Linking Strategy |
|---|---|---|---|
| **Linux** (Debian/Ubuntu, CentOS/Fedora, Alpine) | **Production-grade (Primary)** | `gcc` / `clang`, CMake, Ninja | `ldconfig` & `/usr/local/lib/liboqs.so` |
| **macOS** (Apple Silicon M1/M2/M3 & Intel) | **Production-grade (Primary)** | Xcode Command Line Tools, Homebrew, CMake, Ninja | `DYLD_LIBRARY_PATH` & `liboqs.dylib` |
| **Windows** (10, 11, Server) | **Supported (Stable)** | MSVC (Visual Studio) or MinGW-w64 (MSYS2), CMake | `%PATH%` DLL path or `LIBOQS_INSTALL_PATH` |

---

## Prerequisites: Building `liboqs` for All Platforms

Building `liboqs` from source ensures that you have the latest NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) implementations.

### 1. Compiling `liboqs` on Linux

#### Ubuntu / Debian / Mint
```bash
sudo apt update
sudo apt install -y build-essential cmake ninja-build libssl-dev git
```

#### Fedora / RHEL / CentOS
```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y cmake ninja-build openssl-devel git
```

#### Build and Install
```bash
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

cmake -S . -B build -GNinja \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_USE_OPENSSL=ON

cmake --build build --parallel $(nproc)
sudo cmake --install build
sudo ldconfig
```

---

### 2. Compiling `liboqs` on macOS (Apple Silicon & Intel)

```bash
# 1. Install prerequisites via Homebrew
brew install cmake ninja openssl@3 git

# 2. Clone and build
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

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

#### Option A: Native Visual Studio (MSVC) — Recommended
1. Open **Developer PowerShell for VS**.
2. Run:
```powershell
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE
cmake --build build --config Release --parallel $env:NUMBER_OF_PROCESSORS
cmake --install build --config Release
```

#### Option B: MSYS2 / MinGW-w64
```bash
pacman -S git mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja mingw-w64-x86_64-toolchain mingw-w64-x86_64-openssl
git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
cmake -S . -B build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=ON
cmake --build build
cmake --install build
```

---

### 4. Configuring Dynamic Library Paths

If Python cannot find `liboqs`:
* **Linux:** `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib`
* **macOS:** `export DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH:/usr/local/lib`
* **Windows:** Add `C:\Program Files (x86)\liboqs\bin` to your `PATH`.
* **Universal Override:**
  ```bash
  export LIBOQS_INSTALL_PATH="/usr/local/lib/liboqs.so"  # or .dylib / .dll
  ```

---

### 5. Verifying the Setup

```bash
python -c "import oqs; print('oqs version:', oqs.oqs_version()); kem = oqs.KeyEncapsulation('ML-KEM-768'); sig = oqs.Signature('ML-DSA-65'); print('liboqs and wrappers: OK')"
```

---

## Installation

```bash
# 1. Base Installation (Memory & File stores)
pip install uxsp

# 2. Redis Integration (Distributed replay guards & rate limiting)
pip install "uxsp[redis]"

# 3. PostgreSQL Integration (Durable relational key storage & audit logging)
pip install "uxsp[postgres]"

# 4. Full Production Stack (Redis + PostgreSQL)
pip install "uxsp[redis,postgres]"

# 5. Developer & Testing Suite
pip install "uxsp[dev]"
```

---

## Comprehensive Low-Level API Guide

For advanced custom protocols, microservices, and high-performance servers, UXSP provides granular low-level APIs.

### Level 1: Identity & Key Management
```python
from uxsp import Identity, PublicCard

# 1. Generate new identity keypair
alice = Identity.create(name="Alice", role="USER")

# 2. Save encrypted identity (Argon2id + AES-256-GCM)
alice.save("alice.uxsp", password="strong-master-password")

# 3. Export public card (shareable, non-sensitive)
alice_card = alice.public_card()
card_json = alice_card.to_json()
```

---

### Level 2: One-Shot Sealed Envelopes
```python
from uxsp import Identity, ReplayGuard, MemoryNonceStore, StaleEnvelopeError, DuplicateNonceError

alice = Identity.create("Alice", "USER")
bob = Identity.create("Bob", "SERVER")

# Alice seals a payload for Bob
envelope = alice.seal_for(b"Confidential payload", bob.public_card())

# Bob opens the envelope with mandatory ReplayGuard
guard = ReplayGuard(store=MemoryNonceStore(), window_seconds=300)
try:
    plaintext = bob.open_from(envelope, alice.public_card(), replay_guard=guard)
    print("Decrypted:", plaintext.decode())
except (StaleEnvelopeError, DuplicateNonceError) as e:
    print(f"Envelope validation error: {e}")
```

---

### Level 3: Full-Duplex Authenticated Handshake & Sessions
```python
from uxsp import Identity, Handshake, MemoryNonceStore, SessionConfig

session_cfg = SessionConfig(max_lifetime_seconds=3600, enforce_ordering=True)
ns = MemoryNonceStore()

alice = Identity.create("Alice", "USER")
bob = Identity.create("Bob", "SERVER")

# Step 1: Alice initiates
alice_hs = Handshake.initiate(alice, bob.public_card(), config=session_cfg)

# Step 2: Bob responds
bob_hs = Handshake.respond(bob, alice_hs.hello_message, alice.public_card(), nonce_store=ns, config=session_cfg)

# Step 3: Alice completes
alice_session = alice_hs.complete(bob_hs.ack_message, bob.public_card(), nonce_store=ns)
bob_session = bob_hs.session

# Encrypt and Decrypt over active session
enc = alice_session.encrypt(b"Channel message")
dec = bob_session.decrypt(enc)
assert dec == b"Channel message"
```

---

### Level 4: Advanced Payload Packing & Chunking
```python
from uxsp import pack_file, unpack_to_file, create_chunked_transfer, reassemble_chunked_transfer

# 1. Pack file with MIME metadata
pkg = pack_file("report.pdf", content_type="application/pdf")
unpack_to_file(pkg, target_directory="./downloads")

# 2. Large Chunked Transfer (>64 KB)
chunks = create_chunked_transfer(b"Large binary payload" * 5000, chunk_size=32768)
# Chunks can be sent individually over envelopes or sessions
metadata, reconstructed = reassemble_chunked_transfer(chunks)
```

---

### Level 5: Trust Anchors & PKI Verification
```python
from uxsp import TrustAnchor, TrustStore, Identity

# 1. Create Root Certificate Authority
ca = TrustAnchor.create(name="Corporate Root CA")
ca.save("root_ca.uxsp", password="ca-password")

# 2. Issue Signed Card for peer
alice = Identity.create("Alice", "USER")
signed_card = ca.issue(alice.public_card(), validity_days=365)

# 3. Verify Card in Trust Store
store = TrustStore.from_anchors(ca.public_anchor())
verified_card = store.verify(signed_card)
```

---

### Level 6: Production Storage Backends (KeyStore & NonceStore)
```python
import redis
import psycopg2
from uxsp import RedisNonceStore, PostgresKeyStore, TieredNonceStore

# Redis Nonce Store for distributed replay protection
r = redis.Redis(host="localhost", port=6379)
redis_ns = RedisNonceStore(r, key_prefix="uxsp:nonce:")

# Postgres Key Store
pg_conn = psycopg2.connect("dbname=uxsp_keys user=postgres")
pg_ks = PostgresKeyStore(pg_conn, table="public_cards")
pg_ks.create_table()
```

---

### Level 7: Rate Limiting & Guarded Endpoints
```python
from uxsp import SlidingRateLimiter, GuardedHandshake, Identity, MemoryNonceStore

limiter = SlidingRateLimiter(max_requests=50, window_seconds=60)
server_id = Identity.create("Server", "GATEWAY")

guarded = GuardedHandshake(limiter=limiter, responder=server_id, nonce_store=MemoryNonceStore())
```

---

### Level 8: HTTP & WebSocket Transport Layers
```python
from uxsp.transport.http import UXSPHTTPRequest
from uxsp.transport.websocket import UXSPWebSocket

# HTTP Transport Builder
req_payload = UXSPHTTPRequest.build(envelope)
# Contains headers: X-UXSP-Version, X-UXSP-Sender, X-UXSP-Recipient, X-UXSP-Nonce, X-UXSP-Timestamp

# WebSocket Manager
ws = UXSPWebSocket.as_initiator(alice, bob.public_card())
frame = ws.start_handshake()
```

---

## Command-Line Interface (CLI) Guide

UXSP includes a complete CLI for key management and PKI operations:

```bash
# 1. Generate identity
uxsp keygen --name "Alice" --role "USER" --out ./alice.uxsp

# 2. Export public card
uxsp pubcard --key ./alice.uxsp --out ./alice.card.json

# 3. Create Root Trust Anchor
uxsp anchor create --name "Global CA" --out ./root_ca.uxsp

# 4. Issue a signed certificate
uxsp anchor issue --anchor ./root_ca.uxsp --card ./alice.card.json --days 365 --out ./alice.signed.json

# 5. Inspect key metadata
uxsp info --key ./alice.uxsp

# 6. Check version
uxsp version
```

---

## Cryptographic Specifications

| Component | Classical Primitive | Post-Quantum Primitive | Hybrid Mixing / Symmetric |
|---|---|---|---|
| **Key Exchange** | X25519 (ECDH) | ML-KEM-768 (CRYSTALS-Kyber) | HKDF-SHA256 |
| **Digital Signatures** | Ed25519 | ML-DSA-65 (CRYSTALS-Dilithium) | Length-prefixed field binding |
| **Symmetric Cipher** | — | — | AES-256-GCM (Authenticated) |
| **Key Derivation** | — | — | HKDF-SHA256 |
| **Password Storage** | — | — | Argon2id (64 MB, t=3, p=4) |

---

## Security Guarantees & Threat Model

| Threat | UXSP Defense | Guarantee |
|---|---|---|
| **Network Eavesdropping** | AES-256-GCM with per-message nonces | Complete Confidentiality |
| **Quantum Decryption (HNDL)** | ML-KEM-768 key encapsulation | Quantum-Proof Security |
| **Stateless Replay Attacks** | `ReplayGuard` with timestamp window + nonce store | Replays Blocked |
| **Man-in-the-Middle (MITM)** | HMAC-SHA256 proof of shared secret in handshake | MITM Defeated |
| **Signature Forgery** | Dual signature (Ed25519 + ML-DSA-65) | Forgery Impossible |
| **Out-of-Order Injection** | Strictly monotonically increasing sequence IDs | Desynchronization Blocked |
| **DoS via Memory Bomb** | Pre-crypto byte limit checks (64 KB / 1 MB) | Resource Exhaustion Mitigated |

---

## Production Deployment Checklist

- [ ] Use `RedisNonceStore`, `PostgresNonceStore`, or `TieredNonceStore` (never use `MemoryNonceStore` across process restarts).
- [ ] Wrap all public endpoints in `RateLimiter` or `RedisSlidingRateLimiter`.
- [ ] Enforce strong passwords on saved `.uxsp` files (Argon2id).
- [ ] Sign peer cards with a private `TrustAnchor` and verify them via `TrustStore`.
- [ ] Ensure `liboqs` is linked properly and passes verification on the host OS.

---

## Running the Test Suite

UXSP maintains **100% test coverage** across all 3,663 executable statements.

```bash
# 1. Install dev dependencies
pip install "uxsp[dev]"

# 2. Run all tests
pytest tests/

# 3. Generate detailed coverage report
pytest tests/ --cov=uxsp --cov-report=term-missing
```

---

## Contributing & Security Policy

- **Bug Reports**: Open a public GitHub issue.
- **Security Disclosures**: Report privately via email to [sivaraja5401@gmail.com](mailto:sivaraja5401@gmail.com) with subject `[UXSP SECURITY] <summary>`. See [SECURITY.md](SECURITY.md) for disclosure policies.

---

## License

UXSP is released under the **MIT License**. See [LICENSE](LICENSE) for details.

---

*UXSP v1.0.1 · Python 3.11+*

*Maintained by SIVA RAJA S*