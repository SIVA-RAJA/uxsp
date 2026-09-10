# UXSP Exact Wire Format & Byte-Level Encoding Specification

**Status**: Standard  
**Version**: 1.2.0  
**Date**: September 2026  
**Document Identifier**: UXSP-WIRE-1.2  
**Author**: Siva Raja S (<sivaraja5401@gmail.com>)

---

## 1. Overview & Framing Architecture

This specification defines the exact, bit-level and byte-level wire formats for the **Universal Exchange Security Protocol (UXSP)**. It is written to serve as the definitive implementation guide for building cross-platform UXSP parsers, serializers, and protocol drivers in any programming language (**Rust, Go, C, C++, Zig, Swift, Java, C#, Python, TypeScript**).

### 1.1 Dual-Representation Architecture
UXSP supports two interchangeable wire representations depending on the transport layer:
1. **Binary Wire Framing (`application/x-uxsp-binary`)**: A compact, zero-overhead, strictly aligned binary format optimized for WebSockets, TCP/UDP sockets, WebRTC DataChannels, and low-latency network pipelines.
2. **JSON Wire Envelope (`application/uxsp+json`)**: A human-readable, schema-validated JSON format utilizing lowercase hexadecimal strings for binary fields, optimized for HTTP/REST APIs, web middlewares (FastAPI, Django, Flask), and browser environments.

Both wire representations encapsulate the exact same cryptographic fields and can be converted losslessly between one another.

---

## 2. Structural Envelope Hierarchy

The visual hierarchy of a canonical UXSP binary envelope frame (`UXSP/1`) is structured as follows:

```
UXSP Envelope Wire Frame (UXSP/1)
|
+--- 0x0000: Magic Identifier ("UXSP") [4 Bytes: 0x55 0x58 0x53 0x50]
+--- 0x0004: Protocol Version [2 Bytes: Major 0x01, Minor 0x00]
+--- 0x0006: Message Type [1 Byte Enum: 0x01 = SEALED_ENVELOPE, 0x02 = HELLO, ...]
+--- 0x0007: Flags Bitmask [2 Bytes uint16: PQC Active, Chunked, AD Present, ...]
+--- 0x0009: Algorithm Suite Identifier [2 Bytes uint16: 0x0001 = Default Hybrid]
+--- 0x000B: Key ID / Epoch [4 Bytes uint32 Big-Endian]
+--- 0x000F: Timestamp [8 Bytes uint64 Big-Endian Unix Epoch Seconds]
+--- 0x0017: Sequence Number [8 Bytes uint64 Big-Endian Monotonic Counter]
+--- 0x001F: Envelope Nonce [16 Bytes Raw Cryptographic Entropy]
+--- 0x002F: AEAD Initialization Vector (IV) [12 Bytes AES-GCM IV Nonce]
+--- 0x003B: Sender ID Length [2 Bytes uint16 Big-Endian, L_sender]
+--- 0x003D: Sender ID Bytes [L_sender Bytes UTF-8 String]
+--- Offset: Recipient ID Length [2 Bytes uint16 Big-Endian, L_recipient]
+--- Offset: Recipient ID Bytes [L_recipient Bytes UTF-8 String]
+--- Offset: Ephemeral Public Key Length [2 Bytes uint16 Big-Endian, L_eph]
+--- Offset: Ephemeral Public Key [L_eph Bytes: 32 Bytes X25519]
+--- Offset: KEM Ciphertext Length [2 Bytes uint16 Big-Endian, L_kem]
+--- Offset: KEM Ciphertext [L_kem Bytes: 1088 Bytes ML-KEM-768, 0 if classical]
+--- Offset: Encrypted Payload Length [4 Bytes uint32 Big-Endian, L_payload]
+--- Offset: Encrypted Payload [L_payload Bytes: AES-256-GCM Ciphertext]
+--- Offset: AEAD Authentication Tag [16 Bytes: AES-256-GCM Tag]
+--- Offset: Classical Signature Length [2 Bytes uint16 Big-Endian, L_csig]
+--- Offset: Classical Signature [L_csig Bytes: 64 Bytes Ed25519]
+--- Offset: Post-Quantum Signature Length [2 Bytes uint16 Big-Endian, L_pqsig]
\--- Offset: Post-Quantum Signature [L_pqsig Bytes: 3309 Bytes ML-DSA-65]
```

---

## 3. Exact Byte-Level Encoding Specification

All multibyte integers on the wire MUST be encoded in **Network Byte Order (Big-Endian)**.

### 3.1 Fixed Header Table (Bytes `0x00` through `0x3A`)

| Byte Offset | Field Name | Data Type | Endianness | Typical / Valid Values | Description |
| :---: | :--- | :---: | :---: | :--- | :--- |
| `0x00 - 0x03` | `magic` | `uint8[4]` | Big | `0x55 0x58 0x53 0x50` | ASCII string `"UXSP"`. MUST be verified first. |
| `0x04` | `version_major` | `uint8` | Big | `0x01` | Protocol Major Version (`1`). |
| `0x05` | `version_minor` | `uint8` | Big | `0x00` | Protocol Minor Version (`0`). |
| `0x06` | `message_type` | `uint8` | Big | `0x01 - 0x07` | Envelope Message Type (see §4). |
| `0x07 - 0x08` | `flags` | `uint16` | Big | Bitmask (e.g. `0x0001`) | Operational flags (PQC, chunking, etc. see §5). |
| `0x09 - 0x0A` | `algorithm_suite` | `uint16` | Big | `0x0001` or `0x0002` | Cryptographic suite identifier (see §6). |
| `0x0B - 0x0E` | `key_id` | `uint32` | Big | `0x00000001` | Active key rotation index or epoch counter. |
| `0x0F - 0x16` | `timestamp` | `uint64` | Big | Unix seconds (64-bit) | Epoch timestamp when sealed (e.g. `1757472000`). |
| `0x17 - 0x1E` | `sequence_number`| `uint64` | Big | Monotonic counter | Message sequence counter ($0$ for standalone envelopes). |
| `0x1F - 0x2E` | `envelope_nonce` | `uint8[16]`| N/A | 16 random bytes | Replay guard identifier for NonceStores. |
| `0x2F - 0x3A` | `aead_nonce` | `uint8[12]`| N/A | 12 random bytes | AES-256-GCM Initialization Vector (IV). |

### 3.2 Variable-Length Records Table (Bytes `0x3B` onwards)

Following byte `0x3A`, variable-length fields are encoded in strict sequential order. Each variable field (except the AEAD tag) is prefixed by a Big-Endian length indicator:

| Relative Order | Field Name | Length Prefix Type | Length in Bytes | Description |
| :---: | :--- | :---: | :--- | :--- |
| **1** | `sender_id_len` | `uint16` | 2 bytes | Byte length of `sender_id` ($L_{\text{sender}}$). |
| **2** | `sender_id` | N/A | $L_{\text{sender}}$ bytes | UTF-8 encoded entity ID (e.g., UUID or URI). |
| **3** | `recipient_id_len` | `uint16` | 2 bytes | Byte length of `recipient_id` ($L_{\text{recipient}}$). |
| **4** | `recipient_id` | N/A | $L_{\text{recipient}}$ bytes | UTF-8 encoded entity ID of recipient. |
| **5** | `ephemeral_pub_len`| `uint16` | 2 bytes | Length of ephemeral exchange key ($L_{\text{eph}}$). For X25519, MUST be `32` (`0x0020`). |
| **6** | `ephemeral_pub` | N/A | $L_{\text{eph}}$ bytes | Ephemeral public key bytes. |
| **7** | `kem_ciphertext_len`| `uint16` | 2 bytes | Length of KEM ciphertext ($L_{\text{kem}}$). For ML-KEM-768, MUST be `1088` (`0x0440`). MUST be `0` if classical-only. |
| **8** | `kem_ciphertext` | N/A | $L_{\text{kem}}$ bytes | ML-KEM-768 encapsulated shared secret ciphertext. |
| **9** | `payload_len` | `uint32` | 4 bytes | Byte length of encrypted ciphertext ($L_{\text{payload}}$). |
| **10** | `ciphertext` | N/A | $L_{\text{payload}}$ bytes | AES-256-GCM encrypted payload bytes. |
| **11** | `aead_tag` | N/A | **Exactly 16 bytes** | AES-256-GCM 128-bit authentication tag. |
| **12** | `classical_sig_len`| `uint16` | 2 bytes | Length of classical signature ($L_{\text{csig}}$). For Ed25519, MUST be `64` (`0x0040`). |
| **13** | `classical_sig` | N/A | $L_{\text{csig}}$ bytes | Ed25519 raw signature bytes. |
| **14** | `pqc_sig_len` | `uint16` | 2 bytes | Length of PQC signature ($L_{\text{pqsig}}$). For ML-DSA-65, MUST be `3309` (`0x0CED`). MUST be `0` if classical-only. |
| **15** | `pqc_sig` | N/A | $L_{\text{pqsig}}$ bytes | ML-DSA-65 raw signature bytes. |

---

## 4. Message Types Registry

The `message_type` byte at offset `0x06` defines the envelope semantics:

```
+-------+-------------------------+-------------------------------------------------------------+
| Value | Identifier              | Description                                                 |
+-------+-------------------------+-------------------------------------------------------------+
| 0x01  | MSG_SEALED_ENVELOPE     | Standalone sealed application message (seal() / open_seal()).|
| 0x02  | MSG_HANDSHAKE_HELLO     | Step 1 of mutual session handshake.                         |
| 0x03  | MSG_HANDSHAKE_ACK       | Step 2 of mutual session handshake with HMAC proof.         |
| 0x04  | MSG_SESSION_DATA        | In-session data frame carrying sequential encrypted stream. |
| 0x05  | MSG_CHUNK_FRAME         | Large payload transfer fragment (UXSPChunk).                |
| 0x06  | MSG_CONTROL_CLOSE       | Graceful session closure and key zeroization frame.         |
| 0x07  | MSG_ERROR_FRAME         | Protocol rejection notification frame.                      |
+-------+-------------------------+-------------------------------------------------------------+
```

---

## 5. Flags Bitfield Registry (16-bit)

The `flags` field at offset `0x07 - 0x08` is a 16-bit big-endian bitmask:

```
 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|          Reserved (RFU) MUST be 0    |C |AD|CK|PQ|
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

| Bit Position | Hex Value | Name | Semantics |
| :---: | :---: | :--- | :--- |
| **Bit 0** | `0x0001` | `FLAG_PQC_ACTIVE` | **1**: Hybrid post-quantum operations active (ML-KEM + ML-DSA present).<br/>**0**: Classical-only mode (`kem_ciphertext` and `pqc_sig` omitted). |
| **Bit 1** | `0x0002` | `FLAG_IS_CHUNKED` | **1**: Payload is a chunked transfer fragment (`UXSPChunk`).<br/>**0**: Monolithic payload. |
| **Bit 2** | `0x0004` | `FLAG_HAS_AD` | **1**: Additional Authenticated Data (AAD) is bound to the AEAD tag.<br/>**0**: No external AAD. |
| **Bit 3** | `0x0008` | `FLAG_COMPRESSED` | **1**: Decrypted plaintext is zstd/deflate compressed.<br/>**0**: Uncompressed. |
| **Bits 4–15**| `0xFFF0` | `RFU` | Reserved for future extensions. **MUST be 0**. Parsers MUST reject frames with non-zero RFU bits. |

---

## 6. Algorithm Suite Identifiers (16-bit)

The `algorithm_suite` field at offset `0x09 - 0x0A` identifies the active cryptography:

- `0x0001` (`UXSP_SUITE_HYBRID_DEFAULT`):
  - ECDH: **X25519** (32-byte public key)
  - KEM: **ML-KEM-768** (FIPS 203, 1184-byte public key, 1088-byte ciphertext)
  - Signature: **Ed25519** (32-byte public key, 64-byte signature)
  - PQC Signature: **ML-DSA-65** (FIPS 204, 1952-byte public key, 3309-byte signature)
  - AEAD: **AES-256-GCM** (32-byte key, 12-byte IV, 16-byte tag)
  - KDF: **HKDF-SHA256**
- `0x0002` (`UXSP_SUITE_CLASSICAL_FALLBACK`):
  - ECDH: **X25519**
  - Signature: **Ed25519**
  - AEAD: **AES-256-GCM**
  - KDF: **HKDF-SHA256**

---

## 7. Internal Payload Wire Formats

When `ciphertext` is decrypted with AES-256-GCM, the decrypted plaintext bytes follow one of two standardized framing structures:

### 7.1 Standalone Structured Payload Framing (`UXSP-PAYLOAD-1`)

Used by `uxsp.core.payload` (`pack_text`, `pack_binary`, `pack_file`):

```
+--------------------------+-----------------------+--------------------------+--------------------+
| Magic: "UXSP-PAYLOAD-1"  | Header Length (H_len) | JSON Header Metadata     | Raw Body Bytes     |
| 14 Bytes ASCII           | 4 Bytes uint32 BE     | H_len Bytes UTF-8 JSON   | N Bytes Binary     |
+--------------------------+-----------------------+--------------------------+--------------------+
```

1. **Magic**: Exactly 14 bytes:
   `0x55 0x58 0x53 0x50 0x2D 0x50 0x41 0x59 0x4C 0x4F 0x41 0x44 0x2D 0x31` (`"UXSP-PAYLOAD-1"`).
2. **Header Length**: 4 bytes unsigned big-endian integer ($H_{\text{len}}$).
3. **JSON Header Metadata**: Compact UTF-8 JSON object containing:
   - `"kind"`: `"text"` | `"binary"` | `"file"`
   - `"filename"`: String or `null`
   - `"content_type"`: MIME string (e.g. `"application/json"`, `"video/mp4"`)
   - `"encoding"`: String or `null` (e.g. `"utf-8"`)
   - `"body_len"`: Integer byte count of body
4. **Body**: Raw body bytes of length exactly equal to `body_len`.

### 7.2 Chunked Transfer Framing (`UXSP-CHUNK-1`)

Used by `uxsp.core.chunking` (`create_chunked_transfer`):

```
+--------------------------+-----------------------+--------------------------+--------------------+
| Magic: "UXSP-CHUNK-1"    | Header Length (H_len) | JSON Header Metadata     | Raw Chunk Bytes    |
| 12 Bytes ASCII           | 4 Bytes uint32 BE     | H_len Bytes UTF-8 JSON   | N Bytes Binary     |
+--------------------------+-----------------------+--------------------------+--------------------+
```

1. **Magic**: Exactly 12 bytes:
   `0x55 0x58 0x53 0x50 0x2D 0x43 0x48 0x55 0x4E 0x4B 0x2D 0x31` (`"UXSP-CHUNK-1"`).
2. **Header Length**: 4 bytes unsigned big-endian integer ($H_{\text{len}}$).
3. **JSON Header Metadata**: Compact UTF-8 JSON object containing:
   - `"transfer_id"`: Transfer UUID string
   - `"chunk_index"`: Zero-indexed integer chunk sequence
   - `"total_chunks"`: Total chunk count
   - `"file_hash_sha256"`: 64-hex SHA-256 digest of whole assembled file
   - `"chunk_hash_sha256"`: 64-hex SHA-256 digest of this fragment
   - `"kind"`, `"filename"`, `"content_type"`, `"body_len"`
4. **Chunk Body**: Raw fragment bytes matching `chunk_hash_sha256`.

---

## 8. JSON Wire Format Mapping

In REST APIs, JSON envelopes are sent with `Content-Type: application/uxsp+json`. The mapping between JSON fields and binary wire fields is defined below:

| JSON Key | Binary Field Equivalent | JSON Type | Format / Constraints |
| :--- | :--- | :--- | :--- |
| `version` | `version_major` + `version_minor` | String | Fixed `"UXSP-1"`. |
| `sender_id` | `sender_id` | String | UTF-8 string, minimum length 1. |
| `recipient_id`| `recipient_id` | String | UTF-8 string, minimum length 1. |
| `timestamp` | `timestamp` | Integer | 64-bit Unix integer in seconds. |
| `envelope_nonce`| `envelope_nonce` | String | 32-character lowercase hex (16 raw bytes). |
| `ciphertext` | `ciphertext` + `aead_tag` | String | Lowercase hex string. AES-256-GCM ciphertext with trailing 16-byte tag. |
| `nonce` | `aead_nonce` | String | 24-character lowercase hex (12 raw bytes). |
| `ephemeral_pub`| `ephemeral_pub` | String | 64-character lowercase hex (32 raw bytes X25519). |
| `kem_ciphertext`| `kem_ciphertext` | String | 2176-character lowercase hex (1088 raw bytes ML-KEM-768). |
| `classical_sig`| `classical_sig` | String | 128-character lowercase hex (64 raw bytes Ed25519). |
| `pqc_sig` | `pqc_sig` | String | 6618-character lowercase hex (3309 raw bytes ML-DSA-65). |
| `pqc_mode` | Bit 0 in `flags` | String (Optional)| `"none"` when classical-only downgrade is allowed. |

---

## 9. Comprehensive Annotated Byte-Level Test Vector

The following is an annotated hex dump of an authentic, minimal UXSP-1 binary frame (`UXSP/1`) carrying an encrypted payload. Cross-language implementers can verify parser offset math against this vector.

### 9.1 Hex Byte Stream Dissection

```text
[0000]  55 58 53 50          ; MAGIC: "UXSP" (0x55, 0x58, 0x53, 0x50)
[0004]  01 00                ; VERSION: Major = 1 (0x01), Minor = 0 (0x00)
[0006]  01                   ; TYPE: 0x01 (MSG_SEALED_ENVELOPE)
[0007]  00 01                ; FLAGS: 0x0001 (FLAG_PQC_ACTIVE = 1)
[0009]  00 01                ; SUITE: 0x0001 (UXSP_SUITE_HYBRID_DEFAULT)
[000B]  00 00 00 01          ; KEY_ID: 1 (0x00000001)
[000F]  00 00 00 00 68 C1 20 00 ; TIMESTAMP: 1757478912 (uint64 Big-Endian)
[0017]  00 00 00 00 00 00 00 00 ; SEQUENCE: 0 (uint64 Big-Endian)
[001F]  A1 B2 C3 D4 E5 F6 07 18 ; ENVELOPE_NONCE (Bytes 0..7)
[0027]  29 3A 4B 5C 6D 7E 8F 90 ; ENVELOPE_NONCE (Bytes 8..15) [16 bytes total]
[002F]  10 11 12 13 14 15 16 17 ; AEAD_NONCE / IV (Bytes 0..7)
[0037]  18 19 1A 1B          ; AEAD_NONCE / IV (Bytes 8..11) [12 bytes total]
[003B]  00 05                ; SENDER_ID_LEN: 5 bytes (0x0005)
[003D]  61 6C 69 63 65       ; SENDER_ID: "alice" (UTF-8)
[0042]  00 03                ; RECIPIENT_ID_LEN: 3 bytes (0x0003)
[0044]  62 6F 62             ; RECIPIENT_ID: "bob" (UTF-8)
[0047]  00 20                ; EPHEMERAL_PUB_LEN: 32 bytes (0x0020)
[0049]  73 6F 6D 65 ...      ; EPHEMERAL_PUB: 32 bytes X25519 Public Key
[0069]  04 40                ; KEM_CIPHERTEXT_LEN: 1088 bytes (0x0440)
[006B]  C0 89 12 ...         ; KEM_CIPHERTEXT: 1088 bytes ML-KEM-768 Ciphertext
[04AB]  00 00 00 10          ; PAYLOAD_LEN: 16 bytes (0x00000010)
[04AF]  4E 5A 77 ...         ; CIPHERTEXT: 16 bytes AES-256-GCM Encrypted Data
[04BF]  9A 8B 7C 6D 5E 4F 3A 2B ; AEAD_TAG: 16 bytes GCM Authentication Tag
        1C 0D FE ED BA AD F0 0D ; (Authenticates all ciphertext and associated data)
[04CF]  00 40                ; CLASSICAL_SIG_LEN: 64 bytes (0x0040)
[04D1]  2F A3 8C ...         ; CLASSICAL_SIG: 64 bytes Ed25519 Signature
[0511]  0C ED                ; PQC_SIG_LEN: 3309 bytes (0x0CED)
[0513]  E4 B1 09 ...         ; PQC_SIG: 3309 bytes ML-DSA-65 Signature
[1200]                       ; TOTAL FRAME SIZE: Exactly 4,608 bytes
```

---

## 10. Canonical Signing Wire Format (`bind_fields`)

Before calculating or verifying the dual signatures (`classical_sig` and `pqc_sig`), implementations MUST construct the canonical signable buffer by executing the length-prefixed concatenation algorithm:

```python
# Canonical byte sequence for Envelope signing (UXSP-1)
signable_bytes = (
    struct.pack(">I", len(b"UXSP-1")) + b"UXSP-1"
    + struct.pack(">I", len(ciphertext_bytes)) + ciphertext_bytes
    + struct.pack(">I", len(nonce_bytes)) + nonce_bytes
    + struct.pack(">I", len(sender_id.encode("utf-8"))) + sender_id.encode("utf-8")
    + struct.pack(">I", len(recipient_id.encode("utf-8"))) + recipient_id.encode("utf-8")
    + struct.pack(">I", len(str(timestamp).encode("utf-8"))) + str(timestamp).encode("utf-8")
    + struct.pack(">I", len(envelope_nonce.encode("utf-8"))) + envelope_nonce.encode("utf-8")
    + struct.pack(">I", len(ephemeral_pub_bytes)) + ephemeral_pub_bytes
    + struct.pack(">I", len(kem_ciphertext_bytes)) + kem_ciphertext_bytes
)
```

Both Ed25519 and ML-DSA-65 sign this exact `signable_bytes` buffer directly without hashing beforehand (as both signature schemes operate over arbitrary-length input messages).
