# Low-Level Cryptographic APIs

While `uxsp.secure` and `uxsp.aio` provide automated 1-line APIs, UXSP exposes all of its low-level cryptographic building blocks for advanced developers who need explicit control over encryption, sessions, Nonce storage, and chunking.

---

## 1. Raw Hybrid Cryptography (`uxsp.crypto.hybrid`)

UXSP combines classical cryptography (AES-256-GCM + X25519) and NIST Post-Quantum Cryptography (ML-KEM-768 FIPS 203) using the `Hybrid` suite. 

You can manually generate underlying keys, seal data, and open data without using `Identity` or `SecurePackage`.

### Generating Hybrid Keys
```python
from uxsp.crypto.hybrid import generate_hybrid_keypair

# Generate a raw hybrid keypair (contains both classical and PQC private/public bytes)
keypair = generate_hybrid_keypair()
public_key_bytes = keypair.public_key_bytes
private_key_bytes = keypair.private_key_bytes
```

### Sealing and Opening Raw Bytes
```python
from uxsp.crypto.hybrid import hybrid_seal, hybrid_open

secret_data = b"Highly classified raw data"

# Seal the data for the recipient's public key
ciphertext, shared_secret_sender = hybrid_seal(public_key_bytes, secret_data)

# Open the ciphertext using the recipient's private key
plaintext, shared_secret_receiver = hybrid_open(
    private_key_bytes, 
    public_key_bytes, 
    ciphertext
)

assert plaintext == secret_data
assert shared_secret_sender == shared_secret_receiver
```

---

## 2. Envelopes (`uxsp.core.envelope`)

An Envelope wraps encrypted ciphertext alongside its cryptographic configuration headers (like cipher suites and KDF algorithms). 

```python
from uxsp.core.envelope import Envelope

# Create a sealed envelope
envelope = Envelope.seal(
    receiver_pub_key=public_key_bytes,
    payload=b"Envelope payload"
)

# Export Envelope to JSON
envelope_json = envelope.to_json()

# Open the Envelope
restored_envelope = Envelope.from_json(envelope_json)
decrypted_payload = restored_envelope.open(private_key_bytes)
```

---

## 3. Mutual Handshakes & Sessions (`uxsp.core.session`)

Instead of sealing every message individually (which is slow due to PQC key encapsulation overhead), you can establish a `Session` with a peer to derive a fast, shared symmetric key.

### Mutual Handshake
```python
from uxsp.core.handshake import Handshake

# Alice creates a handshake offer
offer = Handshake.create_offer(sender_keypair=alice_keypair, receiver_pub=bob_pub)

# Bob receives offer, verifies it, and creates an answer
answer, bob_session = Handshake.accept_offer(offer, receiver_keypair=bob_keypair, sender_pub=alice_pub)

# Alice receives the answer and finalizes her session
alice_session = Handshake.finalize_offer(answer, sender_keypair=alice_keypair, receiver_pub=bob_pub)
```

### Session Encryption
Once `alice_session` and `bob_session` are established, you can use AES-GCM directly for blazing-fast encryption.

```python
# Alice encrypts a message
ciphertext = alice_session.encrypt(b"Hello over established session")

# Bob decrypts the message
plaintext = bob_session.decrypt(ciphertext)
```

---

## 4. Replay Protection & Nonce Stores (`uxsp.core.nonce`)

If an attacker intercepts an encrypted package, they might try to send it again later ("Replay Attack"). UXSP prevents this by tracking single-use random identifiers (Nonces).

You can control where these Nonces are stored (Memory, Redis, or Postgres).

```python
from uxsp.storage.noncestore import RedisNonceStore, PostgresNonceStore

# Store nonces in Redis for high-speed microservices
redis_store = RedisNonceStore(redis_client=redis_client)

# Or store in Postgres for durable audit trails
pg_store = PostgresNonceStore(dsn="postgresql://user:pass@localhost/db")

# Mark a nonce as seen
is_new = redis_store.mark_used("nonce-abc-123", ttl=3600)
if not is_new:
    print("Replay Attack Detected!")
```

---

## 5. File Chunking (`uxsp.core.chunking`)

If you want to manually chunk files without using `SendStream`, you can use the `FileChunker`.

```python
from uxsp.core.chunking import FileChunker

chunker = FileChunker(file_path="video.mp4", chunk_size=1024 * 1024)

# Iterate over raw bytes of chunks
for chunk_bytes in chunker.read_chunks():
    # Encrypt raw bytes manually
    ciphertext = my_session.encrypt(chunk_bytes)
    send_to_socket(ciphertext)
```
