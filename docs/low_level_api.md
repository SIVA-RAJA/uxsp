# Low-Level APIs (Core Concepts)

While the High-Level APIs (`uxsp.secure`) are all you need for 99% of applications, sometimes you need to get under the hood. This guide explains the core components of UXSP, how they work together, and how you can manually configure them if you need absolute control.

---

## 1. How UXSP Actually Works (The Assembly Line)

When you call `SendText()`, a lot happens behind the scenes. Here is the assembly line:

1.  **Identity Verification**: UXSP checks your private keys and the recipient's public keys.
2.  **Handshake / Key Exchange**: UXSP generates a completely random, one-time session key. It encrypts this session key using **ML-KEM (Post-Quantum)** and **X25519 (Classical)** public keys of the receiver. This is the "Hybrid" part.
3.  **Data Serialization**: It converts your text (or JSON, or file) into raw bytes.
4.  **AES-GCM Encryption**: It encrypts those bytes using the one-time session key and AES-256-GCM.
5.  **Signing**: It signs the entire package using **ML-DSA (Post-Quantum)** and **Ed25519 (Classical)** so the receiver knows nobody tampered with it.
6.  **Packaging**: It bundles the encrypted data, the encrypted session key, and the signatures into a `SecurePackage`.

When you use the Low-Level APIs, you can manually intervene at any of these steps!

---

## 2. Manual Configuration (`uxsp.core` and `uxsp.crypto`)

If you don't want to use the automatic `SecureContext`, you can manually instantiate and connect the core cryptography modules.

### The Cryptography Engine (`uxsp.crypto`)
The `uxsp.crypto` module contains the raw algorithms. You can use this to encrypt data manually if you don't want to use the `SecurePackage` format.

```python
from uxsp.crypto import AESGCMEncryption

# Manually create a 32-byte AES key
my_secret_key = b"A" * 32 

# Encrypt data manually
encryptor = AESGCMEncryption(my_secret_key)
ciphertext, nonce = encryptor.encrypt(b"Top secret data")

# Decrypt data manually
plaintext = encryptor.decrypt(ciphertext, nonce)
```

### The KeyStore (`uxsp.storage.keystore`)
In the high-level API, UXSP stores peer identities in memory by default. In a real production app, you might want to store them in a database. You can manually connect a `KeyStore`.

```python
from uxsp.storage.keystore import RedisKeyStore
import redis

# Connect to Redis
redis_client = redis.Redis(host='localhost', port=6379)

# Create a manual KeyStore
my_keystore = RedisKeyStore(redis_client)

# Put a card into the store
my_keystore.put(recipient_public_card)

# Later, you can fetch it manually!
card = my_keystore.get("recipient_id_123")
```

---

## 3. Integrating Low-Level and High-Level APIs

You can easily plug your low-level components (like the `RedisKeyStore`) into the high-level `SecureContext` so that `Send` and `Receive` automatically use your custom database!

```python
from uxsp.secure import configure, SendText
from uxsp.storage.keystore import RedisKeyStore
import redis

# 1. Setup low-level components
r = redis.Redis(host='localhost')
custom_keystore = RedisKeyStore(r)

# 2. Tell the high-level API to use it!
configure(
    keystore=custom_keystore,
)

# 3. Now, SendText will automatically look up keys in Redis!
SendText("Hello", receiver_id="friend_id_from_redis")
```

This is the true power of UXSP: It gives you the beautiful, easy-to-use 1-line APIs, while allowing you to swap out the complex internal engines (like databases and cache) effortlessly!
