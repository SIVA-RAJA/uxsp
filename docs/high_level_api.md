# Comprehensive Guide to `uxsp.secure`

The `uxsp.secure` module is the high-level, synchronous developer API for UXSP. It is designed so that you do not need to manually configure cryptographic primitives, memory buffers, or handshakes. 

This guide provides step-by-step instructions for all features available under `uxsp.secure`.

---

## 1. Creating and Managing Identities

Everything in UXSP relies on an `Identity`. An `Identity` contains your private keys, while a `PublicCard` contains the public keys that you share with others.

### Step 1.1: Creating an Identity
```python
import uxsp

# Create a sender identity
alice = uxsp.create_identity(name="Alice", role="sender")

# Create a receiver identity
bob = uxsp.create_identity(name="Bob", role="receiver")
```

### Step 1.2: Passing Cards to Peers
To encrypt data for Bob, Alice needs Bob's `PublicCard`.
```python
bob_card = bob.public_card()
```
*In a real application, you would send `bob_card.to_json()` to Alice over an API, and Alice would load it using `PublicCard.from_json(json_str)`.*

---

## 2. Basic Encryption and Decryption

### Step 2.1: Polymorphic `Send` and `Receive`
The `Send` and `Receive` functions automatically detect what type of data you are passing (text, dict, list, bytes) and handle it appropriately.

```python
import uxsp

# Alice sends a dictionary (JSON) to Bob
encrypted_package = uxsp.secure.Send(
    receiver=bob.public_card(),  # Who is it for?
    item={"secret": "This is a confidential dictionary"}, # What is the data?
    sender=alice # Who is sending it?
)

# Bob receives and decrypts it
decrypted_data = uxsp.secure.Receive(
    sender=alice.public_card(),  # Who sent it?
    package=encrypted_package,   # The encrypted package
    receiver=bob # Bob uses his private keys to decrypt
)

print(decrypted_data) # Output: {'secret': 'This is a confidential dictionary'}
```

### Step 2.2: Specialized Handlers
If you want strict type hinting and validation in your code, use the specialized helpers instead of the generic `Send`.

**For Strings (Text):**
```python
pkg = uxsp.secure.SendText(receiver=bob.public_card(), text="Hello Bob", sender=alice)
text = uxsp.secure.ReceiveText(package=pkg, sender=alice.public_card(), receiver=bob)
```

**For JSON / Dicts:**
```python
pkg = uxsp.secure.SendJSON(receiver=bob.public_card(), data={"id": 1}, sender=alice)
data = uxsp.secure.ReceiveJSON(package=pkg, sender=alice.public_card(), receiver=bob)
```

**For Raw Bytes / Binary:**
```python
pkg = uxsp.secure.SendBinary(receiver=bob.public_card(), data=b"\x00\xFF", sender=alice)
raw = uxsp.secure.ReceiveBinary(package=pkg, sender=alice.public_card(), receiver=bob)
```

---

## 3. Working with Files

UXSP can seamlessly encrypt and decrypt files from your hard drive. It detects 14 different file types based on the extension (e.g., `.pdf`, `.mp4`, `.docx`, `.png`).

### Step 3.1: Encrypting a File
```python
# Alice encrypts a PDF file from her disk
pkg = uxsp.secure.SendFile(
    receiver=bob.public_card(),
    file_path="/home/alice/secret_report.pdf",
    sender=alice
)
```

### Step 3.2: Decrypting a File to Disk
When receiving a file, you can specify an `output_file` path to save the decrypted contents directly to disk, avoiding memory overload.

```python
uxsp.secure.ReceiveFile(
    package=pkg,
    output_file="/home/bob/downloads/restored_report.pdf",
    sender=alice.public_card(),
    receiver=bob
)
```

---

## 4. Multi-Gigabyte File Streaming

If you are dealing with files larger than your available RAM (e.g., a 10GB `.zip` file or a 50GB `.mp4`), loading the entire file into memory to encrypt it will crash your server (OOM Error).

To solve this, UXSP provides `SendStream` and `ReceiveStream`. These functions process the file in small cryptographic chunks (e.g., 1MB at a time).

### Step 4.1: Stream Encryption directly to Disk
You can stream the encryption of a massive file and write the resulting `SecurePackage` JSON strings line-by-line to an output file.

```python
output_path = uxsp.secure.SendStream(
    receiver=bob.public_card(),
    file_input="/path/to/massive_database.sql",
    output_destination="/path/to/encrypted_stream.uxsp",
    chunk_size=1024 * 1024, # 1 MB chunks
    sender=alice
)
```

### Step 4.2: Stream Encryption to a Generator
If you do not provide an `output_destination`, `SendStream` returns a Python generator. You can use this generator to stream the encrypted chunks over a network socket or HTTP response chunk-by-chunk.

```python
chunk_generator = uxsp.secure.SendStream(
    receiver=bob.public_card(),
    file_input="/path/to/massive_database.sql",
    chunk_size=1024 * 1024,
    sender=alice
)

for encrypted_chunk_package in chunk_generator:
    # Send this chunk over the network immediately
    send_to_network(encrypted_chunk_package.to_json())
```

### Step 4.3: Decrypting a Stream Directly to Disk
Bob can read the massive encrypted stream file line-by-line, decrypt it chunk-by-chunk, and write the decrypted bytes directly to a file on his disk.

```python
uxsp.secure.ReceiveStream(
    packages_or_stream="/path/to/encrypted_stream.uxsp",
    output_file="/path/to/restored_database.sql",
    sender=alice.public_card(),
    receiver=bob
)
```

---

## 5. Enterprise Key Lifecycle Management

UXSP allows you to control the lifecycle of your keys securely.

### Step 5.1: Key Rotation
If you want to cycle your cryptographic keys periodically (e.g., every 90 days) without changing your user ID, you can use `rotate_keys()`.

```python
# Alice generates a new underlying keypair
alice_new = alice.rotate_keys()

# The identity ID remains the same!
print(alice.entity_id == alice_new.entity_id) # True

# The Key Version increments
print(alice_new.key_version) # 2
```

### Step 5.2: Public Card Expiration
When distributing a public card to a peer, you can enforce that they must encrypt data using it before a certain expiration date.

```python
# Issue a card that expires in exactly 1 hour (3600 seconds)
expiring_card = alice.public_card(ttl_seconds=3600)

# Check if it has expired
print(expiring_card.is_expired()) # False
```

### Step 5.3: Card Revocation
If a device is compromised, you can revoke a card immediately.

```python
card = alice.public_card()
card.revoke(reason="Laptop was stolen")

try:
    card.verify_validity()
except uxsp.core.identity.CardRevokedError as e:
    print(f"Cannot use this card: {e}")
```

---

## 6. In-Memory Identity Serialization

When running a web server (like FastAPI or Django), you often need to store the server's `Identity` (its private keys) securely in a database or Redis cache. You can encrypt the `Identity` using a strong password before saving it.

### Step 6.1: Exporting an Identity
```python
# Convert Alice's identity into an encrypted JSON string
encrypted_identity_string = alice.export_encrypted(password="SuperStrongMasterPassword!")

# Save this string to your database
database.save("alice_keys", encrypted_identity_string)
```

### Step 6.2: Restoring an Identity
```python
# Retrieve the string from your database
encrypted_identity_string = database.get("alice_keys")

# Restore the Identity object using the password
restored_alice = uxsp.import_identity_encrypted(
    encrypted_json=encrypted_identity_string, 
    password="SuperStrongMasterPassword!"
)
```
