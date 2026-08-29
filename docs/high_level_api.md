# High-Level APIs (`uxsp.secure` & `uxsp.aio`)

Welcome to the High-Level APIs of UXSP! This guide will explain how to encrypt and decrypt data easily. 

Our goal is to make Post-Quantum Security so simple that you only need a single line of code to protect your data. You don't need to worry about complex terms like "AES-GCM", "ML-KEM", or "Handshakes" — UXSP handles all of that automatically for you.

---

## 1. Creating and Using Identities

Before two computers can talk securely, they need an identity. In UXSP, an **Identity** is a package that contains your secret private keys and your public sharing keys.

### How to Create an Identity Correctly
To create an identity, use the `create_identity` function. You should give your identity a unique name (like "ServerA" or "ClientApp") and secure it with a strong password.

```python
from uxsp.secure import create_identity, export_identity_encrypted

# 1. Create a brand new identity
my_identity = create_identity(entity_id="MyServer")

# 2. Save it to a file so you don't lose it!
export_identity_encrypted(my_identity, "my_server_key.uxsp", "SuperSecretPassword123")
```

### Loading an Identity
When you restart your app, you just load that identity back into memory:

```python
from uxsp.secure import import_identity_encrypted, set_identity

# Load the identity from the file
my_identity = import_identity_encrypted("my_server_key.uxsp", "SuperSecretPassword123")

# Set it as the default identity for the entire app
set_identity(my_identity)
```

By calling `set_identity()`, UXSP will automatically use this identity for all background operations. You won't have to pass it manually every time you want to send a message!

---

## 2. Sending and Receiving Data (The `uxsp.secure` module)

The `uxsp.secure` module provides easy-to-use classes for transferring data. Depending on what you are sending, you pick a specific `Send*` and `Receive*` class. 

Under the hood, these classes compress, encrypt, and package your data so it cannot be tampered with or read by anyone except the intended recipient.

### The Send and Receive Classes

Here is exactly how and when to use the available classes:

*   **`SendText` / `ReceiveText`**: Use this when you are sending simple string messages, like chat messages or small status updates.
*   **`SendJSON` / `ReceiveJSON`**: Use this when you need to send structured data (like Python dictionaries). UXSP will automatically convert your dictionary to JSON before encrypting it.
*   **`SendBinary` / `ReceiveBinary`**: Use this when you have raw byte data (`b"hello"`) that doesn't fit into another category.
*   **`SendFile` / `ReceiveFile`**: Use this to securely transfer standard files from your hard drive. Just provide the file path!
*   **`SendImage` / `ReceiveImage` & `SendPhoto` / `ReceivePhoto`**: Use these when transferring pictures (JPG, PNG). They automatically add the correct metadata so the receiver knows it's an image.
*   **`SendVideo` / `ReceiveVideo`**: Use this for video files (MP4, MKV).
*   **`SendAudio` / `ReceiveAudio` & `SendVoice` / `ReceiveVoice`**: Use these for audio files (MP3, WAV) or recorded voice memos.
*   **`SendDocument` / `ReceiveDocument` & `SendDoc` / `ReceiveDoc`**: Use these for office files like Word documents, spreadsheets, or plain text documents.
*   **`SendPDF` / `ReceivePDF`**: Specifically meant for transferring PDF files securely.
*   **`SendZip` / `ReceiveZip` & `SendArchive` / `ReceiveArchive`**: Use these when you are transferring zipped or archived directories.
*   **`SendLocation` / `ReceiveLocation`**: Use this when you want to send GPS coordinates securely (e.g., sharing a live location in a chat app).
*   **`SendContact` / `ReceiveContact`**: Use this when sharing vCard contact information.
*   **`Send` / `Receive`**: The ultimate generic classes. If you don't want to pick a specific class from the list above, you can just use `Send` and `Receive` and let UXSP figure it out!

### Example: Sending a JSON Message

```python
from uxsp.secure import SendJSON, ReceiveJSON

# Sender's Code:
# The `receiver` argument is the public card of the person you are sending data to.
encrypted_package = SendJSON(
    item={"status": "active", "user": "Alice"},
    receiver=recipient_public_card 
)

# You can now send `encrypted_package.to_dict()` over the internet!
print(encrypted_package.to_dict())

# ----------------------------------------

# Receiver's Code:
# When the receiver gets the package, they just call ReceiveJSON!
decrypted_data = ReceiveJSON(
    package=received_package_dict
)

print(decrypted_data) # Output: {'status': 'active', 'user': 'Alice'}
```
It really is that simple. One line to encrypt, one line to decrypt.

---

## 3. Synchronous vs. Asynchronous (`uxsp.secure` vs `uxsp.aio`)

You might have noticed there is a `uxsp.secure` module and a `uxsp.aio` module. 

### What is the difference?
*   **`uxsp.secure` (Synchronous)**: This blocks the current thread until the encryption/decryption finishes. Use this in standard scripts, standard Flask/Django apps, or CLI tools.
*   **`uxsp.aio` (Asynchronous)**: This does *not* block the thread. It uses Python's `async/await` syntax. 

### Why and When to use `aio`?
You should use `uxsp.aio` when you are building highly concurrent applications using frameworks like **FastAPI**, **Starlette**, **Quart**, or when building **WebSocket** servers. 

In a high-traffic web server, if 100 people send a file at the exact same time, a synchronous app will process them one by one, slowing everyone down. An `aio` app will process them simultaneously without blocking the server.

**Example of `aio` usage:**
```python
from uxsp.aio import SendJSON, ReceiveJSON

async def handle_request(incoming_data):
    # Notice the "await" keyword!
    decrypted_data = await ReceiveJSON(package=incoming_data)
    
    # ... process data ...

    response_pkg = await SendJSON(item={"success": True}, receiver=sender_card)
    return response_pkg
```

---

## 4. Sending Very, Very Large Files

If you need to send a massive file (like a 50GB database backup or a 10GB 4K video), you **cannot** use `SendFile` because it will try to load the entire 50GB file into your computer's RAM, causing a crash!

Instead, you must use **Streaming**. 
Streaming reads the file in tiny chunks, encrypts each chunk one by one, and sends it over the network. 

### Using `SendStream` and `ReceiveStream`
```python
from uxsp.secure import SendStream, ReceiveStream

# SENDER:
def stream_my_huge_file():
    # SendStream yields chunks of encrypted data
    for encrypted_chunk in SendStream(item="/path/to/50GB_video.mp4", receiver=recipient_card):
        yield encrypted_chunk  # Send this chunk over the network

# RECEIVER:
# When you receive chunks over the network, pass them to ReceiveStream
def process_incoming_stream(network_stream_iterator):
    # This automatically decrypts chunks as they arrive and writes them to disk
    ReceiveStream(
        package=network_stream_iterator,
        output_file="/path/to/save/50GB_video.mp4"
    )
```
*Note: If you are using FastAPI or WebSockets, use `uxsp.aio.SendStream` and `uxsp.aio.ReceiveStream` instead!*

---

## 5. Key Rotation

In high-security environments, it is a best practice to change your encryption keys regularly. This is called **Key Rotation**. 

If an attacker somehow steals your key today, they can read today's messages. But if you rotate your key tomorrow, they can't read tomorrow's messages.

With UXSP, rotating keys is incredibly easy:

```python
from uxsp.secure import rotate_keys, export_identity_encrypted

# 1. Rotate the keys (generates brand new post-quantum and classical keys)
new_identity = rotate_keys(my_current_identity)

# 2. Save the newly rotated identity
export_identity_encrypted(new_identity, "my_server_key_v2.uxsp", "SuperSecretPassword123")
```
Once rotated, you just distribute your new Public Card to your peers. UXSP handles the transition smoothly!
