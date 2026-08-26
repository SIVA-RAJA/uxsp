# Comprehensive Guide to Native Async Engine (`uxsp.aio`)

When building high-throughput asynchronous Python applications (like FastAPI servers, Discord bots, or WebSockets), blocking the main event loop with heavy cryptographic processing will cause your server to freeze, delaying all other incoming requests.

The `uxsp.aio` module solves this by executing CPU-intensive cryptographic sealing and opening inside non-blocking thread pools (`asyncio.to_thread`). This allows your async server to handle thousands of concurrent cryptographic connections flawlessly.

---

## 1. Asynchronous Text and JSON Dispatchers

Any generic object like a string, dictionary, or list can be asynchronously encrypted and decrypted.

### Step 1.1: Async `SendText` and `ReceiveText`
```python
import asyncio
import uxsp
from uxsp.aio import SendText, ReceiveText

async def handle_text_chat():
    alice = uxsp.create_identity("Alice")
    bob = uxsp.create_identity("Bob")

    # The 'await' keyword ensures the event loop continues running other tasks 
    # while the Post-Quantum encryption happens in the background.
    pkg = await SendText(receiver=bob.public_card(), text="Hello Bob!", sender=alice)
    
    # Decrypt asynchronously
    text = await ReceiveText(package=pkg, sender=alice.public_card(), receiver=bob)
    print(text) # Output: Hello Bob!

asyncio.run(handle_text_chat())
```

### Step 1.2: Async `SendJSON` and `ReceiveJSON`
```python
from uxsp.aio import SendJSON, ReceiveJSON

async def handle_api_data():
    alice = uxsp.create_identity("Alice")
    bob = uxsp.create_identity("Bob")

    # Encrypt a dictionary
    pkg = await SendJSON(
        receiver=bob.public_card(), 
        data={"user_id": 99, "status": "active"}, 
        sender=alice
    )
    
    # Decrypt a dictionary
    data = await ReceiveJSON(
        package=pkg, 
        sender=alice.public_card(), 
        receiver=bob
    )
    print(data["status"]) # Output: active
```

---

## 2. Asynchronous File Dispatchers

Encrypting large files on disk usually blocks the thread while Python reads the file and performs cryptographic matrix math. By using `aio.SendFile`, the event loop is entirely free during file I/O and encryption.

```python
from uxsp.aio import SendFile, ReceiveFile

async def process_user_upload():
    # Asynchronously encrypt file from disk
    pkg = await SendFile(
        receiver=bob.public_card(),
        file_path="/var/www/uploads/user_image.jpg",
        sender=alice
    )

    # Asynchronously decrypt file to disk
    # This writes directly to disk without blocking the event loop
    out_path = await ReceiveFile(
        package=pkg,
        output_file="/var/www/downloads/restored_image.jpg",
        sender=alice.public_card(),
        receiver=bob
    )
    print(f"Decrypted successfully to {out_path}")
```

---

## 3. Asynchronous Streaming (`SendStream` / `ReceiveStream`)

Just like the synchronous `uxsp.secure.SendStream`, the async `uxsp.aio.SendStream` allows you to process multi-gigabyte files chunk-by-chunk without loading the entire file into RAM. However, `aio.SendStream` is designed specifically for asynchronous network streams like WebSockets.

### Step 3.1: Streaming Encrypted Chunks over WebSockets
You can use `async for` to iterate over the encrypted chunks yielded by the `SendStream` generator.

```python
from uxsp.aio import SendStream

async def websocket_file_transfer(websocket, alice, bob):
    # This generator yields `SecurePackage` chunk objects asynchronously
    async for chunk_package in SendStream(
        receiver=bob.public_card(),
        file_input="/path/to/massive_4k_movie.mp4",
        chunk_size=1024 * 1024, # 1 MB chunks
        sender=alice
    ):
        # We can send each chunk over the WebSocket immediately!
        await websocket.send_text(chunk_package.to_json())
        
    await websocket.send_text('{"transfer_complete": true}')
```

### Step 3.2: Async Decryption of a Stream from Disk
If you have a large 10GB file containing encrypted stream packages on your disk, you can decrypt it asynchronously back to its original form.

```python
from uxsp.aio import ReceiveStream

async def decrypt_downloaded_stream():
    await ReceiveStream(
        packages_or_stream="/path/to/encrypted_stream.uxsp",
        output_file="/path/to/restored_4k_movie.mp4",
        sender=alice.public_card(),
        receiver=bob
    )
    print("Decryption complete!")
```
