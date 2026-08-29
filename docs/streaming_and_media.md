# Live Media & Streaming (WebRTC, Voice, CCTV)

UXSP includes high-performance capabilities for negotiating real-time media streams. You can use this for Video Calls, Voice Calls, or live CCTV connections.

Normally, setting up encrypted WebRTC or Socket streams is extremely difficult. UXSP reduces this to a single line of code!

---

## 1. Live Video Calls

When you want to start a video call, both computers need to agree on a secret session key. They will use this key to encrypt the video frames in real-time.

You use `SendLiveSession` to generate and send this session key securely.

### Starting a Video Call
```python
from uxsp.secure import SendLiveSession

# Sender (Initiator):
# This generates a LiveSession object AND an encrypted package to send.
encrypted_package, session = SendLiveSession(
    receiver_id="Alice_App_123"
)

# You send the encrypted_package to Alice over your chat/signaling server.
print(f"Send this to Alice: {encrypted_package.to_dict()}")

# You now have the `session` object! You can use `session.key` to encrypt your WebRTC video.
print(f"My Video Encryption Key: {session.key.hex()}")
```

### Answering a Video Call
```python
from uxsp.secure import ReceiveLiveSession

# Receiver (Alice):
# Alice receives the encrypted package and decrypts it.
session = ReceiveLiveSession(
    package=received_package_dict
)

# Alice now has the EXACT SAME `session.key` as the initiator!
print(f"Alice's Video Encryption Key: {session.key.hex()}")
```

Now, both the initiator and Alice have a shared, perfectly secure `session.key` that they can plug into their WebRTC library!

---

## 2. Live Voice Calls (Audio Calls)

For audio calls (like VOIP or Discord-style voice chats), you need to agree on a bit more than just a key. You need to agree on the Audio Codec (like Opus), the Sample Rate, and the number of channels.

UXSP provides `SendLiveVoiceCall` (also aliased as `SendLiveVoice` or `SendVoiceCall`) for this exact purpose!

### Starting a Voice Call
```python
from uxsp.secure import SendLiveVoiceCall

# The sender proposes the audio settings: Opus codec at 48000Hz, Mono (1 channel)
encrypted_package, voice_session = SendLiveVoiceCall(
    receiver_id="Bob_App_123",
    codec="opus",
    sample_rate=48000,
    channels=1
)

# Send the package to Bob!
```

### Answering a Voice Call
```python
from uxsp.secure import ReceiveLiveVoiceCall

# Bob receives it:
voice_session = ReceiveLiveVoiceCall(
    package=received_package_dict
)

# Bob now knows exactly how to decode the audio!
print(f"Codec: {voice_session.codec}")       # 'opus'
print(f"Sample Rate: {voice_session.sample_rate}") # 48000
print(f"Channels: {voice_session.channels}")    # 1
```

---

## 3. Live CCTV Integration

UXSP is heavily utilized for securing live CCTV camera feeds. A camera feed is essentially a continuous video stream. If someone hacks the camera network, they could spy on your premises. UXSP prevents this entirely.

### How it Works with CCTV
1. The **CCTV Camera** (or the DVR box connected to it) runs a lightweight UXSP script.
2. The **Viewer Application** (like a mobile app or security desk) sends a `SendLiveSession` package to the Camera.
3. The Camera uses `ReceiveLiveSession` to decrypt the request and accepts the session key.
4. The Camera encrypts the RTSP or WebRTC video feed using that session key and streams it back to the Viewer.

### Creating an App for CCTV

If you want to build a secure CCTV network with UXSP:

**On the Camera (The Server):**
The camera should listen for incoming `SendLiveSession` requests. It can use the asynchronous (`aio`) APIs to handle multiple viewers at once.

```python
from uxsp.aio import ReceiveLiveSession
import asyncio

async def handle_viewer_connection(incoming_data):
    # 1. Decrypt the viewer's request
    session = await ReceiveLiveSession(package=incoming_data)
    
    # 2. Start streaming the encrypted video to the viewer!
    await start_encrypted_rtsp_stream(viewer_ip, session.key)
```

**What if an unauthorized person tries to connect?**
Because UXSP requires the Viewer to encrypt their `SendLiveSession` package using the Camera's public keys, and the Camera verifies the Viewer's signatures, an unauthorized hacker *cannot even generate a valid request*. The `ReceiveLiveSession` function will immediately raise a `SecureError` and block the connection instantly!
