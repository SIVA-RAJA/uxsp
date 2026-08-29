# WebRTC Integration Guide with UXSP

The Universal Exchange Security Protocol (UXSP) provides an ultra-low latency, zero-parsing symmetric encryption layer perfectly suited for real-time WebRTC streams. By leveraging `LiveSession` and `LiveVoiceSession`, you can add post-quantum secure end-to-end encryption (E2EE) to WebRTC DataChannels or Insertable Streams.

## Why Use UXSP with WebRTC?
WebRTC's default DTLS-SRTP secures the connection between the client and the server (SFU/TURN). However, the SFU decrypts the media, meaning it is not strictly End-to-End Encrypted (E2EE) across multi-party calls. 
UXSP solves this by encrypting the individual frames **before** they enter the WebRTC pipeline, guaranteeing true E2EE even through untrusted SFUs.

## 1. Initial Handshake & Negotiation

Before streaming, peers must negotiate a `LiveSession` over a secure signaling channel using the UXSP Browser SDK (`sdks/js`).

### Alice (Sender) Creates a Live Voice Package
```typescript
import { UXSPClient, Identity, PublicCard } from "@siva_raja/uxsp";

const sender = await Identity.create("Alice");
// Bob's public card retrieved from key server
const recipientCard: PublicCard = await fetchBobCard(); 

const { pkg, session } = await UXSPClient.createLiveVoicePackage(sender, recipientCard, {
    codec: "opus",
    sampleRate: 48000,
    channels: 2
});

// Send `pkg` to Bob over WebSockets/Signaling Server
signalingServer.send(UXSPClient.serializePackage(pkg));
```

### Bob (Receiver) Accepts the Live Voice Package
```typescript
// Receive `pkg` from signaling server
const parsedPkg = UXSPClient.parsePackage(receivedPayload);

const session = await UXSPClient.openLiveVoicePackage(receiver, senderCard, parsedPkg);
console.log("Ready to decrypt frames from Alice!");
```

## 2. Using WebRTC Insertable Streams

WebRTC Insertable Streams (also known as Encoded Transform) allow you to manipulate encoded media frames before they are packetized and sent over the network.

### Sender Side (Encryption)
```javascript
const sender = peerConnection.addTrack(mediaStream.getAudioTracks()[0]);
const senderStreams = sender.createEncodedStreams();

const transformStream = new TransformStream({
  async transform(encodedFrame, controller) {
    // 1. Convert frame to Uint8Array
    const frameData = new Uint8Array(encodedFrame.data);
    
    // 2. Encrypt with UXSP LiveSession
    const encryptedData = await session.encryptVoiceFrame(frameData);
    
    // 3. Write back to frame and enqueue
    encodedFrame.data = encryptedData.buffer;
    controller.enqueue(encodedFrame);
  }
});

senderStreams.readable.pipeThrough(transformStream).pipeTo(senderStreams.writable);
```

### Receiver Side (Decryption)
```javascript
const receiverStreams = receiver.createEncodedStreams();

const transformStream = new TransformStream({
  async transform(encodedFrame, controller) {
    // 1. Convert frame to Uint8Array
    const encryptedData = new Uint8Array(encodedFrame.data);
    
    // 2. Decrypt with UXSP LiveSession
    // The sequence number logic and replay protection is handled automatically!
    const decryptedData = await session.decryptVoiceFrame(encryptedData);
    
    // 3. Write back to frame and enqueue
    encodedFrame.data = decryptedData.buffer;
    controller.enqueue(encodedFrame);
  }
});

receiverStreams.readable.pipeThrough(transformStream).pipeTo(receiverStreams.writable);
```

## 3. Using WebRTC DataChannels

If you are building chat applications, file transfers, or sending raw binary state updates, UXSP works seamlessly with standard `RTCDataChannel`.

```typescript
// Sender
const dataChannel = peerConnection.createDataChannel("secure-channel");

async function sendSecureMessage(message: string) {
    const plaintext = new TextEncoder().encode(message);
    // Encrypt frame
    const ciphertext = await session.encryptFrame(plaintext);
    dataChannel.send(ciphertext);
}

// Receiver
dataChannel.onmessage = async (event) => {
    const ciphertext = new Uint8Array(event.data);
    try {
        const plaintext = await session.decryptFrame(ciphertext);
        console.log("Decrypted:", new TextDecoder().decode(plaintext));
    } catch (err) {
        console.error("Failed to decrypt or replay detected:", err);
    }
};
```

## Important Security Notes

1. **Replay Protection**: UXSP handles monotonic counters internally. If an SFU reorders packets, UXSP will detect it. Ensure your SFU is configured to drop late packets or you handle UXSP's replay rejection gracefully.
2. **Key Ratcheting**: `LiveSession` automatically derives new keys (via HKDF) every 65,536 frames to prevent AES-GCM nonce exhaustion in long-running video calls. No application-level intervention is needed.
3. **PQC Authenticity**: The initial `LiveSession` negotiation envelope is signed with both Ed25519 and ML-DSA, ensuring post-quantum authenticity of the channel setup.
