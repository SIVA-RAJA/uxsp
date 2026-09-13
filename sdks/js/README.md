# @siva_raja/uxsp

[![NPM Version](https://img.shields.io/npm/v/@siva_raja/uxsp.svg?color=blue)](https://www.npmjs.com/package/@siva_raja/uxsp)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict-blue)](https://www.typescriptlang.org/)
[![NIST Post-Quantum](https://img.shields.io/badge/NIST-ML--KEM--768%20%7C%20ML--DSA--65-blueviolet)](https://csrc.nist.gov/)

**Universal Exchange Security Protocol (UXSP) JavaScript/TypeScript SDK** brings military-grade, hybrid post-quantum cryptography directly to Web Browsers and Node.js environments.

Protect client-side data, web APIs, and real-time WebSockets before information ever touches the network.

---

## What is UXSP?

Most websites today encrypt data with TLS/HTTPS. But TLS only protects data *in transit between your browser and the cloud load balancer*. Once it hits the server or CDN, it sits unencrypted in memory.

Even worse, upcoming **Quantum Computers** will break today's encryption (RSA and ECC). Malicious actors are already capturing encrypted traffic today ("Harvest Now, Decrypt Later") to unlock it in the future.

**UXSP solves this right inside your frontend:**
- 🔒 **End-to-End Application Layer Encryption**: Data is sealed inside the browser and can only be opened by the destination server or peer.
- 🛡️ **Double-Locked Hybrid Armor**: Combines battle-tested classical cryptography (**X25519** + **Ed25519** + **AES-256-GCM**) with NIST-approved Post-Quantum lattice cryptography (**ML-KEM-768** + **ML-DSA-65**).
- 🔄 **Drop-In `uxspFetch`**: Automatically detects whether a backend supports UXSP. If yes, it encrypts the request; if no, it seamlessly falls back to standard HTTP!

---

## 📦 Installation

```bash
# Using npm
npm install @siva_raja/uxsp

# Using pnpm
pnpm add @siva_raja/uxsp

# Using yarn
yarn add @siva_raja/uxsp
```

---

## ⚙️ Bundler Setup (Vite, Next.js, Webpack)

UXSP leverages modern **WebCrypto** and **WebAssembly** for hardware-accelerated post-quantum primitives.

### Vite (`vite.config.ts`)
```ts
import { defineConfig } from 'vite';

export default defineConfig({
  optimizeDeps: {
    exclude: ['@siva_raja/uxsp']
  }
});
```

### Next.js (`next.config.js`)
```js
/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack: (config) => {
    config.experiments = { ...config.experiments, asyncWebAssembly: true };
    return config;
  },
};
module.exports = nextConfig;
```

---

## 🚀 5-Minute Tutorial & Code Examples

### 1. Generating & Exporting Identities

Every browser client creates an `Identity` (with private keys) and a public `PublicCard`:

```ts
import { Identity } from "@siva_raja/uxsp";

// 1. Generate a new identity for the user
const alice = await Identity.generate("AliceClient", "client");

// 2. Extract Alice's PublicCard (shareable with the backend/peers)
const aliceCard = alice.publicCard();
console.log("Alice ID:", aliceCard.entity_id);

// 3. Save Alice's identity safely in browser localStorage (encrypted with user password)
const encryptedBlob = await alice.toEncryptedJson("UserSecretPassword123!");
localStorage.setItem("uxsp_identity", encryptedBlob);

// 4. Restore identity later
const restored = await Identity.fromEncryptedJson(
  localStorage.getItem("uxsp_identity")!,
  "UserSecretPassword123!"
);
```

---

### 2. Drop-In `uxspFetch` (Automatic Protocol Switching & Fallback)

`uxspFetch` is a drop-in replacement for the browser's native `window.fetch`. It automatically probes the destination server:
- If the server has UXSP middleware $\to$ automatically encrypts the request payload and decrypts the response.
- If the server is standard REST (e.g., Stripe, public APIs) $\to$ automatically falls back to standard plaintext HTTPS!

```ts
import { uxspFetch, configureUXSPFetch, Identity } from "@siva_raja/uxsp";

const alice = await Identity.generate("AliceClient");

// Configure default identity and fallback options
configureUXSPFetch({
  identity: alice,
  allowFallback: true // Enables progressive web migration
});

// Example 1: Talking to a UXSP-protected backend (FastAPI / Django / Flask)
// The request body is automatically encrypted; the response is automatically decrypted!
const secureResponse = await uxspFetch("https://api.myapp.com/v1/checkout", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ item: "Laptop", price: 1200 })
});

console.log("Encrypted with Post-Quantum armor?", secureResponse.isEncrypted);
const data = await secureResponse.json();
console.log("Decrypted response:", data);

// Example 2: Talking to a legacy third-party API (e.g. GitHub or Stripe)
// Server does not support UXSP -> uxspFetch seamlessly falls back to standard fetch!
const publicResponse = await uxspFetch("https://api.github.com/zen");
console.log("Encrypted?", publicResponse.isEncrypted); // false
console.log("Plaintext text:", await publicResponse.text());
```

---

### 3. High-Level 1-Line Encryption (`SendText` / `ReceiveText`)

Encrypt messages directly for peer-to-peer or WebSocket dispatch:

```ts
import { configure, setIdentity, SendText, ReceiveText, Identity } from "@siva_raja/uxsp";

const alice = await Identity.generate("Alice");
const bob = await Identity.generate("Bob");

// Alice sends confidential text to Bob
const packageObj = await SendText({
  text: "Confidential coordinates: 48.8584° N, 2.2945° E",
  receiver: bob.publicCard(),
  sender: alice
});

// Bob decrypts the package
const plainText = await ReceiveText({
  package: packageObj,
  sender: alice.publicCard(),
  receiver: bob
});

console.log(plainText);
// Output: "Confidential coordinates: 48.8584° N, 2.2945° E"
```

---

### 4. Real-Time Encrypted WebSockets

Secure live bi-directional messaging with monotonic frame sequencing and sliding-window replay protection:

```ts
import { UXSPWebSocket, Identity } from "@siva_raja/uxsp";

const client = await Identity.generate("BrowserUser");
const ws = new WebSocket("wss://api.myapp.com/live-stream");

const uxspWs = UXSPWebSocket.asInitiator(client);

ws.onopen = async () => {
  // 1. Complete 3-step mutual Post-Quantum handshake
  const helloFrame = await uxspWs.createHello();
  ws.send(JSON.stringify(helloFrame));
};

ws.onmessage = async (event) => {
  const frame = JSON.parse(event.data);

  if (frame.type === "HELLO_ACK") {
    const completeFrame = await uxspWs.handleHelloAck(frame);
    ws.send(JSON.stringify(completeFrame));
    console.log("Secure Post-Quantum Session Established!");
  } else if (frame.type === "DATA") {
    // Decrypt real-time data frame
    const plaintext = await uxspWs.decryptFrame(frame);
    console.log("Live stream frame received:", plaintext);
  }
};
```

---

### 5. Low-Level Direct Sealing (`seal` / `openSeal`)

For custom protocol designers and low-level envelope control:

```ts
import { seal, openSeal, Identity } from "@siva_raja/uxsp";

const alice = await Identity.generate("Alice");
const bob = await Identity.generate("Bob");

const rawBytes = new TextEncoder().encode("Low level binary payload");

// Seal directly into a UXSP Envelope
const envelope = await seal(alice, bob.publicCard(), rawBytes);

// Bob opens and verifies envelope
const decryptedBytes = await openSeal(bob, alice.publicCard(), envelope);
console.log(new TextDecoder().decode(decryptedBytes));
```

---

## 🛡️ Supported Cryptographic Algorithms

| Component | Standard | Primitive |
| :--- | :--- | :--- |
| Classical Key Encapsulation | RFC 7748 | **X25519 (ECDH)** |
| Post-Quantum Key Encapsulation | NIST FIPS 203 | **ML-KEM-768 (CRYSTALS-Kyber)** |
| Classical Digital Signature | RFC 8032 | **Ed25519** |
| Post-Quantum Digital Signature | NIST FIPS 204 | **ML-DSA-65 (CRYSTALS-Dilithium)** |
| Symmetric AEAD Encryption | RFC 5116 | **AES-256-GCM** |
| Key Derivation Function | RFC 5869 | **HKDF-SHA256** |
| Password Key Hashing | RFC 9106 | **Argon2id** |

---

## 📚 Related Resources

- 🐍 **[UXSP Python Core Engine](https://github.com/SIVA-RAJA/uxsp)**: The primary Python implementation and framework middlewares.
- 📜 **[Formal Protocol Specification](https://github.com/SIVA-RAJA/uxsp/blob/main/docs/protocol_specification.md)**: RFC 2119 specifications and security proofs.
- ⚡ **[Exact Wire Format Standard](https://github.com/SIVA-RAJA/uxsp/blob/main/docs/wire_format.md)**: Bit-by-bit wire framing.
- 📖 **[Developer Tutorials](https://github.com/SIVA-RAJA/uxsp/tree/main/tutorial)**: Comprehensive backend and frontend integration guides.

---

## 📄 License

MIT License — Copyright (c) 2026 SIVA RAJA S.
