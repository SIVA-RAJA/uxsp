# End-to-End Fullstack Integration Guide (Frontend + Backend)

This guide walks you through connecting a **JavaScript/TypeScript frontend** (React, Next.js, Vue, or Vanilla JS) with a **Python backend** (FastAPI, Django, or Flask) to achieve **end-to-end Post-Quantum Zero-Trust encryption**.

---

## Mental Model: The Double-Vault Pipeline

Normally, web traffic uses HTTPS (TLS). But HTTPS only encrypts data while traveling between the user's browser and the cloud load balancer / CDN. Once inside your cloud provider's network, data travels or sits in plaintext memory.

With UXSP fullstack integration:
1. The **Browser** seals data using the server's post-quantum public key (**ML-KEM-768 + X25519**) before it ever leaves the client machine.
2. If anyone (ISPs, public Wi-Fi sniffers, CDNs, or quantum eavesdroppers) captures the packets, they only see randomized ciphertext.
3. The **Backend Middleware** decrypts and verifies the data just before your route handler runs.
4. Your route code receives clean, ordinary Python dictionaries—no manual cryptography code required!
5. The backend response is automatically sealed back to the browser.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            THE FULLSTACK PIPELINE                           │
└─────────────────────────────────────────────────────────────────────────────┘

 [ Frontend: React / Next.js / JS ]             [ Backend: FastAPI / Django / Flask ]
               │                                                │
               │ 1. GET /.well-known/uxsp-card                  │
               ├───────────────────────────────────────────────>│
               │                                                │
               │ 2. Server's PublicCard (Kyber & Dilithium PKs) │
               │<───────────────────────────────────────────────┤
               │                                                │
    [Encrypts payload via ML-KEM]                               │
    [Signs request with Client Card]                            │
               │                                                │
               │ 3. POST /api/checkout (UXSP Encrypted Package) │
               ├───────────────────────────────────────────────>│
               │                                                │
               │                              [UXSP Middleware Intercepts]
               │                              [Verifies Nonce & Signature]
               │                              [Decrypts Payload into Python dict]
               │                              [Passes clean dict to Route Handler]
               │                              [Route returns standard response]
               │                              [Middleware encrypts outbound response]
               │                                                │
               │ 4. 200 OK (UXSP Encrypted Response)            │
               │<───────────────────────────────────────────────┤
               │                                                │
    [uxspFetch decrypts response]                               │
    [UI updates with clean JSON]                                │
```

---

## 🛠️ Step 1: The Python Backend

Here is a complete, standalone **FastAPI** backend that exposes a public card and protects sensitive endpoints.

### File: `server.py`

```python
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from uxsp import Identity
from uxsp.contrib.fastapi import UXSPFastAPIMiddleware, protect

# 1. Initialize or load the Server's Persistent Identity
IDENTITY_FILE = "server_identity.card"
PASSWORD = "ServerSuperSecretPassword123!"

if os.path.exists(IDENTITY_FILE):
    server_identity = Identity.load(IDENTITY_FILE, password=PASSWORD)
    print("Loaded existing server identity:", server_identity.entity_id)
else:
    server_identity = Identity.create(name="ProductionAPIServer", role="server")
    server_identity.save(IDENTITY_FILE, password=PASSWORD)
    print("Created new server identity:", server_identity.entity_id)

app = FastAPI(title="Quantum-Safe API")

# 2. Configure CORS so browser frontends can communicate
# IMPORTANT: Expose UXSP headers so browser JavaScript can read them!
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-UXSP-Accept", "X-UXSP-Version", "X-UXSP-Identity"],
    expose_headers=["X-UXSP-Version", "X-UXSP-Identity"],
)

# 3. Add UXSP ASGI Middleware
# Place this closest to your routes so it processes the decrypted body
app.add_middleware(
    UXSPFastAPIMiddleware,
    identity=server_identity,
    allow_unencrypted=True,  # Allows unencrypted clients (fallback mode)
    exclude_paths=["/docs", "/redoc", "/openapi.json", "/.well-known/uxsp-card"]
)

# 4. Public endpoint: Serve Server's PublicCard for frontend discovery
@app.get("/.well-known/uxsp-card")
async def get_public_card():
    """Returns the server's public cryptographic keys."""
    return server_identity.public_card().to_dict()

# 5. Opportunistic Route: Accepts BOTH encrypted and standard plaintext JSON
@app.post("/api/public-or-secure")
async def public_or_secure(data: dict):
    # If client encrypted the request, data is already decrypted!
    return {
        "status": "success",
        "echo": data,
        "note": "This endpoint accepts both encrypted and plaintext clients"
    }

# 6. Strictly Quantum-Protected Route: REJECTS unencrypted requests with 400 Bad Request
@app.post("/api/checkout")
@protect()
async def checkout(request: Request):
    # Guaranteed to be cryptographically verified and decrypted:
    payload = request.state.uxsp_payload

    amount = payload.get("amount")
    currency = payload.get("currency")
    item = payload.get("item")

    print(f"Processing order: {item} for {amount} {currency}")

    # Return a normal dictionary. The middleware intercepts and encrypts it!
    return {
        "order_id": "ORD-987654321",
        "status": "APPROVED",
        "message": f"Successfully charged {amount} {currency} for {item}"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
```

> [!TIP]
> **Django & Flask Developers**: The same principles apply!
> - In **Django**: Add `UXSPDjangoMiddleware` right before `CsrfViewMiddleware` and add a view returning `server_identity.public_card().to_dict()`.
> - In **Flask**: Wrap `app.wsgi_app = UXSPFlaskMiddleware(app.wsgi_app, identity=server_identity)`.

---

## 💻 Step 2: The Frontend Integration

We provide two approaches for the frontend:
1. **Approach A: Drop-in `uxspFetch` (Recommended)**: Exactly like browser `fetch()`, with automatic encryption & fallback.
2. **Approach B: React Component / Hook**: Idiomatic state management for modern SPA frameworks.

### Approach A: Drop-In `uxspFetch` (Vanilla JS or Modern Frameworks)

Install the NPM package:
```bash
npm install @siva_raja/uxsp
```

```javascript
import { Identity, configureUXSPFetch, uxspFetch } from "@siva_raja/uxsp";

async function initializeClient() {
  // 1. Generate or restore client identity from browser storage
  let clientIdentity;
  const savedKey = localStorage.getItem("my_app_identity");

  if (savedKey) {
    clientIdentity = await Identity.fromEncryptedJson(savedKey, "UserSecretPassword!");
  } else {
    clientIdentity = await Identity.generate("WebClientUser", "client");
    const encryptedJson = await clientIdentity.toEncryptedJson("UserSecretPassword!");
    localStorage.setItem("my_app_identity", encryptedJson);
  }

  // 2. Configure the global uxspFetch engine
  // It will automatically fetch /.well-known/uxsp-card from the server!
  await configureUXSPFetch({
    identity: clientIdentity,
    baseUrl: "http://127.0.0.1:8000",
    allowFallback: true // If server doesn't support UXSP, falls back to regular HTTPS
  });

  console.log("UXSP Client initialized:", clientIdentity.publicCard().entity_id);
}

// 3. Make requests exactly like standard fetch()!
async function makeSecurePayment() {
  try {
    const response = await uxspFetch("http://127.0.0.1:8000/api/checkout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        item: "Post-Quantum Security Server",
        amount: 2499.00,
        currency: "USD",
        card_number: "4111-2222-3333-4444"
      })
    });

    // Response is AUTOMATICALLY decrypted and verified before returning!
    const data = await response.json();
    console.log("Order confirmed:", data);
  } catch (err) {
    console.error("Payment failed:", err);
  }
}

// Initialize and execute
initializeClient().then(() => makeSecurePayment());
```

---

### Approach B: React Component / Hook (`useUXSP`)

Here is an idiomatic React implementation:

```tsx
import React, { useState, useEffect } from "react";
import { Identity, uxspFetch, configureUXSPFetch } from "@siva_raja/uxsp";

export function CheckoutForm() {
  const [isReady, setIsReady] = useState(false);
  const [orderResult, setOrderResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function setup() {
      // Create ephemeral or persistent client identity
      const client = await Identity.generate("ReactUser", "client");
      await configureUXSPFetch({
        identity: client,
        baseUrl: "http://127.0.0.1:8000",
        allowFallback: true
      });
      setIsReady(true);
    }
    setup();
  }, []);

  const handleCheckout = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      // uxspFetch automatically:
      // 1. Fetches server public card
      // 2. Performs hybrid key encapsulation (ML-KEM-768 + X25519)
      // 3. Signs payload with Dilithium/Ed25519
      // 4. Encrypts payload with AES-256-GCM
      // 5. Decrypts the server's encrypted response
      const res = await uxspFetch("http://127.0.0.1:8000/api/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          item: "Quantum Armor License",
          amount: 150.00,
          currency: "EUR"
        })
      });

      const result = await res.json();
      setOrderResult(result);
    } catch (err: any) {
      alert("Checkout error: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  if (!isReady) return <p>Initializing Quantum Cryptography...</p>;

  return (
    <div style={{ maxWidth: 400, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h2>Quantum-Safe Checkout</h2>
      <form onSubmit={handleCheckout}>
        <button type="submit" disabled={loading}>
          {loading ? "Encrypting & Transmitting..." : "Pay $150.00 with UXSP"}
        </button>
      </form>

      {orderResult && (
        <div style={{ marginTop: "1rem", padding: "1rem", background: "#e6ffe6", borderRadius: 8 }}>
          <h4>Order Success!</h4>
          <pre>{JSON.stringify(orderResult, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
```

---

## 🔍 Step 3: Inspecting Network Traffic (Verify End-to-End)

Open your browser's Developer Tools (`F12`), go to the **Network** tab, and submit the checkout request.

### What an Attacker or ISP Sees on the Wire:
```http
POST /api/checkout HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: application/octet-stream
X-UXSP-Version: 1.3
X-UXSP-Identity: AliceClient-7a91bf

[Binary Ciphertext: 55 58 53 50 01 01 02 8b a4 19 32 8e fe 11 ... ]
```
- No credit card numbers.
- No item names or amounts.
- No readable JSON.
- Protected against retroactive quantum decryption ("Harvest Now, Decrypt Later").

### What your Python Server Code Sees:
```python
@app.post("/api/checkout")
@protect()
async def checkout(request: Request):
    print(request.state.uxsp_payload)
    # Output:
    # {'item': 'Post-Quantum Security Server', 'amount': 2499.0, 'currency': 'USD', 'card_number': '4111-2222-3333-4444'}
```

---

## 🛡️ Step 4: Fallback & Progressive Migration Behavior

| Scenario | Client Setting | Server Setting | Result |
| :--- | :--- | :--- | :--- |
| **Standard Browser Request** | Native `fetch()` | `allow_unencrypted=True` | Request passes normally as standard JSON. |
| **Standard Browser Request** | Native `fetch()` | `@protect()` (Strict Route) | Server rejects with **HTTP 400 Bad Request** (`Missing UXSP Envelope`). |
| **UXSP Browser Client** | `uxspFetch()` | UXSP Middleware Installed | Fully encrypted & authenticated with NIST Post-Quantum algorithms. |
| **UXSP Browser Client** | `uxspFetch(allowFallback=True)` | External API (e.g. Stripe) | Automatically falls back to standard HTTPS with zero errors. |

---

## ⚠️ Important Checklist for Developers

1. **CORS Configuration**:
   Always ensure your backend CORS configuration explicitly allows and exposes the following headers:
   - Allowed headers: `X-UXSP-Accept`, `X-UXSP-Version`, `X-UXSP-Identity`, `Content-Type`
   - Expose headers: `X-UXSP-Version`, `X-UXSP-Identity`
2. **Card Endpoint**:
   Ensure `/.well-known/uxsp-card` is excluded from encryption requirements (`exclude_paths=[..., "/.well-known/uxsp-card"]`) so new clients can download the server's public key before initiating a session.
3. **Storage Security**:
   On the client side, never store unencrypted private keys in `localStorage`. Always use `identity.toEncryptedJson(password)` to ensure the private keys are protected at rest with Argon2id.
