# Autonomous HTTP Client & Protocol Switching Guide (`uxsp.client`)

The **UXSP Client** (`uxsp.client.UXSPClient` and `uxsp.client.AsyncUXSPClient`) is an intelligent HTTP transport that brings **progressive zero-trust post-quantum security** to web applications and microservices.

It allows applications to communicate securely with UXSP-enabled backends while **automatically falling back to standard plaintext HTTP** when interacting with legacy servers or third-party APIs (such as Stripe, GitHub, or AWS).

---

## The Bilingual Messenger

Imagine you hire a messenger to deliver letters:

```
                      ┌────────────────────────────────────────┐
                      │              UXSP Client               │
                      │         "The Smart Messenger"          │
                      └──────────────────┬─────────────────────┘
                                         │
                    Probes: "Do you speak UXSP Secret Code?"
                                         │
                  ┌──────────────────────┴──────────────────────┐
                  ▼                                             ▼
       [UXSP-Protected Server]                       [Standard Legacy Server]
         "Yes, I speak UXSP!"                          "Huh? Standard HTTP only!"
                  │                                             │
      (Double-Locked Post-Quantum)                    (Standard Plaintext HTTP)
                  │                                             │
                  ▼                                             ▼
          100% Encrypted Safe                           Standard HTTP Request
        Zero-Trust Communication                        Zero Code Breakage!
```

1. **The Problem with "All-or-Nothing" Security**: If you decide to secure your company with quantum-proof encryption, you cannot rewrite all 100 backend services and third-party partner APIs overnight. If your HTTP client only speaks UXSP, all your calls to Stripe, Twilio, or older microservices will crash!
2. **The Bilingual Messenger (`UXSPClient`)**: The UXSP client visits every server and politely checks: *"Do you speak UXSP Post-Quantum encryption?"*
   - If the server says **YES**: The client automatically seals the message in a post-quantum double safe (`SecurePackage`) and decrypts the response.
   - If the server says **NO**: The client gracefully speaks standard HTTP without throwing an error!
3. **No If/Else Spaghetti**: You don't need to write manual `if server_is_secure: encrypt() else: requests.post()`. The client handles everything transparently.

---

## ⚡ Key Capabilities

| Feature | Description |
| :--- | :--- |
| **Dual Engine** | Synchronous (`UXSPClient`) and Asynchronous (`AsyncUXSPClient`) implementations. |
| **Automatic Negotiation** | Probes servers using `X-UXSP-Accept`, `X-UXSP-Version`, and `X-UXSP-Identity` headers. |
| **Transparent Encryption** | Automatically packages payloads into `SecurePackage` and decrypts responses. |
| **Transparent Fallback** | Falls back to standard plaintext HTTP/JSON when contacting legacy servers (`allow_fallback=True`). |
| **Strict Zero-Trust Mode** | Option to forbid unencrypted connections (`force_uxsp=True` / `allow_fallback=False`). |
| **Pluggable Caching** | Caches server capabilities in **Memory**, **Redis**, or **PostgreSQL** to prevent redundant discovery round-trips. |
| **CLI Companion** | Test endpoints directly from your shell using `uxsp curl`. |

---

## 📦 Requirements & Installation

The client comes bundled with `uxsp`:

```bash
# Standard install (includes requests/urllib fallback)
pip install uxsp

# Optional: install httpx2 for high-performance HTTP engine
pip install "uxsp[fastapi]"  # or pip install httpx2
```

---

## 🚀 Quickstart: Synchronous Client (`UXSPClient`)

### 1. Basic Usage with Opportunistic Fallback

```python
from uxsp.client import UXSPClient
from uxsp import Identity

# 1. Create client identity
client_ident = Identity.create(name="WebClient", role="client")

# 2. Instantiate client with opportunistic fallback enabled
with UXSPClient(identity=client_ident, allow_fallback=True) as client:

    # Request A: Talking to a UXSP-enabled server (FastAPI/Django/Flask with UXSP middleware)
    # The client discovers UXSP capability, encrypts the payload, and decrypts the response!
    secure_resp = client.post(
        "https://api.internal.service/transfer",
        json={"recipient": "Bob", "amount": 500}
    )
    print("Was request encrypted?", secure_resp.is_uxsp)  # True
    print("Decrypted payload:", secure_resp.data)         # Decrypted Python dict

    # Request B: Talking to a standard public API (e.g. GitHub or Stripe)
    # The client detects no UXSP capability and seamlessly falls back to standard HTTP!
    public_resp = client.get("https://httpbin.org/get")
    print("Was request encrypted?", public_resp.is_uxsp)  # False
    print("Standard JSON:", public_resp.json())           # Normal HTTP response
```

---

## ⚡ Asynchronous Client (`AsyncUXSPClient`)

For high-throughput async frameworks (FastAPI, Starlette, asyncio workers):

```python
import asyncio
from uxsp.client import AsyncUXSPClient
from uxsp import Identity

async def main():
    client_ident = Identity.create(name="AsyncClient", role="client")

    async with AsyncUXSPClient(identity=client_ident, allow_fallback=True) as client:
        # Send non-blocking async request
        resp = await client.post(
            "https://api.internal.service/orders",
            json={"order_id": "ORD-9876", "item": "Widget"}
        )

        if resp.is_uxsp:
            print("Received verified post-quantum encrypted response:")
            print(resp.data)
        else:
            print("Received plaintext HTTP response:")
            print(resp.json())

asyncio.run(main())
```

---

## 🛡️ Enforceability Modes: Opportunistic vs. Strict Zero-Trust

Depending on your security posture, `UXSPClient` supports three operational modes:

### Mode 1: Opportunistic Migration (`allow_fallback=True`, Default)
Ideal for progressive rollouts. Encrypts whenever the remote server supports UXSP, but allows plaintext when talking to external APIs or legacy services.

```python
client = UXSPClient(identity=client_ident, allow_fallback=True)
```

### Mode 2: Strict Zero-Trust (`force_uxsp=True` or `allow_fallback=False`)
For mission-critical internal networks, banking, or defense applications. The client **refuses** to talk to any server that does not provide end-to-end UXSP post-quantum encryption.

```python
client = UXSPClient(identity=client_ident, force_uxsp=True)

try:
    # If the server is unencrypted or tries to respond with standard plaintext,
    # the client immediately aborts and raises UXSPClientError!
    resp = client.get("https://unencrypted-legacy-server.com/api")
except Exception as e:
    print("Security violation caught:", e)
```

### Mode 3: Forced Plaintext (`force_plain=True`)
Temporarily bypasses UXSP wrapping for specific debugging sessions.

```python
resp = client.get("https://api.example.com/health", force_plain=True)
```

---

## 💾 Host Capability Caching

Probing a server on every request adds header inspection overhead. UXSP uses pluggable **Capability Caching** so the client remembers whether a host speaks UXSP:

```
┌─────────────────┐       Cache Hit (Host Known)       ┌────────────────────────┐
│   UXSP Client   │ ─────────────────────────────────▶ │ Skip Discovery Header  │
└────────┬────────┘                                    │ Encrypt Directly       │
         │                Cache Miss (First Visit)     └────────────────────────┘
         └───────────────────────────────────────────▶ Probe Headers & Store
```

### Supported Cache Backends

#### 1. In-Memory Cache (`InMemoryHostCapabilityCache`)
Fast, thread-safe, zero external dependencies. Ideal for single-process clients and CLI scripts:

```python
from uxsp.client import UXSPClient, InMemoryHostCapabilityCache

cache = InMemoryHostCapabilityCache(default_ttl=3600)  # Cache for 1 hour
client = UXSPClient(identity=client_ident, cache=cache)
```

#### 2. Redis Distributed Cache (`RedisHostCapabilityCache`)
Share capability knowledge across thousands of container pods in Kubernetes:

```python
import redis
from uxsp.client import UXSPClient, RedisHostCapabilityCache

r = redis.Redis(host="localhost", port=6379, db=0)
cache = RedisHostCapabilityCache(redis_client=r, prefix="uxsp:cap:", default_ttl=86400)

client = UXSPClient(identity=client_ident, cache=cache)
```

#### 3. Database Cache (`DatabaseHostCapabilityCache`)
Persist capabilities in PostgreSQL, MySQL, or SQLite:

```python
from uxsp.client import DatabaseHostCapabilityCache

# Custom lookup/store functions wrapping your database ORM
cache = DatabaseHostCapabilityCache(
    get_fn=my_db_get_capability,
    set_fn=my_db_save_capability
)
```

---

## 📡 The Negotiation Wire Protocol

When `UXSPClient` initiates an HTTP request, it automatically includes the following negotiation headers:

```http
POST /api/v1/resource HTTP/1.1
Host: api.example.com
User-Agent: UXSP-Client/1.3.0
X-UXSP-Accept: application/uxsp+json, application/json
X-UXSP-Version: 1.0, 1.3
X-UXSP-Identity: eid-client-883a9f
Content-Type: application/uxsp+json

{
  "uxsp_package_version": "1.0",
  "sender_id": "eid-client-883a9f",
  "receiver_id": "eid-server-994b21",
  "data_type": "JSON",
  "envelope": { ... }
}
```

### How the Server Responds:

1. **UXSP-Aware Server (FastAPI / Django / Flask)**:
   - Responds with `Content-Type: application/uxsp+json` and `X-UXSP-Package: 1`.
   - Client decrypts the payload automatically.
2. **Legacy Server (Nginx / Express / Go / Java standard REST)**:
   - Ignores custom `X-UXSP-*` headers and responds with standard `Content-Type: application/json`.
   - If `allow_fallback=True`, `UXSPClient` accepts the plaintext response and marks `resp.is_uxsp = False`.

---

## 💻 Testing Endpoints with `uxsp curl`

The UXSP CLI includes a built-in `curl` command that uses `UXSPClient` under the hood:

```bash
# 1. Send encrypted JSON to an endpoint
uxsp curl -X POST https://api.mycorp.com/v1/data \
  --data '{"temperature": 24.5}' \
  --sender /path/to/client.card \
  --peer /path/to/server.card

# 2. Upload and encrypt a file using @ prefix
uxsp curl -X POST https://api.mycorp.com/v1/upload \
  --data @database_dump.sql \
  --sender /path/to/client.card \
  --peer /path/to/server.card

# 3. Verbose discovery inspection
uxsp curl -v https://api.mycorp.com/v1/status

# 4. Enforce strict UXSP (fails if server tries to speak plaintext)
uxsp curl https://api.mycorp.com/v1/data --force-uxsp
```

---

## 🛠️ Complete Reference: `UXSPResponse` Object

Both `UXSPClient` and `AsyncUXSPClient` return a unified `UXSPResponse`:

| Property / Method | Type | Description |
| :--- | :--- | :--- |
| `status_code` | `int` | Standard HTTP status code (e.g. `200`, `201`, `404`). |
| `is_uxsp` | `bool` | `True` if the response was an encrypted UXSP package; `False` if plaintext. |
| `data` | `Any` | The decrypted payload object (string, dict, bytes) if `is_uxsp=True`. |
| `package` | `SecurePackage \| None` | The parsed wire envelope object if `is_uxsp=True`. |
| `headers` | `dict[str, str]` | HTTP response headers. |
| `content` | `bytes` | Raw response bytes. |
| `json()` | `dict \| list` | Parse content as standard JSON (works for both plaintext and decrypted JSON). |
| `text` | `str` | Raw decoded text string of the response. |

---

## ❓ Frequently Asked Questions

### Can I pass custom headers or auth tokens?
Yes! `UXSPClient` accepts standard headers, bearer tokens, cookies, and query params:
```python
client.post(
    "https://api.example.com/data",
    json={"metric": 100},
    headers={"Authorization": "Bearer secret-token-xyz"},
    params={"env": "production"}
)
```

### Does `UXSPClient` work without `httpx2` installed?
Yes. If `httpx2` is not installed, `UXSPClient` automatically falls back to Python's standard library `urllib.request`, ensuring zero broken dependencies.

### Where can I learn more?
- 📖 [Web Framework Middlewares Guide (FastAPI, Django, Flask)](./frameworks/fastapi.md)
- 📜 [Formal Protocol Specification](../docs/protocol_specification.md)
- ⚡ [Exact Byte-Level Wire Format Standard](../docs/wire_format.md)
