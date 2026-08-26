# Protecting FastAPI Applications (`uxsp.contrib.fastapi`)

The `uxsp.contrib.fastapi` module provides automatic middleware and endpoint protection decorators to secure FastAPI applications with 1 line of code.

---

## 1. Installation

Install UXSP with FastAPI support:
```bash
pip install uxsp[fastapi]
```

---

## 2. Using `UXSPFastAPIMiddleware`

`UXSPFastAPIMiddleware` automatically decrypts incoming encrypted HTTP request bodies and encrypts outgoing responses:

```python
from fastapi import FastAPI, Request
import uxsp
from uxsp.contrib.fastapi import UXSPFastAPIMiddleware

# 1. Initialize Server Identity
server_identity = uxsp.create_identity("FastAPI Server", role="SERVER")

app = FastAPI()

# 2. Add UXSP Middleware
app.add_middleware(
    UXSPFastAPIMiddleware,
    identity=server_identity,
    require_encryption=True,          # Reject unencrypted requests with HTTP 400
    exclude_paths=["/docs", "/health"] # Unprotected public endpoints
)

@app.post("/api/data")
async def secure_endpoint(request: Request):
    # Access decrypted payload attached to request.state
    payload = request.state.uxsp_payload
    sender_id = request.state.uxsp_sender_id
    
    return {"status": "success", "echo": payload, "processed_by": server_identity.entity_id}
```

---

## 3. Protect Endpoints with `@protect` Decorator

Use `@protect` to protect specific endpoints individually:

```python
from fastapi import FastAPI, Request
import uxsp
from uxsp.contrib.fastapi import protect

app = FastAPI()
server_identity = uxsp.create_identity("FastAPI Server", role="SERVER")

@app.post("/api/sensitive")
@protect(server_identity=server_identity)
async def sensitive_route(request: Request):
    # Endpoint payload is automatically decrypted
    data = request.state.uxsp_payload
    return {"message": "Protected response", "data": data}
```

---

## 4. Automatic Request Headers

UXSP middleware automatically attaches and validates standard protocol headers:

- **`X-UXSP-Package`**: `"1"` (identifies a UXSP sealed package request).
- **`X-UXSP-Sender`**: Entity ID of the sending client.
- **Response Headers**: Outgoing encrypted responses automatically include `X-UXSP-Package` and `X-UXSP-Sender`.
