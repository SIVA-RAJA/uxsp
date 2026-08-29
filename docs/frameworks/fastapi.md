# FastAPI Middleware & Protection Guide

UXSP provides a native ASGI middleware for FastAPI (and Starlette) that automatically handles request decryption and response encryption using the asynchronous (`uxsp.aio`) engine.

---

## 1. Setting up the Middleware

You add `UXSPFastAPIMiddleware` directly to your FastAPI application.

### Middleware Ordering (CRITICAL)

In FastAPI, middleware is executed in the reverse order of how it is added. If you have CORS middleware or other security middlewares, you typically want UXSP to be the inner-most middleware that handles the body.

```python
from fastapi import FastAPI
from uxsp.contrib.fastapi import UXSPFastAPIMiddleware

app = FastAPI()

# Add UXSP Middleware
app.add_middleware(
    UXSPFastAPIMiddleware,
    require_encryption=False,
    exclude_paths=["/docs", "/openapi.json"]
)
```

By excluding `/docs` and `/openapi.json`, you ensure that your Swagger UI remains accessible!

---

## 2. What happens if I only use the Middleware?

If you only add the middleware:
1. **Encrypted Requests**: Are automatically decrypted. You can access the decrypted data via `request.state.uxsp_payload`.
2. **Plain Text Requests**: Pass through normally.
3. **Responses**: Are encrypted ONLY if the incoming request was encrypted.

---

## 3. The `@protect` Decorator

If you want to absolutely guarantee that an endpoint is only accessible via Post-Quantum encryption, you must use the `@protect` decorator.

### Why do programmers need to use decorators?
The middleware parses the request, but it is "opportunistic" by default. If a hacker hits your `/secure_data` endpoint with a plain JSON POST, the middleware will let it through. 

The `@protect` decorator enforces a strict rule: *"If this request was not decrypted by UXSP, throw an HTTP 400 Error immediately and do not execute the route."* It also guarantees that the response returned by the route will be encrypted.

### How and Where to Use It
Place it above your FastAPI route definition.

```python
from fastapi import FastAPI, Request
from uxsp.contrib.fastapi import protect

app = FastAPI()
app.add_middleware(UXSPFastAPIMiddleware)

@app.post("/secure_data")
@protect()  # Enforce UXSP here!
async def secure_endpoint(request: Request):
    # The payload is guaranteed to be decrypted and verified
    data = request.state.uxsp_payload
    
    # Do some processing...
    
    # Return a normal dictionary. The middleware will catch this
    # on the way out and encrypt it before it leaves the server!
    return {"status": "success", "received": data}
```
