# Flask Middleware & Protection Guide

UXSP provides a WSGI middleware for Flask that transparently decrypts incoming requests and encrypts outbound responses.

---

## 1. Setting up the Middleware

In Flask, you wrap your WSGI application with `UXSPFlaskMiddleware`.

### Middleware Ordering (CRITICAL)

If you are using other WSGI middlewares (like Werkzeug ProxyFix), you should wrap the Flask app with UXSP *after* those, so UXSP sits closest to your application logic.

```python
from flask import Flask
from uxsp.contrib.flask import UXSPFlaskMiddleware

app = Flask(__name__)

# Wrap the WSGI app
app.wsgi_app = UXSPFlaskMiddleware(
    app.wsgi_app,
    require_encryption=False,
    exclude_paths=["/static/"]
)
```

---

## 2. What happens if I only use the Middleware?

If you just wrap the `wsgi_app`:
1. **Encrypted Requests**: The middleware intercepts the raw WSGI stream, decrypts it, and passes the plain data to Flask. Flask behaves as if it received standard JSON.
2. **Plain Text Requests**: Pass through to Flask unmodified.
3. **Responses**: The middleware will catch Flask's response and encrypt it *only* if the incoming request was a valid UXSP package.

---

## 3. The `@protect_route` Decorator

To strictly enforce encryption on a specific Flask route, use the `@protect_route` (or `@protect_flask`) decorator.

### Why do programmers need to use decorators?
Without the decorator, a route can still be accessed via plain text (unless you set `require_encryption=True` globally, which breaks static files or health checks). 

The `@protect_route` decorator checks if the current Flask environment was flagged by the UXSP middleware. If it wasn't, it aborts the request before your code runs.

### How and Where to Use It
Place it right below your `@app.route` decorator!

```python
from flask import Flask, request, jsonify
from uxsp.contrib.flask import protect_route, UXSPFlaskMiddleware

app = Flask(__name__)
app.wsgi_app = UXSPFlaskMiddleware(app.wsgi_app)

@app.route("/secure_data", methods=["POST"])
@protect_route()  # Enforce UXSP here!
def secure_endpoint():
    # Because of @protect_route, we know request.json is safe!
    # (The middleware replaced the encrypted body with the decrypted JSON)
    data = request.json
    
    # Process data...
    
    # Return a normal Flask JSON response. The middleware will intercept
    # this and encrypt it for the client.
    return jsonify({"status": "success", "received": data})
```
