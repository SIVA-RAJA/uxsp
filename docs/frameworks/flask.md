# Protecting Flask Applications (`uxsp.contrib.flask`)

The `uxsp.contrib.flask` module brings request decryption and response encryption to Flask web services.

---

## 1. Installation

Install UXSP with Flask support:
```bash
pip install uxsp[flask]
```

---

## 2. Using `UXSPFlaskMiddleware`

Wrap your Flask application object with `UXSPFlaskMiddleware`:

```python
from flask import Flask, g, jsonify
import uxsp
from uxsp.contrib.flask import UXSPFlaskMiddleware

server_identity = uxsp.create_identity("Flask Server", role="SERVER")

app = Flask(__name__)
uxsp_mw = UXSPFlaskMiddleware(app, identity=server_identity, require_encryption=True)

@app.route("/api/endpoint", methods=["POST"])
def endpoint():
    # Access decrypted payload attached to Flask g object
    payload = g.uxsp_payload
    sender_id = g.uxsp_sender_id
    
    return jsonify({"status": "received", "data": payload})

if __name__ == "__main__":
    app.run(port=5000)
```

---

## 3. Protecting Routes with `@protect_flask` Decorator

Protect individual Flask routes using the `@protect_flask` decorator:

```python
from flask import Flask, jsonify
import uxsp
from uxsp.contrib.flask import protect_flask

app = Flask(__name__)
server_identity = uxsp.create_identity("Flask Server", role="SERVER")

@app.route("/api/protected", methods=["POST"])
@protect_flask(server_identity=server_identity)
def protected_route():
    payload = g.uxsp_payload
    return jsonify({"result": "Success", "payload": payload})
```
