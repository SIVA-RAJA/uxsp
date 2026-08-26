# Web & Frontend Interoperability Guide (For JS/TS Developers)

UXSP provides client interoperability for browser interfaces through Draft-07 JSON Schemas, a TypeScript/JavaScript SDK (`@siva_raja/uxsp`), and a WebAssembly/Pyodide browser runtime bridge.

---

## 1. JavaScript / TypeScript Browser SDK (`sdks/js/` & `@siva_raja/uxsp`)

The `@siva_raja/uxsp` SDK allows browser clients to create, parse, serialize, and validate UXSP wire format packages.

### Installation
```bash
npm install @siva_raja/uxsp
```

### Usage Example
```typescript
import { UXSPClient } from '@siva_raja/uxsp';

// Initialize UXSP Client
const client = new UXSPClient({
  name: 'BrowserClient',
  role: 'CLIENT'
});

// Get browser public card JSON to share with backend
const publicCardJson = client.getPublicCardJson();

// Build API request headers
const headers = client.buildHeaders();
// Headers: { "X-UXSP-Package": "1", "X-UXSP-Sender": "client_entity_id" }
```

---

## 2. Draft-07 JSON Schemas (`uxsp/schema/` & `uxsp.schema`)

UXSP defines formal JSON Schema specifications for wire payloads:

- **`envelope_schema.json`**: Schema for sealed `UXSP-1` post-quantum hybrid envelopes.
- **`package_schema.json`**: Schema for single-envelope and chunked `SecurePackage` payloads.
- **`public_card_schema.json`**: Schema for `UXSP-PUBCARD-1` public cards.

### Validating Schemas in Python
```python
import uxsp.schema as schema

# Validate incoming JSON dictionary against schema
schema.validate_package(package_dict)
schema.validate_envelope(envelope_dict)
schema.validate_public_card(card_dict)
```

---

## 3. WebAssembly & Pyodide Browser Bridge (`uxsp.wasm` / `uxsp.pyodide`)

To run complete cryptographic operations inside browser Web Workers without JavaScript reimplementation, UXSP provides `PyodideUXSPBridge`:

```python
from uxsp.wasm import PyodideUXSPBridge
from uxsp.pyodide import js_seal_text, js_open_text

# Initialize bridge in Pyodide Web Worker
bridge = PyodideUXSPBridge(name="WorkerClient")

# Seal text in browser worker
pkg_json = bridge.seal_text("Secret from browser worker", recipient_card_json)

# Open text in browser worker
decrypted_text = bridge.open_text(pkg_json, sender_card_json)
```
