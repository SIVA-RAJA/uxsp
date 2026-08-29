# Web Frontend Integration (JavaScript / TypeScript)

A major feature of UXSP is that it doesn't just encrypt data between backend servers. It can encrypt data **directly in the user's browser** before it even touches the network!

If a hacker intercepts the network traffic between a user's laptop and your server, they will only see AES-GCM encrypted gibberish.

---

## 1. The `@siva_raja/uxsp` NPM Package

We provide a companion JavaScript/TypeScript package. It uses WebAssembly (WASM) to run the exact same Post-Quantum cryptography algorithms in the browser.

### Installation
You can install it in your React, Vue, Angular, or vanilla JS project:

```bash
npm install @siva_raja/uxsp
```

---

## 2. Protecting Data in the Frontend

Imagine you are building a login page. Normally, the user types their password, and your frontend sends that password to the backend. Even over HTTPS, advanced attackers might find ways to intercept this.

With UXSP, you can encrypt the password in the frontend!

### Example: Encrypting a Form Submission

```javascript
import { SecureContext, SendJSON } from '@siva_raja/uxsp';

// 1. Load your Backend Server's Public Card
// (You usually fetch this once when the app loads)
const serverCard = { ... }; // JSON of the server's public card

async function submitLogin(username, password) {
  const loginData = { username, password };

  // 2. Encrypt the data BEFORE sending it over the network!
  const encryptedPackage = await SendJSON(loginData, serverCard);

  // 3. Send the encrypted package to your API
  const response = await fetch('https://api.yourwebsite.com/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(encryptedPackage)
  });

  const result = await response.json();
  console.log("Response:", result);
}
```

Because the data is encrypted in the frontend, it travels across the internet fully protected by Post-Quantum cryptography. When it reaches your server, your backend UXSP Middleware will automatically decrypt it!
