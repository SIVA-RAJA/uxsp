# The UXSP Command-Line Interface (CLI)

The UXSP package comes with a powerful Command-Line Interface (`uxsp`). You can run it directly from your terminal.

This tool is incredibly useful for both **Development** and **Production** environments, allowing you to generate keys, debug connections, and test configurations without writing Python code.

---

## 1. Development: Why the CLI is Useful

When you are developing an app, you need a quick way to create identities for testing. Instead of writing a Python script to generate a key, you can do it in one second via the terminal.

### Generating a New Identity
To create a new identity file for your server:

```bash
# This creates a file called 'server_key.uxsp' protected by 'my_password'
uxsp generate --id "TestServer" --out server_key.uxsp --password "my_password"
```

### Viewing an Identity
If you want to see the public card associated with an identity file (so you can give it to your friends or other servers to connect with you):

```bash
uxsp inspect server_key.uxsp --password "my_password"
```

This will print out the raw JSON of the Public Card, which you can then copy and paste into your test scripts!

---

## 2. Production: Why the CLI is Useful

In production, you often need to handle key rotation, revoke compromised peers, or verify that the system is properly configured without bringing the server down.

### Key Rotation via CLI
If you suspect your keys might be compromised, you can rotate them immediately:

```bash
uxsp rotate --in old_server_key.uxsp --out new_server_key.uxsp --password "old_password" --new-password "new_password"
```

This generates a brand new Post-Quantum keypair and a classical keypair, saving them securely in the new file.

### Debugging and Troubleshooting
Sometimes, you might receive an encrypted package and you want to decrypt it manually to see what's inside, bypassing your application logic. The CLI might offer decryption commands in future updates to help diagnose production issues without writing custom scripts.

The UXSP CLI solves the problem of "How do I manage these complex Post-Quantum keys safely?" by providing a familiar, easy-to-use terminal interface.
