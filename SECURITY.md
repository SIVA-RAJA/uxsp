# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes — receives security fixes |
| < 0.1.0 | ❌ No |

---

## Reporting a SECURITY VULNERABILITY (authentication bypass, replay attack, key compromise, etc.)

**Do NOT open a public issue.** Please report security vulnerabilities privately.

- **Email privately:** sivaraja5401@gmail.com
- **Subject line:** Use `[UXSP SECURITY] <one-line summary>`
- **Workflow:** We fix first, then disclose together.

Include as much of the following as you can in your report:
- A description of the vulnerability and its impact
- The affected component(s) and version(s)
- Steps to reproduce or a minimal proof-of-concept
- Your suggested fix, if you have one (optional but appreciated)

## Reporting a normal BUG (wrong output, crashes, test failures)

For standard bugs that do not have security implications:
- **Open a GitHub issue:** Go to the public repository and open an issue normally.
- **Submit a pull request:** Contributions are welcome!

### What to expect

| Step | Timeline |
|------|----------|
| Acknowledgement | Within 48 hours |
| Initial triage and severity assessment | Within 5 business days |
| Fix developed and reviewed | Depends on severity (see below) |
| Coordinated disclosure | After fix is released |

**Severity targets:**

| Severity | Example | Target fix time |
|----------|---------|-----------------|
| Critical | Remote key compromise, authentication bypass | 7 days |
| High | Session forgery, replay bypass, DoS via crash | 14 days |
| Medium | Information leak, degraded replay protection | 30 days |
| Low | Minor timing side-channel, cosmetic issue | 60 days |

We will credit you in the release notes unless you prefer to remain anonymous.

---

## Security Design

This section documents the threat model and security properties that UXSP is
designed to provide. It helps researchers understand what is in scope.

### Cryptographic primitives

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Key exchange (classical) | X25519 (ECDH) | `cryptography` (OpenSSL) |
| Key exchange (post-quantum) | ML-KEM-768 (CRYSTALS-Kyber) | `liboqs` |
| Digital signature (classical) | Ed25519 | `cryptography` (OpenSSL) |
| Digital signature (post-quantum) | ML-DSA-65 (CRYSTALS-Dilithium) | `liboqs` |
| Symmetric encryption | AES-256-GCM | `cryptography` (OpenSSL) |
| Key derivation | HKDF-SHA256 | `cryptography` |
| Password hashing | Argon2id (64 MB, t=3, p=4) | `argon2-cffi` |
| Nonce generation | `os.urandom(16)` — 128-bit | Python stdlib |

All asymmetric operations use a **hybrid classical + post-quantum** scheme.
Both layers must verify independently; failure of either rejects the message.
This means UXSP is secure against both classical adversaries today and
quantum adversaries in the future (harvest-now-decrypt-later resistance).

### Threat model

UXSP assumes the following attacker capabilities and provides these guarantees:

| Attacker capability | UXSP defence |
|---------------------|--------------|
| Reads all network traffic | AES-256-GCM encryption with per-message nonces. Ciphertext reveals nothing about plaintext. |
| Records traffic for future quantum decryption | Hybrid KEM: ML-KEM-768 key material cannot be broken even with a fault-tolerant quantum computer. |
| Replays a captured envelope | Timestamp window (configurable, default 5 min) + `envelope_nonce` checked against a persistent `NonceStore`. Both must pass. |
| Replays a captured HELLO/ACK handshake message | `session_id`-scoped nonce checked in `NonceStore` before any expensive KEM operation. |
| Sends a forged envelope claiming to be Alice | Ed25519 + ML-DSA-65 dual signature over all envelope fields including ciphertext, nonces, sender/recipient IDs, and version. Forgery requires breaking both. |
| Man-in-the-middle during handshake | Responder's ACK includes an HMAC proof of the shared secret derived from the initiator's KEM ciphertext. The initiator verifies this before activating the session. |
| Injects or reorders session messages | Per-session sequence numbers enforced with strict ordering. Replay or skip of any sequence number raises `SessionReorderError`. |
| Spoofs the identity of a card holder | Cards are signed by a `TrustAnchor`. `TrustStore.verify()` checks issuer trust, time validity, and dual signature before accepting any card. |
| DoS via oversized payloads | `Envelope.MAX_BYTES` (64 KB default) and `UXSPFrame` size limit (1 MB) enforce rejection before any crypto is attempted. |
| DoS via handshake flooding | `RateLimiter` / `SlidingRateLimiter` enforced per `initiator_id` before any PQC operation. |
| DoS via unauthenticated CLOSE frame | `handle_close()` requires the frame to carry the correct `session_id`; frames without it are silently ignored. |
| Nonce store flood (eviction replay) | `MemoryNonceStore` uses a **fail-closed** strategy: when at capacity it cleans up expired entries, and if still full it raises `UXSPStoreError` rather than silently evicting live nonces. |

### What UXSP does NOT protect against

- **Compromised endpoints.** If an attacker controls the process, filesystem, or memory of either peer, all bets are off.
- **Weak passwords on saved identities.** `Identity.save()` derives an AES-256-GCM key via Argon2id from the password you supply. A weak password means a weak file.
- **`MemoryNonceStore` in production.** This store is lost on process restart. An attacker can replay pre-restart envelopes after a reboot. Use `RedisNonceStore` or `PostgresNonceStore` for production deployments.
- **Physical side channels.** UXSP does not implement constant-time comparisons beyond what `cryptography` and `liboqs` provide internally.
- **Key revocation.** Version 0.1 has no online revocation mechanism. A compromised private key must be handled out-of-band (rotate the `TrustAnchor`, re-issue cards).

---

## Known Security-Relevant Decisions

These are deliberate design choices that security reviewers commonly ask about.

**Why hybrid (classical + PQC) rather than PQC-only?**
ML-KEM-768 and ML-DSA-65 are NIST-standardised but relatively new. Classical
X25519/Ed25519 are well-audited and battle-tested. The hybrid approach means
UXSP degrades to classical security (not zero security) if a PQC primitive is
later found to be weak.

**Why AES-256-GCM and not ChaCha20-Poly1305?**
Both are secure choices. AES-NI hardware acceleration is available on virtually
all modern server CPUs, and the `cryptography` library uses OpenSSL's vetted
implementation. ChaCha20-Poly1305 support may be added in a future version.

**Why HKDF and not a direct KDF output?**
The hybrid key exchange produces two independent shared secrets (X25519 and
ML-KEM). HKDF mixes them with a context-specific `info` label into a single
key. This ensures that a partial break of one primitive does not directly yield
the session key.

**Why fail-closed on nonce store capacity?**
A fail-open strategy (evict oldest nonces when full) allows an attacker to flood
the store with fresh nonces, evict older legitimate ones from memory, and then
replay the evicted nonces. Fail-closed means replay protection is maintained
even under attack; operators get a clear error instead of a silent security
regression.

**Why is `replay_guard` a required argument to `open_from()`?**
Making it optional with a default of `None` would let developers accidentally
deploy without replay protection. UXSP treats this as a hard error to prevent
insecure-by-default usage.

---

## Dependency Security

UXSP's security relies on the following upstream libraries. Known CVEs in these
libraries may affect UXSP even without changes to UXSP itself.

| Library | Role | Where to track CVEs |
|---------|------|---------------------|
| `cryptography` | AES-GCM, X25519, Ed25519, HKDF | [PyPI advisory database](https://pypi.org/project/cryptography/) |
| `liboqs` / `liboqs-python` | ML-KEM-768, ML-DSA-65 | [OQS Security page](https://github.com/open-quantum-safe/liboqs/security) |
| `argon2-cffi` | Password hashing (Argon2id) | [PyPI advisory database](https://pypi.org/project/argon2-cffi/) |

We track these and will issue a new UXSP release whenever a security-relevant
upstream update is required.

---

## Responsible Disclosure Policy

We follow coordinated disclosure. Once a fix is ready and released:

1. A `CHANGELOG` entry is published describing the vulnerability, its severity, and the fix (without a working exploit).
2. The reporter is credited by name or handle, unless they prefer anonymity.
3. If the vulnerability is rated High or Critical and has been exploited in the wild, we will notify known users directly and file a CVE.

We ask reporters to give us the target fix time listed above before publishing
their own writeup. We will not take legal action against good-faith security
researchers acting within this policy.

---

*Last updated: 2026 — UXSP v0.1.2*