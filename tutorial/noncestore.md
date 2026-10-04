# Replay Protection and NonceStores

Security is not just about encrypting data. It is also about ensuring that an adversary cannot capture a valid encrypted payload off the wire and resend it later to fool your server into repeating an action.

This type of exploit is known as a **Replay Attack**. For example, if you authorize an encrypted payment instruction *"Transfer $500 to Bob"*, an eavesdropper cannot decrypt the payload, but without replay protection, they could repeat the identical encrypted request 100 times to drain the account!

```mermaid
flowchart TD
    MSG["Incoming UXSP Encrypted Envelope"] --> TIME_CHK{"1. Check Message Timestamp (T_msg)<br/>Age = T_local - T_msg"}
    
    TIME_CHK -->|"Age > 300s"| REJ_EXP["Reject with ENVELOPE_EXPIRED"]
    TIME_CHK -->|"Age < -30s"| REJ_SKEW["Reject with ENVELOPE_CLOCK_SKEW_EXCEEDED"]
    
    TIME_CHK -->|"Valid Window (-30s <= Age <= 300s)"| NONCE_CHK{"2. Check NonceStore<br/>envelope:nonce"}
    
    NONCE_CHK -->|"Nonce already exists"| REJ_REP["Reject with REPLAY_ATTACK_DETECTED<br/>(Drop & Log Security Alert)"]
    NONCE_CHK -->|"Nonce is fresh"| RECORD["3. Record Nonce with TTL (330s)"]
    
    RECORD --> DECRYPT["4. Proceed to Cryptographic Decryption<br/>& Signature Verification"]
```

---

## 1. How UXSP Enforces Replay Defense

UXSP combines two layers of defense:

1. **Strict Timestamp Bounding**:
   - Every envelope contains an authenticated integer Unix timestamp ($T_{\text{msg}}$).
   - Maximum allowable message age: **300 seconds (5 minutes)**.
   - Maximum allowable clock skew: **30 seconds**.
   - If an incoming message is outside this window, it is dropped before attempting database queries.

2. **Durable Nonce Tracking (`NonceStore`)**:
   - Every envelope includes a 128-bit cryptographically random `envelope_nonce`.
   - Before executing decryption, UXSP checks if this nonce has been recorded.
   - Nonces are stored with a Time-To-Live (TTL) matching the freshness window (330 seconds), ensuring memory does not grow unbounded while guaranteeing 100% replay immunity.

---

## 2. Available NonceStore Implementations

UXSP includes pluggable storage backends tailored for different operational scales:

| Store | Backend | Best For | Persistence |
| :--- | :--- | :--- | :--- |
| **`MemoryNonceStore`** | Local Process RAM | Unit tests & local development | Volatile (lost on process restart) |
| **`RedisNonceStore`** | Redis Key-Value | High-throughput distributed clusters | In-Memory with optional RDB/AOF |
| **`PostgresNonceStore`** | PostgreSQL Table | Mission-critical financial durability | 100% ACID Durable on disk |
| **`TieredNonceStore`** | Redis L1 + Postgres L2 | Enterprise zero-downtime architectures | High-speed cache with DB fallback |

---

## 3. Practical Usage Examples

### 3.1 `MemoryNonceStore` (Testing & Development)

```python
from uxsp.secure import configure, SendText, ReceiveText
from uxsp.storage.noncestore import MemoryNonceStore
from uxsp.core.identity import Identity

# 1. Initialize in-memory store
noncestore = MemoryNonceStore()

# 2. Configure global context
configure(nonce_store=noncestore)

alice = Identity.create("Alice", role="CLIENT")
bob = Identity.create("Bob", role="SERVER")

# Encrypt package
pkg = SendText("Hello Bob", receiver_card=bob.public_card(), sender_identity=alice)

# First receipt succeeds:
first_read = ReceiveText(pkg, receiver_identity=bob)
print("Decrypted successfully:", first_read)

# Immediate second receipt of IDENTICAL package raises ReplayError:
try:
    ReceiveText(pkg, receiver_identity=bob)
except Exception as e:
    print("Replay Attack Blocked:", type(e).__name__)
```

---

### 3.2 `RedisNonceStore` (Production Distributed Cluster)

When running multiple load-balanced API servers (e.g. Kubernetes pods or Gunicorn workers), nonces must be shared across all instances in real time:

```python
import redis
from uxsp.storage.noncestore import RedisNonceStore
from uxsp.secure import configure

# Connect to Redis
r = redis.Redis(host="redis.prod.internal", port=6379, db=0, decode_responses=False)

# Initialize Redis NonceStore
prod_noncestore = RedisNonceStore(r, prefix="uxsp:nonce:")

# Attach to UXSP
configure(nonce_store=prod_noncestore)
```

Nonces are automatically saved using Redis atomic `SET NX EX 330` commands:
- `NX`: Ensures only the first insertion succeeds (atomic race-condition protection).
- `EX 330`: Automatically purges the nonce from Redis after 330 seconds, maintaining zero maintenance overhead.

---

### 3.3 `PostgresNonceStore` (Enterprise Durability)

For applications requiring audit compliance or environments where Redis is not available, `PostgresNonceStore` stores nonces in a relational database table:

```python
import psycopg2
from uxsp.storage.noncestore import PostgresNonceStore
from uxsp.secure import configure

# Connect to PostgreSQL
conn = psycopg2.connect("postgresql://user:password@pg.internal:5432/app_db")

# PostgresNonceStore automatically initializes the table schema on startup
pg_noncestore = PostgresNonceStore(conn, table_name="uxsp_nonces")

configure(nonce_store=pg_noncestore)
```

The underlying table structure created automatically by UXSP:
```sql
CREATE TABLE IF NOT EXISTS uxsp_nonces (
    nonce VARCHAR(64) PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_uxsp_expires ON uxsp_nonces(expires_at);
```

---

### 3.4 `TieredNonceStore` (L1 Cache + L2 Database)

For mission-critical banking and defense systems, combine both:

```python
import redis
import psycopg2
from uxsp.storage.noncestore import TieredNonceStore, RedisNonceStore, PostgresNonceStore
from uxsp.secure import configure

r = redis.Redis(host="localhost", port=6379)
pg = psycopg2.connect("postgresql://user:pass@localhost:5432/db")

l1 = RedisNonceStore(r)
l2 = PostgresNonceStore(pg)

# Checks Redis first for sub-millisecond lookups.
# If Redis misses or disconnects, checks PostgreSQL.
tiered_store = TieredNonceStore(l1_cache=l1, l2_backend=l2)

configure(nonce_store=tiered_store)
```

---

## 4. Middleware & Client Integration

You can pass your `NonceStore` directly to any web middleware:

```python
# In FastAPI
app.add_middleware(
    UXSPFastAPIMiddleware,
    identity=server_identity,
    noncestore=prod_noncestore
)

# In Flask
uxsp_ext = UXSPFlaskMiddleware(
    app,
    identity=server_identity,
    noncestore=prod_noncestore
)
```

With a durable `NonceStore` active, every API endpoint and streaming pipeline is completely immune to replay attacks, reflection attacks, and duplicate transaction submission.
