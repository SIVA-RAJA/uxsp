# Replay Protection and NonceStores

Security is not just about encrypting data. It is also about ensuring that an attacker cannot capture a valid encrypted message and resend it later to trick your server.

This type of attack is called a **Replay Attack**. For example, if you send an encrypted message that says "Pay Bob $100", an attacker could capture that message and send it 10 more times to drain your account!

## How UXSP Prevents Replay Attacks

Every message sent by UXSP contains two things:
1. **A Timestamp**: If a message is too old (e.g., older than 5 minutes), UXSP instantly rejects it.
2. **A Nonce (Number Used Once)**: A unique, random serial number.

When UXSP receives a message, it checks a database called a **NonceStore** to see if it has seen that specific Nonce before. If it has, it rejects the message as a Replay Attack.

---

## 1. Types of NonceStores

UXSP provides several out-of-the-box NonceStores. You must choose the right one for your application.

### `MemoryNonceStore` (For Development)
This stores nonces in your computer's RAM. It is extremely fast but if your server crashes or restarts, it forgets all the nonces!
*Do not use this in production.*

### `RedisNonceStore` (For Fast Production)
Stores nonces in a Redis database. It is incredibly fast and allows multiple servers (like in a load-balanced API) to share the same nonce list.

### `PostgresNonceStore` (For Durable Production)
Stores nonces in a PostgreSQL database table. It is slightly slower than Redis, but it is 100% durable. If the power goes out, the nonces are permanently saved.

### `SlidingWindowNonceStore`
A special type of Redis store that strictly enforces expiration times down to the millisecond using Redis Sorted Sets.

### `TieredNonceStore` (The Best of Both Worlds)
This combines Redis and Postgres! It checks Redis first for ultimate speed. If Redis crashes, it falls back to Postgres. This is the recommended configuration for enterprise apps.

---

## 2. Asynchronous NonceStores (`AsyncNonceStore`)

If you are using the Asynchronous high-level APIs (`uxsp.aio`) for frameworks like FastAPI, you must use an Asynchronous NonceStore so that checking the database doesn't block your server.

UXSP provides:
* **`AsyncRedisNonceStore`**: The native async version of the Redis store.

*(Note: We provide async abstractions via `AsyncNonceStore`, and you can implement custom async database checks if needed).*

---

## 3. How to Integrate a NonceStore

Integrating a NonceStore is incredibly easy. You just configure it once when your application starts, and the High-Level APIs (like `Send` and `Receive`), as well as the Web Middlewares, will automatically use it!

### Example: Connecting a Redis NonceStore

```python
import redis
from uxsp.secure import configure
from uxsp.storage.noncestore import RedisNonceStore

# 1. Connect to Redis
redis_client = redis.Redis(host='localhost', port=6379)

# 2. Create the NonceStore
my_nonce_store = RedisNonceStore(redis_client)

# 3. Tell UXSP to use it!
configure(
    nonce_store=my_nonce_store
)

# Now, every time you call ReceiveText(), it will automatically check Redis!
```

### Example: Connecting an Async Redis NonceStore (For FastAPI)

```python
import redis.asyncio as redis
from uxsp.aio import reset_context, set_identity
from uxsp.storage.noncestore import AsyncRedisNonceStore

async def startup_event():
    # 1. Connect to Async Redis
    redis_client = await redis.from_url("redis://localhost")
    
    # 2. Create the Async NonceStore
    async_store = AsyncRedisNonceStore(redis_client)
    
    # 3. Tell UXSP's async engine to use it!
    # (In the aio module, you configure the context differently)
    import uxsp.secure
    uxsp.secure._GLOBAL_CONTEXT.nonce_store = async_store
```

By configuring the NonceStore, you ensure your streaming apps, CCTV endpoints, and Web Middlewares are completely immune to Replay Attacks!
