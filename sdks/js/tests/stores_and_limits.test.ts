import test from "node:test";
import assert from "node:assert";
import {
  Identity,
  MemoryKeyStore,
  LocalStorageKeyStore,
  MemoryNonceStore,
  StorageNonceStore,
  RateLimiter,
  SlidingRateLimiter,
  RateLimitExceededError,
  DuplicatePeerError,
} from "../dist/index.js";

test("MemoryKeyStore & LocalStorageKeyStore", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");
  const cardA = alice.publicCard();
  const cardB = bob.publicCard();

  const ks = new MemoryKeyStore();
  ks.put(cardA);
  ks.put(cardB);

  assert.strictEqual(ks.size, 2);
  assert.strictEqual(ks.has(cardA.entity_id), true);
  assert.strictEqual(ks.get(cardA.entity_id)?.name, "Alice");
  assert.strictEqual(ks.list().length, 2);

  // Duplicate peer without overwrite
  assert.throws(() => {
    ks.put(cardA, false);
  }, DuplicatePeerError);

  assert.strictEqual(ks.delete(cardA.entity_id), true);
  assert.strictEqual(ks.has(cardA.entity_id), false);

  // LocalStorageKeyStore memory fallback
  const lks = new LocalStorageKeyStore();
  lks.put(cardB);
  assert.strictEqual(lks.has(cardB.entity_id), true);
  assert.strictEqual(lks.get(cardB.entity_id)?.name, "Bob");
});

test("MemoryNonceStore & StorageNonceStore", async () => {
  const store = new MemoryNonceStore(100);

  assert.strictEqual(store.isSeen("nonce-1"), false);
  assert.strictEqual(store.markUsed("nonce-1", 10), true);
  assert.strictEqual(store.isSeen("nonce-1"), true);

  // Replay
  assert.strictEqual(store.markUsed("nonce-1", 10), false);

  // StorageNonceStore
  const sStore = new StorageNonceStore();
  assert.strictEqual(sStore.markUsed("s-nonce-1", 10), true);
  assert.strictEqual(sStore.isSeen("s-nonce-1"), true);
  assert.strictEqual(sStore.markUsed("s-nonce-1", 10), false);
});

test("RateLimiter - Token Bucket & Sliding Window", async () => {
  // Token Bucket
  const limiter = new RateLimiter(2, 10);
  limiter.check("peer-1");
  limiter.check("peer-1");
  assert.strictEqual(limiter.isAllowed("peer-1"), false);
  assert.throws(() => {
    limiter.check("peer-1");
  }, RateLimitExceededError);

  // Sliding Rate Limiter
  const sliding = new SlidingRateLimiter(2, 60);
  sliding.check("peer-2");
  sliding.check("peer-2");
  assert.strictEqual(sliding.isAllowed("peer-2"), false);
  assert.throws(() => {
    sliding.check("peer-2");
  }, RateLimitExceededError);

  sliding.reset("peer-2");
  assert.strictEqual(sliding.isAllowed("peer-2"), true);
});
