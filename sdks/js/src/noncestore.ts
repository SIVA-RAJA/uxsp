/**
 * UXSP Nonce Store Implementations
 *
 * Provides in-memory and web-storage backed replay attack protection.
 */

export abstract class NonceStore {
  abstract markUsed(nonce: string, ttlSeconds?: number): boolean | Promise<boolean>;
  abstract isSeen(nonce: string): boolean | Promise<boolean>;
  abstract clear(): void | Promise<void>;
}

export class MemoryNonceStore extends NonceStore {
  private seen = new Map<string, number>();
  private maxEntries: number;

  constructor(maxEntries: number = 100_000) {
    super();
    this.maxEntries = maxEntries;
  }

  private evictExpired(now: number): void {
    for (const [nonce, expiresAt] of this.seen.entries()) {
      if (now >= expiresAt) {
        this.seen.delete(nonce);
      } else {
        break;
      }
    }
  }

  markUsed(nonce: string, ttlSeconds: number = 90): boolean {
    const now = Date.now();
    this.evictExpired(now);

    const existing = this.seen.get(nonce);
    if (existing !== undefined && now < existing) {
      return false; // Replay detected
    }

    while (this.seen.size >= this.maxEntries) {
      const oldestKey = this.seen.keys().next().value;
      if (oldestKey !== undefined) {
        this.seen.delete(oldestKey);
      } else {
        break;
      }
    }

    this.seen.set(nonce, now + ttlSeconds * 1000);
    return true;
  }

  isSeen(nonce: string): boolean {
    const now = Date.now();
    const expiresAt = this.seen.get(nonce);
    if (expiresAt === undefined) return false;
    if (now >= expiresAt) {
      this.seen.delete(nonce);
      return false;
    }
    return true;
  }

  clear(): void {
    this.seen.clear();
  }

  get size(): number {
    return this.seen.size;
  }
}

export class StorageNonceStore extends NonceStore {
  private prefix: string;
  private storage: Storage | null = null;
  private memoryFallback: MemoryNonceStore;

  constructor(storageType: "session" | "local" = "session", prefix: string = "uxsp:nonce:") {
    super();
    this.prefix = prefix;
    this.memoryFallback = new MemoryNonceStore();
    try {
      if (typeof window !== "undefined") {
        this.storage = storageType === "local" ? window.localStorage : window.sessionStorage;
      }
    } catch {
      this.storage = null;
    }
  }

  markUsed(nonce: string, ttlSeconds: number = 90): boolean {
    if (!this.storage) {
      return this.memoryFallback.markUsed(nonce, ttlSeconds);
    }
    const key = this.prefix + nonce;
    const now = Date.now();
    const raw = this.storage.getItem(key);
    if (raw) {
      const expiresAt = parseInt(raw, 10);
      if (now < expiresAt) return false; // Replay
    }
    this.storage.setItem(key, (now + ttlSeconds * 1000).toString());
    return true;
  }

  isSeen(nonce: string): boolean {
    if (!this.storage) {
      return this.memoryFallback.isSeen(nonce);
    }
    const key = this.prefix + nonce;
    const now = Date.now();
    const raw = this.storage.getItem(key);
    if (!raw) return false;
    const expiresAt = parseInt(raw, 10);
    if (now >= expiresAt) {
      this.storage.removeItem(key);
      return false;
    }
    return true;
  }

  clear(): void {
    if (!this.storage) {
      this.memoryFallback.clear();
      return;
    }
    const keysToRemove: string[] = [];
    for (let i = 0; i < this.storage.length; i++) {
      const k = this.storage.key(i);
      if (k && k.startsWith(this.prefix)) {
        keysToRemove.push(k);
      }
    }
    for (const k of keysToRemove) {
      this.storage.removeItem(k);
    }
  }
}
