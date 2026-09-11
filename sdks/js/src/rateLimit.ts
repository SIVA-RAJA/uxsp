/**
 * UXSP Rate Limiting Implementations
 *
 * Protects UXSP servers and responder endpoints against denial-of-service and brute-force attacks.
 */

export class RateLimitExceededError extends Error {
  constructor(message: string = "Rate limit exceeded. Try again later.") {
    super(message);
    this.name = "RateLimitExceededError";
  }
}

export abstract class RateLimiterBase {
  abstract check(key: string): void;
  abstract isAllowed(key: string): boolean;
  abstract reset(key?: string): void;
}

/**
 * Token Bucket Rate Limiter
 */
export class RateLimiter extends RateLimiterBase {
  public capacity: number;
  public refillRatePerSec: number;
  private buckets = new Map<string, { tokens: number; lastRefill: number }>();

  constructor(capacity: number = 10, refillRatePerSec: number = 2.0) {
    super();
    if (capacity <= 0 || refillRatePerSec <= 0) {
      throw new Error("capacity and refillRatePerSec must be positive");
    }
    this.capacity = capacity;
    this.refillRatePerSec = refillRatePerSec;
  }

  private refill(bucket: { tokens: number; lastRefill: number }, now: number): void {
    const elapsed = (now - bucket.lastRefill) / 1000;
    if (elapsed > 0) {
      bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsed * this.refillRatePerSec);
      bucket.lastRefill = now;
    }
  }

  isAllowed(key: string): boolean {
    const now = Date.now();
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: this.capacity, lastRefill: now };
      this.buckets.set(key, bucket);
    }
    this.refill(bucket, now);

    if (bucket.tokens >= 1.0) {
      bucket.tokens -= 1.0;
      return true;
    }
    return false;
  }

  check(key: string): void {
    if (!this.isAllowed(key)) {
      throw new RateLimitExceededError(`Rate limit exceeded for peer '${key}'.`);
    }
  }

  reset(key?: string): void {
    if (key !== undefined) {
      this.buckets.delete(key);
    } else {
      this.buckets.clear();
    }
  }
}

/**
 * Sliding Window Rate Limiter
 */
export class SlidingRateLimiter extends RateLimiterBase {
  public maxRequests: number;
  public windowSeconds: number;
  private requests = new Map<string, number[]>();

  constructor(maxRequests: number = 60, windowSeconds: number = 60) {
    super();
    if (maxRequests <= 0 || windowSeconds <= 0) {
      throw new Error("maxRequests and windowSeconds must be positive");
    }
    this.maxRequests = maxRequests;
    this.windowSeconds = windowSeconds;
  }

  isAllowed(key: string): boolean {
    const now = Date.now();
    const windowMs = this.windowSeconds * 1000;
    const cutoff = now - windowMs;

    let timestamps = this.requests.get(key);
    if (!timestamps) {
      timestamps = [];
      this.requests.set(key, timestamps);
    }

    // Filter out timestamps outside window
    const valid = timestamps.filter(t => t > cutoff);
    if (valid.length < this.maxRequests) {
      valid.push(now);
      this.requests.set(key, valid);
      return true;
    }

    this.requests.set(key, valid);
    return false;
  }

  check(key: string): void {
    if (!this.isAllowed(key)) {
      throw new RateLimitExceededError(`Rate limit exceeded for peer '${key}'.`);
    }
  }

  reset(key?: string): void {
    if (key !== undefined) {
      this.requests.delete(key);
    } else {
      this.requests.clear();
    }
  }
}

