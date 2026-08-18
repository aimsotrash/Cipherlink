/**
 * In-process token-bucket rate limiter.
 *
 * Applied most aggressively to registration and authentication, which are the
 * routes where an attacker would grind at password proofs or challenge
 * signatures. It is per-process and per-IP: adequate for a single instance,
 * and explicitly not a substitute for an edge rate limiter in a real
 * deployment (noted in DEVELOPMENT.md).
 */
export interface RateLimiterOptions {
  /** Maximum burst. */
  readonly capacity: number;
  readonly refillPerSecond: number;
  /** Drop idle buckets after this long, so the map cannot grow without bound. */
  readonly idleEvictionMs?: number;
}

interface Bucket {
  tokens: number;
  updatedAt: number;
}

export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly idleEvictionMs: number;
  private lastSweep = 0;

  constructor(
    private readonly options: RateLimiterOptions,
    private readonly now: () => number = Date.now,
  ) {
    this.idleEvictionMs = options.idleEvictionMs ?? 10 * 60 * 1000;
  }

  /** Consume one token. Returns false when the caller should be rejected. */
  take(key: string, cost = 1): boolean {
    const now = this.now();
    this.sweep(now);

    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: this.options.capacity, updatedAt: now };
      this.buckets.set(key, bucket);
    } else {
      const elapsedSeconds = (now - bucket.updatedAt) / 1000;
      bucket.tokens = Math.min(
        this.options.capacity,
        bucket.tokens + elapsedSeconds * this.options.refillPerSecond,
      );
      bucket.updatedAt = now;
    }

    if (bucket.tokens < cost) return false;
    bucket.tokens -= cost;
    return true;
  }

  private sweep(now: number): void {
    if (now - this.lastSweep < this.idleEvictionMs) return;
    this.lastSweep = now;
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.updatedAt > this.idleEvictionMs) this.buckets.delete(key);
    }
  }
}
