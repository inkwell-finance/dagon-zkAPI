import { createHash, randomBytes } from "node:crypto";

export const DEFAULT_LIMITS = {
  join: { max: 12, windowMs: 3_600_000 },
  poll: { max: 900, windowMs: 600_000 },
  download: { max: 30, windowMs: 600_000 },
  upload: { max: 8, windowMs: 600_000 },
  status: { max: 120, windowMs: 60_000 },
  files: { max: 300, windowMs: 600_000 },
};

/**
 * Fixed-window counters in memory. The client address is only ever held as a salted hash that dies with the process,
 * is never written anywhere and is never logged: it exists to stop one connection hammering the queue.
 */
export class RateLimiter {
  #windows = new Map();
  #salt = randomBytes(16);
  #now;
  #limits;

  constructor({ now, limits = DEFAULT_LIMITS }) {
    this.#now = now;
    this.#limits = limits;
  }

  key(address) {
    return createHash("sha256").update(this.#salt).update(address).digest("hex").slice(0, 24);
  }

  /** @returns {number} 0 when allowed, otherwise the seconds until the window resets */
  check(bucket, key) {
    const { max, windowMs } = this.#limits[bucket];
    const now = this.#now();
    if (this.#windows.size > 10_000) {
      for (const [k, w] of this.#windows) if (w.resetAt <= now) this.#windows.delete(k);
    }
    const id = `${bucket}:${key}`;
    let window = this.#windows.get(id);
    if (!window || window.resetAt <= now) {
      window = { count: 0, resetAt: now + windowMs };
      this.#windows.set(id, window);
    }
    if (window.count >= max) return Math.max(1, Math.ceil((window.resetAt - now) / 1000));
    window.count++;
    return 0;
  }
}
