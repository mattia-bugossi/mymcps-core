// purpose: in-process Map-backed CacheAdapter for local dev with lazy + periodic eviction.

import type { CacheAdapter } from './types.js';

interface Entry {
  value: unknown;
  expiresAt: number;
}

const SWEEP_INTERVAL_MS = 60_000;

export class InMemoryCache implements CacheAdapter {
  private store = new Map<string, Entry>();
  private sweepHandle: NodeJS.Timeout | null;

  constructor() {
    this.sweepHandle = setInterval(() => this.sweep(), SWEEP_INTERVAL_MS);
    this.sweepHandle.unref();
  }

  async get<T>(key: string): Promise<T | null> {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.store.delete(key);
      return null;
    }
    return entry.value as T;
  }

  async set<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
    this.store.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  stopSweep(): void {
    if (this.sweepHandle) {
      clearInterval(this.sweepHandle);
      this.sweepHandle = null;
    }
  }

  private sweep(): void {
    const now = Date.now();
    for (const [key, entry] of this.store) {
      if (entry.expiresAt <= now) this.store.delete(key);
    }
  }
}
