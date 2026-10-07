export interface ReplayStore {
  /** Atomically records a proof key. Returns false when that key was already recorded. */
  claim(key: string, ttlMilliseconds: number): Promise<boolean>;
}

export class ReplayStoreCapacityError extends Error {
  constructor() {
    super("Replay store capacity reached");
    this.name = "ReplayStoreCapacityError";
  }
}

/** A bounded, per-process replay store for single-instance deployments and local use. */
export class MemoryReplayStore implements ReplayStore {
  readonly #entries = new Map<string, number>();

  constructor(readonly maxEntries = 100_000) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new RangeError("maxEntries must be a positive safe integer");
    }
  }

  async claim(key: string, ttlMilliseconds: number): Promise<boolean> {
    if (!Number.isSafeInteger(ttlMilliseconds) || ttlMilliseconds < 1) {
      throw new RangeError("ttlMilliseconds must be a positive safe integer");
    }

    const now = Date.now();
    const existingExpiry = this.#entries.get(key);
    if (existingExpiry !== undefined && existingExpiry > now) return false;
    if (existingExpiry !== undefined) this.#entries.delete(key);

    if (this.#entries.size >= this.maxEntries) {
      for (const [entryKey, expiresAt] of this.#entries) {
        if (expiresAt <= now) this.#entries.delete(entryKey);
      }
    }
    if (this.#entries.size >= this.maxEntries) throw new ReplayStoreCapacityError();

    this.#entries.set(key, now + ttlMilliseconds);
    return true;
  }
}
