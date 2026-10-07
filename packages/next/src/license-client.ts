import {
  decodeProtectedHeader,
  type JSONWebKeySet,
} from "jose";
import {
  LICENSE_OFFLINE_GRACE_SECONDS,
  LICENSE_SIGNING_JWKS,
  sanitizeLicenseJwks,
  verifyLicense,
} from "@tether/core";
import type {
  LicenseEnvironment,
  VerifiedLicense,
} from "@tether/core";

export interface LicenseCacheStore {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  delete?(key: string): Promise<void>;
}

/** A signed, build-time token and the public keys needed to verify it offline. */
export interface TetherLicenseSnapshot {
  readonly token: string;
  readonly jwks: JSONWebKeySet;
}

export interface CreateTetherLicenseClientOptions {
  readonly apiKey: string;
  readonly projectId: string;
  readonly environment: LicenseEnvironment;
  readonly issuer: string;
  readonly licenseEndpoint: string;
  readonly jwksEndpoint?: string;
  readonly embeddedJwks?: JSONWebKeySet;
  /** Verified offline after a cold start when no persistent cache is available. */
  readonly initialSnapshot?: TetherLicenseSnapshot;
  readonly cache?: LicenseCacheStore;
  readonly fetcher?: typeof fetch;
  readonly refreshIntervalMilliseconds?: number;
  readonly now?: () => Date;
  readonly onLicenseChange?: (license: VerifiedLicense | null) => void;
}

export interface TetherLicenseClient {
  /** Load any verified cache and begin network refresh in the background. Never waits on the license service. */
  start(): Promise<void>;
  /** Force an out-of-band refresh, for example from a scheduled runtime hook. */
  refresh(): Promise<VerifiedLicense | null>;
  /** Return the most recently verified in-memory license without I/O. */
  current(): VerifiedLicense | null;
  stop(): void;
}

interface CachedLicense {
  readonly token: string;
  readonly jwks: JSONWebKeySet;
}

const processCache = new Map<string, string>();

/** Process-local default cache. Supply a durable adapter to preserve cache across cold starts. */
export class MemoryLicenseCacheStore implements LicenseCacheStore {
  get(key: string): Promise<string | undefined> {
    return Promise.resolve(processCache.get(key));
  }

  set(key: string, value: string): Promise<void> {
    processCache.set(key, value);
    return Promise.resolve();
  }

  delete(key: string): Promise<void> {
    processCache.delete(key);
    return Promise.resolve();
  }
}

/** Server-side license client: cached verification is synchronous to callers; refresh runs off-path. */
export function createTetherLicenseClient(
  options: CreateTetherLicenseClientOptions,
): TetherLicenseClient {
  const cache = options.cache ?? new MemoryLicenseCacheStore();
  const fetcher = options.fetcher ?? globalThis.fetch.bind(globalThis);
  const baseJwks = sanitizeLicenseJwks(options.embeddedJwks ?? LICENSE_SIGNING_JWKS);
  const cacheKey = `tether-license:v1:${options.issuer}:${options.projectId}:${options.environment}`;
  const jwksEndpoint = options.jwksEndpoint ?? defaultJwksEndpoint(options.licenseEndpoint);
  const refreshEvery = options.refreshIntervalMilliseconds ?? 6 * 60 * 60 * 1000;
  if (!Number.isSafeInteger(refreshEvery) || refreshEvery < 60_000) {
    throw new RangeError("License refresh interval must be at least one minute.");
  }

  let currentLicense: VerifiedLicense | null = null;
  let cached: CachedLicense | undefined;
  let started = false;
  let timer: ReturnType<typeof globalThis.setInterval> | undefined;
  let refreshInProgress: Promise<VerifiedLicense | null> | undefined;

  async function start(): Promise<void> {
    if (started) return;
    started = true;
    await restoreCache();
    void refresh();
    timer = globalThis.setInterval(() => void refresh(), refreshEvery);
    (timer as unknown as { unref?: () => void }).unref?.();
  }

  async function restoreCache(): Promise<void> {
    let serialized: string | undefined;
    try {
      serialized = await cache.get(cacheKey);
    } catch {
      // Fall back to the build-time snapshot when a persistent cache is unavailable.
    }
    if (serialized !== undefined && serialized.length <= 64_000) {
      try {
        const decoded: unknown = JSON.parse(serialized);
        if (isCachedLicense(decoded) && await restoreVerifiedSnapshot(decoded)) return;
      } catch {
        // Try the build-time snapshot after an invalid persistent entry.
      }
    }
    if (options.initialSnapshot !== undefined) {
      await restoreVerifiedSnapshot(options.initialSnapshot, true);
    }
  }

  async function restoreVerifiedSnapshot(
    candidate: TetherLicenseSnapshot,
    persist = false,
  ): Promise<boolean> {
    try {
      const jwks = sanitizeLicenseJwks(candidate.jwks);
      const verified = await verifyLicense(candidate.token, {
        jwks,
        issuer: options.issuer,
        projectId: options.projectId,
        environment: options.environment,
        now: (options.now ?? (() => new Date()))(),
        allowExpiredBySeconds: LICENSE_OFFLINE_GRACE_SECONDS,
      });
      cached = { token: candidate.token, jwks };
      setCurrent(verified);
      if (persist) {
        try {
          await cache.set(cacheKey, JSON.stringify(cached));
        } catch {
          // A verified build-time snapshot remains usable if the cache store is unavailable.
        }
      }
      return true;
    } catch {
      return false;
    }
  }

  async function refresh(): Promise<VerifiedLicense | null> {
    if (refreshInProgress !== undefined) return refreshInProgress;
    refreshInProgress = refreshOnce().finally(() => { refreshInProgress = undefined; });
    return refreshInProgress;
  }

  async function refreshOnce(): Promise<VerifiedLicense | null> {
    let response: Response;
    try {
      response = await fetcher(options.licenseEndpoint, {
        method: "POST",
        headers: {
          authorization: `Bearer ${options.apiKey}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ env: options.environment }),
        cache: "no-store",
      });
    } catch {
      return retainCacheAfterOutage();
    }

    if (response.status === 429 || response.status >= 500) return retainCacheAfterOutage();
    if (!response.ok) {
      cached = undefined;
      setCurrent(null);
      try {
        await cache.delete?.(cacheKey);
      } catch {
        // A stale cache must not replace a definitive rejection from the license service.
      }
      return null;
    }

    try {
      const body: unknown = await response.json();
      if (!isTokenResponse(body)) throw new Error("LICENSE_RESPONSE_REJECTED");
      const token = body.token;
      let jwks = currentJwks();
      let kid = decodeProtectedHeader(token).kid;
      if (typeof kid !== "string") throw new Error("LICENSE_HEADER_REJECTED");
      if (!jwks.keys.some((key) => key.kid === kid)) {
        jwks = await fetchJwks();
        kid = decodeProtectedHeader(token).kid;
        if (typeof kid !== "string" || !jwks.keys.some((key) => key.kid === kid)) {
          throw new Error("LICENSE_UNKNOWN_KID");
        }
      }
      const verified = await verifyLicense(token, {
        jwks,
        issuer: options.issuer,
        projectId: options.projectId,
        environment: options.environment,
        now: (options.now ?? (() => new Date()))(),
      });
      cached = { token, jwks };
      try {
        await cache.set(cacheKey, JSON.stringify(cached));
      } catch {
        // A valid newly-issued license remains usable even if the optional cache is unavailable.
      }
      setCurrent(verified);
      return verified;
    } catch (error) {
      if (error instanceof Error && error.message === "LICENSE_JWKS_UNAVAILABLE") {
        return retainCacheAfterOutage();
      }
      // Do not silently fall back to stale credentials after a successful but invalid response.
      cached = undefined;
      setCurrent(null);
      try {
        await cache.delete?.(cacheKey);
      } catch {
        // Cache cleanup is best-effort; current state is already unlicensed.
      }
      return null;
    }
  }

  async function fetchJwks(): Promise<JSONWebKeySet> {
    try {
      const response = await fetcher(jwksEndpoint, {
        method: "GET",
        headers: { accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) throw new Error("LICENSE_JWKS_UNAVAILABLE");
      const data: unknown = await response.json();
      if (!isJwks(data)) throw new Error("LICENSE_JWKS_REJECTED");
      return sanitizeLicenseJwks(data);
    } catch (error) {
      if (error instanceof Error && error.message === "LICENSE_JWKS_REJECTED") throw error;
      throw new Error("LICENSE_JWKS_UNAVAILABLE");
    }
  }

  function currentJwks(): JSONWebKeySet {
    const keys = [...baseJwks.keys];
    for (const key of cached?.jwks.keys ?? []) {
      if (!keys.some((known) => known.kid === key.kid)) keys.push(key);
    }
    return sanitizeLicenseJwks({ keys });
  }

  async function retainCacheAfterOutage(): Promise<VerifiedLicense | null> {
    if (cached === undefined) return null;
    try {
      const verified = await verifyLicense(cached.token, {
        jwks: cached.jwks,
        issuer: options.issuer,
        projectId: options.projectId,
        environment: options.environment,
        now: (options.now ?? (() => new Date()))(),
        allowExpiredBySeconds: LICENSE_OFFLINE_GRACE_SECONDS,
      });
      setCurrent(verified);
      return verified;
    } catch {
      cached = undefined;
      setCurrent(null);
      try {
        await cache.delete?.(cacheKey);
      } catch {
        // Best-effort cleanup only.
      }
      return null;
    }
  }

  function setCurrent(value: VerifiedLicense | null): void {
    currentLicense = value;
    try {
      options.onLicenseChange?.(value);
    } catch {
      // Application callbacks cannot change verification results.
    }
  }

  function stop(): void {
    if (timer !== undefined) globalThis.clearInterval(timer);
    timer = undefined;
    started = false;
  }

  return {
    start,
    refresh,
    current: () => currentLicense,
    stop,
  };
}

function defaultJwksEndpoint(licenseEndpoint: string): string {
  const url = new URL(licenseEndpoint);
  url.pathname = "/v1/jwks";
  url.search = "";
  url.hash = "";
  return url.href;
}

function isTokenResponse(value: unknown): value is { readonly token: string } {
  if (typeof value !== "object" || value === null) return false;
  const token = (value as Record<string, unknown>).token;
  return typeof token === "string" && token.length > 0 && token.length <= 16_384;
}

function isJwks(value: unknown): value is JSONWebKeySet {
  return typeof value === "object" && value !== null && Array.isArray((value as { keys?: unknown }).keys);
}

function isCachedLicense(value: unknown): value is CachedLicense {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return typeof record.token === "string" && record.token.length > 0 && isJwks(record.jwks);
}
