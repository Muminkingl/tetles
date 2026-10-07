import { TetherClientError, RELOGIN_REQUIRED_EVENT } from "./errors.js";
import { IndexedDbKeyStore } from "./key-store.js";
import type { DeviceKeyRecord, DeviceKeyStore } from "./key-store.js";
import { createProof } from "./proof.js";

export interface TetherSession {
  readonly sessionId: string;
  readonly accessToken: string;
}

export interface TetherClientOptions {
  readonly getSession: () => Promise<TetherSession | null>;
  readonly baseUrl?: string;
  readonly bindEndpoint?: string;
  readonly refreshEndpoint?: string;
  readonly clearCookieEndpoint?: string;
  readonly allowedOrigins?: readonly string[];
  readonly keyStore?: DeviceKeyStore;
  readonly fetcher?: typeof fetch;
  readonly locks?: Pick<LockManager, "request">;
  readonly onReloginRequired?: (detail: { readonly reason: "key-missing" | "key-invalid" }) => void;
}

export interface TetherClient {
  /** Bind the current authenticated session to this browser's device key. */
  bind(): Promise<Response>;
  /** Refresh the five-minute HttpOnly cookie using the session's bound key and a fresh proof. */
  refreshCookie(): Promise<Response>;
  /** Clear the same-origin HttpOnly cookie, including during logout after key loss. */
  clearCookie(): Promise<Response>;
  /** Send an authenticated request with a fresh DPoP-style proof. */
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  /** Coordinate refresh work across same-origin tabs. */
  withSessionLock<T>(work: () => Promise<T>): Promise<T>;
  /** Remove the device key for a session, for example during logout. */
  forgetSession(sessionId: string): Promise<void>;
}

interface Prepared {
  readonly session: TetherSession;
  readonly record: DeviceKeyRecord;
}

/** Browser-side DPoP client. Call bind() after login before using protected routes. */
export function createTetherClient(options: TetherClientOptions): TetherClient {
  const keyStore = options.keyStore ?? new IndexedDbKeyStore();
  const fetcher = options.fetcher ?? globalThis.fetch.bind(globalThis);
  const nonceBySessionAndOrigin = new Map<string, string>();
  const reloginSignalled = new Set<string>();
  const baseUrl = options.baseUrl ?? currentBaseUrl();
  const configuredOrigins = new Set(
    (options.allowedOrigins ?? [new URL(baseUrl).origin]).map((origin) => new URL(origin).origin),
  );

  async function currentSession(): Promise<TetherSession> {
    const session = await options.getSession();
    if (session === null || session.sessionId.length === 0 || session.accessToken.length === 0) {
      throw new TetherClientError("AUTH_SESSION_REQUIRED");
    }
    return session;
  }

  async function getExistingKey(sessionId: string): Promise<DeviceKeyRecord | undefined> {
    try {
      const record = await keyStore.get(sessionId);
      if (record === undefined) return undefined;
      validateRecord(record, sessionId);
      return record;
    } catch (error) {
      if (error instanceof TetherClientError) throw error;
      throw new TetherClientError("KEY_STORAGE_UNAVAILABLE");
    }
  }

  async function createAndStoreKey(sessionId: string): Promise<DeviceKeyRecord> {
    const subtle = globalThis.crypto?.subtle;
    if (subtle === undefined) throw new TetherClientError("CRYPTO_UNAVAILABLE");
    let pair: CryptoKeyPair;
    let publicJwk: JsonWebKey;
    try {
      pair = await subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"],
      ) as CryptoKeyPair;
      if (pair.privateKey.extractable) throw new Error("Private key must not be extractable");
      const exported = await subtle.exportKey("jwk", pair.publicKey);
      if (
        exported.kty !== "EC" || exported.crv !== "P-256" ||
        typeof exported.x !== "string" || typeof exported.y !== "string" ||
        Object.hasOwn(exported, "d")
      ) {
        throw new Error("Public key export was invalid");
      }
      publicJwk = { kty: "EC", crv: "P-256", x: exported.x, y: exported.y };
    } catch {
      throw new TetherClientError("CRYPTO_UNAVAILABLE");
    }

    const candidate = { sessionId, privateKey: pair.privateKey, publicJwk };
    try {
      const record = await keyStore.putIfAbsent(candidate);
      validateRecord(record, sessionId);
      reloginSignalled.delete(sessionId);
      return record;
    } catch (error) {
      if (error instanceof TetherClientError) throw error;
      throw new TetherClientError("KEY_STORAGE_UNAVAILABLE");
    }
  }

  async function prepare(requireExisting: boolean): Promise<Prepared> {
    const session = await currentSession();
    const existing = await getExistingKey(session.sessionId);
    if (existing !== undefined) return { session, record: existing };
    if (requireExisting) {
      signalRelogin(session.sessionId, "key-missing");
      throw new TetherClientError("KEY_MISSING");
    }
    return { session, record: await createAndStoreKey(session.sessionId) };
  }

  function requestUrl(input: RequestInfo | URL): URL {
    const raw = input instanceof Request ? input.url : String(input);
    let url: URL;
    try {
      url = new URL(raw, baseUrl);
    } catch {
      throw new TetherClientError("REQUEST_ORIGIN_REJECTED");
    }
    if (url.username !== "" || url.password !== "" || !configuredOrigins.has(url.origin)) {
      throw new TetherClientError("REQUEST_ORIGIN_REJECTED");
    }
    return url;
  }

  async function createAuthorizedRequest(
    source: Request,
    url: URL,
    prepared: Prepared,
    nonce: string | undefined,
  ): Promise<Request> {
    let proof: string;
    try {
      proof = await createProof({
        privateKey: prepared.record.privateKey,
        publicJwk: prepared.record.publicJwk,
        method: source.method,
        url: url.href,
        accessToken: prepared.session.accessToken,
        ...(nonce === undefined ? {} : { nonce }),
      });
    } catch (error) {
      if (error instanceof TetherClientError && error.code === "KEY_INVALID") {
        signalRelogin(prepared.session.sessionId, "key-invalid");
      }
      throw error;
    }
    const headers = new Headers(source.headers);
    headers.set("Authorization", `Bearer ${prepared.session.accessToken}`);
    headers.set("DPoP", proof);
    return new Request(source, { headers });
  }

  async function bind(): Promise<Response> {
    const prepared = await prepare(false);
    const url = requestUrl(options.bindEndpoint ?? "/tether/bind");
    const source = new Request(url, { method: "POST" });
    return sendWithNonceRetry(source, url, prepared);
  }

  async function refreshCookie(): Promise<Response> {
    const session = await currentSession();
    return lockForSession(session.sessionId, async () => {
      const prepared = await prepare(true);
      if (prepared.session.sessionId !== session.sessionId) {
        throw new TetherClientError("AUTH_SESSION_REQUIRED");
      }
      const url = requestUrl(options.refreshEndpoint ?? "/tether/refresh");
      const source = new Request(url, { method: "POST", credentials: "same-origin" });
      return sendWithNonceRetry(source, url, prepared);
    });
  }

  async function clearCookie(): Promise<Response> {
    const url = requestUrl(
      options.clearCookieEndpoint ?? options.refreshEndpoint ?? "/tether/refresh",
    );
    return fetcher(new Request(url, { method: "DELETE", credentials: "same-origin" }));
  }

  async function tetherFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const url = requestUrl(input);
    let source: Request;
    try {
      source = input instanceof Request ? new Request(input, init) : new Request(url, init);
    } catch {
      throw new TetherClientError("REQUEST_ORIGIN_REJECTED");
    }
    const prepared = await prepare(true);
    return sendWithNonceRetry(source, url, prepared);
  }

  async function sendWithNonceRetry(
    source: Request,
    url: URL,
    prepared: Prepared,
  ): Promise<Response> {
    const retrySource = source.clone();
    const key = nonceKey(prepared.session.sessionId, url.origin);
    const firstRequest = await createAuthorizedRequest(
      source,
      url,
      prepared,
      nonceBySessionAndOrigin.get(key),
    );
    const firstResponse = await fetcher(firstRequest);
    rememberNonce(prepared.session.sessionId, url.origin, firstResponse);
    const responseNonce = firstResponse.headers.get("DPoP-Nonce");
    if (responseNonce === null || !(await announcesNonceChallenge(firstResponse))) return firstResponse;

    const retryRequest = await createAuthorizedRequest(retrySource, url, prepared, responseNonce);
    const retryResponse = await fetcher(retryRequest);
    rememberNonce(prepared.session.sessionId, url.origin, retryResponse);
    return retryResponse;
  }

  function rememberNonce(sessionId: string, origin: string, response: Response): void {
    const nonce = response.headers.get("DPoP-Nonce");
    const key = nonceKey(sessionId, origin);
    if (nonce === null) nonceBySessionAndOrigin.delete(key);
    else nonceBySessionAndOrigin.set(key, nonce);
  }

  async function withSessionLock<T>(work: () => Promise<T>): Promise<T> {
    const session = await currentSession();
    return lockForSession(session.sessionId, work);
  }

  async function lockForSession<T>(sessionId: string, work: () => Promise<T>): Promise<T> {
    const locks = options.locks ?? globalThis.navigator?.locks;
    if (locks === undefined) throw new TetherClientError("LOCKS_UNAVAILABLE");
    return locks.request(`tether:${sessionId}`, { mode: "exclusive" }, work);
  }

  function signalRelogin(sessionId: string, reason: "key-missing" | "key-invalid"): void {
    if (reloginSignalled.has(sessionId)) return;
    reloginSignalled.add(sessionId);
    try {
      options.onReloginRequired?.({ reason });
    } catch {
      // Recovery signaling must not replace the stable client error.
    }
    if (typeof globalThis.dispatchEvent === "function" && typeof CustomEvent === "function") {
      globalThis.dispatchEvent(new CustomEvent(RELOGIN_REQUIRED_EVENT, { detail: { reason } }));
    }
  }

  return {
    bind,
    refreshCookie,
    clearCookie,
    fetch: tetherFetch,
    withSessionLock,
    forgetSession: async (sessionId) => {
      try {
        await keyStore.delete(sessionId);
      } catch {
        throw new TetherClientError("KEY_STORAGE_UNAVAILABLE");
      }
      reloginSignalled.delete(sessionId);
      for (const key of nonceBySessionAndOrigin.keys()) {
        if (key.startsWith(`${sessionId}\n`)) nonceBySessionAndOrigin.delete(key);
      }
    },
  };

  function nonceKey(sessionId: string, origin: string): string {
    return `${sessionId}\n${origin}`;
  }

  function validateRecord(record: DeviceKeyRecord, sessionId: string): void {
    const candidate = record as unknown as Record<string, unknown> | null;
    const key = candidate !== null && typeof candidate === "object"
      ? candidate.privateKey as CryptoKey | null | undefined
      : undefined;
    const publicJwk = candidate !== null && typeof candidate === "object"
      ? candidate.publicJwk as JsonWebKey | null | undefined
      : undefined;
    if (
      candidate === null || typeof candidate !== "object" ||
      candidate.sessionId !== sessionId || key === undefined || key === null ||
      typeof key !== "object" || key.extractable ||
      key.type !== "private" || key.algorithm === undefined || key.algorithm === null ||
      key.algorithm.name !== "ECDSA" ||
      (key.algorithm as EcKeyAlgorithm).namedCurve !== "P-256" ||
      !Array.isArray(key.usages) || !key.usages.includes("sign") ||
      publicJwk === undefined || publicJwk === null || typeof publicJwk !== "object" ||
      publicJwk.kty !== "EC" || publicJwk.crv !== "P-256" ||
      typeof publicJwk.x !== "string" || typeof publicJwk.y !== "string" ||
      Object.hasOwn(publicJwk, "d")
    ) {
      signalRelogin(sessionId, "key-invalid");
      throw new TetherClientError("KEY_INVALID");
    }
  }
}

async function announcesNonceChallenge(response: Response): Promise<boolean> {
  if (response.status !== 400 && response.status !== 401) return false;
  if (/use_dpop_nonce/iu.test(response.headers.get("WWW-Authenticate") ?? "")) return true;
  try {
    const body: unknown = await response.clone().json();
    if (typeof body !== "object" || body === null) return false;
    const record = body as Record<string, unknown>;
    return record.reasonCode === "PROOF_STALE" || record.reasonCode === "PROOF_NONCE_REQUIRED" ||
      record.code === "PROOF_STALE" || record.code === "PROOF_NONCE_REQUIRED";
  } catch {
    return false;
  }
}

function currentBaseUrl(): string {
  if (globalThis.location?.href === undefined) throw new TetherClientError("REQUEST_ORIGIN_REJECTED");
  return globalThis.location.href;
}
