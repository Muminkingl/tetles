import { calculateJwkThumbprint, decodeProtectedHeader } from "jose";
import {
  MemoryReplayStore,
  publicP256JwkSchema,
  verifyProof,
} from "@tether/core";
import type {
  LicenseEnvironment,
  ProofReasonCode,
  ReplayStore,
  VerifiedLicense,
} from "@tether/core";
import {
  clearTetherCookie,
  TetherCookieSessionManager,
} from "./cookie-session.js";
import type {
  TetherCookieSession,
  TetherCookieSessionOptions,
} from "./cookie-session.js";
import { createTetherLicenseClient } from "./license-client.js";
import type {
  CreateTetherLicenseClientOptions,
  LicenseCacheStore,
  TetherLicenseClient,
  TetherLicenseSnapshot,
} from "./license-client.js";
export { createTetherLicenseClient, MemoryLicenseCacheStore } from "./license-client.js";
export type {
  CreateTetherLicenseClientOptions,
  LicenseCacheStore,
  TetherLicenseClient,
  TetherLicenseSnapshot,
} from "./license-client.js";

export { TETHER_COOKIE_NAME, TetherCookieSessionManager } from "./cookie-session.js";
export type {
  TetherCookieIdentity,
  TetherCookieSession,
  TetherCookieSessionOptions,
  TetherCookieTicket,
} from "./cookie-session.js";

export interface TetherIdentity {
  readonly sessionId: string;
  readonly userId: string;
}

export interface TetherBindingStore {
  /** The user ID lets multi-tenant stores scope a session lookup to its project owner. */
  getJkt(sessionId: string, userId?: string): Promise<string | null>;
  /** Return false if this session is already bound to a different key. */
  bindIfAbsent(sessionId: string, jkt: string, userId?: string): Promise<boolean>;
}

export interface TetherNonceStore {
  get(sessionId: string, origin: string): Promise<string | undefined>;
  issue(sessionId: string, origin: string): Promise<string>;
}

export interface TetherRefreshRotationInput extends TetherIdentity {
  /** Thumbprint from the proof already verified against the session binding. */
  readonly jkt: string;
  /** Omitted when this is the first cookie or the browser no longer has a valid cookie. */
  readonly presentedToken?: {
    readonly tokenId: string;
    readonly expiresAt: number;
  };
  readonly nextToken: {
    readonly tokenId: string;
    readonly issuedAt: number;
    readonly expiresAt: number;
  };
}

export type TetherRefreshRotationResult =
  | { readonly status: "rotated" }
  | {
      readonly status: "retry";
      readonly token: { readonly tokenId: string; readonly issuedAt: number; readonly expiresAt: number };
    }
  | { readonly status: "reuse" | "revoked" | "key-mismatch" };

/** Atomically rotates tickets, idempotently handles same-key retries, and logs later reuse. */
export interface TetherRefreshStore {
  rotate(input: TetherRefreshRotationInput): Promise<TetherRefreshRotationResult>;
}

export interface TetherVerifiedContext extends TetherIdentity {
  readonly licensed: true;
  readonly bound: true;
  readonly proofId: string;
}

export interface TetherUnlicensedContext {
  readonly licensed: false;
  readonly bound: false;
  readonly userId: null;
  readonly sessionId: null;
  readonly proofId: null;
  readonly reasonCode: "TETHER_LICENSE_REQUIRED" | "TETHER_LICENSE_INACTIVE";
}

export interface TetherUnlicensedCookieContext extends TetherUnlicensedContext {
  readonly jkt: null;
  readonly tokenId: null;
  readonly issuedAt: null;
  readonly expiresAt: null;
}

export type TetherProtectedContext = TetherVerifiedContext | TetherUnlicensedContext;
export type TetherCookieRouteContext =
  | (TetherCookieSession & { readonly licensed: true; readonly bound: true })
  | TetherUnlicensedCookieContext;

export type TetherAuthenticate = (
  request: Request,
  accessToken: string,
) => Promise<TetherIdentity | null>;

/** Check `context.licensed` before using the identity; open mode supplies a degraded context. */
export type TetherRouteHandler = (
  request: Request,
  context: TetherProtectedContext,
) => Response | Promise<Response>;

/** Check `context.licensed` before using the session; open mode supplies a degraded context. */
export type TetherCookieRouteHandler = (
  request: Request,
  context: TetherCookieRouteContext,
) => Response | Promise<Response>;

export interface TetherRouteOptions {
  /** Override the adapter-wide policy for this route. */
  readonly onUnlicensed?: "open" | "closed";
}

export interface TetherNextLicenseOptions {
  /** Defaults to the server-only TETHER_KEY environment variable. */
  readonly apiKey?: string;
  /** Defaults to TETHER_PROJECT_ID. */
  readonly projectId?: string;
  /** Defaults to TETHER_LICENSE_ISSUER (localhost in development only). */
  readonly issuer?: string;
  /** Defaults to TETHER_ENV, then NODE_ENV. Never read from a request header. */
  readonly environment?: LicenseEnvironment;
  readonly licenseEndpoint?: string;
  readonly jwksEndpoint?: string;
  readonly embeddedJwks?: CreateTetherLicenseClientOptions["embeddedJwks"];
  /** Build-time token/JWKS fallback for cold starts with an empty process cache. */
  readonly initialSnapshot?: TetherLicenseSnapshot;
  readonly cache?: LicenseCacheStore;
  readonly fetcher?: typeof fetch;
  readonly refreshIntervalMilliseconds?: number;
  readonly now?: () => Date;
  readonly onLicenseChange?: (license: VerifiedLicense | null) => void;
  /** Production default is "open": routes run without Tether context/protection. */
  readonly onUnlicensed?: "open" | "closed";
  /** Permit production startup without a usable key; affected routes remain unlicensed. */
  readonly allowUnlicensed?: boolean;
}

export interface CreateTetherNextOptions {
  /** Must verify the bearer token and return claims from that verified token. */
  readonly authenticate: TetherAuthenticate;
  readonly bindings: TetherBindingStore;
  readonly replayStore?: ReplayStore;
  readonly nonceStore?: TetherNonceStore;
  /** Required to rotate tickets and atomically revoke/log a reused ticket. */
  readonly refreshStore?: TetherRefreshStore;
  readonly proofWindowSeconds?: number;
  /** Server-only key for the optional five-minute HttpOnly companion cookie. */
  readonly cookieSession?: TetherCookieSessionOptions;
  /** Override only when the app has a trusted reverse-proxy URL configuration. */
  readonly resolveRequestUrl?: (request: Request) => string;
  /** License settings. Server environment variables fill values not supplied here. */
  readonly license?: TetherNextLicenseOptions;
}

export interface TetherNext {
  /** Route handler for POST /tether/bind (or an app-specific bind route). */
  bind(request: Request): Promise<Response>;
  /** Verify Supabase auth and a fresh device proof, then issue the short-lived cookie. */
  refreshCookie(request: Request): Promise<Response>;
  /** Clear the companion cookie. The request must be same-origin. */
  clearCookie(request: Request): Promise<Response>;
  /** Read and verify a cookie value, for example one returned by Next.js cookies(). */
  readCookieSession(cookieValue: string | null | undefined): Promise<TetherCookieSession | null>;
  /** Wrap a safe, read-only GET or HEAD Route Handler using the signed cookie ticket. */
  protectCookie(
    handler: TetherCookieRouteHandler,
    routeOptions?: TetherRouteOptions,
  ): (request: Request) => Promise<Response>;
  /** Wrap a Next.js App Router Route Handler; the wrapped route is the authorization boundary. */
  protect(
    handler: TetherRouteHandler,
    routeOptions?: TetherRouteOptions,
  ): (request: Request) => Promise<Response>;
  /** Return the latest locally verified license without network I/O. */
  licenseStatus(): VerifiedLicense | null;
}

const MAX_PROOF_LENGTH = 8_192;
let developmentUnlicensedNoticeLogged = false;

/**
 * Creates Web Request/Response-based handlers, so it works in Next.js Route Handlers without
 * putting Supabase or Next.js imports in the verification package.
 */
export function createTetherNext(options: CreateTetherNextOptions): TetherNext {
  const licenseRuntime = initializeLicense(options.license);
  const refreshStore = options.refreshStore;
  if (options.cookieSession !== undefined && refreshStore === undefined) {
    throw new TypeError("A Tether refresh store is required when cookie sessions are enabled.");
  }
  const replayStore = options.replayStore ?? new MemoryReplayStore();
  const nonceStore = options.nonceStore ?? new MemoryTetherNonceStore();
  const cookieSessions = options.cookieSession === undefined
    ? undefined
    : new TetherCookieSessionManager(options.cookieSession);

  const licenseReady = licenseRuntime.client?.start().catch(() => {
    warnUnlicensed(licenseRuntime, "license cache could not be initialized");
  });

  async function unlicensedDisposition(
    policy: "open" | "closed",
  ): Promise<Response | TetherUnlicensedCookieContext | undefined> {
    if (licenseRuntime.environment !== "production") return undefined;
    // Wait only for local cache restoration. start() launches refresh without awaiting the network.
    await licenseReady;
    const reason = licenseGateReason(licenseRuntime);
    if (reason === undefined) return undefined;
    const reasonCode = reason === "inactive" ? "TETHER_LICENSE_INACTIVE" : "TETHER_LICENSE_REQUIRED";
    warnUnlicensed(
      licenseRuntime,
      reason === "inactive"
        ? "the current production license does not allow protection"
        : "no acceptable production license is available",
    );
    if (policy === "closed") {
      return errorResponse(reasonCode, reason === "inactive" ? 403 : 503);
    }
    return {
      licensed: false,
      bound: false,
      userId: null,
      sessionId: null,
      proofId: null,
      reasonCode,
      jkt: null,
      tokenId: null,
      issuedAt: null,
      expiresAt: null,
    };
  }

  async function authenticate(request: Request): Promise<
    | { readonly identity: TetherIdentity; readonly accessToken: string }
    | Response
  > {
    const authorization = request.headers.get("Authorization");
    const match = authorization?.match(/^Bearer\s+([^\s]+)$/iu);
    if (match === null || match === undefined) return errorResponse("AUTH_REQUIRED", 401);

    try {
      const identity = await options.authenticate(request, match[1]!);
      if (
        identity === null || identity.sessionId.length === 0 || identity.userId.length === 0
      ) {
        return errorResponse("AUTH_REQUIRED", 401);
      }
      return { identity, accessToken: match[1]! };
    } catch {
      return errorResponse("AUTH_PROVIDER_UNAVAILABLE", 503);
    }
  }

  function targetUrl(request: Request): URL | Response {
    try {
      const url = new URL(options.resolveRequestUrl?.(request) ?? request.url);
      if (url.protocol !== "https:" && url.protocol !== "http:") {
        return proofError("PROOF_URL_MISMATCH");
      }
      return url;
    } catch {
      return proofError("PROOF_URL_MISMATCH");
    }
  }

  async function candidateJkt(
    request: Request,
  ): Promise<{ readonly jkt: string } | { readonly error: ProofReasonCode }> {
    const proof = request.headers.get("DPoP");
    if (proof === null || proof.length === 0) return { error: "PROOF_MISSING" };
    if (proof.length > MAX_PROOF_LENGTH) return { error: "PROOF_MALFORMED" };

    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(proof);
    } catch {
      return { error: "PROOF_MALFORMED" };
    }
    if (header.typ !== "dpop+jwt") return { error: "PROOF_TYPE_REJECTED" };
    if (header.alg !== "ES256") return { error: "PROOF_ALGORITHM_REJECTED" };
    if (typeof header.jwk === "object" && header.jwk !== null && Object.hasOwn(header.jwk, "d")) {
      return { error: "PROOF_MALFORMED" };
    }
    const jwkResult = publicP256JwkSchema.safeParse(header.jwk);
    if (!jwkResult.success) return { error: "PROOF_MALFORMED" };
    try {
      return { jkt: await calculateJwkThumbprint(jwkResult.data, "sha256") };
    } catch {
      return { error: "PROOF_MALFORMED" };
    }
  }

  async function verifyRequest(
    request: Request,
    authenticated: { readonly identity: TetherIdentity; readonly accessToken: string },
    expectedJkt: string,
    url: URL,
    allowMismatchedKey = false,
  ): Promise<{
    readonly jkt: string;
    readonly proofId: string;
    readonly keyMismatch: boolean;
    readonly nonce?: string;
  } | Response> {
    let expectedNonce: string | undefined;
    try {
      expectedNonce = await nonceStore.get(authenticated.identity.sessionId, url.origin);
    } catch {
      return errorResponse("TETHER_STATE_UNAVAILABLE", 503);
    }

    const proofInput = {
      proof: request.headers.get("DPoP"),
      method: request.method,
      url: url.href,
      accessToken: authenticated.accessToken,
      replayStore,
      ...(options.proofWindowSeconds === undefined
        ? {}
        : { proofWindowSeconds: options.proofWindowSeconds }),
      ...(expectedNonce === undefined ? {} : { expectedNonce }),
    };
    let result = await verifyProof({ ...proofInput, expectedJkt });
    let keyMismatch = false;

    if (!result.ok && result.reasonCode === "PROOF_KEY_MISMATCH" && allowMismatchedKey) {
      const candidate = await candidateJkt(request);
      if ("error" in candidate) return proofError(candidate.error);
      result = await verifyProof({ ...proofInput, expectedJkt: candidate.jkt });
      keyMismatch = result.ok && candidate.jkt !== expectedJkt;
    }

    if (!result.ok) {
      let challengeNonce: string | undefined;
      if (result.reasonCode === "PROOF_STALE" || result.reasonCode === "PROOF_NONCE_REQUIRED") {
        try {
          challengeNonce = await nonceStore.issue(authenticated.identity.sessionId, url.origin);
        } catch {
          return errorResponse("TETHER_STATE_UNAVAILABLE", 503);
        }
      }
      return proofError(result.reasonCode, challengeNonce);
    }

    try {
      const nonce = await nonceStore.get(authenticated.identity.sessionId, url.origin);
      return {
        jkt: result.jkt,
        proofId: result.proofId,
        keyMismatch,
        ...(nonce === undefined ? {} : { nonce }),
      };
    } catch {
      return errorResponse("TETHER_STATE_UNAVAILABLE", 503);
    }
  }

  async function bind(request: Request): Promise<Response> {
    const auth = await authenticate(request);
    if (auth instanceof Response) return auth;
    const url = targetUrl(request);
    if (url instanceof Response) return url;

    const candidate = await candidateJkt(request);
    if ("error" in candidate) return proofError(candidate.error);
    const jkt = candidate.jkt;

    const verified = await verifyRequest(request, auth, jkt, url);
    if (verified instanceof Response) return verified;
    try {
      if (!await options.bindings.bindIfAbsent(auth.identity.sessionId, jkt, auth.identity.userId)) {
        return proofError("PROOF_KEY_MISMATCH");
      }
    } catch {
      return errorResponse("TETHER_STATE_UNAVAILABLE", 503);
    }

    return withNonce(Response.json({ bound: true }, { status: 200 }), verified.nonce);
  }

  async function refreshCookie(request: Request): Promise<Response> {
    if (request.method !== "POST") return methodNotAllowed("POST");
    if (cookieSessions === undefined) return errorResponse("TETHER_COOKIE_UNAVAILABLE", 503);
    if (refreshStore === undefined) return errorResponse("TETHER_REFRESH_UNAVAILABLE", 503);
    const url = targetUrl(request);
    if (url instanceof Response) return url;
    if (!isSameOrigin(request, url)) return errorResponse("ORIGIN_REJECTED", 403);

    const auth = await authenticate(request);
    if (auth instanceof Response) return auth;

    let expectedJkt: string | null;
    try {
      expectedJkt = await options.bindings.getJkt(auth.identity.sessionId, auth.identity.userId);
    } catch {
      return errorResponse("TETHER_STATE_UNAVAILABLE", 503);
    }
    if (expectedJkt === null) return proofError("PROOF_KEY_MISMATCH");

    const verified = await verifyRequest(request, auth, expectedJkt, url, true);
    if (verified instanceof Response) return verified;

    let presented: TetherCookieSession | null;
    try {
      presented = await cookieSessions.readFromRequest(request);
    } catch {
      return errorResponse("TETHER_COOKIE_UNAVAILABLE", 503);
    }
    if (
      presented !== null &&
      (presented.userId !== auth.identity.userId ||
        presented.sessionId !== auth.identity.sessionId || presented.jkt !== expectedJkt)
    ) {
      return refreshError("REFRESH_TOKEN_MISMATCH", 401, verified.nonce);
    }

    let ticket: Awaited<ReturnType<TetherCookieSessionManager["createTicket"]>>;
    try {
      ticket = await cookieSessions.createTicket({
        userId: auth.identity.userId,
        sessionId: auth.identity.sessionId,
        jkt: expectedJkt,
      });
    } catch {
      return refreshError("TETHER_COOKIE_UNAVAILABLE", 503, verified.nonce);
    }

    let rotation: TetherRefreshRotationResult;
    try {
      rotation = await refreshStore.rotate({
        ...auth.identity,
        jkt: verified.jkt,
        ...(presented === null
          ? {}
          : { presentedToken: { tokenId: presented.tokenId, expiresAt: presented.expiresAt } }),
        nextToken: {
          tokenId: ticket.session.tokenId,
          issuedAt: ticket.session.issuedAt,
          expiresAt: ticket.session.expiresAt,
        },
      });
    } catch {
      return refreshError("TETHER_REFRESH_UNAVAILABLE", 503, verified.nonce);
    }
    if (rotation.status === "reuse") return refreshError("REFRESH_REUSE", 401, verified.nonce);
    if (rotation.status === "revoked") return refreshError("TETHER_SESSION_REVOKED", 401, verified.nonce);
    if (rotation.status === "key-mismatch") return proofError("PROOF_KEY_MISMATCH", verified.nonce);

    if (rotation.status === "retry") {
      try {
        ticket = await cookieSessions.createTicket(
          { userId: auth.identity.userId, sessionId: auth.identity.sessionId, jkt: expectedJkt },
          rotation.token,
        );
      } catch {
        return refreshError("TETHER_COOKIE_UNAVAILABLE", 503, verified.nonce);
      }
    }

    const response = withNonce(new Response(null, { status: 204 }), verified.nonce);
    return cookieSessions.attach(response, ticket.value);
  }

  async function clearCookie(request: Request): Promise<Response> {
    if (request.method !== "DELETE") return methodNotAllowed("DELETE");
    const url = targetUrl(request);
    if (url instanceof Response) return url;
    if (!isSameOrigin(request, url)) return errorResponse("ORIGIN_REJECTED", 403);
    return clearTetherCookie(new Response(null, {
      status: 204,
      headers: { "cache-control": "private, no-store" },
    }));
  }

  async function readCookieSession(
    cookieValue: string | null | undefined,
  ): Promise<TetherCookieSession | null> {
    if (cookieSessions === undefined) return null;
    const session = await cookieSessions.verify(cookieValue);
    if (session === null) return null;
    const expectedJkt = await options.bindings.getJkt(session.sessionId, session.userId);
    return expectedJkt === session.jkt ? session : null;
  }

  function protectCookie(
    handler: TetherCookieRouteHandler,
    routeOptions: TetherRouteOptions = {},
  ): (request: Request) => Promise<Response> {
    const policy = resolveRoutePolicy(licenseRuntime.onUnlicensed, routeOptions);
    return async (request) => {
      if (request.method !== "GET" && request.method !== "HEAD") return methodNotAllowed("GET, HEAD");
      const disposition = await unlicensedDisposition(policy);
      if (disposition instanceof Response) return disposition;
      if (disposition !== undefined) return handler(request, disposition);
      if (cookieSessions === undefined) return errorResponse("TETHER_COOKIE_UNAVAILABLE", 503);

      let session: TetherCookieSession | null;
      try {
        session = await cookieSessions.readFromRequest(request);
      } catch {
        return errorResponse("TETHER_COOKIE_UNAVAILABLE", 503);
      }
      if (session === null) return errorResponse("AUTH_REQUIRED", 401);

      let expectedJkt: string | null;
      try {
        expectedJkt = await options.bindings.getJkt(session.sessionId, session.userId);
      } catch {
        return errorResponse("TETHER_STATE_UNAVAILABLE", 503);
      }
      if (expectedJkt === null || expectedJkt !== session.jkt) {
        return errorResponse("AUTH_REQUIRED", 401);
      }

      return withNonce(await handler(request, { ...session, licensed: true, bound: true }));
    };
  }

  function protect(
    handler: TetherRouteHandler,
    routeOptions: TetherRouteOptions = {},
  ): (request: Request) => Promise<Response> {
    const policy = resolveRoutePolicy(licenseRuntime.onUnlicensed, routeOptions);
    return async (request) => {
      const disposition = await unlicensedDisposition(policy);
      if (disposition instanceof Response) return disposition;
      if (disposition !== undefined) return handler(request, disposition);
      const auth = await authenticate(request);
      if (auth instanceof Response) return auth;
      const url = targetUrl(request);
      if (url instanceof Response) return url;

      let expectedJkt: string | null;
      try {
        expectedJkt = await options.bindings.getJkt(auth.identity.sessionId, auth.identity.userId);
      } catch {
        return errorResponse("TETHER_STATE_UNAVAILABLE", 503);
      }
      if (expectedJkt === null) return proofError("PROOF_KEY_MISMATCH");

      const verified = await verifyRequest(request, auth, expectedJkt, url);
      if (verified instanceof Response) return verified;
      const response = await handler(request, {
        ...auth.identity,
        licensed: true,
        bound: true,
        proofId: verified.proofId,
      });
      return withNonce(response, verified.nonce);
    };
  }

  return {
    bind,
    refreshCookie,
    clearCookie,
    readCookieSession,
    protectCookie,
    protect,
    licenseStatus: () => licenseRuntime.client?.current() ?? null,
  };
}

interface LicenseRuntime {
  readonly environment: LicenseEnvironment;
  readonly onUnlicensed: "open" | "closed";
  readonly client?: TetherLicenseClient;
  lastWarningAt: number;
}

function initializeLicense(options: TetherNextLicenseOptions | undefined): LicenseRuntime {
  const env = serverEnvironment();
  const explicitEnvironment = options?.environment ?? env.TETHER_ENV;
  if (
    explicitEnvironment !== undefined &&
    explicitEnvironment !== "production" &&
    explicitEnvironment !== "development"
  ) {
    throw new Error("TETHER_ENV must be 'production' or 'development'.");
  }
  const environment = explicitEnvironment ?? (env.NODE_ENV === "production" ? "production" : "development");
  const onUnlicensed = options?.onUnlicensed ?? "open";
  if (onUnlicensed !== "open" && onUnlicensed !== "closed") {
    throw new TypeError("onUnlicensed must be 'open' or 'closed'.");
  }
  const allowUnlicensed = options?.allowUnlicensed ?? env.TETHER_ALLOW_UNLICENSED === "true";
  const apiKey = options?.apiKey ?? env.TETHER_KEY;
  const projectId = options?.projectId ?? env.TETHER_PROJECT_ID;
  const issuer = options?.issuer ?? env.TETHER_LICENSE_ISSUER ??
    (environment === "development" ? "http://localhost:3000" : undefined);
  const runtime: LicenseRuntime = { environment, onUnlicensed, lastWarningAt: 0 };

  if (apiKey === undefined || apiKey.length === 0) {
    if (environment === "production" && !allowUnlicensed) {
      throw new Error("Tether production protection requires TETHER_KEY. Run 'npx tether init' or set allowUnlicensed: true explicitly.");
    }
    if (environment === "development") {
      if (!developmentUnlicensedNoticeLogged) {
        developmentUnlicensedNoticeLogged = true;
        console.info("[Tether] running without a license in development; DPoP protection remains active.");
      }
    } else {
      warnUnlicensed(runtime, "TETHER_KEY is missing; production routes are not protected");
    }
    return runtime;
  }

  const expectedPrefix = environment === "production" ? "tk_live_" : "tk_test_";
  if (!apiKey.startsWith(expectedPrefix)) {
    throw new Error(`Tether API key does not match ${environment}; expected a ${expectedPrefix} key.`);
  }
  if (projectId === undefined || projectId.length === 0 || issuer === undefined || issuer.length === 0) {
    if (!allowUnlicensed) {
      throw new Error("Tether licensing requires TETHER_PROJECT_ID and TETHER_LICENSE_ISSUER.");
    }
    warnUnlicensed(runtime, "license configuration is incomplete; production routes are not protected");
    return runtime;
  }

  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    throw new Error("TETHER_LICENSE_ISSUER must be an absolute URL.");
  }
  if (
    (issuerUrl.protocol !== "https:" &&
      !(environment === "development" && issuerUrl.protocol === "http:" && issuerUrl.hostname === "localhost"))
  ) {
    throw new Error("TETHER_LICENSE_ISSUER must use HTTPS outside local development.");
  }

  const licenseEndpoint = options?.licenseEndpoint ?? env.TETHER_LICENSE_ENDPOINT ??
    new URL("/v1/license", issuerUrl).href;
  const jwksEndpoint = options?.jwksEndpoint ?? env.TETHER_JWKS_ENDPOINT;
  validateLicenseEndpoint(licenseEndpoint, "TETHER_LICENSE_ENDPOINT", environment);
  if (jwksEndpoint !== undefined) {
    validateLicenseEndpoint(jwksEndpoint, "TETHER_JWKS_ENDPOINT", environment);
  }
  const client = createTetherLicenseClient({
    apiKey,
    projectId,
    issuer,
    environment,
    licenseEndpoint,
    ...(jwksEndpoint === undefined ? {} : { jwksEndpoint }),
    ...(options?.embeddedJwks === undefined ? {} : { embeddedJwks: options.embeddedJwks }),
    ...(options?.initialSnapshot === undefined ? {} : { initialSnapshot: options.initialSnapshot }),
    ...(options?.cache === undefined ? {} : { cache: options.cache }),
    ...(options?.fetcher === undefined ? {} : { fetcher: options.fetcher }),
    ...(options?.refreshIntervalMilliseconds === undefined
      ? {}
      : { refreshIntervalMilliseconds: options.refreshIntervalMilliseconds }),
    ...(options?.now === undefined ? {} : { now: options.now }),
    ...(options?.onLicenseChange === undefined ? {} : { onLicenseChange: options.onLicenseChange }),
  });
  return { ...runtime, client };
}

function licenseGateReason(runtime: LicenseRuntime): "required" | "inactive" | undefined {
  if (runtime.environment !== "production") return undefined;
  const current = runtime.client?.current();
  if (current === undefined || current === null) return "required";
  return current.protectionEnabled ? undefined : "inactive";
}

function warnUnlicensed(runtime: LicenseRuntime, message: string): void {
  const now = Date.now();
  if (now - runtime.lastWarningAt < 60 * 60 * 1000) return;
  runtime.lastWarningAt = now;
  console.warn(`[Tether] UNLICENSED: ${message}. Tether sessions are NOT protected.`);
}

function serverEnvironment(): Record<string, string | undefined> {
  const processLike = (globalThis as typeof globalThis & {
    process?: { readonly env?: Record<string, string | undefined> };
  }).process;
  return processLike?.env ?? {};
}

function validateLicenseEndpoint(
  value: string,
  name: string,
  environment: LicenseEnvironment,
): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL.`);
  }
  if (
    url.protocol !== "https:" &&
    !(environment === "development" && url.protocol === "http:" && url.hostname === "localhost")
  ) {
    throw new Error(`${name} must use HTTPS outside local development.`);
  }
}

function resolveRoutePolicy(
  adapterDefault: "open" | "closed",
  routeOptions: TetherRouteOptions,
): "open" | "closed" {
  const policy = routeOptions.onUnlicensed ?? adapterDefault;
  if (policy !== "open" && policy !== "closed") {
    throw new TypeError("Route onUnlicensed must be 'open' or 'closed'.");
  }
  return policy;
}

/** Process-local nonce store for a single-server demo; production should share it across instances. */
export class MemoryTetherNonceStore implements TetherNonceStore {
  readonly #nonces = new Map<string, { readonly value: string; readonly expiresAt: number }>();
  readonly #ttlMilliseconds: number;
  readonly #maxEntries: number;
  readonly #now: () => number;

  constructor(options: { ttlMilliseconds?: number; maxEntries?: number; now?: () => number } = {}) {
    this.#ttlMilliseconds = options.ttlMilliseconds ?? 30_000;
    this.#maxEntries = options.maxEntries ?? 10_000;
    this.#now = options.now ?? Date.now;
    if (!Number.isSafeInteger(this.#ttlMilliseconds) || this.#ttlMilliseconds < 1) {
      throw new RangeError("Nonce TTL must be a positive integer");
    }
    if (!Number.isSafeInteger(this.#maxEntries) || this.#maxEntries < 1) {
      throw new RangeError("Nonce capacity must be a positive integer");
    }
  }

  async get(sessionId: string, origin: string): Promise<string | undefined> {
    const key = nonceKey(sessionId, origin);
    const record = this.#nonces.get(key);
    if (record === undefined) return undefined;
    if (record.expiresAt <= this.#now()) {
      this.#nonces.delete(key);
      return undefined;
    }
    return record.value;
  }

  async issue(sessionId: string, origin: string): Promise<string> {
    const now = this.#now();
    for (const [key, value] of this.#nonces) {
      if (value.expiresAt <= now) this.#nonces.delete(key);
    }
    const key = nonceKey(sessionId, origin);
    if (!this.#nonces.has(key) && this.#nonces.size >= this.#maxEntries) {
      throw new Error("Nonce store capacity reached");
    }
    const bytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(bytes);
    const value = encodeBase64Url(bytes);
    this.#nonces.set(key, { value, expiresAt: now + this.#ttlMilliseconds });
    return value;
  }
}

function nonceKey(sessionId: string, origin: string): string {
  return `${sessionId}\n${origin}`;
}

function proofError(reasonCode: ProofReasonCode, nonce?: string): Response {
  const status = reasonCode === "PROOF_MALFORMED"
    ? 400
    : reasonCode === "PROOF_REPLAY_STORE_UNAVAILABLE"
      ? 503
      : 401;
  const headers = new Headers({ "cache-control": "private, no-store" });
  if (nonce !== undefined) {
    headers.set("DPoP-Nonce", nonce);
    headers.set("WWW-Authenticate", 'DPoP error="use_dpop_nonce"');
  }
  return Response.json({ reasonCode }, { status, headers });
}

function errorResponse(code: string, status: number): Response {
  return Response.json({ error: code }, {
    status,
    headers: { "cache-control": "private, no-store" },
  });
}

function methodNotAllowed(allow: string): Response {
  return Response.json({ error: "METHOD_NOT_ALLOWED" }, {
    status: 405,
    headers: { allow, "cache-control": "private, no-store" },
  });
}

function refreshError(code: string, status: number, nonce?: string): Response {
  const headers = new Headers({ "cache-control": "private, no-store" });
  if (nonce !== undefined) headers.set("DPoP-Nonce", nonce);
  return Response.json(
    code === "REFRESH_REUSE" ? { reasonCode: code } : { error: code },
    { status, headers },
  );
}

function isSameOrigin(request: Request, url: URL): boolean {
  const origin = request.headers.get("Origin");
  if (origin === null) return false;
  try {
    const parsed = new URL(origin);
    return parsed.origin !== "null" && parsed.origin === url.origin;
  } catch {
    return false;
  }
}

function withNonce(response: Response, nonce?: string): Response {
  const headers = new Headers(response.headers);
  headers.set("cache-control", "private, no-store");
  if (nonce !== undefined) headers.set("DPoP-Nonce", nonce);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
