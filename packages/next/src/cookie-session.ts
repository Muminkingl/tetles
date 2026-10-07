import { jwtVerify, SignJWT } from "jose";

export const TETHER_COOKIE_NAME = "__Host-tether";
const COOKIE_ISSUER = "tether";
const COOKIE_AUDIENCE = "tether-page";

export interface TetherCookieIdentity {
  readonly userId: string;
  readonly sessionId: string;
  readonly jkt: string;
}

export interface TetherCookieSession extends TetherCookieIdentity {
  readonly tokenId: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
}

export interface TetherCookieTicket {
  readonly value: string;
  readonly session: TetherCookieSession;
}

export interface TetherCookieTicketMetadata {
  readonly tokenId: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
}

export interface TetherCookieSessionOptions {
  /** Supply a fresh 32-byte-or-longer secret. A callback supports lazy server configuration. */
  readonly secret: Uint8Array | (() => Uint8Array);
  /** Short-lived companion cookie; defaults to 300 seconds and cannot exceed five minutes. */
  readonly ttlSeconds?: number;
  readonly now?: () => number;
}

/** Signs a short-lived HttpOnly session ticket after the caller has verified a device proof. */
export class TetherCookieSessionManager {
  readonly #secret: Uint8Array | (() => Uint8Array);
  readonly #now: () => number;
  readonly ttlSeconds: number;

  constructor(options: TetherCookieSessionOptions) {
    this.#secret = options.secret;
    this.#now = options.now ?? Date.now;
    this.ttlSeconds = options.ttlSeconds ?? 300;
    if (!Number.isSafeInteger(this.ttlSeconds) || this.ttlSeconds < 1 || this.ttlSeconds > 300) {
      throw new RangeError("Tether cookie lifetime must be between 1 and 300 seconds.");
    }
  }

  async issue(identity: TetherCookieIdentity): Promise<string> {
    return (await this.createTicket(identity)).value;
  }

  async createTicket(
    identity: TetherCookieIdentity,
    metadata?: TetherCookieTicketMetadata,
  ): Promise<TetherCookieTicket> {
    if (!isValidIdentity(identity)) throw new TypeError("Invalid Tether cookie identity.");
    const issuedAt = metadata?.issuedAt ?? Math.floor(this.#now() / 1_000);
    const tokenId = metadata?.tokenId ?? crypto.randomUUID();
    const expiresAt = metadata?.expiresAt ?? issuedAt + this.ttlSeconds;
    if (
      !Number.isSafeInteger(issuedAt) || issuedAt > Math.floor(this.#now() / 1_000) ||
      !Number.isSafeInteger(expiresAt) || expiresAt <= issuedAt ||
      expiresAt - issuedAt > this.ttlSeconds ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(tokenId)
    ) {
      throw new TypeError("Invalid Tether cookie ticket metadata.");
    }
    const value = await new SignJWT({ sid: identity.sessionId, cnf: { jkt: identity.jkt } })
      .setProtectedHeader({ alg: "HS256", typ: "tether-session+jwt" })
      .setIssuer(COOKIE_ISSUER)
      .setAudience(COOKIE_AUDIENCE)
      .setSubject(identity.userId)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .setJti(tokenId)
      .sign(this.#key());
    return {
      value,
      session: {
        ...identity,
        tokenId,
        issuedAt,
        expiresAt,
      },
    };
  }

  async verify(value: string | null | undefined): Promise<TetherCookieSession | null> {
    if (value === null || value === undefined || value.length === 0 || value.length > 4_096) {
      return null;
    }
    const verified = await jwtVerify(value, this.#key(), {
      algorithms: ["HS256"],
      audience: COOKIE_AUDIENCE,
      currentDate: new Date(this.#now()),
      issuer: COOKIE_ISSUER,
      clockTolerance: 0,
      maxTokenAge: this.ttlSeconds,
      requiredClaims: ["sub", "sid", "cnf", "iat", "exp", "jti"],
    }).catch(() => null);
    if (verified === null) return null;

    const payload = verified.payload;
    const confirmation = payload.cnf;
    const jkt = typeof confirmation === "object" && confirmation !== null
      ? (confirmation as Record<string, unknown>).jkt
      : undefined;
    if (
      verified.protectedHeader.typ !== "tether-session+jwt" ||
      typeof payload.sub !== "string" || payload.sub.length === 0 || payload.sub.length > 256 ||
      typeof payload.sid !== "string" || payload.sid.length === 0 || payload.sid.length > 256 ||
      typeof payload.jti !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(payload.jti) ||
      typeof payload.iat !== "number" || !Number.isSafeInteger(payload.iat) ||
      payload.iat > Math.floor(this.#now() / 1_000) ||
      typeof payload.exp !== "number" || !Number.isSafeInteger(payload.exp) ||
      payload.exp <= payload.iat || payload.exp - payload.iat > this.ttlSeconds ||
      typeof jkt !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(jkt)
    ) {
      return null;
    }

    return {
      userId: payload.sub,
      sessionId: payload.sid,
      jkt,
      tokenId: payload.jti,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
    };
  }

  async readFromRequest(request: Request): Promise<TetherCookieSession | null> {
    return this.verify(readCookie(request.headers.get("cookie"), TETHER_COOKIE_NAME));
  }

  attach(response: Response, token: string): Response {
    return withSetCookie(response, serializeCookie(token, this.ttlSeconds));
  }

  clear(response: Response): Response {
    return clearTetherCookie(response);
  }

  #key(): Uint8Array {
    const key = typeof this.#secret === "function" ? this.#secret() : this.#secret;
    if (!(key instanceof Uint8Array) || key.byteLength < 32) {
      throw new Error("Tether cookie secret must contain at least 32 bytes.");
    }
    return key;
  }
}

function isValidIdentity(value: unknown): value is TetherCookieIdentity {
  if (typeof value !== "object" || value === null) return false;
  const identity = value as Record<string, unknown>;
  return typeof identity.userId === "string" && identity.userId.length > 0 && identity.userId.length <= 256 &&
    typeof identity.sessionId === "string" && identity.sessionId.length > 0 && identity.sessionId.length <= 256 &&
    typeof identity.jkt === "string" && /^[A-Za-z0-9_-]{43}$/u.test(identity.jkt);
}

function readCookie(header: string | null, name: string): string | null {
  if (header === null) return null;
  const prefix = `${name}=`;
  const values: string[] = [];
  for (const item of header.split(";")) {
    const cookie = item.trim();
    if (cookie.startsWith(prefix)) values.push(cookie.slice(prefix.length));
  }
  return values.length === 1 ? values[0]! : null;
}

function serializeCookie(token: string, ttlSeconds: number): string {
  return `${TETHER_COOKIE_NAME}=${token}; Path=/; Max-Age=${ttlSeconds}; HttpOnly; Secure; SameSite=Lax`;
}

export function clearTetherCookie(response: Response): Response {
  return withSetCookie(response, `${TETHER_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}

function withSetCookie(response: Response, cookie: string): Response {
  const headers = new Headers(response.headers);
  headers.append("set-cookie", cookie);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
