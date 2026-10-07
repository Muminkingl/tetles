import "server-only";

import type {
  TetherBindingStore,
  TetherRefreshRotationInput,
  TetherRefreshRotationResult,
  TetherRefreshStore,
} from "@tether/next";
import { getSupabaseAdminClient } from "./supabase-admin";

const CACHE_TTL_MS = 30_000;
const CACHE_LIMIT = 10_000;
const EXAMPLE_PROJECT_NAME = "Tether example";

interface CacheEntry<T> {
  readonly value: T;
  readonly expiresAt: number;
}

/**
 * Supabase-backed bindings with a short process-local cache. A cache hit keeps the protected
 * request path free of database calls; revocation changes become visible within 30 seconds.
 */
export class SupabaseBindingStore implements TetherBindingStore, TetherRefreshStore {
  readonly #projectIdByOwner = new Map<string, CacheEntry<string>>();
  readonly #jktByOwnerAndSession = new Map<string, CacheEntry<string | null>>();

  async getJkt(sessionId: string, userId?: string): Promise<string | null> {
    assertUuid(sessionId, "session ID");
    const ownerId = requireOwnerId(userId);
    const cacheKey = bindingCacheKey(ownerId, sessionId);
    const cached = readCache(this.#jktByOwnerAndSession, cacheKey);
    if (cached !== undefined) return cached;

    const projectId = await this.#projectId(ownerId);
    const { data, error } = await getSupabaseAdminClient()
      .from("bindings")
      .select("jkt, revoked_at")
      .eq("project_id", projectId)
      .eq("session_id", sessionId)
      .maybeSingle();
    if (error !== null) throw new Error("Could not read the Tether binding.");

    const jkt = data !== null && data.revoked_at === null ? String(data.jkt) : null;
    writeCache(this.#jktByOwnerAndSession, cacheKey, jkt);
    return jkt;
  }

  async bindIfAbsent(sessionId: string, jkt: string, userId?: string): Promise<boolean> {
    assertUuid(sessionId, "session ID");
    const ownerId = requireOwnerId(userId);
    const projectId = await this.#projectId(ownerId);
    const cacheKey = bindingCacheKey(ownerId, sessionId);

    const { error } = await getSupabaseAdminClient()
      .from("bindings")
      .insert({ project_id: projectId, session_id: sessionId, jkt });

    if (error === null) {
      writeCache(this.#jktByOwnerAndSession, cacheKey, jkt);
      return true;
    }
    if (error.code !== "23505") throw new Error("Could not save the Tether binding.");

    const { data, error: readError } = await getSupabaseAdminClient()
      .from("bindings")
      .select("jkt, revoked_at")
      .eq("project_id", projectId)
      .eq("session_id", sessionId)
      .maybeSingle();
    if (readError !== null) throw new Error("Could not verify the existing Tether binding.");

    const matches = data !== null && data.revoked_at === null && data.jkt === jkt;
    writeCache(this.#jktByOwnerAndSession, cacheKey, matches ? jkt : null);
    return matches;
  }

  async rotate(input: TetherRefreshRotationInput): Promise<TetherRefreshRotationResult> {
    assertUuid(input.sessionId, "session ID");
    const ownerId = requireOwnerId(input.userId);
    assertUuid(input.nextToken.tokenId, "refresh token ID");
    if (input.presentedToken !== undefined) {
      assertUuid(input.presentedToken.tokenId, "presented refresh token ID");
    }
    if (!/^[A-Za-z0-9_-]{43}$/u.test(input.jkt)) {
      throw new TypeError("Invalid refresh proof thumbprint.");
    }
    assertSafeUnixSeconds(input.nextToken.issuedAt, "next ticket issued-at time");
    assertSafeUnixSeconds(input.nextToken.expiresAt, "next ticket expiry time");
    const projectId = await this.#projectId(ownerId);
    const { data, error } = await getSupabaseAdminClient().rpc("rotate_tether_cookie", {
      p_project_id: projectId,
      p_user_id: ownerId,
      p_session_id: input.sessionId,
      p_proof_jkt: input.jkt,
      p_presented_token_id: input.presentedToken?.tokenId ?? null,
      p_presented_expires_at: input.presentedToken === undefined
        ? null
        : new Date(input.presentedToken.expiresAt * 1_000).toISOString(),
      p_next_token_id: input.nextToken.tokenId,
      p_next_issued_at: new Date(input.nextToken.issuedAt * 1_000).toISOString(),
      p_next_expires_at: new Date(input.nextToken.expiresAt * 1_000).toISOString(),
    });
    const cacheKey = bindingCacheKey(ownerId, input.sessionId);
    if (error !== null) {
      this.#jktByOwnerAndSession.delete(cacheKey);
      throw new Error("Could not rotate the Tether cookie.");
    }
    if (typeof data !== "object" || data === null || !("status" in data)) {
      this.#jktByOwnerAndSession.delete(cacheKey);
      throw new Error("The Tether cookie rotation returned an invalid result.");
    }
    const result = data as Record<string, unknown>;
    if (result.status === "rotated") return { status: "rotated" };
    if (result.status === "reuse" || result.status === "revoked" || result.status === "key-mismatch") {
      if (result.status !== "key-mismatch") this.#jktByOwnerAndSession.delete(cacheKey);
      return { status: result.status };
    }
    if (result.status === "retry" && typeof result.token === "object" && result.token !== null) {
      const token = result.token as Record<string, unknown>;
      if (
        typeof token.tokenId === "string" &&
        typeof token.issuedAt === "number" && Number.isSafeInteger(token.issuedAt) &&
        typeof token.expiresAt === "number" && Number.isSafeInteger(token.expiresAt)
      ) {
        assertUuid(token.tokenId, "retry ticket ID");
        return {
          status: "retry",
          token: { tokenId: token.tokenId, issuedAt: token.issuedAt, expiresAt: token.expiresAt },
        };
      }
    }
    {
      this.#jktByOwnerAndSession.delete(cacheKey);
      throw new Error("The Tether cookie rotation returned an invalid result.");
    }
  }

  async #projectId(ownerId: string): Promise<string> {
    const cached = readCache(this.#projectIdByOwner, ownerId);
    if (cached !== undefined) return cached;

    const { data, error } = await getSupabaseAdminClient()
      .from("projects")
      .upsert({ owner_id: ownerId, name: EXAMPLE_PROJECT_NAME }, { onConflict: "owner_id,name" })
      .select("id")
      .single();
    if (error !== null || data === null) throw new Error("Could not load the Tether project.");

    const projectId = String(data.id);
    writeCache(this.#projectIdByOwner, ownerId, projectId);
    return projectId;
  }
}

function requireOwnerId(userId: string | undefined): string {
  assertUuid(userId, "user ID");
  return userId;
}

function assertUuid(value: string | undefined, label: string): asserts value is string {
  if (value === undefined || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
}

function assertSafeUnixSeconds(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`Invalid ${label}.`);
}

function bindingCacheKey(ownerId: string, sessionId: string): string {
  return `${ownerId}:${sessionId}`;
}

function readCache<T>(cache: Map<string, CacheEntry<T>>, key: string): T | undefined {
  const entry = cache.get(key);
  if (entry === undefined) return undefined;
  if (entry.expiresAt <= Date.now()) {
    cache.delete(key);
    return undefined;
  }
  return entry.value;
}

function writeCache<T>(cache: Map<string, CacheEntry<T>>, key: string, value: T): void {
  const now = Date.now();
  for (const [cachedKey, entry] of cache) {
    if (entry.expiresAt <= now) cache.delete(cachedKey);
  }
  while (!cache.has(key) && cache.size >= CACHE_LIMIT) {
    const oldestKey = cache.keys().next().value as string | undefined;
    if (oldestKey === undefined) break;
    cache.delete(oldestKey);
  }
  cache.set(key, { value, expiresAt: now + CACHE_TTL_MS });
}
