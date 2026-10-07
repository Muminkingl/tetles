import "server-only";

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { REASON_CODES } from "@tether/core";
import { getSupabaseAdminClient } from "./supabase-admin";

const MAX_BODY_BYTES = 64 * 1024;
const MAX_EVENTS_PER_BATCH = 100;
const MAX_CLOCK_SKEW_SECONDS = 300;
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 60;
const RATE_LIMIT_CACHE_SIZE = 10_000;
const RETENTION_INTERVAL_MS = 24 * 60 * 60 * 1000;
const EVENT_TYPES = new Set(["request_verified", "request_blocked", "relogin_required"]);
const UA_FAMILIES = new Set(["Chrome", "Edge", "Firefox", "Safari", "Other"]);
const REASON_CODE_SET = new Set<string>([...REASON_CODES, "REFRESH_REUSE"]);

interface RateRecord {
  count: number;
  windowStartedAt: number;
}

interface IngestEvent {
  readonly type: string;
  readonly reason_code: string | null;
  readonly session_id: string | null;
  readonly ip_prefix: string | null;
  readonly ua_family: string | null;
}

const rateRecords = new Map<string, RateRecord>();
let lastRetentionAttemptAt = 0;

/** HMAC-authenticated, batched event endpoint. It is isolated from protected request handlers. */
export async function ingestTetherEvents(request: Request): Promise<Response> {
  const apiKey = request.headers.get("x-tether-key");
  const timestampText = request.headers.get("x-tether-timestamp");
  const signatureText = request.headers.get("x-tether-signature");
  if (
    apiKey === null || !/^tth_live_[A-Za-z0-9_-]{43}$/u.test(apiKey) ||
    timestampText === null || !/^\d{1,12}$/u.test(timestampText) ||
    signatureText === null || !/^[0-9a-f]{64}$/iu.test(signatureText)
  ) {
    return jsonError("INGEST_AUTH_REQUIRED", 401);
  }

  const timestamp = Number(timestampText);
  if (!Number.isSafeInteger(timestamp) || Math.abs(Math.floor(Date.now() / 1000) - timestamp) > MAX_CLOCK_SKEW_SECONDS) {
    return jsonError("INGEST_SIGNATURE_EXPIRED", 401);
  }

  let rawBody: string;
  try {
    rawBody = await readLimitedBody(request);
  } catch (error) {
    if (error instanceof BodyTooLargeError) return jsonError("INGEST_BODY_TOO_LARGE", 413);
    return jsonError("INGEST_INVALID_BODY", 400);
  }

  const expectedSignature = createHmac("sha256", apiKey)
    .update(timestampText)
    .update(".")
    .update(rawBody)
    .digest();
  const providedSignature = Buffer.from(signatureText, "hex");
  if (!timingSafeEqual(expectedSignature, providedSignature)) {
    return jsonError("INGEST_AUTH_REQUIRED", 401);
  }

  const keyHash = createHash("sha256").update(apiKey).digest("hex");
  const rateResult = consumeRateLimit(keyHash);
  if (!rateResult.allowed) {
    return Response.json({ error: "INGEST_RATE_LIMITED" }, {
      status: 429,
      headers: { "cache-control": "no-store", "retry-after": String(rateResult.retryAfterSeconds) },
    });
  }

  let payload: unknown;
  try {
    payload = JSON.parse(rawBody) as unknown;
  } catch {
    return jsonError("INGEST_INVALID_BODY", 400);
  }
  const events = parseEvents(payload);
  if (events === null) return jsonError("INGEST_INVALID_EVENTS", 400);

  const supabase = getSupabaseAdminClient();
  const { data: keyRecord, error: keyError } = await supabase
    .from("api_keys")
    .select("id, project_id, revoked_at")
    .eq("key_hash", keyHash)
    .maybeSingle();
  if (keyError !== null) return jsonError("INGEST_UNAVAILABLE", 503);
  if (keyRecord === null || keyRecord.revoked_at !== null) {
    return jsonError("INGEST_AUTH_REQUIRED", 401);
  }

  const rows = events.map((event) => ({ project_id: keyRecord.project_id, ...event }));
  const { error: insertError } = await supabase.from("events").insert(rows);
  if (insertError !== null) {
    if (insertError.code === "22P02" || insertError.code === "23514") {
      return jsonError("INGEST_INVALID_EVENTS", 400);
    }
    return jsonError("INGEST_UNAVAILABLE", 503);
  }

  runRetentionCleanup(supabase);

  void supabase.from("api_keys")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", keyRecord.id)
    .then(() => undefined, () => undefined);

  return Response.json({ accepted: rows.length }, {
    status: 202,
    headers: { "cache-control": "no-store" },
  });
}

function runRetentionCleanup(supabase: ReturnType<typeof getSupabaseAdminClient>): void {
  const now = Date.now();
  if (now - lastRetentionAttemptAt < RETENTION_INTERVAL_MS) return;
  lastRetentionAttemptAt = now;
  void supabase.rpc("delete_expired_tether_events").then(({ error }) => {
    if (error !== null) lastRetentionAttemptAt = 0;
  }, () => {
    lastRetentionAttemptAt = 0;
  });
}

function parseEvents(payload: unknown): IngestEvent[] | null {
  if (!isRecord(payload) || !onlyKeys(payload, new Set(["events"]))) return null;
  if (!Array.isArray(payload.events) || payload.events.length < 1 || payload.events.length > MAX_EVENTS_PER_BATCH) {
    return null;
  }

  const events: IngestEvent[] = [];
  for (const candidate of payload.events) {
    if (!isRecord(candidate) || !onlyKeys(candidate, new Set([
      "type", "reasonCode", "sessionId", "ipPrefix", "uaFamily",
    ]))) return null;

    const type = candidate.type;
    const reasonCode = candidate.reasonCode;
    const sessionId = candidate.sessionId;
    const ipPrefix = candidate.ipPrefix;
    const uaFamily = candidate.uaFamily;
    if (typeof type !== "string" || !EVENT_TYPES.has(type)) return null;
    if (reasonCode !== undefined && (typeof reasonCode !== "string" || !REASON_CODE_SET.has(reasonCode))) return null;
    if (type === "request_blocked" && typeof reasonCode !== "string") return null;
    if (sessionId !== undefined && (typeof sessionId !== "string" || !isUuid(sessionId))) return null;
    if (ipPrefix !== undefined && (typeof ipPrefix !== "string" || !isPrefixShape(ipPrefix))) return null;
    if (uaFamily !== undefined && (typeof uaFamily !== "string" || !UA_FAMILIES.has(uaFamily))) return null;

    events.push({
      type,
      reason_code: typeof reasonCode === "string" ? reasonCode : null,
      session_id: typeof sessionId === "string" ? sessionId : null,
      ip_prefix: typeof ipPrefix === "string" ? ipPrefix : null,
      ua_family: typeof uaFamily === "string" ? uaFamily : null,
    });
  }
  return events;
}

function isPrefixShape(value: string): boolean {
  if (value.length > 64) return false;
  const slash = value.lastIndexOf("/");
  if (slash < 1 || slash === value.length - 1 || value.indexOf("/") !== slash) return false;
  const mask = value.slice(slash + 1);
  const address = value.slice(0, slash);
  if (!/^\d{1,3}$/u.test(mask)) return false;
  const maskLength = Number(mask);
  const family = isIP(address);
  if (family === 6) return maskLength <= 48;
  if (family === 4) return maskLength <= 24;
  return false;
}

function consumeRateLimit(keyHash: string): { allowed: boolean; retryAfterSeconds: number } {
  const now = Date.now();
  for (const [key, record] of rateRecords) {
    if (now - record.windowStartedAt >= RATE_WINDOW_MS) rateRecords.delete(key);
  }

  let record = rateRecords.get(keyHash);
  if (record === undefined) {
    if (rateRecords.size >= RATE_LIMIT_CACHE_SIZE) {
      const oldestKey = rateRecords.keys().next().value as string | undefined;
      if (oldestKey !== undefined) rateRecords.delete(oldestKey);
    }
    record = { count: 0, windowStartedAt: now };
    rateRecords.set(keyHash, record);
  }

  if (record.count >= RATE_LIMIT) {
    const remaining = Math.max(1, RATE_WINDOW_MS - (now - record.windowStartedAt));
    return { allowed: false, retryAfterSeconds: Math.ceil(remaining / 1000) };
  }
  record.count += 1;
  return { allowed: true, retryAfterSeconds: 0 };
}

async function readLimitedBody(request: Request): Promise<string> {
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > MAX_BODY_BYTES) throw new BodyTooLargeError();
  if (request.body === null) return "";

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new BodyTooLargeError();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

class BodyTooLargeError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}

function jsonError(error: string, status: number): Response {
  return Response.json({ error }, { status, headers: { "cache-control": "no-store" } });
}
