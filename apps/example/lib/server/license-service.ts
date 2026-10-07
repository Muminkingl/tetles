import "server-only";

import { createHash } from "node:crypto";
import { isIP } from "node:net";
import {
  publicLicenseJwks,
  sanitizeLicenseJwks,
  signLicense,
} from "@tether/core";
import type {
  LicenseEnvironment,
  LicenseSigningPrivateJwk,
  LicenseState,
} from "@tether/core";
import { getSupabaseAdminClient } from "./supabase-admin";

const DAY_SECONDS = 24 * 60 * 60;

export async function issueLicense(request: Request): Promise<Response> {
  const body = await readRequestEnvironment(request);
  if (body instanceof Response) return body;

  const authorization = request.headers.get("authorization");
  const match = authorization?.match(/^Bearer\s+((?:tk_(?:live|test)_|tth_live_)[A-Za-z0-9_-]{43})$/u);
  const apiKey = match?.[1];
  if (apiKey === undefined) return licenseError("LICENSE_KEY_INVALID", 401);

  const environment: LicenseEnvironment = apiKey.startsWith("tk_test_") ? "development" : "production";
  if (body !== environment) return licenseError("LICENSE_ENVIRONMENT_MISMATCH", 400);

  try {
    const supabase = getSupabaseAdminClient();
    const ipBucket = hashRateLimitBucket(`ip:${requestIpPrefix(request)}`);
    if (!(await consumeRateLimit(supabase, ipBucket, 120))) {
      return licenseError("LICENSE_RATE_LIMITED", 429);
    }

    const keyHash = createHash("sha256").update(apiKey, "utf8").digest("hex");
    const { data: apiKeyRow, error: keyError } = await supabase
      .from("api_keys")
      .select("id, project_id, env, revoked_at")
      .eq("key_hash", keyHash)
      .maybeSingle();
    if (keyError !== null) return licenseError("LICENSE_SERVICE_UNAVAILABLE", 503);
    if (apiKeyRow === null || apiKeyRow.env !== environment) {
      return licenseError("LICENSE_KEY_INVALID", 401);
    }

    const keyRateBucket = hashRateLimitBucket(`key:${apiKeyRow.id}`);
    if (!(await consumeRateLimit(supabase, keyRateBucket, 60))) {
      return licenseError("LICENSE_RATE_LIMITED", 429);
    }

    const now = new Date();
    const nowSeconds = Math.floor(now.getTime() / 1000);
    const project = apiKeyRow.revoked_at === null
      ? await loadAndTransitionProject(supabase, apiKeyRow.project_id, environment, now)
      : await readProject(supabase, apiKeyRow.project_id);
    if (project === null) return licenseError("LICENSE_PROJECT_NOT_FOUND", 404);

    const { data: plan, error: planError } = await supabase
      .from("plans")
      .select("limits, features")
      .eq("id", project.plan_id)
      .maybeSingle();
    if (planError !== null || plan === null) {
      return licenseError("LICENSE_SERVICE_UNAVAILABLE", 503);
    }

    const settings = getLicenseSigningSettings();
    const expiresAt = nowSeconds + DAY_SECONDS;
    const jti = globalThis.crypto.randomUUID();
    const state: LicenseState = apiKeyRow.revoked_at === null
      ? project.license_state
      : "revoked";
    const token = await signLicense({
      iss: settings.issuer,
      aud: "tether-license",
      sub: project.id,
      jti,
      iat: nowSeconds,
      nbf: nowSeconds,
      exp: expiresAt,
      plan: project.plan_id,
      state,
      trial_ends_at: toNumericDate(project.trial_ends_at),
      grace_ends_at: toNumericDate(project.grace_ends_at),
      limits: plan.limits,
      features: plan.features,
      env: environment,
      ver: 1,
    }, settings.privateJwk, settings.kid);

    const { error: auditError } = await supabase.from("licenses_issued").insert({
      jti,
      project_id: project.id,
      key_id: apiKeyRow.id,
      kid: settings.kid,
      env: environment,
      issued_at: now.toISOString(),
      exp: new Date(expiresAt * 1000).toISOString(),
    });
    if (auditError !== null) return licenseError("LICENSE_SERVICE_UNAVAILABLE", 503);

    await supabase.from("api_keys").update({ last_used_at: now.toISOString() }).eq("id", apiKeyRow.id);
    return Response.json(
      { token, expiresAt },
      { headers: { "cache-control": "private, no-store" } },
    );
  } catch {
    return licenseError("LICENSE_SERVICE_UNAVAILABLE", 503);
  }
}

export async function serveLicenseJwks(): Promise<Response> {
  try {
    const settings = getLicenseSigningSettings();
    const supabase = getSupabaseAdminClient();
    const current = publicLicenseJwks(settings.privateJwk, settings.kid).keys[0]!;
    const { error: upsertError } = await supabase.from("signing_keys").upsert({
      kid: settings.kid,
      public_jwk: current,
      status: "active",
    }, { onConflict: "kid" });
    if (upsertError !== null) return licenseError("LICENSE_SERVICE_UNAVAILABLE", 503);

    const { data, error } = await supabase
      .from("signing_keys")
      .select("public_jwk")
      .in("status", ["active", "retiring"]);
    if (error !== null || data === null) return licenseError("LICENSE_SERVICE_UNAVAILABLE", 503);
    const jwks = sanitizeLicenseJwks({ keys: data.map((row) => row.public_jwk) });
    return Response.json(jwks, {
      headers: { "cache-control": "public, max-age=300, stale-while-revalidate=3600" },
    });
  } catch {
    return licenseError("LICENSE_SERVICE_UNAVAILABLE", 503);
  }
}

async function loadAndTransitionProject(
  supabase: ReturnType<typeof getSupabaseAdminClient>,
  projectId: string,
  environment: LicenseEnvironment,
  now: Date,
): Promise<LicenseProject | null> {
  let project = await readProject(supabase, projectId);
  if (project === null) return null;

  if (environment === "production" && project.plan_id === "free" && project.trial_started_at === null) {
    const trialEnd = new Date(now.getTime() + 14 * DAY_SECONDS * 1000);
    const graceEnd = new Date(trialEnd.getTime() + 14 * DAY_SECONDS * 1000);
    const { error } = await supabase.from("projects").update({
      license_state: "trial",
      trial_started_at: now.toISOString(),
      trial_ends_at: trialEnd.toISOString(),
      grace_ends_at: graceEnd.toISOString(),
    }).eq("id", projectId).is("trial_started_at", null);
    if (error !== null) throw new Error("LICENSE_PROJECT_UPDATE_FAILED");
    project = await readProject(supabase, projectId);
    if (project === null) return null;
  }

  if (
    project.license_state === "trial" && project.trial_ends_at !== null &&
    Date.parse(project.trial_ends_at) <= now.getTime()
  ) {
    const { error } = await supabase.from("projects").update({ license_state: "grace" })
      .eq("id", projectId).eq("license_state", "trial");
    if (error !== null) throw new Error("LICENSE_PROJECT_UPDATE_FAILED");
    project = await readProject(supabase, projectId);
    if (project === null) return null;
  }

  if (
    project.license_state === "grace" && project.grace_ends_at !== null &&
    Date.parse(project.grace_ends_at) <= now.getTime()
  ) {
    const { error } = await supabase.from("projects").update({ license_state: "limited" })
      .eq("id", projectId).eq("license_state", "grace");
    if (error !== null) throw new Error("LICENSE_PROJECT_UPDATE_FAILED");
    project = await readProject(supabase, projectId);
  }
  return project;
}

interface LicenseProject {
  readonly id: string;
  readonly plan_id: "free" | "team" | "business" | "enterprise";
  readonly license_state: LicenseState;
  readonly trial_started_at: string | null;
  readonly trial_ends_at: string | null;
  readonly grace_ends_at: string | null;
}

async function readProject(
  supabase: ReturnType<typeof getSupabaseAdminClient>,
  projectId: string,
): Promise<LicenseProject | null> {
  const { data, error } = await supabase.from("projects")
    .select("id, plan_id, license_state, trial_started_at, trial_ends_at, grace_ends_at")
    .eq("id", projectId)
    .maybeSingle();
  if (error !== null) throw new Error("LICENSE_PROJECT_READ_FAILED");
  if (data === null) return null;
  if (
    typeof data.id !== "string" ||
    !["free", "team", "business", "enterprise"].includes(data.plan_id) ||
    !["trial", "active", "grace", "limited", "suspended", "revoked"].includes(data.license_state)
  ) {
    throw new Error("LICENSE_PROJECT_DATA_INVALID");
  }
  return data as LicenseProject;
}

function getLicenseSigningSettings(): {
  readonly privateJwk: LicenseSigningPrivateJwk;
  readonly kid: string;
  readonly issuer: string;
} {
  const encoded = process.env.TETHER_LICENSE_SIGNING_PRIVATE_JWK_B64;
  const kid = process.env.TETHER_LICENSE_SIGNING_KID;
  const issuer = process.env.TETHER_LICENSE_ISSUER ||
    (process.env.NODE_ENV === "production" ? undefined : "http://localhost:3000");
  if (encoded === undefined || kid === undefined || issuer === undefined) {
    throw new Error("TETHER_LICENSE_SIGNING_CONFIG_MISSING");
  }
  const parsed: unknown = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  if (!isPrivateJwk(parsed)) throw new Error("TETHER_LICENSE_SIGNING_CONFIG_INVALID");
  const parsedIssuer = new URL(issuer);
  if (parsedIssuer.protocol !== "https:" && parsedIssuer.hostname !== "localhost") {
    throw new Error("TETHER_LICENSE_ISSUER_INVALID");
  }
  return { privateJwk: parsed, kid, issuer: parsedIssuer.origin };
}

function isPrivateJwk(value: unknown): value is LicenseSigningPrivateJwk {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return record.kty === "EC" && record.crv === "P-256" &&
    typeof record.x === "string" && typeof record.y === "string" && typeof record.d === "string";
}

async function readRequestEnvironment(request: Request): Promise<LicenseEnvironment | Response> {
  let text: string;
  try {
    text = await request.text();
  } catch {
    return licenseError("LICENSE_REQUEST_INVALID", 400);
  }
  if (text.length > 1024) return licenseError("LICENSE_REQUEST_INVALID", 400);
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return licenseError("LICENSE_REQUEST_INVALID", 400);
  }
  if (
    typeof body !== "object" || body === null ||
    !["production", "development"].includes(String((body as Record<string, unknown>).env))
  ) {
    return licenseError("LICENSE_REQUEST_INVALID", 400);
  }
  return (body as { env: LicenseEnvironment }).env;
}

async function consumeRateLimit(
  supabase: ReturnType<typeof getSupabaseAdminClient>,
  bucketHash: string,
  limit: number,
): Promise<boolean> {
  const { data, error } = await supabase.rpc("consume_tether_license_rate_limit", {
    p_bucket_hash: bucketHash,
    p_limit: limit,
  });
  if (error !== null || typeof data !== "boolean") throw new Error("LICENSE_RATE_LIMIT_UNAVAILABLE");
  return data;
}

function requestIpPrefix(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  if (forwarded === undefined || isIP(forwarded) === 0) return "unknown";
  if (isIP(forwarded) === 4) return `${forwarded.split(".").slice(0, 3).join(".")}.0/24`;
  return `${forwarded.split(":").slice(0, 3).join(":")}/48`;
}

function hashRateLimitBucket(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function toNumericDate(value: string | null): number | null {
  if (value === null) return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new Error("LICENSE_PROJECT_DATE_INVALID");
  return Math.floor(milliseconds / 1000);
}

function licenseError(code: string, status: number): Response {
  return Response.json({ error: code }, {
    status,
    headers: { "cache-control": "private, no-store" },
  });
}
