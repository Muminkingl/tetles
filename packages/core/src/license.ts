import {
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
} from "jose";
import type { JSONWebKeySet } from "jose";
import { z } from "zod";

export const LICENSE_AUDIENCE = "tether-license";
export const LICENSE_SCHEMA_VERSION = 1;
export const LICENSE_CLOCK_SKEW_SECONDS = 120;
export const LICENSE_MAX_LIFETIME_SECONDS = 24 * 60 * 60;
export const LICENSE_OFFLINE_GRACE_SECONDS = 7 * 24 * 60 * 60;

export const licenseEnvironmentSchema = z.enum(["production", "development"]);
export const licenseStateSchema = z.enum([
  "trial",
  "active",
  "grace",
  "limited",
  "suspended",
  "revoked",
]);

export const licenseClaimsSchema = z.object({
  iss: z.string().url(),
  aud: z.literal(LICENSE_AUDIENCE),
  sub: z.string().min(1).max(128),
  jti: z.string().uuid(),
  iat: z.number().int().nonnegative(),
  nbf: z.number().int().nonnegative(),
  exp: z.number().int().nonnegative(),
  plan: z.enum(["free", "team", "business", "enterprise"]),
  state: licenseStateSchema,
  trial_ends_at: z.number().int().nonnegative().nullable(),
  grace_ends_at: z.number().int().nonnegative().nullable(),
  limits: z.object({
    mpu: z.number().int().nonnegative(),
    projects: z.number().int().nonnegative(),
    retention_days: z.number().int().nonnegative(),
    seats: z.number().int().nonnegative(),
  }).strict(),
  features: z.array(z.enum([
    "alerts",
    "shared_store",
    "policies",
    "webhooks",
    "audit_exports",
    "retention",
  ])).max(32),
  env: licenseEnvironmentSchema,
  ver: z.literal(LICENSE_SCHEMA_VERSION),
}).strict();

export type LicenseEnvironment = z.infer<typeof licenseEnvironmentSchema>;
export type LicenseState = z.infer<typeof licenseStateSchema>;
export type LicenseClaims = z.infer<typeof licenseClaimsSchema>;

export interface VerifyLicenseOptions {
  readonly jwks: JSONWebKeySet;
  readonly issuer: string;
  readonly projectId: string;
  readonly environment: LicenseEnvironment;
  readonly now?: Date;
  /** Only set for a previously cached token after a license-server outage. */
  readonly allowExpiredBySeconds?: number;
}

export interface VerifiedLicense {
  readonly claims: LicenseClaims;
  readonly stale: boolean;
  readonly protectionEnabled: boolean;
}

/** Verify the signed license contract. Expired-token allowance is only for caller-verified cache entries. */
export async function verifyLicense(
  token: string,
  options: VerifyLicenseOptions,
): Promise<VerifiedLicense> {
  const now = options.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);
  const allowance = options.allowExpiredBySeconds ?? 0;
  if (!Number.isSafeInteger(allowance) || allowance < 0 || allowance > LICENSE_OFFLINE_GRACE_SECONDS) {
    throw new TypeError("License stale allowance is outside the supported range.");
  }

  let untrustedClaims: ReturnType<typeof decodeJwt>;
  let untrustedHeader: ReturnType<typeof decodeProtectedHeader>;
  try {
    untrustedClaims = decodeJwt(token);
    untrustedHeader = decodeProtectedHeader(token);
  } catch {
    throw new Error("LICENSE_TOKEN_MALFORMED");
  }
  if (
    untrustedHeader.alg !== "ES256" || untrustedHeader.typ !== "JWT" ||
    typeof untrustedHeader.kid !== "string" || untrustedHeader.kid.length === 0
  ) {
    throw new Error("LICENSE_HEADER_REJECTED");
  }

  const claimsResult = licenseClaimsSchema.safeParse(untrustedClaims);
  if (!claimsResult.success) throw new Error("LICENSE_CLAIMS_REJECTED");
  const untrusted = claimsResult.data;
  if (
    untrusted.iss !== options.issuer || untrusted.sub !== options.projectId ||
    untrusted.env !== options.environment || untrusted.exp <= untrusted.iat ||
    untrusted.nbf > untrusted.exp ||
    untrusted.exp - untrusted.iat > LICENSE_MAX_LIFETIME_SECONDS
  ) {
    throw new Error("LICENSE_BINDING_REJECTED");
  }
  if (untrusted.iat > nowSeconds + LICENSE_CLOCK_SKEW_SECONDS) {
    throw new Error("LICENSE_NOT_YET_VALID");
  }
  if (untrusted.nbf > nowSeconds + LICENSE_CLOCK_SKEW_SECONDS) {
    throw new Error("LICENSE_NOT_YET_VALID");
  }
  if (nowSeconds > untrusted.exp + allowance + LICENSE_CLOCK_SKEW_SECONDS) {
    throw new Error("LICENSE_EXPIRED");
  }

  const stale = nowSeconds > untrusted.exp + LICENSE_CLOCK_SKEW_SECONDS;
  const verificationDate = stale
    ? new Date((untrusted.exp - 1) * 1000)
    : now;
  const keySet = sanitizeLicenseJwks(options.jwks);
  try {
    const { payload, protectedHeader } = await jwtVerify(
      token,
      createLocalJWKSet(keySet),
      {
        algorithms: ["ES256"],
        issuer: options.issuer,
        audience: LICENSE_AUDIENCE,
        subject: options.projectId,
        typ: "JWT",
        requiredClaims: ["iat", "nbf", "exp", "jti"],
        clockTolerance: LICENSE_CLOCK_SKEW_SECONDS,
        currentDate: verificationDate,
      },
    );
    if (protectedHeader.kid !== untrustedHeader.kid) throw new Error("LICENSE_KID_MISMATCH");
    const verifiedClaims = licenseClaimsSchema.parse(payload);
    if (verifiedClaims.env !== options.environment) throw new Error("LICENSE_ENVIRONMENT_MISMATCH");
    return {
      claims: verifiedClaims,
      stale,
      protectionEnabled: ["trial", "active", "grace"].includes(verifiedClaims.state),
    };
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("LICENSE_")) throw error;
    throw new Error("LICENSE_SIGNATURE_REJECTED");
  }
}

/** Reject private, non-ES256, duplicate-kid, or malformed keys before constructing a resolver. */
export function sanitizeLicenseJwks(jwks: JSONWebKeySet): JSONWebKeySet {
  if (!Array.isArray(jwks.keys) || jwks.keys.length === 0 || jwks.keys.length > 32) {
    throw new Error("LICENSE_JWKS_REJECTED");
  }
  const kids = new Set<string>();
  const keys = jwks.keys.map((key) => {
    if (
      key.kty !== "EC" || key.crv !== "P-256" || typeof key.x !== "string" ||
      typeof key.y !== "string" || typeof key.kid !== "string" || key.kid.length === 0 ||
      (key.alg !== undefined && key.alg !== "ES256") ||
      (key.use !== undefined && key.use !== "sig") ||
      (key.key_ops !== undefined && !key.key_ops.includes("verify")) ||
      Object.hasOwn(key, "d") || kids.has(key.kid)
    ) {
      throw new Error("LICENSE_JWKS_REJECTED");
    }
    kids.add(key.kid);
    return { ...key, alg: "ES256", use: "sig" };
  });
  return { keys };
}
