import { importJWK, SignJWT } from "jose";
import type { JSONWebKeySet, JWK } from "jose";
import { licenseClaimsSchema } from "./license.js";
import type { LicenseClaims } from "./license.js";

export interface LicenseSigningPrivateJwk {
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
  readonly d: string;
}

export async function signLicense(
  claims: LicenseClaims,
  privateJwk: LicenseSigningPrivateJwk,
  kid: string,
): Promise<string> {
  const validatedClaims = licenseClaimsSchema.parse(claims);
  if (kid.length === 0 || kid.length > 128) throw new TypeError("Invalid license signing key ID.");
  const key = await importJWK(privateJwk as JWK, "ES256");
  return new SignJWT(validatedClaims)
    .setProtectedHeader({ alg: "ES256", typ: "JWT", kid })
    .sign(key);
}

export function publicLicenseJwks(
  privateJwk: LicenseSigningPrivateJwk,
  kid: string,
): JSONWebKeySet {
  if (
    privateJwk.kty !== "EC" || privateJwk.crv !== "P-256" ||
    typeof privateJwk.x !== "string" || typeof privateJwk.y !== "string" ||
    typeof privateJwk.d !== "string" || kid.length === 0
  ) {
    throw new TypeError("Invalid ES256 license signing key.");
  }
  return {
    keys: [{
      kty: "EC",
      crv: "P-256",
      x: privateJwk.x,
      y: privateJwk.y,
      kid,
      alg: "ES256",
      use: "sig",
      key_ops: ["verify"],
    }],
  };
}
