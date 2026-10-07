import {
  calculateJwkThumbprint,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
} from "jose";
import { computeAccessTokenHash } from "./access-token-hash.js";
import { proofClaimsSchema, publicP256JwkSchema } from "./proof-schema.js";
import type { ProofReasonCode } from "./reason-code.js";
import type { ReplayStore } from "./replay-store.js";

export interface VerifyProofInput {
  readonly proof: string | null | undefined;
  readonly method: string;
  /** Absolute request URL as seen by the customer middleware after trusted proxy handling. */
  readonly url: string;
  readonly accessToken: string;
  /** Thumbprint bound to the already-authenticated session. */
  readonly expectedJkt: string;
  readonly replayStore: ReplayStore;
  readonly expectedNonce?: string;
  readonly nowMilliseconds?: number;
  readonly proofWindowSeconds?: number;
}

export type VerifyProofResult =
  | { readonly ok: true; readonly jkt: string; readonly proofId: string }
  | { readonly ok: false; readonly reasonCode: ProofReasonCode };

const failure = (reasonCode: ProofReasonCode): VerifyProofResult => ({
  ok: false,
  reasonCode,
});
const MAX_PROOF_LENGTH = 8_192;

/** Verify a DPoP-style request proof. The caller must authenticate the access token separately. */
export async function verifyProof(input: VerifyProofInput): Promise<VerifyProofResult> {
  if (input.proof === null || input.proof === undefined || input.proof.length === 0) {
    return failure("PROOF_MISSING");
  }
  if (input.proof.length > MAX_PROOF_LENGTH) return failure("PROOF_MALFORMED");

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(input.proof);
  } catch {
    return failure("PROOF_MALFORMED");
  }

  if (header.typ !== "dpop+jwt") return failure("PROOF_TYPE_REJECTED");
  if (header.alg !== "ES256") return failure("PROOF_ALGORITHM_REJECTED");

  if (containsPrivateEcKeyMaterial(header.jwk)) return failure("PROOF_MALFORMED");
  const jwkResult = publicP256JwkSchema.safeParse(header.jwk);
  if (!jwkResult.success) return failure("PROOF_MALFORMED");

  let verifiedPayload: unknown;
  try {
    const publicKey = await importJWK(jwkResult.data, "ES256");
    const verified = await jwtVerify(input.proof, publicKey, {
      algorithms: ["ES256"],
      clockTolerance: 0,
    });
    verifiedPayload = verified.payload;
  } catch {
    return failure("PROOF_BAD_SIG");
  }

  const claimsResult = proofClaimsSchema.safeParse(verifiedPayload);
  if (!claimsResult.success) return failure("PROOF_MALFORMED");
  const claims = claimsResult.data;

  let jkt: string;
  try {
    jkt = await calculateJwkThumbprint(jwkResult.data, "sha256");
  } catch {
    return failure("PROOF_MALFORMED");
  }
  if (!constantTimeEqual(jkt, input.expectedJkt)) {
    return failure("PROOF_KEY_MISMATCH");
  }

  if (claims.htm !== input.method) return failure("PROOF_METHOD_MISMATCH");
  if (!sameRequestTarget(claims.htu, input.url)) return failure("PROOF_URL_MISMATCH");

  let expectedAth: string;
  try {
    expectedAth = await computeAccessTokenHash(input.accessToken);
  } catch {
    return failure("PROOF_TOKEN_MISMATCH");
  }
  if (!constantTimeEqual(claims.ath, expectedAth)) {
    return failure("PROOF_TOKEN_MISMATCH");
  }

  if (input.expectedNonce !== undefined && claims.nonce !== input.expectedNonce) {
    return failure("PROOF_NONCE_REQUIRED");
  }

  const nowMilliseconds = input.nowMilliseconds ?? Date.now();
  const proofWindowSeconds = input.proofWindowSeconds ?? 30;
  if (
    !Number.isFinite(nowMilliseconds) ||
    !Number.isSafeInteger(proofWindowSeconds) ||
    proofWindowSeconds < 1
  ) {
    return failure("PROOF_STALE");
  }
  const outsideProofWindow =
    Math.abs(nowMilliseconds / 1_000 - claims.iat) > proofWindowSeconds;
  // An outstanding server nonce is fresh server-side evidence when a client's clock is skewed.
  // The adapter must scope and expire expectedNonce; jti replay protection still applies below.
  if (
    outsideProofWindow &&
    !(input.expectedNonce !== undefined && claims.nonce === input.expectedNonce)
  ) {
    return failure("PROOF_STALE");
  }

  const replayTtlMilliseconds = proofWindowSeconds * 2_000;
  try {
    const accepted = await input.replayStore.claim(
      JSON.stringify([jkt, claims.jti]),
      replayTtlMilliseconds,
    );
    if (!accepted) return failure("PROOF_REPLAY");
  } catch {
    return failure("PROOF_REPLAY_STORE_UNAVAILABLE");
  }

  return { ok: true, jkt, proofId: claims.jti };
}

function containsPrivateEcKeyMaterial(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.prototype.hasOwnProperty.call(value, "d")
  );
}

function sameRequestTarget(proofUrl: string, requestUrl: string): boolean {
  try {
    return requestTargetWithoutSearchOrHash(proofUrl) ===
      requestTargetWithoutSearchOrHash(requestUrl);
  } catch {
    return false;
  }
}

function requestTargetWithoutSearchOrHash(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new TypeError("Only HTTP request URLs can be verified");
  }
  url.search = "";
  url.hash = "";
  return url.href;
}

function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}
