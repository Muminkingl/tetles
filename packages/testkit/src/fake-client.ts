import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { computeAccessTokenHash } from "../../core/src/index.js";

export interface ProofOptions {
  readonly method: string;
  readonly url: string;
  readonly issuedAtSeconds?: number;
  readonly nonce?: string;
}

export interface FakeClient {
  readonly jkt: string;
  createProof(options: ProofOptions): Promise<string>;
}

/** Creates a throwaway proof signer for security tests; never use it in an application. */
export async function createFakeClient(accessToken: string): Promise<FakeClient> {
  const keys = await generateKeyPair("ES256");
  const exported = await exportJWK(keys.publicKey);
  if (exported.kty !== "EC" || exported.crv !== "P-256" || !exported.x || !exported.y) {
    throw new Error("Test key export did not produce an EC P-256 public key");
  }

  const publicJwk = {
    kty: "EC" as const,
    crv: "P-256" as const,
    x: exported.x,
    y: exported.y,
  };
  const jkt = await calculateJwkThumbprint(publicJwk, "sha256");

  return {
    jkt,
    async createProof(options) {
      const claims: Record<string, unknown> = {
        jti: crypto.randomUUID(),
        htm: options.method,
        htu: withoutQueryOrFragment(options.url),
        iat: options.issuedAtSeconds ?? Math.floor(Date.now() / 1_000),
        ath: await computeAccessTokenHash(accessToken),
      };
      if (options.nonce !== undefined) claims.nonce = options.nonce;

      return new SignJWT(claims)
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
        .sign(keys.privateKey);
    },
  };
}

function withoutQueryOrFragment(value: string): string {
  const url = new URL(value);
  url.search = "";
  url.hash = "";
  return url.href;
}
