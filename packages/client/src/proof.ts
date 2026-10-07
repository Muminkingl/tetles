import { computeAccessTokenHash } from "@tether/core/access-token-hash";
import { TetherClientError } from "./errors.js";

export interface CreateProofInput {
  readonly privateKey: CryptoKey;
  readonly publicJwk: JsonWebKey;
  readonly method: string;
  readonly url: string;
  readonly accessToken: string;
  readonly nonce?: string;
  readonly nowMilliseconds?: number;
  readonly jti?: string;
}

export async function createProof(input: CreateProofInput): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) throw new TetherClientError("CRYPTO_UNAVAILABLE");

  let ath: string;
  try {
    ath = await computeAccessTokenHash(input.accessToken);
  } catch {
    throw new TetherClientError("INVALID_ACCESS_TOKEN");
  }

  const url = new URL(input.url);
  url.search = "";
  url.hash = "";
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: input.publicJwk,
  };
  const payload: Record<string, string | number> = {
    htm: input.method.toUpperCase(),
    htu: url.href,
    iat: Math.floor((input.nowMilliseconds ?? Date.now()) / 1_000),
    jti: input.jti ?? crypto.randomUUID(),
    ath,
  };
  if (input.nonce !== undefined) payload.nonce = input.nonce;

  const signingInput = `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(payload))}`;
  try {
    const signature = await subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      input.privateKey,
      new TextEncoder().encode(signingInput),
    );
    return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
  } catch {
    throw new TetherClientError("KEY_INVALID");
  }
}

function base64Url(value: string | Uint8Array): string {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
