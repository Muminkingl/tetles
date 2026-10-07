import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  SignJWT,
} from "jose";
import * as fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import {
  computeAccessTokenHash,
  MemoryReplayStore,
  REASON_CODES,
  ReplayStoreCapacityError,
  verifyProof,
} from "../src/index.js";
import type { VerifyProofInput } from "../src/index.js";

const RFC_ACCESS_TOKEN = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
const RFC_ATH = "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo";

const TEST_ACCESS_TOKEN = "test.access.token";
const TEST_URL = "https://api.example.test/private/resource";

let privateKey: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
let publicJwk: { kty: "EC"; crv: "P-256"; x: string; y: string };
let testJkt: string;
let proofCounter = 0;

beforeAll(async () => {
  const keys = await generateKeyPair("ES256");
  privateKey = keys.privateKey;
  const exported = await exportJWK(keys.publicKey);
  if (exported.kty !== "EC" || exported.crv !== "P-256" || !exported.x || !exported.y) {
    throw new Error("Test key export did not produce an EC P-256 public key");
  }
  publicJwk = {
    kty: "EC",
    crv: "P-256",
    x: exported.x,
    y: exported.y,
  };
  testJkt = await calculateJwkThumbprint(publicJwk, "sha256");
});

describe("RFC 9449 examples", () => {
  it("computes the RFC access-token hash", async () => {
    await expect(computeAccessTokenHash(RFC_ACCESS_TOKEN)).resolves.toBe(RFC_ATH);
  });

  it("accepts an ES256 proof carrying the Figure 14 claims", async () => {
    const proof = await makeProof({
      claims: {
        jti: "e1j3V_bKic8-LAEB",
        htm: "GET",
        htu: "https://resource.example.org/protectedresource",
        iat: 1_562_262_618,
        ath: RFC_ATH,
      },
    });
    const result = await verifyProof(input(proof, {
      url: "https://resource.example.org/protectedresource?view=full",
      accessToken: RFC_ACCESS_TOKEN,
      nowMilliseconds: 1_562_262_618_000,
    }));

    expect(result).toEqual({
      ok: true,
      jkt: testJkt,
      proofId: "e1j3V_bKic8-LAEB",
    });
  });
});

describe("verifyProof rejection cases", () => {
  it("rejects a missing or oversized proof", async () => {
    expect(await reasonCode(input(null))).toBe("PROOF_MISSING");
    expect(await reasonCode(input("x".repeat(8_193)))).toBe("PROOF_MALFORMED");
  });

  it("rejects malformed proofs and malformed signed claims", async () => {
    expect(await reasonCode(input("not-a-jwt"))).toBe("PROOF_MALFORMED");
    const proof = await makeProof({ omitClaims: ["ath"] });
    expect(await reasonCode(input(proof))).toBe("PROOF_MALFORMED");
  });

  it("rejects an oversized proof identifier", async () => {
    const proof = await makeProof({ claims: { jti: "j".repeat(129) } });
    expect(await reasonCode(input(proof))).toBe("PROOF_MALFORMED");
  });

  it("rejects an unexpected proof type and every non-ES256 algorithm", async () => {
    const proof = await makeProof();
    expect(await reasonCode(input(rewriteHeader(proof, { typ: "JWT" })))).toBe(
      "PROOF_TYPE_REJECTED",
    );
    expect(await reasonCode(input(rewriteHeader(proof, { alg: "HS256" })))).toBe(
      "PROOF_ALGORITHM_REJECTED",
    );
    expect(await reasonCode(input(rewriteHeader(proof, { alg: "none" })))).toBe(
      "PROOF_ALGORITHM_REJECTED",
    );
  });

  it("rejects private key material in the proof JWK", async () => {
    const proof = await makeProof();
    const privateJwk = { ...publicJwk, d: "private" };
    expect(await reasonCode(input(rewriteHeader(proof, { jwk: privateJwk })))).toBe(
      "PROOF_MALFORMED",
    );
  });

  it("accepts standard public JWK metadata such as Web Crypto key_ops", async () => {
    const proof = await makeProof({
      jwkExtensions: {
        key_ops: ["verify"],
        ext: true,
        alg: "ES256",
        use: "sig",
        kid: "browser-export",
      },
    });
    expect((await verifyProof(input(proof))).ok).toBe(true);
  });

  it("rejects a bad signature and a key not bound to the session", async () => {
    const proof = await makeProof();
    expect(await reasonCode(input(tamperSignature(proof)))).toBe("PROOF_BAD_SIG");
    expect(await reasonCode(input(proof, { expectedJkt: "different-thumbprint" }))).toBe(
      "PROOF_KEY_MISMATCH",
    );
  });

  it("rejects a wrong method, URL, or access token", async () => {
    const proof = await makeProof();
    expect(await reasonCode(input(proof, { method: "POST" }))).toBe(
      "PROOF_METHOD_MISMATCH",
    );
    expect(await reasonCode(input(proof, { url: "https://api.example.test/other" }))).toBe(
      "PROOF_URL_MISMATCH",
    );
    expect(await reasonCode(input(proof, { accessToken: "other.access.token" }))).toBe(
      "PROOF_TOKEN_MISMATCH",
    );
  });

  it("rejects stale proofs and missing or incorrect required nonces", async () => {
    const proof = await makeProof();
    expect(
      await reasonCode(input(proof, { nowMilliseconds: Date.now() + 60_000 })),
    ).toBe("PROOF_STALE");
    expect(await reasonCode(input(proof, { expectedNonce: "server-nonce" }))).toBe(
      "PROOF_NONCE_REQUIRED",
    );

    const nonceProof = await makeProof({ claims: { nonce: "wrong-nonce" } });
    expect(
      await reasonCode(input(nonceProof, { expectedNonce: "server-nonce" })),
    ).toBe("PROOF_NONCE_REQUIRED");
  });

  it("accepts a matching nonce and rejects a repeated proof ID", async () => {
    const proof = await makeProof({ claims: { nonce: "server-nonce" } });
    const replayStore = new MemoryReplayStore();
    const proofInput = input(proof, { expectedNonce: "server-nonce", replayStore });

    expect((await verifyProof(proofInput)).ok).toBe(true);
    expect(await reasonCode(proofInput)).toBe("PROOF_REPLAY");
  });

  it("allows a matching outstanding server nonce to recover a stale client clock", async () => {
    const proof = await makeProof({ claims: { iat: 1, nonce: "server-nonce" } });
    expect(await reasonCode(input(proof))).toBe("PROOF_STALE");

    const result = await verifyProof(input(proof, {
      expectedNonce: "server-nonce",
      nowMilliseconds: Date.now(),
    }));
    expect(result.ok).toBe(true);
  });

  it("fails closed when the replay store is unavailable", async () => {
    const proof = await makeProof();
    const replayStore = { claim: async () => { throw new Error("offline"); } };
    expect(await reasonCode(input(proof, { replayStore }))).toBe(
      "PROOF_REPLAY_STORE_UNAVAILABLE",
    );
  });
});

describe("MemoryReplayStore", () => {
  it("atomically grants a proof ID to only one concurrent request", async () => {
    const store = new MemoryReplayStore();
    const claims = await Promise.all(
      Array.from({ length: 20 }, () => store.claim("same-proof", 1_000)),
    );
    expect(claims.filter(Boolean)).toHaveLength(1);
  });

  it("fails closed when it reaches its configured capacity", async () => {
    const store = new MemoryReplayStore(1);
    await store.claim("first", 10_000);
    await expect(store.claim("second", 10_000)).rejects.toBeInstanceOf(
      ReplayStoreCapacityError,
    );
  });
});

describe("proof parser fuzzing", () => {
  it("returns a stable result for arbitrary input strings", async () => {
    const compactJwtLike = fc
      .tuple(
        fc.string({ maxLength: 64 }),
        fc.string({ maxLength: 128 }),
        fc.string({ maxLength: 128 }),
      )
      .map(([header, payload, signature]) => `${header}.${payload}.${signature}`);

    await fc.assert(
      fc.asyncProperty(fc.oneof(fc.string({ maxLength: 256 }), compactJwtLike), async (proof) => {
        const result = await verifyProof(input(proof));
        if (result.ok) {
          expect(result.proofId).toBeTypeOf("string");
        } else {
          expect(REASON_CODES).toContain(result.reasonCode);
        }
      }),
      { numRuns: 250, seed: 20_261_006 },
    );
  });
});

async function makeProof(options: {
  claims?: Record<string, unknown>;
  omitClaims?: string[];
  jwkExtensions?: Record<string, unknown>;
} = {}): Promise<string> {
  proofCounter += 1;
  const nowMilliseconds = Date.now();
  const claims: Record<string, unknown> = {
    htm: "GET",
    htu: TEST_URL,
    iat: Math.floor(nowMilliseconds / 1_000),
    jti: `test-proof-id-${proofCounter.toString().padStart(8, "0")}`,
    ath: await computeAccessTokenHash(TEST_ACCESS_TOKEN),
    ...options.claims,
  };
  for (const claim of options.omitClaims ?? []) delete claims[claim];
  const proofJwk = { ...publicJwk, ...options.jwkExtensions } as typeof publicJwk;

  return new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: proofJwk })
    .sign(privateKey);
}

function input(
  proof: string | null,
  overrides: Partial<Omit<VerifyProofInput, "proof">> = {},
): VerifyProofInput {
  return {
    proof,
    method: "GET",
    url: TEST_URL,
    accessToken: TEST_ACCESS_TOKEN,
    expectedJkt: testJkt,
    replayStore: new MemoryReplayStore(),
    ...overrides,
  };
}

async function reasonCode(proofInput: VerifyProofInput) {
  const result = await verifyProof(proofInput);
  if (result.ok) throw new Error("Expected the proof to be rejected");
  return result.reasonCode;
}

function rewriteHeader(proof: string, update: Record<string, unknown>): string {
  const [header, payload, signature] = proof.split(".");
  if (!header || !payload || !signature) throw new Error("Expected a compact JWT");
  const decodedHeader = JSON.parse(atob(header.replaceAll("-", "+").replaceAll("_", "/")));
  const encodedHeader = encodeBase64Url(JSON.stringify({ ...decodedHeader, ...update }));
  return `${encodedHeader}.${payload}.${signature}`;
}

function tamperSignature(proof: string): string {
  const segments = proof.split(".");
  const signature = segments[2];
  if (!segments[0] || !segments[1] || !signature) throw new Error("Expected a compact JWT");
  const firstCharacter = signature[0] === "a" ? "b" : "a";
  return `${segments[0]}.${segments[1]}.${firstCharacter}${signature.slice(1)}`;
}

function encodeBase64Url(value: string): string {
  return btoa(value).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
