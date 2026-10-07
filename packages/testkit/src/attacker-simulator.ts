import {
  MemoryReplayStore,
  verifyProof,
} from "../../core/src/index.js";
import type {
  ProofReasonCode,
  VerifyProofResult,
} from "../../core/src/index.js";
import { createFakeClient } from "./fake-client.js";

const ACCESS_TOKEN = "simulator.access.token";
const REQUEST_URL = "https://api.example.test/account";

export interface AttackScenario {
  readonly name: string;
  readonly expectedReason: ProofReasonCode;
  run(): Promise<VerifyProofResult>;
}

/** Builds independent attacks against the core verifier using throwaway signing keys. */
export async function buildAttackScenarios(): Promise<readonly AttackScenario[]> {
  const victim = await createFakeClient(ACCESS_TOKEN);
  const attacker = await createFakeClient(ACCESS_TOKEN);
  const capturedProof = await victim.createProof({ method: "GET", url: REQUEST_URL });
  const replayStore = new MemoryReplayStore();

  // Prime the store so the attack scenario tries to reuse a proof already accepted once.
  await verifyProof({
    proof: capturedProof,
    method: "GET",
    url: REQUEST_URL,
    accessToken: ACCESS_TOKEN,
    expectedJkt: victim.jkt,
    replayStore,
  });

  const base = {
    method: "GET",
    url: REQUEST_URL,
    accessToken: ACCESS_TOKEN,
    expectedJkt: victim.jkt,
  } as const;

  return [
    {
      name: "copied access token without the device proof",
      expectedReason: "PROOF_MISSING",
      run: () => verifyProof({ ...base, proof: null, replayStore: new MemoryReplayStore() }),
    },
    {
      name: "captured proof replayed a second time",
      expectedReason: "PROOF_REPLAY",
      run: () => verifyProof({ ...base, proof: capturedProof, replayStore }),
    },
    {
      name: "copied token signed by a different key",
      expectedReason: "PROOF_KEY_MISMATCH",
      run: async () => verifyProof({
        ...base,
        proof: await attacker.createProof({ method: "GET", url: REQUEST_URL }),
        replayStore: new MemoryReplayStore(),
      }),
    },
    {
      name: "proof sent with a different HTTP method",
      expectedReason: "PROOF_METHOD_MISMATCH",
      run: async () => verifyProof({
        ...base,
        proof: await victim.createProof({ method: "POST", url: REQUEST_URL }),
        replayStore: new MemoryReplayStore(),
      }),
    },
    {
      name: "proof sent to a different URL",
      expectedReason: "PROOF_URL_MISMATCH",
      run: async () => verifyProof({
        ...base,
        proof: await victim.createProof({ method: "GET", url: "https://api.example.test/admin" }),
        replayStore: new MemoryReplayStore(),
      }),
    },
    {
      name: "stale proof from a captured request",
      expectedReason: "PROOF_STALE",
      run: async () => verifyProof({
        ...base,
        proof: await victim.createProof({
          method: "GET",
          url: REQUEST_URL,
          issuedAtSeconds: Math.floor(Date.now() / 1_000) - 120,
        }),
        replayStore: new MemoryReplayStore(),
      }),
    },
  ];
}
