import os from "node:os";
import { performance } from "node:perf_hooks";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  computeAccessTokenHash,
  MemoryReplayStore,
  verifyProof,
} from "../dist/index.js";

const sampleCount = parsePositiveInteger(process.env.TETHER_BENCH_SAMPLES, 5_000);
const warmupCount = Math.min(300, Math.max(100, Math.floor(sampleCount / 10)));
const accessToken = "tether-benchmark-token-not-a-secret";
const url = "https://benchmark.example.test/api/private";
const method = "GET";

const keyPair = await generateKeyPair("ES256");
const exportedJwk = await exportJWK(keyPair.publicKey);
const publicJwk = {
  kty: "EC",
  crv: "P-256",
  x: exportedJwk.x,
  y: exportedJwk.y,
};
const expectedJkt = await calculateJwkThumbprint(publicJwk, "sha256");
const ath = await computeAccessTokenHash(accessToken);
const issuedAt = Math.floor(Date.now() / 1_000);
const proofCount = warmupCount + sampleCount;
const proofs = [];
for (let index = 0; index < proofCount; index += 1) {
  proofs.push(await new SignJWT({
    htm: method,
    htu: url,
    iat: issuedAt,
    jti: `benchmark-proof-${String(index).padStart(8, "0")}`,
    ath,
  })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
    .sign(keyPair.privateKey));
}

const replayStore = new MemoryReplayStore(proofCount + 1);
const verify = (proof) => verifyProof({
  proof,
  method,
  url,
  accessToken,
  expectedJkt,
  replayStore,
});

for (let index = 0; index < warmupCount; index += 1) {
  const result = await verify(proofs[index]);
  if (!result.ok) throw new Error(`Warm-up verification failed: ${result.reasonCode}`);
}

const samples = new Array(sampleCount);
for (let index = 0; index < sampleCount; index += 1) {
  const startedAt = performance.now();
  const result = await verify(proofs[warmupCount + index]);
  const elapsedMilliseconds = performance.now() - startedAt;
  if (!result.ok) throw new Error(`Verification failed: ${result.reasonCode}`);
  samples[index] = elapsedMilliseconds;
}

samples.sort((left, right) => left - right);
const totalMilliseconds = samples.reduce((sum, value) => sum + value, 0);
const cpu = os.cpus()[0]?.model ?? "unknown";
console.log(JSON.stringify({
  benchmark: "@tether/core verifyProof; valid unique proofs; in-memory replay store",
  node: process.version,
  platform: `${process.platform}-${process.arch}`,
  cpu,
  samples: sampleCount,
  warmup: warmupCount,
  latencyMilliseconds: {
    mean: round(totalMilliseconds / sampleCount),
    p50: percentile(samples, 0.50),
    p95: percentile(samples, 0.95),
    p99: percentile(samples, 0.99),
    max: round(samples.at(-1)),
  },
  notes: [
    "Excludes access-token authentication, database lookups, HTTP/Next.js overhead, and proof creation.",
    "Run on an otherwise idle machine; compare only results from the same runtime and host.",
  ],
}, null, 2));

function parsePositiveInteger(value, fallback) {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 100) {
    throw new RangeError("TETHER_BENCH_SAMPLES must be an integer of at least 100.");
  }
  return parsed;
}

function percentile(sortedValues, fraction) {
  return round(sortedValues[Math.ceil(sortedValues.length * fraction) - 1]);
}

function round(value) {
  return Math.round(value * 1_000) / 1_000;
}
