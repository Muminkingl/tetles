import { beforeAll, describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair } from "jose";
import {
  LICENSE_AUDIENCE,
  publicLicenseJwks,
  signLicense,
} from "@tether/core";
import type {
  LicenseClaims,
  LicenseEnvironment,
  LicenseSigningPrivateJwk,
  LicenseState,
  VerifiedLicense,
} from "@tether/core";
import { createTetherNext } from "../src/index.js";
import type { TetherLicenseSnapshot } from "../src/index.js";

const STATES: readonly LicenseState[] = [
  "trial",
  "active",
  "grace",
  "limited",
  "suspended",
  "revoked",
];
const POLICIES = ["open", "closed"] as const;
const ENVIRONMENTS: readonly LicenseEnvironment[] = ["development", "production"];
const PROJECT_PREFIX = "license-gate-test";
const URL = "https://app.example.test/private";
const SIGNING_KID = "acceptance-test-key";
const ISSUER_BY_ENV: Record<LicenseEnvironment, string> = {
  development: "http://localhost:3000",
  production: "https://license.example.test",
};

let signer: LicenseSigningPrivateJwk;
let attackerSigner: LicenseSigningPrivateJwk;
let jwks: ReturnType<typeof publicLicenseJwks>;

beforeAll(async () => {
  signer = await generatePrivateJwk();
  attackerSigner = await generatePrivateJwk();
  jwks = publicLicenseJwks(signer, SIGNING_KID);
});

describe("production license gate acceptance matrix", () => {
  for (const environment of ENVIRONMENTS) {
    for (const policy of POLICIES) {
      for (const state of STATES) {
        it(`${environment} / ${state} / onUnlicensed=${policy}`, async () => {
          const projectId = `${PROJECT_PREFIX}-${environment}-${state}-${policy}`;
          const token = await signedLicense({ environment, projectId, state });
          const adapter = createGate({ environment, policy, projectId, token });
          await waitForLicense(adapter);
          expect(adapter.licenseStatus()?.claims.state).toBe(state);

          const route = adapter.protect((_request, context) => Response.json({
            handlerCalled: true,
            licensed: context.licensed,
            bound: context.bound,
          }));
          const response = await route(new Request(URL));

          if (environment === "development" || isProtectionState(state)) {
            // The license does not reject the request; normal DPoP authorization still does.
            expect(response.status).toBe(401);
            expect(await response.json()).toMatchObject({ error: "AUTH_REQUIRED" });
          } else if (policy === "closed") {
            expect(response.status).toBe(403);
            expect(await response.json()).toMatchObject({ error: "TETHER_LICENSE_INACTIVE" });
          } else {
            expect(response.status).toBe(200);
            expect(await response.json()).toEqual({
              handlerCalled: true,
              licensed: false,
              bound: false,
            });
          }
        });
      }
    }
  }

  for (const policy of POLICIES) {
    it(`production / no license / onUnlicensed=${policy} with the explicit escape hatch`, async () => {
      const projectId = `${PROJECT_PREFIX}-none-${policy}`;
      const adapter = createGate({
        environment: "production",
        policy,
        projectId,
        allowUnlicensed: true,
      });
      const route = adapter.protect((_request, context) => Response.json({
        handlerCalled: true,
        licensed: context.licensed,
        bound: context.bound,
      }));
      const response = await route(new Request(URL));

      if (policy === "closed") {
        expect(response.status).toBe(503);
        expect(await response.json()).toMatchObject({ error: "TETHER_LICENSE_REQUIRED" });
      } else {
        expect(response.status).toBe(200);
        expect(await response.json()).toMatchObject({ handlerCalled: true, licensed: false, bound: false });
      }
    });
  }

  it("lets an individual route choose closed behavior while the adapter defaults to open", async () => {
    const adapter = createGate({
      environment: "production",
      policy: "open",
      projectId: `${PROJECT_PREFIX}-route-policy-override`,
      allowUnlicensed: true,
    });
    const route = adapter.protect(
      () => Response.json({ handlerCalled: true }),
      { onUnlicensed: "closed" },
    );
    const response = await route(new Request(URL));
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: "TETHER_LICENSE_REQUIRED" });

    const cookieRoute = adapter.protectCookie(
      () => Response.json({ handlerCalled: true }),
      { onUnlicensed: "closed" },
    );
    const cookieResponse = await cookieRoute(new Request(URL));
    expect(cookieResponse.status).toBe(503);
    expect(await cookieResponse.json()).toMatchObject({ error: "TETHER_LICENSE_REQUIRED" });
  });

  it("development without a license still applies normal DPoP authentication", async () => {
    const adapter = createGate({
      environment: "development",
      policy: "open",
      projectId: `${PROJECT_PREFIX}-no-license-dev`,
    });
    const route = adapter.protect(() => Response.json({ handlerCalled: true }));
    const response = await route(new Request(URL));
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: "AUTH_REQUIRED" });
  });

  it("keeps production protection on a cold start when the license endpoint is unreachable", async () => {
    const projectId = `${PROJECT_PREFIX}-cold-start-snapshot`;
    const token = await signedLicense({
      environment: "production",
      projectId,
      state: "active",
      issuedAgoSeconds: 7 * 24 * 60 * 60,
      expiresInSeconds: -6 * 24 * 60 * 60,
    });
    const snapshot: TetherLicenseSnapshot = { token, jwks };
    const adapter = createGate({
      environment: "production",
      policy: "closed",
      projectId,
      initialSnapshot: snapshot,
      fetchFailure: true,
    });
    await waitForLicense(adapter);
    expect(adapter.licenseStatus()).toMatchObject({
      claims: { state: "active" },
      stale: true,
      protectionEnabled: true,
    });

    const response = await adapter.protect(() => Response.json({ handlerCalled: true }))(
      new Request(URL),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: "AUTH_REQUIRED" });
  });

  it("fetches a rotated public key when a valid license uses a new kid", async () => {
    const rotatedSigner = await generatePrivateJwk();
    const rotatedKid = "acceptance-rotated-key";
    const projectId = `${PROJECT_PREFIX}-kid-rotation`;
    const rotatedJwks = publicLicenseJwks(rotatedSigner, rotatedKid);
    const token = await signedLicense({
      environment: "production",
      projectId,
      state: "active",
      kid: rotatedKid,
      privateJwk: rotatedSigner,
    });
    const adapter = createGate({
      environment: "production",
      policy: "closed",
      projectId,
      token,
      jwksResponse: rotatedJwks,
    });
    await waitForLicense(adapter);
    expect(adapter.licenseStatus()).toMatchObject({
      claims: { state: "active", sub: projectId },
      protectionEnabled: true,
    });
    const response = await adapter.protect(() => Response.json({ handlerCalled: true }))(
      new Request(URL),
    );
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: "AUTH_REQUIRED" });
  });

  it("fails production initialization when the key is missing unless allowUnlicensed is explicit", () => {
    expect(() => createTetherNext({
      authenticate: async () => null,
      bindings: emptyBindings(),
      license: {
        environment: "production",
        projectId: "project-id",
        issuer: ISSUER_BY_ENV.production,
      },
    })).toThrow(/TETHER_KEY/u);

    expect(() => createGate({
      environment: "production",
      policy: "open",
      projectId: `${PROJECT_PREFIX}-allow-unlicensed-missing-key`,
      allowUnlicensed: true,
    })).not.toThrow();
  });

  it("rejects a development key in production, including with allowUnlicensed", () => {
    for (const allowUnlicensed of [false, true]) {
      expect(() => createTetherNext({
        authenticate: async () => null,
        bindings: emptyBindings(),
        license: {
          apiKey: "tk_test_wrong-environment",
          projectId: `${PROJECT_PREFIX}-test-key-in-prod-${allowUnlicensed}`,
          issuer: ISSUER_BY_ENV.production,
          environment: "production",
          allowUnlicensed,
        },
      })).toThrow(/does not match production/u);
    }
  });
});

describe("license gate rejects invalid signed licenses", () => {
  const environment: LicenseEnvironment = "production";
  const policy = "closed";

  it.each([
    "expired",
    "tampered claims",
    "unknown kid",
    "wrong algorithm",
    "future nbf",
    "forged signature",
  ])("rejects %s and applies the closed policy", async (failure) => {
    const projectId = `${PROJECT_PREFIX}-bad-${failure.replaceAll(" ", "-")}`;
    let token: string;
    const testJwks = jwks;
    let rejectedRefresh!: () => void;
    const rejectedRefreshPromise = new Promise<void>((resolve) => { rejectedRefresh = resolve; });
    switch (failure) {
      case "expired":
        token = await signedLicense({ environment, projectId, state: "active", expired: true });
        break;
      case "tampered claims":
        token = tamperPayload(await signedLicense({ environment, projectId, state: "active" }));
        break;
      case "unknown kid":
        token = await signedLicense({ environment, projectId, state: "active", kid: "unknown-key" });
        break;
      case "wrong algorithm":
        token = tamperHeader(await signedLicense({ environment, projectId, state: "active" }), {
          alg: "HS256",
        });
        break;
      case "future nbf":
        token = await signedLicense({ environment, projectId, state: "active", futureNbf: true });
        break;
      case "forged signature":
        token = await signedLicense({
          environment,
          projectId,
          state: "active",
          privateJwk: attackerSigner,
        });
        break;
      default:
        throw new Error(`Unknown acceptance case: ${failure}`);
    }
    const adapter = createGate({
      environment,
      policy,
      projectId,
      token,
      jwks: testJwks,
      onLicenseChange: (license) => { if (license === null) rejectedRefresh(); },
    });
    await rejectedRefreshPromise;
    expect(adapter.licenseStatus()).toBeNull();

    const response = await adapter.protect(() => Response.json({ handlerCalled: true }))(
      new Request(URL),
    );
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: "TETHER_LICENSE_REQUIRED" });
  });
});

function createGate(input: {
  readonly environment: LicenseEnvironment;
  readonly policy: "open" | "closed";
  readonly projectId: string;
  readonly token?: string;
  readonly jwks?: ReturnType<typeof publicLicenseJwks>;
  readonly jwksResponse?: ReturnType<typeof publicLicenseJwks>;
  readonly allowUnlicensed?: boolean;
  readonly initialSnapshot?: TetherLicenseSnapshot;
  readonly fetchFailure?: boolean;
  readonly onLicenseChange?: (license: VerifiedLicense | null) => void;
}) {
  const issuer = ISSUER_BY_ENV[input.environment];
  const apiKey = input.environment === "production" ? "tk_live_acceptance-test" : "tk_test_acceptance-test";
  return createTetherNext({
    authenticate: async () => null,
    bindings: emptyBindings(),
    license: {
      apiKey,
      projectId: input.projectId,
      issuer,
      environment: input.environment,
      licenseEndpoint: `${issuer}/v1/license`,
      embeddedJwks: input.jwks ?? jwks,
      ...(input.initialSnapshot === undefined ? {} : { initialSnapshot: input.initialSnapshot }),
      ...(input.onLicenseChange === undefined ? {} : { onLicenseChange: input.onLicenseChange }),
      fetcher: async (request) => {
        if (input.fetchFailure) throw new Error("Simulated license service outage.");
        if (String(request).endsWith("/v1/jwks")) {
          return Response.json(input.jwksResponse ?? input.jwks ?? jwks);
        }
        return input.token === undefined
          ? new Response(null, { status: 503 })
          : Response.json({ token: input.token });
      },
      onUnlicensed: input.policy,
      ...(input.allowUnlicensed === undefined ? {} : { allowUnlicensed: input.allowUnlicensed }),
    },
  });
}

function emptyBindings() {
  return {
    getJkt: async () => null,
    bindIfAbsent: async () => true,
  };
}

async function signedLicense(input: {
  readonly environment: LicenseEnvironment;
  readonly projectId: string;
  readonly state: LicenseState;
  readonly kid?: string;
  readonly privateJwk?: LicenseSigningPrivateJwk;
  readonly expired?: boolean;
  readonly futureNbf?: boolean;
  readonly issuedAgoSeconds?: number;
  readonly expiresInSeconds?: number;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const iat = now - (input.issuedAgoSeconds ?? (input.expired ? 3_600 : 0));
  const claims: LicenseClaims = {
    iss: ISSUER_BY_ENV[input.environment],
    aud: LICENSE_AUDIENCE,
    sub: input.projectId,
    jti: "00000000-0000-4000-8000-000000000001",
    iat,
    nbf: input.futureNbf ? now + 3_600 : iat,
    exp: now + (input.expiresInSeconds ?? (input.expired ? -300 : 3_600)),
    plan: "free",
    state: input.state,
    trial_ends_at: null,
    grace_ends_at: null,
    limits: { mpu: 100, projects: 1, retention_days: 1, seats: 1 },
    features: [],
    env: input.environment,
    ver: 1,
  };
  return signLicense(claims, input.privateJwk ?? signer, input.kid ?? SIGNING_KID);
}

async function generatePrivateJwk(): Promise<LicenseSigningPrivateJwk> {
  const pair = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(pair.privateKey);
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y || !jwk.d) {
    throw new Error("Could not generate an ES256 test key pair.");
  }
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d };
}

function isProtectionState(state: LicenseState): boolean {
  return state === "trial" || state === "active" || state === "grace";
}

async function waitForLicense(adapter: ReturnType<typeof createTetherNext>): Promise<void> {
  await waitUntil(() => adapter.licenseStatus() !== null);
}

async function waitUntil(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("Timed out waiting for the license client.");
}

function tamperPayload(token: string): string {
  const segments = token.split(".");
  const payload = JSON.parse(decodeBase64Url(segments[1]!)) as Record<string, unknown>;
  payload.plan = "team";
  segments[1] = encodeBase64Url(JSON.stringify(payload));
  return segments.join(".");
}

function tamperHeader(token: string, changes: Record<string, unknown>): string {
  const segments = token.split(".");
  const header = JSON.parse(decodeBase64Url(segments[0]!)) as Record<string, unknown>;
  segments[0] = encodeBase64Url(JSON.stringify({ ...header, ...changes }));
  return segments.join(".");
}

function decodeBase64Url(value: string): string {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  return atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
}

function encodeBase64Url(value: string): string {
  return btoa(value).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
