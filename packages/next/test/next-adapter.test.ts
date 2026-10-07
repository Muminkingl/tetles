import { describe, expect, it } from "vitest";
import { MemoryReplayStore } from "@tether/core";
import { createFakeClient } from "../../testkit/src/fake-client.js";
import {
  createTetherNext,
  MemoryTetherNonceStore,
  type TetherBindingStore,
} from "../src/index.js";

const ACCESS_TOKEN = "verified-access-token";
const IDENTITY = { sessionId: "supabase-session-1", userId: "user-1" };
const ORIGIN = "https://app.example.test";

class TestBindings implements TetherBindingStore {
  readonly #jktBySession = new Map<string, string>();

  async getJkt(sessionId: string): Promise<string | null> {
    return this.#jktBySession.get(sessionId) ?? null;
  }

  async bindIfAbsent(sessionId: string, jkt: string): Promise<boolean> {
    const existing = this.#jktBySession.get(sessionId);
    if (existing !== undefined) return existing === jkt;
    this.#jktBySession.set(sessionId, jkt);
    return true;
  }
}

function makeAdapter(bindings = new TestBindings()) {
  const adapter = createTetherNext({
    authenticate: async (_request, token) => token === ACCESS_TOKEN ? IDENTITY : null,
    bindings,
    replayStore: new MemoryReplayStore(),
    nonceStore: new MemoryTetherNonceStore(),
  });
  return { adapter, bindings };
}

function signedRequest(method: string, url: string, proof: string, token = ACCESS_TOKEN): Request {
  return new Request(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      DPoP: proof,
    },
  });
}

describe("Next.js Route Handler adapter", () => {
  it("binds a Supabase session and lets the same key call a protected handler", async () => {
    const { adapter, bindings } = makeAdapter();
    const client = await createFakeClient(ACCESS_TOKEN);
    const bindUrl = `${ORIGIN}/api/tether/bind`;
    const bindProof = await client.createProof({ method: "POST", url: bindUrl });
    const bindResponse = await adapter.bind(signedRequest("POST", bindUrl, bindProof));

    expect(bindResponse.status).toBe(200);
    expect(await bindResponse.json()).toMatchObject({ bound: true });
    expect(await bindings.getJkt(IDENTITY.sessionId)).toBe(client.jkt);

    const protectedUrl = `${ORIGIN}/api/private`;
    const protectedProof = await client.createProof({ method: "GET", url: protectedUrl });
    const route = adapter.protect(async (_request, context) => {
      if (!context.licensed) throw new Error("Expected an authenticated, bound route context.");
      return Response.json({
        userId: context.userId,
        sessionId: context.sessionId,
        proofId: context.proofId,
      });
    });
    const protectedResponse = await route(
      signedRequest("GET", protectedUrl, protectedProof),
    );

    expect(protectedResponse.status).toBe(200);
    expect(await protectedResponse.json()).toMatchObject({
      userId: IDENTITY.userId,
      sessionId: IDENTITY.sessionId,
    });
    expect(protectedResponse.headers.get("cache-control")).toBe("private, no-store");
  });

  it("rejects missing proofs, invalid Supabase tokens, and replayed proofs", async () => {
    const { adapter } = makeAdapter();
    const client = await createFakeClient(ACCESS_TOKEN);
    const bindUrl = `${ORIGIN}/api/tether/bind`;
    const bindProof = await client.createProof({ method: "POST", url: bindUrl });
    await adapter.bind(signedRequest("POST", bindUrl, bindProof));

    const route = adapter.protect(async () => Response.json({ ok: true }));
    const target = `${ORIGIN}/api/private`;
    const missing = await route(new Request(target, {
      headers: { Authorization: `Bearer ${ACCESS_TOKEN}` },
    }));
    expect(missing.status).toBe(401);
    expect(await missing.json()).toMatchObject({ reasonCode: "PROOF_MISSING" });

    const unauthorized = await route(new Request(target, {
      headers: { Authorization: "Bearer forged-token", DPoP: "invalid" },
    }));
    expect(unauthorized.status).toBe(401);
    expect(await unauthorized.json()).toMatchObject({ error: "AUTH_REQUIRED" });

    const proof = await client.createProof({ method: "GET", url: target });
    expect((await route(signedRequest("GET", target, proof))).status).toBe(200);
    const replay = await route(signedRequest("GET", target, proof));
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reasonCode: "PROOF_REPLAY" });
  });

  it("issues a nonce and recovers a proof made with a stale client clock", async () => {
    const { adapter } = makeAdapter();
    const client = await createFakeClient(ACCESS_TOKEN);
    const bindUrl = `${ORIGIN}/api/tether/bind`;
    const bindProof = await client.createProof({ method: "POST", url: bindUrl });
    await adapter.bind(signedRequest("POST", bindUrl, bindProof));

    const route = adapter.protect(async () => Response.json({ ok: true }));
    const target = `${ORIGIN}/api/private`;
    const staleProof = await client.createProof({
      method: "GET",
      url: target,
      issuedAtSeconds: 1,
    });
    const challenge = await route(signedRequest("GET", target, staleProof));
    expect(challenge.status).toBe(401);
    expect((await challenge.json())).toMatchObject({ reasonCode: "PROOF_STALE" });
    const nonce = challenge.headers.get("DPoP-Nonce");
    expect(nonce).toBeTruthy();

    const recoveredProof = await client.createProof({
      method: "GET",
      url: target,
      issuedAtSeconds: 1,
      nonce: nonce!,
    });
    const recovered = await route(signedRequest("GET", target, recoveredProof));
    expect(recovered.status).toBe(200);
    expect(recovered.headers.get("DPoP-Nonce")).toBe(nonce);
  });

  it("does not let a second key replace the key already bound to a session", async () => {
    const { adapter } = makeAdapter();
    const url = `${ORIGIN}/api/tether/bind`;
    const firstClient = await createFakeClient(ACCESS_TOKEN);
    const firstProof = await firstClient.createProof({ method: "POST", url });
    expect((await adapter.bind(signedRequest("POST", url, firstProof))).status).toBe(200);

    const otherClient = await createFakeClient(ACCESS_TOKEN);
    const otherProof = await otherClient.createProof({ method: "POST", url });
    const conflict = await adapter.bind(signedRequest("POST", url, otherProof));
    expect(conflict.status).toBe(401);
    expect(await conflict.json()).toMatchObject({ reasonCode: "PROOF_KEY_MISMATCH" });
  });

  it("returns the same replacement cookie when the bound key retries within the grace window", async () => {
    const bindings = new TestBindings();
    const client = await createFakeClient(ACCESS_TOKEN);
    await bindings.bindIfAbsent(IDENTITY.sessionId, client.jkt);

    let replacement: { readonly tokenId: string; readonly issuedAt: number; readonly expiresAt: number } | null = null;
    const adapter = createTetherNext({
      authenticate: async (_request, token) => token === ACCESS_TOKEN ? IDENTITY : null,
      bindings,
      replayStore: new MemoryReplayStore(),
      cookieSession: { secret: new Uint8Array(32).fill(7) },
      refreshStore: {
        rotate: async (input) => {
          if (input.presentedToken === undefined) return { status: "rotated" };
          if (replacement === null) {
            replacement = input.nextToken;
            return { status: "rotated" };
          }
          return { status: "retry", token: replacement };
        },
      },
    });

    async function refresh(cookie?: string): Promise<Response> {
      const url = `${ORIGIN}/api/tether/refresh`;
      const proof = await client.createProof({ method: "POST", url });
      const headers = new Headers({
        Authorization: `Bearer ${ACCESS_TOKEN}`,
        DPoP: proof,
        Origin: ORIGIN,
      });
      if (cookie !== undefined) headers.set("Cookie", `__Host-tether=${cookie}`);
      return adapter.refreshCookie(new Request(url, { method: "POST", headers }));
    }

    const first = await refresh();
    expect(first.status).toBe(204);
    const firstCookie = first.headers.get("set-cookie")!.split(";", 1)[0]!.split("=", 2)[1]!;

    const rotated = await refresh(firstCookie);
    expect(rotated.status).toBe(204);
    const rotatedCookie = rotated.headers.get("set-cookie")!.split(";", 1)[0]!.split("=", 2)[1]!;

    const retried = await refresh(firstCookie);
    expect(retried.status).toBe(204);
    const retriedCookie = retried.headers.get("set-cookie")!.split(";", 1)[0]!.split("=", 2)[1]!;
    expect(retriedCookie).toBe(rotatedCookie);
  });

  it("passes a cryptographically valid other-key replay to the refresh store for revocation", async () => {
    const bindings = new TestBindings();
    const legitimateClient = await createFakeClient(ACCESS_TOKEN);
    const attackerClient = await createFakeClient(ACCESS_TOKEN);
    await bindings.bindIfAbsent(IDENTITY.sessionId, legitimateClient.jkt);

    const consumed = new Set<string>();
    let active: { readonly tokenId: string; readonly issuedAt: number; readonly expiresAt: number } | null = null;
    const adapter = createTetherNext({
      authenticate: async (_request, token) => token === ACCESS_TOKEN ? IDENTITY : null,
      bindings,
      replayStore: new MemoryReplayStore(),
      cookieSession: { secret: new Uint8Array(32).fill(9) },
      refreshStore: {
        rotate: async (input) => {
          if (input.presentedToken === undefined) {
            active = input.nextToken;
            return { status: "rotated" };
          }
          if (input.jkt !== legitimateClient.jkt) {
            return consumed.has(input.presentedToken.tokenId)
              ? { status: "reuse" }
              : { status: "key-mismatch" };
          }
          if (consumed.has(input.presentedToken.tokenId)) {
            return active === null ? { status: "revoked" } : { status: "retry", token: active };
          }
          consumed.add(input.presentedToken.tokenId);
          active = input.nextToken;
          return { status: "rotated" };
        },
      },
    });

    async function refresh(client: Awaited<ReturnType<typeof createFakeClient>>, cookie?: string) {
      const url = `${ORIGIN}/api/tether/refresh`;
      const proof = await client.createProof({ method: "POST", url });
      const headers = new Headers({
        Authorization: `Bearer ${ACCESS_TOKEN}`,
        DPoP: proof,
        Origin: ORIGIN,
      });
      if (cookie !== undefined) headers.set("Cookie", `__Host-tether=${cookie}`);
      return adapter.refreshCookie(new Request(url, { method: "POST", headers }));
    }

    function cookieValue(response: Response): string {
      return response.headers.get("set-cookie")!.split(";", 1)[0]!.split("=", 2)[1]!;
    }

    const first = await refresh(legitimateClient);
    const originalCookie = cookieValue(first);
    expect((await refresh(legitimateClient, originalCookie)).status).toBe(204);

    const replay = await refresh(attackerClient, originalCookie);
    expect(replay.status).toBe(401);
    expect(await replay.json()).toMatchObject({ reasonCode: "REFRESH_REUSE" });
  });
});
