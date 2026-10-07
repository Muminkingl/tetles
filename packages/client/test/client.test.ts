import "fake-indexeddb/auto";
import { calculateJwkThumbprint, decodeProtectedHeader, decodeJwt } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryReplayStore, verifyProof } from "@tether/core";
import { createTetherClient, IndexedDbKeyStore, TetherClientError } from "../src/index.js";

afterEach(() => vi.restoreAllMocks());

function makeSession() {
  return { sessionId: crypto.randomUUID(), accessToken: "test-access-token" };
}

describe("browser client", () => {
  it("persists a non-extractable P-256 key and sends a proof accepted by core", async () => {
    const session = makeSession();
    let sent: Request | undefined;
    const client = createTetherClient({
      getSession: async () => session,
      baseUrl: "https://app.example.test/",
      keyStore: new IndexedDbKeyStore(),
      fetcher: async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        sent = request;
        return new Response(null, { status: 204 });
      },
    });

    const bindResponse = await client.bind();
    expect(bindResponse.status).toBe(204);
    expect(sent?.headers.get("Authorization")).toBe(`Bearer ${session.accessToken}`);
    const compact = sent?.headers.get("DPoP");
    expect(compact).toBeTruthy();
    const header = decodeProtectedHeader(compact!);
    const payload = decodeJwt(compact!);
    expect(header.typ).toBe("dpop+jwt");
    expect(header.alg).toBe("ES256");
    expect(header.jwk).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://app.example.test/tether/bind");

    const publicJwk = header.jwk as JsonWebKey;
    const jkt = await calculateJwkThumbprint(publicJwk, "sha256");
    const result = await verifyProof({
      proof: compact,
      method: "POST",
      url: "https://app.example.test/tether/bind?ignored=yes",
      accessToken: session.accessToken,
      expectedJkt: jkt,
      replayStore: new MemoryReplayStore(),
    });
    expect(result.ok).toBe(true);

    const stored = await new IndexedDbKeyStore().get(session.sessionId);
    expect(stored).toBeDefined();
    expect(stored?.privateKey.extractable).toBe(false);
    expect(stored?.privateKey.usages).toContain("sign");
    expect(stored?.publicJwk).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(Object.hasOwn(stored?.publicJwk ?? {}, "d")).toBe(false);
  });

  it("retries one announced nonce challenge with a fresh proof", async () => {
    const session = makeSession();
    const requests: Request[] = [];
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.url.endsWith("/tether/bind")) return new Response(null, { status: 204 });
      requests.push(request);
      if (requests.length === 1) {
        return new Response(JSON.stringify({ reasonCode: "PROOF_NONCE_REQUIRED" }), {
          status: 401,
          headers: { "content-type": "application/json", "DPoP-Nonce": "nonce-1" },
        });
      }
      return new Response("ok", { status: 200 });
    });
    const client = createTetherClient({
      getSession: async () => session,
      baseUrl: "https://app.example.test/",
      keyStore: new IndexedDbKeyStore(),
      fetcher,
    });
    await client.bind();
    requests.length = 0;

    const response = await client.fetch("/api/profile?view=compact", { method: "GET" });
    expect(response.status).toBe(200);
    expect(requests).toHaveLength(2);
    const firstProof = requests[0]?.headers.get("DPoP")!;
    const retryProof = requests[1]?.headers.get("DPoP")!;
    expect(firstProof).not.toBe(retryProof);
    expect(decodeJwt(firstProof).nonce).toBeUndefined();
    expect(decodeJwt(retryProof).nonce).toBe("nonce-1");
    expect(requests[0]?.url).toBe("https://app.example.test/api/profile?view=compact");
  });

  it("also applies one-time nonce recovery to the binding request", async () => {
    const session = makeSession();
    const requests: Request[] = [];
    const client = createTetherClient({
      getSession: async () => session,
      baseUrl: "https://app.example.test/",
      keyStore: new IndexedDbKeyStore(),
      fetcher: async (request) => {
        requests.push(request instanceof Request ? request : new Request(request));
        if (requests.length === 1) {
          return new Response(JSON.stringify({ reasonCode: "PROOF_STALE" }), {
            status: 400,
            headers: { "content-type": "application/json", "DPoP-Nonce": "bind-nonce" },
          });
        }
        return new Response(null, { status: 204 });
      },
    });

    const response = await client.bind();
    expect(response.status).toBe(204);
    expect(requests).toHaveLength(2);
    expect(decodeJwt(requests[0]!.headers.get("DPoP")!).nonce).toBeUndefined();
    expect(decodeJwt(requests[1]!.headers.get("DPoP")!).nonce).toBe("bind-nonce");
  });

  it("keeps simultaneous tabs on the same atomically-created device key", async () => {
    const session = makeSession();
    const proofs: string[] = [];
    const createClient = () => createTetherClient({
      getSession: async () => session,
      baseUrl: "https://app.example.test/",
      keyStore: new IndexedDbKeyStore(),
      fetcher: async (input) => {
        const request = input instanceof Request ? input : new Request(input);
        proofs.push(request.headers.get("DPoP")!);
        return new Response(null, { status: 204 });
      },
    });

    await Promise.all([createClient().bind(), createClient().bind()]);
    expect(proofs).toHaveLength(2);
    expect(decodeProtectedHeader(proofs[0]!).jwk).toEqual(decodeProtectedHeader(proofs[1]!).jwk);
  });

  it("signals re-login once when the session key is absent", async () => {
    const session = makeSession();
    const onReloginRequired = vi.fn();
    const client = createTetherClient({
      getSession: async () => session,
      baseUrl: "https://app.example.test/",
      keyStore: new IndexedDbKeyStore(),
      onReloginRequired,
      fetcher: async () => new Response(null, { status: 200 }),
    });

    await expect(client.fetch("/api/private")).rejects.toMatchObject({ code: "KEY_MISSING" });
    await expect(client.fetch("/api/private")).rejects.toMatchObject({ code: "KEY_MISSING" });
    expect(onReloginRequired).toHaveBeenCalledTimes(1);
    expect(onReloginRequired).toHaveBeenCalledWith({ reason: "key-missing" });
  });

  it("rejects unconfigured origins before sending a credential", async () => {
    const session = makeSession();
    const fetcher = vi.fn(async () => new Response(null, { status: 200 }));
    const client = createTetherClient({
      getSession: async () => session,
      baseUrl: "https://app.example.test/",
      keyStore: new IndexedDbKeyStore(),
      fetcher,
    });
    await client.bind();
    await expect(client.fetch("https://attacker.example/collect")).rejects.toMatchObject({
      code: "REQUEST_ORIGIN_REJECTED",
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("runs work under a same-session exclusive Web Lock", async () => {
    const session = makeSession();
    const calls: unknown[][] = [];
    const locks = {
      request: async (...args: unknown[]) => {
        calls.push(args);
        const callback = args[2] as () => Promise<string>;
        return callback();
      },
    } as unknown as Pick<LockManager, "request">;
    const client = createTetherClient({
      getSession: async () => session,
      baseUrl: "https://app.example.test/",
      keyStore: new IndexedDbKeyStore(),
      locks,
    });

    await expect(client.withSessionLock(async () => "done")).resolves.toBe("done");
    expect(calls[0]?.[0]).toBe(`tether:${session.sessionId}`);
    expect(calls[0]?.[1]).toMatchObject({ mode: "exclusive" });
  });

  it("returns stable typed errors without exposing request credentials", async () => {
    const session = makeSession();
    const client = createTetherClient({
      getSession: async () => null,
      baseUrl: "https://app.example.test/",
      keyStore: new IndexedDbKeyStore(),
    });
    try {
      await client.fetch("/api/private");
      throw new Error("Expected request to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(TetherClientError);
      expect(error).toMatchObject({ code: "AUTH_SESSION_REQUIRED" });
      expect((error as Error).message).not.toContain(session.accessToken);
    }
  });
});
