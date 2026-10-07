"use client";

import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createProof, createTetherClient } from "@tether/client";
import type { TetherClient } from "@tether/client";
import { useRef, useState } from "react";

interface SignInAndVerifyProps {
  readonly supabaseUrl: string;
  readonly supabasePublicKey: string;
}

interface SupabaseClaims {
  readonly session_id?: unknown;
}

export function SignInAndVerify({ supabaseUrl, supabasePublicKey }: SignInAndVerifyProps) {
  const supabaseRef = useRef<SupabaseClient | null>(null);
  const tetherRef = useRef<TetherClient | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState("Sign in with an existing Supabase Auth user.");
  const [attackStatus, setAttackStatus] = useState("Bind first to enable the copied-token attack.");
  const [bound, setBound] = useState(false);
  const [busy, setBusy] = useState(false);

  function getSupabase(): SupabaseClient {
    supabaseRef.current ??= createBrowserClient(supabaseUrl, supabasePublicKey);
    return supabaseRef.current;
  }

  function getTether(): TetherClient {
    tetherRef.current ??= createTetherClient({
      baseUrl: window.location.origin,
      bindEndpoint: "/api/tether/bind",
      refreshEndpoint: "/api/tether/refresh",
      getSession: async () => {
        const supabase = getSupabase();
        const { data: sessionData, error: sessionError } = await supabase.auth.getSession();
        const session = sessionData.session;
        if (sessionError !== null || session === null) return null;

        const { data: claimsData, error: claimsError } = await supabase.auth.getClaims(
          session.access_token,
        );
        if (claimsError !== null || claimsData === null) return null;
        const claims = claimsData.claims as SupabaseClaims;
        if (typeof claims.session_id !== "string" || claims.session_id.length === 0) return null;
        return { sessionId: claims.session_id, accessToken: session.access_token };
      },
      onReloginRequired: () => setStatus("The device key is missing. Sign in again to bind this browser."),
    });
    return tetherRef.current;
  }

  async function runBusy(action: () => Promise<void>): Promise<void> {
    setBusy(true);
    try {
      await action();
    } catch {
      setStatus("The request failed. Check the Supabase config and route response.");
    } finally {
      setBusy(false);
    }
  }

  async function signIn(): Promise<void> {
    await runBusy(async () => {
      const { error } = await getSupabase().auth.signInWithPassword({ email, password });
      if (error !== null) {
        setStatus("Supabase sign-in failed. Check the email, password, and Auth settings.");
        return;
      }
      setBound(false);
      setAttackStatus("Bind first to enable the copied-token attack.");
      setStatus("Signed in. Bind the browser key and call the protected route.");
    });
  }

  async function signUp(): Promise<void> {
    await runBusy(async () => {
      const { error } = await getSupabase().auth.signUp({ email, password });
      if (error !== null) {
        setStatus("Supabase sign-up failed. Check the Auth settings and email confirmation rules.");
        return;
      }
      setStatus("Sign-up submitted. If email confirmation is enabled, confirm your email and then sign in.");
    });
  }

  async function bindAndRequest(): Promise<void> {
    await runBusy(async () => {
      const bindResponse = await getTether().bind();
      if (!bindResponse.ok) {
        setBound(false);
        setStatus(await describeResponse("Binding failed", bindResponse));
        return;
      }
      setBound(true);
      const response = await getTether().fetch("/api/private");
      if (!response.ok) {
        setStatus(await describeResponse("Protected request failed", response));
        return;
      }
      const proofResult: unknown = await response.json();

      const refreshResponse = await getTether().refreshCookie();
      if (!refreshResponse.ok) {
        setStatus(`DPoP route passed; cookie refresh failed: ${await describeResponse("Refresh failed", refreshResponse)}`);
        return;
      }
      const cookieResponse = await fetch("/api/private-cookie", {
        method: "GET",
        credentials: "same-origin",
      });
      if (!cookieResponse.ok) {
        setStatus(`DPoP route passed; cookie route failed: ${await describeResponse("Cookie route failed", cookieResponse)}`);
        return;
      }
      const cookieResult: unknown = await cookieResponse.json();
      setStatus(`DPoP route and five-minute cookie route verified: ${JSON.stringify({ proof: proofResult, cookie: cookieResult })}`);
    });
  }

  async function simulateStolenToken(): Promise<void> {
    await runBusy(async () => {
      const { data, error } = await getSupabase().auth.getSession();
      const accessToken = data.session?.access_token;
      if (error !== null || accessToken === undefined) {
        setAttackStatus("Attack simulation needs a signed-in session.");
        return;
      }

      const attackerKeyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"],
      ) as CryptoKeyPair;
      const exported = await crypto.subtle.exportKey("jwk", attackerKeyPair.publicKey);
      if (typeof exported.x !== "string" || typeof exported.y !== "string") {
        setAttackStatus("The browser could not create the demo attacker key.");
        return;
      }
      const attackerPublicJwk: JsonWebKey = {
        kty: "EC",
        crv: "P-256",
        x: exported.x,
        y: exported.y,
      };
      const target = new URL("/api/private", window.location.origin);
      const proof = await createProof({
        privateKey: attackerKeyPair.privateKey,
        publicJwk: attackerPublicJwk,
        method: "GET",
        url: target.href,
        accessToken,
      });
      const response = await fetch(target, {
        method: "GET",
        headers: { Authorization: `Bearer ${accessToken}`, DPoP: proof },
      });
      const result: unknown = await response.json().catch(() => null);
      const reasonCode = getReasonCode(result);
      if (!response.ok && reasonCode === "PROOF_KEY_MISMATCH") {
        setAttackStatus("Blocked: PROOF_KEY_MISMATCH. The token was valid, but the attacker's key was not bound to this session.");
        return;
      }
      if (response.ok) {
        setAttackStatus("Unexpected result: the copied-token request was accepted.");
        return;
      }
      setAttackStatus(`Attack did not reach the expected check (${response.status}${reasonCode === null ? "" : `, ${reasonCode}`}).`);
    });
  }

  async function signOut(): Promise<void> {
    await runBusy(async () => {
      const tether = getTether();
      const current = await getSupabase().auth.getSession();
      let sessionId: string | undefined;
      if (current.data.session !== null) {
        const claims = await getSupabase().auth.getClaims(current.data.session.access_token);
        const sessionClaims = claims.data?.claims as SupabaseClaims | undefined;
        if (typeof sessionClaims?.session_id === "string") sessionId = sessionClaims.session_id;
      }
      const cookieClearResponse = await tether.clearCookie().catch(() => null);
      const { error } = await getSupabase().auth.signOut();
      if (error !== null) {
        setStatus("Supabase sign-out failed.");
        return;
      }
      if (sessionId !== undefined) await tether.forgetSession(sessionId);
      setBound(false);
      setAttackStatus("Bind first to enable the copied-token attack.");
      setStatus(cookieClearResponse?.ok
        ? "Signed out. The cookie and local device key for this session were removed."
        : "Signed out. The local device key was removed; any cookie expires within five minutes.");
    });
  }

  return (
    <section aria-label="Supabase sign in and Tether demo" style={{ display: "grid", gap: 12, maxWidth: 480 }}>
      <label>
        Email
        <input
          autoComplete="email"
          onChange={(event) => setEmail(event.currentTarget.value)}
          style={{ display: "block", padding: 8, width: "100%" }}
          type="email"
          value={email}
        />
      </label>
      <label>
        Password
        <input
          autoComplete="current-password"
          onChange={(event) => setPassword(event.currentTarget.value)}
          style={{ display: "block", padding: 8, width: "100%" }}
          type="password"
          value={password}
        />
      </label>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        <button disabled={busy} onClick={() => void signIn()} type="button">Sign in</button>
        <button disabled={busy} onClick={() => void signUp()} type="button">Sign up</button>
        <button disabled={busy} onClick={() => void bindAndRequest()} type="button">
          Bind / rotate cookie and call both protected routes
        </button>
        <button disabled={busy || !bound} onClick={() => void simulateStolenToken()} type="button">
          Simulate copied-token attack
        </button>
        <button disabled={busy} onClick={() => void signOut()} type="button">Sign out</button>
      </div>
      <output aria-live="polite">{status}</output>
      <output aria-live="polite" style={{ borderLeft: "3px solid #64748b", padding: 12 }}>
        {attackStatus}
      </output>
    </section>
  );
}

async function describeResponse(label: string, response: Response): Promise<string> {
  try {
    const body: unknown = await response.clone().json();
    return `${label} (${response.status}): ${JSON.stringify(body)}`;
  } catch {
    return `${label} (${response.status}).`;
  }
}

function getReasonCode(value: unknown): string | null {
  if (typeof value !== "object" || value === null) return null;
  const reasonCode = (value as Record<string, unknown>).reasonCode;
  return typeof reasonCode === "string" ? reasonCode : null;
}
