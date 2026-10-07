import "server-only";

import { MemoryReplayStore } from "@tether/core";
import { createTetherNext } from "@tether/next";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { getSupabasePublicConfig } from "./config";
import { SupabaseBindingStore } from "./server/database-binding-store";
import { tetherLicenseSnapshot } from "./license-snapshot.generated";

const bindings = new SupabaseBindingStore();
const replayStore = new MemoryReplayStore();
let supabaseAuthClient: SupabaseClient | undefined;

function getSupabaseAuthClient(): SupabaseClient {
  if (supabaseAuthClient === undefined) {
    const { url, publicKey } = getSupabasePublicConfig();
    supabaseAuthClient = createClient(url, publicKey, {
      auth: {
        autoRefreshToken: false,
        detectSessionInUrl: false,
        persistSession: false,
      },
    });
  }
  return supabaseAuthClient;
}

export const tether = createTetherNext({
  bindings,
  refreshStore: bindings,
  replayStore,
  cookieSession: {
    secret: getTetherCookieSecret,
  },
  license: {
    onUnlicensed: "closed",
    ...(tetherLicenseSnapshot === undefined ? {} : { initialSnapshot: tetherLicenseSnapshot }),
  },
  authenticate: async (_request, accessToken) => {
    const { data, error } = await getSupabaseAuthClient().auth.getClaims(accessToken);
    if (error !== null || data === null) return null;
    const { session_id: sessionId, sub: userId } = data.claims;
    if (typeof sessionId !== "string" || typeof userId !== "string") return null;
    return { sessionId, userId };
  },
});

function getTetherCookieSecret(): Uint8Array {
  const configured = process.env.TETHER_COOKIE_SECRET;
  if (configured === undefined || configured.length === 0) {
    throw new Error("TETHER_COOKIE_SECRET is not configured.");
  }
  const secret = Buffer.from(configured, "base64url");
  if (secret.byteLength < 32) {
    throw new Error("TETHER_COOKIE_SECRET must decode to at least 32 bytes.");
  }
  return secret;
}
