import "server-only";

import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { getSupabasePublicConfig } from "../config";

let adminClient: SupabaseClient | undefined;

/** Server-only Supabase client used for trusted Tether database writes. */
export function getSupabaseAdminClient(): SupabaseClient {
  if (adminClient !== undefined) return adminClient;

  const secretKey =
    process.env.SUPABASE_SECRET_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.NEXT_SERVICE_ROLE_KEY;
  if (secretKey === undefined || secretKey.length === 0) {
    throw new Error("Set SUPABASE_SECRET_KEY in the root .env file for server-side Tether storage.");
  }

  const { url } = getSupabasePublicConfig();
  adminClient = createClient(url, secretKey, {
    auth: {
      autoRefreshToken: false,
      detectSessionInUrl: false,
      persistSession: false,
    },
  });
  return adminClient;
}
