export interface SupabasePublicConfig {
  readonly url: string;
  readonly publicKey: string;
}

export function getSupabasePublicConfig(): SupabasePublicConfig {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.NEXT_URL;
  const publicKey =
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    process.env.NEXT_ANON;
  if (url === undefined || url.length === 0 || publicKey === undefined || publicKey.length === 0) {
    throw new Error("Set the Supabase URL and public anon/publishable key in the root .env file.");
  }
  return { url, publicKey };
}
