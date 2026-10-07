import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";
import { getSupabasePublicConfig } from "../config";

export async function updateSupabaseSession(request: NextRequest): Promise<NextResponse> {
  const { url, publicKey } = getSupabasePublicConfig();
  let response = NextResponse.next({ request });
  const supabase = createServerClient(url, publicKey, {
    cookies: {
      getAll: () => request.cookies.getAll(),
      setAll(cookiesToSet, headersToSet) {
        for (const { name, value } of cookiesToSet) request.cookies.set(name, value);
        response = NextResponse.next({ request });
        for (const { name, value, options } of cookiesToSet) {
          response.cookies.set(name, value, options);
        }
        if (headersToSet !== undefined) {
          for (const [name, value] of Object.entries(headersToSet)) {
            response.headers.set(name, value);
          }
        }
      },
    },
  });

  await supabase.auth.getClaims();
  return response;
}
