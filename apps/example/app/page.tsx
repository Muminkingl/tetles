import { SignInAndVerify } from "./sign-in-and-verify";
import { getSupabasePublicConfig } from "@/lib/config";

export const dynamic = "force-dynamic";

export default function HomePage() {
  const config = getSupabasePublicConfig();
  return (
    <main>
      <h1>Tether stolen-token demo</h1>
      <p>
        Sign in and bind this browser to its non-extractable device key. Then send a normal protected
        request and simulate an attacker using a copied access token with a different key.
      </p>
      <SignInAndVerify supabaseUrl={config.url} supabasePublicKey={config.publicKey} />
    </main>
  );
}
