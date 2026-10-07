# Quick start: Next.js and Supabase Auth

This quick start uses the runnable app in [`apps/example`](../apps/example/README.md). The browser
creates a non-extractable P-256 key, keeps it in IndexedDB, and sends proofs only to the app's
configured origin.

## 1. Configure Supabase

Set the public Supabase URL and anon/publishable key in the repository-root `.env`. Set a
server-only Supabase secret key for the example's binding storage. Keep that key out of browser code.

Set `TETHER_COOKIE_SECRET` to a random base64url-encoded value containing at least 32 bytes. Generate
one with `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"` and
keep it server-only. The example fails closed on cookie refresh if this secret is missing or too
short. Changing it invalidates all outstanding Tether cookies.

Apply the Supabase migration and RLS policies using the instructions in the example README. The
first successful bind creates an owner-scoped `Tether example` project and stores the session's key
thumbprint.

## 2. Add the browser client

Pass the authenticated Supabase session ID and access token to `getSession`:

```ts
import { createTetherClient } from "@tether/client";

const tether = createTetherClient({
  getSession: async () => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return null;
    const { data } = await supabase.auth.getClaims(session.access_token);
    const sessionId = data?.claims.session_id;
    return typeof sessionId === "string"
      ? { sessionId, accessToken: session.access_token }
      : null;
  },
});

await tether.bind();
const response = await tether.fetch("/api/private");
```

Call `bind()` after sign-in and before the first protected request. `fetch()` adds an authorization
bearer token and a fresh proof. The client scopes credentials to the configured origin by default.
After binding, call `refreshCookie()` to send a signed `POST /tether/refresh`; the response sets a
five-minute `__Host-tether` cookie with `HttpOnly`, `Secure`, `SameSite=Lax`, and `Path=/` attributes.
The cookie endpoint requires a same-origin `Origin` header. `clearCookie()` sends a same-origin
`DELETE` to the same endpoint for logout. Refreshes are coordinated with the Web Locks API so tabs
sharing one session do not race a one-use ticket.

## 3. Protect a Next.js route

The example constructs the adapter with Supabase token verification, database-backed bindings, and
the in-memory replay store. Cookie rotation also needs an atomic `refreshStore`; the example uses a
Supabase RPC-backed store that revokes the binding and writes `REFRESH_REUSE` in the same transaction
when an already-consumed ticket is presented again. Wrap each protected Route Handler:

```ts
import { tether } from "@/lib/tether";

export const GET = tether.protect(async (_request, { userId }) =>
  Response.json({ message: "verified", userId }),
);
```

Use `protectCookie()` for read-only `GET` and `HEAD` routes that need a browser cookie instead of
JavaScript-generated proofs:

```ts
export const GET = tether.protectCookie(async (_request, { userId }) =>
  Response.json({ message: "verified by the short-lived cookie", userId }),
);
```

Keep state-changing and sensitive routes on `protect()`, which requires a fresh per-request proof.
The signed cookie is a bearer credential for up to five minutes; `HttpOnly` limits JavaScript access
but does not protect a stolen browser profile. Cookie-only authorization is restricted to safe
methods. Each ticket is accepted for one rotation; reuse revokes its session binding and writes a
`REFRESH_REUSE` event. Cookie-protected requests also confirm that the ticket's key thumbprint still
matches the session binding.

The example `tether` module is server-only. For an adapter in another app, provide its own token
authentication callback, binding/replay stores, and an atomic refresh store whenever cookie
sessions are enabled. The refresh store must revoke the binding and record `REFRESH_REUSE` in the
same transaction. Do not copy the Supabase service key into a client bundle.

## Try the copied-token demo

Run the example, sign in, and select **Bind / rotate cookie and call both protected routes**. Then
select **Simulate copied-token attack**. The demo reuses the valid access token but signs with a new
temporary key. The route should reject it with `PROOF_KEY_MISMATCH`; the token and proof are not
displayed.

The simulator is illustrative, not a replacement for the RFC vector, attacker-simulator, and RLS
checks. Review the [threat model](threat-model.md) and [measured performance](performance.md).
