# Tether + Supabase Auth + Next.js example

This App Router example signs in with Supabase Auth, binds the verified Supabase session to a
browser-held ES256 key, then calls a protected Route Handler with a signed proof. Bindings are stored
in Supabase Postgres and cached in process for 30 seconds so cache hits do not query the database.

## Environment

The scripts load the repository-root `.env`. Set the public Supabase project URL and anon or
publishable key there. The app accepts `NEXT_PUBLIC_SUPABASE_URL` and either
`NEXT_PUBLIC_SUPABASE_ANON_KEY` or `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`; it also accepts the
existing `NEXT_URL` and `NEXT_ANON` names.

Server-side Tether writes require `SUPABASE_SECRET_KEY` (preferred),
`SUPABASE_SERVICE_ROLE_KEY`, or the existing `NEXT_SERVICE_ROLE_KEY` alias. Keep this key out of
client components and `NEXT_PUBLIC_*` variables. `DATABASE_URL` is only needed for direct database
tools; the Supabase CLI uses its own linked-project authentication.

The cookie tier also needs a server-only `TETHER_COOKIE_SECRET` containing at least 32 random bytes,
encoded as base64url. Generate one with:

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

Changing this secret invalidates outstanding Tether cookies. Never expose it through a
`NEXT_PUBLIC_*` variable or commit its value.

## Apply the schema

Install and authenticate the Supabase CLI, then link the target project and preview the migration:

```sh
supabase login
supabase link --project-ref <project-ref>
supabase db push --dry-run
```

After reviewing the preview, apply the checked-in migrations and run the database isolation checks:

```sh
supabase db push
supabase test db --linked
```

The migrations create `projects`, `api_keys`, `bindings`, append-only `events`, and one-use cookie
refresh state with server-only atomic rotation. `supabase/tests/rls_isolation.test.sql`
checks that two authenticated owners can see their own project data but cannot read each other's
events. `supabase/tests/refresh_rotation.test.sql` checks rotation, the ten-second same-key retry
grace, later reuse revocation, and key mismatch handling. Refresh state has RLS enabled and no direct
grants; the server-only RPC is its only access path. The migration also provides
`public.delete_expired_tether_events()` to remove events older
than 30 days and expired refresh-token history; schedule that function daily with the project's
database scheduler for automatic retention.

## Run the example

```sh
pnpm --filter tether-supabase-next-example dev
```

Open http://localhost:3000, sign in with a Supabase Auth user, then choose **Bind / rotate cookie and
call both protected routes**. The first bind creates a `Tether example` project for that user. It
writes the binding using
the server-only Supabase key; only the owner can read the row through the Data API. Then select
**Simulate copied-token attack**. The browser reuses the valid access token but signs with a new
temporary key; the expected result is `PROOF_KEY_MISMATCH`. The demo never displays or stores the
copied token or the temporary private key.

The bind action also requests the signed five-minute `__Host-tether` cookie and calls
`GET /api/private-cookie`, a read-only route protected by that cookie. A later refresh consumes the
presented ticket and issues a new one. A same-key retry within ten seconds returns the active
replacement ticket; later same-key reuse or a different-key replay of a consumed ticket revokes the
session binding and writes a `REFRESH_REUSE` event. State-changing or sensitive routes should continue to
use `tether.protect()` and require a fresh DPoP proof. A stolen current cookie can authorize safe
reads until expiry.

## Issue an ingest key

After signing in and binding once, find that user's project ID in the `public.projects` table. Then
run:

```sh
pnpm --filter tether-supabase-next-example issue-key -- <project-id>
```

The command prints a random `tk_live_...` API key once and stores only its SHA-256 hash and a short
prefix. Keep the returned key in a trusted server environment variable; never put it in browser
code. Revoked keys are rejected by the ingest endpoint. Existing `tth_live_...` keys from the
earlier example remain accepted as production keys; newly issued keys use the PRD's `tk_` format.

## License endpoint and SDK cache

The license-system slice adds a production/development API key, `POST /v1/license`, and
`GET /v1/jwks`. Apply `supabase/migrations/20261007130000_add_license_system.sql` before using
those endpoints. Generate the local ES256 signing key once with `pnpm license:keygen`; the
private JWK stays in the ignored root `.env`, while the generated public JWKS is checked into the
SDK. Copy the one-time API key into the server-only `TETHER_KEY` setting and set
`TETHER_PROJECT_ID` to the project UUID. The default issuer for
local development is `http://localhost:3000`; deployments must set `TETHER_LICENSE_ISSUER` to the
stable HTTPS origin that the SDK will verify. For a deployment, copy both signing variables from
the local `.env` into the hosting provider's server-only secret settings; never use `NEXT_PUBLIC_`
names or commit the private JWK. On another checkout, restore the matching private key from your
secret manager; the key generator refuses to replace a checked-in public key.

Issue a development key with:

```sh
pnpm --filter tether-supabase-next-example issue-key -- <project-id> development
```

`@tether/next` reads the server-only `TETHER_KEY`, `TETHER_PROJECT_ID`, and
`TETHER_LICENSE_ISSUER` variables, restores a verified cache, and refreshes the token and unknown
signing keys in the background. Protected route handlers read the license state locally; requests
never wait on the license service. The default cache is process-local. Supply a `LicenseCacheStore`
implementation if the runtime must retain the seven-day offline allowance across cold starts.
The example's production `build` command pulls a fresh signed token and public JWKS, then embeds
that snapshot in the server build so a new serverless instance can verify it offline during a
license-service outage. The build requires the environment-matching API key and an available
license endpoint; the snapshot is never written to browser code or logged. You can pull a local
snapshot with `pnpm --filter tether-supabase-next-example license:pull`; it is saved under the
ignored `apps/example/.tether/` directory. The SDK re-verifies every snapshot and allows a cached
snapshot to remain valid for up to seven days after its token expiry when refresh is unavailable.

For the first HTTPS deployment, choose the stable production HTTPS origin and set it as
`TETHER_LICENSE_ISSUER` before building. In Vercel, use
`pnpm --filter tether-supabase-next-example build:bootstrap` as the first deployment's build
command. This compiles the issuer without trying to fetch a snapshot from an endpoint that is not
deployed yet. After the deployment is reachable, switch the build command back to the normal
`build` script and redeploy; it will pull and embed a fresh signed snapshot. The example uses
`onUnlicensed: "closed"`, so protected routes return a license error until a valid license is
available; the bootstrap build does not silently open protected routes. Keep the normal snapshot
build for subsequent deployments.

In production, `NODE_ENV=production` selects production unless `TETHER_ENV` explicitly selects
another environment. A production key must use the `tk_live_` prefix; development uses `tk_test_`.
For a local production build using a development key, set `TETHER_ENV=development`; do not set
that override in a production deployment.
The default `onUnlicensed: "open"` runs a protected route without Tether checks and passes
an explicit degraded context with `licensed: false` and `bound: false`; it cannot be mistaken for
a verified route context. Check `context.licensed` before using identity or session fields. Set
`license: { onUnlicensed: "closed" }` in `createTetherNext` to reject routes with a stable license
error, or pass `{ onUnlicensed: "closed" }` as the second argument to `protect()` or
`protectCookie()` for a route-specific override. A production app without a key fails during initialization unless
`license: { allowUnlicensed: true }` or `TETHER_ALLOW_UNLICENSED=true` is explicitly set. That
escape hatch does not enable protection.

## Send events

`POST /api/ingest` accepts batches of up to 100 events. The caller signs the exact UTF-8 request body
with HMAC-SHA-256 using the project API key. The signature input is `<unix-seconds>.<raw-body>`; send
the timestamp and lowercase hex signature in `x-tether-timestamp` and `x-tether-signature`, with the
key in `x-tether-key`.

```js
import { createHmac } from "node:crypto";

const body = JSON.stringify({
  events: [{ type: "request_blocked", reasonCode: "PROOF_REPLAY" }],
});
const timestamp = String(Math.floor(Date.now() / 1000));
const signature = createHmac("sha256", process.env.TETHER_API_KEY)
  .update(`${timestamp}.${body}`)
  .digest("hex");

await fetch("https://your-tether-host/api/ingest", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-tether-key": process.env.TETHER_API_KEY,
    "x-tether-timestamp": timestamp,
    "x-tether-signature": signature,
  },
  body,
});
```

Only event type, stable reason code, Supabase session ID, truncated CIDR prefix, and allowlisted
browser family are accepted. Tokens, proofs, signatures, raw IP addresses, and raw User-Agent strings
are rejected. The endpoint enforces a five-minute signature window, a 64 KiB body limit, and a
per-key in-memory limit of 60 requests per minute. That rate limit is per server instance; use a
shared limiter before deploying multiple ingest instances.

Ingestion is a separate endpoint from authentication and protected-route verification. A database
or ingestion failure therefore cannot delay those request paths.

## Storage scope

Binding lookups are cached per server instance for 30 seconds; an external binding or revocation
change can take up to that long to appear on another instance. Replay and nonce stores remain
process-local, so multiple app instances do not share them. The example is for one-process
development and needs shared replay and nonce storage before multi-instance production use.
