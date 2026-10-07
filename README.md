# Tether

Tether binds a verified Supabase Auth session to a non-extractable browser key. Protected requests
must present both the access token and a fresh ES256 proof from that bound key. A copied access token
used with no key or a different key is rejected by the verifier.

This is an early v1 implementation. The Supabase schema and RLS migration are checked in but still
need to be applied and verified against a Supabase project. See the [Next.js + Supabase example](apps/example/README.md)
for environment setup, migration instructions, a runnable copied-token demo, and event ingestion.

## Quick start

After the client has an authenticated Supabase session, create the browser client and bind once:

```ts
const tether = createTetherClient({ getSession });
await tether.bind();
const response = await tether.fetch("/api/private");
```

In a Next.js Route Handler, wrap the protected handler:

```ts
import { tether } from "@/lib/tether";

export const GET = tether.protect(async (_request, { userId }) =>
  Response.json({ userId }),
);
```

See the [quick start](docs/quickstart.md) for the session callback and setup details, the [threat
model](docs/threat-model.md) for guarantees and limits, and [measured performance](docs/performance.md)
for the current local benchmark and bundle size.

## What is protected

- The access token is authenticated separately by the app's auth provider.
- ES256 request proofs bind the method, URL, token hash, time, and unique proof ID.
- The server compares the proof key with the key bound to the authenticated session.
- Stable reason codes explain why invalid proofs are rejected.

Tether does not replace Supabase Auth. See the threat model before using this in production.
