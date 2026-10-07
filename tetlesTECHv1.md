# Tether: Technical PRD (v1)

*Companion to the product PRD. This one answers: what do we build with, and how is it put together? Scope is v1 only: get real developers using it, measure, then scale.*

## 1. v1 technical goals

1. A stolen token fails on any other device or browser.
2. A developer integrates it into a Next.js + Supabase app in under 10 minutes.
3. Verification runs **inside the customer's app**, so our servers are never on their login path.
4. Our infrastructure costs close to zero until real users arrive.
5. Every crypto decision follows a public standard.

**Non-goals for v1:** Rust, Redis, Kubernetes, ML scoring, native mobile SDKs, hosted verification service, multi-region.

## 2. Stack decisions

| Layer | Choice | Why |
| --- | --- | --- |
| Language | **TypeScript (strict mode)** everywhere | One language for client, middleware, dashboard. A solo builder ships fastest |
| Monorepo | **pnpm workspaces** | Simple, fast, no extra tooling needed on day one |
| Crypto | **Web Crypto API** (client) + **`jose`** (server) | Runs in browsers, Node and edge runtimes. `jose` handles JWT, JWK and thumbprints (RFC 7638) |
| Signature algorithm | **ES256 (ECDSA P-256)** only | Supported by WebCrypto in every major browser. DPoP-compatible. No algorithm choice means no downgrade attack |
| Proof format | **DPoP-style JWT (RFC 9449)** | Existing standard, test vectors, credibility |
| Dashboard and docs | **Next.js (App Router) on Vercel** | Your stack, free tier, preview deploys |
| Database | **Supabase Postgres** with **Row Level Security** | Your stack, auth for dashboard logins included |
| Dashboard login | **Supabase Auth** | We eat our own dog food |
| Validation | **Zod** | One schema for API input and types |
| Build | **tsup** (ESM + CJS + types) | Small, dependable package output |
| Versioning | **Changesets** | Clean semver and changelogs |
| Unit tests | **Vitest** | Fast, TypeScript native |
| Browser tests | **Playwright** (Chromium, Firefox, WebKit) | Safari/WebKit is where session bugs hide |
| CI | **GitHub Actions** | Test matrix, lint, publish with npm provenance |
| Lint and format | **Biome** or ESLint + Prettier | Pick one and enforce in CI |
| Optional VM | **Oracle free tier** | Non-critical jobs only (see section 7) |

## 3. Repo layout

```
tether/
  packages/
    core/        # proof parsing, verification, thumbprints, nonce logic (pure, no I/O)
    client/      # browser: key generation, IndexedDB, fetch wrapper, Web Locks
    next/        # Next.js middleware + route helpers
    express/     # Express/Connect middleware
    testkit/     # RFC vectors, fake clients, attacker simulator
  apps/
    web/         # dashboard + docs + live stolen-token demo (Next.js)
    example/     # Next.js + Supabase Auth starter using Tether
  supabase/
    migrations/  # SQL migrations, RLS policies
```

**Rule:** `core` has zero framework dependencies and zero network calls. Every other package is a thin wrapper. This also makes a later Rust port a drop-in replacement.

## 4. How it works end to end

**4.1 Binding (after login)**

1. The client generates an ES256 key pair with `extractable: false` and stores the `CryptoKey` in **IndexedDB**.
2. It calls `POST /tether/bind` with a signed proof carrying the public JWK.
3. The server computes the key's JWK thumbprint (`jkt`) and stores `{session_id, jkt}`.
4. The session token (or a companion short-lived token) now carries `cnf.jkt`.

**4.2 Every protected request**

1. The client attaches a `DPoP` header: a JWT with header `typ: dpop+jwt`, `alg: ES256`, `jwk`; claims `htm` (method), `htu` (URL without query), `iat`, `jti`, `ath` (hash of the access token), and `nonce` when the server requires it.
2. The middleware verifies, in this order and stopping at the first failure:
   1. Header present and well-formed
   2. `alg` is exactly ES256 and `typ` is `dpop+jwt`
   3. Signature valid against the embedded `jwk`
   4. Thumbprint of that `jwk` equals the token's `cnf.jkt`
   5. `htm` and `htu` match the actual request
   6. `ath` matches the presented token
   7. `iat` within the window (default 30 s)
   8. `jti` not seen before
3. Each failure returns a stable reason code (`PROOF_MISSING`, `PROOF_BAD_SIG`, `PROOF_KEY_MISMATCH`, `PROOF_URL_MISMATCH`, `PROOF_STALE`, `PROOF_REPLAY`).

**4.3 Cookies (page loads JavaScript can't sign)**

- A **5-minute cookie** (HttpOnly, Secure, SameSite=Lax or Strict) is refreshed via a signed `POST /tether/refresh`.
- Sensitive routes can demand a per-request proof on top.
- **Refresh rotation:** each refresh token works once. A second use revokes the session and logs `REFRESH_REUSE`.

**4.4 Clock drift:** on a `PROOF_STALE` failure the server returns a fresh `DPoP-Nonce`, and the client retries once automatically.

**4.5 Multi-tab and recovery:** the client uses the **Web Locks API** so only one tab refreshes at a time. If the key is missing (cleared storage, Safari eviction), the client signals "re-login needed" through one well-defined event, never a raw error.

## 5. Supabase integration (first adapter)

- Use `@supabase/ssr` for Next.js server-side sessions.
- Bind by **Supabase session ID**: after sign-in, call `/tether/bind`. Store `jkt` in our `bindings` table keyed by session ID. Cache hits in memory per instance.
- If you want `cnf.jkt` inside the Supabase JWT itself, Supabase has a custom access token hook. **Check their current docs before relying on it**, since hooks and limits change. The table lookup works regardless and is the safe default for v1.
- Tether never replaces Supabase Auth. It adds a second proof on top.

## 6. Database schema (Supabase Postgres)

| Table | Key columns |
| --- | --- |
| `projects` | id, owner_id (Supabase user), name, allowed_origins\[\], created_at |
| `api_keys` | id, project_id, key_hash (never the raw key), prefix, last_used_at, revoked_at |
| `bindings` | session_id, project_id, jkt, created_at, last_seen_at, revoked_at |
| `events` | id, project_id, session_id, type, reason_code, ip_prefix, ua_family, created_at |

**Rules**

- **RLS on every table.** A user sees only rows for projects they own. Test this with a second account in CI.
- Store **no tokens, no proofs, no private keys, no raw IPs** (truncate IPs to a prefix).
- `events` is append-only and partitioned by month later. In v1 add an index on `(project_id, created_at)` and delete rows older than 30 days.
- API keys are shown once and stored as hashes.

## 7. Where each piece runs

| Piece | Location | Notes |
| --- | --- | --- |
| Client library | Customer's browser |  |
| Verifier middleware | **Customer's backend** | The critical path. Never depends on our servers |
| Dashboard, docs, demo | Vercel |  |
| Events, projects, bindings | Supabase |  |
| Event ingestion `POST /api/ingest` | Next.js route on Vercel | Batched, HMAC-signed with the project key, rate limited |
| Optional background jobs (cleanup, alerts) | Oracle free VM | Non-critical only. Oracle can reclaim idle instances, so never put verification here |

**Failure rule:** if our dashboard, Supabase, or Oracle is down, customer logins and protected requests are unaffected. SDKs buffer events and drop them after a size limit rather than slow a request.

## 8. Known v1 limitation: replay cache

On serverless platforms each instance has its own memory, so a replayed `jti` could hit a different instance. v1 mitigations:

- Short proof window (30 s) and per-request URL and method binding
- Per-instance in-memory cache with TTL
- Documented clearly in the threat model

Later: a shared cache (Redis or Upstash) behind the same `ReplayStore` interface. **Design the interface now** (`has(jti)`, `add(jti, ttl)`) so swapping is a one-file change.

## 9. Security requirements (technical)

- Accept **ES256 only**. Reject `none`, HS\*, RS\*, and any unknown `typ`.
- Constant-time comparison for hashes.
- No tokens or proofs in logs, error messages, or analytics. Add a CI test that greps test output for a canary token.
- Strict CORS: only the project's `allowed_origins`.
- Rate limit `/bind`, `/refresh` and `/ingest`.
- CSP on the dashboard. No inline scripts.
- Dependencies: pin versions, commit the lockfile, enable Dependabot and `npm audit` in CI, publish with provenance. Keep the runtime dependency list tiny (`jose`, `zod`).
- Enable 2FA on npm, GitHub and Supabase accounts. Your accounts are the supply chain.

## 10. Testing requirements

| Layer | What |
| --- | --- |
| Unit (`core`) | RFC 9449 vectors, every reason code, malformed input, property-based fuzzing of the parser |
| Attacker simulator (`testkit`) | Replays, copied token with no key, copied token with a new key, wrong URL, wrong method, stale proof, reused refresh |
| Browser matrix (Playwright) | Chromium, Firefox, WebKit: bind, request, tab race, cleared storage, private window |
| RLS tests | User A can never read user B's events |
| Load test (k6) | Verification throughput of the middleware on a small VM, published as a benchmark |
| Canary test | A secret planted in a token never appears in any log |

**Release gate:** no publish if any attacker-simulator case passes when it should fail.

## 11. Performance and cost budgets (v1)

- Verification in process: **p99 under 2 ms** on a laptop-class CPU (measured, then published)
- Added bundle size for the client: **under 10 KB gzipped**
- Database queries on the verification path: **0** in steady state (one cached lookup per new session)
- Monthly infrastructure cost until first paying customer: **free tiers only**, and note Supabase free projects can pause after inactivity. Check current limits and use the paid tier before the first real customer

## 12. Observability for learning from real users

Opt-in only, and said clearly in the docs. Track in our own database:

- Apps integrated and time from key creation to first verified request
- Verified requests per day, rejected proofs by reason code
- False-logout signals (recovery events, re-login after storage loss)
- Browser family breakdown

Add Sentry (or similar) for our own dashboard errors, never in the SDK.

## 13. Build order

1. **`core`** with tests against RFC vectors
2. **`testkit`** attacker simulator (write the attacks before the defenses)
3. **`client`** with IndexedDB, fetch wrapper, Web Locks
4. **`next`** middleware and the **example** app on Supabase Auth
5. Event ingestion, the `events` and `bindings` tables, RLS and its tests
6. Dashboard (blocked attempts, sessions) and the live demo page
7. `express` adapter, docs, npm publish with provenance, public launch

## 14. Decisions deferred on purpose

| Not now | Revisit when |
| --- | --- |
| Rust core and WASM | A customer needs edge verification we can't serve, or throughput becomes a real cost |
| Redis or Upstash replay store | Multi-instance replays show up in testing or a customer asks |
| Hosted verification API | Customers ask us to run verification for them |
| DBSC hardware upgrade | Browser support is broad enough to justify the work |
| Native mobile SDKs | Developers ask for them |

## 15. Open questions

1. Supabase custom access token hook or table lookup for v1? (Start with the table.)
2. Cookie tier first, or API-proof tier first? (Start with API proofs, add cookies right after.)
3. Biome or ESLint + Prettier?
4. License: MIT or Apache-2.0 for the core? (Apache-2.0 adds a patent grant, which security buyers like.)
5. Where do we publish the benchmark and threat model?