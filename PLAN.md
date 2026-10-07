# Tether implementation plan

This file tracks delivery phase by phase. Work proceeds in small reviewable steps; database changes are made through checked-in migrations when their phase is reached.

## Scope decisions for the kickoff

- Use `tetlesTECHv1.md` as the vsss1 implementation guide: strict TypeScript, a framework-independent core, customer-side verification, and Next.js + Supabase as the first integration.
- Rust/WASM is deferred for v1, as specified by the Technical PRD. The product PRD has been aligned to this scope.dddd
- The product PRD lists more framework adapters in P0 than the technical PRD's build order. Start with Next.js/Supabase, then add adapters in the technical PRD's order while preserving the others as follow-on scope.
- Use the stricter product targets when practical: p99 under 1 ms in-process, under 10 KB gzipped client bundle, under 10 minutes to first protected request, and zero database calls on the steady-state verification path. Measure before claiming success.

## Roadmap

### Phase 0 — Core and demo (PRD weeks 1–4)

1. [x] Bootstrap the pnpm TypeScript monorepo and protect local secrets.
2. [x] Define the core proof and verifier contracts, ES256-only validation, stable reason codes, and replay-store interface.
3. [x] Implement core verification and its RFC 9449 vectors and negative cases.
4. [x] Build the attacker testkit before relying on the defenses.
5. [x] Build the browser client: non-extractable key in IndexedDB, signed fetch, and Web Locks.
6. [x] Add the Next.js adapter and Supabase Auth example.
7. [ ] Add event ingestion, database migrations, RLS, and isolation checks.
   - [x] Add ownership-scoped tables and least-privilege grants/RLS policies.
   - [x] Add two-user pgTAP isolation checks and 30-day retention function.
   - [x] Store example bindings in Supabase with a 30-second process-local cache.
   - [x] Add bounded HMAC-signed batch ingestion and one-time API-key issuance.
   - [ ] Apply the migration and run the isolation checks against the configured Supabase project; schedule daily retention cleanup.
8. [ ] Build the stolen-token demo and initial docs; measure bundle size and verification latency.
   - [x] Add a real protected-route simulation using a valid token and a different ephemeral key.
   - [x] Add quick-start and threat-model docs.
   - [x] Measure and record client bundle size and core verifier latency.
   - [ ] Exercise the demo end-to-end after the database migration is applied.

**Phase 0 exit gate:** copied-token attacks fail in the test suite, the example completes a protected request, and the demo explains the result with stable reason codes.

### Phase 1 — Developer launch (PRD weeks 5–8)

1. [x] Add the short-lived cookie tier and signed refresh endpoint.
   - [x] Add a five-minute HS256 `__Host-tether` ticket and safe-method cookie protector.
   - [x] Add same-origin DPoP-protected refresh and clear-cookie routes/client methods.
   - [x] Integrate the cookie read path into the Supabase/Next.js example and document the limits.
   - [ ] Exercise the signed refresh and cookie route end-to-end after Phase 0's database migration is applied.
2. [x] Add one-use refresh rotation and reuse detection.
   - [x] Add atomic ticket rotation, session binding revocation, and `REFRESH_REUSE` audit logging.
   - [x] Return the active replacement ticket for same-key retries during a ten-second grace window.
   - [x] Serialize browser refreshes across tabs with the Web Locks API.
   - [x] Keep the example's Supabase rotation state private behind a database RPC and RLS-protected table.
   - [ ] Apply the rotation migration and exercise rotation/reuse against the configured Supabase project.
3. [ ] Complete launch docs, benchmark, and threat model; release the open-source packages.
4. [ ] Add adapters from the supported v1 scope, in priority order agreed during Phase 0.

### Phase 2 — First users (PRD weeks 9–16)

1. [ ] Interview 20 developers and record integration time and friction.
2. [ ] Add the next auth-provider adapters (including Clerk) based on those interviews.
3. [ ] Deliver event log and webhooks with opt-in telemetry and documented retention.

### Phase 3 — Paid tier (PRD weeks 17–24)

1. [ ] Build the dashboard for sessions, blocked attempts, and required actions.
2. [ ] Add alerts, explainable risk policies, and audit exports.
3. [ ] Revisit hosted verification only if customer demand justifies changing the self-hosted v1 model.

### License system — spec and first implementation slice

1. [x] Freeze the signed license claims, state behavior, environment selection, and alert delivery rule in `Tether License System PRD.md`.
2. [x] Add ES256 license signing/verification primitives and a generated public JWKS in the SDK.
3. [x] Add `POST /v1/license` and `GET /v1/jwks` to the Supabase-backed example service, including key hashing, trial state, issuance audit, and database-backed rate limits.
4. [x] Add the SDK license cache client with background refresh, JWKS rotation fetch, and the seven-day cached-token allowance.
5. [x] Apply `supabase/migrations/20261007130000_add_license_system.sql` to the configured Supabase project and exercise the local license endpoints.
6. [x] Integrate license status with the production route gate and `onUnlicensed` behavior.

### License-gate release sequence

1. [x] Typecheck and cover the state/policy/environment matrix, invalid tokens, and startup key rules.
2. [x] Use a defined degraded context in open mode and support route-level closed behavior.
3. [x] Add a signed build-time snapshot and prove offline cold-start enforcement through the seven-day cache window.
4. [x] Check production boot rules, signing-key exposure, and public-key rotation.
5. [ ] Deploy over HTTPS with a production key and repeat the copied-token and license-outage scenarios.
6. [ ] Add `npx tether init`, `/v1/usage` with MPU metering, then run a private alpha.

## Progress log

- 2026-10-06: Read both PRDs, recorded the scope conflicts above, confirmed Node.js and pnpm are available, bootstrapped the workspace, and initialized Git. No database changes have been applied.
- 2026-10-06: Added the initial core proof schema, verifier draft, stable reason codes, and bounded in-memory replay store. The RFC vectors, negative cases, and security review remain outstanding; the verifier is not release-ready.
- Replay-store implementation uses one atomic `claim` operation. This strengthens the technical PRD's proposed `has` + `add` pair, which could accept concurrent replays between the two operations.
- 2026-10-06: Added core RFC-based checks, negative cases for every stable reason code, replay-store concurrency/capacity checks, and seeded property-based parser fuzzing. `pnpm typecheck` passes and `pnpm test` passes (16 tests).
- The RFC's Figure 13 compact JWT text does not decode to the header shown in its Figure 14. The suite checks Figure 13's published access-token hash and verifies a freshly signed proof using Figure 14's published claims instead of treating the malformed literal as a valid signature vector.
- 2026-10-06: Added the reusable attacker simulator for copied tokens, replayed proofs, a different signing key, wrong method/URL, and stale proofs. `pnpm typecheck` passes and `pnpm test` passes across both packages (17 tests total).
- 2026-10-06: Added `@tether/client` with a non-extractable P-256 key stored in IndexedDB, signed bind/protected requests, same-origin-by-default credential scoping, one-time nonce retry, missing-key re-login signaling, and a Web Locks helper. IndexedDB key creation is atomic across tabs. `pnpm typecheck` passes and `pnpm test` passes across all packages (25 tests total); `git diff --check` passes. Real-browser Playwright coverage remains part of the later browser-matrix validation.
- 2026-10-06: Added `@tether/next` Route Handler protection and a Supabase Auth example. Supabase bearer claims are verified before the session binding and ES256 proof; the demo includes bind/protected routes, clock-skew nonce recovery, and the Next.js 16 `proxy.ts` Supabase SSR refresh path. The example uses process-local binding/replay/nonce stores until the database phase. `pnpm typecheck`, `pnpm test` (30 tests), `pnpm build`, and `git diff --check` pass. No database changes were applied.
- Local production-server smoke check: the example page returned 200 and the protected route returned 401 `AUTH_REQUIRED` without a bearer token. A sign-in using a real Supabase test user was not exercised.
- 2026-10-06: Implemented the local artifacts for Phase 0 step 7: Supabase project/key/binding/event migrations, owner-scoped RLS, append-only event grants, a 30-day cleanup function, pgTAP isolation checks, a cached database binding store, a one-time API-key issuer, and a timestamped HMAC event-ingest endpoint. `pnpm typecheck` passes. The remote migration and database tests remain pending: the local `.env` has no `DATABASE_URL`, and the Supabase CLI is not installed or linked. No remote database changes have been made.
- 2026-10-06: Added the copied-token attack interaction, quick-start and threat-model documentation, and reproducible measurements. The demo binds a session, then reuses its valid access token with a fresh ephemeral key and expects `PROOF_KEY_MISMATCH`. Initial bundle measurement exposed a 450.8 KB dependency pull-in; extracting a dependency-free access-token hash subpath reduced the full client entry to 8,189 bytes minified / 3,182 bytes gzipped. The 5,000-proof in-process benchmark measured 0.395 ms p99 on Node 24.18.0 / Windows x64 / AMD Ryzen 9 8940HX. `pnpm typecheck` and `pnpm build` pass. End-to-end demo execution is pending the database migration; no database-backed sign-in was exercised.
- 2026-10-06: Implemented Phase 1 step 1: a five-minute HS256 `__Host-tether` companion ticket, DPoP-verified same-origin refresh endpoint, logout clearing endpoint, GET/HEAD-only cookie protector, browser client methods, and example UI/docs. `pnpm typecheck` and `pnpm build` pass. A 32-byte local cookie secret was generated in the ignored `.env` without printing its value. Step 2's one-use rotation/reuse detection remains separate. End-to-end cookie verification is still pending Phase 0's unapplied Supabase migration.
- 2026-10-06: Implemented Phase 1 step 2 locally: one active cookie ticket per session, atomic one-use rotation through a security-definer Supabase RPC, binding revocation plus `REFRESH_REUSE` event insertion on reuse, expiry cleanup, and automatic Web Locks coordination in the client. `pnpm typecheck` and `pnpm build` pass. The migration and end-to-end Supabase rotation/reuse flow remain unexecuted because the Phase 0 schema has not yet been applied remotely.
- 2026-10-07: Added a ten-second same-key refresh retry grace. Duplicate calls return the session's currently active cookie ticket; later same-key reuse and a valid different-key replay of a consumed ticket revoke and audit the session. Added adapter and pgTAP coverage and aligned the product PRD with the Technical PRD's TypeScript v1 scope and cookie bearer limitation. `pnpm typecheck` passes; `pnpm test` passes (32 tests). Remote migration/RLS validation is the current step.
- 2026-10-07: Supabase dry-run did not reach Postgres. The configured direct database host resolves to IPv6 only, and this environment's IPv6 TCP connection is refused; HTTPS to the project's Supabase API is reachable. No remote schema changes were applied. Continue with the project's shared session-pooler connection string from Supabase Connect, then apply migrations and run both pgTAP files.
- 2026-10-07: Froze the license token/state/alert contract and implemented the first license slice locally: ES256 signing and verification, a generated public JWKS with its private key only in ignored `.env`, `/v1/license`, `/v1/jwks`, plan/trial tables, issuance audit, database rate limiting, and the background SDK cache client. `pnpm typecheck` passed. At this point the new migration was not applied and the endpoints had not been exercised; the user later applied the migration and completed the first endpoint/cache check.
- 2026-10-07: The user applied the license migration. Local `GET /v1/jwks` returned 200 with one ES256 key. Issued a development key for the single existing project and stored it only in ignored `.env`; the SDK obtained and verified a free-plan development license, then verified its cached token with the license endpoint offline. Production trial activation and runtime route-gate behavior remain to be validated.
- 2026-10-07: Added the `@tether/next` production license gate. It reads Tether configuration from server environment variables or explicit options, validates environment/key-prefix/issuer settings at initialization, starts background license refresh, and gates both DPoP and cookie-protected routes using only locally verified license state. `onUnlicensed: "open"` runs handlers without a Tether context; `"closed"` returns stable license errors. Development without a key keeps the existing DPoP flow. Automated tests and typechecking were not run in this step.
- 2026-10-07: Typechecked the production gate and added the complete license state/policy/environment matrix, invalid-token cases, key-configuration cases, and a rotated-`kid` test. The first run found that `allowUnlicensed` incorrectly suppressed a key-prefix mismatch; that now fails startup. Recheck passed: full `pnpm typecheck`, full `pnpm test` (44 Next adapter/license tests plus the other workspace suites), and the snapshot script syntax check.
- 2026-10-07: Replaced the `undefined` open-mode context with typed `licensed`/`bound` discriminants, null identity fields, and a stable license reason. Added route-level closed overrides. Added signed build-time license snapshots, restoring/verifying them before the initial background refresh; an offline cold-start test confirms a snapshot six days past token expiry still enables protection. The example production build pulls a fresh license and embeds only the signed token and public JWKS in server output.
- 2026-10-07: Checked signing-key handling without displaying its value: the private JWK is configured in ignored `.env`, and scans found neither its encoded value nor private `d` material in source or the existing Next bundle. Missing production keys and test/live prefix mismatch are covered; a valid new `kid` is fetched and accepted. HTTPS deployment is not available from this checkout: Vercel CLI/auth/project link are absent and Git has no remote. The current key is development-only, so production deployment and live copied-token/outage checks remain pending.
- 2026-10-07: Finalized the build-time snapshot workflow: the example build pulls a license and public JWKS, verifies the environment/key prefix, embeds the signed snapshot only in the server build, and restores the source placeholder afterward. Added the app-local `.tether/` directory to `.gitignore`. `node --check`, `git diff --check`, full `pnpm typecheck`, and full `pnpm test` pass (70 tests total). HTTPS deployment and live-key scenarios remain blocked on Vercel project/auth and a production key.
- 2026-10-07: Set the example's production license policy to `closed` and documented the two-deploy bootstrap needed because the example also hosts its own license issuer. Added `build:bootstrap` for the first deploy; subsequent deploys use the snapshot build. The bootstrap production compilation passed locally with an explicit development override; full typecheck and all 70 tests pass. HTTPS deployment is still waiting on Vercel project linking and a production key.
- 2026-10-07: Audited `.env` without displaying values. It has the Supabase URL/public and server keys, project ID, development Tether key, signing private key and matching public `kid`, and a valid 32-byte cookie secret. `TETHER_LICENSE_ISSUER` and a production `tk_live_` key are still missing. The user has now signed in to Vercel; no project is linked yet. Added `.vercelignore` for local env files and `.tether` artifacts, and documented the monorepo root/source setting plus Production-versus-Preview environment values. Deployment is awaiting the stable Vercel origin and a production API key.
