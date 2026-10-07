# Tether: License System PRD

*Working name. Companion to the product PRD and the technical PRD. This document defines the key, the license, the plans, the limits, and what happens in every state.*

## 1. Purpose

The license system makes the key mandatory in production, turns trials into customers, and meters usage for billing, **without ever putting our servers on a customer's request path.**

**The one-line promise:** *No valid license, no production protection, and we never break your app over billing.*

Those two halves pull in opposite directions, so every rule below is built to satisfy both.

## 2. Principles

1. **Offline-first.** Every request is verified locally. The license is a signed file the SDK checks offline. Our outage never affects a customer's traffic.
2. **Key required in production, free to start.** Signup takes 30 seconds with no credit card. Dev and localhost need no key.
3. **A valid license enables production protection.** The verifier remains auditable, but supported SDKs enforce protected routes in production only while they hold an acceptable signed license. The license also unlocks plan-specific cloud services such as the dashboard, alerts, shared replay store, policies, retention, and audit exports.
4. **Loud, never silent.** When Tether protection is unavailable, the SDK writes a clear local warning and the control plane surfaces the state in the dashboard. Email, Slack, and webhook notifications are best-effort, asynchronous, deduplicated, and retried; alert delivery never runs on or blocks a customer's request path. The SDK warning is the immediate signal when the control plane cannot be reached.
5. **Boot can fail, the host process stays up at runtime.** A missing key at startup is a config error and fails visibly at deploy time unless the explicit escape hatch is used. If a license lapses while the app is running, the process does not crash; protected requests follow `onUnlicensed`. The default `open` mode keeps the host app running without Tether protection and warns loudly; `closed` is an explicit choice to reject protected requests.
6. **Meter something customers understand and can't be surprised by.**

## 3. What we meter and why

**Primary meter: Monthly Protected Users (MPU).** The number of distinct users with at least one verified protected request in a calendar month.

| Candidate | Verdict |
| --- | --- |
| Raw requests | Rejected. Punishes busy apps, spikes during attacks, and nobody can predict it |
| Sessions | Rejected as primary. One person with 4 devices counts 4 times, and bots inflate it |
| **MPU (distinct users)** | **Chosen.** Matches how auth products are priced, predictable, and grows with the customer's success |
| Projects or seats | Used as secondary limits for plan gating |

**How counting works (privacy-safe)**

- The SDK computes `HMAC(project_secret, user_id)` and reports only new hashes it has seen that day (deduplicated in memory per instance). We never receive raw user IDs.
- The server stores `(project_id, month, subject_hash)` with a unique constraint. Repeats are free duplicates, so cold starts and multiple instances can't overcount.
- If no user ID is available, the SDK falls back to the session binding ID and the project is labeled "session-metered."
- **Accuracy goal:** within 2% of true, biased low. Small undercounts are acceptable. Overcounts that cost a customer money are bugs.

## 4. Plans and limits

**Honest note:** the numbers below are **hypotheses to test**, not researched market prices. Infrastructure cost per user is tiny at this scale, so MPU limits act as pricing levers and abuse guards. Real upgrade pressure comes from **feature gates**. Validate everything in the alpha and the 20 developer interviews.

|  | Free | Team | Business | Enterprise |
| --- | --- | --- | --- | --- |
| Included MPU / month | 500 | 10,000 | 100,000 | Custom |
| Projects | 1 | 5 | 25 | Custom |
| Event history | 7 days | 90 days | 1 year | Custom |
| Alerts | Email | Email, Slack, webhooks | Same plus escalation | Same plus custom |
| Shared replay and revocation store | No | Yes | Yes (higher throughput) | Yes |
| Risk policies and step-up | Basic | Full | Full | Full |
| Audit exports | No | No | Yes | Yes |
| Seats | 1 | 5 | 20 | Custom |
| Support | Community | Email | Priority, SLA | Dedicated |
| Placeholder price | $0 | \~$49 / mo | \~$299 / mo | Contact |

**Trial:** 14 days of full Team features, starting at first production use (not at signup), no card required.

**Overage:** soft by design.

- 80% of included MPU: dashboard banner and email.
- 100%: email, and a prompt to upgrade or buy overage.
- Free plan over the limit: **protection continues during the 14-day grace period** and the countdown begins. After that the project moves to `limited`, which disables Tether protection in production (see state table).
- Paid plans: overage billed per 1,000 MPU, with a customer-set spending cap. No surprise bills.

**Why 500 free MPU:** enough for a real app to prove value and show us real usage, small enough that serious products must pay.

## 5. The license token

A signed JWT issued by `/v1/license`, verified **offline** by the SDK. Its JOSE header and payload are a versioned contract; SDKs reject unknown algorithms, unknown key IDs, invalid signatures, and mismatched issuer, audience, project, or environment.

**Protected JOSE header**

| Field | Required value / meaning |
| --- | --- |
| `typ` | `JWT` |
| `alg` | `ES256`; no algorithm negotiation |
| `kid` | ID of the signing key; this is a JOSE header parameter, not a payload claim |

**Payload claims**

| Claim | Meaning |
| --- | --- |
| `iss` | Exact license-service issuer URL configured in the SDK |
| `aud` | `tether-license`; prevents accepting a token minted for a different service |
| `sub` | Project ID |
| `jti` | Unique ID for this issued license token |
| `iat`, `nbf`, `exp` | NumericDate seconds; `exp` is no more than 24 hours after `iat` |
| `plan` | `free`, `team`, `business`, `enterprise` |
| `state` | `trial`, `active`, `grace`, `limited`, `suspended`, `revoked` |
| `trial_ends_at` | NumericDate seconds or null |
| `grace_ends_at` | NumericDate seconds or null |
| `limits` | `{ mpu, projects, retention_days, seats }` |
| `features` | Allowlisted feature names, e.g. `["shared_store","policies","webhooks"]` |
| `env` | `production` or `development`, matching the accepted key/runtime environment |
| `ver` | Integer license schema version; unknown versions are rejected rather than guessed |

**Rules**

- Algorithm: **ES256** (same as proofs, supported by `jose` on every runtime). Nothing else is accepted.
- The SDK ships with a small **set of public keys by `kid`**. It also fetches `/v1/jwks` in the background so rotation never requires an SDK release. An unknown `kid` is rejected and triggers a JWKS refresh.
- Clock skew tolerance: 2 minutes.
- The SDK checks `iat`, `nbf`, and `exp` with the same two-minute clock-skew tolerance. It never extends `nbf` or the license claims; the seven-day allowance only permits using a previously verified cached token after its `exp` when refresh is unavailable.
- **Offline staleness window:** if refresh fails, the SDK trusts the last valid license for up to **7 days past `exp`**. During this window the cached license remains acceptable for local protection. Beyond it the SDK is unlicensed and follows `onUnlicensed`; it never makes a request to our servers on the customer's request path.
- The SDK cache is pluggable. A process-local cache is the default; deployments that need the seven-day allowance across cold starts must provide a durable `LicenseCacheStore`. Cache the signed token and its already-trusted public JWKS, never the raw API key.
- The signing private key lives only in server environment secrets, separate from the event-signing key. Never in the repo, logs, or client bundles.

**A license is acceptable for production protection only when** its signature, issuer, project, environment, time claims, and key ID validate, and its state is `trial`, `active`, or `grace`. The seven-day offline staleness allowance applies only to a previously valid cached license when refresh is unavailable. A license known to be `limited`, `suspended`, or `revoked` is not acceptable and does not enable Tether protection.

## 6. The key

| Property | Rule |
| --- | --- |
| Format | `tk_live_<random>` for production, `tk_test_<random>` for development. 32 bytes of randomness, shown once |
| Storage | Only a hash is stored. We can show the prefix and last 4 characters, nothing more |
| Use | Server-side only. Never in browser code. The public project ID is separate and safe in the browser |
| Rotation | Create a second key, deploy, revoke the first. Up to 3 active keys per project |
| Leak handling | Register with GitHub secret scanning. On a leak report, revoke and email the owner |
| Revocation latency | A revoked key fails on the next license refresh. The optional fast revocation check runs at most hourly; cached licenses may remain usable while offline only within the stated seven-day allowance |

## 7. States and behavior

| State | Meaning | SDK behavior |
| --- | --- | --- |
| `trial` | Within 14 days | Full features. Reminder emails at day 7, 12, 14 |
| `active` | Paid or within free limits | Normal |
| `grace` | Trial ended, over limit, or payment failed. 14 days | **Full protection continues** until grace ends. Warning log on boot and daily, dashboard banner, email |
| `limited` | Grace expired or a plan limit remains unresolved | Tether protection is no longer active in production; `onUnlicensed` applies. Paid cloud features stop. Loud warning hourly |
| `suspended` | Terms or abuse issue, after notice | Tether protection is no longer active in production; `onUnlicensed` applies. A visible dashboard banner explains the suspension |
| `revoked` | The service has confirmed the key or license is revoked | Tether protection is no longer active once the SDK learns of revocation; `onUnlicensed` applies and an error is logged hourly |

The offline staleness allowance is not a revocation grace period: when the SDK receives a signed `revoked` license or learns that the key is revoked through the revocation check, it applies `onUnlicensed` immediately. If disconnected, it can only use the last valid cached license until that license's seven-day offline allowance ends.

**Missing or invalid key**

- **Development:** works with no key. A one-time message says "running unlicensed in dev."
- **Production, key missing at startup:** the SDK **throws at boot** with a clear message and the fix (`npx tether init`). Escape hatch: `allowUnlicensed: true`, which logs `UNLICENSED: sessions are NOT protected` hourly.
- **Production, license unreachable:** keep using the last verified cached license through its 24-hour expiry and seven-day offline staleness allowance. A network outage alone never changes a still-acceptable cached license. Once the cache is outside that allowance, the SDK is unlicensed and applies `onUnlicensed` without crashing the host process.

**`onUnlicensed` setting** (when protection would otherwise stop): `"open"` (default, requests pass, loud warnings) or `"closed"` (protected routes reject). Customers choose, we don't.

**Production detection:** an explicit server-side `TETHER_ENV=production|development` overrides detection. Otherwise, `NODE_ENV=production` means production and every other value means development. Never infer the environment from an HTTP `Host` header or other request-controlled value. Key prefixes must match the selected environment: `tk_live_` for production and `tk_test_` for development. A mismatch is a loud configuration error and does not enable protection. Vercel Preview deployments use `TETHER_ENV=development` explicitly when they should not enforce production licensing. Test every combination.

**When no acceptable license is available in production**, Tether protection is not active. `onUnlicensed: "open"` lets the host application continue without Tether protection and emits loud, repeated warnings; `onUnlicensed: "closed"` rejects protected requests with a stable license error. The host process does not crash because a license expires or the license service is unreachable. A missing key at startup remains a visible configuration error unless `allowUnlicensed: true` is explicitly set.

In `open` mode, the route handler still runs, but the SDK skips Tether authentication, binding, and proof checks and passes a defined degraded context with `licensed: false`, `bound: false`, null identity/proof fields, and a stable license `reasonCode`. Handlers must check `licensed` before using identity fields and remain responsible for application-level authorization. Individual routes may override the adapter-wide `onUnlicensed` policy to `closed`. License refresh runs in the background, and the gate reads only the locally verified cache on requests.

## 8. Endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/license` | Exchange a key for a signed license. Rate limited per key and per IP. Responses are cacheable and cheap |
| `GET /v1/jwks` | Public signing keys by `kid` |
| `POST /v1/usage` | Batched, signed usage reports: MPU hashes, counters, reason-code totals. Returns `202` immediately and writes asynchronously |
| `GET /v1/revoked` | Short list of revoked key IDs (optional fast path) |
| CLI device flow | `npx tether init`: browser login via GitHub, **with email magic link as a fallback** so an identity-provider outage doesn't block signup |

**Alert delivery note:** threshold and license-state alerts are written to an asynchronous outbox. Each event has a stable idempotency key (project, alert type, and threshold or state transition); retries reuse that key. Repeated instances of the same unresolved condition are coalesced, while a new state transition or a newly crossed threshold creates a new alert. Delivery retries use backoff and surface persistent failures in the dashboard. An unavailable alert provider never changes license verification, protection, or the result of a protected request. Local SDK warnings remain the immediate signal when the service is unreachable.

The CLI creates the project, the first key, and writes `TETHER_KEY` plus `TETHER_PROJECT_ID` to `.env`, then prints the 3-line integration.

## 9. Data model (additions)

| Table | Key columns |
| --- | --- |
| `plans` | id, name, limits (jsonb), features (text\[\]), price_ref |
| `projects` | plan_id, state, trial_started_at, trial_ends_at, grace_ends_at, spending_cap |
| `api_keys` | id, project_id, hash, prefix, env, created_at, last_used_at, revoked_at |
| `licenses_issued` | id, project_id, key_id, kid, issued_at, exp, ip_prefix (audit) |
| `mpu_subjects` | project_id, month, subject_hash (unique together) |
| `usage_rollups` | project_id, minute, counters (jsonb) |
| `signing_keys` | kid, public_jwk, status (`active`, `retiring`, `retired`), created_at |
| `alert_outbox` | idempotency_key (unique), project_id, type, payload, status, attempts, next_attempt_at, created_at |

Row Level Security on all tables. Owners see only their projects. Test with a second account in CI.

## 10. Abuse and fraud

- **One free project per verified GitHub or email identity,** with a cap on projects and keys per account.
- **Key sharing detection (soft):** the same key reporting from many unrelated hosts or regions triggers a review flag and an email, never an automatic block.
- **Free-tier farming:** rate limit signups per IP and block disposable email domains.
- **`/license` abuse:** rate limits, a small response cache, and anomaly alerts on spikes.
- **A patched SDK can skip the check.** That is unavoidable for open code. The protection is that cloud features, the shared store, and support live on our servers. Don't spend effort on obfuscation.

## 11. Never allowed

1. Never put a network call to us on the request path.
2. Never crash a running host process solely because of license, billing, or a Tether outage. The configured `onUnlicensed` policy may pass protected requests through without Tether protection (`open`) or reject those requests (`closed`); it must not stop unrelated host application work. A missing production key may produce a visible startup configuration error before the app begins serving.
3. Never let a customer run unprotected without a loud, repeated warning.
4. Never accept any license algorithm except ES256, or an unknown `kid`.
5. Never store raw API keys or raw user IDs.
6. Never put the signing key in the repo, logs, or any bundle.
7. Never bill on a number the customer can't see in the dashboard.
8. Never exceed a customer's spending cap.
9. Never change a license field's meaning without bumping `ver`.
10. Never ship the license code without tests for every state and every failure path.

## 12. Testing requirements

| Area | Cases |
| --- | --- |
| Token | Valid, expired, `nbf` in the future, wrong `kid`, wrong algorithm, tampered claims, clock skew edge |
| States | Every state transition, including trial to grace to limited, payment recovery, and revocation |
| Offline | Server unreachable for 1 hour, 1 day, 7 days, 8 days |
| Boot | Missing key in dev and production, `allowUnlicensed`, both key-prefix/environment mismatch directions, explicit and inferred environment detection, spoofed Host header cannot change environment, Vercel Preview override |
| License gate | `trial`/`active`/`grace` enable protection; `limited`/`suspended`/`revoked` do not; both `onUnlicensed` modes are loud and deterministic without crashing the host process |
| Rotation | Add a `kid`, retire an old one, an SDK with only the old key set |
| Metering | Multi-instance dedup, cold starts, duplicate reports, month boundary, no-user-ID fallback |
| Security | Key hashing, RLS isolation, rate limits, leaked-key revocation |
| Attack | Forged license, replayed old license after downgrade, shared key across hosts |
| Alerts | Threshold and state-transition alerts are deduplicated through the outbox and retried asynchronously; persistent delivery failures appear in the dashboard; provider failures never delay or change protected-request results |

**Release gate:** nothing ships if a forged or expired license is accepted in any test.

## 13. Success metrics

- `npx tether init` to first verified request: **median under 5 minutes**
- Signup to production-key activation rate (the real adoption signal)
- Percent of production projects with a valid license: above 95%
- Support tickets caused by license or billing confusion: near zero
- False license rejections: zero
- Free to paid conversion: measured from alpha onward, no target before we have data

## 14. Build order

1. Freeze this spec, including claims and state table
2. Signing keys, JWKS, `/v1/license`, and the SDK's offline verification and caching
3. Key issuance and hashing, plus `npx tether init` with the fallback login
4. Boot and runtime behavior for each state, with warnings
5. `/v1/usage` and MPU metering
6. Limits, soft overage, and trial emails
7. Stripe, only when someone asks to pay

## 15. Open decisions

1. Final prices and MPU limits (validate in alpha and interviews)
2. License for the open core (Apache-2.0 vs source-available such as BSL). **Needs a lawyer**
3. Default for `onUnlicensed` (`open` is recommended, but revisit with security buyers)
4. Whether the shared replay store is Team or Business-only
5. Final product name (affects the key prefix, the npm scope, and the CLI command)
