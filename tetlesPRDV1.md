# Tether: Product Requirements Document

*Working name. Version 1.0. Stolen session tokens become useless on any other device.*

## 1. The problem

A session token proves that login already happened. Anyone who copies it, from a screenshot, a log file, a proxy, a browser extension or an XSS bug, is logged in without the password or 2FA. Big platforms can't fix this quickly because retrofitting every web, mobile and API path is expensive. Small teams have no easy option.

## 2. The product in one sentence

A drop-in library and fast verification service that binds every session to a key that never leaves the user's device, in every browser, with setup measured in minutes.

## 3. Goals and non-goals

| Goals | Non-goals (v1) |
| --- | --- |
| A stolen token fails on any other device | Replacing login, passwords or OAuth providers |
| Works in all modern browsers, plus an API for apps | Stopping malware that controls the live device |
| First protected request in under 10 minutes | Building our own identity provider |
| Verification so fast no one removes it for speed | Device fingerprinting as proof of identity |
| Honest claims that security teams trust | Native mobile SDKs (v2) |

## 4. Users

- **Solo developers and startups** on Supabase, Clerk, Auth0, NextAuth or custom auth. They want it working today.
- **Security-sensitive teams** (fintech, crypto, admin panels, B2B SaaS). They pay for detection, alerts and audit logs.
- **Auth providers** that want to add binding as a plugin instead of building it.

## 5. The rules (the product's constitution)

1. **Ten minutes or it failed.** If integration takes longer than ten minutes, the product is broken, however secure it is.
2. **Secure by default.** The default configuration is the safe one. Weakening anything needs an explicit, named option.
3. **Proof, not hints.** Only a valid signature proves a device. Everything else is a risk signal.
4. **Explain every decision.** Each block, challenge or revoke carries a plain-language reason code.
5. **Boring standards.** Follow DPoP (RFC 9449), WebCrypto and ES256 wherever possible. Novelty belongs in the developer experience, not the cryptography.
6. **Honest claims.** We say "a stolen token is useless on another device." We never say "unhackable."
7. **Never log you out for no reason.** A false logout is a bug with a severity level.

## 6. Legendary style: how it must look and feel

The reference is Supabase-grade developer experience: you understand it in thirty seconds and ship in ten minutes.

**Developer experience**

- Quickstart is one page with copy-paste code: **3 lines on the frontend, 3 lines on the backend.** No account needed to try it locally.
- A live demo on the homepage shows a stolen token failing. This is the main marketing asset.
- Errors tell you what happened and the fix: `TETHER_PROOF_URL_MISMATCH: proof was signed for /a but sent to /b. Check your proxy rewrites.` Errors never apologize and are never vague.
- Docs have a search bar, a copy button on every snippet, and a framework tab (Next.js, Express, Hono, FastAPI, Go) that remembers your choice.
- Open-source core, readable code, short README, working examples for each framework.

**Dashboard**

- Calm, dense, readable. Light and dark themes. One accent color. No decorative gradients or chart junk.
- The home screen answers three questions: *Are sessions safe? What was blocked? What needs me?*
- Every event is one line: time, user, reason code, action taken. Click for the full proof details.
- Empty states tell you the next action ("No blocked sessions yet. Run the demo to see one.").
- Keyboard-first: command palette, visible focus, works on mobile, respects reduced motion.

## 7. What it must contain

### P0: ships in v1

| # | Requirement |
| --- | --- |
| 1 | **Browser client (JS/TS):** generates a non-extractable ES256 key at login, wraps `fetch`, attaches a DPoP-style proof (method, URL, timestamp, unique ID, token hash) automatically |
| 2 | **Verifier middleware** for Express, Hono, Next.js, FastAPI and Go net/http, all wrapping one core |
| 3 | **Framework-independent TypeScript core** that verifies proofs and issues key-bound tokens for the supported v1 adapters |
| 4 | **Short-lived cookie tier** (default 5 minutes, refreshed with a signed call) for page loads and anything JavaScript can't sign |
| 5 | **Refresh token rotation with reuse detection:** same-key retries within a short grace window return the active replacement ticket; later same-key reuse or a different-key replay of a consumed ticket revokes the session and raises an event |
| 6 | **Replay protection:** each proof ID is accepted once inside its time window |
| 7 | **Server-issued nonces** so client clock drift never causes false rejections |
| 8 | **Multi-tab safety** through the Web Locks API so tabs never race on refresh |
| 9 | **Recovery path:** if the key is lost (cleared storage, Safari eviction), re-login is one smooth step with no error screen |
| 10 | **Event log and webhook** for every block, challenge and revoke |
| 11 | **Integration with existing auth:** works alongside Supabase, Clerk, Auth0 and NextAuth through an adapter, with no migration |

**v1 scope note:** Rust and WASM are deferred. The v1 verifier is TypeScript and runs in the customer's app, as specified by the Technical PRD. The five-minute `__Host-tether` cookie is a short-lived bearer credential for cookie-only safe reads; a copied active cookie can work until expiry. The key-bound theft-resistance claim applies to DPoP-protected requests. Do not claim that cookie-only requests reject copied cookies.

### P1: v1.x

Dashboard with alerts (Slack, email), risk engine with configurable policies, per-route sensitivity ("sign everything for /billing"), WebSocket and streaming tickets, SOC 2 evidence exports.

### P2: later

DBSC upgrade in Chrome, Secure Enclave and Android hardware keys through mobile SDKs, passkey step-up, ML-assisted anomaly scoring, cross-device session approval.

## 8. Never allowed

These are hard rules. A change request that breaks one is rejected, whoever asks.

1. **Never accept a bare token** on a protected route when binding is on.
2. **Never use an extractable key.** Never transmit, store or log a private key.
3. **Never treat a device fingerprint as proof.** Fingerprints may feed risk scoring only.
4. **Never log tokens, proofs or signatures** in plaintext, in any environment.
5. **Never accept weak or unknown algorithms** (`none`, HS256 for proofs, RSA below 2048). v1 accepts ES256 only.
6. **Never accept a proof** missing method, URL, timestamp, unique ID or token hash, or one used twice.
7. **Never fail open silently.** If the replay cache is down, behavior follows a visible config (default: fail closed on sensitive routes), and an alert fires.
8. **Never block or revoke without a reason code** shown to the developer.
9. **Never use cross-site identifiers.** One key per session. No tracking, no sharing keys across sites.
10. **Never claim "unhackable" or "theft-proof"** anywhere, including sales calls.
11. **Never require more than three config values** to get started.
12. **Never ship a breaking change** without a major version and a migration guide.
13. **Never release a crypto path** without RFC test vectors and a fuzz test passing in CI.
14. **Never add a dependency without review.** This is a security product, and a supply-chain attack on us hits every customer.

## 9. Scalability and performance

Targets for the v1 benchmark suite, measured and published, not promised in advance:

| Area | Target |
| --- | --- |
| Proof verification, in process | p99 under 1 ms |
| Verification over the network (same region) | p99 under 5 ms |
| Throughput | 10,000+ verifications per second per core |
| Memory per active session | under 1 KB of server state |
| Per-request database lookups | **zero** on the hot path |

**How we get there**

- **Stateless verification.** The access token carries the thumbprint of the client key. The proof carries the public key. Verification is a thumbprint check plus one signature check.
- **State only where needed.** The sole shared state is a replay cache of recent proof IDs with short expiry (in-memory per node, Redis for shared mode). Sizing follows the 30-second proof window, so it stays small.
- **Horizontal scaling.** Nodes share nothing but the replay cache and revocation list. Revocation is pushed to edges within one second.
- **Edge-ready later.** Rust/WASM for Cloudflare Workers, Deno, and similar runtimes is deferred until a customer requires it, consistent with the Technical PRD's v1 scope.
- **Overload behavior is defined.** Under load, shed non-sensitive checks first and never skip signature verification.

## 10. Fast recognition and smart decisions

**Recognition is instant because it is math.** A copied token with no valid signature is rejected in the first verification step, in under a millisecond, with no model involved.

**Smart signals** sit on top and answer "this is a valid device, but is something wrong?":

- Refresh token reuse (strongest signal: possible theft)
- Sudden change in country, network (ASN) or browser family mid-session
- Impossible travel and unusual request rates
- Proofs signed with a new key for an existing session

**Decisions**

| Risk | Action |
| --- | --- |
| Low | Allow |
| Medium | Step-up: re-authenticate for sensitive actions only |
| High | Revoke the session and alert |

**Requirements**

- Time to detect refresh reuse: at the next refresh attempt.
- Alert delivery: under 5 seconds from detection.
- Revocation propagation: under 1 second to all nodes.
- v1 is **rule-based and explainable.** Every decision returns the signals that triggered it. ML scoring arrives only after we have real data, and never overrides the never-allowed list.

## 11. Threat model (published in the docs)

| Attack | Stopped? |
| --- | --- |
| Token copied from logs, proxy, shared link, screenshot or support ticket | **Yes** |
| Token leaked by an extension or XSS exfiltration | **Yes** (key can't be exported) |
| Captured request replayed | **Yes** (nonce and window) |
| Copy-paste to another tab or device (the original problem) | **Yes** |
| Infostealer malware that copies the whole browser profile | **Partly.** Software keys may be copied. Hardware binding (DBSC, Secure Enclave) is the P2 fix |
| Malware or XSS using the live key inside the victim's browser | **No.** Mitigated with short lifetimes and step-up on sensitive actions |

## 12. Architecture

`Browser client` → signs requests → `Your backend + Tether middleware` → verifies with → `Tether core (TypeScript)` → uses → `Replay and revocation state` → sends events → `Dashboard and webhooks`

V1 stack: strict TypeScript core and adapters, Web Crypto, ES256, and Postgres for events and bindings. Rust/WASM, Redis, and hosted verification are deferred until customer needs justify them, consistent with the Technical PRD.

## 13. Success metrics

- Time to first protected request: **median under 10 minutes** (measured with a timed onboarding test)
- False logout rate: **under 0.1%** of sessions
- Stolen-token replays blocked: 100% in the test suite
- Added latency on a customer's API: under 5 ms p99
- Adoption: GitHub stars, weekly installs, and 10 design partners using it in production by month 6
- Revenue: first paying team by month 6, with dashboard and alerts as the paid tier

## 14. Roadmap

| Phase | Weeks | Output |
| --- | --- | --- |
| 0: Core | 1-4 | TypeScript verifier, ES256 proofs, replay cache, JS client, Next.js + Supabase example, public stolen-token demo |
| 1: Developer launch | 5-8 | Cookie tier, refresh rotation with reuse detection, end-to-end validation, docs, benchmarks, and open-source release; Express follows the first-user alpha |
| 2: First users | 9-16 | Interviews with 20 developers, Supabase and Clerk adapters, event log, webhooks |
| 3: Paid tier | 17-24 | Dashboard, alerts, risk policies, audit exports, hosted verification service |

## 15. Risks and open questions

| Risk | Plan |
| --- | --- |
| Auth providers add the same feature | Be their plugin first. Own simplicity and detection quality |
| Real-world edge cases (service workers, streaming, Safari storage eviction) cause false logouts | Narrow v1 to SPA and API traffic and test with real apps before widening |
| Security buyers distrust new vendors | Open-source core, third-party audit before the paid tier, honest threat model |
| Infostealers bypass software keys | State it openly and prioritize hardware binding |

**Open questions:** Which framework adapter first? Hosted service or self-host first? What does the free tier include? Which 20 developers will we interview first?
