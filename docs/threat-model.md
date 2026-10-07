# Tether v1 threat model

## Security goal

When a backend has bound a Supabase Auth session to a browser key, a copied access token alone must
not authorize a protected request from a different key. The backend first verifies the access token,
then verifies a fresh ES256 proof, including its signature, method, URL, token hash, time, replay ID,
and bound key thumbprint.

## Covered attacks

- A bearer token copied from a log, proxy, screenshot, or support message and replayed without the
  device key is rejected with `PROOF_MISSING`.
- A copied token paired with a fresh attacker-controlled signing key is rejected with
  `PROOF_KEY_MISMATCH`.
- A captured proof replayed to the same process is rejected with `PROOF_REPLAY`.
- A proof for another URL or method, a stale proof, or a proof for another token has a stable reason
  code and is rejected.
- Browser private keys are created as non-extractable WebCrypto keys and are not sent to the server.
- Cookie refresh requires the verified Supabase session, its bound key, a fresh DPoP proof, and a
  same-origin request. Cookie-only authorization accepts GET and HEAD requests only.
- A valid cookie ticket rotates once. A same-key retry within ten seconds receives the currently
  active replacement ticket. Same-key reuse after that grace, or a valid different-key replay of a
  consumed ticket, revokes the session binding and writes a `REFRESH_REUSE` security event atomically
  in the database-backed example store.

## Not covered

- Active XSS or malware running in the victim's browser can ask that browser to sign requests with
  the live key.
- Non-extractable WebCrypto keys are not a promise of hardware isolation. Malware that copies a
  complete browser profile may be able to copy software-backed key material, depending on the
  browser and operating system.
- A compromised application server, Supabase Auth signing infrastructure, or server-only secret is
  outside the client proof's protection boundary.
- A stolen `__Host-tether` cookie can authorize cookie-protected safe reads until it expires, for up
  to five minutes. `HttpOnly` prevents ordinary JavaScript from reading it, but cannot protect a
  stolen browser profile or an active browser compromise. State changes must continue to use DPoP.
- Reusing a consumed cookie after the ten-second same-key retry grace revokes the server-side
  binding; a cryptographically valid refresh proof from a different key revokes immediately when it
  reuses a consumed cookie. The example invalidates its local binding cache on the detecting
  instance; other instances can retain a positive binding cache for up to 30 seconds. A cookie-only
  route also checks the binding before authorizing its request.
- Supabase sign-out clears the current browser's cookie, but a copied cookie can remain valid for
  safe reads until expiry unless the binding is separately revoked.
- The current replay and nonce stores are process-local. A replay sent to a different server
  instance may not be seen by the first instance's cache.

## Operational limits

- The example caches binding lookups for 30 seconds. A bind or revocation performed on another
  instance can take up to 30 seconds to appear there.
- A cache miss needs the bindings database. If Supabase is unavailable on that miss, the example
  fails closed with `TETHER_STATE_UNAVAILABLE`; cached sessions can continue until cache expiry.
- The ingest endpoint is separate from verification and cannot delay protected requests. Its
  in-memory rate limit is per instance and needs a shared limiter for multi-instance deployment.
- Events contain only allowlisted metadata. Do not add access tokens, DPoP proofs, signatures,
  private keys, raw IP addresses, or raw User-Agent strings to event payloads or logs.

## Required checks before production

Apply the checked-in schema, run the two-user RLS isolation tests, run the copied-token and replay
attacker cases, use shared replay/nonce state for multi-instance deployments, and configure daily
event retention. The current database migration and RLS checks are not marked complete until they
have run against a configured project.
