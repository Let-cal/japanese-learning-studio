# Google PKCE transport boundary

This source slice implements fixed Supabase Auth transport, not a connected login flow. Application code imports the `server-only` gateway. Configuration is copied from approved server inputs; no environment values or keys are provisioned here.

The authorization URL selects Google, S256 and the exact configured app callback. It contains the challenge, not the verifier. Supabase manages provider-facing state. Exchange uses the PKCE grant; refresh uses its distinct grant. Requests carry a publishable key and never forward browser cookies or an Authorization header. No automatic retries occur.

The returned token pair is **unverified**. User metadata, provider credentials and upstream expiry fields are discarded. The candidate/continuation verifier and durable transaction still have to establish identity, owner authority, expiry and session binding before tokens can authorize study access.

Every sent failure is conservatively `outcome_unknown`, including an unsuccessful HTTP response. A caller must close or resolve its persisted transmission intent. It must not infer that a code or rotating token is safe to send again. Preflight errors distinguish `not_sent`.

Headers and response-body reading share a five-second maximum, a 64 KiB decoded-body bound, stream cancellation and an optional parent AbortSignal. Monotonic elapsed checks reject late headers/body/success even if the event loop delays the timer callback. A route-wide deadline must still bound the complete multi-step flow.

Auth-action secrets use separate wire prefixes and purpose-separated hashes. Exact cookie fingerprints preserve absence versus present malformed values; neither hashing nor possession establishes authority. PKCE encryption has its own `pkce-v1` envelope and authenticated environment/browser-binding/attempt context. It does not reuse the upstream-token envelope or prevent replay within the same context; the durable store must enforce generations and one-time claims.

## Local evidence and remaining work

Tests-first stub run: 28 transport failures with four preflight passes. Initial implementation: 32 transport tests passed. Independent review reproduced a timer-only deadline gap; two new regressions failed before monotonic checks and passed after the fix. Final focused run: 34 transport tests and nine action-secret tests passed. The action-secret test scaffold also failed before implementation.

These tests use synthetic tokens and injected network boundaries. They prove no live Google login, deployed callback, real Auth/RLS behavior or physical Safari support. Store operations, sent-intent persistence, cleanup, routes and reviewed environment activation remain required. No request is made to the configured sample hosts during these tests.

Sources consulted: [Supabase PKCE flow](https://supabase.com/docs/guides/auth/sessions/pkce-flow), [official Auth client implementation](https://github.com/supabase/auth-js/blob/master/src/GoTrueClient.ts), [RFC 7636 S256 test vector](https://www.rfc-editor.org/rfc/rfc7636#appendix-B). The Auth-server product guide for third-party OAuth clients describes a different flow; it is not used to select these grant paths.
