# Server session lookup adapter

## Decision and scope

On 2026-11-05 the owner selected ADR0006 alternative A: a server-only control RPC capability backed by a Supabase secret key, with ordinary study access kept on a separate verified user-JWT and RLS path. This accepts the privilege boundary, not SQL/configuration activation or a release. The frozen preceding source snapshot retains ADR0006's earlier proposed status; this record supersedes only its pending A/B choice.

The secret capability remains broad and bypasses RLS. A fixed function name in application code is not a database-enforced restriction on the key. Modern secret keys belong on the `apikey` header, not `Authorization: Bearer`. See [Supabase API-key documentation](https://supabase.com/docs/guides/getting-started/api-keys).

This source slice prepares only the read-only session metadata lookup. It does not implement `requireOwnerSession`, Google sign-in, cookie parsing, credential decryption/verification, refresh, logout, `/me`, owner bootstrap or a durable SQL store. No environment variables are read automatically and no hosted function is called by the tests.

## Internal RPC contract

The configured HTTPS Supabase project origin and fixed `jls_auth_session_lookup_v1` function are server-owned. POST a single `p_session_secret_hash` field derived by the existing purpose-separated session-secret hash. Never forward browser headers, URLs, schemas or function names. No response or error includes a raw cookie, digest, key, token or credential envelope.

A valid HTTP200 response is an exact JSON object with either `kind: absent` and authoritative database time, or `kind: found` with the current session, owner, dataset and stored credential metadata. It is not a row-array response. All nested fields/types are validated. A revoked or mismatched owner record is a valid denial fact; malformed or unavailable dependency data is not confirmed absence.

The lookup does not update activity or acknowledge cookie delivery. Stored credential readiness does not verify a user JWT and cannot authorize personal access. Its result must not bypass the remaining session policy, upstream identity verification or transaction-time checks.

## Operating bounds and activation

The design budget is one request, no automatic retries, a two-second total deadline including reading the body, an eight-KiB body bound before JSON parsing and strict UTF-8. These are local correctness limits, not measured hosted capacity or latency promises. Timeout or abort does not prove remote cancellation.

Before runtime activation, review and implement the matching SQL function/grants, verify direct-role denials through actual Supabase/PostgREST, and supply the separate verified user-JWT path. Function execution permissions are distinct from RLS. [PostgREST RPC semantics](https://docs.postgrest.org/en/stable/references/api/functions.html).

Diff/publication, cloud-change, merge, human security, UAT and release approvals remain open. This source introduces no service, account, payment or dependency change.

## Local verification — 2026-11-05

- TDD: all 12 focused tests failed against the initial no-op skeleton, then passed against the adapter. Cases include exact hashed request construction, invalid configuration/input, valid denial facts, malformed success, oversized/invalid UTF-8, non200 cancellation, ignored abort signals and a body stall within the total deadline.
- Parent independently ran the complete ordinary suite: **462 tests / 21 files passed**, then strict TypeScript and the production build passed.
- Independent read-only security review approved the scoped source with no actionable findings. This is not the owner's human security acceptance and did not run live Auth/RLS probes.
- The preceding sample UI source remains byte-identical to its reviewed snapshot, which passed 17 Chromium tests in 32.8 seconds. Browser testing was not repeated for these disconnected server files; no additional Safari or browser-integration claim is made.

The Next build currently lists only the existing public/demo/status routes. A successful build does not prove that this unconnected adapter has been exercised by a real server route or accepted by hosted PostgREST.
