# OAuth lifecycle SQL source verification

This is local source preparation for ADR 0006 and the approved runtime integration brief. It does not wire routes, activate login, enroll an owner, implement refresh mutation, apply hosted SQL, or prove Supabase/Google integration.

The pinned local Supabase CLI 3.0.0 generated `20261107050258_auth_oauth_lifecycle.sql` with `migration new auth_oauth_lifecycle --workdir <exact worktree>`. The frozen first migration remains unchanged. The new migration extends it; both files are required, in order.

## Fixed service capabilities

All nine new public `jls_auth_*_v1` wrappers and their private implementations are `SECURITY INVOKER`. PUBLIC, anon and authenticated have no execute grant or private schema usage. The service role receives explicit underlying rights; it receives no new owner enrollment/update capability. New private tables use forced RLS and a service role policy. The private lock helper is typed and acquires locks only; there is no generic SQL/JSON command executor.

| Operation | Durable behavior |
| --- | --- |
| `issue_proof` | Stable issuance UUID, exact typed request binding and fingerprint; login/logout operation UUID; exact cookie presentation and current generation; mutation additionally requires current unrevoked owner session, credential validity and token/control/epoch fences |
| `begin_login` | Consumes exact login proof once, retains operation/request binding, snapshots the already enrolled active owner, stores distinct `pkce-v1` envelope before redirect, permits one live browser attempt |
| `callback_claim` | Browser/flow/attempt binding; one claim UUID; only the same worker can repeat a still-valid pre-send claim and receive the encrypted verifier; returns a fresh post-lock database `now` for candidate verification |
| `callback_mark_sent` | Persists transmission intent before network; only the first committed response grants `send_intent`; repeat/unknown outcomes require restart and never authorize retransmission |
| `callback_commit` | Rechecks verified subject against current prebound owner, control/epoch/generation, expiry and claim; rotates prior session, queues prior credential cleanup, creates unacknowledged session and encrypted credentials, increments generation once |
| `callback_resolve` | Reads exact attempt/claim/commit-operation/fingerprint result metadata; returns no raw bearer, hash, PKCE or credential envelope |
| `callback_close` | Explicitly closes a pre-send/failed/unknown attempt; after possible transmission queues independent candidate cleanup, including explicit `credential_unavailable` if tokens were lost |
| `candidate_cleanup_claim` | Attempt-keyed work independent of any app session or active owner; local scope only, 15-second lease, at most 3 distinct claim UUIDs within 1 hour; returns the encrypted cleanup capability to service role only; persists terminal `failed` on deadline/exhaustion and `skipped` if the identity is already used by a live app session |
| `candidate_cleanup_complete` | Exact unexpired claim CAS; bounded transport/timeout retries, persisted terminal completed/rejected/deadline/exhausted state; stale or reused claim IDs cannot complete another worker's claim |

SQL does not verify JWTs or perform encryption. The future trusted orchestration must verify the upstream candidate through the identity gateway, then pass the verified subject/upstream UUIDs and exact candidate envelope to commit/close. A request body cannot select a verified mode, owner grant or session identity. Cookie fingerprints likewise come from the exact parsed cookie on the server, not client-provided tags. Mutation proof issuance must follow actual owner/continuation verification; SQL independently rechecks current durable authority and versions.

## Ordering and recovery

Mutations acquire browser → controlled owner → sorted existing app sessions → proof/attempt locks, using database time sampled after relevant locks. Credentials are accessed after the session lock. Commit/close then acquire a namespaced transaction advisory lock for the candidate upstream-session UUID. Cleanup claim acquires that same identity lock before its work row and never acquires browser/session locks afterward. A live app-session identity makes cleanup terminal `skipped`, with no token capability returned. Any retained matching candidate cleanup record or prior app-session cleanup record prevents commit from adopting that upstream identity, including after cleanup completion/failure; a fresh upstream Auth session is required. The persisted cleanup state fences adoption after the transaction releases its advisory lock and the worker starts network work. Hash collisions only add serialization. All private routines set lock_timeout 250ms. No function makes a network call; caller transactions must finish before decrypt/network work.

Expired unsent attempts may be cancelled before starting a new attempt. An exchange with possible transmission remains live until explicitly closed; it cannot be stolen or resent by lease expiry. Logout can cancel an attempt while an upstream response is in flight; the late commit then fails generation/state checks and its candidate can still enter independent cleanup.

Commit input values, including candidate ID, new session ID/hash, token envelope, access expiry and fingerprint, must remain stable across retry. A lost commit ACK resolves by that exact operation. A `committed` result is historical metadata, including after later logout or delivery retirement; it is never fresh authority or an instruction to mint a replacement bearer. Current resulting-cookie verification or the existing `delivery_retire` CAS handles delivery recovery. A missing resulting bearer cannot be reconstructed from its stored hash. An acknowledged or newer session survives retirement of an older attempt.

Proof and operation fingerprints are opaque canonical request fingerprints produced by trusted orchestration. SQL additionally retains and compares the actual typed argument binding, so changing arguments while reusing a fingerprint cannot replay a mutation. Return bodies contain only stable metadata except the explicitly separate service-only PKCE and cleanup capabilities.

## Independent encrypted cleanup context

`candidate_cleanup_work` has no app-session foreign key and grants no owner authority. It retains environment, attempt UUID (also the cleanup work key), candidate UUID, candidate subject and upstream-session UUID. Its opaque envelope must use `orphan-v1`, separately from app-session `v1` and verifier `pkce-v1` envelopes. The decrypt context is:

```text
['japanese-learning-studio:oauth-orphan', 'v1', keyId,
 environment, attemptId, candidateId, authSubject, upstreamSessionId]
```

SQL validates bounded envelope shape and context presence only. AEAD authenticity and exact AAD binding require the dedicated server crypto helper; SQL does not perform that cryptographic verification. Shared tests also use the dedicated helper to round-trip real PKCE, app-session and orphan ciphertext through SQL and decrypt the returned exact context, including rejection of a changed candidate UUID. An unknown exchange whose process lost all returned tokens records `credential_unavailable`; it cannot invent credentials, fake an app session, or promise upstream cleanup succeeded.

## Evidence and remaining checks

On 2026-11-07, the exact two migration files were executed on in-memory PGlite 0.5.15 / PostgreSQL 18.6. All 31 shared SQL behavior cases passed. Tests cover issuance/operation/cookie binding, controlled owner, PKCE purpose separation, claim/send fencing and DB time, commit/resolve, generation and owner/epoch/expiry invalidation, rollback, prior-session rotation, logout cancellation, delivery CAS, real encrypted orphan context, lease/attempt/deadline terminal states, cross-attempt upstream cleanup fencing and role denial. This is sequential embedded SQL evidence, not native PostgreSQL 17 concurrency, WAL/crash durability, PostgREST or Supabase Auth evidence.

TDD evidence: before implementation, the first real SQL proof request failed because the wrapper did not exist in the frozen foundation. A later reuse-of-cleanup-claim test failed (`cleanup` instead of `denied`); persisting bounded claim history made it pass. Review-driven regressions for missing DB time, stranded deadline/exhaustion states and live/pending-cleanup identity collisions also failed against the prior implementation before fixes. Additional regression cases expanded the initial 15 cases to 31.

The new native fixture retains the existing CI-only execution guard and exact PostgreSQL 17 identity checks. It starts only on a fresh owned disposable database, loads both migrations from disk, and removes its explicit new wrapper signatures before inherited fixture cleanup. Reset/cleanup use the owned sentinel. Six additional native cases cover competing callback workers, actual browser/owner/session row contention, browser expiry crossed while awaiting credential lock and shared upstream advisory-lock contention. Their source is prepared; they have not executed locally. No native database was installed, connected or modified. The unchanged guard rejects an empty local execution environment before connection.

The ordinary Vitest suite passed 27 files / 624 tests at this preparation point; TypeScript no-emit and diff whitespace checks passed. The ordinary suite excludes native SQL tests. Fresh parent verification and security/source review remain required. Runtime transport, HTTP flows, refresh mutation, real nonproduction Google/Supabase tests, hosted configuration and human UAT/security/release approvals remain separate work.

References: [PostgreSQL 17 explicit locking](https://www.postgresql.org/docs/17/explicit-locking.html), [Supabase database functions](https://supabase.com/docs/guides/database/functions).
