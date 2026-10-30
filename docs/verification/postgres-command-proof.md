# Disposable Postgres command proof

Recorded 2026-10-31. Source preparation starts from `2ef48b9`; this document describes the new uncommitted follow-up, not the already successful checks on draft PR3. Publication and activation of the additional CI job require the owner's concrete diff approval.

## Evidence layers

| Layer | Observed result |
| --- | --- |
| Ordinary network-free suite | 201 tests across 14 files pass, including 17 fixture guard/transaction orchestration tests and four concurrency-cleanup regressions |
| Strict TypeScript, API artifact/freshness and JavaScript config/script lint | Pass; TypeScript/React lint coverage remains limited as previously documented |
| Frozen install, production build and advisory audit | Pass with ignored install scripts; no known vulnerabilities reported. This is not a full security/provenance/license audit |
| Real PostgreSQL suite discovery | P01–P20 source prepared, expanding to 28 cases; collection does not execute setup or SQL |
| Unflagged `test:postgres` | Expected exit 1 from the before-connect guard; the runner reports 28 skipped because setup failed. This is a guard check, not successful or intentionally skipped database proof |
| Actual PostgreSQL execution | **NOT RUN**; no database was installed, started or connected on the owner's computer, and no hosted database was changed |

Independent source/security and failure-handling reviews initially found undrained concurrent transactions and uncancellable PID polling on a failed assertion. Two regression assertions failed before the correction; all four cleanup tests then passed. All seven concurrent test templates now register tasks/barriers, release barriers and drain started transactions before returning, preserve distinct errors, and use finite signals that react to early setup failure. Scoped re-reviews approved the correction for source review; that is not owner security signoff.

## Prepared correctness cases

| Cases | Intended real-Postgres assertion |
| --- | --- |
| P01–P05 | Atomic visibility; pool reconnect replay; permanent key identity; same-key contention and changed-input rejection |
| P06–P11 | Retained conflict/proposal replay; rollback after each write stage; unsafe acknowledgement and corrupt receipt rejection |
| P12–P14 | Restricted role/grants/forced RLS/composite ownership; missing/wrong/revoked subject; old epoch and both authorization race orders |
| P15–P16 | Aggregate serialization and synthetic answer/finish closure in both orders |
| P17–P20 | Lock-timeout cleanup; simulated lost acknowledgement after actual COMMIT; pooled identity reset; Japanese/Vietnamese/UUID/safe-version roundtrips |

Two controlled operations with barriers and observed database lock state are finite correctness tests. They are not load/stress tests. P02 reconnects the application pool; it does not crash/recover the database. P16 is a synthetic invariant, not product session/grading proof. P18 simulates acknowledgement loss after COMMIT, not a real transport fault or database crash.

## Fixed execution boundary

The dedicated command is `pnpm test:postgres`, separate from `pnpm test`. It requires **both** `JLS_COMMAND_PROOF=owned-disposable` and `GITHUB_ACTIONS=true` before constructing a pool. Do not set these flags on a developer computer merely to bypass the guard.

Only loopback `127.0.0.1:5433`, database `jls_command_fixture` and user `command_fixture_admin` are accepted. The fixed password is disposable fixture data, not a hosted credential. Inherited DSNs, connection credentials, SSL settings and libpq options are not used. Server identity/Postgres17 and a fresh empty database are required before setup; reset/drop require the fixture sentinel. A forged flag is not security authorization.

Setup/inspection use the fixture admin. Commands use a separate nonowner, non-login, non-superuser role without BYPASSRLS and transaction-local synthetic identity. Tables enforce RLS, including FORCE RLS, and owner/dataset composite foreign keys. Synthetic identity does not establish Supabase JWT verification. Authorization control locks, operation locks, aggregate writes, receipts and outbox share one checked-out client transaction.

The proposed optional `command-postgres` CI job runs after `public-sample` on standard Ubuntu, with a digest-pinned Postgres17.11 service, fixture-only values, a 15-minute job deadline and the existing pinned toolchain. It adds no hosted secrets, artifact uploads, deploy steps or required-branch checks. Fixture limits include connection5s, ordinary lock3s, statement5s, transaction10s and test30s; these are not product capacity or availability promises.

## Remaining product gates

The direct `pg` code is **test-only**. The approved request-scoped user-context Supabase/invoker-RPC direction remains unchanged; see [ADR0004](../adr/0004-command-transaction-proof-boundary.md). An HTTP RPC cannot execute the TypeScript callback, and multiple requests do not implement one transaction. A future product-specific RPC gateway needs reviewed mutation/fingerprint/authorization equivalence.

No runtime endpoint, hosted migration, actual auth integration, outbox dispatcher, restore implementation or full Task2 completion is established. Real SQL results must be recorded at the exact published revision after approved CI execution. Merge, physical-device UAT, owner security approval and release remain separate gates.
