# ADR 0004: Command transaction proof and runtime boundary

Status: **test-proof design prepared; production RPC direction unchanged; publication/CI approval pending**

Date: 2026-10-30

## Context

The TypeScript command executor requires authorization, locking, domain mutations, receipts and applicable outbox writes to share one open database transaction. Existing recording-port tests establish orchestration and schema behavior. A real database is needed to prove commit visibility, rollback, contention and reconnect replay.

The approved application architecture uses request-scoped user-context Supabase clients and narrow transactional invoker RPCs. A JavaScript callback cannot execute inside a remote RPC transaction. Several HTTP calls cannot hold the transaction promised by the current TypeScript port.

## Decision for this proof

Prepare a direct `pg` harness under `tests/postgres/` using only a positively identified, disposable CI database. Every transaction uses one checked-out connection. The driver is development-only; no application runtime repository, hosted migration, database credential or new public endpoint is introduced.

| Surface | Scope |
| --- | --- |
| TypeScript executor | Behavioral conformance target using existing fingerprints and closed receipt schemas |
| Disposable SQL | Synthetic controls, aggregates, proposals, receipts and outbox; owner/epoch constraints, restricted actor and RLS |
| Database suite | Finite correctness cases using explicit barriers and observed lock waits; separate from ordinary network-free tests |
| CI job | Optional standard Ubuntu/Postgres service, fixture-only values, no hosted secrets; activates only after the concrete diff is approved |
| Production | Existing user-context/RPC direction remains; no direct SQL application adapter is selected |

The harness locks and revalidates current authorization through commit before operation/aggregate locks. A non-key status/epoch change must conflict with that lock; `FOR KEY SHARE` alone is insufficient. Operation locks are transaction-scoped and supplemented by permanent full-identity uniqueness. A retained conflict commits its proposal and safe rejection receipt before Problem projection.

Known aborts require complete rollback. A failed commit acknowledgement is an unknown outcome resolved through the same operation identity on a fresh connection; the harness must not claim that it rolled back a transaction that may have committed. Uncertain connections are destroyed rather than returned to the pool.

## Production adapter gate

A production command-specific RPC must own the complete mutation, receipt and outbox transaction. Its BFF gateway can share the public contracts and behavior vectors, but cannot pretend to implement the callback port with separate requests. Fingerprint equivalence between Node and SQL requires reviewed vectors or an explicitly versioned encoding; `jsonb::text` is not assumed equivalent to the current policy.

Choosing direct pooled SQL for the application instead would require a separate reviewed ADR covering verified identity propagation, least-privilege connection roles, RLS, pooling and serverless operation. This test harness does not authorize that change.

## Evidence and limits

The execution flag and fixed endpoint guard prevent accidental use; an operator can forge an environment flag, so the flag is not an authorization mechanism. Database identity/sentinel checks precede fixture DDL. The command actor is tested without superuser/BYPASSRLS status. Synthetic transaction-local identity is not Supabase JWT verification.

Preparing or collecting the real-Postgres suite does not mean it has run. Its results must name the actual PostgreSQL version, exact source revision, test outcomes and remaining gaps. Reconnect replay is not a database crash/WAL recovery test. The fixture does not prove real note/session/grading logic, Auth/PostgREST integration, restore, outbox delivery, UAT or release readiness.

References: [node-postgres transactions](https://node-postgres.com/features/transactions), [pool lifecycle](https://node-postgres.com/apis/pool), [PostgreSQL17 locks](https://www.postgresql.org/docs/17/explicit-locking.html), [PostgreSQL17 RLS](https://www.postgresql.org/docs/17/ddl-rowsecurity.html).
