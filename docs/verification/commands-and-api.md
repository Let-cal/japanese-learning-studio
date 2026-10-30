# Local command and core API contract preparation

Recorded 2026-10-30. This local follow-up starts from `21fd47a`, the separately published foundation in draft PR2. Its CI results do not apply automatically to this follow-up.

## Implemented slice

- Versioned, server-derived SHA256 command fingerprint; deterministic object keys, original precondition binding and unmodified Japanese/Vietnamese body text.
- Immutable validated command snapshot; current owner/dataset authorization before receipt access, transaction-scoped operation locking and replay before stale domain preconditions.
- Closed per-command acknowledgement schemas for manual draft batches, repair creation/events, recheck decisions, job cancellation/retry, session events and note writes. Persisted data is lossless on replay and uses the exact domain schemas advertised by the API.
- Precise output types require a command-bound runtime validator; the base factory cannot promise arbitrary generic fields. Both newly produced and replayed outputs are checked. No answer bodies, note text, arbitrary URLs or provider payloads enter receipts.
- A retained conflict returns a committed safe rejection result; project Problem Details through the common registry only after the unit of work resolves. Exceptions still require rollback. This prevents a future handler from rolling back the proposal it just saved merely to return 409/412.
- Strict runtime DTOs for learning/execution, jobs, repair, disclosure, rechecks and note/manual receipts; public input fields cannot grant owner/dataset authority or claim trusted assistance.
- A generated, validated **12-operation OpenAPI 3.1 core slice**, with the remaining approved inventory explicitly listed as not yet specified. All operations are planned, not running routes.

The technical JSON-command envelope limits are 1 MiB encoded, 32 nested levels and 10,000 nodes. They bound command hashing, not binary photo transport or textbook-content policy. UUID identity metadata and acknowledgements use lowercase canonical spelling; arbitrary learner text is never case-folded or normalized by this layer. Individual domain input schemas must handle their declared ID fields before command dispatch.

## Validation and integration evidence

The coordinator observed **180 passing tests across 12 Vitest files**, strict TypeScript and API validation/freshness checks after integration fixes. JavaScript config/API-script lint is separate from the still-limited TypeScript/React lint coverage.

Test-first regressions cover changed-key payloads, replay before stale checks, revoked owner/epoch, safe acknowledgement fields, immutable inputs, per-kind generic output validation, codec transformations, retained-conflict replay and adapter mutation. Integration review found two real seams: conflict Problems failed the shared schema and domain receipts could not pass the original base acknowledgement vocabulary. All ten corresponding cases failed before shared registry/per-kind persistence corrections; they passed afterward. A further test ties every planned mutation's response-data schema to its persisted acknowledgement schema.

Independent API and code/security reviews approved the scoped fixes for local review. Those reviews are not owner security approval. The tests use recording ports to prove orchestration contracts; they are **not** Postgres durability or concurrency tests.

## Reproduce

Use the repository-pinned Node and pnpm toolchain:

```sh
pnpm test
pnpm api:check
pnpm lint
pnpm typecheck
pnpm build
```

`api:check` validates the actual artifact with external/file/HTTP references denied, then compares deterministic generation without overwriting. `api:generate` intentionally writes the artifact and must be followed by diff review. Source schemas use native [Zod JSON Schema conversion](https://zod.dev/json-schema); document validation uses [Swagger Parser](https://apidevtools.com/swagger-parser/). Exact pinned versions are in the root manifest/lockfile; strict 1440-minute maturity and ignored install scripts remain.

## Remaining gates

Task 2 is not complete. Real transaction-bound storage, uniqueness, restart replay, rollback/concurrency, outbox and domain-race proofs are pending. Runtime authentication/CSRF/RLS, authoritative disclosure checks, actual repair/recheck behavior and the rest of the API inventory remain separate work. No shared HTTP client or separately committed receipt can be called a transaction adapter.

No hosted write, API endpoint, migration apply, new CI run, merge, UAT acceptance or deployment follows from this local slice. Physical-device UAT, human security approval and release stay gated.
