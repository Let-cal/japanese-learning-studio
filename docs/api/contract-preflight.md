# Task 2 API implementation preflight

Prepared 2026-10-30 against approved M1 design v1.0. This is an implementation checklist, not a running API, validated OpenAPI document or completed Task 2.

## Binding command rules

1. Authorize the current verified owner and active dataset epoch before looking up any command receipt.
2. Validate and canonicalize semantic command input on the server. The hash includes command kind, target and effect-defining revision references; it excludes incidental request IDs and timing. Define the expected-version hash policy once before implementation.
3. Look up persisted `(owner, dataset, operationId)`. Identical committed input returns the original safe acknowledgement before stale ETag or current domain-state checks. Different input with the same identity returns `409 idempotency_key_reused`. Old epochs never gain authority through replay.
4. For a new operation, validate preconditions and run the handler, domain uniqueness checks, receipt and outbox in one database transaction. Provider calls run outside database locks.
5. Receipts contain acknowledgement IDs/versions and safe data. Protected answer keys, notes, comparisons and media require fresh disclosure authorization; a reusable receipt must not bypass an unfinished Test.

`executeCommand(context, payload, handler)` must use a transaction-bound repository/unit of work. A process-local Map, independently committed receipt or mocked repository cannot demonstrate durable exactly-once effects. The database transaction and unique constraints establish the behavior; the function signature alone does not.

## Transport baseline

- `/api/v1`, OpenAPI 3.1, camelCase JSON, opaque UUID identifiers, UTC instants and explicit IANA timezones.
- Success envelope: `data`, `meta.requestId`, `meta.datasetEpoch`; lists also carry `nextCursor`.
- `201` plus Location for creation; `202` plus job Location for durable work; bodyless `204` where specified.
- Strong resource ETags and If-Match represent mutable resource versions, separately from immutable item/source/grade revision IDs.
- Problem media type: `application/problem+json`; `type`, `title`, `status`, `detail`, `code`, `requestId`, optional field errors/currentVersion/conflictId.
- Status classes: malformed 400, unsigned 401, non-owner 403, absent/inaccessible 404, transition/key conflict 409, stale version 412, invalid domain fields 422, missing precondition 428, limit 429, temporary unavailability 503.
- Fixed codes include `idempotency_key_reused`, `test_reference_locked`, `session_closed`; use 409 for `repair_origin_affected`. Publish remaining codes once in Task 2 schemas.

## Additions that must be settled before consumers

| Family | Contract and precondition |
| --- | --- |
| Manual intake | Pure preview validates 1–10 stable clientRowId rows; create confirmed rows atomically through POST `/manual-draft-batches`, Idempotency-Key and lesson base version. Explicit manual/image provenance; no learning evidence |
| Disclosure | Server resolves protected targets across every unfinished Test, including paused sessions. Caller omission of sessionId is not permission. Apply to detail/search/notes/Issues/results/media/export, not only the execution screen |
| Repair start | POST `/guided-repairs`, Idempotency-Key and origin item/source/grade revisions in body; no repair execution ETag exists at creation |
| Repair events | GET `/guided-repairs/{id}`; POST `/guided-repairs/{id}/events` uses the repair ETag. Origin Test identity/version never substitutes for repair execution state |
| Memory note | GET/PUT `/vocabulary-items/{id}/memory-note`; PUT uses Idempotency-Key and note ETag. Absent note GET has an empty version-0 representation without a write; version-0 PUT is atomic create-if-absent. Empty body clears cue with history retained; 2,000 Unicode code-point bound |
| Recheck | Required domain port retains distinct origin intents, projects one active item/ability task using earliest accepted not-before, and preserves separate FSRS due dates. A bounded additive POST `/targeted-recheck-decisions` is a transport recommendation, not an already implemented endpoint |

A finished origin Test may be referenced by a separately created repair; this never reopens the Test. Merely viewing repair steps cannot create independent recall, XP or schedule extension. Changed relevant origin revisions suspend acceptance with history retained.

Current-question help must persist assistance/mode/condition changes before reference release. Other independent Test targets remain protected. Finish and answer serialize on execution version; historical pending grades can resolve without reopening execution.

Where a stale edit must retain a conflict proposal, commit the proposal without changing canonical content and then return the problem response. Throwing inside an automatically rolled-back transaction must not erase that proposal.

## Proof by layer

| Pure contracts/domain | Owned disposable PostgreSQL integration |
| --- | --- |
| DTO discriminators and rejected extra/protected fields | Concurrent identical and different-payload idempotency keys |
| Manual limits, row identity and provenance | Replay after repository/process recreation |
| ETag parsing and note-v0 representation | Domain mutation/receipt/outbox rollback as one transaction |
| Canonical semantic hash equivalence and differences | Receipt replay before stale ETag/session-closed rejection |
| Problem/status registry and OpenAPI reference validation | Note-v0 create races and retained conflict proposals |
| Recheck projection preserves origins and independent FSRS due | Answer versus Finish; assistance-before-disclosure; repair-origin revision race |
| Safe receipt DTOs contain no reusable answer keys | Epoch switch versus stale writes; domain uniqueness and outbox durability |

These tests are not authorized against production or unrelated customer environments. No hosted migration/configuration follows from this document. Task 2 remains incomplete until executable schemas/OpenAPI and transaction integration pass their owning checks and review.
