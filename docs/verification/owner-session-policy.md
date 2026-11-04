# Owner-session and request policy preparation

Recorded 2026-11-04. This source-only Task3-A slice starts from published `9cd6c89`; it prepares deterministic authorization rules without connecting the sign-in page or adding runtime routes, a Supabase SDK, cookies, credentials or database changes.

## Prepared behavior

`evaluateOwnerSession()` consumes explicit trusted server snapshots. It requires a current active owner, matching authorized Auth subject and dataset owner, a nonrevoked session and valid timestamps. Missing or malformed authority cannot become an owner bootstrap. Email, user metadata and arbitrary extra fields neither grant access nor enter the output.

| Rule | Exact boundary |
| --- | --- |
| Idle lifetime | Expired at age greater than or equal to 24 hours |
| Absolute lifetime | Expired at age greater than or equal to seven days; activity cannot extend creation time |
| Destructive-operation reauthentication | Required age is strictly less than 15 minutes |
| Upstream credential recovery | Refresh/reauthentication/unavailable states grant no context; refresh cannot revive app-session expiry |
| Dataset assertion | Current epoch comes from the server snapshot; stale assertions are rejected, required missing assertions receive an internal missing-epoch decision |

Reauthentication is recorded independently from ordinary activity. It may be newer than last activity, but this record format requires it to fall between session creation and the supplied server time. A future adapter must construct that consistent format from verified events. The policy neither reads the clock nor updates activity.

The successful result has only four canonical UUID fields: `ownerId`, `authSubject`, `datasetEpoch`, `sessionId`. This is internal server context, not a public `/me` response. It does not establish how the facts were authenticated, fetched or made fresh.

`evaluateOwnerRequest()` derives mutation protection from the HTTP method. POST/PUT/PATCH/DELETE require an exactly matching configured Origin and a trusted, previously verified CSRF outcome bound to the same session UUID. A caller-provided claim that POST is read-only cannot change that decision. GET/HEAD/OPTIONS yield only a safe-method classification, never owner authorization. Unsupported methods fail closed.

Configured origins must be canonical HTTPS origins, without credentials, paths, queries, fragments, wildcards or implicit HTTP exceptions. This deliberately leaves the current disconnected HTTP demo unchanged; personal-auth local compatibility needs HTTPS or a separately reviewed explicit loopback design before route integration. Origin checks, successful policy decisions and a TypeScript interface do not verify CSRF, cookies or JWTs by themselves.

## Verified local evidence

- 128 focused policy cases across two files pass; the complete ordinary suite passes 329 cases across 16 files.
- Strict TypeScript, production build, API document/freshness and JavaScript config/script lint pass. Existing TypeScript/React lint limitations remain.
- Recovery verification first found a test-only union-spread TypeScript error. Explicit synthetic owner fields replaced the invalid spread; strict TypeScript and focused cases then passed. The interrupted worker left no completed implementation report, so an initial test-first RED history is not claimed here.
- An independent read-only code/security reviewer approved the four policy/test files without actionable findings. Parent executed the checks; reviewer approval does not replace owner security approval.
- Existing public/demo import-boundary tests remain active and pass. These policies are not imported by application routes. No new browser test or hosted CI run is claimed for this uncommitted slice.

## Remaining integration gates

Full Task3 is incomplete. Future work still needs explicit auth transport contracts, verified cookie/JWT/CSRF adapters, controlled Google-owner bootstrap, encrypted token storage, refresh locking and logout/rotation persistence, current-control revalidation, user-context clients/RPCs, actual RLS/Storage tests and approved hosted callbacks.

Do not implement a placeholder `requireOwnerSession()` around unverified request JSON or treat these pure functions as a runtime authentication guard. Later personal-route wiring must deliberately separate private entry graphs from public/demo coverage rather than disabling the existing boundary test. [ADR0004](../adr/0004-command-transaction-proof-boundary.md) retains the production RPC boundary; the test-only direct-pg fixture is not an application adapter.

This source needs owner diff approval before commit/push and CI. Merge, physical-device UAT, human security approval, hosted changes and release remain separate gates.
