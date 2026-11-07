# Durable Auth control store: source verification

Status: source preparation for the first durable-store unit, 2026-11-06. This is **not a usable login integration**. No owner is enrolled by the migration. No hosted SQL, configuration, managed Auth table, key or actual identity is changed.

## Scope and boundary

The migration `20261106155504_auth_control.sql` was created as an empty file by the pinned official CLI through `migration new auth_control`, after reading the command's help. Its SQL is now reviewable source. The `jls_auth` schema must remain outside PostgREST's exposed schemas; the migration does not change API exposure settings.

Nine private tables separate owner control, datasets, browser generation, app sessions, encrypted session credentials, CSRF proofs, OAuth attempts, action receipts and local-scope cleanup work. There are no initial rows. Controlled operator enrollment and all runtime creation operations remain future work. Dataset replacement/export must exclude these tables and credential/key material.

Every table has forced RLS. No anon/authenticated policy or table/schema capability is granted. Public wrappers and private implementations are security invoker functions with an empty search path; EXECUTE is revoked from PUBLIC/anon/authenticated and explicitly granted only to service_role in the same transaction. service_role receives enumerated SELECT, necessary column UPDATE, and receipt/cleanup INSERT capabilities. There is no owner enrollment, token replacement, blanket table write, managed `auth.sessions` grant or query. The approved server secret still has broad platform privileges; fixed RPC names do not narrow that credential itself.

## Fixed capabilities

| Public RPC | Inputs and result | Meaning |
| --- | --- | --- |
| `jls_auth_session_lookup_v1` | Session secret hash; exact existing `SessionLookupMetadata` DTO | Frozen metadata contract only. Never includes envelopes, versions or secret hashes. |
| `jls_auth_session_snapshot_v1` | Session and browser hashes; safe session/owner/browser/credential snapshot | Discovers actual control/token/generation versions, delivery state and exact durable refresh state. No zero-version fallback and no envelope/hash disclosure. This read is not authorization. |
| `jls_auth_current_credentials_v1` | Session/browser hashes and expected token version, control version, dataset epoch | Locks/rechecks active owner, subject, current dataset, current browser/session/generation, app lifetime and usable unexpired credentials before returning the encrypted envelope with its bound identity and authoritative DB `now`. |
| `jls_auth_confirm_session_v1` | Same CAS inputs plus independently verified subject and upstream session UUID | Rechecks after upstream verification and acknowledges cookie possession, returning fresh safe owner context and versions. No credential envelope in its response. |
| `jls_auth_delivery_ack_v1` | Session/browser hashes and expected token version | Delivery bookkeeping only; this is not verified-user authorization. It does not extend idle time. |
| `jls_auth_delivery_retire_v1` | Browser hash, completed attempt UUID, resulting session UUID and expected resulting generation | Retires only the exact unacknowledged session with CAS. Exact retained retries return `already_retired`; acknowledged delivery or a newer browser generation/session is denied. |
| `jls_auth_logout_v1` | Browser/proof hashes, stable operation UUID and exact cookie presentation fingerprint | Atomically verifies proof, revokes the matched session, fences generation, cancels pending/claimed/unknown OAuth work, invalidates refresh state/version, enqueues cleanup and stores the receipt. |

All timestamps are integer Unix milliseconds in JSON and originate in the database. No RPC accepts browser time. App expiry is 24 hours idle and seven days absolute, with equality expired. `/me`, snapshot, credential lookup, confirmation and delivery acknowledgement never update `last_activity_at` or recent reauthentication.

The intended orchestration is snapshot → closed policy checks → credential read with snapshot CAS values → decrypt and independent upstream identity verification using the returned DB time → confirm with the original CAS values and verified subject/session. A missing/unavailable snapshot cannot be treated as version zero. The returned context has request-time freshness; domain command authorization must still lock and revalidate through its own transaction commit. No domain integration is provided by this migration.

All control updates, including future owner activation/epoch/rebinding changes, must increment the control version atomically when they invalidate an in-flight authorization snapshot. The first unit supplies no such mutation/enrollment RPC. Owner reconfiguration procedures still need their own reviewed, tested implementation.

## Proof, receipt and delivery invariants

Auth-action secrets remain purpose separated in the server crypto layer. SQL stores only their hashes. Cookie fingerprints exactly match `fingerprintSessionCookie`: explicit `absent`, or `present:` plus 64 lowercase hexadecimal characters. This fingerprints the bounded exact parsed cookie value, including malformed values; it is distinct from a valid session secret hash. A fingerprint alone never authenticates a session. Future proof issuance must resolve and validate the presented session before storing the proof's target.

Logout accepts an expired/revoked session and inactive owner when its browser-bound proof is valid. Owner authorization is never a prerequisite for revocation, and its absence never bypasses CSRF. Anonymous logout requires a proof explicitly bound to absence and no current session. Pending activation is cancelled under the held browser lock before the same transaction commits its generation fence. An old proof cannot revoke or instruct clearing a newer session.

A committed receipt retains original proof/operation identity, exact fingerprint, before/after generation, target and outcome. Identical old-cookie retries and cleared-cookie absence retries are accepted only for that receipt and unchanged resulting browser generation with no current session. They return the original outcome without another generation increment. A valid retained receipt may outlive the proof's issuance TTL; an expired proof without such a receipt fails closed. Unknown COMMIT acknowledgement must be resolved by repeating the same operation identity; unconfirmed outcome remains unavailable, not fabricated success.

Retirement has a separate CAS retry result bound to the exact attempt/session and before/after browser generations. It never retires acknowledged delivery. A successful independently verified request may acknowledge delivery; sending Set-Cookie alone is not acknowledgement. Browser response reordering can still clear a later cookie; SQL prevents restored authority but cannot serialize delivery of already-sent bytes.

Upstream session UUID uniqueness is partial over nonrevoked app sessions, so revocation history does not prevent a later valid app-session rotation. Composite foreign keys bind owner/subject, session/browser/generation, proof/receipt and completed OAuth result. Encrypted upstream envelopes and `pkce-v1` envelopes have different format/size checks. SQL checks shape only; authenticated decryption and context binding remain the crypto layer's responsibility.

## Locking and deadlines

Mutating/current-credential routines lock browser → owner → relevant app sessions in UUID order → proof/attempt/receipt records. Credentials are accessed under their session lock; receipt rows are immutable and the held browser lock serializes receipt creation/replay. Provider/network calls must occur outside all database transactions. This unit targets one session per operation; future multi-session callback rotation must preserve the sorted session order.

Private functions set a 250 ms lock timeout, including lock acquisition within credential/current-state checks. This bounds an individual contended lock attempt; it is not an overall transaction/request deadline. No claim is made that setting `statement_timeout` inside an executing function would cap the already-running outer request. The future service must supply its end-to-end deadline, configure a real connection/request statement budget and retain unknown-commit resolution. A client abort does not prove database rollback or provider cancellation.

## Tests and actual evidence

Tests were written before filling the CLI-generated empty migration. `pnpm exec vitest list --config vitest.postgres.config.ts tests/postgres/auth-control-postgres.test.ts` succeeds and discovers the real-SQL cases. `pnpm exec tsc --noEmit` and `git diff --check` succeed. Discovery/type checking do not execute or validate PostgreSQL SQL semantics.

**Native PostgreSQL 17 RED/GREEN: NOT RUN.** No approved native disposable server is available in this local session. The existing guard remains unchanged: it requires both `JLS_COMMAND_PROOF=owned-disposable` and `GITHUB_ACTIONS=true` before constructing a pool, plus the fixed loopback service/database/user and PostgreSQL 17 identity. No native database service was installed or started and no guard was bypassed. Do not count unexecuted cases as passes or claim a completed native TDD cycle.

Separate local smoke: an ignored development tool using PGlite 0.5.15 reported PostgreSQL 18.6 on WASM. Twelve single-connection checks passed against migration SHA256 `1abef18ad8961280f0a063d7114c06fd0d37544bf25397d75b04c2fa4ee4ab1e`: actual DDL, invoker metadata without an envelope, version-bound credential read and stale denial, safe version discovery, stale-control confirmation denial, successful confirmation without idle extension, injected mid-logout constraint failure with rollback, committed logout, receipt retry without another generation increment, post-logout denial and authenticated execution denial. This is not the target PostgreSQL 17 engine or native multi-connection evidence. The tool is absent from application dependencies, runtime and CI; it creates only an in-memory synthetic database and closes it after each run. [PGlite documentation](https://pglite.dev/docs/).

Independent source review found and resolved missing version discovery, post-network control fencing, retirement retry resolution and lock deadlines. A second review caught browser expiry crossing the credential lock; the final guard rechecks fresh DB time after that lock, and A20 prepares the native regression. Review approval covers this bounded draft source only.

The auth fixture uses the same serial suite configuration as the existing command proof. Both require a fresh empty service and remove only their own fixtures before the next suite. Auth setup verifies identity and freshness, creates synthetic NOLOGIN/NOSUPERUSER/NOBYPASSRLS roles, and executes the actual migration DDL within a single fixture transaction after removing only its verified outer BEGIN/COMMIT framing. Reset/cleanup recheck the fixture marker, fixed database identity and owned synthetic role flags. Teardown drops the enumerated public wrappers, the two fixture-owned schemas and only roles created after the fresh-service check; no unrelated reset, DROP OWNED or existing role replacement occurs.

Prepared native cases cover the closed metadata DTO, role/grant/RLS denial, owner/subject binding, nonzero versions and exact refresh state, app/access expiry before credentials, delivery acknowledgement/retirement, post-network confirmation, expired/anonymous logout, receipt retries, generation fencing, partial uniqueness, atomic rollback, concurrent repeated logout, bounded lock contention and observed native browser-row lock competition among acknowledgement/retirement/logout. These remain pending execution in the guarded disposable PostgreSQL 17 service. Any separate embedded-engine smoke evidence must identify that engine/version and cannot substitute for native concurrency or Supabase evidence.

## Explicit remaining integration

- Browser/proof creation and OAuth claim/exchange/commit mutation RPCs, including one-use claims, generation increment on successful login, competing callbacks and unknown exchange outcome closure. The partial outstanding-attempt index currently covers pending/claimed; `exchange_unknown` must be closed without blindly resending a one-use exchange, and its relationship to a fresh attempt must be settled in the complete state machine before activation.
- Durable refresh claim/prepared/transmission-intent/completion CAS and uncertain-outcome recovery. Tables represent these states, but no refresh worker may send or retry a rotating token based solely on these table definitions.
- Candidate/orphan upstream cleanup before an app session exists. `cleanup_work` deliberately represents existing app sessions only and requires their FK. A rejected candidate must not be represented by a fabricated app session; its independent durable cleanup model is required before callback activation.
- Cleanup claim/retry/deadline execution, encrypted credential retention/purge and receipt/proof/browser expiration maintenance. Current constraints bound cleanup to local scope, three attempts and a one-hour deadline, but no worker is installed.
- Fixed runtime gateway decoders for the new capabilities, strict routes, HTTPS browser fixtures, current-state domain authorization and actual Auth/PostgREST/Storage role tests.
- Reviewed enrollment/configuration, exact approved nonproduction origins/callbacks/owner identity, server key names/rotation, confirmed USD0 eligibility and separate hosted-change, security, UAT and release gates.

Official references checked while preparing this source: [function execution and permissions](https://supabase.com/docs/guides/database/functions), [RLS and grants](https://supabase.com/docs/guides/database/postgres/row-level-security), and the [Supabase changelog](https://supabase.com/changelog).
