# Auth refresh and session cleanup verification

The source-only migration is `20261111153831_auth_refresh.sql`, generated with Supabase CLI 3.0.0. It follows the Auth control and OAuth lifecycle migrations.

## Refresh contract

| RPC suffix | Durable behavior |
| --- | --- |
| `refresh_claim_v1` | Returns the encrypted pair only for the matching prepared holder. The lease lasts 25 seconds from the first claim. Another caller receives busy while a matching prepare or sent lease is live. An expired prepare can be replaced once its durable record proves there was no transmission intent. |
| `refresh_mark_sent_v1` | Authorizes a single upstream refresh when the first mark acknowledgement returns `transmit`. Duplicate marks return `already_sent`. An ambiguous mark acknowledgement gives the caller no permission to send. |
| `refresh_finish_v1` | Rechecks app identity, owner control, epoch, browser generation, session expiry, token version and lease. It checks the stored session UUID and subject against the managed Auth row and its `not_after`. It swaps the pair atomically and increments token version once. |
| `refresh_resolve_v1` | Reads historical finish receipts using the same typed arguments, operation UUID, fingerprint, expiry and digest of the encrypted pair. A receipt supplies no current authorization or credentials. |
| `refresh_close_v1` | Releases a demonstrably unsent prepare, settles a possible transmission as unknown, or retains a verified late pair using a separate operation UUID. The late pair is kept for retirement while the app session is live. |
| `session_cleanup_claim_v1` | Claims local-scope cleanup for a revoked session and returns the session-bound encrypted pair. The claim expires after 15 seconds or at the original one-hour deadline, whichever comes first. At most three claims can succeed. |
| `session_cleanup_complete_v1` | Accepts only the current claim UUID and revision within the lease. Late replacement advances the revision while preserving the original deadline, attempts and claim history. |

All seven public wrappers use the `jls_auth_` prefix and run with invoker rights and an empty search path. Only `service_role` receives execute access. The migration grants that existing role Auth schema usage and SELECT on `auth.sessions(id,user_id,not_after)`. It verifies the effective grants and existing BYPASSRLS attribute. The Auth existence check reads the transaction's visible row. Auth-side session deletion can race that read.

The browser, owner, app session, credential and attempt locks precede the refresh operation and shared upstream identity locks. Session cleanup acquires the shared upstream identity lock before the work row. Logout, delivery retirement and OAuth replacement move late-pair custody to session cleanup in the local revocation transaction. Upstream HTTP stays outside these transactions.

## Evidence

- The embedded smoke run passed 18 refresh cases and 31 existing OAuth lifecycle cases against the three migration sources on PGlite 0.5.15 (PostgreSQL 18.6, WebAssembly). It covered exact holder binding, repeated marks, pre-send expiry, possible transmission, receipt replays, managed-session denial, grants and local cleanup custody. The Auth fixture used a synthetic managed-owner table with RLS enabled, zero policies and a service role with BYPASSRLS.
- The native suite registers the same 18 cases and five multi-connection cases for concurrent claims, mark versus release, idle expiry while waiting on the identity lock, logout versus late arrival, and cleanup completion versus a new revision. The local invocation reached the existing guard before connection. Native execution requires the owned disposable PostgreSQL 17 CI service configured for `test:postgres`.
- Hosted Supabase validation remains pending. Before activation it needs evidence for the exact grants, actual Auth row deletion and expiry, PostgREST RPC behavior, and end-to-end request and settlement budgets. [Supabase session documentation](https://supabase.com/docs/guides/auth/sessions)
