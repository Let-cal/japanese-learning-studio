# Current owner session verification

The server composition connects the repeated Google callback to current owner verification. It also exposes the verifier for subsequent owner route work. The Next.js Auth operations remain unmounted.

The verifier checks the cookie pair against the current browser generation, app session, owner and dataset before loading credentials. It decrypts the exact session envelope, verifies the stored bearer at Supabase Auth and compares the verified subject, upstream session and expiry. The final control RPC checks the same token version, owner control version, dataset epoch and identity before recording delivery. Access and refresh tokens stay server-side. A confirmed callback with the existing session cookie redirects without reissuing it.

The additive migration preserves the existing confirmation RPC and grants. After locking the app state and the cooperating upstream identity, it reads the exact managed session by ID and subject, checks its deadline, and rechecks browser, access, idle and absolute expiry. This preserves the first delivery timestamp and the last activity time. Supabase Auth can remove the managed row after the read, so private-data authorization still requires its own RLS and mutation checks. [Supabase session documentation](https://supabase.com/docs/guides/auth/sessions#how-to-ensure-an-access-token-jwt-cannot-be-used-after-a-user-signs-out)

Ordinary access-token expiry yields a refresh-needed result. In-progress or ambiguous verification grants no context. In the callback adapter, refresh-needed and temporary unavailability map to 503. Confirmed refusal maps to restart. A callback replay with an exact cookie can discover the current epoch at verification time. Its redirect carries no private data or token. Any epoch or control version change after the verifier reads its snapshot must pass the final SQL fence for the examined version.

## Verification

- 772 local application tests, including 21 owner-session tests, passed on Node 24.22.1. Tests cover identity/expiry, bound decryption, transport key separation, abort and callback status mapping. TypeScript, the OpenAPI check and production build passed.
- All 90 embedded SQL cases passed across six migrations. Five confirmation cases cover wrong, missing, deleted and expired managed sessions, acknowledgement and privilege checks. A separate synthetic HTTP-to-SQL case exercised callback replay through the local verifier before and after the managed row was added and removed.
- The disposable PostgreSQL 17 suite registers six additional cases, including lock contention with idle expiry. Native execution awaits CI.

Before activation, connect refresh orchestration, request-scoped user-JWT repositories and RLS, finish Auth route wiring and verify real Google/Supabase behavior on Development.
