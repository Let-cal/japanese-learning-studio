# Request-local upstream identity verification

## Scope and trust boundary

This prepares the next Task3 server adapter, separate from the published sample Practice. It does not wire Google sign-in, `/me`, session persistence, refresh, owner bootstrap or SQL. No production keys or live Auth requests are used by its tests.

For the supported native Supabase token profile, the adapter sends the **exact unchanged access token** to the configured project's `GET /auth/v1/user`. Successful Auth-server verification supplies token integrity; local JWT decoding alone supplies no authentication. In continuation verification, a valid returned user ID must match both the token subject and the independently stored expected subject. The token's upstream session ID must match the stored expected upstream session.

Initial callback verification is a separate capability with a distinct `verified_candidate` result. It binds the returned Auth user to the token subject and validates the token's session claim without pretending that a database session binding already exists. The future callback must still compare that candidate with the operator-approved owner and current browser generation before committing an app session. A valid upstream candidate, including one belonging to another user, grants no app access. Requests cannot select a mode to downgrade continuation checks.

Only a publishable API key accompanies that user's bearer. The adapter has no control secret or fallback to a privileged client. Owner authorization, app-session expiry and current dataset checks remain separate. A verified upstream identity is not an authorized app-owner context.

## Supported protocol

- Fixed configured canonical HTTPS Supabase project origin, fixed `/auth/v1/user`, no redirects, no browser cookies, no forwarded request headers and no persistent Auth client state.
- Fixed `X-Supabase-Api-Version: 2024-01-01` header. The official Auth source maps that profile to the `code`/`message` error response. A generic HTTP401 is ambiguous and must not silently become an invalid-user result.
- After successful Auth verification, enforce the expected subject/session UUID, issuer, authenticated audience/role, nonanonymous state and token lifetime. Ignore provider-added user metadata and never retain email or identities.
- Bound token input, strict UTF-8 response parsing and response byte limits; one total deadline covering fetch and body; no automatic refresh or retry. Sanitized results exclude the token, API key, upstream body and raw exception.

Authoritative database time must be fresh within the same request; monotonic elapsed time accounts for verification duration. This does not make an arbitrarily old lookup snapshot safe. Future composition must bound snapshot age and perform current-state checks after network work before granting access or committing mutations.

## Evidence required before activation

Fake-transport tests exercise local protocol behavior, not cryptographic verification or actual project compatibility. Actual Auth/PostgREST verification, credential-read SQL with current session/token-version binding, encryption-key configuration and app-session/owner/dataset checks remain required. No hosted configuration, SQL, secret provisioning or release is approved by source preparation.

Primary references: [getUser](https://supabase.com/docs/reference/javascript/auth-getuser), [JWT verification](https://supabase.com/docs/guides/auth/jwts), [Auth error codes](https://supabase.com/docs/guides/auth/debugging/error-codes), [Auth API-version source](https://github.com/supabase/auth/blob/master/internal/api/apiversions.go), [Auth error serialization](https://github.com/supabase/auth/blob/master/internal/api/errors.go). Read on 2026-11-05; hosted compatibility remains unverified.

## Local verification — 2026-11-06

The final focused suite passed 78 tests: the 70 continuation/transport cases plus eight initial-candidate cases. The worker observed behavioral failures before implementation, then verified a new fractional not-before boundary regression RED-to-GREEN: expiry checks round elapsed time up conservatively; not-before checks round down so a token cannot become valid a fraction of a millisecond early. The candidate scaffold initially produced seven failures and 71 passes, followed by 78 passes with the shared implementation.

The parent independently ran the complete ordinary suite: **540 tests / 22 files passed**, followed by strict TypeScript and a production build. Independent read-only security review approved both the continuation implementation and the scoped candidate refactor, and independently reran all 78 focused tests. This does not satisfy human security acceptance. The existing public/demo/status route inventory is unchanged; this adapter is not yet connected to a route. No browser rerun, live Auth or personal-data persistence result is implied.

Fixtures contain fabricated compact JWS strings and injected transport/clock behavior. The tests prove the local protocol and binding rules, not real signature verification by the provider. Fresh database snapshot composition, actual project compatibility, SQL/RLS, Google login and human acceptance remain open.
