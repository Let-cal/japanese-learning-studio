# Planned Auth HTTP contract

The six operations in the generated OpenAPI document remain `planned` until the Task 3 Auth routes are mounted and verified. Local source and synthetic evidence for login and recovery are recorded in [Google OAuth application wiring](../verification/google-oauth-application.md) and [Google OAuth recovery](../verification/google-oauth-recovery.md). See [ADR 0006](../adr/0006-runtime-auth-control-plane.md) for the proposed runtime integration and [the decision record](../verification/auth-session-lookup.md) for the accepted privilege boundary and later acceptance gates.

## Operations and prerequisites

All paths use `/api/v1`. All POSTs require the exact configured HTTPS `Origin`; missing, mismatched or untrusted origins are forbidden. No Auth operation accepts domain `Idempotency-Key`, `If-Match` or client `X-Dataset-Epoch` as a prerequisite. Ordinary unrelated browser headers and cookies are allowed. A future raw-cookie parser must reject duplicate relevant cookie names before constructing a cookie object.

| Operation | Request | Additional authorization | Success |
| --- | --- | --- | --- |
| `POST /auth/csrf` | Strict JSON `{purpose: "login" \| "logout" \| "mutation"}` | No prior proof; mutation purpose additionally needs a valid owner session | 200, strict `{data:{purpose,token,expiresAt},meta:{requestId}}` |
| `POST /auth/login` | Strict `application/x-www-form-urlencoded` body `{csrfToken}`; at most 256 raw bytes | Mandatory login-purpose form-body proof **and** browser-binding cookie | 303, no response body; native top-level navigation to the exact approved Supabase authorize URL selected from server-only configuration |
| `POST /auth/recover` | Strict `application/x-www-form-urlencoded` body `{csrfToken}`; at most 256 raw bytes; no query | Browser-binding and OAuth-attempt cookies plus a recovery proof bound to that exact flow | 204, no response body or cookie writes |
| `GET /auth/callback` | No body; closed callback query below | OAuth-attempt cookie **and** browser-binding cookie | 303, no response body; fixed `Location: /today` (canonical S02) |
| `POST /auth/logout` | Exactly zero raw body bytes | Logout-purpose Auth-action proof **and** browser-binding cookie | 204, no response body, after confirmed local revocation/absence |
| `GET /me` | No body | Server-verified owner session | 200, strict `{data:{authenticated:true},meta:{requestId,datasetEpoch}}` |

Logout and callback OpenAPI AND requirements share one security-requirement object. Login has `security: [{BrowserBinding: []}]` plus its required form-body proof; `x-auth-proof` records `in: body`, `name: csrfToken`, `purpose: login` and authoritative body selection. OpenAPI cannot express a body field as an API-key security scheme. CSRF issuance has `security: []` with a separate `x-auth-purpose-authorizations` extension for the mutation-purpose owner-session condition. This describes required future checks; it does not claim a verifier exists. The global authorization-order extension applies only to domain operations.

Logout `requestBody` is omitted intentionally. `{}`, `null`, a JSON string, a newline and other whitespace are nonempty bodies and must be rejected as `malformed_request`. GET request bodies are forbidden. `x-body-byte-length: 0` records this raw-byte contract; OpenAPI cannot enforce it and future handlers must inspect raw bytes before JSON parsing. There is no empty-object DTO standing in for an empty body.

Login instead uses a native top-level HTML form (`method=post`, `enctype=application/x-www-form-urlencoded`) so its 303 performs browser navigation to the external authorization origin. A native form cannot supply `X-CSRF-Token`; a fetch redirect does not navigate the top-level page. The only authoritative login proof is its mandatory `csrfToken` form field, with no header alternative or fallback. No login JSON body, empty body, `returnTo`, provider selection or owner assertion is accepted. The proof may be held in a hidden field of the same-origin sign-in HTML body; it must never enter a URL, browser storage or logs. The binding cookie remains HttpOnly.

`AuthLoginForm` is a closed Zod object. `parseAuthLoginForm(URLSearchParams)` validates exactly one decoded field named `csrfToken`, rejecting duplicate names (including encoded equivalents), unknown fields and noncanonical tokens before constructing the object. It returns a fixed sanitized validation error without input values. Future handlers separately enforce the actual content type and a maximum of 256 raw request-body bytes before decoding; `x-max-body-bytes: 256` records that requirement. Reserializing decoded entries cannot prove the original raw-byte bound.

Login/logout proof issuance does not require an active owner/session/dataset. Mutation-purpose issuance does. Proofs bind purpose, browser generation and the exact presented session-cookie fingerprint or explicit absence. Bounded malformed presented session-cookie text remains fingerprintable without becoming an authorized session. A logout proof and its retained receipt preserve stable operation identity and before/after generations: retry never increments twice, and an old proof cannot revoke or clear a newer session. No sentinel owner session or domain command identity is manufactured.

## Recover an interrupted Google login

The server can issue a short-lived recovery proof for the exact current flow while rendering a private, same-origin form. It shares the login proof wire syntax. Its hash is domain-separated from ordinary login proofs, and the persisted issuance fingerprint also binds the exact flow. Public `/auth/csrf` keeps its existing purposes and does not issue recovery proofs. The recovery form uses the same bounded URL-encoded parser as login. The request must match the session-cookie presentation bound at issuance, including explicit absence.

Submit recovery through same-origin fetch and keep the existing proof while confirming an uncertain response. The server acknowledges only the exact locked transition or an exact receipt replay. On 204, reload sign-in state and obtain a fresh ordinary login proof. A 503 can mean that an attempt is still processing or that recovery could not be confirmed. Recovery responses carry no cookie instructions, including after retry or denial.

A new ordinary login can settle an expired possibly-sent attempt after verifying its own fresh proof. This allows recovery when the old flow cookie expired or was lost. A fresh login must verify its new Google identity before replacing any existing app session. Callback replay and provider denial do not initiate recovery.

## Strict payloads and syntax-only secrets

`AuthCsrfBody`, `AuthLoginForm`, `AuthCsrfSuccess` and `MeSuccess` are closed Zod objects at every level. Request IDs and the discovered dataset epoch use the existing UUID schema. `expiresAt` reuses the existing UTC-instant schema. No owner/session/Auth-subject IDs, email, access/refresh tokens, provider URLs or client-supplied verification claims are accepted in these DTOs. `/me` discovers the current epoch without a client epoch assertion and does not extend idle lifetime.

| Purpose | Exact wire syntax | Location |
| --- | --- | --- |
| Auth-action CSRF proof | `jls-csrf-v1.` followed by canonical base64url of 32 bytes | Login form `csrfToken`; logout `X-CSRF-Token`; issuance response `data.token` |
| Browser binding | `jls-browser-v1.` followed by canonical base64url of 32 bytes | `__Host-jls-browser` cookie |
| OAuth attempt | `jls-oauth-v1.` followed by canonical base64url of 32 bytes | `__Host-jls-oauth` cookie |

The suffix is exactly 43 characters: the first 42 are `[A-Za-z0-9_-]` and the final character is `[AEIMQUYcgkosw048]`. Padding and noncanonical unused bits are forbidden. These schemas verify syntax only, using no Node `Buffer`; they do not generate secrets or verify hashes, expiry, binding, purpose, receipts, owner identity or database state. The existing bare 43-character app-session secret format is unchanged. A browser-binding or OAuth-attempt value cannot substitute for a CSRF token.

## Callback query and redirects

The complete decoded query is exactly one of these closed objects:

- `{code: string}` with length 1–2048.
- `{error: string, error_code?: string, error_description?: string}` with error/error-code lengths 1–128 and description length 0–2048.

All fields reject C0/C1 controls, including DEL. Reject unknown names, mixed branches and duplicate decoded names before object construction, including identical duplicate values. `parseAuthCallbackQuery(URLSearchParams)` inspects multiplicity first, validates the closed schema and returns a fixed sanitized validation error on failure. `URLSearchParams` has already decoded once: never decode its values again. No query value, provider error, authorization code or token may be logged or echoed. No application `state` or `returnTo` input is accepted; Supabase owns provider-facing OAuth state.

OpenAPI's optional individual query parameters cannot express dependent exclusive branches. `x-query-schema` references the actual closed union, and the helper tests cover its full behavior. Future handlers must use the duplicate-preserving parser rather than `Object.fromEntries` alone.

Login's `Location` must be the exact environment-specific approved Supabase authorize URL returned by the validated server adapter. Its actual configured value is not known or activated here. The schema's HTTPS constraint is only transport syntax, not an allowlist verifier. Request URLs never select an authorization destination. Callback has one fixed same-origin post-login target, `/today`, with no fallback or user-selected destination. No provider URL is returned in JSON.

## Headers, cookies and sanitized failures

Every Auth response, including failures, requires `Cache-Control: private, no-store` and UUID `X-Request-Id`. Every callback response additionally requires `Referrer-Policy: no-referrer`. No Auth success has an ETag. Redirect/204 responses omit `content` entirely; clients must not parse them as JSON.

Conditional `Set-Cookie` responses issue or expire only the cookie values justified by the verified state transition. Use separate repeated `Set-Cookie` header fields, never a comma-joined value. All three `__Host-jls-*` cookies require `Secure; HttpOnly; SameSite=Lax; Path=/` and no `Domain`. Emit an app-session cookie only after confirmed commit. Cookie secrets never appear in JSON; the explicitly returned short-lived CSRF proof is the only secret-bearing DTO field. Sending a cookie does not prove browser delivery. Later delivery acknowledgements, receipt retries and CAS fencing remain runtime work.

| Status | Only Auth code at that status | Applicable operations |
| --- | --- | --- |
| 400 | `malformed_request` | All six: malformed body/query/header/cookie syntax |
| 401 | `unauthenticated` | `/me`; mutation-purpose `/auth/csrf` |
| 403 | `forbidden` | Origin/proof/binding/owner rejection; callback provider denial |
| 409 | `sign_in_restart_required` | Callback closed/uncertain exchange or undelivered sign-in requiring a fresh login |
| 429 | `rate_limited` | All six; required `Retry-After` integer 1–3600 seconds |
| 503 | `temporarily_unavailable` | All six, including an unresolved commit outcome |

Problems reuse the existing fixed-message registry and strict problem shape, narrowed into Auth-specific status schemas. The restart message is exactly `Sign-in must be restarted.` Never map an unresolved session/logout commit to restart, absence or success; resolve by stable identity or return 503. Never retry a possibly consumed one-use code blindly. No raw provider data, trace or token enters a Problem.

The new registry entry is additive to the existing general `Problem409` schema. Existing domain session/epoch/command/precondition/ETag requirements are preserved. Runtime rate-limit counters, raw body/cookie parsing, server proof checks and real Google/Supabase acceptance remain future work; this contract provides no live authorization or RLS evidence.

`tests/e2e/auth-form-transport.spec.ts` is a synthetic browser transport fixture using two owned loopback HTTPS servers, fabricated proof/cookie and a native form with an actual HTTP303 response. The two hosts isolate the app's host-only cookie from the simulated authorization destination. Its assertions check browser Origin/cookie/body/header behavior and top-level navigation. Ephemeral test certificates use the existing OpenSSL command; no certificate trust is installed and no production TLS configuration changes. It is separate from the app and does not prove real OAuth, server proof verification, runtime route implementation or product readiness.

## Verification checkpoint — 2026-11-06

The parent independently ran 548 ordinary tests across 23 files, OpenAPI syntax/freshness checks, strict TypeScript, JavaScript/config lint and the production build successfully. The full Chromium suite passed 18 tests in 35.6 seconds, including the new loopback HTTPS transport fixture and the existing sample/accessibility checks.

The initial login contract incorrectly combined an exclusive custom proof header with top-level external303 navigation. API review identified that mismatch; the native form body contract resolved it before publication. An initial route-interception fixture then failed on redirected DNS lookup. It was replaced by owned HTTPS servers and a real303 rather than weakening navigation or cookie-isolation assertions. No real provider request was made.

Read-only API and security re-reviews approved the form correction. A separate failure/cleanup review approved bounded local-server teardown and owned TLS-file deletion. These source reviews do not replace human security acceptance, physical Safari UAT or live Auth/RLS evidence. All six operations remain planned; the current app route inventory still contains no Auth handlers.
