# Google OAuth application wiring

The Task 3 local source connects the start and callback HTTP handlers to fixed server control RPCs. The handler factory is exercised with synthetic HTTP requests and is not mounted in Next.js. The generated Auth operations remain planned.

## Behavior verified

- The start handler requires exact HTTPS Origin, an explicit browser binding and a login-purpose body proof. The request body is bounded before decoding. Duplicate relevant cookies and decoded form fields are rejected.
- The server resolves opaque browser, proof and flow values through service-only invoker reads. It binds the PKCE envelope to environment, browser and attempt. A begin write with an unknown result may replay the exact same tuple once.
- The callback accepts only GET, checks query shape before mutation, and exchanges a code only after a durable send acknowledgement. It verifies the returned Auth identity and compares the approved owner before attempting commit.
- An unknown commit is resolved with the same operation and fingerprint. Failed or uncertain closure may retry the identical close once within the same recovery budget. Verified cleanup credentials are encrypted separately.
- A valid current cookie may reach the fixed post-login destination after current-session verification. A replay never issues another bearer. Missing or wrong cookie, or provider denial, cannot trigger retirement from the ambient GET.
- Normal work is bounded by a shared ten-second request deadline. Callback settlement may use a separate four-second reserve for exact resolution and closure. Hosted timeouts and actual performance still require validation.

## Local evidence

The application suite passed 737 tests, including 80 focused OAuth application, handler and RPC adapter cases. The production build, TypeScript, lint and OpenAPI consistency checks passed. PGlite executed all four migrations and passed 63 cases, including 14 lookup cases. A separate synthetic Request/Response smoke exercised the TypeScript handlers against the same SQL using named RPC arguments, losing the first begin and commit responses after SQL committed and observing one upstream exchange. The new lookup suite is registered for the disposable native PostgreSQL job. It has not run on native PostgreSQL or hosted Supabase.

## Remaining before activation

Implement same-origin, proof-bound attempt abandonment and recovery. A provider denial leaves a pending attempt until its expiry. A crashed worker can leave an exchange marked as possibly sent and prevent a new login. The locked recovery needs to fence successor attempts and protect an in-flight cookie delivery or an acknowledged session. The callback does not accept an untrusted provider error as permission to cancel an attempt.

Connect CSRF issuance, current-owner continuation and acknowledgement, logout and cleanup, rate limiting, HTTP route composition and telemetry redaction. Validate Google redirect and browser behavior on the approved Development environment, managed Auth session and RLS enforcement, and owner enrollment before enabling personal study.

[Supabase PKCE](https://supabase.com/docs/guides/auth/sessions/pkce-flow) · [Supabase Google sign-in](https://supabase.com/docs/guides/auth/social-sign-in/auth-google)
