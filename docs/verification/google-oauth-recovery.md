# Google OAuth recovery

The recovery handler and proof issuer are local Task 3 source. The planned route is `POST /api/v1/auth/recover`. It uses exact HTTPS Origin, both opaque binding cookies, and a single bounded form proof. The private form issuer derives a proof digest scoped to the exact flow. The proof issuance fingerprint binds that digest to the flow in SQL. The ordinary login endpoint derives a different digest from the same wire syntax.

## State transitions

| Attempt or request | Result |
| --- | --- |
| Exact unsent pending attempt | Cancel the attempt and retain any prior session. |
| Claimed or possibly sent attempt within its deadline | Return temporary unavailable. The proof can still be used. |
| Expired possibly sent attempt | Record missing credential custody and close the attempt without another provider exchange. A new proof-bound login also settles this blocker if the old flow cookie is unavailable. |
| Completed attempt with matching result cookie or acknowledged delivery | Preserve the session. |
| Completed attempt with undelivered result | Wait for the 30-second database grace period. Retire only the exact current, unacknowledged result with no successor attempt, then queue local cleanup. |
| Repeated or ambiguous write | Use the same proof and exact presentation. Confirm the same receipt only while its browser generation and session pointer still match and a later sign-in has not superseded the receipt. A successor permanently invalidates the prior receipt even if it closes in the same browser generation. |

The original verified claimant can record a late token pair for cleanup through the existing close operation. An expired-exchange record retains the history of missing custody. Recovery never issues or clears a browser cookie. After 204, reload the sign-in form and use a fresh ordinary login proof. A 503 leaves the user able to retry the exact recovery request while its proof is available.

The grace interval is an implementation default measured from the database session creation time. Hosted measurements must confirm it against transaction and browser delivery latency. A cookie that arrives after its session has been retired cannot recover authorization.

## Activation evidence still required

The recovery form and HTTP handlers need server-only route composition, rate limits and telemetry redaction. End-to-end Google and Supabase Development verification must cover proof issuance, a closed provider window, a delayed or dropped response, the current owner, and private-data access. Run the native SQL suite in the owned disposable PostgreSQL CI job and keep the UAT and deployment gates separate.
