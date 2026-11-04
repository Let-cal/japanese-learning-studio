# Auth-secret primitive verification

Recorded2026-11-04, prepared from published `4ea74ea`. Modules remain disconnected from application entry points and use only builtin Node crypto. No credentials, environment values, SDKs, routes, cookie storage or cloud resources are activated.

## Observed evidence

- Worker recorded45meaningful failing assertions against unimplemented exports after separately resolving test setup/import mechanics. Final focused suite:47tests/2files PASS.
- Parent ran the complete ordinary suite:376tests/18files PASS, including the original329cases and47new cryptographic cases. Parent separately selected the original16files and observed329PASS under the dependency remediation, without claiming that the new crypto code was published.
- Strict TypeScript, production build, API document/freshness, frozen ignored-script installation, config/script lint and advisory audit pass locally. Existing limited TypeScript/React lint coverage remains explicit.
- Independent source/security review approved the four crypto/test files with no actionable findings. Reviewer read source; parent ran checks. This is not owner security signoff.

Tests use actual encryption/decryption, tampered IV/ciphertext/tag, wrong keys and independently changed AAD fields, strict base64url aliases, token/serialized boundaries, independently authenticated invalid JSON/UTF8/schema, explicit key rotation, key views/input immutability and secure-RNG failure. They exercise fail-closed results without provider calls or attack/stress loops. Synthetic token/key fixtures are not real credentials.

## Limits

See [ADR0005](../adr/0005-auth-secret-primitives.md) for exact format, bounds, trusted context and key-lifecycle decisions. Strict lowercase context UUIDs are required rather than silently normalized. The primitives do not verify JWTs, owner authorization or CSRF; they do not persist/revoke sessions or coordinate refresh. Valid older ciphertext replay for the same context is a future store/versioning responsibility.

PR5's published `4ea74ea` had an audit failure and skipped its dependent SQL job. The [prepared dependency fix](dependency-advisories.md) passes local checks, but no new Linux CI pass is claimed for either that fix or these uncommitted primitives. Publish the reviewed fix first; record actual follow-up CI before publishing the dependent crypto PR. Merge, hosted changes, physical-device UAT, human security acceptance and release remain gated.
