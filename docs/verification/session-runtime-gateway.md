# Runtime session RPC gateway

The server-only gateway connects three fixed control RPCs: metadata snapshot, version-bound encrypted credential read, and post-network session confirmation. It does not replace owner policy, token decryption, upstream identity verification or user-context RLS. No HTTP route or environment is activated by these modules.

The supplied configuration is snapshotted once. Only a canonical project HTTPS origin and a server secret key are accepted. Cookie secrets are purpose-hashed before transmission; raw browser/session cookies never enter RPC bodies. Requests omit cookies and Authorization, reject redirects and caching, and cannot select a function, schema, URL or SQL string.

Snapshot responses preserve revoked/expired/stale states so the application can decide denial, refresh or temporary unavailability from actual metadata. This read never grants authority. Credentials and confirmation require explicit observed owner/session/subject/upstream-session, token/control/browser versions and dataset epoch; omitted versions are not replaced by zero. Closed response schemas reject unexpected fields and mismatched CAS/identity facts. The caller must independently verify identity; this gateway merely compares it with stored expectations. Its confirmation response cannot contain an encrypted token envelope.

Each RPC has a two-second header/body deadline, monotonic late-result checks, a 64 KiB response limit and caller AbortSignal support. There are no automatic retries. Failed reads are unavailable; a sent confirmation with no valid acknowledgement is outcome-unknown because its delivery ACK might have committed. The caller must re-establish current state rather than assuming rollback. An already cancelled operation is not sent.

Tests first observed 14 failures and two configuration-denial passes against a scaffold, then all 16 focused cases passed after implementation. Independent scoped review reran 16/16 and found no concrete finding. This evidence uses injected HTTP responses, not a live database. The SQL smoke and pending native PostgreSQL tests are documented separately in [Auth control store](auth-control-store.md).

Remaining integration: request-wide deadlines; policy before decrypt/network; real identity verification; current upstream-session existence; fresh confirmation; verified-user client construction; refresh coordination and routes. The gateway must remain separate from ordinary repositories that use a publishable key and the verified user's JWT. It is not a claim that personal login or study persistence works yet.
