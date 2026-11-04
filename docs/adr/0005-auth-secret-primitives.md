# ADR0005: Server auth-secret primitives

Date: 2026-11-04. Status: **source prepared and reviewed; publication and runtime key provisioning pending**.

## Context and decision

The approved server-mediated session design stores only a lookup hash of the opaque app-session bearer and encrypts upstream credentials on the server. This slice prepares disconnected Node24 primitives for those responsibilities. It adds no route, cookie, JWT verifier, CSRF transport, persistence, environment access or key configuration.

Session bearers contain32cryptographically random bytes, encoded as canonical unpadded base64url. The stored digest is SHA256 over a fixed versioned app-session purpose and decoded bytes. A digest is never accepted as a bearer. Verification checks canonical shapes before comparing equal-length digests with `timingSafeEqual`; this is not a claim that all surrounding code is constant time.

Upstream credentials use AES-256-GCM with an explicitly supplied32byte key, a fresh random12byte IV and16byte tag. AAD binds fixed purpose/version/keyID plus independently trusted environment, ownerUUID, sessionUUID and Auth-subjectUUID. Context must already use canonical lowercase UUIDs from verified server records. Dataset epoch is excluded because credentials follow identity/session lifecycle; dataset authorization still applies independently.

Envelope grammar is fixed: `v1.keyId.iv.ciphertext.tag`. There is no algorithm negotiation, key search, default key or plaintext fallback. Binary components must round-trip through canonical base64url. Decryption authenticates before decoding UTF8, parsing JSON, validating its closed schema or returning plaintext. All malformed/tampered/wrong-key/context failures have one fixed sanitized decryption error.

The implementation uses standard [Node crypto primitives](https://nodejs.org/docs/latest-v24.x/api/crypto.html), not a new cipher. Authenticated modes and secure randomness follow the [OWASP cryptographic storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html). Actual tests use pinned Node24.22.1; documentation browsing does not update that runtime.

## Defensive technical bounds

| Input | Bound |
| --- | --- |
| KeyID/environment | 1–64 ASCII identifier characters, first alphanumeric |
| Access/refresh token | Each1–8192UTF8bytes; well-formed Unicode with meaningful non-whitespace/control content; accepted bytes preserved |
| Serialized plaintext | At most33KiB, independently of token limits |
| Encoded envelope | At most48KiB, checked before split/binary decode |
| IV/tag/key | Exactly12/16/32bytes respectively |

These are defensive implementation choices, not provider compatibility or capacity guarantees. Token contents are opaque and are not parsed as JWTs here. Closed own-data schemas reject missing/extra/inherited fields and accessors; key-byte views are copied without modifying caller input.

## Key lifecycle and integration gate

The caller explicitly supplies the current keyID and key bytes. An old envelope opens only with its expected keyID/key/context. Future integration must keep old keys until dependent sessions are expired, revoked or safely re-encrypted, and must not replace bytes under a reused keyID. Replacement ciphertext must persist successfully before old ciphertext/key retirement. No key was generated, configured, stored or rotated by preparing this module.

Authenticated encryption does not detect rollback to an older valid envelope for the same context. Future storage versions, refresh/revocation locking and controlled writes remain required. Bearer possession/decryption does not establish current ownership, session validity, JWT validity or CSRF proof. Plaintext strings still exist transiently in server memory; no JavaScript zeroization guarantee is made.

The actual opaque-cookie adapter, encrypted token store/key lifecycle, owner bootstrap, logout CSRF/retry binding and user-context RLS/RPC still require reviewed integration. Source approval does not replace human security approval, UAT or release gates.
