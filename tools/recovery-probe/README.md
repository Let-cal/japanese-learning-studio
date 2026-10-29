# Local recovery compatibility probe

Isolated Task 0 code. Synthetic, disposable data only; no product implementation, cloud upload, credentials, or network calls at runtime.

Pinned candidates: `age-encryption@0.3.1` and `@zip.js/zip.js@2.24.0`, both BSD-3-Clause (installed package manifests and LICENSE files). Preserve dependency license notices when distributing. Exact dependency graph/integrities are in `pnpm-lock.yaml`. Use Node `24.22.1` and pnpm `12.16.1` (pinned in the manifest). From `tools/recovery-probe`, install with `pnpm install --frozen-lockfile --ignore-scripts`. The isolated `pnpm-workspace.yaml` enforces `minimumReleaseAge: 1440` and `minimumReleaseAgeStrict: true`; no advisory exclusions, overrides, or release-age exceptions.

Primary API references inspected before implementation:
- https://github.com/FiloSottile/typage/blob/main/README.md (Streams API and passphrase API)
- https://github.com/gildas-lormeau/zip.js/blob/master/README.md (ZipWriter Streams API)
- Installed version-specific `age-encryption/dist/index.js`, `index.d.ts`, `io.js` and zip.js `index.d.ts`.

Run with Node 24.22.1: `node tools/recovery-probe/probe.mjs 25` (default), or `node tools/recovery-probe/probe.mjs 249`. Only those two sizes are accepted. Results and synthetic artifacts go to a unique directory under ignored `artifacts/recovery-probe/`. No automatic deletion. The passphrase is generated in memory for each process and is never written to disk.

Pipeline: generate 64KiB random chunks -> ZIP stored entry (`level:0`) -> disk archive -> standard age stream encryption at default scrypt logN18 -> local 4MiB ciphertext transport parts -> concatenate stream -> standard age decryption -> disk ZIP -> random-access disk ZIP reader -> extracted-entry hash. Archive and entry SHA256 must match. Part splitting changes no age framing; parts must be rejoined in order before decryption. No whole archive or whole encrypted envelope is buffered. The small adversarial fixture is intentionally bounded to128KiB plus envelope overhead.

A level0 entry represents an incompressible asset and exercises a near249MiB ZIP; it does not measure Deflate performance. Code enforces existing250MiB ZIP and1GiB extracted-byte bounds for the generated fixture. It does not exercise10,000entries,1GiB extraction, exactly250MiB, archive attacks, path traversal, manifest/schema validation, or malicious metadata. The generated one-entry fixture has a fixed safe filename; this reader is not a production safe restore implementation.

Negative checks use the full small streaming decrypt consumer: wrong passphrase, payload bit flip, and missing final byte must reject. Stream cancellation uses AbortSignal with pipeTo, checks upstream cancel and downstream abort, and confirms source pulls stop. The age API performs scrypt setup before returning its stream; this synchronous/async KDF setup has no exposed AbortSignal and was not proven cancellable. A production browser worker termination strategy would require a separate approved evaluation. Stream decryption can yield authenticated prefix chunks before a later corruption/truncation is detected; the probe never publishes them as restored product state. No atomic promotion or rollback is implemented or claimed.

RSS samples every20ms plus stream/read guards. The1GiB guard exits the local process immediately; this leaves only owned synthetic artifacts, and is not a production cancellation handler. Peak sampling can miss short-lived native allocations. Results include all setup/negative cases and process warmup/GC variation; they are not throughput benchmarks. Random-access reads are sized by the library for this generated archive; this adapter is not safe for arbitrary untrusted archives without additional limits.

No browser, Safari, OPFS, mobile memory, CLI interoperability, Supabase upload/object operations, offline restore, full product restore, or security certification has been validated. Audit zero advisories is a point-in-time package advisory result, not a cryptographic review. Diff and independent security review remain required before adopting the candidate.


## Local verification after short-write fix (2026-10-29)

`node --test tools/recovery-probe/write-all.test.mjs` runs two focused I/O tests: short writes must persist the entire byte sequence; a zero-progress write must reject immediately. The unchecked single-write baseline produced2failures (RED, exit1); the writeAll helper produced2passes (GREEN, exit0). Ciphertext part writes now advance by actual bytesWritten.

A new25MiB probe passed after this source change: archive26,214,600bytes, encrypted26,221,182bytes,7parts, maximum4,194,304bytes; hashes matched, all three corruption/password cases rejected, and stream cancellation passed. Peak sampled RSS368,312,320bytes; elapsed6,225ms. Results: `artifacts/recovery-probe/25MiB-1793237509387/results.json`.

The249MiB measurement in `artifacts/recovery-probe/249MiB-1793204994593/results.json` is historical evidence from2026-10-28 before the short-write fix; it was not repeated after this change.

Fresh isolated installation with the pinned Node/pnpm and identical strict1440-minute age policy succeeded with `pnpm install --frozen-lockfile --ignore-scripts` (actual exit0). It used a new empty artifact directory and reused the pnpm content-addressed store. Evidence: `artifacts/recovery-probe/fresh-policy-1793237521809/install-result.json` and `install.log`. An initial frozen attempt failed with exit1 because the new package-manager pin required lock metadata; this was resolved by `pnpm install --lockfile-only --ignore-scripts` under the same policy before the successful fresh frozen verification. No exclusions were added.
