# ADR 0002: HEIC and recovery profile evaluation

Status: **proposed candidates; final decisions deferred**

Date: 2026-10-28; bounded media/recovery evidence reviewed 2026-10-29

## Media candidates

| Candidate | Version | License consideration |
| --- | --- | --- |
| @ai-ecoverse/wasm-libheif | 1.23.6-8 | Selected for further compatibility evaluation only; inspected recipe reports LGPL-3.0-or-later/MIT/BSD-2-Clause; source, notices and relinking distribution review pending |
| heic-decode | 2.1.0 | ISC wrapper; transitive libheif/LGPL obligations unresolved |
| sharp | 0.35.5 | Apache-2.0 package; binary/transitive distribution needs review |
| heic-to | 1.6.7 | LGPL-3.0 candidate; obligations require review |

No decoder is selected for product use. Evaluate permitted fixtures including actual iPhone HEIC behavior, orientation, visible-content preservation, metadata stripping, corrupt inputs and bounded memory. Enforce ten images/batch, 12 MiB/input and 30 MP decoded image. Do not assume paid image transformations.

The pinned Node/WASM candidate actually reports libheif1.23.6 and libde2651.1.3, converts four CC0 HEVC charts and correctly selects the burst's third/primary image in the local Windows experiment. Its registry signature and build attestation were verified, and runtime artifacts matched the audited package. This identifies the release origin; it does not prove publisher trust, a reproducible rebuild, final license compliance or absence of all vulnerabilities. The upstream [1.0.17 release](https://github.com/strukturag/libde265/releases/tag/v1.0.17) lists the two previously identified codec CVEs as fixed; tested1.1.3 is newer and source fix ancestry was checked.

The old convenience wrapper's first-image selection is not the accepted behavior. The new candidate's current CLI adapter also remains unsuitable as a final API: it parses textual metadata and decodes all frames before choosing the primary. Pixel guards run after container parsing. A separate [optional Linux probe](../../tools/media-probe/README.md) evaluates the candidate, actual child termination and observed resource use before any product adoption. Its768MiB fixture peak budget and aggregate multi-image check are research controls, not an approved product-policy change or OS-enforced memory isolation. Linux/Vercel, actual iPhone/Safari, HEIC GPS, color fidelity and stable API/resource/security acceptance remain pending.

## Recovery candidates

| Candidate | Version | Evaluation role |
| --- | --- | --- |
| age-encryption | 0.3.1 | BSD-3-Clause; upstream FiloSottile/typage streaming encryption candidate |
| @zip.js/zip.js | 2.24.0 | BSD-3-Clause; streaming archive candidate |

Candidate availability does not approve a crypto profile. Select a vetted authenticated-encryption format and library profile; do not invent cryptography. Document format/version, key and passphrase handling, stream framing, failure semantics, memory bounds and interoperability before implementation. Verify tampering/wrong-key failure without activating partial restored data, archive traversal rejection and resource-limit enforcement.

Retain 250 MiB compressed, 1 GiB expanded and 10,000 entries. Supabase Free Storage's 50 MB per-object limit requires a proven compatible transport/staging design for the full package bound. Chunking or streaming is a proposal until tested; it must preserve authentication and atomic activation. Seven-day checkpoints and media-inclusive off-site recovery remain required. Capacity failures must not silently weaken these requirements.

Local Node evaluation of the candidate passed ZIP-to-standard-age streaming round trips for synthetic25MiB and249MiB payloads. The249MiB run generated261,159,550encrypted bytes in63parts, each at most4MiB; archive and extracted-entry hashes matched. This local part size fits under50MB, but no Storage upload was performed. Wrong passphrase, payload tampering and truncation rejected; stream cancellation stopped the source and aborted the sink. These results are not an end-to-end product recovery pass.

The source now handles short file writes and zero-progress writes with two targeted tests (observed failing before the helper, then passing). The25MiB pipeline was rerun after that change; the249MiB result predates this I/O-only fix and is labeled historical. The default age scrypt18 setup does not expose an AbortSignal. Node RSS samples were approximately330–352MiB in these bounded runs, not a mobile memory guarantee. Browser/worker cancellation, independent age interoperability, exactly250MiB,10,000entries/1GiB expansion, hostile archive checks, actual cloud transfer and atomic promotion/rollback remain unverified.

## Gate

License review, reproducible bounded spikes, security review and owner approval remain pending. Dependent media/recovery implementation is blocked until its profile is accepted. Destructive restore is outside Task 0 authorization.
