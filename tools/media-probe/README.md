# Task 0 media capability probe

This is a bounded Node experiment for Linux/API/resource evaluation. It is not a production upload handler, application acceptance, security clearance, or deployment. The optional `Task 0 media Linux / media-linux` workflow adds a separate Ubuntu 24.04 job and leaves the existing bootstrap jobs and required-check configuration untouched. It requires an owner-reviewed diff before integration; Linux has not yet been executed in this draft.

## Reproduce

Use Node **24.22.1** from the repository `.node-version`. From the repository root, install the committed local toolchain and these exact dependencies:

```sh
npm ci --ignore-scripts --prefix tools/toolchain
node tools/toolchain/node_modules/pnpm/bin/pnpm.mjs --dir tools/media-probe install --frozen-lockfile --ignore-scripts
cd tools/media-probe
node prepare-fixtures.mjs
node run.mjs
node verify-results.mjs artifacts/runs/REPLACE_WITH_CURRENT_RUN_ID/results.json
node deadline-canary.mjs
```

`run.mjs` prints its exact `resultFile` in the JSON summary. Pass that current value explicitly to the verifier. The workflow captures the current summary and does this automatically; the verifier's no-argument `artifacts/latest-run.json` convenience pointer is not used by CI. Run `node tools/toolchain/node_modules/pnpm/bin/pnpm.mjs --dir tools/media-probe audit` from repository root to refresh registry advisory evidence.

pnpm is **12.16.1**, bootstrapped by the repository's npm lock. This package pins `@ai-ecoverse/wasm-libheif` **1.23.6-8** and Sharp **0.35.5** directly. Its own lock retains Linux optional Sharp/libvips packages. Resolution uses a strict 1440-minute minimum release age with no exemptions; installation is frozen and ignores lifecycle scripts. No OS packages, global tools, custom runner, credentials, provider integration, artifact upload, or network service are required.

## Fixtures and privacy

`fixture-manifest.json` pins exactly four fixed HTTPS HEIC chart URLs, dimensions, SHA256 values, and the SHA256 of their [CC0 rights statement](https://heic.fyi/samples/LICENSE.txt). The [sample documentation](https://heic.fyi/heic-sample-files) describes procedural charts. Preparation fetches the license and charts with a 30-second request deadline, rejects redirects, checks declared length, streams with a 12MiB maximum (64KiB for the license), verifies SHA256, then writes. It never buffers an unbounded response via `arrayBuffer`.

Sharp generates eight 120x80 asymmetric quadrant JPEGs carrying EXIF orientations 1-8 and synthetic GPS coordinates. The matrix verifies input GPS tag IDs, corner colors after orientation, dimensions, and final EXIF/XMP/ICC/IPTC/orientation removal. There are no private photos, emails, audio, or cloud identifiers. Small corrupt/truncated chart copies, one 6001x5000 header patch, and a 12MiB+1 sparse length fixture are deterministic negative cases, not fuzzing, exploit testing, or oversized raster allocation. The fixture-only `ispe` byte patch and synthetic JPEG EXIF inspection are not production parsers.

All fetched licenses, fixture binaries, outputs, summaries and logs are written below this package's `artifacts/`, already ignored by the repository's `artifacts/` rule. Installed dependencies use the existing `node_modules/` ignore. Commit only source, manifests, locks, documentation and the optional workflow.

## What is asserted

The matrix runs 26 sequential direct children and expects 59 checks plus exactly 12 fresh JPEG outputs. The independent Node assertion verifier checks actual CLI reports of libheif **1.23.6** and libde265 **1.1.3**, actual Node/Sharp versions, fixture hashes, four HEIC dimensions, and burst primary item ID 3/index 2 mapped to `/decoded-3.png`. It reopens every JPEG to check metadata and hashes, verifies eight JPEG orientation/GPS regressions, and rejects unexpected outcomes with a nonzero exit status. HEIC orientation dimensions are asserted; the current Linux orientation chart's upright arrow and normal F still require visual inspection. Real iPhone/Safari and photographic quality are unverified.

The preflight contract rejects hash changes, nonpositive or unsafe dimensions, duplicate/invalid item IDs, missing/multiple primary markers, unrecognized `image:` rows, per-image/aggregate pixel overflow and decoded-output count mismatch. Eight cheap explicit negative plan cases cover the contract branches. Corrupt/truncated headers fail metadata inspection; truncated body parses then fails decoding; the synthetic >30MP header is rejected before decoder-module initialization; >12MiB is rejected before the worker reads the file. Ordinary children must all finish without timeout or signal.

**The primary-image adapter is a fragile textual CLI contract, not a supported production library API.** It parses `heif-info` rows and maps their order to `heif-dec` output numbering. The pinned [libheif CLI source](https://github.com/strukturag/libheif/tree/v1.23.6/examples) must be re-reviewed if upgraded. The CLI decodes every top-level burst image into virtual-memory PNGs before selecting its primary. The 30MP per-image and aggregate guard occurs **after container parsing** in the separate info process; it does not bound internal tiles, auxiliary images, or parser allocations. No homegrown HEIC production parser or custom WASM loader is introduced.

## Deadlines and resources

Each HEIC/CLI child runs without a shell, using the current Node executable, a reduced environment, a 30-second `spawnSync` timeout, explicit `killSignal: 'SIGKILL'`, and a 1MiB captured-output bound. JPEG synthetic regressions run in the coordinator. No package CLI operation in this matrix is expected to spawn descendants; this supervisor makes no general descendant-tree termination guarantee.

The separate deadline canary creates only its own direct Node child. That child installs a SIGTERM handler, prints a readiness marker, and loops synchronously. The parent gives startup one second, then asserts real `ETIMEDOUT`, force termination, and that the owned PID is gone after `spawnSync` returns. On POSIX it additionally asserts SIGKILL. Windows validates force termination/PID disappearance and cannot establish POSIX signal semantics. This is an expected deadline branch, separate from the ordinary matrix's no-timeout assertion; it is not `Promise.race` or a stress/load test.

Workers record `process.resourceUsage().maxRSS` in KiB, including module imports and process startup, plus end RSS and elapsed time. A declared **768MiB per-worker peak** is a corpus observation gate, checked by the verifier. It is **not an enforced OS memory cap**. There is no `RLIMIT_AS`, `RLIMIT_RSS`, cgroup, sudo, external monitor or total-batch-memory claim. Counts 10 and 11 are explicitly array-length policy simulations with zero decoder jobs; actual concurrency, simultaneous memory and batch admission remain open. Any platform budget needs measurement and owner review before production integration.

## Provenance, advisories and remaining gates

The pinned package's [public provenance commit](https://github.com/ai-ecoverse/homescoop/tree/b34191cf5db627e52d49451e11567dfa227e9cf5) and recipe provide source/build review starting points. Earlier local research verified that exact package's npm registry signature and attestation and matched its subject SHA512 to registry integrity; that verification is separate evidence and is not rerun or claimed by this workflow. A signed publisher identity does not prove publisher trust, reproducibility or binary safety. The upstream [libde265 1.0.17 release](https://github.com/strukturag/libde265/releases/tag/v1.0.17) names fixes for CVE-2026-33164 and CVE-2026-33165; the tested runtime is [1.1.3](https://github.com/strukturag/libde265/releases/tag/v1.1.3). Earlier source ancestry research is separate evidence. Runtime version assertions establish the exercised codec version, not comprehensive CVE clearance. `pnpm audit` covers current registry-reported dependency advisories; zero findings do not clear bundled native/WASM codecs.

The installed package declares `LGPL-3.0-or-later AND MIT AND BSD-2-Clause`; its bundled object/relink kit is not a final distribution/legal clearance. LGPL/relink duties and HEVC patent/distribution obligations need deliberate owner review. New-publisher trust, independent build/source verification and reproducibility, advisory-specific patch ancestry, Linux packaging and resource results, real iPhone/iOS variants, HEIC EXIF/GPS, HDR/P3/10-bit fidelity, upload/auth/storage, OCR, actual batch/concurrency, hard memory isolation, customer UAT and security/release approval remain open. The diff/UAT/security/release gates stay in force.

Draft Windows validation on 2026-10-29: frozen install, public fixture preparation, 26 jobs/59 checks/12 JPEGs, 158 independent assertions, deadline canary and zero registry advisories passed. This is point-in-time Windows evidence; Linux remains pending. No CI, commit, push, deploy or cloud change was performed by this draft.
