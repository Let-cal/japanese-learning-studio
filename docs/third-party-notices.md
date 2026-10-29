# Third-party and source-content rights

Status: preliminary Task 0 inventory, updated 2026-10-29. No final product dependency/license audit has passed.

The MIT license covers owned application code. It does not relicense dependencies, bundled binaries, fonts, textbooks, photos, recordings or user materials. Public fixtures must be original or have documented permission compatible with publication. No textbook or private account material is included in the authorized public fixture scope.

## Candidates requiring attention

| Package | Candidate version | Reported license / pending work |
| --- | --- | --- |
| @ai-ecoverse/wasm-libheif | 1.23.6-8 | Compatibility probe only; inspected build recipe reports LGPL-3.0-or-later AND MIT AND BSD-2-Clause. Review exact binaries, corresponding sources, notices and relink materials before distribution; no product adoption implied |
| heic-decode | 2.1.0 | ISC wrapper; inspect transitive libheif/LGPL distribution obligations |
| sharp | 0.35.5 | Apache-2.0; inspect bundled/transitive binary notices |
| heic-to | 1.6.7 | LGPL-3.0; review obligations before selecting |
| age-encryption | 0.3.1 | BSD-3-Clause; retain required license text if distributed |
| @zip.js/zip.js | 2.24.0 | BSD-3-Clause; retain required license text if distributed |

These metadata labels are not clearance to distribute. Before shipping, inspect the exact lockfile graph and distributed files, record sources and versions, retain required copyright/license/NOTICE texts, and resolve copyleft obligations. ADR 0001 lists other runtime candidates; all selected direct and transitive packages require the same final inventory process.

The installed Windows dependency-fixture inventory contains76package/version entries. Besides permissive licenses, observed notices include Sharp's native distribution marked Apache-2.0 AND LGPL-3.0-or-later, lightningcss MPL-2.0 and caniuse-lite CC-BY-4.0. This inventory is platform-specific and does not clear Linux/browser distribution or replace required upstream notice texts before shipping. Advisory audits reported0known vulnerabilities; this is not provenance verification or license approval.

Media and recovery package selection remains deferred pending bounded compatibility spikes and license/security review. Do not infer a final choice from this inventory.

The media probe downloads four procedural HEIC charts under [explicit CC0 image permission](https://heic.fyi/samples/LICENSE.txt), with fixed SHA256 values in its manifest. Generated inputs and downloaded binaries/images remain ignored local or ephemeral CI artifacts; no textbook or personal media is used. Fetching a permitted fixture does not approve third-party decoder distribution or establish real-device compatibility.
