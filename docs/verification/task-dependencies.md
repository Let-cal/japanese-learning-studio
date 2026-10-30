# Execution dependencies and retained gates

Updated 2026-10-30. This map enables independent work under the approved M1 plan; it does not waive an acceptance criterion.

| Work | Available evidence / prerequisite | Execution boundary |
| --- | --- | --- |
| Task 0 runtime/UI | Pinned dependency fixture built on Windows and Ubuntu; Node 24.22.1 | Enables local Task 1 preparation; product validation remains necessary |
| Task 1 shell/demo | Approved visual tokens; isolated public-safe sample data; no auth/provider/media dependency | Implement and test locally, then present exact diff before publication |
| Task 2 contracts/receipts | Approved command/API rules; shell test tooling | Draft contracts and verify pure rules locally; durable receipts need actual transaction/DB tests, not an in-memory substitute |
| Task 3 identity/RLS | Controlled stable-subject bootstrap, reviewed schema/config and real access tests | Draft locally; hosted changes await exact approval |
| Task 4 automatic HEIC intake | Patched-codec fixture passes; production API/resource/license profile unresolved | Keep automatic HEIC requirement; do not wire the probe into uploads or replace it with manual conversion |
| Tasks 5–9 learning/UI | Shared contracts, content/evidence rules and dependent domain implementations | Implement approved independent slices; sample UI cannot establish durable learning behavior |
| Task 10 real providers/audio | Finite evaluation, rights, consent and hard USD 0 | Activate only a qualifying path; prepared demo AI remains explicitly labeled |
| Task 11 persistence/sync | Receipts, versioned data and reviewed adapters | Validate interrupted/replayed writes before claiming saved/recovered work |
| Task 12 recovery | Node encryption/archive research only; full format/limits/transport acceptance pending | Retain complete recovery requirements; no destructive restore or reduced limits inferred |
| Task 13 UAT/security | Integrated application and device access | Physical Chrome/Safari/capture/audio/IME/VoiceOver checks; owner UAT and security approval remain required |
| Task 14 release | Reviewed exact source, passing checks, UAT and security approval | Separate explicit release approval; no implicit merge, deployment or promotion |

## Device coverage

Original personal-iPhone photo transfer is not a current setup prerequisite. Public/synthetic HEIC/JPEG fixtures support repeatable engineering checks. Browser tests should cover desktop Chrome and mobile Chromium/WebKit viewports; emulated WebKit is not an actual iPhone Safari result. The owner's iPhone 13 / iOS 18.1.1 is one UAT target, not the entire supported-device population. Android/desktop JPEG and supported HEIC inputs remain part of the import design.

AC02/43 require actual capture/import without a desktop conversion workaround before acceptance. Record the real device, OS and browser at that test rather than treating a model specification or a web search as behavioral evidence.

## Approval granularity

Resolve ordinary local implementation choices in the ledger and proceed across independent tasks. Present a consolidated, tested diff at the next source/configuration publication boundary. A review does not authorize unrelated hosted writes, paid activation, merge, UAT sign-off, security sign-off or release.
