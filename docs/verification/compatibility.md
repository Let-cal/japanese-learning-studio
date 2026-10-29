# Compatibility record

Recorded 2026-10-28; reviewed 2026-10-29. Status words distinguish observed results, user-provided information, proposals and checks not run. This record does not certify compatibility or readiness.

| Check | Evidence state | Result / next gate |
| --- | --- | --- |
| Node.js 24.22.1 basic runtime | Observed | Local Web Crypto, fetch and streams smoke passed; this does not prove package integration |
| Candidate package versions | Registry and local fixture observed | ADR0001 pins, isolated lockfiles and strict1440-minute release-age policy; clean frozen installs passed without exceptions |
| Chrome | Fixture interaction observed | 156.0.8078.48; Japanese text, hydration, dialog open/Escape close and returned focus passed; no captured console errors; product test not run |
| Physical target | User-provided screenshot | iPhone 13, iOS 18.1.1; no physical-device application or photo test run |
| Next.js / React / TypeScript build | Local Windows pass | Next16.4.3, React19.3.1 and strict TS7.0.2 fixture production build passed; Ubuntu remains unrun |
| FSRS | Local dependency contract pass | ts-fsrs5.4.2 outcome/nonmutation/chained-review APIs passed; approved product evidence/scheduling policy is not implemented |
| Motion / Radix / styling | Local build and bounded browser pass | SSR imports, Tailwind processing and dialog hydration checked; no reduced-motion, full keyboard/axe or product UI acceptance claim |
| HEIC normalization | Proposed candidates | ADR 0002; actual-device samples, license chain, resource limits and output verification pending |
| Encrypted recovery | Bounded Node passes; profile still candidate | Standard age/ZIP25MiB and historical249MiB round trips, negative crypto cases and stream cancellation passed; short-write fix has2tests and25MiB rerun; Safari/cloud/full restore unrun |
| Ephemeral Ubuntu CI | Not run | Bootstrap after diff/publication approval; record actual workflow/check names after a run |
| Disposable database fixture replay | Not run | Minimal permitted fixture schema/policy proof required; no product migration claim |
| Hosted Google/Auth/Storage/Cron/restore | Not run | Separate hosted-service proof and approval required |

## Reproduction and bounded evidence

- [Dependency fixture](../../tools/compatibility/README.md): exact pins/lock, frozen-install stop condition and direct compiler/build commands. Three dependency contract tests passed; these do not implement product policy.
- [Recovery fixture](../../tools/recovery-probe/README.md): standard-format pipeline, security rejection cases, size/memory/abort limits and historical-versus-current results. Both source trees enforce strict1440-minute release age without exceptions.
- [CI draft](../../tools/ci/README.md): pinned Node/pnpm, full-SHA Actions and digest-pinned ephemeral PostgreSQL fixture; not run until approved publication. The toolchain npm locked install was additionally rerun successfully with Node24.22.1 by the coordinator.
- [Chrome fixture screenshot](evidence/compatibility-chrome.jpg): a technical dependency fixture, not the M1 interface or a Safari test. Console log capture contained no errors in this bounded interaction.

Full raw logs and synthetic large archives remain in ignored local `artifacts/`; public summaries and source are intentionally separate. The current public GitHub repository is empty; no files, workflow, branch protection or deployment has been published/configured. GitHub read-only checks show Actions enabled, default workflow token read-only, PR-review approval by Actions disabled, no branch/ruleset yet. Required checks will be selected only after a real successful bootstrap run. No workflow run is claimed.

## Required evidence before closing Task 0

For every spike record the exact command, tool/package versions, operating system, fixture origin, exit status and bounded output. Keep private identities and secrets out of logs. A local pass does not imply Ubuntu, hosted-service or physical-iPhone success.

Required bounds remain: ten images per batch, **12 MiB per input**, **30 MP decoded image**; recovery **250 MiB compressed**, **1 GiB expanded**, **10,000 entries**. Evaluate the Free Storage **50 MB object limit** explicitly; a larger approved recovery package must not silently become one unsupported upload object.

Record real observed CI check names before requiring them in branch protection. A solo-owner review path must be feasible and honest about human review availability. Do not describe an AI review as an independent human approval.

Task 0 checks a minimal permitted database fixture only. Full application reconstruction, product RLS, receipts and transaction correctness remain later-task requirements. Docker/WSL installation on the owner machine is not a prerequisite for this cloud-first workflow.
