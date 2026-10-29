# Compatibility record

Recorded 2026-10-28; reviewed 2026-10-29. Status words distinguish observed results, user-provided information, proposals and checks not run. This record does not certify compatibility or readiness.

| Check | Evidence state | Result / next gate |
| --- | --- | --- |
| Node.js 24.22.1 basic runtime | Observed | Local Web Crypto, fetch and streams smoke passed; this does not prove package integration |
| Candidate package versions | Registry and local fixture observed | ADR0001 pins, isolated lockfiles and strict1440-minute release-age policy; clean frozen installs passed without exceptions |
| Chrome | Fixture interaction observed | 156.0.8078.48; Japanese text, hydration, dialog open/Escape close and returned focus passed; no captured console errors; product test not run |
| Physical target | User-provided screenshot | iPhone 13, iOS 18.1.1; no physical-device application or photo test run |
| Next.js / React / TypeScript build | Windows and bootstrap Ubuntu pass | Next16.4.3, React19.3.1 and strict TS7.0.2 fixture production build passed; not product implementation |
| FSRS | Local dependency contract pass | ts-fsrs5.4.2 outcome/nonmutation/chained-review APIs passed; approved product evidence/scheduling policy is not implemented |
| Motion / Radix / styling | Local build and bounded browser pass | SSR imports, Tailwind processing and dialog hydration checked; no reduced-motion, full keyboard/axe or product UI acceptance claim |
| HEIC normalization | Bounded Windows candidate evidence; Linux pending | Patched-codec Node/WASM candidate converts four CC0 charts and selects the burst primary correctly; CLI/API, resource, license and actual-device gates remain. See ADR 0002 and the optional media probe |
| Encrypted recovery | Bounded Node passes; profile still candidate | Standard age/ZIP25MiB and historical249MiB round trips, negative crypto cases and stream cancellation passed; short-write fix has2tests and25MiB rerun; Safari/cloud/full restore unrun |
| Ephemeral Ubuntu CI | Bootstrap observed | `node-spikes` and `postgres-fixture` succeeded on the first reviewed baseline; optional `media-linux` has not run |
| Disposable database fixture replay | Observed | PostgreSQL17.11 disposable fixture/policy checks replayed twice with rollback; no hosted or product migration/RLS claim |
| Hosted Google/Auth/Storage/Cron/restore | Not run | Separate hosted-service proof and approval required |

## Reproduction and bounded evidence

- [Dependency fixture](../../tools/compatibility/README.md): exact pins/lock, frozen-install stop condition and direct compiler/build commands. Three dependency contract tests passed; these do not implement product policy.
- [Recovery fixture](../../tools/recovery-probe/README.md): standard-format pipeline, security rejection cases, size/memory/abort limits and historical-versus-current results. Both source trees enforce strict1440-minute release age without exceptions.
- [Bootstrap CI](../../tools/ci/README.md): pinned Node/pnpm, full-SHA Actions and digest-pinned ephemeral PostgreSQL fixture. Both jobs passed in [run40807854922](https://github.com/Let-cal/japanese-learning-studio/actions/runs/40807854922) on baseline `93da51a491651b7e434b171da273c72b2ba45ed7`.
- [Media candidate probe](../../tools/media-probe/README.md): public SHA256-pinned HEIC charts, synthetic JPEG/negative cases, explicit process termination canary and observed peak-memory budget. Windows evidence does not establish Linux success, a stable production adapter or an OS memory cap.
- [Chrome fixture screenshot](evidence/compatibility-chrome.jpg): a technical dependency fixture, not the M1 interface or a Safari test. Console log capture contained no errors in this bounded interaction.

Full raw logs and synthetic large archives remain in ignored local `artifacts/`; public summaries and source are intentionally separate. The first reviewed baseline is published and its bootstrap CI succeeded. Main now requires PRs and the observed `node-spikes`/`postgres-fixture` checks; force push/deletion are blocked and no bypass actor is configured. Owner approval remains a separately recorded process gate. No application deployment is claimed. The optional media workflow is a proposal pending approved publication and an actual Linux run; its check is not added to main protection.

## Required evidence before closing Task 0

For every spike record the exact command, tool/package versions, operating system, fixture origin, exit status and bounded output. Keep private identities and secrets out of logs. A local pass does not imply Ubuntu, hosted-service or physical-iPhone success.

Required bounds remain: ten images per batch, **12 MiB per input**, **30 MP decoded image**; recovery **250 MiB compressed**, **1 GiB expanded**, **10,000 entries**. Evaluate the Free Storage **50 MB object limit** explicitly; a larger approved recovery package must not silently become one unsupported upload object.

Record real observed CI check names before requiring them in branch protection. A solo-owner review path must be feasible and honest about human review availability. Do not describe an AI review as an independent human approval.

Task 0 checks a minimal permitted database fixture only. Full application reconstruction, product RLS, receipts and transaction correctness remain later-task requirements. Docker/WSL installation on the owner machine is not a prerequisite for this cloud-first workflow.
