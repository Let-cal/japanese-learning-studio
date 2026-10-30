# Local M1 foundation verification

Recorded 2026-10-30. This is local preparation for human diff review, not a release or completed M1 acceptance record.

## Task 1 sample shell

- Anonymous sample Today, Library, Practice, Progress and Guide; unavailable owner/later functionality labeled explicitly.
- Separate `StudyShell` and `MotionProvider`; route titles/focus, keyboard navigation, scoped sample reset, user effects preference and OS reduction.
- Four original sample words with Japanese contexts and Vietnamese meanings/prepared teaching notes. No textbook images, personal data or live provider calls.
- Root exact lockfile and drafted product workflow. No new hosted CI run, deployment, Supabase operation or merge follows from local preparation.

| Check | Observed local result |
| --- | --- |
| Frozen install with scripts disabled | Passed; strict 1440-minute release-age policy retained |
| Demo dependency graph regression | 6 tests passed, including unsafe transitive canaries |
| Browser shell suite after language correction | 11 Chromium tests passed; 26.4 seconds for that bounded run |
| Responsive and automated accessibility matrix | Today/Library/Practice/Progress/Guide at 320/390/768/1024/1440; no page overflow or tagged axe violations on those 25 views |
| Storage failure regressions | Denied storage and read-allowed/write-quota failure keep sample actions usable; reset preserves unrelated keys |
| Keyboard/motion | Skip/navigation/reveal and heading focus; OS reduced motion remains authoritative |

Final coordinator validation after all code fixes: **119 tests passed across four Vitest files**, JavaScript config lint passed, strict route generation/typecheck passed, the production build passed and the registry audit reported no known vulnerabilities. The implementer also observed no peer dependency issues. TS/React/Next-specific lint is not covered because the evaluated plugin range excludes TS 7. Strict compilation is a separate check, not an equivalent substitute.

Independent code review found one content-language mismatch. A regression first failed for the missing Vietnamese language annotation; the prepared notes were corrected to Vietnamese, the Japanese ten-minute example was disambiguated and the complete browser suite passed again. Automated browser/axe checks do not establish screen-reader quality, WCAG conformity or physical Safari acceptance.

## Task 2-A pure contracts

The first contract slice validates opaque identifiers, versions/ETags, manual draft previews/confirmed batches and memory-note representations/writes. It preserves kana/Vietnamese input, rejects unknown fields, returns row diagnostics without persistence, requires explicit note revision/version preconditions, and enforces 1–10 rows and 2,000 Unicode code points. Invalid-size batches return before inspecting elements; note counting stops at code point 2,001. The two resource-handling regressions were observed failing before their fixes.

Its three targeted suites passed 113 tests; combined with the six demo-boundary checks, the final aggregate is 119. Both task reviews and the integration review found no remaining publication blocker for this local slice. OpenAPI, command hashing, disclosure/repair/job/session contracts, authentication, durable receipts and real transaction/concurrency tests remain incomplete. No in-memory receipt store substitutes for those obligations.

## Reproduce

Use Node 24.22.1 and the exact local toolchain. `node` denotes that selected runtime; Windows portable users can invoke its full executable path without changing global PATH.

```sh
npm ci --ignore-scripts --prefix tools/toolchain
node tools/toolchain/node_modules/pnpm/bin/pnpm.mjs install --frozen-lockfile --ignore-scripts
node tools/toolchain/node_modules/pnpm/bin/pnpm.mjs lint
node tools/toolchain/node_modules/pnpm/bin/pnpm.mjs typecheck
node tools/toolchain/node_modules/pnpm/bin/pnpm.mjs test
node node_modules/@playwright/test/cli.js install chromium
node node_modules/@playwright/test/cli.js test tests/e2e/demo-shell.spec.ts
node tools/toolchain/node_modules/pnpm/bin/pnpm.mjs build
```

Automated tests own port 3101 and refuse to reuse an existing server. The independent local review server uses 3102. Do not stop a port owner without verifying it belongs to this task. Public fixture screenshots and test traces remain ignored local artifacts.

## Remaining acceptance

Physical Chrome/Safari, screen-reader/VoiceOver, real capture/audio/IME, full TS lint coverage, product CI on Linux, owner UAT, security approval and release remain separate checks. The shell creates no durable attempts, rewards, schedules, uploads or authentication. Task 2 contracts and database transactions are independent implementation work, not inferred from sample interactions.
