# ADR 0001: Runtime and dependency evaluation

Status: **runtime selected; evaluated UI pins selected for local Task 1 preparation; publication review pending**

Date: 2026-10-28; evidence reviewed 2026-10-29

## Context and decision

Use Node.js 24.22.1 through a portable, project-scoped runtime without global PATH changes. Keep domain modules independent of Next.js, provider and Storage SDKs. Exact dependency versions become approved only after bounded compatibility checks, review and reproducible lockfile creation.

The following table records evaluated pins and test-tool candidates. Task 1 uses the runtime/UI subset: Node/Next/React/TypeScript/Motion/Radix/Tailwind were exercised by the isolated Windows and Ubuntu dependency fixture. FSRS remains a separately evaluated scheduler candidate for Task 7, not a shell dependency. Test tools still require product integration checks; media, recovery and authentication have separate activation gates.

| Package | Candidate version |
| --- | --- |
| pnpm | 12.16.1 |
| next | 16.4.3 |
| react / react-dom | 19.3.1 |
| typescript | 7.0.2 |
| ts-fsrs | 5.4.2 |
| motion | 14.7.1 |
| @radix-ui/react-dialog | 1.3.1 |
| tailwindcss | 4.3.3 |
| vitest | 5.0.5 |
| @playwright/test | 1.64.1 |

## Acceptance and consequences

Local Node Web Crypto, fetch and streams smoke passed. The isolated fixture passed a clean frozen install, three dependency contract tests, strict TypeScript7 checking and a Next16.4.3 production build on Windows and Ubuntu. Chrome verified hydration, Japanese rendering, dialog open/Escape close and focus return; no full accessibility or reduced-motion claim. Ubuntu checks passed again on reviewed head `a56c04e` in [run 40896636504](https://github.com/Let-cal/japanese-learning-studio/actions/runs/40896636504). On 2026-10-30 the owner authorized continuous local preparation under the approved plan and delegated routine technical choices. These results enable the independent Task 1 shell; they do not accept media/recovery/authentication features. Physical Safari remains a UAT gate and is not replaced by emulation.

FSRS6.0.0 and its newly released dependency failed the strict release-age gate during evaluation. The existing stable5.4.2 release was explicitly evaluated instead; unchanged API contract tests and a fresh frozen install passed. Both probes retain a1440-minute minimum release age in strict mode, without exceptions. This is candidate selection, not a change to the approved learning policy. Historical failed evidence is retained privately. Advisory audits found0reported vulnerabilities at the time checked; provenance signatures were not cryptographically verified.

The exact pnpm toolchain has its own reviewed npm lockfile under `tools/toolchain/`; invoke its actual v12 `bin/pnpm.mjs`. Do not assume the older `pnpm.cjs` path. Disable install lifecycle scripts, keep changes local to a shell, and stop on a failed frozen install before executing checks. A pnpm script exit alone is insufficient evidence that dependency verification succeeded.

Dependency license metadata and actual installed transitive notices must be reviewed before distribution. Registry existence alone establishes neither security nor license compatibility.

## Task 1 tooling limitation

The local shell pins Vitest5.0.5, Playwright1.64.1, axe4.14.0 and test-only Babel parser8.0.8. ESLint10.13.0 checks JavaScript configuration files. The evaluated Next ESLint configuration's parser/plugin dependency range excludes TypeScript7; no peer override is used. Strict TypeScript checking runs separately and is not equivalent to React/Next/TypeScript lint rules. Full compatible lint coverage remains an explicit tooling follow-up rather than a claimed check. This limitation does not change runtime or learning semantics.
