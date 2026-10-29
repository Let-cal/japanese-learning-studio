# ADR 0001: Runtime and dependency evaluation

Status: **runtime selected; dependency profile candidate, compatibility approval pending**

Date: 2026-10-28; evidence reviewed 2026-10-29

## Context and decision

Use Node.js 24.22.1 through a portable, project-scoped runtime without global PATH changes. Keep domain modules independent of Next.js, provider and Storage SDKs. Exact dependency versions become approved only after bounded compatibility checks, review and reproducible lockfile creation.

The following versions were observed in official npm registry metadata. They are **candidate pins**, not a passed compatibility matrix or an installed product dependency set.

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

Local Node Web Crypto, fetch and streams smoke passed. The isolated fixture passed a clean frozen install, three dependency contract tests, strict TypeScript7 checking and a Next16.4.3 production build on Windows. Chrome verified hydration, Japanese rendering, dialog open/Escape close and focus return; no full accessibility or reduced-motion claim. Ubuntu CI and physical Safari remain pending. These are evaluation pins, not installed product dependencies or permission to start Task1.

FSRS6.0.0 and its newly released dependency failed the strict release-age gate during evaluation. The existing stable5.4.2 release was explicitly evaluated instead; unchanged API contract tests and a fresh frozen install passed. Both probes retain a1440-minute minimum release age in strict mode, without exceptions. This is candidate selection, not a change to the approved learning policy. Historical failed evidence is retained privately. Advisory audits found0reported vulnerabilities at the time checked; provenance signatures were not cryptographically verified.

The exact pnpm toolchain has its own reviewed npm lockfile under `tools/toolchain/`; invoke its actual v12 `bin/pnpm.mjs`. Do not assume the older `pnpm.cjs` path. Disable install lifecycle scripts, keep changes local to a shell, and stop on a failed frozen install before executing checks. A pnpm script exit alone is insufficient evidence that dependency verification succeeded.

Dependency license metadata and actual installed transitive notices must be reviewed before distribution. Registry existence alone establishes neither security nor license compatibility.
