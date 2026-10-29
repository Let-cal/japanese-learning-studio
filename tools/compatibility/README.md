# Task 0 dependency compatibility fixture

This disposable local fixture checks candidate package API/build compatibility. It is not product implementation or approval for Task 1.

## Reproduce on this Windows machine

Run from this directory in PowerShell. The PATH change below affects only that shell.

```powershell
$toolchainRoot = Join-Path $env:LOCALAPPDATA 'JapaneseLearningStudio/toolchains'
$nodeRoot = Join-Path $toolchainRoot 'node-v24.22.1-win-x64'
$env:Path = $nodeRoot + ';' + $env:Path
$env:NEXT_TELEMETRY_DISABLED = '1'
$pnpmCli = Join-Path $toolchainRoot 'pnpm-12.16.1/node_modules/pnpm/bin/pnpm.mjs'
node $pnpmCli install --frozen-lockfile --ignore-scripts
# Stop if install fails. Do not disable the release-age policy.
node $pnpmCli test
node $pnpmCli typecheck
node $pnpmCli build
node $pnpmCli audit --json
```

## Current candidate evidence (2026-10-28)

Node 24.22.1; pnpm 12.16.1. Exact direct pins are in package.json; resolved transitive pins/integrities are in pnpm-lock.yaml.

- All three Node smoke tests passed: FSRS review outcomes/nonmutation, chained review API, React static rendering with Motion/Radix Japanese text.
- TypeScript 7.0.2 strict typecheck passed with dependency declarations checked (`skipLibCheck: false`). Next production build passed and prerendered `/` and `/_not-found`, including Tailwind processing. The build ran with telemetry disabled. It used installed Windows native binaries without enabling install lifecycle scripts.
- `pnpm audit --json` returned zero reported vulnerabilities; this is advisory evidence, not a security certification.
- ts-fsrs **5.4.2** is the current compatibility candidate. npm records publication at 2026-09-01T02:23:24.171Z, Node >=20, and no dependencies. It replaces the same-day v6 candidate solely to satisfy the strict 24-hour release-age policy and establish a reproducible Task 0 baseline; no product algorithm or learning policy is approved by this choice. Existing dependency contract tests required no API changes.
- A fresh directory with no node_modules passed pnpm install --frozen-lockfile --ignore-scripts under minimumReleaseAge: 1440 and minimumReleaseAgeStrict: true, with no exclusions. It reused the local content-addressed package cache; this is a clean dependency installation, not a cold network-cache test.
- Historical v6.0.0 installation auto-generated release-age exceptions for ts-fsrs and srs-kit 1.0.0. Removing those exceptions correctly blocked frozen install. The old lockfile and original logs are retained under v6-historical/; v6 is not the selected candidate. Registry metadata declared signatures/SLSA attestations, but cryptographic provenance was not verified. The old lockfile had to be regenerated because pnpm rejected its too-new entries before updating to v5.
- Inventory covers 76 installed package/version entries on Windows, not every optional platform dependency in the lockfile. Licenses include MIT, Apache-2.0, BSD-3-Clause, ISC, 0BSD, MPL-2.0 (lightningcss), CC-BY-4.0 (caniuse-lite), and Apache-2.0 AND LGPL-3.0-or-later (Sharp Windows native distribution). Packaging/distribution obligations need review before shipping.

Current evidence files have a `v5-` prefix. Full install/build/test/audit/license/registry logs are under `../../artifacts/compatibility/` (gitignored). The generated exception file is retained there as evidence only. No server, browser, Playwright, mobile device, iPhone, hydration, focus, dialog interaction, accessibility, reduced-motion, or product-policy verification is claimed. No product data or cloud resources were used.
