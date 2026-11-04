# Dependency advisory remediation

Recorded 2026-11-04. At published `4ea74ea`, [PR5 product run41820603158](https://github.com/Let-cal/japanese-learning-studio/actions/runs/41820603158) failed at audit after ordinary/browser tests and build passed. The dependent command-Postgres job was skipped. This document prepares a source fix; it does not claim new Linux CI success.

## Finding and selected fix

[GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249) affects minimatch below11.0.1. The installed10.2.6 appears through ESLint10.13.0 and config-array0.23.5, development-only lint tooling. Official registry metadata showed ESLint10.14.0 still uses a vulnerable major range, so an ESLint patch update alone cannot remove this finding.

Exact parent-scoped workspace overrides select minimatch11.0.4 for those two parent versions only. The root manifest and Node pin stay unchanged; the lock adds only the matcher's required `@isaacs/nonrecursive-glob-match1.0.3`. Strict1440minute maturity and ignored install scripts remain. No advisory allowlist, reduced audit threshold or broad override is added.

## Compatibility and evidence

This crosses upstream major-version ranges. Version11 removes APIs and changes internals, so matching a version number alone is insufficient. Inspected ESLint uses the retained constructor, `.match(path, partial)` and `.pattern`; config-array uses the constructor and `.match`. Neither uses the removed APIs/internals in the inspected paths.

Parent reran 16 comparisons between cached10.2.6 and both11.0.4 consumer resolutions, checked the three actual lint files and ten ignored paths, then ran lint and audit successfully. The worker also observed frozen ignored-script installation pass. The audit now reports no known vulnerabilities locally; this does not establish universal compatibility or full security clearance.

Evidence covers current consumers and repository globs, not all glob patterns or future parent upgrades. Repeat fresh Linux CI after owner-approved publication. Remove the narrow overrides once upstream parents natively accept a patched range, with normal diff review. Keep the audit active.
