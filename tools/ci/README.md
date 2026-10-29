# Task 0 bootstrap draft

This workflow checks isolated spikes. There is deliberately no root product
package or application CI yet. Publication and the first workflow run require
the owner's diff approval. No workflow has been run as part of preparing this draft.

The Node job installs the exact local pnpm package with `npm ci --ignore-scripts`
inside `tools/toolchain`, then invokes `node_modules/pnpm/bin/pnpm.mjs` directly.
Frozen installs must succeed before tests, direct type checking, the Next build,
the 25 MiB recovery probe, and dependency audits. Audit errors fail the job.
No recovery artifacts are uploaded. The larger probe remains a local exercise.

The independent database job uses a disposable PostgreSQL 17.11 service. Its
Docker Official Image multi-platform manifest digest was resolved anonymously
from `registry-1.docker.io/v2/library/postgres/manifests/17-bookworm` on
2026-10-29. The official 17.11-bookworm tag returned the same digest; the linux/amd64 entry reports version 17.11-bookworm. Config-blob retrieval failed with a transport reset, so PG_VERSION was not independently read. This upstream fixture differs from the Development Supabase vendor build 17.11.0.003 and does not verify vendor extensions or policies.

`bash tools/ci/postgres-fixture.sh` connects only to the fixed loopback endpoint,
database and dummy account declared in the workflow. It clears inherited libpq
settings and ignores password files. Run it only against that disposable service.
There is no remote DSN parameter or hosted credential input. Each SQL pass uses
BEGIN/ROLLBACK, creates a synthetic role/schema, checks two-owner SELECT
isolation and denied cross-owner INSERT, then rolls back; a second pass checks
replay. These fixtures are not product migrations, hosted migration writers,
Supabase policies, or evidence that hosted RLS works. Actual Ubuntu/PostgreSQL
execution remains unverified until an approved workflow run.

The workflow uses standard Ubuntu hosted runners, read-only repository
permissions, pinned official actions and no deployment or credential persistence.
Check repository visibility and billing before publication; free standard hosted
runner use assumes a public repository.
