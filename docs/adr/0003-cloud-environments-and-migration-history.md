# ADR 0003: Cloud environments and migration history

Status: **temporary environment map and Git + CLI/CI-only migration direction approved; actual hosted operations await reviewed diffs**

Date: 2026-10-28

## Approved boundaries

Hosting, services and AI must cost USD 0. Use only explicitly authorized, legitimately eligible Free resources. No paid branches/add-ons, upgrades, implicit reuse of unrelated projects or membership changes to bypass quota.

| Role | Data and isolation | State |
| --- | --- | --- |
| Development | Authorized Supabase cloud project in Singapore; permitted fixtures only | Approved scope; live configuration verification pending |
| Trusted staging | Temporarily shares development; fixture-only; controlled freeze/reset during UAT | Approved temporary arrangement; independent isolation is not claimed |
| Production | Separate eligible second Free project near release | Reserved direction; not provisioned by this task |
| Public demo | Isolated prepared fixtures, no private data or provider credentials | Planned; not deployed |
| CI | Ephemeral Ubuntu and disposable database fixture reconstruction | Proposed execution, not run |

Development reset is a controlled operation, not blanket permission to delete data or resources. A freeze/reset runbook must protect active UAT and prevent concurrent deployers. Real private learner data must not enter shared development/staging.

Private environment records must map the exact organization/project/branch, region, data classification, callback/base URL, secret references, migration/fixture revision and permitted operations. These identifiers and credentials do not belong in public documentation. Validate owner Google identity through a private controlled procedure, never first-visitor administrator bootstrap.

## Approved migration boundary

Use one deployer per target with Git-to-remote migration history parity. The owner selected Git plus project-scoped CLI/CI as the only migration apply path; MCP reads and compares state. Do not apply migrations through MCP or replay the same DDL from another path. This choice does not itself authorize a schema/RLS/Auth/Storage write; every concrete hosted change still requires owner diff approval.

Generate timestamped migration files using the selected pinned CLI workflow. Record actual version/name/digest and fixture revision. Compare history before and after applying a reviewed migration. Do not replay DDL already applied by another path or rewrite migration history to conceal drift.

Owner diff approval precedes hosted schema, RLS or configuration changes. CI bootstrap follows diff/publication approval. The initial Ubuntu proof uses a minimal permitted fixture schema/policy; later tasks own complete product reconstruction and RLS/receipt tests. Hosted Google/Auth/Storage/Cron/restore checks are separate evidence.

## Operational checks pending

Verify project-scoped read-only connector controls, Free entitlement/capacity, preview isolation, callbacks, deployment eligibility, and a Free-compatible minute-sweeper strategy. Do not assume paid Custom Environments or Vercel Hobby minute Cron. App-owned session expiry/log retention and real off-site backups must not be replaced by unavailable paid platform features.
