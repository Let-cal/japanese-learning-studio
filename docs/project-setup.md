# Project setup

Recorded 2026-10-28; updated 2026-10-29. This is the public-safe Task 0 foundation record. Private account configuration and approval records are maintained outside this repository.

| Item | State |
| --- | --- |
| Identity | Japanese Learning Studio; public repository `Let-cal/japanese-learning-studio` |
| Publication and CI | First reviewed baseline published; `node-spikes` and `postgres-fixture` passed on that baseline |
| Main protection | PR and both observed bootstrap checks required, strict up-to-date policy, resolved review threads, no bypass actors; zero mandatory GitHub approvers for the selected solo-owner process |
| Media CI | Separate optional `media-linux` candidate job prepared; first Linux result pending, not a required main check |
| Application license | MIT, copyright 2026 Let-cal; third-party and source-content rights are separate |
| Runtime | Portable Node.js 24.22.1 selected; no global PATH change |
| Toolchain | Candidate exact versions in ADR 0001; compatibility approval pending |
| Product | Not implemented or deployed |
| Service and AI budget | Hard USD 0 |
| Domain | `nihongostudio.dpdns.org` registered; no deployed website claim |

## Installation boundary

Use a project-scoped runtime and package manager. Do not install global tooling or change the machine's PATH. Registry availability is not evidence that a dependency combination works. Record actual commands, platform, results and limitations before promoting candidates to approved pins. A product lockfile and application setup belong to the subsequent approved implementation stage.

## Data and identity boundary

Public code, examples, CI logs and artifacts must contain only permitted synthetic fixtures. Never publish textbook pages, private study history, recordings, account screenshots, credentials, owner email addresses, identity subjects or infrastructure identifiers.

The private application will authorize a stable, verified Google identity subject through a controlled owner-bootstrap procedure. The first visitor must never become administrator. That procedure remains pending and must be reviewed privately before authentication implementation.

Public demo fixtures must be separate from private application data and provider credentials. Untrusted pull requests receive no hosted secrets. Preview and CI configuration must enforce these boundaries before use.

## Environment boundary

Cloud development is approved. Development temporarily doubles as trusted staging with **fixture-only** data; release-candidate validation requires a controlled freeze and reset procedure. Production is reserved for a second eligible Free project near release. Git plus CLI/CI is the selected sole migration apply path; MCP reads and compares. No hosted write follows merely from this document. See ADR0003 for the exact boundary.

## Review gates

Task 0 prepares evidence and a reviewable diff. Human diff approval precedes every new commit/push and CI expansion. Owner chat approval is recorded against the reviewed PR head; GitHub does not automatically establish that conversation. Task 1 requires its prerequisite setup decisions to be closed. Hosted schema, RLS and configuration changes require owner diff approval and a selected migration method. UAT, security review and production release remain independent gates. AI review does not satisfy a second-human approval requirement.
