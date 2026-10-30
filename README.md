# Japanese Learning Studio

An owner-focused Japanese vocabulary and Kanji learning application, with an isolated sample workspace.

**Status:** Local M1 foundation under review. The sample shell is the first implementation slice; owner authentication, durable learning records, imports, evaluated providers and recovery are not implemented. The bounded Task 0 bootstrap and Linux media candidate checks passed on reviewed head `a56c04e`. These probes do not establish complete-product or physical-device compatibility. No deployed application is claimed.

The approved direction is a Next.js/TypeScript application with separate recall evidence for meaning, kana and Kanji recognition, FSRS scheduling, private media and recoverable study data. The local `/demo` uses original sample fixtures and clearly labeled prepared explanations without personal data or live provider credentials. It is not a study record or exam-readiness assessment.

Hosting, services and AI must remain **USD 0**. Paid upgrades, provider substitutions and production releases require separate review.

- [Setup and boundaries](docs/project-setup.md)
- [Compatibility evidence and pending checks](docs/verification/compatibility.md)
- [Runtime and dependency candidates](docs/adr/0001-runtime-and-dependencies.md)
- [Media and recovery evaluation](docs/adr/0002-heic-and-recovery-profile.md)
- [Optional Linux media candidate probe](tools/media-probe/README.md)
- [Cloud environments and migration history](docs/adr/0003-cloud-environments-and-migration-history.md)
- [Third-party notices](docs/third-party-notices.md)
- [Task dependencies and retained approval gates](docs/verification/task-dependencies.md)
- [API contract preflight](docs/api/contract-preflight.md)
- [Planned core API contract](docs/api/openapi.yaml) and [local command/API verification](docs/verification/commands-and-api.md)
- [Local foundation checks and limitations](docs/verification/foundation.md)

## Local sample workspace

Use the exact Node version in `.node-version`. A portable runtime can be invoked by its absolute path without changing the machine's PATH; `node` below denotes that selected executable.

```sh
npm ci --ignore-scripts --prefix tools/toolchain
node tools/toolchain/node_modules/pnpm/bin/pnpm.mjs install --frozen-lockfile --ignore-scripts
node node_modules/next/dist/bin/next dev --hostname 127.0.0.1 --port 3102
```

Open `http://127.0.0.1:3102/demo`. No environment variables or cloud accounts are needed. Stop if an install fails; do not continue with a partially installed dependency graph. The lockfile and strict 1440-minute release-age policy are intentional.

The sample supports navigation, word filtering, prepared card explanations and an effects preference. Later screen families show an explicit implementation status in the guide. No camera/microphone, private upload, real Google login, provider quota or live learning persistence is enabled. Task 0 probes remain separate evaluation tools.

Application code is licensed under [MIT](LICENSE). Third-party dependencies, textbooks, user media and other source materials retain their own rights; the application license does not grant rights to those materials.
