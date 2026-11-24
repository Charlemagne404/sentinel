# Development

## Tooling

- Rust stable, edition 2024, Cargo and committed Cargo.lock.
- Node/npm for React, TypeScript, Vite, Vitest and uPlot.
- Linux procfs/sysfs are required only for live collection; deterministic tests use pure helpers or temporary SQLite files.

## Commands

    cargo fmt --all
    cargo test --locked -j1
    cd frontend && npm test -- --reporter=dot
    cd frontend && npm run build
    scripts/build.sh

The frontend build writes frontend/dist, which the Rust server serves in production. There is no production Node process. Unit tests do not require the real monitoring server. Do not use load/stress tests on the target machine; audit current host resources first.

## Structure

Rust modules live under src/. Frontend source and tests live under frontend/src/. User-level build/install/update/uninstall helpers live in scripts/. docs/openapi.yaml describes the versioned HTTP API.

## Contribution rules

- Keep collectors unprivileged and read-only.
- Keep outbound requests bounded, validated and opt-in.
- Do not add command-line/environment capture.
- Keep collector queues and API/history limits bounded.
- Add deterministic parser/statistical/storage tests with fixtures rather than asserting current host readings.
- Update docs with behavior changes; do not claim production/resource verification based only on unit tests.
