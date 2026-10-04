# nsshared - task runner
# https://github.com/casey/just

set dotenv-load := false

# Show available recipes
default:
    @just --list

# Fast static checks for daily development (fmt + clippy)
dev-check: fmt-check lint

# Full quality gate
qa: qa-checks qa-tests

# Static checks: formatting, lints, supply chain, spelling, vectors and API compatibility
qa-checks: fmt-check lint deny shear typos vectors-check semver

# Tests: nextest plus the doctests nextest does not run
qa-tests: test doc

check:
    cargo check --workspace --all-targets --locked

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# The deny-warnings policy lives in [workspace.lints]
lint:
    cargo clippy --workspace --all-targets --locked

test:
    cargo nextest run --workspace --locked

doc:
    cargo test --workspace --doc --locked
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

deny:
    cargo deny --locked check

shear:
    cargo shear --locked --deny-warnings

typos:
    typos --config typos.toml

# Regenerate the spec-derived test vector fixtures
vectors:
    python3 tools/vectors/generate.py

# Check that the committed test vector fixtures match the generator
vectors-check:
    python3 tools/vectors/generate.py --check

# Check the public API of the library crates against the previous release tag.
# In 0.x a minor version bump may break the API; any other bump must not.
semver:
    #!/usr/bin/env bash
    set -euo pipefail
    baseline="$(git describe --tags --abbrev=0 --match 'v[0-9]*' --exclude '*-*' HEAD^ 2>/dev/null || true)"
    if [ -z "$baseline" ]; then
        echo "semver: no release tag before HEAD; skipped"
        exit 0
    fi
    cargo semver-checks --package nsshared-proto --package nsshared-telemetry --baseline-rev "$baseline"
