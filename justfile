# ns-shared - task runner
# https://github.com/casey/just

set dotenv-load := false

# Show available recipes
default:
    @just --list

# Fast static checks for daily development (fmt + clippy)
dev-check: fmt-check lint

# Full quality gate
qa: qa-checks qa-tests

# Static checks: formatting, lints, supply chain and spelling
qa-checks: fmt-check lint deny shear typos

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

deny:
    cargo deny --locked check

shear:
    cargo shear --locked --deny-warnings

typos:
    typos --config typos.toml
