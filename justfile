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

# Static checks: formatting, lints, supply chain, spelling and vector generators
qa-checks: fmt-check lint deny shear typos vectors-check

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

# Independent vector generators and refutation checks for quick-wire
vectors-check:
    python3 crates/quick-wire/tests/generate_default_context_vectors.py --check
    python3 crates/quick-wire/tests/refutation_cbor_dependency.py
    python3 crates/quick-wire/tests/refutation_literal_coverage.py
