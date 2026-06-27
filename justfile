# ns-shared - task runner
# https://github.com/casey/just

set dotenv-load := false

# Default: show available recipes
default:
    @just --list

# Full quality gate for this library workspace.
qa: fmt-check lint test deny shear typos

check:
    cargo check --workspace --all-targets --locked

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

test:
    cargo nextest run --workspace --locked

deny:
    cargo deny --locked check

shear:
    cargo shear --locked

typos:
    typos
