# PLAN-004 Reconcile current docs with implementation

- **status**: completed
- **createdAt**: 2026-06-15 05:35
- **approvedAt**: 2026-06-15 05:35
- **relatedTask**: DOC-001

## Context

Investigation found a small docs-only reconciliation surface:

- `Cargo.toml` sets `[workspace.package] publish = false`, and every member
  crate inherits `publish.workspace = true`. `README.md` currently tells
  consumers to pin this repository by tag or commit "when it is published",
  which implies a package-publishing path that is not configured.
- `docs/architecture.md` correctly lists the five workspace members, sibling
  path dependencies, and `just qa` expansion, but it does not state the
  non-published workspace contract that explains the consumer model.
- `crates/control/src/envelope.rs` points at `docs/plan/PLAN-022.md`, but this
  repository has no such file. The design context exists in the sibling `ns`
  repository as `docs/plan/PLAN-022.md`.
- `crates/control/src/messages.rs` points at
  `docs/acl-identity-transport-design.md`, but this repository has no such
  file. The design context exists in the sibling `ns` repository as
  `docs/acl-identity-transport-design.md`.

No mismatch was found in the workspace member list, sibling path dependency
table, or `just qa` recipe expansion.

## Proposal

- Update README consumer guidance to say the crates are source-pinned and local
  consumers use path dependencies because the workspace is not configured for
  package publication.
- Add one architecture sentence/paragraph documenting `publish = false` beside
  the live dependency root section.
- Update the two source doc comments so they identify the sibling `ns`
  repository as the location of the design docs instead of presenting broken
  local paths.

## Risks

- The changes are documentation-only. The main risk is over-documenting
  historical PMA records, so completed plan/task files will not be rewritten.

## Scope

Expected files: `README.md`, `docs/architecture.md`,
`crates/control/src/envelope.rs`, `crates/control/src/messages.rs`, and PMA
tracking files for this docs task.

## Alternatives

- Copy the sibling design documents into this repository. Rejected because the
  user asked to reconcile docs with implementation, not duplicate cross-repo
  historical plans.

## Annotations

- 2026-06-15 05:35: User assignment explicitly requested implementation and a
  commit in the same turn; treating that as approval after investigation.
- 2026-06-15 05:35: Completed docs-only reconciliation. Verification:
  `PATH="$HOME/.cargo/bin:$PATH" cargo fmt --all -- --check` and
  `PATH="$HOME/.cargo/bin:$PATH" typos README.md docs
  crates/control/src/envelope.rs crates/control/src/messages.rs` both passed.
