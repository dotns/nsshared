# PLAN-010 Reproducible ns-shared QA lockfile

- **status**: completed
- **createdAt**: 2026-06-27 05:21
- **approvedAt**: 2026-06-27 05:21
- **relatedTask**: HYG-001

## Context

`ns-shared/.gitignore` ignores `Cargo.lock`, while `ns-shared/justfile` runs
`cargo deny check` as part of `just qa`. Without a tracked lockfile, a fresh
checkout can resolve newer compatible transitive dependencies than the graph
that was verified locally.

The local ignored lockfile currently resolves:

- `quinn-proto 0.11.15`
- `time 0.3.51`

crates.io reports `time 0.3.48` as yanked and `time 0.3.51` as the current
stable release on 2026-06-27. `quinn-proto 0.11.15` is the current 0.11 patch
release.

Path-dependency consumers such as ns, nsgw, and nsd retain their own root
lockfiles. Committing this workspace lockfile affects ns-shared's own QA graph,
not those consumers' dependency resolution.

## Proposal

- Remove `Cargo.lock` from `.gitignore`.
- Track the current `Cargo.lock`.
- Add `--locked` to cargo-based QA commands in `justfile`.
- Run focused verification against the locked graph.

## Risks

- The committed lockfile can drift unless dependency refreshes are intentional.
- Consumers with their own root lockfiles may still need separate dependency
  refreshes; this change does not update ns, nsgw, or nsd lockfiles.

## Scope

Touch only ns-shared repository hygiene and QA command wiring:

- `.gitignore`
- `justfile`
- `Cargo.lock`
- PMA task and plan tracking files

## Alternatives

- Keep ignoring `Cargo.lock` and depend on scheduled updates or external CI
  artifacts. Rejected for this task because it leaves local and CI QA dependent
  on fresh dependency resolution.

## Annotations

- 2026-06-27 05:21: Approved to implement the proposed lockfile hygiene scope.
- 2026-06-27 05:23: Verified with `cargo tree -i time --locked`,
  `cargo tree -i quinn-proto --locked`, `cargo deny --locked check`, and
  `just qa`.
