# Scoped workspace self-check

- **status**: implementing
- **createdAt**: 2026-10-18 22:14
- **approvedAt**: 2026-10-18 22:14

## Context

`just qa` runs workspace static checks, nextest, documentation tests and a
warning-free documentation build. There is no path-based test selector.
The workspace includes contract crates and example consumers.

## Proposal

Add `just self-check base`, with the comparison ref supplied as its argument
and defaulting to `main`. Collect committed, staged, unstaged and untracked
paths relative to the merge base. Use Cargo metadata to map crate directories
and compute transitive workspace reverse dependencies for documentation.
Use nextest's `rdeps` filter for the same affected test set.

Always retain formatting, lint, deny, shear, typos, vectors and semver checks.
Deny, shear and typos inspect workspace policy without tests; vector drift
checks are deterministic generator comparisons; semver preserves the existing
public API check. Keeping all of them avoids weakening contract quality.

Unknown paths, manifests, vectors, configuration, an empty diff or an empty
package set select the complete QA recipe. Treat every manifest edit as global
because it can change the dependency graph. Integrate Python selection tests
into QA without changing the existing Rust checks or their order.

## Risks

An incomplete path mapping could omit affected tests. Conservative full QA and
Cargo's resolved dependency graph prevent that. NUL-separated Git output and
argument arrays preserve filenames and ref arguments.

## Scope

`justfile`, the selection script, its Python tests and the associated records.

## Alternatives

A hard-coded crate list would become stale as workspace members change.
Cargo metadata provides the package mapping and reverse dependency graph.

## Verification

The selector and its 10 tests are implemented. `just qa` and
`just self-check main` both pass, including all existing static checks,
393 Rust tests, 1 documentation test and documentation generation.
A real Git/Cargo fixture verifies transitive reverse dependencies and executes
restricted nextest plus the selected documentation commands successfully.

Acceptance remains open for a crate-only invocation on the final source tree:
the new infrastructure and records require complete QA for every available
ancestor comparison, and crate source edits are outside the implementation
scope. No scoped-versus-complete duration comparison is claimed.
