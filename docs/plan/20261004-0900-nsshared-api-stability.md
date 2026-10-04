# 20261004-0900-nsshared-api-stability Prepare the nsshared API for stability (v0.3.0)

- **status**: completed
- **createdAt**: 2026-10-04 09:00
- **approvedAt**: 2026-10-04 09:00
- **relatedPlan**: 20261003-2300-nsshared-v0-2-scope

## Context

nsshared is not yet a stable release: no consumer has integrated `v0.2.0`, the
public API was a flat glob re-export of about 270 items, no type was
`#[non_exhaustive]`, and nothing checked API compatibility between releases.

## Proposal

1. Export modules instead of glob re-exports; keep the seven central types at
   the root.
2. Mark every public error and rejection enum `#[non_exhaustive]`.
3. Remove application constants that belong to ns.
4. Add `just semver` (cargo-semver-checks) against the previous release tag to
   `just qa`, and deny rustdoc warnings.
5. Document the version policy and release `v0.3.0`.

The `v1.0.0` stable release waits for ns integration, the relay v2 server
interop test and a single protocol implementation.

## Annotations

- 2026-10-04: Owner approved steps 4 and 5 of the stability path (conversation).
