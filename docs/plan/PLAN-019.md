# PLAN-019 Remove the standalone Mesh shared protocol

- **status**: completed
- **createdAt**: 2026-09-16
- **approvedAt**: 2026-09-16
- **relatedTask**: SH-MESH-003

## Context

Current main `3aef14fd` includes standalone Mesh v1/v2 under
`crates/control/src/mesh`, its tests/fixtures, a public module export, and a
Mesh design document. It does not include Keynet. The account crates' source
outside this module differs from pre-Mesh `d02a29c` only in the module export and
Mesh signing support in `ControlEnvelope`.

`sign_request_with_nonce` was added by `2800175b` for Mesh registration proofs.
`sign_response_in_place` and `sign_response_at` were added by `98f4fce7` for
Mesh key-grant/response signing. Current shared, NS, NSGW, and NSD call-site
inspection finds no account-mode consumer of these helper APIs. Ordinary
request/response signing and all existing verification APIs must remain.

## Proposal

1. Preserve the original main tip in a backup branch and work on a new branch.
2. Remove the dedicated Mesh module, integration tests, fixtures, export, and
   current design document; preserve task/plan records and historical changelog.
3. Remove the three Mesh-only signing helpers and restore the ordinary request
   signing implementation, preserving its domain, fields, and account semantics.
4. Remove only unused direct Mesh dependencies, retaining transitive crypto
   requirements still used by Noise and the account transports.
5. Record the removed API boundary for NS/NSGW, update current documentation,
   and verify the preserved account crates and focused workspace checks.

## Risks

Sibling NS and NSGW currently consume shared `control::mesh`; they must remove
their consumers before coordinated integration. Historical records will refer
to removed source paths and remain recoverable through Git and the backup ref.
Do not equate account-mode peer/relay support with the removed standalone mode.

## Scope

Only Mesh-specific shared code, tests, fixtures, dependencies, current docs, and
new removal tracking. Keep all account fixes, old feature branches, and runtime
data. No Keynet integration, deployment, force push, or broad baseline reset.

## Alternatives

Replacing main with Keynet or resetting to the pre-Mesh baseline was rejected:
this operation removes only the independently identified Mesh surface from the
latest tree and preserves unrelated history and functionality.

## Annotations

The user approved this removal on 2026-09-16. Build work is serialized with the
coordinating task; runtime and platform acceptance are not implied by static
source checks.

## Verification

The removal is complete and account-code equivalence, 709 workspace tests,
Clippy, formatting, metadata, shear, and changed-file spelling checks passed.
The doctest command completed with zero doctests. Exact commands and evidence
are recorded in [SH-MESH-003](../task/SH-MESH-003.md).

The cached offline advisory gate failed on unchanged `rustls 0.23.41`
(RUSTSEC-2026-0285); dependency upgrades are not included and no full-QA or
production-readiness claim is made. Local preservation is approved with this
pre-existing limitation recorded. Downstream NS/NSGW integration is separate.
