# Service grant and Node authority contracts

- **status**: completed
- **createdAt**: 2026-10-20 15:09
- **approvedAt**: 2026-10-20 15:09
- **relatedTask**: 20261020-1509-grant-authority

## Context

The registry names grants, payer and withdrawal but has no corresponding payload codecs. Existing Node L3 scopes and rules contain full identities without authorized transport keys. Subnet selection already validates route references and exact prefix arithmetic. Service usage still has its predecessor subject type and is revised separately.

## Proposal

Add bounded, canonical pure grant publications, payer bindings and resource authority snapshots. Reuse canonical M6 ServiceRef bytes and existing Subnet publications. Require exactly one explicit realm-local 16-byte UserId payer. Keep retired tokens as caller-supplied validated data and validate successor snapshots without owning state. Add a Node L3 authority wrapper with explicit identity-to-key bindings, preserving existing policy bytes. Define independent accepted and refused vectors before implementation.

## Risks

Missing and ambiguous payer must not become inferred authority. Retired tokens must survive replacement, including identical-content regrant. Missing membership, binding or policy must deny. An authority wrapper grants no transport installation or authenticated issuer trust by itself.

## Scope

Account contracts, independent producer and consumer fixtures, profile and review request. No runtime, session, usage wire revision or duplicate M6 codec.

## Verification

Run the consumer first to establish failure, then format/lint and focused contract tests. Run the prescribed self-check before marking completed. Independent fixtures describe candidate authority, not live producer interoperability.

## Results

Delivered pure Egress/Exit grants, binary realm-local payer assignments, resource
claim/retirement snapshots and complete I/K Node authority. M6 resource bytes,
existing Subnet selection and legacy Node policy bytes are reused unchanged.
No dependency, runtime or usage-wire change is included. The specification and
independent producer precede the implementation; review questions retain the
outstanding NSD producer and owner-confirmation boundaries.

The first consumer failed to compile with unresolved new contract exports.
After implementation and correction of a test borrow, format and lint passed.
The independent fixture contains 72 cases: 16 accepted and 56 typed refusals.
Five new consumer tests compare exact context, floor/selection and I/K fields,
policy denial, selective withdrawal, fresh identical-content regrant, retained
history and invalid constructed contracts. The focused account/Subnet/new
consumer run passed 14 tests. Existing account fixture bytes are unchanged.

The prescribed self-check passed at `09dcebb0ad598287eb5477729853c33a4a0ff8ac`, including static checks, 11
independently generated fixture files, API compatibility, 28 check-selection
tests, 434 workspace tests with zero skips, doctests and warning-free docs.
Only completion records change after that check. Local review covered the full
Rust/Python and documentation change, with no remaining correctness findings.
Candidate fixtures do not certify deployed producer interoperability.

## Node authority review question

Q09 in `docs/l8-candidate-review-request.md` now directly describes the complete
`[1, bindings, policy_bytes]` wrapper, explicit full-I/authorized-K bindings,
validation and denial boundaries, and links to the normalized Node L3
specification. It requests the outstanding NSD/ns string-identifier and
NodeL3Config graph projection, byte-string keys and independent producer vectors.
Q12 retains realm/peer contribution provenance and selective withdrawal context,
with a reference to Q09 instead of presenting the complete contract elsewhere.
No executable source or fixture changed.

The self-check on `977d98a547051a836665b871b5284f263fbcff01` passed static and
API compatibility checks, all 11 generated fixture files, 28 check-selection
tests, 434 workspace tests with zero skips, doctests and warning-free docs.
Only these completion records changed after that verification.
