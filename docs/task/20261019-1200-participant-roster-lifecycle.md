# Signed participant roster lifecycle

- **status**: completed
- **createdAt**: 2026-10-19 12:00
- **updatedAt**: 2026-10-19 12:12
- **plan**: ../plan/20261019-1200-participant-roster-lifecycle.md

## Goal

Return complete authenticated participant generations with typed refusals and
supplied-clock validity/degradation decisions, preserving existing signed bytes.

## Investigation

The roster's issuer and recipient already identify participant scope. Version is
the attribution epoch; entries are complete replacement. Existing verification
collapses authority and freshness causes. Enrollment demonstrates typed decisions
and independent expected values in the account fixture.

## Acceptance

- [x] Independent vectors cover acceptance, complete replacement, class changes,
  authority/version/signature refusals and validity/degradation boundaries.
- [x] Consumer reads canonical bytes, decisions and clock inputs from the fixture.
- [x] Existing vectors retain their names and bytes.
- [x] Formatting, lint and self-check pass.

## Validation

The initial `participant_roster_vectors` test failed with
`missing independently signed participant lifecycle vectors`. After implementation,
the focused account, enrollment and participant consumer tests passed. The final
participant consumer verifies 27 fixture-fed decisions and reads the complete
expected scope, version, identity/class mapping, issue time and deadline directly.

Relative to the previous contract, expiry now returns a typed refusal, with
acceptance one millisecond before the deadline and refusal at it. Lifecycle status
is valid one millisecond before 24 hours since the supplied authenticated renewal
and diagnostically degraded at that instant; the mapping remains intact. A recent
renewal cannot move the signed expiry deadline. Complete empty, identity omission
and class-only replacement return the exact new complete mapping and epoch.

`cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked`
passed before the tests. `just self-check` passed with the integration comparison,
including 406 tests passed with zero skipped, exact vector regeneration, API
compatibility, doctests and documentation. The original account fixture remains an
unchanged prefix of the regenerated file. The existing `SignedRoster::verify`
implementation and errors remain unchanged.

The existing account consumer's dispatch filters now leave the added participant
vector kind to its dedicated consumer; its original assertions remain intact.
Q03 and Q18 retain `prepared` dispositions and request independent NSD vectors;
broader authorized scopes remain open.
