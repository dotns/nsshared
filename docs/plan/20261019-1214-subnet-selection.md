# Subnet route selection contract

- **status**: implementing
- **createdAt**: 2026-10-19 12:14
- **approvedAt**: 2026-10-19 12:14
- **relatedTask**: 20261019-1214-subnet-selection

## Context

Family 4 already names routes, grants, exclusions, bypasses and selection, but only its registry exists. Enrollment supplies the canonical CBOR and independent fixture-consumer pattern. M6 owns ServiceRef, Id and Identity. The node mapping requires /96 plus the real IPv4 prefix length and exact low network bits; local egress bindings stay outside control payloads.

## Proposal

Specify a complete recipient-scoped Subnet route publication. Embed canonical M6 ServiceRef bytes, reuse M6 identifiers and full identities, and validate family-neutral prefixes without runtime effects. Distinguish default and explicit selection; subtract exclusions into a canonical CIDR set while retaining bypasses separately. Advertise TCP, UDP and echo only for nonempty selected real IPv4 routes. Add independent Python vectors and direct Rust consumers before the pure implementation. Extend Q14 with the candidate and request independent NSD producer vectors.

## Risks

Prefix subtraction must handle /0, host prefixes and both address widths without shift overflow. A family-neutral schema must not imply native IPv6 Internet Exit. Empty complete publications must remain distinct from missing or malformed input. Nested routes retain separate stable resource identities; this contract does not choose a runtime route winner.

## Scope

The Subnet module, its producer and consumer test, additive account exports and producer registration, generated account fixture, Subnet specification section and Q14, and the one-way proto dependency with its generated lockfile edge. Registry bytes and existing vectors remain unchanged. Grants, payer and incarnation are separate contracts.

## Alternatives

Duplicating M6 references or importing runtime route structures would create divergent contracts. The publication instead embeds the original M6 canonical reference bytes and contains no local host binding.

## Verification

Establish a failing consumer before implementation; run format and lint checks, the fixture consumers, vector regeneration checks and the prescribed self-check. Compare existing fixture blocks against the base and verify the lockfile adds only the service-control dependency edge.
