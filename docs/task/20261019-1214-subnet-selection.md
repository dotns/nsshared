# Subnet route selection contract

- **status**: completed
- **priority**: P1
- **owner**: subnet-selection
- **createdAt**: 2026-10-19 12:14

## Description

Specify and validate family 4 route selection with stable M6 references, exact real/mapped prefixes, provider/client identities, exclusions, distinct bypasses, explicit/default selection and explicit proxy coverage. Cover accepted and typed refused publications with independently computed Python fixture outputs. Complete empty publication withdraws routes; missing and malformed input fail.

## ActiveForm

Completed the Subnet selection contract and independent consumer validation.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation and implementation approach are recorded in the matching plan. Only the generated proto-to-service-control edge may change in Cargo.lock. No runtime, host binding, grant or payer behavior is included.

## Acceptance results

- `subnet_selection_vectors` consumes 52 independent fixture cases: 15 accepted and 37 refused. It compares each decision and canonical byte string, every accepted route and scope field, selected CIDR cover and explicit TCP/UDP/echo coverage. Refused publications produce no selected output.
- `subnet_selection_refusals` checks named typed failures for mapping mismatch, outside/overlapping prefixes, ordering and duplicates, misalignment/length, mixed/default selection, unknown discriminants, missing/truncated publications and trailing/nonminimal encodings.
- `subnet_constructed_contracts` confirms encoding and selection reject invalid constructed contracts and oversized input. IPv4/IPv6 /0 and host-prefix subtraction, empty withdrawal/selection, full exclusion, sibling coalescing and count boundaries are fixture-fed acceptance cases.
- `SubnetRoute` and `SelectedSubnetRoute` contain no interface, local source address or host port. M6 ServiceRef bytes use the original M6 codec. Existing 79 account vectors retain their names and field bytes; registry bytes have no change. Cargo.lock adds only the proto-to-service-control dependency edge.
- The initial consumer run failed with `E0432` because the Subnet API did not exist. A subsequent run exposed an invalid test assumption: zero bytes encode an Ed25519 point. The refusal sample now uses y=2, independently checked to have no square root in the Ed25519 curve equation; existing identity validation remains authoritative.
- Focused account, enrollment and Subnet tests: 12 passed. Format and lint passed before the successful focused run. The self-check on implementation commit `3b93b9bd26e206ac9c0d4fc68f6b49b30ef317c0` passed all static checks, independent vector checks, API compatibility, 10 check-selection tests, 408 workspace tests with zero skips, doctests and warning-free documentation. Only these completion records changed afterward.
- Q14 remains prepared and requests independently owned NSD producer vectors. Candidate fixtures do not establish live interoperability or producer approval.
