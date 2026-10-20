# Service grant and Node authority contracts

- **status**: completed
- **priority**: P1
- **owner**: grant-authority
- **createdAt**: 2026-10-20 15:09

## Description

Complete service grants, explicit payer bindings, resource withdrawal and identity-to-key Node L3 authority with independent consumer vectors.

## ActiveForm

Completed the pure contracts and independent consumer validation.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Investigation, proposal and verification approach are in the matching plan.

## Acceptance results

- `grant_l3_consumer_vectors` consumes all 72 independent fixture cases, re-encodes accepted bytes exactly and matches typed refusals for every new family. The fixture includes malformed, truncated, nonminimal and tagged/wrong-width UserId forms.
- `grant_fields_and_subnet_selection` compares client/provider/resource, floor/name/protocol/port/alias generation, binary payer realm/UserId, incarnation and expiry, plus every Exit route field and independently computed selected CIDR output. Payer assignments match the full resource/client/incarnation context.
- `grant_denial_vectors` checks exact active-claim admission, unchanged survivors, selective removal, durable-history requirements, retired-token refusal and identical-content fresh regrant for both service families. Changed payer content cannot reuse an active token.
- `node_l3_exact_authority_boundaries` checks explicit I/K bindings, namespace/TCP/UDP/ports, missing membership/policy denial and selective namespace withdrawal without changing surviving policy or bindings. Policy interpretation is confined to the fixture consumer; the library exports types and validation only.
- `constructed_authority_refusals` checks cardinality, ordering, missing bindings and payload/collection bounds on constructed and encoded inputs.
- RED: the initial consumer failed with `E0432` because the new exports were absent. GREEN: 14 focused tests passed after format/lint. The self-check at `09dcebb0ad598287eb5477729853c33a4a0ff8ac` passed static checks, vector regeneration, API compatibility, 28 selection tests, 434 workspace tests with zero skips, doctests and warning-free documentation. Only these completion records changed afterward.
- The five new tests and all 72 cases are fixture-fed contract observations. Original account vectors, registry bytes, Cargo manifests and lockfile remain unchanged. Q09 and Q13–Q16 record outstanding NSD producer formats/vectors and owner confirmation; service usage retains its separately revised predecessor subject.
