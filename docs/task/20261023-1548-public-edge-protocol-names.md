# Protocol-specific public-edge names

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-23 15:48

## Description

Require HTTP hostnames and unnamed TCP/UDP routes without changing listener conflicts or HTTP bytes.

## ActiveForm

Validating protocol-specific public-edge names.

## Notes

Investigation and approved implementation are recorded in the matching plan. Independent fixtures precede the codec change. Producer adoption remains outstanding.

## Acceptance results

Implementation and documentation are complete. The independent
`public_edge_protocol_names` test first failed because decoding the valid null
raw name returned `Cbor(UnexpectedType)`. After implementation all 17 focused
public-edge, cross-realm listener and anonymous-selector tests passed with zero
skips. Formatting and workspace lint passed. Generator verification reports all
34 fixture files current. Direct comparison against the previous producer
confirms all 37 HTTP-only fixtures keep their exact bytes.

The initial repository self-check stopped at dependency auditing: Tokio 1.53.2
was affected by RUSTSEC-2026-0386 (`AsyncFd::new` and related constructors violate
I/O safety). That run failed before acceptance could complete. Its failure
remains part of the validation history.

Existing raw fixtures and their derived realm-membership publications now use
null. The realm-local hostname/material fixture uses HTTP with distinct ports
to preserve its original ownership assertion. The cross-realm TCP listener test
clears the copied HTTP name collections so isolated inputs remain valid.
Producer adoption remains outstanding. No runtime or compatibility path was added.

## Completed validation

The upstream dependency repair updates Tokio to 1.54.1. Synchronizing it required
no independent lockfile, manifest, advisory-policy or product changes. The full
`just self-check feat/l8-account-profile` passed on
`e9dd42ec839717e21d1dc08d1eed8b4e8b2fdcdb`: formatting, workspace lint,
dependency audit, dependency usage, spelling, independent vector regeneration,
API compatibility, selection tests, 537 tests with zero skips, doctests and
warning-free documentation all passed. The initial advisory failure is retained
above. Acceptance is complete; real producer adoption remains outstanding.
