# Enrollment and membership identity

- **status**: completed
- **createdAt**: 2026-10-19 11:20
- **approvedAt**: 2026-10-19 11:20
- **relatedTask**: 20261019-1120-enrollment-identity

## Context

The family registry fixes enrollment at identifier 1. NodeBinding and Lifecycle
already distinguish identity replacement from stable-identity key rotation.
The consumer vectors currently check derived identifiers only against each other.
Ordinary membership derivation uses a u32 version and one WireGuard key per version;
Quick derives a separate key per generation. Accepted registration is the durable
boundary for a staged identity replacement.

## Proposal

Specify enrollment bytes and capability bounds before adding the pure type.
Reuse NodeBinding and Lifecycle, refuse unlinked or lower bindings, and require
explicit producer-profile authorization for stable-identity rebinds. Generate
expected NodeId and address values independently in Python and consume named
acceptance and refusal vectors directly in Rust.

## Risks

Endpoint forms, same-key record refresh, signed key generation and version width
still require producer confirmation. The candidate adds no runtime policy or
implicit conversion between membership and Quick profiles.

## Scope

Enrollment specification, review questions, account module, independent producer,
consumer vectors, and these implementation records. Registry bytes stay fixed.

## Alternatives

A new binding or transition vocabulary would duplicate existing contracts;
reuse the existing lifecycle and leave unresolved producer semantics explicit.

## Validation

Focused failing test, format and lint checks, independent fixture comparison,
and the repository self-check.

## Results

Enrollment uses the existing NodeBinding and Lifecycle without changing registry
bytes. Capabilities are bounded opaque canonical sets. Binding acceptance is pure,
and stable-identity rebind requires explicit producer-profile authorization.
Q07 and Q11 retain prepared questions about producer semantics and identifiers.

The independent producer adds 29 enrollment vectors. Every presented, accepted,
and lifecycle before/after identity has independently derived NodeId, N6 and N4
expectations. The existing account fixture is an unchanged prefix of the result.

The first consumer test failed with `missing independent consumer vector:
enrollment-accepted`. A later focused run exposed a malformed mismatch vector
whose before and after K were equal; using a different accepted generation made
it a valid lifecycle with a mismatched origin, as intended.

The focused account and enrollment suites passed all nine tests. Format, workspace
lint, independent fixture comparison, semantic compatibility, all 405 workspace
tests (zero skipped), doctests and documentation checks passed. The final code
and fixture tree was checked at `a330e1327772cc9b6a68a71df1ca1b5f6df97fbd`.
The code review found no remaining correctness findings.
