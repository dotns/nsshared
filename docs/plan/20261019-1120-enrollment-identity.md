# Enrollment and membership identity

- **status**: implementing
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
