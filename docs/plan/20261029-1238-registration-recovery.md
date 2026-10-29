# Exact registration recovery

- **status**: completed
- **createdAt**: 2026-10-29 12:38
- **approvedAt**: 2026-10-29 12:38
- **relatedTask**: 20261029-1238-registration-recovery

## Context

Registration acceptance comparison currently verifies a BootstrapEnvelope and its original pending nonce. Historical receipt recovery uses an independently authenticated legacy named-field carrier, so it must verify the stored source signature without correlating it to the new transport nonce. Existing source enrollment expectations lack exact contribution and custody floors.

## Proposal

Add a versioned pure query context and original acceptance attachment. Compare operation, membership and SHA-256 canonical request digest with retained inputs. Share enrollment, profile and lifecycle comparison with ordinary registration. Require an independently retained exact source tuple and epoch/generation floors. Keep source signature verification independent of receipt transport.

## Risks

A caller that derives expectations from a response cannot establish trust. Historical acceptance does not establish current authority. Original registration encodings and exports must remain compatible.

## Scope

Control exchange and recovery contracts, independent Python vectors, Rust validation tests and account specification.

## Alternatives

Reusing the original BootstrapEnvelope verifier incorrectly requires the historical transport correlation. Re-signing a current source loses the original committed result.

## Annotations

Implementation is authorized. Existing named-field receipt transport, persistence, issuer pinning and current-authority observations remain consumer responsibilities.

## Verification

Implemented the proposal without changing legacy registration encodings, receipt transport, dependencies or mutable state. Shared lifecycle comparisons and exact caller-provided source expectations are used by recovery. Independent vectors preserve original source signatures across fresh query correlations. The existing self-check passed on `6a5ea834642f4f7a9574f8849418fb273beffa41`, including vectors, default-feature compatibility, 70 script tests and both nextest feature sets (421 and 581 passing tests). Only completion records changed afterward.
