# L8 candidate review request

- **status**: implementing
- **createdAt**: 2026-10-19 02:03
- **approvedAt**: 2026-10-19 02:03
- **relatedTask**: [L8 candidate review request](../task/20261019-0203-l8-candidate-review-request.md)

## Context

The published candidate is `41149fe1febf2ecee07f077d68a500e18822442c`.
The specification and account vectors define the registry, lifecycle, normalized
L3 rules, service usage unit and two roster carriers. All eleven registry rows
exist, but full family payload contracts and independent NSD producer vectors
remain open. The existing request describes the producer responsibilities;
the gateway inventory at `51c278cdc63c:docs/design/v1-consumers.md` supplies
consumer counts and exact M6 reuse. The private `valid_service_label` function
in `nsshared-service-control/src/snapshot.rs` is not callable by other families.

## Proposal

Prepare one forwardable request with immutable candidate references, family
states, inventory ownership counts, exact M6 reuse, independently answerable
questions and requested M6 API/vector changes. Link it from the specification.
Give every question and change a prepared disposition with no claimed delivery
or answer. Keep NSD producer vectors and implementation independently owned.

## Risks

Registry entries and candidate fixtures can be mistaken for finished family
schemas or NSD conformance. State their limits explicitly. Historical roster
attribution must retain the original scope/version after roster replacement.
M6 API and vector changes require agreement with its contract owner.

## Scope

The request, its specification link and these two detail records. No runtime,
codec, fixture, M6 implementation or external repository changes.

## Alternatives

A short forwarding note omits independent questions and disposition tracking.
Changing M6 now would preempt agreement on the required public API and vectors.

## Acceptance

Check request completeness before and after writing it, then run formatting,
lint and the scoped self-check. Completion means a prepared request, not
approval, delivery, NSD producer vectors or implementation.
