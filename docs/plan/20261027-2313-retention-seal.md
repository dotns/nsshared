# Retention seal and acknowledgement

- **status**: completed
- **createdAt**: 2026-10-27 23:13
- **approvedAt**: 2026-10-27 23:13
- **relatedTask**: 20261027-2313-retention-seal

## Context

Usage reports use family 9 kinds 0 and 1 with arity 12; usage answers have arity 8.
Participant REPORT and ANSWER frames already accept bounded opaque contracts.
Roster scope supplies the issuer and recipient; reporter incarnations identify
immutable usage parts. All account contracts remain feature-gated.

## Proposal

Add a bounded canonical retention seal using family 9 kind 2 and arity 8,
and its acknowledgement using family 9 kind 3 and arity 9. Include issuer,
recipient, positive custody generation and roster epoch, and strictly ordered
part references. Hash the complete seal through a distinct domain_digest domain.
Compare authenticated scope and expected generation explicitly. Exact replay is
idempotent; changed content under the same identity is a conflict. Acknowledgements
echo identity and digest, with committed and explicit refusal outcomes.

Add independent Python vectors, Rust round-trip and rejection tests, and protocol
specification updates. Keep session framing and control usage carriers unchanged.

## Risks

A seal declares complete durable custody closure; the pure contract cannot prove
that closure or persistence. Callers must verify retained history and committed
receipts. Oversized manifests fail closed and never authorize partial coverage.

## Scope

Usage contracts, digest domain, participant frame documentation, independent
vectors, account tests and account specifications.

## Alternatives

Reusing usage report or answer semantics would conflate quantity acceptance with
custody closure. Distinct payload tags preserve their existing interpretation.

## Results

Implemented the distinct canonical seal and acknowledgement, strict bounds and
identity correlation, dedicated content digest, independent fixture and protocol
documentation. Focused tests and the complete selected self-check passed. The
existing participant frame enum and default-feature public surface are preserved.
