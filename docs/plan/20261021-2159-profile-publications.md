# 20261021-2159-profile-publications Profile publications

- **status**: completed
- **createdAt**: 2026-10-21 21:59
- **approvedAt**: 2026-10-21 21:59
- **relatedTask**: 20261021-2159-profile-publications

## Context

Both profile kinds already own the stream channel, but publication payloads remain opaque. UsageProfile owns the two existing quantity identifiers. MembershipScope uses two fixed 16-byte identifiers with no additional validity predicate.

## Proposal

Specify exact DTO signatures and independently generated canonical payload and signed publication bytes first. Add strict pure codecs, independent reporter/membership comparisons, and typed publication mapping. Reject malformed catalogues before exposing replacement. Preserve explicit empty withdrawal and existing quantity/control bytes.

## Risks

Malformed payloads must not advance versions. Decoding cannot establish membership authority; consumers must compare independently accepted membership before committing any replacement.

## Scope

Protocol account module, independent vector producer and consumer, payload/usage/review documentation.

## Alternatives

Opaque profile acceptance cannot validate the catalogue contract. Existing quantity and control types remain the sole definitions.

## Acceptance

The exact payload specification and independent canonical signed fixtures preceded
the codecs. Public types reuse UsageProfile and MembershipScope; malformed
catalogues refuse before publication replacement. Context comparison remains
independent of decoding. Existing report/ACK and control message bytes are unchanged.

`just self-check` passed all static checks, API compatibility, 503 tests with zero
skips, doctests and documentation build. The three new profile tests cover 5 valid
payloads, 39 malformed payloads, size refusal, reporter/membership mismatches and
source-bound replacement/withdrawal/replay decisions. Static review covered the
complete change with no outstanding findings. Gateway durable restart and
historical state preservation remain consumer acceptance obligations.
