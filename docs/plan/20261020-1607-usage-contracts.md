# feat: service and relay usage contracts

- **status**: implementing
- **createdAt**: 2026-10-20 16:07
- **approvedAt**: 2026-10-20 16:07
- **relatedTask**: 20261020-1607-usage-contracts

## Context

ServiceUsage currently encodes a validated 32-byte identity subject. Grants
already carry the 16-byte realm-local UserId. Reports and relay units have no
shared implementation. Historical attribution must survive delayed delivery.

## Proposal

Replace the service subject with raw 16-byte ULID bytes, retaining the version
and nine-field tuple. Specify and independently produce relay units, bounded
report parts and correlated acknowledgement/error bytes before implementing
pure validation. Reuse M6 references and existing incarnation/roster types.
Compare historical grants and captured roster generations without reading time
or resolving current ownership. Keep delivery and persistence in consumers.

## Risks

The subject change is incompatible with predecessor candidate bytes. No fallback
is permitted. Echo byte completion needs consumer adaptation because the current
neutral recorder exposes echo message counts. Fixtures do not establish live
NSD historical ownership or released producer interoperability.

## Scope

Account usage codecs, independent Python fixtures and Rust consumers, profile
and review-request updates. Shared indexes and changelog are composed separately.

## Alternatives

Identity conversion and a tagged compatibility union are excluded: neither
preserves the exact historical realm-local payer assignment.
