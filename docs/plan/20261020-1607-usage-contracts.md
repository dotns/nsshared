# feat: service and relay usage contracts

- **status**: completed
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

## Acceptance

The independent usage fixture contains 77 cases across grants, service units,
relay units, report parts and answers. `service_usage_vectors` validates the
exact realm/UserId pair, both directions, partial completion, UDP, echo and
public-ingress units, unset versus measured-zero loss windows, and historical
grant mismatch across two realms sharing the same UserId. `relay_usage_vectors`
validates both gateway endpoint positions and directions, original roster scope
and epoch, delayed attribution and typed unknown-mapping repair.
`usage_report_vectors` and `usage_answer_vectors` validate committed ownership,
multipart sequences, exact duplicate acceptance, changed duplicate refusal,
tri-state watermarks, permanent rejection and correlated mapping repair.

The initial `service_usage_vectors` run failed with `StringLength { expected:
32, actual: 16 }`, proving the predecessor rejected the revised subject.
After implementation, the focused account and usage suites passed 11 tests.
The final `just self-check feat/l8-account-profile` at
`e01471b92fc860dee8b4c2bb05efb7a597abce05` selected full QA: 439 tests passed,
zero skipped, one doctest passed, and formatting, lint, dependency policy,
unused dependencies, spelling, both vector generators, semver and strict
rustdoc all passed. Local review found no unresolved correctness findings.
Only the completion records change after this checked source revision.

The boundary difference adds pure account contracts and consumers without new
dependencies, transport, runtime, persistence or retry logic. Existing service
fixture bytes migrate with the exact predecessor and implementation revisions
recorded in the review request. Producer fixtures remain candidate authority;
NSD history/producer delivery and gateway echo byte instrumentation remain
consumer obligations before adoption.
