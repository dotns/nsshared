# Complete realm publication payloads

- **status**: completed
- **createdAt**: 2026-10-20 16:20
- **approvedAt**: 2026-10-20 16:20

## Context

The registry and signed publication envelope already assign realm-peers to snapshots
and policy-version to streams, but neither content contract has a pure codec.
NodeBinding provides membership identity version and record generation; NodeRecord
already verifies the signing identity and transport key. Membership is independent
of L3 permissions. Publication decisions leave content validation to the consumer.

## Proposal

Specify canonical complete realm contributions and a diagnostic counter first.
Reuse NodeBinding and signed NodeRecord, refusing inconsistent bindings and global
identity/key duplication. Add independent Python fixtures and Rust consumer tests
for complete replacement and durable publication version tombstones. Keep enclosing
authority exclusively in the signed publication key. Update review questions and
explicitly retire gateway device configuration fields.

## Scope and risks

Pure contracts, independent vectors and documentation only. No runtime, persistence
implementation or new M6 objects. Consumers must validate content before atomically
committing publication versions; malformed content must not renew freshness.

## Acceptance

Completed: independent realm publication fixtures contain 47 cases, including
binding/signature/ordering/size refusals and policy observation cases. The four
consumer tests pass, including realm_membership_replacement and restored version
tombstones. Format and workspace lint pass. `just self-check feat/l8-account-profile`
passes with 438 tests passed and zero skipped, plus doctests, documentation,
vectors, dependency checks and API compatibility. The consumer tests use configured
issuer/recipient identities and an exact publication key independent of input.

## Remaining external requirements

NSD producer confirmation and independently owned producer vectors are outstanding.
The delivered candidate does not imply producer agreement.
