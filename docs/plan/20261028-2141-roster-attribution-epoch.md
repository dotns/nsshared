# Separate roster attribution epochs

- **status**: implementing
- **createdAt**: 2026-10-28 21:41
- **approvedAt**: 2026-10-28 21:41

## Context

Signed rosters currently encode one version as both publication and billing epoch. Both decoding paths assume seven fields; verification persists only the publication floor.

## Proposal

Preserve schema 1 exactly with attribution epoch equal to version. Add schema 2 with an explicit positive attribution epoch and preserve the schema on decode/re-encode. Require independent publication and epoch floors in both verification APIs. Expose the authenticated epoch in participant generations and document producer and consumer custody. Add independent signed vectors and regression tests.

## Risks

The unstable-account Rust API changes: constructors supply schema and epoch, and verification callers supply the persisted epoch floor. Released default-feature APIs remain unchanged. Schema 1 signatures must remain byte-identical.

## Scope

Relay roster contracts, usage terminology, account tests, independent vectors and account specifications.

## Alternatives

Inferring the epoch from publication version cannot represent unchanged membership renewal. Keeping a verification overload without an epoch floor would permit rollback.
