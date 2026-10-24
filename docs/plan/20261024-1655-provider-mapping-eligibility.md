# Provider mapping eligibility

- **status**: implementing
- **createdAt**: 2026-10-24 16:55
- **approvedAt**: 2026-10-24 16:55

## Context

Family 4 currently separates provider grants and client route snapshots. Neither carries an eligible mapping inventory. The existing source publication verifier supplies signatures, exact source and pending context checks, version tombstones and validity decisions. SubnetPrefix already owns canonical network alignment.

## Proposal

Specify the separate provider-mappings snapshot before generating independent consumer bytes. Add a bounded typed inventory codec reusing SubnetPrefix, register its replacement rule, and extend source and membership validation. Exercise populated, replacement and empty inventories with authenticated refusal cases. Preserve existing report, grant and route bytes.

## Risks

Decoded inventories alone convey no authority. Installation requires source decisions and independent membership context. Empty inventories affect only their exact collection.

## Scope

Pure proto contracts, independent vector producers and consumer tests, profile, public-edge specification, review request and candidate handoff.

## Alternatives

Embedding mappings in grants would couple independent authority collections and alter existing bytes; retain a separate kind.
