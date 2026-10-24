# Provider mapping eligibility

- **status**: completed
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

## Acceptance results

- `provider_mapping_replacement` initially failed because the new kind had no Snapshot registration (`left: None`, `right: Some(Snapshot)`).
- Independent fixture authorities now verify populated and replacement sets, typed empty and authenticated carrier withdrawal, collection isolation, wrong recipient/kind/channel/Network/current source, and malformed inventory refusal.
- `provider_mapping_codec_bounds` verifies canonical round trips, maximum ids, the 256-entry boundary, invalid construction and the payload ceiling.
- Existing provider report and grant/client-route vector files are unchanged relative to the implementation base.
- `just fmt` and `just lint` passed before focused tests. Both new tests and `subnet_publication_views` passed.
- `just self-check` passed with all static, vector, API compatibility, selected test, doctest and documentation checks. The checked code and contract documentation revision is `e85d193b0e41903f71759ff961abfbffa4a92ba7`; only these acceptance records changed afterward.
- External publication and activation adoption remain outstanding; the contract adds no runtime or gateway inventory consumer.
