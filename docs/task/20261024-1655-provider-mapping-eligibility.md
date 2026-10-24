# Provider mapping eligibility

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-24 16:55

## Description

Deliver a canonical provider mapping inventory with source-bound context verification and independent replacement vectors. Preserve report and grant/client-route encodings.

## Acceptance

Verify exact eligible sets through replacement and authenticated empty, refuse mismatched authority and malformed payloads, and retain independent collections.

## Notes

Investigation and approved implementation are described in the matching plan. Shared indexes and changelog are updated separately.

## Acceptance results

- `provider_mapping_replacement` initially failed because the new kind had no Snapshot registration (`left: None`, `right: Some(Snapshot)`).
- Independent fixture authorities now verify populated and replacement sets, typed empty and authenticated carrier withdrawal, collection isolation, wrong recipient/kind/channel/Network/current source, and malformed inventory refusal.
- `provider_mapping_codec_bounds` verifies canonical round trips, maximum ids, the 256-entry boundary, invalid construction and the payload ceiling.
- Existing provider report and grant/client-route vector files are unchanged relative to the implementation base.
- `just fmt` and `just lint` passed before focused tests. Both new tests and `subnet_publication_views` passed.
- `just self-check` passed with all static, vector, API compatibility, selected test, doctest and documentation checks. The checked code and contract documentation revision is `e85d193b0e41903f71759ff961abfbffa4a92ba7`; only these acceptance records changed afterward.
- External publication and activation adoption remain outstanding; the contract adds no runtime or gateway inventory consumer.
