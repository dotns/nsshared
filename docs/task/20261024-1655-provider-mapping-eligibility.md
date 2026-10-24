# Provider mapping eligibility

- **status**: in_progress
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

## Validate inventory before actions

Investigation found that the common decision validates profile, grant and route
payloads but omits the mapping decoder. Source events and both snapshot forms
inherit that omission. The approved correction adds mapping validation alongside
the existing typed checks, before any action is exposed. Independent tests will
inspect decisions directly and exercise atomic mixed snapshot refusal through
plain, source, scoped and correlated response entry points. Existing membership,
source and legitimate empty behavior remain unchanged.

## Publication entry point inspection

`PublicationEvent` has four typed payload decoder entry points: profiles, grants,
client routes and provider mappings. The common decision already called the first
three; it now also calls the mapping decoder before exposing any action.
`source_publication.rs` delegates single events to that decision and rejects an
entire source/scoped snapshot on a refused event before returning its vector.
`publication_snapshot_request.rs` authenticates and correlates the response before
delegating to the scoped snapshot. Plain snapshot validation checks every decision
before constructing the iterator, which delegates to the same common decision.
`account.rs` only reexports these APIs. Public-edge M6 snapshot joins, local roster
snapshot validation and service-control M6 SnapshotPush validate different typed
contracts and expose no mapping publication action. No additional omission was found.

The imported `mapping_actions_require_a_well_formed_inventory` test is retained
unchanged, including its valid populated control and direct refusal assertions.
`provider_mapping_replacement` now inspects returned actions before membership
validation, retaining the distinct wrong-Network membership refusal. New independent
`provider-mapping-actions.vec` cases keep a valid adjacent Exit grant and verify
whole-response refusal for malformed inventories through every snapshot entry point.
