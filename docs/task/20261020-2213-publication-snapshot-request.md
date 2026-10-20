# Publication snapshot poll request

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-20 22:13

## Description

Specify and validate independently polled publication requests and correlated existing snapshots. Independent vectors cover accepted requests, malformed bytes and mismatched responses without runtime or I/O.

## Investigation

The predecessor poll carries only stream_session; its response is a realm collection of signed events. The candidate replaces realm-only addressing with exact issuer/recipient/realm/scope entries, retains restart and attempt meaning and uses existing signed publication snapshots. Producer confirmation remains outstanding.

## Acceptance

Run publication_snapshot_request_vectors and the scoped self-check, preserving canonical bytes and per-key snapshot acceptance.

## Notes

Specification and independent vectors precede the pure implementation.

## Acceptance results

- The first consumer build failed with unresolved snapshot request module and
  operation imports, establishing that the requested API was absent.
- publication_snapshot_request_vectors passes with independently generated
  canonical bytes, signed request/response input, malformed requests, stream
  selectors, unknown fields, nonminimal bytes and mismatched response refusals.
- Accepted responses expose the existing PublicationSnapshot and its per-key
  decisions; retained equal versions still refuse replay. An empty snapshot
  preserves absence instead of manufacturing withdrawal.
- The focused consumer passed twice after implementation. Formatting and lint
  passed before the final test runs. The scoped self-check passed again after
  documenting predecessor retirements: 480 tests passed with none skipped,
  API compatibility required no version update, and doctests/documentation passed.
- Local diff review covered all changed contracts, producer, consumer and docs;
  no remaining correctness findings were identified.

## Remaining inputs

NSD confirmation of exact scope authorization, active subscription association,
response nonce echo and independent producer vectors remains outstanding.
