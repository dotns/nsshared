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

## Extension investigation

A registry lookup returning None means an unknown pair, not stream ownership.
The poll predicate rejects such pairs before the existing authenticated snapshot
validator can return UnknownKind. Preserve exact scope, recipient, correlation,
signed channel and signature checks while correcting this predicate. The
snapshot_unknown_events_preserve_known_updates tests demonstrate both failures
with authenticated mixed snapshots, successful known-only snapshots and refused
corrupted envelope signatures.

## Extension acceptance results

- The first run of snapshot_unknown_events_preserve_known_updates failed both
  mixed-snapshot tests with Err(Channel). The known-only and corrupted-envelope
  controls were retained unchanged. The independent mixed-unknown-kind-accepted
  fixture also failed before implementation.
- The boundary now distinguishes None from Some(Stream), retaining declared
  snapshot-channel and pending-request checks. Unknown items reach the existing
  authenticated UnknownKind decision without discarding adjacent known updates.
- Fourteen independent mixed-event cases cover unknown kinds/families and inner
  signature, declared channel, known stream ownership, scope, recipient and
  correlation refusals. The consumer checks exact Replace/UnknownKind decisions,
  event contents, typed errors and retained known-key replay refusal.
- Formatting and lint passed before the focused tests. The focused publication
  decoder, poll vectors and mixed-snapshot tests passed. The complete scoped
  self-check passed: 482 tests, none skipped, compatible APIs, matching vectors,
  passing doctests and documentation.
- All registry lookup and UnknownKind sites were inspected: the public re-export,
  ownership registry, authenticated publication decision, snapshot decision
  collection, poll filter, decoder-vector action/state handling and both poll
  test consumers. Only the poll filter required a production change. No
  out-of-scope defects were found.
