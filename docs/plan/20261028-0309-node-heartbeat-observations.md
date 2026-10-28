# Node heartbeat observations

- **status**: completed
- **createdAt**: 2026-10-28 03:09
- **approvedAt**: 2026-10-28 03:09

## Context

Node heartbeat currently wraps process observations in a four-element tuple with membership and runtime custody. Its response already carries endpoint feature tokens and correlates scope, fence and request ID. Pair and RTT observations are missing.

## Proposal

Preserve the four-element tuple when all observations are absent. Otherwise encode seven elements, appending nullable UDP, pair snapshot and RTT fields. Reject a seven-element all-null alias. Use validated full identity keys, strictly ordered unique pair tuples and gateway entries, and a 256-item bound per list. Compare snapshot runtime with the request fence; leave revision freshness to consumers. Retain the response wire form and feature negotiation.

## Scope

Node report contracts and exports, independent vector producer and fixtures, account tests, and control specification.

## Risks

New struct fields require callers of the unstable API to supply omission explicitly. Old payloads retain their exact bytes. Malformed extensions must never become omission or an empty snapshot.

## Alternatives

A mandatory longer tuple would invalidate existing liveness payloads. Changing the shared gateway heartbeat would extend the wrong operation.

## Validation

Independent vectors establish failing decoding before implementation, then test byte-exact round trips, typed refusals, omission semantics and receipt correlation. Run formatting and lint before tests, then the complete scoped self-check.

## Results

- `node_heartbeat_observation_vectors_roundtrip` initially failed with `udp-true: array of 7 items, expected 4`, establishing the missing decoder behavior before implementation.
- All six Node liveness tests pass, including direct field assertions, exact response correlation and typed in-memory and wire refusals. Independent vectors cover all tiers, omitted and empty fields, full-key validation, zero and maximum u64 counters, the 256-entry limit and refusal at 257 entries.
- Existing Node liveness vectors remain byte-identical; new cases are appended.
- Formatting and both lint configurations pass. The complete `just self-check` passes, including `just vectors-check` (45 fixture files), `just semver`, 413 default-feature tests and 559 tests with the account feature, documentation and migration checks. Both test configurations report zero skipped tests.
- Local review found no remaining correctness or compatibility defects within the changed contract. The unstable request struct gains three fields; stable default-feature APIs and gateway heartbeat bytes remain unchanged.
