# Node heartbeat observations

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-28 03:09

## Description

Carry optional UDP reachability, identity-keyed pair snapshots and gateway RTT observations in the Node heartbeat contract, preserving old payloads and exact receipt correlation.

## Acceptance

Independent vectors cover present, absent and empty fields, all RTT tiers, invalid runtime, ordering, duplicates, identities and bounds. Account tests, vector verification, default API compatibility and the scoped self-check pass.

## Notes

Investigation and approved implementation design are recorded in [the plan](../plan/20261028-0309-node-heartbeat-observations.md).

## Results

- `node_heartbeat_observation_vectors_roundtrip` initially failed with `udp-true: array of 7 items, expected 4`, establishing the missing decoder behavior before implementation.
- All six Node liveness tests pass, including direct field assertions, exact response correlation and typed in-memory and wire refusals. Independent vectors cover all tiers, omitted and empty fields, full-key validation, zero and maximum u64 counters, the 256-entry limit and refusal at 257 entries.
- Existing Node liveness vectors remain byte-identical; new cases are appended.
- Formatting and both lint configurations pass. The complete `just self-check` passes, including `just vectors-check` (45 fixture files), `just semver`, 413 default-feature tests and 559 tests with the account feature, documentation and migration checks. Both test configurations report zero skipped tests.
- Local review found no remaining correctness or compatibility defects within the changed contract. The unstable request struct gains three fields; stable default-feature APIs and gateway heartbeat bytes remain unchanged.
