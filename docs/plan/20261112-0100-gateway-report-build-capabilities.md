# 20261112-0100-gateway-report-build-capabilities Gateway report build capabilities

- **status**: completed
- **createdAt**: 2026-11-12 01:00
- **approvedAt**: 2026-11-12 01:00
- **relatedTask**: 20261112-0100-gateway-report-build-capabilities

## Context

NSD's health inventory shows each gateway's source revision from `GatewayReport.source_revision`. Gateways also have a compile-time capability version and feature token list, which NSD cannot receive: `GatewayReport` is a fixed 14-element schema-2 array.

## Proposal

Add `BuildCapabilities { capability_version, features }` and an optional `GatewayReport.build_capabilities`. `None` encodes the unchanged schema-2 bytes; `Some` encodes schema 3, the schema-2 elements with tag 3 plus a trailing `[capability_version, features]`. Decode accepts exactly these two forms. Validate a positive version, at most 32 strictly ascending tokens of at most 64 bytes in the `<area>.<name>.v<N>` grammar. Release as 0.13.0.

## Risks

Receivers built before 0.13.0 (including NSD on 0.9.0-0.12.0) refuse schema 3, so senders must wait for receiver upgrades. The values are observations and must not gate behaviour.

## Scope

nsshared control report codec, independent vectors, spec and version. NSD stores and shows the values and nsgw sends them in separate pull requests.

## Alternatives

Flat optional slots in schema 2 would change the meaning of existing bytes within one schema, which the wire policy forbids.

## Annotations

Owner-approved 2026-11-12: NSD `/v1/health` shows each gateway's and relay's capability version and features.
