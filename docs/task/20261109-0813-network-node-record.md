# 20261109-0813-network-node-record Network-scoped signed NodeRecord

- **status**: in_progress
- **priority**: P1
- **owner**: root/relay-implementation-20261109
- **createdAt**: 2026-11-09 08:13

## Description

Define an independently signed, Network-bound Account NodeRecord without changing Quick's NodeRecord format. Reject cross-Network substitution and noncanonical or expired inner records. This is the shared protocol foundation for per-Network registration, publication, and peer path selection.

## ActiveForm

The Account-only signed envelope, deterministic per-Network identity derivation, and root-signed proof binding one derived identity to one Network are implemented. Four Network-record/proof tests pass. NS, NSD, and NSGW integration remains open, including active root membership authorization, durable binding, and same-relay Node ID collision rejection.

## Dependencies

- **blocks**: Account per-Network registry key and client publication contract
