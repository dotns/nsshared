# 20261109-0813-network-node-record Network-scoped signed NodeRecord

- **status**: implementing
- **createdAt**: 2026-11-09 08:13
- **approvedAt**: 2026-11-09 08:12
- **relatedTask**: 20261109-0813-network-node-record

## Context

Quick's v2 NodeRecord has one Node ID and at most four relay IDs. Its existing registry key is the Node ID. Account currently reuses this record and one runtime across all Networks in an NSD membership. Different Network relay sets therefore overwrite one another in that registry and cannot be safely merged.

## Proposal

Add a canonical Account-only envelope containing a Network ID, an existing verified NodeRecord, and a separate Ed25519 signature under the same Node identity over a domain-separated message that includes the exact Network ID and inner bytes. Keep the Quick record unchanged. Require Network ID as part of the eventual Account registry lookup key and authorization scope. Reject cross-Network replay, signature mismatch, invalid inner records, and oversized encodings. Test distinct records for the same Node in two Networks.

## Risks

The envelope alone does not change the registry key or authorize a session. NS, NSD, and NSGW must migrate together before deployment. Never publish an Account envelope through the unscoped Quick registry.

## Scope

Shared signed-record format and validation only. Account storage, transport, registry API, and multi-membership admission belong to follow-on integrations.

## Annotations

- 2026-11-09 08:18 UTC: RED compile failed on the missing NetworkNodeRecord API. GREEN: two adversarial tests plus 104 existing identity tests pass. Strict Clippy passes for nsshared-identity and nsshared-proto. This shared type is not deployed until the Account registry and consumer contracts are scoped by Network.
