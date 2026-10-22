# Confidential certificate and client-CA acquisition

- **status**: implementing
- **createdAt**: 2026-10-22 22:27
- **approvedAt**: 2026-10-22 22:27
- **relatedTask**: 20261022-2227-confidential-material

## Context

AuthConfigRequest already defines the required seven-field request but refuses
non-auth material. EdgeMaterialRef supplies exact kinds, references and positive
generations. PublicEdge supplies canonical hostname validation. BootstrapEnvelope
supplies the authenticated confidential carrier. Acquisition must remain separate
from installation status and from public references.

## Proposal

Specify a separate confidential_material module with EdgeMaterialRequest,
EdgeMaterialResponse, EdgeMaterialValues and EdgeMaterialError. Define exact
canonical tuples and validation boundaries before implementation. Generate
independent Python fixtures, establish a failing consumer test, implement pure
codecs and byte-exact pending-request validation, then run static and full
selected checks. Preserve all authentication and installation ACK bytes.

## Risks

Decoded values are not installation or route authority. Secrets must not appear
in Debug. Envelope custody, current dependencies, trust-domain comparison and
X.509 validation remain external and are documented explicitly.

## Scope

Protocol module and operation constant, independent fixture producer and consumer,
canonical specification, profile, review package and these records.

## Alternatives

Extending AuthConfigRequest would change its auth-only meaning. A separate pure
contract preserves that meaning without duplicating runtime behavior.

## Annotations

The specified wire format and boundaries are approved for implementation.
