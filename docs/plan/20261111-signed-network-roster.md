# Signed Network scope in participant rosters

- **status**: implementing
- **createdAt**: 2026-11-11
- **relatedTask**: 20261111-signed-network-roster

## Context

Production participants receive only a signed NSD roster. Its schema 2 entries contain identity and class, so the Account Network registry cannot establish Network authority. Local snapshot tests did not cover this path.

## Proposal

Add schema 3 entries `(identity, class, Network)` to the signed canonical roster. Require exactly one Network on every schema 3 entry and preserve strict legacy decoding. Verify that changing the Network invalidates the signature. NSD must publish schema 3 from its scoped provenance; NSGW must use the verified generation for registry and DATA admission. Deploy the updated NSGW reader before NSD begins publishing schema 3.

## Risks and acceptance

An old participant rejects schema 3, so rollout order is mandatory. Legacy rosters remain usable for existing forwarding but grant no Network registry authority. Accept only when signed scope round trips, tampering fails, and production participant integration passes same-Network and cross-Network tests.

Local snapshot schema 4 must also preserve distinct `(identity, Network)` grants for a gateway shared by multiple Networks. Repeated pairs or inconsistent class and admission history for one identity remain invalid; the NSGW local reader must authorize from the full set.
