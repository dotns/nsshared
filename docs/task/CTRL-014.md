# CTRL-014 nsc cold-registration over the fallback list

- **status**: todo
- **priority**: P3
- **owner**: unassigned
- **createdAt**: 2026-06-20

## Description

Follow-up to PLAN-009 (ratified amendment / known-limitation, M ruling #5).
**NOT in PLAN-009 scope** — tracked as a candidate task.

nsc performs signed info discovery and first-run REGISTRATION via
`primary_nsd_url` (primary-only) BEFORE constructing `ControlPlane`. So a COLD
node whose primary transport is already blocked/down cannot complete first-ever
registration via the ordered fallback — it fails before reaching S1's
`ControlPlane` fallback. PLAN-009's core resilience property (a REGISTERED node's
auth / services_report / config_stream falling back over the ordered list) is
covered by S1; only cold-registration-during-primary-outage is out of scope.

Proposed scope (when scheduled):

- Route nsc's pre-`ControlPlane` info-discovery + first-run registration through
  the ordered control_centers list (per-endpoint attempt + fallback), not just
  `primary_nsd_url`, so a cold node can register over a surviving fallback
  endpoint.

## Dependencies

- **related**: PLAN-009 (CTRL-011 ordered fallback), ns CTRL-013 (S3), S4 E2E
  (records this as a known_limitation).
