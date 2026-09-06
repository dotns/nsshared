# COMPAT-001 Restore relay interoperability with current NS nodes

- **status**: completed
- **priority**: P0
- **owner**: local
- **createdAt**: 2026-09-06
- **relatedPlan**: [NSD PLAN-133](../../../nsd/docs/plan/PLAN-133.md)

## Description

Implement the approved cross-repository relay compatibility repair. Preserve
existing node addresses and the NS device-key index contract while retaining
canonical pair ownership, conflict rejection, and atomic route admission.

## Notes

- Approved with `proceed` on 2026-09-06. Shared planning and deployment tracking
  live in NSD PLAN-133 and COMPAT-001.

- Verification: 709 workspace tests, formatting, Clippy, dependency checks, and
  typos passed. JSON and CBOR cover the explicit device-key mode and the
  omitted legacy default. Coordinated consumer verification is tracked by NSD.
