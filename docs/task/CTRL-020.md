# CTRL-020 Add the gateway build identity report contract

- **status**: closed
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-07-28 05:29
- **plan**: nsgw PLAN-119

## Description

Extend `GatewayReportRequest` with an optional structured build identity while
retaining `nsgw_version` as the legacy release-version mirror. Distinguish
Docker image ID from OCI manifest digest and carry the NSGW plus `ns-shared`
source identities needed to identify the complete path-dependent build.

Acceptance requires CBOR round trips and both compatibility directions:
new readers accept old reports without build identity, and old readers ignore
the additive field.

## ActiveForm

Defining the additive gateway build identity wire contract.

## Dependencies

- **blocked by**: (none)
- **blocks**: nsgw GWREPORT-002 and nsd GWREPORT-003

## Notes

- 2026-07-28 05:29 - Draft contract recorded in nsgw PLAN-119. No
  implementation approval has been granted.
- 2026-07-28 05:44 - Closed before implementation. The approved minimal design
  reuses `GatewayReportRequest.nsgw_version` and needs no wire change.
