# Local Node naming declaration

- **status**: completed
- **createdAt**: 2026-10-23 03:17

- **priority**: P1

## Investigation

Enrollment already enforces sorted unique bounded capability identifiers. Exact control exchange tuples embed enrollment bytes and compare authenticated acceptance against the staged request. Naming needs a public declaration and independent fixtures, with no tuple extension.

## Proposal

Expose the naming capability beside enrollment limits; add independent registration and authenticated acceptance fixtures and duplicate/unsorted refusals. Document four retired registration values, retained naming ownership and consumer cutover custody.

## Scope and risks

Only proto enrollment exports, vector producers/fixtures/tests and naming documentation change. Legacy state migration remains consumer-owned; naming mode grants no service or DNS publication permission.

## Acceptance

Run formatting and lint before focused tests, then the documented self-check. Preserve existing fixture bytes and exact tuple definitions.

## Results

`r3_local_naming_capability` first failed with `missing local naming vector`.
Seven independent fixture vectors now cover exact registration/acceptance enrollment
and capability bytes, authenticated acceptance comparison and typed duplicate/unsorted
refusals. A subsequent test assertion used an incorrect CBOR length prefix for the
19-byte capability; the expected prefix was corrected from 0x72 to 0x73.
The independent producer and consumer agreed on the actual bytes throughout.
All prior control exchange vector blocks are unchanged, as are exchange tuples.

`just dev-check` and the control-exchange/enrollment suites passed (11 tests).
`just self-check` passed: 41 selection tests, 522 workspace tests with zero skips,
one documentation test and warning-free documentation generation. Static checks,
independent vector regeneration and semantic compatibility checks passed.
Local diff review found no unresolved correctness or compatibility findings.

The three specifications contain the exact four-value disposition and consumer-owned
cutover policy. External producer confirmation and runtime adoption remain outstanding;
fixture-fed checks establish candidate behavior only. Shared indexes and changelog
are left unchanged for integration alongside these detail records.
