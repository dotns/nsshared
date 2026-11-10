# 20261110-0628-relay-epoch-contract Relay attribution epoch request contract

- **status**: completed
- **priority**: P1
- **owner**: relay-epoch/0us4okb0
- **createdAt**: 2026-11-10 06:28

## Description

Implement the approved [epoch request contract](../plan/20261110-0525-relay-epoch-request-contract.md) at main f8589f9c. Add strict version-1 kinds 11/12, dedicated request/result/pending types, independent vectors, recovery semantics and the 0.10.0 minor transition. Preserve all existing wire formats. Deliver a branch and pull request against main; merging and tagging are separate work.

## ActiveForm

Implementing and verifying the relay epoch contract.

## Dependencies

- **blocked by**: (none; owner approved 2026-11-10 06:30 UTC)
- **blocks**: downstream NSD and gateway adoption

## Notes

- Kinds 11/12 are unused at the base; v0.9.0 is the newest existing release.
- Work is isolated from the read-only workspace checkout. No consumer implementation is included.
- Acceptance: RED -> GREEN -> IMPROVE, exact layouts, old fixture preservation, migration inventory, semver and just qa.

- RED: `cargo test -p nsshared-control --test account relay::epoch --locked` failed on the valid independent request (`Err(Frame)`), 1 failed. An initial overqualified filter selected zero tests and was corrected before implementation.
- GREEN: focused relay suite passed 19 tests after strict codecs and expanded context/constructor checks.
- Baseline alignment is tracked as tk nsdoc #1155 for delivered main pins after merge; no feature-branch baseline pin is published.
- Independent v0.9.0 archive probe passed: kinds 11/12 refused and all ten existing kinds round-trip unchanged. All 52 tracked existing fixture files are byte-identical to the base.
- Migration inventory regeneration produced no changes to the historical import map; `just account-migration-check` passed.
- Initial full QA and its network retry hit crates.io TLS EOF during semver's Cargo metadata/update operation (different crates), after prior checks passed. Running the same complete gate with Cargo's already populated registry cache (`CARGO_NET_OFFLINE=true`); no recipe or assertion is disabled.
- IMPROVE/review: clarified the delayed-receipt test to compare an old committed publication with a strictly newer accepted roster. No result/roster numerical coupling or runtime state mutation was introduced.

- Final complete gate: `CARGO_NET_OFFLINE=true just qa` exit 0; 71 script tests, 626 nextest tests passed, 0 skipped, three passing doctests and one pre-existing ignored testkit example, rustdoc warnings denied. Focused relay suite 19/19. `just vectors-check` reports 51 managed fixture files current. `just account-migration-check` and v0.9.0 compatibility probe exit 0.
- Semver against v0.9.0 recognizes the approved 0.10.0 minor as a breaking 0.x transition (260 policy skips per checked library); facade inventories have zero missing/added paths. Forced-patch diagnostic exit 100 is expected: 229 checks, 228 passed, exactly enum_variant_added failed for EpochRequest/EpochResult, 31 unrelated skips. No unstable-account exception or gate modification.
- Local review: complete coverage of the resulting diff, no blocking findings. Runtime integration, deployment and lab acceptance are not claimed. Durable logs and old-fixture hashes are saved under the relay-epoch-fix warehouse evidence directory.

- complete: Implemented the approved strict version-1 epoch frames and 0.10.0 metadata; focused tests, complete QA, migration and compatibility checks passed. Branch/PR delivery follows; merge and tagging remain separate.
