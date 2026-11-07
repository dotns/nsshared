# 20261107-0213-stable-account-release Release the unconditional account API

- **status**: in_progress
- **priority**: P1
- **owner**: release-account/20261107-0213
- **createdAt**: 2026-11-07 02:13

## Description

Remove the unstable-account feature and expose all account contracts unconditionally. Update affected tools, tests and current documentation. Release 0.8.0 because removing a Cargo feature is breaking. Run semver against v0.7.0 including account, run just qa on the clean final head, and update release PR #27 without merging or tagging.

## ActiveForm

Preparing the stable account release.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Owner approved the complete scope on 2026-11-07. Review answers no longer block this release; existing operational and adoption evidence remains separate. Consumers nsgw main, NSD and ns currently pin 165cce57 with the feature and must remove that feature when moving to v0.8.0.

Reproduction: `cargo test -p nsshared-control --test account --no-default-features --locked --offline --no-run` initially failed because the test required unstable-account; it now builds. The migration-helper test initially failed because advice injected the removed feature; all 24 migration-helper tests and all 71 script tests now pass.

`just semver` against v0.7.0 passes with the unconditional account surface. The 0.7.0 to 0.8.0 version change permits breaking changes, so each of seven libraries skips all 260 compatibility rules. Proto facade: 2692 baseline lines, zero missing or added. Service-control facade: 1361 baseline lines, zero missing and 121 added. A supplementary strict comparison of control with the old baseline account feature enabled runs 229 checks: 224 pass, five fail, 31 skip, requiring a major release. The failures cover added public struct fields, exhaustive enum additions/discriminant changes, and changed function/method arity. Both those pre-release candidate differences and Cargo feature removal support 0.8.0.

Regenerated the account migration map from its historical base and current unconditional API; it now also records the intervening account changes instead of retaining stale moved classifications. No wire encoding implementation changed.
