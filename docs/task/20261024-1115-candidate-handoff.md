# Candidate handoff

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-24 11:15

## Description

Prepare the immutable candidate handoff with exact deliveries, corrections,
independent vectors, current consumer inputs and unresolved producer/review work.

## Acceptance

The comparison must reject manifest, lock, source and vector drift. Existing QA
retains independent vector and API checks. Review requests never imply approval.

## Notes

Investigation and approved implementation are recorded in the related plan.
The focused comparison test first failed because the comparison module was absent.

## Acceptance results

The [handoff](../l8-candidate-handoff.md) lists all shared contract deliveries,
P12–P19 additions, independent vectors, subsequent corrections, exact current
consumer inputs and unresolved producer/review obligations. The architecture
now records the existing one-way proto to service-control dependency accurately.
The historical review package remains separately identified; preparation and
silence never establish delivery or approval.

`test_manifest_lock_and_candidate_drift_are_refused` first failed with
FileNotFoundError for the absent comparison module. It now passes with real
Git inputs in a temporary directory, exercising manifest pins, floating branches,
lock commit/version/missing-package refusal, source/lock/vector changes and
added files. The focused test passed again at
`b4f1039c1a5d02d7cbc127af45a91bc241104b9b`.

`python3 -B tools/candidate_handoff.py` with candidate
`50dc9db5fe106536d0a7d8b113b5bb4a3e210368` and gateway
`e506df51e5e580d20d5cdaa25a8f134f87bf3caf` passed and was confirmed.
All 251 selected package/lock/API/vector inputs match. The four specified
consumer pairs resolve 3, 3, 2 and 2 shared packages at the exact candidate
revision and version 0.6.0. Frozen r1 inputs remain historical; NSD and ns
adoption remains unresolved without an inferred pin.

The independent `cargo tree --locked --edges normal --package nsshared-proto
--package nsshared-service-control --prefix none` inspection found no Tokio,
Rustls, ring, reqwest, hyper or async-std package in those normal closures.
`git diff --exit-code 50dc9db5fe106536d0a7d8b113b5bb4a3e210368` over the
workspace manifest/lockfile, three library packages and vector producers found
no differences. This preserves the selected pure-contract boundary rather than
claiming a new whole-source purity proof.

Formatting and workspace lint passed. The complete
`just self-check feat/l8-account-profile` passed first at
`968f95b3d7cab6ecb2204b2bf1e93d225d87b3fe` and again at final source/documentation
commit `b4f1039c1a5d02d7cbc127af45a91bc241104b9b` after the external handoff
list was completed. Both runs selected full QA: dependency auditing/usage,
spelling, all 34 independently generated proto fixture files, M6 generator,
public API compatibility, 41 selection tests, 537 Rust tests with zero skips,
one doctest and warning-free documentation passed. The API checker reported
202 applicable checks passed for each checked package. The standalone spelling
command initially lacked its executable search path and exited 127; it passed
with the configured tool path, and both complete checks passed spelling.

Only these acceptance records changed after the final self-check. Shared indexes
and changelog entries remain for integration. External review, producer vectors,
real-component interoperability, main publication and release remain outstanding
as explicitly enumerated in the handoff.
