# feat: complete candidate control exchange

- **status**: completed
- **priority**: P1
- **owner**: contract-maintenance
- **createdAt**: 2026-10-20 17:44

## Description

Deliver canonical registration/acceptance, authentication/information and machine
claim/key-set values with independent consumer vectors and exact trust predicates.

## ActiveForm

Completed pure exchange contracts and independent vectors.

## Dependencies

- **blocked by**: none
- **blocks**: none

## Notes

Investigation and approved proposal: [plan](../plan/20261020-1744-control-exchange.md).
Gateway audience remains unchecked; NSD audience comparison is distinct.
Producer confirmation and possible later gateway audience enforcement stay open.

Acceptance is complete: registration compares authenticated acceptance against the
staged scope, exact enrollment/profile and recomputed lifecycle; authentication
and information use fixed operation/path constants. Machine claims and public
keys preserve the pinned audience boundaries, self-binding, expiry, refresh,
key selection and pin ownership predicates. The independent consumer covers
66 fixture vectors and six focused tests. No runtime or key-custody code moved.

Failing-first evidence: the consumer initially could not import the new exchange
and machine-token modules. Fixture setup was corrected to reuse EnvelopePins's
existing intersect API. The separately specified NSD array-audience case also
failed before its pure predicate was corrected. These failures were resolved
by implementation changes rather than rerunning unchanged assertions.

The final self-check on `88533c48c97d279277d673c7134e873d850568e6` passed all
static, vector and API checks, 41 selection tests, 455 workspace tests with zero
skips, doctests and documentation. Source size remains within the existing limit.
The [plan](../plan/20261020-1744-control-exchange.md) records acceptance and open
producer-review inputs. Shared index and changelog updates are separate.
