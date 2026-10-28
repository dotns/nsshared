# Snapshot admission history

- **status**: completed
- **createdAt**: 2026-10-28 01:31
- **approvedAt**: 2026-10-28 01:31

## Context

The JSON schema-2 validator shares RosterEntry with signed rosters and cannot
distinguish uninterrupted admission from readmission. AccountError already
distinguishes malformed JSON from invalid contract fields.

## Proposal

Add a snapshot-only entry containing identity, class and admission_since.
Require schema 3 and a positive admission_since no greater than roster_version.
Keep signed roster encoding unchanged. Extend independent vectors and strict
shape tests, and describe continuity in the relay specification.

## Risks

Schema-2 producers must migrate before their files can be accepted. Snapshot
consumers must use the separate entry type; default-feature APIs are unchanged.

## Scope

Relay snapshot validator, account tests, vector producer and relay specification.

## Alternatives

Extending RosterEntry would incorrectly change the signed roster contract.
Optional admission history would incorrectly imply continuity.

## Validation

Run a failing schema-3 test first, then formatting, lint, snapshot and roster
tests, independent vector regeneration checks and default-feature semver checks.

## Acceptance results

- The initial schema_three_admission_history_is_required regression failed at the
  acceptance assertion against schema 2 after formatting and lint passed.
- admission_history_vectors validates 14 independent cases, including continuous
  admission, readmission, empty snapshots, legacy schema refusal, missing and
  malformed history, zero and upper bounds, and the maximum u64 version.
  Accepted results compare identity, class and admission_since exactly.
- Existing strict field, identity count, byte size and supplied-clock tests pass
  with schema-3 fixtures. Duplicate admission_since fields are refused.
- All six signed roster profile cases and the participant-roster vector file are
  byte-for-byte unchanged.
- just dev-check and just self-check passed. The self-check includes 45 current
  vector files, default-feature semver compatibility, 70 selection-script tests,
  413 default-feature tests and 556 account-feature tests, with zero skipped
  nextest tests, plus doctests and warning-free documentation builds.
- The final check includes the account profile schema reference correction.
