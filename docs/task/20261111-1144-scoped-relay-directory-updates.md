# 20261111-1144-scoped-relay-directory-updates Define Network-scoped relay directory updates

- **status**: completed
- **priority**: P1
- **owner**: root/scoped-directory-20261111
- **createdAt**: 2026-11-11 11:44

## Description

Define and test the Account Network projection update contract. A higher-version projection may remove a relay while preserving permanent relay ID and code ownership; Quick directories retain their existing append-only rule.

## ActiveForm

Defining Network-scoped relay directory update rules.

## Dependencies

- **blocked by**: (none)
- **blocks**: NSGW and NS Account directory consumers

## Notes

NSD #631 and #651 project directories by Network. Existing `check_update` rejects removal.

- complete: 101 rendezvous tests and strict Clippy passed.
