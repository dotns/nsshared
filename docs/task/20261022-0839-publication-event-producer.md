# 20261022-0839-publication-event-producer Publication event producer

- **status**: pending
- **priority**: P1
- **owner**: (unassigned)
- **createdAt**: 2026-10-22 08:39

## Description

Expose shared canonical encoding and signing input for inner signed publication events without holding producer keys. Verify independent byte equality, signature acceptance and invalid-content refusal.

## ActiveForm

Clarifying producer validation and round-trip coverage.

## Dependencies

- **blocked by**: Definition of producer-valid content versus all decodable vector events.
- **blocks**: (none)

## Notes

Investigation found that the existing signed-channel-mismatch vector is decodable but must be refused by the requested producer. Reproducing every decoded vector and refusing this content cannot both hold. Unknown kinds and partial or invalid typed profile content also distinguish decoder validity from decision acceptance. No executable files changed; no tests or checks ran. Shared indexes and changelog remain unchanged.
