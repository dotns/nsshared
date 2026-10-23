# Refuse group labels as principals

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-10-23 11:53

## Description

Group labels deny under every public-edge selector. Verified explicit group members retain their matches, and all wire bytes remain unchanged.

## Investigation and proposal

See [the implementation plan](../plan/20261023-1153-group-label-principals.md). The supplied specification authorizes this correction.

## Acceptance

- Six group-label rows deny and are never classified as verified.
- Verified Node membership continues to match the group selector.
- Existing selector bytes remain unchanged.

## Notes

Validation pending.
