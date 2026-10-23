# Refuse group labels as principals

- **status**: completed
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

The regression `group_label_principals_are_refused` failed before the correction:
`any-verified-verified-group: group label admitted as verified-user`.
It now passes, alongside the existing matching table and selector encoding tests.

`just dev-check` passed formatting and workspace lint checks. The complete
`just self-check` passed static checks, generated-vector checks, API compatibility,
selected tests, doctests, and documentation generation.

All 88 vector payloads and subject bytes equal the preceding profile revision.
All six group-label rows deny; the existing verified Node row remains an explicit
member distinct from the qualified user and matches the group selector. The
matching matrix therefore remains six selectors by seven principal states (42).
No codec, selector, group, credential binding, or admin claim changed.
