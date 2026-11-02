# Independent service-label input boundaries

- **status**: completed
- **priority**: P2
- **createdAt**: 2026-10-30 00:06

## Description

Add genuinely missing independent label-input coverage through existing snapshot validation, preserving original refusals and canonical bytes.

## Acceptance

- Accepted length boundary round-trips through the existing snapshot API.
- Invalid inputs fail both canonical encoding and snapshot decoding.
- Inventory distinguishes candidate coverage from pending standalone agreement and producer evidence.

## Notes

Investigation: existing label inputs are embedded in the messages tests; no standalone public validator exists. The approved scope uses that same snapshot context.

## Verification

- Failing first: `messages::independent_service_label_input_boundaries` failed because the independent label fixture did not yet exist (`NotFound`); one selected test failed. This establishes missing fixture coverage, not a production validator defect.
- Added `tests/vectors/service/labels.json` and embedded it using the existing compile-time fixture style. All six outcomes follow the unchanged validator: 1–63 bytes, lowercase ASCII letters/digits/hyphens, alphanumeric edges.
- `just dev-check` passed before the focused test; the full service suite passed 19 tests with no skipped tests.
- `just self-check` passed, including static checks, canonical vector regeneration checks, API compatibility, tests and documentation checks.
- The inventory diff changes only the service-label row. Existing matrix and checklist prose, original label tests and canonical fixtures are preserved.
- Diff review found no required corrections. Evidence is local fixture coverage through snapshot validation. Standalone owner agreement/operation and NSD producer evidence remain pending.
