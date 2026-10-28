# Export the discovery representation selector

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-28 03:18

## Description

Publish DISCOVERY_MEDIA_TYPE alongside DISCOVERY_PATH. Assert its exact value in
the existing constants test. Specify Accept selection, Content-Type, Vary and
no-fallback client behavior without changing tuple or envelope shapes.

## ActiveForm

Exporting and validating the discovery media type.

## Dependencies

None.

## Notes

Investigation and approved implementation are recorded in the matching plan.
The constants test first failed with E0425 for DISCOVERY_MEDIA_TYPE, then
passed through the public re-export with the exact application/cbor value.
Formatting and both Clippy configurations passed. The scoped self-check passed,
including semver, vector consistency, default and account-enabled tests and docs.
The spec now records exact Accept selection, Content-Type, Vary: Accept and
strict CBOR-only decoding. No payload shapes or vectors changed.
