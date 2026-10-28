# Discovery representation selector

- **status**: completed
- **createdAt**: 2026-10-28 03:18
- **approvedAt**: 2026-10-28 03:18

## Context

The control module exports DISCOVERY_PATH but no shared media type. The existing
exchange constants test asserts the endpoint. Bootstrap discovery already defines
a canonical family-11 CBOR tuple and excludes JSON fallback.

## Proposal

Export DISCOVERY_MEDIA_TYPE with value `application/cbor` next to DISCOVERY_PATH
through the same control module. Extend the existing constants assertion and
document request selection, response headers, other representations and strict
client decoding.

## Risks

This additive constant changes no wire bytes or existing payload shapes. Keeping
it in the same module preserves the existing feature boundary.

## Scope

Control methods and re-exports, the exchange constants test and control spec.
No vectors change.

## Alternatives

Separate Accept and Content-Type constants would duplicate the same media type.

## Validation

The existing exchange constants test first failed to compile because
DISCOVERY_MEDIA_TYPE was absent, then passed with the exported value.
Formatting, default and account-enabled Clippy, and the scoped self-check
passed, including semver, unchanged vectors and both test configurations.
The local diff review found no defects within the changed files.
