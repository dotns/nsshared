# 20261021-2159-profile-publications Profile publications

- **status**: completed
- **createdAt**: 2026-10-21 21:59
- **priority**: P1
- **owner**: protocol-maintenance

## Description

Deliver scoped usage and Node-control catalogue payloads with exact canonical bytes, independent fixtures, contextual validation and typed publication mapping. Preserve existing reporting/control semantics and withdrawal tombstones.

## ActiveForm

Implementing profile publication contracts and independent vectors.

## Dependencies

- **blocked by**: none
- **blocks**: none

## Notes

Investigation and approved implementation scope are recorded in the matching plan. External producer adoption and NSD/ns review remain outstanding.

## Results

- Specified and implemented UsageProfilePublication, NodeControlProfilePublication
  and typed PublicationEvent profile decoding with independent context validators.
- Added independent Python producer and Rust consumer fixtures, including the
  source-bound profile_publication_replacement sequence for gateway reuse.
- The first focused build failed on the absent public types and decoder method.
  Subsequent fixture validation corrected an invalid-point assumption using an
  independently checked non-point encoding and corrected the refusal inventory
  count to 39; no identity validation rule was changed.
- Format and workspace lint passed before the implementation regression checks.
  The complete self-check passed: 503 tests, zero skipped, successful doctests,
  document build, semver, vector consistency and dependency/static checks.
- Existing publication channel fixtures now use valid typed profile payloads;
  their channel-ownership assertions retain the same scope.
- Full local source/test/specification review found no remaining defects.
- NSD/ns review, producer-owned vectors, producer adoption and gateway durable
  installation/restart acceptance remain outstanding external work.
