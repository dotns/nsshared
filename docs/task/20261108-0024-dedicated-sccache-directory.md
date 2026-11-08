# Dedicated sccache directory in CI

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-11-08 00:24

## Description

The QA workflow set `SCCACHE_DIR=/sccache` with a 60 GiB limit. On the shared
runner host that mount also holds other repositories' persistent build
directories and Cargo homes. sccache's LRU disk cache adopts every regular file
under its directory and evicts the oldest ones, so nsshared runs deleted files
from those sibling trees (crate sources, the advisory database checkout) and
broke unrelated CI jobs.

## ActiveForm

Moving the nsshared sccache directory to its own subtree.

## Dependencies

None.

## Notes

`SCCACHE_DIR` is now `/sccache/nsshared`; the size limit is unchanged. The
first runs after the change start with an empty compiler cache. The previous
cache files directly under `/sccache` are no longer used by this workflow and
can be removed by the runner host's operator.
