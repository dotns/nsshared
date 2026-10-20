# Build input scoped self-check

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-10-20 11:18

## Description

Select tests from actual build inputs, preserving static checks and complete QA
for configurations, vectors, included fixtures and uncertain file access.

## ActiveForm

Implementing input classification and temporary-repository regression coverage

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Investigation

`select` currently escalates any path outside a known crate and an empty
package set. `commands` always constructs package test commands. Existing
coverage exercises reverse dependencies, Git state and complete QA selection.

## Proposal

Implement tracked-source input scanning with explicit diagnostic reasons and
return static checks alone when no package is selected. Preserve existing
selection assertions by making their global fixture document an actual input.

## Verification

- The first regression, `test_record_only_diff_runs_static_checks_without_tests`,
  failed with `AssertionError: True is not false` before the implementation.
- Review regressions separately exposed a lock `read()` mistaken for file
  access and a missing package diagnostic for an included fixture. Both failed
  before their corrections and pass in the final selection suite.
- `just fmt-check lint` passed before the final self-check.
- `just self-check feat/l8-account-profile` passed on source commit
  `9f097123d0ea71592dcbea1c0497de48a3106567`: 23 selector tests, 416 Rust tests with zero skips,
  one documentation test and warning-free workspace documentation builds.
  Dependency checks, spelling, generated vectors and API compatibility passed.
- Temporary-repository observations show that a record-only addition selects
  static checks without package tests; included fixtures and documents,
  directory readers, computed paths, globs and Cargo.lock select complete QA.
  Unincluded crate documents select no packages. Existing selection assertions
  are preserved; the existing global document fixture now has a tracked Rust
  inclusion reference.
- Unknown computed readers deliberately retain complete QA, including for
  documentation when the scan cannot rule out a dependency. The selection
  output identifies each unresolved reader's source.
- Only these completion records changed after the final self-check.

## Executable reader coverage

The scanner omitted command-style shell readers and the Rust `include!`
macro, allowing unresolved executable inputs to appear unreferenced. Extend
conservative detection to shell file commands, input redirection and directory
commands, and recognize every Rust inclusion macro delimiter. Preserve
selection for a shell command that reads a known unrelated literal path.
Temporary repositories must commit each reader before changing only a fixture.
