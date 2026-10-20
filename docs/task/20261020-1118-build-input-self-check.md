# Build input scoped self-check

- **status**: completed
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

## Executable reader verification

- `test_unresolved_shell_file_read_selects_complete_check` and
  `test_unresolved_rust_include_selects_complete_check` both failed before the
  fix with `AssertionError: False is not true`. Each temporary repository
  commits its reader before changing only `fixtures/data.txt`.
- Both now select complete QA and identify the referencing source as an
  unresolved input. Shell coverage includes file commands, sourced files,
  input redirection, directory commands, expansion and command substitution.
  A known unrelated shell file path retains scoped selection.
- All three Rust inclusion macros are recognized with parentheses, braces,
  brackets and whitespace before the macro marker. Unresolved environment
  joins conservatively select complete QA.
- An additional failing regression exposed character-class globs in the shared
  uncertainty check. Shell and function-style readers now conservatively
  recognize bracket patterns alongside other wildcard forms.
- `just fmt-check lint` passed before verification.
- `just self-check feat/l8-account-profile` passed on source commit
  `39940f45c2a59cdb699c04bf85ee0560de77f922`: 28 selection tests, 416 Rust tests with zero
  skips, one documentation test and warning-free documentation builds. All
  static checks and API compatibility checks passed. Existing selection
  assertions remain intact.
- Only these completion records changed after that passing self-check.
