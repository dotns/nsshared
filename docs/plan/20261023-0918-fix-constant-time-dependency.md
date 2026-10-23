# Fix constant-time dependency

- **status**: completed
- **createdAt**: 2026-10-23 09:18
- **approvedAt**: 2026-10-23 09:18

## Context

The lockfile selects ctutils 0.4.2 through digest 0.11.3. The advisory check rejects this version for non-constant-time mask generation and u128 comparisons. The reported patched range starts at 0.4.4.

## Proposal

Update ctutils to 0.4.4 using Cargo resolution, preserving existing dependency requirements and advisory policy. Run the advisory check before and after, then formatting, lint and the scoped quality check.

## Risks

Transitive dependency resolution may require additional lockfile changes. Keep the update limited to the affected package and necessary dependencies.

## Scope

Cargo.lock and the accompanying plan and acceptance record.

## Alternatives

Keeping the affected version or suppressing the advisory does not satisfy the security requirement.

## Verification

`cargo deny check advisories` failed before the update with `advisories FAILED`, identifying ctutils 0.4.2 and recommending >=0.4.4. Cargo accepted 0.4.4 without changing requirements; only its version and checksum changed. `just fmt-check lint` and `just self-check` passed, including the advisory check, compatibility checks, workspace tests, doctests and documentation generation. No advisory exception was added.
