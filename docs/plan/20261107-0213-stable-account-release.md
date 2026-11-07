# 20261107-0213-stable-account-release Release the unconditional account API

- **status**: implementing
- **createdAt**: 2026-11-07 02:13
- **approvedAt**: 2026-11-07 02:13
- **relatedTask**: 20261107-0213-stable-account-release

## Context

Release PR #27 currently proposes 0.7.1 with account gated. Account dependencies, integration tests, QA recipes, scoped checks and migration helpers depend on that feature. Current specifications and review status documents describe the gate as a release prerequisite.

## Proposal

Remove feature declarations, optional dependency flags, required-features and conditional compilation. Keep one unconditional QA configuration. Remove feature injection from scoped checks and migration helpers, update their tests, and regenerate the migration map. Update current API and release documentation while preserving historical evidence. Bump workspace, internal requirements and lockfile to 0.8.0; run semver and complete QA; update PR #27.

## Risks

Removing the Cargo feature breaks consumers that still request it. The changelog and PR must instruct consumers to remove it. Stable API status does not establish production qualification or answer outstanding review questions.

## Scope

Account exposure, affected release tooling and documentation only; no wire encoding or runtime behavior changes.

## Alternatives

A no-op compatibility feature is explicitly disallowed. The approved release version is 0.8.0.

## Annotations

Owner approval on 2026-11-07 supersedes the earlier 0.7.1 release scope and account gate prerequisite.
