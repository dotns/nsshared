# Signed publication events

- **status**: implementing
- **createdAt**: 2026-10-19 14:13
- **approvedAt**: 2026-10-19 14:13
- **relatedTask**: 20261019-1413-signed-publication-events

## Context

Family 11 already covers snapshot/events vocabulary. BootstrapEnvelope provides a signed opaque carrier but lacks completeness, publication versions, served realms and validity intervals. The immutable family registry and existing M6 Snapshot, SnapshotPush and SnapshotAck bytes must remain unchanged.

## Proposal

Specify a domain-separated signed publication using the existing two-byte-string carrier shape. Bind issuer, recipient, served realm, scope, family/kind, owning channel, completeness, publication version, issue/expiry and an opaque typed-outcome payload. Validate borrowed bytes before allocation, using the measured complete signed-event length. Return explicit pure replacement, withdrawal, absence, fetch-failure denial, ignored-kind/channel, refusal and stream-termination decisions. Validate whole bounded snapshots before exposing decisions, with ordered unique keys. Independently generate Python signed fixtures with supplied clocks and expected decisions; consume canonical bytes directly in Rust.

## Risks

Unknown or misplaced kinds cannot gain authority. Scope/version checks and actual exclusive expiry must precede replacement. Typed ACL failure is authenticated authority; outer fetch failure retains existing state. Snapshot container absence does not withdraw anything. Family payload validation remains with each owning family.

## Scope

Account publication module and exports, one independent producer and consumer test, additive account fixtures, profile/review-request additions and these records.

## Alternatives

The call carrier's content and signature domains cannot express per-kind replacement or validity. Reuse its outer shape only; do not duplicate service-control types or implement transport/runtime behavior.

## Annotations

Candidate fixture qualification does not imply NSD producer confirmation.

## Verification

The publication consumer passed all 95 independent fixtures; the focused account and publication suites passed seven tests with no ignored tests. Formatting, lint, both vector checks, dependency policy, spelling and API compatibility passed. Existing vectors and registry bytes are unchanged.

Complete repository verification remains pending: `just self-check feat/l8-account-profile` exited 100 because `external_mode_announces_wss_without_a_tcp_listener` failed with `AddrInUse` at `examples/mock-relay/tests/external.rs:269`. The unrelated listener test is outside this implementation. The initial generic fixture-dispatch failure was fixed by recognizing dedicated publication consumers and preserving their canonical mutation checks.
