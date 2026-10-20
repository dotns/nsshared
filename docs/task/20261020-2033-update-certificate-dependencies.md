# Update certificate dependencies

- **status**: completed
- **priority**: P1
- **createdAt**: 2026-10-20 20:33

## Description

Resolve RUSTSEC-2026-0382 and RUSTSEC-2026-0381 using the smallest dependency change without unrelated upgrades, exemptions or API changes.

## Investigation and proposal

The existing `cargo deny --locked check` supplies the regression check. Before changes it reports both advisories and ends with `advisories FAILED, bans ok, licenses ok, sources ok`.

Updating webpki-roots 1.0.9 to 1.0.10 alone leaves the affected 0.26.11 compatibility package required by tokio-tungstenite 0.30.0. Published metadata confirms its requirement is ^0.26.0, while the advisory accepts only >=1.0.10; no compatible published successor exists.

The activating feature is the mock-rendezvous development dependency's `rustls-tls-webpki-roots`. Its TLS clients already pass an explicitly configured aws-lc-rs Rustls connector and trust only the generated server certificate. Public trust roots are unnecessary. See the matching plan for the dependency investigation and final proposal.

## Changes

- rustls-webpki: 0.103.15 -> 0.103.16, the lowest patched release for RUSTSEC-2026-0382.
- webpki-roots: remove 0.26.11 and 1.0.9 from the final graph, clearing RUSTSEC-2026-0381. The intermediate 1.0.10 update is superseded by removing the unused bundle.
- Replace `rustls-tls-webpki-roots` with `__rustls-tls` in the mock-rendezvous development dependency, preserving `connect` and inherited `handshake`.
- Retain the connector code, trust configuration and every existing test assertion unchanged. No direct public-root dependency is added.
- Retain unrelated package versions and dependency edges, including the tempfile edge that Cargo attempted to rewrite during the targeted updates.

## Acceptance

Formatting and workspace Clippy pass. `just deny` reports `advisories ok, bans ok, licenses ok, sources ok`. `cargo tree --locked --target all -i ring` reports no resolved reverse dependencies; existing inactive ring lockfile entries are unchanged.

The self-check selected full QA and passed. Both nsshared-proto and nsshared-telemetry API compatibility checks report no semver update required. The selection suite passed 41 tests; the workspace suite passed all 479 tests with zero skips; doctests and documentation passed. `server_smoke::challenge_and_directory` passed in the full suite and again in a separate focused run, exercising the unchanged explicit connector and verification configuration.

The initial failing dependency audit and the later compatibility-package failure are retained as regression evidence. The final dependency audit passes because the verifier is patched and the unused affected bundles are removed. No advisory exemption, fork, patch section or bypass is used.
