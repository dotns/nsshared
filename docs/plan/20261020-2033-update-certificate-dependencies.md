# Update certificate dependencies

- **status**: completed
- **createdAt**: 2026-10-20 20:33
- **approvedAt**: 2026-10-20 20:33
- **relatedTask**: 20261020-2033-update-certificate-dependencies

## Context

The dependency audit initially reports RUSTSEC-2026-0382 for rustls-webpki 0.103.15 and RUSTSEC-2026-0381 for webpki-roots 1.0.9 and its 0.26.11 compatibility package. The sole patched root-bundle range is >=1.0.10. Although 0.26.11 delegates to the 1.x bundle, its package version remains affected according to the advisory.

The mock-rendezvous development dependency enables tokio-tungstenite's `rustls-tls-webpki-roots` feature, which requires webpki-roots ^0.26.0. Refreshed registry metadata lists tokio-tungstenite 0.30.0 as the latest published release, with no compatible dependency update that removes that edge.

Both clients in `examples/mock-rendezvous/tests/server_smoke.rs` and `examples/mock-rendezvous/tests/support/mod.rs` already construct an explicit aws-lc-rs Rustls configuration, trust only the generated server certificate, and pass `Connector::Rustls` to the WebSocket handshake. Public roots are unused.

## Proposal

Update rustls-webpki from 0.103.15 to the lowest patched release, 0.103.16. Replace the development dependency feature `rustls-tls-webpki-roots` with `__rustls-tls`, preserving `connect` and inherited `handshake`. Remove both unused root-bundle packages from the lockfile. Keep every connector implementation and verification assertion unchanged.

The initial precise webpki-roots update from 1.0.9 to 1.0.10 cleared that package's advisory but did not clear the compatibility package. Removing the unused bundle feature resolves the remaining advisory without additional dependencies or changes to certificate verification.

## Risks

Rustls connector support must remain enabled after removing the bundled-root feature. Existing TLS smoke and integration tests exercise the explicit connector and generated trust anchor.

## Scope

Cargo.lock, examples/mock-rendezvous/Cargo.toml and these implementation records. No connector code change, direct public-root dependency, advisory exemption, source override or public API change is needed.

## Alternatives

A future upstream dependency release could migrate the optional bundle requirement to ^1, but no such release is currently available. Loading public roots would add unused trust anchors and dependencies. The existing explicit connector is sufficient.

## Verification

The initial dependency audit and subsequent compatibility-package failure establish the failing regression check. Formatting, linting, the dependency audit, the resolved graph across all targets and API compatibility all pass. The self-check selected full QA and passed: 41 selection tests, 479 workspace tests with zero skips, doctests and documentation. The TLS smoke test also passed independently after the full suite.
