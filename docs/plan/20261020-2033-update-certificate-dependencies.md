# Update certificate dependencies

- **status**: implementing
- **createdAt**: 2026-10-20 20:33
- **approvedAt**: 2026-10-20 20:33
- **relatedTask**: 20261020-2033-update-certificate-dependencies

## Context

The dependency audit reports RUSTSEC-2026-0382 for rustls-webpki 0.103.15 and RUSTSEC-2026-0381 for webpki-roots 1.0.9 and its 0.26.11 compatibility package. Neither dependency is pinned directly in the workspace manifest.

## Proposal

Update rustls-webpki to 0.103.16 and webpki-roots 1.0.9 to 1.0.10 with precise lockfile updates. Retain unrelated package versions and dependency edges. Run the dependency audit, verify the resolved graph excludes ring, and run formatting, linting and the self-check.

## Risks

The audit also flags the older webpki-roots compatibility package; its continued presence may prevent an audit pass even after its underlying root bundle is updated.

## Scope

Cargo.lock and these implementation records. No advisory exemptions or public API changes.

## Alternatives

The refreshed registry index has no tokio-tungstenite successor after 0.30.0 and no compatible webpki-roots successor after 0.26.11. The current release requires webpki-roots ^0.26.0, which cannot resolve to the advisory minimum 1.0.10.

One alternative is to change the mock-rendezvous development dependency from `rustls-tls-webpki-roots` to the existing Rustls connector support and supply trusted roots explicitly. This requires inspecting and potentially changing its manifest and TLS tests, which are outside the current edit scope. TLS verification and the existing test assertions must be preserved. Another alternative is an upstream tokio-tungstenite release that requires webpki-roots ^1; no such release is currently available in the registry. Advisory correction for the delegating compatibility package is an upstream option, but cannot be assumed or replaced by a local exemption.

## Verification result

The two precise updates are complete; formatting and linting pass. The self-check fails on RUSTSEC-2026-0381 for the unchanged 0.26.11 compatibility package. Cargo metadata identifies the activating edge as the mock-rendezvous development dependency feature `rustls-tls-webpki-roots`. Published feature definitions map it to optional webpki-roots ^0.26.0. The 0.26.11 package re-exports the 1.x root bundle, but the exact advisory range still excludes every 0.26 release. Workspace features are additive, so the root manifest cannot disable this explicit child feature. A refreshed dry-run update selects zero new packages. No Cargo.toml/Cargo.lock-only fix is available from the published dependency graph. No advisory policy was relaxed.
