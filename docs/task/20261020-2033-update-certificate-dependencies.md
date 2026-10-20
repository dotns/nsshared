# Update certificate dependencies

- **status**: in_progress
- **priority**: P1
- **createdAt**: 2026-10-20 20:33

## Description

Resolve RUSTSEC-2026-0382 and RUSTSEC-2026-0381 using the lowest patched versions without unrelated upgrades, exemptions or API changes.

## Investigation and proposal

See the matching plan. The existing cargo-deny check provides the regression check: before the update, it reports both advisories and ends with `advisories FAILED, bans ok, licenses ok, sources ok`.

## Changes

rustls-webpki: 0.103.15 -> 0.103.16. webpki-roots: 1.0.9 -> 1.0.10. The 0.26.11 compatibility package remains unchanged. An unrelated tempfile dependency-edge change produced by Cargo was restored.

## Acceptance

Formatting and workspace Clippy passed. `cargo tree --locked --target all -i ring` reports no resolved reverse dependencies. The lockfile retains inactive ring entries from the existing resolution.

`just self-check` selects full QA for the lockfile change and fails in `cargo deny --locked check`: RUSTSEC-2026-0382 is cleared, but RUSTSEC-2026-0381 still flags webpki-roots 0.26.11, required by tokio-tungstenite 0.30.0. The advisory accepts only versions >=1.0.10. The compatibility package delegates to the updated 1.0.10 bundle, but remains affected according to the audit metadata. No exemption was added.

Completion is blocked on removing the older compatibility dependency through a compatible upstream dependency update or correcting the advisory metadata upstream. API compatibility and test execution were not reached because the dependency audit failed. The implementation remains incomplete.

## Dependency edge investigation

`cargo metadata --locked --no-deps --format-version 1` identifies `examples/mock-rendezvous/Cargo.toml` as the source of the development dependency features `handshake`, `connect`, and `rustls-tls-webpki-roots`. Published tokio-tungstenite 0.30.0 maps the last feature to optional webpki-roots ^0.26.0. The 0.26.11 package depends on webpki-roots ^1 and re-exports its TLS_SERVER_ROOTS, but RUSTSEC-2026-0381 defines its sole patched range as >=1.0.10 without a compatibility-package exception.

A refreshed `cargo update -p tokio-tungstenite --dry-run` selects zero packages. Registry metadata lists 0.30.0 as the latest non-yanked release and 0.26.11 as the latest compatible root package; there is no published compatible successor that removes the flagged edge. Root workspace feature changes cannot subtract explicitly enabled child dependency features.

Formatting and linting passed again. The self-check again failed in the dependency audit on the unchanged compatibility package. The dependency graph and implementation are unchanged from the precise updates. Completion requires extending the edit scope to the development dependency and relevant TLS tests, or a published upstream dependency fix. See the plan for the concrete alternatives. No audit bypass or advisory exemption is used.
