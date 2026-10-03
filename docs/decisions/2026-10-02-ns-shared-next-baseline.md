# ADR: The next workspace baseline and how consumers depend on it

Status : Accepted
Date   : 2026-10-02
Sunset : none; revisit if nsshared is published to a registry

## Context

nsshared was consumed only by nsgw, through `../ns-shared` path dependencies
and a commit pinned in nsgw's `[workspace.metadata.release] ns-shared-rev`,
with CI checking out the sibling repository separately. ns kept diverged
copies of the same crates. The workspace is rebuilt on `next` around the
Quick protocol (plan `20261002-1516-ns-shared-rebuild`).

## Decision

- Baseline: edition 2024, `rust-version = "1.96"` equal to the pinned
  toolchain, resolver 3, rustfmt `style_edition = "2024"`, workspace lints that
  deny warnings, forbid `unsafe` and deny `unwrap`, `expect` and `panic`
  outside tests, cargo-deny, cargo-shear, typos and nextest, all through
  `just qa` and the Gitea QA workflow. Dependencies use the latest stable
  versions.
- TLS, when a future crate needs it, uses rustls with the aws-lc-rs provider,
  the same as ns, so a consumer process links one provider.
- Consumers use Cargo git dependencies on
  `https://git.pvv.cc/nsiod/nsshared.git` pinned by `tag`; `Cargo.lock`
  records the exact commit. CI and release jobs need read credentials for the
  repository (`CARGO_NET_GIT_FETCH_WITH_CLI=true` with a token-backed git
  credential). Local development overrides the dependencies with an
  uncommitted `[patch."https://git.pvv.cc/nsiod/nsshared.git"]` entry pointing
  at the sibling checkout.
- A change to a wire contract is released in one window for every consumer,
  and the changelog lists the affected consumers and the switch order.

## Consequences

- nsgw drops its `ns-shared-rev` metadata and the separate CI checkout once it
  moves to git dependencies.
- Builds without network access must vendor or pre-fetch the git source.
