# 20261002-1516-ns-shared-rebuild Rebuild ns-shared around a complete Quick protocol

- **status**: implementing
- **createdAt**: 2026-10-02 15:16
- **approvedAt**: 2026-10-02 15:16
- **relatedTask**: 20261002-1516-next-workspace-baseline, 20261002-1516-quick-wire, 20261002-1516-quick-vectors, 20261002-1516-quick-rendezvous, 20261002-1516-quick-consumers

## Context

ns-shared is meant to hold the contracts that two or more components encode
or enforce (scope: docs site `ns-shared/index.md`, 2026-10-02). In practice:

- Only nsgw depends on it (path dependency `../ns-shared`, pinned through
  `[workspace.metadata.release] ns-shared-rev`). ns keeps its own crates with
  the same names, and nsd defines its own types.
- The ns and ns-shared crates with the same names did not fork from one
  snapshot: ns has used its own ACL model since its first commit, while the
  extraction commit `044353d` carried code that never existed in ns. The APIs
  differ by hundreds of public items per crate, so the copies cannot be merged
  mechanically.
- The Quick protocol exists twice: `keynet-proto` here (about 21,000 lines,
  used by the nsgw quick relay) and an independent `quick-wire` in ns. Wire and
  crypto constants still use the Keynet spelling. The normative specification
  is docs `ns/quick-protocol.md` §12 and, for rendezvous v2, `ns/rendezvous.md`.

## Proposal

Rebuild on a new `next` branch of this repository. Old `main` is tagged
`archive/v1-20261002`; `next` replaces `main` once consumers have moved.

1. **P0 workspace baseline** (`20261002-1516-next-workspace-baseline`): a new
   workspace that starts with only the Quick crates, on the pma-rust
   baseline (edition 2024, MSRV 1.96, workspace lints that deny warnings,
   forbid unsafe and deny unwrap/expect/panic outside tests, rustls with
   aws-lc-rs, cargo-deny, cargo-shear, typos, nextest, justfile, Gitea QA
   workflow). Consumers depend through Cargo git dependencies on
   `https://git.pvv.cc/nsiod/ns-shared.git` pinned by tag; local development
   overrides them with an uncommitted `[patch]` pointing at `../ns-shared`.
2. **P1a `quick-wire`** (`20261002-1516-quick-wire`): `keynet-proto` renamed,
   with every identifier and protocol value moved from Keynet to Quick (for
   example `quick/pairing-token/v1`, WSS path `/quick/v1/relay`), checked
   section by section against §12 with a specification-to-code table.
3. **P1b independent vectors** (`20261002-1516-quick-vectors`): a generator
   that implements the specification directly (RFC 8032 Ed25519, RFC 7748
   X25519, canonical CBOR, BLAKE2s, HKDF) without calling `quick-wire`, so the
   conformance vectors keep cross-checking the Rust implementation.
4. **P1c `quick-rendezvous`** (`20261002-1516-quick-rendezvous`):
   `keynet-quick` renamed and extended to the rendezvous v2 mailbox message
   types, the relay capability vocabulary and the relay directory v2 types.
5. **P2 consumers** (`20261002-1516-quick-consumers`): the nsgw quick relay and
   ns move to the shared crates through git dependencies; ns removes its
   protocol copy. The ns move is coordinated with the nstun data-plane plan so
   that `quick-runtime` is ported once.
6. **P3** (later, separate tasks): `control`, `common`, `acl`, `tunnel-ws` and
   `telemetry` return one at a time after a per-crate analysis of what is a
   shared contract and what is client- or gateway-specific; nsd adopts the
   `control` contract types.

## Risks

- Renaming protocol values breaks Quick interoperability between ns and nsgw
  until both consume the new crates in P2. Accepted: the project is in
  development.
- Cargo git dependencies on a private repository need fetch credentials in
  every CI and release job and in Docker builds.
- While nsgw still uses old `main` for the non-Quick crates, it depends on two
  revisions of this repository.

## Scope

New `next` workspace, two protocol crates, a vector generator, CI and docs in
this repository; dependency changes in nsgw and ns in P2.

## Alternatives

- New repository or orphan history: rejected; history and issue links stay in
  one place.
- Base `quick-wire` on the ns implementation: rejected; `keynet-proto` is
  more complete and already serves the nsgw relay.

## Annotations

- 2026-10-02: Owner approved the recommended options: rebuild on `next` in
  this repository with old `main` archived by tag, base on `keynet-proto`,
  rename protocol values to Quick, consumers pin by tag.
- 2026-10-02: Owner decided that everything moves to the v2 protocol with no
  v1 compatibility, because the migration (docs `migration.md`, M0-M9) starts
  now. P1 therefore implements docs `ns/quick-v2.md` and `ns/rendezvous.md`
  directly (migration milestone M1) instead of renaming the v1 values; the v1
  code in `quick-wire` and `quick-rendezvous` is replaced, not kept. P0 is the
  ns-shared part of migration milestone M0.
