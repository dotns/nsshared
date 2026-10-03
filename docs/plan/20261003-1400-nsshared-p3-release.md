# 20261003-1400-nsshared-p3-release Complete nsshared for its first release (P3a) and publish

- **status**: proposed
- **createdAt**: 2026-10-03 14:00
- **relatedPlan**: 20261002-1516-ns-shared-rebuild

## Context

`next` holds the v2 protocol crates (`nsshared-wire`, `nsshared-rendezvous`,
433 tests, independent vectors). It is local only; the remote `main` is still
the v1 workspace that nsgw consumes through `../ns-shared` path dependencies.
The owner wants nsshared complete enough that ns and nsgw take every shared
behavior from it (logging, address and key generation, protocol), then
published to the remote.

The archived v1 crates (`control`, `common`, `acl`, `tunnel-ws`, `telemetry`)
differ from ns's copies by thousands of lines each and encode the v1 account
contract, which migration M6 replaces (node IDs and `node6` instead of NSD
IPv4). Porting them now would be rewritten at M6.

## Proposal

P3a, contracts that M6 does not change (this release):

1. **Keys and identities** in `nsshared-wire`: typed identity (`I`) and
   session (`K`) keys with generation, canonical text and binary encodings,
   and redacted `Debug`; node ID, `node6` / `node4` / `lan6` derivation as the
   one public entry point. ns `overlay` and nsgw drop their local helpers.
2. **`nsshared-telemetry`**: tracing subscriber setup (format, filter from
   env, JSON option), secret redaction helpers, and the shared metric and label
   names (path, transport, peer source). No exporter policy: each binary keeps
   its own OTel wiring.
3. **`nsshared-relay-carrier`** (only if the analysis confirms both sides
   frame the same bytes): relay v2 WSS carrier framing shared by ns
   `RelayClient` and nsgw `nsgw-relay`. Otherwise the framing stays in
   `nsshared-wire` and no crate is added.
4. Per-crate analysis note in `docs/design/` for `control`, `common`, `acl`,
   `tunnel-ws`: what returns in P3b (with M6), what moves to nsplane
   (`acl` -> `nsplane-acl`), what stays client- or gateway-specific.

Publish:

5. Push `next`, push tag `archive/v1-20261002`, tag `v0.1.0` on `next` after
   P3a, and update the README consumption example. `main` keeps v1 until nsgw
   moves (replacing it now breaks nsgw CI, which checks out `main`).
6. ns switches its temporary `file://` dependency to the remote tag.

P3b (later, with M6): `nsshared-control` v2 contract designed against the M6
address plan, not ported from v1.

Old v1 tasks still open on `main` (CTRL-015..017, NODE-001..003, SH-MESH-001/002,
cascaded relays) are closed as superseded by v2 / M6, with the reason in the
changelog.

## Risks

- Pushing a private git dependency: ns, nsgw CI and Docker builds need Gitea
  fetch credentials.
- Moving key helpers changes call sites in ns `overlay` (in the active ns
  campaign); the ns side lands after B's branch merges.

## Scope

This repository: two crate additions or extensions, one design note, docs,
QA, tags. ns: one dependency switch. nsgw: none in P3a.

## Alternatives

- Port all v1 crates now: rejected, M6 rewrites the account contract.
- Replace `main` with `next` now: rejected until nsgw consumes `next`.
