# nsshared

Shared Rust crates for the generic protocols and tools that two or more NSIO
components encode or use. Application protocols (the ns app channel, pairing,
file transfer) and component-internal architecture (node address planning,
in-tunnel control, relay regions) stay with their owners. The scope is defined
on the docs site (`ns-shared/index.md`).

It contains:

- `nsshared-proto` — identities and typed keys (generation, canonical text and
  binary forms, node ID, `node6` / `node4`), `NodeRecord`, relay packets v2
  (normative source: docs `ns/quick-v2.md`), the rendezvous service
  `/rendezvous/v1` messages in `nsshared_proto::rendezvous` (transport,
  capabilities, actor `hello`, relay directory v2, mailbox phase rules, node
  registry; docs `ns/rendezvous.md`), and the shared encodings
  (`nsshared_proto::encoding` base64url / base64, canonical CBOR)
- `nsshared-telemetry` — `tracing` subscriber setup (text or JSON, env filter
  with a default) and redaction helpers; no exporter
- `nsshared-mock-relay` (`examples/mock-relay`, `publish = false`) — in-memory
  relay v2 mock over UDP and WSS for tests, as a library and a binary
- `nsshared-mock-rendezvous` (`examples/mock-rendezvous`, `publish = false`) —
  single-instance `/rendezvous/v1` mock (mailbox broker, directory, node
  registry) over TLS WebSocket for ns development and tests
- `nsshared-mock-server` (`examples/mock-server`, `publish = false`) — both
  mocks on one `host:port` and certificate (UDP, `/ns/v2`, `/rendezvous/v1`)

`tools/vectors` is an independent Python generator of the conformance vectors
`nsshared-proto` tests against (`just vectors`, `just vectors-check`). Spec
coverage: `docs/spec-coverage/nsshared-proto.md`,
`docs/spec-coverage/nsshared-proto-rendezvous.md`.

The v1 workspace (`control`, `common`, `acl`, `tunnel-ws`, `telemetry`) is
archived at tag `archive/v1-20261002`; see `docs/design/v1-crate-analysis.md`.

## Consuming

Consumers use Cargo git dependencies pinned by tag:

```toml
nsshared-proto = { git = "https://git.pvv.cc/nsiod/nsshared.git", tag = "v0.3.0" }
```

For local development against a sibling checkout, add an uncommitted override
in the consumer's `.cargo/config.toml`:

```toml
[patch."https://git.pvv.cc/nsiod/nsshared.git"]
nsshared-proto = { path = "../nsshared/crates/nsshared-proto" }
```

See `docs/decisions/2026-10-02-ns-shared-next-baseline.md`.

## Versioning

Tags `vX.Y.Z` mark releases. While in 0.x, a minor bump may break the API and
a patch bump must not; from 1.0, semver applies. `just semver` enforces this
for `nsshared-proto` and `nsshared-telemetry` against the previous tag. Wire
formats change only with a new protocol version or context string, never
silently within one.

## Development

```sh
just dev-check   # fmt + clippy
just qa          # full quality gate
```
