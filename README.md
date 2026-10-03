# nsshared

Shared Rust crates for the contracts that two or more NSIO components encode
or enforce. The scope is defined on the docs site (`ns-shared/index.md`).

This is the `next` workspace, rebuilt around the Quick protocol. It contains:

- `nsshared-wire` — NS protocol v2 wire formats: identities, node records, relay
  packets and in-tunnel control messages (normative source: docs
  `ns/quick-v2.md`)
- `nsshared-rendezvous` — NS rendezvous v2 (`/quick/v2`): JSON transport,
  capabilities, actor `hello`, relay directory v2, mailbox phase rules, the
  node registry and pairing payloads (normative
  source: docs `ns/rendezvous.md`, `ns/quick-v2.md` §7, §10.2)
- `nsshared-telemetry` — shared telemetry conventions: `tracing` subscriber
  setup (text or JSON, env filter with a default), redaction helpers and the
  sensitive field names, and the shared `path`, `transport` and `peer_source`
  label names and values (source: NS `telemetry` labels); no exporter
- `nsshared-mock-relay` (`examples/mock-relay`, `publish = false`) — in-memory
  relay v2 mock over UDP and WSS for tests, as a library and a binary
- `nsshared-mock-rendezvous` (`examples/mock-rendezvous`, `publish = false`) —
  single-instance `/quick/v2` mock relay (mailbox broker, directory, node
  registry) over TLS WebSocket for ns development and tests
- `nsshared-mock-server` (`examples/mock-server`, `publish = false`) — both
  mocks on one `host:port` and certificate (UDP, `/ns/v2`, `/quick/v2`)

`tools/vectors` is an independent Python generator of the conformance vectors
both crates test against (`just vectors`, `just vectors-check`). Spec
coverage: `docs/spec-coverage/nsshared-wire.md`, `docs/spec-coverage/nsshared-rendezvous.md`.

The previous workspace (`control`, `common`, `acl`, `tunnel-ws`, `telemetry`)
is archived at tag `archive/v1-20261002`; those crates return one at a time
after a per-crate analysis.

## Consuming

Consumers use Cargo git dependencies pinned by tag:

```toml
nsshared-wire = { git = "https://git.pvv.cc/nsiod/nsshared.git", tag = "v0.1.0" }
```

For local development against a sibling checkout, add an uncommitted override
in the consumer's `.cargo/config.toml`:

```toml
[patch."https://git.pvv.cc/nsiod/nsshared.git"]
nsshared-wire = { path = "../ns-shared/crates/nsshared-wire" }
```

See `docs/decisions/2026-10-02-ns-shared-next-baseline.md`.

## Development

```sh
just dev-check   # fmt + clippy
just qa          # full quality gate
```
