# nsshared Architecture

`nsshared` holds the generic protocols and tools that two or more NSIO
components encode or use, together with their reference implementations.
Application protocols and component-internal architecture stay in the owning
repository, so that their changes never require an nsshared release. The scope and the ownership
rules are defined on the docs site (`ns-shared/index.md`).

## Workspace

The `next` workspace was rebuilt on 2026-10-02 around the Quick protocol. The
previous workspace is archived at tag `archive/v1-20261002`.

| Crate | Contract | Encoded by |
| --- | --- | --- |
| `nsshared-proto` | Identities and typed keys, node ID / `node6` / `node4`, `NodeRecord`, relay packets v2; `rendezvous`: the `/rendezvous/v1` JSON transport, capabilities, actor `hello`, relay directory v2, mailbox phase rules and node registry; `encoding`: strict base64url / base64 and canonical CBOR | ns and the relay |
| `nsshared-telemetry` | `tracing` subscriber setup (text or JSON, env filter with a default; installs the global subscriber, no exporter), `Redacted` and the sensitive field names | Every Rust component |

`nsshared-proto` is pure: no I/O, no async runtime, no TLS. Not here, by
scope: the ns app channel and its applications (pairing, file transfer), the
in-tunnel control channel, IPv4 aliases and `lan6`, peer-source and path
labels (all ns), and the relay region member protocol (the relay). Crates
forbid `unsafe` and deny `unwrap`, `expect` and `panic` outside tests.

## Examples

`examples/` holds mock crates: libraries (with a binary) for ns development
and tests, `publish = false`, never consumed by production components.

| Crate | Serves |
| --- | --- |
| `nsshared-mock-relay` | A single-instance, in-memory relay v2 over the UDP and WSS carriers on one port: REGISTER, PRESENCE-confirmed sessions and DATA forwarding, with a sans-IO core built on `nsshared-proto`; no region, mesh or owner fencing. Its integration tests include a client that reproduces the ns `RelayClient` byte layout |
| `nsshared-mock-rendezvous` | A single-instance `/rendezvous/v1` relay over TLS WebSocket: challenge and `hello`, the mailbox broker, `directory` and the node registry, with every rendezvous §6 and quick-v2 §7.4 limit configurable; no region |
| `nsshared-mock-server` | Both mocks behind one authority: relay UDP and one TCP+TLS listener with one certificate on the same port, routing `/ns/v2` to the relay mock and `/rendezvous/v1` to the rendezvous mock; the served directory is the server itself with `udp`, `wss`, `mailbox` and `registry` |

The rendezvous mock reuses `nsshared_proto::rendezvous` for every encoding and
protocol rule and adds only storage, randomness, clocks, rate limits and I/O
(tokio, rustls with aws-lc-rs, tokio-tungstenite). Its state modules do no I/O
and take time and randomness from the caller. The combined server adds only the
shared listener, the per-upgrade router and the lifecycle; each mock keeps its
own state.

## Conformance

`crates/nsshared-proto/tests/fixtures/vectors` holds the conformance vectors. They
are produced by `tools/vectors`, a standard-library Python generator that
implements the specification directly and never builds or calls the Rust
crates, so the vectors cross-check the implementation. `just vectors`
regenerates them; `just vectors-check` reruns the generator in check mode and
is part of `just qa`. The specification-to-code tables are
`docs/spec-coverage/nsshared-proto.md` and
`docs/spec-coverage/nsshared-proto-rendezvous.md`.

## Consumers

| Consumer | Status (2026-10-03) |
| --- | --- |
| ns | Uses `nsshared-wire` / `nsshared-rendezvous` at a pinned local commit; moves to `nsshared-proto` at tag `v0.2.0` and takes over the pairing, control-channel, alias and `lan6` code |
| nsgw | Uses the archived v1 workspace; adopts `nsshared-proto` when it implements the relay v2 server (migration M2) |
| nsd | Defines its own types |

Consumers pin a tag through Cargo git dependencies; see
`docs/decisions/2026-10-02-ns-shared-next-baseline.md`.
