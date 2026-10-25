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
| `nsshared-codec` | Canonical CBOR: the NS array profile (`cbor::CborReader`, `cbor::CborWriter`) and the M6 value profile with maps (`cbor::value`), sharing one head encoding; strict base64url / base64 | every contract crate |
| `nsshared-identity` | Typed identity and WireGuard keys, node ID / `node6` / `node4`, canonical realm ids, relay ids, `NodeRecord` and its ordering and conflict state, DNS discovery of records, identity and record constants | ns, the relay, nsd |
| `nsshared-relay` | Relay packets v2, REGISTER, session key, MACs, DATA admission and budget defaults, relay constants | ns and the relay |
| `nsshared-rendezvous` | The `/rendezvous/v1` JSON transport, capabilities, actor `hello`, relay directory v2, mailbox phase rules, node registry, registry constants | ns and the rendezvous service |
| `nsshared-control` | `service`: M6 private service control; `node_control`: Node-control v2 messages and endpoint selection; `account`: the account payload contracts | ns, nsd and the gateway |
| `nsshared-telemetry` | `tracing` subscriber setup (text or JSON, env filter with a default; installs the global subscriber, no exporter), `Redacted` and the sensitive field names | Every Rust component |
| `nsshared-proto` | Deprecated facade: the 0.6 paths of the identity, relay, rendezvous, Node-control and encoding modules | existing consumers |
| `nsshared-service-control` | Deprecated facade: the M6 contract at its existing paths | existing consumers |
| `nsshared-testkit` | Development only: the `.vec` fixture reader, hex helpers, seeded fixture authorities | the integration tests |

Dependencies point one way:

```
nsshared-codec <- nsshared-identity <- nsshared-relay
                                    <- nsshared-rendezvous
                                    <- nsshared-control
nsshared-proto           -> codec, identity, relay, rendezvous, control (facade)
nsshared-service-control -> codec, control (facade)
```

The contract crates are pure: no I/O, no async runtime, no TLS and no runtime
state; callers pass time, randomness, keys and authenticated context. There is
no v1 compatibility code. Not here, by scope: the ns app channel and its
applications (pairing, file transfer), the in-tunnel control runtime, IPv4
aliases and `lan6`, peer-source and path labels (all ns), and the relay region
member protocol (the relay). Crates forbid `unsafe` and deny `unwrap`, `expect`
and `panic` outside tests.

### Export rule

Every public item has exactly one path in its crate. A module either exposes
public child modules or re-exports the public items of private child modules,
never both for the same item. `nsshared-identity`, `nsshared-rendezvous`,
`nsshared-codec` and `nsshared-control` expose area modules; `nsshared-relay`
re-exports its private files at the root beside the public `budget` and
`constants` modules. The facades are the only crates that re-export items of
other crates at additional paths.

### Account contracts

`nsshared_control::account` is organized by layer and family. The layer areas
are `node` (enrollment, lifecycle, Node L3 form and authority), `control`
(bootstrap, signed envelopes and requests, control exchanges and reports,
machine tokens, route commands, Node L3 status, the M6 carrier, operation
names) and `publication` (signed events and snapshots, the family registry,
source bindings and publications, subscriptions and snapshot requests). The
family areas are `realm`, `grants`, `subnet`, `edge`, `relay` and `usage`.
`account::domains` holds every signature and digest domain. Private `codec`,
`limits` and `signing` modules hold the reader, writer, validation and
signature rules every family shares; every signed contract builds its signing
input and verifies with the same domain-separated strict Ed25519 rule. The
specifications are in [docs/spec](spec/README.md).

## Examples

`examples/` holds mock crates: libraries (with a binary) for ns development
and tests, `publish = false`, never consumed by production components.

| Crate | Serves |
| --- | --- |
| `nsshared-mock-relay` | A single-instance, in-memory relay v2 over the UDP and WSS carriers on one port: REGISTER, PRESENCE-confirmed sessions and DATA forwarding, with a sans-IO core built on `nsshared-relay`; no region, mesh or owner fencing. Its integration tests include a client that reproduces the ns `RelayClient` byte layout |
| `nsshared-mock-rendezvous` | A single-instance `/rendezvous/v1` relay over TLS WebSocket: challenge and `hello`, the mailbox broker, `directory` and the node registry, with every rendezvous §6 and quick-v2 §7.4 limit configurable; no region |
| `nsshared-mock-server` | Both mocks behind one authority: relay UDP and one TCP+TLS listener with one certificate on the same port, routing `/ns/v2` to the relay mock and `/rendezvous/v1` to the rendezvous mock; the served directory is the server itself with `udp`, `wss`, `mailbox` and `registry` |

The rendezvous mock reuses `nsshared_rendezvous` for every encoding and
protocol rule and adds only storage, randomness, clocks, rate limits and I/O
(tokio, rustls with aws-lc-rs, tokio-tungstenite). Its state modules do no I/O
and take time and randomness from the caller. The combined server adds only the
shared listener, the per-upgrade router and the lifecycle; each mock keeps its
own state.

## Conformance

`crates/<crate>/tests/vectors/` holds the conformance vectors of each crate. They
are produced by `tools/vectors`, a standard-library Python generator that
implements the specification directly and never builds or calls the Rust
crates, so the vectors cross-check the implementation. Each vector file is
named after the test module that reads it, and its producer after both:
`account::edge::routing` reads `tests/vectors/account/edge/routing.vec`, written
by `tools/vectors/nsvec/producers/control/account/edge/routing.py`. Vector
headers name the specification in this repository and, separately, the
sections of the external docs at their pinned commit. `just vectors`
regenerates them; `just vectors-check` reruns the generator in check mode and
is part of `just qa`. The specification-to-code tables are
`docs/spec-coverage/quick-v2.md` and `docs/spec-coverage/rendezvous.md`.

Each crate has one integration test binary per contract area, built on
`nsshared-testkit`.

## Consumers

| Consumer | Status (2026-10-10) |
| --- | --- |
| ns | Uses `nsshared-proto`, `nsshared-telemetry` and the three mocks at tag `v0.5.0` from `https://github.com/dotns/nsshared`; owns the pairing, control-channel runtime, alias and `lan6` code since `v0.2.0` |
| nsgw | Uses the archived v1 workspace; its next line adopts `nsshared-proto` for the relay v2 server (R1), including the `v0.6.0` registry state |
| nsd | Defines its own types |

Consumers pin a tag through Cargo git dependencies; see
`docs/decisions/2026-10-02-ns-shared-next-baseline.md`. The facades keep their
existing imports building; each consumer moves its imports to the defining
crates in its own repository.
