# nsshared Architecture

`nsshared` holds the contracts that two or more NSIO components encode or
enforce, together with their reference implementations. Code used by a single
component stays in that component's repository. The scope and the ownership
rules are defined on the docs site (`ns-shared/index.md`).

## Workspace

The `next` workspace was rebuilt on 2026-10-02 around the Quick protocol. The
previous workspace is archived at tag `archive/v1-20261002`.

| Crate | Contract | Encoded by |
| --- | --- | --- |
| `nsshared-wire` | NS protocol v2 wire formats: identities, node records, relay packets, region and in-tunnel control messages | nsgw quick relay and Quick nodes |
| `nsshared-rendezvous` | NS rendezvous v2 (`/quick/v2`): JSON transport, capabilities, actor `hello`, relay directory v2, mailbox phase rules, node registry, pairing payloads, region frame bodies 10-12 | nsgw quick relay and Quick nodes |

Both crates are pure: no I/O, no async runtime, no TLS. They forbid `unsafe`
and deny `unwrap`, `expect` and `panic` outside tests.

## Conformance

`crates/nsshared-wire/tests/fixtures/vectors` and
`crates/nsshared-rendezvous/tests/fixtures/vectors` hold conformance vectors. They
are produced by `tools/vectors`, a standard-library Python generator that
implements the specification directly and never builds or calls the Rust
crates, so the vectors cross-check the implementation. `just vectors`
regenerates them; `just vectors-check` reruns the generator in check mode and
is part of `just qa`. The specification-to-code tables are
`docs/spec-coverage/nsshared-wire.md` and `docs/spec-coverage/nsshared-rendezvous.md`.

## Consumers

| Consumer | Status (2026-10-02) |
| --- | --- |
| nsgw | Uses the archived workspace through `../ns-shared` path dependencies; moves to Cargo git dependencies on this workspace in plan `20261002-1516-ns-shared-rebuild` P2 |
| ns | Keeps its own protocol copy; moves to this workspace in the same P2 |
| nsd | Defines its own types |

Consumers pin a tag through Cargo git dependencies; see
`docs/decisions/2026-10-02-ns-shared-next-baseline.md`.
