# ns-shared Architecture

`ns-shared` holds the contracts that two or more NSIO components encode or
enforce, together with their reference implementations. Code used by a single
component stays in that component's repository. The scope and the ownership
rules are defined on the docs site (`ns-shared/index.md`).

## Workspace

The `next` workspace was rebuilt on 2026-10-02 around the Quick protocol. The
previous workspace is archived at tag `archive/v1-20261002`.

| Crate | Contract | Encoded by |
| --- | --- | --- |
| `ns-wire` | NS protocol v2 wire formats: identities, node records, relay packets, region and in-tunnel control messages | nsgw quick relay and Quick nodes |
| `quick-rendezvous` | Invitation locators, identity proofs, encrypted handoffs; target rendezvous v2 mailbox messages | nsgw quick relay and Quick nodes |

Both crates are pure: no I/O, no async runtime, no TLS. They forbid `unsafe`
and deny `unwrap`, `expect` and `panic` outside tests.

## Conformance

`crates/ns-wire/tests/fixtures` holds conformance vectors. Vectors are
produced by generators that implement the specification directly and never
call `ns-wire`, so the vectors cross-check the Rust implementation.
`just vectors-check` reruns the generators in check mode.

## Consumers

| Consumer | Status (2026-10-02) |
| --- | --- |
| nsgw | Uses the archived workspace through `../ns-shared` path dependencies; moves to Cargo git dependencies on this workspace in plan `20261002-1516-ns-shared-rebuild` P2 |
| ns | Keeps its own protocol copy; moves to this workspace in the same P2 |
| nsd | Defines its own types |

Consumers pin a tag through Cargo git dependencies; see
`docs/decisions/2026-10-02-ns-shared-next-baseline.md`.
