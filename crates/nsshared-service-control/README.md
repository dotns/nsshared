# M6 service control wire contract

`nsshared-service-control` is the pure, versioned wire contract shared by `ns`,
`nsd`, and service-control consumers. It does not perform authentication, state
persistence, port allocation, lease timing, or traffic enforcement. Callers use
the existing signed control transport and verify its authenticated identity
before applying a decoded `Message`.

The capability is `service_control.v1`; the wire schema is integer `1`. The
public entry points are `Message::encode` and `Message::decode`. `MessageBody`
determines its wire kind, and each body has exact fields. Unknown fields,
noncanonical CBOR, duplicate map keys, nonminimal item heads, invalid service
references, stale body/header echoes, and malformed typed snapshots are
rejected. The raw envelope is private to the crate.

`ReportContent::canonical`, `ListenerIntent::canonical`, and
`Snapshot::canonical` return domain-separated SHA-256 digests. A report contains
the complete declaration set. A snapshot is per recipient and Network;
publisher-only `listeners` carry backend coordinates. Consumer-visible
`resources` carry the validated declaration `service_label` for local DNS, and
`grants` carry an allowed TCP/UDP subset. Collection order is by complete
`ServiceRef` and endpoint identity, rather than map or arrival order.

The independent Python generator in `vectors/generate.py` produces the checked
CBOR and digest fixtures in `vectors/service-control-v1.json`. `just vectors-check`
checks for drift. `tests/message_schema.rs` exercises every
message kind, negative field cases, scope echoes and a nonempty snapshot.

The companion M6 service-control plan in `ns/docs/plan` defines persistence,
port arbitration, runtime/session fencing, ready/lease timing, and the real R1
Relay v2 acceptance path. A caller must persist the required floors and apply
its data gate before reporting successful enforcement. A successful snapshot
ACK does not grant service use.
