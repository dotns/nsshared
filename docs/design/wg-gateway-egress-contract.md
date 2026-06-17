# WG GatewayEgress Control Contract

## Status

Accepted for additive shared contract definition.

## Purpose

NSGW needs a control-plane snapshot that tells it which WireGuard source VIPs
may reach which gateway-owned service VIPs, and how to recover the ACL source
identity at the transparent listener. The NSD producer lives outside this crate,
so `ns-shared` only defines the wire contract and compatibility rules.

## Message

`ControlMessage::GatewayEgressWgConfig` uses the server-to-gateway config-stream
wire tag `gateway_egress_wg_config.v1`.

The snapshot is split into two lists:

- `pairings`: service authorization rows.
- `source_identities`: source VIP to ACL identity rows.

The split keeps identity data from being duplicated across multiple service
ports for the same source VIP.

## Pairing Schema

Each `GatewayEgressWgPairing` row contains:

- `realm_id: String`: realm that owns the selection.
- `source_vip: Ipv4Addr`: WG source VIP assigned to the connector.
- `service_vip: Ipv4Addr`: gateway-owned service VIP matched by NSGW.
- `protocol: RouteProtocol`: concrete L4 protocol, `tcp` or `udp`.
- `port: u16`: service port matched with the protocol.
- `service_ref: String`: gateway service declaration reference.
- `generation: u64`: monotonic producer generation for stale-row rejection.

`Ipv4Addr` matches existing WG tunnel and VIP conventions. `RouteProtocol` is
used instead of `Protocol` because nft/TPROXY matching needs one concrete L4
protocol, not `both`, `http`, or `https`.

## Source Identity Schema

Each `GatewayEgressWgSourceIdentity` row contains:

- `realm_id: String`: realm that owns the VIP assignment.
- `source_vip: Ipv4Addr`: WG source VIP used as the lookup key.
- `subject: String`: canonical ACL subject such as `user:alice`,
  `group:eng`, or `machine:m-1`.
- `terminate_binding_anchor: String`: anchor used to build
  `SourceAssertion::Terminate { binding: TerminateBinding { anchor } }`.
- `generation: u64`: monotonic producer generation for stale-row rejection.

The identity key is `(realm_id, source_vip)`. Consumers must fail closed when a
key has duplicate conflicting rows, no identity row, or an identity generation
older than the pairing generation being evaluated.

## Source Identity Recovery

After WireGuard decapsulation, the source VIP is cryptokey-authenticated by the
WG peer state. NSD owns the invariant that each active connector has a unique
source VIP within a realm and generation.

At the TPROXY flow point, NSGW uses the packet source VIP and realm-scoped
snapshot to recover `subject` and `terminate_binding_anchor`. It then builds a
terminate-mode ACL context and calls the shared GatewayEgress core with
terminate-mode ACL semantics. The ACL subject is never inferred directly from an
IP address without this signed control-plane mapping.

Duplicate, missing, or stale VIP mappings must fail closed in the NSGW consumer.

## Producer Responsibilities

NSD projects this snapshot from selection state, route/service VIP allocation,
gateway service declarations, and ACL binding state after the contract is
available. It must keep pairings and source identities generation consistent
enough for consumers to reject stale joins.

`nsd-remote` is out of scope for this campaign and is not a producer for this
contract rollout.

## Consumer Responsibilities

NSGW consumes the snapshot by installing nft matches for
`iifname/source_vip/service_vip/protocol/port`. The transparent listener
recovers the original destination, joins `(realm_id, source_vip)` to
`source_identities`, builds a terminate-mode source assertion, and invokes the
shared GatewayEgress ACL, floor, and proxy core.

NSGW must reject traffic when the snapshot join is ambiguous, missing, stale, or
targets an unknown service reference.

## Compatibility

This is an additive control protocol change. It does not remove fields, rename
existing enum variants, change existing wire tags, or alter `GatewayExit`,
`GatewayServicesReport`, or ACL policy semantics. Older consumers continue to
decode unknown config-stream message tags as `ControlMessage::Unknown`.
