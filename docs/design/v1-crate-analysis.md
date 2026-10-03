# v1 Crate Analysis: control, common, acl, tunnel-ws

## Status

Accepted analysis, 2026-10-03.

## Purpose

The v1 workspace (tag `archive/v1-20261002`) carried four crates that P3a does
not port: `control`, `common`, `acl` and `tunnel-ws`. They encode the v1
account contract (NSD-assigned IPv4 VIPs, machine IDs, realm registrations),
which migration M6 replaces with node IDs and `node6`. This note classifies
every part of them so that P3b can design `nsshared-control` v2 from a known
inventory instead of porting v1 code.

Classes used in the tables:

- **(a) P3b / M6**: the concept returns in P3b as part of a newly designed
  `nsshared-control` v2 contract. Nothing is ported; the v1 shape is input only.
- **(b) nsplane**: moves to nsplane as `nsplane-acl`.
- **(c) client**: stays in ns as client runtime, configuration or local state.
- **(d) superseded / dropped**: covered by `nsshared-wire` or
  `nsshared-rendezvous` already, or not carried forward.

## control

### Purpose

Control-plane client for the v1 node: Ed25519 machine registration and
authentication against NSD, a signed CBOR envelope around every call, the
config stream (SSE, Noise or QUIC outer transport), the typed config messages,
and the multi-NSD merge that turns several streams into one effective config.
About 25,000 lines; `messages.rs` alone is 7,469.

### Modules

- `api` — CBOR payload structs per envelope `api` identifier (info, register, auth, heartbeat, services report).
- `auth` — `AuthClient`, envelope signer and pinned verification, NSD JWT verifier, config-stream replay cache, heartbeat client.
- `bootstrap` — control-transport bootstrap and multi-endpoint fallback orchestration.
- `device_flow` — OAuth2 device authorization grant (RFC 8628) client for interactive registration.
- `envelope` — `ControlEnvelope` CBOR format, domain-separated signing input, clock-skew and replay windows, WG relay lease deadlines.
- `merge` — multi-NSD merge of `WgConfig`, `ProxyConfig` and layered `AclConfig`.
- `messages` — `ControlMessage` and its config payloads (WG, proxy, ACL, routing, DNS, peer candidates, policy version, edge configs).
- `multi` — `MultiControlPlane`, concurrent connections to every configured NSD with merged republish.
- `retry` — bounded exponential backoff for cold-boot registration.
- `signed_url` — SigV4-style canonical request for HMAC signed URLs.
- `sse` — `ControlStream` trait and the SSE / Noise stream readers.
- `subnet_route` — node subnet-route report, approved-route config, IPv4 overlap and reserved-range checks.
- `transport/builder` — picks an outer transport from `control_mode` and advertised key material.
- `transport/framing` — HTTP/1.1 unary and GET framing over a byte stream, body and header limits.
- `transport/mod` — `ControlTransport` trait, `BoxStream`, instrumented call helpers.
- `transport/noise` — `Noise_IK_25519_ChaChaPoly_BLAKE2s` over TCP.
- `transport/quic` — HTTP over QUIC with a pinned self-signed certificate.
- `transport/sse` — HTTPS via `tokio-rustls`.
- `types` — `ConnectorType` and `WssLegRole` tokens.
- `tests/node_contract_fixtures` — fixture tests for node-facing payload shapes.

### Classification

| Part | Class | Reason |
| --- | --- | --- |
| `api` register / auth / heartbeat / info payloads | (a) | Two-party ns ↔ nsd contract; v1 keys them by machine ID and realm, M6 keys them by node ID. |
| `api` services report / ack payloads | (a) | Shared report shape; service addresses move from NSD IPv4 VIPs to `node6`. |
| `envelope` format, signing input, skew and replay windows | (a) | Signature rules must match byte for byte on both sides; v2 restates them with new domain strings and vectors. |
| `envelope` WG relay lease deadlines | (d) | v1 relay lease model; relay v2 (`NSR2`, `nsshared-wire`) has no lease. |
| `auth` envelope and stream-event verification rules | (a) | The verification algorithm is part of the envelope contract. |
| `auth` HTTP client, JWT verifier, replay cache, heartbeat loop | (c) | Client runtime around the contract. |
| `bootstrap`, `retry`, `device_flow` | (c) | Client orchestration and UX; nsd does not encode them. |
| `messages` `WgConfig`, `PeerConfig`, `ProxyConfig`, `RoutingConfig`, `DnsConfig` | (a) | Core config stream; every address field is NSD IPv4 and is redesigned for `node6`. |
| `messages` `PeerCandidates`, `PolicyVersion`, `TokenRefresh`, `Ping` / `Pong` | (a) | Stream control messages both sides encode; the shapes are small but tied to v1 identifiers. |
| `messages` `AclConfig` envelope | (a) | The config message that carries policy stays a control message. |
| `messages` `AclConfig` policy payload | (b) | The policy model belongs to `nsplane-acl`; control carries it opaquely or by reference. |
| `messages` `WssRelayDial`, `LinkMode` | (d) | Superseded by the relay directory v2 in `nsshared-rendezvous` and relay v2 framing in `nsshared-wire`. |
| `messages` `Gateway*` config and report variants | (d) | Not part of the ns ↔ nsd contract set; dropped from nsshared. |
| `merge` WG / proxy merge, `multi` | (c) | Multi-NSD merge is client policy, not a wire contract. |
| `merge` layered ACL merge | (b) | ACL layering semantics move with the policy engine. |
| `signed_url` | (d) | Not used by ns or nsd; dropped. |
| `sse` `ControlStream` readers | (c) | Client stream runtime; the event shape is covered by the `messages` rows. |
| `subnet_route` report, config and limits | (a) | Authority split (report is intent, config is approval) is a real contract; prefixes and reserved ranges are IPv4 and are redesigned with M6. |
| `transport` Noise pattern, QUIC pin rule, framing limits | (a) | Parameters the NSD-side proxy must match; v2 restates them as constants with vectors. |
| `transport` implementations (`builder`, `noise`, `quic`, `sse`) | (c) | Client I/O code. |
| `types::ConnectorType` | (a) | Replaced by the node capability vocabulary designed in P3b. |
| `types::WssLegRole` | (d) | v1 WSS leg roles; relay v2 has no leg roles. |
| `tests/node_contract_fixtures` | (a) | Returns as independent vectors in `tools/vectors`, not as Rust-only fixtures. |

## common

### Purpose

Shared types for the v1 node workspace: layered node configuration, machine
identity and per-realm registration state, local `services.toml` validation,
capability tokens, internal DNS name helpers, TOFU pin stores, and the
`Tunnel` trait.

### Modules

- `lib` — `ConnectorConfig`, `ControlCenterConfig`, `ConntrackConfig`, `LocalAclConfig`, `DataPlaneMode`, `SystemInfo`, `Protocol`, `IpNet` re-export.
- `dns_names` — `n.ns.io` / `m.ns.io` / `gw.ns.io` suffixes and FQDN builders and checks.
- `envelope_pins` — TOFU store for NSD envelope signing keys, OKP thumbprints.
- `jwt_pins` — TOFU store for NSD JWKS RSA keys, JWK thumbprints and validation.
- `node_capability` — versioned `node.*.v1` capability tokens and recognition.
- `services` — `services.toml` model, settings, validation, port and protocol matching.
- `state` — `MachineState` (Ed25519 + X25519 keys), per-realm registration files, capability and scope constants.
- `tunnel` — `Tunnel` trait, `TransportType`, default WG plaintext MTU.

### Classification

| Part | Class | Reason |
| --- | --- | --- |
| `lib` node configuration structs and `DataPlaneMode` | (c) | ns configuration file model, read only by ns. |
| `lib` `SystemInfo` | (a) | Sent in registration; returns as a field set of the v2 register payload. |
| `lib` `Protocol` | (a) | Shared L4 vocabulary used by services and config messages. |
| `lib` `GatewayConfig`, `IpNet` re-export | (d) | Not needed by the v2 contract set; callers depend on `ipnet` directly. |
| `dns_names` | (a) | Internal names are agreed by ns and nsd; v2 names are node-ID based (quick-v2 §11) and the suffix plan is set with M6. |
| `envelope_pins`, `jwt_pins` | (c) | Client trust-on-first-use state under the state directory. |
| `node_capability` | (a) | Capability negotiation is a two-party contract; tokens are re-versioned for v2. |
| `services` `services.toml` model and validation | (c) | Local whitelist enforced only by ns. |
| `services` public-ingress and preference enums | (d) | Edge routing preferences outside the ns ↔ nsd contract; dropped. |
| `state` `MachineIdentity` keys | (d) | Superseded by the typed identity and session keys in `nsshared-wire` (P3a item 1). |
| `state` registration files, `NsdInfo`, `AuthMethod` | (c) | Client persistence; the registration exchange itself is covered in `control`. |
| `state` capability tokens for node features and `policy_version.v1` | (a) | Negotiated with nsd; folded into the v2 capability vocabulary. |
| `state` public-edge capability and scope constants | (d) | Not part of the ns ↔ nsd contract set; dropped. |
| `tunnel` | (c) | Data-plane abstraction inside ns. |

## acl

### Purpose

Accept-only ACL engine: the policy data model (rules, groups, bindings,
tests), subject matching, the evaluation engine with verified source and
target identities, layered local + remote policy merge, and a local
deny-scope post-filter.

### Modules

- `policy` — `AclPolicy`, rules, bindings, service floor, inline tests, lint.
- `engine` — `AclEngine`, `AccessContext`, source and target identities, decisions, `wg_peer_anchor`.
- `matcher` — internal CIDR, port and subject matching.
- `merge` — layered merge of local and per-NSD remote policies with provenance.
- `deny_scope` — operator deny-scope filter applied before load.
- `subject` — canonical encoding of colon-delimited external subjects.

### Classification

| Part | Class | Reason |
| --- | --- | --- |
| `policy` | (b) | Policy model is authored and validated by the plane. |
| `engine`, `matcher` | (b) | Evaluation must match the plane's own checks; one engine lives in `nsplane-acl`. |
| `merge`, `deny_scope` | (b) | Layering semantics are part of the policy contract. |
| `subject` | (b) | Subject encoding is defined with the policy model. |
| `engine::wg_peer_anchor` | (d) | Peer anchors become node IDs from `nsshared-wire`. |

ns consumes `nsplane-acl` for enforcement; nothing of `acl` stays in nsshared.

## tunnel-ws

### Purpose

Single-file crate (3,587 lines): a WebSocket stream multiplexer that proxies
TCP and UDP to local services without WireGuard, plus the opaque WSS carrier
that tunnels WireGuard datagrams over WebSocket, the TLS connector helper and
connection events.

### Modules

- `lib` (only module) — sections: TLS connector helper, `WssTargetResolver` trait, errors, connection events, opaque carrier helpers and `run_wg_over_ws_*` pumps, frame command discriminants, `WsFrame` codec, per-stream handle, `WsTunnel`, ACL policy check, frame dispatch, TCP relay, UDP relay.

### Classification

| Part | Class | Reason |
| --- | --- | --- |
| Opaque WSS carrier paths, URL builders, `run_wg_over_ws_*` | (d) | Superseded by relay v2 over WSS (`NSR2`, `nsshared-wire`) and the relay directory v2. |
| `WsFrame` stream-mux codec | (d) | v1 proxy mux framing; v2 carries WireGuard over the relay, no stream mux contract. |
| `WsTunnel`, TCP / UDP relay, frame dispatch | (c) | Data-plane runtime; if ns keeps a WSS proxy path it owns it. |
| ACL policy check | (c) | Enforcement call site in ns; the engine comes from `nsplane-acl`. |
| TLS connector helper, resolver trait, connection events | (c) | Client I/O plumbing. |

## What P3b Needs

`nsshared-control` v2, designed against the M6 address plan (node IDs,
`node6`), covering:

1. The signed envelope: format, domain-separated signing input, skew and
   replay windows, with independent vectors in `tools/vectors`.
2. Register, auth, heartbeat, info and services-report payloads keyed by node
   ID, including the `SystemInfo` field set.
3. The config stream messages: WG, proxy, routing, DNS, peer candidates,
   policy version, token refresh, keepalive, and an ACL config message that
   carries the `nsplane-acl` policy without nsshared depending on its model.
4. The subnet-route report / approved-config split with v2 prefix rules.
5. The node capability vocabulary and the shared `Protocol` token.
6. The internal DNS name plan for node-ID names.
7. Outer transport parameters (Noise pattern, QUIC pin rule, framing limits)
   as constants.

Everything else is client runtime in ns, moves to `nsplane-acl`, or is already
covered by `nsshared-wire` and `nsshared-rendezvous`.
