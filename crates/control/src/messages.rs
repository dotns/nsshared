use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64_STANDARD};
use common::{
    GatewayPreference, IpNet, Protocol, PublicIngressSubjectPolicy, ServicesConfig, SystemInfo,
    TunnelPreference,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// WireGuard configuration received from the control plane.
///
/// The private key is **not** included — clients use their local `peer_key`
/// from the machine state file.
///
/// Structural equality is used by consumers to skip redelivered identical
/// configs without tearing down the running WireGuard device.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WgConfig {
    pub ip_address: Ipv4Addr,
    pub listen_port: u16,
    pub peers: Vec<PeerConfig>,
}

/// WireGuard peer configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerConfig {
    #[serde(deserialize_with = "deserialize_wg_public_key")]
    pub public_key: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive: u16,
    /// Present on a connector's NSN peer for any edge whose primary or
    /// fallback path is `wss-relay`. When set, the peer is reached through an
    /// opaque WireGuard-over-WebSocket dial to the gateway
    /// (`/client?mode=wss-relay&nsn=...`) driven by a local UDP pump,
    /// instead of `endpoint`. Additive and `None` for every other mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wss_relay: Option<WssRelayDial>,
    /// Opaque WSS-relay dial to fall back to when the UDP primary path fails.
    /// Contract: valid only alongside `endpoint: Some(..)` (a wg-relay or
    /// direct primary); mutually exclusive with `wss_relay: Some(..)`; absent
    /// on every non-dual edge. Preference is positional: the primary slot
    /// (`endpoint` or `wss_relay`) is tried before this fallback slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wss_relay_fallback: Option<WssRelayDial>,
}

/// Opaque WSS-relay dial hint carried on a [`PeerConfig`] for a `wss-relay` edge.
///
/// NSD projects the NSN `machine_id` here (the NSGW bridge pairs the two opaque
/// legs by authenticated identity, so NSC must know which NSN to target). No NSN
/// endpoint is ever carried — both ends dial outbound to NSGW (DERP invariant,
/// `docs/acl-identity-transport-design.md` §8).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct WssRelayDial {
    pub nsn_machine_id: String,
    /// NSC machine id of the authorized client pair this dial belongs to.
    /// On an NSN-side client peer it drives one outbound opaque leg per pair
    /// (`GET /wss-relay?nsc=...`). Absent on projections from an older NSD —
    /// consumers then keep the legacy single-leg behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsc_machine_id: Option<String>,
    /// Id of the gateway both ends of the pair must dial (rendezvous hint).
    /// Resolved against the gateway roster; consumers fall back to the
    /// primary/first gateway when absent or unresolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<String>,
}

/// Link-mode tokens advertised at registration and used by NSD projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkMode {
    Direct,
    Terminate,
    WgRelay,
    WssRelay,
}

impl std::str::FromStr for LinkMode {
    type Err = String;

    /// Parse the kebab-case wire token (`direct`, `terminate`, `wg-relay`,
    /// `wss-relay`); case-insensitive and `_`/`-` tolerant for CLI ergonomics.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "direct" => Ok(LinkMode::Direct),
            "terminate" => Ok(LinkMode::Terminate),
            "wg-relay" => Ok(LinkMode::WgRelay),
            "wss-relay" => Ok(LinkMode::WssRelay),
            other => Err(format!(
                "unknown link mode {other:?}: expected direct|terminate|wg-relay|wss-relay"
            )),
        }
    }
}

/// Parse a comma-separated list of [`LinkMode`] tokens, ignoring empty entries.
///
/// # Errors
///
/// Returns the first unparsable token's error message.
pub fn parse_link_modes(list: &str) -> Result<Vec<LinkMode>, String> {
    use std::str::FromStr as _;
    list.split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(LinkMode::from_str)
        .collect()
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WirePublicKey {
    Bytes(Vec<u8>),
    Text(String),
}

fn deserialize_wg_public_key<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    match WirePublicKey::deserialize(deserializer)? {
        WirePublicKey::Bytes(bytes) => key_bytes_to_array(bytes).map_err(de::Error::custom),
        WirePublicKey::Text(text) => parse_wg_public_key(&text).map_err(de::Error::custom),
    }
}

fn serialize_wg_public_key<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&B64_STANDARD.encode(value))
}

fn parse_wg_public_key(raw: &str) -> Result<[u8; 32], String> {
    let value = raw.trim();
    let bytes = if value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        hex::decode(value).map_err(|err| format!("invalid WireGuard public_key hex: {err}"))?
    } else {
        B64_STANDARD
            .decode(value)
            .map_err(|err| format!("invalid WireGuard public_key: {err}"))?
    };
    key_bytes_to_array(bytes)
}

fn key_bytes_to_array(bytes: Vec<u8>) -> Result<[u8; 32], String> {
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("invalid WireGuard public_key length: expected 32 bytes, got {len}"))
}

/// Proxy configuration received from the control plane.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    pub chain_id: String,
    pub rules: Vec<SubnetRule>,
    /// Virtual-port mappings (D2): each entry tells NSN to listen on
    /// `listen_port` on its WG IP and forward to `target_host:target_port`.
    ///
    /// Defaults to empty so pre-D2 payloads still deserialize; the field is
    /// omitted from the wire when empty so byte parity with pre-D2 producers
    /// is preserved for the common case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_mappings: Vec<PortMapping>,
}

/// Virtual-port forwarding rule pushed by NSD to NSN.
///
/// Mirrors the TypeScript [`PortMapping`] shape used by `nsd-mock`
/// (`tests/docker/nsd-mock/src/types.ts:39-44`) and emitted by
/// `tests/docker/nsd-mock/src/registry.ts:171-176`. NSN's `ServiceRouter`
/// binds `listen_port` on its WG interface and proxies incoming TCP/UDP
/// connections to `target_host:target_port`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PortMapping {
    /// Virtual port NSN binds on its WG IP.
    pub listen_port: u16,
    /// Address (typically a loopback or RFC-1918 IP) of the real service.
    pub target_host: String,
    /// Real service port behind the proxy.
    pub target_port: u16,
    /// Transport protocol for both the listener and the upstream connection.
    pub protocol: Protocol,
}

/// A single subnet-level DNAT rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubnetRule {
    pub resource_id: String,
    pub source_prefix: IpNet,
    pub dest_prefix: IpNet,
    pub rewrite_to: RewriteTarget,
    pub port_range: Option<(u16, u16)>,
    pub protocol: Protocol,
}

/// Where to rewrite the destination.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RewriteTarget {
    Ip(IpAddr),
    Cidr(IpNet),
    Domain(String),
}

/// Payload carried by an [`AclConfig`] on the wire.
///
/// Three-state sentinel distinguishes real policies from explicit empties and
/// transient fetch failures, so the merger can preserve last-good state instead
/// of collapsing silence into default deny (PLAN-020).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AclPayload {
    /// NSD shipped a real policy.
    Loaded { policy: Box<acl::AclPolicy> },
    /// NSD deliberately published an empty policy.
    ExplicitEmpty,
    /// NSN could not fetch a policy (SSE error, NSD 5xx, etc.). The merger
    /// should serve the last-good cache, or mark the merge as `degraded` when
    /// no cache is available.
    FetchFailed { error: String },
}

impl AclPayload {
    /// Build a loaded ACL payload.
    pub fn loaded(policy: acl::AclPolicy) -> Self {
        Self::Loaded {
            policy: Box::new(policy),
        }
    }

    /// Convenience: the policy to use when this payload is contributing to a
    /// merge. Returns `None` for `ExplicitEmpty` and `FetchFailed`.
    pub fn policy(&self) -> Option<&acl::AclPolicy> {
        match self {
            AclPayload::Loaded { policy } => Some(policy.as_ref()),
            AclPayload::ExplicitEmpty | AclPayload::FetchFailed { .. } => None,
        }
    }

    /// `true` when this payload represents a transient failure.
    pub fn is_failed(&self) -> bool {
        matches!(self, AclPayload::FetchFailed { .. })
    }

    /// Short static label for metrics/observability.
    pub fn label(&self) -> &'static str {
        match self {
            AclPayload::Loaded { .. } => "loaded",
            AclPayload::ExplicitEmpty => "empty",
            AclPayload::FetchFailed { .. } => "failed",
        }
    }
}

impl<'de> Deserialize<'de> for AclPayload {
    /// Accept only the sentinel shape. `acl_config` is a breaking schema:
    /// every payload must carry a `state` discriminator.
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let value = serde_json::Value::deserialize(de)?;
        let obj = value
            .as_object()
            .ok_or_else(|| D::Error::custom("AclPayload must be an object"))?;

        let state = obj
            .get("state")
            .and_then(|v| v.as_str())
            .ok_or_else(|| D::Error::custom("AclPayload requires a 'state' discriminator"))?;
        match state {
            "loaded" => {
                let policy = obj
                    .get("policy")
                    .cloned()
                    .ok_or_else(|| D::Error::custom("state=loaded requires policy"))?;
                let policy: acl::AclPolicy =
                    serde_json::from_value(policy).map_err(D::Error::custom)?;
                Ok(AclPayload::loaded(policy))
            }
            "explicit_empty" => Ok(AclPayload::ExplicitEmpty),
            "fetch_failed" => {
                let error = obj
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned();
                Ok(AclPayload::FetchFailed { error })
            }
            other => Err(D::Error::custom(format!(
                "unknown AclPayload state '{other}'"
            ))),
        }
    }
}

/// ACL policy delivered by the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclConfig {
    /// Idempotency key — same semantics as `ProxyConfig::chain_id`.
    pub chain_id: String,
    /// Sentinel-tagged payload: loaded policy, explicit empty, or fetch failure.
    #[serde(flatten)]
    pub payload: AclPayload,
}

impl AclConfig {
    /// Build a `Loaded` config from a plain policy — convenience for callers
    /// that do not need the failure sentinel.
    pub fn loaded(chain_id: impl Into<String>, policy: acl::AclPolicy) -> Self {
        Self {
            chain_id: chain_id.into(),
            payload: AclPayload::loaded(policy),
        }
    }

    /// Build an `ExplicitEmpty` config.
    pub fn explicit_empty(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            payload: AclPayload::ExplicitEmpty,
        }
    }

    /// Build a `FetchFailed` config.
    pub fn fetch_failed(chain_id: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            payload: AclPayload::FetchFailed {
                error: error.into(),
            },
        }
    }

    /// Borrow the inner policy if this envelope is `Loaded`.
    pub fn policy(&self) -> Option<&acl::AclPolicy> {
        self.payload.policy()
    }
}

// ── services report ───────────────────────────────────────────────────────────

/// A single service entry in a [`ServiceReport`].
///
/// Mirrors [`common::ServiceDef`] but is owned by the control crate so it can
/// be serialised and sent over the SSE data channel.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceInfo {
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Layer-7 virtual domain for HTTP Host / TLS SNI routing.
    ///
    /// Mirrors [`common::ServiceDef::domain`] so that the control plane can
    /// publish alias DNS records (e.g. a human-friendly name that resolves to
    /// the same NSN as the FQID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Preferred tunnel transport for this service.
    #[serde(default)]
    pub tunnel: TunnelPreference,
    /// Preferred gateway for this service.
    #[serde(default)]
    pub gateway: GatewayPreference,
    /// Public ingress subject policy for this service.
    #[serde(default)]
    pub public_ingress_subject_policy: PublicIngressSubjectPolicy,
}

/// Snapshot of the client's local service whitelist, sent to the server
/// immediately after the SSE connection is established.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceReport {
    /// Map from service name → service metadata.
    pub services: HashMap<String, ServiceInfo>,
    /// Whether the client is running in strict validation mode.
    pub strict_mode: bool,
    /// System information snapshot. Present on initial report and reconnects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_info: Option<SystemInfo>,
}

impl From<&ServicesConfig> for ServiceReport {
    fn from(config: &ServicesConfig) -> Self {
        let services = config
            .services
            .iter()
            .map(|(name, def)| {
                let info = ServiceInfo {
                    protocol: def.protocol,
                    host: def.host.clone(),
                    port: def.port,
                    enabled: def.enabled,
                    description: def.description.clone(),
                    domain: def.domain.clone(),
                    tunnel: def.tunnel.clone(),
                    gateway: def.gateway.clone(),
                    public_ingress_subject_policy: def.public_ingress_subject_policy,
                };
                (name.clone(), info)
            })
            .collect();
        ServiceReport {
            services,
            strict_mode: config.is_strict(),
            system_info: None,
        }
    }
}

/// Server acknowledgement of a [`ServiceReport`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServicesAck {
    /// Service names that have at least one matching proxy rule.
    pub matched: Vec<String>,
    /// Service names with no proxy rules targeting them.
    pub unmatched: Vec<String>,
    /// Proxy rule resource IDs targeting services not in the client report.
    pub rejected: Vec<String>,
}

// ── routing config ────────────────────────────────────────────────────────────

/// A single route entry in a [`RoutingConfig`].
///
/// Used by NSGW for HTTP reverse-proxy routing and by NSC for local DNS
/// resolution.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteEntry {
    /// Virtual domain name for this service (e.g. `"web.n.ns"`).
    pub domain: String,
    /// Site identifier — typically the NSD site name or NSN machine ID.
    pub site: String,
    /// Service name as defined in `services.toml`.
    pub service: String,
    /// Port the service listens on.
    pub port: u16,
    /// NSN's WG virtual IP for this service (D1).
    ///
    /// Reverse-proxies (NSGW Traefik) connect to this address — it is
    /// reachable via the WG tunnel. `None` on pre-D1 payloads; downstream
    /// consumers fall back to legacy routing in that case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsn_wg_ip: Option<Ipv4Addr>,
    /// NSD-assigned virtual port on NSN's WG IP (D1).
    ///
    /// NSN's `ServiceRouter` listens on this port and proxies to the actual
    /// service (e.g. `10.0.0.2:10000` → `127.0.0.1:80`). `None` on pre-D1
    /// payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_port: Option<u16>,
}

/// Routing configuration pushed by NSD.
///
/// Consumed by NSGW (HTTP reverse-proxy routing) and NSC (local DNS).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoutingConfig {
    pub routes: Vec<RouteEntry>,
}

// ── dns config ────────────────────────────────────────────────────────────────

/// A single DNS record in a [`DnsConfig`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsRecord {
    /// Virtual domain name (e.g. `"web.n.ns"`).
    pub domain: String,
    /// Site identifier — typically the NSD site name or NSN machine ID.
    pub site: String,
    /// Service name.
    pub service: String,
    /// Port the service listens on.
    pub port: u16,
}

/// Global DNS records pushed by NSD to all NSC clients.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    pub records: Vec<DnsRecord>,
}

// ── gateway config ────────────────────────────────────────────────────────────

/// A single gateway entry pushed to NSN clients so they know where to reach
/// the WSS relay endpoint.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayInfo {
    pub id: String,
    /// Resolved "ip:port" UDP WireGuard endpoint.
    pub wg_endpoint: String,
    /// WebSocket relay base URL, e.g. `"ws://172.18.0.5:9443"`.
    pub wss_endpoint: String,
    /// Gateway's tunnel-side IPv4 address. Used by NSN as the ICMP probe
    /// target (PLAN-016). Optional for backward compatibility — when absent
    /// the probe is skipped for this gateway and liveness falls back to the
    /// handshake-count silence detector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_ip: Option<Ipv4Addr>,
    /// Resolved "ip:port" of the gateway's zero-trust WireGuard relay listener
    /// (the separate relay UDP port). Authoritative single source of truth for
    /// the gateway relay socket: NSN derives its wg-relay registration target
    /// and NSN/NSC derive the p2p-reflector target from this. Absent when the
    /// gateway has relay disabled or runs an older build; consumers then fall
    /// back to the legacy port-swap of `wg_endpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_relay_endpoint: Option<String>,
}

/// Gateway configuration pushed by the control plane.
///
/// Contains the WSS relay endpoint for every registered gateway so that NSN
/// can connect to the correct relay when falling back from UDP to WSS.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayConfig {
    pub gateways: Vec<GatewayInfo>,
}

// ── gateway WireGuard relay config ───────────────────────────────────────────

/// How an NSGW relay should demultiplex a relayed WireGuard association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayWgRelayAddressing {
    #[default]
    ReceiverIndex,
    Port,
}

/// A single zero-trust WireGuard relay allowance for one gateway.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GatewayWgRelayPair {
    /// Client-side WireGuard public key.
    #[serde(
        serialize_with = "serialize_wg_public_key",
        deserialize_with = "deserialize_wg_public_key"
    )]
    pub nsc_pubkey: [u8; 32],
    /// NSD-authenticated NSC machine subject allowed to use relay-socket
    /// reflection for this pair.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nsc_machine_id: String,
    /// NSC Ed25519 machine public key expected on reflection envelopes.
    #[serde(
        default,
        serialize_with = "serialize_wg_public_key",
        deserialize_with = "deserialize_wg_public_key"
    )]
    pub nsc_machine_key_pub: [u8; 32],
    /// NSD-authenticated NSN machine subject that owns the registered source.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nsn_machine_id: String,
    /// NSN Ed25519 machine public key expected on registration envelopes.
    #[serde(
        default,
        serialize_with = "serialize_wg_public_key",
        deserialize_with = "deserialize_wg_public_key"
    )]
    pub nsn_machine_key_pub: [u8; 32],
    /// NSN-side WireGuard public key used for mac1 validation.
    #[serde(
        serialize_with = "serialize_wg_public_key",
        deserialize_with = "deserialize_wg_public_key"
    )]
    pub nsn_pubkey: [u8; 32],
    /// Optional public UDP endpoint for static fallback. NAT-only relay pairs
    /// omit this and rely on authenticated learned-source registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsn_endpoint: Option<SocketAddr>,
    /// Relay association addressing strategy.
    #[serde(default)]
    pub addressing: GatewayWgRelayAddressing,
    /// Optional dedicated per-pair relay port for future port-addressed mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
}

/// Gateway-specific WireGuard relay table pushed by NSD.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct GatewayWgRelayConfig {
    pub relay_pairs: Vec<GatewayWgRelayPair>,
}

// ── gateway WebSocket relay config ──────────────────────────────────────────

/// A single zero-trust WebSocket relay allowance for one gateway.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GatewayWssRelayPair {
    /// Authenticated NSC machine subject allowed to use this opaque relay.
    pub nsc_machine_id: String,
    /// Authenticated NSN machine subject that terminates the end-to-end WG leg.
    pub nsn_machine_id: String,
    /// Client-side WireGuard public key.
    #[serde(
        serialize_with = "serialize_wg_public_key",
        deserialize_with = "deserialize_wg_public_key"
    )]
    pub nsc_pubkey: [u8; 32],
    /// NSN-side WireGuard public key used by the NSN peer-key judge.
    #[serde(
        serialize_with = "serialize_wg_public_key",
        deserialize_with = "deserialize_wg_public_key"
    )]
    pub nsn_pubkey: [u8; 32],
}

/// Gateway-specific opaque WebSocket relay table pushed by NSD.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct GatewayWssRelayConfig {
    pub relay_pairs: Vec<GatewayWssRelayPair>,
}

// ── public edge config ───────────────────────────────────────────────────────

/// Public edge listener protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicEdgeProtocol {
    Http,
    Tcp,
    Udp,
}

/// Transport policy for a public edge route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicEdgeTransportPolicy {
    Wg,
    Wss,
    #[default]
    PreferWg,
    PreferWss,
}

impl PublicEdgeTransportPolicy {
    /// Map service tunnel intent into the public ingress gateway policy token.
    pub fn from_service_tunnel_preference(tunnel: &TunnelPreference) -> Self {
        match tunnel {
            TunnelPreference::Auto => Self::PreferWg,
            TunnelPreference::Wg => Self::Wg,
            TunnelPreference::Ws => Self::Wss,
        }
    }
}

/// Public edge backend kind.
///
/// First cut only constructs `NsnBacked`. Gateway-owned egress/exit backends
/// are intentionally omitted until their trust model and declaration contract
/// are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicEdgeBackendKind {
    #[default]
    NsnBacked,
}

/// ACL resource consumed by NSN for `NsnBacked` public edge routes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PublicEdgeAclRef {
    pub realm_id: String,
    pub resource_id: String,
}

/// Policy generation metadata carried with a public edge route.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PublicEdgePolicyRevision {
    pub generation: u64,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_of: Option<u64>,
}

/// Stable route identity for NSD-produced public edge artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PublicEdgeRouteIdentity {
    pub protocol: PublicEdgeProtocol,
    pub realm_id: String,
    pub gateway_id: String,
    pub route_id: String,
    pub public_port: u16,
    pub nsgw_internal_port: u16,
    pub nsn_wg_vip: Ipv4Addr,
    pub upstream_port: u16,
    pub acl: PublicEdgeAclRef,
    pub subject_policy: PublicIngressSubjectPolicy,
    pub transport_policy: PublicEdgeTransportPolicy,
    pub policy_revision: PublicEdgePolicyRevision,
}

/// Transport-agnostic certificate reference carried by public edge snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PublicEdgeCertificateRef {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub policy: PublicEdgeCertificatePolicy,
    pub source: PublicEdgeCertificateSource,
}

/// Certificate policy metadata. Private keys never appear in this contract.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct PublicEdgeCertificatePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_tls_version: Option<String>,
    #[serde(default)]
    pub require_sni: bool,
}

/// Where Envoy/NSGW should resolve certificate material.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicEdgeCertificateSource {
    CertManager { secret_ref: String },
    Sds { secret_name: String },
    MountedSecret { path_ref: String },
    ExternalAcme { certificate_ref: String },
}

/// HTTP external identity import shape. Runtime activation is deferred.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct HttpExternalIdentityImport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<ExternalIdentityProviderRef>,
    #[serde(default)]
    pub anonymous_bypass: bool,
    #[serde(default)]
    pub fail_closed: bool,
}

/// Reference to an external identity provider or credential store.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ExternalIdentityProviderRef {
    pub kind: ExternalIdentityProviderKind,
    pub ref_id: String,
}

/// External identity mechanisms reserved by the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalIdentityProviderKind {
    Oidc,
    OAuth2,
    ClientMtls,
    ApiKey,
    BearerToken,
    SignedRequest,
    BasicAuth,
}

/// Signed internal subject-header policy for NSGW-to-NSN forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct SignedSubjectHeaderPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_header_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyset_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity_seconds: Option<u32>,
    #[serde(default)]
    pub strip_inbound_headers: bool,
}

/// HTTP middleware references reserved by the public edge contract.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct HttpMiddlewarePolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waf_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext_authz_ref: Option<String>,
}

/// Edge rate, connection, and body-size limit references.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct EdgeLimitPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_limit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slow_client_ref: Option<String>,
}

/// HTTP request/response transform references.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct HttpTransformPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_rewrite_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_header_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarded_subject_ref: Option<String>,
}

/// Audit policy references and stable route metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct EdgeAuditPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// A single HTTP public edge host route.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GatewayHttpRoute {
    pub identity: PublicEdgeRouteIdentity,
    pub host: String,
    #[serde(default)]
    pub backend: PublicEdgeBackendKind,
    pub service: String,
    pub site: String,
    #[serde(default)]
    pub identity_import: HttpExternalIdentityImport,
    #[serde(default)]
    pub signed_subject_headers: SignedSubjectHeaderPolicy,
    #[serde(default)]
    pub middleware: HttpMiddlewarePolicy,
    #[serde(default)]
    pub edge_limits: EdgeLimitPolicy,
    #[serde(default)]
    pub transforms: HttpTransformPolicy,
    #[serde(default)]
    pub audit: EdgeAuditPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_ref: Option<String>,
}

/// HTTP public edge routes pushed to capable gateways.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GatewayHttpConfig {
    pub gateway_id: String,
    pub realm_id: String,
    pub routes: Vec<GatewayHttpRoute>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<PublicEdgeCertificateRef>,
}

/// L4 route policy references reserved by the public edge contract.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct L4Policy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_limit_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_limit_ref: Option<String>,
}

/// A single TCP or UDP public listener route.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GatewayL4Route {
    pub identity: PublicEdgeRouteIdentity,
    #[serde(default)]
    pub backend: PublicEdgeBackendKind,
    pub service: String,
    pub site: String,
    /// Required public listener port allocated by NSD from `virtual_port`.
    pub virtual_port: u16,
    #[serde(default)]
    pub l4: L4Policy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_ref: Option<String>,
}

/// TCP/UDP public edge listener map pushed to capable gateways.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GatewayL4Map {
    pub gateway_id: String,
    pub realm_id: String,
    pub routes: Vec<GatewayL4Route>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<PublicEdgeCertificateRef>,
}

// ── direct P2P candidate signaling ──────────────────────────────────────────

/// Direct-P2P candidate category advertised by NSN peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum P2pCandidateKind {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
}

impl P2pCandidateKind {
    /// Maximum number of candidates accepted in one `peer_candidates.report`.
    pub const MAX_PER_REPORT: usize = 16;

    /// Stable DB token for this candidate kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "server_reflexive",
            Self::PeerReflexive => "peer_reflexive",
            Self::Relay => "relay",
        }
    }

    /// Inverse of [`Self::as_str`].
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "host" => Some(Self::Host),
            "server_reflexive" => Some(Self::ServerReflexive),
            "peer_reflexive" => Some(Self::PeerReflexive),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }
}

/// Maximum number of direct-P2P candidates accepted in one report.
pub const MAX_P2P_CANDIDATES_PER_REPORT: usize = P2pCandidateKind::MAX_PER_REPORT;

/// One candidate endpoint for a peer's direct-P2P WireGuard socket.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct P2pCandidate {
    pub kind: P2pCandidateKind,
    pub endpoint: SocketAddr,
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub observed_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
}

/// Client → NSD direct-P2P candidate report.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerCandidatesReport {
    pub epoch: u64,
    #[serde(
        serialize_with = "serialize_wg_public_key",
        deserialize_with = "deserialize_wg_public_key"
    )]
    pub peer_key_pub: [u8; 32],
    #[serde(default)]
    pub candidates: Vec<P2pCandidate>,
}

/// NSD → client direct-P2P candidate update for one remote peer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerCandidatesUpdate {
    pub machine_id: String,
    pub epoch: u64,
    #[serde(
        serialize_with = "serialize_wg_public_key",
        deserialize_with = "deserialize_wg_public_key"
    )]
    pub peer_key_pub: [u8; 32],
    #[serde(default)]
    pub candidates: Vec<P2pCandidate>,
}

// ── control message ───────────────────────────────────────────────────────────

/// Control-plane messages exchanged over the SSE stream.
#[allow(
    clippy::large_enum_variant,
    reason = "ControlMessage keeps stable serde wire shapes; boxing variants would churn every consumer"
)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    WgConfig(WgConfig),
    ProxyConfig(ProxyConfig),
    AclConfig(AclConfig),
    TokenRefresh {
        token: String,
    },
    Ping,
    Pong,
    /// Client → Server: local service whitelist snapshot.
    ServicesReport(ServiceReport),
    /// Server → Client: acknowledgement of [`ServicesReport`].
    ServicesAck(ServicesAck),
    /// Server → Client: gateway list with WSS relay endpoints.
    GatewayConfig(GatewayConfig),
    /// Server → Gateway: zero-trust WireGuard relay pair table.
    GatewayWgRelay(GatewayWgRelayConfig),
    /// Server → Gateway: zero-trust opaque WebSocket relay pair table.
    GatewayWssRelay(GatewayWssRelayConfig),
    /// Server → Client: HTTP routing rules for NSGW and NSC DNS.
    RoutingConfig(RoutingConfig),
    /// Server → Client: global DNS records for all NSC clients.
    DnsConfig(DnsConfig),
    /// Server → Gateway: HTTP public edge routes.
    #[serde(rename = "gateway_http_config.v1")]
    GatewayHttpConfig(GatewayHttpConfig),
    /// Server → Gateway: TCP/UDP public edge listener map.
    #[serde(rename = "gateway_l4_map.v1")]
    GatewayL4Map(GatewayL4Map),
    /// Server → Client: direct-P2P candidate update for one peer.
    PeerCandidates(PeerCandidatesUpdate),
    /// Catch-all for `type` tags introduced by a newer NSD.
    ///
    /// Forward-compatibility contract: an unrecognized tag decodes to this
    /// unit variant (payload discarded) so a single future variant cannot
    /// poison the whole `config.stream` for an older consumer. Decode-only:
    /// this crate must never serialize it — `skip_serializing` turns any
    /// attempt into a serialization error. The original wire tag is not
    /// captured here; recover it from the raw payload with
    /// [`crate::api::probe_config_stream_message_type`].
    #[serde(other, skip_serializing)]
    Unknown,
}

impl ControlMessage {
    /// Bounded, `'static` label for this message kind.
    ///
    /// Used as the `event_type` attribute on the SSE delivery latency
    /// histogram; the domain is the fixed set of variants below, so the
    /// label cardinality is bounded by code.
    pub fn event_type(&self) -> &'static str {
        match self {
            ControlMessage::WgConfig(_) => "wg_config",
            ControlMessage::ProxyConfig(_) => "proxy_config",
            ControlMessage::AclConfig(_) => "acl_config",
            ControlMessage::TokenRefresh { .. } => "token_refresh",
            ControlMessage::Ping => "ping",
            ControlMessage::Pong => "pong",
            ControlMessage::ServicesReport(_) => "services_report",
            ControlMessage::ServicesAck(_) => "services_ack",
            ControlMessage::GatewayConfig(_) => "gateway_config",
            ControlMessage::GatewayWgRelay(_) => "gateway_wg_relay",
            ControlMessage::GatewayWssRelay(_) => "gateway_wss_relay",
            ControlMessage::RoutingConfig(_) => "routing_config",
            ControlMessage::DnsConfig(_) => "dns_config",
            ControlMessage::GatewayHttpConfig(_) => "gateway_http_config.v1",
            ControlMessage::GatewayL4Map(_) => "gateway_l4_map.v1",
            ControlMessage::PeerCandidates(_) => "peer_candidates",
            ControlMessage::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sample_wg_config() -> WgConfig {
        WgConfig {
            ip_address: Ipv4Addr::new(10, 0, 0, 1),
            listen_port: 51820,
            peers: vec![PeerConfig {
                public_key: [2u8; 32],
                endpoint: Some("127.0.0.1:51820".parse().unwrap()),
                allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                persistent_keepalive: 25,
                wss_relay: None,
                wss_relay_fallback: None,
            }],
        }
    }

    // ── WgConfig ──────────────────────────────────────────────────────────────

    #[test]
    fn wg_config_round_trips_via_json() {
        let orig = sample_wg_config();
        let json = serde_json::to_string(&orig).unwrap();
        let decoded: WgConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.ip_address, orig.ip_address);
        assert_eq!(decoded.listen_port, orig.listen_port);
        assert_eq!(decoded.peers.len(), 1);
        assert_eq!(decoded.peers[0].public_key, orig.peers[0].public_key);
        assert_eq!(decoded.peers[0].endpoint, orig.peers[0].endpoint);
        assert_eq!(decoded.peers[0].persistent_keepalive, 25);
    }

    #[test]
    fn wg_config_accepts_hex_public_key_without_endpoint() {
        let cfg: WgConfig = serde_json::from_value(serde_json::json!({
            "ip_address": "10.255.0.1",
            "listen_port": 51820,
            "peers": [{
                "public_key": "f2b39b93f68616b7abf2c3c1f95e09b326820314a4f15fe2dbe5a1c0cb16d43d",
                "allowed_ips": ["10.0.0.2/32"],
                "persistent_keepalive": 0
            }]
        }))
        .unwrap();

        assert_eq!(cfg.peers[0].public_key[0], 0xf2);
        assert_eq!(cfg.peers[0].endpoint, None);
    }

    #[test]
    fn wg_config_accepts_base64_public_key() {
        let key = [7u8; 32];
        let cfg: WgConfig = serde_json::from_value(serde_json::json!({
            "ip_address": "10.255.0.1",
            "listen_port": 51820,
            "peers": [{
                "public_key": B64_STANDARD.encode(key),
                "endpoint": "127.0.0.1:51820",
                "allowed_ips": ["10.0.0.2/32"],
                "persistent_keepalive": 25
            }]
        }))
        .unwrap();

        assert_eq!(cfg.peers[0].public_key, key);
        assert_eq!(cfg.peers[0].endpoint.unwrap().port(), 51820);
    }

    #[test]
    fn wg_config_rejects_invalid_public_key() {
        let err = serde_json::from_value::<WgConfig>(serde_json::json!({
            "ip_address": "10.255.0.1",
            "listen_port": 51820,
            "peers": [{
                "public_key": "bad",
                "allowed_ips": ["10.0.0.2/32"],
                "persistent_keepalive": 0
            }]
        }))
        .unwrap_err();

        assert!(err.to_string().contains("invalid WireGuard public_key"));
    }

    #[test]
    fn wg_config_no_private_key_in_json() {
        let cfg = sample_wg_config();
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(
            !json.contains("private_key"),
            "WgConfig JSON must not contain private_key"
        );
    }

    // Structural equality is what consumers use to skip redelivered identical
    // configs; pin that identical configs compare equal and that every field
    // class (device-level, peer endpoint, peer set) breaks equality.
    #[test]
    fn wg_config_structural_equality_detects_changes() {
        let base = sample_wg_config();
        assert_eq!(base, sample_wg_config());

        let mut listen_port_changed = sample_wg_config();
        listen_port_changed.listen_port += 1;
        assert_ne!(base, listen_port_changed);

        let mut endpoint_changed = sample_wg_config();
        endpoint_changed.peers[0].endpoint = Some("127.0.0.1:51821".parse().unwrap());
        assert_ne!(base, endpoint_changed);

        let mut peer_added = sample_wg_config();
        peer_added.peers.push(PeerConfig {
            public_key: [3u8; 32],
            endpoint: None,
            allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
            persistent_keepalive: 0,
            wss_relay: Some(WssRelayDial {
                nsn_machine_id: "m-nsn".to_owned(),
                nsc_machine_id: None,
                gateway_id: None,
            }),
            wss_relay_fallback: None,
        });
        assert_ne!(base, peer_added);
    }

    // Per-pair wss-relay dial fields are additive: an old-NSD wire body
    // without them decodes to `None` (legacy single-leg behavior), absent
    // fields stay off the wire, and populated fields round-trip.
    #[test]
    fn wss_relay_dial_per_pair_fields_are_additive() {
        let legacy: WssRelayDial = serde_json::from_value(serde_json::json!({
            "nsn_machine_id": "m-nsn",
        }))
        .unwrap();
        assert_eq!(legacy.nsn_machine_id, "m-nsn");
        assert_eq!(legacy.nsc_machine_id, None);
        assert_eq!(legacy.gateway_id, None);

        let json = serde_json::to_string(&legacy).unwrap();
        assert!(
            !json.contains("nsc_machine_id") && !json.contains("gateway_id"),
            "absent per-pair fields must be omitted on the wire; got {json}"
        );

        let full = WssRelayDial {
            nsn_machine_id: "m-nsn".to_owned(),
            nsc_machine_id: Some("m-nsc".to_owned()),
            gateway_id: Some("gw-primary".to_owned()),
        };
        let decoded: WssRelayDial =
            serde_json::from_str(&serde_json::to_string(&full).unwrap()).unwrap();
        assert_eq!(decoded, full);
    }

    // The fallback dial is additive: a legacy wire body without the field
    // decodes to `None`, `None` stays off the wire, and a populated field
    // round-trips.
    #[test]
    fn peer_config_wss_relay_fallback_is_additive() {
        let legacy: PeerConfig = serde_json::from_value(serde_json::json!({
            "public_key": B64_STANDARD.encode([9u8; 32]),
            "endpoint": "127.0.0.1:51821",
            "allowed_ips": ["10.0.0.3/32"],
            "persistent_keepalive": 25,
        }))
        .unwrap();
        assert_eq!(legacy.wss_relay_fallback, None);

        let json = serde_json::to_string(&legacy).unwrap();
        assert!(
            !json.contains("wss_relay_fallback"),
            "absent fallback dial must be omitted on the wire; got {json}"
        );

        let mut full = legacy.clone();
        full.wss_relay_fallback = Some(WssRelayDial {
            nsn_machine_id: "m-nsn".to_owned(),
            nsc_machine_id: Some("m-nsc".to_owned()),
            gateway_id: Some("gw-primary".to_owned()),
        });
        let decoded: PeerConfig =
            serde_json::from_str(&serde_json::to_string(&full).unwrap()).unwrap();
        assert_eq!(decoded, full);
    }

    // ── ProxyConfig ───────────────────────────────────────────────────────────

    #[test]
    fn proxy_config_empty_rules_round_trips() {
        let orig = ProxyConfig {
            chain_id: "chain-1".to_string(),
            rules: vec![],
            port_mappings: vec![],
        };
        let json = serde_json::to_string(&orig).unwrap();
        let decoded: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.chain_id, "chain-1");
        assert!(decoded.rules.is_empty());
        assert!(decoded.port_mappings.is_empty());
        assert!(
            !json.contains("port_mappings"),
            "empty port_mappings must be omitted on the wire; got {json}"
        );
    }

    #[test]
    fn proxy_config_with_port_mappings_round_trips() {
        let orig = ProxyConfig {
            chain_id: "chain-pm".to_string(),
            rules: vec![],
            port_mappings: vec![PortMapping {
                listen_port: 10_000,
                target_host: "127.0.0.1".into(),
                target_port: 80,
                protocol: Protocol::Tcp,
            }],
        };
        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.contains("\"port_mappings\""));
        let decoded: ProxyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.port_mappings.len(), 1);
        assert_eq!(decoded.port_mappings[0].listen_port, 10_000);
        assert_eq!(decoded.port_mappings[0].target_host, "127.0.0.1");
        assert_eq!(decoded.port_mappings[0].target_port, 80);
        assert_eq!(decoded.port_mappings[0].protocol, Protocol::Tcp);
    }

    #[test]
    fn proxy_config_accepts_legacy_payload_without_port_mappings() {
        // Pre-D2 wire shape: no `port_mappings` field. Must deserialize to
        // an empty Vec so adversarial gate A holds.
        let legacy = r#"{"chain_id":"legacy","rules":[]}"#;
        let decoded: ProxyConfig = serde_json::from_str(legacy).unwrap();
        assert_eq!(decoded.chain_id, "legacy");
        assert!(decoded.port_mappings.is_empty());
    }

    // ── ServiceReport ─────────────────────────────────────────────────────────

    #[test]
    fn service_report_round_trips_via_json() {
        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            ServiceInfo {
                protocol: Protocol::Tcp,
                host: "192.168.1.10".into(),
                port: 80,
                enabled: true,
                description: Some("Main web server".into()),
                domain: None,
                tunnel: TunnelPreference::Auto,
                gateway: GatewayPreference::Auto,
                public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
            },
        );
        services.insert(
            "dns".to_string(),
            ServiceInfo {
                protocol: Protocol::Udp,
                host: "192.168.1.1".into(),
                port: 53,
                enabled: true,
                description: None,
                domain: None,
                tunnel: TunnelPreference::Auto,
                gateway: GatewayPreference::Auto,
                public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
            },
        );
        let report = ServiceReport {
            services,
            strict_mode: true,
            system_info: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        let decoded: ServiceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.services.len(), 2);
        assert!(decoded.strict_mode);
        assert_eq!(decoded.services["web"].port, 80);
        assert_eq!(
            decoded.services["web"].description.as_deref(),
            Some("Main web server")
        );
    }

    #[test]
    fn service_report_description_none_omitted_from_json() {
        let mut services = HashMap::new();
        services.insert(
            "dns".to_string(),
            ServiceInfo {
                protocol: Protocol::Udp,
                host: "192.168.1.1".into(),
                port: 53,
                enabled: true,
                description: None,
                domain: None,
                tunnel: TunnelPreference::Auto,
                gateway: GatewayPreference::Auto,
                public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
            },
        );
        let report = ServiceReport {
            services,
            strict_mode: false,
            system_info: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(
            !json.contains("description"),
            "None description must be omitted"
        );
    }

    #[test]
    fn service_report_from_services_config() {
        let config = common::ServicesConfig::from_toml_str(
            r#"
[settings]
strict = true

[services.web]
protocol = "tcp"
host = "192.168.1.10"
port = 80
description = "Main web"

[services.ssh]
protocol = "tcp"
host = "127.0.0.1"
port = 22
enabled = false

[services.public]
protocol = "http"
host = "127.0.0.1"
port = 8080
domain = "public.example.test"
public_ingress_subject_policy = "anonymous"
"#,
        )
        .unwrap();
        let report = ServiceReport::from(&config);
        assert!(report.strict_mode);
        assert_eq!(report.services.len(), 3);
        assert_eq!(report.services["web"].port, 80);
        assert!(report.services["web"].enabled);
        assert!(!report.services["ssh"].enabled);
        assert_eq!(
            report.services["web"].description.as_deref(),
            Some("Main web")
        );
        assert_eq!(
            report.services["public"].public_ingress_subject_policy,
            PublicIngressSubjectPolicy::Anonymous
        );
    }

    #[test]
    fn service_report_domain_propagated_from_config() {
        let config = common::ServicesConfig::from_toml_str(
            r#"
[services.local-http]
protocol = "http"
host = "127.0.0.1"
port = 17777
domain = "local-http.test.n.ns"

[services.plain-tcp]
protocol = "tcp"
host = "10.0.0.1"
port = 22
"#,
        )
        .unwrap();
        let report = ServiceReport::from(&config);
        assert_eq!(
            report.services["local-http"].domain.as_deref(),
            Some("local-http.test.n.ns")
        );
        assert!(
            report.services["plain-tcp"].domain.is_none(),
            "services without a `domain` field must serialise as None"
        );
    }

    #[test]
    fn service_info_domain_round_trips_via_json() {
        let info = ServiceInfo {
            protocol: Protocol::Http,
            host: "127.0.0.1".into(),
            port: 17777,
            enabled: true,
            description: None,
            domain: Some("local-http.test.n.ns".into()),
            tunnel: TunnelPreference::Auto,
            gateway: GatewayPreference::Auto,
            public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(
            json.contains("\"domain\":\"local-http.test.n.ns\""),
            "domain must be serialised when Some; got {json}"
        );
        let decoded: ServiceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.domain.as_deref(), Some("local-http.test.n.ns"));
    }

    #[test]
    fn service_info_domain_none_omitted_from_json() {
        let info = ServiceInfo {
            protocol: Protocol::Tcp,
            host: "10.0.0.1".into(),
            port: 22,
            enabled: true,
            description: None,
            domain: None,
            tunnel: TunnelPreference::Auto,
            gateway: GatewayPreference::Auto,
            public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(
            !json.contains("\"domain\""),
            "domain must be omitted when None; got {json}"
        );
    }

    #[test]
    fn service_report_tunnel_and_gateway_propagated_from_config() {
        let config = common::ServicesConfig::from_toml_str(
            r#"
[services.db]
protocol = "tcp"
host = "10.0.0.5"
port = 5432
tunnel = "wg"
gateway = "gw-eu-west"

[services.cache]
protocol = "tcp"
host = "10.0.0.6"
port = 6379
tunnel = "ws"
"#,
        )
        .unwrap();
        let report = ServiceReport::from(&config);
        assert_eq!(report.services["db"].tunnel, TunnelPreference::Wg);
        assert_eq!(
            report.services["db"].gateway,
            GatewayPreference::Specific("gw-eu-west".to_string())
        );
        assert_eq!(report.services["cache"].tunnel, TunnelPreference::Ws);
        assert_eq!(report.services["cache"].gateway, GatewayPreference::Auto);
    }

    #[test]
    fn service_info_tunnel_gateway_round_trip_via_json() {
        let info = ServiceInfo {
            protocol: Protocol::Tcp,
            host: "10.0.0.1".into(),
            port: 443,
            enabled: true,
            description: None,
            domain: None,
            tunnel: TunnelPreference::Wg,
            gateway: GatewayPreference::Specific("gw-1".to_string()),
            public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: ServiceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.tunnel, TunnelPreference::Wg);
        assert_eq!(
            decoded.gateway,
            GatewayPreference::Specific("gw-1".to_string())
        );
    }

    #[test]
    fn service_info_tunnel_gateway_default_to_auto() {
        // JSON without tunnel/gateway fields should deserialize to Auto defaults.
        let json = r#"{"protocol":"tcp","host":"10.0.0.1","port":80,"enabled":true}"#;
        let info: ServiceInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.tunnel, TunnelPreference::Auto);
        assert_eq!(info.gateway, GatewayPreference::Auto);
    }

    // ── ServicesAck ───────────────────────────────────────────────────────────

    #[test]
    fn services_ack_round_trips_via_json() {
        let ack = ServicesAck {
            matched: vec!["web".into(), "db".into()],
            unmatched: vec!["dns".into()],
            rejected: vec!["redis".into()],
        };
        let json = serde_json::to_string(&ack).unwrap();
        let decoded: ServicesAck = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.matched, vec!["web", "db"]);
        assert_eq!(decoded.unmatched, vec!["dns"]);
        assert_eq!(decoded.rejected, vec!["redis"]);
    }

    // ── ControlMessage ────────────────────────────────────────────────────────

    #[test]
    fn control_message_ping_round_trips() {
        let msg = ControlMessage::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"ping\""));
        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, ControlMessage::Ping));
    }

    #[test]
    fn control_message_wg_config_round_trips() {
        let msg = ControlMessage::WgConfig(sample_wg_config());
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"wg_config\""));
        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, ControlMessage::WgConfig(_)));
    }

    #[test]
    fn control_message_token_refresh_round_trips() {
        let msg = ControlMessage::TokenRefresh {
            token: "tok.abc.xyz".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"token_refresh\""));
        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            ControlMessage::TokenRefresh { token } => assert_eq!(token, "tok.abc.xyz"),
            _ => panic!("wrong variant"),
        }
    }

    // Forward compatibility: a `type` tag from a newer NSD decodes to the
    // tolerant catch-all instead of failing the whole payload.
    #[test]
    fn control_message_unknown_tag_decodes_to_unknown() {
        let json = r#"{"type":"flux_capacitor_config","flux":88}"#;
        let decoded: ControlMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(decoded, ControlMessage::Unknown));
        assert_eq!(decoded.event_type(), "unknown");
    }

    // Decode-only contract: this crate must never put `Unknown` on the wire.
    #[test]
    fn control_message_unknown_never_serializes() {
        serde_json::to_string(&ControlMessage::Unknown)
            .expect_err("the decode-only Unknown variant must refuse to serialize");
    }

    // ── RoutingConfig ─────────────────────────────────────────────────────────

    #[test]
    fn routing_config_round_trips_via_json() {
        let orig = RoutingConfig {
            routes: vec![
                RouteEntry {
                    domain: "web.n.ns".to_string(),
                    site: "site-a".to_string(),
                    service: "web".to_string(),
                    port: 80,
                    nsn_wg_ip: None,
                    virtual_port: None,
                },
                RouteEntry {
                    domain: "db.n.ns".to_string(),
                    site: "site-a".to_string(),
                    service: "db".to_string(),
                    port: 5432,
                    nsn_wg_ip: None,
                    virtual_port: None,
                },
            ],
        };
        let json = serde_json::to_string(&orig).unwrap();
        let decoded: RoutingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.routes.len(), 2);
        assert_eq!(decoded.routes[0].domain, "web.n.ns");
        assert_eq!(decoded.routes[0].site, "site-a");
        assert_eq!(decoded.routes[0].service, "web");
        assert_eq!(decoded.routes[0].port, 80);
        assert_eq!(decoded.routes[1].port, 5432);
        assert!(decoded.routes[0].nsn_wg_ip.is_none());
        assert!(decoded.routes[0].virtual_port.is_none());
        assert!(
            !json.contains("nsn_wg_ip") && !json.contains("virtual_port"),
            "None D1 fields must be omitted on the wire; got {json}"
        );
    }

    #[test]
    fn route_entry_with_d1_fields_round_trips() {
        let orig = RouteEntry {
            domain: "web.n.ns".into(),
            site: "site-d1".into(),
            service: "web".into(),
            port: 80,
            nsn_wg_ip: Some(Ipv4Addr::new(10, 0, 0, 2)),
            virtual_port: Some(10_000),
        };
        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.contains("\"nsn_wg_ip\":\"10.0.0.2\""));
        assert!(json.contains("\"virtual_port\":10000"));
        let decoded: RouteEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.nsn_wg_ip, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(decoded.virtual_port, Some(10_000));
    }

    #[test]
    fn route_entry_accepts_legacy_payload_without_d1_fields() {
        // Pre-D1 wire shape: no `nsn_wg_ip` / `virtual_port`. Must
        // deserialize with both fields absent to satisfy adversarial gate A.
        let legacy = r#"{"domain":"a","site":"b","service":"c","port":1}"#;
        let decoded: RouteEntry = serde_json::from_str(legacy).unwrap();
        assert!(decoded.nsn_wg_ip.is_none());
        assert!(decoded.virtual_port.is_none());
    }

    #[test]
    fn routing_config_empty_routes_round_trips() {
        let orig = RoutingConfig { routes: vec![] };
        let json = serde_json::to_string(&orig).unwrap();
        let decoded: RoutingConfig = serde_json::from_str(&json).unwrap();
        assert!(decoded.routes.is_empty());
    }

    // ── DnsConfig ─────────────────────────────────────────────────────────────

    #[test]
    fn dns_config_round_trips_via_json() {
        let orig = DnsConfig {
            records: vec![DnsRecord {
                domain: "cache.n.ns".to_string(),
                site: "site-b".to_string(),
                service: "cache".to_string(),
                port: 6379,
            }],
        };
        let json = serde_json::to_string(&orig).unwrap();
        let decoded: DnsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.records.len(), 1);
        assert_eq!(decoded.records[0].domain, "cache.n.ns");
        assert_eq!(decoded.records[0].site, "site-b");
        assert_eq!(decoded.records[0].service, "cache");
        assert_eq!(decoded.records[0].port, 6379);
    }

    #[test]
    fn dns_config_empty_records_round_trips() {
        let orig = DnsConfig { records: vec![] };
        let json = serde_json::to_string(&orig).unwrap();
        let decoded: DnsConfig = serde_json::from_str(&json).unwrap();
        assert!(decoded.records.is_empty());
    }

    // ── ControlMessage routing/dns variants ───────────────────────────────────

    #[test]
    fn control_message_routing_config_round_trips() {
        let msg = ControlMessage::RoutingConfig(RoutingConfig {
            routes: vec![RouteEntry {
                domain: "web.n.ns".to_string(),
                site: "s1".to_string(),
                service: "web".to_string(),
                port: 8080,
                nsn_wg_ip: None,
                virtual_port: None,
            }],
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"routing_config\""));
        assert!(json.contains("\"routes\""));
        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            ControlMessage::RoutingConfig(cfg) => {
                assert_eq!(cfg.routes.len(), 1);
                assert_eq!(cfg.routes[0].port, 8080);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn control_message_dns_config_round_trips() {
        let msg = ControlMessage::DnsConfig(DnsConfig {
            records: vec![DnsRecord {
                domain: "db.n.ns".to_string(),
                site: "s1".to_string(),
                service: "db".to_string(),
                port: 5432,
            }],
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"dns_config\""));
        assert!(json.contains("\"records\""));
        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            ControlMessage::DnsConfig(cfg) => {
                assert_eq!(cfg.records.len(), 1);
                assert_eq!(cfg.records[0].port, 5432);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ── public edge config ───────────────────────────────────────────────────

    fn sample_public_edge_identity(
        protocol: PublicEdgeProtocol,
        public_port: u16,
        internal_port: u16,
    ) -> PublicEdgeRouteIdentity {
        PublicEdgeRouteIdentity {
            protocol,
            realm_id: "realm-a".to_owned(),
            gateway_id: "gw-a".to_owned(),
            route_id: format!("realm-a:gw-a:{protocol:?}:{public_port}:web"),
            public_port,
            nsgw_internal_port: internal_port,
            nsn_wg_vip: Ipv4Addr::new(10, 0, 0, 2),
            upstream_port: 8080,
            acl: PublicEdgeAclRef {
                realm_id: "realm-a".to_owned(),
                resource_id: "service:web".to_owned(),
            },
            subject_policy: PublicIngressSubjectPolicy::Anonymous,
            transport_policy: PublicEdgeTransportPolicy::PreferWss,
            policy_revision: PublicEdgePolicyRevision {
                generation: 42,
                version: "public-edge-v42".to_owned(),
                previous_generation: Some(41),
                rollback_of: None,
            },
        }
    }

    fn sample_gateway_http_route() -> GatewayHttpRoute {
        GatewayHttpRoute {
            identity: sample_public_edge_identity(PublicEdgeProtocol::Http, 443, 18_080),
            host: "web.example.test".to_owned(),
            backend: PublicEdgeBackendKind::NsnBacked,
            service: "web".to_owned(),
            site: "site-a".to_owned(),
            identity_import: HttpExternalIdentityImport {
                providers: vec![ExternalIdentityProviderRef {
                    kind: ExternalIdentityProviderKind::Oidc,
                    ref_id: "idp-main".to_owned(),
                }],
                anonymous_bypass: true,
                fail_closed: false,
            },
            signed_subject_headers: SignedSubjectHeaderPolicy {
                enabled: true,
                header_name: Some("X-NSIO-Subject".to_owned()),
                signature_header_name: Some("X-NSIO-Subject-Sig".to_owned()),
                keyset_ref: Some("gateway-subject-keyset".to_owned()),
                validity_seconds: Some(30),
                strip_inbound_headers: true,
            },
            middleware: HttpMiddlewarePolicy {
                chain_ref: Some("http-chain-a".to_owned()),
                waf_ref: Some("waf-a".to_owned()),
                ext_authz_ref: Some("ext-authz-a".to_owned()),
            },
            edge_limits: EdgeLimitPolicy {
                rate_limit_ref: Some("rate-a".to_owned()),
                connection_limit_ref: Some("conn-a".to_owned()),
                request_body_bytes: Some(1_048_576),
                response_body_bytes: Some(2_097_152),
                slow_client_ref: Some("slow-client-a".to_owned()),
            },
            transforms: HttpTransformPolicy {
                request_rewrite_ref: Some("rewrite-a".to_owned()),
                response_header_ref: Some("headers-a".to_owned()),
                forwarded_subject_ref: Some("subject-forward-a".to_owned()),
            },
            audit: EdgeAuditPolicy {
                audit_ref: Some("audit-a".to_owned()),
                metadata: BTreeMap::from([("owner".to_owned(), "platform".to_owned())]),
            },
            certificate_ref: Some("cert-web".to_owned()),
        }
    }

    fn sample_certificate() -> PublicEdgeCertificateRef {
        PublicEdgeCertificateRef {
            id: "cert-web".to_owned(),
            hostnames: vec!["web.example.test".to_owned()],
            policy: PublicEdgeCertificatePolicy {
                issuer_ref: Some("letsencrypt-prod".to_owned()),
                min_tls_version: Some("1.3".to_owned()),
                require_sni: true,
            },
            source: PublicEdgeCertificateSource::Sds {
                secret_name: "web-example-test".to_owned(),
            },
        }
    }

    #[test]
    fn gateway_http_config_round_trips_via_json() {
        let orig = GatewayHttpConfig {
            gateway_id: "gw-a".to_owned(),
            realm_id: "realm-a".to_owned(),
            routes: vec![sample_gateway_http_route()],
            certificates: vec![sample_certificate()],
        };
        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.contains("\"protocol\":\"http\""));
        assert!(json.contains("\"public_port\":443"));
        assert!(json.contains("\"nsgw_internal_port\":18080"));
        assert!(json.contains("\"nsn_wg_vip\":\"10.0.0.2\""));
        assert!(json.contains("\"upstream_port\":8080"));
        assert!(json.contains("\"resource_id\":\"service:web\""));
        assert!(json.contains("\"subject_policy\":\"anonymous\""));
        assert!(json.contains("\"transport_policy\":\"prefer_wss\""));
        assert!(json.contains("\"identity_import\""));
        assert!(json.contains("\"signed_subject_headers\""));
        assert!(json.contains("\"middleware\""));
        assert!(json.contains("\"edge_limits\""));
        assert!(json.contains("\"transforms\""));
        assert!(json.contains("\"audit\""));
        assert!(json.contains("\"certificates\""));

        let decoded: GatewayHttpConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, orig);
        assert_eq!(
            decoded.routes[0].identity.protocol,
            PublicEdgeProtocol::Http
        );
        assert_eq!(decoded.routes[0].identity.public_port, 443);
        assert_eq!(decoded.routes[0].identity.nsgw_internal_port, 18_080);
        assert_eq!(
            decoded.routes[0].identity.nsn_wg_vip,
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert_eq!(decoded.routes[0].identity.acl.resource_id, "service:web");
    }

    #[test]
    fn default_http_route_shape_decodes_empty_contract_fields() {
        let decoded: GatewayHttpRoute = serde_json::from_str(
            r#"{
                "identity":{
                    "protocol":"http",
                    "realm_id":"realm-a",
                    "gateway_id":"gw-a",
                    "route_id":"realm-a:gw-a:http:443:web",
                    "public_port":443,
                    "nsgw_internal_port":18080,
                    "nsn_wg_vip":"10.0.0.2",
                    "upstream_port":8080,
                    "acl":{"realm_id":"realm-a","resource_id":"service:web"},
                    "subject_policy":"external_idp",
                    "transport_policy":"prefer_wg",
                    "policy_revision":{"generation":1,"version":"v1"}
                },
                "host":"web.example.test",
                "backend":"nsn_backed",
                "site":"site-a",
                "service":"web"
            }"#,
        )
        .unwrap();

        assert_eq!(decoded.identity.protocol, PublicEdgeProtocol::Http);
        assert_eq!(
            decoded.identity.transport_policy,
            PublicEdgeTransportPolicy::PreferWg
        );
        assert_eq!(
            decoded.identity.subject_policy,
            PublicIngressSubjectPolicy::ExternalIdp
        );
        assert_eq!(decoded.backend, PublicEdgeBackendKind::NsnBacked);
        assert!(decoded.identity_import.providers.is_empty());
        assert!(!decoded.identity_import.fail_closed);
        assert!(!decoded.signed_subject_headers.enabled);
        assert!(decoded.middleware.chain_ref.is_none());
        assert!(decoded.edge_limits.rate_limit_ref.is_none());
        assert!(decoded.transforms.request_rewrite_ref.is_none());
        assert!(decoded.audit.metadata.is_empty());
    }

    #[test]
    fn public_edge_transport_policy_tokens_round_trip() {
        let policies = [
            ("wg", PublicEdgeTransportPolicy::Wg),
            ("wss", PublicEdgeTransportPolicy::Wss),
            ("prefer_wg", PublicEdgeTransportPolicy::PreferWg),
            ("prefer_wss", PublicEdgeTransportPolicy::PreferWss),
        ];

        for (token, policy) in policies {
            let json = format!(r#""{token}""#);
            let decoded: PublicEdgeTransportPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, policy);
            assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
        }
    }

    #[test]
    fn public_edge_policy_maps_service_tunnel_tokens() {
        let cases = [
            (
                TunnelPreference::Auto,
                r#""auto""#,
                PublicEdgeTransportPolicy::PreferWg,
                r#""prefer_wg""#,
            ),
            (
                TunnelPreference::Wg,
                r#""wg""#,
                PublicEdgeTransportPolicy::Wg,
                r#""wg""#,
            ),
            (
                TunnelPreference::Ws,
                r#""ws""#,
                PublicEdgeTransportPolicy::Wss,
                r#""wss""#,
            ),
        ];

        for (service_tunnel, service_token, public_policy, public_token) in cases {
            assert_eq!(
                serde_json::to_string(&service_tunnel).unwrap(),
                service_token
            );
            let derived =
                PublicEdgeTransportPolicy::from_service_tunnel_preference(&service_tunnel);
            assert_eq!(derived, public_policy);
            assert_eq!(serde_json::to_string(&derived).unwrap(), public_token);
        }
    }

    #[test]
    fn gateway_l4_map_round_trips_via_json_with_tcp_and_udp_entries() {
        let tcp = GatewayL4Route {
            identity: sample_public_edge_identity(PublicEdgeProtocol::Tcp, 10_000, 20_000),
            backend: PublicEdgeBackendKind::NsnBacked,
            service: "tcp-web".to_owned(),
            site: "site-a".to_owned(),
            virtual_port: 10_000,
            l4: L4Policy {
                connection_limit_ref: Some("conn-l4".to_owned()),
                session_limit_ref: None,
            },
            certificate_ref: None,
        };
        let udp = GatewayL4Route {
            identity: PublicEdgeRouteIdentity {
                protocol: PublicEdgeProtocol::Udp,
                route_id: "realm-a:gw-a:udp:10000:dns".to_owned(),
                upstream_port: 53,
                ..sample_public_edge_identity(PublicEdgeProtocol::Udp, 10_000, 20_001)
            },
            backend: PublicEdgeBackendKind::NsnBacked,
            service: "dns".to_owned(),
            site: "site-a".to_owned(),
            virtual_port: 10_000,
            l4: L4Policy {
                connection_limit_ref: None,
                session_limit_ref: Some("udp-session".to_owned()),
            },
            certificate_ref: None,
        };
        let orig = GatewayL4Map {
            gateway_id: "gw-a".to_owned(),
            realm_id: "realm-a".to_owned(),
            routes: vec![tcp, udp],
            certificates: Vec::new(),
        };

        let json = serde_json::to_string(&orig).unwrap();
        assert!(json.contains("\"protocol\":\"tcp\""));
        assert!(json.contains("\"protocol\":\"udp\""));
        assert!(json.contains("\"virtual_port\":10000"));
        assert!(json.contains("\"public_port\":10000"));
        assert!(json.contains("\"nsgw_internal_port\":20000"));
        assert!(json.contains("\"nsgw_internal_port\":20001"));
        let decoded: GatewayL4Map = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, orig);
        assert_eq!(decoded.routes[0].identity.protocol, PublicEdgeProtocol::Tcp);
        assert_eq!(decoded.routes[1].identity.protocol, PublicEdgeProtocol::Udp);
        assert_eq!(
            decoded.routes[0].identity.public_port,
            decoded.routes[1].identity.public_port
        );
    }

    #[test]
    fn control_message_public_edge_configs_round_trip_with_v1_types() {
        let msg = ControlMessage::GatewayHttpConfig(GatewayHttpConfig {
            gateway_id: "gw-a".to_owned(),
            realm_id: "realm-a".to_owned(),
            routes: vec![sample_gateway_http_route()],
            certificates: Vec::new(),
        });

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"gateway_http_config.v1\""));
        assert!(!json.contains("\"type\":\"routing_config\""));
        assert!(!json.contains("\"type\":\"gateway_config\""));
        assert_eq!(msg.event_type(), "gateway_http_config.v1");

        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            ControlMessage::GatewayHttpConfig(cfg) => {
                assert_eq!(cfg.routes.len(), 1);
                assert_eq!(
                    cfg.routes[0].identity.nsn_wg_vip,
                    Ipv4Addr::new(10, 0, 0, 2)
                );
                assert_eq!(cfg.routes[0].identity.upstream_port, 8080);
            }
            _ => panic!("wrong variant"),
        }

        let l4_msg = ControlMessage::GatewayL4Map(GatewayL4Map {
            gateway_id: "gw-a".to_owned(),
            realm_id: "realm-a".to_owned(),
            routes: Vec::new(),
            certificates: Vec::new(),
        });
        let l4_json = serde_json::to_string(&l4_msg).unwrap();
        assert!(l4_json.contains("\"type\":\"gateway_l4_map.v1\""));
        assert_eq!(l4_msg.event_type(), "gateway_l4_map.v1");
    }

    #[test]
    fn control_message_peer_candidates_round_trips() {
        let candidate_endpoint: SocketAddr = "198.51.100.10:51820".parse().unwrap();
        let msg = ControlMessage::PeerCandidates(PeerCandidatesUpdate {
            machine_id: "m-peer".to_owned(),
            epoch: 42,
            peer_key_pub: [9u8; 32],
            candidates: vec![P2pCandidate {
                kind: P2pCandidateKind::ServerReflexive,
                endpoint: candidate_endpoint,
                priority: 100,
                observed_at_unix_ms: 1_787_000_000_000,
                source: Some("stun:203.0.113.1:3478".to_owned()),
                relay_url: None,
            }],
        });

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"peer_candidates\""));
        assert!(json.contains("\"kind\":\"server_reflexive\""));
        assert!(json.contains("\"endpoint\":\"198.51.100.10:51820\""));
        assert_eq!(msg.event_type(), "peer_candidates");

        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            ControlMessage::PeerCandidates(update) => {
                assert_eq!(update.machine_id, "m-peer");
                assert_eq!(update.epoch, 42);
                assert_eq!(update.peer_key_pub, [9u8; 32]);
                assert_eq!(update.candidates.len(), 1);
                assert_eq!(update.candidates[0].kind, P2pCandidateKind::ServerReflexive);
                assert_eq!(update.candidates[0].endpoint, candidate_endpoint);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn link_mode_tokens_round_trip() {
        let cases = [
            ("direct", LinkMode::Direct),
            ("terminate", LinkMode::Terminate),
            ("wg-relay", LinkMode::WgRelay),
            ("wss-relay", LinkMode::WssRelay),
        ];

        for (token, mode) in cases {
            let json = format!(r#""{token}""#);
            let decoded: LinkMode = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, mode);
            assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
        }
    }

    #[test]
    fn link_mode_from_str_is_tolerant() {
        use std::str::FromStr as _;
        assert_eq!(LinkMode::from_str("wg-relay").unwrap(), LinkMode::WgRelay);
        // Case-insensitive and `_`/`-` tolerant for CLI ergonomics.
        assert_eq!(LinkMode::from_str("WG_RELAY").unwrap(), LinkMode::WgRelay);
        assert_eq!(LinkMode::from_str(" Direct ").unwrap(), LinkMode::Direct);
        assert!(LinkMode::from_str("bogus").is_err());
    }

    #[test]
    fn parse_link_modes_splits_and_trims() {
        assert_eq!(
            parse_link_modes("wg-relay, terminate").unwrap(),
            vec![LinkMode::WgRelay, LinkMode::Terminate]
        );
        // Empty entries are ignored; an empty string yields an empty list.
        assert_eq!(parse_link_modes("").unwrap(), Vec::<LinkMode>::new());
        assert_eq!(
            parse_link_modes("direct,,wss-relay,").unwrap(),
            vec![LinkMode::Direct, LinkMode::WssRelay]
        );
        assert!(parse_link_modes("wg-relay,nope").is_err());
    }

    #[test]
    fn gateway_wg_relay_config_round_trips_via_json() {
        let cfg = GatewayWgRelayConfig {
            relay_pairs: vec![GatewayWgRelayPair {
                nsc_pubkey: [3u8; 32],
                nsc_machine_id: "m-client".to_owned(),
                nsc_machine_key_pub: [6u8; 32],
                nsn_machine_id: "m-nsn".to_owned(),
                nsn_machine_key_pub: [7u8; 32],
                nsn_pubkey: [4u8; 32],
                nsn_endpoint: Some("203.0.113.10:51820".parse().unwrap()),
                addressing: GatewayWgRelayAddressing::ReceiverIndex,
                listen_port: None,
            }],
        };

        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"nsc_machine_id\":\"m-client\""));
        assert!(json.contains("\"nsc_machine_key_pub\""));
        assert!(json.contains("\"nsn_machine_id\":\"m-nsn\""));
        assert!(json.contains("\"nsn_machine_key_pub\""));
        assert!(json.contains("\"nsn_endpoint\":\"203.0.113.10:51820\""));
        assert!(json.contains("\"addressing\":\"receiver_index\""));
        assert!(!json.contains("listen_port"));

        let decoded: GatewayWgRelayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, cfg);
    }

    #[test]
    fn gateway_wg_relay_config_accepts_registration_only_pair() {
        let cfg = GatewayWgRelayConfig {
            relay_pairs: vec![GatewayWgRelayPair {
                nsc_pubkey: [3u8; 32],
                nsc_machine_id: "m-client".to_owned(),
                nsc_machine_key_pub: [6u8; 32],
                nsn_machine_id: "m-nsn".to_owned(),
                nsn_machine_key_pub: [7u8; 32],
                nsn_pubkey: [4u8; 32],
                nsn_endpoint: None,
                addressing: GatewayWgRelayAddressing::ReceiverIndex,
                listen_port: None,
            }],
        };

        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("nsn_endpoint"));

        let decoded: GatewayWgRelayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, cfg);
    }

    #[test]
    fn control_message_gateway_wg_relay_round_trips() {
        let msg = ControlMessage::GatewayWgRelay(GatewayWgRelayConfig {
            relay_pairs: Vec::new(),
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"gateway_wg_relay\""));
        assert_eq!(msg.event_type(), "gateway_wg_relay");

        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, ControlMessage::GatewayWgRelay(_)));
    }

    #[test]
    fn gateway_wss_relay_config_round_trips_via_json() {
        let cfg = GatewayWssRelayConfig {
            relay_pairs: vec![GatewayWssRelayPair {
                nsc_machine_id: "m-client".to_owned(),
                nsn_machine_id: "m-nsn".to_owned(),
                nsc_pubkey: [5u8; 32],
                nsn_pubkey: [6u8; 32],
            }],
        };

        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("nsn_endpoint"));
        assert!(json.contains("\"nsc_machine_id\""));
        assert!(json.contains("\"nsn_machine_id\""));
        assert!(json.contains("\"nsc_pubkey\""));
        assert!(json.contains("\"nsn_pubkey\""));

        let decoded: GatewayWssRelayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, cfg);
    }

    #[test]
    fn control_message_gateway_wss_relay_round_trips() {
        let msg = ControlMessage::GatewayWssRelay(GatewayWssRelayConfig {
            relay_pairs: Vec::new(),
        });
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"gateway_wss_relay\""));
        assert_eq!(msg.event_type(), "gateway_wss_relay");

        let decoded: ControlMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded, ControlMessage::GatewayWssRelay(_)));
    }

    // ── AclConfig sentinel ────────────────────────────────────────────────────

    #[test]
    fn acl_config_loaded_state_round_trips_via_json() {
        let cfg = AclConfig::loaded("chain-1", acl::AclPolicy::default());
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"state\":\"loaded\""));
        let decoded: AclConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.chain_id, "chain-1");
        assert!(matches!(decoded.payload, AclPayload::Loaded { .. }));
    }

    #[test]
    fn acl_config_explicit_empty_round_trips() {
        let cfg = AclConfig::explicit_empty("chain-2");
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"state\":\"explicit_empty\""));
        let decoded: AclConfig = serde_json::from_str(&json).unwrap();
        assert!(matches!(decoded.payload, AclPayload::ExplicitEmpty));
    }

    #[test]
    fn acl_config_fetch_failed_carries_error() {
        let cfg = AclConfig::fetch_failed("chain-3", "boom");
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"state\":\"fetch_failed\""));
        assert!(json.contains("\"error\":\"boom\""));
        let decoded: AclConfig = serde_json::from_str(&json).unwrap();
        match decoded.payload {
            AclPayload::FetchFailed { error } => assert_eq!(error, "boom"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn acl_config_rejects_legacy_plain_policy_shape() {
        let legacy = r#"{"chain_id":"chain-legacy","policy":{"rules":[]}}"#;
        assert!(serde_json::from_str::<AclConfig>(legacy).is_err());
    }

    #[test]
    fn acl_config_rejects_object_without_state() {
        let bad = r#"{"chain_id":"x"}"#;
        assert!(serde_json::from_str::<AclConfig>(bad).is_err());
    }

    #[test]
    fn acl_config_rejects_unknown_state() {
        let bad = r#"{"chain_id":"x","state":"banana"}"#;
        assert!(serde_json::from_str::<AclConfig>(bad).is_err());
    }

    #[test]
    fn jwt_token_has_three_parts() {
        let token = "header.payload.signature";
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "JWT must have exactly 3 dot-separated parts"
        );
    }
}
