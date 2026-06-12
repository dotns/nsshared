//! Typed payload structs for each [`envelope::api`](crate::envelope::api)
//! identifier.
//!
//! Each envelope carries an opaque `payload: ByteBuf` that is CBOR-encoded
//! according to the logical `api` field. The structs here are the canonical
//! wire shapes for those payloads on both the Rust side and the nsd-mock
//! TypeScript side.
//!
//! The envelope already carries `machine_id`, `machine_key_pub`, `ts`, and
//! the Ed25519 signature, so individual payloads do **not** re-encode those
//! fields. `peer_key_pub` (X25519) is separate from the Ed25519 identity
//! key and continues to ride in the register payload.
//!
//! CBOR is used for wire encoding. All fields use `snake_case` naming to
//! match the existing JSON shim on nsd-mock.
#![allow(missing_docs)]

use std::net::{Ipv4Addr, SocketAddr};

use common::{NsdInfo, SystemInfo};
use serde::{Deserialize, Serialize};

use crate::messages::{ControlMessage, LinkMode, PeerCandidatesReport, ServiceReport, ServicesAck};
use crate::types::ConnectorType;

pub use crate::types::ConnectorType as RegisterType;

/// UDP datagram prefix for `wg_relay.register_source` envelopes.
///
/// The first byte is outside the WireGuard packet type range (`1..=4`), so the
/// gateway relay can demultiplex this before normal WireGuard parsing.
pub const WG_RELAY_REGISTRATION_MAGIC: &[u8; 8] = b"NSGWGRS1";

/// UDP datagram prefix for gateway-reflexive address probes on the NSGW relay
/// socket.
///
/// Like [`WG_RELAY_REGISTRATION_MAGIC`], the first byte is outside the
/// WireGuard packet type range (`1..=4`) so the relay can demultiplex this
/// before normal WireGuard parsing.
pub const GATEWAY_REFLEXIVE_MAGIC: &[u8; 8] = b"NSGWP2P1";

// ── info.get ─────────────────────────────────────────────────────────────────

/// Empty request for `api = "info.get"`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InfoGetRequest {}

/// Response for `api = "info.get"`.
///
/// Wraps [`NsdInfo`] unchanged — the `envelope_versions` handshake field
/// lives on `NsdInfo` so both the legacy JSON `/api/v1/info` endpoint and
/// the signed-envelope path share a single shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoGetResponse {
    #[serde(flatten)]
    pub info: NsdInfo,
}

// ── machine.register ─────────────────────────────────────────────────────────

/// Request payload for `api = "machine.register"`.
///
/// The Ed25519 identity key is in the envelope's `machine_key_pub` field.
/// Only fields the envelope does **not** already carry live here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Pre-shared auth key. Present on authkey-flow; absent on OAuth flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,

    /// OAuth2 device-flow access token. Present on OAuth flow; absent on
    /// authkey flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,

    /// X25519 peer key. Distinct from the Ed25519 identity in the envelope.
    /// Encoded as a 32-byte CBOR byte string.
    #[serde(with = "serde_bytes_array_32")]
    pub peer_key_pub: [u8; 32],

    pub hostname: String,
    pub os: String,
    pub version: String,

    /// Machine role (D3). Absent on the wire when `None`; server-side
    /// semantics treat absent as [`ConnectorType::Connector`].
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
    pub r#type: Option<ConnectorType>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_info: Option<SystemInfo>,

    /// Client capability tokens advertised during registration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    /// Link modes this machine can participate in. Empty or absent means the
    /// server applies its backward-compatible default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_link_modes: Vec<LinkMode>,

    /// Preferred link mode when several supported modes are viable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_mode: Option<LinkMode>,
}

/// Response payload for `api = "machine.register"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub machine_id: String,
    /// Hex-encoded 32-byte X25519 server peer key.
    pub server_peer_key_pub: String,
    /// `host:port` of the WireGuard server endpoint.
    pub server_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_base: Option<String>,
    /// Ed25519 envelope-signing public key (64-char lowercase hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsd_envelope_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_tunnel_ip: Option<Ipv4Addr>,
}

// ── machine.auth ─────────────────────────────────────────────────────────────

/// Request payload for `api = "machine.auth"`.
///
/// The envelope already carries the machine identity (`machine_id`,
/// `machine_key_pub`, signature), so this payload only conveys the requested
/// token purpose. `purpose` is `"control"` (NSD machine-control) or `"wss"`
/// (NSGW WSS relay); an absent value defaults to machine-control server-side.
/// Any unrecognised value is rejected by NSD with `bad_payload`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// Response payload for `api = "machine.auth"` — the minted compact JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
}

// ── machine.heartbeat ────────────────────────────────────────────────────────

/// Request payload for `api = "machine.heartbeat"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub uptime_secs: u64,
    pub local_ips: Vec<String>,
}

/// Response payload for `api = "machine.heartbeat"`. Empty on success.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeartbeatResponse {}

// ── services.report ──────────────────────────────────────────────────────────

/// Request payload for `api = "services.report"` — reuses [`ServiceReport`].
pub type ServicesReportRequest = ServiceReport;

/// Response payload for `api = "services.report"` — reuses [`ServicesAck`].
pub type ServicesReportResponse = ServicesAck;

// ── peer_candidates.report ──────────────────────────────────────────────────

/// Request payload for `api = "peer_candidates.report"`.
pub type PeerCandidatesReportRequest = PeerCandidatesReport;

/// Response payload for `api = "peer_candidates.report"`. Empty on success.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerCandidatesReportResponse {}

// ── config.stream ────────────────────────────────────────────────────────────

/// Request payload for `api = "config.stream"`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigStreamRequest {
    /// Subscriber capability tokens for this stream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Public ingress route scopes requested by this stream subscriber.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_ingress_scopes: Vec<String>,
}

/// Signed pushed-event payload for `api = "config.stream"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigStreamEventPayloadV1 {
    pub v: u8,
    pub message: ControlMessage,
}

/// Best-effort probe of the `message.type` tag inside a raw (already
/// verified) `config.stream` event payload.
///
/// Used to surface the wire tag when the typed decode lands on
/// [`ControlMessage::Unknown`]: `#[serde(other)]` discards the tag, so the
/// only place it can be recovered is the raw CBOR.
#[must_use]
pub fn probe_config_stream_message_type(payload: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct ProbeMessage {
        #[serde(rename = "type", default)]
        type_tag: Option<String>,
    }
    #[derive(Deserialize)]
    struct ProbePayload {
        message: ProbeMessage,
    }
    from_cbor::<ProbePayload>(payload)
        .ok()
        .and_then(|p| p.message.type_tag)
}

// ── gateway.report ───────────────────────────────────────────────────────────

/// Request payload for `api = "gateway.report"` (D4).
///
/// CBOR shape. `wg_pubkey` is a raw 32-byte CBOR byte string (major type 2),
/// matching the local shape NSD used in INGEST-004 prior to upstream
/// promotion. The envelope already carries `machine_id` and the signature,
/// so this payload only adds the gateway-specific fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayReportRequest {
    /// Stable gateway identifier.
    pub gateway_id: String,
    /// Raw 32-byte WireGuard public key.
    #[serde(with = "serde_bytes_array_32")]
    pub wg_pubkey: [u8; 32],
    /// `host:port` literal (DNS-resolved by NSD at write time).
    pub wg_endpoint: String,
    /// WSS relay base URL.
    pub wss_endpoint: String,
    /// Optional tunnel-side IPv4 — the ICMP probe target NSN uses for
    /// liveness (PLAN-016). Older builds omit it; NSD falls back to the
    /// handshake-count silence detector when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_tunnel_ip: Option<Ipv4Addr>,
    /// NSGW software version reported by the gateway binary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsgw_version: Option<String>,
    /// Live NSC `/client` WSS sessions observed by NSGW. Phase 1 does not count
    /// WireGuard-mode NSC peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsc_connections: Option<u32>,
    /// Public `host:port` of the gateway's zero-trust WireGuard relay listener
    /// (the separate relay UDP port, not the main `wg_endpoint`). Present only
    /// when relay is enabled. DNS-resolved by NSD at write time. This is the
    /// authoritative gateway relay address that NSN/NSC derive registration and
    /// p2p-reflector targets from; older gateways omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_relay_endpoint: Option<String>,
    /// Whether this gateway is intentionally draining new public ingress
    /// traffic while keeping existing routes visible.
    #[serde(default)]
    pub draining: bool,
    /// Gateway capability tokens advertised with the endpoint report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Public ingress route scopes advertised by this gateway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_ingress_scopes: Vec<String>,
}

/// Response payload for `api = "gateway.report"` (D4). Empty on success — the
/// envelope's response signature still ties the empty body to the verified
/// `machine_id`, matching the ack-less precedent set by `ServicesReport`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayReportResponse {}

// ── gateway.realm_config_snapshot ────────────────────────────────────────────

/// Empty request for `api = "gateway.realm_config_snapshot"`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayRealmConfigSnapshotRequest {}

/// One realm's signed config-stream snapshot bodies for
/// `api = "gateway.realm_config_snapshot"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayRealmConfigSnapshotRealm {
    pub realm_id: String,
    pub events: Vec<String>,
}

/// Response payload for `api = "gateway.realm_config_snapshot"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayRealmConfigSnapshotResponse {
    pub realms: Vec<GatewayRealmConfigSnapshotRealm>,
}

// ── wg_relay.register_source ────────────────────────────────────────────────

/// Request payload for `api = "wg_relay.register_source"`.
///
/// The envelope carries the authenticated NSN machine identity. This payload
/// binds the observed UDP source address to the NSN WireGuard public key used
/// by `gateway_wg_relay` mac1 routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgRelayRegistrationRequest {
    #[serde(with = "serde_bytes_array_32")]
    pub nsn_pubkey: [u8; 32],
}

// ── gateway.reflexive ───────────────────────────────────────────────────────

/// Request payload for `api = "gateway.reflexive"`.
///
/// The signed envelope carries the caller's authenticated machine id and
/// Ed25519 machine key. This payload binds that identity to the caller's
/// WireGuard peer key and an application nonce that the unsigned response must
/// echo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayReflexiveRequest {
    #[serde(with = "serde_bytes_array_32")]
    pub peer_key_pub: [u8; 32],
    #[serde(with = "serde_bytes_array_16")]
    pub nonce: [u8; 16],
}

/// Nonce-bound response to a gateway-reflexive probe.
///
/// This slice intentionally keeps the response unsigned: NSD only accepts
/// signed peer-candidate reports, and WireGuard still authenticates the data
/// plane. A future gateway-signed response can add a signature field without
/// changing the relay socket demux.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayReflexiveResponse {
    #[serde(with = "serde_bytes_array_16")]
    pub nonce: [u8; 16],
    pub observed_addr: SocketAddr,
    pub gateway_id: String,
    pub relay_socket_addr: SocketAddr,
    pub timestamp_unix_ms: u64,
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Encode a payload to CBOR bytes suitable for an envelope `payload` field.
pub fn to_cbor<T: Serialize>(payload: &T) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut buf = Vec::with_capacity(128);
    ciborium::ser::into_writer(payload, &mut buf)?;
    Ok(buf)
}

/// Decode CBOR bytes from an envelope `payload` field.
pub fn from_cbor<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, ciborium::de::Error<std::io::Error>> {
    ciborium::de::from_reader(bytes)
}

// ── serde helpers ────────────────────────────────────────────────────────────
// CBOR major type 2 (byte string) for fixed-size arrays. Mirrors the helper
// already used by `crate::envelope` but kept local so `api.rs` does not
// depend on envelope internals.

mod serde_bytes_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_bytes::ByteBuf;

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(v.as_slice(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let b = ByteBuf::deserialize(d)?;
        if b.len() != 32 {
            return Err(serde::de::Error::invalid_length(b.len(), &"32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(b.as_ref());
        Ok(out)
    }
}

mod serde_bytes_array_16 {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_bytes::ByteBuf;

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::serialize(v.as_slice(), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let b = ByteBuf::deserialize(d)?;
        if b.len() != 16 {
            return Err(serde::de::Error::invalid_length(b.len(), &"16 bytes"));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(b.as_ref());
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{
        CAPABILITY_PUBLIC_INGRESS_CONFIG_V1, PUBLIC_INGRESS_SCOPE_HTTP_1_1_REVERSE_PROXY,
    };

    #[test]
    fn register_request_roundtrip() {
        let req = RegisterRequest {
            auth_key: Some("secret".into()),
            access_token: None,
            peer_key_pub: [7u8; 32],
            hostname: "host-1".into(),
            os: "linux".into(),
            version: "0.1.0".into(),
            r#type: None,
            system_info: None,
            capabilities: vec![CAPABILITY_PUBLIC_INGRESS_CONFIG_V1.into()],
            supported_link_modes: vec![LinkMode::Direct, LinkMode::WgRelay],
            preferred_mode: Some(LinkMode::WgRelay),
        };
        let bytes = to_cbor(&req).unwrap();
        let decoded: RegisterRequest = from_cbor(&bytes).unwrap();
        assert_eq!(req.auth_key, decoded.auth_key);
        assert_eq!(req.peer_key_pub, decoded.peer_key_pub);
        assert_eq!(req.hostname, decoded.hostname);
        assert_eq!(
            decoded.capabilities,
            vec![CAPABILITY_PUBLIC_INGRESS_CONFIG_V1]
        );
        assert_eq!(
            decoded.supported_link_modes,
            vec![LinkMode::Direct, LinkMode::WgRelay]
        );
        assert_eq!(decoded.preferred_mode, Some(LinkMode::WgRelay));
        assert!(decoded.r#type.is_none());
    }

    #[test]
    fn register_request_auth_key_none_is_omitted() {
        // auth_key: None should be encoded as absent so the server can
        // distinguish authkey vs oauth flows by field presence.
        let req = RegisterRequest {
            auth_key: None,
            access_token: Some("oauth-token".into()),
            peer_key_pub: [0u8; 32],
            hostname: "h".into(),
            os: "linux".into(),
            version: "v".into(),
            r#type: None,
            system_info: None,
            capabilities: Vec::new(),
            supported_link_modes: Vec::new(),
            preferred_mode: None,
        };
        let bytes = to_cbor(&req).unwrap();
        let decoded: RegisterRequest = from_cbor(&bytes).unwrap();
        assert!(decoded.auth_key.is_none());
        assert_eq!(decoded.access_token.as_deref(), Some("oauth-token"));
    }

    #[test]
    fn register_request_with_type_gateway_roundtrips() {
        let req = RegisterRequest {
            auth_key: Some("k".into()),
            access_token: None,
            peer_key_pub: [1u8; 32],
            hostname: "h".into(),
            os: "linux".into(),
            version: "v".into(),
            r#type: Some(ConnectorType::Gateway),
            system_info: None,
            capabilities: Vec::new(),
            supported_link_modes: vec![LinkMode::Terminate, LinkMode::WgRelay],
            preferred_mode: Some(LinkMode::Terminate),
        };
        let bytes = to_cbor(&req).unwrap();
        let decoded: RegisterRequest = from_cbor(&bytes).unwrap();
        assert_eq!(decoded.r#type, Some(ConnectorType::Gateway));
        assert_eq!(
            decoded.supported_link_modes,
            vec![LinkMode::Terminate, LinkMode::WgRelay]
        );
        assert_eq!(decoded.preferred_mode, Some(LinkMode::Terminate));
    }

    #[test]
    fn gateway_reflexive_payloads_roundtrip() {
        let req = GatewayReflexiveRequest {
            peer_key_pub: [9u8; 32],
            nonce: [7u8; 16],
        };
        let req_bytes = to_cbor(&req).unwrap();
        let decoded_req: GatewayReflexiveRequest = from_cbor(&req_bytes).unwrap();
        assert_eq!(decoded_req, req);

        let resp = GatewayReflexiveResponse {
            nonce: req.nonce,
            observed_addr: "198.51.100.20:41020".parse().unwrap(),
            gateway_id: "gw-primary".to_owned(),
            relay_socket_addr: "203.0.113.10:51821".parse().unwrap(),
            timestamp_unix_ms: 1_787_000_000_000,
        };
        let resp_bytes = to_cbor(&resp).unwrap();
        let decoded_resp: GatewayReflexiveResponse = from_cbor(&resp_bytes).unwrap();
        assert_eq!(decoded_resp, resp);
    }

    #[test]
    fn register_request_accepts_legacy_payload_without_capabilities() {
        #[derive(Serialize)]
        struct LegacyRegisterRequest {
            auth_key: Option<String>,
            access_token: Option<String>,
            #[serde(with = "serde_bytes_array_32")]
            peer_key_pub: [u8; 32],
            hostname: String,
            os: String,
            version: String,
            #[serde(rename = "type")]
            r#type: Option<ConnectorType>,
            system_info: Option<SystemInfo>,
        }

        let legacy = LegacyRegisterRequest {
            auth_key: Some("k".into()),
            access_token: None,
            peer_key_pub: [1u8; 32],
            hostname: "h".into(),
            os: "linux".into(),
            version: "v".into(),
            r#type: None,
            system_info: None,
        };
        let bytes = to_cbor(&legacy).unwrap();
        let decoded: RegisterRequest = from_cbor(&bytes).unwrap();
        assert!(decoded.capabilities.is_empty());
        assert!(decoded.supported_link_modes.is_empty());
        assert!(decoded.preferred_mode.is_none());
    }

    #[test]
    fn gateway_report_request_roundtrip() {
        let req = GatewayReportRequest {
            gateway_id: "gw-1".into(),
            wg_pubkey: [9u8; 32],
            wg_endpoint: "1.2.3.4:51820".into(),
            wss_endpoint: "wss://gw-1:9443".into(),
            wg_tunnel_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            nsgw_version: Some("1.2.3".into()),
            nsc_connections: Some(7),
            wg_relay_endpoint: Some("1.2.3.4:51999".into()),
            draining: true,
            capabilities: vec![CAPABILITY_PUBLIC_INGRESS_CONFIG_V1.into()],
            public_ingress_scopes: vec![PUBLIC_INGRESS_SCOPE_HTTP_1_1_REVERSE_PROXY.into()],
        };
        let bytes = to_cbor(&req).unwrap();
        let decoded: GatewayReportRequest = from_cbor(&bytes).unwrap();
        assert_eq!(decoded.gateway_id, "gw-1");
        assert_eq!(decoded.wg_pubkey, [9u8; 32]);
        assert_eq!(decoded.wg_endpoint, "1.2.3.4:51820");
        assert_eq!(decoded.wss_endpoint, "wss://gw-1:9443");
        assert_eq!(decoded.wg_tunnel_ip, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(decoded.nsgw_version.as_deref(), Some("1.2.3"));
        assert_eq!(decoded.nsc_connections, Some(7));
        assert_eq!(decoded.wg_relay_endpoint.as_deref(), Some("1.2.3.4:51999"));
        assert!(decoded.draining);
        assert_eq!(
            decoded.capabilities,
            vec![CAPABILITY_PUBLIC_INGRESS_CONFIG_V1]
        );
        assert_eq!(
            decoded.public_ingress_scopes,
            vec![PUBLIC_INGRESS_SCOPE_HTTP_1_1_REVERSE_PROXY]
        );
    }

    #[test]
    fn gateway_report_request_accepts_legacy_payload_without_capabilities() {
        #[derive(Serialize)]
        struct LegacyGatewayReportRequest {
            gateway_id: String,
            #[serde(with = "serde_bytes_array_32")]
            wg_pubkey: [u8; 32],
            wg_endpoint: String,
            wss_endpoint: String,
            wg_tunnel_ip: Option<Ipv4Addr>,
        }

        let legacy = LegacyGatewayReportRequest {
            gateway_id: "gw-1".into(),
            wg_pubkey: [9u8; 32],
            wg_endpoint: "1.2.3.4:51820".into(),
            wss_endpoint: "wss://gw-1:9443".into(),
            wg_tunnel_ip: None,
        };
        let bytes = to_cbor(&legacy).unwrap();
        let decoded: GatewayReportRequest = from_cbor(&bytes).unwrap();
        assert!(decoded.nsgw_version.is_none());
        assert!(decoded.nsc_connections.is_none());
        assert!(decoded.wg_relay_endpoint.is_none());
        assert!(!decoded.draining);
        assert!(decoded.capabilities.is_empty());
        assert!(decoded.public_ingress_scopes.is_empty());
    }

    #[test]
    fn gateway_report_request_extra_metadata_is_ignored_by_older_shape() {
        #[derive(Deserialize)]
        struct OlderGatewayReportRequest {
            gateway_id: String,
            #[serde(with = "serde_bytes_array_32")]
            wg_pubkey: [u8; 32],
            wg_endpoint: String,
            wss_endpoint: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            wg_tunnel_ip: Option<Ipv4Addr>,
            #[serde(default)]
            draining: bool,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            capabilities: Vec<String>,
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            public_ingress_scopes: Vec<String>,
        }

        let req = GatewayReportRequest {
            gateway_id: "gw-1".into(),
            wg_pubkey: [9u8; 32],
            wg_endpoint: "1.2.3.4:51820".into(),
            wss_endpoint: "wss://gw-1:9443".into(),
            wg_tunnel_ip: None,
            nsgw_version: Some("1.2.3".into()),
            nsc_connections: Some(5),
            wg_relay_endpoint: None,
            draining: false,
            capabilities: Vec::new(),
            public_ingress_scopes: Vec::new(),
        };

        let bytes = to_cbor(&req).unwrap();
        let decoded: OlderGatewayReportRequest = from_cbor(&bytes).unwrap();
        assert_eq!(decoded.gateway_id, "gw-1");
        assert_eq!(decoded.wg_pubkey, [9u8; 32]);
        assert_eq!(decoded.wg_endpoint, "1.2.3.4:51820");
        assert_eq!(decoded.wss_endpoint, "wss://gw-1:9443");
        assert!(decoded.wg_tunnel_ip.is_none());
        assert!(!decoded.draining);
        assert!(decoded.capabilities.is_empty());
        assert!(decoded.public_ingress_scopes.is_empty());
    }

    #[test]
    fn gateway_report_response_roundtrip() {
        let resp = GatewayReportResponse::default();
        let bytes = to_cbor(&resp).unwrap();
        let _: GatewayReportResponse = from_cbor(&bytes).unwrap();
    }

    #[test]
    fn auth_payload_roundtrip_and_purpose_optional() {
        // purpose present round-trips.
        let req = AuthPayload {
            purpose: Some("wss".into()),
        };
        let bytes = to_cbor(&req).unwrap();
        let decoded: AuthPayload = from_cbor(&bytes).unwrap();
        assert_eq!(decoded.purpose.as_deref(), Some("wss"));

        // purpose absent is omitted from the encoding and decodes to None, so
        // NSD can distinguish "absent" (defaults to control) from an explicit
        // value.
        let req = AuthPayload::default();
        let value = serde_json::to_value(&req).unwrap();
        assert!(value.get("purpose").is_none());
        let bytes = to_cbor(&req).unwrap();
        let decoded: AuthPayload = from_cbor(&bytes).unwrap();
        assert!(decoded.purpose.is_none());
    }

    #[test]
    fn auth_response_roundtrip() {
        let resp = AuthResponse {
            token: "header.payload.sig".into(),
        };
        let bytes = to_cbor(&resp).unwrap();
        let decoded: AuthResponse = from_cbor(&bytes).unwrap();
        assert_eq!(decoded.token, "header.payload.sig");
    }

    #[test]
    fn heartbeat_request_roundtrip() {
        let req = HeartbeatRequest {
            uptime_secs: 3600,
            local_ips: vec!["10.0.0.1".into(), "192.168.1.2".into()],
        };
        let bytes = to_cbor(&req).unwrap();
        let decoded: HeartbeatRequest = from_cbor(&bytes).unwrap();
        assert_eq!(req.uptime_secs, decoded.uptime_secs);
        assert_eq!(req.local_ips, decoded.local_ips);
    }

    #[test]
    fn config_stream_event_payload_v1_roundtrip() {
        let payload = ConfigStreamEventPayloadV1 {
            v: 1,
            message: ControlMessage::Ping,
        };
        let bytes = to_cbor(&payload).unwrap();
        let decoded: ConfigStreamEventPayloadV1 = from_cbor(&bytes).unwrap();
        assert_eq!(decoded.v, 1);
        assert!(matches!(decoded.message, ControlMessage::Ping));
    }

    #[test]
    fn config_stream_request_public_ingress_fields_are_backward_compatible() {
        let legacy = ConfigStreamRequest::default();
        let bytes = to_cbor(&legacy).unwrap();
        let decoded: ConfigStreamRequest = from_cbor(&bytes).unwrap();
        assert!(decoded.capabilities.is_empty());
        assert!(decoded.public_ingress_scopes.is_empty());

        let capable = ConfigStreamRequest {
            capabilities: vec![CAPABILITY_PUBLIC_INGRESS_CONFIG_V1.into()],
            public_ingress_scopes: vec![PUBLIC_INGRESS_SCOPE_HTTP_1_1_REVERSE_PROXY.into()],
        };
        let bytes = to_cbor(&capable).unwrap();
        let decoded: ConfigStreamRequest = from_cbor(&bytes).unwrap();
        assert_eq!(
            decoded.capabilities,
            vec![CAPABILITY_PUBLIC_INGRESS_CONFIG_V1]
        );
        assert_eq!(
            decoded.public_ingress_scopes,
            vec![PUBLIC_INGRESS_SCOPE_HTTP_1_1_REVERSE_PROXY]
        );
    }

    #[test]
    fn register_response_omits_absent_domain_base() {
        let resp = RegisterResponse {
            machine_id: "m-1".into(),
            server_peer_key_pub: "aa".repeat(32),
            server_endpoint: "1.2.3.4:51820".into(),
            domain_base: None,
            nsd_envelope_pubkey: None,
            wg_tunnel_ip: None,
        };
        let bytes = to_cbor(&resp).unwrap();
        let decoded: RegisterResponse = from_cbor(&bytes).unwrap();
        assert!(decoded.domain_base.is_none());
    }

    #[test]
    fn register_response_wg_tunnel_ip_roundtrips_when_present() {
        let resp = RegisterResponse {
            machine_id: "gw-1".into(),
            server_peer_key_pub: "aa".repeat(32),
            server_endpoint: "1.2.3.4:51820".into(),
            domain_base: Some("gw-1.n.ns".into()),
            nsd_envelope_pubkey: Some("bb".repeat(32)),
            wg_tunnel_ip: Some(Ipv4Addr::new(10, 100, 0, 1)),
        };

        let cbor = to_cbor(&resp).unwrap();
        let cbor_decoded: RegisterResponse = from_cbor(&cbor).unwrap();
        assert_eq!(
            cbor_decoded.wg_tunnel_ip,
            Some(Ipv4Addr::new(10, 100, 0, 1))
        );

        let json = serde_json::to_string(&resp).unwrap();
        let json_decoded: RegisterResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(
            json_decoded.wg_tunnel_ip,
            Some(Ipv4Addr::new(10, 100, 0, 1))
        );
    }

    #[test]
    fn register_response_omits_absent_wg_tunnel_ip() {
        let resp = RegisterResponse {
            machine_id: "m-1".into(),
            server_peer_key_pub: "aa".repeat(32),
            server_endpoint: "1.2.3.4:51820".into(),
            domain_base: None,
            nsd_envelope_pubkey: None,
            wg_tunnel_ip: None,
        };

        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("wg_tunnel_ip").is_none());
    }

    #[test]
    fn register_response_legacy_payload_decodes_absent_wg_tunnel_ip() {
        #[derive(serde::Serialize)]
        struct LegacyRegisterResponse {
            machine_id: String,
            server_peer_key_pub: String,
            server_endpoint: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            domain_base: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            nsd_envelope_pubkey: Option<String>,
        }

        let legacy = LegacyRegisterResponse {
            machine_id: "m-1".into(),
            server_peer_key_pub: "aa".repeat(32),
            server_endpoint: "1.2.3.4:51820".into(),
            domain_base: None,
            nsd_envelope_pubkey: None,
        };

        let cbor = to_cbor(&legacy).unwrap();
        let cbor_decoded: RegisterResponse = from_cbor(&cbor).unwrap();
        assert!(cbor_decoded.wg_tunnel_ip.is_none());

        let json = serde_json::to_string(&legacy).unwrap();
        let json_decoded: RegisterResponse = serde_json::from_str(&json).unwrap();
        assert!(json_decoded.wg_tunnel_ip.is_none());
    }

    #[test]
    fn info_get_response_carries_envelope_versions() {
        use common::{AuthMethod, NsdType};

        let info = NsdInfo {
            nsd_type: NsdType::SelfHosted,
            realm: "r".into(),
            auth_methods: vec![AuthMethod::AuthKey],
            provider: "p".into(),
            version: "v".into(),
            nsd_noise_pubkey: None,
            nsd_quic_pubkey: None,
            signed_transport_keyset: None,
            nsd_envelope_pubkey: None,
            envelope_versions: vec![1],
            capabilities: vec![CAPABILITY_PUBLIC_INGRESS_CONFIG_V1.into()],
            public_ingress_scopes: vec![PUBLIC_INGRESS_SCOPE_HTTP_1_1_REVERSE_PROXY.into()],
        };
        let resp = InfoGetResponse { info };
        let bytes = to_cbor(&resp).unwrap();
        let decoded: InfoGetResponse = from_cbor(&bytes).unwrap();
        assert_eq!(decoded.info.envelope_versions, vec![1]);
        assert_eq!(
            decoded.info.capabilities,
            vec![CAPABILITY_PUBLIC_INGRESS_CONFIG_V1]
        );
        assert_eq!(
            decoded.info.public_ingress_scopes,
            vec![PUBLIC_INGRESS_SCOPE_HTTP_1_1_REVERSE_PROXY]
        );
    }

    #[test]
    fn info_get_request_is_empty_cbor() {
        let req = InfoGetRequest::default();
        let bytes = to_cbor(&req).unwrap();
        // CBOR empty map is a single byte (0xA0). We only assert the struct
        // round-trips; the actual bytes may vary across ciborium versions.
        let _: InfoGetRequest = from_cbor(&bytes).unwrap();
    }

    #[test]
    fn wg_relay_registration_request_roundtrips() {
        let req = WgRelayRegistrationRequest {
            nsn_pubkey: [8u8; 32],
        };
        let bytes = to_cbor(&req).unwrap();
        let decoded: WgRelayRegistrationRequest = from_cbor(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn peer_candidates_report_request_roundtrips() {
        let req = PeerCandidatesReportRequest {
            epoch: 7,
            peer_key_pub: [3u8; 32],
            candidates: vec![crate::messages::P2pCandidate {
                kind: crate::messages::P2pCandidateKind::ServerReflexive,
                endpoint: "203.0.113.10:40000".parse().unwrap(),
                priority: 100,
                observed_at_unix_ms: 1_787_000_000_000,
                source: Some("stun:198.51.100.1:3478".to_owned()),
                relay_url: None,
            }],
        };
        let bytes = to_cbor(&req).unwrap();
        let decoded: PeerCandidatesReportRequest = from_cbor(&bytes).unwrap();
        assert_eq!(decoded, req);

        let resp = PeerCandidatesReportResponse::default();
        let bytes = to_cbor(&resp).unwrap();
        let _: PeerCandidatesReportResponse = from_cbor(&bytes).unwrap();
    }
}
