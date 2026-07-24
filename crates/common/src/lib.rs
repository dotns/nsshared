#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! Shared types for the NSN workspace.
//!
//! Provides the configuration structs, machine-state management, and shared
//! protocol types used by all other crates:
//!
//! - [`ConnectorConfig`] — top-level layered configuration (figment).
//! - [`ControlCenterConfig`] / [`GatewayConfig`] — per-endpoint config.
//! - [`MachineState`] — Ed25519 + X25519 key management and registration.
//! - [`ServicesConfig`] / [`ServiceDef`] — local service whitelist.
//! - [`Protocol`], [`IpNet`] — shared protocol primitives.

pub mod dns_names;
pub mod envelope_pins;
pub mod jwt_pins;
pub mod services;
pub mod state;
pub mod tunnel;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use dns_names::{
    GATEWAY_DNS_SUFFIX, MACHINE_DNS_SUFFIX, SERVICE_DNS_SUFFIX, gateway_fqdn, is_gateway_fqdn,
    is_machine_fqdn, is_service_fqdn, machine_fqdn, service_fqdn,
};
pub use ipnet::IpNet;
pub use services::{
    GatewayPreference, PublicIngressSubjectPolicy, RuleViolation, ServiceDef, ServiceError,
    ServiceSettings, ServicesConfig, TunnelPreference, port_in_range, proto_matches,
};
pub use state::{
    AuthMethod, CAPABILITY_CAPTURE_ROUTES_V1, CAPABILITY_GATEWAY_PUBLIC_EDGE_V1,
    CAPABILITY_NSC_APPLICATION_UDP_V1, CAPABILITY_NSN_VIRTUAL_LISTENER_V1,
    CAPABILITY_POLICY_VERSION_V1, MachineIdentity, MachineState, NsdInfo, NsdTransportKeyset,
    NsdType, PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_CONFIG, PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_STATE_FENCE,
    PUBLIC_EDGE_SCOPE_GATEWAY_HTTP_UPSTREAM_TLS_ACCEPT_UNTRUSTED, PUBLIC_EDGE_SCOPE_GATEWAY_L4_MAP,
    RealmRegistration, StateError,
};

/// Shared error type for common configuration.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Config(String),
}

/// Configuration for a single NSD (control-plane) endpoint.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ControlCenterConfig {
    /// Unique identifier for this control center.
    pub id: String,
    /// Base URL of the NSD (e.g. `https://nsd1.example.com`).
    pub url: String,
    /// Expected NSD realm for tunnel-first bootstrap.
    ///
    /// Required for `control_mode = "noise"` / `"quic"` so static trust anchors
    /// can be selected before plaintext discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// Static first-transport Noise X25519 responder public key.
    ///
    /// Hex-encoded 32-byte key used only to bootstrap signed `info.get` in
    /// anti-DPI mode. The signed response may rotate this key for subsequent
    /// control calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noise_bootstrap_pubkey: Option<String>,
    /// Static first-transport QUIC certificate SHA-256 fingerprint.
    ///
    /// Hex-encoded 32-byte fingerprint used only to bootstrap signed `info.get`
    /// in anti-DPI mode. The signed response may rotate this key for subsequent
    /// control calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_bootstrap_cert_sha256: Option<String>,
    /// RFC 7638 SHA-256 thumbprints for this NSD's envelope signing keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nsd_envelope_key_pins: Vec<String>,
    /// Priority — lower value = higher priority (primary).
    #[serde(default = "default_priority")]
    pub priority: u32,
}

/// Configuration for a single NSGW (gateway) endpoint.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GatewayConfig {
    /// Unique identifier for this gateway.
    pub id: String,
    /// Gateway endpoint in `hostname:port` form (e.g. `us.gw.example.com:51820`).
    pub endpoint: String,
    /// Priority — lower value = preferred gateway.
    #[serde(default = "default_priority")]
    pub priority: u32,
    /// Transport mode: `auto` (default), `wss`, or `udp`.
    #[serde(default = "default_transport_mode")]
    pub transport_mode: String,
    /// Whether this gateway is enabled.  Disabled gateways are never connected.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Gateway's tunnel-side IPv4 address used as the ICMP probe target
    /// (PLAN-016). Optional because the control protocol does not yet
    /// surface it; when absent the probe is skipped for this gateway and
    /// failover falls back to the handshake-count silence detector.
    #[serde(default)]
    pub tunnel_ip: Option<std::net::Ipv4Addr>,
}

/// Top-level connector configuration, assembled by figment in `crates/nsn`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConnectorConfig {
    /// Single-endpoint backward-compatible URL.  When non-empty and
    /// `control_centers` / `gateways` are empty, this URL is used for both
    /// the control plane and gateway.
    #[serde(default)]
    pub server_url: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Path to the local services definition file (TOML).
    /// Defaults to `"services.toml"` in the working directory.
    #[serde(default = "default_services_file")]
    pub services_file: String,
    /// Directory where machine state (keys, registration info) is stored.
    /// Defaults to `/var/lib/nsio`.
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    /// One-time auth key used on the first run to register this machine.
    /// When combined with `machine_id`, keys are derived deterministically so no
    /// state file is required — the machine re-registers on every startup.
    #[serde(default)]
    pub auth_key: Option<String>,
    /// Fixed device identifier.  When set together with `auth_key` the client
    /// operates in stateless / config-free mode: keys are derived from the pair
    /// and the machine re-registers idempotently on every startup.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Timeout for DNS resolution of `RewriteTarget::Domain` entries, in seconds.
    /// Defaults to 5 seconds.
    #[serde(default = "default_dns_timeout_secs")]
    pub dns_timeout_secs: u64,
    /// Per-NSD control endpoint establishment timeout, in seconds.
    ///
    /// Bounds endpoint selection (auth, services report, stream open) but not
    /// the long-lived config stream after it is established.
    #[serde(default = "default_nsd_endpoint_attempt_timeout_secs")]
    pub nsd_endpoint_attempt_timeout_secs: u64,
    /// TTL for the DNS result cache, in seconds. Defaults to 60 seconds.
    #[serde(default = "default_dns_cache_ttl_secs")]
    pub dns_cache_ttl_secs: u64,
    /// Maximum inbound SSE stream events accepted per second.
    /// Default: 100.
    #[serde(default = "default_ws_max_messages_per_sec")]
    pub ws_max_messages_per_sec: u32,
    /// Maximum inbound SSE event payload size in bytes.
    /// Default: 1 MiB (1_048_576 bytes).
    #[serde(default = "default_ws_max_message_size")]
    pub ws_max_message_size: usize,
    /// Transport mode: `auto` (default), `wss`, or `udp`.
    #[serde(default = "default_transport_mode")]
    pub transport_mode: String,
    /// Control center (NSD) endpoints.  When non-empty, takes precedence over
    /// `server_url` for control-plane connectivity.  Entries are sorted by
    /// priority (ascending) — first entry is primary.
    #[serde(default)]
    pub control_centers: Vec<ControlCenterConfig>,
    /// Gateway (NSGW) endpoints.  When non-empty, takes precedence over
    /// `server_url` for data-plane connectivity.
    #[serde(default)]
    pub gateways: Vec<GatewayConfig>,
    /// Directory to write structured JSON log files.
    /// When set, a daily-rotating `nsn.log` (JSON) is written here.
    /// `None` disables file logging (default).
    #[serde(default)]
    pub log_dir: Option<String>,
    /// NSN LAN IP used as the SNAT source address when proxying to remote
    /// (non-loopback) services.  When `None`, SNAT is disabled.
    ///
    /// Set via `--snat-addr` CLI flag or `SNAT_ADDR` environment variable.
    /// If not set, remote services will see the virtual tunnel IP as the
    /// source, which prevents reply routing back through NSN.
    #[serde(default)]
    pub snat_addr: Option<IpAddr>,
    /// Control transport mode: `"sse"` (default) or `"noise"`.
    ///
    /// Set via `--control-mode` CLI flag or `CONTROL_MODE` env var.
    #[serde(default = "default_control_mode")]
    pub control_mode: String,
    /// Explicit primary control endpoint selector by transport (PLAN-009).
    ///
    /// Names the PRIMARY control endpoint by transport mode — one of `"sse"`,
    /// `"noise"`, or `"quic"` — independently of `control_centers` list / priority
    /// order. When set, the effective control endpoint sequence is reordered so
    /// the first entry whose URL scheme maps to this mode (`noise://` → `noise`,
    /// `quic://` → `quic`, `http(s)://` or scheme-less → `sse`) becomes primary;
    /// the remaining entries keep their relative order, and the per-endpoint
    /// fallback chain is preserved. The reordering is performed by the shared
    /// `control::order_endpoints_by_default_mode` helper so all consumers
    /// (ns-shared, nsgw, ns) reorder identically.
    ///
    /// `None` (unset) leaves list order authoritative — `control_centers[0]`
    /// (lowest priority value) stays primary, byte-for-byte backward compatible.
    /// An unrecognised value matches no endpoint and is therefore ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsd_default_mode: Option<String>,
    /// Expected default NSD realm for tunnel-first bootstrap.
    ///
    /// Used for single-endpoint configs and as a fallback for
    /// `control_centers[*].realm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// Static first-transport Noise X25519 responder public key.
    ///
    /// Hex-encoded 32-byte key. `nsd_pubkey` is accepted as a serde alias for
    /// existing config files and environment-driven Figment input.
    #[serde(default, alias = "nsd_pubkey", skip_serializing_if = "Option::is_none")]
    pub noise_bootstrap_pubkey: Option<String>,
    /// Static first-transport QUIC certificate SHA-256 fingerprint.
    ///
    /// Hex-encoded 32-byte fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic_bootstrap_cert_sha256: Option<String>,
    /// RFC 7638 SHA-256 thumbprints for NSD RS256 JWT signing keys.
    ///
    /// These are base64url-without-padding JWK thumbprints over the RSA
    /// canonical input `{e,kty,n}`. They intentionally do not share storage
    /// with `noise_bootstrap_pubkey`, which is X25519 transport material.
    #[serde(default)]
    pub nsd_jwt_key_pins: Vec<String>,
    /// RFC 7638 SHA-256 thumbprints for NSD Ed25519 envelope signing keys.
    ///
    /// These are base64url-without-padding OKP JWK thumbprints over the
    /// canonical input `{crv,kty,x}` where `x` is the raw 32-byte Ed25519
    /// public key encoded as base64url without padding.
    #[serde(default)]
    pub nsd_envelope_key_pins: Vec<String>,
    /// Conntrack TTL + capacity cap + GC cadence (PLAN-019).
    ///
    /// Tunes the reverse-NAT conntrack table that backs TUN-mode hybrid
    /// routing.  Defaults are safe for production; override only when a
    /// deployment has known long-lived quiet flows or very tight memory
    /// budgets.
    #[serde(default)]
    pub conntrack: ConntrackConfig,
    /// Local (operator-authored) ACL layer configuration (PLAN-020).
    ///
    /// Controls loading of an on-disk `acls.toml` whose accept rules are
    /// evaluated first in the layered union merge and whose `deny_scope`
    /// narrows the final policy.  Defaults are backward-compatible: a missing
    /// file is tolerated unless `strict = true`.
    #[serde(default)]
    pub local_acl: LocalAclConfig,
    /// Path to a PEM bundle of additional X.509 CA certificates to trust
    /// when establishing TLS to NSGW WSS relay endpoints.
    ///
    /// File format: concatenated PEM-encoded X.509 certificates
    /// (the standard input shape accepted by `rustls::pki_types::pem::PemObject`).
    /// Non-certificate PEM entries (private keys, CRLs, …) are ignored.
    ///
    /// When `None` (default), only the Mozilla WebPKI roots are trusted —
    /// matching the production behaviour for publicly-signed gateways.
    /// When set, the bundle is added on top of the WebPKI roots. NSC fails
    /// to start if the file is missing, unreadable, or contains zero certs,
    /// so operator misconfiguration is surfaced loudly rather than silently
    /// falling back to system roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_ca_certs: Option<PathBuf>,
    /// Optional NSGW UDP endpoint used by NATed NSNs to register the observed
    /// source address for zero-trust `wg-relay`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_relay_registration_endpoint: Option<SocketAddr>,
}

/// Conntrack TTL, capacity cap, and background cleanup interval.
///
/// Seconds-based and serde-deserializable.  The `nat` crate converts this
/// into its internal [`Duration`]-based form at tunnel build time.
///
/// Defaults:
/// - `tcp_ttl_secs = 300` — two kernel keepalive cycles.
/// - `udp_ttl_secs = 30` — aggressive because UDP has no FIN; `last_seen`
///   is refreshed on every reply.
/// - `cap = 65_536` — soft cap; after a TTL sweep, any excess is LRU-evicted.
/// - `cleanup_interval_secs = 10` — GC runs one pass every 10 s.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConntrackConfig {
    #[serde(default = "default_conntrack_tcp_ttl_secs")]
    pub tcp_ttl_secs: u64,
    #[serde(default = "default_conntrack_udp_ttl_secs")]
    pub udp_ttl_secs: u64,
    #[serde(default = "default_conntrack_cap")]
    pub cap: usize,
    #[serde(default = "default_conntrack_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,
}

impl Default for ConntrackConfig {
    fn default() -> Self {
        Self {
            tcp_ttl_secs: default_conntrack_tcp_ttl_secs(),
            udp_ttl_secs: default_conntrack_udp_ttl_secs(),
            cap: default_conntrack_cap(),
            cleanup_interval_secs: default_conntrack_cleanup_interval_secs(),
        }
    }
}

fn default_conntrack_tcp_ttl_secs() -> u64 {
    300
}

fn default_conntrack_udp_ttl_secs() -> u64 {
    30
}

fn default_conntrack_cap() -> usize {
    65_536
}

fn default_conntrack_cleanup_interval_secs() -> u64 {
    10
}

/// Local ACL layer configuration (PLAN-020).
///
/// `file` points at an operator-authored `acls.toml`; its accept rules are
/// prepended to the layered union merge and its `[local.deny_scope]` section
/// narrows the merged policy. `strict` makes a missing / invalid file a
/// startup failure (fail-closed on misconfiguration) instead of a logged
/// warning. `last_good_max_age_secs` bounds how long a per-NSD last-good ACL
/// cache may be served while that NSD is in `FetchFailed` state before the
/// merge treats the entry as degraded (defaults to 24 h per PLAN-020).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LocalAclConfig {
    /// Path to the local ACL file. Defaults to `acls.toml` alongside
    /// `services.toml`. The layer is skipped if the file is absent and
    /// `strict` is false.
    #[serde(default = "default_local_acl_file")]
    pub file: Option<String>,
    /// When `true`, a missing or invalid local ACL file aborts startup.
    /// Defaults to `false` so existing deployments without `acls.toml`
    /// keep starting (remote-only policy).
    #[serde(default)]
    pub strict: bool,
    /// Maximum age, in seconds, of a per-NSD last-good ACL cache before the
    /// merge downgrades it to degraded. Defaults to 86_400 (24 h).
    #[serde(default = "default_last_good_max_age_secs")]
    pub last_good_max_age_secs: u64,
}

impl Default for LocalAclConfig {
    fn default() -> Self {
        Self {
            file: default_local_acl_file(),
            strict: false,
            last_good_max_age_secs: default_last_good_max_age_secs(),
        }
    }
}

fn default_local_acl_file() -> Option<String> {
    Some("acls.toml".to_string())
}

fn default_last_good_max_age_secs() -> u64 {
    86_400
}

impl ConnectorConfig {
    /// Returns `true` if at least one endpoint is configured.
    pub fn has_endpoint(&self) -> bool {
        !self.server_url.is_empty() || !self.control_centers.is_empty()
    }

    /// Returns effective control-center configs, sorted by priority.
    ///
    /// When `control_centers` is non-empty, returns those (sorted).
    /// Otherwise, derives a single entry from `server_url`.
    pub fn effective_control_centers(&self) -> Vec<ControlCenterConfig> {
        if !self.control_centers.is_empty() {
            let mut ccs = self.control_centers.clone();
            for cc in &mut ccs {
                if cc.realm.is_none() {
                    cc.realm = self.realm.clone();
                }
                if cc.nsd_envelope_key_pins.is_empty() {
                    cc.nsd_envelope_key_pins = self.nsd_envelope_key_pins.clone();
                }
            }
            ccs.sort_by_key(|c| c.priority);
            ccs
        } else if !self.server_url.is_empty() {
            vec![ControlCenterConfig {
                id: "default".to_string(),
                url: self.server_url.clone(),
                realm: self.realm.clone(),
                noise_bootstrap_pubkey: self.noise_bootstrap_pubkey.clone(),
                quic_bootstrap_cert_sha256: self.quic_bootstrap_cert_sha256.clone(),
                nsd_envelope_key_pins: self.nsd_envelope_key_pins.clone(),
                priority: 1,
            }]
        } else {
            vec![]
        }
    }

    /// Returns effective gateway configs for enabled gateways, sorted by priority.
    ///
    /// When `gateways` is non-empty, returns enabled entries (sorted).
    /// Otherwise, derives a single entry from `server_url`.
    pub fn effective_gateways(&self) -> Vec<GatewayConfig> {
        if !self.gateways.is_empty() {
            let mut gws: Vec<_> = self
                .gateways
                .iter()
                .filter(|g| g.enabled)
                .cloned()
                .collect();
            gws.sort_by_key(|g| g.priority);
            gws
        } else if !self.server_url.is_empty() {
            vec![GatewayConfig {
                id: "default".to_string(),
                endpoint: self.server_url.clone(),
                priority: 1,
                transport_mode: self.transport_mode.clone(),
                enabled: true,
                tunnel_ip: None,
            }]
        } else {
            vec![]
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_services_file() -> String {
    "services.toml".to_string()
}

fn default_state_dir() -> String {
    "/var/lib/nsio".to_string()
}

fn default_dns_timeout_secs() -> u64 {
    5
}

fn default_nsd_endpoint_attempt_timeout_secs() -> u64 {
    8
}

fn default_dns_cache_ttl_secs() -> u64 {
    60
}

fn default_ws_max_messages_per_sec() -> u32 {
    100
}

fn default_ws_max_message_size() -> usize {
    1_048_576 // 1 MiB
}

fn default_transport_mode() -> String {
    "auto".to_string()
}

fn default_priority() -> u32 {
    1
}

fn default_enabled() -> bool {
    true
}

fn default_control_mode() -> String {
    "sse".to_string()
}

/// Data-plane mode for WireGuard decrypted packet processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataPlaneMode {
    /// Kernel TCP via TUN interface. Requires root or CAP_NET_ADMIN.
    Tun,
    /// smoltcp user-space TCP/IP stack. No elevated privileges required.
    #[default]
    UserSpace,
    /// Pure WebSocket relay, no WireGuard.
    Wss,
}

impl std::str::FromStr for DataPlaneMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tun" => Ok(Self::Tun),
            "userspace" => Ok(Self::UserSpace),
            "wss" => Ok(Self::Wss),
            other => Err(format!(
                "unknown data-plane mode '{other}', expected: tun, userspace, wss"
            )),
        }
    }
}

impl std::fmt::Display for DataPlaneMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tun => write!(f, "tun"),
            Self::UserSpace => write!(f, "userspace"),
            Self::Wss => write!(f, "wss"),
        }
    }
}

/// System information reported by NSN to NSD on registration and heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Machine hostname.
    pub hostname: String,
    /// OS family: "linux", "macos", "windows".
    pub os: String,
    /// Human-readable OS version (e.g. "Ubuntu 22.04", "Debian 12").
    pub os_version: String,
    /// CPU architecture: "x86_64", "aarch64", etc.
    pub arch: String,
    /// Kernel release string (e.g. "6.1.0-43-amd64").
    pub kernel: String,
    /// NSN binary version from `CARGO_PKG_VERSION`.
    pub nsn_version: String,
    /// Active data-plane mode: "tun", "userspace", or "wss".
    pub data_plane: String,
    /// Process uptime in seconds. Updated on each heartbeat.
    pub uptime_secs: u64,
    /// Primary non-loopback interface IP addresses.
    pub local_ips: Vec<String>,
    /// Number of logical CPU cores available to the process.
    pub cpu_count: usize,
    /// Total system memory in megabytes (0 if unavailable).
    pub memory_total_mb: u64,
    /// Reachable WireGuard UDP endpoint (`ip:port`) advertised as the static
    /// fallback for zero-trust `wg-relay`. NATed NSNs can omit this and use the
    /// authenticated registration leg to teach NSGW the observed UDP source.
    /// Absent for NSC and for NSNs that do not opt into wg-relay; `wss-relay`
    /// deliberately carries no endpoint (the NSN dials outbound).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_endpoint: Option<String>,
}

impl SystemInfo {
    /// Collect current system info.
    ///
    /// `data_plane` is the active data-plane mode string (e.g. "userspace").
    /// `uptime_secs` is set by the caller so the heartbeat can pass fresh values.
    pub fn collect(data_plane: &str, uptime_secs: u64) -> Self {
        SystemInfo {
            hostname: sysinfo_hostname(),
            os: std::env::consts::OS.to_string(),
            os_version: sysinfo_os_version(),
            arch: std::env::consts::ARCH.to_string(),
            kernel: sysinfo_kernel(),
            nsn_version: env!("CARGO_PKG_VERSION").to_string(),
            data_plane: data_plane.to_string(),
            uptime_secs,
            local_ips: SystemInfo::collect_local_ips(),
            cpu_count: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            memory_total_mb: sysinfo_memory_mb(),
            wg_endpoint: None,
        }
    }

    /// Attach the reachable WireGuard endpoint advertised for `wg-relay`.
    #[must_use]
    pub fn with_wg_endpoint(mut self, wg_endpoint: Option<String>) -> Self {
        self.wg_endpoint = wg_endpoint;
        self
    }

    /// Return the primary non-loopback IP addresses of this host.
    ///
    /// Uses a UDP connect trick (no packets sent) to discover the outbound
    /// interface address. Returns an empty `Vec` on failure.
    pub fn collect_local_ips() -> Vec<String> {
        use std::net::UdpSocket;
        let mut ips = Vec::new();
        // connect() on UDP sets the default destination but sends nothing.
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0")
            && socket.connect("8.8.8.8:80").is_ok()
            && let Ok(addr) = socket.local_addr()
        {
            let ip = addr.ip();
            if !ip.is_loopback() && !ip.is_unspecified() {
                ips.push(ip.to_string());
            }
        }
        ips
    }
}

fn sysinfo_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Parse `PRETTY_NAME` from `/etc/os-release` (Linux/macOS); fall back to OS name.
fn sysinfo_os_version() -> String {
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                return val.trim_matches('"').to_string();
            }
        }
    }
    std::env::consts::OS.to_string()
}

/// Read kernel release from `/proc/sys/kernel/osrelease` (Linux).
fn sysinfo_kernel() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Parse `MemTotal` from `/proc/meminfo` and convert kB → MB.
fn sysinfo_memory_mb() -> u64 {
    let content = match std::fs::read_to_string("/proc/meminfo") {
        Ok(c) => c,
        Err(_) => return 0,
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return kb / 1024;
        }
    }
    0
}

/// Network protocol selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
    /// HTTP service — routes by `Host` header on port 80.
    Http,
    /// HTTPS service — routes by TLS SNI on port 443.
    Https,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SystemInfo wg_endpoint (wg-relay advertise) ───────────────────────

    #[test]
    fn system_info_wg_endpoint_round_trips_and_defaults_absent() {
        // Default collect() leaves wg_endpoint absent — older blobs and NSC
        // never carry it, and `skip_serializing_if` keeps the wire clean.
        let base = SystemInfo::collect("userspace", 0);
        assert!(base.wg_endpoint.is_none());
        let json = serde_json::to_string(&base).unwrap();
        assert!(
            !json.contains("wg_endpoint"),
            "absent wg_endpoint must not serialize: {json}"
        );

        // An advertised endpoint round-trips and is readable under the exact
        // key NSD's gateway_wg_relay projection may use as static fallback.
        let with = base.with_wg_endpoint(Some("198.51.100.20:51820".to_owned()));
        let value = serde_json::to_value(&with).unwrap();
        assert_eq!(
            value.get("wg_endpoint").and_then(|v| v.as_str()),
            Some("198.51.100.20:51820")
        );
        let decoded: SystemInfo = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.wg_endpoint.as_deref(), Some("198.51.100.20:51820"));

        // Backward compatibility: a blob without the field decodes to None.
        let legacy = serde_json::json!({
            "hostname": "h", "os": "linux", "os_version": "", "arch": "x86_64",
            "kernel": "", "nsn_version": "0", "data_plane": "userspace",
            "uptime_secs": 0, "local_ips": [], "cpu_count": 1, "memory_total_mb": 0
        });
        let decoded: SystemInfo = serde_json::from_value(legacy).unwrap();
        assert!(decoded.wg_endpoint.is_none());
    }

    // ── ConnectorConfig ───────────────────────────────────────────────────

    #[test]
    fn config_round_trips_via_json() {
        let cfg = ConnectorConfig {
            server_url: "http://127.0.0.1:3000".to_string(),
            log_level: "debug".to_string(),
            services_file: "/etc/nsio/services.toml".to_string(),
            state_dir: "/tmp/nsio".to_string(),
            auth_key: None,
            machine_id: None,
            dns_timeout_secs: 5,
            nsd_endpoint_attempt_timeout_secs: 8,
            dns_cache_ttl_secs: 60,
            ws_max_messages_per_sec: 100,
            ws_max_message_size: 1_048_576,
            transport_mode: "wss".to_string(),
            control_centers: vec![],
            gateways: vec![],
            log_dir: None,
            snat_addr: None,
            control_mode: "sse".to_string(),
            nsd_default_mode: None,
            realm: None,
            noise_bootstrap_pubkey: None,
            quic_bootstrap_cert_sha256: None,
            nsd_jwt_key_pins: vec![],
            nsd_envelope_key_pins: vec![],
            conntrack: ConntrackConfig::default(),
            local_acl: LocalAclConfig::default(),
            extra_ca_certs: None,
            wg_relay_registration_endpoint: None,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: ConnectorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.server_url, cfg.server_url);
        assert_eq!(decoded.log_level, cfg.log_level);
        assert_eq!(decoded.services_file, cfg.services_file);
        assert_eq!(decoded.state_dir, cfg.state_dir);
        assert_eq!(decoded.transport_mode, cfg.transport_mode);
    }

    #[test]
    fn config_transport_mode_defaults_to_auto() {
        let json = r#"{"server_url":"http://localhost"}"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.transport_mode, "auto");
    }

    #[test]
    fn config_nsd_jwt_key_pins_defaults_and_deserializes() {
        let cfg: ConnectorConfig =
            serde_json::from_str(r#"{"server_url":"http://localhost"}"#).unwrap();
        assert!(cfg.nsd_jwt_key_pins.is_empty());

        let cfg: ConnectorConfig = serde_json::from_str(
            r#"{"server_url":"http://localhost","nsd_jwt_key_pins":["pin-a","pin-b"]}"#,
        )
        .unwrap();
        assert_eq!(cfg.nsd_jwt_key_pins, vec!["pin-a", "pin-b"]);
    }

    #[test]
    fn config_nsd_envelope_key_pins_defaults_and_deserializes() {
        let cfg: ConnectorConfig =
            serde_json::from_str(r#"{"server_url":"http://localhost"}"#).unwrap();
        assert!(cfg.nsd_envelope_key_pins.is_empty());

        let cfg: ConnectorConfig = serde_json::from_str(
            r#"{"server_url":"http://localhost","nsd_envelope_key_pins":["pin-a","pin-b"]}"#,
        )
        .unwrap();
        assert_eq!(cfg.nsd_envelope_key_pins, vec!["pin-a", "pin-b"]);
    }

    #[test]
    fn config_transport_bootstrap_fields_default_and_alias() {
        let cfg: ConnectorConfig =
            serde_json::from_str(r#"{"server_url":"http://localhost"}"#).unwrap();
        assert!(cfg.realm.is_none());
        assert!(cfg.noise_bootstrap_pubkey.is_none());
        assert!(cfg.quic_bootstrap_cert_sha256.is_none());

        let cfg: ConnectorConfig = serde_json::from_str(
            r#"{
                "server_url":"noise://nsd.example:4001",
                "realm":"realm-a",
                "nsd_pubkey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "quic_bootstrap_cert_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }"#,
        )
        .unwrap();
        assert_eq!(cfg.realm.as_deref(), Some("realm-a"));
        assert_eq!(cfg.noise_bootstrap_pubkey, Some("aa".repeat(32)));
        assert_eq!(cfg.quic_bootstrap_cert_sha256, Some("bb".repeat(32)));
    }

    #[test]
    fn config_state_dir_defaults_to_var_lib_nsio() {
        let json = r#"{"server_url":"http://localhost"}"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.state_dir, "/var/lib/nsio");
    }

    #[test]
    fn config_log_level_defaults_to_info() {
        let json = r#"{"server_url":"http://localhost"}"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.log_level, "info");
    }

    #[test]
    fn config_ws_max_messages_per_sec_defaults_to_100() {
        let json = r#"{"server_url":"http://localhost"}"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.ws_max_messages_per_sec, 100);
    }

    #[test]
    fn config_nsd_endpoint_attempt_timeout_defaults_to_8() {
        let json = r#"{"server_url":"http://localhost"}"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.nsd_endpoint_attempt_timeout_secs, 8);
    }

    #[test]
    fn config_empty_has_no_endpoint() {
        // server_url now defaults to empty string; has_endpoint() catches missing config.
        let json = r#"{}"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.server_url.is_empty());
        assert!(cfg.control_centers.is_empty());
        assert!(!cfg.has_endpoint());
    }

    #[test]
    fn config_effective_control_centers_falls_back_to_server_url() {
        let json = r#"{"server_url":"http://nsd.example.com"}"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        let ccs = cfg.effective_control_centers();
        assert_eq!(ccs.len(), 1);
        assert_eq!(ccs[0].url, "http://nsd.example.com");
        assert_eq!(ccs[0].id, "default");
    }

    #[test]
    fn config_effective_control_centers_uses_explicit_entries() {
        let json = r#"{
            "control_centers": [
                {"id": "nsd-b", "url": "https://nsd2.example.com", "priority": 2},
                {"id": "nsd-a", "url": "https://nsd1.example.com", "priority": 1}
            ]
        }"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        let ccs = cfg.effective_control_centers();
        assert_eq!(ccs.len(), 2);
        // sorted by priority
        assert_eq!(ccs[0].id, "nsd-a");
        assert_eq!(ccs[1].id, "nsd-b");
    }

    #[test]
    fn config_effective_control_centers_inherits_shared_realm_and_envelope_pins() {
        let json = r#"{
            "realm": "realm-a",
            "nsd_envelope_key_pins": ["pin-shared"],
            "control_centers": [
                {"id": "nsd-a", "url": "https://nsd1.example.com", "priority": 1},
                {
                    "id": "nsd-b",
                    "url": "https://nsd2.example.com",
                    "realm": "realm-b",
                    "nsd_envelope_key_pins": ["pin-b"],
                    "priority": 2
                }
            ]
        }"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        let ccs = cfg.effective_control_centers();
        assert_eq!(ccs[0].realm.as_deref(), Some("realm-a"));
        assert_eq!(ccs[0].nsd_envelope_key_pins, vec!["pin-shared"]);
        assert_eq!(ccs[1].realm.as_deref(), Some("realm-b"));
        assert_eq!(ccs[1].nsd_envelope_key_pins, vec!["pin-b"]);
    }

    #[test]
    fn config_effective_gateways_filters_disabled() {
        let json = r#"{
            "gateways": [
                {"id": "gw-1", "endpoint": "us.gw.example.com:51820", "priority": 1, "enabled": true},
                {"id": "gw-2", "endpoint": "eu.gw.example.com:51820", "priority": 2, "enabled": false}
            ]
        }"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        let gws = cfg.effective_gateways();
        assert_eq!(gws.len(), 1);
        assert_eq!(gws[0].id, "gw-1");
    }

    #[test]
    fn config_has_endpoint_true_when_server_url_set() {
        let json = r#"{"server_url":"http://localhost"}"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.has_endpoint());
    }

    #[test]
    fn config_has_endpoint_true_when_control_centers_set() {
        let json = r#"{"control_centers":[{"id":"nsd","url":"https://nsd.example.com"}]}"#;
        let cfg: ConnectorConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.has_endpoint());
    }

    // ── Error ─────────────────────────────────────────────────────────────

    #[test]
    fn error_display_contains_message() {
        let err = Error::Config("bad value".to_string());
        assert!(err.to_string().contains("bad value"));
    }

    // ── Protocol ─────────────────────────────────────────────────────────

    #[test]
    fn protocol_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Protocol::Tcp).unwrap(), r#""tcp""#);
        assert_eq!(serde_json::to_string(&Protocol::Udp).unwrap(), r#""udp""#);
        assert_eq!(serde_json::to_string(&Protocol::Both).unwrap(), r#""both""#);
    }

    #[test]
    fn protocol_deserializes_from_lowercase() {
        assert_eq!(
            serde_json::from_str::<Protocol>(r#""tcp""#).unwrap(),
            Protocol::Tcp
        );
        assert_eq!(
            serde_json::from_str::<Protocol>(r#""udp""#).unwrap(),
            Protocol::Udp
        );
        assert_eq!(
            serde_json::from_str::<Protocol>(r#""both""#).unwrap(),
            Protocol::Both
        );
    }
}
