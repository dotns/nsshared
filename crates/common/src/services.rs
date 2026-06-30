//! Local service definitions and validation for NSN.
//!
//! A `services.toml` file declares which local services this connector may
//! proxy to.  Services are keyed by name:
//!
//! ```toml
//! [settings]
//! strict = true
//!
//! [services.web]
//! protocol = "tcp"
//! host = "192.168.1.10"
//! port = 80
//!
//! [services.dns]
//! protocol = "udp"
//! host = "192.168.1.1"
//! port = 53
//! ```
//!
//! # Default behaviour (no file / empty file)
//!
//! If `services.toml` does not exist or contains no service entries,
//! [`ServicesConfig::load`] returns a **strict empty config** that denies
//! every server-sent proxy rule.  This is the safe, fail-closed default.
//!
//! To opt into permissive mode (all rules accepted), either:
//! - Set `strict = false` in the `[settings]` section of `services.toml`, or
//! - Pass the `--permissive` CLI flag (intended for dev/testing only).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{IpNet, Protocol, dns_names};

// ── errors ───────────────────────────────────────────────────────────────────

/// Errors that can occur while loading a services config file.
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("failed to read services file '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse services file '{path}': {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
}

// ── types ─────────────────────────────────────────────────────────────────────

/// Preferred tunnel transport for a service.
///
/// Controls which data-plane path NSN uses when forwarding traffic for this
/// service.  `Auto` lets NSN pick based on runtime conditions (default).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelPreference {
    /// Let NSN choose (WireGuard UDP preferred, WSS fallback).
    #[default]
    Auto,
    /// Force WireGuard UDP tunnel.
    Wg,
    /// Force WebSocket (WSS) relay tunnel.
    Ws,
}

/// Subject policy for public ingress exposure.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PublicIngressSubjectPolicy {
    /// Require a verified external identity provider subject.
    #[default]
    ExternalIdp,
    /// Admit unauthenticated traffic as the explicit `anonymous` ACL subject.
    Anonymous,
}

/// Preferred gateway for a service.
///
/// `Auto` (default) means all connected gateways are eligible and
/// connection-level load balancing / failover applies.  `Specific` pins
/// traffic for this service to a named gateway (by its `id` field in the
/// connector config), enabling symmetric routing for stateful protocols.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum GatewayPreference {
    /// All connected gateways are eligible (load balance / failover).
    #[default]
    Auto,
    /// Pin to the gateway with this ID.
    Specific(String),
}

impl<'de> Deserialize<'de> for GatewayPreference {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s.eq_ignore_ascii_case("auto") {
            Ok(GatewayPreference::Auto)
        } else {
            Ok(GatewayPreference::Specific(s))
        }
    }
}

impl Serialize for GatewayPreference {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            GatewayPreference::Auto => serializer.serialize_str("auto"),
            GatewayPreference::Specific(id) => serializer.serialize_str(id),
        }
    }
}

/// Top-level settings for service validation.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceSettings {
    /// When `true`, proxy rules that do not match any local service are
    /// rejected.  When `false` (permissive), they are logged but still loaded.
    #[serde(default = "default_strict")]
    pub strict: bool,
}

fn default_strict() -> bool {
    true
}

impl Default for ServiceSettings {
    fn default() -> Self {
        Self { strict: true }
    }
}

/// A single locally defined service that the connector is allowed to proxy to.
///
/// The service name is the key in [`ServicesConfig::services`]; it does not
/// appear as a field inside the struct.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceDef {
    /// Network protocol (tcp / udp / both / http / https).
    pub protocol: Protocol,
    /// Target host — an IP address or domain name.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Optional user-pinned overlay (virtual) port.
    ///
    /// When set, NSD pins this as the service's overlay `virtual_port` instead
    /// of defaulting to `port` / allocating from the pool. Must be unique per
    /// machine. `None` lets NSD choose (default = `port`, pool-fallback on a
    /// same-port conflict).
    #[serde(default)]
    pub virtual_port: Option<u16>,
    /// Domain name used for Layer-7 routing.
    ///
    /// Required when `protocol` is `http` or `https`.  NSN matches the
    /// HTTP `Host` header (for `http`) or TLS SNI (for `https`) against this
    /// value to select the correct backend service.  Ignored for `tcp`/`udp`.
    #[serde(default)]
    pub domain: Option<String>,
    /// Optional free-form description (not used for matching).
    #[serde(default)]
    pub description: Option<String>,
    /// When `false` the service is ignored; server rules targeting it are
    /// rejected even in permissive mode.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Preferred tunnel transport for this service.  Defaults to `Auto`.
    #[serde(default)]
    pub tunnel: TunnelPreference,
    /// Preferred gateway for this service.  Defaults to `Auto` (all gateways).
    #[serde(default)]
    pub gateway: GatewayPreference,
    /// Public ingress subject policy. Defaults to requiring an external IdP
    /// subject; anonymous public ingress must be explicit.
    #[serde(default)]
    pub public_ingress_subject_policy: PublicIngressSubjectPolicy,
}

fn default_enabled() -> bool {
    true
}

impl ServiceDef {
    /// Returns `true` if this service targets the local machine.
    ///
    /// Hosts considered local: `127.0.0.1`, `localhost`, `0.0.0.0`, `::1`.
    /// Remote services (LAN IPs, domain names) return `false` and require SNAT
    /// so that the remote host can route replies back through the NSN LAN IP.
    pub fn is_local(&self) -> bool {
        matches!(
            self.host.as_str(),
            "127.0.0.1" | "localhost" | "0.0.0.0" | "::1"
        )
    }

    /// Returns the fully-qualified identifier for this service.
    ///
    /// Format: `"{name}.{node_id}.n.ns.io"`, e.g. `"web.ab3xk9mnpq.n.ns.io"`.
    ///
    /// `name` is the service key from `services.toml` (the `[services.NAME]` section header).
    /// `node_id` is the machine ID assigned by NSD on registration.
    pub fn fqid(&self, name: &str, node_id: &str) -> String {
        dns_names::service_fqdn(name, node_id)
    }
}

/// A server-sent proxy rule that did not match any local service definition.
#[derive(Debug, Clone)]
pub struct RuleViolation {
    /// The `resource_id` from the offending `SubnetRule`.
    pub rule_resource_id: String,
    /// Human-readable explanation of the mismatch.
    pub reason: String,
}

/// Whitelist of local services loaded from a TOML file.
///
/// Services are stored by name in a [`HashMap`].  Use
/// [`ServicesConfig::load`] to construct and [`ServicesConfig::is_allowed`]
/// to validate individual rule targets.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ServicesConfig {
    #[serde(default)]
    pub settings: ServiceSettings,
    /// Map from service name → definition.
    #[serde(default)]
    pub services: HashMap<String, ServiceDef>,
}

impl ServicesConfig {
    /// Load from a TOML file at `path`.
    ///
    /// **Fail-closed by default.** Returns a strict empty config (denies all
    /// proxy rules) when:
    /// - the file does not exist, or
    /// - the file defines no services.
    ///
    /// Use `strict = false` in `[settings]` or the `--permissive` CLI flag to
    /// opt into permissive mode.
    pub fn load(path: &Path) -> Result<Self, ServiceError> {
        if !path.exists() {
            tracing::warn!(
                path = %path.display(),
                "services file not found — running in strict mode (all proxy rules denied); \
                 create services.toml or pass --permissive to opt out"
            );
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path).map_err(|source| ServiceError::Io {
            path: path.display().to_string(),
            source,
        })?;

        let config: Self = toml::from_str(&content).map_err(|source| ServiceError::Parse {
            path: path.display().to_string(),
            source,
        })?;

        if config.services.is_empty() {
            tracing::warn!(
                path = %path.display(),
                "services file defines no services — all proxy rules will be denied; \
                 add service definitions or set strict = false to opt into permissive mode"
            );
        }

        Ok(config)
    }

    /// Parse a `ServicesConfig` from a TOML string.
    ///
    /// Intended for use in tests and documentation examples.
    /// An empty string or file with no `[services]` section yields a strict
    /// config (denies all proxy rules) unless `strict = false` is set explicitly.
    ///
    /// [`load`]: ServicesConfig::load
    pub fn from_toml_str(content: &str) -> Result<Self, ServiceError> {
        let config: Self = toml::from_str(content).map_err(|source| ServiceError::Parse {
            path: "<string>".to_string(),
            source,
        })?;
        Ok(config)
    }

    /// Returns `true` if strict validation mode is active.
    pub fn is_strict(&self) -> bool {
        self.settings.strict
    }

    /// Check whether (`host`, `port`, `protocol`) matches any enabled service.
    ///
    /// Host comparison is canonical for IP addresses and case-insensitive for
    /// domain names.
    pub fn is_allowed(&self, host: &str, port: u16, protocol: Protocol) -> bool {
        self.services.values().filter(|s| s.enabled).any(|s| {
            host_eq(&s.host, host) && s.port == port && proto_matches(s.protocol, protocol)
        })
    }

    /// Check whether any enabled service with an IP host falls within `cidr`,
    /// with a port covered by `port_range` and a matching protocol.
    ///
    /// Services whose `host` cannot be parsed as an [`IpAddr`] are skipped.
    pub fn is_cidr_allowed(
        &self,
        cidr: &IpNet,
        port_range: Option<(u16, u16)>,
        protocol: Protocol,
    ) -> bool {
        self.services.values().filter(|s| s.enabled).any(|s| {
            if let Ok(ip) = s.host.parse::<IpAddr>() {
                cidr.contains(&ip)
                    && port_in_range(s.port, port_range)
                    && proto_matches(s.protocol, protocol)
            } else {
                false
            }
        })
    }

    /// Check whether (`host`, a port within `port_range`, `protocol`) matches
    /// any enabled service.  `None` for `port_range` means any port.
    pub fn is_allowed_in_range(
        &self,
        host: &str,
        port_range: Option<(u16, u16)>,
        protocol: Protocol,
    ) -> bool {
        self.services.values().filter(|s| s.enabled).any(|s| {
            host_eq(&s.host, host)
                && port_in_range(s.port, port_range)
                && proto_matches(s.protocol, protocol)
        })
    }

    /// Find the first enabled service whose port and protocol match.
    ///
    /// `Protocol::Both` on either side counts as a match (see [`proto_matches`]).
    pub fn find_by_port(&self, port: u16, proto: Protocol) -> Option<&ServiceDef> {
        self.services
            .values()
            .filter(|s| s.enabled)
            .find(|s| s.port == port && proto_matches(s.protocol, proto))
    }

    /// Like [`find_by_port`] but also returns the service name (map key).
    pub fn find_named_by_port(&self, port: u16, proto: Protocol) -> Option<(&String, &ServiceDef)> {
        self.services
            .iter()
            .filter(|(_, s)| s.enabled)
            .find(|(_, s)| s.port == port && proto_matches(s.protocol, proto))
    }

    /// Find the first enabled `http` service whose `domain` matches `host`.
    ///
    /// Comparison is case-insensitive.  The port suffix (`:80`) in the HTTP
    /// `Host` header is stripped before comparison.
    pub fn find_by_domain(&self, host: &str) -> Option<&ServiceDef> {
        let host = host.split(':').next().unwrap_or(host);
        self.services.values().filter(|s| s.enabled).find(|s| {
            s.protocol == Protocol::Http
                && s.domain
                    .as_deref()
                    .is_some_and(|d| d.eq_ignore_ascii_case(host))
        })
    }

    /// Like [`find_by_domain`] but also returns the service name (map key).
    pub fn find_named_by_domain(&self, host: &str) -> Option<(&String, &ServiceDef)> {
        let host = host.split(':').next().unwrap_or(host);
        self.services
            .iter()
            .filter(|(_, s)| s.enabled)
            .find(|(_, s)| {
                s.protocol == Protocol::Http
                    && s.domain
                        .as_deref()
                        .is_some_and(|d| d.eq_ignore_ascii_case(host))
            })
    }

    /// Find the first enabled `https` service whose `domain` matches `sni`.
    ///
    /// Comparison is case-insensitive.
    pub fn find_by_sni(&self, sni: &str) -> Option<&ServiceDef> {
        self.services.values().filter(|s| s.enabled).find(|s| {
            s.protocol == Protocol::Https
                && s.domain
                    .as_deref()
                    .is_some_and(|d| d.eq_ignore_ascii_case(sni))
        })
    }

    /// Like [`find_by_sni`] but also returns the service name (map key).
    pub fn find_named_by_sni(&self, sni: &str) -> Option<(&String, &ServiceDef)> {
        self.services
            .iter()
            .filter(|(_, s)| s.enabled)
            .find(|(_, s)| {
                s.protocol == Protocol::Https
                    && s.domain
                        .as_deref()
                        .is_some_and(|d| d.eq_ignore_ascii_case(sni))
            })
    }

    /// Iterate over `(name, definition)` pairs for all enabled services.
    pub fn enabled_services(&self) -> impl Iterator<Item = (&String, &ServiceDef)> {
        self.services.iter().filter(|(_, s)| s.enabled)
    }

    /// Number of enabled services.
    pub fn enabled_count(&self) -> usize {
        self.services.values().filter(|s| s.enabled).count()
    }

    /// Number of disabled services.
    pub fn disabled_count(&self) -> usize {
        self.services.values().filter(|s| !s.enabled).count()
    }

    /// Check whether `ip:port:protocol` matches any enabled service.
    ///
    /// When a service's `host` field is a hostname rather than an IP literal,
    /// it is resolved via DNS and the result is compared to `ip`.  This allows
    /// WSS `Open` frames (which carry IPs) to be validated against services
    /// configured with Docker/DNS hostnames.
    ///
    /// The fast path (IP literals) avoids any DNS call.
    ///
    /// Protocol compatibility is evaluated at the transport layer via
    /// [`proto_matches_transport`] so that services declared as `http` or
    /// `https` (Layer-7 protocols that ride on TCP) whitelist the underlying
    /// TCP connection that carries them.  Layer-7 dispatch by Host-header or
    /// SNI is performed separately by the caller, not here.
    pub async fn is_allowed_by_ip(&self, ip: IpAddr, port: u16, protocol: Protocol) -> bool {
        for svc in self.services.values().filter(|s| s.enabled) {
            if svc.port != port || !proto_matches_transport(svc.protocol, protocol) {
                continue;
            }
            // Fast path: service host is an IP literal — compare directly.
            if let Ok(svc_ip) = svc.host.parse::<IpAddr>() {
                if svc_ip == ip {
                    return true;
                }
                continue;
            }
            // Slow path: service host is a hostname — resolve via DNS and compare.
            // Note: nested if kept separate for Rust <1.88 compatibility (let-chains).
            #[allow(clippy::collapsible_if)]
            if let Ok(addrs) = tokio::net::lookup_host(format!("{}:{}", svc.host, port)).await {
                if addrs
                    .into_iter()
                    .any(|addr: std::net::SocketAddr| addr.ip() == ip)
                {
                    return true;
                }
            }
        }
        false
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Compare two host strings with canonical IP normalisation and
/// case-insensitive domain matching.
fn host_eq(a: &str, b: &str) -> bool {
    if let (Ok(ia), Ok(ib)) = (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        return ia == ib;
    }
    a.eq_ignore_ascii_case(b)
}

/// Returns `true` if `port` falls within `range`, or `range` is `None`.
pub fn port_in_range(port: u16, range: Option<(u16, u16)>) -> bool {
    match range {
        None => true,
        Some((lo, hi)) => port >= lo && port <= hi,
    }
}

/// Returns `true` if `service_proto` is compatible with `rule_proto`.
///
/// `Protocol::Both` on either side is considered a match.  This is the strict
/// match used for Layer-7 routing (by `Host` header or SNI), where `Http` and
/// `Https` are distinct selectors — a raw TCP rule must not silently route to
/// an HTTP service and bypass domain validation.  For transport-layer
/// whitelist checks (does this IP/port/proto correspond to *any* configured
/// service, regardless of Layer-7 discriminator) use [`proto_matches_transport`].
pub fn proto_matches(service_proto: Protocol, rule_proto: Protocol) -> bool {
    service_proto == rule_proto || service_proto == Protocol::Both || rule_proto == Protocol::Both
}

/// Transport-layer protocol compatibility check.
///
/// Behaves like [`proto_matches`] but additionally treats `Http` and `Https`
/// services as TCP at the transport layer, since both protocols ride on TCP.
/// Use this for whitelist/ACL checks where we care that *some* service owns
/// the port at the network level; the Layer-7 routing decision (by Host
/// header or SNI) happens later, independently, via [`find_named_by_domain`]
/// or [`find_named_by_sni`].
///
/// [`find_named_by_domain`]: ServicesConfig::find_named_by_domain
/// [`find_named_by_sni`]: ServicesConfig::find_named_by_sni
pub fn proto_matches_transport(service_proto: Protocol, rule_proto: Protocol) -> bool {
    if proto_matches(service_proto, rule_proto) {
        return true;
    }
    matches!(
        (service_proto, rule_proto),
        (Protocol::Http | Protocol::Https, Protocol::Tcp)
            | (Protocol::Tcp, Protocol::Http | Protocol::Https)
    )
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── load / parse ──────────────────────────────────────────────────────────

    #[test]
    fn missing_file_returns_strict() {
        let cfg = ServicesConfig::load(Path::new("/nonexistent/__no_such_services.toml")).unwrap();
        assert!(
            cfg.is_strict(),
            "missing file must default to strict (fail-closed)"
        );
        assert!(cfg.services.is_empty());
    }

    #[test]
    fn empty_toml_returns_strict() {
        let cfg = ServicesConfig::from_toml_str("").unwrap();
        assert!(
            cfg.is_strict(),
            "empty file must default to strict (fail-closed)"
        );
        assert!(cfg.services.is_empty());
    }

    #[test]
    fn explicit_permissive_setting_respected() {
        let cfg = ServicesConfig::from_toml_str("[settings]\nstrict = false").unwrap();
        assert!(!cfg.is_strict(), "explicit strict = false must be honoured");
        assert!(cfg.services.is_empty());
    }

    #[test]
    fn valid_named_services_parsed() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[settings]
strict = true

[services.web]
protocol = "tcp"
host = "192.168.1.10"
port = 80
"#,
        )
        .unwrap();
        assert!(cfg.is_strict());
        assert_eq!(cfg.services.len(), 1);
        let web = cfg.services.get("web").unwrap();
        assert_eq!(web.port, 80);
        assert!(web.enabled);
        assert!(web.description.is_none());
    }

    #[test]
    fn multiple_named_services_parsed() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[settings]
strict = true

[services.web]
protocol = "tcp"
host = "192.168.1.10"
port = 80
description = "Main web server"

[services.dns]
protocol = "udp"
host = "192.168.1.1"
port = 53
"#,
        )
        .unwrap();
        assert_eq!(cfg.services.len(), 2);
        assert!(cfg.services.contains_key("web"));
        assert!(cfg.services.contains_key("dns"));
        assert_eq!(
            cfg.services["web"].description.as_deref(),
            Some("Main web server")
        );
    }

    #[test]
    fn optional_fields_have_defaults() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.svc]
protocol = "udp"
host = "10.0.0.1"
port = 53
"#,
        )
        .unwrap();
        let svc = &cfg.services["svc"];
        assert!(svc.enabled, "enabled should default to true");
        assert!(svc.description.is_none());
        assert_eq!(
            svc.tunnel,
            TunnelPreference::Auto,
            "tunnel defaults to Auto"
        );
        assert_eq!(
            svc.gateway,
            GatewayPreference::Auto,
            "gateway defaults to Auto"
        );
    }

    // ── TunnelPreference ──────────────────────────────────────────────────────

    #[test]
    fn tunnel_preference_auto_is_default() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.svc]
protocol = "tcp"
host = "10.0.0.1"
port = 80
"#,
        )
        .unwrap();
        assert_eq!(cfg.services["svc"].tunnel, TunnelPreference::Auto);
    }

    #[test]
    fn tunnel_preference_wg_parsed() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.svc]
protocol = "tcp"
host = "10.0.0.1"
port = 80
tunnel = "wg"
"#,
        )
        .unwrap();
        assert_eq!(cfg.services["svc"].tunnel, TunnelPreference::Wg);
    }

    #[test]
    fn tunnel_preference_ws_parsed() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.svc]
protocol = "tcp"
host = "10.0.0.1"
port = 80
tunnel = "ws"
"#,
        )
        .unwrap();
        assert_eq!(cfg.services["svc"].tunnel, TunnelPreference::Ws);
    }

    #[test]
    fn tunnel_preference_auto_explicit_parsed() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.svc]
protocol = "tcp"
host = "10.0.0.1"
port = 80
tunnel = "auto"
"#,
        )
        .unwrap();
        assert_eq!(cfg.services["svc"].tunnel, TunnelPreference::Auto);
    }

    // ── GatewayPreference ─────────────────────────────────────────────────────

    #[test]
    fn gateway_preference_auto_is_default() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.svc]
protocol = "tcp"
host = "10.0.0.1"
port = 80
"#,
        )
        .unwrap();
        assert_eq!(cfg.services["svc"].gateway, GatewayPreference::Auto);
    }

    #[test]
    fn gateway_preference_auto_explicit_parsed() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.svc]
protocol = "tcp"
host = "10.0.0.1"
port = 80
gateway = "auto"
"#,
        )
        .unwrap();
        assert_eq!(cfg.services["svc"].gateway, GatewayPreference::Auto);
    }

    #[test]
    fn gateway_preference_auto_case_insensitive() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.svc]
protocol = "tcp"
host = "10.0.0.1"
port = 80
gateway = "AUTO"
"#,
        )
        .unwrap();
        assert_eq!(cfg.services["svc"].gateway, GatewayPreference::Auto);
    }

    #[test]
    fn gateway_preference_specific_parsed() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.svc]
protocol = "tcp"
host = "10.0.0.1"
port = 80
gateway = "gw-us-east"
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.services["svc"].gateway,
            GatewayPreference::Specific("gw-us-east".to_string())
        );
    }

    #[test]
    fn tunnel_and_gateway_combined() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.db]
protocol = "tcp"
host = "10.0.0.5"
port = 5432
tunnel = "wg"
gateway = "gw-eu-west"
"#,
        )
        .unwrap();
        let db = &cfg.services["db"];
        assert_eq!(db.tunnel, TunnelPreference::Wg);
        assert_eq!(
            db.gateway,
            GatewayPreference::Specific("gw-eu-west".to_string())
        );
    }

    #[test]
    fn gateway_preference_serializes_auto() {
        let gw = GatewayPreference::Auto;
        let json = serde_json::to_string(&gw).unwrap();
        assert_eq!(json, r#""auto""#);
    }

    #[test]
    fn gateway_preference_serializes_specific() {
        let gw = GatewayPreference::Specific("gw-1".to_string());
        let json = serde_json::to_string(&gw).unwrap();
        assert_eq!(json, r#""gw-1""#);
    }

    #[test]
    fn tunnel_preference_serializes_correctly() {
        assert_eq!(
            serde_json::to_string(&TunnelPreference::Auto).unwrap(),
            r#""auto""#
        );
        assert_eq!(
            serde_json::to_string(&TunnelPreference::Wg).unwrap(),
            r#""wg""#
        );
        assert_eq!(
            serde_json::to_string(&TunnelPreference::Ws).unwrap(),
            r#""ws""#
        );
    }

    #[test]
    fn disabled_service_parsed() {
        let cfg = ServicesConfig::from_toml_str(
            r#"
[services.ssh]
protocol = "tcp"
host = "127.0.0.1"
port = 22
enabled = false
"#,
        )
        .unwrap();
        assert!(!cfg.services["ssh"].enabled);
    }

    // ── is_allowed ────────────────────────────────────────────────────────────

    fn cfg_with_services() -> ServicesConfig {
        let mut services = HashMap::new();
        services.insert(
            "web".to_string(),
            ServiceDef {
                protocol: Protocol::Tcp,
                host: "192.168.1.10".into(),
                port: 80,
                domain: None,
                description: None,
                enabled: true,
                tunnel: TunnelPreference::Auto,
                gateway: GatewayPreference::Auto,
                public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
            },
        );
        services.insert(
            "dns".to_string(),
            ServiceDef {
                protocol: Protocol::Udp,
                host: "192.168.1.1".into(),
                port: 53,
                domain: None,
                description: None,
                enabled: true,
                tunnel: TunnelPreference::Auto,
                gateway: GatewayPreference::Auto,
                public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
            },
        );
        services.insert(
            "ssh".to_string(),
            ServiceDef {
                protocol: Protocol::Tcp,
                host: "127.0.0.1".into(),
                port: 22,
                domain: None,
                description: None,
                enabled: false,
                tunnel: TunnelPreference::Auto,
                gateway: GatewayPreference::Auto,
                public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
            },
        );
        ServicesConfig {
            settings: ServiceSettings { strict: true },
            services,
        }
    }

    #[test]
    fn is_allowed_matches_enabled_service() {
        let cfg = cfg_with_services();
        assert!(cfg.is_allowed("192.168.1.10", 80, Protocol::Tcp));
        assert!(cfg.is_allowed("192.168.1.1", 53, Protocol::Udp));
    }

    #[test]
    fn is_allowed_rejects_disabled_service() {
        let cfg = cfg_with_services();
        assert!(!cfg.is_allowed("127.0.0.1", 22, Protocol::Tcp));
    }

    #[test]
    fn is_allowed_rejects_protocol_mismatch() {
        let cfg = cfg_with_services();
        assert!(!cfg.is_allowed("192.168.1.10", 80, Protocol::Udp));
    }

    #[test]
    fn is_allowed_rejects_port_mismatch() {
        let cfg = cfg_with_services();
        assert!(!cfg.is_allowed("192.168.1.10", 8080, Protocol::Tcp));
    }

    #[test]
    fn is_allowed_rejects_unknown_host() {
        let cfg = cfg_with_services();
        assert!(!cfg.is_allowed("10.0.0.5", 80, Protocol::Tcp));
    }

    // ── is_allowed_in_range ───────────────────────────────────────────────────

    #[test]
    fn is_allowed_in_range_with_exact_port() {
        let cfg = cfg_with_services();
        assert!(cfg.is_allowed_in_range("192.168.1.10", Some((80, 80)), Protocol::Tcp));
    }

    #[test]
    fn is_allowed_in_range_with_range_containing_service_port() {
        let cfg = cfg_with_services();
        assert!(cfg.is_allowed_in_range("192.168.1.10", Some((70, 90)), Protocol::Tcp));
    }

    #[test]
    fn is_allowed_in_range_with_none_port_range() {
        let cfg = cfg_with_services();
        assert!(cfg.is_allowed_in_range("192.168.1.10", None, Protocol::Tcp));
    }

    #[test]
    fn is_allowed_in_range_rejects_out_of_range_port() {
        let cfg = cfg_with_services();
        assert!(!cfg.is_allowed_in_range("192.168.1.10", Some((443, 443)), Protocol::Tcp));
    }

    // ── is_cidr_allowed ───────────────────────────────────────────────────────

    #[test]
    fn is_cidr_allowed_matches_service_in_cidr() {
        let cfg = cfg_with_services();
        let cidr: IpNet = "192.168.1.0/24".parse().unwrap();
        assert!(cfg.is_cidr_allowed(&cidr, Some((80, 80)), Protocol::Tcp));
    }

    #[test]
    fn is_cidr_allowed_rejects_service_outside_cidr() {
        let cfg = cfg_with_services();
        let cidr: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(!cfg.is_cidr_allowed(&cidr, Some((80, 80)), Protocol::Tcp));
    }

    // ── proto_matches ─────────────────────────────────────────────────────────

    #[test]
    fn both_protocol_matches_tcp_and_udp() {
        assert!(proto_matches(Protocol::Both, Protocol::Tcp));
        assert!(proto_matches(Protocol::Both, Protocol::Udp));
        assert!(proto_matches(Protocol::Tcp, Protocol::Both));
        assert!(proto_matches(Protocol::Udp, Protocol::Both));
    }

    #[test]
    fn mismatched_protocols_do_not_match() {
        assert!(!proto_matches(Protocol::Tcp, Protocol::Udp));
        assert!(!proto_matches(Protocol::Udp, Protocol::Tcp));
    }

    #[test]
    fn proto_matches_keeps_http_and_tcp_distinct() {
        // Strict Layer-7 matcher must not conflate Http/Https with Tcp, so
        // Layer-7 dispatch (by Host / SNI) stays authoritative.
        assert!(!proto_matches(Protocol::Http, Protocol::Tcp));
        assert!(!proto_matches(Protocol::Tcp, Protocol::Http));
        assert!(!proto_matches(Protocol::Https, Protocol::Tcp));
        assert!(!proto_matches(Protocol::Tcp, Protocol::Https));
    }

    // ── proto_matches_transport ──────────────────────────────────────────────

    #[test]
    fn transport_matcher_treats_http_as_tcp() {
        assert!(proto_matches_transport(Protocol::Http, Protocol::Tcp));
        assert!(proto_matches_transport(Protocol::Tcp, Protocol::Http));
        assert!(proto_matches_transport(Protocol::Https, Protocol::Tcp));
        assert!(proto_matches_transport(Protocol::Tcp, Protocol::Https));
    }

    #[test]
    fn transport_matcher_still_rejects_cross_transport() {
        // TCP ↔ UDP must never match, even with the relaxed Layer-7 rule.
        assert!(!proto_matches_transport(Protocol::Tcp, Protocol::Udp));
        assert!(!proto_matches_transport(Protocol::Udp, Protocol::Tcp));
        // Http is still incompatible with UDP.
        assert!(!proto_matches_transport(Protocol::Http, Protocol::Udp));
        assert!(!proto_matches_transport(Protocol::Udp, Protocol::Http));
    }

    #[test]
    fn transport_matcher_delegates_to_strict_for_same_protos() {
        assert!(proto_matches_transport(Protocol::Tcp, Protocol::Tcp));
        assert!(proto_matches_transport(Protocol::Udp, Protocol::Udp));
        assert!(proto_matches_transport(Protocol::Http, Protocol::Http));
        assert!(proto_matches_transport(Protocol::Both, Protocol::Udp));
        assert!(proto_matches_transport(Protocol::Both, Protocol::Tcp));
    }

    // ── is_allowed_by_ip (transport-layer whitelist) ─────────────────────────

    #[tokio::test]
    async fn is_allowed_by_ip_accepts_tcp_for_http_service() {
        // A service declared as `protocol = "http"` on port 17777 must allow
        // an incoming raw-TCP Open on the same (IP, port) — Layer-7 routing
        // by Host-header happens later.  Regression test for wss_05
        // (local HTTP reached through WSS relay tcp Open frame).
        let mut map = HashMap::new();
        map.insert(
            "local-http".to_string(),
            ServiceDef {
                protocol: Protocol::Http,
                host: "127.0.0.1".into(),
                port: 17777,
                domain: Some("local-http.test.n.ns.io".into()),
                description: None,
                enabled: true,
                tunnel: TunnelPreference::Auto,
                gateway: GatewayPreference::Auto,
                public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
            },
        );
        let cfg = ServicesConfig {
            settings: ServiceSettings { strict: true },
            services: map,
        };
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(cfg.is_allowed_by_ip(ip, 17777, Protocol::Tcp).await);
    }

    #[tokio::test]
    async fn is_allowed_by_ip_accepts_tcp_for_https_service() {
        let mut map = HashMap::new();
        map.insert(
            "secure".to_string(),
            ServiceDef {
                protocol: Protocol::Https,
                host: "10.0.0.1".into(),
                port: 8443,
                domain: Some("secure.test.n.ns.io".into()),
                description: None,
                enabled: true,
                tunnel: TunnelPreference::Auto,
                gateway: GatewayPreference::Auto,
                public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
            },
        );
        let cfg = ServicesConfig {
            settings: ServiceSettings { strict: true },
            services: map,
        };
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(cfg.is_allowed_by_ip(ip, 8443, Protocol::Tcp).await);
    }

    #[tokio::test]
    async fn is_allowed_by_ip_still_rejects_udp_on_http_port() {
        let mut map = HashMap::new();
        map.insert(
            "local-http".to_string(),
            ServiceDef {
                protocol: Protocol::Http,
                host: "127.0.0.1".into(),
                port: 17777,
                domain: Some("local-http.test.n.ns.io".into()),
                description: None,
                enabled: true,
                tunnel: TunnelPreference::Auto,
                gateway: GatewayPreference::Auto,
                public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
            },
        );
        let cfg = ServicesConfig {
            settings: ServiceSettings { strict: true },
            services: map,
        };
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!cfg.is_allowed_by_ip(ip, 17777, Protocol::Udp).await);
    }

    #[tokio::test]
    async fn is_allowed_by_ip_rejects_disabled_http_service() {
        let mut map = HashMap::new();
        map.insert(
            "local-http".to_string(),
            ServiceDef {
                protocol: Protocol::Http,
                host: "127.0.0.1".into(),
                port: 17777,
                domain: Some("local-http.test.n.ns.io".into()),
                description: None,
                enabled: false,
                tunnel: TunnelPreference::Auto,
                gateway: GatewayPreference::Auto,
                public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
            },
        );
        let cfg = ServicesConfig {
            settings: ServiceSettings { strict: true },
            services: map,
        };
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!cfg.is_allowed_by_ip(ip, 17777, Protocol::Tcp).await);
    }

    // ── port_in_range ─────────────────────────────────────────────────────────

    #[test]
    fn port_in_range_none_matches_any() {
        assert!(port_in_range(0, None));
        assert!(port_in_range(65535, None));
    }

    #[test]
    fn port_in_range_boundary_conditions() {
        assert!(port_in_range(80, Some((80, 80))));
        assert!(port_in_range(80, Some((70, 90))));
        assert!(!port_in_range(79, Some((80, 80))));
        assert!(!port_in_range(81, Some((80, 80))));
    }

    // ── find_by_port ──────────────────────────────────────────────────────────

    #[test]
    fn find_by_port_returns_matching_service() {
        let cfg = cfg_with_services();
        let svc = cfg.find_by_port(80, Protocol::Tcp);
        assert!(svc.is_some());
        assert_eq!(svc.unwrap().host, "192.168.1.10");
    }

    #[test]
    fn find_by_port_returns_none_for_unknown_port() {
        let cfg = cfg_with_services();
        assert!(cfg.find_by_port(9999, Protocol::Tcp).is_none());
    }

    #[test]
    fn find_by_port_returns_none_for_disabled_service() {
        let cfg = cfg_with_services();
        // Port 22 exists but is disabled
        assert!(cfg.find_by_port(22, Protocol::Tcp).is_none());
    }

    #[test]
    fn find_by_port_returns_none_for_protocol_mismatch() {
        let cfg = cfg_with_services();
        // Port 80 is TCP only
        assert!(cfg.find_by_port(80, Protocol::Udp).is_none());
    }

    // ── counts ────────────────────────────────────────────────────────────────

    #[test]
    fn enabled_disabled_counts() {
        let cfg = cfg_with_services();
        assert_eq!(cfg.enabled_count(), 2);
        assert_eq!(cfg.disabled_count(), 1);
    }

    // ── is_local ──────────────────────────────────────────────────────────────

    fn svc(host: &str) -> ServiceDef {
        ServiceDef {
            protocol: Protocol::Tcp,
            host: host.to_string(),
            port: 22,
            domain: None,
            description: None,
            enabled: true,
            tunnel: TunnelPreference::Auto,
            gateway: GatewayPreference::Auto,
            public_ingress_subject_policy: PublicIngressSubjectPolicy::ExternalIdp,
        }
    }

    #[test]
    fn fqid_uses_canonical_service_dns_name() {
        assert_eq!(
            svc("127.0.0.1").fqid("web", "site-001"),
            "web.site-001.n.ns.io"
        );
    }

    #[test]
    fn is_local_returns_true_for_loopback_addresses() {
        assert!(svc("127.0.0.1").is_local());
        assert!(svc("localhost").is_local());
        assert!(svc("0.0.0.0").is_local());
        assert!(svc("::1").is_local());
    }

    #[test]
    fn is_local_returns_false_for_remote_addresses() {
        assert!(!svc("192.168.1.10").is_local());
        assert!(!svc("10.0.0.5").is_local());
        assert!(!svc("ssh.internal").is_local());
        assert!(!svc("172.16.0.1").is_local());
    }

    // ── enabled_services iterator ─────────────────────────────────────────────

    #[test]
    fn enabled_services_yields_name_and_def() {
        let cfg = cfg_with_services();
        let names: Vec<&String> = cfg.enabled_services().map(|(n, _)| n).collect();
        assert_eq!(names.len(), 2);
        assert!(names.iter().any(|n| n.as_str() == "web"));
        assert!(names.iter().any(|n| n.as_str() == "dns"));
        assert!(!names.iter().any(|n| n.as_str() == "ssh"));
    }
}
