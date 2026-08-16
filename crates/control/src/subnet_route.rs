//! L3 subnet-route contracts for a unified node.
//!
//! Two shapes live here and they are deliberately **not** interchangeable:
//!
//! * [`NodeSubnetRouteReport`] — what a node *wants*. A node advertises the
//!   prefixes it can reach. Reporting is intent and carries no authority
//!   whatsoever; a compromised node cannot promote itself into a route
//!   authority by reporting.
//! * [`SubnetRouteConfig`] — what NSD has *approved*. Only this projection
//!   authorizes a consumer to install a route, and only NSD produces it.
//!
//! Collapsing the two would make advertisement self-authorizing, so they stay
//! separate types with separate wire tags and separate validators.
//!
//! Neither replaces [`crate::messages::RouteEntry`] (an L4 logical service
//! route) or [`crate::messages::CaptureRoute`] (an NSC capture/exit
//! instruction). Those keep their current meanings unchanged.
//!
//! # Full-snapshot semantics
//!
//! Both shapes are full snapshots carrying a monotonic `generation`. Applying
//! a snapshot replaces the previous route set in full: a route the sender
//! omits is withdrawn, not retained. A snapshot whose generation does not
//! advance past the last applied one is stale and must be dropped whole — see
//! [`SubnetRouteConfig::supersedes`] and
//! [`SubnetRouteConfig::withdrawn_route_ids`].

use std::fmt;
use std::marker::PhantomData;
use std::net::Ipv4Addr;

use common::Ipv4Net;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

use crate::messages::{deserialize_wg_public_key, serialize_wg_public_key};

// ── bounds ───────────────────────────────────────────────────────────────────

/// Maximum advertised routes accepted in one [`NodeSubnetRouteReport`].
pub const MAX_SUBNET_ROUTES_PER_REPORT: usize = 64;

/// Maximum approved routes accepted in one [`SubnetRouteConfig`].
pub const MAX_APPROVED_SUBNET_ROUTES: usize = 256;

/// Maximum byte length of a route, realm, or machine identifier.
pub const MAX_SUBNET_ROUTE_IDENTIFIER_BYTES: usize = 128;

/// Maximum encoded size accepted for a [`NodeSubnetRouteReport`] payload.
pub const MAX_NODE_SUBNET_ROUTE_REPORT_BYTES: usize = 16 * 1024;

/// Maximum encoded size accepted for a [`SubnetRouteConfig`] payload.
pub const MAX_SUBNET_ROUTE_CONFIG_BYTES: usize = 256 * 1024;

/// Domain separator for [`canonical_subnet_route_id`].
const ROUTE_ID_DOMAIN: &[u8] = b"nsio-subnet-route-id-v1\0";

/// Prefix on every [`canonical_subnet_route_id`] output.
const ROUTE_ID_PREFIX: &str = "snr1-";

/// IPv4 ranges that can never carry a routed subnet, with the label reported
/// when one is hit.
///
/// This list is fixed by IANA assignment. Overlay-reserved ranges are **not**
/// here: they are operator configuration and arrive through
/// [`OverlayReservedRanges`].
const FORBIDDEN_RANGES: [(&str, Ipv4Net); 3] = [
    (
        "loopback",
        Ipv4Net::new_assert(Ipv4Addr::new(127, 0, 0, 0), 8),
    ),
    (
        "link-local",
        Ipv4Net::new_assert(Ipv4Addr::new(169, 254, 0, 0), 16),
    ),
    (
        "multicast",
        Ipv4Net::new_assert(Ipv4Addr::new(224, 0, 0, 0), 4),
    ),
];

// ── overlay-reserved ranges ──────────────────────────────────────────────────

/// The control plane's **effective** overlay address space.
///
/// These are NSD's operator-configurable `vip_pool` and `tunnel_ip_pool`
/// (`nsd/crates/nsd-api/src/config.rs`, `Config::parse_vip_pool` /
/// `Config::parse_tunnel_ip_pool`), not constants. A validator pinned to the
/// documented defaults (`100.64.0.0/10`, `10.100.0.0/24`) would accept an
/// advertisement that swallows the overlay's own address space in any
/// deployment that overrides either pool, so the effective ranges are an
/// **input** to validation and are never recomputed or assumed here.
///
/// There is deliberately no `Default` implementation: defaulting would
/// reintroduce exactly the pinning defect described above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayReservedRanges {
    vip_pool: Ipv4Net,
    tunnel_ip_pool: Ipv4Net,
}

impl OverlayReservedRanges {
    /// Build the reserved set from the control plane's effective configuration.
    #[must_use]
    pub const fn new(vip_pool: Ipv4Net, tunnel_ip_pool: Ipv4Net) -> Self {
        Self {
            vip_pool,
            tunnel_ip_pool,
        }
    }

    /// Effective VIP pool this validator was built with.
    #[must_use]
    pub const fn vip_pool(&self) -> Ipv4Net {
        self.vip_pool
    }

    /// Effective gateway tunnel-IP pool this validator was built with.
    #[must_use]
    pub const fn tunnel_ip_pool(&self) -> Ipv4Net {
        self.tunnel_ip_pool
    }

    /// The reserved range `prefix` collides with, if any.
    #[must_use]
    pub fn conflict(&self, prefix: Ipv4Net) -> Option<(&'static str, Ipv4Net)> {
        if prefixes_overlap(prefix, self.vip_pool) {
            return Some(("vip_pool", self.vip_pool));
        }
        if prefixes_overlap(prefix, self.tunnel_ip_pool) {
            return Some(("tunnel_ip_pool", self.tunnel_ip_pool));
        }
        None
    }
}

/// Whether two IPv4 prefixes share at least one address.
#[must_use]
pub fn prefixes_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.network() <= right.broadcast() && right.network() <= left.broadcast()
}

// ── wire enums ───────────────────────────────────────────────────────────────

/// How the route owner forwards traffic for an approved prefix.
///
/// Used both for the mode a node *requests* on a report and the mode NSD
/// *approves* on a projection, so the two can never drift apart.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubnetRouteForwardingMode {
    /// The owner applies source NAT to routed traffic before it reaches the
    /// LAN. This is the default for the first release.
    #[default]
    Snat,
    /// The owner forwards routed traffic with the original source address
    /// preserved.
    NoSnat,
}

/// Scope an approved route was authorized under.
///
/// Only NSD sets this; an advertisement has no scope. NSD projects a route
/// solely to consumers it has entitled, so this value describes the basis of
/// the receiver's own entitlement rather than naming other consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubnetRouteAuthorizationScope {
    /// Approved for every capability-eligible consumer in the route's realm.
    Realm,
    /// Approved for the receiving consumer through an explicit entitlement.
    Consumer,
}

// ── advertisement (intent) ───────────────────────────────────────────────────

/// One prefix a node advertises that it can reach.
///
/// This is intent only. Presence in a report never authorizes traffic, never
/// installs a route, and never makes the reporting node a route authority.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeSubnetRouteAdvertisement {
    /// Stable, deterministic identity for this advertisement. Prefer
    /// [`canonical_subnet_route_id`] so the same realm/owner/prefix triple
    /// always yields the same id.
    pub route_id: String,
    /// Canonical IPv4 network prefix the node offers to route.
    #[serde(with = "serde_ipv4net")]
    pub prefix: Ipv4Net,
    /// Monotonic generation of this advertisement.
    pub generation: u64,
    /// Forwarding mode the node asks NSD to approve. Requested, not granted.
    pub requested_forwarding: SubnetRouteForwardingMode,
}

/// Full-snapshot subnet-route advertisement (node → NSD).
///
/// Replaces the node's previous advertisement set in full: an omitted route is
/// withdrawn.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeSubnetRouteReport {
    /// Monotonic generation of this snapshot.
    pub generation: u64,
    /// Advertised routes, bounded by [`MAX_SUBNET_ROUTES_PER_REPORT`] during
    /// deserialization so an oversized payload is rejected before the vector
    /// can grow without bound.
    #[serde(
        default,
        deserialize_with = "deserialize_report_routes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub routes: Vec<NodeSubnetRouteAdvertisement>,
}

/// NSD's acknowledgement of a [`NodeSubnetRouteReport`].
///
/// Acceptance records an advertisement in NSD's inventory. It is **not**
/// approval: a route only becomes usable when it appears in a
/// [`SubnetRouteConfig`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct NodeSubnetRouteReportAck {
    /// Route ids recorded as advertisements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_route_ids: Vec<String>,
    /// Route ids NSD refused to record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected_route_ids: Vec<String>,
}

// ── approved projection (authority) ──────────────────────────────────────────

/// One NSD-approved subnet route projected to an entitled consumer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ApprovedSubnetRoute {
    /// Stable route identity, matching the owner's advertisement.
    pub route_id: String,
    /// Realm the approval belongs to.
    pub realm_id: String,
    /// Exact machine identity that owns and forwards this prefix.
    pub owner_machine_id: String,
    /// Canonical IPv4 network prefix reachable through the owner.
    #[serde(with = "serde_ipv4net")]
    pub prefix: Ipv4Net,
    /// WireGuard public key of the next hop, i.e. the peer the consumer must
    /// send this prefix's traffic to. Serialized as standard base64; hex and
    /// raw 32-byte strings are also accepted on decode.
    #[serde(
        serialize_with = "serialize_wg_public_key",
        deserialize_with = "deserialize_wg_public_key"
    )]
    pub next_hop_wg_public_key: [u8; 32],
    /// Monotonic generation of the approval that produced this route.
    pub generation: u64,
    /// Forwarding mode NSD approved for the owner.
    pub forwarding: SubnetRouteForwardingMode,
    /// Basis on which the receiving consumer is authorized.
    pub scope: SubnetRouteAuthorizationScope,
}

/// Full-snapshot approved subnet-route projection (NSD → node).
///
/// This is the only shape that authorizes a route. Applying it replaces the
/// consumer's installed route set in full.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct SubnetRouteConfig {
    /// Monotonic authoritative generation of this snapshot.
    pub generation: u64,
    /// Approved routes, bounded by [`MAX_APPROVED_SUBNET_ROUTES`] during
    /// deserialization so an oversized payload is rejected before the vector
    /// can grow without bound.
    #[serde(
        default,
        deserialize_with = "deserialize_approved_routes",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub routes: Vec<ApprovedSubnetRoute>,
}

// ── errors ───────────────────────────────────────────────────────────────────

/// Deterministic rejection reason for a subnet-route report or projection.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SubnetRouteError {
    /// Encoded payload exceeded its limit; rejected before decoding.
    #[error("encoded payload is {size} bytes, limit is {limit}")]
    EncodedTooLarge { size: usize, limit: usize },
    /// Payload could not be decoded.
    #[error("decode failed: {0}")]
    Decode(String),
    /// More routes than the shape's limit.
    #[error("{count} routes exceed the limit of {limit}")]
    TooManyRoutes { count: usize, limit: usize },
    /// An identifier was empty or longer than
    /// [`MAX_SUBNET_ROUTE_IDENTIFIER_BYTES`].
    #[error("{field} identifier must be 1..={limit} bytes, got {len}")]
    Identifier {
        field: &'static str,
        len: usize,
        limit: usize,
    },
    /// The prefix carried host bits, so it is not a canonical network.
    #[error("prefix {prefix} is not canonical; network is {network}")]
    NonCanonicalPrefix { prefix: String, network: String },
    /// A default route cannot be advertised as a subnet route.
    #[error("prefix {prefix} is a default route")]
    DefaultRoute { prefix: String },
    /// The prefix overlapped a range that can never be routed.
    #[error("prefix {prefix} overlaps {label} range {range}")]
    ForbiddenRange {
        prefix: String,
        label: &'static str,
        range: String,
    },
    /// The prefix overlapped the control plane's effective overlay space.
    #[error("prefix {prefix} overlaps overlay-reserved {label} {range}")]
    OverlayReserved {
        prefix: String,
        label: &'static str,
        range: String,
    },
    /// Two routes shared a route id.
    #[error("duplicate route id {route_id}")]
    DuplicateRouteId { route_id: String },
    /// Two routes carried the same prefix under the same owner.
    #[error("duplicate prefix {prefix}")]
    DuplicatePrefix { prefix: String },
    /// The same prefix was claimed by two owners.
    #[error("prefix {prefix} is claimed by both {first_owner} and {second_owner}")]
    ConflictingOwner {
        prefix: String,
        first_owner: String,
        second_owner: String,
    },
    /// Two routes claimed overlapping prefixes.
    #[error("prefix {prefix} overlaps prefix {other} in the same snapshot")]
    OverlappingPrefixes { prefix: String, other: String },
    /// A route's generation ran ahead of its snapshot's generation.
    #[error("route {route_id} generation {route} exceeds snapshot generation {snapshot}")]
    RouteGenerationAhead {
        route_id: String,
        route: u64,
        snapshot: u64,
    },
    /// A projected route belonged to a different realm.
    #[error("route {route_id} belongs to realm {found}, expected {expected}")]
    RealmMismatch {
        route_id: String,
        expected: String,
        found: String,
    },
}

// ── canonical route identity ─────────────────────────────────────────────────

/// Deterministic route id for one realm / owner / prefix triple.
///
/// The same triple always produces the same id on every repository and every
/// run, so an advertisement, an approval, and a projection can be correlated
/// without a shared counter. Inputs are domain-separated and NUL-delimited so
/// no two distinct triples can collide by concatenation.
///
/// The prefix is canonicalized before hashing: `10.0.0.1/24` and `10.0.0.0/24`
/// yield the same id. Validation still rejects the non-canonical spelling on
/// the wire.
#[must_use]
pub fn canonical_subnet_route_id(
    realm_id: &str,
    owner_machine_id: &str,
    prefix: Ipv4Net,
) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(ROUTE_ID_DOMAIN);
    hasher.update(realm_id.as_bytes());
    hasher.update([0]);
    hasher.update(owner_machine_id.as_bytes());
    hasher.update([0]);
    hasher.update(prefix.trunc().to_string().as_bytes());
    let digest = hasher.finalize();
    format!("{ROUTE_ID_PREFIX}{}", hex::encode(&digest[..16]))
}

// ── validation ───────────────────────────────────────────────────────────────

/// Validate one advertised or approved IPv4 prefix.
///
/// `reserved` carries the control plane's effective overlay pools; see
/// [`OverlayReservedRanges`].
///
/// # Errors
///
/// Returns the first failing rule in a fixed order: default route, canonical
/// network, IANA-forbidden range, then overlay-reserved range.
pub fn validate_subnet_prefix(
    prefix: Ipv4Net,
    reserved: &OverlayReservedRanges,
) -> Result<(), SubnetRouteError> {
    if prefix.prefix_len() == 0 {
        return Err(SubnetRouteError::DefaultRoute {
            prefix: prefix.to_string(),
        });
    }
    if prefix.network() != prefix.addr() {
        return Err(SubnetRouteError::NonCanonicalPrefix {
            prefix: prefix.to_string(),
            network: prefix.trunc().to_string(),
        });
    }
    for (label, range) in FORBIDDEN_RANGES {
        if prefixes_overlap(prefix, range) {
            return Err(SubnetRouteError::ForbiddenRange {
                prefix: prefix.to_string(),
                label,
                range: range.to_string(),
            });
        }
    }
    if let Some((label, range)) = reserved.conflict(prefix) {
        return Err(SubnetRouteError::OverlayReserved {
            prefix: prefix.to_string(),
            label,
            range: range.to_string(),
        });
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), SubnetRouteError> {
    let len = value.len();
    if len == 0 || len > MAX_SUBNET_ROUTE_IDENTIFIER_BYTES {
        return Err(SubnetRouteError::Identifier {
            field,
            len,
            limit: MAX_SUBNET_ROUTE_IDENTIFIER_BYTES,
        });
    }
    Ok(())
}

/// One already-validated route, reduced to the fields collision checks need.
struct RouteIdentity<'a> {
    route_id: &'a str,
    prefix: Ipv4Net,
    owner: &'a str,
}

/// Reject duplicate ids, duplicate prefixes, conflicting owners, and
/// overlapping prefixes, in route order so the first violation is stable.
fn check_route_collisions(routes: &[RouteIdentity<'_>]) -> Result<(), SubnetRouteError> {
    for (index, route) in routes.iter().enumerate() {
        for earlier in &routes[..index] {
            if earlier.route_id == route.route_id {
                return Err(SubnetRouteError::DuplicateRouteId {
                    route_id: route.route_id.to_owned(),
                });
            }
            if earlier.prefix == route.prefix {
                if earlier.owner == route.owner {
                    return Err(SubnetRouteError::DuplicatePrefix {
                        prefix: route.prefix.to_string(),
                    });
                }
                return Err(SubnetRouteError::ConflictingOwner {
                    prefix: route.prefix.to_string(),
                    first_owner: earlier.owner.to_owned(),
                    second_owner: route.owner.to_owned(),
                });
            }
            if prefixes_overlap(earlier.prefix, route.prefix) {
                return Err(SubnetRouteError::OverlappingPrefixes {
                    prefix: route.prefix.to_string(),
                    other: earlier.prefix.to_string(),
                });
            }
        }
    }
    Ok(())
}

impl NodeSubnetRouteReport {
    /// Validate bounds, prefixes, identifiers, generations, and collisions.
    ///
    /// `reserved` carries the control plane's effective overlay pools.
    ///
    /// # Errors
    ///
    /// Returns the first failing rule; validation is order-deterministic.
    pub fn validate(&self, reserved: &OverlayReservedRanges) -> Result<(), SubnetRouteError> {
        if self.routes.len() > MAX_SUBNET_ROUTES_PER_REPORT {
            return Err(SubnetRouteError::TooManyRoutes {
                count: self.routes.len(),
                limit: MAX_SUBNET_ROUTES_PER_REPORT,
            });
        }
        for route in &self.routes {
            validate_identifier("route_id", &route.route_id)?;
            validate_subnet_prefix(route.prefix, reserved)?;
            if route.generation > self.generation {
                return Err(SubnetRouteError::RouteGenerationAhead {
                    route_id: route.route_id.clone(),
                    route: route.generation,
                    snapshot: self.generation,
                });
            }
        }
        // One report has exactly one owner, so a repeated prefix is a
        // duplicate rather than an ownership conflict.
        let identities: Vec<_> = self
            .routes
            .iter()
            .map(|route| RouteIdentity {
                route_id: &route.route_id,
                prefix: route.prefix,
                owner: "",
            })
            .collect();
        check_route_collisions(&identities)
    }

    /// Route ids present in `previous` that this snapshot withdraws.
    #[must_use]
    pub fn withdrawn_route_ids<'a>(&self, previous: &'a Self) -> Vec<&'a str> {
        withdrawn_ids(
            previous.routes.iter().map(|route| route.route_id.as_str()),
            self.routes.iter().map(|route| route.route_id.as_str()),
        )
    }

    /// Whether this snapshot is authoritative over `last_applied_generation`.
    #[must_use]
    pub const fn supersedes(&self, last_applied_generation: Option<u64>) -> bool {
        match last_applied_generation {
            None => true,
            Some(applied) => self.generation > applied,
        }
    }
}

impl SubnetRouteConfig {
    /// Validate bounds, realm binding, prefixes, identifiers, generations, and
    /// collisions.
    ///
    /// `expected_realm_id` is the realm the receiving consumer is registered
    /// in; a route from any other realm fails closed. `reserved` carries the
    /// control plane's effective overlay pools.
    ///
    /// # Errors
    ///
    /// Returns the first failing rule; validation is order-deterministic.
    pub fn validate(
        &self,
        expected_realm_id: &str,
        reserved: &OverlayReservedRanges,
    ) -> Result<(), SubnetRouteError> {
        if self.routes.len() > MAX_APPROVED_SUBNET_ROUTES {
            return Err(SubnetRouteError::TooManyRoutes {
                count: self.routes.len(),
                limit: MAX_APPROVED_SUBNET_ROUTES,
            });
        }
        for route in &self.routes {
            validate_identifier("route_id", &route.route_id)?;
            validate_identifier("realm_id", &route.realm_id)?;
            validate_identifier("owner_machine_id", &route.owner_machine_id)?;
            if route.realm_id != expected_realm_id {
                return Err(SubnetRouteError::RealmMismatch {
                    route_id: route.route_id.clone(),
                    expected: expected_realm_id.to_owned(),
                    found: route.realm_id.clone(),
                });
            }
            validate_subnet_prefix(route.prefix, reserved)?;
            if route.generation > self.generation {
                return Err(SubnetRouteError::RouteGenerationAhead {
                    route_id: route.route_id.clone(),
                    route: route.generation,
                    snapshot: self.generation,
                });
            }
        }
        let identities: Vec<_> = self
            .routes
            .iter()
            .map(|route| RouteIdentity {
                route_id: &route.route_id,
                prefix: route.prefix,
                owner: &route.owner_machine_id,
            })
            .collect();
        check_route_collisions(&identities)
    }

    /// Route ids present in `previous` that this snapshot withdraws.
    ///
    /// A route the authority stops projecting is withdrawn; it never survives
    /// on the strength of an earlier snapshot.
    #[must_use]
    pub fn withdrawn_route_ids<'a>(&self, previous: &'a Self) -> Vec<&'a str> {
        withdrawn_ids(
            previous.routes.iter().map(|route| route.route_id.as_str()),
            self.routes.iter().map(|route| route.route_id.as_str()),
        )
    }

    /// Whether this snapshot is authoritative over `last_applied_generation`.
    ///
    /// A snapshot that does not advance the generation is stale and must be
    /// dropped whole rather than merged.
    #[must_use]
    pub const fn supersedes(&self, last_applied_generation: Option<u64>) -> bool {
        match last_applied_generation {
            None => true,
            Some(applied) => self.generation > applied,
        }
    }
}

fn withdrawn_ids<'previous, P, C>(previous: P, current: C) -> Vec<&'previous str>
where
    P: Iterator<Item = &'previous str>,
    C: Iterator<Item: AsRef<str>>,
{
    let retained: Vec<_> = current.collect();
    previous
        .filter(|route_id| !retained.iter().any(|kept| kept.as_ref() == *route_id))
        .collect()
}

// ── size-bounded decoding ────────────────────────────────────────────────────

/// Decode a CBOR [`NodeSubnetRouteReport`], rejecting oversized input first.
///
/// # Errors
///
/// Returns [`SubnetRouteError::EncodedTooLarge`] before any decoding when
/// `bytes` exceeds [`MAX_NODE_SUBNET_ROUTE_REPORT_BYTES`], and
/// [`SubnetRouteError::Decode`] when the payload is malformed or carries more
/// routes than [`MAX_SUBNET_ROUTES_PER_REPORT`].
pub fn decode_node_subnet_route_report(
    bytes: &[u8],
) -> Result<NodeSubnetRouteReport, SubnetRouteError> {
    decode_bounded(bytes, MAX_NODE_SUBNET_ROUTE_REPORT_BYTES)
}

/// Decode a CBOR [`SubnetRouteConfig`], rejecting oversized input first.
///
/// # Errors
///
/// Returns [`SubnetRouteError::EncodedTooLarge`] before any decoding when
/// `bytes` exceeds [`MAX_SUBNET_ROUTE_CONFIG_BYTES`], and
/// [`SubnetRouteError::Decode`] when the payload is malformed or carries more
/// routes than [`MAX_APPROVED_SUBNET_ROUTES`].
pub fn decode_subnet_route_config(bytes: &[u8]) -> Result<SubnetRouteConfig, SubnetRouteError> {
    decode_bounded(bytes, MAX_SUBNET_ROUTE_CONFIG_BYTES)
}

fn decode_bounded<T>(bytes: &[u8], limit: usize) -> Result<T, SubnetRouteError>
where
    T: for<'de> Deserialize<'de>,
{
    if bytes.len() > limit {
        return Err(SubnetRouteError::EncodedTooLarge {
            size: bytes.len(),
            limit,
        });
    }
    crate::api::from_cbor(bytes).map_err(|err| SubnetRouteError::Decode(err.to_string()))
}

// ── serde helpers ────────────────────────────────────────────────────────────

/// Canonical string form for an IPv4 prefix in both JSON and CBOR.
///
/// `ipnet`'s own implementation switches shape on
/// `Serializer::is_human_readable`, which would give this contract two
/// different wire encodings and two different cross-repository fixtures. The
/// string form keeps one.
mod serde_ipv4net {
    use super::{Deserialize, Deserializer, Ipv4Net, Serializer, de};

    pub fn serialize<S>(prefix: &Ipv4Net, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&prefix.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Ipv4Net, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

fn deserialize_report_routes<'de, D>(
    deserializer: D,
) -> Result<Vec<NodeSubnetRouteAdvertisement>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedSeq::new(
        "advertised subnet routes",
        MAX_SUBNET_ROUTES_PER_REPORT,
    ))
}

fn deserialize_approved_routes<'de, D>(
    deserializer: D,
) -> Result<Vec<ApprovedSubnetRoute>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(BoundedSeq::new(
        "approved subnet routes",
        MAX_APPROVED_SUBNET_ROUTES,
    ))
}

/// Sequence visitor that refuses to accumulate past `limit`.
///
/// The element count is checked while the sequence is being read, so a
/// hostile payload cannot drive the vector past the limit before validation
/// runs. `size_hint` is treated as untrusted and only used to pre-allocate up
/// to `limit`.
struct BoundedSeq<T> {
    what: &'static str,
    limit: usize,
    marker: PhantomData<T>,
}

impl<T> BoundedSeq<T> {
    const fn new(what: &'static str, limit: usize) -> Self {
        Self {
            what,
            limit,
            marker: PhantomData,
        }
    }
}

impl<'de, T> de::Visitor<'de> for BoundedSeq<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {} {}", self.limit, self.what)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.limit));
        while let Some(item) = seq.next_element()? {
            if out.len() == self.limit {
                return Err(de::Error::custom(format!(
                    "{} exceed the limit of {}",
                    self.what, self.limit
                )));
            }
            out.push(item);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Documented NSD defaults. Present only so tests can prove the validator
    /// reads its input instead of pinning these values.
    const DEFAULT_VIP_POOL: &str = "100.64.0.0/10";
    const DEFAULT_TUNNEL_IP_POOL: &str = "10.100.0.0/24";

    fn net(cidr: &str) -> Ipv4Net {
        cidr.parse().expect("test CIDR")
    }

    fn default_ranges() -> OverlayReservedRanges {
        OverlayReservedRanges::new(net(DEFAULT_VIP_POOL), net(DEFAULT_TUNNEL_IP_POOL))
    }

    fn advertisement(route_id: &str, cidr: &str) -> NodeSubnetRouteAdvertisement {
        NodeSubnetRouteAdvertisement {
            route_id: route_id.to_owned(),
            prefix: net(cidr),
            generation: 7,
            requested_forwarding: SubnetRouteForwardingMode::Snat,
        }
    }

    fn report(routes: Vec<NodeSubnetRouteAdvertisement>) -> NodeSubnetRouteReport {
        NodeSubnetRouteReport {
            generation: 7,
            routes,
        }
    }

    fn approved(route_id: &str, cidr: &str, owner: &str) -> ApprovedSubnetRoute {
        ApprovedSubnetRoute {
            route_id: route_id.to_owned(),
            realm_id: "realm-a".to_owned(),
            owner_machine_id: owner.to_owned(),
            prefix: net(cidr),
            next_hop_wg_public_key: [3u8; 32],
            generation: 9,
            forwarding: SubnetRouteForwardingMode::Snat,
            scope: SubnetRouteAuthorizationScope::Consumer,
        }
    }

    fn config(routes: Vec<ApprovedSubnetRoute>) -> SubnetRouteConfig {
        SubnetRouteConfig {
            generation: 9,
            routes,
        }
    }

    // ── prefix bounds ────────────────────────────────────────────────────────

    #[test]
    fn canonical_private_prefixes_validate() {
        let ranges = default_ranges();
        // `10.0.0.0/8` is deliberately absent: it swallows the default
        // `tunnel_ip_pool`, which `default_pools_reject_prefixes_inside_them`
        // covers.
        for cidr in [
            "192.168.1.0/24",
            "10.0.0.0/16",
            "172.16.0.0/12",
            "8.8.8.8/32",
        ] {
            validate_subnet_prefix(net(cidr), &ranges).unwrap_or_else(|err| {
                panic!("{cidr} should validate, got {err}");
            });
        }
    }

    #[test]
    fn host_bits_are_rejected_as_non_canonical() {
        let err = validate_subnet_prefix(net("192.168.1.5/24"), &default_ranges()).unwrap_err();
        assert_eq!(
            err,
            SubnetRouteError::NonCanonicalPrefix {
                prefix: "192.168.1.5/24".to_owned(),
                network: "192.168.1.0/24".to_owned(),
            }
        );
    }

    #[test]
    fn default_route_is_rejected() {
        let err = validate_subnet_prefix(net("0.0.0.0/0"), &default_ranges()).unwrap_err();
        assert_eq!(
            err,
            SubnetRouteError::DefaultRoute {
                prefix: "0.0.0.0/0".to_owned(),
            }
        );
    }

    #[test]
    fn loopback_link_local_and_multicast_are_rejected() {
        let ranges = default_ranges();
        for (cidr, label) in [
            ("127.0.0.0/8", "loopback"),
            ("127.0.0.0/24", "loopback"),
            ("169.254.0.0/16", "link-local"),
            ("224.0.0.0/4", "multicast"),
            ("239.255.255.0/24", "multicast"),
        ] {
            let err = validate_subnet_prefix(net(cidr), &ranges).unwrap_err();
            assert!(
                matches!(&err, SubnetRouteError::ForbiddenRange { label: got, .. } if *got == label),
                "{cidr} expected {label}, got {err}"
            );
        }
    }

    #[test]
    fn a_supernet_that_swallows_a_forbidden_range_is_rejected() {
        // 224.0.0.0/3 strictly contains the multicast block; the rule tests
        // overlap, so containment in either direction is a rejection.
        let err = validate_subnet_prefix(net("224.0.0.0/3"), &default_ranges()).unwrap_err();
        assert!(matches!(
            err,
            SubnetRouteError::ForbiddenRange {
                label: "multicast",
                ..
            }
        ));
    }

    // ── overlay-reserved ranges are an input, never a constant ───────────────

    #[test]
    fn default_pools_reject_prefixes_inside_them() {
        let ranges = default_ranges();
        for cidr in ["100.64.0.0/10", "100.80.0.0/12", "10.100.0.0/24"] {
            let err = validate_subnet_prefix(net(cidr), &ranges).unwrap_err();
            assert!(
                matches!(err, SubnetRouteError::OverlayReserved { .. }),
                "{cidr} should be overlay-reserved, got {err}"
            );
        }
    }

    #[test]
    fn an_overridden_vip_pool_is_rejected_where_the_default_would_have_allowed_it() {
        // A deployment that moved `vip_pool` off the documented default. A
        // validator pinned to 100.64.0.0/10 would accept this advertisement and
        // let a node swallow the overlay's own VIP space.
        let overridden =
            OverlayReservedRanges::new(net("10.200.0.0/16"), net(DEFAULT_TUNNEL_IP_POOL));

        assert!(validate_subnet_prefix(net("10.200.5.0/24"), &default_ranges()).is_ok());

        let err = validate_subnet_prefix(net("10.200.5.0/24"), &overridden).unwrap_err();
        assert_eq!(
            err,
            SubnetRouteError::OverlayReserved {
                prefix: "10.200.5.0/24".to_owned(),
                label: "vip_pool",
                range: "10.200.0.0/16".to_owned(),
            }
        );
    }

    #[test]
    fn an_overridden_tunnel_ip_pool_is_rejected_where_the_default_would_have_allowed_it() {
        let overridden = OverlayReservedRanges::new(net(DEFAULT_VIP_POOL), net("172.31.9.0/24"));

        assert!(validate_subnet_prefix(net("172.31.9.0/24"), &default_ranges()).is_ok());

        let err = validate_subnet_prefix(net("172.31.9.0/24"), &overridden).unwrap_err();
        assert_eq!(
            err,
            SubnetRouteError::OverlayReserved {
                prefix: "172.31.9.0/24".to_owned(),
                label: "tunnel_ip_pool",
                range: "172.31.9.0/24".to_owned(),
            }
        );
    }

    #[test]
    fn the_documented_defaults_are_routable_when_the_deployment_moved_its_pools() {
        // The mirror image: nothing in this crate treats 100.64.0.0/10 or
        // 10.100.0.0/24 as inherently reserved.
        let moved = OverlayReservedRanges::new(net("10.200.0.0/16"), net("172.31.9.0/24"));

        validate_subnet_prefix(net("100.64.0.0/10"), &moved).unwrap();
        validate_subnet_prefix(net("10.100.0.0/24"), &moved).unwrap();
    }

    #[test]
    fn a_prefix_that_merely_overlaps_a_pool_edge_is_rejected() {
        let ranges =
            OverlayReservedRanges::new(net("10.200.128.0/17"), net(DEFAULT_TUNNEL_IP_POOL));
        // /16 supernet strictly contains the configured /17 pool.
        let err = validate_subnet_prefix(net("10.200.0.0/16"), &ranges).unwrap_err();
        assert!(matches!(err, SubnetRouteError::OverlayReserved { .. }));
    }

    // ── report validation ────────────────────────────────────────────────────

    #[test]
    fn a_well_formed_report_validates() {
        report(vec![
            advertisement("snr-a", "192.168.1.0/24"),
            advertisement("snr-b", "192.168.2.0/24"),
        ])
        .validate(&default_ranges())
        .unwrap();
    }

    #[test]
    fn an_empty_report_validates_and_withdraws_everything() {
        let previous = report(vec![advertisement("snr-a", "192.168.1.0/24")]);
        let current = NodeSubnetRouteReport {
            generation: 8,
            routes: Vec::new(),
        };

        current.validate(&default_ranges()).unwrap();
        assert_eq!(current.withdrawn_route_ids(&previous), vec!["snr-a"]);
    }

    #[test]
    fn a_report_over_the_route_limit_is_rejected() {
        let routes = (0..=MAX_SUBNET_ROUTES_PER_REPORT)
            .map(|index| advertisement(&format!("snr-{index}"), &format!("10.{index}.0.0/24")))
            .collect();

        let err = report(routes).validate(&default_ranges()).unwrap_err();
        assert_eq!(
            err,
            SubnetRouteError::TooManyRoutes {
                count: MAX_SUBNET_ROUTES_PER_REPORT + 1,
                limit: MAX_SUBNET_ROUTES_PER_REPORT,
            }
        );
    }

    #[test]
    fn a_report_with_a_duplicate_route_id_is_rejected() {
        let err = report(vec![
            advertisement("snr-a", "192.168.1.0/24"),
            advertisement("snr-a", "192.168.2.0/24"),
        ])
        .validate(&default_ranges())
        .unwrap_err();

        assert_eq!(
            err,
            SubnetRouteError::DuplicateRouteId {
                route_id: "snr-a".to_owned(),
            }
        );
    }

    #[test]
    fn a_report_with_a_duplicate_prefix_is_rejected() {
        let err = report(vec![
            advertisement("snr-a", "192.168.1.0/24"),
            advertisement("snr-b", "192.168.1.0/24"),
        ])
        .validate(&default_ranges())
        .unwrap_err();

        assert_eq!(
            err,
            SubnetRouteError::DuplicatePrefix {
                prefix: "192.168.1.0/24".to_owned(),
            }
        );
    }

    #[test]
    fn a_report_with_overlapping_prefixes_is_rejected() {
        let err = report(vec![
            advertisement("snr-a", "192.168.0.0/16"),
            advertisement("snr-b", "192.168.1.0/24"),
        ])
        .validate(&default_ranges())
        .unwrap_err();

        assert_eq!(
            err,
            SubnetRouteError::OverlappingPrefixes {
                prefix: "192.168.1.0/24".to_owned(),
                other: "192.168.0.0/16".to_owned(),
            }
        );
    }

    #[test]
    fn a_route_generation_ahead_of_its_snapshot_is_rejected() {
        let mut snapshot = report(vec![advertisement("snr-a", "192.168.1.0/24")]);
        snapshot.routes[0].generation = snapshot.generation + 1;

        let err = snapshot.validate(&default_ranges()).unwrap_err();
        assert_eq!(
            err,
            SubnetRouteError::RouteGenerationAhead {
                route_id: "snr-a".to_owned(),
                route: 8,
                snapshot: 7,
            }
        );
    }

    #[test]
    fn empty_and_oversized_identifiers_are_rejected() {
        let ranges = default_ranges();

        let mut empty = report(vec![advertisement("", "192.168.1.0/24")]);
        assert_eq!(
            empty.validate(&ranges).unwrap_err(),
            SubnetRouteError::Identifier {
                field: "route_id",
                len: 0,
                limit: MAX_SUBNET_ROUTE_IDENTIFIER_BYTES,
            }
        );

        empty.routes[0].route_id = "x".repeat(MAX_SUBNET_ROUTE_IDENTIFIER_BYTES + 1);
        assert_eq!(
            empty.validate(&ranges).unwrap_err(),
            SubnetRouteError::Identifier {
                field: "route_id",
                len: MAX_SUBNET_ROUTE_IDENTIFIER_BYTES + 1,
                limit: MAX_SUBNET_ROUTE_IDENTIFIER_BYTES,
            }
        );

        empty.routes[0].route_id = "x".repeat(MAX_SUBNET_ROUTE_IDENTIFIER_BYTES);
        empty.validate(&ranges).unwrap();
    }

    // ── projection validation ────────────────────────────────────────────────

    #[test]
    fn a_well_formed_projection_validates() {
        config(vec![
            approved("snr-a", "192.168.1.0/24", "machine-a"),
            approved("snr-b", "10.7.0.0/16", "machine-b"),
        ])
        .validate("realm-a", &default_ranges())
        .unwrap();
    }

    #[test]
    fn a_projection_over_the_route_limit_is_rejected() {
        let routes = (0..=MAX_APPROVED_SUBNET_ROUTES)
            .map(|index| {
                approved(
                    &format!("snr-{index}"),
                    &format!("10.{}.{}.0/24", index / 256, index % 256),
                    "machine-a",
                )
            })
            .collect();

        let err = config(routes)
            .validate("realm-a", &default_ranges())
            .unwrap_err();
        assert_eq!(
            err,
            SubnetRouteError::TooManyRoutes {
                count: MAX_APPROVED_SUBNET_ROUTES + 1,
                limit: MAX_APPROVED_SUBNET_ROUTES,
            }
        );
    }

    #[test]
    fn a_projection_from_another_realm_fails_closed() {
        let err = config(vec![approved("snr-a", "192.168.1.0/24", "machine-a")])
            .validate("realm-b", &default_ranges())
            .unwrap_err();

        assert_eq!(
            err,
            SubnetRouteError::RealmMismatch {
                route_id: "snr-a".to_owned(),
                expected: "realm-b".to_owned(),
                found: "realm-a".to_owned(),
            }
        );
    }

    #[test]
    fn the_same_prefix_under_two_owners_is_an_ownership_conflict() {
        let err = config(vec![
            approved("snr-a", "192.168.1.0/24", "machine-a"),
            approved("snr-b", "192.168.1.0/24", "machine-b"),
        ])
        .validate("realm-a", &default_ranges())
        .unwrap_err();

        assert_eq!(
            err,
            SubnetRouteError::ConflictingOwner {
                prefix: "192.168.1.0/24".to_owned(),
                first_owner: "machine-a".to_owned(),
                second_owner: "machine-b".to_owned(),
            }
        );
    }

    #[test]
    fn the_same_prefix_under_one_owner_is_a_duplicate() {
        let err = config(vec![
            approved("snr-a", "192.168.1.0/24", "machine-a"),
            approved("snr-b", "192.168.1.0/24", "machine-a"),
        ])
        .validate("realm-a", &default_ranges())
        .unwrap_err();

        assert_eq!(
            err,
            SubnetRouteError::DuplicatePrefix {
                prefix: "192.168.1.0/24".to_owned(),
            }
        );
    }

    #[test]
    fn overlapping_prefixes_across_owners_are_rejected() {
        let err = config(vec![
            approved("snr-a", "192.168.0.0/16", "machine-a"),
            approved("snr-b", "192.168.4.0/24", "machine-b"),
        ])
        .validate("realm-a", &default_ranges())
        .unwrap_err();

        assert_eq!(
            err,
            SubnetRouteError::OverlappingPrefixes {
                prefix: "192.168.4.0/24".to_owned(),
                other: "192.168.0.0/16".to_owned(),
            }
        );
    }

    #[test]
    fn validation_reports_the_first_violation_in_route_order() {
        // Two independent violations; the earlier route's must be returned so
        // two peers reach the same verdict for the same bytes.
        let err = config(vec![
            approved("snr-a", "127.0.0.0/8", "machine-a"),
            approved("snr-b", "0.0.0.0/0", "machine-b"),
        ])
        .validate("realm-a", &default_ranges())
        .unwrap_err();

        assert!(matches!(
            err,
            SubnetRouteError::ForbiddenRange {
                label: "loopback",
                ..
            }
        ));
    }

    // ── snapshot and withdrawal semantics ────────────────────────────────────

    #[test]
    fn a_snapshot_supersedes_only_a_strictly_older_generation() {
        let snapshot = config(Vec::new());
        assert!(snapshot.supersedes(None));
        assert!(snapshot.supersedes(Some(8)));
        assert!(!snapshot.supersedes(Some(9)));
        assert!(!snapshot.supersedes(Some(10)));
    }

    #[test]
    fn an_omitted_route_is_withdrawn_by_a_newer_snapshot() {
        let previous = config(vec![
            approved("snr-a", "192.168.1.0/24", "machine-a"),
            approved("snr-b", "10.7.0.0/16", "machine-b"),
        ]);
        let current = SubnetRouteConfig {
            generation: 10,
            routes: vec![approved("snr-b", "10.7.0.0/16", "machine-b")],
        };

        assert!(current.supersedes(Some(previous.generation)));
        assert_eq!(current.withdrawn_route_ids(&previous), vec!["snr-a"]);
    }

    #[test]
    fn an_empty_newer_snapshot_withdraws_every_route() {
        let previous = config(vec![
            approved("snr-a", "192.168.1.0/24", "machine-a"),
            approved("snr-b", "10.7.0.0/16", "machine-b"),
        ]);
        let current = SubnetRouteConfig {
            generation: 10,
            routes: Vec::new(),
        };

        assert_eq!(
            current.withdrawn_route_ids(&previous),
            vec!["snr-a", "snr-b"]
        );
    }

    // ── canonical route identity ─────────────────────────────────────────────

    #[test]
    fn canonical_route_ids_are_deterministic_and_bounded() {
        let id = canonical_subnet_route_id("realm-a", "machine-a", net("192.168.1.0/24"));

        assert_eq!(
            id,
            canonical_subnet_route_id("realm-a", "machine-a", net("192.168.1.0/24"))
        );
        assert!(id.starts_with(ROUTE_ID_PREFIX));
        assert_eq!(id.len(), ROUTE_ID_PREFIX.len() + 32);
        assert!(id.len() <= MAX_SUBNET_ROUTE_IDENTIFIER_BYTES);
    }

    #[test]
    fn canonical_route_ids_normalize_host_bits() {
        assert_eq!(
            canonical_subnet_route_id("realm-a", "machine-a", net("192.168.1.9/24")),
            canonical_subnet_route_id("realm-a", "machine-a", net("192.168.1.0/24"))
        );
    }

    #[test]
    fn canonical_route_ids_separate_their_inputs() {
        // Without NUL separation, ("ab", "c") and ("a", "bc") would collide.
        assert_ne!(
            canonical_subnet_route_id("ab", "c", net("192.168.1.0/24")),
            canonical_subnet_route_id("a", "bc", net("192.168.1.0/24"))
        );
        assert_ne!(
            canonical_subnet_route_id("realm-a", "machine-a", net("192.168.1.0/24")),
            canonical_subnet_route_id("realm-a", "machine-b", net("192.168.1.0/24"))
        );
        assert_ne!(
            canonical_subnet_route_id("realm-a", "machine-a", net("192.168.1.0/24")),
            canonical_subnet_route_id("realm-a", "machine-a", net("192.168.1.0/25"))
        );
    }

    // ── bounded decoding ─────────────────────────────────────────────────────

    #[test]
    fn a_report_body_over_the_size_limit_is_rejected_before_decoding() {
        // Not valid CBOR: if the size gate did not run first, the decoder would
        // have produced a `Decode` error instead.
        let oversized = vec![0xffu8; MAX_NODE_SUBNET_ROUTE_REPORT_BYTES + 1];

        assert_eq!(
            decode_node_subnet_route_report(&oversized).unwrap_err(),
            SubnetRouteError::EncodedTooLarge {
                size: MAX_NODE_SUBNET_ROUTE_REPORT_BYTES + 1,
                limit: MAX_NODE_SUBNET_ROUTE_REPORT_BYTES,
            }
        );
    }

    #[test]
    fn a_config_body_over_the_size_limit_is_rejected_before_decoding() {
        let oversized = vec![0xffu8; MAX_SUBNET_ROUTE_CONFIG_BYTES + 1];

        assert_eq!(
            decode_subnet_route_config(&oversized).unwrap_err(),
            SubnetRouteError::EncodedTooLarge {
                size: MAX_SUBNET_ROUTE_CONFIG_BYTES + 1,
                limit: MAX_SUBNET_ROUTE_CONFIG_BYTES,
            }
        );
    }

    #[test]
    fn a_report_carrying_more_routes_than_the_limit_fails_during_decoding() {
        let routes: Vec<_> = (0..=MAX_SUBNET_ROUTES_PER_REPORT)
            .map(|index| advertisement(&format!("snr-{index}"), &format!("10.{index}.0.0/24")))
            .collect();
        let json = serde_json::to_string(&report(routes)).unwrap();

        let err = serde_json::from_str::<NodeSubnetRouteReport>(&json).unwrap_err();
        assert!(
            err.to_string().contains("advertised subnet routes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_config_carrying_more_routes_than_the_limit_fails_during_decoding() {
        let routes: Vec<_> = (0..=MAX_APPROVED_SUBNET_ROUTES)
            .map(|index| {
                approved(
                    &format!("snr-{index}"),
                    &format!("10.{}.{}.0/24", index / 256, index % 256),
                    "machine-a",
                )
            })
            .collect();
        let cbor = crate::api::to_cbor(&config(routes)).unwrap();

        let err = decode_subnet_route_config(&cbor).unwrap_err();
        assert!(
            matches!(&err, SubnetRouteError::Decode(message)
                if message.contains("approved subnet routes")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_report_at_exactly_the_route_limit_decodes() {
        let routes: Vec<_> = (0..MAX_SUBNET_ROUTES_PER_REPORT)
            .map(|index| advertisement(&format!("snr-{index}"), &format!("10.{index}.0.0/24")))
            .collect();
        let cbor = crate::api::to_cbor(&report(routes)).unwrap();

        let decoded = decode_node_subnet_route_report(&cbor).unwrap();
        assert_eq!(decoded.routes.len(), MAX_SUBNET_ROUTES_PER_REPORT);
        decoded.validate(&default_ranges()).unwrap();
    }

    // ── wire shape ───────────────────────────────────────────────────────────

    #[test]
    fn a_report_round_trips_through_json_and_cbor() {
        let original = report(vec![advertisement("snr-a", "192.168.1.0/24")]);

        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(
            serde_json::from_str::<NodeSubnetRouteReport>(&json).unwrap(),
            original
        );

        let cbor = crate::api::to_cbor(&original).unwrap();
        assert_eq!(decode_node_subnet_route_report(&cbor).unwrap(), original);
    }

    #[test]
    fn a_config_round_trips_through_json_and_cbor() {
        let original = config(vec![approved("snr-a", "192.168.1.0/24", "machine-a")]);

        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(
            serde_json::from_str::<SubnetRouteConfig>(&json).unwrap(),
            original
        );

        let cbor = crate::api::to_cbor(&original).unwrap();
        assert_eq!(decode_subnet_route_config(&cbor).unwrap(), original);
    }

    #[test]
    fn prefixes_use_the_same_string_form_in_json_and_cbor() {
        let original = report(vec![advertisement("snr-a", "192.168.1.0/24")]);

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains(r#""prefix":"192.168.1.0/24""#), "{json}");

        // `ipnet`'s own impl switches to a tuple when the format is not
        // human-readable; the contract must not.
        let cbor = crate::api::to_cbor(&original).unwrap();
        let as_value: ciborium::Value = ciborium::de::from_reader(cbor.as_slice()).unwrap();
        let encoded = format!("{as_value:?}");
        assert!(encoded.contains("192.168.1.0/24"), "{encoded}");
    }

    #[test]
    fn a_non_canonical_prefix_still_decodes_and_is_caught_by_validation() {
        // Decoding stays permissive so the rejection is one deterministic
        // validation error rather than an opaque parse failure.
        let json = r#"{"generation":7,"routes":[{"route_id":"snr-a",
            "prefix":"192.168.1.9/24","generation":7,
            "requested_forwarding":"snat"}]}"#;

        let decoded: NodeSubnetRouteReport = serde_json::from_str(json).unwrap();
        assert!(matches!(
            decoded.validate(&default_ranges()).unwrap_err(),
            SubnetRouteError::NonCanonicalPrefix { .. }
        ));
    }

    #[test]
    fn a_malformed_prefix_is_rejected_at_decode_time() {
        let json = r#"{"generation":7,"routes":[{"route_id":"snr-a",
            "prefix":"not-a-cidr","generation":7,
            "requested_forwarding":"snat"}]}"#;

        assert!(serde_json::from_str::<NodeSubnetRouteReport>(json).is_err());
    }

    #[test]
    fn an_ipv6_prefix_is_rejected_at_decode_time() {
        let json = r#"{"generation":7,"routes":[{"route_id":"snr-a",
            "prefix":"2001:db8::/32","generation":7,
            "requested_forwarding":"snat"}]}"#;

        assert!(serde_json::from_str::<NodeSubnetRouteReport>(json).is_err());
    }

    #[test]
    fn forwarding_and_scope_tokens_are_pinned() {
        let json =
            serde_json::to_string(&approved("snr-a", "192.168.1.0/24", "machine-a")).unwrap();
        assert!(json.contains(r#""forwarding":"snat""#), "{json}");
        assert!(json.contains(r#""scope":"consumer""#), "{json}");

        let no_snat = serde_json::to_string(&SubnetRouteForwardingMode::NoSnat).unwrap();
        assert_eq!(no_snat, r#""no_snat""#);
        let realm = serde_json::to_string(&SubnetRouteAuthorizationScope::Realm).unwrap();
        assert_eq!(realm, r#""realm""#);
    }

    #[test]
    fn the_next_hop_key_is_required_and_fixed_width() {
        let mut json: serde_json::Value =
            serde_json::to_value(approved("snr-a", "192.168.1.0/24", "machine-a")).unwrap();

        json["next_hop_wg_public_key"] = serde_json::Value::String("AAAA".to_owned());
        assert!(serde_json::from_value::<ApprovedSubnetRoute>(json.clone()).is_err());

        json.as_object_mut()
            .unwrap()
            .remove("next_hop_wg_public_key");
        assert!(serde_json::from_value::<ApprovedSubnetRoute>(json).is_err());
    }

    #[test]
    fn default_forwarding_is_snat() {
        assert_eq!(
            SubnetRouteForwardingMode::default(),
            SubnetRouteForwardingMode::Snat
        );
    }
}
