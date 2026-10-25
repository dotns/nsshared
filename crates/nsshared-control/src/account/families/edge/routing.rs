//! Complete public discovery and routing facts without forwarding runtime.

use crate::{
    account::AccountError, account::MAX_BYTES, account::codec::ascending,
    account::codec::ascending_by, account::codec::bounded, account::codec::hostname,
    account::codec::identity, account::codec::read_optional_text,
    account::codec::read_optional_uint, account::codec::read_reference, account::codec::read_texts,
    account::codec::reader, account::codec::realm, account::codec::require, account::codec::token,
    account::codec::write_optional_text, account::codec::write_optional_uint,
    account::codec::write_reference, account::codec::write_texts, account::edge::EdgeAuth,
    account::edge::EdgeMaterialAck, account::edge::EdgeMaterialKind,
    account::edge::EdgeMaterialRef, account::edge::MAX_EDGE_ITEMS,
    account::edge::material::materials_valid, account::edge::material::read_materials,
    account::limits::MAX_HOSTNAME_BYTES, account::limits::MAX_TEXT_BYTES,
    account::publication::PublicationContent, account::publication::PublicationOutcome,
    account::realm::SignedSubjectHeaderPolicy, account::realm::SubjectPolicy, service::ServiceRef,
    service::Snapshot,
};
use nsshared_identity::realm::RealmId;

use std::collections::{BTreeMap, BTreeSet};

use nsshared_codec::cbor::CborWriter;
use nsshared_identity::keys::IdentityKey;

/// Public listener protocol; HTTP uses TCP for backend port conflict checks.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u64)]
pub enum EdgeProtocol {
    /// HTTP reverse proxy.
    Http = 0,
    /// Raw TCP listener.
    Tcp = 6,
    /// Raw UDP listener.
    Udp = 17,
}

/// One protocol-qualified route and its explicit Node destination, if available.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeRoute {
    /// Stable contribution-local route id.
    pub id: String,
    /// HTTP public hostname; raw TCP/UDP routes have no name.
    pub name: Option<String>,
    /// Ordered public aliases.
    pub aliases: Vec<String>,
    /// Ordered public domains.
    pub domains: Vec<String>,
    /// Existing full M6 service identity.
    pub service: ServiceRef,
    /// None means no connector; forwarding remains unavailable without fallback.
    pub backend: Option<IdentityKey>,
    /// Explicit public protocol.
    pub protocol: EdgeProtocol,
    /// Public listener port.
    pub public_port: u16,
    /// Published Node service port, not its private backend port.
    pub virtual_port: u16,
    /// Existing realm-qualified subject policy, with no evaluation here.
    pub policy: SubjectPolicy,
    /// Existing signed subject header configuration.
    pub headers: SignedSubjectHeaderPolicy,
    /// Exact auth/certificate/client-CA generations required before exposure.
    pub dependencies: Vec<EdgeMaterialRef>,
    /// Transport, upstream and policy configuration, with no evaluation.
    pub options: EdgeRouteOptions,
}

/// One realm's full routing and auth contribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeRealm {
    /// Binary policy realm identity.
    pub realm: RealmId,
    /// Complete material references and public auth bindings.
    pub auth: EdgeAuth,
    /// Complete routes, strictly ordered by id.
    pub routes: Vec<EdgeRoute>,
}

/// Family 7 complete replacement under an exact signed publication scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicEdge {
    /// Exact signed served realm.
    pub served_realm: RealmId,
    /// Exact signed opaque scope.
    pub scope: String,
    /// Complete contributions, strictly ordered by realm; empty withdraws.
    pub realms: Vec<EdgeRealm>,
}

impl PublicEdge {
    /// Encodes complete validated content without sorting, applying or installing it.
    ///
    /// # Errors
    /// Rejects malformed scopes, duplicates, port conflicts, invalid joins or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        token(&self.scope)?;
        require(
            self.realms.len() <= MAX_EDGE_ITEMS && ascending_by(&self.realms, |value| &value.realm),
        )?;
        let mut out = CborWriter::default();
        out.array(5)
            .uint(1)
            .uint(7)
            .text(&self.served_realm.to_string())
            .text(&self.scope)
            .array(self.realms.len());
        let mut http_ports = BTreeSet::new();
        let mut tcp_ports = BTreeSet::new();
        let mut listeners = BTreeSet::new();
        let mut backend_ports = BTreeSet::new();
        for realm in &self.realms {
            require(realm.realm == realm.auth.realm && realm.routes.len() <= MAX_EDGE_ITEMS)?;
            require(ascending_by(&realm.routes, |value| &value.id))?;
            out.array(3)
                .bytes(realm.realm.as_bytes())
                .bytes(&realm.auth.canonical()?)
                .array(realm.routes.len());
            let mut public_names = BTreeSet::new();
            let mut hostname_owners = BTreeMap::new();
            for route in &realm.routes {
                token(&route.id)?;
                if route.protocol == EdgeProtocol::Http {
                    let name = route.name.as_ref().ok_or(AccountError::Field)?;
                    hostname(name)?;
                    require(public_names.insert(name))?;
                    for alias in &route.aliases {
                        require(public_names.insert(alias))?;
                    }
                    for name in std::iter::once(name)
                        .chain(&route.aliases)
                        .chain(&route.domains)
                    {
                        require(
                            hostname_owners
                                .insert(name, &route.id)
                                .is_none_or(|owner| owner == &route.id),
                        )?;
                    }
                } else {
                    require(
                        route.name.is_none()
                            && route.aliases.is_empty()
                            && route.domains.is_empty(),
                    )?;
                }
                match route.protocol {
                    EdgeProtocol::Http => {
                        require(!tcp_ports.contains(&route.public_port))?;
                        http_ports.insert(route.public_port);
                    }
                    EdgeProtocol::Tcp => {
                        require(!http_ports.contains(&route.public_port))?;
                        tcp_ports.insert(route.public_port);
                    }
                    EdgeProtocol::Udp => {}
                }
                require(
                    route.public_port > 0
                        && route.virtual_port > 0
                        && route.policy.realm == realm.realm,
                )?;
                if route.protocol == EdgeProtocol::Http {
                    let hosts: BTreeSet<_> = route
                        .name
                        .iter()
                        .chain(&route.aliases)
                        .chain(&route.domains)
                        .collect();
                    for host in hosts {
                        require(listeners.insert((
                            route.protocol,
                            route.public_port,
                            host.as_str(),
                        )))?;
                    }
                } else {
                    require(listeners.insert((route.protocol, route.public_port, "")))?;
                }
                if let Some(backend) = route.backend {
                    let protocol = if route.protocol == EdgeProtocol::Udp {
                        17
                    } else {
                        6
                    };
                    require(backend_ports.insert((backend, protocol, route.virtual_port)))?;
                }
                materials_valid(&route.dependencies)?;
                require(
                    route
                        .dependencies
                        .iter()
                        .all(|v| realm.auth.materials.contains(v)),
                )?;
                if route.headers.enabled {
                    require(route.dependencies.iter().any(|v| {
                        v.kind == EdgeMaterialKind::Auth
                            && Some(&v.reference) == route.headers.keyset_ref.as_ref()
                    }))?;
                }
                out.array(13).text(&route.id);
                if let Some(name) = &route.name {
                    out.text(name);
                } else {
                    out.null();
                }
                write_texts(&mut out, &route.aliases, hostname)?;
                write_texts(&mut out, &route.domains, hostname)?;
                write_reference(&mut out, &route.service)?;
                if let Some(backend) = route.backend {
                    out.bytes(backend.as_bytes());
                } else {
                    out.null();
                }
                out.uint(route.protocol as u64)
                    .uint(u64::from(route.public_port))
                    .uint(u64::from(route.virtual_port));
                out.bytes(&route.policy.canonical()?)
                    .bytes(&route.headers.canonical()?)
                    .array(route.dependencies.len());
                for value in &route.dependencies {
                    value.write(&mut out)?;
                }
                route.options.write(&mut out)?;
            }
        }
        bounded(out.into_bytes())
    }

    /// Decodes an exact bounded complete contribution set.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical CBOR, invalid identities, joins and conflicts.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 5)?;
        require(input.uint()? == 7)?;
        let served_realm = realm(&mut input)?;
        let scope = input.text_up_to(MAX_TEXT_BYTES)?.to_owned();
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let mut realms = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(3)?;
            let realm = RealmId::from_bytes(input.fixed_bytes()?);
            let auth = EdgeAuth::decode(input.bytes_up_to(MAX_BYTES)?)?;
            let count = input.array_up_to(MAX_EDGE_ITEMS)?;
            let mut routes = Vec::with_capacity(count);
            for _ in 0..count {
                input.array(13)?;
                let id = input.text_up_to(MAX_TEXT_BYTES)?.to_owned();
                let name = if input.take_null() {
                    None
                } else {
                    Some(input.text_up_to(MAX_HOSTNAME_BYTES)?.to_owned())
                };
                let aliases = read_texts(&mut input, MAX_HOSTNAME_BYTES)?;
                let domains = read_texts(&mut input, MAX_HOSTNAME_BYTES)?;
                let service = read_reference(&mut input)?;
                let backend = if input.take_null() {
                    None
                } else {
                    Some(identity(&mut input)?)
                };
                let protocol = match input.uint()? {
                    0 => EdgeProtocol::Http,
                    6 => EdgeProtocol::Tcp,
                    17 => EdgeProtocol::Udp,
                    _ => return Err(AccountError::Field),
                };
                let public_port = u16::try_from(input.uint()?).map_err(|_| AccountError::Field)?;
                let virtual_port = u16::try_from(input.uint()?).map_err(|_| AccountError::Field)?;
                let policy = SubjectPolicy::decode(input.bytes_up_to(MAX_BYTES)?)?;
                let headers = SignedSubjectHeaderPolicy::decode(input.bytes_up_to(MAX_BYTES)?)?;
                let dependencies = read_materials(&mut input)?;
                let options = EdgeRouteOptions::read(&mut input)?;
                routes.push(EdgeRoute {
                    id,
                    name,
                    aliases,
                    domains,
                    service,
                    backend,
                    protocol,
                    public_port,
                    virtual_port,
                    policy,
                    headers,
                    dependencies,
                    options,
                });
            }
            realms.push(EdgeRealm {
                realm,
                auth,
                routes,
            });
        }
        input.finish()?;
        let value = Self {
            served_realm,
            scope,
            realms,
        };
        value.canonical()?;
        Ok(value)
    }

    /// Joins decoded content to the existing authenticated publication carrier.
    ///
    /// # Errors
    /// Rejects kind, scope, channel, outcome, completeness or payload mismatch.
    pub fn validate_publication(
        &self,
        content: &PublicationContent<'_>,
    ) -> Result<(), AccountError> {
        require(
            content.key.family == 7
                && content.key.kind == "public-edge"
                && content.key.served_realm == self.served_realm
                && content.key.scope == self.scope
                && content.channel == crate::account::publication::PublicationChannel::Stream
                && content.complete
                && content.outcome == PublicationOutcome::Data,
        )?;
        require(self.canonical()? == content.payload)
    }

    /// Joins Node backends to a caller-authenticated M6 recipient snapshot.
    ///
    /// # Errors
    /// Rejects invalid snapshots, recipient, publisher, scope, port or protocol.
    pub fn validate_snapshot(
        &self,
        recipient: IdentityKey,
        snapshot: &Snapshot,
    ) -> Result<(), AccountError> {
        self.validate_snapshots(recipient, std::slice::from_ref(snapshot))
    }

    /// Joins all Node backends to a complete set of authenticated M6 snapshots.
    ///
    /// # Errors
    /// Rejects missing or duplicate scopes, wrong recipients, publishers or ports.
    pub fn validate_snapshots(
        &self,
        recipient: IdentityKey,
        snapshots: &[Snapshot],
    ) -> Result<(), AccountError> {
        self.canonical()?;
        require(snapshots.len() <= MAX_EDGE_ITEMS * MAX_EDGE_ITEMS)?;
        let mut scopes = BTreeSet::new();
        for snapshot in snapshots {
            snapshot.canonical().map_err(|_| AccountError::Field)?;
            require(
                snapshot.target_identity == *recipient.as_bytes()
                    && scopes.insert((snapshot.nsd_id, snapshot.network_id)),
            )?;
        }
        for realm in &self.realms {
            for route in &realm.routes {
                if let Some(backend) = route.backend {
                    let snapshot = snapshots
                        .iter()
                        .find(|v| {
                            v.nsd_id == route.service.nsd_id
                                && v.network_id == route.service.network_id
                        })
                        .ok_or(AccountError::Authority)?;
                    let resource = snapshot
                        .resources
                        .iter()
                        .find(|v| v.service_ref == route.service)
                        .ok_or(AccountError::Authority)?;
                    require(
                        resource.publisher_identity == *backend.as_bytes()
                            && resource.node6
                                == nsshared_identity::identity::AddressGroup::derive(
                                    backend.as_bytes(),
                                )
                                .n6_bytes()
                            && resource.port == route.virtual_port
                            && route.service.nsd_id == snapshot.nsd_id
                            && route.service.network_id == snapshot.network_id,
                    )?;
                    require(if route.protocol == EdgeProtocol::Udp {
                        resource.protocols.udp
                    } else {
                        resource.protocols.tcp
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Checks all supplied route dependencies against correlated installation ACKs.
    ///
    /// # Errors
    /// Rejects missing/rejected ACKs, wrong scope, request id or generation.
    pub fn validate_materials(
        &self,
        request_id: [u8; 16],
        acknowledgements: &[EdgeMaterialAck],
    ) -> Result<(), AccountError> {
        self.canonical()?;
        require(acknowledgements.len() <= MAX_EDGE_ITEMS * MAX_EDGE_ITEMS)?;
        for realm in &self.realms {
            for route in &realm.routes {
                for material in &route.dependencies {
                    require(acknowledgements.iter().any(|ack| {
                        ack.validate_installation(
                            request_id,
                            self.served_realm,
                            &self.scope,
                            realm.realm,
                            material,
                        )
                        .is_ok()
                    }))?;
                }
            }
        }
        Ok(())
    }
}

/// Explicit client-to-Node carrier selection policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum EdgeTransport {
    /// Require WireGuard.
    WireGuard = 0,
    /// Require WebSocket transport.
    WebSocket = 1,
    /// Prefer WireGuard according to the consumer's qualified carrier support.
    PreferWireGuard = 2,
    /// Prefer WebSocket according to the consumer's qualified carrier support.
    PreferWebSocket = 3,
}

/// Reencrypted upstream TLS and its explicit validation choice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeUpstreamTls {
    /// Canonical DNS SNI.
    pub sni: String,
    /// Explicitly permitted untrusted certificates; never inferred from absence.
    pub accept_untrusted: bool,
}

/// Input source network admission configuration; enforcement stays external.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeSourceIp {
    /// Canonical network CIDRs in strict string order.
    pub allow_cidrs: Vec<String>,
    /// Canonical network CIDRs in strict string order.
    pub deny_cidrs: Vec<String>,
    /// Explicit failure behavior.
    pub fail_closed: bool,
}

/// Retained public route configuration with an explicit bounded field set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeRouteOptions {
    /// Client carrier policy.
    pub transport: EdgeTransport,
    /// Optional upstream Host authority.
    pub upstream_authority: Option<String>,
    /// Optional upstream reencryption.
    pub upstream_tls: Option<EdgeUpstreamTls>,
    /// Optional middleware chain reference.
    pub chain_ref: Option<String>,
    /// Optional WAF policy reference.
    pub waf_ref: Option<String>,
    /// Optional external authorization reference.
    pub ext_authz_ref: Option<String>,
    /// Optional rate limit reference.
    pub rate_limit_ref: Option<String>,
    /// Optional connection limit reference.
    pub connection_limit_ref: Option<String>,
    /// Optional slow client policy reference.
    pub slow_client_ref: Option<String>,
    /// Optional L4 session limit reference.
    pub session_limit_ref: Option<String>,
    /// Optional request rewrite reference.
    pub request_rewrite_ref: Option<String>,
    /// Optional response header policy reference.
    pub response_header_ref: Option<String>,
    /// Optional forwarded subject policy reference.
    pub forwarded_subject_ref: Option<String>,
    /// Optional audit policy reference.
    pub audit_ref: Option<String>,
    /// Optional positive request body byte ceiling.
    pub request_body_bytes: Option<u64>,
    /// Optional positive response body byte ceiling.
    pub response_body_bytes: Option<u64>,
    /// Optional source IP policy.
    pub source_ip: Option<EdgeSourceIp>,
    /// Strictly ordered unique metadata keys and bounded token values.
    pub audit_metadata: Vec<(String, String)>,
}

fn write_limit(value: Option<u64>, out: &mut CborWriter) -> Result<(), AccountError> {
    require(value != Some(0))?;
    write_optional_uint(out, value);
    Ok(())
}

fn cidrs(values: &[String], out: &mut CborWriter) -> Result<(), AccountError> {
    use std::net::IpAddr;
    require(values.len() <= MAX_EDGE_ITEMS && ascending(values))?;
    out.array(values.len());
    for value in values {
        let (address, prefix) = value.split_once('/').ok_or(AccountError::Field)?;
        let address: IpAddr = address.parse().map_err(|_| AccountError::Field)?;
        let prefix: u32 = prefix.parse().map_err(|_| AccountError::Field)?;
        require(format!("{address}/{prefix}") == *value)?;
        let network = match address {
            IpAddr::V4(address) => {
                prefix <= 32
                    && (prefix == 32 || u32::from(address).checked_shl(prefix).unwrap_or(0) == 0)
            }
            IpAddr::V6(address) => {
                prefix <= 128
                    && (prefix == 128 || u128::from(address).checked_shl(prefix).unwrap_or(0) == 0)
            }
        };
        require(network)?;
        out.text(value);
    }
    Ok(())
}

impl EdgeRouteOptions {
    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(8).uint(self.transport as u64);
        if let Some(authority) = &self.upstream_authority {
            hostname(authority)?;
        }
        write_optional_text(out, self.upstream_authority.as_deref(), token)?;
        if let Some(tls) = &self.upstream_tls {
            hostname(&tls.sni)?;
            out.array(2).text(&tls.sni).boolean(tls.accept_untrusted);
        } else {
            out.null();
        }
        out.array(11);
        for value in [
            &self.chain_ref,
            &self.waf_ref,
            &self.ext_authz_ref,
            &self.rate_limit_ref,
            &self.connection_limit_ref,
            &self.slow_client_ref,
            &self.session_limit_ref,
            &self.request_rewrite_ref,
            &self.response_header_ref,
            &self.forwarded_subject_ref,
            &self.audit_ref,
        ] {
            write_optional_text(out, value.as_deref(), token)?;
        }
        write_limit(self.request_body_bytes, out)?;
        write_limit(self.response_body_bytes, out)?;
        if let Some(source) = &self.source_ip {
            out.array(3);
            cidrs(&source.allow_cidrs, out)?;
            cidrs(&source.deny_cidrs, out)?;
            out.boolean(source.fail_closed);
        } else {
            out.null();
        }
        require(
            self.audit_metadata.len() <= MAX_EDGE_ITEMS
                && ascending_by(&self.audit_metadata, |value| &value.0),
        )?;
        out.array(self.audit_metadata.len());
        for (key, value) in &self.audit_metadata {
            token(key)?;
            token(value)?;
            out.array(2).text(key).text(value);
        }
        Ok(())
    }

    fn read(input: &mut nsshared_codec::cbor::CborReader<'_>) -> Result<Self, AccountError> {
        input.array(8)?;
        let transport = match input.uint()? {
            0 => EdgeTransport::WireGuard,
            1 => EdgeTransport::WebSocket,
            2 => EdgeTransport::PreferWireGuard,
            3 => EdgeTransport::PreferWebSocket,
            _ => return Err(AccountError::Field),
        };
        let upstream_authority = read_optional_text(input, MAX_TEXT_BYTES)?;
        let upstream_tls = if input.take_null() {
            None
        } else {
            input.array(2)?;
            Some(EdgeUpstreamTls {
                sni: input.text_up_to(MAX_HOSTNAME_BYTES)?.to_owned(),
                accept_untrusted: input.boolean()?,
            })
        };
        input.array(11)?;
        let chain_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let waf_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let ext_authz_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let rate_limit_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let connection_limit_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let slow_client_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let session_limit_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let request_rewrite_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let response_header_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let forwarded_subject_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let audit_ref = read_optional_text(input, MAX_TEXT_BYTES)?;
        let request_body_bytes = read_optional_uint(input)?;
        let response_body_bytes = read_optional_uint(input)?;
        let source_ip = if input.take_null() {
            None
        } else {
            input.array(3)?;
            Some(EdgeSourceIp {
                allow_cidrs: read_texts(input, MAX_HOSTNAME_BYTES)?,
                deny_cidrs: read_texts(input, MAX_HOSTNAME_BYTES)?,
                fail_closed: input.boolean()?,
            })
        };
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let mut audit_metadata = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(2)?;
            audit_metadata.push((
                input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
                input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            ));
        }
        Ok(Self {
            transport,
            upstream_authority,
            upstream_tls,
            chain_ref,
            waf_ref,
            ext_authz_ref,
            rate_limit_ref,
            connection_limit_ref,
            slow_client_ref,
            session_limit_ref,
            request_rewrite_ref,
            response_header_ref,
            forwarded_subject_ref,
            audit_ref,
            request_body_bytes,
            response_body_bytes,
            source_ip,
            audit_metadata,
        })
    }
}
