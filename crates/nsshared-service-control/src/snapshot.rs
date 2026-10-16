//! Typed full recipient snapshots. Every nested map and collection is validated.

use crate::cbor::{Value, decode_canonical, encode_canonical};
use crate::contract::{
    ContractError, Digest, Id, Identity, ListenerIntent, Protocols, ServiceRef, bytes,
    domain_digest, exact_map, field, fixed, map, port, unsigned,
};
use crate::message::PortProposal;

/// Published service resource visible to an authorized recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resource {
    /// Stable resource identity.
    pub service_ref: ServiceRef,
    /// Validated service label from the publisher declaration, for local DNS.
    pub service_label: String,
    /// Full publisher identity.
    pub publisher_identity: Identity,
    /// One-based listener revision.
    pub listener_revision: u64,
    /// Full listener intent digest.
    pub intent_digest: Digest,
    /// Published service port.
    pub port: u16,
    /// TCP/UDP set.
    pub protocols: Protocols,
    /// Publisher's Node6 address.
    pub node6: [u8; 16],
    /// Optional service VIP, 4 or 16 network-order octets.
    pub vip: Option<Vec<u8>>,
}

/// One service route target; no publisher backend is exposed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Route {
    /// Service identity.
    pub service_ref: ServiceRef,
    /// Full destination identity.
    pub destination_identity: Identity,
    /// Destination Node6 address.
    pub destination_node6: [u8; 16],
    /// Destination published port.
    pub port: u16,
}

/// One policy grant for a consumer and a service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    /// Service identity.
    pub service_ref: ServiceRef,
    /// Authorized consumer identity.
    pub consumer_identity: Identity,
    /// Authorized protocol subset of the corresponding resource.
    pub allowed_protocols: Protocols,
    /// Existing authorization compiler version.
    pub policy_version: u64,
    /// Digest of compiled service authorization.
    pub policy_digest: Digest,
}

/// Publisher-only listener details and its current proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublisherListener {
    /// Exact backend-bearing listener intent.
    pub intent: ListenerIntent,
    /// Current proposal if allocation has begun.
    pub proposal: Option<PortProposal>,
}

/// Explicit withdrawal of a service listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Withdrawal {
    /// Service identity.
    pub service_ref: ServiceRef,
    /// Last known listener revision.
    pub listener_revision: u64,
}

/// Full configuration captured for one recipient, NSD and Network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Recipient's full identity.
    pub target_identity: Identity,
    /// NSD identity-bound identifier.
    pub nsd_id: Id,
    /// Network identifier.
    pub network_id: Id,
    /// One-based complete snapshot revision.
    pub snapshot_revision: u64,
    /// Resources sorted by full ServiceRef.
    pub resources: Vec<Resource>,
    /// Routes sorted by ServiceRef and destination identity.
    pub routes: Vec<Route>,
    /// Grants sorted by ServiceRef and consumer identity.
    pub grants: Vec<Grant>,
    /// Publisher-only listeners sorted by full ServiceRef.
    pub listeners: Vec<PublisherListener>,
    /// Withdrawals sorted by full ServiceRef.
    pub withdrawals: Vec<Withdrawal>,
}

impl Snapshot {
    /// Encodes a complete snapshot and returns its domain-separated digest.
    ///
    /// # Errors
    /// Returns an error for invalid fields, duplicate keys or nonpublisher backend exposure.
    pub fn canonical(&self) -> Result<(Vec<u8>, Digest), ContractError> {
        self.validate_order()?;
        let value = self.value()?;
        let content = encode_canonical(&value)?;
        let digest = domain_digest("ns.service.snapshot.v1", &content);
        Ok((content, digest))
    }

    /// Decodes exact canonical snapshot bytes.
    ///
    /// # Errors
    /// Returns an error for malformed or noncanonical data.
    pub fn decode(content: &[u8]) -> Result<Self, ContractError> {
        let value = decode_canonical(content)?;
        let snapshot = Self::from_value(&value)?;
        if snapshot.canonical()?.0 != content {
            return Err(ContractError::InvalidEncoding);
        }
        Ok(snapshot)
    }

    /// Parses an already decoded canonical value.
    ///
    /// # Errors
    /// Returns an error for unknown nested fields, invalid scope or member order.
    pub fn from_value(value: &Value) -> Result<Self, ContractError> {
        let fields = exact_map(
            value,
            &[
                "scope",
                "snapshot_revision",
                "resources",
                "routes",
                "grants",
                "listeners",
                "withdrawals",
            ],
        )?;
        let Value::Array(scope) = field(fields, "scope")? else {
            return Err(ContractError::InvalidField);
        };
        if scope.len() != 3 {
            return Err(ContractError::InvalidField);
        }
        let snapshot = Self {
            target_identity: fixed(&scope[0])?,
            nsd_id: fixed(&scope[1])?,
            network_id: fixed(&scope[2])?,
            snapshot_revision: unsigned(field(fields, "snapshot_revision")?)?,
            resources: array(field(fields, "resources")?)?
                .iter()
                .map(Resource::from_value)
                .collect::<Result<_, _>>()?,
            routes: array(field(fields, "routes")?)?
                .iter()
                .map(Route::from_value)
                .collect::<Result<_, _>>()?,
            grants: array(field(fields, "grants")?)?
                .iter()
                .map(Grant::from_value)
                .collect::<Result<_, _>>()?,
            listeners: array(field(fields, "listeners")?)?
                .iter()
                .map(PublisherListener::from_value)
                .collect::<Result<_, _>>()?,
            withdrawals: array(field(fields, "withdrawals")?)?
                .iter()
                .map(Withdrawal::from_value)
                .collect::<Result<_, _>>()?,
        };
        snapshot.validate_order()?;
        Ok(snapshot)
    }

    fn value(&self) -> Result<Value, ContractError> {
        Ok(map(vec![
            (
                "scope",
                Value::Array(vec![
                    bytes(self.target_identity),
                    bytes(self.nsd_id),
                    bytes(self.network_id),
                ]),
            ),
            ("snapshot_revision", Value::UInt(self.snapshot_revision)),
            (
                "resources",
                Value::Array(self.resources.iter().map(Resource::value).collect()),
            ),
            (
                "routes",
                Value::Array(self.routes.iter().map(Route::value).collect()),
            ),
            (
                "grants",
                Value::Array(self.grants.iter().map(Grant::value).collect()),
            ),
            (
                "listeners",
                Value::Array(
                    self.listeners
                        .iter()
                        .map(PublisherListener::value)
                        .collect::<Result<_, _>>()?,
                ),
            ),
            (
                "withdrawals",
                Value::Array(self.withdrawals.iter().map(Withdrawal::value).collect()),
            ),
        ]))
    }

    fn validate_order(&self) -> Result<(), ContractError> {
        if self.snapshot_revision == 0 {
            return Err(ContractError::InvalidField);
        }
        strict_order(self.resources.iter().map(|item| item.service_ref))?;
        strict_order(
            self.routes
                .iter()
                .map(|item| (item.service_ref, item.destination_identity)),
        )?;
        strict_order(
            self.grants
                .iter()
                .map(|item| (item.service_ref, item.consumer_identity)),
        )?;
        strict_order(self.listeners.iter().map(|item| item.intent.service_ref))?;
        strict_order(self.withdrawals.iter().map(|item| item.service_ref))?;
        for item in &self.resources {
            scoped(item.service_ref, self.nsd_id, self.network_id)?;
            if item.listener_revision == 0
                || item.port == 0
                || (!item.protocols.tcp && !item.protocols.udp)
                || !valid_service_label(&item.service_label)
                || item
                    .vip
                    .as_ref()
                    .is_some_and(|vip| vip.len() != 4 && vip.len() != 16)
            {
                return Err(ContractError::InvalidField);
            }
        }
        for item in &self.routes {
            scoped(item.service_ref, self.nsd_id, self.network_id)?;
            let resource = self
                .resources
                .iter()
                .find(|resource| resource.service_ref == item.service_ref)
                .ok_or(ContractError::InvalidField)?;
            if item.port != resource.port
                || item.destination_identity != resource.publisher_identity
                || item.destination_node6 != resource.node6
            {
                return Err(ContractError::DigestConflict);
            }
        }
        for item in &self.grants {
            scoped(item.service_ref, self.nsd_id, self.network_id)?;
            let resource = self
                .resources
                .iter()
                .find(|resource| resource.service_ref == item.service_ref)
                .ok_or(ContractError::InvalidField)?;
            if item.policy_version == 0
                || (!item.allowed_protocols.tcp && !item.allowed_protocols.udp)
                || (item.allowed_protocols.tcp && !resource.protocols.tcp)
                || (item.allowed_protocols.udp && !resource.protocols.udp)
            {
                return Err(ContractError::InvalidField);
            }
        }
        for item in &self.listeners {
            scoped(item.intent.service_ref, self.nsd_id, self.network_id)?;
            if item.intent.publisher_identity != self.target_identity {
                return Err(ContractError::DigestConflict);
            }
            let (_, intent_digest) = item.intent.canonical()?;
            let resource = self
                .resources
                .iter()
                .find(|resource| resource.service_ref == item.intent.service_ref)
                .ok_or(ContractError::InvalidField)?;
            if resource.publisher_identity != item.intent.publisher_identity
                || resource.listener_revision != item.intent.listener_revision
                || resource.intent_digest != intent_digest
                || resource.port != item.intent.port
                || resource.protocols != item.intent.protocols
            {
                return Err(ContractError::DigestConflict);
            }
            if let Some(proposal) = &item.proposal
                && (proposal.service_ref != item.intent.service_ref
                    || proposal.listener_revision != item.intent.listener_revision
                    || proposal.intent_digest != intent_digest
                    || proposal.port != item.intent.port)
            {
                return Err(ContractError::DigestConflict);
            }
            if let Some(proposal) = &item.proposal {
                proposal_from_value(&proposal_value(proposal))?;
            }
        }
        for item in &self.withdrawals {
            scoped(item.service_ref, self.nsd_id, self.network_id)?;
            if item.listener_revision == 0 {
                return Err(ContractError::InvalidField);
            }
        }
        Ok(())
    }
}

fn strict_order<T: Ord>(items: impl Iterator<Item = T>) -> Result<(), ContractError> {
    let mut previous = None;
    for item in items {
        if previous.as_ref().is_some_and(|prev| prev >= &item) {
            return Err(ContractError::InvalidField);
        }
        previous = Some(item);
    }
    Ok(())
}

fn scoped(reference: ServiceRef, nsd_id: Id, network_id: Id) -> Result<(), ContractError> {
    if reference.nsd_id == nsd_id && reference.network_id == network_id {
        Ok(())
    } else {
        Err(ContractError::DigestConflict)
    }
}

fn valid_service_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn array(value: &Value) -> Result<&[Value], ContractError> {
    if let Value::Array(items) = value {
        Ok(items)
    } else {
        Err(ContractError::InvalidField)
    }
}

fn nonzero(value: &Value) -> Result<u64, ContractError> {
    let value = unsigned(value)?;
    if value == 0 {
        Err(ContractError::InvalidField)
    } else {
        Ok(value)
    }
}

impl Resource {
    fn value(&self) -> Value {
        map(vec![
            ("service_ref", self.service_ref.value()),
            ("service_label", Value::Text(self.service_label.clone())),
            ("publisher_identity", bytes(self.publisher_identity)),
            ("listener_revision", Value::UInt(self.listener_revision)),
            ("intent_digest", bytes(self.intent_digest)),
            ("port", Value::UInt(u64::from(self.port))),
            ("protocols", self.protocols.value()),
            ("node6", bytes(self.node6)),
            (
                "vip",
                self.vip
                    .as_ref()
                    .map_or(Value::Null, |vip| Value::Bytes(vip.clone())),
            ),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ContractError> {
        let fields = exact_map(
            value,
            &[
                "service_ref",
                "service_label",
                "publisher_identity",
                "listener_revision",
                "intent_digest",
                "port",
                "protocols",
                "node6",
                "vip",
            ],
        )?;
        let vip = match field(fields, "vip")? {
            Value::Null => None,
            Value::Bytes(vip) => Some(vip.clone()),
            _ => return Err(ContractError::InvalidField),
        };
        Ok(Self {
            service_ref: ServiceRef::from_value(field(fields, "service_ref")?)?,
            service_label: crate::contract::text(field(fields, "service_label")?)?.to_owned(),
            publisher_identity: fixed(field(fields, "publisher_identity")?)?,
            listener_revision: nonzero(field(fields, "listener_revision")?)?,
            intent_digest: fixed(field(fields, "intent_digest")?)?,
            port: port(field(fields, "port")?)?,
            protocols: Protocols::from_value(field(fields, "protocols")?)?,
            node6: fixed(field(fields, "node6")?)?,
            vip,
        })
    }
}

impl Route {
    fn value(&self) -> Value {
        map(vec![
            ("service_ref", self.service_ref.value()),
            ("destination_identity", bytes(self.destination_identity)),
            ("destination_node6", bytes(self.destination_node6)),
            ("port", Value::UInt(u64::from(self.port))),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ContractError> {
        let fields = exact_map(
            value,
            &[
                "service_ref",
                "destination_identity",
                "destination_node6",
                "port",
            ],
        )?;
        Ok(Self {
            service_ref: ServiceRef::from_value(field(fields, "service_ref")?)?,
            destination_identity: fixed(field(fields, "destination_identity")?)?,
            destination_node6: fixed(field(fields, "destination_node6")?)?,
            port: port(field(fields, "port")?)?,
        })
    }
}

impl Grant {
    fn value(&self) -> Value {
        map(vec![
            ("service_ref", self.service_ref.value()),
            ("consumer_identity", bytes(self.consumer_identity)),
            ("allowed_protocols", self.allowed_protocols.value()),
            ("policy_version", Value::UInt(self.policy_version)),
            ("policy_digest", bytes(self.policy_digest)),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ContractError> {
        let fields = exact_map(
            value,
            &[
                "service_ref",
                "consumer_identity",
                "allowed_protocols",
                "policy_version",
                "policy_digest",
            ],
        )?;
        Ok(Self {
            service_ref: ServiceRef::from_value(field(fields, "service_ref")?)?,
            consumer_identity: fixed(field(fields, "consumer_identity")?)?,
            allowed_protocols: Protocols::from_value(field(fields, "allowed_protocols")?)?,
            policy_version: nonzero(field(fields, "policy_version")?)?,
            policy_digest: fixed(field(fields, "policy_digest")?)?,
        })
    }
}

impl PublisherListener {
    fn value(&self) -> Result<Value, ContractError> {
        let (content, _) = self.intent.canonical()?;
        Ok(map(vec![
            ("intent", Value::Bytes(content)),
            (
                "proposal",
                self.proposal.as_ref().map_or(Value::Null, proposal_value),
            ),
        ]))
    }

    fn from_value(value: &Value) -> Result<Self, ContractError> {
        let fields = exact_map(value, &["intent", "proposal"])?;
        let Value::Bytes(content) = field(fields, "intent")? else {
            return Err(ContractError::InvalidField);
        };
        let proposal = match field(fields, "proposal")? {
            Value::Null => None,
            value => Some(proposal_from_value(value)?),
        };
        Ok(Self {
            intent: ListenerIntent::decode(content)?,
            proposal,
        })
    }
}

impl Withdrawal {
    fn value(&self) -> Value {
        map(vec![
            ("service_ref", self.service_ref.value()),
            ("listener_revision", Value::UInt(self.listener_revision)),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ContractError> {
        let fields = exact_map(value, &["service_ref", "listener_revision"])?;
        Ok(Self {
            service_ref: ServiceRef::from_value(field(fields, "service_ref")?)?,
            listener_revision: nonzero(field(fields, "listener_revision")?)?,
        })
    }
}

pub(crate) fn proposal_value(proposal: &PortProposal) -> Value {
    map(vec![
        ("service_ref", proposal.service_ref.value()),
        ("listener_revision", Value::UInt(proposal.listener_revision)),
        ("intent_digest", bytes(proposal.intent_digest)),
        ("allocation_round", Value::UInt(proposal.allocation_round)),
        ("proposal_seq", Value::UInt(proposal.proposal_seq)),
        ("proposal_id", bytes(proposal.proposal_id)),
        ("port", Value::UInt(u64::from(proposal.port))),
    ])
}

pub(crate) fn proposal_from_value(value: &Value) -> Result<PortProposal, ContractError> {
    let fields = exact_map(
        value,
        &[
            "service_ref",
            "listener_revision",
            "intent_digest",
            "allocation_round",
            "proposal_seq",
            "proposal_id",
            "port",
        ],
    )?;
    let proposal = PortProposal {
        service_ref: ServiceRef::from_value(field(fields, "service_ref")?)?,
        listener_revision: nonzero(field(fields, "listener_revision")?)?,
        intent_digest: fixed(field(fields, "intent_digest")?)?,
        allocation_round: nonzero(field(fields, "allocation_round")?)?,
        proposal_seq: nonzero(field(fields, "proposal_seq")?)?,
        proposal_id: fixed(field(fields, "proposal_id")?)?,
        port: port(field(fields, "port")?)?,
    };
    if proposal.proposal_id == [0; 16] {
        return Err(ContractError::InvalidField);
    }
    Ok(proposal)
}
