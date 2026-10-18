//! Versioned M6 service-control message and digest types.

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::cbor::{CborError, Value, decode_canonical, encode_canonical};

#[path = "contract_body.rs"]
mod body;

/// Capability exchanged before M6 messages.
pub const CAPABILITY: &str = "service_control.v1";
/// Wire schema number.
pub const SCHEMA: u64 = 1;
/// Local persistent-state schema identifier.
pub const LOCAL_SCHEMA: &str = "ns.service-control.v1";
/// Maximum service use lease in milliseconds.
pub const MAX_LEASE_MS: u64 = 30_000;
/// Nominal lease renewal interval in milliseconds.
pub const REFRESH_MS: u64 = 10_000;

/// A 16-byte UUID or ULID, according to field context.
pub type Id = [u8; 16];
/// A complete identity public key.
pub type Identity = [u8; 32];
/// A SHA-256 content digest.
pub type Digest = [u8; 32];

/// A service is scoped by NSD, Network and its stable ULID.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServiceRef {
    /// Identity-bound NSD identifier.
    pub nsd_id: Id,
    /// Network identifier.
    pub network_id: Id,
    /// Stable service identifier.
    pub service_id: Id,
}

impl ServiceRef {
    /// Returns the canonical wire value.
    #[must_use]
    pub fn value(self) -> Value {
        Value::Array(vec![
            bytes(self.nsd_id),
            bytes(self.network_id),
            bytes(self.service_id),
        ])
    }

    /// Reads an exact service reference.
    ///
    /// # Errors
    /// Returns [`ContractError::InvalidField`] on the wrong shape or length.
    pub fn from_value(value: &Value) -> Result<Self, ContractError> {
        let Value::Array(parts) = value else {
            return Err(ContractError::InvalidField);
        };
        if parts.len() != 3 {
            return Err(ContractError::InvalidField);
        }
        Ok(Self {
            nsd_id: fixed(&parts[0])?,
            network_id: fixed(&parts[1])?,
            service_id: fixed(&parts[2])?,
        })
    }
}

/// Stable control-plane errors. The wire form is the lowercase code in [`Self::code`].
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    /// Malformed CBOR.
    #[error("invalid-encoding")]
    InvalidEncoding,
    /// Unsupported schema.
    #[error("unsupported-version")]
    UnsupportedVersion,
    /// Unknown or unsupported field.
    #[error("unsupported-field")]
    UnsupportedField,
    /// A required field is absent or invalid.
    #[error("invalid-field")]
    InvalidField,
    /// A field or digest disagrees with its scope.
    #[error("digest-conflict")]
    DigestConflict,
    /// A counter has no successor.
    #[error("counter-exhausted")]
    CounterExhausted,
}

impl ContractError {
    /// The stable lowercase wire code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncoding => "invalid-encoding",
            Self::UnsupportedVersion => "unsupported-version",
            Self::UnsupportedField => "unsupported-field",
            Self::InvalidField => "invalid-encoding",
            Self::DigestConflict => "digest-conflict",
            Self::CounterExhausted => "counter-exhausted",
        }
    }
}

impl From<CborError> for ContractError {
    fn from(_: CborError) -> Self {
        Self::InvalidEncoding
    }
}

/// Returns the next one-based sequence value.
///
/// # Errors
/// Returns `counter-exhausted` at `u64::MAX`.
pub fn next_revision(current: u64) -> Result<u64, ContractError> {
    current
        .checked_add(1)
        .ok_or(ContractError::CounterExhausted)
}

/// A full common envelope. Authentication covers these original bytes externally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Envelope {
    /// Message kind.
    pub kind: String,
    /// NSD identifier.
    pub nsd_id: Id,
    /// Network identifier.
    pub network_id: Id,
    /// Complete subject identity.
    pub subject_identity: Identity,
    /// Persisted daemon startup generation; null only for `runtime.floor`.
    pub runtime_generation: Option<u64>,
    /// Random daemon runtime ID; null only for `runtime.floor`.
    pub runtime_id: Option<Id>,
    /// Server authority epoch; null only for bootstrap messages.
    pub authority_epoch: Option<u64>,
    /// Logical request ID, retained across transport retries.
    pub request_id: Id,
    /// Session high-water, required for stream-bound messages.
    pub session_seq: Option<u64>,
    /// Kind-specific body. Its exact shape is checked by the caller's handler.
    pub body: Value,
}

impl Envelope {
    /// Encodes the envelope as deterministic CBOR.
    ///
    /// # Errors
    /// Returns an error for invalid bootstrap fields or CBOR bounds.
    pub fn encode(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        Ok(encode_canonical(&self.value())?)
    }

    /// Decodes an exact envelope; unknown fields and noncanonical CBOR are rejected.
    ///
    /// # Errors
    /// Returns an error for invalid schema, shape, fields or CBOR.
    pub fn decode(input: &[u8]) -> Result<Self, ContractError> {
        let value = decode_canonical(input)?;
        let map = exact_map(
            &value,
            &[
                "schema",
                "kind",
                "nsd_id",
                "network_id",
                "subject_identity",
                "runtime_generation",
                "runtime_id",
                "authority_epoch",
                "request_id",
                "session_seq",
                "body",
            ],
        )?;
        if unsigned(field(map, "schema")?)? != SCHEMA {
            return Err(ContractError::UnsupportedVersion);
        }
        let message = Self {
            kind: text(field(map, "kind")?)?.to_owned(),
            nsd_id: fixed(field(map, "nsd_id")?)?,
            network_id: fixed(field(map, "network_id")?)?,
            subject_identity: fixed(field(map, "subject_identity")?)?,
            runtime_generation: optional_uint(field(map, "runtime_generation")?)?,
            runtime_id: optional_fixed(field(map, "runtime_id")?)?,
            authority_epoch: optional_uint(field(map, "authority_epoch")?)?,
            request_id: fixed(field(map, "request_id")?)?,
            session_seq: optional_uint(field(map, "session_seq")?)?,
            body: field(map, "body")?.clone(),
        };
        message.validate()?;
        Ok(message)
    }

    fn validate(&self) -> Result<(), ContractError> {
        let floor = matches!(self.kind.as_str(), "runtime.floor" | "runtime.floor.result");
        let bootstrap = matches!(self.kind.as_str(), "runtime.floor" | "runtime.bind");
        if self.kind.is_empty()
            || self.kind.len() > 64
            || !self.kind.is_ascii()
            || self.request_id == [0; 16]
            || (self.runtime_generation.is_some() != self.runtime_id.is_some())
            || (self.runtime_generation == Some(0))
            || (!floor && (self.runtime_generation.is_none() || self.runtime_id.is_none()))
            || (!bootstrap && self.authority_epoch.unwrap_or(0) == 0)
            || self.runtime_id == Some([0; 16])
            || (!bootstrap && self.session_seq == Some(0))
        {
            return Err(ContractError::InvalidField);
        }
        body::validate(self)
    }

    fn value(&self) -> Value {
        map(vec![
            ("schema", Value::UInt(SCHEMA)),
            ("kind", Value::Text(self.kind.clone())),
            ("nsd_id", bytes(self.nsd_id)),
            ("network_id", bytes(self.network_id)),
            ("subject_identity", bytes(self.subject_identity)),
            ("runtime_generation", option_uint(self.runtime_generation)),
            ("runtime_id", option_bytes(self.runtime_id)),
            ("authority_epoch", option_uint(self.authority_epoch)),
            ("request_id", bytes(self.request_id)),
            ("session_seq", option_uint(self.session_seq)),
            ("body", self.body.clone()),
        ])
    }
}

/// A typed backend address, with DNS text already normalized by the producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackendHost {
    /// Four network-order address octets.
    Ipv4([u8; 4]),
    /// Sixteen network-order address octets.
    Ipv6([u8; 16]),
    /// Canonical ASCII DNS hostname.
    Dns(String),
}

impl BackendHost {
    fn value(&self) -> Value {
        match self {
            Self::Ipv4(address) => Value::Array(vec![Value::Text("ipv4".into()), bytes(*address)]),
            Self::Ipv6(address) => Value::Array(vec![Value::Text("ipv6".into()), bytes(*address)]),
            Self::Dns(host) => {
                Value::Array(vec![Value::Text("dns".into()), Value::Text(host.clone())])
            }
        }
    }

    fn validate(&self) -> Result<(), ContractError> {
        if let Self::Dns(name) = self
            && (name.is_empty()
                || name.len() > 253
                || !name.is_ascii()
                || name != &name.to_ascii_lowercase()
                || name.starts_with('.')
                || name.ends_with('.')
                || name.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                }))
        {
            return Err(ContractError::InvalidField);
        }
        Ok(())
    }

    fn from_value(value: &Value) -> Result<Self, ContractError> {
        let Value::Array(parts) = value else {
            return Err(ContractError::InvalidField);
        };
        if parts.len() != 2 {
            return Err(ContractError::InvalidField);
        }
        let host = match text(&parts[0])? {
            "ipv4" => Self::Ipv4(fixed(&parts[1])?),
            "ipv6" => Self::Ipv6(fixed(&parts[1])?),
            "dns" => Self::Dns(text(&parts[1])?.to_owned()),
            _ => return Err(ContractError::UnsupportedField),
        };
        host.validate()?;
        Ok(host)
    }
}

/// TCP/UDP protocol set; at least one protocol is required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Protocols {
    /// TCP listener enabled.
    pub tcp: bool,
    /// UDP listener enabled.
    pub udp: bool,
}

impl Protocols {
    pub(crate) fn value(self) -> Value {
        let mut items = Vec::new();
        if self.tcp {
            items.push(Value::Text("tcp".into()));
        }
        if self.udp {
            items.push(Value::Text("udp".into()));
        }
        Value::Array(items)
    }

    fn validate(self) -> Result<(), ContractError> {
        if self.tcp || self.udp {
            Ok(())
        } else {
            Err(ContractError::InvalidField)
        }
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, ContractError> {
        let Value::Array(items) = value else {
            return Err(ContractError::InvalidField);
        };
        match items.as_slice() {
            [Value::Text(tcp)] if tcp == "tcp" => Ok(Self {
                tcp: true,
                udp: false,
            }),
            [Value::Text(udp)] if udp == "udp" => Ok(Self {
                tcp: false,
                udp: true,
            }),
            [Value::Text(tcp), Value::Text(udp)] if tcp == "tcp" && udp == "udp" => Ok(Self {
                tcp: true,
                udp: true,
            }),
            _ => Err(ContractError::InvalidField),
        }
    }
}

/// A full private service declaration. `declaration_key` is the stable identity key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Declaration {
    /// Stable publisher-local key.
    pub declaration_key: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// Optional description.
    pub description: Option<String>,
    /// Whether the declaration is enabled.
    pub enabled: bool,
    /// Supported transport protocols.
    pub protocols: Protocols,
    /// Backend host.
    pub backend_host: BackendHost,
    /// Backend port.
    pub backend_port: u16,
    /// Fixed or automatic published port.
    pub port_mode: PortMode,
}

/// Published port choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortMode {
    /// Use this exact port or reject.
    Fixed(u16),
    /// Allocate a port; first try the backend port.
    Auto,
}

impl Declaration {
    /// Encodes one declaration as canonical CBOR for durable resource rows.
    ///
    /// # Errors
    /// Returns an error for invalid declaration fields or CBOR bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, ContractError> {
        self.validate()?;
        encode_canonical(&self.value()).map_err(Into::into)
    }

    /// Decodes one exact declaration from canonical CBOR.
    ///
    /// # Errors
    /// Returns an error for malformed, noncanonical or unsupported fields.
    pub fn decode(input: &[u8]) -> Result<Self, ContractError> {
        let value = decode_canonical(input)?;
        let declaration = Self::from_value(&value)?;
        if declaration.canonical()? != input {
            return Err(ContractError::InvalidEncoding);
        }
        Ok(declaration)
    }

    fn value(&self) -> Value {
        let (mode, requested) = match self.port_mode {
            PortMode::Fixed(port) => ("fixed", Value::UInt(u64::from(port))),
            PortMode::Auto => ("auto", Value::Null),
        };
        map(vec![
            ("declaration_key", Value::Text(self.declaration_key.clone())),
            ("display_name", option_text(&self.display_name)),
            ("description", option_text(&self.description)),
            ("enabled", Value::Bool(self.enabled)),
            ("protocols", self.protocols.value()),
            ("backend_host", self.backend_host.value()),
            ("backend_port", Value::UInt(u64::from(self.backend_port))),
            ("port_mode", Value::Text(mode.into())),
            ("requested_port", requested),
        ])
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.declaration_key.is_empty()
            || self.declaration_key.len() > 255
            || self.backend_port == 0
            || matches!(self.port_mode, PortMode::Fixed(0))
        {
            return Err(ContractError::InvalidField);
        }
        self.protocols.validate()?;
        self.backend_host.validate()
    }

    fn from_value(value: &Value) -> Result<Self, ContractError> {
        let fields = exact_map(
            value,
            &[
                "declaration_key",
                "display_name",
                "description",
                "enabled",
                "protocols",
                "backend_host",
                "backend_port",
                "port_mode",
                "requested_port",
            ],
        )?;
        let port_mode = match text(field(fields, "port_mode")?)? {
            "fixed" => PortMode::Fixed(port(field(fields, "requested_port")?)?),
            "auto" if *field(fields, "requested_port")? == Value::Null => PortMode::Auto,
            "auto" => return Err(ContractError::InvalidField),
            _ => return Err(ContractError::UnsupportedField),
        };
        let declaration = Self {
            declaration_key: text(field(fields, "declaration_key")?)?.to_owned(),
            display_name: optional_text(field(fields, "display_name")?)?,
            description: optional_text(field(fields, "description")?)?,
            enabled: boolean(field(fields, "enabled")?)?,
            protocols: Protocols::from_value(field(fields, "protocols")?)?,
            backend_host: BackendHost::from_value(field(fields, "backend_host")?)?,
            backend_port: port(field(fields, "backend_port")?)?,
            port_mode,
        };
        declaration.validate()?;
        Ok(declaration)
    }
}

/// Full report content, independent of runtime and local short names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportContent {
    /// Publisher identity.
    pub publisher_identity: Identity,
    /// NSD scope.
    pub nsd_id: Id,
    /// Network scope.
    pub network_id: Id,
    /// Strict service mode.
    pub strict_mode: bool,
    /// Full declarations, sorted by declaration-key UTF-8 bytes when encoded.
    pub declarations: Vec<Declaration>,
}

impl ReportContent {
    /// Decodes a complete report from canonical CBOR, rejecting unknown fields.
    ///
    /// # Errors
    /// Returns an error for malformed content or declarations out of key order.
    pub fn decode(input: &[u8]) -> Result<Self, ContractError> {
        let value = decode_canonical(input)?;
        let fields = exact_map(&value, &["scope", "strict_mode", "declarations"])?;
        let Value::Array(scope) = field(fields, "scope")? else {
            return Err(ContractError::InvalidField);
        };
        if scope.len() != 3 {
            return Err(ContractError::InvalidField);
        }
        let Value::Array(items) = field(fields, "declarations")? else {
            return Err(ContractError::InvalidField);
        };
        let declarations: Vec<_> = items
            .iter()
            .map(Declaration::from_value)
            .collect::<Result<_, _>>()?;
        if declarations
            .windows(2)
            .any(|pair| pair[0].declaration_key.as_bytes() >= pair[1].declaration_key.as_bytes())
        {
            return Err(ContractError::InvalidField);
        }
        let report = Self {
            publisher_identity: fixed(&scope[0])?,
            nsd_id: fixed(&scope[1])?,
            network_id: fixed(&scope[2])?,
            strict_mode: boolean(field(fields, "strict_mode")?)?,
            declarations,
        };
        if report.canonical()?.0 != input {
            return Err(ContractError::InvalidEncoding);
        }
        Ok(report)
    }

    /// Computes canonical bytes and SHA-256 report digest.
    ///
    /// # Errors
    /// Returns an error for duplicate keys, unsupported fields or CBOR bounds.
    pub fn canonical(&self) -> Result<(Vec<u8>, Digest), ContractError> {
        let mut declarations = self.declarations.clone();
        declarations.sort_unstable_by(|left, right| {
            left.declaration_key
                .as_bytes()
                .cmp(right.declaration_key.as_bytes())
        });
        for (index, declaration) in declarations.iter().enumerate() {
            declaration.validate()?;
            if index > 0 && declarations[index - 1].declaration_key == declaration.declaration_key {
                return Err(ContractError::InvalidField);
            }
        }
        let value = map(vec![
            (
                "scope",
                Value::Array(vec![
                    bytes(self.publisher_identity),
                    bytes(self.nsd_id),
                    bytes(self.network_id),
                ]),
            ),
            ("strict_mode", Value::Bool(self.strict_mode)),
            (
                "declarations",
                Value::Array(declarations.iter().map(Declaration::value).collect()),
            ),
        ]);
        let encoded = encode_canonical(&value)?;
        let digest = domain_digest("ns.service.report.v1", &encoded);
        Ok((encoded, digest))
    }
}

/// Exact publisher listener intent whose digest excludes names, runtime and lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerIntent {
    /// Service identity.
    pub service_ref: ServiceRef,
    /// Complete publisher identity.
    pub publisher_identity: Identity,
    /// One-based listener revision.
    pub listener_revision: u64,
    /// Published transport port.
    pub port: u16,
    /// TCP/UDP set.
    pub protocols: Protocols,
    /// Local backend host.
    pub backend_host: BackendHost,
    /// Local backend port.
    pub backend_port: u16,
    /// Existing authorization compiler input version.
    pub enforcement_policy_version: u64,
    /// Full digest of compiled service enforcement input.
    pub enforcement_policy_digest: Digest,
}

impl ListenerIntent {
    /// Decodes one exact listener intent from canonical CBOR.
    ///
    /// # Errors
    /// Returns an error for malformed content, unknown fields or invalid intent.
    pub fn decode(input: &[u8]) -> Result<Self, ContractError> {
        let value = decode_canonical(input)?;
        let fields = exact_map(
            &value,
            &[
                "service_ref",
                "publisher_identity",
                "listener_revision",
                "port",
                "protocols",
                "backend_host",
                "backend_port",
                "enforcement_policy_version",
                "enforcement_policy_digest",
            ],
        )?;
        let intent = Self {
            service_ref: ServiceRef::from_value(field(fields, "service_ref")?)?,
            publisher_identity: fixed(field(fields, "publisher_identity")?)?,
            listener_revision: unsigned(field(fields, "listener_revision")?)?,
            port: port(field(fields, "port")?)?,
            protocols: Protocols::from_value(field(fields, "protocols")?)?,
            backend_host: BackendHost::from_value(field(fields, "backend_host")?)?,
            backend_port: port(field(fields, "backend_port")?)?,
            enforcement_policy_version: unsigned(field(fields, "enforcement_policy_version")?)?,
            enforcement_policy_digest: fixed(field(fields, "enforcement_policy_digest")?)?,
        };
        if intent.canonical()?.0 != input {
            return Err(ContractError::InvalidEncoding);
        }
        Ok(intent)
    }

    /// Computes canonical bytes and SHA-256 listener digest.
    ///
    /// # Errors
    /// Returns an error for an invalid port, revision, backend or protocol set.
    pub fn canonical(&self) -> Result<(Vec<u8>, Digest), ContractError> {
        if self.listener_revision == 0
            || self.port == 0
            || self.backend_port == 0
            || self.enforcement_policy_version == 0
        {
            return Err(ContractError::InvalidField);
        }
        self.protocols.validate()?;
        self.backend_host.validate()?;
        let value = map(vec![
            ("service_ref", self.service_ref.value()),
            ("publisher_identity", bytes(self.publisher_identity)),
            ("listener_revision", Value::UInt(self.listener_revision)),
            ("port", Value::UInt(u64::from(self.port))),
            ("protocols", self.protocols.value()),
            ("backend_host", self.backend_host.value()),
            ("backend_port", Value::UInt(u64::from(self.backend_port))),
            (
                "enforcement_policy_version",
                Value::UInt(self.enforcement_policy_version),
            ),
            (
                "enforcement_policy_digest",
                bytes(self.enforcement_policy_digest),
            ),
        ]);
        let encoded = encode_canonical(&value)?;
        let digest = domain_digest("ns.service.listener.v1", &encoded);
        Ok((encoded, digest))
    }
}

/// Computes the digest for a complete recipient snapshot CBOR value.
///
/// # Errors
/// Returns an error if the value is outside the canonical subset.
pub fn snapshot_digest(snapshot: &Value) -> Result<Digest, ContractError> {
    crate::snapshot::Snapshot::from_value(snapshot)?;
    Ok(domain_digest(
        "ns.service.snapshot.v1",
        &encode_canonical(snapshot)?,
    ))
}

/// SHA-256 with an ASCII domain and a zero separator.
#[must_use]
pub fn domain_digest(domain: &str, content: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(content);
    hasher.finalize().into()
}

pub(crate) fn bytes<const N: usize>(value: [u8; N]) -> Value {
    Value::Bytes(value.to_vec())
}
pub(crate) fn option_bytes<const N: usize>(value: Option<[u8; N]>) -> Value {
    value.map_or(Value::Null, bytes)
}
pub(crate) fn option_uint(value: Option<u64>) -> Value {
    value.map_or(Value::Null, Value::UInt)
}
pub(crate) fn option_text(value: &Option<String>) -> Value {
    value
        .as_ref()
        .map_or(Value::Null, |text| Value::Text(text.clone()))
}
pub(crate) fn map(fields: Vec<(&str, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}
pub(crate) fn fixed<const N: usize>(value: &Value) -> Result<[u8; N], ContractError> {
    let Value::Bytes(bytes) = value else {
        return Err(ContractError::InvalidField);
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| ContractError::InvalidField)
}
pub(crate) fn optional_fixed<const N: usize>(
    value: &Value,
) -> Result<Option<[u8; N]>, ContractError> {
    if *value == Value::Null {
        Ok(None)
    } else {
        Ok(Some(fixed(value)?))
    }
}
pub(crate) fn unsigned(value: &Value) -> Result<u64, ContractError> {
    if let Value::UInt(value) = value {
        Ok(*value)
    } else {
        Err(ContractError::InvalidField)
    }
}
pub(crate) fn optional_uint(value: &Value) -> Result<Option<u64>, ContractError> {
    if *value == Value::Null {
        Ok(None)
    } else {
        Ok(Some(unsigned(value)?))
    }
}
pub(crate) fn boolean(value: &Value) -> Result<bool, ContractError> {
    if let Value::Bool(value) = value {
        Ok(*value)
    } else {
        Err(ContractError::InvalidField)
    }
}
pub(crate) fn optional_text(value: &Value) -> Result<Option<String>, ContractError> {
    if *value == Value::Null {
        Ok(None)
    } else {
        Ok(Some(text(value)?.to_owned()))
    }
}
pub(crate) fn port(value: &Value) -> Result<u16, ContractError> {
    u16::try_from(unsigned(value)?)
        .ok()
        .filter(|port| *port != 0)
        .ok_or(ContractError::InvalidField)
}
pub(crate) fn text(value: &Value) -> Result<&str, ContractError> {
    if let Value::Text(value) = value {
        Ok(value)
    } else {
        Err(ContractError::InvalidField)
    }
}
pub(crate) fn field<'a>(
    map: &'a [(String, Value)],
    name: &str,
) -> Result<&'a Value, ContractError> {
    map.iter()
        .find_map(|(key, value)| (key == name).then_some(value))
        .ok_or(ContractError::InvalidField)
}
pub(crate) fn exact_map<'a>(
    value: &'a Value,
    names: &[&str],
) -> Result<&'a [(String, Value)], ContractError> {
    let Value::Map(map) = value else {
        return Err(ContractError::InvalidField);
    };
    if map.iter().any(|(key, _)| !names.contains(&key.as_str())) {
        return Err(ContractError::UnsupportedField);
    }
    if map.len() != names.len() {
        return Err(ContractError::InvalidField);
    }
    Ok(map)
}
