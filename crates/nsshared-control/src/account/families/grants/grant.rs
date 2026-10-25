//! Pure service authority payloads; installation and history custody stay in consumers.

use crate::{
    account::AccountError, account::MAX_BYTES, account::MAX_IDENTITIES, account::SCHEMA,
    account::codec::identity, account::grants::authority::RetiredGrant,
    account::grants::payer::Payer, account::grants::payer::payer,
    account::grants::payer::read_payers, account::grants::payer::write_payers,
    account::limits::MAX_TEXT_BYTES, account::node::GrantIncarnation,
    account::node::TransportProtocol, account::subnet::SubnetError,
    account::subnet::SubnetPublication, service::ServiceRef,
};

use thiserror::Error;

use nsshared_codec::{cbor::CborError, cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// Typed refusal of service authority.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GrantError {
    /// Strict CBOR refusal of the grant payload itself.
    #[error(transparent)]
    Encoding(#[from] CborError),
    /// Invalid full identity, normalized Node policy or other shared contract field.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Invalid embedded Subnet selection.
    #[error(transparent)]
    Subnet(#[from] SubnetError),
    /// Invalid M6 ServiceRef bytes.
    #[error("invalid M6 resource reference")]
    Reference,
    /// No payer was supplied.
    #[error("missing payer")]
    MissingPayer,
    /// Multiple payers were supplied, including equal values.
    #[error("ambiguous payer")]
    AmbiguousPayer,
    /// Unsupported schema, family, protocol, port or field.
    #[error("invalid grant field")]
    Field,
    /// Provider, publication or embedded route scope differs.
    #[error("grant authority scope mismatch")]
    Scope,
    /// A set is unsorted or has duplicate keys.
    #[error("noncanonical grant ordering")]
    Ordering,
    /// Payload or collection exceeds its limit.
    #[error("grant bound exceeded")]
    Bounds,
    /// An active resource token has already retired.
    #[error("retired grant incarnation")]
    RetiredIncarnation,
    /// Changed content reused an active token.
    #[error("changed grant requires a fresh incarnation")]
    ReusedIncarnation,
    /// A successor lost retirement history or failed to retire a removed claim.
    #[error("incomplete retirement history")]
    History,
    /// Missing, zero or ambiguous identity-to-key authority.
    #[error("invalid identity-to-key binding")]
    Binding,
}

pub(in crate::account) fn write_reference(
    value: &ServiceRef,
    out: &mut CborWriter,
) -> Result<(), GrantError> {
    out.bytes(&value.canonical().map_err(|_| GrantError::Reference)?);
    Ok(())
}

pub(in crate::account) fn read_reference(
    input: &mut CborReader<'_>,
) -> Result<ServiceRef, GrantError> {
    ServiceRef::decode(input.bytes_up_to(MAX_BYTES)?).map_err(|_| GrantError::Reference)
}

pub(in crate::account) fn checked_bytes(out: CborWriter) -> Result<Vec<u8>, GrantError> {
    let bytes = out.into_bytes();
    if bytes.len() > MAX_BYTES {
        Err(GrantError::Bounds)
    } else {
        Ok(bytes)
    }
}

pub(in crate::account) fn field(condition: bool) -> Result<(), GrantError> {
    if condition {
        Ok(())
    } else {
        Err(GrantError::Field)
    }
}

/// Canonical protocol-qualified grant identity, ordered by numeric components.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GrantDiscriminator {
    /// Egress TCP, encoded as `[0, 6]`.
    EgressTcp,
    /// Egress UDP, encoded as `[0, 17]`.
    EgressUdp,
    /// Exit, encoded as `[1]`.
    Exit,
}

impl GrantDiscriminator {
    pub(in crate::account) fn write(self, out: &mut CborWriter) {
        match self {
            Self::EgressTcp => {
                out.array(2).uint(0).uint(6);
            }
            Self::EgressUdp => {
                out.array(2).uint(0).uint(17);
            }
            Self::Exit => {
                out.array(1).uint(1);
            }
        }
    }

    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, GrantError> {
        let count = input.array_up_to(2)?;
        match (count, input.uint()?) {
            (1, 1) => Ok(Self::Exit),
            (2, 0) => match input.uint()? {
                6 => Ok(Self::EgressTcp),
                17 => Ok(Self::EgressUdp),
                _ => Err(GrantError::Field),
            },
            _ => Err(GrantError::Field),
        }
    }
}

pub(in crate::account) fn unique_tokens<'a>(
    values: impl Iterator<Item = (&'a ServiceRef, [u8; 16])>,
) -> Result<(), GrantError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(GrantError::ReusedIncarnation);
        }
    }
    Ok(())
}

/// Family-specific resource facts, independent of host bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantDetails {
    /// Private service intersected with an exact local floor declaration.
    Egress {
        /// Exact local service declaration reference.
        floor: String,
        /// Exact projected listener name.
        name: String,
        /// Concrete transport.
        protocol: TransportProtocol,
        /// Virtual listener port.
        virtual_port: u16,
        /// Current alias generation, absent for a non-alias.
        alias_generation: Option<u64>,
    },
    /// Existing Subnet selection publication containing exactly one matching route.
    Exit(SubnetPublication),
}

impl GrantDetails {
    /// Derives the canonical identity discriminator from exact grant facts.
    #[must_use]
    pub const fn discriminator(&self) -> GrantDiscriminator {
        match self {
            Self::Egress {
                protocol: TransportProtocol::Tcp,
                ..
            } => GrantDiscriminator::EgressTcp,
            Self::Egress {
                protocol: TransportProtocol::Udp,
                ..
            } => GrantDiscriminator::EgressUdp,
            Self::Exit(_) => GrantDiscriminator::Exit,
        }
    }
}

/// One client/resource grant with explicit payer and lifetime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceGrant {
    /// Existing M6 resource reference.
    pub resource: ServiceRef,
    /// Authorized full client identity.
    pub client: IdentityKey,
    /// Authorized full provider identity.
    pub provider: IdentityKey,
    /// Exactly one binding; cardinality errors are explicit refusals.
    pub payers: Vec<Payer>,
    /// Opaque resource lifetime.
    pub incarnation: GrantIncarnation,
    /// Actual hard expiry in Unix milliseconds, compared by the consumer.
    pub expires_at_unix_ms: u64,
    /// Exact resource and floor/route facts.
    pub details: GrantDetails,
}

impl ServiceGrant {
    /// Returns the sole explicit payer, without inference or deduplication.
    ///
    /// # Errors
    /// Refuses zero or multiple bindings.
    pub fn payer(&self) -> Result<&Payer, GrantError> {
        payer(&self.payers)
    }

    fn validate(&self, family: u64) -> Result<(), GrantError> {
        self.payer()?;
        field(self.expires_at_unix_ms > 0)?;
        match &self.details {
            GrantDetails::Egress {
                floor,
                name,
                virtual_port,
                alias_generation,
                ..
            } => field(
                family == 3
                    && !floor.is_empty()
                    && floor.len() <= MAX_TEXT_BYTES
                    && !name.is_empty()
                    && name.len() <= MAX_TEXT_BYTES
                    && *virtual_port > 0
                    && alias_generation.is_none_or(|value| value > 0),
            ),
            GrantDetails::Exit(publication) => {
                field(family == 4)?;
                publication.canonical()?;
                let [route] = publication.routes.as_slice() else {
                    return Err(GrantError::Scope);
                };
                if route.resource != self.resource
                    || route.client != *self.client.as_bytes()
                    || route.provider != *self.provider.as_bytes()
                {
                    return Err(GrantError::Scope);
                }
                Ok(())
            }
        }
    }

    fn write(&self, out: &mut CborWriter) -> Result<(), GrantError> {
        out.array(7);
        write_reference(&self.resource, out)?;
        out.bytes(self.client.as_bytes())
            .bytes(self.provider.as_bytes());
        write_payers(&self.payers, out);
        out.bytes(&self.incarnation.0).uint(self.expires_at_unix_ms);
        match &self.details {
            GrantDetails::Egress {
                floor,
                name,
                protocol,
                virtual_port,
                alias_generation,
            } => {
                out.array(6)
                    .uint(0)
                    .text(floor)
                    .text(name)
                    .uint(*protocol as u64)
                    .uint(u64::from(*virtual_port));
                if let Some(value) = alias_generation {
                    out.array(1).uint(*value);
                } else {
                    out.null();
                }
            }
            GrantDetails::Exit(publication) => {
                out.array(2).uint(1).bytes(&publication.canonical()?);
            }
        }
        Ok(())
    }

    fn read(input: &mut CborReader<'_>, family: u64) -> Result<Self, GrantError> {
        input.array(7)?;
        let resource = read_reference(input)?;
        let client = identity(input)?;
        let provider = identity(input)?;
        let payers = read_payers(input)?;
        let incarnation = GrantIncarnation(input.fixed_bytes()?);
        let expires_at_unix_ms = input.uint()?;
        let details = match family {
            3 => {
                input.array(6)?;
                field(input.uint()? == 0)?;
                let floor = input.text_up_to(MAX_TEXT_BYTES)?.to_owned();
                let name = input.text_up_to(MAX_TEXT_BYTES)?.to_owned();
                let protocol = match input.uint()? {
                    6 => TransportProtocol::Tcp,
                    17 => TransportProtocol::Udp,
                    _ => return Err(GrantError::Field),
                };
                let virtual_port = u16::try_from(input.uint()?).map_err(|_| GrantError::Field)?;
                let alias_generation = if input.take_null() {
                    None
                } else {
                    input.array(1)?;
                    Some(input.uint()?)
                };
                GrantDetails::Egress {
                    floor,
                    name,
                    protocol,
                    virtual_port,
                    alias_generation,
                }
            }
            4 => {
                input.array(2)?;
                field(input.uint()? == 1)?;
                GrantDetails::Exit(SubnetPublication::decode(input.bytes_up_to(MAX_BYTES)?)?)
            }
            _ => return Err(GrantError::Field),
        };
        let value = Self {
            resource,
            client,
            provider,
            payers,
            incarnation,
            expires_at_unix_ms,
            details,
        };
        value.validate(family)?;
        Ok(value)
    }
}

/// Complete provider-recipient grant publication for one authenticated scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantPublication {
    /// Registry family 3 (Egress) or 4 (Exit).
    pub family: u64,
    /// Authenticated issuing identity.
    pub issuer: IdentityKey,
    /// Provider receiving these grants.
    pub recipient: IdentityKey,
    /// Positive complete replacement revision.
    pub revision: u64,
    /// Strictly ordered resource/client/discriminator grants; empty withdraws this scope.
    pub grants: Vec<ServiceGrant>,
}

impl GrantPublication {
    fn validate(&self) -> Result<(), GrantError> {
        field(matches!(self.family, 3 | 4) && self.revision > 0)?;
        if self.grants.len() > MAX_IDENTITIES {
            return Err(GrantError::Bounds);
        }
        if !self.grants.windows(2).all(|p| {
            (&p[0].resource, p[0].client, p[0].details.discriminator())
                < (&p[1].resource, p[1].client, p[1].details.discriminator())
        }) {
            return Err(GrantError::Ordering);
        }
        unique_tokens(self.grants.iter().map(|g| (&g.resource, g.incarnation.0)))?;
        for grant in &self.grants {
            if grant.provider != self.recipient {
                return Err(GrantError::Scope);
            }
            grant.validate(self.family)?;
        }
        Ok(())
    }

    /// Encodes exact fields without normalization.
    ///
    /// # Errors
    /// Refuses invalid scope, cardinality, ordering, fields or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, GrantError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(6)
            .uint(SCHEMA)
            .uint(self.family)
            .bytes(self.issuer.as_bytes())
            .bytes(self.recipient.as_bytes())
            .uint(self.revision)
            .array(self.grants.len());
        for grant in &self.grants {
            grant.write(&mut out)?;
        }
        checked_bytes(out)
    }

    /// Decodes a complete canonical service grant publication.
    ///
    /// # Errors
    /// Refuses malformed bytes and invalid authority fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(6)?;
        field(input.uint()? == SCHEMA)?;
        let family = input.uint()?;
        field(matches!(family, 3 | 4))?;
        let issuer = identity(&mut input)?;
        let recipient = identity(&mut input)?;
        let revision = input.uint()?;
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let grants = (0..count)
            .map(|_| ServiceGrant::read(&mut input, family))
            .collect::<Result<_, _>>()?;
        input.finish()?;
        let value = Self {
            family,
            issuer,
            recipient,
            revision,
            grants,
        };
        value.validate()?;
        Ok(value)
    }

    /// Checks replacement against complete previous content and retained retirements.
    ///
    /// # Errors
    /// Refuses scope/revision mismatch, retired tokens and changed-content token reuse.
    pub fn validate_successor(
        &self,
        previous: &Self,
        retired: &[RetiredGrant],
    ) -> Result<(), GrantError> {
        self.canonical()?;
        previous.canonical()?;
        if self.family != previous.family
            || self.issuer != previous.issuer
            || self.recipient != previous.recipient
            || self.revision <= previous.revision
        {
            return Err(GrantError::Scope);
        }
        for grant in &self.grants {
            if retired
                .iter()
                .any(|old| old.resource == grant.resource && old.incarnation == grant.incarnation.0)
            {
                return Err(GrantError::RetiredIncarnation);
            }
            if previous.grants.iter().any(|old| {
                if old.resource != grant.resource || old.incarnation != grant.incarnation {
                    return false;
                }
                let mut renewed = old.clone();
                renewed.expires_at_unix_ms = grant.expires_at_unix_ms;
                grant.expires_at_unix_ms < old.expires_at_unix_ms || renewed != *grant
            }) {
                return Err(GrantError::ReusedIncarnation);
            }
        }
        Ok(())
    }
}
