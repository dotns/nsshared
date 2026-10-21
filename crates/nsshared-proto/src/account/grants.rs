//! Pure service authority payloads; installation and history custody stay in consumers.

use crate::RealmId;

use nsshared_service_control::ServiceRef;
use thiserror::Error;

use super::{
    AccountError, GrantIncarnation, MAX_BYTES, MAX_IDENTITIES, SCHEMA, SubnetError,
    SubnetPublication, TransportProtocol, identity,
};
use crate::{
    IdentityKey,
    encoding::{CborError, CborReader, CborWriter},
};

/// Typed refusal of candidate service authority.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GrantError {
    /// Strict CBOR refusal.
    #[error(transparent)]
    Encoding(#[from] CborError),
    /// Invalid full identity or normalized Node policy.
    #[error(transparent)]
    Policy(#[from] AccountError),
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

/// Explicit paying realm and realm-local UserId; neither component is an identity key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payer {
    /// Paying realm's binary identifier.
    pub realm: RealmId,
    /// Realm-local UserId, unsigned big-endian ULID bytes.
    pub subject: [u8; 16],
}

fn payer(values: &[Payer]) -> Result<&Payer, GrantError> {
    match values {
        [] => Err(GrantError::MissingPayer),
        [value] => Ok(value),
        _ => Err(GrantError::AmbiguousPayer),
    }
}

fn write_payers(values: &[Payer], out: &mut CborWriter) {
    out.array(values.len());
    for value in values {
        out.array(2)
            .bytes(value.realm.as_bytes())
            .bytes(&value.subject);
    }
}

fn read_payers(input: &mut CborReader<'_>) -> Result<Vec<Payer>, GrantError> {
    let count = input.array_up_to(MAX_IDENTITIES)?;
    // Refuse cardinality before decoding values, without choosing or deduplicating a payer.
    if count == 0 {
        return Err(GrantError::MissingPayer);
    }
    if count != 1 {
        return Err(GrantError::AmbiguousPayer);
    }
    input.array(2)?;
    Ok(vec![Payer {
        realm: RealmId::from_bytes(input.fixed_bytes()?),
        subject: input.fixed_bytes()?,
    }])
}

pub(super) fn write_reference(value: &ServiceRef, out: &mut CborWriter) -> Result<(), GrantError> {
    let bytes = nsshared_service_control::encode_canonical(&value.value())
        .map_err(|_| GrantError::Reference)?;
    out.bytes(&bytes);
    Ok(())
}

pub(super) fn read_reference(input: &mut CborReader<'_>) -> Result<ServiceRef, GrantError> {
    let value = nsshared_service_control::decode_canonical(input.bytes_up_to(MAX_BYTES)?)
        .map_err(|_| GrantError::Reference)?;
    ServiceRef::from_value(&value).map_err(|_| GrantError::Reference)
}

pub(super) fn checked_bytes(out: CborWriter) -> Result<Vec<u8>, GrantError> {
    let bytes = out.into_bytes();
    if bytes.len() > MAX_BYTES {
        Err(GrantError::Bounds)
    } else {
        Ok(bytes)
    }
}

fn field(condition: bool) -> Result<(), GrantError> {
    if condition {
        Ok(())
    } else {
        Err(GrantError::Field)
    }
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
                    && floor.len() <= 256
                    && !name.is_empty()
                    && name.len() <= 256
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
                let floor = input.text_up_to(256)?.to_owned();
                let name = input.text_up_to(256)?.to_owned();
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
    /// Strictly ordered resource/client grants; empty withdraws this scope.
    pub grants: Vec<ServiceGrant>,
}

impl GrantPublication {
    fn validate(&self) -> Result<(), GrantError> {
        field(matches!(self.family, 3 | 4) && self.revision > 0)?;
        if self.grants.len() > MAX_IDENTITIES {
            return Err(GrantError::Bounds);
        }
        if !self
            .grants
            .windows(2)
            .all(|p| (&p[0].resource, p[0].client) < (&p[1].resource, p[1].client))
        {
            return Err(GrantError::Ordering);
        }
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
                old.resource == grant.resource
                    && old.client == grant.client
                    && old != grant
                    && old.incarnation == grant.incarnation
            }) {
                return Err(GrantError::ReusedIncarnation);
            }
        }
        Ok(())
    }
}

/// One resource/client/incarnation payer assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayerBinding {
    /// Full M6 resource reference.
    pub resource: ServiceRef,
    /// Authorized client.
    pub client: IdentityKey,
    /// Exact grant lifetime.
    pub incarnation: GrantIncarnation,
    /// Exactly one explicit realm-local payer.
    pub payers: Vec<Payer>,
}

/// Complete payer assignments; this payload alone grants no service access.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayerBindings {
    /// Issuing authority.
    pub issuer: IdentityKey,
    /// Provider recipient.
    pub recipient: IdentityKey,
    /// Positive replacement revision.
    pub revision: u64,
    /// Strict resource/client order.
    pub bindings: Vec<PayerBinding>,
}

impl PayerBindings {
    /// Encodes a complete payer assignment set.
    ///
    /// # Errors
    /// Refuses cardinality, ordering, revision or size violations.
    pub fn canonical(&self) -> Result<Vec<u8>, GrantError> {
        field(self.revision > 0)?;
        if self.bindings.len() > MAX_IDENTITIES {
            return Err(GrantError::Bounds);
        }
        if !self
            .bindings
            .windows(2)
            .all(|p| (&p[0].resource, p[0].client) < (&p[1].resource, p[1].client))
        {
            return Err(GrantError::Ordering);
        }
        let mut out = CborWriter::default();
        out.array(6)
            .uint(SCHEMA)
            .uint(5)
            .bytes(self.issuer.as_bytes())
            .bytes(self.recipient.as_bytes())
            .uint(self.revision)
            .array(self.bindings.len());
        for binding in &self.bindings {
            payer(&binding.payers)?;
            out.array(4);
            write_reference(&binding.resource, &mut out)?;
            out.bytes(binding.client.as_bytes())
                .bytes(&binding.incarnation.0);
            write_payers(&binding.payers, &mut out);
        }
        checked_bytes(out)
    }

    /// Decodes exact binary UserId payer pairs.
    ///
    /// # Errors
    /// Refuses malformed or ambiguous assignments.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(6)?;
        field(input.uint()? == SCHEMA && input.uint()? == 5)?;
        let issuer = identity(&mut input)?;
        let recipient = identity(&mut input)?;
        let revision = input.uint()?;
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let mut bindings = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(4)?;
            bindings.push(PayerBinding {
                resource: read_reference(&mut input)?,
                client: identity(&mut input)?,
                incarnation: GrantIncarnation(input.fixed_bytes()?),
                payers: read_payers(&mut input)?,
            });
        }
        input.finish()?;
        let value = Self {
            issuer,
            recipient,
            revision,
            bindings,
        };
        value.canonical()?;
        Ok(value)
    }
}

/// Active client/resource claim, independent of grant content.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GrantClaim {
    /// Full resource scope.
    pub resource: ServiceRef,
    /// Full client.
    pub client: IdentityKey,
    /// Active lifetime token.
    pub incarnation: [u8; 16],
}

/// Retired token for one resource, across all clients.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetiredGrant {
    /// Full resource scope.
    pub resource: ServiceRef,
    /// Irrevocably retired token.
    pub incarnation: [u8; 16],
}

/// Caller-owned authority snapshot; validation owns no mutable lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceAuthority {
    /// Authenticated issuer.
    pub issuer: IdentityKey,
    /// Exact provider recipient.
    pub recipient: IdentityKey,
    /// Positive complete replacement revision.
    pub revision: u64,
    /// Current claims in strict resource/client order.
    pub active: Vec<GrantClaim>,
    /// Retained strictly ordered retirement history.
    pub retired: Vec<RetiredGrant>,
}

impl ResourceAuthority {
    /// Joins a service publication to this snapshot's exact active claims.
    ///
    /// # Errors
    /// Refuses invalid input, mismatched authority or any absent client/resource/token.
    pub fn validate_grants(&self, grants: &GrantPublication) -> Result<(), GrantError> {
        self.canonical()?;
        grants.canonical()?;
        if self.issuer != grants.issuer || self.recipient != grants.recipient {
            return Err(GrantError::Scope);
        }
        for grant in &grants.grants {
            if !self.active.contains(&GrantClaim {
                resource: grant.resource,
                client: grant.client,
                incarnation: grant.incarnation.0,
            }) {
                return Err(GrantError::Scope);
            }
        }
        Ok(())
    }

    /// Encodes current claims and retained retired tokens.
    ///
    /// # Errors
    /// Refuses retired claims, invalid ordering, revision and bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, GrantError> {
        field(self.revision > 0)?;
        if self.active.len() > MAX_IDENTITIES || self.retired.len() > MAX_IDENTITIES {
            return Err(GrantError::Bounds);
        }
        if !self
            .active
            .windows(2)
            .all(|p| (&p[0].resource, p[0].client) < (&p[1].resource, p[1].client))
            || !self.retired.windows(2).all(|p| p[0] < p[1])
        {
            return Err(GrantError::Ordering);
        }
        let mut out = CborWriter::default();
        out.array(7)
            .uint(SCHEMA)
            .uint(6)
            .bytes(self.issuer.as_bytes())
            .bytes(self.recipient.as_bytes())
            .uint(self.revision)
            .array(self.active.len());
        for claim in &self.active {
            if self
                .retired
                .iter()
                .any(|r| r.resource == claim.resource && r.incarnation == claim.incarnation)
            {
                return Err(GrantError::RetiredIncarnation);
            }
            out.array(3);
            write_reference(&claim.resource, &mut out)?;
            out.bytes(claim.client.as_bytes()).bytes(&claim.incarnation);
        }
        out.array(self.retired.len());
        for old in &self.retired {
            out.array(2);
            write_reference(&old.resource, &mut out)?;
            out.bytes(&old.incarnation);
        }
        checked_bytes(out)
    }

    /// Decodes a present canonical resource authority snapshot.
    ///
    /// # Errors
    /// Refuses malformed snapshots and active retired tokens.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(7)?;
        field(input.uint()? == SCHEMA && input.uint()? == 6)?;
        let issuer = identity(&mut input)?;
        let recipient = identity(&mut input)?;
        let revision = input.uint()?;
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let mut active = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(3)?;
            active.push(GrantClaim {
                resource: read_reference(&mut input)?,
                client: identity(&mut input)?,
                incarnation: input.fixed_bytes()?,
            });
        }
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let mut retired = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(2)?;
            retired.push(RetiredGrant {
                resource: read_reference(&mut input)?,
                incarnation: input.fixed_bytes()?,
            });
        }
        input.finish()?;
        let value = Self {
            issuer,
            recipient,
            revision,
            active,
            retired,
        };
        value.canonical()?;
        Ok(value)
    }

    /// Validates a replacement without mutating or persisting either snapshot.
    ///
    /// # Errors
    /// Refuses scope/revision mismatch, lost history and unretired removed claims.
    pub fn validate_successor(&self, previous: &Self) -> Result<(), GrantError> {
        self.canonical()?;
        previous.canonical()?;
        if self.issuer != previous.issuer
            || self.recipient != previous.recipient
            || self.revision <= previous.revision
        {
            return Err(GrantError::Scope);
        }
        if previous
            .retired
            .iter()
            .any(|old| self.retired.binary_search(old).is_err())
        {
            return Err(GrantError::History);
        }
        for old in &previous.active {
            if !self.active.contains(old)
                && !self.retired.contains(&RetiredGrant {
                    resource: old.resource,
                    incarnation: old.incarnation,
                })
            {
                return Err(GrantError::History);
            }
        }
        Ok(())
    }
}
