use crate::{
    account::AccountError, account::MAX_IDENTITIES, account::SCHEMA, account::codec::ascending,
    account::codec::ascending_by, account::codec::bounded, account::codec::identity,
    account::codec::reader, account::codec::require,
};
use nsshared_codec::cbor::CborWriter;
use nsshared_identity::keys::IdentityKey;

/// Authorized L4 transport protocol. No implicit protocol wildcard exists.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u64)]
pub enum TransportProtocol {
    /// TCP (IP protocol 6).
    Tcp = 6,
    /// UDP (IP protocol 17).
    Udp = 17,
}

impl TransportProtocol {
    fn read(value: u64) -> Result<Self, AccountError> {
        match value {
            6 => Ok(Self::Tcp),
            17 => Ok(Self::Udp),
            _ => Err(AccountError::Field),
        }
    }
}

/// Complete identity scope for one authority-assigned namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L3Scope {
    /// Opaque namespace identifier, independent of local interface names.
    pub namespace: [u8; 16],
    /// Full identity set in strictly increasing byte order.
    pub identities: Vec<IdentityKey>,
}

/// One explicit allow rule; overlapping ranges mean set union.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct L3Rule {
    /// Namespace whose identity scope contains both endpoints.
    pub namespace: [u8; 16],
    /// Source full identity.
    pub source: IdentityKey,
    /// Destination full identity.
    pub destination: IdentityKey,
    /// TCP or UDP.
    pub protocol: TransportProtocol,
    /// Inclusive first destination port, nonzero.
    pub first_port: u16,
    /// Inclusive last destination port, at least first_port.
    pub last_port: u16,
}

/// Normalized Node L3 input. Policy compilation stays in consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeL3 {
    /// Authenticated authority.
    pub issuer: IdentityKey,
    /// Node receiving the complete input.
    pub recipient: IdentityKey,
    /// Positive complete replacement revision in this issuer/recipient scope.
    pub revision: u64,
    /// Namespace scopes, strictly sorted by namespace.
    pub scopes: Vec<L3Scope>,
    /// Rules sorted lexicographically by all their fields, without duplicates.
    pub rules: Vec<L3Rule>,
}

impl NodeL3 {
    fn validate(&self) -> Result<(), AccountError> {
        require(self.revision > 0)?;
        require(self.scopes.len() <= MAX_IDENTITIES && self.rules.len() <= MAX_IDENTITIES)?;
        require(ascending_by(&self.scopes, |value| &value.namespace))?;
        for scope in &self.scopes {
            require(scope.identities.len() <= MAX_IDENTITIES)?;
            require(ascending(&scope.identities))?;
        }
        require(ascending(&self.rules))?;
        for rule in &self.rules {
            require(rule.first_port > 0 && rule.first_port <= rule.last_port)?;
            let index = self
                .scopes
                .binary_search_by_key(&rule.namespace, |scope| scope.namespace)
                .map_err(|_| AccountError::Field)?;
            let scope = &self.scopes[index];
            require(
                scope.identities.binary_search(&rule.source).is_ok()
                    && scope.identities.binary_search(&rule.destination).is_ok(),
            )?;
        }
        Ok(())
    }

    /// Encodes the exact normalized scopes and rules.
    ///
    /// # Errors
    /// Rejects invalid ports, scope membership, ordering, bounds or duplicates.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(6)
            .uint(SCHEMA)
            .bytes(self.issuer.as_bytes())
            .bytes(self.recipient.as_bytes())
            .uint(self.revision)
            .array(self.scopes.len());
        for scope in &self.scopes {
            out.array(2)
                .bytes(&scope.namespace)
                .array(scope.identities.len());
            for identity in &scope.identities {
                out.bytes(identity.as_bytes());
            }
        }
        out.array(self.rules.len());
        for rule in &self.rules {
            out.array(6)
                .bytes(&rule.namespace)
                .bytes(rule.source.as_bytes())
                .bytes(rule.destination.as_bytes())
                .uint(rule.protocol as u64)
                .uint(u64::from(rule.first_port))
                .uint(u64::from(rule.last_port));
        }
        bounded(out.into_bytes())
    }

    /// Decodes one complete canonical L3 input without compiling host policy.
    ///
    /// # Errors
    /// Rejects malformed CBOR or any invalid normalized field or scope.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 6)?;
        let issuer = identity(&mut input)?;
        let recipient = identity(&mut input)?;
        let revision = input.uint()?;
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let mut scopes = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(2)?;
            let namespace = input.fixed_bytes()?;
            let count = input.array_up_to(MAX_IDENTITIES)?;
            let mut identities = Vec::with_capacity(count);
            for _ in 0..count {
                identities.push(identity(&mut input)?);
            }
            scopes.push(L3Scope {
                namespace,
                identities,
            });
        }
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let mut rules = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(6)?;
            rules.push(L3Rule {
                namespace: input.fixed_bytes()?,
                source: identity(&mut input)?,
                destination: identity(&mut input)?,
                protocol: TransportProtocol::read(input.uint()?)?,
                first_port: u16::try_from(input.uint()?).map_err(|_| AccountError::Field)?,
                last_port: u16::try_from(input.uint()?).map_err(|_| AccountError::Field)?,
            });
        }
        input.finish()?;
        let value = Self {
            issuer,
            recipient,
            revision,
            scopes,
            rules,
        };
        value.validate()?;
        Ok(value)
    }
}
