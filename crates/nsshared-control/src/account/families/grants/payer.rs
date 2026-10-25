//! Explicit payers and payer bindings of service grants.

use crate::{
    account::MAX_BYTES, account::MAX_IDENTITIES, account::SCHEMA, account::codec::identity,
    account::grants::grant::GrantDiscriminator, account::grants::grant::GrantError,
    account::grants::grant::GrantPublication, account::grants::grant::checked_bytes,
    account::grants::grant::field, account::grants::grant::read_reference,
    account::grants::grant::unique_tokens, account::grants::grant::write_reference,
    account::node::GrantIncarnation, service::ServiceRef,
};
use nsshared_identity::realm::RealmId;

use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// Explicit paying realm and realm-local UserId; neither component is an identity key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payer {
    /// Paying realm's binary identifier.
    pub realm: RealmId,
    /// Realm-local UserId, unsigned big-endian ULID bytes.
    pub subject: [u8; 16],
}

pub(in crate::account) fn payer(values: &[Payer]) -> Result<&Payer, GrantError> {
    match values {
        [] => Err(GrantError::MissingPayer),
        [value] => Ok(value),
        _ => Err(GrantError::AmbiguousPayer),
    }
}

pub(in crate::account) fn write_payers(values: &[Payer], out: &mut CborWriter) {
    out.array(values.len());
    for value in values {
        out.array(2)
            .bytes(value.realm.as_bytes())
            .bytes(&value.subject);
    }
}

pub(in crate::account) fn read_payers(
    input: &mut CborReader<'_>,
) -> Result<Vec<Payer>, GrantError> {
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
    /// Exact protocol or Exit identity.
    pub discriminator: GrantDiscriminator,
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
    /// Strict resource/client/discriminator order.
    pub bindings: Vec<PayerBinding>,
}

impl PayerBindings {
    /// Joins exact protocol-qualified grants, lifetimes and historical payer pairs.
    ///
    /// # Errors
    /// Refuses invalid inputs, scope differences and missing or differing bindings.
    pub fn validate_grants(&self, grants: &GrantPublication) -> Result<(), GrantError> {
        self.canonical()?;
        grants.canonical()?;
        if self.issuer != grants.issuer || self.recipient != grants.recipient {
            return Err(GrantError::Scope);
        }
        for grant in &grants.grants {
            if !self.bindings.iter().any(|binding| {
                binding.resource == grant.resource
                    && binding.client == grant.client
                    && binding.discriminator == grant.details.discriminator()
                    && binding.incarnation == grant.incarnation
                    && binding.payers == grant.payers
            }) {
                return Err(GrantError::Scope);
            }
        }
        Ok(())
    }

    /// Encodes a complete payer assignment set.
    ///
    /// # Errors
    /// Refuses cardinality, ordering, revision or size violations.
    pub fn canonical(&self) -> Result<Vec<u8>, GrantError> {
        field(self.revision > 0)?;
        if self.bindings.len() > MAX_IDENTITIES {
            return Err(GrantError::Bounds);
        }
        if !self.bindings.windows(2).all(|p| {
            (&p[0].resource, p[0].client, p[0].discriminator)
                < (&p[1].resource, p[1].client, p[1].discriminator)
        }) {
            return Err(GrantError::Ordering);
        }
        unique_tokens(self.bindings.iter().map(|b| (&b.resource, b.incarnation.0)))?;
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
            out.array(5);
            write_reference(&binding.resource, &mut out)?;
            out.bytes(binding.client.as_bytes())
                .bytes(&binding.incarnation.0);
            write_payers(&binding.payers, &mut out);
            binding.discriminator.write(&mut out);
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
            input.array(5)?;
            bindings.push(PayerBinding {
                resource: read_reference(&mut input)?,
                client: identity(&mut input)?,
                incarnation: GrantIncarnation(input.fixed_bytes()?),
                payers: read_payers(&mut input)?,
                discriminator: GrantDiscriminator::read(&mut input)?,
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
