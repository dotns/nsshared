//! Resource authority: active grant claims, retired incarnations, withdrawal and regrant.

use crate::{
    account::MAX_BYTES, account::MAX_IDENTITIES, account::SCHEMA, account::codec::ascending,
    account::codec::identity, account::grants::grant::GrantDiscriminator,
    account::grants::grant::GrantError, account::grants::grant::GrantPublication,
    account::grants::grant::checked_bytes, account::grants::grant::field,
    account::grants::grant::read_reference, account::grants::grant::unique_tokens,
    account::grants::grant::write_reference, service::ServiceRef,
};

use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// Active client/resource claim, independent of grant content.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GrantClaim {
    /// Full resource scope.
    pub resource: ServiceRef,
    /// Full client.
    pub client: IdentityKey,
    /// Exact protocol or Exit identity.
    pub discriminator: GrantDiscriminator,
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
    /// Current claims in strict resource/client/discriminator order.
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
                discriminator: grant.details.discriminator(),
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
        if !self.active.windows(2).all(|p| {
            (&p[0].resource, p[0].client, p[0].discriminator)
                < (&p[1].resource, p[1].client, p[1].discriminator)
        }) || !ascending(&self.retired)
        {
            return Err(GrantError::Ordering);
        }
        unique_tokens(self.active.iter().map(|c| (&c.resource, c.incarnation)))?;
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
            out.array(4);
            write_reference(&claim.resource, &mut out)?;
            out.bytes(claim.client.as_bytes()).bytes(&claim.incarnation);
            claim.discriminator.write(&mut out);
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
            input.array(4)?;
            active.push(GrantClaim {
                resource: read_reference(&mut input)?,
                client: identity(&mut input)?,
                incarnation: input.fixed_bytes()?,
                discriminator: GrantDiscriminator::read(&mut input)?,
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
            if self.active.iter().any(|claim| {
                claim.resource == old.resource
                    && claim.incarnation == old.incarnation
                    && claim != old
            }) {
                return Err(GrantError::ReusedIncarnation);
            }
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
