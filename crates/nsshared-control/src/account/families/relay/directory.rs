//! NSD-signed eligibility alongside the unchanged global relay directory.

use crate::{
    account::AccountError, account::MAX_BYTES, account::MAX_IDENTITIES, account::codec::ascending,
    account::codec::identity, account::codec::reader, account::codec::realm,
    account::codec::require,
};
use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::{keys::IdentityKey, realm::RealmId};

/// Domain separation from rosters, publications and connection proofs.
pub const DIRECTORY_BINDING_DOMAIN: &[u8] = b"ns.account.directory-binding.v1\0";

/// Invalid content grants no new eligibility and never represents withdrawal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BindingError {
    /// Invalid canonical fields, CBOR or bounds.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Wrong issuer, selected directory id, owner or supplied retained state.
    #[error("directory binding authority mismatch")]
    Authority,
    /// Lower version or changed equal version, including replay after restart.
    #[error("stale or changed directory binding version")]
    Stale,
    /// Future issue or expired exclusive deadline.
    #[error("directory binding outside signed lifetime")]
    Time,
    /// Invalid domain-separated signature.
    #[error("invalid directory binding signature")]
    Signature,
}
crate::account::contract_error!(BindingError);

/// Complete NSD ownership and eligible realm set for one permanent numeric id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryBinding {
    /// Trusted NSD public identity.
    pub issuer: IdentityKey,
    /// Positive numeric RelayEntry.id, never the endpoint RelayId.
    pub relay_id: u16,
    /// Independent enrolled participant owning this directory id.
    pub participant: IdentityKey,
    /// Complete canonical set in strictly increasing RealmId order; empty withdraws all.
    pub realms: Vec<RealmId>,
    /// Positive monotonic version per issuer/relay id.
    pub version: u64,
    /// Signed Unix-millisecond issue instant.
    pub issued_at_unix_ms: u64,
    /// Exclusive signed Unix-millisecond expiry.
    pub expires_at_unix_ms: u64,
}
impl DirectoryBinding {
    /// Exact canonical content for domain-separated signing.
    /// # Errors
    /// Refuses zero id/version, unordered/duplicate realms, invalid lifetime and bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, BindingError> {
        require(
            self.relay_id > 0
                && self.version > 0
                && self.expires_at_unix_ms > self.issued_at_unix_ms,
        )?;
        if self.realms.len() > MAX_IDENTITIES {
            return Err(AccountError::Bounds.into());
        }
        require(ascending(&self.realms))?;
        let mut out = CborWriter::default();
        out.array(8)
            .uint(1)
            .bytes(self.issuer.as_bytes())
            .uint(u64::from(self.relay_id))
            .bytes(self.participant.as_bytes())
            .array(self.realms.len());
        for realm in &self.realms {
            out.text(&realm.to_string());
        }
        out.uint(self.version)
            .uint(self.issued_at_unix_ms)
            .uint(self.expires_at_unix_ms);
        Ok(crate::account::codec::bounded(out.into_bytes())?)
    }
    /// Decode bounded canonical content without trusting the self-presented issuer.
    /// # Errors
    /// Refuses invalid keys, ids, realm text/order, lifetime, version and extra fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, BindingError> {
        let mut input = reader(bytes, 8)?;
        let issuer = identity(&mut input)?;
        let relay_id = u16::try_from(input.uint()?).map_err(|_| AccountError::Field)?;
        let participant = identity(&mut input)?;
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let mut realms = Vec::with_capacity(count);
        for _ in 0..count {
            realms.push(realm(&mut input)?);
        }
        let value = Self {
            issuer,
            relay_id,
            participant,
            realms,
            version: input.uint()?,
            issued_at_unix_ms: input.uint()?,
            expires_at_unix_ms: input.uint()?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Signed separate record; decoding alone does not establish eligibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedDirectoryBinding {
    /// Complete signed ownership facts.
    pub content: DirectoryBinding,
    /// Ed25519 signature covering every field.
    pub signature: [u8; 64],
}

/// Installation outcome. The caller persists the scoped floor before replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingDecision {
    /// Replace the complete owner/set and advance the floor, including empty withdrawal.
    Replace,
    /// Exact accepted record repeated; keep its original deadlines unchanged.
    Idempotent,
}
impl SignedDirectoryBinding {
    /// Domain followed by canonical content, with no unsigned fields.
    /// # Errors
    /// Refuses invalid constructed content.
    pub fn signing_input(&self) -> Result<Vec<u8>, BindingError> {
        let mut bytes = DIRECTORY_BINDING_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.content.canonical()?);
        Ok(bytes)
    }
    /// Exact signed carrier within the shared bound.
    /// # Errors
    /// Refuses invalid content or oversized carrier.
    pub fn canonical(&self) -> Result<Vec<u8>, BindingError> {
        let mut out = CborWriter::default();
        out.array(2)
            .bytes(&self.content.canonical()?)
            .bytes(&self.signature);
        Ok(crate::account::codec::bounded(out.into_bytes())?)
    }
    /// Exact canonical signed carrier, without accepting its issuer.
    /// # Errors
    /// Refuses malformed, nonminimal, extended or oversized bytes and invalid content.
    pub fn decode(bytes: &[u8]) -> Result<Self, BindingError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(2)?;
        let content = DirectoryBinding::decode(input.bytes_up_to(MAX_BYTES)?)?;
        let signature = input.fixed_bytes()?;
        input.finish()?;
        Ok(Self { content, signature })
    }
    fn authenticate(
        &self,
        issuer: IdentityKey,
        relay_id: u16,
        now_ms: u64,
    ) -> Result<(), BindingError> {
        if self.content.issuer != issuer || self.content.relay_id != relay_id {
            return Err(BindingError::Authority);
        }
        let input = self.signing_input()?;
        VerifyingKey::from_bytes(issuer.as_bytes())
            .map_err(|_| BindingError::Signature)?
            .verify_strict(&input, &Signature::from_bytes(&self.signature))
            .map_err(|_| BindingError::Signature)?;
        if now_ms < self.content.issued_at_unix_ms || now_ms >= self.content.expires_at_unix_ms {
            return Err(BindingError::Time);
        }
        Ok(())
    }
    /// Verify trust, selected id, signature, supplied time and scoped persisted floor.
    /// A floor alone never permits equal replay; exact retained accepted bytes are required.
    /// # Errors
    /// Refuses authority/time/signature mismatch, stale versions and inconsistent retained state.
    pub fn verify(
        &self,
        issuer: IdentityKey,
        relay_id: u16,
        floor: u64,
        previous: Option<&Self>,
        now_ms: u64,
    ) -> Result<BindingDecision, BindingError> {
        self.authenticate(issuer, relay_id, now_ms)?;
        if let Some(previous) = previous
            && (previous.content.issuer != issuer
                || previous.content.relay_id != relay_id
                || previous.content.version != floor)
        {
            return Err(BindingError::Authority);
        }
        if self.content.version > floor {
            return Ok(BindingDecision::Replace);
        }
        if self.content.version == floor && previous == Some(self) {
            return Ok(BindingDecision::Idempotent);
        }
        Err(BindingError::Stale)
    }
    /// Query signed association for a selected entry, owner and authenticated realm.
    /// Caller first accepts this record with verify and its persisted floor.
    /// # Errors
    /// Refuses wrong issuer/id/owner, invalid signature or time; absent realms return false.
    pub fn eligible(
        &self,
        issuer: IdentityKey,
        relay_id: u16,
        participant: IdentityKey,
        realm: RealmId,
        now_ms: u64,
    ) -> Result<bool, BindingError> {
        self.authenticate(issuer, relay_id, now_ms)?;
        if self.content.participant != participant {
            return Err(BindingError::Authority);
        }
        Ok(self.content.realms.binary_search(&realm).is_ok())
    }
}
