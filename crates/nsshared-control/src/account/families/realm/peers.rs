//! Complete membership content; enclosing publication authority stays external.

use crate::{
    account::AccountError, account::MAX_IDENTITIES, account::SCHEMA, account::codec::ascending_by,
    account::codec::bounded, account::codec::realm, account::codec::require,
    account::node::NodeBinding,
};
use nsshared_identity::realm::RealmId;

use std::collections::BTreeSet;

use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::{constants::MAX_NODE_RECORD_BYTES, record::NodeRecord};

/// Maximum contributing realms in one authenticated collection.
pub const MAX_PEER_REALMS: usize = 256;
/// Maximum encoded diagnostic counter content.
pub const MAX_POLICY_VERSION_BYTES: usize = 13;

/// One authorized membership binding and its existing signed Node record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmMember {
    /// Versioned membership identity and authorized transport key.
    pub binding: NodeBinding,
    /// Signed record matching the binding's I, K and generation.
    pub record: NodeRecord,
}

/// Complete members of a contributing served realm, including an empty realm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmContribution {
    /// Contributing realm identity, independent of the enclosing authority scope.
    pub realm: RealmId,
    /// Strict full-identity order within this realm.
    pub members: Vec<RealmMember>,
}

/// Complete replacement within one independently authenticated publication key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmPeers {
    /// Strict realm byte order; empty withdraws this collection.
    pub realms: Vec<RealmContribution>,
}

impl RealmPeers {
    fn validate(&self) -> Result<(), AccountError> {
        if self.realms.len() > MAX_PEER_REALMS {
            return Err(AccountError::Bounds);
        }
        require(ascending_by(&self.realms, |value| &value.realm))?;
        let mut identities = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut total = 0usize;
        for realm in &self.realms {
            if realm.members.len() > MAX_IDENTITIES - total {
                return Err(AccountError::Bounds);
            }
            total += realm.members.len();
            require(
                realm
                    .members
                    .windows(2)
                    .all(|v| v[0].binding.identity < v[1].binding.identity),
            )?;
            for member in &realm.members {
                let binding = &member.binding;
                binding.validate()?;
                require(identities.insert(binding.identity) && keys.insert(binding.wg_key))?;
                require(
                    binding.identity.as_bytes() == member.record.identity()
                        && binding.wg_key == *member.record.wg_key()
                        && binding.generation.0 == member.record.generation(),
                )?;
            }
        }
        Ok(())
    }

    /// Validates content and each record's exclusive expiry at caller time.
    ///
    /// # Errors
    /// Refuses invalid collections and expired records without renewing state.
    pub fn validate_at(&self, now_seconds: u64) -> Result<(), AccountError> {
        self.validate()?;
        for realm in &self.realms {
            for member in &realm.members {
                member
                    .record
                    .check_not_expired(now_seconds)
                    .map_err(|_| AccountError::Authority)?;
            }
        }
        Ok(())
    }

    /// Encodes the complete collection without a duplicate enclosing scope.
    ///
    /// # Errors
    /// Refuses inconsistent binding, duplicate identity/key, ordering or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(3).uint(SCHEMA).uint(2).array(self.realms.len());
        for realm in &self.realms {
            out.array(2)
                .text(&realm.realm.to_string())
                .array(realm.members.len());
            for member in &realm.members {
                out.array(2);
                member.binding.write(&mut out);
                out.bytes(member.record.as_bytes());
            }
        }
        bounded(out.into_bytes())
    }

    /// Decodes the whole collection before any replacement can be committed.
    ///
    /// # Errors
    /// Refuses malformed CBOR, invalid signed records, bindings and collections.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = crate::account::codec::reader(bytes, 3)?;
        require(input.uint()? == 2)?;
        let count = input.array_up_to(MAX_PEER_REALMS)?;
        let mut realms = Vec::with_capacity(count);
        let mut total = 0usize;
        for _ in 0..count {
            input.array(2)?;
            let realm = realm(&mut input)?;
            let count = input.array_up_to(MAX_IDENTITIES - total)?;
            total += count;
            let mut members = Vec::with_capacity(count);
            for _ in 0..count {
                input.array(2)?;
                let binding = NodeBinding::read(&mut input)?;
                let record = NodeRecord::decode(input.bytes_up_to(MAX_NODE_RECORD_BYTES)?)
                    .map_err(|_| AccountError::Field)?;
                members.push(RealmMember { binding, record });
            }
            realms.push(RealmContribution { realm, members });
        }
        input.finish()?;
        let value = Self { realms };
        value.validate()?;
        Ok(value)
    }
}

/// Last-seen policy counter; confers no authorization or applied-policy evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyVersion {
    /// Diagnostic observation, independent of enclosing publication version.
    pub counter: u64,
}

impl PolicyVersion {
    /// Encodes the observation using its existing family 11 stream kind.
    ///
    /// # Errors
    /// Returns a size error if the content exceeds its contract bound.
    pub fn canonical(self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(3).uint(SCHEMA).uint(11).uint(self.counter);
        Ok(out.into_bytes())
    }

    /// Decodes a canonical observation without establishing publication authority.
    ///
    /// # Errors
    /// Refuses noncanonical, oversized or incorrectly tagged content.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = CborReader::new(bytes, MAX_POLICY_VERSION_BYTES)?;
        input.array(3)?;
        require(input.uint()? == SCHEMA && input.uint()? == 11)?;
        let value = Self {
            counter: input.uint()?,
        };
        input.finish()?;
        Ok(value)
    }
}
