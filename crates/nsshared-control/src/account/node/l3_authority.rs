use std::collections::BTreeSet;

use crate::account::grants::grant::checked_bytes;
use crate::{
    account::MAX_BYTES, account::MAX_IDENTITIES, account::SCHEMA, account::grants::GrantError,
    account::identity, account::node::NodeL3,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// Explicit full signing identity to authorized transport key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L3Binding {
    /// Full signing identity I.
    pub identity: IdentityKey,
    /// Authorized WireGuard key K.
    pub wg_key: [u8; 32],
}

/// Complete normalized authority; existing policy fragment bytes are unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeL3Authority {
    /// Strict identity order, unique nonzero keys.
    pub bindings: Vec<L3Binding>,
    /// Complete issuer/recipient policy revision.
    pub policy: NodeL3,
}

impl NodeL3Authority {
    fn validate(&self) -> Result<(), GrantError> {
        self.policy.canonical()?;
        if self.bindings.len() > MAX_IDENTITIES {
            return Err(GrantError::Bounds);
        }
        if !self
            .bindings
            .windows(2)
            .all(|p| p[0].identity < p[1].identity)
        {
            return Err(GrantError::Ordering);
        }
        let mut keys = BTreeSet::new();
        for binding in &self.bindings {
            if binding.wg_key == [0; 32] || !keys.insert(binding.wg_key) {
                return Err(GrantError::Binding);
            }
        }
        for scope in &self.policy.scopes {
            for member in &scope.identities {
                if self
                    .bindings
                    .binary_search_by_key(member, |binding| binding.identity)
                    .is_err()
                {
                    return Err(GrantError::Binding);
                }
            }
        }
        Ok(())
    }

    /// Encodes complete I/K authority and exact policy bytes.
    ///
    /// # Errors
    /// Refuses invalid policy, missing or ambiguous binding and bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, GrantError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(3).uint(SCHEMA).array(self.bindings.len());
        for binding in &self.bindings {
            out.array(2)
                .bytes(binding.identity.as_bytes())
                .bytes(&binding.wg_key);
        }
        out.bytes(&self.policy.canonical()?);
        checked_bytes(out)
    }

    /// Decodes complete canonical Node authority without installing any effects.
    ///
    /// # Errors
    /// Refuses malformed encoding, policy, missing membership bindings or duplicate keys.
    pub fn decode(bytes: &[u8]) -> Result<Self, GrantError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(3)?;
        if input.uint()? != SCHEMA {
            return Err(GrantError::Field);
        }
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let mut bindings = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(2)?;
            bindings.push(L3Binding {
                identity: identity(&mut input)?,
                wg_key: input.fixed_bytes()?,
            });
        }
        let policy = NodeL3::decode(input.bytes_up_to(MAX_BYTES)?)?;
        input.finish()?;
        let value = Self { bindings, policy };
        value.validate()?;
        Ok(value)
    }
}
