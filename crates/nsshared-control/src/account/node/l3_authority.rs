use std::collections::BTreeSet;

use crate::{
    account::AccountError, account::MAX_BYTES, account::MAX_IDENTITIES, account::SCHEMA,
    account::codec::ascending_by, account::codec::identity, account::node::NodeL3,
};
use nsshared_codec::{cbor::CborError, cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;
use thiserror::Error;

/// A refused Node L3 authority; no error installs or withdraws effects.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum L3AuthorityError {
    /// Strict CBOR refusal of the authority itself.
    #[error(transparent)]
    Encoding(#[from] CborError),
    /// Invalid full identity or normalized Node policy.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Unsupported schema.
    #[error("invalid Node L3 authority field")]
    Field,
    /// Too many bindings.
    #[error("Node L3 authority bound exceeded")]
    Bounds,
    /// Bindings are not in strict identity order.
    #[error("Node L3 authority bindings are not in strict identity order")]
    Ordering,
    /// A key is zero or repeated, or a policy member has no binding.
    #[error("missing, zero or repeated Node L3 binding")]
    Binding,
}

/// Explicit full signing identity to authorized transport key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct L3Binding {
    /// Full signing identity I.
    pub identity: IdentityKey,
    /// Authorized WireGuard key K.
    pub wg_key: [u8; 32],
    /// NSD-authorized relay identity for this binding's sole Network, if any.
    pub relay_identity: Option<IdentityKey>,
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
    fn validate(&self) -> Result<(), L3AuthorityError> {
        self.policy.canonical()?;
        if self.bindings.len() > MAX_IDENTITIES {
            return Err(L3AuthorityError::Bounds);
        }
        if !ascending_by(&self.bindings, |value| &value.identity) {
            return Err(L3AuthorityError::Ordering);
        }
        let mut keys = BTreeSet::new();
        let mut relay_identities = BTreeSet::new();
        for binding in &self.bindings {
            if binding.wg_key == [0; 32] || !keys.insert(binding.wg_key) {
                return Err(L3AuthorityError::Binding);
            }
            if binding.relay_identity.is_some_and(|identity| {
                identity == binding.identity || !relay_identities.insert(identity)
            }) {
                return Err(L3AuthorityError::Binding);
            }
        }
        if self.bindings.iter().any(|binding| {
            binding.relay_identity.is_some_and(|identity| {
                self.bindings
                    .binary_search_by_key(&identity, |member| member.identity)
                    .is_ok()
            })
        }) {
            return Err(L3AuthorityError::Binding);
        }
        for scope in &self.policy.scopes {
            for member in &scope.identities {
                if self
                    .bindings
                    .binary_search_by_key(member, |binding| binding.identity)
                    .is_err()
                {
                    return Err(L3AuthorityError::Binding);
                }
            }
        }
        Ok(())
    }

    /// Encodes complete I/K authority and exact policy bytes.
    ///
    /// # Errors
    /// Refuses invalid policy, missing or ambiguous binding and bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, L3AuthorityError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(3).uint(SCHEMA).array(self.bindings.len());
        for binding in &self.bindings {
            out.array(if binding.relay_identity.is_some() {
                3
            } else {
                2
            })
            .bytes(binding.identity.as_bytes())
            .bytes(&binding.wg_key);
            if let Some(identity) = binding.relay_identity {
                out.bytes(identity.as_bytes());
            }
        }
        out.bytes(&self.policy.canonical()?);
        let bytes = out.into_bytes();
        if bytes.len() > MAX_BYTES {
            return Err(L3AuthorityError::Bounds);
        }
        Ok(bytes)
    }

    /// Decodes complete canonical Node authority without installing any effects.
    ///
    /// # Errors
    /// Refuses malformed encoding, policy, missing membership bindings or duplicate keys.
    pub fn decode(bytes: &[u8]) -> Result<Self, L3AuthorityError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        input.array(3)?;
        if input.uint()? != SCHEMA {
            return Err(L3AuthorityError::Field);
        }
        let count = input.array_up_to(MAX_IDENTITIES)?;
        let mut bindings = Vec::with_capacity(count);
        for _ in 0..count {
            let arity = input.array_up_to(3)?;
            if arity < 2 {
                return Err(L3AuthorityError::Field);
            }
            let binding_identity = identity(&mut input)?;
            let wg_key = input.fixed_bytes()?;
            let relay_identity = (arity == 3).then(|| identity(&mut input)).transpose()?;
            bindings.push(L3Binding {
                identity: binding_identity,
                wg_key,
                relay_identity,
            });
        }
        let policy = NodeL3::decode(input.bytes_up_to(MAX_BYTES)?)?;
        input.finish()?;
        let value = Self { bindings, policy };
        value.validate()?;
        Ok(value)
    }
}
