//! Scoped catalogues of existing usage quantities and Node-control vocabulary.

use super::{
    AccountError, UsageProfile, control_exchange::MembershipScope, identity, reader, require,
};
use crate::{IdentityKey, encoding::CborWriter, node_control};

/// Complete quantity catalogue for one independently authenticated reporter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageProfilePublication {
    /// Existing full reporter identity, never a reporter incarnation.
    pub reporter: IdentityKey,
    /// Nonempty existing quantity identifiers in strict UTF-8 byte order.
    pub profiles: Vec<UsageProfile>,
}

impl UsageProfilePublication {
    fn validate(&self) -> Result<(), AccountError> {
        require(!self.profiles.is_empty() && self.profiles.len() <= 2)?;
        require(
            self.profiles
                .windows(2)
                .all(|pair| pair[0].as_str() < pair[1].as_str()),
        )
    }

    /// Encodes the existing quantity references without changing their definitions.
    /// # Errors
    /// Refuses empty, duplicate or unsorted profile lists.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(3)
            .uint(1)
            .bytes(self.reporter.as_bytes())
            .array(self.profiles.len());
        for profile in &self.profiles {
            out.text(profile.as_str());
        }
        Ok(out.into_bytes())
    }

    /// Decodes exact canonical bytes without authenticating the reporter.
    /// # Errors
    /// Refuses malformed fields, unknown identifiers, ordering and byte bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 3)?;
        let reporter = identity(&mut input)?;
        let count = input.array_up_to(2)?;
        let mut profiles = Vec::with_capacity(count);
        for _ in 0..count {
            profiles.push(UsageProfile::read(&mut input).map_err(|_| AccountError::InvalidField)?);
        }
        input.finish()?;
        let value = Self { reporter, profiles };
        value.validate()?;
        Ok(value)
    }

    /// Compares against the caller's independently accepted reporter identity.
    /// # Errors
    /// Refuses invalid lists and a different reporter.
    pub fn validate_reporter(&self, expected: IdentityKey) -> Result<(), AccountError> {
        self.validate()?;
        require(self.reporter == expected)
    }
}

/// Descriptive catalogue of supported existing Node-control message kinds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeControlProfilePublication {
    /// Exact independently accepted membership; the payload confers no authority.
    pub membership_scope: MembershipScope,
    /// Nonempty strictly increasing supported kinds, never permissions.
    pub capabilities: Vec<u8>,
}

impl NodeControlProfilePublication {
    fn validate(&self) -> Result<(), AccountError> {
        require(!self.capabilities.is_empty() && self.capabilities.len() <= 5)?;
        require(
            self.capabilities.iter().all(|kind| {
                matches!(
                    *kind,
                    node_control::kind::ACK
                        | node_control::kind::ENDPOINTS
                        | node_control::kind::RECORD
                        | node_control::kind::PROBE_REQUEST
                        | node_control::kind::PROBE_REPLY
                )
            }) && self.capabilities.windows(2).all(|pair| pair[0] < pair[1]),
        )
    }

    /// Encodes the exact membership and unchanged control vocabulary version.
    /// # Errors
    /// Refuses empty, unknown, duplicate or unsorted kinds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(4).uint(1);
        self.membership_scope.write(&mut out);
        out.uint(u64::from(node_control::VERSION))
            .array(self.capabilities.len());
        for kind in &self.capabilities {
            out.uint(u64::from(*kind));
        }
        Ok(out.into_bytes())
    }

    /// Decodes the existing membership encoding and fixed control vocabulary.
    /// # Errors
    /// Refuses malformed bytes, unsupported versions/kinds and invalid ordering.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 4)?;
        let membership_scope = MembershipScope::read(&mut input)?;
        require(input.uint()? == u64::from(node_control::VERSION))?;
        let count = input.array_up_to(5)?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(u8::try_from(input.uint()?).map_err(|_| AccountError::InvalidField)?);
        }
        input.finish()?;
        let value = Self {
            membership_scope,
            capabilities,
        };
        value.validate()?;
        Ok(value)
    }

    /// Compares against the caller's independently accepted membership.
    /// # Errors
    /// Refuses invalid lists or any membership identifier mismatch.
    pub fn validate_membership(&self, accepted: &MembershipScope) -> Result<(), AccountError> {
        self.validate()?;
        require(&self.membership_scope == accepted)
    }
}

/// Typed nonempty profile payload; absence is represented by publication outcomes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProfilePublicationPayload {
    /// Existing usage quantity catalogue.
    Usage(UsageProfilePublication),
    /// Existing Node-control vocabulary catalogue.
    NodeControl(NodeControlProfilePublication),
}
