use crate::{
    account::AccountError, account::SCHEMA, account::codec::identity, account::codec::reader,
    account::codec::require,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// Monotonic derivation version, comparable only within one NSD membership.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MembershipIdentityVersion(pub u64);

/// Monotonic generation, comparable only within one full identity.
/// Existing NodeRecord ordering still resolves same-generation records.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RecordGeneration(pub u64);

/// Opaque grant lifecycle token. Equality only; regrant requires a fresh token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantIncarnation(pub [u8; 16]);

/// Opaque usage reporter lifecycle token. Equality only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReporterIncarnation(pub [u8; 16]);

/// Own Node binding shared by all served realms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeBinding {
    /// Per-membership identity derivation version.
    pub identity_version: MembershipIdentityVersion,
    /// Full signing identity; NodeId, N6 and N4 derive from it.
    pub identity: IdentityKey,
    /// Current authorized WireGuard public key K.
    pub wg_key: [u8; 32],
    /// Generation within this identity.
    pub generation: RecordGeneration,
}

impl NodeBinding {
    pub(in crate::account) fn validate(&self) -> Result<(), AccountError> {
        require(self.identity_version.0 > 0 && self.generation.0 > 0 && self.wg_key != [0; 32])
    }

    pub(in crate::account) fn write(&self, out: &mut CborWriter) {
        out.array(4)
            .uint(self.identity_version.0)
            .bytes(self.identity.as_bytes())
            .bytes(&self.wg_key)
            .uint(self.generation.0);
    }

    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(4)?;
        let binding = Self {
            identity_version: MembershipIdentityVersion(input.uint()?),
            identity: identity(input)?,
            wg_key: input.fixed_bytes()?,
            generation: RecordGeneration(input.uint()?),
        };
        binding.validate()?;
        Ok(binding)
    }
}

/// Identity replacement and K-only record rotation have different invariants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transition {
    /// New versioned derivation replaces both keys and all derived identifiers.
    IdentityReplacement,
    /// Identity and derived identifiers stay fixed while K and generation change.
    RecordRotation,
}

/// Identity lifecycle with explicitly separate incarnation domains.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lifecycle {
    /// Kind of key transition.
    pub transition: Transition,
    /// Previous binding.
    pub before: NodeBinding,
    /// Replacement binding.
    pub after: NodeBinding,
    /// Independent current grant token.
    pub grant: GrantIncarnation,
    /// Independent reporter token.
    pub reporter: ReporterIncarnation,
}

impl Lifecycle {
    pub(in crate::account) fn validate(&self) -> Result<(), AccountError> {
        self.before.validate()?;
        self.after.validate()?;
        require(self.before.wg_key != self.after.wg_key)?;
        match self.transition {
            Transition::IdentityReplacement => require(
                self.after.identity_version > self.before.identity_version
                    && self.before.identity != self.after.identity,
            ),
            Transition::RecordRotation => require(
                self.before.identity == self.after.identity
                    && self.before.identity_version == self.after.identity_version
                    && self.after.generation > self.before.generation,
            ),
        }
    }

    /// Encodes the lifecycle distinctions with canonical CBOR.
    ///
    /// # Errors
    /// Rejects a transition that violates identity or generation invariants.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(6).uint(SCHEMA).uint(match self.transition {
            Transition::IdentityReplacement => 0,
            Transition::RecordRotation => 1,
        });
        self.before.write(&mut out);
        self.after.write(&mut out);
        out.bytes(&self.grant.0).bytes(&self.reporter.0);
        Ok(out.into_bytes())
    }

    /// Decodes and validates an exact lifecycle.
    ///
    /// # Errors
    /// Rejects malformed CBOR, unsupported tags and invalid transitions.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 6)?;
        let transition = match input.uint()? {
            0 => Transition::IdentityReplacement,
            1 => Transition::RecordRotation,
            _ => return Err(AccountError::Field),
        };
        let value = Self {
            transition,
            before: NodeBinding::read(&mut input)?,
            after: NodeBinding::read(&mut input)?,
            grant: GrantIncarnation(input.fixed_bytes()?),
            reporter: ReporterIncarnation(input.fixed_bytes()?),
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }
}
