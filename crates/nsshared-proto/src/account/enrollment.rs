use super::{AccountError, Lifecycle, NodeBinding, SCHEMA, Transition, reader};
use crate::encoding::{CborError, CborWriter};
use thiserror::Error;

/// Maximum opaque capability identifiers in an enrollment publication.
pub const MAX_CAPABILITIES: usize = 64;
/// Maximum ASCII bytes in one capability identifier.
pub const MAX_CAPABILITY_BYTES: usize = 64;

/// Ordinary per-membership external key binding and declared capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enrollment {
    /// The membership's own binding; derived identifiers are never carried.
    pub binding: NodeBinding,
    /// Strictly sorted, duplicate-free opaque identifiers matching `[a-z0-9._-]+`.
    pub capabilities: Vec<String>,
}

/// Explicit authorization from the reviewed producer profile, not Quick derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RebindAuthorization {
    /// The profile does not authorize a stable-identity rebind.
    Denied,
    /// The profile authorizes rebind with the supplied new K.
    Authorized,
}

/// Acceptance of a binding within the caller's authenticated membership scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentDecision {
    /// No binding has yet been accepted for this membership.
    Initial,
    /// The presented binding equals the accepted binding.
    Equal,
    /// A linked lifecycle replaces both identity and K.
    IdentityReplacement,
    /// A linked, explicitly authorized lifecycle rotates K under stable I.
    RecordRotation,
}

/// A typed refusal of enrollment bytes or membership binding advancement.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EnrollmentError {
    /// Invalid binding, lifecycle, schema or CBOR encoding.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// A capability set is unsorted, duplicate, empty-valued or has invalid characters.
    #[error("invalid canonical capability set")]
    InvalidCapabilities,
    /// Capability count or identifier length exceeds its bound.
    #[error("capability bound exceeded")]
    CapabilityBounds,
    /// A lower membership version cannot replace accepted registration.
    #[error("membership identity version rollback")]
    LowerVersion,
    /// A different binding needs a lifecycle from accepted registration.
    #[error("differing binding requires a lifecycle")]
    LifecycleRequired,
    /// The lifecycle does not connect the accepted and presented bindings.
    #[error("lifecycle binding mismatch")]
    LifecycleMismatch,
    /// Stable-I rebind lacks producer-profile authorization.
    #[error("stable-identity rebind is not authorized")]
    RebindUnauthorized,
}

fn capability_error(error: CborError) -> EnrollmentError {
    match error {
        CborError::ArrayLength { .. } | CborError::StringLength { .. } => {
            EnrollmentError::CapabilityBounds
        }
        _ => EnrollmentError::Contract(error.into()),
    }
}

impl Enrollment {
    fn validate(&self) -> Result<(), EnrollmentError> {
        self.binding.validate()?;
        validate_capabilities(&self.capabilities)?;
        Ok(())
    }

    /// Encodes the binding and canonical declared capability set without normalization.
    ///
    /// # Errors
    /// Rejects invalid bindings, capability characters, ordering, duplicates or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, EnrollmentError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(3).uint(SCHEMA);
        self.binding.write(&mut out);
        out.array(self.capabilities.len());
        for identifier in &self.capabilities {
            out.text(identifier);
        }
        Ok(out.into_bytes())
    }

    /// Decodes exactly one enrollment, including strict capability-set validation.
    ///
    /// # Errors
    /// Refuses malformed/nonminimal CBOR, trailing bytes and invalid contract fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnrollmentError> {
        let mut input = reader(bytes, 3)?;
        let binding = NodeBinding::read(&mut input)?;
        let count = input
            .array_up_to(MAX_CAPABILITIES)
            .map_err(capability_error)?;
        let mut capabilities = Vec::with_capacity(count);
        for _ in 0..count {
            capabilities.push(
                input
                    .text_up_to(MAX_CAPABILITY_BYTES)
                    .map_err(capability_error)?
                    .to_owned(),
            );
        }
        input.finish().map_err(AccountError::from)?;
        let value = Self {
            binding,
            capabilities,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Decides a presented enrollment against registration accepted for one membership.
///
/// The caller supplies authenticated scope and explicit producer-profile rebind
/// authorization. Success does not persist registration or fence old resources.
/// Equal bindings are accepted; every differing binding requires a valid lifecycle.
///
/// # Errors
/// Refuses invalid publications/bindings, rollback, missing or mismatched lifecycle,
/// invalid transitions and unauthorized stable-I rebinds.
pub fn decide_enrollment(
    accepted: Option<&NodeBinding>,
    presented: &Enrollment,
    lifecycle: Option<&Lifecycle>,
    rebind: RebindAuthorization,
) -> Result<EnrollmentDecision, EnrollmentError> {
    presented.validate()?;
    let Some(accepted) = accepted else {
        return if lifecycle.is_none() {
            Ok(EnrollmentDecision::Initial)
        } else {
            Err(EnrollmentError::LifecycleMismatch)
        };
    };
    accepted.validate()?;
    if presented.binding == *accepted {
        return Ok(EnrollmentDecision::Equal);
    }
    if presented.binding.identity_version < accepted.identity_version {
        return Err(EnrollmentError::LowerVersion);
    }
    let lifecycle = lifecycle.ok_or(EnrollmentError::LifecycleRequired)?;
    lifecycle.validate()?;
    if lifecycle.before != *accepted || lifecycle.after != presented.binding {
        return Err(EnrollmentError::LifecycleMismatch);
    }
    match lifecycle.transition {
        Transition::IdentityReplacement => Ok(EnrollmentDecision::IdentityReplacement),
        Transition::RecordRotation if rebind == RebindAuthorization::Authorized => {
            Ok(EnrollmentDecision::RecordRotation)
        }
        Transition::RecordRotation => Err(EnrollmentError::RebindUnauthorized),
    }
}

pub(super) fn validate_capabilities(capabilities: &[String]) -> Result<(), EnrollmentError> {
    if capabilities.len() > MAX_CAPABILITIES
        || capabilities
            .iter()
            .any(|id| id.len() > MAX_CAPABILITY_BYTES)
    {
        return Err(EnrollmentError::CapabilityBounds);
    }
    if !capabilities.windows(2).all(|pair| pair[0] < pair[1])
        || capabilities.iter().any(|id| {
            id.is_empty()
                || !id.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
    {
        return Err(EnrollmentError::InvalidCapabilities);
    }
    Ok(())
}
