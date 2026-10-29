//! Historical registration results for independently authenticated receipt carriers.
use crate::{
    account::{
        AccountError, MAX_BYTES,
        codec::{bounded, reader, require},
        control::{ExchangeError, MembershipScope, RegistrationAcceptance, RegistrationRequest},
        node::{EnrollmentDecision, NodeBinding, RebindAuthorization},
        publication::{SourceBinding, SourceError},
    },
    service::Id,
};
use nsshared_codec::cbor::CborWriter;
use nsshared_identity::realm::RealmId;
use sha2::{Digest as _, Sha256};

/// Exact shared context added to the existing grant or approved-operation lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationRecoveryQuery {
    /// Existing approved operation identifier, never a newly invented retry id.
    pub operation: Id,
    /// Exact provisioned NSD and Network.
    pub scope: MembershipScope,
    /// SHA-256 of the original canonical RegistrationRequest.
    pub request_digest: [u8; 32],
}
impl RegistrationRecoveryQuery {
    /// Derives context from the retained approved operation and staged request.
    /// # Errors
    /// Refuses a zero operation or invalid request.
    pub fn for_request(
        operation: Id,
        request: &RegistrationRequest,
    ) -> Result<Self, ExchangeError> {
        let value = Self {
            operation,
            scope: request.scope.clone(),
            request_digest: Sha256::digest(request.canonical()?).into(),
        };
        value.canonical()?;
        Ok(value)
    }

    /// Encodes version one shared lookup context, without its transport locator.
    /// # Errors
    /// Refuses a zero operation identifier.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        require(self.operation != [0; 16])?;
        let mut out = CborWriter::default();
        out.array(4).uint(1).bytes(&self.operation);
        self.scope.write(&mut out);
        out.bytes(&self.request_digest);
        Ok(bounded(out.into_bytes())?)
    }

    /// Decodes exactly one canonical version one context.
    /// # Errors
    /// Refuses unknown versions, malformed fields or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        let mut input = reader(bytes, 4)?;
        let value = Self {
            operation: input.fixed_bytes().map_err(AccountError::from)?,
            scope: MembershipScope::read(&mut input)?,
            request_digest: input.fixed_bytes().map_err(AccountError::from)?,
        };
        input.finish().map_err(AccountError::from)?;
        value.canonical()?;
        Ok(value)
    }

    /// Compares a query or stored context with independently retained inputs.
    /// # Errors
    /// Refuses any operation, membership or request-digest difference.
    pub fn compare(&self, expected: &Self) -> Result<(), ExchangeError> {
        self.canonical()?;
        expected.canonical()?;
        require(self == expected)?;
        Ok(())
    }
}

/// Version one original shared result attached to the existing signed receipt.
/// This attachment never grants current authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationRecoveryAttachment {
    /// Immutable approved operation, membership and canonical request digest.
    pub query: RegistrationRecoveryQuery,
    /// Original acceptance, including the original source signature.
    pub acceptance: RegistrationAcceptance,
}

/// Independently retained plan and custody facts; never populated from the result.
#[derive(Clone, Debug)]
pub struct RegistrationRecoveryExpectation<'a> {
    /// Retained approved operation and exact request context.
    pub query: &'a RegistrationRecoveryQuery,
    /// Original staged request, including enrollment and lifecycle.
    pub request: &'a RegistrationRequest,
    /// Unchanged committed baseline used for the original enrollment decision.
    pub committed: Option<&'a NodeBinding>,
    /// Original explicit rebind authorization.
    pub rebind: RebindAuthorization,
    /// Independently expected issuer, recipient, realm, scope, profile and custody tuple.
    pub source: &'a SourceBinding,
    /// Retained minimum source epoch; never lowered for historical recovery.
    pub epoch_floor: u64,
    /// Retained minimum source generation; never lowered for historical recovery.
    pub generation_floor: u64,
}
impl RegistrationRecoveryAttachment {
    /// Encodes the exact original canonical acceptance without signing it again.
    /// # Errors
    /// Refuses invalid context, nested acceptance or oversized attachment.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        let mut out = CborWriter::default();
        out.array(3)
            .uint(1)
            .bytes(&self.query.canonical()?)
            .bytes(&self.acceptance.canonical()?);
        Ok(bounded(out.into_bytes())?)
    }

    /// Decodes a bounded version one attachment without authenticating it.
    /// # Errors
    /// Refuses unsupported versions, invalid nested contracts and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        let mut input = reader(bytes, 3)?;
        let value = Self {
            query: RegistrationRecoveryQuery::decode(
                input.bytes_up_to(MAX_BYTES).map_err(AccountError::from)?,
            )?,
            acceptance: RegistrationAcceptance::decode(
                input.bytes_up_to(MAX_BYTES).map_err(AccountError::from)?,
            )?,
        };
        input.finish().map_err(AccountError::from)?;
        value.canonical()?;
        Ok(value)
    }

    /// Validates the historical result independently of any transport nonce or clock.
    /// The caller must authenticate the receipt and separately check current authority.
    /// # Errors
    /// Refuses context, enrollment, lifecycle, source signature or custody disagreement.
    pub fn validate(
        &self,
        expected: &RegistrationRecoveryExpectation<'_>,
    ) -> Result<EnrollmentDecision, ExchangeError> {
        self.canonical()?;
        self.query.compare(expected.query)?;
        self.query.compare(&RegistrationRecoveryQuery::for_request(
            expected.query.operation,
            expected.request,
        )?)?;
        let decision = super::exchange::compare_registration_payload(
            &self.acceptance,
            expected.request,
            expected.committed,
            expected.rebind,
        )?;
        let source = expected.source;
        source.canonical()?;
        if source.scope != "nodes"
            || source.served_realm != RealmId::from_bytes(expected.request.scope.network_id)
            || source.recipient != expected.request.enrollment.binding.identity
            || source.source_node != expected.request.enrollment.binding.identity
            || source.profile.as_str() != expected.request.profile
            || source.source_epoch < expected.epoch_floor
            || source.source_generation < expected.generation_floor
            || self.acceptance.source_binding.binding != *source
        {
            return Err(SourceError::Authority.into());
        }
        self.acceptance.source_binding.verify(source.nsd)?;
        Ok(decision)
    }
}
