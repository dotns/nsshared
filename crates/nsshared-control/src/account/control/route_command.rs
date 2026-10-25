//! Pure Node/route commands and immutable receipt decisions on the authenticated control carrier.

use crate::{
    account::AccountError, account::codec::identity, account::codec::require,
    account::control::BootstrapEnvelope, account::control::BootstrapError,
    account::control::EnvelopeDirection, account::control::EnvelopeExpectation,
    account::publication::source_binding::MAX_SOURCE_BYTES,
    account::publication::source_binding::SignedSourceBinding,
    account::publication::source_binding::SourceBinding,
    account::publication::source_binding::SourceError,
    account::publication::source_binding::nonzero, account::subnet::SubnetError,
    account::subnet::SubnetSelection, account::subnet::views::read_set,
    account::subnet::views::validate_set, account::subnet::views::write_set, service::ServiceRef,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;
use thiserror::Error;

/// Typed refusal of a route command or receipt; no error changes committed selections.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RouteError {
    /// Invalid bounded canonical encoding or fields.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Invalid confidential signed carrier.
    #[error(transparent)]
    Envelope(#[from] BootstrapError),
    /// Invalid embedded source binding.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// Invalid Subnet selection.
    #[error(transparent)]
    Subnet(#[from] SubnetError),
    /// Caller, source, provider or pending command differs.
    #[error("route authority mismatch")]
    Authority,
    /// Request identity was reused for different content.
    #[error("route request content conflict")]
    Conflict,
    /// Invalid canonical M6 service reference.
    #[error("invalid route reference")]
    Reference,
}

crate::account::contract_error!(RouteError);

/// Confidential Node/route selection operation.
pub const NODE_ROUTE_SELECT: &str = "node.route.select";
/// Confidential exact selection withdrawal operation.
pub const NODE_ROUTE_CLEAR: &str = "node.route.clear";

/// Command intent, not an assertion that routing has been applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteAction {
    /// Select a stable route with a full provider identity and SubnetSelection scope.
    Select {
        /// Full provider Node I.
        provider: IdentityKey,
        /// Existing stable M6 route reference.
        resource: ServiceRef,
        /// Existing default or explicit destination set.
        scope: SubnetSelection,
    },
    /// Withdraw only the named selection's exact generation.
    Clear {
        /// Positive committed generation of the target selection.
        generation: u64,
    },
}

/// Exact request, source/profile and selection identities are mandatory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteCommand {
    /// Original authenticated source authority.
    pub binding: SignedSourceBinding,
    /// Nonzero immutable request identity within this profile/source.
    pub request_id: [u8; 16],
    /// Nonzero stable identity for this exact selection.
    pub selection_id: [u8; 16],
    /// Full selection or exact clear target.
    pub action: RouteAction,
}
impl RouteCommand {
    /// The only permitted operation for this command's action.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        match self.action {
            RouteAction::Select { .. } => NODE_ROUTE_SELECT,
            RouteAction::Clear { .. } => NODE_ROUTE_CLEAR,
        }
    }
    /// Encodes exact fields with SubnetSelection scope and unchanged canonical M6 reference bytes.
    /// # Errors
    /// Refuses invalid identities, source, prefixes, generation or encoded size.
    pub fn canonical(&self) -> Result<Vec<u8>, RouteError> {
        nonzero(&self.request_id)?;
        nonzero(&self.selection_id)?;
        let mut out = CborWriter::default();
        out.array(5)
            .uint(1)
            .bytes(&self.binding.canonical()?)
            .bytes(&self.request_id)
            .bytes(&self.selection_id);
        match &self.action {
            RouteAction::Clear { generation } => {
                require(*generation > 0)?;
                out.array(2).uint(1).uint(*generation);
            }
            RouteAction::Select {
                provider,
                resource,
                scope,
            } => {
                let resource = resource.canonical().map_err(|_| RouteError::Reference)?;
                out.array(4)
                    .uint(0)
                    .bytes(provider.as_bytes())
                    .bytes(&resource)
                    .array(2);
                match scope {
                    SubnetSelection::Default => {
                        out.uint(0).array(0);
                    }
                    SubnetSelection::Explicit(prefixes) => {
                        validate_set(prefixes)?;
                        out.uint(1);
                        write_set(prefixes, &mut out);
                    }
                }
            }
        }
        let bytes = out.into_bytes();
        require(bytes.len() <= MAX_SOURCE_BYTES)?;
        Ok(bytes)
    }
    /// Decodes exact new forms without predecessor field conversion.
    /// # Errors
    /// Refuses unknown, missing, retired, malformed or over-bound fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, RouteError> {
        let mut input = CborReader::new(bytes, MAX_SOURCE_BYTES)?;
        input.array(5)?;
        require(input.uint()? == 1)?;
        let binding = SignedSourceBinding::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)?;
        let request_id = input.fixed_bytes()?;
        let selection_id = input.fixed_bytes()?;
        let count = input.array_up_to(4)?;
        let action = match (input.uint()?, count) {
            (1, 2) => RouteAction::Clear {
                generation: input.uint()?,
            },
            (0, 4) => {
                let provider = identity(&mut input)?;
                let resource = ServiceRef::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)
                    .map_err(|_| RouteError::Reference)?;
                input.array(2)?;
                let tag = input.uint()?;
                let prefixes = read_set(&mut input)?;
                let scope = match tag {
                    0 => {
                        require(prefixes.is_empty())?;
                        SubnetSelection::Default
                    }
                    1 => SubnetSelection::Explicit(prefixes),
                    _ => return Err(RouteError::Authority),
                };
                RouteAction::Select {
                    provider,
                    resource,
                    scope,
                }
            }
            _ => return Err(RouteError::Authority),
        };
        input.finish()?;
        let value = Self {
            binding,
            request_id,
            selection_id,
            action,
        };
        value.canonical()?;
        Ok(value)
    }
    /// Authenticates the existing confidential request carrier and its source issuer.
    /// Current-source transaction authorization remains a separate decision.
    /// # Errors
    /// Refuses signature, invalid nonce, operation, caller or explicit recipient mismatch.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        nsd: IdentityKey,
    ) -> Result<Self, RouteError> {
        envelope.verify(expected)?;
        let value = Self::decode(&envelope.payload)?;
        nonzero(&envelope.nonce)?;
        value.binding.verify(nsd)?;
        if envelope.direction != EnvelopeDirection::Request
            || envelope.kind != value.operation()
            || envelope.recipient != Some(nsd)
            || expected.recipient != nsd
            || envelope.signer != value.binding.binding.recipient
        {
            return Err(RouteError::Authority);
        }
        Ok(value)
    }
}

/// Immutable committed command result, retained per profile/source/request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteReceipt {
    /// Original exact request; all source and scope facts remain attached.
    pub command: RouteCommand,
    /// Positive committed selection generation, or exact clear target generation.
    pub selection_generation: u64,
    /// Result of the original transaction, never recomputed on replay.
    pub outcome: RouteOutcome,
}
/// Committed outcome, independent of any actual route application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum RouteOutcome {
    /// Selection committed with NSD-allocated generation.
    Selected = 0,
    /// Exact target cleared.
    Cleared = 1,
    /// Exact clear target was absent.
    ClearAbsent = 2,
}
impl RouteReceipt {
    /// Original immutable canonical receipt bytes.
    /// # Errors
    /// Refuses invalid command, outcome or target generation disagreement.
    pub fn canonical(&self) -> Result<Vec<u8>, RouteError> {
        require(self.selection_generation > 0)?;
        match self.command.action {
            RouteAction::Select { .. } => require(self.outcome == RouteOutcome::Selected)?,
            RouteAction::Clear { generation } => require(
                self.outcome != RouteOutcome::Selected && self.selection_generation == generation,
            )?,
        }
        let mut out = CborWriter::default();
        out.array(4)
            .uint(1)
            .bytes(&self.command.canonical()?)
            .uint(self.selection_generation)
            .uint(self.outcome as u64);
        let bytes = out.into_bytes();
        require(bytes.len() <= MAX_SOURCE_BYTES)?;
        Ok(bytes)
    }
    /// Decodes without authenticating a committed result.
    /// # Errors
    /// Refuses malformed, retired, conflicting or unsupported fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, RouteError> {
        let mut input = CborReader::new(bytes, MAX_SOURCE_BYTES)?;
        input.array(4)?;
        require(input.uint()? == 1)?;
        let command = RouteCommand::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)?;
        let selection_generation = input.uint()?;
        let outcome = match input.uint()? {
            0 => RouteOutcome::Selected,
            1 => RouteOutcome::Cleared,
            2 => RouteOutcome::ClearAbsent,
            _ => return Err(RouteError::Authority),
        };
        input.finish()?;
        let value = Self {
            command,
            selection_generation,
            outcome,
        };
        value.canonical()?;
        Ok(value)
    }
}

/// A response carries an unchanged receipt and independent replay observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteResponse {
    /// Immutable original transaction result.
    pub receipt: RouteReceipt,
    /// Replay confers no current mutation authority.
    pub replayed: bool,
}
impl RouteResponse {
    /// Exact response payload for the NSD-signed control-envelope carrier.
    /// # Errors
    /// Refuses invalid receipt fields or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, RouteError> {
        let mut out = CborWriter::default();
        out.array(3)
            .uint(1)
            .bytes(&self.receipt.canonical()?)
            .boolean(self.replayed);
        let bytes = out.into_bytes();
        require(bytes.len() <= MAX_SOURCE_BYTES)?;
        Ok(bytes)
    }
    /// Decodes response fields without asserting NSD commitment.
    /// # Errors
    /// Refuses invalid receipt, malformed or extra fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, RouteError> {
        let mut input = CborReader::new(bytes, MAX_SOURCE_BYTES)?;
        input.array(3)?;
        require(input.uint()? == 1)?;
        let receipt = RouteReceipt::decode(input.bytes_up_to(MAX_SOURCE_BYTES)?)?;
        let replayed = input.boolean()?;
        input.finish()?;
        let value = Self { receipt, replayed };
        value.canonical()?;
        Ok(value)
    }
    /// Verifies NSD commitment to the exact pending original request and profile/source.
    /// The pending nonce identifies this transmission attempt independently of the
    /// immutable request identity. Never authorizes mutation or applied routing.
    /// # Errors
    /// Refuses signature, wrong request, retired profile, operation or recipient.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        pending: &RouteCommand,
        pending_nonce: [u8; 16],
    ) -> Result<Self, RouteError> {
        envelope.verify(expected)?;
        pending.canonical()?;
        nonzero(&pending_nonce)?;
        let binding = &pending.binding.binding;
        pending.binding.verify(binding.nsd)?;
        let value = Self::decode(&envelope.payload)?;
        if envelope.direction != EnvelopeDirection::Response
            || envelope.signer != binding.nsd
            || envelope.recipient != Some(binding.recipient)
            || expected.recipient != binding.recipient
            || envelope.kind != pending.operation()
            || envelope.nonce != pending_nonce
            || &value.receipt.command != pending
        {
            return Err(RouteError::Authority);
        }
        Ok(value)
    }
}

/// Caller-restored committed selection; no store or generation allocator is provided.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedSelection {
    /// Original select command.
    pub command: RouteCommand,
    /// Positive NSD-allocated selection generation.
    pub generation: u64,
}
/// Pure transaction intent; only non-replay outcomes may produce a new receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteDecision {
    /// Return this exact original result without touching current selection.
    Replay(Box<RouteReceipt>),
    /// Authorize a new selection subject to NSD's resource authorization recheck.
    Select,
    /// Clear only the supplied exact matching committed selection.
    Clear,
    /// Record that the exact clear target is absent, leaving current state intact.
    ClearAbsent,
}

/// Compares caller-supplied authority, receipt history and selection without mutation.
/// Receipt lookup must use the full profile/source/request identity, durably across restart.
/// # Errors
/// Refuses caller, signature, changed request, malformed retained state or stale source.
pub fn decide_route_command(
    request: &RouteCommand,
    authenticated_caller: IdentityKey,
    current: &SourceBinding,
    original: Option<&RouteReceipt>,
    selection: Option<&CommittedSelection>,
) -> Result<RouteDecision, RouteError> {
    request.canonical()?;
    current.canonical()?;
    request.binding.verify(current.nsd)?;
    if request.binding.binding.recipient != authenticated_caller {
        return Err(RouteError::Authority);
    }
    if let Some(original) = original {
        original.canonical()?;
        if original.command != *request {
            return Err(RouteError::Conflict);
        }
        return Ok(RouteDecision::Replay(Box::new(original.clone())));
    }
    if request.binding.binding != *current {
        return Err(RouteError::Authority);
    }
    match request.action {
        RouteAction::Select { .. } => Ok(RouteDecision::Select),
        RouteAction::Clear { generation } => {
            if let Some(selection) = selection {
                selection.command.canonical()?;
                require(
                    selection.generation > 0
                        && matches!(selection.command.action, RouteAction::Select { .. }),
                )?;
                selection.command.binding.verify(current.nsd)?;
                if selection.command.binding.binding == request.binding.binding
                    && selection.command.selection_id == request.selection_id
                    && selection.generation == generation
                {
                    return Ok(RouteDecision::Clear);
                }
            }
            Ok(RouteDecision::ClearAbsent)
        }
    }
}
