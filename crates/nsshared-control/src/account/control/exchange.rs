//! Pure enrollment, authentication and information exchanges.
use crate::{
    account::AccountError, account::MAX_BYTES, account::SCHEMA, account::codec::ascending,
    account::codec::bounded, account::codec::data_text, account::codec::reader,
    account::codec::realm, account::codec::require, account::codec::token,
    account::control::BootstrapDiscovery, account::control::BootstrapEnvelope,
    account::control::BootstrapError, account::control::EnvelopeDirection,
    account::control::EnvelopeExpectation, account::control::methods::MACHINE_AUTH,
    account::control::methods::MACHINE_AUTH_PURPOSE, account::control::methods::MACHINE_REGISTER,
    account::limits::MAX_CREDENTIAL_BYTES, account::limits::MAX_TEXT_BYTES,
    account::node::Enrollment, account::node::EnrollmentDecision, account::node::EnrollmentError,
    account::node::Lifecycle, account::node::NodeBinding, account::node::RebindAuthorization,
    account::node::decide_enrollment, account::publication::source_binding::MAX_SOURCE_BYTES,
    account::publication::source_binding::SignedSourceBinding,
    account::publication::source_binding::SourceEnrollmentExpectation,
    account::publication::source_binding::SourceError, service::Id,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::realm::RealmId;
use thiserror::Error;

/// Explicit membership owner; identities are shared across its served realms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipScope {
    /// Provisioned NSD identifier.
    pub nsd_id: Id,
    /// Provisioned membership network identifier.
    pub network_id: Id,
}
impl MembershipScope {
    pub(in crate::account) fn write(&self, out: &mut CborWriter) {
        out.array(2).bytes(&self.nsd_id).bytes(&self.network_id);
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(2)?;
        Ok(Self {
            nsd_id: input.fixed_bytes()?,
            network_id: input.fixed_bytes()?,
        })
    }
}

/// Typed refusal; successful decoding alone never accepts a membership.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExchangeError {
    /// Invalid or mismatched nested source authority.
    #[error(transparent)]
    Source(#[from] SourceError),
    /// Malformed contract bytes or fields.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Invalid enrollment or lifecycle.
    #[error(transparent)]
    Enrollment(#[from] EnrollmentError),
    /// Unauthenticated or wrongly bound carrier.
    #[error(transparent)]
    Envelope(#[from] BootstrapError),
    /// Membership owner differs from the staged request.
    #[error("membership scope mismatch")]
    Scope,
    /// Accepted binding differs in any field.
    #[error("accepted binding mismatch")]
    Binding,
    /// Accepted profile differs.
    #[error("accepted profile mismatch")]
    Profile,
    /// Accepted capability set differs.
    #[error("accepted capabilities mismatch")]
    Capabilities,
    /// Acceptance decision differs from the local lifecycle decision.
    #[error("accepted lifecycle mismatch")]
    Lifecycle,
}

fn tag(decision: EnrollmentDecision) -> u64 {
    match decision {
        EnrollmentDecision::Initial => 0,
        EnrollmentDecision::Equal => 1,
        EnrollmentDecision::IdentityReplacement => 2,
        EnrollmentDecision::RecordRotation => 3,
    }
}
fn decision(value: u64) -> Result<EnrollmentDecision, AccountError> {
    match value {
        0 => Ok(EnrollmentDecision::Initial),
        1 => Ok(EnrollmentDecision::Equal),
        2 => Ok(EnrollmentDecision::IdentityReplacement),
        3 => Ok(EnrollmentDecision::RecordRotation),
        _ => Err(AccountError::Field),
    }
}

/// Staged enrollment request. The opaque credential is redacted from Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistrationRequest {
    /// Requested provisioned membership.
    pub scope: MembershipScope,
    /// Existing binding and declared capabilities.
    pub enrollment: Enrollment,
    /// Exact declared profile identifier.
    pub profile: String,
    /// Provisioned enrollment authorization, carried confidentially.
    pub credential: Vec<u8>,
    /// Existing lifecycle linking a replacement to committed registration.
    pub lifecycle: Option<Lifecycle>,
}
impl std::fmt::Debug for RegistrationRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationRequest")
            .field("scope", &self.scope)
            .field("enrollment", &self.enrollment)
            .field("profile", &self.profile)
            .field("credential", &"[redacted]")
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}
impl RegistrationRequest {
    /// Encodes the staged request without interpreting its credential.
    /// # Errors
    /// Refuses invalid fields, enrollment or lifecycle and oversized credentials.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        data_text(&self.profile)?;
        require(!self.credential.is_empty() && self.credential.len() <= MAX_CREDENTIAL_BYTES)?;
        let mut out = CborWriter::default();
        out.array(6).uint(SCHEMA);
        self.scope.write(&mut out);
        out.bytes(&self.enrollment.canonical()?)
            .text(&self.profile)
            .bytes(&self.credential);
        if let Some(lifecycle) = &self.lifecycle {
            out.bytes(&lifecycle.canonical()?);
        } else {
            out.null();
        }
        Ok(bounded(out.into_bytes())?)
    }
    /// Decodes exact canonical request bytes; no authority is inferred.
    /// # Errors
    /// Refuses malformed or invalid nested values.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        let mut input = reader(bytes, 6)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            enrollment: Enrollment::decode(
                input.bytes_up_to(MAX_BYTES).map_err(AccountError::from)?,
            )?,
            profile: input
                .text_up_to(MAX_TEXT_BYTES)
                .map_err(AccountError::from)?
                .into(),
            credential: input
                .bytes_up_to(MAX_CREDENTIAL_BYTES)
                .map_err(AccountError::from)?
                .to_vec(),
            lifecycle: if input.take_null() {
                None
            } else {
                Some(Lifecycle::decode(
                    input.bytes_up_to(MAX_BYTES).map_err(AccountError::from)?,
                )?)
            },
        };
        input.finish().map_err(AccountError::from)?;
        value.canonical()?;
        Ok(value)
    }
    /// Authenticates the existing request carrier and its presented signing identity.
    /// # Errors
    /// Refuses trust, operation, direction or signer mismatch and invalid payloads.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
    ) -> Result<Self, ExchangeError> {
        envelope.verify(expected)?;
        if envelope.direction != EnvelopeDirection::Request || envelope.kind != MACHINE_REGISTER {
            return Err(BootstrapError::Kind.into());
        }
        let request = Self::decode(&envelope.payload)?;
        if envelope.signer != request.enrollment.binding.identity {
            return Err(ExchangeError::Binding);
        }
        Ok(request)
    }
}

/// Explicit authenticated registration acceptance; never a token or receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationAcceptance {
    /// Exact accepted membership.
    pub scope: MembershipScope,
    /// Exact accepted binding and capability declaration.
    pub enrollment: Enrollment,
    /// Exact accepted profile.
    pub profile: String,
    /// Authority's declared lifecycle decision.
    pub decision: EnrollmentDecision,
    /// Required NSD-signed nodes authority in the accepted Network, including Equal.
    pub source_binding: SignedSourceBinding,
}
impl RegistrationAcceptance {
    /// Encodes a complete acceptance.
    /// # Errors
    /// Refuses invalid profile or enrollment.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        data_text(&self.profile)?;
        let mut out = CborWriter::default();
        out.array(6).uint(SCHEMA);
        self.scope.write(&mut out);
        out.bytes(&self.enrollment.canonical()?)
            .text(&self.profile)
            .uint(tag(self.decision))
            .bytes(&self.source_binding.canonical()?);
        Ok(bounded(out.into_bytes())?)
    }
    /// Decodes one complete acceptance without committing it.
    /// # Errors
    /// Refuses malformed encodings and unsupported decision tags.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        let mut input = reader(bytes, 6)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            enrollment: Enrollment::decode(
                input.bytes_up_to(MAX_BYTES).map_err(AccountError::from)?,
            )?,
            profile: input
                .text_up_to(MAX_TEXT_BYTES)
                .map_err(AccountError::from)?
                .into(),
            decision: decision(input.uint().map_err(AccountError::from)?)?,
            source_binding: SignedSourceBinding::decode(
                input
                    .bytes_up_to(MAX_SOURCE_BYTES)
                    .map_err(AccountError::from)?,
            )?,
        };
        input.finish().map_err(AccountError::from)?;
        value.canonical()?;
        Ok(value)
    }
}

/// Verifies the authority's response and compares every staged enrollment fact.
/// # Errors
/// Refuses unauthenticated carriers, mismatches and invalid lifecycle transitions.
pub fn compare_registration_acceptance(
    envelope: &BootstrapEnvelope,
    expected: &EnvelopeExpectation<'_>,
    staged: &RegistrationRequest,
    committed: Option<&NodeBinding>,
    rebind: RebindAuthorization,
    pending: &SourceEnrollmentExpectation<'_>,
) -> Result<EnrollmentDecision, ExchangeError> {
    staged.canonical()?;
    envelope.verify(expected)?;
    if envelope.direction != EnvelopeDirection::Response || envelope.kind != MACHINE_REGISTER {
        return Err(BootstrapError::Kind.into());
    }
    if envelope.recipient != Some(staged.enrollment.binding.identity) {
        return Err(BootstrapError::Recipient.into());
    }
    let accepted = RegistrationAcceptance::decode(&envelope.payload)?;
    let local = compare_registration_payload(&accepted, staged, committed, rebind)?;
    if pending.scope != "nodes"
        || pending.served_realm != RealmId::from_bytes(staged.scope.network_id)
        || pending.recipient != staged.enrollment.binding.identity
        || pending.source_node != staged.enrollment.binding.identity
        || pending.profile.as_str() != staged.profile
    {
        return Err(SourceError::Authority.into());
    }
    accepted
        .source_binding
        .verify_response(envelope, expected, pending)?;
    Ok(local)
}

/// Compares a decoded acceptance independently of its authenticated transport.
pub(super) fn compare_registration_payload(
    accepted: &RegistrationAcceptance,
    staged: &RegistrationRequest,
    committed: Option<&NodeBinding>,
    rebind: RebindAuthorization,
) -> Result<EnrollmentDecision, ExchangeError> {
    staged.canonical()?;
    if accepted.scope != staged.scope {
        return Err(ExchangeError::Scope);
    }
    if accepted.enrollment.binding != staged.enrollment.binding {
        return Err(ExchangeError::Binding);
    }
    if accepted.enrollment.capabilities != staged.enrollment.capabilities {
        return Err(ExchangeError::Capabilities);
    }
    if accepted.profile != staged.profile {
        return Err(ExchangeError::Profile);
    }
    let local = decide_enrollment(
        committed,
        &staged.enrollment,
        staged.lifecycle.as_ref(),
        rebind,
    )?;
    if local != accepted.decision {
        return Err(ExchangeError::Lifecycle);
    }
    Ok(local)
}

/// Exact requested source authority; selection itself grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationSourceScope {
    /// Enrollment Network for nodes, accepted contribution Network for egress.
    pub served_realm: RealmId,
    /// Existing bounded source scope, compared exactly with the response.
    pub publication_scope: String,
}
impl AuthenticationSourceScope {
    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        token(&self.publication_scope)?;
        out.array(2)
            .text(&self.served_realm.to_string())
            .text(&self.publication_scope);
        Ok(())
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(2)?;
        Ok(Self {
            served_realm: realm(input)?,
            publication_scope: input.text_up_to(MAX_TEXT_BYTES)?.into(),
        })
    }
}

/// Exact registration custody observed from an authenticated enrollment receipt.
///
/// These identifiers are independent of Node binding and publication generations.
/// The authority must compare all three under the same locks as current Account
/// standing and shared custody, before issuing any token or source. They do not
/// themselves authorize anything; gateways without an Account do not fabricate them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationCondition {
    /// Immutable server Node record identifier, not the identity-derived Node ID.
    pub node_id: Id,
    /// Exact credential incarnation established by explicit enrollment.
    pub credential_incarnation: Id,
    /// Exact deployment Account activation established by explicit enrollment.
    pub activation_generation: Id,
}

impl RegistrationCondition {
    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        require(self.node_id != [0; 16])?;
        require(self.credential_incarnation != [0; 16])?;
        require(self.activation_generation != [0; 16])?;
        out.array(3)
            .bytes(&self.node_id)
            .bytes(&self.credential_incarnation)
            .bytes(&self.activation_generation);
        Ok(())
    }

    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(3)?;
        Ok(Self {
            node_id: input.fixed_bytes()?,
            credential_incarnation: input.fixed_bytes()?,
            activation_generation: input.fixed_bytes()?,
        })
    }
}

/// Authentication of the already accepted binding; grants no enrollment acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationRequest {
    /// Exact membership to authenticate.
    pub scope: MembershipScope,
    /// Previously accepted Node binding.
    pub binding: NodeBinding,
    /// Required exact source selector retained with the pending request nonce.
    pub source_scope: AuthenticationSourceScope,
    /// Required for Account-owned Connectors. Only an independently established
    /// non-Account gateway may use None; decoding cannot determine that role.
    pub registration: Option<RegistrationCondition>,
}
impl AuthenticationRequest {
    /// Authenticates a request against the already committed scope and binding.
    /// # Errors
    /// Refuses untrusted carriers, wrong operations, scope or signing self-binding.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        scope: &MembershipScope,
        binding: &NodeBinding,
    ) -> Result<Self, ExchangeError> {
        envelope.verify(expected)?;
        if envelope.direction != EnvelopeDirection::Request || envelope.kind != MACHINE_AUTH {
            return Err(BootstrapError::Kind.into());
        }
        let request = Self::decode(&envelope.payload)?;
        if &request.scope != scope {
            return Err(ExchangeError::Scope);
        }
        if &request.binding != binding || envelope.signer != binding.identity {
            return Err(ExchangeError::Binding);
        }
        Ok(request)
    }

    /// Encodes the fixed machine-control purpose.
    /// # Errors
    /// Refuses an invalid binding.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.binding.validate()?;
        let mut out = CborWriter::default();
        out.array(6).uint(SCHEMA);
        self.scope.write(&mut out);
        self.binding.write(&mut out);
        out.text(MACHINE_AUTH_PURPOSE);
        self.source_scope.write(&mut out)?;
        if let Some(registration) = &self.registration {
            registration.write(&mut out)?;
        } else {
            out.null();
        }
        bounded(out.into_bytes())
    }
    /// Decodes a canonical authentication request.
    /// # Errors
    /// Refuses unsupported purpose or invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 6)?;
        let scope = MembershipScope::read(&mut input)?;
        let binding = NodeBinding::read(&mut input)?;
        require(input.text_up_to(MAX_TEXT_BYTES)? == MACHINE_AUTH_PURPOSE)?;
        let value = Self {
            scope,
            binding,
            source_scope: AuthenticationSourceScope::read(&mut input)?,
            registration: if input.take_null() {
                None
            } else {
                Some(RegistrationCondition::read(&mut input)?)
            },
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Opaque compact token response; verification and custody stay with the consumer.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticationResponse {
    /// Unverified compact JWT, never sufficient registration acceptance.
    pub token: String,
    /// Required NSD-signed authority for the independently accepted source Node.
    pub source_binding: SignedSourceBinding,
}
impl std::fmt::Debug for AuthenticationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticationResponse([redacted])")
    }
}
impl AuthenticationResponse {
    /// Authenticates the response and its nested source against pending enrollment facts.
    /// Token signature, claims verification and custody remain consumer responsibilities.
    /// # Errors
    /// Refuses carrier trust, operation, correlation or nested authority disagreement.
    pub fn from_envelope(
        envelope: &BootstrapEnvelope,
        expected: &EnvelopeExpectation<'_>,
        pending: &SourceEnrollmentExpectation<'_>,
    ) -> Result<Self, ExchangeError> {
        envelope.verify(expected)?;
        if envelope.direction != EnvelopeDirection::Response || envelope.kind != MACHINE_AUTH {
            return Err(BootstrapError::Kind.into());
        }
        let value = Self::decode(&envelope.payload)?;
        value
            .source_binding
            .verify_response(envelope, expected, pending)?;
        Ok(value)
    }

    /// Encodes bounded opaque compact token data and required signed source authority.
    /// # Errors
    /// Refuses empty, non-ASCII or oversized data and invalid source fields.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        require(
            !self.token.is_empty()
                && self.token.len() <= MAX_CREDENTIAL_BYTES
                && self.token.bytes().all(|b| b.is_ascii_graphic()),
        )?;
        let mut out = CborWriter::default();
        out.array(3)
            .uint(SCHEMA)
            .text(&self.token)
            .bytes(&self.source_binding.canonical()?);
        Ok(bounded(out.into_bytes())?)
    }
    /// Decodes token and source data without authenticating either.
    /// # Errors
    /// Refuses missing binding, malformed fields and noncanonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        let mut input = reader(bytes, 3)?;
        let value = Self {
            token: input
                .text_up_to(MAX_CREDENTIAL_BYTES)
                .map_err(AccountError::from)?
                .into(),
            source_binding: SignedSourceBinding::decode(
                input
                    .bytes_up_to(MAX_SOURCE_BYTES)
                    .map_err(AccountError::from)?,
            )?,
        };
        input.finish().map_err(AccountError::from)?;
        value.canonical()?;
        Ok(value)
    }
}

/// Empty signed information request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InformationRequest;
impl InformationRequest {
    /// Canonical empty request tuple.
    #[must_use]
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = CborWriter::default();
        out.array(1).uint(SCHEMA);
        out.into_bytes()
    }
    /// Decodes exactly one empty request.
    /// # Errors
    /// Refuses any other shape, schema or trailing data.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        reader(bytes, 1)?.finish()?;
        Ok(Self)
    }
}

/// Signed information retaining bootstrap trust and declared metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InformationResponse {
    /// Existing canonical bootstrap discovery.
    pub discovery: BootstrapDiscovery,
    /// Instance-level discovery hint; never the authenticated tenant membership.
    pub realm: String,
    /// Provider identifier.
    pub provider: String,
    /// Declared software version.
    pub version: String,
    /// Sorted unique supported authentication method identifiers.
    pub auth_methods: Vec<String>,
    /// Sorted unique declared capabilities, never grants.
    pub capabilities: Vec<String>,
}
impl InformationResponse {
    /// Encodes information with unchanged bootstrap discovery bytes.
    /// # Errors
    /// Refuses invalid discovery, metadata or canonical sets.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        data_text(&self.provider)?;
        data_text(&self.version)?;
        data_text(&self.realm)?;
        require(
            ascending(&self.auth_methods)
                && self
                    .auth_methods
                    .iter()
                    .all(|s| matches!(s.as_str(), "auth_key" | "device_flow" | "oauth2")),
        )?;
        // Reuse enrollment's capability-set validator without a parallel syntax.
        crate::account::node::enrollment::validate_capabilities(&self.capabilities)?;
        let mut out = CborWriter::default();
        out.array(7)
            .uint(SCHEMA)
            .bytes(&self.discovery.canonical()?)
            .text(&self.realm)
            .text(&self.provider)
            .text(&self.version)
            .array(self.auth_methods.len());
        for method in &self.auth_methods {
            out.text(method);
        }
        out.array(self.capabilities.len());
        for capability in &self.capabilities {
            out.text(capability);
        }
        Ok(bounded(out.into_bytes())?)
    }
    /// Decodes signed information payload values without trusting them.
    /// # Errors
    /// Refuses malformed or noncanonical fields and unsupported methods.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        let mut input = reader(bytes, 7)?;
        let discovery =
            BootstrapDiscovery::decode(input.bytes_up_to(MAX_BYTES).map_err(AccountError::from)?)?;
        let realm = input
            .text_up_to(MAX_TEXT_BYTES)
            .map_err(AccountError::from)?
            .into();
        let provider = input
            .text_up_to(MAX_TEXT_BYTES)
            .map_err(AccountError::from)?
            .into();
        let version = input
            .text_up_to(MAX_TEXT_BYTES)
            .map_err(AccountError::from)?
            .into();
        let methods = input.array_up_to(3).map_err(AccountError::from)?;
        let mut auth_methods = Vec::new();
        for _ in 0..methods {
            auth_methods.push(
                input
                    .text_up_to(MAX_TEXT_BYTES)
                    .map_err(AccountError::from)?
                    .into(),
            );
        }
        let count = input
            .array_up_to(crate::account::node::MAX_CAPABILITIES)
            .map_err(AccountError::from)?;
        let mut capabilities = Vec::new();
        for _ in 0..count {
            capabilities.push(
                input
                    .text_up_to(crate::account::node::MAX_CAPABILITY_BYTES)
                    .map_err(AccountError::from)?
                    .into(),
            );
        }
        input.finish().map_err(AccountError::from)?;
        let value = Self {
            discovery,
            realm,
            provider,
            version,
            auth_methods,
            capabilities,
        };
        value.canonical()?;
        Ok(value)
    }
}
