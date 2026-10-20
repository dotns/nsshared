//! Pure candidate enrollment, authentication and information exchange.
use super::{
    AccountError, BootstrapDiscovery, BootstrapEnvelope, BootstrapError, Enrollment,
    EnrollmentDecision, EnrollmentError, EnvelopeDirection, EnvelopeExpectation, Lifecycle,
    MAX_BYTES, NodeBinding, RebindAuthorization, SCHEMA, bounded, decide_enrollment, reader,
    require,
};
use crate::encoding::{CborReader, CborWriter};
use nsshared_service_control::Id;
use thiserror::Error;

/// Confidential authentication configuration request/response operation.
pub const EDGE_AUTH_CONFIG_GET: &str = "edge.auth.config.get";

/// Registration operation inside the signed carrier.
pub const MACHINE_REGISTER: &str = "machine.register";
/// Authentication operation inside the signed carrier.
pub const MACHINE_AUTH: &str = "machine.auth";
/// Signed information operation.
pub const INFO_GET: &str = "info.get";
/// Machine-control token purpose.
pub const MACHINE_AUTH_PURPOSE: &str = "control";
/// Confidential signed operation endpoint.
pub const CONTROL_ENVELOPE_PATH: &str = "/api/v1/control";
/// WebPKI discovery endpoint.
pub const DISCOVERY_PATH: &str = "/api/v1/info";
/// Confidential machine key-set endpoint.
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

/// Explicit membership owner; identities are shared across its served realms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipScope {
    /// Provisioned NSD identifier.
    pub nsd_id: Id,
    /// Provisioned membership network identifier.
    pub network_id: Id,
}
impl MembershipScope {
    fn write(&self, out: &mut CborWriter) {
        out.array(2).bytes(&self.nsd_id).bytes(&self.network_id);
    }
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
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

fn text(value: &str) -> Result<(), AccountError> {
    require(!value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control))
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
        _ => Err(AccountError::InvalidField),
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
        text(&self.profile)?;
        require(!self.credential.is_empty() && self.credential.len() <= 16_384)?;
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
            profile: input.text_up_to(256).map_err(AccountError::from)?.into(),
            credential: input
                .bytes_up_to(16_384)
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
}
impl RegistrationAcceptance {
    /// Encodes a complete acceptance.
    /// # Errors
    /// Refuses invalid profile or enrollment.
    pub fn canonical(&self) -> Result<Vec<u8>, ExchangeError> {
        text(&self.profile)?;
        let mut out = CborWriter::default();
        out.array(5).uint(SCHEMA);
        self.scope.write(&mut out);
        out.bytes(&self.enrollment.canonical()?)
            .text(&self.profile)
            .uint(tag(self.decision));
        Ok(bounded(out.into_bytes())?)
    }
    /// Decodes one complete acceptance without committing it.
    /// # Errors
    /// Refuses malformed encodings and unsupported decision tags.
    pub fn decode(bytes: &[u8]) -> Result<Self, ExchangeError> {
        let mut input = reader(bytes, 5)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            enrollment: Enrollment::decode(
                input.bytes_up_to(MAX_BYTES).map_err(AccountError::from)?,
            )?,
            profile: input.text_up_to(256).map_err(AccountError::from)?.into(),
            decision: decision(input.uint().map_err(AccountError::from)?)?,
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

/// Authentication of the already accepted binding; grants no enrollment acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationRequest {
    /// Exact membership to authenticate.
    pub scope: MembershipScope,
    /// Previously accepted Node binding.
    pub binding: NodeBinding,
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
        out.array(4).uint(SCHEMA);
        self.scope.write(&mut out);
        self.binding.write(&mut out);
        out.text(MACHINE_AUTH_PURPOSE);
        bounded(out.into_bytes())
    }
    /// Decodes a canonical authentication request.
    /// # Errors
    /// Refuses unsupported purpose or invalid fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 4)?;
        let value = Self {
            scope: MembershipScope::read(&mut input)?,
            binding: NodeBinding::read(&mut input)?,
        };
        require(input.text_up_to(256)? == MACHINE_AUTH_PURPOSE)?;
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
}
impl std::fmt::Debug for AuthenticationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthenticationResponse([redacted])")
    }
}
impl AuthenticationResponse {
    /// Encodes bounded opaque compact token data.
    /// # Errors
    /// Refuses empty, non-ASCII or oversized data.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(
            !self.token.is_empty()
                && self.token.len() <= 16_384
                && self.token.bytes().all(|b| b.is_ascii_graphic()),
        )?;
        let mut out = CborWriter::default();
        out.array(2).uint(SCHEMA).text(&self.token);
        Ok(out.into_bytes())
    }
    /// Decodes opaque token data, without authenticating it.
    /// # Errors
    /// Refuses malformed fields and noncanonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 2)?;
        let value = Self {
            token: input.text_up_to(16_384)?.into(),
        };
        input.finish()?;
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
        vec![0x81, 1]
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
        text(&self.provider)?;
        text(&self.version)?;
        text(&self.realm)?;
        require(
            self.auth_methods.windows(2).all(|p| p[0] < p[1])
                && self
                    .auth_methods
                    .iter()
                    .all(|s| matches!(s.as_str(), "auth_key" | "device_flow" | "oauth2")),
        )?;
        // Reuse enrollment's capability-set validator without a parallel syntax.
        super::enrollment::validate_capabilities(&self.capabilities)?;
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
        let realm = input.text_up_to(256).map_err(AccountError::from)?.into();
        let provider = input.text_up_to(256).map_err(AccountError::from)?.into();
        let version = input.text_up_to(256).map_err(AccountError::from)?.into();
        let methods = input.array_up_to(3).map_err(AccountError::from)?;
        let mut auth_methods = Vec::new();
        for _ in 0..methods {
            auth_methods.push(input.text_up_to(256).map_err(AccountError::from)?.into());
        }
        let count = input
            .array_up_to(super::MAX_CAPABILITIES)
            .map_err(AccountError::from)?;
        let mut capabilities = Vec::new();
        for _ in 0..count {
            capabilities.push(
                input
                    .text_up_to(super::MAX_CAPABILITY_BYTES)
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
