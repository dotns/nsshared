//! Confidential catalog values; decoding never performs credential verification.
use super::*;
use crate::{
    account::codec::ascending_by, account::codec::read_optional_text, account::codec::read_texts,
    account::codec::write_texts, account::limits::MAX_TEXT_BYTES,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};

fn data(value: &str) -> Result<(), AccountError> {
    require(!value.is_empty() && value.len() <= 8192)
}
fn write_text(value: &str, out: &mut CborWriter, is_token: bool) -> Result<(), AccountError> {
    if is_token {
        token(value)?;
    } else {
        data(value)?;
    }
    out.text(value);
    Ok(())
}
fn write_optional(
    value: &Option<String>,
    out: &mut CborWriter,
    token: bool,
) -> Result<(), AccountError> {
    if let Some(value) = value {
        write_text(value, out, token)?;
    } else {
        out.null();
    }
    Ok(())
}
fn write_strings(values: &[String], out: &mut CborWriter) -> Result<(), AccountError> {
    write_texts(out, values, token)
}
fn read_strings(input: &mut CborReader<'_>) -> Result<Vec<String>, AccountError> {
    read_texts(input, MAX_TEXT_BYTES)
}

/// Provider protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum AuthProviderKind {
    /// OIDC relying party.
    Oidc = 0,
}
impl AuthProviderKind {
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        match input.uint()? {
            0 => Ok(Self::Oidc),
            _ => Err(AccountError::Field),
        }
    }
}

/// Provider-specific organization behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum AuthOrganizationMode {
    /// Logto organization login and exchange.
    Logto = 0,
}
impl AuthOrganizationMode {
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        match input.uint()? {
            0 => Ok(Self::Logto),
            _ => Err(AccountError::Field),
        }
    }
}

/// Public JWT key source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum AuthKeySourceKind {
    /// OIDC discovery.
    Discovery = 0,
    /// Fixed HTTPS JWKS URI.
    Uri = 1,
    /// Actual public JWKS document.
    Inline = 2,
}
impl AuthKeySourceKind {
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        match input.uint()? {
            0 => Ok(Self::Discovery),
            1 => Ok(Self::Uri),
            2 => Ok(Self::Inline),
            _ => Err(AccountError::Field),
        }
    }
}

/// Authentication chain method; reserved OAuth2 is excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum AuthMethodKind {
    /// OIDC browser login.
    Oidc = 0,
    /// Client mTLS.
    Mtls = 1,
    /// API key.
    ApiKey = 2,
    /// Bearer JWT.
    Bearer = 3,
    /// Signed URL.
    SignedRequest = 4,
    /// Basic authentication.
    Basic = 5,
}
impl AuthMethodKind {
    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        match input.uint()? {
            0 => Ok(Self::Oidc),
            1 => Ok(Self::Mtls),
            2 => Ok(Self::ApiKey),
            3 => Ok(Self::Bearer),
            4 => Ok(Self::SignedRequest),
            5 => Ok(Self::Basic),
            _ => Err(AccountError::Field),
        }
    }
}

/// One actual confidential secret and its rotation deadline.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthSecretVersion {
    /// Secret identity, never a substitute for value.
    pub reference: String,
    /// Positive rotation version.
    pub version: u32,
    /// Actual Unix-second expiry.
    pub expires_seconds: u64,
    /// Exact confidential value.
    pub value: String,
}
impl AuthSecretVersion {
    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(4);
        write_text(&self.reference, out, true)?;
        out.uint(u64::from(self.version));
        out.uint(self.expires_seconds);
        write_text(&self.value, out, false)?;
        Ok(())
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(4)?;
        Ok(Self {
            reference: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            version: u32::try_from(input.uint()?).map_err(|_| AccountError::Field)?,
            expires_seconds: input.uint()?,
            value: input.text_up_to(8192)?.to_owned(),
        })
    }
}

/// Current secret plus bounded rotation overlap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthSecretSet {
    /// Active version.
    pub current: AuthSecretVersion,
    /// Previous versions in increasing version order.
    pub previous: Vec<AuthSecretVersion>,
}
impl AuthSecretSet {
    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(2);
        self.current.write(out)?;
        require(self.previous.len() <= MAX_EDGE_ITEMS)?;
        out.array(self.previous.len());
        for value in &self.previous {
            value.write(out)?;
        }
        Ok(())
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(2)?;
        Ok(Self {
            current: AuthSecretVersion::read(input)?,
            previous: {
                let count = input.array_up_to(MAX_EDGE_ITEMS)?;
                (0..count)
                    .map(|_| AuthSecretVersion::read(input))
                    .collect::<Result<Vec<_>, _>>()?
            },
        })
    }
}

/// Complete OIDC relying-party configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthProvider {
    /// Realm-local provider reference.
    pub reference: String,
    /// Explicit provider protocol.
    pub kind: AuthProviderKind,
    /// Explicit HTTPS issuer.
    pub issuer: String,
    /// Exact client identifier.
    pub client_id: String,
    /// Actual rotating client secrets.
    pub client_secret: AuthSecretSet,
    /// Ordered unique requested scopes.
    pub scopes: Vec<String>,
    /// Optional exact resource indicator.
    pub audience: Option<String>,
    /// Optional exact subject template.
    pub subject_template: Option<String>,
    /// Optional exact external IdP template.
    pub idp_template: Option<String>,
    /// External namespace, independent of control realm.
    pub subject_realm: String,
    /// Optional organization identifier.
    pub organization_id: Option<String>,
    /// Explicit provider-specific organization semantics.
    pub organization_mode: Option<AuthOrganizationMode>,
    /// Explicit HTTPS callback base.
    pub redirect_base_url: String,
}
impl AuthProvider {
    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(13);
        write_text(&self.reference, out, true)?;
        out.uint(self.kind as u64);
        write_text(&self.issuer, out, false)?;
        write_text(&self.client_id, out, false)?;
        self.client_secret.write(out)?;
        write_strings(&self.scopes, out)?;
        write_optional(&self.audience, out, false)?;
        write_optional(&self.subject_template, out, false)?;
        write_optional(&self.idp_template, out, false)?;
        write_text(&self.subject_realm, out, false)?;
        write_optional(&self.organization_id, out, false)?;
        if let Some(value) = self.organization_mode {
            out.uint(value as u64);
        } else {
            out.null();
        }
        write_text(&self.redirect_base_url, out, false)?;
        Ok(())
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(13)?;
        Ok(Self {
            reference: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            kind: AuthProviderKind::read(input)?,
            issuer: input.text_up_to(8192)?.to_owned(),
            client_id: input.text_up_to(8192)?.to_owned(),
            client_secret: AuthSecretSet::read(input)?,
            scopes: read_strings(input)?,
            audience: read_optional_text(input, 8192)?,
            subject_template: read_optional_text(input, 8192)?,
            idp_template: read_optional_text(input, 8192)?,
            subject_realm: input.text_up_to(8192)?.to_owned(),
            organization_id: read_optional_text(input, 8192)?,
            organization_mode: if input.take_null() {
                None
            } else {
                Some(AuthOrganizationMode::read(input)?)
            },
            redirect_base_url: input.text_up_to(8192)?.to_owned(),
        })
    }
}

/// Explicit consumer principal independent of credential material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthConsumer {
    /// Realm-local consumer reference.
    pub reference: String,
    /// Exact qualified non-group subject.
    pub subject: PolicySubject,
    /// Consumer enablement, independent of credential enablement.
    pub enabled: bool,
    /// Optional presentation text.
    pub display_name: Option<String>,
}
impl AuthConsumer {
    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(4);
        write_text(&self.reference, out, true)?;
        out.bytes(&self.subject.canonical()?);
        out.boolean(self.enabled);
        write_optional(&self.display_name, out, false)?;
        Ok(())
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(4)?;
        Ok(Self {
            reference: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            subject: PolicySubject::decode(input.bytes_up_to(MAX_BYTES)?)?,
            enabled: input.boolean()?,
            display_name: read_optional_text(input, 8192)?,
        })
    }
}

/// Private verifier joined to an unchanged public credential binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthCredential {
    /// Explicit owning consumer.
    pub consumer_ref: String,
    /// Credential identity, subject, enabled state and expiry.
    pub binding: SubjectBinding,
    /// Ordered opaque credential scopes.
    pub scopes: Vec<String>,
    /// Actual verifier or exact CA dependency.
    pub verifier: AuthVerifier,
}
impl AuthCredential {
    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(4);
        write_text(&self.consumer_ref, out, true)?;
        out.bytes(&self.binding.canonical()?);
        write_strings(&self.scopes, out)?;
        self.verifier.write(out)?;
        Ok(())
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(4)?;
        Ok(Self {
            consumer_ref: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            binding: SubjectBinding::decode(input.bytes_up_to(MAX_BYTES)?)?,
            scopes: read_strings(input)?,
            verifier: AuthVerifier::read(input)?,
        })
    }
}

/// Public key acquisition configuration for an existing authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthKeySource {
    /// Exact EdgeJwtAuthority reference.
    pub authority_ref: String,
    /// Authority enablement.
    pub enabled: bool,
    /// Discovery, fixed URI or inline public JWKS.
    pub kind: AuthKeySourceKind,
    /// Null only for discovery; URI or actual inline public JWKS otherwise.
    pub value: Option<String>,
}
impl AuthKeySource {
    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(4);
        write_text(&self.authority_ref, out, true)?;
        out.boolean(self.enabled);
        out.uint(self.kind as u64);
        write_optional(&self.value, out, false)?;
        Ok(())
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(4)?;
        Ok(Self {
            authority_ref: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            enabled: input.boolean()?,
            kind: AuthKeySourceKind::read(input)?,
            value: read_optional_text(input, 8192)?,
        })
    }
}

/// One ordered route authentication method.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthImportMethod {
    /// Explicit authentication mechanism.
    pub kind: AuthMethodKind,
    /// Exact provider/authority/CA reference or opaque method-catalog selector.
    pub reference: String,
    /// Optional HTTPS override, only for OIDC.
    pub redirect_base_url: Option<String>,
}
impl AuthImportMethod {
    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(3);
        out.uint(self.kind as u64);
        write_text(&self.reference, out, true)?;
        write_optional(&self.redirect_base_url, out, false)?;
        Ok(())
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(3)?;
        Ok(Self {
            kind: AuthMethodKind::read(input)?,
            reference: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            redirect_base_url: read_optional_text(input, 8192)?,
        })
    }
}

/// Route-local ordered authentication chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthRouteImport {
    /// Exact route id; ownership is checked by the consumer.
    pub route_id: String,
    /// Evaluator order, never sorted.
    pub methods: Vec<AuthImportMethod>,
    /// Explicit anonymous bypass behavior.
    pub anonymous_bypass: bool,
    /// Explicit failure behavior.
    pub fail_closed: bool,
}
impl AuthRouteImport {
    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(4);
        write_text(&self.route_id, out, true)?;
        require(self.methods.len() <= MAX_EDGE_ITEMS)?;
        out.array(self.methods.len());
        for value in &self.methods {
            value.write(out)?;
        }
        out.boolean(self.anonymous_bypass);
        out.boolean(self.fail_closed);
        Ok(())
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(4)?;
        Ok(Self {
            route_id: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            methods: {
                let count = input.array_up_to(MAX_EDGE_ITEMS)?;
                (0..count)
                    .map(|_| AuthImportMethod::read(input))
                    .collect::<Result<Vec<_>, _>>()?
            },
            anonymous_bypass: input.boolean()?,
            fail_closed: input.boolean()?,
        })
    }
}

impl std::fmt::Debug for AuthSecretVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSecretVersion")
            .field("reference", &self.reference)
            .field("version", &self.version)
            .field("expires_seconds", &self.expires_seconds)
            .finish_non_exhaustive()
    }
}
impl AuthSecretSet {
    pub(in crate::account) fn validate(&self) -> Result<(), AccountError> {
        require(self.current.version > 0 && self.current.expires_seconds > 0)?;
        require(self.previous.len() <= MAX_EDGE_ITEMS)?;
        require(ascending_by(&self.previous, |value| &value.version))?;
        for old in &self.previous {
            require(
                old.reference == self.current.reference
                    && old.version > 0
                    && old.version < self.current.version
                    && old.expires_seconds > 0,
            )?;
        }
        Ok(())
    }
}

/// Actual private verifier material; Debug never includes verifier contents.
#[derive(Clone, Eq, PartialEq)]
pub enum AuthVerifier {
    /// API key hash, never the plaintext API key.
    ApiKey {
        /// Lookup key id.
        key_id: String,
        /// Actual verifier hash.
        verifier_hash: String,
    },
    /// Password hash, never a plaintext password.
    Basic {
        /// Exact username data.
        username: String,
        /// Actual PHC verifier string.
        phc_hash: String,
    },
    /// Signed URL key id and actual rotating HMAC keys.
    SignedUrl {
        /// Signature key id.
        kid: String,
        /// Current and previous keys.
        hmac_keys: AuthSecretSet,
    },
    /// Client-mTLS identity with a separately installed CA dependency.
    Mtls {
        /// Exact workload SPIFFE identity.
        spiffe_id: String,
        /// Exact client-CA reference/generation.
        trust_material: EdgeMaterialRef,
    },
}
impl std::fmt::Debug for AuthVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthVerifier")
            .field("method", &self.method())
            .finish_non_exhaustive()
    }
}
impl AuthVerifier {
    pub(in crate::account) const fn method(&self) -> AuthMethodKind {
        match self {
            Self::ApiKey { .. } => AuthMethodKind::ApiKey,
            Self::Basic { .. } => AuthMethodKind::Basic,
            Self::SignedUrl { .. } => AuthMethodKind::SignedRequest,
            Self::Mtls { .. } => AuthMethodKind::Mtls,
        }
    }
    pub(in crate::account) fn validate(&self, public: &EdgeAuth) -> Result<(), AccountError> {
        match self {
            Self::SignedUrl { hmac_keys, .. } => hmac_keys.validate(),
            Self::Mtls { trust_material, .. } => require(
                trust_material.kind == EdgeMaterialKind::ClientCa
                    && public.materials.contains(trust_material),
            ),
            _ => Ok(()),
        }
    }
    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(3);
        match self {
            Self::ApiKey {
                key_id,
                verifier_hash,
            } => {
                out.uint(0);
                write_text(key_id, out, true)?;
                write_text(verifier_hash, out, false)?;
            }
            Self::Basic { username, phc_hash } => {
                out.uint(1);
                write_text(username, out, false)?;
                write_text(phc_hash, out, false)?;
            }
            Self::SignedUrl { kid, hmac_keys } => {
                out.uint(2);
                write_text(kid, out, true)?;
                hmac_keys.write(out)?;
            }
            Self::Mtls {
                spiffe_id,
                trust_material,
            } => {
                out.uint(3);
                write_text(spiffe_id, out, false)?;
                trust_material.write(out)?;
            }
        }
        Ok(())
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(3)?;
        match input.uint()? {
            0 => Ok(Self::ApiKey {
                key_id: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
                verifier_hash: input.text_up_to(8192)?.to_owned(),
            }),
            1 => Ok(Self::Basic {
                username: input.text_up_to(8192)?.to_owned(),
                phc_hash: input.text_up_to(8192)?.to_owned(),
            }),
            2 => Ok(Self::SignedUrl {
                kid: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
                hmac_keys: AuthSecretSet::read(input)?,
            }),
            3 => Ok(Self::Mtls {
                spiffe_id: input.text_up_to(8192)?.to_owned(),
                trust_material: EdgeMaterialRef::read(input)?,
            }),
            _ => Err(AccountError::Field),
        }
    }
}

/// Explicit JWT credential-to-consumer join; equal subjects do not imply ownership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthJwtConsumer {
    /// Existing JwtSubjectBinding credential anchor.
    pub credential_ref: String,
    /// Exact owning AuthConsumer reference.
    pub consumer_ref: String,
}
impl AuthJwtConsumer {
    pub(in crate::account) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        out.array(2);
        write_text(&self.credential_ref, out, true)?;
        write_text(&self.consumer_ref, out, true)?;
        Ok(())
    }
    pub(in crate::account) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(2)?;
        Ok(Self {
            credential_ref: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            consumer_ref: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
        })
    }
}
