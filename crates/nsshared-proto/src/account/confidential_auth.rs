//! Pure confidential authentication delivery; see `docs/confidential-auth-candidate.md`.

use crate::RealmId;
mod values;
pub use values::*;

use super::policy_subject::{ordered_text, text};
use super::{
    AccountError, EdgeAuth, EdgeMaterialKind, EdgeMaterialRef, MAX_BYTES, MAX_EDGE_ITEMS,
    PolicySubject, SubjectAnchor, SubjectBinding, bounded, identity, reader, require, scope_text,
};
use crate::{IdentityKey, encoding::CborWriter};
use thiserror::Error;

/// Complete configuration delivered only inside a confidential authenticated envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthConfiguration {
    /// Contributing binary realm, independent of served realm.
    pub realm: RealmId,
    /// Positive generation in the requested auth reference's domain.
    pub generation: u64,
    /// Explicit default provider; None selects no provider.
    pub default_provider_ref: Option<String>,
    /// Complete providers, ordered by reference.
    pub providers: Vec<AuthProvider>,
    /// Actual current and previous cookie keys.
    pub cookie_keys: AuthSecretSet,
    /// Complete consumers, ordered by reference.
    pub consumers: Vec<AuthConsumer>,
    /// Complete private verifiers, ordered by credential anchor.
    pub credentials: Vec<AuthCredential>,
    /// Existing public subject/material/JWT metadata, unchanged.
    pub public_auth: EdgeAuth,
    /// Exactly one key source per public JWT authority.
    pub key_sources: Vec<AuthKeySource>,
    /// Exact JWT credential-to-consumer joins, ordered by credential reference.
    pub jwt_consumers: Vec<AuthJwtConsumer>,
    /// Route imports, ordered by route id; route authority stays external.
    pub imports: Vec<AuthRouteImport>,
}

fn https(value: &str) -> Result<(), AccountError> {
    require(value.len() <= 8192 && !value.chars().any(|c| c.is_whitespace() || c.is_control()))?;
    super::edge_material::issuer_url(value)
}
fn fixed_jwks_uri(value: &str) -> Result<(), AccountError> {
    require(value.len() <= 8192 && !value.chars().any(|c| c.is_whitespace() || c.is_control()))?;
    require(!value.contains(['#', '\\']))?;
    let authority = value
        .strip_prefix("https://")
        .ok_or(AccountError::InvalidField)?
        .split(['/', '?'])
        .next()
        .ok_or(AccountError::InvalidField)?;
    super::edge_material::issuer_url(&format!("https://{authority}"))?;
    for (index, byte) in value.bytes().enumerate() {
        if byte == b'%' {
            require(
                value
                    .as_bytes()
                    .get(index + 1..index + 3)
                    .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit)),
            )?;
        }
    }
    Ok(())
}
fn ordered<T>(values: &[T], key: impl Fn(&T) -> &str) -> Result<(), AccountError> {
    require(values.len() <= MAX_EDGE_ITEMS && values.windows(2).all(|p| key(&p[0]) < key(&p[1])))
}
fn anchor(binding: &SubjectBinding) -> Result<&str, AccountError> {
    if let SubjectAnchor::Credential(reference) = &binding.anchor {
        Ok(reference)
    } else {
        Err(AccountError::InvalidField)
    }
}

impl AuthConfiguration {
    fn validate(&self) -> Result<(), AccountError> {
        require(self.generation > 0 && self.realm == self.public_auth.realm)?;
        ordered(&self.providers, |v| &v.reference)?;
        ordered(&self.consumers, |v| &v.reference)?;
        ordered(&self.key_sources, |v| &v.authority_ref)?;
        ordered(&self.jwt_consumers, |v| &v.credential_ref)?;
        ordered(&self.imports, |v| &v.route_id)?;
        require(self.credentials.len() <= MAX_EDGE_ITEMS)?;
        self.cookie_keys.validate()?;
        for provider in &self.providers {
            provider.client_secret.validate()?;
            https(&provider.issuer)?;
            https(&provider.redirect_base_url)?;
            require(provider.organization_mode.is_none() || provider.organization_id.is_some())?;
        }
        if let Some(default) = &self.default_provider_ref {
            text(default)?;
            require(self.providers.iter().any(|p| &p.reference == default))?;
        }
        for consumer in &self.consumers {
            consumer.subject.in_realm(self.realm)?;
            require(!consumer.subject.is_group())?;
        }
        let mut credential_anchors = std::collections::BTreeSet::new();
        let mut previous: Option<&str> = None;
        for credential in &self.credentials {
            let key = anchor(&credential.binding)?;
            require(credential_anchors.insert(key))?;
            require(previous.is_none_or(|old| old < key))?;
            previous = Some(key);
            require(credential.binding.realm == self.realm)?;
            require(self.public_auth.bindings.contains(&credential.binding))?;
            require(self.consumers.iter().any(|c| {
                c.reference == credential.consumer_ref && c.subject == credential.binding.subject
            }))?;
            credential.verifier.validate(&self.public_auth)?;
        }
        require(self.key_sources.len() == self.public_auth.authorities.len())?;
        for source in &self.key_sources {
            require(
                self.public_auth
                    .authorities
                    .iter()
                    .any(|a| a.reference == source.authority_ref),
            )?;
            match source.kind {
                AuthKeySourceKind::Discovery => require(source.value.is_none())?,
                AuthKeySourceKind::Uri => {
                    fixed_jwks_uri(source.value.as_deref().ok_or(AccountError::InvalidField)?)?
                }
                AuthKeySourceKind::Inline => require(source.value.is_some())?,
            }
        }
        for binding in &self.public_auth.jwt_bindings {
            require(credential_anchors.insert(anchor(&binding.binding)?))?;
        }
        require(self.jwt_consumers.len() == self.public_auth.jwt_bindings.len())?;
        for join in &self.jwt_consumers {
            let binding = self
                .public_auth
                .jwt_bindings
                .iter()
                .find(|b| anchor(&b.binding).is_ok_and(|key| key == join.credential_ref))
                .ok_or(AccountError::InvalidField)?;
            require(self.consumers.iter().any(|c| {
                c.reference == join.consumer_ref && c.subject == binding.binding.subject
            }))?;
        }
        for import in &self.imports {
            require(import.methods.len() <= MAX_EDGE_ITEMS)?;
            let mut seen = std::collections::BTreeSet::new();
            for method in &import.methods {
                require(seen.insert((method.kind as u64, &method.reference)))?;
                if let Some(redirect) = &method.redirect_base_url {
                    require(method.kind == AuthMethodKind::Oidc)?;
                    https(redirect)?;
                }
                let exists = match method.kind {
                    AuthMethodKind::Oidc => self
                        .providers
                        .iter()
                        .any(|p| p.reference == method.reference),
                    AuthMethodKind::Bearer => self
                        .public_auth
                        .authorities
                        .iter()
                        .any(|a| a.reference == method.reference),
                    AuthMethodKind::Mtls => self.public_auth.materials.iter().any(|m| {
                        m.kind == EdgeMaterialKind::ClientCa && m.reference == method.reference
                    }),
                    AuthMethodKind::ApiKey
                    | AuthMethodKind::Basic
                    | AuthMethodKind::SignedRequest => true,
                };
                require(exists)?;
            }
        }
        Ok(())
    }

    /// Encodes complete private configuration without applying it.
    /// # Errors
    /// Rejects malformed values, duplicate entries, missing joins or bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(12)
            .uint(1)
            .bytes(self.realm.as_bytes())
            .uint(self.generation);
        if let Some(value) = &self.default_provider_ref {
            out.text(value);
        } else {
            out.null();
        }
        out.array(self.providers.len());
        for value in &self.providers {
            value.write(&mut out)?;
        }
        self.cookie_keys.write(&mut out)?;
        out.array(self.consumers.len());
        for value in &self.consumers {
            value.write(&mut out)?;
        }
        out.array(self.credentials.len());
        for value in &self.credentials {
            value.write(&mut out)?;
        }
        out.bytes(&self.public_auth.canonical()?);
        out.array(self.key_sources.len());
        for value in &self.key_sources {
            value.write(&mut out)?;
        }
        out.array(self.jwt_consumers.len());
        for value in &self.jwt_consumers {
            value.write(&mut out)?;
        }
        out.array(self.imports.len());
        for value in &self.imports {
            value.write(&mut out)?;
        }
        bounded(out.into_bytes())
    }

    /// Decodes bounded canonical configuration; authentication and installation stay external.
    /// # Errors
    /// Rejects noncanonical input, missing/unknown fields and invalid joins.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 12)?;
        let realm = RealmId::from_bytes(input.fixed_bytes()?);
        let generation = input.uint()?;
        let default_provider_ref = if input.take_null() {
            None
        } else {
            Some(input.text_up_to(256)?.to_owned())
        };
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let providers = (0..count)
            .map(|_| AuthProvider::read(&mut input))
            .collect::<Result<_, _>>()?;
        let cookie_keys = AuthSecretSet::read(&mut input)?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let consumers = (0..count)
            .map(|_| AuthConsumer::read(&mut input))
            .collect::<Result<_, _>>()?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let credentials = (0..count)
            .map(|_| AuthCredential::read(&mut input))
            .collect::<Result<_, _>>()?;
        let public_auth = EdgeAuth::decode(input.bytes_up_to(MAX_BYTES)?)?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let key_sources = (0..count)
            .map(|_| AuthKeySource::read(&mut input))
            .collect::<Result<_, _>>()?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let jwt_consumers = (0..count)
            .map(|_| AuthJwtConsumer::read(&mut input))
            .collect::<Result<_, _>>()?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let imports = (0..count)
            .map(|_| AuthRouteImport::read(&mut input))
            .collect::<Result<_, _>>()?;
        input.finish()?;
        let value = Self {
            realm,
            generation,
            default_provider_ref,
            providers,
            cookie_keys,
            consumers,
            credentials,
            public_auth,
            key_sources,
            jwt_consumers,
            imports,
        };
        value.canonical()?;
        Ok(value)
    }
}

/// Pending request bound to the authenticated public dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthConfigRequest {
    /// Correlation distinct from envelope replay nonce.
    pub request_id: [u8; 16],
    /// Exact gateway recipient; accepted binding validation remains external.
    pub recipient: IdentityKey,
    /// Signed served realm.
    pub served_realm: RealmId,
    /// Signed publication scope.
    pub scope: String,
    /// Realm contributing the material.
    pub realm: RealmId,
    /// Exact auth reference and generation.
    pub material: EdgeMaterialRef,
}
impl AuthConfigRequest {
    /// Encodes a pending configuration request.
    /// # Errors
    /// Rejects invalid scope, non-auth material and bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        scope_text(&self.scope)?;
        require(self.material.kind == EdgeMaterialKind::Auth)?;
        let mut out = CborWriter::default();
        out.array(7)
            .uint(1)
            .bytes(&self.request_id)
            .bytes(self.recipient.as_bytes())
            .text(&self.served_realm.to_string())
            .text(&self.scope)
            .bytes(self.realm.as_bytes());
        self.material.write(&mut out)?;
        bounded(out.into_bytes())
    }
    /// Decodes a bounded canonical pending request.
    /// # Errors
    /// Rejects malformed, missing or unknown fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 7)?;
        let value = Self {
            request_id: input.fixed_bytes()?,
            recipient: identity(&mut input)?,
            served_realm: input.text_up_to(26)?.parse()?,
            scope: input.text_up_to(256)?.to_owned(),
            realm: RealmId::from_bytes(input.fixed_bytes()?),
            material: EdgeMaterialRef::read(&mut input)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Correlated confidential response, not an installation acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthConfigResponse {
    /// Exact echoed pending request.
    pub request: AuthConfigRequest,
    /// Actual configuration, never synthesized from the material reference.
    pub configuration: AuthConfiguration,
}
/// Typed configuration refusal; carries no secret material.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthConfigError {
    /// Malformed contract.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Request id differs.
    #[error("configuration correlation mismatch")]
    Correlation,
    /// Recipient, served realm or scope differs.
    #[error("configuration scope mismatch")]
    Scope,
    /// Contributing realm differs.
    #[error("configuration realm mismatch")]
    Realm,
    /// Reference or kind differs.
    #[error("configuration reference mismatch")]
    Reference,
    /// Requested or payload generation differs.
    #[error("configuration generation mismatch")]
    Generation,
    /// Current authenticated dependency differs from the pending request.
    #[error("configuration dependency mismatch")]
    Dependency,
}
impl AuthConfigResponse {
    /// Encodes configuration with the exact request correlation.
    /// # Errors
    /// Rejects malformed nested request/configuration values and size overflow.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        out.array(3)
            .uint(1)
            .bytes(&self.request.canonical()?)
            .bytes(&self.configuration.canonical()?);
        bounded(out.into_bytes())
    }
    /// Decodes a response without accepting its correlation or authority.
    /// # Errors
    /// Rejects malformed/noncanonical nested data and bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 3)?;
        let value = Self {
            request: AuthConfigRequest::decode(input.bytes_up_to(MAX_BYTES)?)?,
            configuration: AuthConfiguration::decode(input.bytes_up_to(MAX_BYTES)?)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
    /// Compares pending request, payload and current authenticated dependency.
    ///
    /// The caller first verifies the confidential envelope's signer and explicit
    /// recipient against the accepted binding. No authority is established here.
    /// # Errors
    /// Refuses any scope, correlation, reference, generation or dependency mismatch.
    pub fn validate_for(
        &self,
        pending: &AuthConfigRequest,
        current_realm: RealmId,
        current_material: &EdgeMaterialRef,
    ) -> Result<(), AuthConfigError> {
        self.canonical()?;
        pending.canonical()?;
        let request = &self.request;
        if request.request_id != pending.request_id {
            return Err(AuthConfigError::Correlation);
        }
        if request.recipient != pending.recipient
            || request.served_realm != pending.served_realm
            || request.scope != pending.scope
        {
            return Err(AuthConfigError::Scope);
        }
        if request.realm != pending.realm || self.configuration.realm != pending.realm {
            return Err(AuthConfigError::Realm);
        }
        if request.material.kind != pending.material.kind
            || request.material.reference != pending.material.reference
        {
            return Err(AuthConfigError::Reference);
        }
        if request.material.generation != pending.material.generation
            || self.configuration.generation != pending.material.generation
        {
            return Err(AuthConfigError::Generation);
        }
        if current_realm != pending.realm
            || current_material != &pending.material
            || !self
                .configuration
                .public_auth
                .materials
                .contains(current_material)
        {
            return Err(AuthConfigError::Dependency);
        }
        Ok(())
    }
}
