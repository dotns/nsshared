//! Supplied claims and policy values, without token verification or key custody.

use nsshared_identity::realm::RealmId;

use crate::account::realm::rules::read_texts;
use crate::{
    account::AccountError, account::MAX_BYTES, account::SCHEMA, account::bounded, account::reader,
    account::realm::PolicySubject, account::realm::SubjectAnchor, account::realm::SubjectBinding,
    account::require,
};
use crate::{
    account::realm::subject::MAX_POLICY_TEXT, account::realm::subject::ordered_text,
    account::realm::subject::text,
};
use nsshared_codec::{cbor::CborReader, cbor::CborWriter};

use serde::{Deserialize, Serialize};

/// Ordered admin authorization scope; unknown wire names and values refuse.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
#[repr(u64)]
pub enum AdminScope {
    /// Read administration state.
    ReadOnly = 0,
    /// Read and mutate administration state.
    ReadWrite = 1,
    /// Cross-realm or irreversible administration operations.
    SuperAdmin = 2,
}

/// Claims supplied inside an independently authenticated admin token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTokenClaims {
    /// Explicit operator or service principal, never a group or wildcard.
    pub subject: PolicySubject,
    /// Required typed scope with no default.
    pub scope: AdminScope,
    /// Optional realm constraint; None alone grants no cross-realm authority.
    pub realm: Option<RealmId>,
    /// Actual Unix-second expiry; checked against a supplied clock only.
    pub expires_seconds: u64,
}

impl AdminTokenClaims {
    /// Requires an authorization level; token authentication remains external.
    ///
    /// # Errors
    /// Rejects insufficient scope.
    pub fn require_scope(&self, required: AdminScope) -> Result<(), AccountError> {
        require(self.scope >= required)
    }

    /// Compares exact caller-supplied context and actual expiry, without verifying a token.
    ///
    /// # Errors
    /// Rejects mismatched principal/realm, expired claims or insufficient scope.
    pub fn validate_context(
        &self,
        subject: &PolicySubject,
        realm: Option<RealmId>,
        required: AdminScope,
        now_seconds: u64,
    ) -> Result<(), AccountError> {
        self.canonical()?;
        require(
            &self.subject == subject && self.realm == realm && now_seconds < self.expires_seconds,
        )?;
        self.require_scope(required)
    }

    /// Encodes exact typed claims; decoding alone grants no admin authority.
    ///
    /// # Errors
    /// Rejects group or cross-realm principal bindings.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(!self.subject.is_group())?;
        if let Some(realm) = self.realm {
            self.subject.in_realm(realm)?;
        }
        let mut out = CborWriter::default();
        out.array(5)
            .uint(SCHEMA)
            .bytes(&self.subject.canonical()?)
            .uint(self.scope as u64);
        if let Some(realm) = self.realm {
            out.bytes(realm.as_bytes());
        } else {
            out.null();
        }
        out.uint(self.expires_seconds);
        bounded(out.into_bytes())
    }

    /// Decodes canonical claims, refusing missing/unknown scopes and malformed subjects.
    ///
    /// # Errors
    /// Rejects malformed, unqualified or noncanonical claim fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 5)?;
        let subject = PolicySubject::decode(input.bytes_up_to(MAX_BYTES)?)?;
        let scope = match input.uint()? {
            0 => AdminScope::ReadOnly,
            1 => AdminScope::ReadWrite,
            2 => AdminScope::SuperAdmin,
            _ => return Err(AccountError::InvalidField),
        };
        let realm = if input.take_null() {
            None
        } else {
            Some(RealmId::from_bytes(input.fixed_bytes()?))
        };
        let expires_seconds = input.uint()?;
        input.finish()?;
        let value = Self {
            subject,
            scope,
            realm,
            expires_seconds,
        };
        value.canonical()?;
        Ok(value)
    }
}

/// Exact claim-to-subject join under an externally authenticated JWT authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwtSubjectBinding {
    /// Realm, credential anchor, subject, enabled flag and expiry.
    pub binding: SubjectBinding,
    /// Realm-local reference to externally supplied authority metadata.
    pub authority_ref: String,
    /// Exact verified UTF-8 claim name, including whitespace or empty data; at most 256 bytes.
    pub claim_name: String,
    /// Exact verified UTF-8 claim value, including whitespace or empty data; at most 256 bytes.
    pub claim_value: String,
    /// Opaque ordered unique credential scopes; these are not admin scopes.
    pub scopes: Vec<String>,
}

impl JwtSubjectBinding {
    /// Encodes public binding metadata without keys, secrets or token verification.
    ///
    /// # Errors
    /// Rejects malformed references, oversized claim data, non-credential anchors and scope/order violations.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        require(matches!(self.binding.anchor, SubjectAnchor::Credential(_)))?;
        text(&self.authority_ref)?;
        require(
            self.claim_name.len() <= MAX_POLICY_TEXT && self.claim_value.len() <= MAX_POLICY_TEXT,
        )?;
        ordered_text(&self.scopes)?;
        let mut out = CborWriter::default();
        out.array(6)
            .uint(SCHEMA)
            .bytes(&self.binding.canonical()?)
            .text(&self.authority_ref)
            .text(&self.claim_name)
            .text(&self.claim_value)
            .array(self.scopes.len());
        for scope in &self.scopes {
            out.text(scope);
        }
        bounded(out.into_bytes())
    }

    /// Decodes one bounded public JWT consumer binding.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical fields and invalid nested subject bindings.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 6)?;
        let value = Self {
            binding: SubjectBinding::decode(input.bytes_up_to(MAX_BYTES)?)?,
            authority_ref: input.text_up_to(MAX_POLICY_TEXT)?.to_owned(),
            claim_name: input.text_up_to(MAX_POLICY_TEXT)?.to_owned(),
            claim_value: input.text_up_to(MAX_POLICY_TEXT)?.to_owned(),
            scopes: read_texts(&mut input)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Signed internal subject-header configuration; key material stays external.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSubjectHeaderPolicy {
    /// Whether header production is authorized by this policy.
    pub enabled: bool,
    /// Lowercase subject header token.
    pub header_name: Option<String>,
    /// Distinct lowercase signature header token.
    pub signature_header_name: Option<String>,
    /// Reference to separately managed signing material.
    pub keyset_ref: Option<String>,
    /// Positive lifetime in seconds, required for enabled policies.
    pub validity_seconds: Option<u32>,
    /// Untrusted inbound headers must be stripped when enabled.
    pub strip_inbound: bool,
}

fn header(value: &str) -> Result<(), AccountError> {
    text(value)?;
    require(
        value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&b)
        }),
    )
}

fn write_optional(value: Option<&str>, out: &mut CborWriter) {
    if let Some(value) = value {
        out.text(value);
    } else {
        out.null();
    }
}

fn read_optional(input: &mut CborReader<'_>) -> Result<Option<String>, AccountError> {
    Ok(if input.take_null() {
        None
    } else {
        Some(input.text_up_to(MAX_POLICY_TEXT)?.to_owned())
    })
}

impl SignedSubjectHeaderPolicy {
    /// Encodes a header policy without creating a signature or obtaining a key.
    ///
    /// # Errors
    /// Rejects invalid names, missing enabled-policy fields and unsafe inbound retention.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        if let Some(name) = &self.header_name {
            header(name)?;
        }
        if let Some(name) = &self.signature_header_name {
            header(name)?;
        }
        require(self.header_name.is_none() || self.header_name != self.signature_header_name)?;
        if let Some(key) = &self.keyset_ref {
            text(key)?;
        }
        require(self.validity_seconds != Some(0))?;
        if self.enabled {
            require(
                self.header_name.is_some()
                    && self.signature_header_name.is_some()
                    && self.keyset_ref.is_some()
                    && self.validity_seconds.is_some()
                    && self.strip_inbound,
            )?;
        }
        let mut out = CborWriter::default();
        out.array(7).uint(SCHEMA).boolean(self.enabled);
        write_optional(self.header_name.as_deref(), &mut out);
        write_optional(self.signature_header_name.as_deref(), &mut out);
        write_optional(self.keyset_ref.as_deref(), &mut out);
        if let Some(seconds) = self.validity_seconds {
            out.uint(u64::from(seconds));
        } else {
            out.null();
        }
        out.boolean(self.strip_inbound);
        bounded(out.into_bytes())
    }

    /// Decodes an explicit, bounded canonical signed-header configuration.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical values or incomplete enabled policies.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 7)?;
        let value = Self {
            enabled: input.boolean()?,
            header_name: read_optional(&mut input)?,
            signature_header_name: read_optional(&mut input)?,
            keyset_ref: read_optional(&mut input)?,
            validity_seconds: if input.take_null() {
                None
            } else {
                Some(u32::try_from(input.uint()?).map_err(|_| AccountError::InvalidField)?)
            },
            strip_inbound: input.boolean()?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}
