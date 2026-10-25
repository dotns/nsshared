//! Qualified subjects and bindings; credential verification remains external.

use crate::{
    account::AccountError, account::MAX_BYTES, account::SCHEMA, account::codec::bounded,
    account::codec::identity, account::codec::reader, account::codec::require,
    account::codec::token, account::grants::Payer, account::limits::MAX_TEXT_BYTES,
};
use nsshared_identity::realm::RealmId;

use nsshared_codec::{cbor::CborReader, cbor::CborWriter};
use nsshared_identity::keys::IdentityKey;

/// A policy label, paying-realm user or complete Node signing identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicySubject {
    /// Opaque realm-local namespaced label, never derived from a credential.
    Realm {
        /// Realm in which the label is meaningful.
        realm: RealmId,
        /// Canonical user:, group:, machine: or external: label.
        name: String,
    },
    /// Binary realm-local user; reuses the existing payer pair unchanged.
    User(Payer),
    /// Full Node signing identity, not a transport key or address.
    Node(IdentityKey),
}

impl PolicySubject {
    /// Realm qualification, absent only for a globally qualified Node identity.
    #[must_use]
    pub const fn realm(&self) -> Option<RealmId> {
        match self {
            Self::Realm { realm, .. } => Some(*realm),
            Self::User(payer) => Some(payer.realm),
            Self::Node(_) => None,
        }
    }

    pub(in crate::account) fn is_group(&self) -> bool {
        matches!(self, Self::Realm { name, .. } if name.starts_with("group:"))
    }

    pub(in crate::account) fn in_realm(&self, realm: RealmId) -> Result<(), AccountError> {
        require(self.realm().is_none_or(|own| own == realm))
    }

    /// Encodes one fully qualified canonical subject.
    ///
    /// # Errors
    /// Rejects unsupported, empty, unqualified or oversized labels.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        let mut out = CborWriter::default();
        match self {
            Self::Realm { realm, name } => {
                token(name)?;
                let (prefix, suffix) = name.split_once(':').ok_or(AccountError::Field)?;
                require(
                    matches!(prefix, "user" | "group" | "machine" | "external")
                        && !suffix.is_empty(),
                )?;
                out.array(4)
                    .uint(SCHEMA)
                    .uint(0)
                    .bytes(realm.as_bytes())
                    .text(name);
            }
            Self::User(payer) => {
                out.array(4)
                    .uint(SCHEMA)
                    .uint(1)
                    .bytes(payer.realm.as_bytes())
                    .bytes(&payer.subject);
            }
            Self::Node(node) => {
                out.array(3).uint(SCHEMA).uint(2).bytes(node.as_bytes());
            }
        }
        Ok(out.into_bytes())
    }

    /// Decodes a strict subject; null and missing subjects never imply anonymous access.
    ///
    /// # Errors
    /// Rejects invalid shape, identity, namespace, widths or noncanonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = CborReader::new(bytes, MAX_BYTES)?;
        let arity = input.array_up_to(4)?;
        require(input.uint()? == SCHEMA)?;
        let value = match input.uint()? {
            0 if arity == 4 => Self::Realm {
                realm: RealmId::from_bytes(input.fixed_bytes()?),
                name: input.text_up_to(MAX_TEXT_BYTES)?.to_owned(),
            },
            1 if arity == 4 => Self::User(Payer {
                realm: RealmId::from_bytes(input.fixed_bytes()?),
                subject: input.fixed_bytes()?,
            }),
            2 if arity == 3 => Self::Node(identity(&mut input)?),
            _ => return Err(AccountError::Field),
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

/// Authenticated anchor whose subject mapping is explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubjectAnchor {
    /// Existing full Node identity; I/K authorization remains NodeL3Authority.
    Node(IdentityKey),
    /// Realm-local credential reference, not its secret or verifier.
    Credential(String),
}

/// One realm-qualified mapping supplied by an authenticated authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectBinding {
    /// Realm owning the anchor and local subject.
    pub realm: RealmId,
    /// Exact verified identity or credential reference to match.
    pub anchor: SubjectAnchor,
    /// Explicit resolved subject, never a group.
    pub subject: PolicySubject,
    /// Disabled bindings grant no authority.
    pub enabled: bool,
    /// Actual Unix-second expiry, checked by the consumer.
    pub expires_seconds: Option<u64>,
}

impl SubjectBinding {
    /// Encodes an explicit mapping without inferring identity or permissions.
    ///
    /// # Errors
    /// Rejects cross-realm or group subjects and invalid credential references.
    pub fn canonical(&self) -> Result<Vec<u8>, AccountError> {
        self.subject.in_realm(self.realm)?;
        require(!self.subject.is_group())?;
        let mut out = CborWriter::default();
        out.array(7).uint(SCHEMA).bytes(self.realm.as_bytes());
        match &self.anchor {
            SubjectAnchor::Node(node) => {
                out.uint(0).bytes(node.as_bytes());
            }
            SubjectAnchor::Credential(reference) => {
                token(reference)?;
                out.uint(1).text(reference);
            }
        }
        out.bytes(&self.subject.canonical()?).boolean(self.enabled);
        if let Some(expiry) = self.expires_seconds {
            out.uint(expiry);
        } else {
            out.null();
        }
        bounded(out.into_bytes())
    }

    /// Decodes one bounded canonical anchor mapping.
    ///
    /// # Errors
    /// Rejects malformed fields, cross-realm subjects and unsupported anchors.
    pub fn decode(bytes: &[u8]) -> Result<Self, AccountError> {
        let mut input = reader(bytes, 7)?;
        let realm = RealmId::from_bytes(input.fixed_bytes()?);
        let anchor = match input.uint()? {
            0 => SubjectAnchor::Node(identity(&mut input)?),
            1 => SubjectAnchor::Credential(input.text_up_to(MAX_TEXT_BYTES)?.to_owned()),
            _ => return Err(AccountError::Field),
        };
        let subject = PolicySubject::decode(input.bytes_up_to(MAX_BYTES)?)?;
        let enabled = input.boolean()?;
        let expires_seconds = if input.take_null() {
            None
        } else {
            Some(input.uint()?)
        };
        input.finish()?;
        let value = Self {
            realm,
            anchor,
            subject,
            enabled,
            expires_seconds,
        };
        value.canonical()?;
        Ok(value)
    }
}
