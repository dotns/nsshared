//! Pure confidential material acquisition; see `docs/confidential-material-candidate.md`.

use super::{
    AccountError, EdgeMaterialKind, EdgeMaterialRef, MAX_BYTES, MAX_EDGE_ITEMS, bounded, identity,
    policy_subject::text, public_edge::hostname, reader, require,
};
use crate::{
    IdentityKey, RealmId,
    encoding::{CborError, CborWriter},
};
use thiserror::Error;

/// Exact pending request derived from an authenticated public-edge dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeMaterialRequest {
    /// Acquisition correlation, independent of the envelope replay nonce and status id.
    pub request_id: [u8; 16],
    /// Gateway recipient from accepted control custody.
    pub recipient: IdentityKey,
    /// Signed served realm.
    pub served_realm: RealmId,
    /// Signed publication scope.
    pub scope: String,
    /// Realm contributing the material.
    pub realm: RealmId,
    /// Exact certificate or client-CA reference and generation.
    pub material: EdgeMaterialRef,
}

/// Actual confidential values; decoding does not parse or install X.509 material.
#[derive(Clone, Eq, PartialEq)]
pub enum EdgeMaterialValues {
    /// Server certificate chain and matching private key, as UTF-8 PEM text.
    Certificate {
        /// Complete certificate chain.
        fullchain_pem: String,
        /// Private key, never a public reference.
        private_key_pem: String,
    },
    /// Client trust bundle, retaining optional CRLs, and its claimed trust domain.
    ClientCa {
        /// Complete CA/CRL PEM text.
        ca_pem: String,
        /// Domain compared externally with current validated authentication configuration.
        trust_domain: String,
    },
}

impl std::fmt::Debug for EdgeMaterialValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Certificate { .. } => "Certificate([redacted])",
            Self::ClientCa { .. } => "ClientCa([redacted])",
        })
    }
}

/// Successful acquisition, never an installation acknowledgement or route authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeMaterialResponse {
    /// Complete canonical echoed acquisition request.
    pub request: EdgeMaterialRequest,
    /// Strictly increasing unique permitted hostnames under public-edge rules.
    pub hostnames: Vec<String>,
    /// Exclusive unsigned Unix-seconds deadline; clock validation stays external.
    pub not_after_unix_seconds: u64,
    /// Mandatory actual values matching the requested kind.
    pub values: EdgeMaterialValues,
}

/// Typed material refusal, containing no secret values.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EdgeMaterialError {
    /// Invalid, noncanonical, missing or oversized contract data.
    #[error(transparent)]
    Contract(#[from] AccountError),
    /// Forbidden request kind or request/value kind disagreement.
    #[error("material kind mismatch")]
    Kind,
    /// Echoed contributing realm differs from the pending acquisition.
    #[error("material realm mismatch")]
    Realm,
    /// Echoed generation differs from the pending acquisition.
    #[error("material generation mismatch")]
    Generation,
    /// Complete canonical request echo differs from the pending acquisition.
    #[error("material request echo mismatch")]
    Echo,
}

impl From<CborError> for EdgeMaterialError {
    fn from(value: CborError) -> Self {
        Self::Contract(value.into())
    }
}

impl EdgeMaterialRequest {
    /// Encodes the exact acquisition tuple, preserving the auth-only request contract.
    /// # Errors
    /// Rejects auth material, invalid scope/reference/generation and bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, EdgeMaterialError> {
        if !matches!(
            self.material.kind,
            EdgeMaterialKind::Certificate | EdgeMaterialKind::ClientCa
        ) {
            return Err(EdgeMaterialError::Kind);
        }
        text(&self.scope)?;
        let mut out = CborWriter::default();
        out.array(7)
            .uint(1)
            .bytes(&self.request_id)
            .bytes(self.recipient.as_bytes())
            .text(&self.served_realm.to_string())
            .text(&self.scope)
            .bytes(self.realm.as_bytes());
        self.material.write(&mut out)?;
        Ok(bounded(out.into_bytes())?)
    }

    /// Decodes a bounded canonical certificate/client-CA acquisition request.
    /// # Errors
    /// Rejects malformed identities, kinds, fields, bounds and noncanonical CBOR.
    pub fn decode(bytes: &[u8]) -> Result<Self, EdgeMaterialError> {
        let mut input = reader(bytes, 7)?;
        let value = Self {
            request_id: input.fixed_bytes()?,
            recipient: identity(&mut input)?,
            served_realm: input.text_up_to(26)?.parse().map_err(AccountError::from)?,
            scope: input.text_up_to(256)?.to_owned(),
            realm: RealmId::from_bytes(input.fixed_bytes()?),
            material: EdgeMaterialRef::read(&mut input)?,
        };
        input.finish()?;
        value.canonical()?;
        Ok(value)
    }
}

fn pem(value: &str) -> Result<(), AccountError> {
    require(!value.trim().is_empty())?;
    if value.len() > MAX_BYTES {
        return Err(AccountError::Bounds);
    }
    Ok(())
}

impl EdgeMaterialValues {
    fn kind(&self) -> EdgeMaterialKind {
        match self {
            Self::Certificate { .. } => EdgeMaterialKind::Certificate,
            Self::ClientCa { .. } => EdgeMaterialKind::ClientCa,
        }
    }

    fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        match self {
            Self::Certificate {
                fullchain_pem,
                private_key_pem,
            } => {
                pem(fullchain_pem)?;
                pem(private_key_pem)?;
                out.array(3)
                    .uint(1)
                    .text(fullchain_pem)
                    .text(private_key_pem);
            }
            Self::ClientCa {
                ca_pem,
                trust_domain,
            } => {
                pem(ca_pem)?;
                text(trust_domain)?;
                out.array(3).uint(2).text(ca_pem).text(trust_domain);
            }
        }
        Ok(())
    }
}

impl EdgeMaterialResponse {
    /// Encodes complete successful material with its canonical request echo.
    /// # Errors
    /// Rejects kind disagreement, empty values, hostname violations and bounds.
    pub fn canonical(&self) -> Result<Vec<u8>, EdgeMaterialError> {
        let request = self.request.canonical()?;
        if self.values.kind() != self.request.material.kind {
            return Err(EdgeMaterialError::Kind);
        }
        require(
            self.hostnames.len() <= MAX_EDGE_ITEMS
                && self.hostnames.windows(2).all(|p| p[0] < p[1]),
        )?;
        let mut out = CborWriter::default();
        out.array(5)
            .uint(1)
            .bytes(&request)
            .array(self.hostnames.len());
        for name in &self.hostnames {
            hostname(name)?;
            out.text(name);
        }
        out.uint(self.not_after_unix_seconds);
        self.values.write(&mut out)?;
        Ok(bounded(out.into_bytes())?)
    }

    /// Decodes a response without authenticating custody or accepting installation.
    /// # Errors
    /// Rejects noncanonical, oversized, malformed, missing or mismatched values.
    pub fn decode(bytes: &[u8]) -> Result<Self, EdgeMaterialError> {
        let mut input = reader(bytes, 5)?;
        let request = EdgeMaterialRequest::decode(input.bytes_up_to(MAX_BYTES)?)?;
        let count = input.array_up_to(MAX_EDGE_ITEMS)?;
        let hostnames = (0..count)
            .map(|_| input.text_up_to(253).map(str::to_owned))
            .collect::<Result<_, _>>()?;
        let not_after_unix_seconds = input.uint()?;
        input.array(3)?;
        let values = match input.uint()? {
            1 => EdgeMaterialValues::Certificate {
                fullchain_pem: input.text_up_to(MAX_BYTES)?.to_owned(),
                private_key_pem: input.text_up_to(MAX_BYTES)?.to_owned(),
            },
            2 => EdgeMaterialValues::ClientCa {
                ca_pem: input.text_up_to(MAX_BYTES)?.to_owned(),
                trust_domain: input.text_up_to(256)?.to_owned(),
            },
            _ => return Err(EdgeMaterialError::Kind),
        };
        input.finish()?;
        let value = Self {
            request,
            hostnames,
            not_after_unix_seconds,
            values,
        };
        value.canonical()?;
        Ok(value)
    }

    /// Validates the full canonical pending echo and kind/value agreement.
    ///
    /// The caller verifies envelope signer/recipient/operation/correlation against
    /// accepted custody, rechecks the current public-edge dependency, route host
    /// coverage and trust domain, and performs X.509/time/installation validation.
    /// # Errors
    /// Refuses malformed contracts and any differing pending request byte.
    pub fn validate_for(&self, pending: &EdgeMaterialRequest) -> Result<(), EdgeMaterialError> {
        self.canonical()?;
        let pending_bytes = pending.canonical()?;
        if self.request.realm != pending.realm {
            return Err(EdgeMaterialError::Realm);
        }
        if self.request.material.generation != pending.material.generation {
            return Err(EdgeMaterialError::Generation);
        }
        if self.request.canonical()? != pending_bytes {
            return Err(EdgeMaterialError::Echo);
        }
        Ok(())
    }
}
