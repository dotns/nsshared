//! Existing account envelope and secret-free signed URL canonical input.

use crate::{
    account::AccountError, account::codec::hex, account::codec::require, account::codec::token,
    account::control::BootstrapEnvelope, account::control::BootstrapError,
    account::control::EnvelopeDirection, account::limits::MAX_CREDENTIAL_BYTES,
};
use sha2::{Digest as _, Sha256};

/// Request-only view of the existing domain-separated account envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAccountRequest(BootstrapEnvelope);

impl SignedAccountRequest {
    /// Requires request direction without authenticating the supplied envelope.
    ///
    /// # Errors
    /// Rejects response direction or invalid carrier fields.
    pub fn new(envelope: BootstrapEnvelope) -> Result<Self, BootstrapError> {
        if envelope.direction != EnvelopeDirection::Request {
            return Err(BootstrapError::Direction);
        }
        envelope.canonical()?;
        Ok(Self(envelope))
    }

    /// Borrows the existing envelope for caller-supplied trust/time verification.
    #[must_use]
    pub const fn envelope(&self) -> &BootstrapEnvelope {
        &self.0
    }

    /// Returns unchanged canonical account request bytes.
    ///
    /// # Errors
    /// Rejects invalid or oversized carrier fields.
    pub fn canonical(&self) -> Result<Vec<u8>, BootstrapError> {
        self.0.canonical()
    }

    /// Decodes only request-direction carriers; callers must still authenticate them.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical or response-direction input.
    pub fn decode(bytes: &[u8]) -> Result<Self, BootstrapError> {
        Self::new(BootstrapEnvelope::decode(bytes)?)
    }
}

/// Public request facts bound into the existing signed URL HMAC input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedUrlScope<'a> {
    /// GET or HEAD, case-sensitive.
    pub method: &'a str,
    /// http or https, case-insensitive, selecting default-port removal.
    pub scheme: &'a str,
    /// Host authority; lowercase and trim before signing.
    pub host: &'a str,
    /// Raw path without normalization.
    pub path: &'a str,
    /// Raw query; plus is literal and duplicate pairs are preserved.
    pub query: &'a str,
    /// Exact realm, without a slash scope separator.
    pub realm: &'a str,
    /// Exact route, without a slash scope separator.
    pub route: &'a str,
    /// Absolute Unix-second deadline; actual expiry is checked by the consumer.
    pub expires_seconds: u64,
}

fn nibble(byte: u8) -> Result<u8, AccountError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AccountError::Field),
    }
}

fn percent_decode(value: &str) -> Result<Vec<u8>, AccountError> {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        out.push(if byte == b'%' {
            let high = nibble(bytes.next().ok_or(AccountError::Field)?)?;
            let low = nibble(bytes.next().ok_or(AccountError::Field)?)?;
            high * 16 + low
        } else {
            byte
        });
    }
    Ok(out)
}

fn percent_encode(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for &byte in value {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    out
}

impl SignedUrlScope<'_> {
    /// Builds the canonical GET/HEAD request without secret or HMAC operations.
    ///
    /// # Errors
    /// Rejects unsupported methods/schemes, multiline or oversized inputs and bad escapes.
    pub fn canonical_request(&self) -> Result<String, AccountError> {
        require(matches!(self.method, "GET" | "HEAD"))?;
        require(
            self.scheme.eq_ignore_ascii_case("http") || self.scheme.eq_ignore_ascii_case("https"),
        )?;
        token(self.realm)?;
        token(self.route)?;
        require(!self.realm.contains('/') && !self.route.contains('/'))?;
        for value in [self.host, self.path, self.query] {
            require(value.len() <= MAX_CREDENTIAL_BYTES && !value.chars().any(char::is_control))?;
        }
        require(self.path.starts_with('/') && !self.path.contains(['?', '#']))?;
        let mut host = self.host.trim().to_ascii_lowercase();
        require(
            !host.is_empty()
                && !host.chars().any(char::is_whitespace)
                && !host.contains(['/', '?', '#', '@']),
        )?;
        let port = if self.scheme.eq_ignore_ascii_case("http") {
            ":80"
        } else {
            ":443"
        };
        if host.ends_with(port) {
            host.truncate(host.len() - port.len());
        }
        require(!host.is_empty())?;
        let mut pairs = Vec::new();
        for part in self.query.split('&').filter(|part| !part.is_empty()) {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            let name = percent_decode(name)?;
            let value = percent_decode(value)?;
            if name != b"X-Nsgw-Signature" {
                pairs.push((percent_encode(&name), percent_encode(&value)));
            }
        }
        pairs.sort();
        let query = pairs
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        Ok(format!(
            "{}\n{}\n{query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD",
            self.method, self.path
        ))
    }

    /// Returns the public string the consumer signs or verifies using HMAC-SHA256.
    ///
    /// # Errors
    /// Rejects invalid request facts; no key is read and no signature is verified.
    pub fn signing_input(&self) -> Result<String, AccountError> {
        let request = self.canonical_request()?;
        let hash = hex(&Sha256::digest(request.as_bytes()));
        Ok(format!(
            "NSGW-HMAC-SHA256\n{}\n{}/{}/nsgw_signed_url\n{hash}",
            self.expires_seconds, self.realm, self.route
        ))
    }
}
