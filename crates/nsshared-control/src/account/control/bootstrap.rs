//! Canonical discovery and trust facts authenticated by the caller's HTTPS WebPKI.

use nsshared_codec::{
    base64::decode_base64url, base64::encode_base64url, cbor::CborError, cbor::CborReader,
    cbor::CborWriter,
};
use nsshared_identity::keys::IdentityKey;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;

/// Maximum complete discovery document size.
pub const MAX_BOOTSTRAP_BYTES: usize = 256 * 1024;
/// Maximum complete unary call body, including its signed carrier.
pub const MAX_CONTROL_BODY: usize = 8 * 1024 * 1024;
/// Maximum complete HTTP response headers.
pub const MAX_CONTROL_HEADERS: usize = 16 * 1024;
/// Maximum encoded subscription envelope, before hex/base64 decoding.
pub const MAX_ENCODED_SUBSCRIPTION: usize = 16 * 1024;
/// Maximum Noise plaintext, excluding the authentication tag.
pub const MAX_CONTROL_NOISE_PAYLOAD: usize = 65_519;
/// Maximum Noise ciphertext, including its tag but excluding the two-byte prefix.
pub const MAX_CONTROL_NOISE_FRAME: usize = 65_535;

/// Boundary whose exact bytes must be checked before decoding or transport use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlBoundary {
    /// Complete canonical discovery document.
    Discovery,
    /// Complete unary response body or signed carrier.
    CallBody,
    /// Complete HTTP response headers.
    Headers,
    /// Encoded subscription before hex/base64 decoding.
    EncodedSubscription,
    /// Plaintext without authentication tag.
    NoisePayload,
    /// Ciphertext with tag, without length prefix.
    NoiseFrame,
}

/// Checks supplied bytes against their inventoried boundary, without I/O.
///
/// # Errors
/// Returns [`BootstrapError::Bounds`] above the inclusive limit.
pub fn validate_control_input(
    boundary: ControlBoundary,
    bytes: &[u8],
) -> Result<(), BootstrapError> {
    let maximum = match boundary {
        ControlBoundary::Discovery => MAX_BOOTSTRAP_BYTES,
        ControlBoundary::CallBody => MAX_CONTROL_BODY,
        ControlBoundary::Headers => MAX_CONTROL_HEADERS,
        ControlBoundary::EncodedSubscription => MAX_ENCODED_SUBSCRIPTION,
        ControlBoundary::NoisePayload => MAX_CONTROL_NOISE_PAYLOAD,
        ControlBoundary::NoiseFrame => MAX_CONTROL_NOISE_FRAME,
    };
    if bytes.len() > maximum {
        Err(BootstrapError::Bounds)
    } else {
        Ok(())
    }
}

/// Typed discovery or authenticated-carrier refusal.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BootstrapError {
    /// Malformed or noncanonical CBOR.
    #[error(transparent)]
    Contract(crate::account::AccountError),
    /// Encoded bytes or declared lengths exceed the boundary.
    #[error("control input bound exceeded")]
    Bounds,
    /// Missing or unsupported schema, trust or envelope version.
    #[error("unsupported bootstrap or envelope version")]
    Version,
    /// An origin is not exact, canonical and confidential.
    #[error("invalid canonical control origin")]
    Origin,
    /// Endpoints are empty or duplicated.
    #[error("empty or duplicate control endpoints")]
    Endpoints,
    /// Plaintext or unknown endpoint kind.
    #[error("unsupported control endpoint kind")]
    EndpointKind,
    /// Noise endpoint lacks its static key.
    #[error("missing Noise static key")]
    NoiseKey,
    /// QUIC endpoint lacks SPKI pins.
    #[error("missing QUIC SPKI pins")]
    QuicPins,
    /// A pin is malformed, noncanonical or duplicated.
    #[error("invalid canonical pin set")]
    Pins,
    /// Discovery has no envelope signer pins.
    #[error("empty discovered signer pins")]
    EmptyPins,
    /// Configured and discovered signer pins do not intersect.
    #[error("empty signer pin intersection")]
    EmptyIntersection,
    /// Signer is invalid or absent from the effective pins.
    #[error("untrusted envelope signer")]
    Signer,
    /// Named recipient differs from the expected identity.
    #[error("envelope recipient mismatch")]
    Recipient,
    /// Kind is empty, too long or different from the expected kind.
    #[error("envelope kind mismatch")]
    Kind,
    /// Unknown direction or unexpected request/response domain.
    #[error("envelope direction mismatch")]
    Direction,
    /// Signed timestamp exceeds the supplied-time skew.
    #[error("envelope clock skew exceeded")]
    Clock,
    /// Caller-supplied prior observation is inside the replay window.
    #[error("replayed envelope nonce")]
    Replay,
    /// Ed25519 verification failed.
    #[error("invalid envelope signature")]
    Signature,
}

impl From<CborError> for BootstrapError {
    fn from(error: CborError) -> Self {
        match error {
            CborError::TooLarge { .. }
            | CborError::StringLength { .. }
            | CborError::ArrayLength { .. } => Self::Bounds,
            other => Self::Contract(crate::account::AccountError::Cbor(other)),
        }
    }
}

/// Confidential carrier kinds; no plaintext variant exists.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u64)]
pub enum ConfidentialCarrier {
    /// HTTPS authenticated with WebPKI.
    Https = 0,
    /// Noise authenticated with the discovered static key.
    Noise = 1,
    /// QUIC authenticated with the discovered SPKI pins.
    Quic = 2,
}

impl ConfidentialCarrier {
    fn scheme(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::Noise => "noise",
            Self::Quic => "quic",
        }
    }
}

/// One endpoint, retaining its discovery preference position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapEndpoint {
    /// Confidential transport kind.
    pub kind: ConfidentialCarrier,
    /// Exact canonical origin with the kind's scheme.
    pub origin: String,
}

/// Versioned canonical trust publication; legacy trust fields are absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapDiscovery {
    /// HTTPS origin through which the caller authenticated discovery with WebPKI.
    pub https_origin: String,
    /// Nonempty duplicate-free endpoints in preference order.
    pub endpoints: Vec<BootstrapEndpoint>,
    /// Raw static X25519 key, mandatory when Noise is advertised.
    pub noise_key: Option<[u8; 32]>,
    /// Canonical SHA-256 pins over complete DER SPKI, retaining advertised order.
    pub quic_spki_pins: Vec<String>,
    /// Canonical RFC 7638 Ed25519 JWK thumbprints, retaining advertised order.
    pub envelope_pins: Vec<String>,
}

fn canonical_ipv6(ip: Ipv6Addr) -> String {
    let segments = ip.segments();
    let mut best_start = 0;
    let mut best_length = 0;
    let mut index = 0;
    while index < segments.len() {
        if segments[index] != 0 {
            index += 1;
            continue;
        }
        let start = index;
        while index < segments.len() && segments[index] == 0 {
            index += 1;
        }
        if index - start > best_length {
            best_start = start;
            best_length = index - start;
        }
    }
    let text: Vec<_> = segments.iter().map(|part| format!("{part:x}")).collect();
    if best_length < 2 {
        return text.join(":");
    }
    format!(
        "{}::{}",
        text[..best_start].join(":"),
        text[best_start + best_length..].join(":")
    )
}

fn canonical_host(host: &str) -> bool {
    if host.starts_with('[') && host.ends_with(']') {
        let address = &host[1..host.len() - 1];
        return address
            .parse::<Ipv6Addr>()
            .is_ok_and(|ip| canonical_ipv6(ip) == address);
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return ip.to_string() == host;
    }
    // URL hosts ending in an IPv4 number must use canonical dotted IPv4.
    let last = host.rsplit('.').next().unwrap_or_default();
    if last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return false;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        // Validate decoded A-labels and reject normalization of signed origins.
        && idna::domain_to_ascii_cow(host.as_bytes(), idna::AsciiDenyList::URL)
            .is_ok_and(|ascii| ascii == host)
}

fn validate_origin(origin: &str, kind: ConfidentialCarrier) -> Result<(), BootstrapError> {
    let (scheme, rest) = origin.split_once("://").ok_or(BootstrapError::Origin)?;
    let authority = rest.strip_suffix('/').ok_or(BootstrapError::Origin)?;
    if scheme != kind.scheme() {
        return Err(BootstrapError::Origin);
    }
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']').ok_or(BootstrapError::Origin)?;
        let (host, suffix) = authority.split_at(close + 1);
        (
            host,
            if suffix.is_empty() {
                None
            } else {
                Some(suffix.strip_prefix(':').ok_or(BootstrapError::Origin)?)
            },
        )
    } else if let Some((host, port)) = authority.split_once(':') {
        (host, Some(port))
    } else {
        (authority, None)
    };
    if !canonical_host(host) {
        return Err(BootstrapError::Origin);
    }
    if let Some(port) = port {
        let number = port.parse::<u16>().map_err(|_| BootstrapError::Origin)?;
        if number == 0
            || number.to_string() != port
            || (kind == ConfidentialCarrier::Https && number == 443)
        {
            return Err(BootstrapError::Origin);
        }
    } else if kind != ConfidentialCarrier::Https {
        return Err(BootstrapError::Origin);
    }
    Ok(())
}

pub(in crate::account) fn validate_pins(pins: &[String]) -> Result<(), BootstrapError> {
    let mut seen = BTreeSet::new();
    for pin in pins {
        let raw = decode_base64url(pin, 32).map_err(|_| BootstrapError::Pins)?;
        if raw.len() != 32 || encode_base64url(&raw) != *pin || !seen.insert(pin) {
            return Err(BootstrapError::Pins);
        }
    }
    Ok(())
}

pub(in crate::account) fn read_pins(
    input: &mut CborReader<'_>,
) -> Result<Vec<String>, BootstrapError> {
    let count = input.array_up_to(MAX_BOOTSTRAP_BYTES / 44)?;
    let mut pins = Vec::new();
    for _ in 0..count {
        pins.push(input.text_up_to(MAX_BOOTSTRAP_BYTES)?.to_owned());
    }
    validate_pins(&pins)?;
    Ok(pins)
}

pub(in crate::account) fn write_pins(out: &mut CborWriter, pins: &[String]) {
    out.array(pins.len());
    for pin in pins {
        out.text(pin);
    }
}

/// Established signer set; private contents prevent bypassing intersection validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopePins(Vec<String>);

impl EnvelopePins {
    /// Intersects local pins when configured, preserving discovery order.
    ///
    /// # Errors
    /// Rejects malformed/duplicate pins, empty discovery or an empty intersection.
    pub fn intersect(discovered: &[String], configured: &[String]) -> Result<Self, BootstrapError> {
        validate_pins(discovered)?;
        validate_pins(configured)?;
        if discovered.is_empty() {
            return Err(BootstrapError::EmptyPins);
        }
        let pins: Vec<_> = discovered
            .iter()
            .filter(|p| configured.is_empty() || configured.contains(p))
            .cloned()
            .collect();
        if pins.is_empty() {
            return Err(BootstrapError::EmptyIntersection);
        }
        Ok(Self(pins))
    }

    /// Pins in discovery order.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    pub(in crate::account) fn trusts(&self, signer: IdentityKey) -> bool {
        let x = encode_base64url(signer.as_bytes());
        let jwk = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
        let pin = encode_base64url(&Sha256::digest(jwk.as_bytes()));
        self.0.contains(&pin)
    }
}

impl BootstrapDiscovery {
    fn validate(&self) -> Result<(), BootstrapError> {
        validate_origin(&self.https_origin, ConfidentialCarrier::Https)?;
        validate_pins(&self.quic_spki_pins)?;
        validate_pins(&self.envelope_pins)?;
        if self.envelope_pins.is_empty() {
            return Err(BootstrapError::EmptyPins);
        }
        if self.endpoints.is_empty() {
            return Err(BootstrapError::Endpoints);
        }
        let mut seen = BTreeSet::new();
        for endpoint in &self.endpoints {
            validate_origin(&endpoint.origin, endpoint.kind)?;
            if !seen.insert((endpoint.kind, &endpoint.origin)) {
                return Err(BootstrapError::Endpoints);
            }
            match endpoint.kind {
                ConfidentialCarrier::Noise if self.noise_key.is_none() => {
                    return Err(BootstrapError::NoiseKey);
                }
                ConfidentialCarrier::Quic if self.quic_spki_pins.is_empty() => {
                    return Err(BootstrapError::QuicPins);
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Encodes canonical discovery, retaining exact origin, endpoint and pin order.
    ///
    /// # Errors
    /// Rejects invalid origins, missing trust, duplicate sets and excessive size.
    pub fn canonical(&self) -> Result<Vec<u8>, BootstrapError> {
        self.validate()?;
        let mut out = CborWriter::default();
        out.array(8)
            .uint(1)
            .uint(1)
            .text(&self.https_origin)
            .array(1)
            .uint(1)
            .array(self.endpoints.len());
        for endpoint in &self.endpoints {
            out.array(2)
                .uint(endpoint.kind as u64)
                .text(&endpoint.origin);
        }
        if let Some(key) = self.noise_key {
            out.bytes(&key);
        } else {
            out.null();
        }
        write_pins(&mut out, &self.quic_spki_pins);
        write_pins(&mut out, &self.envelope_pins);
        let bytes = out.into_bytes();
        validate_control_input(ControlBoundary::Discovery, &bytes)?;
        Ok(bytes)
    }

    /// Decodes one strict discovery document without using legacy trust fields.
    ///
    /// # Errors
    /// Rejects noncanonical CBOR, unsupported versions, oversized or invalid trust.
    pub fn decode(bytes: &[u8]) -> Result<Self, BootstrapError> {
        let mut input = CborReader::new(bytes, MAX_BOOTSTRAP_BYTES)?;
        input.array(8)?;
        for _ in 0..2 {
            if input.take_null() || input.uint()? != 1 {
                return Err(BootstrapError::Version);
            }
        }
        let https_origin = input.text_up_to(MAX_BOOTSTRAP_BYTES)?.to_owned();
        if input.array_up_to(MAX_BOOTSTRAP_BYTES)? != 1 || input.uint()? != 1 {
            return Err(BootstrapError::Version);
        }
        let count = input.array_up_to(MAX_BOOTSTRAP_BYTES / 4)?;
        let mut endpoints = Vec::new();
        for _ in 0..count {
            input.array(2)?;
            let kind = match input.uint()? {
                0 => ConfidentialCarrier::Https,
                1 => ConfidentialCarrier::Noise,
                2 => ConfidentialCarrier::Quic,
                _ => return Err(BootstrapError::EndpointKind),
            };
            endpoints.push(BootstrapEndpoint {
                kind,
                origin: input.text_up_to(MAX_BOOTSTRAP_BYTES)?.to_owned(),
            });
        }
        let noise_key = if input.take_null() {
            None
        } else {
            Some(input.fixed_bytes()?)
        };
        let quic_spki_pins = read_pins(&mut input)?;
        let envelope_pins = read_pins(&mut input)?;
        input.finish()?;
        let value = Self {
            https_origin,
            endpoints,
            noise_key,
            quic_spki_pins,
            envelope_pins,
        };
        value.validate()?;
        Ok(value)
    }

    /// Selects the first supported confidential endpoint in discovery preference order.
    /// This chooses a candidate only; it performs no connection attempt.
    ///
    /// # Errors
    /// Rejects invalid discovery, including missing transport or envelope trust.
    pub fn first_supported(
        &self,
        supported: &[ConfidentialCarrier],
    ) -> Result<Option<&BootstrapEndpoint>, BootstrapError> {
        self.canonical()?;
        Ok(self
            .endpoints
            .iter()
            .find(|endpoint| supported.contains(&endpoint.kind)))
    }

    /// Establishes effective pins after validating every discovery field and bound.
    ///
    /// # Errors
    /// Rejects invalid discovery, malformed local pins or an empty intersection.
    pub fn effective_envelope_pins(
        &self,
        configured: &[String],
    ) -> Result<EnvelopePins, BootstrapError> {
        self.canonical()?;
        EnvelopePins::intersect(&self.envelope_pins, configured)
    }
}
