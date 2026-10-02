use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// Maximum encoded relay-identifier or endpoint-hint text length (§§13.5.1, 13.6).
pub const MAX_RELAY_IDENTIFIER_BYTES: usize = 255;
/// Maximum short relay identifier length (§13.5.1).
pub const MAX_RELAY_SHORT_ID_BYTES: usize = 63;

/// A strict canonical relay identifier accepted from signed wire text (§13.5.1).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelayIdentifier(String);

/// A strict canonical transport authority accepted as an endpoint hint (§13.5.1).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EndpointHint(String);

/// A relay-identifier or endpoint-hint grammar failure (§13.5.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayIdentifierError {
    /// The input is empty or exceeds the complete 255-byte field bound.
    InvalidLength,
    /// The input contains a forbidden URL component, whitespace, or delimiter shape.
    InvalidSyntax,
    /// A short identifier is not the canonical lowercase 1-63 byte form.
    InvalidShortId,
    /// The decimal port is absent, noncanonical, zero, or exceeds 65535.
    InvalidPort,
    /// A numeric-looking IPv4 address is malformed or noncanonical.
    InvalidIpv4,
    /// An IPv6 literal is malformed, noncanonical, scoped, or forbidden as a destination.
    InvalidIpv6,
    /// A DNS name is malformed or noncanonical.
    InvalidDnsName,
    /// Endpoint hints cannot use short relay identifiers.
    ShortIdEndpoint,
}

impl RelayIdentifier {
    /// Parses received signed text without normalization (§13.5.1).
    pub fn parse(input: &str) -> Result<Self, RelayIdentifierError> {
        validate_field_length(input)?;
        if input.contains(':') {
            validate_authority(input, false)?;
        } else {
            validate_short_id(input)?;
        }
        Ok(Self(input.to_owned()))
    }

    /// Canonicalizes permitted local pre-signing input (§13.5.1).
    pub fn canonicalize(input: &str) -> Result<Self, RelayIdentifierError> {
        validate_local_input(input)?;
        if input.contains(':') {
            Self::parse(&canonical_authority(input)?)
        } else {
            Self::parse(input)
        }
    }

    /// Returns the exact canonical identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl EndpointHint {
    /// Parses a received canonical authority; short IDs are rejected (§13.5.1).
    pub fn parse(input: &str) -> Result<Self, RelayIdentifierError> {
        validate_field_length(input)?;
        if !input.contains(':') {
            return Err(RelayIdentifierError::ShortIdEndpoint);
        }
        validate_authority(input, false)?;
        Ok(Self(input.to_owned()))
    }

    /// Canonicalizes permitted local authority input (§13.5.1).
    pub fn canonicalize(input: &str) -> Result<Self, RelayIdentifierError> {
        Self::parse(&canonical_authority(input)?)
    }

    /// Returns the exact canonical authority text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelayIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for EndpointHint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RelayIdentifier {
    type Err = RelayIdentifierError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl FromStr for EndpointHint {
    type Err = RelayIdentifierError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl AsRef<str> for RelayIdentifier {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for EndpointHint {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

fn validate_field_length(input: &str) -> Result<(), RelayIdentifierError> {
    if input.is_empty() || input.len() > MAX_RELAY_IDENTIFIER_BYTES {
        return Err(RelayIdentifierError::InvalidLength);
    }
    if !input.is_ascii() || input.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(RelayIdentifierError::InvalidSyntax);
    }
    Ok(())
}

fn validate_local_input(input: &str) -> Result<(), RelayIdentifierError> {
    if input.is_empty() || input.len() > MAX_RELAY_IDENTIFIER_BYTES + 1 {
        return Err(RelayIdentifierError::InvalidLength);
    }
    if !input.is_ascii() || input.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(RelayIdentifierError::InvalidSyntax);
    }
    Ok(())
}

fn validate_short_id(input: &str) -> Result<(), RelayIdentifierError> {
    if input.len() > MAX_RELAY_SHORT_ID_BYTES
        || !input.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        || input.ends_with('-')
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(RelayIdentifierError::InvalidShortId);
    }
    Ok(())
}

fn split_authority(input: &str) -> Result<(&str, &str, bool), RelayIdentifierError> {
    if input.starts_with('[') {
        let close = input.find(']').ok_or(RelayIdentifierError::InvalidSyntax)?;
        if input.as_bytes().get(close + 1) != Some(&b':') || input[close + 2..].contains(':') {
            return Err(RelayIdentifierError::InvalidSyntax);
        }
        Ok((&input[1..close], &input[close + 2..], true))
    } else {
        let (host, port) = input
            .rsplit_once(':')
            .ok_or(RelayIdentifierError::InvalidSyntax)?;
        if host.contains(':') || host.contains(['[', ']']) {
            return Err(RelayIdentifierError::InvalidSyntax);
        }
        Ok((host, port, false))
    }
}

fn parse_port(port: &str) -> Result<u16, RelayIdentifierError> {
    if port.is_empty()
        || (port.len() > 1 && port.starts_with('0'))
        || !port.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(RelayIdentifierError::InvalidPort);
    }
    port.parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(RelayIdentifierError::InvalidPort)
}

fn validate_authority(input: &str, allow_local_form: bool) -> Result<(), RelayIdentifierError> {
    if input
        .bytes()
        .any(|byte| matches!(byte, b'/' | b'@' | b'?' | b'#' | b'%'))
    {
        return Err(RelayIdentifierError::InvalidSyntax);
    }
    let (host, port, bracketed) = split_authority(input)?;
    let _ = parse_port(port)?;
    if bracketed {
        validate_ipv6(host, allow_local_form)
    } else if numeric_dotted(host) {
        validate_ipv4(host)
    } else {
        validate_dns(host, allow_local_form)
    }
}

fn numeric_dotted(host: &str) -> bool {
    host.contains('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

fn validate_ipv4(host: &str) -> Result<(), RelayIdentifierError> {
    let address = Ipv4Addr::from_str(host).map_err(|_| RelayIdentifierError::InvalidIpv4)?;
    if address.to_string() != host
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_link_local()
    {
        return Err(RelayIdentifierError::InvalidIpv4);
    }
    Ok(())
}

fn validate_ipv6(host: &str, allow_local_form: bool) -> Result<(), RelayIdentifierError> {
    if host.contains('.') || host.contains('%') {
        return Err(RelayIdentifierError::InvalidIpv6);
    }
    let address = Ipv6Addr::from_str(host).map_err(|_| RelayIdentifierError::InvalidIpv6)?;
    if address.is_unspecified()
        || address.is_multicast()
        || address.is_unicast_link_local()
        || is_site_local(address)
        || address.to_ipv4_mapped().is_some()
    {
        return Err(RelayIdentifierError::InvalidIpv6);
    }
    if !allow_local_form && address.to_string() != host {
        return Err(RelayIdentifierError::InvalidIpv6);
    }
    Ok(())
}

fn is_site_local(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    octets[0] == 0xfe && octets[1] & 0xc0 == 0xc0
}

fn validate_dns(host: &str, allow_local_form: bool) -> Result<(), RelayIdentifierError> {
    let canonical = if allow_local_form {
        host.strip_suffix('.').unwrap_or(host)
    } else {
        host
    };
    if canonical.is_empty() || (!allow_local_form && host.ends_with('.')) {
        return Err(RelayIdentifierError::InvalidDnsName);
    }
    for label in canonical.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || (!allow_local_form && label.bytes().any(|byte| byte.is_ascii_uppercase()))
        {
            return Err(RelayIdentifierError::InvalidDnsName);
        }
    }
    Ok(())
}

fn canonical_authority(input: &str) -> Result<String, RelayIdentifierError> {
    validate_local_input(input)?;
    let (host, port_text, bracketed) = split_authority(input)?;
    let port = parse_port(port_text)?;
    let canonical = if bracketed {
        validate_ipv6(host, true)?;
        let address = Ipv6Addr::from_str(host).map_err(|_| RelayIdentifierError::InvalidIpv6)?;
        format!("[{address}]:{port}")
    } else if numeric_dotted(host) {
        validate_ipv4(host)?;
        format!("{host}:{port}")
    } else {
        validate_dns(host, true)?;
        let dns = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
        format!("{dns}:{port}")
    };
    validate_field_length(&canonical)?;
    Ok(canonical)
}
