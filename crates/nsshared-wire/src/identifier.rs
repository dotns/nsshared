//! Relay identifiers (quick-v2 §8.6, authority syntax of quick-protocol §12.5.1).

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use thiserror::Error;

/// Maximum relay identifier length in bytes, brackets and port included (quick-v2 §8.6).
pub const MAX_RELAY_ID_BYTES: usize = 255;

/// Maximum DNS label length in bytes (quick-protocol §12.5.1).
const MAX_DNS_LABEL_BYTES: usize = 63;

/// A canonical relay identifier `host:port` (quick-v2 §8.6).
///
/// `host` is a lowercase DNS name, an IPv4 literal or a bracketed IPv6 literal and `port`
/// is 1..65535, with the authority syntax of quick-protocol §12.5.1. Signed identifiers
/// are never rewritten, so parsing accepts only the canonical form and never normalises.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelayId(String);

/// A rejected relay identifier (quick-v2 §8.6, quick-protocol §12.5.1).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RelayIdError {
    /// The identifier is empty or longer than 255 bytes.
    #[error("relay identifier must be 1..={MAX_RELAY_ID_BYTES} bytes")]
    Length,
    /// The identifier is not `host:port`, or contains non-ASCII, whitespace or URL
    /// delimiters (scheme, path, userinfo, query, fragment, percent escapes).
    #[error("relay identifier is not a host:port authority")]
    Syntax,
    /// The port is missing, has a leading zero, is not decimal, is 0 or exceeds 65535.
    #[error("relay identifier port must be 1..65535 without leading zeros")]
    Port,
    /// An all-numeric dotted host that is not a canonical, routable IPv4 literal.
    #[error("relay identifier IPv4 literal is invalid or non-canonical")]
    Ipv4,
    /// A bracketed host that is not a canonical, routable IPv6 literal.
    #[error("relay identifier IPv6 literal is invalid or non-canonical")]
    Ipv6,
    /// A host that is not a canonical lowercase DNS name.
    #[error("relay identifier DNS name is invalid or non-canonical")]
    DnsName,
}

impl RelayId {
    /// Parses a canonical relay identifier without normalisation (quick-v2 §8.6).
    ///
    /// # Errors
    ///
    /// [`RelayIdError`] naming the first rule the text violates.
    pub fn parse(text: &str) -> Result<Self, RelayIdError> {
        if text.is_empty() || text.len() > MAX_RELAY_ID_BYTES {
            return Err(RelayIdError::Length);
        }
        if !text.is_ascii()
            || text.bytes().any(|byte| {
                byte.is_ascii_whitespace()
                    || byte.is_ascii_control()
                    || matches!(byte, b'/' | b'@' | b'?' | b'#' | b'%')
            })
        {
            return Err(RelayIdError::Syntax);
        }
        if let Some(rest) = text.strip_prefix('[') {
            let (host, port) = rest.split_once("]:").ok_or(RelayIdError::Syntax)?;
            if host.contains(['[', ']']) || port.contains(':') {
                return Err(RelayIdError::Syntax);
            }
            parse_port(port)?;
            validate_ipv6(host)?;
        } else {
            let (host, port) = text.rsplit_once(':').ok_or(RelayIdError::Syntax)?;
            if host.contains([':', '[', ']']) {
                return Err(RelayIdError::Syntax);
            }
            parse_port(port)?;
            if is_numeric_dotted(host) {
                validate_ipv4(host)?;
            } else {
                validate_dns(host)?;
            }
        }
        Ok(Self(text.to_owned()))
    }

    /// Returns the exact canonical identifier text (quick-v2 §8.6).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelayId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RelayId {
    type Err = RelayIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl AsRef<str> for RelayId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

fn parse_port(port: &str) -> Result<u16, RelayIdError> {
    if port.is_empty()
        || (port.len() > 1 && port.starts_with('0'))
        || !port.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RelayIdError::Port);
    }
    port.parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(RelayIdError::Port)
}

/// All-numeric dotted text is reserved for IPv4 and never falls back to DNS.
fn is_numeric_dotted(host: &str) -> bool {
    host.contains('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

fn validate_ipv4(host: &str) -> Result<(), RelayIdError> {
    let address = Ipv4Addr::from_str(host).map_err(|_| RelayIdError::Ipv4)?;
    if address.to_string() != host
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_link_local()
    {
        return Err(RelayIdError::Ipv4);
    }
    Ok(())
}

fn validate_ipv6(host: &str) -> Result<(), RelayIdError> {
    if host.contains('.') {
        return Err(RelayIdError::Ipv6);
    }
    let address = Ipv6Addr::from_str(host).map_err(|_| RelayIdError::Ipv6)?;
    let site_local = address.segments()[0] & 0xffc0 == 0xfec0;
    if address.to_string() != host
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_unicast_link_local()
        || site_local
        || address.to_ipv4_mapped().is_some()
    {
        return Err(RelayIdError::Ipv6);
    }
    Ok(())
}

fn validate_dns(host: &str) -> Result<(), RelayIdError> {
    if host.is_empty() {
        return Err(RelayIdError::DnsName);
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > MAX_DNS_LABEL_BYTES
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(RelayIdError::DnsName);
        }
    }
    Ok(())
}
