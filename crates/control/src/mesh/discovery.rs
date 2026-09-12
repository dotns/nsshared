//! Bounded WebPKI discovery documents. Parsing does not establish or migrate trust.

use serde::{Deserialize, Serialize};

use super::{Error, validate_relay_origin};

pub const DISCOVERY_PATH: &str = "/.well-known/nsmesh";
pub const DISCOVERY_VERSION: &str = "mesh_trust.v1";
pub const MAX_DISCOVERY_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryKeys {
    pub current: [u8; 32],
    pub next: Option<[u8; 32]>,
}

/// Carrier availability only; unrelated to a member's capability bits or authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryCapability {
    Udp,
    Wss,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryDocument {
    pub relay_origin: String,
    pub relay_key: DiscoveryKeys,
    pub udp_port: u16,
    pub wss_port: Option<u16>,
    pub capabilities: Vec<DiscoveryCapability>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDocument {
    version: String,
    relay_origin: String,
    relay_key: WireKeys,
    udp_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wss_port: Option<u16>,
    capabilities: Vec<DiscoveryCapability>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireKeys {
    current: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next: Option<String>,
}

fn key(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(Error::Payload("discovery lowercase hex key"));
    }
    let mut decoded = [0; 32];
    hex::decode_to_slice(value, &mut decoded).map_err(|_| Error::Payload("discovery key"))?;
    Ok(decoded)
}

impl DiscoveryDocument {
    pub fn validate(&self) -> Result<(), Error> {
        validate_relay_origin(&self.relay_origin)?;
        let udp = self
            .capabilities
            .iter()
            .filter(|v| **v == DiscoveryCapability::Udp)
            .count();
        let wss = self
            .capabilities
            .iter()
            .filter(|v| **v == DiscoveryCapability::Wss)
            .count();
        if self.udp_port == 0
            || self.wss_port == Some(0)
            || udp != 1
            || wss > 1
            || (wss == 1) != self.wss_port.is_some()
        {
            return Err(Error::Payload("discovery carrier/port binding"));
        }
        Ok(())
    }

    /// Callers must cap HTTP body collection at MAX_DISCOVERY_BYTES before this boundary.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_DISCOVERY_BYTES {
            return Err(Error::TooLarge);
        }
        let wire: WireDocument =
            serde_json::from_slice(bytes).map_err(|_| Error::Payload("discovery JSON"))?;
        if wire.version != DISCOVERY_VERSION {
            return Err(Error::Payload("discovery version"));
        }
        let result = Self {
            relay_origin: wire.relay_origin,
            relay_key: DiscoveryKeys {
                current: key(&wire.relay_key.current)?,
                next: wire.relay_key.next.as_deref().map(key).transpose()?,
            },
            udp_port: wire.udp_port,
            wss_port: wire.wss_port,
            capabilities: wire.capabilities,
        };
        result.validate()?;
        Ok(result)
    }

    /// The caller supplies actual ready listeners and the retained relay identity.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let wire = WireDocument {
            version: DISCOVERY_VERSION.into(),
            relay_origin: self.relay_origin.clone(),
            relay_key: WireKeys {
                current: hex::encode(self.relay_key.current),
                next: self.relay_key.next.map(hex::encode),
            },
            udp_port: self.udp_port,
            wss_port: self.wss_port,
            capabilities: self.capabilities.clone(),
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| Error::Payload("discovery JSON"))?;
        if bytes.len() > MAX_DISCOVERY_BYTES {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }
}
