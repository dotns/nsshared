//! Relay directory v2 (rendezvous §5.4, short codes of quick §4).
//!
//! Each entry lists the connect addresses and the TLS name, so a client needs no public
//! DNS. Ids and their short codes are permanent; an update may add entries or change
//! `ips` and `capabilities` but never removes an id, reassigns a code or reuses a retired
//! one. Every change needs a higher version and an equal version must be identical.

use crate::RelayId;
use crate::rendezvous::{capability::Capabilities, error::ErrorCode, transport::Object};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr, str::FromStr};
use thiserror::Error;

/// Maximum directory entries, 24 × 24 short codes (rendezvous §5.4, quick §4.1).
pub const MAX_RELAYS: usize = 576;
/// Short code letters, `A`-`Z` without `I` and `O` (quick §4.1).
pub const CODE_LETTERS: &[u8; 24] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
/// Maximum IP literals per entry (rendezvous §5.4).
pub const MAX_RELAY_IPS: usize = 4;

/// An invalid directory or directory update (rendezvous §5.4); every case is reported
/// on the wire as [`ErrorCode::InvalidDirectory`].
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DirectoryError {
    /// The version is 0.
    #[error("directory version must be at least 1")]
    Version,
    /// The directory lists no relay.
    #[error("directory lists no relay")]
    Empty,
    /// More than 576 entries.
    #[error("directory lists more than {MAX_RELAYS} relays")]
    TooManyRelays,
    /// An id is 0.
    #[error("relay id must not be 0")]
    Id,
    /// A code is not two short-code letters.
    #[error("relay code must be two letters of {CODE_LETTERS:?}")]
    Code,
    /// A host is not a lowercase DNS name, or is an IP literal.
    #[error("relay host must be a lowercase DNS name")]
    Host,
    /// `ips` is empty, longer than 4, or holds a non-canonical, unspecified, multicast or
    /// repeated IP literal.
    #[error("relay ips must be 1..={MAX_RELAY_IPS} distinct canonical IP literals")]
    Ips,
    /// A port is 0.
    #[error("relay port must not be 0")]
    Port,
    /// Two entries share an id.
    #[error("relay id is not unique")]
    DuplicateId,
    /// Two entries share a code.
    #[error("relay code is not unique")]
    DuplicateCode,
    /// Two entries share a host.
    #[error("relay host is not unique")]
    DuplicateHost,
    /// The update has a lower version.
    #[error("directory version went backwards")]
    VersionRegressed,
    /// The update has the same version but different content.
    #[error("directory changed without a higher version")]
    ChangedWithoutVersion,
    /// The update removes an id.
    #[error("directory update removes a relay id")]
    IdRemoved,
    /// The update changes the code of an id.
    #[error("directory update changes a relay code")]
    CodeChanged,
    /// A new id takes an existing or retired code.
    #[error("directory update reuses a relay code")]
    CodeReused,
}

impl From<DirectoryError> for ErrorCode {
    fn from(_: DirectoryError) -> Self {
        Self::InvalidDirectory
    }
}

/// One relay of the directory (rendezvous §5.4).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "Object<RelayEntryFields>")]
pub struct RelayEntry {
    id: u16,
    code: String,
    host: String,
    ips: Vec<IpAddr>,
    port: u16,
    capabilities: Capabilities,
    #[serde(skip_serializing)]
    relay_id: RelayId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayEntryFields {
    id: u16,
    code: String,
    host: String,
    ips: Vec<String>,
    port: u16,
    capabilities: Capabilities,
}

impl TryFrom<Object<RelayEntryFields>> for RelayEntry {
    type Error = DirectoryError;

    fn try_from(Object(fields): Object<RelayEntryFields>) -> Result<Self, Self::Error> {
        if fields.ips.len() > MAX_RELAY_IPS {
            return Err(DirectoryError::Ips);
        }
        let ips = fields
            .ips
            .iter()
            .map(|text| {
                IpAddr::from_str(text)
                    .ok()
                    .filter(|ip| ip.to_string() == *text)
                    .ok_or(DirectoryError::Ips)
            })
            .collect::<Result<_, _>>()?;
        Self::new(
            fields.id,
            fields.code,
            fields.host,
            ips,
            fields.port,
            fields.capabilities,
        )
    }
}

impl RelayEntry {
    /// Validates one entry (rendezvous §5.4, quick §4.1).
    ///
    /// # Errors
    ///
    /// [`DirectoryError`] naming the first violated field rule.
    pub fn new(
        id: u16,
        code: String,
        host: String,
        ips: Vec<IpAddr>,
        port: u16,
        capabilities: Capabilities,
    ) -> Result<Self, DirectoryError> {
        if id == 0 {
            return Err(DirectoryError::Id);
        }
        if !is_code(&code) {
            return Err(DirectoryError::Code);
        }
        if port == 0 {
            return Err(DirectoryError::Port);
        }
        // A TLS name, never an IP literal: all-numeric dotted text and brackets are
        // excluded before the RelayId DNS rules apply.
        if host.starts_with('[')
            || host
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return Err(DirectoryError::Host);
        }
        let relay_id =
            RelayId::parse(&format!("{host}:{port}")).map_err(|_| DirectoryError::Host)?;
        let distinct: BTreeSet<_> = ips.iter().collect();
        if ips.is_empty()
            || ips.len() > MAX_RELAY_IPS
            || distinct.len() != ips.len()
            || ips
                .iter()
                .any(|ip| ip.is_unspecified() || ip.is_multicast())
        {
            return Err(DirectoryError::Ips);
        }
        Ok(Self {
            id,
            code,
            host,
            ips,
            port,
            capabilities,
            relay_id,
        })
    }

    /// The permanent relay id.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// The permanent two-letter short code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The TLS name used for SNI and certificate checks.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The connect addresses, a hint that may change between versions.
    #[must_use]
    pub fn ips(&self) -> &[IpAddr] {
        &self.ips
    }

    /// The TLS port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The announced capabilities, a hint until the `challenge` confirms them.
    #[must_use]
    pub const fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// The relay identity `host:port` (rendezvous §5.4, quick-v2 §8.6).
    #[must_use]
    pub fn relay_id(&self) -> RelayId {
        self.relay_id.clone()
    }
}

/// A validated relay directory (rendezvous §5.4).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "Object<DirectoryFields>")]
pub struct Directory {
    version: u64,
    relays: Vec<RelayEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryFields {
    version: u64,
    relays: Vec<RelayEntry>,
}

impl TryFrom<Object<DirectoryFields>> for Directory {
    type Error = DirectoryError;

    fn try_from(Object(fields): Object<DirectoryFields>) -> Result<Self, Self::Error> {
        Self::new(fields.version, fields.relays)
    }
}

impl Directory {
    /// Validates a directory: version at least 1, 1..=576 entries, and id, code and host
    /// each unique (rendezvous §5.4).
    ///
    /// # Errors
    ///
    /// [`DirectoryError`] naming the first violated rule.
    pub fn new(version: u64, relays: Vec<RelayEntry>) -> Result<Self, DirectoryError> {
        if version == 0 {
            return Err(DirectoryError::Version);
        }
        if relays.is_empty() {
            return Err(DirectoryError::Empty);
        }
        if relays.len() > MAX_RELAYS {
            return Err(DirectoryError::TooManyRelays);
        }
        let mut ids = BTreeSet::new();
        let mut codes = BTreeSet::new();
        let mut hosts = BTreeSet::new();
        for relay in &relays {
            if !ids.insert(relay.id) {
                return Err(DirectoryError::DuplicateId);
            }
            if !codes.insert(relay.code.as_str()) {
                return Err(DirectoryError::DuplicateCode);
            }
            if !hosts.insert(relay.host.as_str()) {
                return Err(DirectoryError::DuplicateHost);
            }
        }
        Ok(Self { version, relays })
    }

    /// The directory version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// The entries in directory order.
    #[must_use]
    pub fn relays(&self) -> &[RelayEntry] {
        &self.relays
    }
}

/// Checks that `new` is an acceptable update of `old` (rendezvous §5.4, quick §4.1):
/// a lower version is rejected, an equal version must be identical, every old id stays
/// with its code, and no new id takes a code already in `old`.
///
/// # Errors
///
/// [`DirectoryError`] naming the first violated update rule.
pub fn check_update(old: &Directory, new: &Directory) -> Result<(), DirectoryError> {
    if new.version < old.version {
        return Err(DirectoryError::VersionRegressed);
    }
    if new.version == old.version {
        return if new == old {
            Ok(())
        } else {
            Err(DirectoryError::ChangedWithoutVersion)
        };
    }
    let old_codes: BTreeSet<_> = old.relays.iter().map(|relay| relay.code.as_str()).collect();
    let old_ids: BTreeSet<_> = old.relays.iter().map(|relay| relay.id).collect();
    if new
        .relays
        .iter()
        .any(|relay| !old_ids.contains(&relay.id) && old_codes.contains(relay.code.as_str()))
    {
        return Err(DirectoryError::CodeReused);
    }
    for previous in &old.relays {
        let current = new
            .relays
            .iter()
            .find(|relay| relay.id == previous.id)
            .ok_or(DirectoryError::IdRemoved)?;
        if current.code != previous.code {
            return Err(DirectoryError::CodeChanged);
        }
    }
    Ok(())
}

fn is_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|byte| CODE_LETTERS.contains(&byte))
}
