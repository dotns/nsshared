//! Registry store and served directory (quick-v2 §3.3, §7; rendezvous §5.4).
//!
//! [`RegistryStore`] stores one [`RegistryEntry`] per identity, indexed by its node ID
//! `BLAKE2s-96(I)`, plus the mock's own directory entry and the served [`Directory`].
//! The publish proof, the responsibility check, record acceptance (quick-v2 §3.3),
//! `lookup_node` answers, deletion and directory update rules all come from
//! `nsshared_proto::rendezvous::registry` and `nsshared_proto::rendezvous::directory`; the store adds
//! storage, the record cap (quick-v2 §7.4) and the sweep. The mock is a single instance:
//! its registry domain is its own entry (quick-v2 §7.1), so it is responsible for every
//! node ID.
//!
//! The store is synchronous, does no I/O and reads no clock: callers pass `now` (Unix
//! seconds). Rate limits are the server's job. The per-identity publish interval
//! (quick-v2 §7.4) needs the identity of a verified record, so a publish runs in two
//! steps: [`RegistryStore::verify`], then the server's limiter keyed by
//! [`VerifiedPublish::record`]'s identity, then [`RegistryStore::accept`].
//! [`RegistryStore::publish`] runs both steps without a limiter.

use crate::config::Limits;
use nsshared_proto::NodeId;
use nsshared_proto::rendezvous::{
    capability::{self, Capabilities, Capability},
    directory::{self, Directory, RelayEntry},
    error::ErrorCode,
    message::{LookupNodeRequest, PublishRequest, Published, RecordResult},
    registry::{self, RegistryEntry, VerifiedPublish},
};
use std::{collections::HashMap, net::IpAddr};

/// Builds the mock's own directory entry announcing `mailbox` and `registry` followed
/// by `extra` capabilities such as `udp` or `wss` (rendezvous §3.1, §5.4); repeated
/// tokens are announced once.
///
/// # Errors
///
/// [`ErrorCode::InvalidDirectory`] when a field breaks a §5.4 rule or more than 16
/// tokens result.
pub fn self_entry(
    id: u16,
    code: String,
    host: String,
    ips: Vec<IpAddr>,
    port: u16,
    extra: &[Capability],
) -> Result<RelayEntry, ErrorCode> {
    let mut tokens = vec![capability::MAILBOX, capability::REGISTRY];
    for token in extra {
        if !tokens.contains(token) {
            tokens.push(token.clone());
        }
    }
    let capabilities = Capabilities::new(tokens).map_err(|_| ErrorCode::InvalidDirectory)?;
    Ok(RelayEntry::new(id, code, host, ips, port, capabilities)?)
}

/// Every stored registry record with the mock's directory (quick-v2 §7; rendezvous
/// §5.4).
#[derive(Debug)]
pub struct RegistryStore {
    limits: Limits,
    self_entry: RelayEntry,
    directory: Directory,
    entries: HashMap<NodeId, RegistryEntry>,
}

impl RegistryStore {
    /// An empty store serving directory version 1 with only `self_entry`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidDirectory`] when `self_entry` does not announce `registry`
    /// and `mailbox`.
    pub fn new(limits: Limits, self_entry: RelayEntry) -> Result<Self, ErrorCode> {
        let directory = Directory::new(1, vec![self_entry.clone()])?;
        Self::with_directory(limits, self_entry, directory)
    }

    /// An empty store serving `directory`, which must list `self_entry` (same id, host
    /// and port) announcing `registry` and `mailbox`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidDirectory`] when it does not.
    pub fn with_directory(
        limits: Limits,
        self_entry: RelayEntry,
        directory: Directory,
    ) -> Result<Self, ErrorCode> {
        check_self_listed(&self_entry, &directory)?;
        Ok(Self {
            limits,
            self_entry,
            directory,
            entries: HashMap::new(),
        })
    }

    /// The mock's own directory entry; its `relay_id()` is the `challenge.authority`.
    #[must_use]
    pub const fn self_entry(&self) -> &RelayEntry {
        &self.self_entry
    }

    /// The served directory (rendezvous §5.4).
    #[must_use]
    pub const fn directory(&self) -> &Directory {
        &self.directory
    }

    /// Replaces the served directory after `directory::check_update`; the new
    /// directory must still list the self entry (rendezvous §5.4).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidDirectory`] when the update is rejected; nothing changes.
    pub fn set_directory(&mut self, new: Directory) -> Result<(), ErrorCode> {
        directory::check_update(&self.directory, &new)?;
        check_self_listed(&self.self_entry, &new)?;
        self.directory = new;
        Ok(())
    }

    /// Number of stored registry entries, conflict latches and entries awaiting the
    /// sweep included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no registry entry is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Verifies `publish` against the connection's challenge nonce and the self
    /// authority, then checks responsibility over the single-relay domain (quick-v2
    /// §7.1, §7.2).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidMessage`] for a bad record, expired record or bad proof.
    pub fn verify(
        &self,
        request: &PublishRequest,
        challenge_nonce: &[u8; 32],
        now: u64,
    ) -> Result<VerifiedPublish, ErrorCode> {
        let verified =
            registry::verify_publish(request, challenge_nonce, &self.self_entry.relay_id(), now)?;
        registry::check_responsible(
            &verified.node_id(),
            self.self_entry.id(),
            &registry::single_relay_domain(&self.self_entry),
        )?;
        Ok(verified)
    }

    /// Applies a verified publish (quick-v2 §3.3, §7.2, §7.4). A new identity is
    /// refused with `capacity` when the record cap is reached; stored records are never
    /// evicted.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Capacity`] as above; otherwise the codes of
    /// [`RegistryEntry::apply_publish`].
    pub fn accept(&mut self, verified: &VerifiedPublish, now: u64) -> Result<Published, ErrorCode> {
        let node_id = verified.node_id();
        let identity = verified.record().identity();
        match self.entries.get_mut(&node_id) {
            // A different identity behind the same node ID may only take over once the
            // old state is past deletion.
            Some(entry) if entry.marks().identity() == identity || !entry.deletion_due(now) => {
                entry.apply_publish(verified, now)
            }
            stored => {
                if stored.is_none() && self.entries.len() >= self.limits.registry_records {
                    return Err(ErrorCode::Capacity);
                }
                let mut entry = RegistryEntry::new(*identity);
                let published = entry.apply_publish(verified, now)?;
                self.entries.insert(node_id, entry);
                Ok(published)
            }
        }
    }

    /// [`verify`](Self::verify) then [`accept`](Self::accept), without the
    /// per-identity rate limit.
    ///
    /// # Errors
    ///
    /// The codes of both steps.
    pub fn publish(
        &mut self,
        request: &PublishRequest,
        challenge_nonce: &[u8; 32],
        now: u64,
    ) -> Result<Published, ErrorCode> {
        let verified = self.verify(request, challenge_nonce, now)?;
        self.accept(&verified, now)
    }

    /// Answers `lookup_node` (quick-v2 §7.2): the unexpired record, or `record: null`
    /// when unknown, expired or past deletion.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Conflict`] while a conflict is latched.
    pub fn lookup_node(
        &self,
        request: &LookupNodeRequest,
        now: u64,
    ) -> Result<RecordResult, ErrorCode> {
        let node_id = NodeId::from_bytes(request.node_id);
        registry::lookup(self.entries.get(&node_id), now)
    }

    /// Drops every entry whose deletion is due at `now` (quick-v2 §7.2): records and
    /// conflict latches go 10 s after `expires`.
    pub fn sweep(&mut self, now: u64) {
        self.entries.retain(|_, entry| !entry.deletion_due(now));
    }
}

/// Checks that `directory` lists `self_entry` (same id, host and port) announcing
/// `registry` and `mailbox`.
fn check_self_listed(self_entry: &RelayEntry, directory: &Directory) -> Result<(), ErrorCode> {
    let listed = directory.relays().iter().any(|entry| {
        entry.id() == self_entry.id()
            && entry.host() == self_entry.host()
            && entry.port() == self_entry.port()
            && entry.capabilities().contains(&capability::REGISTRY)
            && entry.capabilities().contains(&capability::MAILBOX)
    });
    if listed {
        Ok(())
    } else {
        Err(ErrorCode::InvalidDirectory)
    }
}
