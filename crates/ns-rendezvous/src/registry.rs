//! Node registry: publish and lookup_node (quick-v2 §7).
//!
//! The registry domain and HRW sharding (quick-v2 §7.1), the publish proof and the
//! relay-side acceptance against [`RecordMarks`] (quick-v2 §3.3, §7.2), `lookup_node`
//! (quick-v2 §7.2) and the client check of a lookup result (quick-v2 §7.5).

use crate::{
    capability, crypto,
    directory::{Directory, RelayEntry},
    error::ErrorCode,
    message::{PublishRequest, Published, RecordResult},
};
use ed25519_dalek::{Signer, SigningKey};
use ns_wire::{
    Identity, NodeId, NodeRecord, NodeRecordError, REGISTRY_LOOKUP_MAX, REGISTRY_SHARD_REPLICAS,
    RecordDecision, RecordExpired, RecordMarks, RelayId,
};
use std::cmp::Reverse;
use thiserror::Error;

/// Signature context of the publish proof (quick-v2 §7.2, §12.2).
pub const PUBLISH_CONTEXT: &[u8] = b"ns/registry-publish/v2";
/// BLAKE2s key of the HRW shard weight (quick-v2 §7.1).
pub const SHARD_LABEL: &[u8] = b"ns-registry-shard-v2";

// Keyed BLAKE2s accepts keys of at most 32 bytes.
const _: () = assert!(SHARD_LABEL.len() <= 32);

/// Records stored per relay; when full, new identities get `capacity` and unexpired
/// records are never evicted (quick-v2 §7.4).
pub const MAX_RECORDS: usize = 10_000_000;
/// `publish` per source IP per minute (quick-v2 §7.4).
pub const PUBLISHES_PER_IP_PER_MINUTE: u32 = 12;
/// Minimum interval between `publish` of one `I`, in seconds (quick-v2 §7.4).
pub const PUBLISH_INTERVAL_PER_IDENTITY_SECONDS: u64 = 60;
/// `publish` across all sources per second (quick-v2 §7.4).
pub const PUBLISHES_PER_SECOND: u32 = 1000;
/// `lookup_node` per source IP per minute (quick-v2 §7.4).
pub const LOOKUP_NODES_PER_IP_PER_MINUTE: u32 = 60;
/// `lookup_node` across all sources per second (quick-v2 §7.4).
pub const LOOKUP_NODES_PER_SECOND: u32 = 5000;
/// A record is deleted within this many seconds after `expires` (quick-v2 §7.2).
pub const DELETION_GRACE_SECONDS: u64 = 10;

/// `"ns/registry-publish/v2" ‖ nonce ‖ authority ‖ SHA-256(record) ‖ dns_u8`, without
/// length prefixes (quick-v2 §7.2, §12.2).
#[must_use]
pub fn publish_proof_message(
    nonce: &[u8; 32],
    authority: &RelayId,
    record: &[u8],
    dns: bool,
) -> Vec<u8> {
    let authority = authority.as_str().as_bytes();
    let mut message =
        Vec::with_capacity(PUBLISH_CONTEXT.len() + nonce.len() + authority.len() + 32 + 1);
    message.extend_from_slice(PUBLISH_CONTEXT);
    message.extend_from_slice(nonce);
    message.extend_from_slice(authority);
    message.extend_from_slice(&crypto::sha256(&[record]));
    message.push(u8::from(dns));
    message
}

/// Signs the publish proof with the identity key `I` (quick-v2 §7.2).
#[must_use]
pub fn create_publish_proof(
    identity_key: &SigningKey,
    nonce: &[u8; 32],
    authority: &RelayId,
    record: &[u8],
    dns: bool,
) -> [u8; 64] {
    identity_key
        .sign(&publish_proof_message(nonce, authority, record, dns))
        .to_bytes()
}

/// Builds `publish {record, dns, proof}` for the connection's challenge (quick-v2 §7.2).
#[must_use]
pub fn publish_request(
    identity_key: &SigningKey,
    nonce: &[u8; 32],
    authority: &RelayId,
    record: &NodeRecord,
    dns: bool,
) -> PublishRequest {
    PublishRequest {
        record: record.as_bytes().to_vec(),
        dns,
        proof: create_publish_proof(identity_key, nonce, authority, record.as_bytes(), dns),
    }
}

/// A publish whose record is valid and unexpired and whose proof verifies (quick-v2 §7.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPublish {
    record: NodeRecord,
    dns: bool,
}

impl VerifiedPublish {
    /// The published record.
    #[must_use]
    pub const fn record(&self) -> &NodeRecord {
        &self.record
    }

    /// Whether the publisher asked for public DNS.
    #[must_use]
    pub const fn dns(&self) -> bool {
        self.dns
    }

    /// The record's node ID `BLAKE2s-96(I)`.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.record.node_id()
    }
}

/// Verifies a `publish` against the connection's challenge: the record decodes as a
/// valid NodeRecord, is unexpired at `now`, and `proof` strictly verifies under its `I`
/// (quick-v2 §3.2, §7.2, §12.2).
///
/// # Errors
///
/// [`ErrorCode::InvalidMessage`] for any failed check.
pub fn verify_publish(
    request: &PublishRequest,
    nonce: &[u8; 32],
    authority: &RelayId,
    now: u64,
) -> Result<VerifiedPublish, ErrorCode> {
    let record = NodeRecord::decode(&request.record).map_err(|_| ErrorCode::InvalidMessage)?;
    record
        .check_not_expired(now)
        .map_err(|_| ErrorCode::InvalidMessage)?;
    let message = publish_proof_message(nonce, authority, &request.record, request.dns);
    if !crypto::verify_strict(record.identity(), &message, &request.proof) {
        return Err(ErrorCode::InvalidMessage);
    }
    Ok(VerifiedPublish {
        record,
        dns: request.dns,
    })
}

/// The HRW weight `BLAKE2s(out = 8, key = "ns-registry-shard-v2")(node_id ‖ id_be16)`
/// (quick-v2 §7.1).
#[must_use]
pub fn shard_weight(node_id: &NodeId, relay_id: u16) -> [u8; 8] {
    crypto::blake2s_keyed::<8>(SHARD_LABEL, &[node_id.as_bytes(), &relay_id.to_be_bytes()])
}

/// The registry domain: the directory entries announcing `registry` (quick-v2 §7.1).
#[must_use]
pub fn registry_domain(directory: &Directory) -> Vec<&RelayEntry> {
    directory
        .relays()
        .iter()
        .filter(|entry| entry.capabilities().contains(&capability::REGISTRY))
        .collect()
}

/// The registry domain of a node configured with a single relay: that relay
/// (quick-v2 §7.1).
#[must_use]
pub fn single_relay_domain(entry: &RelayEntry) -> Vec<&RelayEntry> {
    vec![entry]
}

/// All domain relay ids in HRW order: weight descending as a big-endian integer, ties
/// by id ascending (quick-v2 §7.1).
#[must_use]
pub fn shard_order(node_id: &NodeId, domain: &[&RelayEntry]) -> Vec<u16> {
    rank(
        domain
            .iter()
            .map(|entry| (shard_weight(node_id, entry.id()), entry.id()))
            .collect(),
    )
}

/// Sorts `(weight, id)` by weight descending, then id ascending (quick-v2 §7.1).
fn rank(mut ranked: Vec<([u8; 8], u16)>) -> Vec<u16> {
    ranked.sort_by_key(|&(weight, id)| (Reverse(weight), id));
    ranked.into_iter().map(|(_, id)| id).collect()
}

/// The shard relays: the first [`REGISTRY_SHARD_REPLICAS`] of the HRW order, where the
/// node publishes (quick-v2 §7.1).
#[must_use]
pub fn shard_relays(node_id: &NodeId, domain: &[&RelayEntry]) -> Vec<u16> {
    let mut order = shard_order(node_id, domain);
    order.truncate(REGISTRY_SHARD_REPLICAS);
    order
}

/// The lookup relays: the first [`REGISTRY_LOOKUP_MAX`] of the HRW order, asked in
/// order to cover one directory change (quick-v2 §7.1).
#[must_use]
pub fn lookup_relays(node_id: &NodeId, domain: &[&RelayEntry]) -> Vec<u16> {
    let mut order = shard_order(node_id, domain);
    order.truncate(REGISTRY_LOOKUP_MAX);
    order
}

/// The lenient responsibility check: `self_id` is among the lookup relays of
/// `node_id` (quick-v2 §7.2).
#[must_use]
pub fn is_responsible(node_id: &NodeId, self_id: u16, domain: &[&RelayEntry]) -> bool {
    lookup_relays(node_id, domain).contains(&self_id)
}

/// [`is_responsible`] as a relay-side check (quick-v2 §7.2).
///
/// # Errors
///
/// [`ErrorCode::InvalidMessage`] when this relay is not responsible; rendezvous §7 has
/// no more specific code.
pub fn check_responsible(
    node_id: &NodeId,
    self_id: u16,
    domain: &[&RelayEntry],
) -> Result<(), ErrorCode> {
    if is_responsible(node_id, self_id, domain) {
        Ok(())
    } else {
        Err(ErrorCode::InvalidMessage)
    }
}

/// The registry state of one identity on a shard relay: the [`RecordMarks`] ordering
/// state and the `dns` choice of the most recent accepted publish (quick-v2 §3.3, §7.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryEntry {
    marks: RecordMarks,
    dns: bool,
}

impl RegistryEntry {
    /// The empty state for `identity`: no record, `committed_gen = 0`, `dns = false`.
    #[must_use]
    pub const fn new(identity: Identity) -> Self {
        Self {
            marks: RecordMarks::new(identity),
            dns: false,
        }
    }

    /// The stored record, if any.
    #[must_use]
    pub const fn record(&self) -> Option<&NodeRecord> {
        self.marks.current()
    }

    /// Whether the stored record is published as public DNS (quick-v2 §7.2, §11.2).
    #[must_use]
    pub const fn dns(&self) -> bool {
        self.dns
    }

    /// The §3.3 ordering state.
    #[must_use]
    pub const fn marks(&self) -> &RecordMarks {
        &self.marks
    }

    /// Applies a verified publish (quick-v2 §3.3, §7.2).
    ///
    /// A lower `gen`, a new same-`gen` conflict (which is latched) and any publish
    /// below a higher `gen` while a conflict is latched are rejected with `conflict`;
    /// rejected publishes change nothing else. An accepted publish stores the record
    /// as §3.3 decides and takes its `dns` choice. A state past its deletion grace is
    /// treated as deleted first.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Conflict`] as above; [`ErrorCode::InvalidMessage`] when the record
    /// has expired at `now` or belongs to another identity.
    pub fn apply_publish(
        &mut self,
        verified: &VerifiedPublish,
        now: u64,
    ) -> Result<Published, ErrorCode> {
        verified
            .record
            .check_not_expired(now)
            .map_err(|_| ErrorCode::InvalidMessage)?;
        if verified.record.identity() != self.marks.identity() {
            return Err(ErrorCode::InvalidMessage);
        }
        if self.deletion_due(now) {
            *self = Self::new(*self.marks.identity());
        }
        let decision = self
            .marks
            .evaluate(&verified.record)
            .map_err(|_| ErrorCode::InvalidMessage)?;
        match decision {
            RecordDecision::Stale => return Err(ErrorCode::Conflict),
            RecordDecision::Conflict => {
                self.marks
                    .apply(&verified.record)
                    .map_err(|_| ErrorCode::InvalidMessage)?;
                return Err(ErrorCode::Conflict);
            }
            RecordDecision::Refreshed | RecordDecision::Unchanged if self.marks.is_conflicted() => {
                return Err(ErrorCode::Conflict);
            }
            RecordDecision::Advanced | RecordDecision::Refreshed | RecordDecision::Unchanged => {}
        }
        self.marks
            .apply(&verified.record)
            .map_err(|_| ErrorCode::InvalidMessage)?;
        self.dns = verified.dns;
        let expires = self
            .marks
            .current()
            .map_or(verified.record.expires(), NodeRecord::expires);
        Ok(Published { expires })
    }

    /// True once `now > expires + 10`, when the relay deletes the state; an empty state
    /// is always due (quick-v2 §7.2).
    #[must_use]
    pub fn deletion_due(&self, now: u64) -> bool {
        self.marks
            .current()
            .is_none_or(|record| now > record.expires().saturating_add(DELETION_GRACE_SECONDS))
    }
}

/// Answers `lookup_node` from the entry stored for the node ID: the unexpired record,
/// `record: null` when absent, expired or past deletion (quick-v2 §7.2).
///
/// # Errors
///
/// [`ErrorCode::Conflict`] while a conflict is latched.
pub fn lookup(entry: Option<&RegistryEntry>, now: u64) -> Result<RecordResult, ErrorCode> {
    let Some(entry) = entry.filter(|entry| !entry.deletion_due(now)) else {
        return Ok(RecordResult { record: None });
    };
    if entry.marks.is_conflicted() {
        return Err(ErrorCode::Conflict);
    }
    let record = entry
        .record()
        .filter(|record| !record.is_expired(now))
        .map(|record| record.as_bytes().to_vec());
    Ok(RecordResult { record })
}

/// A `record` result the client discards (quick-v2 §3.2, §7.5).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LookupError {
    /// The bytes are not a valid NodeRecord.
    #[error(transparent)]
    Record(#[from] NodeRecordError),
    /// The record has expired.
    #[error(transparent)]
    Expired(#[from] RecordExpired),
    /// `BLAKE2s-96(I)` differs from the node ID looked up.
    #[error("record identity does not match the node ID looked up")]
    NodeIdMismatch,
}

/// Client check of a non-null `record` result: valid, `BLAKE2s-96(I)` equals the node
/// ID looked up, and unexpired at `now` (quick-v2 §3.2, §7.5).
///
/// # Errors
///
/// [`LookupError`] naming the first failed check.
pub fn verify_lookup_result(
    expected: &NodeId,
    record: &[u8],
    now: u64,
) -> Result<NodeRecord, LookupError> {
    let record = NodeRecord::decode(record)?;
    if &NodeId::derive(record.identity()) != expected {
        return Err(LookupError::NodeIdMismatch);
    }
    record.check_not_expired(now)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::rank;

    #[test]
    fn rank_breaks_weight_ties_by_id_ascending() {
        let high = [0x80, 0, 0, 0, 0, 0, 0, 0];
        let low = [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            rank(vec![(low, 1), (high, 9), (high, 3), (low, 0), (high, 5)]),
            [3, 5, 9, 0, 1]
        );
        // Weights compare as big-endian integers: the last byte decides last.
        assert_eq!(
            rank(vec![([0; 8], 1), ([0, 0, 0, 0, 0, 0, 0, 1], 2)]),
            [2, 1]
        );
    }
}
