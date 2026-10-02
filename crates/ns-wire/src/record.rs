//! Node records, their validity and the per-identity ordering state (quick-v2 §3).

use crate::{
    codec::{CborError, CborReader, CborWriter},
    constants::{
        MAX_NODE_RECORD_BYTES, MAX_RECORD_SERVICE_SECONDS, NODE_RECORD_CONTEXT, NODE_RECORD_VERSION,
    },
    identifier::{RelayId, RelayIdError},
    identity::{Identity, NodeId},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

/// Maximum relays in a NodeRecord (quick-v2 §3.1).
pub const MAX_NODE_RECORD_RELAYS: usize = 4;

/// An X25519 WireGuard public key `K` (quick-v2 §2.1).
pub type WireGuardKey = [u8; 32];

/// The signed fields of a NodeRecord other than `ver` and `I`, supplied when signing
/// (quick-v2 §3.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRecordFields {
    /// The WireGuard public key `K`.
    pub wg_key: WireGuardKey,
    /// The generation of `K`, starting at 1 and incremented on every rotation.
    pub generation: u64,
    /// Unix seconds, strictly increasing per identity (see [`next_issued_at`]).
    pub issued_at: u64,
    /// Unix seconds, exclusive; must exceed `issued_at`.
    pub expires: u64,
    /// 0..=4 relays holding an active slot for the node, home relay first.
    pub relays: Vec<RelayId>,
}

/// A valid NodeRecord together with its exact canonical encoding (quick-v2 §3.1-§3.2).
///
/// Values are only produced by [`NodeRecord::sign`] and [`NodeRecord::decode`], so every
/// value is valid: canonical, `ver = 2`, `gen >= 1`, `expires > issued_at`, at most four
/// valid relays and a strictly verified signature under `I`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRecord {
    identity: Identity,
    fields: NodeRecordFields,
    signature: [u8; 64],
    encoded: Vec<u8>,
}

/// A rejected NodeRecord (quick-v2 §3.1-§3.2).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NodeRecordError {
    /// The encoding exceeds 600 bytes (quick-v2 §3.1, §12.3).
    #[error("node record of {0} bytes exceeds {MAX_NODE_RECORD_BYTES} bytes")]
    TooLarge(usize),
    /// The input is not canonical CBOR of the record shape (quick-v2 §12.1).
    #[error("non-canonical node record: {0}")]
    Cbor(#[from] CborError),
    /// `ver` is not 2 (quick-v2 §3.2).
    #[error("unknown node record version {0}")]
    Version(u64),
    /// More than four relays (quick-v2 §3.1).
    #[error("node record lists {0} relays, at most {MAX_NODE_RECORD_RELAYS} allowed")]
    TooManyRelays(usize),
    /// A relay entry is not a canonical relay identifier (quick-v2 §3.2, §8.6).
    #[error("invalid relay identifier: {0}")]
    RelayId(#[from] RelayIdError),
    /// `gen` is 0; generations start at 1 (quick-v2 §3.1).
    #[error("node record generation must start at 1")]
    ZeroGeneration,
    /// `expires <= issued_at` (quick-v2 §3.2).
    #[error("node record expires {expires} is not after issued_at {issued_at}")]
    ExpiresNotAfterIssued {
        /// The record `issued_at`.
        issued_at: u64,
        /// The record `expires`.
        expires: u64,
    },
    /// `I` is not a valid Ed25519 point (quick-v2 §12.2).
    #[error("identity is not a valid Ed25519 public key")]
    InvalidIdentity,
    /// `I` is a small-order point (quick-v2 §12.2).
    #[error("identity is a small-order Ed25519 point")]
    WeakIdentity,
    /// The signature does not strictly verify under `I` (quick-v2 §3.2, §12.2).
    #[error("node record signature does not verify")]
    BadSignature,
}

/// A record whose exclusive `expires` is not after `now` (quick-v2 §3.2).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("node record expired at {expires}, now {now}")]
pub struct RecordExpired {
    /// The record `expires`.
    pub expires: u64,
    /// The caller-supplied time.
    pub now: u64,
}

/// A record whose service period `expires - issued_at` exceeds seven days (quick-v2 §3.1).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("node record service period {0} s exceeds {MAX_RECORD_SERVICE_SECONDS} s")]
pub struct ServicePeriodTooLong(pub u64);

/// The next `issued_at` would exceed `u64::MAX` (quick-v2 §3.1).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("issued_at overflow after {0}")]
pub struct IssuedAtOverflow(pub u64);

/// Returns the next `issued_at = max(now, last + 1)`; `last` is the persisted previous
/// value, `None` before the first record (quick-v2 §3.1).
///
/// # Errors
///
/// [`IssuedAtOverflow`] when `last + 1` overflows.
pub fn next_issued_at(now: u64, last: Option<u64>) -> Result<u64, IssuedAtOverflow> {
    match last {
        None => Ok(now),
        Some(last) => last
            .checked_add(1)
            .map(|next| next.max(now))
            .ok_or(IssuedAtOverflow(last)),
    }
}

impl NodeRecord {
    /// Signs a record for the identity of `signer`:
    /// `sig = Ed25519_I("ns/node-record/v2" ‖ CBOR(first seven fields))` (quick-v2 §3.1).
    ///
    /// # Errors
    ///
    /// [`NodeRecordError::ZeroGeneration`], [`NodeRecordError::ExpiresNotAfterIssued`],
    /// [`NodeRecordError::TooManyRelays`] or [`NodeRecordError::TooLarge`] for fields that
    /// would not form a valid record.
    pub fn sign(signer: &SigningKey, fields: NodeRecordFields) -> Result<Self, NodeRecordError> {
        let identity = signer.verifying_key().to_bytes();
        check_fields(&fields)?;
        let signature = signer.sign(&signing_message(&identity, &fields)).to_bytes();
        let encoded = encode(&identity, &fields, Some(&signature));
        if encoded.len() > MAX_NODE_RECORD_BYTES {
            return Err(NodeRecordError::TooLarge(encoded.len()));
        }
        Ok(Self {
            identity,
            fields,
            signature,
            encoded,
        })
    }

    /// Decodes and validates a record (quick-v2 §3.1-§3.2, §12.1).
    ///
    /// Size, canonical CBOR, version, arity, trailing bytes, relay count and syntax,
    /// `gen` and `expires > issued_at` are all checked before the signature.
    ///
    /// # Errors
    ///
    /// [`NodeRecordError`] naming the first violated rule.
    pub fn decode(encoded: &[u8]) -> Result<Self, NodeRecordError> {
        if encoded.len() > MAX_NODE_RECORD_BYTES {
            return Err(NodeRecordError::TooLarge(encoded.len()));
        }
        let mut reader = CborReader::new(encoded, MAX_NODE_RECORD_BYTES)?;
        reader.array(8)?;
        let version = reader.uint()?;
        if version != u64::from(NODE_RECORD_VERSION) {
            return Err(NodeRecordError::Version(version));
        }
        let identity = reader.fixed_bytes::<32>()?;
        let wg_key = reader.fixed_bytes::<32>()?;
        let generation = reader.uint()?;
        let issued_at = reader.uint()?;
        let expires = reader.uint()?;
        let count = reader.array_up_to(MAX_NODE_RECORD_BYTES)?;
        if count > MAX_NODE_RECORD_RELAYS {
            return Err(NodeRecordError::TooManyRelays(count));
        }
        let mut relays = Vec::with_capacity(count);
        for _ in 0..count {
            relays.push(RelayId::parse(reader.text_up_to(MAX_NODE_RECORD_BYTES)?)?);
        }
        let signature = reader.fixed_bytes::<64>()?;
        reader.finish()?;
        let fields = NodeRecordFields {
            wg_key,
            generation,
            issued_at,
            expires,
            relays,
        };
        check_fields(&fields)?;
        let record = Self {
            identity,
            fields,
            signature,
            encoded: encoded.to_vec(),
        };
        record.verify()?;
        Ok(record)
    }

    /// Strictly verifies the signature under `I` (quick-v2 §3.2, §12.2).
    ///
    /// # Errors
    ///
    /// [`NodeRecordError::InvalidIdentity`], [`NodeRecordError::WeakIdentity`] or
    /// [`NodeRecordError::BadSignature`].
    pub fn verify(&self) -> Result<(), NodeRecordError> {
        let key = VerifyingKey::from_bytes(&self.identity)
            .map_err(|_| NodeRecordError::InvalidIdentity)?;
        if key.is_weak() {
            return Err(NodeRecordError::WeakIdentity);
        }
        key.verify_strict(
            &signing_message(&self.identity, &self.fields),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| NodeRecordError::BadSignature)
    }

    /// Returns the exact canonical encoding (quick-v2 §3.1).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns the identity `I` (quick-v2 §3.1).
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the node ID `BLAKE2s-96(I)` (quick-v2 §2.2, §11.2).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId::derive(&self.identity)
    }

    /// Returns the WireGuard key `K` (quick-v2 §3.1).
    #[must_use]
    pub const fn wg_key(&self) -> &WireGuardKey {
        &self.fields.wg_key
    }

    /// Returns the generation `gen` of `K` (quick-v2 §3.1).
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.fields.generation
    }

    /// Returns `issued_at` in Unix seconds (quick-v2 §3.1).
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.fields.issued_at
    }

    /// Returns the exclusive `expires` in Unix seconds (quick-v2 §3.1).
    #[must_use]
    pub const fn expires(&self) -> u64 {
        self.fields.expires
    }

    /// Returns the relays, home relay first (quick-v2 §3.1).
    #[must_use]
    pub fn relays(&self) -> &[RelayId] {
        &self.fields.relays
    }

    /// Returns the signed fields (quick-v2 §3.1).
    #[must_use]
    pub const fn fields(&self) -> &NodeRecordFields {
        &self.fields
    }

    /// Returns the signature (quick-v2 §3.1).
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Returns true when the record has expired at `now`; `expires` is exclusive
    /// (quick-v2 §3.1-§3.2).
    #[must_use]
    pub const fn is_expired(&self, now: u64) -> bool {
        now >= self.fields.expires
    }

    /// Checks that the record has not expired at `now`, as relays and clients of the
    /// registry and DNS do (quick-v2 §3.2).
    ///
    /// # Errors
    ///
    /// [`RecordExpired`] when `now >= expires`.
    pub const fn check_not_expired(&self, now: u64) -> Result<(), RecordExpired> {
        if self.is_expired(now) {
            Err(RecordExpired {
                expires: self.fields.expires,
                now,
            })
        } else {
            Ok(())
        }
    }

    /// Returns the service period `expires - issued_at` in seconds (quick-v2 §3.1).
    #[must_use]
    pub const fn service_period(&self) -> u64 {
        self.fields.expires.saturating_sub(self.fields.issued_at)
    }

    /// Checks `expires - issued_at <= 604800` (quick-v2 §3.1).
    ///
    /// # Errors
    ///
    /// [`ServicePeriodTooLong`] with the actual period.
    pub const fn check_service_period(&self) -> Result<(), ServicePeriodTooLong> {
        let period = self.service_period();
        if period > MAX_RECORD_SERVICE_SECONDS {
            Err(ServicePeriodTooLong(period))
        } else {
            Ok(())
        }
    }

    /// Returns true when less than half of the service period remains at `now`, so the
    /// node re-signs with the same `gen` and `K` (quick-v2 §3.1). A change of `relays`
    /// also requires re-signing; that is the caller's comparison.
    #[must_use]
    pub const fn needs_resign(&self, now: u64) -> bool {
        let remaining = self.fields.expires.saturating_sub(now) as u128;
        remaining * 2 < self.service_period() as u128
    }
}

fn check_fields(fields: &NodeRecordFields) -> Result<(), NodeRecordError> {
    if fields.generation == 0 {
        return Err(NodeRecordError::ZeroGeneration);
    }
    if fields.expires <= fields.issued_at {
        return Err(NodeRecordError::ExpiresNotAfterIssued {
            issued_at: fields.issued_at,
            expires: fields.expires,
        });
    }
    if fields.relays.len() > MAX_NODE_RECORD_RELAYS {
        return Err(NodeRecordError::TooManyRelays(fields.relays.len()));
    }
    Ok(())
}

/// Encodes the eight-element record, or the seven signed fields when `signature` is
/// `None` (quick-v2 §3.1).
fn encode(identity: &Identity, fields: &NodeRecordFields, signature: Option<&[u8; 64]>) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(MAX_NODE_RECORD_BYTES);
    writer
        .array(if signature.is_some() { 8 } else { 7 })
        .uint(u64::from(NODE_RECORD_VERSION))
        .bytes(identity)
        .bytes(&fields.wg_key)
        .uint(fields.generation)
        .uint(fields.issued_at)
        .uint(fields.expires)
        .array(fields.relays.len());
    for relay in &fields.relays {
        writer.text(relay.as_str());
    }
    if let Some(signature) = signature {
        writer.bytes(signature);
    }
    writer.into_bytes()
}

/// `"ns/node-record/v2" ‖ CBOR(first seven fields)` (quick-v2 §3.1, §12.2).
fn signing_message(identity: &Identity, fields: &NodeRecordFields) -> Vec<u8> {
    let mut message = NODE_RECORD_CONTEXT.to_vec();
    message.extend_from_slice(&encode(identity, fields, None));
    message
}

/// The per-identity ordering state: current record, `committed_gen` and conflict flag
/// (quick-v2 §3.3).
///
/// The initial state holds no record and `committed_gen = 0`; since every valid record
/// has `gen >= 1`, the first valid record is always accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordMarks {
    identity: Identity,
    current: Option<NodeRecord>,
    conflicted: bool,
}

/// The outcome of evaluating a valid candidate record against [`RecordMarks`]
/// (quick-v2 §3.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordDecision {
    /// `gen < committed_gen`: rejected, state unchanged.
    Stale,
    /// `gen > committed_gen`: accepted; record and `K` replaced, `committed_gen = gen`,
    /// conflict cleared.
    Advanced,
    /// `gen == committed_gen` with a different `K`: the generation is latched as
    /// conflicted until a higher `gen`; report `record_conflict`.
    Conflict,
    /// `gen == committed_gen`, same `K`, larger `issued_at`: only the record bytes
    /// (`relays`, `expires`) are replaced; a latched conflict stays latched.
    Refreshed,
    /// Any other input: idempotent, state unchanged.
    Unchanged,
}

/// A candidate record that cannot be evaluated against this state (quick-v2 §3.3).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("candidate record identity differs from the state identity")]
pub struct IdentityMismatch;

impl RecordMarks {
    /// Returns the initial state for `identity`: no record, `committed_gen = 0`, no
    /// conflict (quick-v2 §3.3).
    #[must_use]
    pub const fn new(identity: Identity) -> Self {
        Self {
            identity,
            current: None,
            conflicted: false,
        }
    }

    /// Returns the identity `I` this state is kept for (quick-v2 §3.3).
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the current record, if any (quick-v2 §3.3).
    #[must_use]
    pub const fn current(&self) -> Option<&NodeRecord> {
        self.current.as_ref()
    }

    /// Returns `committed_gen`, 0 before the first record (quick-v2 §3.3).
    #[must_use]
    pub fn committed_gen(&self) -> u64 {
        self.current.as_ref().map_or(0, NodeRecord::generation)
    }

    /// Returns true while the committed generation is latched as conflicted; that
    /// generation is disabled until a higher `gen` (quick-v2 §3.3).
    #[must_use]
    pub const fn is_conflicted(&self) -> bool {
        self.conflicted
    }

    /// Classifies a valid candidate without changing state (quick-v2 §3.3).
    ///
    /// # Errors
    ///
    /// [`IdentityMismatch`] when the candidate `I` differs from the state `I`.
    pub fn evaluate(&self, candidate: &NodeRecord) -> Result<RecordDecision, IdentityMismatch> {
        if candidate.identity != self.identity {
            return Err(IdentityMismatch);
        }
        let Some(current) = &self.current else {
            return Ok(RecordDecision::Advanced);
        };
        let decision = if candidate.generation() < current.generation() {
            RecordDecision::Stale
        } else if candidate.generation() > current.generation() {
            RecordDecision::Advanced
        } else if candidate.wg_key() != current.wg_key() {
            RecordDecision::Conflict
        } else if candidate.issued_at() > current.issued_at() {
            RecordDecision::Refreshed
        } else {
            RecordDecision::Unchanged
        };
        Ok(decision)
    }

    /// Evaluates a valid candidate and applies the decision (quick-v2 §3.3).
    ///
    /// # Errors
    ///
    /// [`IdentityMismatch`] when the candidate `I` differs from the state `I`; the state
    /// is unchanged.
    pub fn apply(&mut self, candidate: &NodeRecord) -> Result<RecordDecision, IdentityMismatch> {
        let decision = self.evaluate(candidate)?;
        match decision {
            RecordDecision::Advanced => {
                self.current = Some(candidate.clone());
                self.conflicted = false;
            }
            RecordDecision::Refreshed => self.current = Some(candidate.clone()),
            RecordDecision::Conflict => self.conflicted = true,
            RecordDecision::Stale | RecordDecision::Unchanged => {}
        }
        Ok(decision)
    }
}
