//! Relay-side REGISTER admission, §8.3 rule 1 (quick-v2 §8.3, quick-protocol §12.5 rule 1).

use super::{
    crypto::{SessionKey, ZeroSharedSecret, derive_session_key, ephemeral_public},
    packet::{BadRegisterSignature, Register, RelayBody, RelayPacket, RelayPacketError, RelayType},
};
use crate::{
    constants::REGISTER_TS_WINDOW_SECONDS,
    identifier::RelayId,
    identity::NodeId,
    record::{NodeRecord, NodeRecordError, RecordDecision, RecordExpired, RecordMarks},
};
use thiserror::Error;

/// A REGISTER rejected by §8.3 rule 1; variants are listed in check order
/// (quick-v2 §8.3 rule 1).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegisterRejection {
    /// Length, magic, type, direction, size or body schema (quick-v2 §8.1-§8.2).
    #[error("invalid relay packet: {0}")]
    Packet(#[from] RelayPacketError),
    /// A well-formed packet of another type.
    #[error("{0:?} packet is not a REGISTER")]
    NotRegister(RelayType),
    /// The header src is not `NodeId(record.I)` (quick-v2 §8.3 rule 1).
    #[error("src {src} is not the node ID {expected} of record.I")]
    SourceMismatch {
        /// The header src slot.
        src: NodeId,
        /// The node ID of `record.I`.
        expected: NodeId,
    },
    /// `relay_name` differs from the published identifier of this relay
    /// (quick-v2 §8.3 rule 1).
    #[error("relay_name is not the published identifier of this relay")]
    RelayName,
    /// `|now - ts| > 120 s` (quick-v2 §8.3 rule 1).
    #[error("REGISTER ts {ts} is more than 120 s from now {now}")]
    Timestamp {
        /// The REGISTER `ts`.
        ts: u64,
        /// The caller-supplied time.
        now: u64,
    },
    /// The nested record is not valid (quick-v2 §3.2).
    #[error("invalid node record: {0}")]
    Record(#[from] NodeRecordError),
    /// The nested record has expired at `now` (quick-v2 §3.2).
    #[error(transparent)]
    RecordExpired(#[from] RecordExpired),
    /// The REGISTER signature does not verify (quick-v2 §8.3).
    #[error(transparent)]
    Signature(#[from] BadRegisterSignature),
    /// The supplied marks are kept for a different identity.
    #[error("record marks are kept for a different identity")]
    MarksIdentity,
    /// `gen < committed_gen` (quick-v2 §3.3).
    #[error("record generation {generation} is below committed generation {committed}")]
    StaleGeneration {
        /// The record `gen`.
        generation: u64,
        /// The stored `committed_gen`.
        committed: u64,
    },
    /// `gen == committed_gen` with a different `K`: the caller latches the conflict by
    /// applying the record to its marks and reports `record_conflict` (quick-v2 §3.3).
    #[error("record generation {0} conflicts with the committed key")]
    Conflict(u64),
    /// The committed generation is already latched as conflicted (quick-v2 §3.3).
    #[error("record generation {0} is latched as conflicted")]
    ConflictLatched(u64),
}

/// A REGISTER that passed every pre-cryptographic check of §8.3 rule 1; the caller may
/// charge its REGISTER verification budget before calling [`Self::verify`]
/// (quick-v2 §8.3 rule 1, §8.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterCandidate {
    register: Register,
    now: u64,
}

impl RegisterCandidate {
    /// Runs the pre-cryptographic checks in order: length, magic, direction, schema,
    /// size limits, `src = NodeId(record.I)`, `relay_name` equals `published`, and
    /// `|now - ts| <= 120 s` (quick-v2 §8.3 rule 1).
    ///
    /// A non-zero src is part of the direction check; an identity whose node ID is all
    /// zero therefore never passes (quick-v2 §8.1).
    ///
    /// # Errors
    ///
    /// [`RegisterRejection`] naming the first failed check.
    pub fn precheck(
        packet: &[u8],
        published: &RelayId,
        now: u64,
    ) -> Result<Self, RegisterRejection> {
        let packet = RelayPacket::decode(packet)?;
        let RelayBody::Register(register) = packet.body else {
            return Err(RegisterRejection::NotRegister(packet.body.packet_type()));
        };
        let expected = register.node_id();
        if packet.src != expected {
            return Err(RegisterRejection::SourceMismatch {
                src: packet.src,
                expected,
            });
        }
        if register.relay_name().as_bytes() != published.as_str().as_bytes() {
            return Err(RegisterRejection::RelayName);
        }
        if now.abs_diff(register.ts()) > REGISTER_TS_WINDOW_SECONDS {
            return Err(RegisterRejection::Timestamp {
                ts: register.ts(),
                now,
            });
        }
        Ok(Self { register, now })
    }

    /// Returns the prechecked REGISTER (quick-v2 §8.2).
    #[must_use]
    pub const fn register(&self) -> &Register {
        &self.register
    }

    /// Runs the cryptographic checks in order: record valid and not expired at `now`,
    /// REGISTER signature, then the §3.3 comparison against `marks`; nothing is
    /// committed (quick-v2 §8.3 rule 1).
    ///
    /// # Errors
    ///
    /// [`RegisterRejection`] naming the first failed check.
    pub fn verify(self, marks: &RecordMarks) -> Result<VerifiedRegister, RegisterRejection> {
        let record = NodeRecord::decode(self.register.record())?;
        record.check_not_expired(self.now)?;
        self.register.verify_signature()?;
        let decision = marks
            .evaluate(&record)
            .map_err(|_| RegisterRejection::MarksIdentity)?;
        let generation = record.generation();
        match decision {
            RecordDecision::Stale => Err(RegisterRejection::StaleGeneration {
                generation,
                committed: marks.committed_gen(),
            }),
            _ if marks.is_conflicted() && generation == marks.committed_gen() => {
                Err(RegisterRejection::ConflictLatched(generation))
            }
            RecordDecision::Conflict => Err(RegisterRejection::Conflict(generation)),
            RecordDecision::Advanced | RecordDecision::Refreshed | RecordDecision::Unchanged => {
                Ok(VerifiedRegister {
                    reg_hash: self.register.reg_hash(),
                    register: self.register,
                    record,
                    decision,
                })
            }
        }
    }
}

/// Runs the whole of §8.3 rule 1 on a received packet: [`RegisterCandidate::precheck`]
/// then [`RegisterCandidate::verify`] (quick-v2 §8.3 rule 1).
///
/// # Errors
///
/// [`RegisterRejection`] naming the first failed check; every pre-cryptographic failure
/// is reported before any signature is checked.
pub fn check_register(
    packet: &[u8],
    published: &RelayId,
    now: u64,
    marks: &RecordMarks,
) -> Result<VerifiedRegister, RegisterRejection> {
    RegisterCandidate::precheck(packet, published, now)?.verify(marks)
}

/// A REGISTER that passed §8.3 rule 1 (quick-v2 §8.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRegister {
    register: Register,
    record: NodeRecord,
    reg_hash: [u8; 32],
    decision: RecordDecision,
}

impl VerifiedRegister {
    /// Returns the REGISTER (quick-v2 §8.2).
    #[must_use]
    pub const fn register(&self) -> &Register {
        &self.register
    }

    /// Returns the valid, unexpired nested record (quick-v2 §3.2).
    #[must_use]
    pub const fn record(&self) -> &NodeRecord {
        &self.record
    }

    /// Returns the src slot, `NodeId(record.I)` (quick-v2 §8.3).
    #[must_use]
    pub fn src(&self) -> NodeId {
        self.record.node_id()
    }

    /// Returns `reg_hash = SHA-256(CBOR(six-field REGISTER body))` (quick-v2 §8.3).
    #[must_use]
    pub const fn reg_hash(&self) -> &[u8; 32] {
        &self.reg_hash
    }

    /// Returns how the marks would change when the registration is committed:
    /// [`RecordDecision::Advanced`], [`RecordDecision::Refreshed`] or
    /// [`RecordDecision::Unchanged`] (quick-v2 §3.3, §8.3 rule 3).
    #[must_use]
    pub const fn decision(&self) -> RecordDecision {
        self.decision
    }

    /// Derives the relay side of `sk` from the relay ephemeral secret (quick-v2 §8.3).
    ///
    /// # Errors
    ///
    /// [`ZeroSharedSecret`].
    pub fn relay_session_key(
        &self,
        relay_secret: &[u8; 32],
    ) -> Result<SessionKey, ZeroSharedSecret> {
        derive_session_key(
            relay_secret,
            self.register.node_ephemeral(),
            &self.src(),
            self.register.incarnation(),
            self.register.node_ephemeral(),
            &ephemeral_public(relay_secret),
            &self.reg_hash,
        )
    }
}

impl Register {
    /// Derives the node side of `sk` from the node ephemeral secret and the
    /// `relay_ephemeral` of REGISTERED (quick-v2 §8.3).
    ///
    /// # Errors
    ///
    /// [`ZeroSharedSecret`].
    pub fn node_session_key(
        &self,
        node_secret: &[u8; 32],
        relay_ephemeral: &[u8; 32],
    ) -> Result<SessionKey, ZeroSharedSecret> {
        derive_session_key(
            node_secret,
            relay_ephemeral,
            &self.node_id(),
            self.incarnation(),
            self.node_ephemeral(),
            relay_ephemeral,
            &self.reg_hash(),
        )
    }
}
