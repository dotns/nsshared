//! Pairing application payloads, mailbox `kind = "pairing"` (quick-v2 §10.2, rendezvous §9).
//!
//! Invite, Join and the ACCEPT / COMPLETE messages are canonical CBOR arrays (quick-v2
//! §12.1) signed under the embedded NodeRecord's identity `I` (quick-v2 §12.2). Decoding
//! rejects non-canonical input, trailing bytes and unknown versions or types before any
//! signature check; the `verify` methods then mirror the checks of quick-v2 §10.2 steps 2
//! and 4. The `Removed` list and the address-group check of those steps are caller policy:
//! pass the verified record's identity to [`ns_wire::check_address_conflict`].
//!
//! This module only covers the payloads, the PSK and the mailbox `open` mapping; it holds
//! no pairing state machine.

use crate::{
    crypto,
    limits::{MAX_DATA_BYTES, MAX_INTRO_BYTES, MAX_TTL_SECONDS, MIN_TTL_SECONDS},
    message::{Admission, Kind, MailboxId, MessageError, OpenRequest},
};
use ed25519_dalek::{Signer, SigningKey};
use ns_wire::{
    CborError, CborReader, CborWriter, Identity, MAX_NODE_RECORD_RELAYS, MAX_RELAY_ID_BYTES,
    NodeRecord, NodeRecordError, RecordExpired, RelayId, RelayIdError, ServicePeriodTooLong,
};
use thiserror::Error;
use zeroize::Zeroizing;

/// Mailbox kind of pairing (quick-v2 §10.2, rendezvous §9.1).
pub const KIND_PAIRING: &str = "pairing";
/// Mailbox kind of file transfer (rendezvous §9.2).
pub const KIND_TRANSFER: &str = "transfer";
/// The `ver` of every pairing payload (quick-v2 §10.2).
pub const PAIRING_VERSION: u8 = 2;

/// Signature context of an Invite (quick-v2 §10.2, §12.2).
pub const INVITE_CONTEXT: &[u8] = b"ns/pairing-invite/v2";
/// Signature context of a Join (quick-v2 §10.2, §12.2).
pub const JOIN_CONTEXT: &[u8] = b"ns/pairing-join/v2";
/// Signature context of an ACCEPT (quick-v2 §10.2, §12.2).
pub const ACCEPT_CONTEXT: &[u8] = b"ns/pairing-accept/v2";
/// HKDF info context of the pairing PSK (quick-v2 §10.2, §12.2).
pub const PSK_CONTEXT: &[u8] = b"ns/pairing-psk/v2";

/// Message type ACCEPT (quick-v2 §10.2).
pub const MESSAGE_ACCEPT: u8 = 1;
/// Message type COMPLETE (quick-v2 §10.2).
pub const MESSAGE_COMPLETE: u8 = 2;

/// Default pairing mailbox `ttl` in seconds (quick-v2 §10.2, §12.3).
pub const DEFAULT_PAIRING_TTL_SECONDS: u64 = ns_wire::DEFAULT_PAIRING_MAILBOX_TTL_SECONDS;
/// Maximum pairing mailbox `ttl` in seconds (quick-v2 §10.2, §12.3).
pub const MAX_PAIRING_TTL_SECONDS: u64 = ns_wire::MAX_PAIRING_MAILBOX_TTL_SECONDS;
/// Waiting candidates of a pairing mailbox (quick-v2 §10.2, rendezvous §9.1).
pub const PAIRING_CANDIDATES: u8 = 4;
/// Maximum `name` length in UTF-8 bytes; quick-v2 §10.2 gives no bound.
pub const MAX_NAME_BYTES: usize = 64;

/// A rejected pairing payload or failed pairing check (quick-v2 §10.2, §12.1).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PairingError {
    /// The encoding exceeds 4 KiB (Invite, Join) or 8 KiB (message) (rendezvous §5.2).
    #[error("pairing payload of {length} bytes exceeds {maximum} bytes")]
    TooLarge {
        /// Payload length in bytes.
        length: usize,
        /// Maximum accepted length in bytes.
        maximum: usize,
    },
    /// The input is not canonical CBOR of the payload shape (quick-v2 §12.1).
    #[error("non-canonical pairing payload: {0}")]
    Cbor(#[from] CborError),
    /// `ver` is not 2 (quick-v2 §10.2).
    #[error("unknown pairing version {0}")]
    Version(u64),
    /// The message `type` is neither ACCEPT nor COMPLETE (quick-v2 §10.2).
    #[error("unknown pairing message type {0}")]
    MessageType(u64),
    /// `name` exceeds [`MAX_NAME_BYTES`].
    #[error("name of {0} bytes exceeds {MAX_NAME_BYTES} bytes")]
    NameTooLong(usize),
    /// `authority` is not a canonical relay identifier (quick-v2 §8.6).
    #[error("invalid authority: {0}")]
    InvalidAuthority(#[from] RelayIdError),
    /// The embedded NodeRecord is not valid (quick-v2 §3.2).
    #[error("invalid node record: {0}")]
    Record(#[from] NodeRecordError),
    /// The embedded NodeRecord has expired (quick-v2 §3.2).
    #[error("{0}")]
    RecordExpired(#[from] RecordExpired),
    /// The embedded NodeRecord's service period is too long (quick-v2 §3.1).
    #[error("{0}")]
    ServicePeriod(#[from] ServicePeriodTooLong),
    /// The signing key is not the identity `I` of the record (quick-v2 §10.2).
    #[error("signing key is not the record identity")]
    SignerMismatch,
    /// The payload signature does not strictly verify under the record's `I`
    /// (quick-v2 §10.2, §12.2).
    #[error("pairing signature does not verify")]
    Signature,
    /// The Invite `authority` is not the dialed relay (quick-v2 §10.2 step 2).
    #[error("invite authority is not the dialed relay")]
    Authority,
    /// The Invite has expired: `now >= expires` (quick-v2 §10.2 step 2).
    #[error("invite expired at {expires}, now {now}")]
    Expired {
        /// The Invite `expires`.
        expires: u64,
        /// The caller-supplied time.
        now: u64,
    },
    /// The Join `mailbox_id` is not this mailbox (quick-v2 §10.2 step 4).
    #[error("join mailbox id is not this mailbox")]
    MailboxId,
    /// The Join `invite_hash` is not the hash of this Invite (quick-v2 §10.2 step 4).
    #[error("join invite hash does not match")]
    InviteHash,
    /// The ACCEPT `join_hash` is not the hash of this Join (quick-v2 §10.2).
    #[error("accept join hash does not match")]
    JoinHash,
    /// The message is not an ACCEPT (quick-v2 §10.2).
    #[error("message is not an ACCEPT")]
    NotAccept,
    /// A mailbox `open` field is out of range (rendezvous §5.1-§5.2).
    #[error("{0}")]
    Open(#[from] MessageError),
    /// The X25519 result is all zero (quick-v2 §10.2).
    #[error("pairing DH result is all zero")]
    AllZeroSharedSecret,
}

/// A decoded Invite with its exact canonical encoding (quick-v2 §10.2):
/// `[ver = 2, record_a, e_a, authority, expires, name, sig_a]`.
///
/// Decoding checks the shape and the embedded record; [`Invite::verify`] checks the rest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invite {
    record: NodeRecord,
    ephemeral: [u8; 32],
    authority: RelayId,
    expires: u64,
    name: Option<String>,
    signature: [u8; 64],
    encoded: Vec<u8>,
}

impl Invite {
    /// Builds and signs an Invite:
    /// `sig_a = Ed25519_Ia("ns/pairing-invite/v2" ‖ CBOR(first six fields))` (quick-v2 §10.2).
    ///
    /// `authority` is the dialed relay and `expires = now + ttl` (quick-v2 §10.2 step 1).
    ///
    /// # Errors
    ///
    /// [`PairingError::SignerMismatch`] when `identity_key` is not `record.I`, or
    /// [`PairingError::NameTooLong`].
    pub fn create(
        identity_key: &SigningKey,
        record: NodeRecord,
        e_a_public: &[u8; 32],
        authority: &RelayId,
        expires: u64,
        name: Option<&str>,
    ) -> Result<Self, PairingError> {
        check_signer(identity_key, &record)?;
        let name = check_name(name)?;
        let mut invite = Self {
            record,
            ephemeral: *e_a_public,
            authority: authority.clone(),
            expires,
            name,
            signature: [0; 64],
            encoded: Vec::new(),
        };
        invite.signature = sign(identity_key, INVITE_CONTEXT, &invite.encode(false));
        invite.encoded = invite.encode(true);
        Ok(invite)
    }

    /// Decodes an Invite (quick-v2 §10.2, §12.1).
    ///
    /// Size (4 KiB intro limit), canonical CBOR, version, arity and trailing bytes are
    /// checked before the embedded record and its signature.
    ///
    /// # Errors
    ///
    /// [`PairingError`] naming the first violated rule.
    pub fn decode(encoded: &[u8]) -> Result<Self, PairingError> {
        let mut reader = open_reader(encoded, MAX_INTRO_BYTES)?;
        reader.array(7)?;
        check_version(&mut reader)?;
        let record = read_record(&mut reader)?;
        let ephemeral = reader.fixed_bytes()?;
        let authority = reader.text_up_to(MAX_RELAY_ID_BYTES)?;
        let expires = reader.uint()?;
        let name = read_name(&mut reader)?;
        let signature = reader.fixed_bytes()?;
        reader.finish()?;
        Ok(Self {
            authority: RelayId::parse(authority)?,
            record: NodeRecord::decode(record)?,
            ephemeral,
            expires,
            name,
            signature,
            encoded: encoded.to_vec(),
        })
    }

    /// The joiner's checks of quick-v2 §10.2 step 2: the record is valid, `sig_a` strictly
    /// verifies under `record_a.I`, `authority` is the `dialed` relay and `now < expires`.
    ///
    /// The `Removed` list and the address-group conflict check are caller policy (see
    /// [`ns_wire::check_address_conflict`]).
    ///
    /// # Errors
    ///
    /// [`PairingError`] naming the first failed check.
    pub fn verify(&self, dialed: &RelayId, now: u64) -> Result<&NodeRecord, PairingError> {
        check_record(&self.record, now)?;
        verify_signature(
            &self.record,
            INVITE_CONTEXT,
            &self.encode(false),
            &self.signature,
        )?;
        if self.authority != *dialed {
            return Err(PairingError::Authority);
        }
        if now >= self.expires {
            return Err(PairingError::Expired {
                expires: self.expires,
                now,
            });
        }
        Ok(&self.record)
    }

    /// Returns `invite_hash = SHA-256(CBOR(Invite))` (quick-v2 §10.2).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        crypto::sha256(&[&self.encoded])
    }

    /// Returns the exact canonical encoding, the mailbox `intro` (quick-v2 §10.2).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns the inviter's record `record_a` (quick-v2 §10.2).
    #[must_use]
    pub const fn record(&self) -> &NodeRecord {
        &self.record
    }

    /// Returns the inviter's ephemeral X25519 public key `e_a` (quick-v2 §10.2).
    #[must_use]
    pub const fn ephemeral(&self) -> &[u8; 32] {
        &self.ephemeral
    }

    /// Returns the relay the mailbox was opened on (quick-v2 §10.2).
    #[must_use]
    pub const fn authority(&self) -> &RelayId {
        &self.authority
    }

    /// Returns the exclusive `expires` in Unix seconds (quick-v2 §10.2).
    #[must_use]
    pub const fn expires(&self) -> u64 {
        self.expires
    }

    /// Returns the inviter's display name (quick-v2 §10.2).
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns `sig_a` (quick-v2 §10.2).
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// The seven-element Invite, or its first six fields when not `signed`.
    fn encode(&self, signed: bool) -> Vec<u8> {
        let mut tail = CborWriter::with_capacity(MAX_INTRO_BYTES);
        tail.bytes(&self.ephemeral)
            .text(self.authority.as_str())
            .uint(self.expires);
        write_name(&mut tail, self.name.as_deref());
        if signed {
            tail.bytes(&self.signature);
        }
        assemble(if signed { 7 } else { 6 }, &self.record, tail)
    }
}

/// A decoded Join with its exact canonical encoding (quick-v2 §10.2):
/// `[ver = 2, record_b, e_b, mailbox_id, invite_hash, name, sig_b]`.
///
/// Decoding checks the shape and the embedded record; [`Join::verify`] checks the rest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Join {
    record: NodeRecord,
    ephemeral: [u8; 32],
    mailbox_id: MailboxId,
    invite_hash: [u8; 32],
    name: Option<String>,
    signature: [u8; 64],
    encoded: Vec<u8>,
}

impl Join {
    /// Builds and signs a Join:
    /// `sig_b = Ed25519_Ib("ns/pairing-join/v2" ‖ CBOR(first six fields))` (quick-v2 §10.2).
    ///
    /// # Errors
    ///
    /// [`PairingError::SignerMismatch`] when `identity_key` is not `record.I`, or
    /// [`PairingError::NameTooLong`].
    pub fn create(
        identity_key: &SigningKey,
        record: NodeRecord,
        e_b_public: &[u8; 32],
        mailbox_id: &MailboxId,
        invite_hash: &[u8; 32],
        name: Option<&str>,
    ) -> Result<Self, PairingError> {
        check_signer(identity_key, &record)?;
        let name = check_name(name)?;
        let mut join = Self {
            record,
            ephemeral: *e_b_public,
            mailbox_id: *mailbox_id,
            invite_hash: *invite_hash,
            name,
            signature: [0; 64],
            encoded: Vec::new(),
        };
        join.signature = sign(identity_key, JOIN_CONTEXT, &join.encode(false));
        join.encoded = join.encode(true);
        Ok(join)
    }

    /// Decodes a Join (quick-v2 §10.2, §12.1).
    ///
    /// Size (4 KiB intro limit), canonical CBOR, version, arity and trailing bytes are
    /// checked before the embedded record and its signature.
    ///
    /// # Errors
    ///
    /// [`PairingError`] naming the first violated rule.
    pub fn decode(encoded: &[u8]) -> Result<Self, PairingError> {
        let mut reader = open_reader(encoded, MAX_INTRO_BYTES)?;
        reader.array(7)?;
        check_version(&mut reader)?;
        let record = read_record(&mut reader)?;
        let ephemeral = reader.fixed_bytes()?;
        let mailbox_id = MailboxId(reader.fixed_bytes()?);
        let invite_hash = reader.fixed_bytes()?;
        let name = read_name(&mut reader)?;
        let signature = reader.fixed_bytes()?;
        reader.finish()?;
        Ok(Self {
            record: NodeRecord::decode(record)?,
            ephemeral,
            mailbox_id,
            invite_hash,
            name,
            signature,
            encoded: encoded.to_vec(),
        })
    }

    /// The inviter's checks of quick-v2 §10.2 step 4: the record is valid, `sig_b`
    /// strictly verifies under `record_b.I`, `mailbox_id` is this mailbox and
    /// `invite_hash` is the hash of this mailbox's Invite.
    ///
    /// The `Removed` list and the address-group conflict check are caller policy (see
    /// [`ns_wire::check_address_conflict`]).
    ///
    /// # Errors
    ///
    /// [`PairingError`] naming the first failed check.
    pub fn verify(
        &self,
        mailbox_id: &MailboxId,
        invite_hash: &[u8; 32],
        now: u64,
    ) -> Result<&NodeRecord, PairingError> {
        check_record(&self.record, now)?;
        verify_signature(
            &self.record,
            JOIN_CONTEXT,
            &self.encode(false),
            &self.signature,
        )?;
        if self.mailbox_id != *mailbox_id {
            return Err(PairingError::MailboxId);
        }
        if self.invite_hash != *invite_hash {
            return Err(PairingError::InviteHash);
        }
        Ok(&self.record)
    }

    /// Returns `join_hash = SHA-256(CBOR(Join))` (quick-v2 §10.2).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        crypto::sha256(&[&self.encoded])
    }

    /// Returns the exact canonical encoding, the `join` `intro` (quick-v2 §10.2).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Returns the joiner's record `record_b` (quick-v2 §10.2).
    #[must_use]
    pub const fn record(&self) -> &NodeRecord {
        &self.record
    }

    /// Returns the joiner's ephemeral X25519 public key `e_b` (quick-v2 §10.2).
    #[must_use]
    pub const fn ephemeral(&self) -> &[u8; 32] {
        &self.ephemeral
    }

    /// Returns the mailbox the Join is bound to (quick-v2 §10.2).
    #[must_use]
    pub const fn mailbox_id(&self) -> &MailboxId {
        &self.mailbox_id
    }

    /// Returns the hash of the Invite the Join answers (quick-v2 §10.2).
    #[must_use]
    pub const fn invite_hash(&self) -> &[u8; 32] {
        &self.invite_hash
    }

    /// Returns the joiner's display name (quick-v2 §10.2).
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns `sig_b` (quick-v2 §10.2).
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// The seven-element Join, or its first six fields when not `signed`.
    fn encode(&self, signed: bool) -> Vec<u8> {
        let mut tail = CborWriter::with_capacity(MAX_INTRO_BYTES);
        tail.bytes(&self.ephemeral)
            .bytes(&self.mailbox_id.0)
            .bytes(&self.invite_hash);
        write_name(&mut tail, self.name.as_deref());
        if signed {
            tail.bytes(&self.signature);
        }
        assemble(if signed { 7 } else { 6 }, &self.record, tail)
    }
}

/// A pairing mailbox message `[ver = 2, type, body]` (quick-v2 §10.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairingMessage {
    /// Type 1, body `[join_hash, sig]`:
    /// `sig = Ed25519_Ia("ns/pairing-accept/v2" ‖ invite_hash ‖ join_hash)`.
    Accept {
        /// Hash of the admitted Join.
        join_hash: [u8; 32],
        /// The inviter's signature.
        signature: [u8; 64],
    },
    /// Type 2, body `[]`: the joiner is ready.
    Complete,
}

impl PairingMessage {
    /// Builds the ACCEPT the inviter sends for the admitted `join` (quick-v2 §10.2 step 4).
    ///
    /// # Errors
    ///
    /// [`PairingError::SignerMismatch`] when `identity_key` is not `invite.record_a.I`.
    pub fn accept(
        identity_key: &SigningKey,
        invite: &Invite,
        join: &Join,
    ) -> Result<Self, PairingError> {
        check_signer(identity_key, &invite.record)?;
        let join_hash = join.hash();
        let signature = identity_key
            .sign(&accept_message(&invite.hash(), &join_hash))
            .to_bytes();
        Ok(Self::Accept {
            join_hash,
            signature,
        })
    }

    /// Encodes the message (quick-v2 §10.2, §12.1).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = CborWriter::with_capacity(128);
        writer.array(3).uint(u64::from(PAIRING_VERSION));
        match self {
            Self::Accept {
                join_hash,
                signature,
            } => {
                writer
                    .uint(u64::from(MESSAGE_ACCEPT))
                    .array(2)
                    .bytes(join_hash)
                    .bytes(signature);
            }
            Self::Complete => {
                writer.uint(u64::from(MESSAGE_COMPLETE)).array(0);
            }
        }
        writer.into_bytes()
    }

    /// Decodes a message (8 KiB data limit, quick-v2 §10.2, §12.1); version and type are
    /// checked before the body.
    ///
    /// # Errors
    ///
    /// [`PairingError`] naming the first violated rule.
    pub fn decode(encoded: &[u8]) -> Result<Self, PairingError> {
        let mut reader = open_reader(encoded, MAX_DATA_BYTES)?;
        reader.array(3)?;
        check_version(&mut reader)?;
        let message = match reader.uint()? {
            kind if kind == u64::from(MESSAGE_ACCEPT) => {
                reader.array(2)?;
                Self::Accept {
                    join_hash: reader.fixed_bytes()?,
                    signature: reader.fixed_bytes()?,
                }
            }
            kind if kind == u64::from(MESSAGE_COMPLETE) => {
                reader.array(0)?;
                Self::Complete
            }
            other => return Err(PairingError::MessageType(other)),
        };
        reader.finish()?;
        Ok(message)
    }
}

/// The joiner's check of the ACCEPT (quick-v2 §10.2 step 5): `message` is an ACCEPT whose
/// `join_hash` is the hash of `join` and whose signature strictly verifies under
/// `invite.record_a.I` over `"ns/pairing-accept/v2" ‖ invite_hash ‖ join_hash`.
///
/// # Errors
///
/// [`PairingError::NotAccept`], [`PairingError::JoinHash`] or [`PairingError::Signature`].
pub fn verify_accept(
    invite: &Invite,
    join: &Join,
    message: &PairingMessage,
) -> Result<(), PairingError> {
    let PairingMessage::Accept {
        join_hash,
        signature,
    } = message
    else {
        return Err(PairingError::NotAccept);
    };
    if *join_hash != join.hash() {
        return Err(PairingError::JoinHash);
    }
    verify_signature(
        &invite.record,
        &[],
        &accept_message(&invite.hash(), join_hash),
        signature,
    )
}

/// Derives the pairing PSK (quick-v2 §10.2):
/// `HKDF-SHA256(salt = "", ikm = X25519(own, peer), info = "ns/pairing-psk/v2" ‖ I_a ‖ I_b
/// ‖ invite_hash ‖ join_hash)`, 32 bytes.
///
/// The inviter passes `e_a`'s secret and `e_b`, the joiner `e_b`'s secret and `e_a`; both
/// pass the identities in inviter-then-joiner order.
///
/// # Errors
///
/// [`PairingError::AllZeroSharedSecret`] for a small-order `peer_public`.
pub fn pairing_psk(
    own_secret: &[u8; 32],
    peer_public: &[u8; 32],
    i_a: &Identity,
    i_b: &Identity,
    invite_hash: &[u8; 32],
    join_hash: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, PairingError> {
    let shared = Zeroizing::new(
        crypto::x25519(own_secret, peer_public).map_err(|_| PairingError::AllZeroSharedSecret)?,
    );
    let mut psk = Zeroizing::new([0; 32]);
    // 32 bytes is far below the HKDF-SHA256 output limit, so expansion cannot fail.
    let _ = crypto::hkdf_sha256(
        shared.as_slice(),
        &[PSK_CONTEXT, i_a, i_b, invite_hash, join_hash],
        psk.as_mut_slice(),
    );
    Ok(psk)
}

/// The inviter's `open` (quick-v2 §10.2 step 1, rendezvous §9.1): `kind = "pairing"`,
/// `admission = owner`, `candidates = 4`, `intro = Invite`.
///
/// # Errors
///
/// [`PairingError::Open`] with [`MessageError::Ttl`] when `ttl` is outside
/// 1..=[`MAX_PAIRING_TTL_SECONDS`].
pub fn pairing_open_request(ttl: u64, invite: &Invite) -> Result<OpenRequest, PairingError> {
    check_ttl(ttl, MAX_PAIRING_TTL_SECONDS)?;
    Ok(OpenRequest {
        kind: Kind::parse(KIND_PAIRING)?,
        ttl,
        admission: Admission::Owner,
        candidates: PAIRING_CANDIDATES,
        intro: invite.as_bytes().to_vec(),
    })
}

/// The sender's `open` (rendezvous §9.2): `kind = "transfer"`, `admission = first`,
/// `candidates = 1`, `intro` the caller's CPace message.
///
/// # Errors
///
/// [`PairingError::Open`] with [`MessageError::Ttl`] when `ttl` is outside the mailbox
/// range, or [`PairingError::TooLarge`] when `intro` exceeds 4 KiB.
pub fn transfer_open_request(ttl: u64, intro: Vec<u8>) -> Result<OpenRequest, PairingError> {
    check_ttl(ttl, MAX_TTL_SECONDS)?;
    if intro.len() > MAX_INTRO_BYTES {
        return Err(PairingError::TooLarge {
            length: intro.len(),
            maximum: MAX_INTRO_BYTES,
        });
    }
    Ok(OpenRequest {
        kind: Kind::parse(KIND_TRANSFER)?,
        ttl,
        admission: Admission::First,
        candidates: 1,
        intro,
    })
}

fn check_ttl(ttl: u64, maximum: u64) -> Result<(), MessageError> {
    if (MIN_TTL_SECONDS..=maximum).contains(&ttl) {
        Ok(())
    } else {
        Err(MessageError::Ttl)
    }
}

fn check_signer(identity_key: &SigningKey, record: &NodeRecord) -> Result<(), PairingError> {
    if identity_key.verifying_key().to_bytes() == *record.identity() {
        Ok(())
    } else {
        Err(PairingError::SignerMismatch)
    }
}

fn check_name(name: Option<&str>) -> Result<Option<String>, PairingError> {
    match name {
        Some(name) if name.len() > MAX_NAME_BYTES => Err(PairingError::NameTooLong(name.len())),
        name => Ok(name.map(str::to_owned)),
    }
}

/// Record validity at `now`: unexpired with a service period of at most seven days
/// (quick-v2 §3.1-§3.2); the signature was verified by [`NodeRecord::decode`].
fn check_record(record: &NodeRecord, now: u64) -> Result<(), PairingError> {
    record.check_not_expired(now)?;
    record.check_service_period()?;
    Ok(())
}

fn sign(identity_key: &SigningKey, context: &[u8], unsigned: &[u8]) -> [u8; 64] {
    let mut message = context.to_vec();
    message.extend_from_slice(unsigned);
    identity_key.sign(&message).to_bytes()
}

fn verify_signature(
    record: &NodeRecord,
    context: &[u8],
    unsigned: &[u8],
    signature: &[u8; 64],
) -> Result<(), PairingError> {
    let mut message = context.to_vec();
    message.extend_from_slice(unsigned);
    if crypto::verify_strict(record.identity(), &message, signature) {
        Ok(())
    } else {
        Err(PairingError::Signature)
    }
}

/// `"ns/pairing-accept/v2" ‖ invite_hash ‖ join_hash` (quick-v2 §10.2).
fn accept_message(invite_hash: &[u8; 32], join_hash: &[u8; 32]) -> Vec<u8> {
    [ACCEPT_CONTEXT, invite_hash, join_hash].concat()
}

/// `[length-element array head, ver, record]` followed by the `tail` fields.
fn assemble(length: usize, record: &NodeRecord, tail: CborWriter) -> Vec<u8> {
    let mut head = CborWriter::with_capacity(2);
    head.array(length).uint(u64::from(PAIRING_VERSION));
    let mut encoded = head.into_bytes();
    encoded.extend_from_slice(record.as_bytes());
    encoded.extend_from_slice(&tail.into_bytes());
    encoded
}

fn open_reader(encoded: &[u8], maximum: usize) -> Result<CborReader<'_>, PairingError> {
    if encoded.len() > maximum {
        return Err(PairingError::TooLarge {
            length: encoded.len(),
            maximum,
        });
    }
    Ok(CborReader::new(encoded, maximum)?)
}

fn check_version(reader: &mut CborReader<'_>) -> Result<(), PairingError> {
    let version = reader.uint()?;
    if version == u64::from(PAIRING_VERSION) {
        Ok(())
    } else {
        Err(PairingError::Version(version))
    }
}

/// Reads the nested eight-field NodeRecord array structurally and returns its exact
/// bytes; [`NodeRecord::decode`] validates them after the outer item (quick-v2 §3.1).
fn read_record<'a>(reader: &mut CborReader<'a>) -> Result<&'a [u8], PairingError> {
    let start = reader.consumed().len();
    reader.array(8)?;
    reader.uint()?;
    reader.fixed_bytes::<32>()?;
    reader.fixed_bytes::<32>()?;
    reader.uint()?;
    reader.uint()?;
    reader.uint()?;
    let relays = reader.array_up_to(MAX_NODE_RECORD_RELAYS)?;
    for _ in 0..relays {
        reader.text_up_to(MAX_RELAY_ID_BYTES)?;
    }
    reader.fixed_bytes::<64>()?;
    Ok(reader.consumed().get(start..).unwrap_or_default())
}

fn read_name(reader: &mut CborReader<'_>) -> Result<Option<String>, PairingError> {
    if reader.take_null() {
        return Ok(None);
    }
    Ok(Some(reader.text_up_to(MAX_NAME_BYTES)?.to_owned()))
}

fn write_name(writer: &mut CborWriter, name: Option<&str>) {
    match name {
        Some(name) => writer.text(name),
        None => writer.null(),
    };
}
