//! Node-side test helpers built only on `nsshared-proto`: a signed record, a signed
//! REGISTER, the node session key and sealed PRESENCE / REFLECT / REVOKE packets
//! (quick-v2 §3.1, §8.2-§8.3).
//!
//! These helpers build what a node sends and check what it receives; they are not a node
//! implementation (no timers, retransmissions or carrier selection). A typical flow:
//!
//! 1. [`TestNode::new`] signs a record; [`TestNode::register`] signs a REGISTER and
//!    returns an [`Attempt`] holding the packet and the node ephemeral secret.
//! 2. [`Attempt::accept`] verifies the tentative REGISTERED and derives the node side of
//!    `sk`, returning a [`NodeSession`].
//! 3. [`NodeSession::presence`], [`NodeSession::reflect`] and [`NodeSession::revoke`] seal
//!    control packets; [`NodeSession::open`] decodes and authenticates replies;
//!    [`data_packet`] wraps a WireGuard payload in DATA.
//!
//! [`TestRng`] is a deterministic random source for [`crate::Relay`] in tests.

use ed25519_dalek::SigningKey;
use nsshared_proto::{
    Identity, NodeId, NodeRecord, NodeRecordError, NodeRecordFields, Presence, RELAY_SLOT, Reflect,
    Register, Registered, RelayBody, RelayId, RelayMacError, RelayPacket, RelayPacketError, Revoke,
    RevokeReason, SessionKey, SignerMismatch, ZeroSharedSecret, ephemeral_public,
};
use rand_core::{Infallible, TryCryptoRng, TryRng};
use thiserror::Error;

/// The service period of a [`TestNode::new`] record: one day.
pub const TEST_RECORD_SECONDS: u64 = 86_400;

/// A failed test helper step.
#[derive(Debug, Error)]
pub enum TestingError {
    /// The record could not be signed.
    #[error(transparent)]
    Record(#[from] NodeRecordError),
    /// The REGISTER signer is not the record identity.
    #[error(transparent)]
    Signer(#[from] SignerMismatch),
    /// A packet could not be encoded or decoded.
    #[error(transparent)]
    Packet(#[from] RelayPacketError),
    /// A reply MAC does not verify.
    #[error(transparent)]
    Mac(#[from] RelayMacError),
    /// X25519 produced the all-zero shared secret.
    #[error(transparent)]
    ZeroSharedSecret(#[from] ZeroSharedSecret),
    /// The packet is not the expected reply: wrong type, destination, incarnation or a
    /// non-zero `ack_seq` where a tentative reply was expected.
    #[error("unexpected relay reply")]
    Unexpected,
}

/// A node identity with its current signed record (quick-v2 §2.1, §3.1).
#[derive(Debug)]
pub struct TestNode {
    signer: SigningKey,
    record: NodeRecord,
}

impl TestNode {
    /// Signs a generation-1 record issued at `issued_at`, valid for
    /// [`TEST_RECORD_SECONDS`], listing `relay` as home relay; `K` is the X25519 public
    /// key of `seed`.
    ///
    /// # Errors
    ///
    /// [`TestingError::Record`].
    pub fn new(seed: [u8; 32], relay: &RelayId, issued_at: u64) -> Result<Self, TestingError> {
        Self::with_fields(
            seed,
            NodeRecordFields {
                wg_key: ephemeral_public(&seed),
                generation: 1,
                issued_at,
                expires: issued_at.saturating_add(TEST_RECORD_SECONDS),
                relays: vec![relay.clone()],
            },
        )
    }

    /// Signs a record with explicit fields under the Ed25519 key of `seed`.
    ///
    /// # Errors
    ///
    /// [`TestingError::Record`].
    pub fn with_fields(seed: [u8; 32], fields: NodeRecordFields) -> Result<Self, TestingError> {
        let signer = SigningKey::from_bytes(&seed);
        let record = NodeRecord::sign(&signer, fields)?;
        Ok(Self { signer, record })
    }

    /// Re-signs the record with new fields, e.g. a higher generation or another `K`.
    ///
    /// # Errors
    ///
    /// [`TestingError::Record`]; the record is unchanged.
    pub fn resign(&mut self, fields: NodeRecordFields) -> Result<(), TestingError> {
        self.record = NodeRecord::sign(&self.signer, fields)?;
        Ok(())
    }

    /// Returns the current record.
    #[must_use]
    pub const fn record(&self) -> &NodeRecord {
        &self.record
    }

    /// Returns the identity `I`.
    #[must_use]
    pub const fn identity(&self) -> &Identity {
        self.record.identity()
    }

    /// Returns the node ID, the relay slot of this node (quick-v2 §2.2, §8.1).
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        self.record.node_id()
    }

    /// Signs a REGISTER of the current record for `relay_name` with the node ephemeral
    /// of `ephemeral_secret` (quick-v2 §8.3).
    ///
    /// # Errors
    ///
    /// [`TestingError::Signer`] or [`TestingError::Packet`].
    pub fn register(
        &self,
        relay_name: &RelayId,
        incarnation: u64,
        ts: u64,
        ephemeral_secret: [u8; 32],
    ) -> Result<Attempt, TestingError> {
        let register = Register::sign(
            &self.signer,
            &self.record,
            incarnation,
            ts,
            ephemeral_public(&ephemeral_secret),
            relay_name,
        )?;
        let packet = RelayPacket {
            src: register.node_id(),
            dst: RELAY_SLOT,
            body: RelayBody::Register(register.clone()),
        }
        .encode()?;
        Ok(Attempt {
            register,
            secret: ephemeral_secret,
            packet,
        })
    }
}

/// One registration attempt: the signed REGISTER, its packet and the node ephemeral
/// secret (quick-v2 §8.3).
#[derive(Debug)]
pub struct Attempt {
    register: Register,
    secret: [u8; 32],
    packet: Vec<u8>,
}

impl Attempt {
    /// Returns the REGISTER packet; retransmissions send these exact bytes.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Returns the signed REGISTER.
    #[must_use]
    pub const fn register(&self) -> &Register {
        &self.register
    }

    /// Verifies a tentative REGISTERED for this attempt (destination, incarnation,
    /// `ack_seq = 0`, reply MAC under the derived `sk`) and returns it with the node side
    /// of the session (quick-v2 §8.3 rule 3).
    ///
    /// # Errors
    ///
    /// [`TestingError`] when the packet is not a valid tentative reply.
    pub fn accept(&self, packet: &[u8]) -> Result<(Registered, NodeSession), TestingError> {
        let decoded = RelayPacket::decode(packet)?;
        let node_id = self.register.node_id();
        let RelayBody::Registered(registered) = &decoded.body else {
            return Err(TestingError::Unexpected);
        };
        if decoded.dst != node_id
            || registered.ack_seq != 0
            || registered.incarnation != self.register.incarnation()
        {
            return Err(TestingError::Unexpected);
        }
        let key = self
            .register
            .node_session_key(&self.secret, &registered.relay_ephemeral)?;
        decoded.verify_mac(&key)?;
        let session = NodeSession {
            node_id,
            incarnation: registered.incarnation,
            key,
        };
        Ok((registered.clone(), session))
    }
}

/// The node side of a relay session: slot, incarnation and `sk` (quick-v2 §8.3).
#[derive(Clone, Debug)]
pub struct NodeSession {
    node_id: NodeId,
    incarnation: u64,
    key: SessionKey,
}

impl NodeSession {
    /// Wraps explicit session parts, e.g. to seal packets under a wrong key in tests.
    #[must_use]
    pub const fn new(node_id: NodeId, incarnation: u64, key: SessionKey) -> Self {
        Self {
            node_id,
            incarnation,
            key,
        }
    }

    /// Returns the node ID.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// Returns `sk`.
    #[must_use]
    pub const fn key(&self) -> &SessionKey {
        &self.key
    }

    /// Seals a PRESENCE with `seq` (quick-v2 §8.2-§8.3).
    ///
    /// # Errors
    ///
    /// [`TestingError::Packet`], e.g. for `seq = 0`.
    pub fn presence(&self, seq: u64) -> Result<Vec<u8>, TestingError> {
        self.seal(RelayBody::Presence(Presence {
            incarnation: self.incarnation,
            seq,
            mac: [0; 32],
        }))
    }

    /// Seals a REFLECT with `seq` and `nonce` (quick-v2 §8.2-§8.3).
    ///
    /// # Errors
    ///
    /// [`TestingError::Packet`], e.g. for `seq = 0`.
    pub fn reflect(&self, seq: u64, nonce: [u8; 16]) -> Result<Vec<u8>, TestingError> {
        self.seal(RelayBody::Reflect(Reflect {
            incarnation: self.incarnation,
            seq,
            nonce,
            mac: [0; 32],
        }))
    }

    /// Seals a REVOKE with `seq` and `reason` (quick-v2 §8.2-§8.3).
    ///
    /// # Errors
    ///
    /// [`TestingError::Packet`], e.g. for `seq = 0`.
    pub fn revoke(&self, seq: u64, reason: RevokeReason) -> Result<Vec<u8>, TestingError> {
        self.seal(RelayBody::Revoke(Revoke {
            incarnation: self.incarnation,
            seq,
            reason,
            mac: [0; 32],
        }))
    }

    /// Decodes a relay packet addressed to this node; REGISTERED and REFLECTED must carry
    /// a valid reply MAC under `sk`, STATUS and DATA carry none (quick-v2 §8.2-§8.3).
    ///
    /// # Errors
    ///
    /// [`TestingError`] for a malformed packet, another destination or a bad MAC.
    pub fn open(&self, packet: &[u8]) -> Result<RelayBody, TestingError> {
        let decoded = RelayPacket::decode(packet)?;
        if decoded.dst != self.node_id {
            return Err(TestingError::Unexpected);
        }
        match decoded.body {
            RelayBody::Registered(_) | RelayBody::Reflected(_) => decoded.verify_mac(&self.key)?,
            RelayBody::Status(_) | RelayBody::Data(_) => {}
            RelayBody::Register(_)
            | RelayBody::Presence(_)
            | RelayBody::Reflect(_)
            | RelayBody::Revoke(_) => return Err(TestingError::Unexpected),
        }
        Ok(decoded.body)
    }

    fn seal(&self, body: RelayBody) -> Result<Vec<u8>, TestingError> {
        let mut packet = RelayPacket {
            src: self.node_id,
            dst: RELAY_SLOT,
            body,
        };
        packet.seal(&self.key)?;
        Ok(packet.encode()?)
    }
}

/// Wraps a WireGuard payload of 1..=2019 bytes in a DATA packet (quick-v2 §8.2, §8.4).
///
/// # Errors
///
/// [`TestingError::Packet`] for a zero slot or a payload outside 1..=2019 bytes.
pub fn data_packet(src: NodeId, dst: NodeId, payload: &[u8]) -> Result<Vec<u8>, TestingError> {
    Ok(RelayPacket {
        src,
        dst,
        body: RelayBody::Data(payload.to_vec()),
    }
    .encode()?)
}

/// A deterministic SplitMix64 generator for tests.
///
/// **Not cryptographically secure**: it is marked [`TryCryptoRng`] only so tests can drive
/// [`crate::Relay`] reproducibly. Never use it outside tests.
#[derive(Debug)]
pub struct TestRng(u64);

impl TestRng {
    /// Creates a generator from `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }
}

impl TryRng for TestRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok((self.try_next_u64()? >> 32) as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let word = self.try_next_u64()?.to_le_bytes();
            for (byte, value) in chunk.iter_mut().zip(word) {
                *byte = value;
            }
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}
