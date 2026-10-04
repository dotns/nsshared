//! Relay session key and control / reply MACs (quick-v2 §8.3, quick-protocol §12.5).

use super::packet::{RelayPacket, RelayType};
use crate::{
    codec::CborWriter,
    constants::{
        MAX_RELAY_CONTROL_BYTES, RELAY_CTL_CONTEXT, RELAY_MAGIC, RELAY_REPLY_CONTEXT,
        RELAY_SESSION_CONTEXT,
    },
    identity::NodeId,
};
use hmac::{
    Hmac, KeyInit, Mac,
    digest::{Output, array::Array},
};
use sha2::Sha256;
use std::fmt;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

/// The SHA-256 block size; HMAC keys shorter than a block are zero-padded to it
/// (RFC 2104 §2), so padding here gives the same MAC without a fallible key setup.
const SHA256_BLOCK_BYTES: usize = 64;

/// The relay session key `sk` (quick-v2 §8.3).
#[derive(Clone, Eq, PartialEq)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Wraps raw key bytes, e.g. a persisted `sk` (quick-v2 §8.3 rule 3).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw key bytes (quick-v2 §8.3).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(..)")
    }
}

/// X25519 produced the all-zero shared secret `ss` (quick-v2 §8.3 rule 1).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("X25519 shared secret is all zero")]
pub struct ZeroSharedSecret;

/// Returns the X25519 public key of an ephemeral secret, e.g. `node_ephemeral` or
/// `relay_ephemeral` (quick-v2 §8.3).
#[must_use]
pub fn ephemeral_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Derives `sk = HKDF-SHA256(salt = "", ikm = X25519(own_secret, peer_public),
/// info = "ns/relay-session/v2" ‖ src_slot ‖ incarnation_be64 ‖ node_ephemeral ‖
/// relay_ephemeral ‖ reg_hash)`, 32 bytes (quick-v2 §8.3, quick-protocol §12.5).
///
/// The node passes its ephemeral secret and `relay_ephemeral`; the relay passes its
/// ephemeral secret and `node_ephemeral`. Both derive the same key.
///
/// # Errors
///
/// [`ZeroSharedSecret`] when the X25519 output is all zero.
pub fn derive_session_key(
    own_secret: &[u8; 32],
    peer_public: &[u8; 32],
    src_slot: &NodeId,
    incarnation: u64,
    node_ephemeral: &[u8; 32],
    relay_ephemeral: &[u8; 32],
    reg_hash: &[u8; 32],
) -> Result<SessionKey, ZeroSharedSecret> {
    let shared = StaticSecret::from(*own_secret).diffie_hellman(&PublicKey::from(*peer_public));
    if !shared.was_contributory() {
        return Err(ZeroSharedSecret);
    }
    // HKDF-Extract with a zero-length salt, i.e. a HashLen zero key (RFC 5869 §2.2).
    let prk = hmac_sha256(&[0; 32], &[shared.as_bytes()]);
    // HKDF-Expand to one 32-byte block: T(1) = HMAC(PRK, info ‖ 0x01) (RFC 5869 §2.3).
    let okm = hmac_sha256(
        &prk,
        &[
            RELAY_SESSION_CONTEXT,
            src_slot.as_bytes(),
            &incarnation.to_be_bytes(),
            node_ephemeral,
            relay_ephemeral,
            reg_hash,
            &[1],
        ],
    );
    Ok(SessionKey(okm))
}

/// A relay MAC that cannot be produced or does not verify (quick-v2 §8.3).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RelayMacError {
    /// The packet type carries no MAC (REGISTER, DATA, STATUS).
    #[error("{0:?} packets carry no MAC")]
    NoMac(RelayType),
    /// The MAC does not match (constant-time comparison).
    #[error("relay MAC does not verify")]
    BadMac,
}

impl RelayPacket {
    /// Returns the MAC input `context ‖ CBOR([magic, type, src, dst, U])`, where the
    /// context is `ns/relay-ctl/v2` for types 3, 4, 8 and `ns/relay-reply/v2` for types
    /// 2, 5, and `U` is the nested body array without its `mac` (quick-v2 §8.3,
    /// quick-protocol §12.5).
    ///
    /// # Errors
    ///
    /// [`RelayMacError::NoMac`] for REGISTER, DATA and STATUS.
    pub fn mac_input(&self) -> Result<Vec<u8>, RelayMacError> {
        let packet_type = self.body.packet_type();
        let context = match packet_type {
            RelayType::Presence | RelayType::Reflect | RelayType::Revoke => RELAY_CTL_CONTEXT,
            RelayType::Registered | RelayType::Reflected => RELAY_REPLY_CONTEXT,
            RelayType::Register | RelayType::Data | RelayType::Status => {
                return Err(RelayMacError::NoMac(packet_type));
            }
        };
        let mut writer = CborWriter::with_capacity(MAX_RELAY_CONTROL_BYTES);
        writer
            .array(5)
            .bytes(&RELAY_MAGIC)
            .uint(u64::from(packet_type.as_u8()))
            .bytes(self.src.as_bytes())
            .bytes(self.dst.as_bytes());
        self.body.write_mac_body(&mut writer, false);
        let mut input = context.to_vec();
        input.extend_from_slice(&writer.into_bytes());
        Ok(input)
    }

    /// Computes the control / reply MAC under `sk` and stores it in the body
    /// (quick-v2 §8.3).
    ///
    /// # Errors
    ///
    /// [`RelayMacError::NoMac`] for REGISTER, DATA and STATUS.
    pub fn seal(&mut self, key: &SessionKey) -> Result<(), RelayMacError> {
        let tag = hmac_sha256(&key.0, &[&self.mac_input()?]);
        if let Some(mac) = self.body.mac_mut() {
            *mac = tag;
        }
        Ok(())
    }

    /// Verifies the control / reply MAC under `sk` in constant time (quick-v2 §8.3).
    ///
    /// # Errors
    ///
    /// [`RelayMacError::NoMac`] for REGISTER, DATA and STATUS, or
    /// [`RelayMacError::BadMac`].
    pub fn verify_mac(&self, key: &SessionKey) -> Result<(), RelayMacError> {
        let input = self.mac_input()?;
        let tag = self
            .body
            .mac()
            .ok_or(RelayMacError::NoMac(self.body.packet_type()))?;
        hmac_state(&key.0, &[&input])
            .verify(&Output::<Hmac<Sha256>>::from(*tag))
            .map_err(|_| RelayMacError::BadMac)
    }
}

fn hmac_state(key: &[u8; 32], parts: &[&[u8]]) -> Hmac<Sha256> {
    let mut block = [0; SHA256_BLOCK_BYTES];
    for (slot, byte) in block.iter_mut().zip(key) {
        *slot = *byte;
    }
    let mut mac = Hmac::<Sha256>::new(&Array::from(block));
    for part in parts {
        mac.update(part);
    }
    mac
}

/// HMAC-SHA256 with a 32-byte key (RFC 2104).
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    hmac_state(key, parts).finalize().into_bytes().into()
}
