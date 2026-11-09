//! Account record envelope bound to one Network.

use super::{NodeRecord, NodeRecordError, RecordExpired};
use crate::{identity::NodeId, keys::IdentitySecret, realm::RealmId};
use blake2::{
    Blake2sMac,
    digest::{KeyInit, Mac, consts::U32},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nsshared_codec::cbor::{CborError, CborReader, CborWriter};
use thiserror::Error;
use zeroize::Zeroizing;

const VERSION: u64 = 1;
const CONTEXT: &[u8] = b"ns/account-network-node-record/v1";
const MAX_BYTES: usize = 768;
const IDENTITY_CONTEXT: &[u8] = b"ns/account-network-identity/v1";

/// Derives a distinct signing identity and relay slot for one Account Network.
///
/// The root seed keys BLAKE2s-256 over a fixed domain and the exact Network ID.
/// NSD must authorize the derived public identity for this Network before use.
#[must_use]
pub fn derive_network_identity(root: &IdentitySecret, network: RealmId) -> IdentitySecret {
    let mut mac = Blake2sMac::<U32>::new(root.expose_seed().into());
    mac.update(IDENTITY_CONTEXT);
    mac.update(network.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut seed = Zeroizing::new([0; 32]);
    seed.copy_from_slice(&digest);
    IdentitySecret::from_seed(*seed)
}

/// Account registry key: Network scope plus the Node ID within that Network.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NetworkRecordKey {
    /// The authenticated Network scope.
    pub network: RealmId,
    /// The record signer's Node ID.
    pub node: NodeId,
}

/// One canonical Account NodeRecord signed for exactly one Network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkNodeRecord {
    network: RealmId,
    record: NodeRecord,
    signature: [u8; 64],
    encoded: Vec<u8>,
}

/// A rejected Network-bound Account record.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum NetworkNodeRecordError {
    /// The encoded envelope exceeds its fixed wire bound.
    #[error("network node record of {0} bytes exceeds {MAX_BYTES} bytes")]
    TooLarge(usize),
    /// The envelope is not canonical CBOR.
    #[error("invalid network node record encoding: {0}")]
    Cbor(#[from] CborError),
    /// The envelope version is unknown.
    #[error("unknown network node record version {0}")]
    Version(u64),
    /// The enclosed NodeRecord is invalid.
    #[error("invalid enclosed node record: {0}")]
    Record(#[from] NodeRecordError),
    /// The signing key differs from the enclosed NodeRecord identity.
    #[error("network record signer differs from node record identity")]
    SignerMismatch,
    /// The record is presented for another Network.
    #[error("network record scope mismatch")]
    NetworkMismatch,
    /// The Network-bound signature is invalid.
    #[error("network record signature does not verify")]
    BadSignature,
    /// The enclosed NodeRecord has expired.
    #[error("enclosed node record expired: {0}")]
    Expired(#[from] RecordExpired),
}

impl NetworkNodeRecord {
    /// Signs an existing valid NodeRecord for `network` using the same Node identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the signer differs from the record identity or the
    /// canonical envelope exceeds its size bound.
    pub fn sign(
        signer: &SigningKey,
        network: RealmId,
        record: NodeRecord,
    ) -> Result<Self, NetworkNodeRecordError> {
        if signer.verifying_key().to_bytes() != *record.identity() {
            return Err(NetworkNodeRecordError::SignerMismatch);
        }
        record.verify()?;
        let signature = signer.sign(&message(network, &record)).to_bytes();
        let encoded = encode(network, &record, &signature);
        if encoded.len() > MAX_BYTES {
            return Err(NetworkNodeRecordError::TooLarge(encoded.len()));
        }
        Ok(Self {
            network,
            record,
            signature,
            encoded,
        })
    }

    /// Decodes and verifies the canonical Network-bound record.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, unsupported, or unsigned data.
    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkNodeRecordError> {
        if bytes.len() > MAX_BYTES {
            return Err(NetworkNodeRecordError::TooLarge(bytes.len()));
        }
        let mut reader = CborReader::new(bytes, MAX_BYTES)?;
        reader.array(4)?;
        let version = reader.uint()?;
        if version != VERSION {
            return Err(NetworkNodeRecordError::Version(version));
        }
        let network = RealmId::from_bytes(reader.fixed_bytes::<16>()?);
        let record = NodeRecord::decode(reader.bytes_up_to(MAX_BYTES)?)?;
        let signature = reader.fixed_bytes::<64>()?;
        reader.finish()?;
        let result = Self {
            network,
            record,
            signature,
            encoded: bytes.to_vec(),
        };
        result.verify()?;
        Ok(result)
    }

    /// Verifies the enclosed record and its Network-bound signature.
    ///
    /// # Errors
    ///
    /// Returns an error if either signature or the enclosed record is invalid.
    pub fn verify(&self) -> Result<(), NetworkNodeRecordError> {
        self.record.verify()?;
        let key = VerifyingKey::from_bytes(self.record.identity())
            .map_err(|_| NetworkNodeRecordError::BadSignature)?;
        key.verify_strict(
            &message(self.network, &self.record),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| NetworkNodeRecordError::BadSignature)
    }

    /// Verifies that this signed record belongs to `network`.
    ///
    /// # Errors
    ///
    /// Returns an error for a different Network or an invalid signature.
    pub fn verify_for(&self, network: RealmId) -> Result<(), NetworkNodeRecordError> {
        if self.network != network {
            return Err(NetworkNodeRecordError::NetworkMismatch);
        }
        self.verify()
    }

    /// Verifies the Network and the enclosed record expiry at `now` Unix seconds.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong Network, invalid signature, or expired record.
    pub fn verify_current_for(
        &self,
        network: RealmId,
        now: u64,
    ) -> Result<(), NetworkNodeRecordError> {
        self.verify_for(network)?;
        self.record.check_not_expired(now)?;
        Ok(())
    }

    /// Returns the Network scope authenticated by the outer signature.
    #[must_use]
    pub const fn network(&self) -> RealmId {
        self.network
    }

    /// Returns the enclosed, independently signed NodeRecord.
    #[must_use]
    pub const fn record(&self) -> &NodeRecord {
        &self.record
    }

    /// Returns the composite key required for Account registry storage and lookup.
    #[must_use]
    pub fn key(&self) -> NetworkRecordKey {
        NetworkRecordKey {
            network: self.network,
            node: self.record.node_id(),
        }
    }

    /// Returns the exact canonical envelope bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

fn message(network: RealmId, record: &NodeRecord) -> Vec<u8> {
    let mut result = CONTEXT.to_vec();
    let mut writer = CborWriter::with_capacity(640);
    writer
        .array(3)
        .uint(VERSION)
        .bytes(network.as_bytes())
        .bytes(record.as_bytes());
    result.extend(writer.into_bytes());
    result
}

fn encode(network: RealmId, record: &NodeRecord, signature: &[u8; 64]) -> Vec<u8> {
    let mut writer = CborWriter::with_capacity(MAX_BYTES);
    writer
        .array(4)
        .uint(VERSION)
        .bytes(network.as_bytes())
        .bytes(record.as_bytes())
        .bytes(signature);
    writer.into_bytes()
}
