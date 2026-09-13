use crate::{Identity, KeyBindingScope, NetworkId, codec::CborReader};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Serialize, ser::SerializeTuple};

const REVOCATION_CONTEXT: &[u8] = b"keynet/revocation/v1";
const MAX_REVOCATION_BYTES: usize = 256;

/// A signed inclusive binding-generation revocation (§§13.2-13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revocation {
    /// The record version, which must be one.
    pub ver: u8,
    /// The network containing the revoked binding generations.
    pub network_id: NetworkId,
    /// The identity signing and owning this record.
    pub identity: Identity,
    /// The greatest binding generation revoked inclusively.
    pub revoked_through: u64,
    /// Informational Unix-second issuance time.
    pub issued_at: u64,
    /// The identity's Ed25519 signature.
    pub signature: [u8; 64],
}

/// A strict Revocation decoding failure (§13.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationDecodeError {
    /// The input is not the exact canonical six-field record.
    InvalidEncoding,
    /// The record version is not one.
    UnsupportedVersion,
}

/// A Revocation signing or verification failure (§13.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationSignatureError {
    /// The record version is not one.
    UnsupportedVersion,
    /// The signing key does not match the record identity.
    SignerIdentityMismatch,
    /// The identity is not a valid strict Ed25519 public key.
    InvalidIdentityKey,
    /// The signature is invalid.
    InvalidSignature,
}

/// A canonical-decode or Revocation-signature failure, in rejection order (§§13.1-13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationInputError {
    /// Canonical decoding failed before cryptography.
    Decode(RevocationDecodeError),
    /// Signature verification failed after decoding.
    Signature(RevocationSignatureError),
}

/// A Revocation whose signature and version have been verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRevocation(Revocation);

/// Caller-owned revocation high-water for one `(network_id, identity)` scope (§13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationState {
    /// The exact scope governed by this state.
    pub scope: KeyBindingScope,
    /// The optional inclusive revocation high-water.
    pub revoked_through: Option<u64>,
}

/// A pure Revocation high-water decision (§13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationDecision {
    /// The record does not raise the current high-water.
    Idempotent,
    /// The caller may replace its state with this raised high-water.
    Raise(RevocationState),
}

/// A Revocation high-water decision failure (§13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationDecisionError {
    /// The verified record belongs to a different network or identity.
    ScopeMismatch,
}

impl Revocation {
    /// Returns the canonical unsigned five-field array (§13.2).
    #[must_use]
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        serialize(&UnsignedRevocationWire(self))
    }

    /// Returns the exact Ed25519 signing message (§13.2).
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let unsigned = self.unsigned_bytes();
        let mut output = Vec::with_capacity(REVOCATION_CONTEXT.len() + unsigned.len());
        output.extend_from_slice(REVOCATION_CONTEXT);
        output.extend_from_slice(&unsigned);
        output
    }

    /// Signs this version-one record with its identity key (§13.2).
    pub fn sign(&mut self, signer: &SigningKey) -> Result<(), RevocationSignatureError> {
        if self.ver != 1 {
            return Err(RevocationSignatureError::UnsupportedVersion);
        }
        if signer.verifying_key().to_bytes() != self.identity {
            return Err(RevocationSignatureError::SignerIdentityMismatch);
        }
        self.signature = signer.sign(&self.signing_preimage()).to_bytes();
        Ok(())
    }

    /// Encodes the canonical signed six-field array (§§13.1-13.2).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        serialize(&SignedRevocationWire(self))
    }

    /// Decodes an exact canonical signed six-field array before cryptography (§13.1).
    pub fn decode(encoded: &[u8]) -> Result<Self, RevocationDecodeError> {
        if encoded.len() > MAX_REVOCATION_BYTES {
            return Err(RevocationDecodeError::InvalidEncoding);
        }
        let mut reader = CborReader::new(encoded);
        reader
            .array(6)
            .map_err(|_| RevocationDecodeError::InvalidEncoding)?;
        let ver = u8::try_from(
            reader
                .uint()
                .map_err(|_| RevocationDecodeError::InvalidEncoding)?,
        )
        .map_err(|_| RevocationDecodeError::InvalidEncoding)?;
        let record = Self {
            ver,
            network_id: reader
                .fixed_bytes()
                .map_err(|_| RevocationDecodeError::InvalidEncoding)?,
            identity: reader
                .fixed_bytes()
                .map_err(|_| RevocationDecodeError::InvalidEncoding)?,
            revoked_through: reader
                .uint()
                .map_err(|_| RevocationDecodeError::InvalidEncoding)?,
            issued_at: reader
                .uint()
                .map_err(|_| RevocationDecodeError::InvalidEncoding)?,
            signature: reader
                .fixed_bytes()
                .map_err(|_| RevocationDecodeError::InvalidEncoding)?,
        };
        if !reader.finished() || record.encode() != encoded {
            return Err(RevocationDecodeError::InvalidEncoding);
        }
        if ver != 1 {
            return Err(RevocationDecodeError::UnsupportedVersion);
        }
        Ok(record)
    }

    /// Verifies the version and ordinary Ed25519 signature (§13.2).
    pub fn verify(&self) -> Result<VerifiedRevocation, RevocationSignatureError> {
        if self.ver != 1 {
            return Err(RevocationSignatureError::UnsupportedVersion);
        }
        let key = VerifyingKey::from_bytes(&self.identity)
            .map_err(|_| RevocationSignatureError::InvalidIdentityKey)?;
        key.verify_strict(
            &self.signing_preimage(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| RevocationSignatureError::InvalidSignature)?;
        Ok(VerifiedRevocation(*self))
    }

    /// Decodes canonical bytes before verifying the signature (§§13.1-13.2).
    pub fn decode_and_verify(encoded: &[u8]) -> Result<VerifiedRevocation, RevocationInputError> {
        Self::decode(encoded)
            .map_err(RevocationInputError::Decode)?
            .verify()
            .map_err(RevocationInputError::Signature)
    }
}

impl VerifiedRevocation {
    /// Returns the verified record.
    #[must_use]
    pub fn record(self) -> Revocation {
        self.0
    }

    /// Evaluates the monotonic scoped high-water transition without mutation (§13.3).
    pub fn high_water_decision(
        self,
        state: &RevocationState,
    ) -> Result<RevocationDecision, RevocationDecisionError> {
        let record = self.0;
        if state.scope.network_id != record.network_id || state.scope.identity != record.identity {
            return Err(RevocationDecisionError::ScopeMismatch);
        }
        if state
            .revoked_through
            .is_some_and(|current| record.revoked_through <= current)
        {
            return Ok(RevocationDecision::Idempotent);
        }
        Ok(RevocationDecision::Raise(RevocationState {
            revoked_through: Some(record.revoked_through),
            ..*state
        }))
    }
}

struct UnsignedRevocationWire<'a>(&'a Revocation);
struct SignedRevocationWire<'a>(&'a Revocation);

fn fields<S>(record: &Revocation, array: &mut S) -> Result<(), S::Error>
where
    S: SerializeTuple,
{
    array.serialize_element(&record.ver)?;
    array.serialize_element(&serde_bytes::Bytes::new(&record.network_id))?;
    array.serialize_element(&serde_bytes::Bytes::new(&record.identity))?;
    array.serialize_element(&record.revoked_through)?;
    array.serialize_element(&record.issued_at)
}

impl Serialize for UnsignedRevocationWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(5)?;
        fields(self.0, &mut array)?;
        array.end()
    }
}

impl Serialize for SignedRevocationWire<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut array = serializer.serialize_tuple(6)?;
        fields(self.0, &mut array)?;
        array.serialize_element(&serde_bytes::Bytes::new(&self.0.signature))?;
        array.end()
    }
}

fn serialize(value: &impl Serialize) -> Vec<u8> {
    let mut output = Vec::with_capacity(MAX_REVOCATION_BYTES);
    let result = ciborium::ser::into_writer(value, &mut output);
    debug_assert!(result.is_ok());
    output
}
