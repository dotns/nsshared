//! WG-only network-key payloads. Codec validation is not live member authority.

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use secrecy::{ExposeSecret as _, SecretBox, zeroize::Zeroize as _};

use super::codec::{self, Field};
use super::{Error, SyncVersion};

mod framing;
pub use framing::{KeyEnvelope, WgPeerFrame, decode_wg_peer_frame};

pub const MAX_KEY_FRAME: usize = 1200;
pub const MAX_KEY_BODY: usize = MAX_KEY_FRAME - 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPeerBinding {
    pub signing_pub: [u8; 32],
    pub wg_pub: [u8; 32],
    pub incarnation: u64,
}

impl KeyPeerBinding {
    fn validate(&self) -> Result<(), Error> {
        if self.incarnation == 0 {
            return Err(Error::Payload("key peer incarnation"));
        }
        ed25519_dalek::VerifyingKey::from_bytes(&self.signing_pub)
            .map_err(|_| Error::Payload("key peer signing key"))?;
        Ok(())
    }
}

impl Field for KeyPeerBinding {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (0_u64.to_value(), 1_u64.to_value()),
            (1_u64.to_value(), self.signing_pub.to_value()),
            (2_u64.to_value(), self.wg_pub.to_value()),
            (3_u64.to_value(), self.incarnation.to_value()),
        ])
    }

    fn from_value(value: Value) -> Result<Self, Error> {
        let mut fields = codec::fields(value)?;
        let peer = Self {
            signing_pub: codec::take(&mut fields, 1)?,
            wg_pub: codec::take(&mut fields, 2)?,
            incarnation: codec::take(&mut fields, 3)?,
        };
        peer.validate()?;
        Ok(peer)
    }

    fn sign_into(&self, out: &mut Vec<u8>) {
        self.signing_pub.sign_into(out);
        self.wg_pub.sign_into(out);
        self.incarnation.sign_into(out);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRequest {
    pub network_pub: [u8; 32],
    pub requester: KeyPeerBinding,
    pub grantor: KeyPeerBinding,
    pub version: SyncVersion,
}

impl KeyRequest {
    pub const API: &'static str = "mesh.key.request";

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        codec::encode(&self.to_value())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_value(codec::decode(bytes)?)
    }

    fn validate(&self) -> Result<(), Error> {
        self.requester.validate()?;
        self.grantor.validate()?;
        ed25519_dalek::VerifyingKey::from_bytes(&self.network_pub)
            .map_err(|_| Error::Payload("network public key"))?;
        if self.requester.signing_pub == self.grantor.signing_pub
            || self.requester.wg_pub == self.grantor.wg_pub
        {
            return Err(Error::Payload("key exchange peers must differ"));
        }
        Ok(())
    }
}

impl Field for KeyRequest {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (0_u64.to_value(), 1_u64.to_value()),
            (1_u64.to_value(), self.network_pub.to_value()),
            (2_u64.to_value(), self.requester.to_value()),
            (3_u64.to_value(), self.grantor.to_value()),
            (4_u64.to_value(), self.version.to_value()),
        ])
    }

    fn from_value(value: Value) -> Result<Self, Error> {
        let mut fields = codec::fields(value)?;
        let request = Self {
            network_pub: codec::take(&mut fields, 1)?,
            requester: codec::take(&mut fields, 2)?,
            grantor: codec::take(&mut fields, 3)?,
            version: codec::take(&mut fields, 4)?,
        };
        request.validate()?;
        Ok(request)
    }

    fn sign_into(&self, out: &mut Vec<u8>) {
        self.network_pub.sign_into(out);
        self.requester.sign_into(out);
        self.grantor.sign_into(out);
        self.version.sign_into(out);
    }
}

pub struct KeyGrant {
    request: KeyRequest,
    request_nonce: [u8; 16],
    network_secret: SecretBox<[u8; 32]>,
}

impl std::fmt::Debug for KeyGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyGrant")
            .field("request", &self.request)
            .field("request_nonce", &self.request_nonce)
            .field("network_secret", &"[REDACTED]")
            .finish()
    }
}

impl KeyGrant {
    pub const API: &'static str = "mesh.key.grant";

    pub fn new(
        request: KeyRequest,
        request_nonce: [u8; 16],
        network_secret: SecretBox<[u8; 32]>,
    ) -> Result<Self, Error> {
        request.validate()?;
        if SigningKey::from_bytes(network_secret.expose_secret())
            .verifying_key()
            .to_bytes()
            != request.network_pub
        {
            return Err(Error::Payload("network secret binding"));
        }
        Ok(Self {
            request,
            request_nonce,
            network_secret,
        })
    }

    pub fn request(&self) -> &KeyRequest {
        &self.request
    }

    pub const fn request_nonce(&self) -> &[u8; 16] {
        &self.request_nonce
    }

    /// Only the WG sender and durable vault installation should expose these bytes.
    pub fn network_secret(&self) -> &SecretBox<[u8; 32]> {
        &self.network_secret
    }

    pub fn encode(&self) -> Result<SecretBox<Vec<u8>>, Error> {
        let value = SensitiveValue(Value::Map(vec![
            (0_u64.to_value(), 1_u64.to_value()),
            (1_u64.to_value(), self.request.to_value()),
            (2_u64.to_value(), self.request_nonce.to_value()),
            (
                3_u64.to_value(),
                self.network_secret.expose_secret().to_value(),
            ),
        ]));
        codec::encode(&value.0).map(|bytes| SecretBox::new(Box::new(bytes)))
    }

    /// The caller owns and must protect the input buffer; no authentication is implied.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut value = SensitiveValue(codec::decode(bytes)?);
        let Value::Map(entries) = &mut value.0 else {
            return Err(Error::Payload("key grant map"));
        };
        let mut request = None;
        let mut nonce = None;
        let mut secret = None;
        let mut version = None;
        for (key, field) in entries {
            match u64::from_value(key.clone())? {
                0 => version = Some(u64::from_value(field.clone())?),
                1 => request = Some(KeyRequest::from_value(field.clone())?),
                2 => nonce = Some(<[u8; 16]>::from_value(field.clone())?),
                3 => {
                    let Value::Bytes(bytes) = field else {
                        return Err(Error::Payload("network secret bytes"));
                    };
                    if bytes.len() != 32 {
                        return Err(Error::Payload("network secret width"));
                    }
                    let mut seed = SecretBox::new(Box::new([0; 32]));
                    use secrecy::ExposeSecretMut as _;
                    seed.expose_secret_mut().copy_from_slice(bytes);
                    secret = Some(seed);
                }
                _ => {}
            }
        }
        if version != Some(1) {
            return Err(Error::Payload("schema version"));
        }
        Self::new(
            request.ok_or(Error::Payload("missing request"))?,
            nonce.ok_or(Error::Payload("missing request nonce"))?,
            secret.ok_or(Error::Payload("missing network secret"))?,
        )
    }
}

// The generic CBOR parser owns temporary buffers too; this guard only wipes this tree.
struct SensitiveValue(Value);

impl Drop for SensitiveValue {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            match value {
                Value::Bytes(bytes) => bytes.zeroize(),
                Value::Text(text) => text.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(wipe),
                Value::Tag(_, value) => wipe(value),
                Value::Map(entries) => {
                    for (key, value) in entries {
                        wipe(key);
                        wipe(value);
                    }
                }
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

#[cfg(test)]
mod tests;
