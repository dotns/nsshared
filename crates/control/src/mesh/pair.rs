//! Node-pair credentials. Decoding authenticates structure, never local consent.
//!
//! A consumer must retain its own revocation floor and durable grant, then
//! exchange fresh session proofs before enabling either direction of business.

use ciborium::value::Value;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use ring::hmac;
use sha2::{Digest as _, Sha256};

use super::codec::{self, Field};
use super::{Error, MeshV2RegistrationAllocation};

mod messages;
pub use messages::*;

/// Pair payloads have their own closed schema, separate from v1 group records.
pub const MESH_V2_PAIR_SCHEMA: u64 = 2;
pub const MESH_V2_PAIR_REQUEST_TTL: u64 = 120;
pub const MESH_V2_PAIR_CAP_NATIVE: u64 = 1;
pub const MESH_V2_PAIR_CAP_TRANSLATED: u64 = 2;

// Unlike the legacy payload macro, every pair map rejects unknown fields and
// requires the pair schema. This also applies to nested records.
macro_rules! record {
    ($name:ident { $( $number:literal => $field:ident : $ty:ty ),+ $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name { $(pub $field: $ty),+ }
        impl $name {
            pub fn encode(&self) -> Result<Vec<u8>, Error> {
                self.validate()?;
                codec::encode(&self.to_value())
            }
            pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
                Self::from_value(codec::decode(bytes)?)
            }
        }
        impl Field for $name {
            fn to_value(&self) -> Value {
                Value::Map(vec![
                    (0_u64.to_value(), MESH_V2_PAIR_SCHEMA.to_value()),
                    $(($number.to_value(), self.$field.to_value())),+
                ])
            }
            fn from_value(value: Value) -> Result<Self, Error> {
                let mut fields = pair_fields(value)?;
                let result = Self { $($field: codec::take(&mut fields, $number)?),+ };
                if !fields.is_empty() { return Err(Error::Payload("unknown pair field")); }
                result.validate()?;
                Ok(result)
            }
            fn sign_into(&self, out: &mut Vec<u8>) { $(self.$field.sign_into(out);)+ }
        }
    };
}
pub(super) use record;

fn pair_fields(value: Value) -> Result<std::collections::BTreeMap<u64, Value>, Error> {
    let Value::Map(entries) = value else {
        return Err(Error::Payload("pair map"));
    };
    let mut fields = std::collections::BTreeMap::new();
    let mut previous = None;
    for (key, value) in entries {
        let key = u64::from_value(key)?;
        if previous.is_some_and(|previous| previous >= key) {
            return Err(Error::Payload("pair field order"));
        }
        previous = Some(key);
        fields.insert(key, value);
    }
    if codec::take::<u64>(&mut fields, 0)? != MESH_V2_PAIR_SCHEMA {
        return Err(Error::Payload("pair schema"));
    }
    Ok(fields)
}

record!(MeshV2NodeIdentity {
    1_u64 => signing_pub: [u8; 32], 2_u64 => wg_pub: [u8; 32],
});

impl MeshV2NodeIdentity {
    pub fn validate(&self) -> Result<(), Error> {
        let key = VerifyingKey::from_bytes(&self.signing_pub)
            .map_err(|_| Error::Payload("pair signing key"))?;
        if key.is_weak() || self.wg_pub == [0; 32] {
            return Err(Error::Payload("pair weak identity"));
        }
        Ok(())
    }
}

/// Stable authority identity, pinned through authenticated discovery/registration.
/// Equal DNS strings alone never identify the same registry.
pub fn mesh_v2_realm_id(authority_pub: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"nsmesh-v2-realm\0");
    digest.update(authority_pub);
    digest.finalize().into()
}

record!(MeshV2PairBinding {
    1_u64 => realm: [u8; 32],
    2_u64 => first: MeshV2NodeIdentity, 3_u64 => second: MeshV2NodeIdentity,
    4_u64 => first_generation: u64, 5_u64 => second_generation: u64,
    6_u64 => operation_id: [u8; 16],
});

impl MeshV2PairBinding {
    pub fn validate(&self) -> Result<(), Error> {
        self.first.validate()?;
        self.second.validate()?;
        if self.first.signing_pub >= self.second.signing_pub
            || self.first.wg_pub == self.second.wg_pub
            || self.first_generation == 0
            || self.second_generation == 0
            || self.operation_id == [0; 16]
            || self.realm == [0; 32]
        {
            return Err(Error::Payload("pair binding"));
        }
        Ok(())
    }

    pub fn signing_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut input = b"nsmesh-v2-pair-grant\0".to_vec();
        MESH_V2_PAIR_SCHEMA.sign_into(&mut input);
        self.sign_into(&mut input);
        Ok(input)
    }

    pub fn digest(&self) -> Result<[u8; 32], Error> {
        Ok(Sha256::digest(self.signing_input()?).into())
    }

    /// Check both retained revocation floors. Runtime restarts do not increment them.
    pub fn verify_floors(&self, realm: &[u8; 32], first: u64, second: u64) -> Result<(), Error> {
        self.validate()?;
        if &self.realm != realm
            || self.first_generation <= first
            || self.second_generation <= second
        {
            return Err(Error::Payload("pair realm or revoked generation"));
        }
        Ok(())
    }

    pub fn peer(&self, signer: &[u8; 32]) -> Result<&MeshV2NodeIdentity, Error> {
        if signer == &self.first.signing_pub {
            Ok(&self.second)
        } else if signer == &self.second.signing_pub {
            Ok(&self.first)
        } else {
            Err(Error::Payload("not a pair endpoint"))
        }
    }
}

record!(MeshV2PairGrant {
    1_u64 => binding: MeshV2PairBinding,
    2_u64 => first_signature: [u8; 64], 3_u64 => second_signature: [u8; 64],
});

impl MeshV2PairGrant {
    fn validate(&self) -> Result<(), Error> {
        self.binding.validate()
    }

    /// Verify both explicit authorizations; not evidence of local persistence or liveness.
    pub fn verify(&self) -> Result<(), Error> {
        let input = self.binding.signing_input()?;
        super::recovery::verify(
            &self.binding.first.signing_pub,
            &input,
            &self.first_signature,
        )?;
        super::recovery::verify(
            &self.binding.second.signing_pub,
            &input,
            &self.second_signature,
        )
    }
}

record!(MeshV2PairRevocation {
    1_u64 => realm: [u8; 32], 2_u64 => owner: MeshV2NodeIdentity,
    3_u64 => peer: MeshV2NodeIdentity, 4_u64 => revoked_through: u64,
    5_u64 => signature: [u8; 64],
});

impl MeshV2PairRevocation {
    fn validate(&self) -> Result<(), Error> {
        self.owner.validate()?;
        self.peer.validate()?;
        if self.owner.signing_pub == self.peer.signing_pub
            || self.owner.wg_pub == self.peer.wg_pub
            || self.revoked_through == 0
            || self.realm == [0; 32]
        {
            return Err(Error::Payload("pair revocation"));
        }
        Ok(())
    }

    pub fn signing_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut input = b"nsmesh-v2-pair-revoke\0".to_vec();
        self.realm.sign_into(&mut input);
        self.owner.sign_into(&mut input);
        self.peer.sign_into(&mut input);
        self.revoked_through.sign_into(&mut input);
        Ok(input)
    }

    pub fn verify(&self) -> Result<(), Error> {
        super::recovery::verify(
            &self.owner.signing_pub,
            &self.signing_input()?,
            &self.signature,
        )
    }
}

record!(MeshV2PairSession {
    1_u64 => grant_digest: [u8; 32], 2_u64 => sender: [u8; 32],
    3_u64 => sender_challenge: [u8; 32], 4_u64 => receiver_challenge: [u8; 32],
    5_u64 => capabilities: u64, 6_u64 => wg_proof: [u8; 32],
    7_u64 => signature: [u8; 64],
});

impl MeshV2PairSession {
    /// Authenticate a sender and exact grant for directed relay delivery only.
    /// This does NOT verify WG possession, freshness, local consent or readiness.
    pub fn verify_sender(&self, grant: &MeshV2PairGrant) -> Result<(), Error> {
        grant.verify()?;
        grant.binding.peer(&self.sender)?;
        if self.grant_digest != grant.binding.digest()? {
            return Err(Error::Payload("pair session grant binding"));
        }
        super::recovery::verify(&self.sender, &self.signing_input()?, &self.signature)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.sender_challenge == [0; 32]
            || self.receiver_challenge == [0; 32]
            || self.sender_challenge == self.receiver_challenge
            || self.capabilities & !(MESH_V2_PAIR_CAP_NATIVE | MESH_V2_PAIR_CAP_TRANSLATED) != 0
        {
            return Err(Error::Payload("pair session challenge or capabilities"));
        }
        Ok(())
    }

    fn proof_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut input = b"nsmesh-v2-pair-session\0".to_vec();
        self.grant_digest.sign_into(&mut input);
        self.sender.sign_into(&mut input);
        self.sender_challenge.sign_into(&mut input);
        self.receiver_challenge.sign_into(&mut input);
        self.capabilities.sign_into(&mut input);
        Ok(input)
    }

    fn signing_input(&self) -> Result<Vec<u8>, Error> {
        let mut input = self.proof_input()?;
        self.wg_proof.sign_into(&mut input);
        Ok(input)
    }

    /// Sign only after durable grant storage and current policy/floor checks.
    /// `wg_shared_secret` MUST be X25519(local WG secret, bound remote WG key).
    /// Never accept this secret from a peer or relay, or persist/log it.
    pub fn sign(&mut self, key: &SigningKey, wg_shared_secret: &[u8; 32]) -> Result<(), Error> {
        if key.verifying_key().to_bytes() != self.sender || *wg_shared_secret == [0; 32] {
            return Err(Error::Payload("pair session key binding"));
        }
        let tag = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, wg_shared_secret),
            &self.proof_input()?,
        );
        self.wg_proof.copy_from_slice(tag.as_ref());
        self.signature = key.sign(&self.signing_input()?).to_bytes();
        Ok(())
    }

    /// Verify against the exact LOCAL durable grant and current challenge pair.
    /// Callers also check their current revocation floor/policy under the owner lock.
    pub fn verify(
        &self,
        grant: &MeshV2PairGrant,
        receiver: &[u8; 32],
        sender_challenge: &[u8; 32],
        receiver_challenge: &[u8; 32],
        wg_shared_secret: &[u8; 32],
    ) -> Result<(), Error> {
        self.verify_sender(grant)?;
        if grant.binding.peer(&self.sender)?.signing_pub != *receiver
            || self.grant_digest != grant.binding.digest()?
            || &self.sender_challenge != sender_challenge
            || &self.receiver_challenge != receiver_challenge
            || *wg_shared_secret == [0; 32]
        {
            return Err(Error::Payload("pair session binding"));
        }
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, wg_shared_secret),
            &self.proof_input()?,
            &self.wg_proof,
        )
        .map_err(|_| Error::Payload("pair WG possession"))
    }
}

#[cfg(test)]
mod tests;
