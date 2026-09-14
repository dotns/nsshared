use ciborium::value::Value;
use serde::{Deserialize, Serialize};

use super::codec::{Field, decode, encode, fields, take};
use super::recovery::verify;
use super::{
    Error, MESH_V2_REGISTER_API, MeshV2AddressPurpose, mesh_v2_name_label, mesh_v2_overlay_ipv6,
    mesh_v2_registration_proof_input,
};

/// The authenticated response API paired with [`MeshV2Register::API`].
pub const MESH_V2_REGISTERED_API: &str = "mesh.v2.registered";

/// A terminal result of a Mesh v2 registration attempt.
///
/// Non-successful results deliberately carry no allocation. This prevents a
/// client from treating a partial or uncommitted allocation as durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum MeshV2RegistrationStatus {
    Registered = 0,
    Unavailable = 1,
    IdentityConflict = 2,
    NameExhausted = 3,
}

impl MeshV2RegistrationStatus {
    fn from_u64(value: u64) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::Registered),
            1 => Ok(Self::Unavailable),
            2 => Ok(Self::IdentityConflict),
            3 => Ok(Self::NameExhausted),
            _ => Err(Error::Payload("unknown v2 registration status")),
        }
    }
}

impl Field for MeshV2RegistrationStatus {
    fn to_value(&self) -> Value {
        (*self as u64).to_value()
    }

    fn from_value(value: Value) -> Result<Self, Error> {
        Self::from_u64(u64::from_value(value)?)
    }

    fn sign_into(&self, out: &mut Vec<u8>) {
        (*self as u64).sign_into(out);
    }
}

/// The server-authoritative, permanently occupied attributes of one Mesh v2
/// node identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshV2RegistrationAllocation {
    pub wg_pub: [u8; 32],
    pub native_ipv6: [u8; 16],
    pub translated_ipv6: [u8; 16],
    pub name_salt: [u8; 16],
    pub name_len: u64,
    pub dns_root: String,
}

impl MeshV2RegistrationAllocation {
    /// Verify that a registry allocation still matches the immutable v2
    /// identity derivations and safe name parameters.
    pub fn validate(&self) -> Result<(), Error> {
        if !(5..=super::MESH_V2_MAX_NAME_LABEL_LEN as u64).contains(&self.name_len) {
            return Err(Error::Payload("v2 name length"));
        }
        if !mesh_v2_valid_dns_root(&self.dns_root)
            || self.name_len + 1 + self.dns_root.len() as u64 > 253
        {
            return Err(Error::Payload("v2 DNS root"));
        }
        if self.native_ipv6 != mesh_v2_overlay_ipv6(&self.wg_pub, MeshV2AddressPurpose::Native)
            || self.translated_ipv6
                != mesh_v2_overlay_ipv6(&self.wg_pub, MeshV2AddressPurpose::Ipv4Translated)
        {
            return Err(Error::Payload("v2 allocation address"));
        }
        mesh_v2_name_label(
            &self.wg_pub,
            &self.name_salt,
            usize::try_from(self.name_len).map_err(|_| Error::Payload("v2 name length"))?,
        )?;
        Ok(())
    }
}

impl Field for MeshV2RegistrationAllocation {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (0_u64.to_value(), 1_u64.to_value()),
            (1_u64.to_value(), self.wg_pub.to_value()),
            (2_u64.to_value(), self.native_ipv6.to_value()),
            (3_u64.to_value(), self.translated_ipv6.to_value()),
            (4_u64.to_value(), self.name_salt.to_value()),
            (5_u64.to_value(), self.name_len.to_value()),
            (6_u64.to_value(), self.dns_root.to_value()),
        ])
    }

    fn from_value(value: Value) -> Result<Self, Error> {
        let mut fields = fields(value)?;
        let result = Self {
            wg_pub: take(&mut fields, 1)?,
            native_ipv6: take(&mut fields, 2)?,
            translated_ipv6: take(&mut fields, 3)?,
            name_salt: take(&mut fields, 4)?,
            name_len: take(&mut fields, 5)?,
            dns_root: take(&mut fields, 6)?,
        };
        if !fields.is_empty() {
            return Err(Error::Payload("unknown v2 allocation field"));
        }
        result.validate()?;
        Ok(result)
    }

    fn sign_into(&self, out: &mut Vec<u8>) {
        self.wg_pub.sign_into(out);
        self.native_ipv6.sign_into(out);
        self.translated_ipv6.sign_into(out);
        self.name_salt.sign_into(out);
        self.name_len.sign_into(out);
        self.dns_root.sign_into(out);
    }
}

/// The authenticated result of one Mesh v2 registration request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshV2Registered {
    pub nonce: [u8; 16],
    pub status: MeshV2RegistrationStatus,
    pub allocation: Option<MeshV2RegistrationAllocation>,
}

impl MeshV2Registered {
    pub const API: &'static str = MESH_V2_REGISTERED_API;

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode(&self.to_value())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_value(decode(bytes)?)
    }

    fn validate(&self) -> Result<(), Error> {
        match (self.status, self.allocation.is_some()) {
            (MeshV2RegistrationStatus::Registered, true)
            | (MeshV2RegistrationStatus::Unavailable, false)
            | (MeshV2RegistrationStatus::IdentityConflict, false)
            | (MeshV2RegistrationStatus::NameExhausted, false) => {
                if let Some(allocation) = &self.allocation {
                    allocation.validate()?;
                }
                Ok(())
            }
            _ => Err(Error::Payload("v2 registration allocation status")),
        }
    }
}

impl Field for MeshV2Registered {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (0_u64.to_value(), 1_u64.to_value()),
            (1_u64.to_value(), self.nonce.to_value()),
            (2_u64.to_value(), self.status.to_value()),
            (3_u64.to_value(), self.allocation.to_value()),
        ])
    }

    fn from_value(value: Value) -> Result<Self, Error> {
        let mut fields = fields(value)?;
        let result = Self {
            nonce: take(&mut fields, 1)?,
            status: take(&mut fields, 2)?,
            allocation: take(&mut fields, 3)?,
        };
        if !fields.is_empty() {
            return Err(Error::Payload("unknown v2 registered field"));
        }
        result.validate()?;
        Ok(result)
    }

    fn sign_into(&self, out: &mut Vec<u8>) {
        self.nonce.sign_into(out);
        self.status.sign_into(out);
        self.allocation.sign_into(out);
    }
}

/// Validate a canonical Mesh v2 DNS root with the registry allocation rules.
pub fn mesh_v2_valid_dns_root(root: &str) -> bool {
    !root.is_empty()
        && root.len() <= 253
        && root.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

/// The closed, authenticated first-contact payload for Mesh v2 registration.
///
/// Group authorization and durable allocation are deliberately absent here:
/// those are registry responsibilities introduced by the registration block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshV2Register {
    pub wg_pub: [u8; 32],
    pub registration_proof: [u8; 64],
}

impl MeshV2Register {
    pub const API: &'static str = MESH_V2_REGISTER_API;

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        encode(&self.to_value())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_value(decode(bytes)?)
    }

    pub fn proof_input(&self, signing_pub: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
        mesh_v2_registration_proof_input(signing_pub, &self.wg_pub, nonce)
    }

    pub fn verify_registration_proof(
        &self,
        signing_pub: &[u8; 32],
        nonce: &[u8; 16],
    ) -> Result<(), Error> {
        verify(
            signing_pub,
            &self.proof_input(signing_pub, nonce),
            &self.registration_proof,
        )
    }
}

impl Field for MeshV2Register {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (0_u64.to_value(), 1_u64.to_value()),
            (1_u64.to_value(), self.wg_pub.to_value()),
            (2_u64.to_value(), self.registration_proof.to_value()),
        ])
    }

    fn from_value(value: Value) -> Result<Self, Error> {
        let mut fields = fields(value)?;
        let result = Self {
            wg_pub: take(&mut fields, 1)?,
            registration_proof: take(&mut fields, 2)?,
        };
        if !fields.is_empty() {
            return Err(Error::Payload("unknown v2 registration field"));
        }
        Ok(result)
    }

    fn sign_into(&self, out: &mut Vec<u8>) {
        self.wg_pub.sign_into(out);
        self.registration_proof.sign_into(out);
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    fn registration(key: &SigningKey, wg_pub: [u8; 32], nonce: [u8; 16]) -> MeshV2Register {
        let signing_pub = key.verifying_key().to_bytes();
        let registration_proof = key
            .sign(&mesh_v2_registration_proof_input(
                &signing_pub,
                &wg_pub,
                &nonce,
            ))
            .to_bytes();
        MeshV2Register {
            wg_pub,
            registration_proof,
        }
    }

    fn allocation(wg_pub: [u8; 32]) -> MeshV2RegistrationAllocation {
        MeshV2RegistrationAllocation {
            wg_pub,
            native_ipv6: mesh_v2_overlay_ipv6(&wg_pub, MeshV2AddressPurpose::Native),
            translated_ipv6: mesh_v2_overlay_ipv6(&wg_pub, MeshV2AddressPurpose::Ipv4Translated),
            name_salt: [0x44; 16],
            name_len: 5,
            dns_root: super::super::MESH_V2_DEFAULT_DNS_ROOT.to_string(),
        }
    }

    #[test]
    fn v2_allocation_limits_the_complete_dns_name() {
        let mut entry = allocation([0x33; 32]);
        entry.dns_root = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(55),
        ]
        .join(".");
        assert_eq!(entry.dns_root.len(), 247);
        entry.validate().unwrap();
        entry.name_len = 6;
        assert!(entry.validate().is_err());
        entry.name_len = 5;
        entry.dns_root.push('d');
        assert!(mesh_v2_valid_dns_root(&entry.dns_root));
        assert!(entry.validate().is_err());
    }

    #[test]
    fn v2_registration_proof_binds_enclosing_signer_and_nonce() {
        let key = SigningKey::from_bytes(&[0x11; 32]);
        let nonce = [0x22; 16];
        let request = registration(&key, [0x33; 32], nonce);
        request
            .verify_registration_proof(&key.verifying_key().to_bytes(), &nonce)
            .unwrap();
        assert!(
            request
                .verify_registration_proof(&key.verifying_key().to_bytes(), &[0x23; 16])
                .is_err()
        );
        assert!(
            request
                .verify_registration_proof(
                    &SigningKey::from_bytes(&[0x44; 32])
                        .verifying_key()
                        .to_bytes(),
                    &nonce,
                )
                .is_err()
        );
    }

    #[test]
    fn v2_registration_encoding_is_canonical_and_closed() {
        let request = MeshV2Register {
            wg_pub: [0x22; 32],
            registration_proof: [0x33; 64],
        };
        let mut expected = vec![0xa3, 0x00, 0x01, 0x01, 0x58, 0x20];
        expected.extend_from_slice(&request.wg_pub);
        expected.extend_from_slice(&[0x02, 0x58, 0x40]);
        expected.extend_from_slice(&request.registration_proof);
        assert_eq!(request.encode().unwrap(), expected);
        assert_eq!(MeshV2Register::decode(&expected).unwrap(), request);

        let mut unknown = expected;
        unknown[0] = 0xa4;
        unknown.extend_from_slice(&[0x03, 0x00]);
        assert!(matches!(
            MeshV2Register::decode(&unknown),
            Err(Error::Payload("unknown v2 registration field"))
        ));
    }

    #[test]
    fn v2_registered_response_is_canonical_and_binds_one_complete_allocation() {
        let reply = MeshV2Registered {
            nonce: [0x11; 16],
            status: MeshV2RegistrationStatus::Registered,
            allocation: Some(allocation([0x22; 32])),
        };
        let encoded = reply.encode().unwrap();
        let mut expected = vec![0xa4, 0x00, 0x01, 0x01, 0x50];
        expected.extend_from_slice(&reply.nonce);
        expected.extend_from_slice(&[0x02, 0x00, 0x03, 0xa7, 0x00, 0x01, 0x01, 0x58, 0x20]);
        let allocation = reply.allocation.as_ref().unwrap();
        expected.extend_from_slice(&allocation.wg_pub);
        expected.extend_from_slice(&[0x02, 0x50]);
        expected.extend_from_slice(&allocation.native_ipv6);
        expected.extend_from_slice(&[0x03, 0x50]);
        expected.extend_from_slice(&allocation.translated_ipv6);
        expected.extend_from_slice(&[0x04, 0x50]);
        expected.extend_from_slice(&allocation.name_salt);
        expected.extend_from_slice(&[0x05, 0x05, 0x06, 0x6a]);
        expected.extend_from_slice(allocation.dns_root.as_bytes());
        assert_eq!(encoded, expected);
        assert_eq!(MeshV2Registered::decode(&encoded).unwrap(), reply);
    }

    #[test]
    fn v2_registered_response_rejects_partial_or_unverified_allocations() {
        let unavailable = MeshV2Registered {
            nonce: [0x11; 16],
            status: MeshV2RegistrationStatus::Unavailable,
            allocation: None,
        };
        assert_eq!(
            MeshV2Registered::decode(&unavailable.encode().unwrap()).unwrap(),
            unavailable
        );

        let partial = MeshV2Registered {
            nonce: [0x11; 16],
            status: MeshV2RegistrationStatus::Registered,
            allocation: None,
        };
        assert!(matches!(
            partial.encode(),
            Err(Error::Payload("v2 registration allocation status"))
        ));

        let mut bad_allocation = allocation([0x22; 32]);
        bad_allocation.native_ipv6[15] ^= 1;
        let unverified = MeshV2Registered {
            nonce: [0x11; 16],
            status: MeshV2RegistrationStatus::Registered,
            allocation: Some(bad_allocation),
        };
        assert!(matches!(
            unverified.encode(),
            Err(Error::Payload("v2 allocation address"))
        ));

        let mut malformed = unavailable.encode().unwrap();
        malformed[22] = 4;
        assert!(matches!(
            MeshV2Registered::decode(&malformed),
            Err(Error::Payload("unknown v2 registration status"))
        ));
    }
}
