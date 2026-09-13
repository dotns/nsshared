use ciborium::value::Value;

use super::codec::{Field, decode, encode, fields, take};
use super::recovery::verify;
use super::{Error, MESH_V2_REGISTER_API, mesh_v2_registration_proof_input};

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
}
