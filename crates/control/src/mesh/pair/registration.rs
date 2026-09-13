//! WG private-key possession before allocating a permanent node identity.

use super::*;

record!(MeshV2RegistrationBegin {
    1_u64 => node: MeshV2NodeIdentity, 2_u64 => request_id: [u8; 16],
    3_u64 => cookie: Option<[u8; 16]>,
});
impl MeshV2RegistrationBegin {
    pub const API: &'static str = "mesh.v2.registration.begin";
    fn validate(&self) -> Result<(), Error> {
        self.node.validate()?;
        if self.request_id == [0; 16] {
            return Err(Error::Payload("registration request identifier"));
        }
        Ok(())
    }
}

record!(MeshV2RegistrationChallenge {
    1_u64 => nonce: [u8; 16], 2_u64 => realm: [u8; 32],
    3_u64 => node: MeshV2NodeIdentity, 4_u64 => request_id: [u8; 16],
    5_u64 => relay_ephemeral_wg: [u8; 32], 6_u64 => challenge: [u8; 32],
    7_u64 => issued_at: u64, 8_u64 => expires_at: u64,
});
impl MeshV2RegistrationChallenge {
    pub const API: &'static str = "mesh.v2.registration.challenge";
    fn validate(&self) -> Result<(), Error> {
        self.node.validate()?;
        if self.realm == [0; 32]
            || self.request_id == [0; 16]
            || self.relay_ephemeral_wg == [0; 32]
            || self.challenge == [0; 32]
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 60
        {
            return Err(Error::Payload("registration challenge binding"));
        }
        Ok(())
    }

    /// Correlate a signed, pinned relay response before performing key agreement.
    pub fn verify_begin(
        &self,
        begin: &MeshV2RegistrationBegin,
        nonce: &[u8; 16],
        realm: &[u8; 32],
        now: u64,
    ) -> Result<(), Error> {
        self.validate()?;
        begin.validate()?;
        if self.nonce != *nonce
            || self.realm != *realm
            || self.node != begin.node
            || self.request_id != begin.request_id
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(Error::Payload("registration challenge correlation"));
        }
        Ok(())
    }

    /// The response nonce correlates carrier retries; the stable request ID binds this proof.
    /// Verify the relay's enclosing signature and pinned realm before using its DH key.
    pub fn proof_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut input = b"nsmesh-v2-registration-wg-proof\0".to_vec();
        MESH_V2_PAIR_SCHEMA.sign_into(&mut input);
        self.realm.sign_into(&mut input);
        self.node.sign_into(&mut input);
        self.request_id.sign_into(&mut input);
        self.relay_ephemeral_wg.sign_into(&mut input);
        self.challenge.sign_into(&mut input);
        self.issued_at.sign_into(&mut input);
        self.expires_at.sign_into(&mut input);
        Ok(input)
    }

    /// Compute using X25519(local WG private key, verified relay ephemeral public key).
    /// Never accept the agreement secret from the network.
    pub fn prove(&self, shared_secret: &[u8; 32]) -> Result<[u8; 32], Error> {
        if *shared_secret == [0; 32] {
            return Err(Error::Payload("invalid registration WG agreement"));
        }
        let tag = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, shared_secret),
            &self.proof_input()?,
        );
        let mut proof = [0; 32];
        proof.copy_from_slice(tag.as_ref());
        Ok(proof)
    }

    /// The registry supplies its locally computed agreement secret and current time.
    pub fn verify_proof(
        &self,
        proof: &[u8; 32],
        shared_secret: &[u8; 32],
        now: u64,
    ) -> Result<(), Error> {
        if now < self.issued_at || now >= self.expires_at || *shared_secret == [0; 32] {
            return Err(Error::Payload("registration WG proof lifetime or key"));
        }
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, shared_secret),
            &self.proof_input()?,
            proof,
        )
        .map_err(|_| Error::Payload("registration WG proof mismatch"))
    }
}

record!(MeshV2RegistrationFinish {
    1_u64 => node: MeshV2NodeIdentity, 2_u64 => request_id: [u8; 16],
    3_u64 => challenge: [u8; 32], 4_u64 => wg_proof: [u8; 32],
    5_u64 => cookie: Option<[u8; 16]>,
});
impl MeshV2RegistrationFinish {
    pub const API: &'static str = "mesh.v2.registration.finish";
    fn validate(&self) -> Result<(), Error> {
        self.node.validate()?;
        if self.request_id == [0; 16] || self.challenge == [0; 32] || self.wg_proof == [0; 32] {
            return Err(Error::Payload("registration finish binding"));
        }
        Ok(())
    }
}
