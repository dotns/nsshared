//! Bounded node-PIN and directed pairing controls. All relay requests/responses
//! additionally require the existing authenticated ControlEnvelope carrier.

use super::*;

/// Explicit display is allowed; Debug always hides the PIN.
#[derive(Clone, PartialEq, Eq)]
pub struct MeshV2Pin(String);

impl std::fmt::Debug for MeshV2Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED PIN]")
    }
}

impl MeshV2Pin {
    pub fn new(value: String) -> Result<Self, Error> {
        let bytes = value.as_bytes();
        if bytes.len() != 11
            || bytes[2] != b'-'
            || !bytes[..2]
                .iter()
                .all(|b| b.is_ascii_uppercase() && *b != b'I' && *b != b'O')
            || !bytes[3..].iter().all(u8::is_ascii_digit)
        {
            return Err(Error::Payload("node PIN format"));
        }
        Ok(Self(value))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Field for MeshV2Pin {
    fn to_value(&self) -> Value {
        self.0.to_value()
    }
    fn from_value(value: Value) -> Result<Self, Error> {
        Self::new(String::from_value(value)?)
    }
    fn sign_into(&self, out: &mut Vec<u8>) {
        self.0.sign_into(out);
    }
}

record!(MeshV2NodePin {
    1_u64 => value: MeshV2Pin, 2_u64 => generation: [u8; 16], 3_u64 => expires_at: u64,
});
impl MeshV2NodePin {
    fn validate(&self) -> Result<(), Error> {
        if self.generation == [0; 16] || self.expires_at == 0 {
            return Err(Error::Payload("node PIN lifetime"));
        }
        Ok(())
    }
}

record!(MeshV2PinSet {
    1_u64 => realm: [u8; 32], 2_u64 => node: MeshV2NodeIdentity, 3_u64 => ttl_secs: u64,
});
impl MeshV2PinSet {
    pub const API: &'static str = "mesh.v2.pin.set";
    fn validate(&self) -> Result<(), Error> {
        self.node.validate()?;
        if self.realm == [0; 32] || self.ttl_secs > 3600 {
            return Err(Error::Payload("node PIN TTL"));
        }
        Ok(())
    }
}

record!(MeshV2PinResult {
    1_u64 => nonce: [u8; 16], 2_u64 => realm: [u8; 32], 3_u64 => pin: Option<MeshV2NodePin>,
});
impl MeshV2PinResult {
    pub const API: &'static str = "mesh.v2.pin.result";
    fn validate(&self) -> Result<(), Error> {
        if self.realm == [0; 32] {
            return Err(Error::Payload("node realm"));
        }
        self.pin.as_ref().map_or(Ok(()), MeshV2NodePin::validate)
    }
}

record!(MeshV2PairLookup {
    1_u64 => realm: [u8; 32], 2_u64 => node: MeshV2NodeIdentity,
    3_u64 => pin: MeshV2Pin, 4_u64 => request_id: [u8; 16],
    5_u64 => cookie: Option<[u8; 16]>,
});
impl MeshV2PairLookup {
    pub const API: &'static str = "mesh.v2.pair.lookup";
    fn validate(&self) -> Result<(), Error> {
        self.node.validate()?;
        if self.realm == [0; 32] || self.request_id == [0; 16] {
            return Err(Error::Payload("pair lookup binding"));
        }
        Ok(())
    }
}

record!(MeshV2PairTarget {
    1_u64 => nonce: [u8; 16], 2_u64 => realm: [u8; 32], 3_u64 => request_id: [u8; 16],
    4_u64 => target: MeshV2NodeIdentity, 5_u64 => pin_generation: [u8; 16],
    6_u64 => expires_at: u64, 7_u64 => allocation: MeshV2RegistrationAllocation,
});
impl MeshV2PairTarget {
    pub const API: &'static str = "mesh.v2.pair.target";
    fn validate(&self) -> Result<(), Error> {
        self.target.validate()?;
        self.allocation.validate()?;
        if self.target.wg_pub != self.allocation.wg_pub
            || self.realm == [0; 32]
            || self.request_id == [0; 16]
            || self.pin_generation == [0; 16]
            || self.expires_at == 0
        {
            return Err(Error::Payload("pair target binding"));
        }
        Ok(())
    }
}

// Applicant intent carries only its OWN generation. The answering endpoint
// supplies its independently retained generation in the signed offer.
record!(MeshV2PairRequest {
    1_u64 => realm: [u8; 32], 2_u64 => applicant: MeshV2NodeIdentity,
    3_u64 => target: MeshV2NodeIdentity, 4_u64 => operation_id: [u8; 16],
    5_u64 => applicant_generation: u64, 6_u64 => pin_generation: [u8; 16],
    7_u64 => issued_at: u64, 8_u64 => expires_at: u64, 9_u64 => signature: [u8; 64],
});
impl MeshV2PairRequest {
    pub const API: &'static str = "mesh.v2.pair.request";
    fn validate(&self) -> Result<(), Error> {
        self.applicant.validate()?;
        self.target.validate()?;
        if self.applicant.signing_pub == self.target.signing_pub
            || self.applicant.wg_pub == self.target.wg_pub
            || self.realm == [0; 32]
            || self.operation_id == [0; 16]
            || self.applicant_generation == 0
            || self.pin_generation == [0; 16]
            || !self
                .expires_at
                .checked_sub(self.issued_at)
                .is_some_and(|ttl| (1..=MESH_V2_PAIR_REQUEST_TTL).contains(&ttl))
        {
            return Err(Error::Payload("pair request binding or lifetime"));
        }
        Ok(())
    }
    pub fn signing_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut input = b"nsmesh-v2-pair-request\0".to_vec();
        self.realm.sign_into(&mut input);
        self.applicant.sign_into(&mut input);
        self.target.sign_into(&mut input);
        self.operation_id.sign_into(&mut input);
        self.applicant_generation.sign_into(&mut input);
        self.pin_generation.sign_into(&mut input);
        self.issued_at.sign_into(&mut input);
        self.expires_at.sign_into(&mut input);
        Ok(input)
    }
    pub fn verify(&self, now: u64) -> Result<(), Error> {
        self.validate()?;
        if now < self.issued_at || now >= self.expires_at {
            return Err(Error::Expired);
        }
        super::super::recovery::verify(
            &self.applicant.signing_pub,
            &self.signing_input()?,
            &self.signature,
        )
    }
}

record!(MeshV2PairOffer {
    1_u64 => binding: MeshV2PairBinding, 2_u64 => initiator: [u8; 32],
    3_u64 => pin_generation: [u8; 16], 4_u64 => issued_at: u64, 5_u64 => expires_at: u64,
    6_u64 => grant_signature: [u8; 64], 7_u64 => signature: [u8; 64],
});
impl MeshV2PairOffer {
    pub const API: &'static str = "mesh.v2.pair.offer";
    fn validate(&self) -> Result<(), Error> {
        self.binding.validate()?;
        self.binding.peer(&self.initiator)?;
        if self.pin_generation == [0; 16]
            || !self
                .expires_at
                .checked_sub(self.issued_at)
                .is_some_and(|ttl| (1..=MESH_V2_PAIR_REQUEST_TTL).contains(&ttl))
        {
            return Err(Error::Payload("pair offer lifetime"));
        }
        Ok(())
    }
    pub fn signing_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut input = b"nsmesh-v2-pair-offer\0".to_vec();
        self.binding.sign_into(&mut input);
        self.initiator.sign_into(&mut input);
        self.pin_generation.sign_into(&mut input);
        self.issued_at.sign_into(&mut input);
        self.expires_at.sign_into(&mut input);
        self.grant_signature.sign_into(&mut input);
        Ok(input)
    }
    pub fn verify(&self, now: u64) -> Result<(), Error> {
        self.validate()?;
        if now < self.issued_at || now >= self.expires_at {
            return Err(Error::Expired);
        }
        super::super::recovery::verify(
            &self.initiator,
            &self.binding.signing_input()?,
            &self.grant_signature,
        )?;
        super::super::recovery::verify(&self.initiator, &self.signing_input()?, &self.signature)
    }

    /// Match an answering endpoint's offer to the applicant's retained intent.
    /// `initiator` is the initiator of this offer, i.e. the request TARGET.
    pub fn verify_request(&self, request: &MeshV2PairRequest, now: u64) -> Result<(), Error> {
        request.verify(now)?;
        self.verify(now)?;
        let applicant_generation = if self.binding.first == request.applicant {
            self.binding.first_generation
        } else if self.binding.second == request.applicant {
            self.binding.second_generation
        } else {
            return Err(Error::Payload("pair offer applicant"));
        };
        if self.initiator != request.target.signing_pub
            || self.binding.peer(&request.applicant.signing_pub)? != &request.target
            || self.binding.realm != request.realm
            || self.binding.operation_id != request.operation_id
            || applicant_generation != request.applicant_generation
            || self.pin_generation != request.pin_generation
            || self.expires_at > request.expires_at
        {
            return Err(Error::Payload("pair offer request binding"));
        }
        Ok(())
    }
}

record!(MeshV2PairHello {
    1_u64 => realm: [u8; 32], 2_u64 => sender: MeshV2NodeIdentity,
    3_u64 => receiver: MeshV2NodeIdentity, 4_u64 => grant_digest: [u8; 32],
    5_u64 => challenge: [u8; 32], 6_u64 => signature: [u8; 64],
});
impl MeshV2PairHello {
    pub const API: &'static str = "mesh.v2.pair.hello";
    fn validate(&self) -> Result<(), Error> {
        self.sender.validate()?;
        self.receiver.validate()?;
        if self.sender.signing_pub == self.receiver.signing_pub
            || self.sender.wg_pub == self.receiver.wg_pub
            || self.realm == [0; 32]
            || self.challenge == [0; 32]
        {
            return Err(Error::Payload("pair hello binding"));
        }
        Ok(())
    }
    pub fn signing_input(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut input = b"nsmesh-v2-pair-hello\0".to_vec();
        self.realm.sign_into(&mut input);
        self.sender.sign_into(&mut input);
        self.receiver.sign_into(&mut input);
        self.grant_digest.sign_into(&mut input);
        self.challenge.sign_into(&mut input);
        Ok(input)
    }
    pub fn verify(&self, grant: &MeshV2PairGrant) -> Result<(), Error> {
        grant.verify()?;
        if self.realm != grant.binding.realm
            || self.grant_digest != grant.binding.digest()?
            || grant.binding.peer(&self.receiver.signing_pub)? != &self.sender
            || grant.binding.peer(&self.sender.signing_pub)? != &self.receiver
        {
            return Err(Error::Payload("pair hello grant binding"));
        }
        super::super::recovery::verify(
            &self.sender.signing_pub,
            &self.signing_input()?,
            &self.signature,
        )
    }
}

record!(MeshV2PairApproved {
    1_u64 => grant: MeshV2PairGrant,
});
impl MeshV2PairApproved {
    pub const API: &'static str = "mesh.v2.pair.approved";
    fn validate(&self) -> Result<(), Error> {
        self.grant.verify()
    }
}

record!(MeshV2PairRejected {
    1_u64 => operation_id: [u8; 16], 2_u64 => peer: [u8; 32], 3_u64 => reason: u64,
});
impl MeshV2PairRejected {
    pub const API: &'static str = "mesh.v2.pair.rejected";
    fn validate(&self) -> Result<(), Error> {
        if self.operation_id == [0; 16] || self.reason > 7 {
            return Err(Error::Payload("pair rejection"));
        }
        Ok(())
    }
}

impl MeshV2PairRevocation {
    pub const API: &'static str = "mesh.v2.pair.revoke";
}
impl MeshV2PairSession {
    pub const API: &'static str = "mesh.v2.pair.session";
}

record!(MeshV2PairPoll {
    1_u64 => realm: [u8; 32], 2_u64 => node: MeshV2NodeIdentity,
    3_u64 => acknowledged: Option<[u8; 16]>,
});
impl MeshV2PairPoll {
    pub const API: &'static str = "mesh.v2.pair.poll";
    fn validate(&self) -> Result<(), Error> {
        self.node.validate()?;
        if self.realm == [0; 32] {
            return Err(Error::Payload("node realm"));
        }
        Ok(())
    }
}

record!(MeshV2PairDelivery {
    1_u64 => nonce: [u8; 16], 2_u64 => delivery_id: Option<[u8; 16]>,
    3_u64 => original: Option<Vec<u8>>,
});
impl MeshV2PairDelivery {
    pub const API: &'static str = "mesh.v2.pair.delivery";
    fn validate(&self) -> Result<(), Error> {
        if self.delivery_id.is_some() != self.original.is_some()
            || self
                .original
                .as_ref()
                .is_some_and(|bytes| bytes.is_empty() || bytes.len() > 850)
        {
            return Err(Error::Payload("pair delivery bounds"));
        }
        Ok(())
    }
}

record!(MeshV2PairDirectoryQuery {
    1_u64 => realm: [u8; 32], 2_u64 => node: MeshV2NodeIdentity,
    3_u64 => target: MeshV2NodeIdentity, 4_u64 => grant_digest: [u8; 32],
});
impl MeshV2PairDirectoryQuery {
    pub const API: &'static str = "mesh.v2.pair.directory";
    fn validate(&self) -> Result<(), Error> {
        self.node.validate()?;
        self.target.validate()?;
        if self.realm == [0; 32]
            || self.grant_digest == [0; 32]
            || self.node.signing_pub == self.target.signing_pub
            || self.node.wg_pub == self.target.wg_pub
        {
            return Err(Error::Payload("pair directory identity binding"));
        }
        Ok(())
    }

    /// This authenticates the exact pair; the owner also checks its current revocation floors.
    pub fn verify_grant(&self, grant: &MeshV2PairGrant) -> Result<(), Error> {
        self.validate()?;
        grant.verify()?;
        if self.realm != grant.binding.realm
            || self.grant_digest != grant.binding.digest()?
            || grant.binding.peer(&self.node.signing_pub)? != &self.target
            || grant.binding.peer(&self.target.signing_pub)? != &self.node
        {
            return Err(Error::Payload("pair directory grant mismatch"));
        }
        Ok(())
    }
}

record!(MeshV2PairDirectoryResult {
    1_u64 => nonce: [u8; 16], 2_u64 => realm: [u8; 32],
    3_u64 => target: MeshV2NodeIdentity, 4_u64 => grant_digest: [u8; 32],
    5_u64 => allocation: MeshV2RegistrationAllocation,
});
impl MeshV2PairDirectoryResult {
    pub const API: &'static str = "mesh.v2.pair.directory.result";
    fn validate(&self) -> Result<(), Error> {
        self.target.validate()?;
        self.allocation.validate()?;
        if self.realm == [0; 32]
            || self.grant_digest == [0; 32]
            || self.allocation.wg_pub != self.target.wg_pub
        {
            return Err(Error::Payload("pair directory allocation binding"));
        }
        Ok(())
    }

    /// Verify the enclosing pinned-relay signature before matching this response.
    /// Directory metadata never grants live session capabilities or business permission.
    pub fn verify_query(
        &self,
        query: &MeshV2PairDirectoryQuery,
        nonce: &[u8; 16],
    ) -> Result<(), Error> {
        self.validate()?;
        query.validate()?;
        if self.nonce != *nonce
            || self.realm != query.realm
            || self.target != query.target
            || self.grant_digest != query.grant_digest
        {
            return Err(Error::Payload("pair directory response mismatch"));
        }
        Ok(())
    }
}
