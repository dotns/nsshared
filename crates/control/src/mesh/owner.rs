use sha2::{Digest, Sha256};

use crate::envelope::ControlEnvelope;

use super::codec::payload;
use super::{
    CAPABILITY_EXIT, CompactState, Error, OverlayAddresses, derive_overlay_addresses,
    verify_historical_request,
};

payload!(AddressUpdate, "mesh.addr", {
    1_u64 => network_pub: [u8; 32], 2_u64 => member_incarnation: u64,
    3_u64 => v4_salt: u64,
});
payload!(CapabilityUpdate, "mesh.capability", {
    1_u64 => network_pub: [u8; 32], 2_u64 => member_incarnation: u64,
    3_u64 => capabilities: u64,
});

impl AddressUpdate {
    fn validate(&self) -> Result<(), Error> {
        if self.member_incarnation == 0 || u32::try_from(self.v4_salt).is_err() {
            return Err(Error::Payload("owner address incarnation or salt"));
        }
        Ok(())
    }
}

impl CapabilityUpdate {
    fn validate(&self) -> Result<(), Error> {
        if self.member_incarnation == 0 || self.capabilities & !CAPABILITY_EXIT != 0 {
            return Err(Error::Payload("owner capability incarnation or flags"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerRecordKind {
    Address,
    Capability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerContents {
    Address(OverlayAddresses),
    Capability(u64),
}

/// Peer-only historical records. Authentication binds the current incarnation and WG key;
/// it does not imply ledger freshness, business readiness or exit consent.
pub struct AuthenticatedOwnerRecord<'a> {
    original: &'a [u8],
    network_pub: [u8; 32],
    owner_pub: [u8; 32],
    wg_pub: [u8; 32],
    incarnation: u64,
    timestamp: u64,
    digest: [u8; 32],
    contents: OwnerContents,
}

impl<'a> AuthenticatedOwnerRecord<'a> {
    pub fn verify(original: &'a [u8], state: &CompactState) -> Result<Self, Error> {
        state.validate()?;
        if original.is_empty() || original.len() > 1200 {
            return Err(Error::TooLarge);
        }
        let mut remaining = original;
        let envelope: ControlEnvelope =
            ciborium::de::from_reader_with_recursion_limit(&mut remaining, 16)
                .map_err(|_| Error::Payload("owner envelope encoding"))?;
        if !remaining.is_empty() {
            return Err(Error::Payload("owner envelope trailing data"));
        }
        verify_historical_request(&envelope)?;
        let member = state
            .members
            .get(&envelope.machine_key_pub)
            .ok_or(Error::Payload("owner is not a current member"))?;
        let (network, incarnation, contents) = match envelope.api.as_str() {
            AddressUpdate::API => {
                let update = AddressUpdate::decode(&envelope.payload)?;
                let salt = u32::try_from(update.v4_salt)
                    .map_err(|_| Error::Payload("owner salt width"))?;
                (
                    update.network_pub,
                    update.member_incarnation,
                    OwnerContents::Address(derive_overlay_addresses(&member.wg_pub, salt)?),
                )
            }
            CapabilityUpdate::API => {
                let update = CapabilityUpdate::decode(&envelope.payload)?;
                (
                    update.network_pub,
                    update.member_incarnation,
                    OwnerContents::Capability(update.capabilities),
                )
            }
            _ => return Err(Error::Payload("owner record kind")),
        };
        if network != state.network_pub || incarnation != member.incarnation {
            return Err(Error::Payload("owner network or incarnation binding"));
        }
        Ok(Self {
            original,
            network_pub: network,
            owner_pub: envelope.machine_key_pub,
            wg_pub: member.wg_pub,
            incarnation,
            timestamp: envelope.ts,
            digest: Sha256::digest(original).into(),
            contents,
        })
    }

    pub fn original(&self) -> &'a [u8] {
        self.original
    }
    pub fn network_pub(&self) -> &[u8; 32] {
        &self.network_pub
    }
    pub fn owner_pub(&self) -> &[u8; 32] {
        &self.owner_pub
    }
    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn contents(&self) -> &OwnerContents {
        &self.contents
    }
    pub fn kind(&self) -> OwnerRecordKind {
        match self.contents {
            OwnerContents::Address(_) => OwnerRecordKind::Address,
            OwnerContents::Capability(_) => OwnerRecordKind::Capability,
        }
    }

    /// Compare only versions of the same owner/kind/incarnation. A caller changing membership
    /// must revalidate cached records, not carry a previous incarnation's capability forward.
    pub fn supersedes(&self, previous: &Self) -> Result<bool, Error> {
        if self.network_pub != previous.network_pub
            || self.owner_pub != previous.owner_pub
            || self.wg_pub != previous.wg_pub
            || self.incarnation != previous.incarnation
            || self.kind() != previous.kind()
        {
            return Err(Error::Payload("owner version scope mismatch"));
        }
        Ok((self.timestamp, self.digest) > (previous.timestamp, previous.digest))
    }
}
