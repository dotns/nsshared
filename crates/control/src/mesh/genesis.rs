use std::collections::{BTreeMap, BTreeSet};

use crate::envelope::ControlEnvelope;

use super::{
    CommitReceipt, CompactMember, CompactState, Error, Register, verify_historical_request,
};

/// Verified creation material, not permission to replace an existing network or anchor.
/// Live creation checks and durable publication remain the relay owner's responsibility.
pub struct Genesis<'a> {
    original: &'a [u8],
    creator: [u8; 32],
    creation_id: [u8; 16],
    state: CompactState,
}

impl<'a> Genesis<'a> {
    pub fn from_register(original: &'a [u8], network_pub: &[u8; 32]) -> Result<Self, Error> {
        if original.is_empty() || original.len() > 1200 {
            return Err(Error::TooLarge);
        }
        let mut remaining = original;
        let envelope: ControlEnvelope =
            ciborium::de::from_reader_with_recursion_limit(&mut remaining, 16)
                .map_err(|_| Error::Payload("genesis envelope encoding"))?;
        if !remaining.is_empty() || envelope.api != Register::API {
            return Err(Error::Payload("genesis envelope kind or trailing data"));
        }
        verify_historical_request(&envelope)?;
        let register = Register::decode(&envelope.payload)?;
        if register.network_pub != *network_pub || register.member_incarnation != 1 {
            return Err(Error::Payload("genesis network or incarnation"));
        }
        register.verify_network_proof(&envelope.nonce, &envelope.machine_key_pub)?;
        let state = CompactState {
            network_pub: *network_pub,
            seq: 0,
            members: BTreeMap::from([(
                envelope.machine_key_pub,
                CompactMember {
                    wg_pub: register.wg_pub,
                    incarnation: 1,
                },
            )]),
            admins_revision: 0,
            admins: BTreeSet::new(),
            evicted_through: BTreeMap::new(),
        };
        state.validate()?;
        Ok(Self {
            original,
            creator: envelope.machine_key_pub,
            creation_id: envelope.nonce,
            state,
        })
    }

    pub fn original(&self) -> &'a [u8] {
        self.original
    }
    pub fn creator(&self) -> &[u8; 32] {
        &self.creator
    }
    pub fn creation_id(&self) -> &[u8; 16] {
        &self.creation_id
    }
    pub fn state(&self) -> &CompactState {
        &self.state
    }

    /// Genesis receipts bind the canonical initial state, unlike management original digests.
    /// Historical verification deliberately does not apply today's expiry or nonce cache.
    pub fn verify_receipt(
        &self,
        receipt: &CommitReceipt,
        relay_key: &[u8; 32],
    ) -> Result<(), Error> {
        if receipt.network_pub != self.state.network_pub
            || receipt.seq != 0
            || receipt.author_pub != self.creator
            || receipt.op_id != self.creation_id
            || receipt.record_digest != self.state.digest()?
        {
            return Err(Error::Payload("genesis receipt binding"));
        }
        receipt.verify(relay_key)
    }
}
