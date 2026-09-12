use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::MAX_SYNC_OWNERS;
use crate::mesh::{
    AuthenticatedOwnerRecord, AuthenticatedRecord, CommitReceipt, CompactState, Error, Genesis,
    OwnerRecordKind,
};

/// Hashes authenticated, contiguous history. Membership reduction and durable publication
/// remain separate: this value alone never establishes authority, synchronization or Ready.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncHistoryDigest {
    network_pub: [u8; 32],
    relay_key: [u8; 32],
    seq: u64,
    digest: [u8; 32],
}

impl SyncHistoryDigest {
    pub fn from_genesis(
        genesis: &Genesis<'_>,
        receipt: &CommitReceipt,
        relay_key: &[u8; 32],
    ) -> Result<Self, Error> {
        genesis.verify_receipt(receipt, relay_key)?;
        let network_pub = genesis.state().network_pub;
        let mut hash = Sha256::new();
        hash.update(b"nsmesh-history-genesis-v1\0");
        hash.update(network_pub);
        hash.update(Sha256::digest(genesis.original()));
        hash.update(Sha256::digest(receipt.encode()?));
        Ok(Self {
            network_pub,
            relay_key: *relay_key,
            seq: 0,
            digest: hash.finalize().into(),
        })
    }

    pub fn advance(&self, record: &AuthenticatedRecord<'_>) -> Result<Self, Error> {
        let seq = self
            .seq
            .checked_add(1)
            .ok_or(Error::Payload("sync history sequence overflow"))?;
        let receipt = record.receipt();
        if receipt.network_pub != self.network_pub || receipt.seq != seq {
            return Err(Error::Payload("sync history context"));
        }
        receipt.verify(&self.relay_key)?;
        let mut hash = Sha256::new();
        hash.update(b"nsmesh-history-record-v1\0");
        hash.update(self.digest);
        hash.update(seq.to_be_bytes());
        hash.update(Sha256::digest(record.original()));
        hash.update(Sha256::digest(receipt.encode()?));
        Ok(Self {
            seq,
            digest: hash.finalize().into(),
            ..self.clone()
        })
    }

    pub fn network_pub(&self) -> &[u8; 32] {
        &self.network_pub
    }

    pub const fn seq(&self) -> u64 {
        self.seq
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Hash a caller-selected winner set, never merge or authorize it. Revalidate the authenticated
/// originals against this exact membership snapshot so old WG/incarnation bindings cannot leak in.
pub fn sync_owners_digest(
    state: &CompactState,
    winners: &[AuthenticatedOwnerRecord<'_>],
) -> Result<[u8; 32], Error> {
    state.validate()?;
    if winners.len() > MAX_SYNC_OWNERS {
        return Err(Error::TooLarge);
    }
    let mut ordered = BTreeMap::new();
    for winner in winners {
        let checked = AuthenticatedOwnerRecord::verify(winner.original(), state)?;
        let _ = checked.supersedes(winner)?;
        let kind = match checked.kind() {
            OwnerRecordKind::Address => 0_u8,
            OwnerRecordKind::Capability => 1,
        };
        let key = (*checked.owner_pub(), checked.incarnation(), kind);
        if ordered.insert(key, checked).is_some() {
            return Err(Error::Payload("duplicate sync owner winner"));
        }
    }
    let mut hash = Sha256::new();
    hash.update(b"nsmesh-owner-snapshot-v1\0");
    hash.update(state.network_pub);
    hash.update((ordered.len() as u32).to_be_bytes());
    for ((owner, incarnation, kind), record) in ordered {
        let member = state
            .members
            .get(&owner)
            .ok_or(Error::Payload("sync owner membership"))?;
        hash.update(owner);
        hash.update(member.wg_pub);
        hash.update(incarnation.to_be_bytes());
        hash.update([kind]);
        hash.update(record.timestamp().to_be_bytes());
        hash.update(record.digest());
    }
    Ok(hash.finalize().into())
}
