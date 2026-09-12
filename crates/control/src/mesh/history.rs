use sha2::{Digest, Sha256};

use crate::envelope::ControlEnvelope;

use super::{Accept, Admins, CommitReceipt, Error, Eviction, SignedManagementRecord, member_id};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementKind {
    Add,
    Evict,
    Admins,
}

#[derive(Clone, Debug)]
pub enum ManagementContents {
    Add(Box<Accept>),
    Evict(Eviction),
    Admins(Admins),
}

/// Authenticated history is not authorization. Apply against the preceding membership state.
pub struct AuthenticatedRecord<'a> {
    original: &'a [u8],
    receipt: CommitReceipt,
    contents: ManagementContents,
    issued_at: u64,
    expires_at: u64,
}

impl<'a> AuthenticatedRecord<'a> {
    pub fn verify(
        kind: ManagementKind,
        original: &'a [u8],
        receipt: &CommitReceipt,
        relay_key: &[u8; 32],
        network_pub: &[u8; 32],
        previous_seq: u64,
    ) -> Result<Self, Error> {
        // Every original first passed the v1 control budget; a ledger frame is not an escape.
        if original.is_empty() || original.len() > 1200 {
            return Err(Error::TooLarge);
        }
        let next_seq = previous_seq
            .checked_add(1)
            .ok_or(Error::Payload("management sequence overflow"))?;
        let digest: [u8; 32] = Sha256::digest(original).into();
        if receipt.network_pub != *network_pub
            || receipt.seq != next_seq
            || receipt.record_digest != digest
        {
            return Err(Error::Payload("history receipt binding"));
        }
        receipt.verify(relay_key)?;
        let (contents, author, network, op_id, issued_at, expires_at) = match kind {
            ManagementKind::Add => {
                let mut remaining = original;
                let envelope: ControlEnvelope =
                    ciborium::de::from_reader_with_recursion_limit(&mut remaining, 16)
                        .map_err(|_| Error::Payload("history envelope encoding"))?;
                if !remaining.is_empty() {
                    return Err(Error::Payload("history envelope trailing data"));
                }
                let add = Accept::verify_historical(&envelope)?;
                let fields = (
                    envelope.machine_key_pub,
                    add.network_pub,
                    add.request_id,
                    add.added_at,
                    add.expires_at,
                );
                (
                    ManagementContents::Add(Box::new(add)),
                    fields.0,
                    fields.1,
                    fields.2,
                    fields.3,
                    fields.4,
                )
            }
            ManagementKind::Evict | ManagementKind::Admins => {
                let record = SignedManagementRecord::decode(original)?;
                record.verify()?;
                let contents = match (kind, record.kind) {
                    (ManagementKind::Evict, SignedManagementRecord::EVICT) => {
                        let eviction = Eviction::decode(&record.body)?;
                        if member_id(&eviction.member_pub) != eviction.member_id {
                            return Err(Error::Payload("history member identity binding"));
                        }
                        ManagementContents::Evict(eviction)
                    }
                    (ManagementKind::Admins, SignedManagementRecord::ADMINS) => {
                        ManagementContents::Admins(Admins::decode(&record.body)?)
                    }
                    _ => return Err(Error::Payload("history record kind")),
                };
                (
                    contents,
                    record.author_pub,
                    record.network_pub,
                    record.op_id,
                    record.issued_at,
                    record.expires_at,
                )
            }
        };
        if author != receipt.author_pub || network != *network_pub || op_id != receipt.op_id {
            return Err(Error::Payload("history operation binding"));
        }
        Ok(Self {
            original,
            receipt: receipt.clone(),
            contents,
            issued_at,
            expires_at,
        })
    }

    pub fn original(&self) -> &'a [u8] {
        self.original
    }

    pub fn receipt(&self) -> &CommitReceipt {
        &self.receipt
    }

    pub fn contents(&self) -> &ManagementContents {
        &self.contents
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}
