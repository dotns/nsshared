//! Bounded peer-only synchronization framing. Decoding never authenticates a ledger or grants Ready.

use ciborium::value::Value;

use super::codec::{self, Field};
use super::{CommitReceipt, Error, MAX_CONTROL_FRAME};

mod digest;
pub use digest::{SyncHistoryDigest, sync_owners_digest};

pub const MAX_SYNC_FRAME: usize = 65_536;
pub const MAX_SYNC_BODY: usize = MAX_SYNC_FRAME - 4;
pub const MAX_SYNC_PAGE: usize = 24;
pub const MAX_SYNC_OWNERS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncVersion {
    pub history_seq: u64,
    pub history_digest: [u8; 32],
    pub owners_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncSection {
    History,
    Owners,
}

impl SyncSection {
    const fn number(self) -> u64 {
        match self {
            Self::History => 0,
            Self::Owners => 1,
        }
    }

    fn from_number(value: u64) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::History),
            1 => Ok(Self::Owners),
            _ => Err(Error::Payload("sync section")),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncHistoryEntry {
    pub original: Vec<u8>,
    pub receipt: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncEntries {
    History(Vec<SyncHistoryEntry>),
    Owners(Vec<Vec<u8>>),
}

impl SyncEntries {
    pub const fn section(&self) -> SyncSection {
        match self {
            Self::History(_) => SyncSection::History,
            Self::Owners(_) => SyncSection::Owners,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::History(entries) => entries.len(),
            Self::Owners(entries) => entries.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncMessage {
    Digest {
        owner_count: u64,
    },
    Pull {
        request_id: u64,
        section: SyncSection,
        start: u64,
        limit: u64,
        base_history_digest: Option<[u8; 32]>,
    },
    Records {
        request_id: u64,
        start: u64,
        entries: SyncEntries,
        more: bool,
    },
    Done {
        token: [u8; 16],
    },
    DoneAck {
        token: [u8; 16],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncFrame {
    pub network_pub: [u8; 32],
    pub version: SyncVersion,
    pub message: SyncMessage,
}

/// Check a complete prefix before allocating its body. The four prefix bytes count toward 64 KiB.
pub fn decode_sync_length(prefix: [u8; 4]) -> Result<usize, Error> {
    let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| Error::TooLarge)?;
    if length == 0 {
        return Err(Error::Framing);
    }
    if length > MAX_SYNC_BODY {
        return Err(Error::TooLarge);
    }
    Ok(length)
}

impl SyncFrame {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let body = self.encode_body()?;
        let length = u32::try_from(body.len()).map_err(|_| Error::TooLarge)?;
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(&body);
        Ok(frame)
    }

    pub fn decode(frame: &[u8]) -> Result<Self, Error> {
        if frame.len() > MAX_SYNC_FRAME {
            return Err(Error::TooLarge);
        }
        let prefix = frame.get(..4).ok_or(Error::Framing)?;
        let length = decode_sync_length(prefix.try_into().map_err(|_| Error::Framing)?)?;
        if frame.len() - 4 != length {
            return Err(Error::Framing);
        }
        Self::decode_body(&frame[4..])
    }

    pub fn encode_body(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let kind: u64 = match self.message {
            SyncMessage::Digest { .. } => 0,
            SyncMessage::Pull { .. } => 1,
            SyncMessage::Records { .. } => 2,
            SyncMessage::Done { .. } => 3,
            SyncMessage::DoneAck { .. } => 4,
        };
        let mut fields = vec![
            (0_u64.to_value(), 1_u64.to_value()),
            (1_u64.to_value(), kind.to_value()),
            (2_u64.to_value(), self.network_pub.to_value()),
            (3_u64.to_value(), self.version.to_value()),
        ];
        let values = match &self.message {
            SyncMessage::Digest { owner_count } => vec![owner_count.to_value()],
            SyncMessage::Pull {
                request_id,
                section,
                start,
                limit,
                base_history_digest,
            } => vec![
                request_id.to_value(),
                section.number().to_value(),
                start.to_value(),
                limit.to_value(),
                base_history_digest.to_value(),
            ],
            SyncMessage::Records {
                request_id,
                start,
                entries,
                more,
            } => {
                let values = match entries {
                    SyncEntries::History(entries) => entries
                        .iter()
                        .map(|entry| {
                            Value::Array(vec![entry.original.to_value(), entry.receipt.to_value()])
                        })
                        .collect(),
                    SyncEntries::Owners(entries) => entries.iter().map(Field::to_value).collect(),
                };
                vec![
                    request_id.to_value(),
                    entries.section().number().to_value(),
                    start.to_value(),
                    Value::Array(values),
                    Value::Bool(*more),
                ]
            }
            SyncMessage::Done { token } | SyncMessage::DoneAck { token } => vec![token.to_value()],
        };
        for (index, value) in values.into_iter().enumerate() {
            fields.push(((index as u64 + 4).to_value(), value));
        }
        codec::encode_with_limit(&Value::Map(fields), MAX_SYNC_BODY)
    }

    pub fn decode_body(body: &[u8]) -> Result<Self, Error> {
        if body.is_empty() {
            return Err(Error::Framing);
        }
        let mut fields = codec::fields(codec::decode_with_limit(body, MAX_SYNC_BODY)?)?;
        let kind = codec::take::<u64>(&mut fields, 1)?;
        let network_pub = codec::take(&mut fields, 2)?;
        let version = codec::take(&mut fields, 3)?;
        let message = match kind {
            0 => SyncMessage::Digest {
                owner_count: codec::take(&mut fields, 4)?,
            },
            1 => SyncMessage::Pull {
                request_id: codec::take(&mut fields, 4)?,
                section: SyncSection::from_number(codec::take(&mut fields, 5)?)?,
                start: codec::take(&mut fields, 6)?,
                limit: codec::take(&mut fields, 7)?,
                base_history_digest: codec::take(&mut fields, 8)?,
            },
            2 => {
                let request_id = codec::take(&mut fields, 4)?;
                let section = SyncSection::from_number(codec::take(&mut fields, 5)?)?;
                let start = codec::take(&mut fields, 6)?;
                let Some(Value::Array(values)) = fields.remove(&7) else {
                    return Err(Error::Payload("sync entries array"));
                };
                if values.is_empty() || values.len() > MAX_SYNC_PAGE {
                    return Err(Error::Payload("sync page count"));
                }
                let entries = match section {
                    SyncSection::History => SyncEntries::History(
                        values
                            .into_iter()
                            .map(|value| {
                                let Value::Array(pair) = value else {
                                    return Err(Error::Payload("sync history pair"));
                                };
                                let [original, receipt]: [Value; 2] = pair
                                    .try_into()
                                    .map_err(|_| Error::Payload("sync history pair width"))?;
                                Ok(SyncHistoryEntry {
                                    original: Vec::<u8>::from_value(original)?,
                                    receipt: Vec::<u8>::from_value(receipt)?,
                                })
                            })
                            .collect::<Result<_, Error>>()?,
                    ),
                    SyncSection::Owners => SyncEntries::Owners(
                        values
                            .into_iter()
                            .map(Vec::<u8>::from_value)
                            .collect::<Result<_, _>>()?,
                    ),
                };
                let Some(Value::Bool(more)) = fields.remove(&8) else {
                    return Err(Error::Payload("sync more flag"));
                };
                SyncMessage::Records {
                    request_id,
                    start,
                    entries,
                    more,
                }
            }
            3 => SyncMessage::Done {
                token: codec::take(&mut fields, 4)?,
            },
            4 => SyncMessage::DoneAck {
                token: codec::take(&mut fields, 4)?,
            },
            _ => return Err(Error::Payload("sync message kind")),
        };
        let frame = Self {
            network_pub,
            version,
            message,
        };
        frame.validate()?;
        Ok(frame)
    }

    fn validate(&self) -> Result<(), Error> {
        match &self.message {
            SyncMessage::Digest { owner_count } => {
                if *owner_count > MAX_SYNC_OWNERS as u64 {
                    return Err(Error::Payload("sync owner count"));
                }
            }
            SyncMessage::Pull {
                request_id,
                section,
                start,
                limit,
                base_history_digest,
            } => {
                if *request_id == 0 || !(1..=MAX_SYNC_PAGE as u64).contains(limit) {
                    return Err(Error::Payload("sync request or page limit"));
                }
                match section {
                    SyncSection::History
                        if *start <= self.version.history_seq
                            && base_history_digest.is_some() == (*start > 0) => {}
                    SyncSection::Owners
                        if *start < MAX_SYNC_OWNERS as u64 && base_history_digest.is_none() => {}
                    _ => return Err(Error::Payload("sync pull range or base")),
                }
            }
            SyncMessage::Records {
                request_id,
                start,
                entries,
                more,
            } => {
                if *request_id == 0 || entries.is_empty() || entries.len() > MAX_SYNC_PAGE {
                    return Err(Error::Payload("sync response or page count"));
                }
                let last = start
                    .checked_add(entries.len() as u64 - 1)
                    .ok_or(Error::Payload("sync page range overflow"))?;
                match entries {
                    SyncEntries::History(entries) => {
                        if last > self.version.history_seq
                            || *more != (last < self.version.history_seq)
                        {
                            return Err(Error::Payload("sync history range or finality"));
                        }
                        for (offset, entry) in entries.iter().enumerate() {
                            bounded_original(&entry.original)?;
                            bounded_original(&entry.receipt)?;
                            let receipt = CommitReceipt::decode(&entry.receipt)?;
                            if receipt.network_pub != self.network_pub
                                || receipt.seq != start + offset as u64
                            {
                                return Err(Error::Payload("sync receipt range or network"));
                            }
                        }
                    }
                    SyncEntries::Owners(entries) => {
                        if last >= MAX_SYNC_OWNERS as u64
                            || (*more && last + 1 >= MAX_SYNC_OWNERS as u64)
                        {
                            return Err(Error::Payload("sync owner page range"));
                        }
                        for original in entries {
                            bounded_original(original)?;
                        }
                    }
                }
            }
            SyncMessage::Done { .. } | SyncMessage::DoneAck { .. } => {}
        }
        Ok(())
    }
}

fn bounded_original(bytes: &[u8]) -> Result<(), Error> {
    if bytes.is_empty() || bytes.len() > MAX_CONTROL_FRAME {
        return Err(Error::TooLarge);
    }
    Ok(())
}

impl Field for SyncVersion {
    fn to_value(&self) -> Value {
        Value::Map(vec![
            (0_u64.to_value(), 1_u64.to_value()),
            (1_u64.to_value(), self.history_seq.to_value()),
            (2_u64.to_value(), self.history_digest.to_value()),
            (3_u64.to_value(), self.owners_digest.to_value()),
        ])
    }

    fn from_value(value: Value) -> Result<Self, Error> {
        let mut fields = codec::fields(value)?;
        Ok(Self {
            history_seq: codec::take(&mut fields, 1)?,
            history_digest: codec::take(&mut fields, 2)?,
            owners_digest: codec::take(&mut fields, 3)?,
        })
    }

    fn sign_into(&self, out: &mut Vec<u8>) {
        self.history_seq.sign_into(out);
        self.history_digest.sign_into(out);
        self.owners_digest.sign_into(out);
    }
}
