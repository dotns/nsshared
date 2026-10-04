//! Mailbox and registry payloads with field validation on decode (rendezvous §5.1, §5.2;
//! quick-v2 §7.2).
//!
//! Byte strings are unpadded base64url (rendezvous §3) and integers are exact JSON
//! numbers; floats and negatives are rejected. Every field is required, `null` included.

use crate::rendezvous::{
    limits::{
        DIGITS_LEN, MAILBOX_ID_BYTES, MAX_CANDIDATES, MAX_DATA_BYTES, MAX_INTRO_BYTES,
        MAX_TTL_SECONDS, MAX_UNACKED_MESSAGES, MAX_WAIT_MS, MIN_CANDIDATES, MIN_TTL_SECONDS,
    },
    transport::{self, Object},
};
use crate::{constants::MAX_NODE_RECORD_BYTES, constants::NODE_ID_BYTES};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Maximum `kind` length in bytes (rendezvous §5.1).
pub const MAX_KIND_BYTES: usize = 32;

/// A payload field outside its rendezvous §5.1-§5.2 or quick-v2 §7.2 rule.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum MessageError {
    /// `kind` is not `[a-z0-9-]{1,32}`.
    #[error("kind must be [a-z0-9-]{{1,{MAX_KIND_BYTES}}}")]
    Kind,
    /// The digits are not exactly 8 ASCII digits.
    #[error("digits must be exactly {DIGITS_LEN} ASCII digits")]
    Digits,
    /// `admission` is not `first` or `owner`.
    #[error("admission must be first or owner")]
    Admission,
    /// `dns` is not `none`, `address` or `record`.
    #[error("dns must be none, address or record")]
    Dns,
    /// `stage` is not `open`, `admitted` or `closing`.
    #[error("stage must be open, admitted or closing")]
    Stage,
    /// `ttl` is outside 1..=900 seconds.
    #[error("ttl must be {MIN_TTL_SECONDS}..={MAX_TTL_SECONDS} seconds")]
    Ttl,
    /// `candidates` is outside 1..=4.
    #[error("candidates must be {MIN_CANDIDATES}..={MAX_CANDIDATES}")]
    Candidates,
    /// `admission = first` with `candidates` other than 1.
    #[error("admission first requires candidates 1")]
    FirstAdmission,
    /// `wait_ms` exceeds 20 000.
    #[error("wait_ms must be at most {MAX_WAIT_MS}")]
    WaitMs,
    /// A message `seq` is 0; sequence numbers start at 1.
    #[error("seq must be at least 1")]
    Seq,
    /// More `waiting` entries than the candidate limit.
    #[error("at most {MAX_CANDIDATES} waiting candidates")]
    Waiting,
    /// More messages than the unacknowledged-message limit.
    #[error("at most {MAX_UNACKED_MESSAGES} messages")]
    Messages,
}

/// An application label, `[a-z0-9-]{1,32}`; agreed by the two sides, never allow-listed
/// by the relay (rendezvous §5.1).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Kind(String);

impl Kind {
    /// Parses a kind (rendezvous §5.1).
    ///
    /// # Errors
    ///
    /// [`MessageError::Kind`].
    pub fn parse(text: &str) -> Result<Self, MessageError> {
        if text.is_empty()
            || text.len() > MAX_KIND_BYTES
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(MessageError::Kind);
        }
        Ok(Self(text.to_owned()))
    }

    /// Returns the kind text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Kind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Kind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// How candidates become the peer (rendezvous §5.1).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", try_from = "String")]
pub enum Admission {
    /// The first joiner is admitted immediately; `candidates` is 1.
    First,
    /// The owner admits a waiting candidate.
    Owner,
}

/// The public DNS publication level of a registry record (quick-v2 §7.2, §11.2).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", try_from = "String")]
pub enum DnsPublication {
    /// Not published; the record is only found by exact `lookup_node` (the default).
    #[default]
    None,
    /// Only `<node id>.n.ns.io AAAA N6` is published; the AAAA is unauthenticated.
    Address,
    /// The AAAA and the TXT carrying the whole record are published.
    Record,
}

impl DnsPublication {
    /// The `dns_u8` of the publish proof: 0, 1 or 2 (quick-v2 §7.2).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Address => 1,
            Self::Record => 2,
        }
    }

    /// Whether the AAAA is published.
    #[must_use]
    pub const fn publishes_address(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether the TXT record is published.
    #[must_use]
    pub const fn publishes_record(self) -> bool {
        matches!(self, Self::Record)
    }
}

impl TryFrom<String> for DnsPublication {
    type Error = MessageError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        match text.as_str() {
            "none" => Ok(Self::None),
            "address" => Ok(Self::Address),
            "record" => Ok(Self::Record),
            _ => Err(MessageError::Dns),
        }
    }
}

/// The mailbox stage (rendezvous §5.1, §5.3).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", try_from = "String")]
pub enum Stage {
    /// Findable by its digits and accepting candidates.
    Open,
    /// A peer is admitted; messages flow.
    Admitted,
    /// Closed by one side; the other may still drain its queue.
    Closing,
}

impl TryFrom<String> for Admission {
    type Error = MessageError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        match text.as_str() {
            "first" => Ok(Self::First),
            "owner" => Ok(Self::Owner),
            _ => Err(MessageError::Admission),
        }
    }
}

impl TryFrom<String> for Stage {
    type Error = MessageError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        match text.as_str() {
            "open" => Ok(Self::Open),
            "admitted" => Ok(Self::Admitted),
            "closing" => Ok(Self::Closing),
            _ => Err(MessageError::Stage),
        }
    }
}

/// A 16-byte mailbox id generated by the broker (rendezvous §5.1).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MailboxId(#[serde(with = "transport::bytes")] pub [u8; MAILBOX_ID_BYTES]);

/// The 8 lookup digits, leading zeros kept; a JSON string on the wire (rendezvous §5.1).
///
/// Digits only locate a mailbox and never authorize, but they are kept out of logs:
/// `Debug` is redacted and the bytes are zeroized on drop. `Hash` lets a broker key its
/// lookup index by digits.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Digits([u8; DIGITS_LEN]);

impl Digits {
    /// Parses exactly 8 ASCII digits (rendezvous §5.1).
    ///
    /// # Errors
    ///
    /// [`MessageError::Digits`].
    pub fn parse(text: &str) -> Result<Self, MessageError> {
        let bytes: [u8; DIGITS_LEN] = text
            .as_bytes()
            .try_into()
            .map_err(|_| MessageError::Digits)?;
        if !bytes.iter().all(u8::is_ascii_digit) {
            return Err(MessageError::Digits);
        }
        Ok(Self(bytes))
    }

    /// Returns the digits text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl fmt::Debug for Digits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Digits(..)")
    }
}

impl Drop for Digits {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for Digits {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Digits {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        Self::parse(&text).map_err(D::Error::custom)
    }
}

/// `open {kind, ttl, admission, candidates, intro}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "OpenFields")]
pub struct OpenRequest {
    /// Application label.
    pub kind: Kind,
    /// Lifetime in seconds, 1..=900.
    pub ttl: u64,
    /// Admission mode.
    pub admission: Admission,
    /// Concurrent waiting candidates, 1..=4; 1 when `admission = first`.
    pub candidates: u8,
    /// The owner's introduction payload, at most 4 KiB, may be empty.
    #[serde(serialize_with = "transport::byte_vec::serialize")]
    pub intro: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenFields {
    kind: Kind,
    #[serde(deserialize_with = "ttl")]
    ttl: u64,
    admission: Admission,
    #[serde(deserialize_with = "candidates")]
    candidates: u8,
    #[serde(deserialize_with = "intro")]
    intro: Vec<u8>,
}

impl TryFrom<OpenFields> for OpenRequest {
    type Error = MessageError;

    fn try_from(fields: OpenFields) -> Result<Self, Self::Error> {
        if fields.admission == Admission::First && fields.candidates != 1 {
            return Err(MessageError::FirstAdmission);
        }
        Ok(Self {
            kind: fields.kind,
            ttl: fields.ttl,
            admission: fields.admission,
            candidates: fields.candidates,
            intro: fields.intro,
        })
    }
}

/// `join {id, intro}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    /// Mailbox id.
    pub id: MailboxId,
    /// The joiner's introduction payload, at most 4 KiB.
    #[serde(
        serialize_with = "transport::byte_vec::serialize",
        deserialize_with = "intro"
    )]
    pub intro: Vec<u8>,
}

/// `admit {id, actor}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitRequest {
    /// Mailbox id.
    pub id: MailboxId,
    /// The waiting candidate to admit.
    #[serde(with = "transport::bytes")]
    pub actor: [u8; 32],
}

/// `reject {id, actor}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectRequest {
    /// Mailbox id.
    pub id: MailboxId,
    /// The candidate to remove or the peer to evict.
    #[serde(with = "transport::bytes")]
    pub actor: [u8; 32],
}

/// `send {id, data}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    /// Mailbox id.
    pub id: MailboxId,
    /// Opaque message, at most 8 KiB.
    #[serde(
        serialize_with = "transport::byte_vec::serialize",
        deserialize_with = "data"
    )]
    pub data: Vec<u8>,
}

/// `recv {id, after, wait_ms}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecvRequest {
    /// Mailbox id.
    pub id: MailboxId,
    /// Return messages with `seq > after`, acknowledging the earlier ones.
    pub after: u64,
    /// Long-poll time in milliseconds, 0..=20 000.
    #[serde(deserialize_with = "wait_ms")]
    pub wait_ms: u64,
}

/// `close {id}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloseRequest {
    /// Mailbox id.
    pub id: MailboxId,
}

/// `opened {id, digits, expires}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Opened {
    /// Mailbox id.
    pub id: MailboxId,
    /// Lookup digits.
    pub digits: Digits,
    /// Absolute expiry, Unix seconds.
    pub expires: u64,
}

/// `found {id, kind, expires, intro}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Found {
    /// Mailbox id.
    pub id: MailboxId,
    /// Application label.
    pub kind: Kind,
    /// Absolute expiry, Unix seconds.
    pub expires: u64,
    /// The owner's introduction payload.
    #[serde(
        serialize_with = "transport::byte_vec::serialize",
        deserialize_with = "intro"
    )]
    pub intro: Vec<u8>,
}

/// `sent {seq}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sent {
    /// Sequence number of the queued message, from 1 per direction.
    #[serde(deserialize_with = "seq")]
    pub seq: u64,
}

/// A waiting candidate in a `mailbox` view (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Waiting {
    /// Candidate actor.
    #[serde(with = "transport::bytes")]
    pub actor: [u8; 32],
    /// The candidate's introduction payload.
    #[serde(
        serialize_with = "transport::byte_vec::serialize",
        deserialize_with = "intro"
    )]
    pub intro: Vec<u8>,
}

/// A message in a `mailbox` view (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxMessage {
    /// Sequence number, from 1 per direction.
    #[serde(deserialize_with = "seq")]
    pub seq: u64,
    /// Opaque message.
    #[serde(
        serialize_with = "transport::byte_vec::serialize",
        deserialize_with = "data"
    )]
    pub data: Vec<u8>,
}

/// `mailbox {stage, waiting, peer, messages}` (rendezvous §5.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxView {
    /// Current stage.
    pub stage: Stage,
    /// Waiting candidates; empty unless the requester is the owner.
    #[serde(deserialize_with = "waiting")]
    pub waiting: Vec<Waiting>,
    /// The admitted peer actor, or `null`.
    #[serde(with = "transport::option_bytes")]
    pub peer: Option<[u8; 32]>,
    /// Messages to the requester with `seq > after`.
    #[serde(deserialize_with = "messages")]
    pub messages: Vec<MailboxMessage>,
}

/// `publish {record, dns, proof}` (quick-v2 §7.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    /// Canonical NodeRecord CBOR, at most 600 bytes; decoded by the registry module.
    #[serde(
        serialize_with = "transport::byte_vec::serialize",
        deserialize_with = "record"
    )]
    pub record: Vec<u8>,
    /// The public DNS publication level; `none` when omitted.
    #[serde(default)]
    pub dns: DnsPublication,
    /// Registry publish proof signed by the record's `I`.
    #[serde(with = "transport::bytes")]
    pub proof: [u8; 64],
}

/// `published {expires}` (quick-v2 §7.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Published {
    /// The stored record's expiry, Unix seconds.
    pub expires: u64,
}

/// `lookup_node {node_id}`, the 12 raw node ID bytes (quick-v2 §7.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LookupNodeRequest {
    /// Full raw node ID.
    #[serde(with = "transport::bytes")]
    pub node_id: [u8; NODE_ID_BYTES],
}

/// `record {record}`: canonical NodeRecord CBOR, or `null` (quick-v2 §7.2).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordResult {
    /// The unexpired record, or `None`.
    #[serde(
        serialize_with = "optional_bytes",
        deserialize_with = "optional_record"
    )]
    pub record: Option<Vec<u8>>,
}

fn ttl<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let ttl = u64::deserialize(deserializer)?;
    if (MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl) {
        Ok(ttl)
    } else {
        Err(D::Error::custom(MessageError::Ttl))
    }
}

fn candidates<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    let candidates = u8::deserialize(deserializer)?;
    if (MIN_CANDIDATES..=MAX_CANDIDATES).contains(&candidates) {
        Ok(candidates)
    } else {
        Err(D::Error::custom(MessageError::Candidates))
    }
}

fn wait_ms<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let wait_ms = u64::deserialize(deserializer)?;
    if wait_ms <= MAX_WAIT_MS {
        Ok(wait_ms)
    } else {
        Err(D::Error::custom(MessageError::WaitMs))
    }
}

fn seq<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let seq = u64::deserialize(deserializer)?;
    if seq == 0 {
        Err(D::Error::custom(MessageError::Seq))
    } else {
        Ok(seq)
    }
}

fn intro<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    transport::deserialize_bytes_up_to(deserializer, MAX_INTRO_BYTES)
}

fn data<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    transport::deserialize_bytes_up_to(deserializer, MAX_DATA_BYTES)
}

fn record<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    transport::deserialize_bytes_up_to(deserializer, MAX_NODE_RECORD_BYTES)
}

fn optional_record<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    #[derive(Deserialize)]
    #[serde(transparent)]
    struct Record(#[serde(deserialize_with = "record")] Vec<u8>);
    Ok(Option::<Record>::deserialize(deserializer)?.map(|record| record.0))
}

fn optional_bytes<S: Serializer>(
    value: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(bytes) => transport::byte_vec::serialize(bytes, serializer),
        None => serializer.serialize_none(),
    }
}

fn waiting<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Waiting>, D::Error> {
    let waiting: Vec<Waiting> = Vec::<Object<Waiting>>::deserialize(deserializer)?
        .into_iter()
        .map(|object| object.0)
        .collect();
    if waiting.len() <= usize::from(MAX_CANDIDATES) {
        Ok(waiting)
    } else {
        Err(D::Error::custom(MessageError::Waiting))
    }
}

fn messages<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<MailboxMessage>, D::Error> {
    let messages: Vec<MailboxMessage> = Vec::<Object<MailboxMessage>>::deserialize(deserializer)?
        .into_iter()
        .map(|object| object.0)
        .collect();
    if messages.len() <= MAX_UNACKED_MESSAGES {
        Ok(messages)
    } else {
        Err(D::Error::custom(MessageError::Messages))
    }
}
