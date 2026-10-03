//! `/rendezvous/v1` WebSocket framing: one JSON message per text frame (rendezvous §3, §5.2).
//!
//! Requests are `{"operation": <name>, "value": <payload>}` and responses
//! `{"result": <name>, "value": <payload>}`; both keys are always present and a
//! payload-less operation or result carries `"value": null`. Names are snake_case, unknown
//! and missing fields are rejected everywhere, and byte strings are unpadded base64url.
//! The size limit is checked before parsing.

use crate::{
    encoding::{decode_base64url, encode_base64url},
    rendezvous::{
        auth::{Challenge, Hello},
        directory::Directory,
        error::ErrorCode,
        limits,
        message::{
            AdmitRequest, CloseRequest, Digits, Found, JoinRequest, LookupNodeRequest, MailboxView,
            OpenRequest, Opened, PublishRequest, Published, RecordResult, RecvRequest,
            RejectRequest, SendRequest, Sent,
        },
    },
};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, Error as _},
    ser::SerializeMap,
};
use serde_json::value::RawValue;
use thiserror::Error;

/// WebSocket URL path, `wss://{authority}/rendezvous/v1` (rendezvous §3).
pub const PATH: &str = "/rendezvous/v1";
/// WebSocket subprotocol (rendezvous §3).
pub const SUBPROTOCOL: &str = "ns-rendezvous-v1";
/// Maximum JSON message size in bytes, checked before parsing (rendezvous §3, §6).
pub const MAX_MESSAGE_BYTES: usize = limits::MAX_MESSAGE_BYTES;

/// A request operation name (rendezvous §5.2).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", try_from = "String")]
pub enum Operation {
    /// `directory`: fetch the relay directory.
    Directory,
    /// `publish`: publish a NodeRecord to the registry (quick-v2 §7.2).
    Publish,
    /// `lookup_node`: look up a NodeRecord by node ID (quick-v2 §7.2).
    LookupNode,
    /// `hello`: bind the connection to an actor (rendezvous §4).
    Hello,
    /// `open`: create a mailbox.
    Open,
    /// `lookup`: find an open mailbox by its digits.
    Lookup,
    /// `join`: join a mailbox as a candidate.
    Join,
    /// `admit`: admit a candidate as the peer.
    Admit,
    /// `reject`: remove a candidate or evict the peer.
    Reject,
    /// `send`: queue a message for the other side.
    Send,
    /// `recv`: long-poll the mailbox view and messages.
    Recv,
    /// `close`: leave or close the mailbox.
    Close,
}

impl Operation {
    /// Returns the snake_case wire name (rendezvous §5.2).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::Publish => "publish",
            Self::LookupNode => "lookup_node",
            Self::Hello => "hello",
            Self::Open => "open",
            Self::Lookup => "lookup",
            Self::Join => "join",
            Self::Admit => "admit",
            Self::Reject => "reject",
            Self::Send => "send",
            Self::Recv => "recv",
            Self::Close => "close",
        }
    }

    /// Whether the connection must have sent `hello` first: false only for `directory`,
    /// `publish` and `lookup_node`; the mailbox `lookup` requires it (rendezvous §4, §5.2).
    #[must_use]
    pub const fn requires_hello(self) -> bool {
        !matches!(self, Self::Directory | Self::Publish | Self::LookupNode)
    }
}

/// A client request (rendezvous §5.2, quick-v2 §7.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    /// `directory`, value `null`.
    Directory,
    /// `publish {record, dns, proof}`.
    Publish(PublishRequest),
    /// `lookup_node {node_id}`.
    LookupNode(LookupNodeRequest),
    /// `hello {actor, signature}`.
    Hello(Hello),
    /// `open {kind, ttl, admission, candidates, intro}`.
    Open(OpenRequest),
    /// `lookup`, value the 8 digits as a JSON string.
    Lookup(Digits),
    /// `join {id, intro}`.
    Join(JoinRequest),
    /// `admit {id, actor}`.
    Admit(AdmitRequest),
    /// `reject {id, actor}`.
    Reject(RejectRequest),
    /// `send {id, data}`.
    Send(SendRequest),
    /// `recv {id, after, wait_ms}`.
    Recv(RecvRequest),
    /// `close {id}`.
    Close(CloseRequest),
}

impl Request {
    /// Returns the operation of this request.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        match self {
            Self::Directory => Operation::Directory,
            Self::Publish(_) => Operation::Publish,
            Self::LookupNode(_) => Operation::LookupNode,
            Self::Hello(_) => Operation::Hello,
            Self::Open(_) => Operation::Open,
            Self::Lookup(_) => Operation::Lookup,
            Self::Join(_) => Operation::Join,
            Self::Admit(_) => Operation::Admit,
            Self::Reject(_) => Operation::Reject,
            Self::Send(_) => Operation::Send,
            Self::Recv(_) => Operation::Recv,
            Self::Close(_) => Operation::Close,
        }
    }
}

/// A broker message: the initial `challenge` or the response to a request
/// (rendezvous §3, §5.2, §7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Response {
    /// `challenge {nonce, authority, capabilities}`, sent first on every connection.
    Challenge(Challenge),
    /// `directory`: the relay directory v2.
    Directory(Directory),
    /// `published {expires}`.
    Published(Published),
    /// `record {record}`.
    Record(RecordResult),
    /// `ok`, value `null`.
    Ok,
    /// `opened {id, digits, expires}`.
    Opened(Opened),
    /// `found {id, kind, expires, intro}`.
    Found(Found),
    /// `sent {seq}`.
    Sent(Sent),
    /// `mailbox {stage, waiting, peer, messages}`.
    Mailbox(MailboxView),
    /// `error`, value the error code.
    Error(ErrorCode),
}

#[derive(Clone, Copy, Deserialize)]
#[serde(try_from = "String")]
enum ResultName {
    Challenge,
    Directory,
    Published,
    Record,
    Ok,
    Opened,
    Found,
    Sent,
    Mailbox,
    Error,
}

impl TryFrom<String> for Operation {
    type Error = UnknownName;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Ok(match text.as_str() {
            "directory" => Self::Directory,
            "publish" => Self::Publish,
            "lookup_node" => Self::LookupNode,
            "hello" => Self::Hello,
            "open" => Self::Open,
            "lookup" => Self::Lookup,
            "join" => Self::Join,
            "admit" => Self::Admit,
            "reject" => Self::Reject,
            "send" => Self::Send,
            "recv" => Self::Recv,
            "close" => Self::Close,
            _ => return Err(UnknownName),
        })
    }
}

impl TryFrom<String> for ResultName {
    type Error = UnknownName;

    fn try_from(text: String) -> Result<Self, UnknownName> {
        Ok(match text.as_str() {
            "challenge" => Self::Challenge,
            "directory" => Self::Directory,
            "published" => Self::Published,
            "record" => Self::Record,
            "ok" => Self::Ok,
            "opened" => Self::Opened,
            "found" => Self::Found,
            "sent" => Self::Sent,
            "mailbox" => Self::Mailbox,
            "error" => Self::Error,
            _ => return Err(UnknownName),
        })
    }
}

/// An operation or result name that rendezvous §5.2 does not define.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("unknown operation or result name")]
pub struct UnknownName;

/// A JSON object decoded as `T`, rejecting the array form serde derives also accept for
/// structs (rendezvous §3).
pub(crate) struct Object<T>(pub(crate) T);

impl<'de, T: DeserializeOwned> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<RawValue>::deserialize(deserializer)?;
        object(&raw).map(Self).map_err(D::Error::custom)
    }
}

fn object<T: DeserializeOwned>(value: &RawValue) -> Result<T, serde_json::Error> {
    if !value.get().starts_with('{') {
        return Err(serde_json::Error::custom("expected a JSON object"));
    }
    serde_json::from_str(value.get())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest<'a> {
    operation: Operation,
    #[serde(borrow)]
    value: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawResponse<'a> {
    result: ResultName,
    #[serde(borrow)]
    value: &'a RawValue,
}

/// `{key: name, "value": value}` in that order.
struct Envelope<'a, T> {
    key: &'static str,
    name: &'static str,
    value: &'a T,
}

impl<T: Serialize> Serialize for Envelope<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry(self.key, self.name)?;
        map.serialize_entry("value", self.value)?;
        map.end()
    }
}

fn check_size(text: &str) -> Result<(), ErrorCode> {
    if text.len() > MAX_MESSAGE_BYTES {
        Err(ErrorCode::InvalidMessage)
    } else {
        Ok(())
    }
}

/// Rejects the array form serde derives also accept for the envelope struct.
fn check_object(text: &str) -> Result<(), ErrorCode> {
    if text.trim_start().starts_with('{') {
        Ok(())
    } else {
        Err(ErrorCode::InvalidMessage)
    }
}

fn envelope<T: Serialize>(
    key: &'static str,
    name: &'static str,
    value: &T,
) -> Result<String, ErrorCode> {
    let text = serde_json::to_string(&Envelope { key, name, value })
        .map_err(|_| ErrorCode::InvalidMessage)?;
    check_size(&text)?;
    Ok(text)
}

/// A JSON string or `null` payload.
fn payload<T: DeserializeOwned>(value: &RawValue) -> Result<T, ErrorCode> {
    serde_json::from_str(value.get()).map_err(|_| ErrorCode::InvalidMessage)
}

/// A JSON object payload.
fn object_payload<T: DeserializeOwned>(value: &RawValue) -> Result<T, ErrorCode> {
    object(value).map_err(|_| ErrorCode::InvalidMessage)
}

/// Encodes a request as compact JSON (rendezvous §3, §5.2).
///
/// # Errors
///
/// [`ErrorCode::InvalidMessage`] when the encoding exceeds [`MAX_MESSAGE_BYTES`].
pub fn encode_request(request: &Request) -> Result<String, ErrorCode> {
    const KEY: &str = "operation";
    let name = request.operation().as_str();
    match request {
        Request::Directory => envelope(KEY, name, &()),
        Request::Publish(value) => envelope(KEY, name, value),
        Request::LookupNode(value) => envelope(KEY, name, value),
        Request::Hello(value) => envelope(KEY, name, value),
        Request::Open(value) => envelope(KEY, name, value),
        Request::Lookup(value) => envelope(KEY, name, value),
        Request::Join(value) => envelope(KEY, name, value),
        Request::Admit(value) => envelope(KEY, name, value),
        Request::Reject(value) => envelope(KEY, name, value),
        Request::Send(value) => envelope(KEY, name, value),
        Request::Recv(value) => envelope(KEY, name, value),
        Request::Close(value) => envelope(KEY, name, value),
    }
}

/// Decodes a request, checking the size before parsing (rendezvous §3, §5.2).
///
/// # Errors
///
/// [`ErrorCode::InvalidMessage`] for an oversize, malformed or invalid message.
pub fn decode_request(text: &str) -> Result<Request, ErrorCode> {
    check_size(text)?;
    check_object(text)?;
    let raw: RawRequest<'_> = serde_json::from_str(text).map_err(|_| ErrorCode::InvalidMessage)?;
    let value = raw.value;
    Ok(match raw.operation {
        Operation::Directory => {
            payload::<()>(value)?;
            Request::Directory
        }
        Operation::Publish => Request::Publish(object_payload(value)?),
        Operation::LookupNode => Request::LookupNode(object_payload(value)?),
        Operation::Hello => Request::Hello(object_payload(value)?),
        Operation::Open => Request::Open(object_payload(value)?),
        Operation::Lookup => Request::Lookup(payload(value)?),
        Operation::Join => Request::Join(object_payload(value)?),
        Operation::Admit => Request::Admit(object_payload(value)?),
        Operation::Reject => Request::Reject(object_payload(value)?),
        Operation::Send => Request::Send(object_payload(value)?),
        Operation::Recv => Request::Recv(object_payload(value)?),
        Operation::Close => Request::Close(object_payload(value)?),
    })
}

/// Encodes a broker message as compact JSON (rendezvous §3, §5.2, §7).
///
/// # Errors
///
/// [`ErrorCode::InvalidMessage`] when the encoding exceeds [`MAX_MESSAGE_BYTES`].
pub fn encode_response(response: &Response) -> Result<String, ErrorCode> {
    const KEY: &str = "result";
    match response {
        Response::Challenge(value) => envelope(KEY, "challenge", value),
        Response::Directory(value) => envelope(KEY, "directory", value),
        Response::Published(value) => envelope(KEY, "published", value),
        Response::Record(value) => envelope(KEY, "record", value),
        Response::Ok => envelope(KEY, "ok", &()),
        Response::Opened(value) => envelope(KEY, "opened", value),
        Response::Found(value) => envelope(KEY, "found", value),
        Response::Sent(value) => envelope(KEY, "sent", value),
        Response::Mailbox(value) => envelope(KEY, "mailbox", value),
        Response::Error(value) => envelope(KEY, "error", value),
    }
}

/// Decodes a broker message, checking the size before parsing (rendezvous §3, §5.2, §7).
///
/// # Errors
///
/// [`ErrorCode::InvalidMessage`] for an oversize, malformed or invalid message.
pub fn decode_response(text: &str) -> Result<Response, ErrorCode> {
    check_size(text)?;
    check_object(text)?;
    let raw: RawResponse<'_> = serde_json::from_str(text).map_err(|_| ErrorCode::InvalidMessage)?;
    let value = raw.value;
    Ok(match raw.result {
        ResultName::Challenge => Response::Challenge(object_payload(value)?),
        ResultName::Directory => Response::Directory(object_payload(value)?),
        ResultName::Published => Response::Published(object_payload(value)?),
        ResultName::Record => Response::Record(object_payload(value)?),
        ResultName::Ok => {
            payload::<()>(value)?;
            Response::Ok
        }
        ResultName::Opened => Response::Opened(object_payload(value)?),
        ResultName::Found => Response::Found(object_payload(value)?),
        ResultName::Sent => Response::Sent(object_payload(value)?),
        ResultName::Mailbox => Response::Mailbox(object_payload(value)?),
        ResultName::Error => Response::Error(payload(value)?),
    })
}

/// Deserializes a strict base64url byte string of at most `maximum` bytes, for
/// `deserialize_with` helpers of bounded fields.
///
/// # Errors
///
/// A custom deserializer error naming no input.
pub fn deserialize_bytes_up_to<'de, D: Deserializer<'de>>(
    deserializer: D,
    maximum: usize,
) -> Result<Vec<u8>, D::Error> {
    let text = String::deserialize(deserializer)?;
    decode_base64url(&text, maximum).map_err(D::Error::custom)
}

/// Serde helpers for `[u8; N]` as a base64url string of exactly `N` bytes.
pub mod bytes {
    use super::{decode_base64url, encode_base64url};
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    /// Serializes `value` as unpadded base64url.
    ///
    /// # Errors
    ///
    /// Only the serializer's own errors.
    pub fn serialize<S: Serializer, const N: usize>(
        value: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_base64url(value))
    }

    /// Deserializes strict unpadded base64url of exactly `N` bytes.
    ///
    /// # Errors
    ///
    /// A custom error for any other input.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(deserializer)?;
        decode_base64url(&text, N)
            .ok()
            .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
            .ok_or_else(|| D::Error::custom("invalid fixed-length byte string"))
    }
}

/// Serde helpers for `Option<[u8; N]>` as a base64url string or `null`; the field is
/// still required.
pub mod option_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes `Some` as unpadded base64url and `None` as `null`.
    ///
    /// # Errors
    ///
    /// Only the serializer's own errors.
    pub fn serialize<S: Serializer, const N: usize>(
        value: &Option<[u8; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => super::bytes::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes `null` or strict unpadded base64url of exactly `N` bytes.
    ///
    /// # Errors
    ///
    /// A custom error for any other input.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<Option<[u8; N]>, D::Error> {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct Fixed<const N: usize>(#[serde(with = "super::bytes")] [u8; N]);
        Ok(Option::<Fixed<N>>::deserialize(deserializer)?.map(|fixed| fixed.0))
    }
}

/// Serde helpers for `Vec<u8>` as a base64url string, bounded only by the message size.
pub mod byte_vec {
    use super::{MAX_MESSAGE_BYTES, deserialize_bytes_up_to, encode_base64url};
    use serde::{Deserializer, Serializer};

    /// Serializes `value` as unpadded base64url.
    ///
    /// # Errors
    ///
    /// Only the serializer's own errors.
    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_base64url(value))
    }

    /// Deserializes strict unpadded base64url.
    ///
    /// # Errors
    ///
    /// A custom error for any other input.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        deserialize_bytes_up_to(deserializer, MAX_MESSAGE_BYTES)
    }
}
