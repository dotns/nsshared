//! Region rendezvous forwarding bodies, frame types 10-12 (quick-v2 §7.1, §8.5,
//! rendezvous §5.3).
//!
//! In a relay region the rendezvous service has one owner per owner epoch; the member that
//! holds the client's `/quick/v2` connection (the entry member) forwards each request to the
//! owner in a RENDEZVOUS_REQUEST and relays the owner's RENDEZVOUS_RESPONSE back
//! (rendezvous §5.3). A shard region replicates every verified registry publish to the other
//! members in a REGISTRY_RECORD (quick-v2 §7.1). The bodies are canonical CBOR (quick-v2
//! §12.1) carried in the region frame envelope `[ver = 2, type, body]` of `nsshared_wire`.
//!
//! # Proposed spec text (quick-v2 §8.5, replacing the types 10-12 bullet)
//!
//! - Types 10 RENDEZVOUS_REQUEST, 11 RENDEZVOUS_RESPONSE and 12 REGISTRY_RECORD are carried
//!   only on the control connection after HELLO; on the data connection they close the
//!   channel like any other wrong-channel frame. The 4-byte length prefix may be up to 20480
//!   on the control connection and up to 4096 on the data connection, checked before
//!   allocating; once the envelope is decoded, a frame above 4096 bytes is accepted only for
//!   types 10 and 11. Every other frame keeps the 4096-byte limit.
//! - RENDEZVOUS_REQUEST is `[request_id u64, owner_epoch u64, client_addr [ip bytes4 /
//!   bytes16, port u16], challenge_nonce bytes32, actor (bytes32 or null), request text]`.
//!   `request_id` is non-zero and unique among the requests outstanding on that control
//!   connection; `owner_epoch` is the owner epoch the entry member targets; `client_addr` is
//!   the client's source address for the per-source-IP limits (rendezvous §6, quick-v2 §7.4),
//!   with an IPv4 source always in the 4-byte form; `challenge_nonce` is the non-zero nonce of
//!   the entry connection's `challenge`, to which the `publish` proof is bound;
//!   `actor` is the actor the entry member authenticated with `hello` on that connection,
//!   null before `hello`, and must be present for every operation that requires `hello`;
//!   `request` is the client's exact `/quick/v2` JSON request, at most 16384 bytes. `hello`
//!   and `directory` are answered by the entry member and never forwarded.
//! - RENDEZVOUS_RESPONSE is `[request_id u64, owner_epoch u64, response text]`: the
//!   request's `request_id` and `owner_epoch` and the owner's exact JSON response, at most
//!   16384 bytes, never `challenge` or `directory`. An owner whose current epoch differs
//!   from the request's `owner_epoch` answers `unavailable`; an entry member whose view of
//!   the owner epoch changed before the response arrived answers the client `unavailable`;
//!   the client retries on the next member (rendezvous §5.3, §7).
//! - REGISTRY_RECORD is `[record, dns bool, challenge_nonce bytes32, proof bytes64]`, at most
//!   4096 bytes: the nested canonical NodeRecord array, the `dns` choice, and the nonce and
//!   proof of the `publish` that carried them (quick-v2 §7.2). The member that verifies a
//!   `publish` and accepts it, or latches a conflict from it, sends it to every other member;
//!   it is never forwarded again. The receiver verifies the proof against the region identity
//!   and applies the publish by the §3.3 rules exactly as a local `publish`, so a conflict is
//!   latched locally. `dns` follows the record that wins §3.3; a replica of an older record of
//!   the same generation and key changes nothing; on identical records the last accepted
//!   `publish` wins.
//!
//! # 建议的规范文本（quick-v2 §8.5，替换类型 10–12 一条）
//!
//! - 类型 10 RENDEZVOUS_REQUEST、11 RENDEZVOUS_RESPONSE 与 12 REGISTRY_RECORD 只在 HELLO
//!   之后的控制连接上；出现在数据连接上时与其他通道错误一样关闭该通道。4 字节长度前缀在
//!   控制连接上最大 20480、在数据连接上最大 4096，在分配内存前检查；解开帧封装后，只有类型
//!   10 与 11 的帧可以超过 4096 字节，其余帧仍以 4096 字节为上限。
//! - RENDEZVOUS_REQUEST 为 `[request_id u64, owner_epoch u64, client_addr [ip bytes4 /
//!   bytes16, port u16], challenge_nonce bytes32, actor (bytes32 或 null), request text]`。
//!   `request_id` 非零，在该控制连接上未完成的请求之间唯一；`owner_epoch` 是入口成员所针对的
//!   owner epoch；`client_addr` 是客户端的源地址，用于按源 IP 的上限（会合协议 §6、§7.4），
//!   IPv4 源地址一律用 4 字节形式；`challenge_nonce` 是入口连接 `challenge` 的非零 nonce，
//!   `publish` 的证明绑定于它；`actor` 是入口成员在该连接上经 `hello` 认证的参与方，`hello`
//!   之前为 null，需要 `hello` 的操作必须带上；`request` 是客户端原样的 `/quick/v2` JSON
//!   请求，最多 16384 字节。`hello` 与 `directory` 由入口成员应答，从不转发。
//! - RENDEZVOUS_RESPONSE 为 `[request_id u64, owner_epoch u64, response text]`：原样带回请求
//!   的 `request_id` 与 `owner_epoch`，以及 owner 原样的 JSON 响应，最多 16384 字节，从不是
//!   `challenge` 或 `directory`。owner 当前的 epoch 与请求的 `owner_epoch` 不同时应答
//!   `unavailable`；响应到达前入口成员看到的 owner epoch 已变化时，向客户端应答
//!   `unavailable`；客户端换下一个成员重试（会合协议 §5.3、§7）。
//! - REGISTRY_RECORD 为 `[record, dns bool, challenge_nonce bytes32, proof bytes64]`，最多
//!   4096 字节：嵌套的规范 NodeRecord 数组、`dns` 选择，以及携带它们的那次 `publish` 的
//!   nonce 与证明（§7.2）。校验并接受某次 `publish`、或因它锁存冲突的成员把它发给其他每个
//!   成员，接收方从不再次转发。接收方以区域标识校验证明，并与本地 `publish` 完全相同地按
//!   §3.3 应用，因此冲突在本地锁存。`dns` 跟随按 §3.3 胜出的记录；同一代际、同一 `K` 的较旧
//!   记录的副本不改变任何状态；记录完全相同时以最后一次被接受的 `publish` 为准。

use crate::{
    error::ErrorCode,
    message::{PublishRequest, Published},
    registry::{self, RegistryEntry},
    transport::{self, MAX_MESSAGE_BYTES, Operation, Request, Response},
};
use nsshared_wire::{
    CborError, CborReader, CborWriter, MAX_NODE_RECORD_RELAYS, MAX_REGION_RENDEZVOUS_FRAME_BYTES,
    MAX_RELAY_ID_BYTES, NodeRecord, NodeRecordError, RecordDecision, RegionChannel,
    RegionFrameError, RegionFrameType, RelayId, decode_region_envelope, encode_region_envelope,
    max_region_frame_bytes_for,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// The `unavailable` error response, compact JSON as `transport::encode_response` writes it
/// (rendezvous §3, §7).
const UNAVAILABLE_TEXT: &str = r#"{"result":"error","value":"unavailable"}"#;

/// A rejected region rendezvous body or frame (quick-v2 §8.5, §12.1).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegionBodyError {
    /// The frame envelope or its size is invalid.
    #[error(transparent)]
    Frame(#[from] RegionFrameError),
    /// The frame carries another type than the body decoder expects.
    #[error("frame type {actual}, expected {expected:?}")]
    WrongType {
        /// The body type the decoder handles.
        expected: RegionFrameType,
        /// The frame's type byte.
        actual: u8,
    },
    /// The body is not canonical CBOR of its shape: size, arity, field types or widths of
    /// strings, or trailing bytes (quick-v2 §12.1).
    #[error("non-canonical region body: {0}")]
    Cbor(#[from] CborError),
    /// An integer field exceeds its width.
    #[error("{field} {value} exceeds its field width")]
    FieldWidth {
        /// The field name.
        field: &'static str,
        /// The decoded value.
        value: u64,
    },
    /// `request_id` is 0.
    #[error("request_id must not be 0")]
    ZeroRequestId,
    /// `challenge_nonce` is all zero (rendezvous §3).
    #[error("challenge nonce must not be all zero")]
    ZeroChallengeNonce,
    /// The `client_addr` ip is neither 4 nor 16 bytes.
    #[error("client address of {0} bytes is neither 4 nor 16 bytes")]
    ClientAddrLength(usize),
    /// The `client_addr` ip is an IPv4-mapped IPv6 address; IPv4 uses the 4-byte form.
    #[error("IPv4-mapped client address must use the 4-byte form")]
    MappedClientAddr,
    /// The JSON message exceeds 16384 bytes (rendezvous §3, §6).
    #[error("JSON message of {0} bytes exceeds {MAX_MESSAGE_BYTES} bytes")]
    MessageTooLarge(usize),
    /// The JSON text is not a valid `/quick/v2` request or response (rendezvous §3, §5.2).
    #[error("invalid rendezvous JSON message: {0}")]
    Message(ErrorCode),
    /// A `hello` or `directory` request, which the entry member answers itself.
    #[error("{0:?} requests are answered by the entry member and never forwarded")]
    NotForwarded(Operation),
    /// A `challenge` or `directory` result, which no forwarded request produces.
    #[error("challenge and directory results are never forwarded")]
    ResponseNotForwarded,
    /// A request that requires `hello` without an authenticated actor (rendezvous §4).
    #[error("{0:?} requires hello but no actor is forwarded")]
    MissingActor(Operation),
    /// The nested NodeRecord is invalid (quick-v2 §3.2).
    #[error("invalid nested NodeRecord: {0}")]
    Record(#[from] NodeRecordError),
}

/// RENDEZVOUS_REQUEST `client_addr`: the client's source IP and port as the entry member
/// sees them, for the per-source-IP limits (rendezvous §6, quick-v2 §7.4).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ClientAddr {
    /// The source IP; IPv4 is never in the IPv4-mapped IPv6 form.
    pub ip: IpAddr,
    /// The source port.
    pub port: u16,
}

/// Type 10 RENDEZVOUS_REQUEST body `[request_id, owner_epoch, client_addr, challenge_nonce,
/// actor, request]` (quick-v2 §8.5, rendezvous §5.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RendezvousRequest {
    request_id: u64,
    owner_epoch: u64,
    client_addr: ClientAddr,
    challenge_nonce: [u8; 32],
    actor: Option<[u8; 32]>,
    text: String,
    request: Request,
}

impl RendezvousRequest {
    /// Builds a request after checking every field rule: non-zero `request_id` and nonce, a
    /// canonical client address, and `text` a valid forwardable request of at most 16384
    /// bytes whose actor is present when its operation requires `hello` (rendezvous §3-§5).
    ///
    /// - `request_id`: correlates the response; unique while outstanding on the control
    ///   connection.
    /// - `owner_epoch`: the rendezvous owner epoch the entry member targets.
    /// - `client_addr`: the client's source address, for the per-source-IP limits.
    /// - `challenge_nonce`: the entry connection's challenge nonce; the `publish` proof is
    ///   bound to it (quick-v2 §7.2).
    /// - `actor`: the actor authenticated by `hello` on the entry connection, `None` before.
    /// - `text`: the client's exact JSON request.
    ///
    /// # Errors
    ///
    /// [`RegionBodyError`] naming the first violated rule.
    pub fn new(
        request_id: u64,
        owner_epoch: u64,
        client_addr: ClientAddr,
        challenge_nonce: [u8; 32],
        actor: Option<[u8; 32]>,
        text: String,
    ) -> Result<Self, RegionBodyError> {
        check_request_id(request_id)?;
        if challenge_nonce == [0; 32] {
            return Err(RegionBodyError::ZeroChallengeNonce);
        }
        check_client_ip(&client_addr.ip)?;
        check_message_size(&text)?;
        let request = transport::decode_request(&text).map_err(RegionBodyError::Message)?;
        let operation = request.operation();
        if matches!(operation, Operation::Hello | Operation::Directory) {
            return Err(RegionBodyError::NotForwarded(operation));
        }
        if operation.requires_hello() && actor.is_none() {
            return Err(RegionBodyError::MissingActor(operation));
        }
        Ok(Self {
            request_id,
            owner_epoch,
            client_addr,
            challenge_nonce,
            actor,
            text,
            request,
        })
    }

    /// The request id.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// The targeted owner epoch.
    #[must_use]
    pub const fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }

    /// The client's source address.
    #[must_use]
    pub const fn client_addr(&self) -> ClientAddr {
        self.client_addr
    }

    /// The entry connection's challenge nonce.
    #[must_use]
    pub const fn challenge_nonce(&self) -> &[u8; 32] {
        &self.challenge_nonce
    }

    /// The authenticated actor, `None` before `hello`.
    #[must_use]
    pub const fn actor(&self) -> Option<&[u8; 32]> {
        self.actor.as_ref()
    }

    /// The client's exact JSON request.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The decoded request.
    #[must_use]
    pub const fn request(&self) -> &Request {
        &self.request
    }

    /// Encodes the canonical body (quick-v2 §8.5, §12.1).
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        let mut writer = CborWriter::with_capacity(self.text.len().saturating_add(96));
        writer
            .array(6)
            .uint(self.request_id)
            .uint(self.owner_epoch)
            .array(2);
        match self.client_addr.ip {
            IpAddr::V4(ip) => writer.bytes(&ip.octets()),
            IpAddr::V6(ip) => writer.bytes(&ip.octets()),
        };
        writer
            .uint(u64::from(self.client_addr.port))
            .bytes(&self.challenge_nonce);
        match &self.actor {
            Some(actor) => writer.bytes(actor),
            None => writer.null(),
        };
        writer.text(&self.text);
        writer.into_bytes()
    }

    /// Decodes a canonical body: size and canonical shape with no trailing bytes first, then
    /// the field rules of [`RendezvousRequest::new`] (quick-v2 §8.5, §12.1).
    ///
    /// # Errors
    ///
    /// [`RegionBodyError`] naming the first violated rule.
    pub fn decode_body(body: &[u8]) -> Result<Self, RegionBodyError> {
        let mut reader = body_reader(body, RegionFrameType::RendezvousRequest)?;
        reader.array(6)?;
        let request_id = reader.uint()?;
        let owner_epoch = reader.uint()?;
        reader.array(2)?;
        let ip = reader.bytes_up_to(16)?;
        let port = reader.uint()?;
        let challenge_nonce = reader.fixed_bytes()?;
        let actor = if reader.take_null() {
            None
        } else {
            Some(reader.fixed_bytes()?)
        };
        let text = read_message(&mut reader)?;
        reader.finish()?;
        let ip = match ip.len() {
            4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(ip).unwrap_or_default())),
            16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip).unwrap_or_default())),
            other => return Err(RegionBodyError::ClientAddrLength(other)),
        };
        let port = u16::try_from(port).map_err(|_| RegionBodyError::FieldWidth {
            field: "port",
            value: port,
        })?;
        Self::new(
            request_id,
            owner_epoch,
            ClientAddr { ip, port },
            challenge_nonce,
            actor,
            text.to_owned(),
        )
    }

    /// Encodes the unprefixed control-connection frame `[2, 10, body]` (quick-v2 §8.5).
    ///
    /// # Errors
    ///
    /// [`RegionBodyError::Frame`] when the frame exceeds 20480 bytes.
    pub fn encode_frame(&self) -> Result<Vec<u8>, RegionBodyError> {
        encode_frame(RegionFrameType::RendezvousRequest, &self.encode_body())
    }

    /// Decodes an unprefixed control-connection frame of type 10 (quick-v2 §8.5).
    ///
    /// # Errors
    ///
    /// [`RegionBodyError`] for the envelope, the type or the body.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, RegionBodyError> {
        Self::decode_body(frame_body(frame, RegionFrameType::RendezvousRequest)?)
    }
}

/// Type 11 RENDEZVOUS_RESPONSE body `[request_id, owner_epoch, response]` (quick-v2 §8.5,
/// rendezvous §5.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RendezvousResponse {
    request_id: u64,
    owner_epoch: u64,
    text: String,
    response: Response,
}

impl RendezvousResponse {
    /// Builds a response after checking a non-zero `request_id` and `text` a valid response
    /// of at most 16384 bytes other than `challenge` and `directory` (rendezvous §3, §5).
    ///
    /// - `request_id` and `owner_epoch`: echoed from the request.
    /// - `text`: the owner's exact JSON response.
    ///
    /// # Errors
    ///
    /// [`RegionBodyError`] naming the first violated rule.
    pub fn new(request_id: u64, owner_epoch: u64, text: String) -> Result<Self, RegionBodyError> {
        check_request_id(request_id)?;
        check_message_size(&text)?;
        let response = transport::decode_response(&text).map_err(RegionBodyError::Message)?;
        if matches!(response, Response::Challenge(_) | Response::Directory(_)) {
            return Err(RegionBodyError::ResponseNotForwarded);
        }
        Ok(Self {
            request_id,
            owner_epoch,
            text,
            response,
        })
    }

    /// The `unavailable` answer of an owner whose current epoch is not the request's
    /// (rendezvous §5.3, §7).
    #[must_use]
    pub fn unavailable(request: &RendezvousRequest) -> Self {
        Self {
            request_id: request.request_id,
            owner_epoch: request.owner_epoch,
            text: UNAVAILABLE_TEXT.to_owned(),
            response: Response::Error(ErrorCode::Unavailable),
        }
    }

    /// The request id.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// The owner epoch of the request.
    #[must_use]
    pub const fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }

    /// The owner's exact JSON response.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The decoded response.
    #[must_use]
    pub const fn response(&self) -> &Response {
        &self.response
    }

    /// The response for the client given the entry member's current view of the owner
    /// epoch: the owner's response, or `unavailable` when the epoch changed (rendezvous
    /// §5.3).
    #[must_use]
    pub fn client_response(&self, current_owner_epoch: u64) -> Response {
        match check_owner_epoch(self.owner_epoch, current_owner_epoch) {
            Ok(()) => self.response.clone(),
            Err(code) => Response::Error(code),
        }
    }

    /// Encodes the canonical body (quick-v2 §8.5, §12.1).
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        let mut writer = CborWriter::with_capacity(self.text.len().saturating_add(24));
        writer
            .array(3)
            .uint(self.request_id)
            .uint(self.owner_epoch)
            .text(&self.text);
        writer.into_bytes()
    }

    /// Decodes a canonical body: size and canonical shape with no trailing bytes first, then
    /// the field rules of [`RendezvousResponse::new`] (quick-v2 §8.5, §12.1).
    ///
    /// # Errors
    ///
    /// [`RegionBodyError`] naming the first violated rule.
    pub fn decode_body(body: &[u8]) -> Result<Self, RegionBodyError> {
        let mut reader = body_reader(body, RegionFrameType::RendezvousResponse)?;
        reader.array(3)?;
        let request_id = reader.uint()?;
        let owner_epoch = reader.uint()?;
        let text = read_message(&mut reader)?;
        reader.finish()?;
        Self::new(request_id, owner_epoch, text.to_owned())
    }

    /// Encodes the unprefixed control-connection frame `[2, 11, body]` (quick-v2 §8.5).
    ///
    /// # Errors
    ///
    /// [`RegionBodyError::Frame`] when the frame exceeds 20480 bytes.
    pub fn encode_frame(&self) -> Result<Vec<u8>, RegionBodyError> {
        encode_frame(RegionFrameType::RendezvousResponse, &self.encode_body())
    }

    /// Decodes an unprefixed control-connection frame of type 11 (quick-v2 §8.5).
    ///
    /// # Errors
    ///
    /// [`RegionBodyError`] for the envelope, the type or the body.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, RegionBodyError> {
        Self::decode_body(frame_body(frame, RegionFrameType::RendezvousResponse)?)
    }
}

/// Checks the owner epoch of a forwarded request or response against the current one: any
/// difference means the owner fence moved and maps to `unavailable` (rendezvous §5.3).
///
/// # Errors
///
/// [`ErrorCode::Unavailable`] when `owner_epoch != current_owner_epoch`.
pub const fn check_owner_epoch(
    owner_epoch: u64,
    current_owner_epoch: u64,
) -> Result<(), ErrorCode> {
    if owner_epoch == current_owner_epoch {
        Ok(())
    } else {
        Err(ErrorCode::Unavailable)
    }
}

/// Type 12 REGISTRY_RECORD body `[record, dns, challenge_nonce, proof]`: one verified
/// `publish` replicated to the other members of a shard region (quick-v2 §3.3, §7.1, §7.2).
///
/// The nonce and proof let the receiver verify the `dns` choice under `I` and apply the
/// publish through [`RegistryEntry`] exactly like a local one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryRecord {
    record: NodeRecord,
    dns: bool,
    challenge_nonce: [u8; 32],
    proof: [u8; 64],
}

impl RegistryRecord {
    /// Builds the replica of a `publish` received on a connection whose challenge carried
    /// `challenge_nonce` (quick-v2 §7.2).
    ///
    /// # Errors
    ///
    /// [`RegionBodyError::Record`] for an invalid record or
    /// [`RegionBodyError::ZeroChallengeNonce`].
    pub fn new(
        publish: &PublishRequest,
        challenge_nonce: [u8; 32],
    ) -> Result<Self, RegionBodyError> {
        if challenge_nonce == [0; 32] {
            return Err(RegionBodyError::ZeroChallengeNonce);
        }
        Ok(Self {
            record: NodeRecord::decode(&publish.record)?,
            dns: publish.dns,
            challenge_nonce,
            proof: publish.proof,
        })
    }

    /// The replicated record.
    #[must_use]
    pub const fn record(&self) -> &NodeRecord {
        &self.record
    }

    /// The publisher's `dns` choice.
    #[must_use]
    pub const fn dns(&self) -> bool {
        self.dns
    }

    /// The nonce the publish proof is bound to.
    #[must_use]
    pub const fn challenge_nonce(&self) -> &[u8; 32] {
        &self.challenge_nonce
    }

    /// The publish proof.
    #[must_use]
    pub const fn proof(&self) -> &[u8; 64] {
        &self.proof
    }

    /// The original `publish` request.
    #[must_use]
    pub fn publish_request(&self) -> PublishRequest {
        PublishRequest {
            record: self.record.as_bytes().to_vec(),
            dns: self.dns,
            proof: self.proof,
        }
    }

    /// Applies the replica on a receiving member: the proof is verified against the
    /// region identity `authority` at `now`, then the publish goes through
    /// [`RegistryEntry::apply_publish`] so §3.3 conflicts are latched locally
    /// (quick-v2 §3.3, §7.1, §7.2).
    ///
    /// A replica of an older record of the committed generation and key, which §3.3 leaves
    /// unchanged, does not take over the `dns` choice: it changes nothing and returns the
    /// stored expiry. The result is local bookkeeping; a REGISTRY_RECORD is never answered
    /// and never forwarded again.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidMessage`] for an expired record or a proof that does not verify,
    /// [`ErrorCode::Conflict`] as [`RegistryEntry::apply_publish`].
    pub fn apply(
        &self,
        entry: &mut RegistryEntry,
        authority: &RelayId,
        now: u64,
    ) -> Result<Published, ErrorCode> {
        let verified = registry::verify_publish(
            &self.publish_request(),
            &self.challenge_nonce,
            authority,
            now,
        )?;
        if !entry.deletion_due(now)
            && !entry.marks().is_conflicted()
            && entry.marks().evaluate(&self.record) == Ok(RecordDecision::Unchanged)
            && let Some(current) = entry.record()
            && current.as_bytes() != self.record.as_bytes()
        {
            return Ok(Published {
                expires: current.expires(),
            });
        }
        entry.apply_publish(&verified, now)
    }

    /// Encodes the canonical body; at most 4096 bytes since the record is at most 600
    /// (quick-v2 §8.5, §12.1, §12.3).
    #[must_use]
    pub fn encode_body(&self) -> Vec<u8> {
        let mut writer = CborWriter::with_capacity(2);
        writer.array(4);
        let mut encoded = writer.into_bytes();
        encoded.extend_from_slice(self.record.as_bytes());
        let mut tail = CborWriter::with_capacity(104);
        tail.boolean(self.dns)
            .bytes(&self.challenge_nonce)
            .bytes(&self.proof);
        encoded.extend_from_slice(&tail.into_bytes());
        encoded
    }

    /// Decodes a canonical body: size, canonical shape and trailing bytes first, then the
    /// nested record and the nonce (quick-v2 §3.2, §8.5, §12.1).
    ///
    /// # Errors
    ///
    /// [`RegionBodyError`] naming the first violated rule.
    pub fn decode_body(body: &[u8]) -> Result<Self, RegionBodyError> {
        let mut reader = body_reader(body, RegionFrameType::RegistryRecord)?;
        reader.array(4)?;
        let record = read_record(&mut reader)?;
        let dns = reader.boolean()?;
        let challenge_nonce = reader.fixed_bytes()?;
        let proof = reader.fixed_bytes()?;
        reader.finish()?;
        if challenge_nonce == [0; 32] {
            return Err(RegionBodyError::ZeroChallengeNonce);
        }
        Ok(Self {
            record: NodeRecord::decode(record)?,
            dns,
            challenge_nonce,
            proof,
        })
    }

    /// Encodes the unprefixed control-connection frame `[2, 12, body]` (quick-v2 §8.5).
    ///
    /// # Errors
    ///
    /// [`RegionBodyError::Frame`] when the frame exceeds 4096 bytes.
    pub fn encode_frame(&self) -> Result<Vec<u8>, RegionBodyError> {
        encode_frame(RegionFrameType::RegistryRecord, &self.encode_body())
    }

    /// Decodes an unprefixed control-connection frame of type 12 (quick-v2 §8.5).
    ///
    /// # Errors
    ///
    /// [`RegionBodyError`] for the envelope, the type or the body.
    pub fn decode_frame(frame: &[u8]) -> Result<Self, RegionBodyError> {
        Self::decode_body(frame_body(frame, RegionFrameType::RegistryRecord)?)
    }
}

fn check_request_id(request_id: u64) -> Result<(), RegionBodyError> {
    if request_id == 0 {
        Err(RegionBodyError::ZeroRequestId)
    } else {
        Ok(())
    }
}

fn check_client_ip(ip: &IpAddr) -> Result<(), RegionBodyError> {
    match ip {
        IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => Err(RegionBodyError::MappedClientAddr),
        _ => Ok(()),
    }
}

fn check_message_size(text: &str) -> Result<(), RegionBodyError> {
    if text.len() > MAX_MESSAGE_BYTES {
        Err(RegionBodyError::MessageTooLarge(text.len()))
    } else {
        Ok(())
    }
}

/// A reader over a body no larger than its frame may be (quick-v2 §8.5).
fn body_reader(body: &[u8], frame_type: RegionFrameType) -> Result<CborReader<'_>, CborError> {
    CborReader::new(
        body,
        max_region_frame_bytes_for(RegionChannel::Control, frame_type.as_u8()),
    )
}

/// Reads the JSON text, bounded by the frame, and checks the 16384-byte message limit
/// before any JSON parsing.
fn read_message<'a>(reader: &mut CborReader<'a>) -> Result<&'a str, RegionBodyError> {
    let text = reader.text_up_to(MAX_REGION_RENDEZVOUS_FRAME_BYTES)?;
    check_message_size(text)?;
    Ok(text)
}

/// Reads the nested NodeRecord array and returns its exact bytes (quick-v2 §12.3).
fn read_record<'a>(reader: &mut CborReader<'a>) -> Result<&'a [u8], CborError> {
    let start = reader.consumed().len();
    reader.array(8)?;
    reader.uint()?;
    reader.fixed_bytes::<32>()?;
    reader.fixed_bytes::<32>()?;
    reader.uint()?;
    reader.uint()?;
    reader.uint()?;
    let relays = reader.array_up_to(MAX_NODE_RECORD_RELAYS)?;
    for _ in 0..relays {
        reader.text_up_to(MAX_RELAY_ID_BYTES)?;
    }
    reader.fixed_bytes::<64>()?;
    Ok(reader.consumed().get(start..).unwrap_or_default())
}

fn encode_frame(frame_type: RegionFrameType, body: &[u8]) -> Result<Vec<u8>, RegionBodyError> {
    Ok(encode_region_envelope(
        frame_type.as_u8(),
        body,
        RegionChannel::Control,
    )?)
}

fn frame_body(frame: &[u8], expected: RegionFrameType) -> Result<&[u8], RegionBodyError> {
    let envelope = decode_region_envelope(frame, RegionChannel::Control)?;
    if envelope.frame_type != expected.as_u8() {
        return Err(RegionBodyError::WrongType {
            expected,
            actual: envelope.frame_type,
        });
    }
    Ok(envelope.body)
}
