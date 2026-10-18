//! Strongly typed service-control messages. The raw CBOR value is private.

use crate::contract::{Digest, Id, Identity, ReportContent, ServiceRef};

/// Every message kind in schema 1. Unknown kinds are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    /// Read the current runtime floor without taking authority.
    RuntimeFloor,
    /// Return the current runtime floor.
    RuntimeFloorResult,
    /// Bind a daemon runtime to current authority.
    RuntimeBind,
    /// Return the current authority epoch.
    RuntimeBindResult,
    /// Open a new stream session.
    SessionOpen,
    /// Confirm a stream session.
    SessionOpenResult,
    /// Read the accepted report head.
    ReportHead,
    /// Return the report head.
    ReportHeadResult,
    /// Replace the full declaration catalogue.
    ReportReplace,
    /// Confirm the accepted report.
    ReportAccepted,
    /// Deliver a full recipient snapshot.
    SnapshotPush,
    /// Acknowledge configured phases.
    SnapshotAck,
    /// Prove the publisher listener is installed closed.
    ListenerReady,
    /// Refresh a publisher grant.
    LeaseRefresh,
    /// Acquire consumer use leases.
    LeaseAcquire,
    /// Return one service use lease result.
    LeaseResult,
    /// Return a fully bound port decision.
    PortResult,
    /// Cancel a proposal with a durable terminal fence.
    PortCancel,
    /// Query one exact proposal.
    PortQuery,
    /// Return a proposal state.
    PortQueryResult,
    /// Explicitly request another allocation round.
    ServiceRetryPort,
    /// Return a stable error code.
    Error,
}

impl MessageKind {
    /// The stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeFloor => "runtime.floor",
            Self::RuntimeFloorResult => "runtime.floor.result",
            Self::RuntimeBind => "runtime.bind",
            Self::RuntimeBindResult => "runtime.bind.result",
            Self::SessionOpen => "session.open",
            Self::SessionOpenResult => "session.open.result",
            Self::ReportHead => "report.head",
            Self::ReportHeadResult => "report.head.result",
            Self::ReportReplace => "report.replace",
            Self::ReportAccepted => "report.accepted",
            Self::SnapshotPush => "snapshot.push",
            Self::SnapshotAck => "snapshot.ack",
            Self::ListenerReady => "listener.ready",
            Self::LeaseRefresh => "lease.refresh",
            Self::LeaseAcquire => "lease.acquire",
            Self::LeaseResult => "lease.result",
            Self::PortResult => "port.result",
            Self::PortCancel => "port.cancel",
            Self::PortQuery => "port.query",
            Self::PortQueryResult => "port.query.result",
            Self::ServiceRetryPort => "service.retry-port",
            Self::Error => "error",
        }
    }
}

impl TryFrom<&str> for MessageKind {
    type Error = crate::contract::ContractError;

    fn try_from(kind: &str) -> Result<Self, crate::contract::ContractError> {
        Ok(match kind {
            "runtime.floor" => Self::RuntimeFloor,
            "runtime.floor.result" => Self::RuntimeFloorResult,
            "runtime.bind" => Self::RuntimeBind,
            "runtime.bind.result" => Self::RuntimeBindResult,
            "session.open" => Self::SessionOpen,
            "session.open.result" => Self::SessionOpenResult,
            "report.head" => Self::ReportHead,
            "report.head.result" => Self::ReportHeadResult,
            "report.replace" => Self::ReportReplace,
            "report.accepted" => Self::ReportAccepted,
            "snapshot.push" => Self::SnapshotPush,
            "snapshot.ack" => Self::SnapshotAck,
            "listener.ready" => Self::ListenerReady,
            "lease.refresh" => Self::LeaseRefresh,
            "lease.acquire" => Self::LeaseAcquire,
            "lease.result" => Self::LeaseResult,
            "port.result" => Self::PortResult,
            "port.cancel" => Self::PortCancel,
            "port.query" => Self::PortQuery,
            "port.query.result" => Self::PortQueryResult,
            "service.retry-port" => Self::ServiceRetryPort,
            "error" => Self::Error,
            _ => return Err(crate::contract::ContractError::UnsupportedField),
        })
    }
}

/// Runtime recovery proof sent during bootstrap bind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeBind {
    /// True only when the local generation was lost and floor was read.
    pub recovery: bool,
    /// Observed server generation when recovering.
    pub observed_generation: Option<u64>,
    /// Observed runtime ID when recovering.
    pub observed_runtime_id: Option<Id>,
    /// Explicit local-owner recovery approval; never implied by floor alone.
    pub owner_recovery: bool,
}

/// Read-only server runtime floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFloorResult {
    /// Current generation, if any.
    pub current_generation: Option<u64>,
    /// Current runtime ID, if any.
    pub current_runtime_id: Option<Id>,
    /// Whether the prior runtime is still active.
    pub active: bool,
    /// Current server authority epoch.
    pub authority_epoch: u64,
}

/// Full report with a one-based revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportReplace {
    /// One-based report revision.
    pub report_revision: u64,
    /// Full declaration content.
    pub report: ReportContent,
}

/// Binding returned for each accepted declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportBinding {
    /// Stable declaration key.
    pub declaration_key: String,
    /// Stable service reference.
    pub service_ref: ServiceRef,
    /// Published port when assigned.
    pub port: Option<u16>,
    /// Proposal or ready state.
    pub proposal_state: String,
}

/// Accepted full report head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportAccepted {
    /// Zero means no report.
    pub accepted_revision: u64,
    /// Null only when revision is zero.
    pub report_digest: Option<Digest>,
    /// Bindings sorted by declaration-key bytes.
    pub bindings: Vec<ReportBinding>,
}

/// A fully bound candidate port proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortProposal {
    /// Stable resource reference.
    pub service_ref: ServiceRef,
    /// Current listener revision.
    pub listener_revision: u64,
    /// Current listener digest.
    pub intent_digest: Digest,
    /// One-based allocation round.
    pub allocation_round: u64,
    /// Per-service persistent proposal sequence.
    pub proposal_seq: u64,
    /// Random nonzero proposal identifier.
    pub proposal_id: Id,
    /// Proposed port.
    pub port: u16,
}

/// Publisher ready or refresh proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyProof {
    /// Exact proposal.
    pub proposal: PortProposal,
    /// Per-runtime persistent refresh sequence.
    pub refresh_seq: u64,
    /// Snapshot revision whose enforcement was applied.
    pub snapshot_revision: u64,
    /// Snapshot digest whose enforcement was applied.
    pub snapshot_digest: Digest,
    /// Compiled service enforcement digest.
    pub enforcement_policy_digest: Digest,
}

/// One consumer service request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceLeaseRef {
    /// Stable resource reference.
    pub service_ref: ServiceRef,
    /// Listener revision.
    pub listener_revision: u64,
    /// Listener digest.
    pub intent_digest: Digest,
}

/// Consumer actively acquires leases after snapshot application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseAcquire {
    /// Consumer persistent sequence.
    pub consumer_seq: u64,
    /// Applied snapshot revision.
    pub snapshot_revision: u64,
    /// Applied snapshot digest.
    pub snapshot_digest: Digest,
    /// Sorted per-service requests.
    pub services: Vec<ServiceLeaseRef>,
}

/// One service lease result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseResult {
    /// Exact service listener.
    pub service: ServiceLeaseRef,
    /// Grant ID on success.
    pub grant_id: Option<Id>,
    /// Publisher refresh sequence, or null for a consumer.
    pub refresh_seq: Option<u64>,
    /// Consumer sequence, or null for a publisher.
    pub consumer_seq: Option<u64>,
    /// Remaining milliseconds at reply time, bounded to 30000.
    pub remaining_ms: u64,
    /// `ok` or a stable error code.
    pub result: String,
    /// Consumer snapshot revision, null for publisher.
    pub snapshot_revision: Option<u64>,
    /// Consumer snapshot digest, null for publisher.
    pub snapshot_digest: Option<Digest>,
}

/// Port result with an optional durable pure-termination floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortResult {
    /// Exact proposal.
    pub proposal: PortProposal,
    /// Stable proposal result.
    pub result: String,
    /// Durable termination floor, required for `terminated-pure`.
    pub terminal_floor: Option<u64>,
}

/// A phased snapshot application acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotAck {
    /// Exact snapshot revision.
    pub snapshot_revision: u64,
    /// Exact snapshot digest.
    pub snapshot_digest: Digest,
    /// Content accepted.
    pub accepted: bool,
    /// Enforcement installed with the use gate closed.
    pub enforcement_applied: bool,
    /// Local DNS view applied.
    pub dns_applied: bool,
    /// Stable error code, if a phase failed.
    pub error: Option<String>,
}

/// Snapshot delivery binds a full typed snapshot to the target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotPush {
    /// Full snapshot content.
    pub snapshot: crate::snapshot::Snapshot,
}

/// Complete authenticated envelope exposed to consumers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message {
    /// NSD identifier.
    pub nsd_id: Id,
    /// Network identifier.
    pub network_id: Id,
    /// Full subject identity.
    pub subject_identity: Identity,
    /// Current daemon generation, absent only for runtime floor.
    pub runtime_generation: Option<u64>,
    /// Current daemon runtime ID, absent only for runtime floor.
    pub runtime_id: Option<Id>,
    /// Current authority epoch, absent only for bootstrap requests.
    pub authority_epoch: Option<u64>,
    /// Logical request ID.
    pub request_id: Id,
    /// Stream session sequence for session-bound messages.
    pub session_seq: Option<u64>,
    /// Strongly typed body; its variant determines kind.
    pub body: MessageBody,
}

/// Exhaustive schema-1 bodies. No caller can insert an arbitrary CBOR value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageBody {
    /// Empty runtime-floor request.
    RuntimeFloor,
    /// Runtime floor response.
    RuntimeFloorResult(RuntimeFloorResult),
    /// Bind a runtime.
    RuntimeBind(RuntimeBind),
    /// Bind response current epoch.
    RuntimeBindResult(u64),
    /// Empty session-open request; sequence is in the envelope.
    SessionOpen,
    /// Confirmed session sequence.
    SessionOpenResult(u64),
    /// Empty report-head request.
    ReportHead,
    /// Report-head response.
    ReportHeadResult(ReportAccepted),
    /// Replace a report.
    ReportReplace(ReportReplace),
    /// Report acceptance response.
    ReportAccepted(ReportAccepted),
    /// Full snapshot delivery.
    SnapshotPush(SnapshotPush),
    /// Phased snapshot ACK.
    SnapshotAck(SnapshotAck),
    /// Publisher ready.
    ListenerReady(ReadyProof),
    /// Publisher refresh.
    LeaseRefresh(ReadyProof),
    /// Consumer acquire.
    LeaseAcquire(LeaseAcquire),
    /// Per-service lease result.
    LeaseResult(LeaseResult),
    /// Port proposal result.
    PortResult(PortResult),
    /// Cancel one exact proposal.
    PortCancel(PortProposal),
    /// Query one exact proposal.
    PortQuery(PortProposal),
    /// Query response.
    PortQueryResult(PortResult),
    /// Explicit new allocation round.
    ServiceRetryPort(ServiceRef),
    /// Stable error code.
    Error(String),
}

impl MessageBody {
    /// The kind fixed by this variant.
    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        match self {
            Self::RuntimeFloor => MessageKind::RuntimeFloor,
            Self::RuntimeFloorResult(_) => MessageKind::RuntimeFloorResult,
            Self::RuntimeBind(_) => MessageKind::RuntimeBind,
            Self::RuntimeBindResult(_) => MessageKind::RuntimeBindResult,
            Self::SessionOpen => MessageKind::SessionOpen,
            Self::SessionOpenResult(_) => MessageKind::SessionOpenResult,
            Self::ReportHead => MessageKind::ReportHead,
            Self::ReportHeadResult(_) => MessageKind::ReportHeadResult,
            Self::ReportReplace(_) => MessageKind::ReportReplace,
            Self::ReportAccepted(_) => MessageKind::ReportAccepted,
            Self::SnapshotPush(_) => MessageKind::SnapshotPush,
            Self::SnapshotAck(_) => MessageKind::SnapshotAck,
            Self::ListenerReady(_) => MessageKind::ListenerReady,
            Self::LeaseRefresh(_) => MessageKind::LeaseRefresh,
            Self::LeaseAcquire(_) => MessageKind::LeaseAcquire,
            Self::LeaseResult(_) => MessageKind::LeaseResult,
            Self::PortResult(_) => MessageKind::PortResult,
            Self::PortCancel(_) => MessageKind::PortCancel,
            Self::PortQuery(_) => MessageKind::PortQuery,
            Self::PortQueryResult(_) => MessageKind::PortQueryResult,
            Self::ServiceRetryPort(_) => MessageKind::ServiceRetryPort,
            Self::Error(_) => MessageKind::Error,
        }
    }
}
