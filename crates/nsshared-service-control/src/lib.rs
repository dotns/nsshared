#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Pure wire types and deterministic CBOR for M6 private service control.
//! Authentication and durable state transitions belong to the caller.
//!
//! Deprecated facade: the contract is `nsshared_control::service` on the M6 value
//! profile of `nsshared_codec::cbor::value`. This crate keeps the existing paths.

pub mod cbor;

/// Versioned M6 service-control message and digest types.
pub mod contract {
    pub use nsshared_control::service::{
        BackendHost, CAPABILITY, ContractError, Declaration, Digest, Id, Identity, LOCAL_SCHEMA,
        ListenerIntent, MAX_LEASE_MS, PortMode, Protocols, REFRESH_MS, ReportContent, SCHEMA,
        ServiceRef, domain_digest, next_revision, snapshot_digest,
    };
}

/// Strongly typed service-control messages. The raw CBOR value is private.
pub mod message {
    pub use nsshared_control::service::{
        LeaseAcquire, LeaseResult, Message, MessageBody, MessageKind, PortProposal, PortResult,
        ReadyProof, ReportAccepted, ReportBinding, ReportReplace, RuntimeBind, RuntimeFloorResult,
        ServiceLeaseRef, SnapshotAck, SnapshotPush,
    };
}

/// Typed full recipient snapshots. Every nested map and collection is validated.
pub mod snapshot {
    pub use nsshared_control::service::{
        Grant, PublisherListener, Resource, Route, Snapshot, Withdrawal,
    };
}

pub use cbor::{CborError, Value, decode_canonical, encode_canonical};
pub use contract::*;
pub use message::*;
pub use snapshot::*;

/// Versioned whole-floor report types on the existing M6 carrier.
pub use nsshared_control::service::{
    ExitSelection, FloorContent, FloorExitProfile, FloorMetadata, FloorReportMessage,
    FloorReportReplace, MAX_FLOOR_BYTES, MAX_FLOOR_ITEMS, MAX_FLOOR_TEXT,
};
