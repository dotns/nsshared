#![forbid(unsafe_code)]
#![allow(missing_docs)]

//! Accept-only ACL engine for NSN.
//!
//! Evaluates access contexts against an [`AclPolicy`] loaded from the control
//! plane.  The default action is **deny**; rules explicitly grant access to
//! verified source subjects and destinations.
//!
//! Key exports:
//! - [`AclEngine`] — thread-safe engine, updated atomically on policy reload.
//! - [`AclPolicy`] — policy data model (rules, groups, bindings, tests).
//! - [`AccessContext`] — input for an access decision.
//! - [`AclDecision`] — `Allow` or `Deny` outcome.

pub mod deny_scope;
pub mod engine;
pub mod matcher;
pub mod merge;
pub mod policy;
pub mod subject;

pub use deny_scope::{DenyScope, DenyScopeOutcome, DropReason, DroppedRule, apply_deny_scope};
pub use engine::{
    AccessContext, AclDecision, AclEngine, AclTestFailure, NetworkTuple, SourceAssertion,
    SourceIdentity, TargetIdentity, TerminateBinding, TransportKind, valid_subject, wg_peer_anchor,
};
pub use merge::{
    MergeStats, MergedPolicy, PolicyLayers, RemotePolicy, RuleProvenance, merge_layered,
};
pub use policy::{AclPolicy, PolicyLint};
pub use subject::{encode_external_subject, encode_subject_component};

use thiserror::Error;

/// Errors produced by the ACL crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid CIDR '{addr}': {reason}")]
    InvalidCidr { addr: String, reason: String },

    #[error("invalid destination '{dst}': {reason}")]
    InvalidDst { dst: String, reason: String },

    #[error("unknown host alias: '{0}'")]
    UnknownAlias(String),

    #[error("{count} policy test(s) failed")]
    TestsFailed { count: usize },

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
}
