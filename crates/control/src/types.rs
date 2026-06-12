//! Shared wire-level type tokens used across legacy JSON and signed-envelope
//! shapes.
//!
//! Types in this module are referenced by both [`crate::auth`] (legacy JSON
//! request bodies) and [`crate::api`] (CBOR envelope payloads). Centralising
//! them here keeps the two shapes from drifting and from minting independent
//! parallel enums for the same token set.

use serde::{Deserialize, Serialize};

/// Role of a machine registering with NSD.
///
/// Mirrors `nsd_store::MachineType` on the server side. Serialised as a
/// lowercase string so the token set matches the existing nsd-mock TS shape
/// (`"connector"`, `"gateway"`).
///
/// No `#[serde(other)]` fallback: an unknown variant must surface a
/// deserialization error so server-side feature drift is caught immediately,
/// not silently bucketed into `Connector`. Server-side semantics treat an
/// *absent* `type` field as [`ConnectorType::Connector`] (the wire shape
/// makes the field `Option<ConnectorType>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectorType {
    /// NSN-style outbound machine (default semantic when the field is absent).
    Connector,
    /// NSGW-style inbound machine that needs `gateway.report` privileges.
    Gateway,
}
