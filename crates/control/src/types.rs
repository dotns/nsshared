//! Shared wire-level type tokens used across legacy JSON and signed-envelope
//! shapes.
//!
//! Types in this module are referenced by both [`crate::auth`] (legacy JSON
//! request bodies) and [`crate::api`] (CBOR envelope payloads). Centralising
//! them here keeps the two shapes from drifting and from minting independent
//! parallel enums for the same token set.

use serde::{Deserialize, Serialize};

/// WSS **leg** a machine asks NSD to scope a token to.
///
/// A unified node terminates two opaque WSS legs under one identity: a
/// consumer leg on NSGW's `/client` surface and a provider leg on its `/relay`
/// surface. NSD's role derivation is scalar today — a connector with any
/// service row resolves to `relay`, otherwise `client` — so exactly one of the
/// two legs is refused for a node that both publishes and consumes. Naming the
/// leg lets one identity request each leg separately.
///
/// # Request input only
///
/// This value is what the machine *asks for*. It is never self-asserting and
/// never a grant: NSD remains the sole authority and authorizes each leg
/// independently against the current projected pair and capability state at
/// issue time. NSD may refuse the requested leg, and an absent value keeps the
/// legacy scalar derivation.
///
/// Tokens match NSGW's `SessionRole` wire strings (`nsgw-wss::serve`), so a
/// minted token's `role` claim compares equal to the endpoint's expected role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WssLegRole {
    /// Consumer leg — NSGW's `/client` surface.
    Client,
    /// Provider leg — NSGW's `/relay` surface.
    Relay,
}

impl WssLegRole {
    /// Wire token for this leg.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Relay => "relay",
        }
    }

    /// Inverse of [`Self::as_str`]. Unknown tokens yield `None` and must never
    /// be coerced into a neighbouring leg.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "client" => Some(Self::Client),
            "relay" => Some(Self::Relay),
            _ => None,
        }
    }
}

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
