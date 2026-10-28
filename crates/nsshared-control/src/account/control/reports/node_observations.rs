//! Optional transport observations carried only by ordinary Node heartbeats.
use crate::account::{
    AccountError,
    codec::{identity, require},
};
use nsshared_codec::cbor::{CborReader, CborWriter};
use nsshared_identity::keys::IdentityKey;

/// Maximum entries in each Node heartbeat observation list.
pub const MAX_NODE_OBSERVATIONS: usize = 256;
/// Endpoint feature for gateway round-trip observations.
pub const GATEWAY_RTT_FEATURE: &str = "gateway_rtt.v1";
/// Capability and endpoint feature for full unhealthy-pair snapshots.
pub const PAIR_TRANSPORT_FALLBACK_FEATURE: &str = "pair_transport_fallback.v1";

/// One unhealthy transport pair, ordered by full peer key then gateway key.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PairTransportUnhealthy {
    /// Peer identity from authenticated peer publications.
    pub peer: IdentityKey,
    /// Gateway identity from authenticated gateway publications.
    pub gateway: IdentityKey,
}

/// Complete unhealthy set for one runtime; an empty set explicitly clears it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairTransportSnapshot {
    /// Must equal the enclosing request's runtime identifier.
    pub runtime_id: [u8; 16],
    /// Consumer-compared revision within this reporter/runtime.
    pub revision: u64,
    /// Strictly ordered unique pairs, bounded by [`MAX_NODE_OBSERVATIONS`].
    pub unhealthy: Vec<PairTransportUnhealthy>,
}
impl PairTransportSnapshot {
    pub(super) fn write(&self, out: &mut CborWriter) -> Result<(), AccountError> {
        if self.unhealthy.len() > MAX_NODE_OBSERVATIONS {
            return Err(AccountError::Bounds);
        }
        require(self.unhealthy.windows(2).all(|pair| pair[0] < pair[1]))?;
        out.array(3)
            .bytes(&self.runtime_id)
            .uint(self.revision)
            .array(self.unhealthy.len());
        for entry in &self.unhealthy {
            out.array(2)
                .bytes(entry.peer.as_bytes())
                .bytes(entry.gateway.as_bytes());
        }
        Ok(())
    }

    pub(super) fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        input.array(3)?;
        let runtime_id = input.fixed_bytes()?;
        let revision = input.uint()?;
        let count = input.array_up_to(MAX_NODE_OBSERVATIONS)?;
        let mut unhealthy = Vec::with_capacity(count);
        for _ in 0..count {
            input.array(2)?;
            unhealthy.push(PairTransportUnhealthy {
                peer: identity(input)?,
                gateway: identity(input)?,
            });
        }
        Ok(Self {
            runtime_id,
            revision,
            unhealthy,
        })
    }
}

/// Observed round-trip tier, without routing or authorization effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayRttTier {
    /// Below 30 milliseconds.
    Lt30,
    /// At least 30 and below 100 milliseconds.
    Lt100,
    /// At least 100 milliseconds.
    Ge100,
    /// No response to recent probes.
    Unreachable,
}
impl GatewayRttTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lt30 => "lt30",
            Self::Lt100 => "lt100",
            Self::Ge100 => "ge100",
            Self::Unreachable => "unreachable",
        }
    }

    fn read(input: &mut CborReader<'_>) -> Result<Self, AccountError> {
        match input.text_up_to(11)? {
            "lt30" => Ok(Self::Lt30),
            "lt100" => Ok(Self::Lt100),
            "ge100" => Ok(Self::Ge100),
            "unreachable" => Ok(Self::Unreachable),
            _ => Err(AccountError::Field),
        }
    }
}

/// One gateway measurement, keyed by its full published identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRttObservation {
    /// Gateway identity from authenticated gateway publications.
    pub gateway: IdentityKey,
    /// Observed latency or unreachability tier.
    pub tier: GatewayRttTier,
    /// Completed probes within this runtime.
    pub samples: u64,
    /// Timed-out probes within this runtime.
    pub timeouts: u64,
}

pub(super) fn write_rtt(
    out: &mut CborWriter,
    entries: &[GatewayRttObservation],
) -> Result<(), AccountError> {
    if entries.len() > MAX_NODE_OBSERVATIONS {
        return Err(AccountError::Bounds);
    }
    require(
        entries
            .windows(2)
            .all(|pair| pair[0].gateway < pair[1].gateway),
    )?;
    out.array(entries.len());
    for entry in entries {
        out.array(4)
            .bytes(entry.gateway.as_bytes())
            .text(entry.tier.as_str())
            .uint(entry.samples)
            .uint(entry.timeouts);
    }
    Ok(())
}

pub(super) fn read_rtt(
    input: &mut CborReader<'_>,
) -> Result<Vec<GatewayRttObservation>, AccountError> {
    let count = input.array_up_to(MAX_NODE_OBSERVATIONS)?;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        input.array(4)?;
        entries.push(GatewayRttObservation {
            gateway: identity(input)?,
            tier: GatewayRttTier::read(input)?,
            samples: input.uint()?,
            timeouts: input.uint()?,
        });
    }
    Ok(entries)
}
