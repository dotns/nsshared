//! DATA forwarding helpers (quick-v2 §8.4).

use super::packet::{RelayBody, RelayPacket, RelayType};
use crate::identity::NodeId;
use thiserror::Error;

/// The WireGuard message type of a handshake initiation (quick-v2 §8.4).
pub const WIREGUARD_HANDSHAKE_INITIATION: u8 = 1;

/// Returns true when a DATA body is a WireGuard handshake initiation, judged by its first
/// byte only, for the per-destination handshake-initiation budget (quick-v2 §8.4).
#[must_use]
pub fn is_handshake_initiation(data: &[u8]) -> bool {
    data.first() == Some(&WIREGUARD_HANDSHAKE_INITIATION)
}

/// A relayed packet dropped by the receiver before decryption (quick-v2 §8.4).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum DataRejection {
    /// The packet is not DATA.
    #[error("{0:?} packet is not DATA")]
    NotData(RelayType),
    /// dst is not the receiver's own node ID.
    #[error("dst {0} is not the own node ID")]
    Destination(NodeId),
    /// src is not the node ID of an installed peer.
    #[error("src {0} is not an installed peer")]
    Source(NodeId),
}

/// The receiver's pre-decrypt check: dst is `own` and src is an installed peer node ID;
/// returns the WireGuard packet with the header stripped (quick-v2 §8.4).
///
/// # Errors
///
/// [`DataRejection`] naming the failed check.
pub fn accept_relayed_data<'a>(
    packet: &'a RelayPacket,
    own: &NodeId,
    is_installed_peer: impl FnOnce(&NodeId) -> bool,
) -> Result<&'a [u8], DataRejection> {
    let RelayBody::Data(data) = &packet.body else {
        return Err(DataRejection::NotData(packet.body.packet_type()));
    };
    if packet.dst != *own {
        return Err(DataRejection::Destination(packet.dst));
    }
    if !is_installed_peer(&packet.src) {
        return Err(DataRejection::Source(packet.src));
    }
    Ok(data)
}
