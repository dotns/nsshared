//! The region quick owner agreement and fencing decision.
//!
//! Every member of a region carries an optional quick owner with its epoch and presents it in the
//! control HELLO extension. The decision here classifies one control link and tracks, in memory,
//! whether the local member may still serve a quick pairing broker. It performs no I/O; the caller
//! serialises access to the state.

use crate::RegionHelloExtension;

/// A configured quick owner with its epoch, as held locally or presented in a HELLO extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionQuickOwner {
    owner: u8,
    epoch: u64,
}

impl RegionQuickOwner {
    /// Returns the claim for an owner in 1 through 16 and an epoch of at least 1, or `None`.
    pub fn new(owner: u8, epoch: u64) -> Option<Self> {
        ((1..=16).contains(&owner) && epoch != 0).then_some(Self { owner, epoch })
    }

    /// Returns the claim a HELLO extension presents, or `None` when its values are out of range.
    pub fn from_extension(extension: RegionHelloExtension) -> Option<Self> {
        Self::new(extension.quick_owner, extension.quick_owner_epoch)
    }

    /// The quick owner member identifier.
    pub const fn owner(self) -> u8 {
        self.owner
    }

    /// The quick owner epoch.
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
}

/// The quick owner state of one control link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionQuickLink {
    /// Both sides carry the same owner and the same epoch; only this link carries quick frames.
    Agreed,
    /// Neither side has an owner.
    Inactive,
    /// Any other combination, including a legacy HELLO read by a member that has an owner.
    Mismatched,
}

/// The result of reading one peer's HELLO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionQuickOwnerDecision {
    /// The state of the link to that peer.
    pub link: RegionQuickLink,
    /// Whether the local member may serve a quick pairing broker.
    pub may_serve: bool,
}

/// The in-memory fencing state of one member, created fresh when the member starts.
///
/// It records the highest owner epoch any peer has presented and whether peers presented that
/// epoch with more than one owner. Epochs below the highest need no record: a local epoch below
/// the highest is fenced regardless, and one above it is not fenced by any of them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RegionQuickOwnerState {
    highest: Option<RegionQuickOwner>,
    conflict: bool,
}

impl RegionQuickOwnerState {
    /// The highest owner epoch a peer has presented since the state was created, or 0.
    pub fn highest_observed_epoch(&self) -> u64 {
        self.highest.map_or(0, RegionQuickOwner::epoch)
    }

    /// Whether a member with the `local` owner configuration may serve a quick pairing broker.
    ///
    /// The member is fenced while a peer has presented an epoch higher than the local one, or the
    /// local epoch with a different owner. A local epoch above the highest observed one lifts the
    /// fence; a local epoch equal to it lifts the fence only when every peer presented that epoch
    /// with the local owner.
    pub fn may_serve(&self, local: Option<RegionQuickOwner>) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        match local {
            None => false,
            Some(local) if local.epoch > highest.epoch => true,
            Some(local) => local == highest && !self.conflict,
        }
    }

    fn observe(&mut self, peer: RegionQuickOwner) {
        match self.highest {
            Some(highest) if peer.epoch < highest.epoch => {}
            Some(highest) if peer.epoch == highest.epoch => {
                self.conflict |= peer.owner != highest.owner;
            }
            _ => {
                self.highest = Some(peer);
                self.conflict = false;
            }
        }
    }
}

/// Decides the link state for a peer HELLO and records the peer's claim in `state`.
///
/// `peer` is the claim of the HELLO extension, or `None` for a legacy HELLO. The returned
/// permission already includes this peer's claim and every claim recorded before it.
pub fn decide_region_quick_owner(
    state: &mut RegionQuickOwnerState,
    local: Option<RegionQuickOwner>,
    peer: Option<RegionQuickOwner>,
) -> RegionQuickOwnerDecision {
    if let Some(peer) = peer {
        state.observe(peer);
    }
    let link = match (local, peer) {
        (None, None) => RegionQuickLink::Inactive,
        (Some(local), Some(peer)) if local == peer => RegionQuickLink::Agreed,
        _ => RegionQuickLink::Mismatched,
    };
    RegionQuickOwnerDecision {
        link,
        may_serve: state.may_serve(local),
    }
}
