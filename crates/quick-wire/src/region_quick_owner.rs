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
/// It records the highest owner epoch any peer has presented and the owner every peer presented
/// with it, if there is one. Epochs below the highest need no record: a local epoch below the
/// highest is fenced regardless, and one above it is not fenced by any of them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RegionQuickOwnerState {
    highest: Option<ObservedEpoch>,
}

/// The highest epoch presented by a peer and its owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObservedEpoch {
    epoch: u64,
    /// `None` when peers presented the epoch with different owners or with an out-of-range claim.
    owner: Option<u8>,
}

impl RegionQuickOwnerState {
    /// The highest owner epoch a peer has presented since the state was created, or 0.
    pub fn highest_observed_epoch(&self) -> u64 {
        self.highest.map_or(0, |highest| highest.epoch)
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
        let local_epoch = local.map_or(0, RegionQuickOwner::epoch);
        local_epoch > highest.epoch
            || (local_epoch == highest.epoch
                && local.is_some_and(|local| highest.owner == Some(local.owner)))
    }

    /// Records one presented epoch; `owner` is `None` for a claim whose values are out of range.
    fn observe(&mut self, epoch: u64, owner: Option<u8>) {
        match &mut self.highest {
            Some(highest) if epoch < highest.epoch => {}
            Some(highest) if epoch == highest.epoch => {
                if highest.owner != owner {
                    highest.owner = None;
                }
            }
            _ => self.highest = Some(ObservedEpoch { epoch, owner }),
        }
    }
}

/// Decides the link state for a peer HELLO and records the peer's claim in `state`.
///
/// `peer` is the extension of the peer's HELLO, or `None` for the legacy HELLO. An extension whose
/// owner is outside 1 through 16 or whose epoch is 0 is recorded as its epoch with no acceptable
/// owner: the link is mismatched and the member is fenced until its local epoch exceeds that
/// epoch. It never fences less than a valid claim with the same epoch. The returned permission
/// includes this peer's claim and every claim recorded before it.
pub fn decide_region_quick_owner(
    state: &mut RegionQuickOwnerState,
    local: Option<RegionQuickOwner>,
    peer: Option<RegionHelloExtension>,
) -> RegionQuickOwnerDecision {
    let link = match (local, peer) {
        (None, None) => RegionQuickLink::Inactive,
        (_, None) => RegionQuickLink::Mismatched,
        (local, Some(extension)) => {
            let claim = RegionQuickOwner::new(extension.quick_owner, extension.quick_owner_epoch);
            state.observe(
                extension.quick_owner_epoch,
                claim.map(RegionQuickOwner::owner),
            );
            match (local, claim) {
                (Some(local), Some(claim)) if local == claim => RegionQuickLink::Agreed,
                _ => RegionQuickLink::Mismatched,
            }
        }
    };
    RegionQuickOwnerDecision {
        link,
        may_serve: state.may_serve(local),
    }
}
