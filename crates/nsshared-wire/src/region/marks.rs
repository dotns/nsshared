//! The monotone region mark merge and its link to the per-identity record state
//! (quick-v2 §3.3, §8.5, quick-protocol §12.8 rule 2).

use super::frame::RegionMarks;
use crate::record::RecordMarks;
use thiserror::Error;

/// The result of joining two MARKS for one owner (quick-protocol §12.8 rule 2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionMarksJoin {
    /// The joined state.
    pub state: RegionMarks,
    /// Whether `state` differs from the caller's current state; an unchanged result is not
    /// re-sent (quick-protocol §12.8).
    pub changed: bool,
}

/// The two MARKS name different owners `I` (quick-protocol §12.8 rule 2).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("MARKS name different owners")]
pub struct RegionMarksOwnerMismatch;

/// Joins `incoming` into `current` for the same owner `I` (quick-v2 §8.5,
/// quick-protocol §12.8 rule 2 without `revoked_through`).
///
/// The larger `committed_gen` wins together with its `committed_K`, `conflicted` and
/// `incarnation_high_water`; an older generation's incarnation never carries into a newer
/// one. At equal generation the incarnation high water is the maximum, `conflicted` is the
/// OR and latches true when the keys differ, and the lexicographically smaller key is kept
/// only as the deterministic representative. The join is commutative, associative,
/// idempotent and monotone in `committed_gen`. No persistence or other effect is applied.
///
/// # Errors
///
/// [`RegionMarksOwnerMismatch`] when the identities differ.
pub fn join_region_marks(
    current: RegionMarks,
    incoming: RegionMarks,
) -> Result<RegionMarksJoin, RegionMarksOwnerMismatch> {
    if current.identity != incoming.identity {
        return Err(RegionMarksOwnerMismatch);
    }
    let state = if current.committed_gen > incoming.committed_gen {
        current
    } else if current.committed_gen < incoming.committed_gen {
        incoming
    } else {
        RegionMarks {
            identity: current.identity,
            committed_gen: current.committed_gen,
            committed_key: current.committed_key.min(incoming.committed_key),
            conflicted: current.conflicted
                || incoming.conflicted
                || current.committed_key != incoming.committed_key,
            incarnation_high_water: current
                .incarnation_high_water
                .max(incoming.incarnation_high_water),
        }
    };
    Ok(RegionMarksJoin {
        changed: state != current,
        state,
    })
}

impl RegionMarks {
    /// Builds the MARKS of a per-identity record state: its identity, `committed_gen`, the
    /// committed `K` and the latched conflict flag, plus the caller's incarnation high water
    /// for that generation (quick-v2 §3.3, §8.5).
    ///
    /// Returns `None` before the first record, when there is no committed `K`. The mapping is
    /// one way: a MARKS carries no NodeRecord, so it cannot rebuild a [`RecordMarks`]. For a
    /// conflicted generation `RecordMarks` keeps the first accepted key, which may differ
    /// from the representative chosen by [`join_region_marks`]; the region state only uses
    /// it as a representative.
    #[must_use]
    pub fn from_record_marks(marks: &RecordMarks, incarnation_high_water: u64) -> Option<Self> {
        let record = marks.current()?;
        Some(Self {
            identity: *marks.identity(),
            committed_gen: record.generation(),
            committed_key: *record.wg_key(),
            conflicted: marks.is_conflicted(),
            incarnation_high_water,
        })
    }
}
