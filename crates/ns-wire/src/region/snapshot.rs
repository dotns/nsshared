//! SNAPSHOT chunking and the per-chunk sequence check (quick-protocol §12.8 rule 6).

use super::frame::{
    MAX_REGION_FRAME_BYTES, MAX_REGION_SNAPSHOT_ENTRIES, RegionFrameError, RegionMarks,
    RegionPresent, RegionSnapshot, marks_len, present_len,
};
use crate::identity::Identity;
use std::collections::BTreeSet;
use thiserror::Error;

/// The snapshot cut shared by every chunk of one snapshot (quick-protocol §12.8 rule 6).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RegionSnapshotCut {
    /// The non-zero sender snapshot counter.
    pub snapshot_id: u64,
    /// The presence revision of the cut.
    pub base_revision: u64,
    /// The sender's durable marks revision of the cut.
    pub marks_revision: u64,
}

impl RegionSnapshotCut {
    /// Returns the cut carried by a chunk (quick-protocol §12.8 rule 6).
    #[must_use]
    pub const fn of(chunk: &RegionSnapshot) -> Self {
        Self {
            snapshot_id: chunk.snapshot_id,
            base_revision: chunk.base_revision,
            marks_revision: chunk.marks_revision,
        }
    }
}

/// A snapshot that cannot be split into chunks (quick-protocol §12.8 rule 6).
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegionChunkError {
    /// The cut or an entry violates a SNAPSHOT field rule.
    #[error("invalid snapshot content: {0}")]
    Frame(#[from] RegionFrameError),
    /// The entry at this position (presence entries first, then marks) does not fit in a
    /// frame on its own.
    #[error("snapshot entry {0} does not fit in one frame")]
    EntryTooLarge(usize),
    /// The snapshot needs more chunks than a u32 `chunk_index` can number.
    #[error("snapshot chunk_index would overflow")]
    ChunkIndexOverflow,
}

/// Splits a snapshot into SNAPSHOT chunks (quick-protocol §12.8 rule 6).
///
/// Presence entries are placed first, then mark entries, both in input order and never
/// split. Each chunk holds at most 256 combined entries and encodes to at most 4096 bytes;
/// `chunk_index` runs contiguously from 0 and only the last chunk has `more = false`. An
/// empty snapshot yields one chunk with empty lists. Each owner may appear at most once per
/// entry list across the whole snapshot.
///
/// # Errors
///
/// [`RegionChunkError::Frame`] for a zero `snapshot_id`, an invalid presence entry or a
/// duplicate owner, [`RegionChunkError::EntryTooLarge`] or
/// [`RegionChunkError::ChunkIndexOverflow`].
pub fn chunk_region_snapshot(
    cut: RegionSnapshotCut,
    presence: &[RegionPresent],
    marks: &[RegionMarks],
) -> Result<Vec<RegionSnapshot>, RegionChunkError> {
    if cut.snapshot_id == 0 {
        return Err(RegionFrameError::ZeroSnapshotId.into());
    }
    for present in presence {
        present.validate_entry(cut.base_revision)?;
    }
    if has_duplicate(presence.iter().map(|present| &present.identity)) {
        return Err(RegionFrameError::DuplicateOwner("presence").into());
    }
    if has_duplicate(marks.iter().map(|marks| &marks.identity)) {
        return Err(RegionFrameError::DuplicateOwner("mark").into());
    }

    let entries: Vec<usize> = presence
        .iter()
        .map(present_len)
        .chain(marks.iter().map(marks_len))
        .collect();
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut chunk_index: u32 = 0;
    loop {
        let fixed = fixed_len(cut, chunk_index);
        let mut end = start;
        let mut body = 0_usize;
        while let Some(&length) = entries.get(end) {
            let count = end - start + 1;
            let presence_count = presence.len().saturating_sub(start).min(count);
            let marks_count = count - presence_count;
            let total = fixed
                .saturating_add(head_len(presence_count))
                .saturating_add(head_len(marks_count))
                .saturating_add(body)
                .saturating_add(length);
            if count > MAX_REGION_SNAPSHOT_ENTRIES || total > MAX_REGION_FRAME_BYTES {
                break;
            }
            body += length;
            end += 1;
        }
        if end == start && end < entries.len() {
            return Err(RegionChunkError::EntryTooLarge(start));
        }
        let more = end < entries.len();
        let split = presence.len();
        chunks.push(RegionSnapshot {
            snapshot_id: cut.snapshot_id,
            base_revision: cut.base_revision,
            marks_revision: cut.marks_revision,
            chunk_index,
            presence: presence
                .get(start.min(split)..end.min(split))
                .unwrap_or_default()
                .to_vec(),
            marks: marks
                .get(start.max(split) - split..end.max(split) - split)
                .unwrap_or_default()
                .to_vec(),
            more,
        });
        if !more {
            return Ok(chunks);
        }
        start = end;
        chunk_index = chunk_index
            .checked_add(1)
            .ok_or(RegionChunkError::ChunkIndexOverflow)?;
    }
}

/// A violation of the chunk sequence of one snapshot (quick-protocol §12.8 rule 6).
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegionSnapshotSequenceError {
    /// No chunk was supplied.
    #[error("snapshot has no chunks")]
    Empty,
    /// The first chunk does not have `chunk_index = 0`.
    #[error("first snapshot chunk has chunk_index {0}")]
    FirstChunkIndex(u32),
    /// A chunk carries a different `snapshot_id`.
    #[error("snapshot_id changed from {expected} to {actual}")]
    SnapshotId {
        /// The snapshot id of the first chunk.
        expected: u64,
        /// The snapshot id of this chunk.
        actual: u64,
    },
    /// A chunk carries a different `base_revision` or `marks_revision`.
    #[error("snapshot cut changed between chunks")]
    CutChanged,
    /// A chunk index is skipped or repeated.
    #[error("chunk_index {actual}, expected {expected}")]
    ChunkIndex {
        /// The next expected index.
        expected: u32,
        /// The received index.
        actual: u32,
    },
    /// A chunk arrived after the chunk with `more = false`.
    #[error("chunk after the last snapshot chunk")]
    AfterLast,
    /// `more = true` on chunk index `u32::MAX`; the index never wraps.
    #[error("snapshot chunk_index would overflow")]
    ChunkIndexOverflow,
    /// The chunks end without a chunk with `more = false`.
    #[error("snapshot ends before its last chunk")]
    Incomplete,
}

/// The receiver's sequence state for the chunks of one incoming snapshot
/// (quick-protocol §12.8 rule 6).
///
/// Only the chunk headers are checked; each chunk's own field rules are checked by
/// [`RegionSnapshot::validate`] when it is decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSnapshotCursor {
    cut: RegionSnapshotCut,
    next_chunk_index: Option<u32>,
}

impl RegionSnapshotCursor {
    /// Starts a snapshot from its first chunk, which must have `chunk_index = 0`
    /// (quick-protocol §12.8 rule 6).
    ///
    /// # Errors
    ///
    /// [`RegionSnapshotSequenceError::FirstChunkIndex`] or
    /// [`RegionSnapshotSequenceError::ChunkIndexOverflow`].
    pub fn start(first: &RegionSnapshot) -> Result<Self, RegionSnapshotSequenceError> {
        if first.chunk_index != 0 {
            return Err(RegionSnapshotSequenceError::FirstChunkIndex(
                first.chunk_index,
            ));
        }
        let mut cursor = Self {
            cut: RegionSnapshotCut::of(first),
            next_chunk_index: Some(0),
        };
        cursor.accept(first)?;
        Ok(cursor)
    }

    /// Accepts the next chunk: same snapshot id and cut, the next contiguous index, and no
    /// chunk after the last (quick-protocol §12.8 rule 6).
    ///
    /// # Errors
    ///
    /// [`RegionSnapshotSequenceError`] naming the violated rule; the cursor is unchanged.
    pub fn accept(&mut self, chunk: &RegionSnapshot) -> Result<(), RegionSnapshotSequenceError> {
        let expected = self
            .next_chunk_index
            .ok_or(RegionSnapshotSequenceError::AfterLast)?;
        if chunk.snapshot_id != self.cut.snapshot_id {
            return Err(RegionSnapshotSequenceError::SnapshotId {
                expected: self.cut.snapshot_id,
                actual: chunk.snapshot_id,
            });
        }
        if RegionSnapshotCut::of(chunk) != self.cut {
            return Err(RegionSnapshotSequenceError::CutChanged);
        }
        if chunk.chunk_index != expected {
            return Err(RegionSnapshotSequenceError::ChunkIndex {
                expected,
                actual: chunk.chunk_index,
            });
        }
        self.next_chunk_index = if chunk.more {
            Some(
                expected
                    .checked_add(1)
                    .ok_or(RegionSnapshotSequenceError::ChunkIndexOverflow)?,
            )
        } else {
            None
        };
        Ok(())
    }

    /// Returns the snapshot cut (quick-protocol §12.8 rule 6).
    #[must_use]
    pub const fn cut(&self) -> RegionSnapshotCut {
        self.cut
    }

    /// Returns true once the chunk with `more = false` has been accepted
    /// (quick-protocol §12.8 rule 6).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.next_chunk_index.is_none()
    }
}

/// Checks that `chunks` form exactly one complete snapshot sequence
/// (quick-protocol §12.8 rule 6).
///
/// # Errors
///
/// [`RegionSnapshotSequenceError`] naming the violated rule, including
/// [`RegionSnapshotSequenceError::Empty`] and [`RegionSnapshotSequenceError::Incomplete`].
pub fn check_region_snapshot_chunks(
    chunks: &[RegionSnapshot],
) -> Result<RegionSnapshotCut, RegionSnapshotSequenceError> {
    let (first, rest) = chunks
        .split_first()
        .ok_or(RegionSnapshotSequenceError::Empty)?;
    let mut cursor = RegionSnapshotCursor::start(first)?;
    for chunk in rest {
        cursor.accept(chunk)?;
    }
    if cursor.is_complete() {
        Ok(cursor.cut())
    } else {
        Err(RegionSnapshotSequenceError::Incomplete)
    }
}

/// Encoded length of a SNAPSHOT frame without its entries and entry-list heads.
fn fixed_len(cut: RegionSnapshotCut, chunk_index: u32) -> usize {
    // Frame array head, ver, type, body array head and the `more` boolean.
    5 + head_len_u64(cut.snapshot_id)
        + head_len_u64(cut.base_revision)
        + head_len_u64(cut.marks_revision)
        + head_len_u64(u64::from(chunk_index))
}

fn head_len(value: usize) -> usize {
    head_len_u64(value as u64)
}

/// Length of a canonical CBOR item head carrying `value` (quick-v2 §12.1).
const fn head_len_u64(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn has_duplicate<'a>(identities: impl Iterator<Item = &'a Identity>) -> bool {
    let mut seen = BTreeSet::new();
    identities
        .into_iter()
        .any(|identity| !seen.insert(identity))
}
