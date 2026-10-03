//! SNAPSHOT chunking and chunk sequences: quick-protocol §12.8 rule 6 with the v2 entry
//! bodies of quick-v2 §8.5.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test fixture helpers")]

use nsshared_wire::{
    MAX_REGION_FRAME_BYTES, MAX_REGION_SNAPSHOT_ENTRIES, NodeId, RegionCarrier, RegionChunkError,
    RegionFrame, RegionFrameError, RegionMarks, RegionPresent, RegionSnapshot,
    RegionSnapshotCursor, RegionSnapshotCut, RegionSnapshotSequenceError,
    check_region_snapshot_chunks, chunk_region_snapshot,
};
use proptest::prelude::*;

fn identity(index: u16, seed: u8) -> [u8; 32] {
    let mut identity = [seed; 32];
    identity[..2].copy_from_slice(&index.to_be_bytes());
    identity
}

fn present(index: u16, revision: u64) -> RegionPresent {
    let identity = identity(index, 0xa5);
    RegionPresent {
        slot: NodeId::derive(&identity),
        identity,
        generation: u64::MAX,
        incarnation: u64::MAX,
        carrier: RegionCarrier::Wss,
        boot_epoch: u64::MAX,
        revision,
    }
}

fn marks(index: u16) -> RegionMarks {
    RegionMarks {
        identity: identity(index, 0x5a),
        committed_gen: u64::MAX,
        committed_key: [0x44; 32],
        conflicted: true,
        incarnation_high_water: u64::MAX,
    }
}

fn cut(snapshot_id: u64) -> RegionSnapshotCut {
    RegionSnapshotCut {
        snapshot_id,
        base_revision: 1000,
        marks_revision: 77,
    }
}

/// Checks every chunking invariant and returns the chunks.
fn check_chunks(
    cut: RegionSnapshotCut,
    presence: &[RegionPresent],
    marks: &[RegionMarks],
) -> Vec<RegionSnapshot> {
    let chunks = chunk_region_snapshot(cut, presence, marks).unwrap();
    assert!(!chunks.is_empty());
    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk.chunk_index, u32::try_from(index).unwrap());
        assert_eq!(RegionSnapshotCut::of(chunk), cut);
        assert_eq!(chunk.more, index + 1 < chunks.len());
        assert!(chunk.presence.len() + chunk.marks.len() <= MAX_REGION_SNAPSHOT_ENTRIES);
        let frame = RegionFrame::Snapshot(chunk.clone());
        let encoded = frame.encode().unwrap();
        assert!(encoded.len() <= MAX_REGION_FRAME_BYTES);
        assert_eq!(RegionFrame::decode(&encoded), Ok(frame));
    }
    let all_presence: Vec<_> = chunks
        .iter()
        .flat_map(|chunk| chunk.presence.clone())
        .collect();
    let all_marks: Vec<_> = chunks
        .iter()
        .flat_map(|chunk| chunk.marks.clone())
        .collect();
    assert_eq!(all_presence, presence);
    assert_eq!(all_marks, marks);
    assert_eq!(check_region_snapshot_chunks(&chunks), Ok(cut));
    chunks
}

#[test]
fn empty_snapshot_yields_one_final_chunk() {
    let chunks = check_chunks(cut(1), &[], &[]);
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].presence.is_empty() && chunks[0].marks.is_empty());
    assert!(!chunks[0].more);
}

#[test]
fn large_snapshot_fills_chunks_to_the_frame_limit() {
    let presence: Vec<_> = (0..500)
        .map(|index| present(index, 1 + u64::from(index)))
        .collect();
    let marks: Vec<_> = (0..700).map(marks).collect();
    let chunks = check_chunks(cut(u64::MAX), &presence, &marks);
    assert!(chunks.len() > 2);
    // Every chunk but the last is full: one more entry of either kind would not fit.
    for chunk in &chunks[..chunks.len() - 1] {
        let size = RegionFrame::Snapshot(chunk.clone()).encode().unwrap().len();
        assert!(size > MAX_REGION_FRAME_BYTES - 128, "chunk of {size} bytes");
    }
    // A chunk may hold both presence and mark entries.
    assert!(
        chunks
            .iter()
            .any(|chunk| !chunk.presence.is_empty() && !chunk.marks.is_empty())
    );
}

#[test]
fn refutation_chunking_zero_snapshot_id() {
    assert_eq!(
        chunk_region_snapshot(cut(0), &[], &[]),
        Err(RegionChunkError::Frame(RegionFrameError::ZeroSnapshotId))
    );
}

#[test]
fn refutation_chunking_invalid_presence_entry() {
    assert_eq!(
        chunk_region_snapshot(cut(1), &[present(1, 1001)], &[]),
        Err(RegionChunkError::Frame(RegionFrameError::EntryAfterCut {
            revision: 1001,
            base_revision: 1000
        }))
    );
    let mut wrong_slot = present(1, 1);
    wrong_slot.slot = NodeId::from_bytes([1; 12]);
    assert_eq!(
        chunk_region_snapshot(cut(1), &[wrong_slot], &[]),
        Err(RegionChunkError::Frame(RegionFrameError::SlotMismatch))
    );
}

#[test]
fn refutation_chunking_duplicate_owner_across_chunks() {
    let mut presence: Vec<_> = (0..200).map(|index| present(index, 1)).collect();
    presence.push(present(0, 2));
    assert_eq!(
        chunk_region_snapshot(cut(1), &presence, &[]),
        Err(RegionChunkError::Frame(RegionFrameError::DuplicateOwner(
            "presence"
        )))
    );
    let marks: Vec<_> = [1, 2, 1].into_iter().map(marks).collect();
    assert_eq!(
        chunk_region_snapshot(cut(1), &[], &marks),
        Err(RegionChunkError::Frame(RegionFrameError::DuplicateOwner(
            "mark"
        )))
    );
}

fn chunk(index: u32, more: bool) -> RegionSnapshot {
    RegionSnapshot {
        snapshot_id: 9,
        base_revision: 5,
        marks_revision: 6,
        chunk_index: index,
        presence: Vec::new(),
        marks: Vec::new(),
        more,
    }
}

#[test]
fn cursor_tracks_completion() {
    let mut cursor = RegionSnapshotCursor::start(&chunk(0, true)).unwrap();
    assert!(!cursor.is_complete());
    cursor.accept(&chunk(1, true)).unwrap();
    cursor.accept(&chunk(2, false)).unwrap();
    assert!(cursor.is_complete());
    assert_eq!(cursor.cut(), RegionSnapshotCut::of(&chunk(0, true)));
}

#[test]
fn refutation_sequence_first_chunk_index() {
    assert_eq!(
        RegionSnapshotCursor::start(&chunk(1, true)),
        Err(RegionSnapshotSequenceError::FirstChunkIndex(1))
    );
}

#[test]
fn refutation_sequence_snapshot_id_changes() {
    let mut cursor = RegionSnapshotCursor::start(&chunk(0, true)).unwrap();
    let mut other = chunk(1, false);
    other.snapshot_id = 10;
    assert_eq!(
        cursor.accept(&other),
        Err(RegionSnapshotSequenceError::SnapshotId {
            expected: 9,
            actual: 10
        })
    );
}

#[test]
fn refutation_sequence_cut_changes() {
    let mut cursor = RegionSnapshotCursor::start(&chunk(0, true)).unwrap();
    let mut other = chunk(1, false);
    other.base_revision = 6;
    assert_eq!(
        cursor.accept(&other),
        Err(RegionSnapshotSequenceError::CutChanged)
    );
    let mut other = chunk(1, false);
    other.marks_revision = 7;
    assert_eq!(
        cursor.accept(&other),
        Err(RegionSnapshotSequenceError::CutChanged)
    );
    // The cursor is unchanged after a rejection.
    assert_eq!(cursor.accept(&chunk(1, false)), Ok(()));
}

#[test]
fn refutation_sequence_skipped_or_repeated_index() {
    let mut cursor = RegionSnapshotCursor::start(&chunk(0, true)).unwrap();
    assert_eq!(
        cursor.accept(&chunk(2, true)),
        Err(RegionSnapshotSequenceError::ChunkIndex {
            expected: 1,
            actual: 2
        })
    );
    assert_eq!(
        cursor.accept(&chunk(0, true)),
        Err(RegionSnapshotSequenceError::ChunkIndex {
            expected: 1,
            actual: 0
        })
    );
}

#[test]
fn refutation_sequence_chunk_after_last() {
    let mut cursor = RegionSnapshotCursor::start(&chunk(0, false)).unwrap();
    assert_eq!(
        cursor.accept(&chunk(1, false)),
        Err(RegionSnapshotSequenceError::AfterLast)
    );
    assert_eq!(
        check_region_snapshot_chunks(&[chunk(0, false), chunk(1, false)]),
        Err(RegionSnapshotSequenceError::AfterLast)
    );
}

#[test]
fn refutation_sequence_incomplete_or_empty() {
    assert_eq!(
        check_region_snapshot_chunks(&[]),
        Err(RegionSnapshotSequenceError::Empty)
    );
    assert_eq!(
        check_region_snapshot_chunks(&[chunk(0, true), chunk(1, true)]),
        Err(RegionSnapshotSequenceError::Incomplete)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn chunking_preserves_order_and_limits(
        presence_count in 0..400_u16,
        marks_count in 0..400_u16,
        snapshot_id in 1..=u64::MAX,
        base_revision in 400..=u64::MAX,
        marks_revision in any::<u64>(),
        revisions in prop::collection::vec(1..400_u64, 400),
    ) {
        let presence: Vec<_> = (0..presence_count)
            .map(|index| present(index, revisions[usize::from(index)]))
            .collect();
        let marks: Vec<_> = (0..marks_count).map(marks).collect();
        check_chunks(
            RegionSnapshotCut { snapshot_id, base_revision, marks_revision },
            &presence,
            &marks,
        );
    }
}
