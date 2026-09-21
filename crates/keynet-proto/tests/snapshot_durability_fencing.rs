use keynet_proto::{
    RegionMarks, RegionPresenceCapacity, RegionPresenceOrigin, RegionPresenceStream,
    RegionPresenceTable, RegionSnapshot, RegionSnapshotCompletionInput, RegionSnapshotDecision,
    RegionSnapshotDisposition, RegionSnapshotEffect, RegionSnapshotStagingCapacity,
    RegionSnapshotStagingInput, RegionSnapshotStagingTable, begin_region_snapshot_control,
    complete_region_snapshot, join_region_marks, stage_region_snapshot,
};

fn origin() -> RegionPresenceOrigin {
    RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 9,
    }
}

fn mark() -> RegionMarks {
    RegionMarks {
        network_id: [1; 32],
        identity: [2; 32],
        committed_generation: 4,
        committed_key: [3; 32],
        conflicted: true,
        revoked_through: Some(2),
        incarnation_high_water: 7,
    }
}

fn input(durable_marks: &[RegionMarks], maximum_origins: usize) -> RegionSnapshotStagingInput<'_> {
    RegionSnapshotStagingInput {
        stream: RegionPresenceStream {
            origin: origin(),
            is_current: true,
        },
        durable_marks,
        capacity: RegionSnapshotStagingCapacity {
            maximum_origins,
            maximum_entries: 1,
            maximum_mark_owners: 2,
            maximum_mark_staging_bytes: 64 * 1024,
        },
    }
}

fn snapshot(
    snapshot_id: u64,
    chunk_index: u32,
    mark_entries: Vec<RegionMarks>,
    more: bool,
) -> RegionSnapshot {
    RegionSnapshot {
        snapshot_id,
        base_revision: 0,
        marks_revision: 1,
        chunk_index,
        presence_entries: Vec::new(),
        mark_entries,
        more,
    }
}

fn drained(required: RegionMarks) -> RegionSnapshotDecision {
    let first = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(7, 0, vec![required], true),
        input(&[], 1),
    );
    assert_eq!(first.disposition, RegionSnapshotDisposition::Staged);
    assert_eq!(
        first.effects,
        vec![RegionSnapshotEffect::PersistDurableMark(required)]
    );
    let last = stage_region_snapshot(
        &first.table,
        &first.staging,
        snapshot(7, 1, Vec::new(), false),
        input(&[required], 1),
    );
    assert_eq!(
        last.disposition,
        RegionSnapshotDisposition::AwaitingDurableMarks
    );
    assert!(last.effects.is_empty());
    last
}

fn complete(
    stage: &RegionSnapshotDecision,
    durable_marks: &[RegionMarks],
) -> RegionSnapshotDecision {
    complete_region_snapshot(
        &stage.table,
        &stage.staging,
        RegionSnapshotCompletionInput {
            stream: input(&[], 1).stream,
            snapshot_id: 7,
            durable_marks,
            channel_states: &[],
            capacity: RegionPresenceCapacity { maximum_entries: 1 },
        },
    )
}

fn rejects_regression(current: RegionMarks) -> Result<(), String> {
    let required = mark();
    let joined = join_region_marks(current, required).map_err(|error| format!("{error:?}"))?;
    assert_ne!(
        joined.state, current,
        "the supplied record must not dominate the cut"
    );
    let stage = drained(required);
    let completed = complete(&stage, &[current]);
    assert_eq!(
        completed.disposition,
        RegionSnapshotDisposition::DurableMarksNotPersisted,
        "a same-owner record lost part of the previously persisted cut"
    );
    assert_eq!(completed.table, stage.table);
    assert!(completed.staging.stages.is_empty());
    assert!(completed.effects.is_empty());
    assert!(
        completed
            .table
            .origins
            .iter()
            .all(|state| state.snapshot_required)
    );
    Ok(())
}

#[test]
fn drained_generation_must_remain_durable() -> Result<(), String> {
    rejects_regression(RegionMarks {
        committed_generation: 3,
        ..mark()
    })
}

#[test]
fn drained_incarnation_must_remain_durable() -> Result<(), String> {
    rejects_regression(RegionMarks {
        incarnation_high_water: 6,
        ..mark()
    })
}

#[test]
fn drained_revocation_must_remain_durable() -> Result<(), String> {
    rejects_regression(RegionMarks {
        revoked_through: None,
        ..mark()
    })
}

#[test]
fn drained_conflict_must_remain_durable() -> Result<(), String> {
    rejects_regression(RegionMarks {
        conflicted: false,
        ..mark()
    })
}

#[test]
fn drained_key_representative_must_remain_durable() -> Result<(), String> {
    rejects_regression(RegionMarks {
        committed_key: [8; 32],
        ..mark()
    })
}

#[test]
fn unchanged_and_dominating_durable_records_complete() {
    let stage = drained(mark());
    assert_eq!(
        complete(&stage, &[mark()]).disposition,
        RegionSnapshotDisposition::Completed
    );
    let stronger = RegionMarks {
        committed_generation: 5,
        committed_key: [9; 32],
        conflicted: false,
        incarnation_high_water: 1,
        ..mark()
    };
    assert_eq!(
        complete(&stage, &[stronger]).disposition,
        RegionSnapshotDisposition::Completed
    );
}

#[test]
fn losing_a_required_record_is_rejected() {
    assert_eq!(
        complete(&drained(mark()), &[]).disposition,
        RegionSnapshotDisposition::DurableMarksNotPersisted
    );
}

fn origin_overflow(reconnect: bool) {
    let overflowed = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(7, 0, Vec::new(), false),
        input(&[], 0),
    );
    assert_eq!(
        overflowed.disposition,
        RegionSnapshotDisposition::CapacityExhausted
    );
    assert!(overflowed.staging.stages.is_empty());
    assert!(overflowed.effects.is_empty());
    let retry_state = if reconnect {
        begin_region_snapshot_control(&overflowed.table, &overflowed.staging, input(&[], 1).stream)
    } else {
        overflowed
    };
    let fresh = stage_region_snapshot(
        &retry_state.table,
        &retry_state.staging,
        snapshot(8, 0, Vec::new(), false),
        input(&[], 1),
    );
    assert_eq!(
        fresh.disposition,
        RegionSnapshotDisposition::AwaitingDurableMarks,
        "capacity recovery must admit a fresh identifier"
    );
    let reused = stage_region_snapshot(
        &retry_state.table,
        &retry_state.staging,
        snapshot(7, 0, Vec::new(), false),
        input(&[], 1),
    );
    assert_eq!(
        reused.disposition,
        RegionSnapshotDisposition::ChunkAfterCompletion,
        "origin-capacity rejection must consume the abandoned identifier"
    );
    assert!(reused.staging.stages.is_empty());
    assert!(reused.effects.is_empty());
}

#[test]
fn origin_capacity_failure_consumes_snapshot_id() {
    origin_overflow(false);
}

#[test]
fn origin_capacity_failure_consumes_snapshot_id_across_reconnect() {
    origin_overflow(true);
}
