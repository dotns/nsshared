use keynet_proto::{
    RegionMarks, RegionPresenceCapacity, RegionPresenceChannels, RegionPresenceOrigin,
    RegionPresenceStream, RegionPresenceTable, RegionSnapshot, RegionSnapshotCompletionInput,
    RegionSnapshotDisposition, RegionSnapshotStagingCapacity, RegionSnapshotStagingInput,
    RegionSnapshotStagingTable, complete_region_snapshot, stage_region_snapshot,
};

fn mark(index: u16) -> RegionMarks {
    let mut identity = [0; 32];
    identity[..2].copy_from_slice(&index.to_be_bytes());
    RegionMarks {
        network_id: [1; 32],
        identity,
        committed_generation: 1,
        committed_key: [2; 32],
        conflicted: false,
        revoked_through: None,
        incarnation_high_water: 1,
    }
}

fn input(
    origin: RegionPresenceOrigin,
    durable_marks: &[RegionMarks],
) -> RegionSnapshotStagingInput<'_> {
    RegionSnapshotStagingInput {
        stream: RegionPresenceStream {
            origin,
            is_current: true,
        },
        durable_marks,
        capacity: RegionSnapshotStagingCapacity {
            maximum_origins: 15,
            maximum_entries: 10_000,
            maximum_mark_owners: 10_000,
        },
    }
}

fn snapshot(chunk_index: u32, mark_entries: Vec<RegionMarks>, more: bool) -> RegionSnapshot {
    RegionSnapshot {
        snapshot_id: 1,
        base_revision: 0,
        marks_revision: 257,
        chunk_index,
        presence_entries: Vec::new(),
        mark_entries,
        more,
    }
}

#[test]
fn persisted_mark_batches_do_not_accumulate_in_snapshot_staging() -> Result<(), String> {
    let origin = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 9,
    };
    let first_batch = (0..256).map(mark).collect::<Vec<_>>();
    let first = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(0, first_batch.clone(), true),
        input(origin, &[]),
    );
    if first.disposition != RegionSnapshotDisposition::Staged || first.effects.len() != 256 {
        return Err("the first bounded mark batch was not accepted".to_owned());
    }

    let second = stage_region_snapshot(
        &first.table,
        &first.staging,
        snapshot(1, vec![mark(256)], false),
        input(origin, &first_batch),
    );
    if second.disposition != RegionSnapshotDisposition::AwaitingDurableMarks {
        return Err("the next mark batch was not accepted after persistence".to_owned());
    }
    let retained = second
        .staging
        .stages
        .iter()
        .find(|stage| stage.origin == origin)
        .ok_or_else(|| "accepted snapshot lost its stage".to_owned())?
        .mark_entries
        .len();
    if retained > 256 {
        return Err(format!(
            "snapshot staging retained {retained} mark records after the first batch was durable"
        ));
    }
    let channels = [RegionPresenceChannels {
        origin,
        control_up: true,
        data_up: true,
    }];
    let incomplete = complete_region_snapshot(
        &second.table,
        &second.staging,
        RegionSnapshotCompletionInput {
            stream: RegionPresenceStream {
                origin,
                is_current: true,
            },
            snapshot_id: 1,
            durable_marks: &first_batch,
            channel_states: &channels,
            capacity: RegionPresenceCapacity {
                maximum_entries: 10_000,
            },
        },
    );
    if incomplete.disposition != RegionSnapshotDisposition::DurableMarksNotPersisted {
        return Err("final completion accepted an undurable snapshot cut".to_owned());
    }
    Ok(())
}

#[test]
fn drained_mark_owners_remain_unique_across_the_snapshot() -> Result<(), String> {
    let origin = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 9,
    };
    let first_mark = mark(1);
    let first = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(0, vec![first_mark], true),
        input(origin, &[]),
    );
    let duplicate = stage_region_snapshot(
        &first.table,
        &first.staging,
        snapshot(1, vec![first_mark], false),
        input(origin, &[first_mark]),
    );
    if duplicate.disposition != RegionSnapshotDisposition::DuplicateMarkOwner {
        return Err("a drained mark owner was accepted twice in one snapshot".to_owned());
    }
    Ok(())
}
