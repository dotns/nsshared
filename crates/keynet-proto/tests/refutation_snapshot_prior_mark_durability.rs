use keynet_proto::{
    RegionMarks, RegionPresenceCapacity, RegionPresenceChannels, RegionPresenceOrigin,
    RegionPresenceStream, RegionPresenceTable, RegionSnapshot, RegionSnapshotCompletionInput,
    RegionSnapshotDisposition, RegionSnapshotStagingCapacity, RegionSnapshotStagingInput,
    RegionSnapshotStagingTable, complete_region_snapshot, stage_region_snapshot,
};

fn mark() -> RegionMarks {
    RegionMarks {
        network_id: [1; 32],
        identity: [2; 32],
        committed_generation: 1,
        committed_key: [3; 32],
        conflicted: false,
        revoked_through: None,
        incarnation_high_water: 1,
    }
}

fn staging_input(
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
            maximum_mark_owners: 1_000_000,
            maximum_mark_staging_bytes: 64 * 1024,
        },
    }
}

fn snapshot(chunk_index: u32, mark_entries: Vec<RegionMarks>, more: bool) -> RegionSnapshot {
    RegionSnapshot {
        snapshot_id: 1,
        base_revision: 0,
        marks_revision: 1,
        chunk_index,
        presence_entries: Vec::new(),
        mark_entries,
        more,
    }
}

#[test]
fn completion_rechecks_marks_from_every_durable_batch() -> Result<(), String> {
    let origin = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 9,
    };
    let retained_mark = mark();
    let first = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(0, vec![retained_mark], true),
        staging_input(origin, &[]),
    );
    if first.disposition != RegionSnapshotDisposition::Staged || first.effects.len() != 1 {
        return Err("initial mark batch was not staged for persistence".to_owned());
    }

    let final_chunk = stage_region_snapshot(
        &first.table,
        &first.staging,
        snapshot(1, Vec::new(), false),
        staging_input(origin, &[retained_mark]),
    );
    if final_chunk.disposition != RegionSnapshotDisposition::AwaitingDurableMarks {
        return Err("snapshot did not accept its final chunk".to_owned());
    }

    let channels = [RegionPresenceChannels {
        origin,
        control_up: true,
        data_up: true,
    }];
    let completed_without_prior_mark = complete_region_snapshot(
        &final_chunk.table,
        &final_chunk.staging,
        RegionSnapshotCompletionInput {
            stream: RegionPresenceStream {
                origin,
                is_current: true,
            },
            snapshot_id: 1,
            durable_marks: &[],
            channel_states: &channels,
            capacity: RegionPresenceCapacity {
                maximum_entries: 160_000,
            },
        },
    );

    if completed_without_prior_mark.disposition
        != RegionSnapshotDisposition::DurableMarksNotPersisted
        || completed_without_prior_mark.table != final_chunk.table
        || completed_without_prior_mark
            .staging
            .stages
            .iter()
            .any(|stage| stage.origin == origin)
        || !completed_without_prior_mark.effects.is_empty()
        || !completed_without_prior_mark
            .table
            .origins
            .iter()
            .any(|state| state.origin == origin && state.snapshot_required)
    {
        return Err("snapshot completed after an earlier durable floor disappeared".to_owned());
    }
    Ok(())
}
