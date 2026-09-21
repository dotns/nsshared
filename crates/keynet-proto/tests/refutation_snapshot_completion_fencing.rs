use keynet_proto::{
    RegionMarks, RegionPresenceCapacity, RegionPresenceChannels, RegionPresenceOrigin,
    RegionPresenceStream, RegionPresenceTable, RegionSnapshot, RegionSnapshotCompletionInput,
    RegionSnapshotDisposition, RegionSnapshotStagingCapacity, RegionSnapshotStagingInput,
    RegionSnapshotStagingTable, begin_region_snapshot_control, complete_region_snapshot,
    interrupt_region_snapshot, stage_region_snapshot,
};

fn mark(identity: u8) -> RegionMarks {
    RegionMarks {
        network_id: [1; 32],
        identity: [identity; 32],
        committed_generation: 1,
        committed_key: [2; 32],
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
            maximum_mark_owners: 10_000,
            maximum_mark_staging_bytes: 64 * 1024,
        },
    }
}

fn snapshot(snapshot_id: u64, mark_entries: Vec<RegionMarks>) -> RegionSnapshot {
    RegionSnapshot {
        snapshot_id,
        base_revision: 0,
        marks_revision: snapshot_id,
        chunk_index: 0,
        presence_entries: Vec::new(),
        mark_entries,
        more: false,
    }
}

#[test]
fn delayed_completion_cannot_invalidate_a_reconnected_snapshot() -> Result<(), String> {
    let origin = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 9,
    };
    let old_mark = mark(1);
    let old = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(1, vec![old_mark]),
        staging_input(origin, &[]),
    );
    if old.disposition != RegionSnapshotDisposition::AwaitingDurableMarks {
        return Err("old snapshot did not reach durable completion".to_owned());
    }

    let interrupted = interrupt_region_snapshot(&old.table, &old.staging, origin);
    let restarted = begin_region_snapshot_control(
        &interrupted.table,
        &interrupted.staging,
        RegionPresenceStream {
            origin,
            is_current: true,
        },
    );
    let new_mark = mark(2);
    let current = stage_region_snapshot(
        &restarted.table,
        &restarted.staging,
        snapshot(2, vec![new_mark]),
        staging_input(origin, &[old_mark]),
    );
    if current.disposition != RegionSnapshotDisposition::AwaitingDurableMarks {
        return Err("reconnected snapshot did not reach durable completion".to_owned());
    }

    let channels = [RegionPresenceChannels {
        origin,
        control_up: true,
        data_up: true,
    }];
    let delayed_old_completion = complete_region_snapshot(
        &current.table,
        &current.staging,
        RegionSnapshotCompletionInput {
            stream: RegionPresenceStream {
                origin,
                is_current: true,
            },
            snapshot_id: 1,
            durable_marks: &[old_mark],
            channel_states: &channels,
            capacity: RegionPresenceCapacity {
                maximum_entries: 160_000,
            },
        },
    );

    if delayed_old_completion.disposition
        != RegionSnapshotDisposition::IgnoredStaleSnapshotCompletion
        || delayed_old_completion.staging != current.staging
    {
        return Err("an old persistence completion discarded the reconnected snapshot".to_owned());
    }
    let stale_stream_completion = complete_region_snapshot(
        &current.table,
        &current.staging,
        RegionSnapshotCompletionInput {
            stream: RegionPresenceStream {
                origin,
                is_current: false,
            },
            snapshot_id: 2,
            durable_marks: &[new_mark],
            channel_states: &channels,
            capacity: RegionPresenceCapacity {
                maximum_entries: 160_000,
            },
        },
    );
    if stale_stream_completion.disposition != RegionSnapshotDisposition::IgnoredStaleStream
        || stale_stream_completion.staging != current.staging
    {
        return Err("a stale stream completion changed the active snapshot".to_owned());
    }
    Ok(())
}
