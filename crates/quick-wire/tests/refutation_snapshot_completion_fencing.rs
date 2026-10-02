use quick_wire::{
    RegionMarks, RegionPresenceCapacity, RegionPresenceChannels, RegionPresenceOrigin,
    RegionPresenceTable, RegionSnapshot, RegionSnapshotCompletionInput, RegionSnapshotDisposition,
    RegionSnapshotOwnerValidationInput, RegionSnapshotStagingCapacity, RegionSnapshotStagingInput,
    RegionSnapshotStagingTable, begin_region_snapshot_control, complete_region_snapshot,
    interrupt_region_snapshot, stage_region_snapshot, validate_region_snapshot_owners,
};

mod snapshot_test_support;

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
    control: quick_wire::RegionSnapshotControl,
    durable_marks: &[RegionMarks],
    durable_revision: u64,
) -> RegionSnapshotStagingInput<'_> {
    RegionSnapshotStagingInput {
        control,
        durable_marks,
        durable_store: snapshot_test_support::store(durable_revision),
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
    let old_control = snapshot_test_support::control(origin);
    let old_mark = mark(1);
    let old_requested = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(1, vec![old_mark]),
        staging_input(old_control, &[], 0),
    );
    let old_validation = snapshot_test_support::unique_validation(
        snapshot_test_support::validation_request(&old_requested)?,
    );
    let old = validate_region_snapshot_owners(
        &old_requested.table,
        &old_requested.staging,
        RegionSnapshotOwnerValidationInput {
            control: old_control,
            validation: &old_validation,
            durable_marks: &[],
            durable_store: snapshot_test_support::store(0),
            capacity: staging_input(old_control, &[], 0).capacity,
        },
    );
    if old.disposition != RegionSnapshotDisposition::AwaitingDurableMarks {
        return Err("old snapshot did not reach durable completion".to_owned());
    }

    let interrupted = interrupt_region_snapshot(&old.table, &old.staging, old_control);
    let current_control = snapshot_test_support::control_with_id(origin, 2);
    let restarted =
        begin_region_snapshot_control(&interrupted.table, &interrupted.staging, current_control);
    let new_mark = mark(2);
    let current_requested = stage_region_snapshot(
        &restarted.table,
        &restarted.staging,
        snapshot(2, vec![new_mark]),
        staging_input(current_control, &[old_mark], 0),
    );
    let current_validation = snapshot_test_support::unique_validation(
        snapshot_test_support::validation_request(&current_requested)?,
    );
    let current = validate_region_snapshot_owners(
        &current_requested.table,
        &current_requested.staging,
        RegionSnapshotOwnerValidationInput {
            control: current_control,
            validation: &current_validation,
            durable_marks: &[old_mark],
            durable_store: snapshot_test_support::store(0),
            capacity: staging_input(current_control, &[old_mark], 0).capacity,
        },
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
            control: old_control,
            snapshot_id: 1,
            durable_cut_receipt: None,
            durable_marks: &[old_mark],
            durable_store: snapshot_test_support::store(0),
            channel_states: &channels,
            capacity: RegionPresenceCapacity {
                maximum_entries: 160_000,
            },
            local_member_id: 16,
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
            control: quick_wire::RegionSnapshotControl {
                stream: quick_wire::RegionPresenceStream {
                    origin,
                    is_current: false,
                },
                local_boot_epoch: current_control.local_boot_epoch,
                control_stream_id: current_control.control_stream_id,
            },
            snapshot_id: 2,
            durable_cut_receipt: None,
            durable_marks: &[new_mark],
            durable_store: snapshot_test_support::store(0),
            channel_states: &channels,
            capacity: RegionPresenceCapacity {
                maximum_entries: 160_000,
            },
            local_member_id: 16,
        },
    );
    if stale_stream_completion.disposition != RegionSnapshotDisposition::IgnoredStaleStream
        || stale_stream_completion.staging != current.staging
    {
        return Err("a stale stream completion changed the active snapshot".to_owned());
    }
    Ok(())
}
