use keynet_proto::{
    RegionMarks, RegionPresenceCapacity, RegionPresenceChannels, RegionPresenceOrigin,
    RegionPresenceTable, RegionSnapshot, RegionSnapshotCompletionInput, RegionSnapshotDisposition,
    RegionSnapshotDurableBatchAcknowledgmentInput, RegionSnapshotOwnerValidationInput,
    RegionSnapshotStagingCapacity, RegionSnapshotStagingInput, RegionSnapshotStagingTable,
    acknowledge_region_snapshot_durable_batch, complete_region_snapshot, stage_region_snapshot,
    validate_region_snapshot_owners,
};

mod snapshot_test_support;

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
    control: keynet_proto::RegionSnapshotControl,
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
    let control = snapshot_test_support::control(origin);
    let retained_mark = mark();
    let first_requested = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(0, vec![retained_mark], true),
        staging_input(control, &[], 0),
    );
    let first_validation = snapshot_test_support::unique_validation(
        snapshot_test_support::validation_request(&first_requested)?,
    );
    let first = validate_region_snapshot_owners(
        &first_requested.table,
        &first_requested.staging,
        RegionSnapshotOwnerValidationInput {
            control,
            validation: &first_validation,
            durable_marks: &[],
            durable_store: snapshot_test_support::store(0),
            capacity: staging_input(control, &[], 0).capacity,
        },
    );
    if first.disposition != RegionSnapshotDisposition::Staged || first.effects.len() != 1 {
        return Err("initial mark batch was not staged for persistence".to_owned());
    }

    let batch = snapshot_test_support::durable_batch(&first)?;
    let drained = acknowledge_region_snapshot_durable_batch(
        &first.table,
        &first.staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: snapshot_test_support::acknowledgment(
                &batch,
                snapshot_test_support::store(1),
            ),
            durable_marks: &[retained_mark],
            durable_store: snapshot_test_support::store(1),
        },
    );

    let final_chunk = stage_region_snapshot(
        &drained.table,
        &drained.staging,
        snapshot(1, Vec::new(), false),
        staging_input(control, &[retained_mark], 1),
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
            control,
            snapshot_id: 1,
            durable_cut_receipt: None,
            durable_marks: &[],
            durable_store: snapshot_test_support::store(1),
            channel_states: &channels,
            capacity: RegionPresenceCapacity {
                maximum_entries: 160_000,
            },
        },
    );

    if completed_without_prior_mark.disposition
        != RegionSnapshotDisposition::InvalidDurableCutReceipt
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
