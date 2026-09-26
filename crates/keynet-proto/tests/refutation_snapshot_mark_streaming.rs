use keynet_proto::{
    RegionMarks, RegionPresenceCapacity, RegionPresenceChannels, RegionPresenceOrigin,
    RegionPresenceTable, RegionSnapshot, RegionSnapshotCompletionInput, RegionSnapshotDisposition,
    RegionSnapshotDurableBatchAcknowledgmentInput, RegionSnapshotOwnerIndexOutcome,
    RegionSnapshotOwnerValidation, RegionSnapshotOwnerValidationInput,
    RegionSnapshotStagingCapacity, RegionSnapshotStagingInput, RegionSnapshotStagingTable,
    acknowledge_region_snapshot_durable_batch, complete_region_snapshot, stage_region_snapshot,
    validate_region_snapshot_owners,
};

mod snapshot_test_support;

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
            maximum_mark_owners: 10_000,
            maximum_mark_staging_bytes: 64 * 1024,
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
    let control = snapshot_test_support::control(origin);
    let first_batch = (0..256).map(mark).collect::<Vec<_>>();
    let first_requested = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(0, first_batch.clone(), true),
        input(control, &[], 0),
    );
    if first_requested.disposition != RegionSnapshotDisposition::AwaitingOwnerValidation {
        return Err(
            "the first bounded mark batch was not sent to the exact owner index".to_owned(),
        );
    }
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
            capacity: input(control, &[], 0).capacity,
        },
    );
    if first.disposition != RegionSnapshotDisposition::Staged
        || snapshot_test_support::durable_batch(&first)?.joins.len() != 256
    {
        return Err("the first bounded mark batch was not accepted".to_owned());
    }

    let first_batch_effect = snapshot_test_support::durable_batch(&first)?;
    let drained_first = acknowledge_region_snapshot_durable_batch(
        &first.table,
        &first.staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: snapshot_test_support::acknowledgment(
                &first_batch_effect,
                snapshot_test_support::store(1),
            ),
            durable_marks: &first_batch,
            durable_store: snapshot_test_support::store(1),
        },
    );
    if drained_first.disposition != RegionSnapshotDisposition::Staged {
        return Err("the first durable batch did not drain".to_owned());
    }
    let drained_bytes = drained_first
        .staging
        .stages
        .iter()
        .find(|stage| stage.origin == origin)
        .ok_or_else(|| "drained snapshot lost its stage".to_owned())?
        .mark_staging_bytes()
        .ok_or_else(|| "drained mark staging bytes overflowed".to_owned())?;
    if drained_bytes != 0 {
        return Err(format!(
            "snapshot retained {drained_bytes} mark-staging bytes after a durable batch drained"
        ));
    }

    let second_requested = stage_region_snapshot(
        &drained_first.table,
        &drained_first.staging,
        snapshot(1, vec![mark(256)], false),
        input(control, &first_batch, 1),
    );
    let second_validation = snapshot_test_support::unique_validation(
        snapshot_test_support::validation_request(&second_requested)?,
    );
    let second = validate_region_snapshot_owners(
        &second_requested.table,
        &second_requested.staging,
        RegionSnapshotOwnerValidationInput {
            control,
            validation: &second_validation,
            durable_marks: &first_batch,
            durable_store: snapshot_test_support::store(1),
            capacity: input(control, &first_batch, 1).capacity,
        },
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
        .pending_mark_batch
        .as_ref()
        .map_or(0, |batch| batch.marks.len());
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
            control,
            snapshot_id: 1,
            durable_cut_receipt: None,
            durable_marks: &first_batch,
            durable_store: snapshot_test_support::store(1),
            channel_states: &channels,
            capacity: RegionPresenceCapacity {
                maximum_entries: 10_000,
            },
            local_member_id: 16,
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
    let control = snapshot_test_support::control(origin);
    let first_mark = mark(1);
    let first_requested = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(0, vec![first_mark], true),
        input(control, &[], 0),
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
            capacity: input(control, &[], 0).capacity,
        },
    );
    let first_batch = snapshot_test_support::durable_batch(&first)?;
    let drained = acknowledge_region_snapshot_durable_batch(
        &first.table,
        &first.staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: snapshot_test_support::acknowledgment(
                &first_batch,
                snapshot_test_support::store(1),
            ),
            durable_marks: &[first_mark],
            durable_store: snapshot_test_support::store(1),
        },
    );
    let duplicate_requested = stage_region_snapshot(
        &drained.table,
        &drained.staging,
        snapshot(1, vec![first_mark], false),
        input(control, &[first_mark], 1),
    );
    let duplicate_request = snapshot_test_support::validation_request(&duplicate_requested)?;
    let duplicate_validation = RegionSnapshotOwnerValidation {
        request: duplicate_request,
        outcome: RegionSnapshotOwnerIndexOutcome::Duplicate,
    };
    let duplicate = validate_region_snapshot_owners(
        &duplicate_requested.table,
        &duplicate_requested.staging,
        RegionSnapshotOwnerValidationInput {
            control,
            validation: &duplicate_validation,
            durable_marks: &[first_mark],
            durable_store: snapshot_test_support::store(1),
            capacity: input(control, &[first_mark], 1).capacity,
        },
    );
    if duplicate.disposition != RegionSnapshotDisposition::DuplicateMarkOwner {
        return Err("a drained mark owner was accepted twice in one snapshot".to_owned());
    }
    Ok(())
}
