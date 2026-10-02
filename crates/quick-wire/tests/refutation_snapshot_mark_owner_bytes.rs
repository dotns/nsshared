use quick_wire::{
    MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES, RegionMarks, RegionOwner, RegionPresenceOrigin,
    RegionPresenceTable, RegionSnapshot, RegionSnapshotDisposition,
    RegionSnapshotDurableBatchAcknowledgmentInput, RegionSnapshotOwnerValidationInput,
    RegionSnapshotStagingCapacity, RegionSnapshotStagingInput, RegionSnapshotStagingTable,
    acknowledge_region_snapshot_durable_batch, stage_region_snapshot,
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
    control: quick_wire::RegionSnapshotControl,
    durable_marks: &[RegionMarks],
    durable_revision: u64,
    maximum_mark_staging_bytes: usize,
) -> RegionSnapshotStagingInput<'_> {
    RegionSnapshotStagingInput {
        control,
        durable_marks,
        durable_store: snapshot_test_support::store(durable_revision),
        capacity: RegionSnapshotStagingCapacity {
            maximum_origins: 15,
            maximum_entries: 10_000,
            maximum_mark_owners: 1_000_000,
            maximum_mark_staging_bytes,
        },
    }
}

#[test]
fn mark_owner_index_obeys_the_snapshot_staging_byte_cap() -> Result<(), String> {
    if std::mem::size_of::<RegionOwner>() != 64 {
        return Err("owner-size control did not match its two fixed 32-byte fields".to_owned());
    }

    let origin = RegionPresenceOrigin {
        member_id: 2,
        boot_epoch: 9,
    };
    let control = snapshot_test_support::control(origin);
    let first_batch = (0..256).map(mark).collect::<Vec<_>>();
    let first_requested = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        RegionSnapshot {
            snapshot_id: 1,
            base_revision: 0,
            marks_revision: 512,
            chunk_index: 0,
            presence_entries: Vec::new(),
            mark_entries: first_batch.clone(),
            more: true,
        },
        input(control, &[], 0, MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES),
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
            capacity: input(control, &[], 0, MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES).capacity,
        },
    );
    if first.disposition != RegionSnapshotDisposition::Staged
        || snapshot_test_support::durable_batch(&first)?.joins.len() != 256
    {
        return Err("the initial mark batch did not fit the explicit byte budget".to_owned());
    }

    let stage = first
        .staging
        .stages
        .iter()
        .find(|stage| stage.origin == origin)
        .ok_or_else(|| "accepted snapshot lost its stage".to_owned())?;
    if stage.pending_owner_validation.is_some() {
        return Err("snapshot retained a second owner-validation batch".to_owned());
    }

    let retained_mark_bytes = stage
        .mark_staging_bytes()
        .ok_or_else(|| "mark byte accounting overflowed".to_owned())?;
    if retained_mark_bytes > MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES {
        return Err(format!(
            "snapshot retained {retained_mark_bytes} staged mark bytes"
        ));
    }

    let lower_mark_budget = retained_mark_bytes
        .checked_sub(1)
        .ok_or_else(|| "mark byte control did not reserve any bytes".to_owned())?;
    let lower_budget = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        RegionSnapshot {
            snapshot_id: 1,
            base_revision: 0,
            marks_revision: 512,
            chunk_index: 0,
            presence_entries: Vec::new(),
            mark_entries: first_batch.clone(),
            more: true,
        },
        input(control, &[], 0, lower_mark_budget),
    );
    if lower_budget.disposition != RegionSnapshotDisposition::CapacityExhausted
        || lower_budget
            .staging
            .stages
            .iter()
            .any(|stage| stage.origin == origin)
    {
        return Err("the caller-supplied mark byte budget was not enforced".to_owned());
    }

    let first_batch_effect = snapshot_test_support::durable_batch(&first)?;
    let drained = acknowledge_region_snapshot_durable_batch(
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
    let second_batch = (256..512).map(mark).collect::<Vec<_>>();
    let continued = stage_region_snapshot(
        &drained.table,
        &drained.staging,
        RegionSnapshot {
            snapshot_id: 1,
            base_revision: 0,
            marks_revision: 512,
            chunk_index: 1,
            presence_entries: Vec::new(),
            mark_entries: second_batch,
            more: false,
        },
        input(
            control,
            &first_batch,
            1,
            MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES,
        ),
    );
    if continued.disposition != RegionSnapshotDisposition::AwaitingOwnerValidation
        || continued
            .staging
            .stages
            .iter()
            .find(|stage| stage.origin == origin)
            .is_none_or(|stage| {
                stage
                    .mark_staging_bytes()
                    .is_none_or(|bytes| bytes > MAX_REGION_SNAPSHOT_MARK_STAGING_BYTES)
            })
        || !continued.table.entries.is_empty()
    {
        return Err(
            "drained mark batches did not remain bounded before the next index validation"
                .to_owned(),
        );
    }
    Ok(())
}
