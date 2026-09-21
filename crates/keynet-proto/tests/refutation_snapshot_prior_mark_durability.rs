use keynet_proto::{
    RegionMarks, RegionPresenceCapacity, RegionPresenceOrigin, RegionPresenceTable, RegionSnapshot,
    RegionSnapshotCompletionInput, RegionSnapshotDecision, RegionSnapshotDisposition,
    RegionSnapshotDurableBatch, RegionSnapshotDurableBatchAcknowledgmentInput,
    RegionSnapshotDurableCutReceipt, RegionSnapshotOwnerValidationInput,
    RegionSnapshotStagingCapacity, RegionSnapshotStagingInput, RegionSnapshotStagingTable,
    acknowledge_region_snapshot_durable_batch, complete_region_snapshot, join_region_marks,
    stage_region_snapshot, validate_region_snapshot_owners,
};

mod snapshot_test_support;

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

fn pending_batch() -> Result<(RegionSnapshotDecision, RegionSnapshotDurableBatch), String> {
    let control = snapshot_test_support::control(origin());
    let required = mark();
    let requested = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(0, vec![required], true),
        staging_input(control, &[], 0),
    );
    let validation = snapshot_test_support::unique_validation(
        snapshot_test_support::validation_request(&requested)?,
    );
    let accepted = validate_region_snapshot_owners(
        &requested.table,
        &requested.staging,
        RegionSnapshotOwnerValidationInput {
            control,
            validation: &validation,
            durable_marks: &[],
            durable_store: snapshot_test_support::store(0),
            capacity: staging_input(control, &[], 0).capacity,
        },
    );
    if accepted.disposition != RegionSnapshotDisposition::Staged || accepted.effects.len() != 1 {
        return Err("initial mark batch was not staged for persistence".to_owned());
    }
    Ok((
        accepted.clone(),
        snapshot_test_support::durable_batch(&accepted)?,
    ))
}

fn final_stage() -> Result<RegionSnapshotDecision, String> {
    let control = snapshot_test_support::control(origin());
    let required = mark();
    let (pending, batch) = pending_batch()?;
    let drained = acknowledge_region_snapshot_durable_batch(
        &pending.table,
        &pending.staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: snapshot_test_support::acknowledgment(
                &batch,
                snapshot_test_support::store(1),
            ),
            durable_marks: &[required],
            durable_store: snapshot_test_support::store(1),
        },
    );
    if drained.disposition != RegionSnapshotDisposition::Staged || !drained.effects.is_empty() {
        return Err("a matching durable batch acknowledgment did not drain the batch".to_owned());
    }
    let final_chunk = stage_region_snapshot(
        &drained.table,
        &drained.staging,
        snapshot(1, Vec::new(), false),
        staging_input(control, &[required], 1),
    );
    if final_chunk.disposition != RegionSnapshotDisposition::AwaitingDurableMarks
        || !final_chunk.effects.is_empty()
    {
        return Err("the drained cut did not wait only for a complete-cut receipt".to_owned());
    }
    Ok(final_chunk)
}

fn complete(
    stage: &RegionSnapshotDecision,
    durable_cut_receipt: Option<RegionSnapshotDurableCutReceipt>,
) -> RegionSnapshotDecision {
    let required = mark();
    complete_region_snapshot(
        &stage.table,
        &stage.staging,
        RegionSnapshotCompletionInput {
            control: snapshot_test_support::control(origin()),
            snapshot_id: 1,
            durable_cut_receipt,
            durable_marks: &[required],
            durable_store: snapshot_test_support::store(1),
            channel_states: &[],
            capacity: RegionPresenceCapacity {
                maximum_entries: 160_000,
            },
        },
    )
}

fn require_invalid_receipt(
    stage: &RegionSnapshotDecision,
    receipt: Option<RegionSnapshotDurableCutReceipt>,
    boundary: &str,
) -> Result<(), String> {
    let rejected = complete(stage, receipt);
    if rejected.disposition != RegionSnapshotDisposition::InvalidDurableCutReceipt
        || !rejected.staging.stages.is_empty()
        || !rejected.effects.is_empty()
        || !rejected
            .table
            .origins
            .iter()
            .any(|state| state.origin == origin() && state.snapshot_required)
    {
        return Err(format!(
            "the complete-cut receipt did not reject {boundary}"
        ));
    }
    Ok(())
}

#[test]
fn retained_batch_domination_and_complete_cut_receipts_are_distinct_boundaries()
-> Result<(), String> {
    let control = snapshot_test_support::control(origin());
    let required = mark();
    let regressed = RegionMarks {
        committed_generation: 0,
        ..required
    };
    let joined = join_region_marks(regressed, required).map_err(|error| format!("{error:?}"))?;
    if joined.state == regressed {
        return Err(
            "the retained test record unexpectedly dominated the requested floor".to_owned(),
        );
    }
    let (pending, batch) = pending_batch()?;
    let rejected = acknowledge_region_snapshot_durable_batch(
        &pending.table,
        &pending.staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: snapshot_test_support::acknowledgment(
                &batch,
                snapshot_test_support::store(1),
            ),
            durable_marks: &[regressed],
            durable_store: snapshot_test_support::store(1),
        },
    );
    if rejected.disposition != RegionSnapshotDisposition::DurableMarksNotPersisted
        || !rejected.staging.stages.is_empty()
        || !rejected.effects.is_empty()
        || !rejected
            .table
            .origins
            .iter()
            .any(|state| state.origin == origin() && state.snapshot_required)
    {
        return Err("a retained batch drained without a dominating durable floor".to_owned());
    }

    let stage = final_stage()?;
    require_invalid_receipt(&stage, None, "missing evidence")?;

    let receipt = snapshot_test_support::receipt(&stage, control, snapshot_test_support::store(1))?;
    let mut wrong_control = receipt;
    wrong_control.control = snapshot_test_support::control_with_id(origin(), 2);
    require_invalid_receipt(&stage, Some(wrong_control), "control scope")?;

    let mut wrong_progress = receipt;
    wrong_progress.accepted_through = 0;
    require_invalid_receipt(&stage, Some(wrong_progress), "contiguous progress")?;

    let mut wrong_commitment = receipt;
    wrong_commitment.cut_commitment.digest[0] ^= 1;
    require_invalid_receipt(&stage, Some(wrong_commitment), "cut commitment")?;

    let mut wrong_lineage = receipt;
    wrong_lineage.durable_store.lineage.bytes[0] ^= 1;
    require_invalid_receipt(&stage, Some(wrong_lineage), "store lineage")?;

    let mut rolled_back_store = receipt;
    rolled_back_store.durable_store.durable_revision = 0;
    require_invalid_receipt(&stage, Some(rolled_back_store), "store continuity")?;

    let completed = complete(&stage, Some(receipt));
    if completed.disposition != RegionSnapshotDisposition::Completed
        || !completed.staging.stages.is_empty()
        || !completed.effects.is_empty()
        || !completed
            .table
            .origins
            .iter()
            .any(|state| state.origin == origin() && !state.snapshot_required)
    {
        return Err(
            "a matching explicit complete-cut receipt did not complete the drained cut".to_owned(),
        );
    }
    Ok(())
}
