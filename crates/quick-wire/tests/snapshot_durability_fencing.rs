use quick_wire::{
    RegionMarks, RegionPresenceCapacity, RegionPresenceOrigin, RegionPresenceTable, RegionSnapshot,
    RegionSnapshotCompletionInput, RegionSnapshotDecision, RegionSnapshotDisposition,
    RegionSnapshotDurableBatch, RegionSnapshotDurableBatchAcknowledgmentInput,
    RegionSnapshotOwnerIndexOutcome, RegionSnapshotOwnerValidationInput,
    RegionSnapshotStagingCapacity, RegionSnapshotStagingInput, RegionSnapshotStagingTable,
    acknowledge_region_snapshot_durable_batch, begin_region_snapshot_control,
    complete_region_snapshot, interrupt_region_snapshot, join_region_marks, stage_region_snapshot,
    validate_region_snapshot_owners,
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
        committed_generation: 4,
        committed_key: [3; 32],
        conflicted: true,
        revoked_through: Some(2),
        incarnation_high_water: 7,
    }
}

fn input(
    control: quick_wire::RegionSnapshotControl,
    durable_marks: &[RegionMarks],
    maximum_origins: usize,
    durable_revision: u64,
) -> RegionSnapshotStagingInput<'_> {
    RegionSnapshotStagingInput {
        control,
        durable_marks,
        durable_store: snapshot_test_support::store(durable_revision),
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

fn drained(required: RegionMarks) -> Result<RegionSnapshotDecision, String> {
    let control = snapshot_test_support::control(origin());
    let first_requested = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(7, 0, vec![required], true),
        input(control, &[], 1, 0),
    );
    if first_requested.disposition != RegionSnapshotDisposition::AwaitingOwnerValidation {
        return Err("changed mark batch was not sent to exact owner validation".to_owned());
    }
    let first_request = snapshot_test_support::validation_request(&first_requested)?;
    let first_validation = snapshot_test_support::unique_validation(first_request);
    let first = validate_region_snapshot_owners(
        &first_requested.table,
        &first_requested.staging,
        RegionSnapshotOwnerValidationInput {
            control,
            validation: &first_validation,
            durable_marks: &[],
            durable_store: snapshot_test_support::store(0),
            capacity: input(control, &[], 1, 0).capacity,
        },
    );
    if first.disposition != RegionSnapshotDisposition::Staged {
        return Err("validated changed mark batch did not stage".to_owned());
    }
    if !snapshot_test_support::is_durable_batch_for(&first, required) {
        return Err("changed mark batch did not request the exact durable join".to_owned());
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
            durable_marks: &[required],
            durable_store: snapshot_test_support::store(1),
        },
    );
    if drained.disposition != RegionSnapshotDisposition::Staged {
        return Err("accepted durable batch did not drain before the next chunk".to_owned());
    }
    let last = stage_region_snapshot(
        &drained.table,
        &drained.staging,
        snapshot(7, 1, Vec::new(), false),
        input(control, &[required], 1, 1),
    );
    if last.disposition != RegionSnapshotDisposition::AwaitingDurableMarks
        || !last.effects.is_empty()
    {
        return Err("final empty chunk did not await only the complete-cut receipt".to_owned());
    }
    Ok(last)
}

fn complete(
    stage: &RegionSnapshotDecision,
    durable_marks: &[RegionMarks],
) -> Result<RegionSnapshotDecision, String> {
    let control = snapshot_test_support::control(origin());
    let receipt = snapshot_test_support::receipt(stage, control, snapshot_test_support::store(1))?;
    Ok(complete_region_snapshot(
        &stage.table,
        &stage.staging,
        RegionSnapshotCompletionInput {
            control,
            snapshot_id: 7,
            durable_cut_receipt: Some(receipt),
            durable_marks,
            durable_store: snapshot_test_support::store(1),
            channel_states: &[],
            capacity: RegionPresenceCapacity { maximum_entries: 1 },
            local_member_id: 16,
        },
    ))
}

fn complete_without_receipt(
    stage: &RegionSnapshotDecision,
    durable_marks: &[RegionMarks],
) -> RegionSnapshotDecision {
    complete_region_snapshot(
        &stage.table,
        &stage.staging,
        RegionSnapshotCompletionInput {
            control: snapshot_test_support::control(origin()),
            snapshot_id: 7,
            durable_cut_receipt: None,
            durable_marks,
            durable_store: snapshot_test_support::store(1),
            channel_states: &[],
            capacity: RegionPresenceCapacity { maximum_entries: 1 },
            local_member_id: 16,
        },
    )
}

fn pending_batch(
    required: RegionMarks,
) -> Result<(RegionSnapshotDecision, RegionSnapshotDurableBatch), String> {
    let control = snapshot_test_support::control(origin());
    let requested = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(11, 0, vec![required], true),
        input(control, &[], 1, 0),
    );
    if requested.disposition != RegionSnapshotDisposition::AwaitingOwnerValidation {
        return Err("changed mark batch was not sent to exact owner validation".to_owned());
    }
    let request = snapshot_test_support::validation_request(&requested)?;
    let validation = snapshot_test_support::unique_validation(request);
    let accepted = validate_region_snapshot_owners(
        &requested.table,
        &requested.staging,
        RegionSnapshotOwnerValidationInput {
            control,
            validation: &validation,
            durable_marks: &[],
            durable_store: snapshot_test_support::store(0),
            capacity: input(control, &[], 1, 0).capacity,
        },
    );
    if accepted.disposition != RegionSnapshotDisposition::Staged {
        return Err("validated changed mark batch did not stage".to_owned());
    }
    Ok((
        accepted.clone(),
        snapshot_test_support::durable_batch(&accepted)?,
    ))
}

#[test]
fn durable_batch_acknowledgments_bind_commitment_and_revision() -> Result<(), String> {
    let required = mark();
    let control = snapshot_test_support::control(origin());
    let (pending, batch) = pending_batch(required)?;
    let mut mismatched =
        snapshot_test_support::acknowledgment(&batch, snapshot_test_support::store(1));
    mismatched.commitment.digest[0] ^= 1;
    let mismatched_result = acknowledge_region_snapshot_durable_batch(
        &pending.table,
        &pending.staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: mismatched,
            durable_marks: &[required],
            durable_store: snapshot_test_support::store(1),
        },
    );
    if mismatched_result.disposition != RegionSnapshotDisposition::InvalidDurableBatchAcknowledgment
        || !mismatched_result.staging.stages.is_empty()
        || !mismatched_result.effects.is_empty()
    {
        return Err(
            "mismatched durable batch evidence was accepted or retained staging".to_owned(),
        );
    }

    let (pending, batch) = pending_batch(required)?;
    let rollback = acknowledge_region_snapshot_durable_batch(
        &pending.table,
        &pending.staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: snapshot_test_support::acknowledgment(
                &batch,
                snapshot_test_support::store(0),
            ),
            durable_marks: &[required],
            durable_store: snapshot_test_support::store(0),
        },
    );
    if rollback.disposition != RegionSnapshotDisposition::InvalidDurableBatchAcknowledgment
        || !rollback.staging.stages.is_empty()
    {
        return Err("a changed durable batch did not require a forward local revision".to_owned());
    }
    Ok(())
}

#[test]
fn owner_index_result_must_bind_exact_bounded_accounting() -> Result<(), String> {
    let required = mark();
    let control = snapshot_test_support::control(origin());
    let requested = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(13, 0, vec![required], true),
        input(control, &[], 1, 0),
    );
    let mut validation = snapshot_test_support::unique_validation(
        snapshot_test_support::validation_request(&requested)?,
    );
    if let RegionSnapshotOwnerIndexOutcome::Unique { indexed_bytes, .. } = &mut validation.outcome {
        *indexed_bytes = indexed_bytes.saturating_sub(1);
    }
    let rejected = validate_region_snapshot_owners(
        &requested.table,
        &requested.staging,
        RegionSnapshotOwnerValidationInput {
            control,
            validation: &validation,
            durable_marks: &[],
            durable_store: snapshot_test_support::store(0),
            capacity: input(control, &[], 1, 0).capacity,
        },
    );
    if rejected.disposition != RegionSnapshotDisposition::InvalidOwnerValidation
        || !rejected.staging.stages.is_empty()
    {
        return Err("a non-exact owner-index allocation report was accepted".to_owned());
    }
    Ok(())
}

#[test]
fn empty_snapshot_does_not_consume_mark_staging_budget() -> Result<(), String> {
    let control = snapshot_test_support::control(origin());
    let empty = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(14, 0, Vec::new(), false),
        RegionSnapshotStagingInput {
            control,
            durable_marks: &[],
            durable_store: snapshot_test_support::store(0),
            capacity: RegionSnapshotStagingCapacity {
                maximum_origins: 1,
                maximum_entries: 1,
                maximum_mark_owners: 2,
                maximum_mark_staging_bytes: 0,
            },
        },
    );
    let stage = empty
        .staging
        .stages
        .iter()
        .find(|stage| stage.control == control)
        .ok_or_else(|| "empty snapshot did not retain its final stage".to_owned())?;
    if empty.disposition != RegionSnapshotDisposition::AwaitingDurableMarks
        || stage.mark_staging_bytes() != Some(0)
        || !empty.effects.is_empty()
    {
        return Err(
            "empty snapshot consumed mark staging capacity or published an effect".to_owned(),
        );
    }
    Ok(())
}

#[test]
fn final_receipt_binds_the_complete_cut() -> Result<(), String> {
    let required = mark();
    let stage = drained(required)?;
    let control = snapshot_test_support::control(origin());
    let mut receipt =
        snapshot_test_support::receipt(&stage, control, snapshot_test_support::store(1))?;
    receipt.cut_commitment.digest[0] ^= 1;
    let rejected = complete_region_snapshot(
        &stage.table,
        &stage.staging,
        RegionSnapshotCompletionInput {
            control,
            snapshot_id: 7,
            durable_cut_receipt: Some(receipt),
            durable_marks: &[required],
            durable_store: snapshot_test_support::store(1),
            channel_states: &[],
            capacity: RegionPresenceCapacity { maximum_entries: 1 },
            local_member_id: 16,
        },
    );
    if rejected.disposition != RegionSnapshotDisposition::InvalidDurableCutReceipt
        || !rejected.staging.stages.is_empty()
        || !rejected.table.entries.is_empty()
    {
        return Err("a mismatched final durable-cut receipt completed a snapshot".to_owned());
    }
    Ok(())
}

#[test]
fn unchanged_batch_needs_no_durable_write() -> Result<(), String> {
    let required = mark();
    let control = snapshot_test_support::control(origin());
    let requested = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(12, 0, vec![required], false),
        input(control, &[required], 1, 0),
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
            durable_marks: &[required],
            durable_store: snapshot_test_support::store(0),
            capacity: input(control, &[required], 1, 0).capacity,
        },
    );
    if accepted.disposition != RegionSnapshotDisposition::AwaitingDurableMarks
        || !accepted.effects.is_empty()
    {
        return Err("an identical durable floor requested a no-op durable write".to_owned());
    }
    let receipt =
        snapshot_test_support::receipt(&accepted, control, snapshot_test_support::store(0))?;
    let completed = complete_region_snapshot(
        &accepted.table,
        &accepted.staging,
        RegionSnapshotCompletionInput {
            control,
            snapshot_id: 12,
            durable_cut_receipt: Some(receipt),
            durable_marks: &[required],
            durable_store: snapshot_test_support::store(0),
            channel_states: &[],
            capacity: RegionPresenceCapacity { maximum_entries: 1 },
            local_member_id: 16,
        },
    );
    if completed.disposition != RegionSnapshotDisposition::Completed {
        return Err("an unchanged durable batch did not complete with local evidence".to_owned());
    }
    Ok(())
}

fn rejects_regression(current: RegionMarks) -> Result<(), String> {
    let required = mark();
    let joined = join_region_marks(current, required).map_err(|error| format!("{error:?}"))?;
    assert_ne!(
        joined.state, current,
        "the supplied record must not dominate the cut"
    );
    let control = snapshot_test_support::control(origin());
    let (pending, batch) = pending_batch(required)?;
    let rejected = acknowledge_region_snapshot_durable_batch(
        &pending.table,
        &pending.staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: snapshot_test_support::acknowledgment(
                &batch,
                snapshot_test_support::store(1),
            ),
            durable_marks: &[current],
            durable_store: snapshot_test_support::store(1),
        },
    );
    assert_eq!(
        rejected.disposition,
        RegionSnapshotDisposition::DurableMarksNotPersisted,
        "a same-owner record that does not dominate a pending batch must not drain it"
    );
    assert_eq!(rejected.table, pending.table);
    assert!(rejected.staging.stages.is_empty());
    assert!(rejected.effects.is_empty());
    assert!(
        rejected
            .table
            .origins
            .iter()
            .all(|state| state.snapshot_required)
    );
    Ok(())
}

#[test]
fn retained_generation_must_be_durable_before_batch_drain() -> Result<(), String> {
    rejects_regression(RegionMarks {
        committed_generation: 3,
        ..mark()
    })
}

#[test]
fn retained_incarnation_must_be_durable_before_batch_drain() -> Result<(), String> {
    rejects_regression(RegionMarks {
        incarnation_high_water: 6,
        ..mark()
    })
}

#[test]
fn retained_revocation_must_be_durable_before_batch_drain() -> Result<(), String> {
    rejects_regression(RegionMarks {
        revoked_through: None,
        ..mark()
    })
}

#[test]
fn retained_conflict_must_be_durable_before_batch_drain() -> Result<(), String> {
    rejects_regression(RegionMarks {
        conflicted: false,
        ..mark()
    })
}

#[test]
fn retained_key_representative_must_be_durable_before_batch_drain() -> Result<(), String> {
    rejects_regression(RegionMarks {
        committed_key: [8; 32],
        ..mark()
    })
}

#[test]
fn identical_and_dominating_durable_records_acknowledge() -> Result<(), String> {
    let required = mark();
    let control = snapshot_test_support::control(origin());
    let (pending, batch) = pending_batch(required)?;
    let identical = acknowledge_region_snapshot_durable_batch(
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
    if identical.disposition != RegionSnapshotDisposition::Staged
        || !identical.effects.is_empty()
        || identical.staging.stages.len() != 1
    {
        return Err("an identical durable record did not acknowledge the pending batch".to_owned());
    }

    let stronger = RegionMarks {
        committed_generation: 5,
        committed_key: [9; 32],
        conflicted: false,
        incarnation_high_water: 1,
        ..mark()
    };
    let (pending, batch) = pending_batch(required)?;
    let dominating = acknowledge_region_snapshot_durable_batch(
        &pending.table,
        &pending.staging,
        RegionSnapshotDurableBatchAcknowledgmentInput {
            control,
            acknowledgment: snapshot_test_support::acknowledgment(
                &batch,
                snapshot_test_support::store(1),
            ),
            durable_marks: &[stronger],
            durable_store: snapshot_test_support::store(1),
        },
    );
    if dominating.disposition != RegionSnapshotDisposition::Staged
        || !dominating.effects.is_empty()
        || dominating.staging.stages.len() != 1
    {
        return Err("a dominating durable record did not acknowledge the pending batch".to_owned());
    }
    Ok(())
}

#[test]
fn matching_complete_cut_receipt_completes_drained_batch() -> Result<(), String> {
    let stage = drained(mark())?;
    if complete(&stage, &[mark()])?.disposition != RegionSnapshotDisposition::Completed {
        return Err(
            "a matching complete-cut receipt did not complete the drained batch".to_owned(),
        );
    }
    Ok(())
}

#[test]
fn missing_complete_cut_receipt_is_rejected() -> Result<(), String> {
    let stage = drained(mark())?;
    assert_eq!(
        complete_without_receipt(&stage, &[]).disposition,
        RegionSnapshotDisposition::InvalidDurableCutReceipt
    );
    Ok(())
}

fn origin_overflow(reconnect: bool) {
    let initial_control = snapshot_test_support::control(origin());
    let overflowed = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(7, 0, Vec::new(), false),
        input(initial_control, &[], 0, 0),
    );
    assert_eq!(
        overflowed.disposition,
        RegionSnapshotDisposition::CapacityExhausted
    );
    assert!(overflowed.staging.stages.is_empty());
    assert!(overflowed.effects.is_empty());
    let retry_state = if reconnect {
        begin_region_snapshot_control(
            &overflowed.table,
            &overflowed.staging,
            snapshot_test_support::control_with_id(origin(), 2),
        )
    } else {
        overflowed
    };
    let retry_control = if reconnect {
        snapshot_test_support::control_with_id(origin(), 2)
    } else {
        initial_control
    };
    let fresh = stage_region_snapshot(
        &retry_state.table,
        &retry_state.staging,
        snapshot(8, 0, Vec::new(), false),
        input(retry_control, &[], 1, 0),
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
        input(retry_control, &[], 1, 0),
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

#[test]
fn a_fenced_origin_cannot_bypass_an_active_staging_slot() -> Result<(), String> {
    let active_origin = origin();
    let fenced_origin = RegionPresenceOrigin {
        member_id: 3,
        boot_epoch: 9,
    };
    let active_control = snapshot_test_support::control(active_origin);
    let fenced_control = snapshot_test_support::control(fenced_origin);
    let active = stage_region_snapshot(
        &RegionPresenceTable::default(),
        &RegionSnapshotStagingTable::default(),
        snapshot(1, 0, Vec::new(), true),
        input(active_control, &[], 1, 0),
    );
    if active.disposition != RegionSnapshotDisposition::Staged {
        return Err("the active staging slot was not occupied".to_owned());
    }
    let refused = stage_region_snapshot(
        &active.table,
        &active.staging,
        snapshot(1, 0, Vec::new(), false),
        input(fenced_control, &[], 1, 0),
    );
    let refused_again = stage_region_snapshot(
        &refused.table,
        &refused.staging,
        snapshot(2, 0, Vec::new(), false),
        input(fenced_control, &[], 1, 0),
    );
    if refused.disposition != RegionSnapshotDisposition::CapacityExhausted
        || refused_again.disposition != RegionSnapshotDisposition::CapacityExhausted
        || refused_again.staging.stages.len() != 1
    {
        return Err("a replay fence bypassed the occupied staging bound".to_owned());
    }
    let released =
        interrupt_region_snapshot(&refused_again.table, &refused_again.staging, active_control);
    let admitted = stage_region_snapshot(
        &released.table,
        &released.staging,
        snapshot(3, 0, Vec::new(), false),
        input(fenced_control, &[], 1, 0),
    );
    if admitted.disposition != RegionSnapshotDisposition::AwaitingDurableMarks {
        return Err(
            "a strictly newer fenced snapshot was not admitted after capacity released".to_owned(),
        );
    }
    Ok(())
}
